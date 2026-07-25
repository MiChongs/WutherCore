use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use neqo_common::{Datagram, Header, Tos, event::Provider as _, header::HeadersExt as _};
use neqo_http3::{
    Http3Client, Http3ClientEvent, Http3Parameters, Http3State, WebTransportEvent,
    webtransport::ClientSession as _,
};
use neqo_transport::{
    ConnectionParameters, Output, RandomConnectionIdGenerator, StreamId, StreamType,
};
use nss::AuthenticationStatus;
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    net::UdpSocket,
    sync::{Mutex, mpsc, oneshot},
};
use tracing::{debug, warn};

use crate::codec::{
    FlowKind, FlowOpen, SessionKey, Status, Target, UdpReassembler, YoungKey, create_authorization,
    decode_flow_response, decode_udp_fragment, derive_rotating_path, derive_session_key,
    encode_flow_open, encode_udp_fragments, unix_time_secs, verify_server_accept_proof,
};

const STREAM_BUFFER_BYTES: usize = 256 * 1024;
const STREAM_CHUNK_BYTES: usize = 32 * 1024;
const MAX_FLOW_WRITE_BUFFER_BYTES: usize = 1024 * 1024;
const EXPORTER_LABEL: &[u8] = b"young-session-v1";
const EXPORTER_CONTEXT: &[u8] = b"wuther-core";
const CAP_TCP: u32 = 1;
const CAP_UDP: u32 = 2;

#[derive(Clone)]
pub struct YoungClientConfig {
    pub server: String,
    pub port: u16,
    pub server_name: String,
    pub authority: String,
    pub path: String,
    pub key: YoungKey,
    pub certificate_sha256: [u8; 32],
    pub idle_timeout: Duration,
    pub max_streams: u64,
    pub padding_min: u16,
    pub padding_max: u16,
}

impl fmt::Debug for YoungClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungClientConfig")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("server_name", &self.server_name)
            .field("authority", &self.authority)
            .field("path", &self.path)
            .field("key", &self.key)
            .field("certificate_sha256", &"<redacted>")
            .field("idle_timeout", &self.idle_timeout)
            .field("max_streams", &self.max_streams)
            .field("padding_min", &self.padding_min)
            .field("padding_max", &self.padding_max)
            .finish()
    }
}

use std::fmt;

impl YoungClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.server.trim().is_empty()
            || self.server_name.trim().is_empty()
            || self.authority.trim().is_empty()
            || self.port == 0
        {
            return Err(invalid_input(
                "Young client server、server_name、authority 和 port 均不能为空",
            ));
        }
        if self.padding_min > self.padding_max
            || usize::from(self.padding_max) > crate::codec::MAX_PADDING_BYTES
        {
            return Err(invalid_input("Young client padding 范围无效"));
        }
        if self.max_streams == 0 {
            return Err(invalid_input("Young client max_streams 必须大于 0"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct YoungClient {
    commands: mpsc::UnboundedSender<ClientCommand>,
}

impl fmt::Debug for YoungClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungClient")
            .field("worker", &"neqo")
            .finish()
    }
}

impl YoungClient {
    pub fn start(config: YoungClientConfig) -> io::Result<Self> {
        config.validate()?;
        let (commands, receiver) = mpsc::unbounded_channel();
        let worker_commands = commands.clone();
        thread::Builder::new()
            .name(format!("young-neqo-client-{}", config.server_name))
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        warn!(%error, "Young Neqo client runtime 创建失败");
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &runtime,
                    ClientDriver::new(config, receiver, worker_commands).run(),
                );
            })
            .map_err(|error| io::Error::other(format!("Young client worker 启动失败：{error}")))?;
        Ok(Self { commands })
    }

    pub async fn open_tcp(&self, target: Target) -> io::Result<DuplexStream> {
        let (result, receiver) = oneshot::channel();
        self.commands
            .send(ClientCommand::OpenTcp { target, result })
            .map_err(|_| not_connected("Young client worker 已退出"))?;
        receiver
            .await
            .map_err(|_| not_connected("Young client worker 未返回 TCP 结果"))?
    }

    pub async fn open_udp(&self, target: Target) -> io::Result<YoungUdpChannel> {
        let (result, receiver) = oneshot::channel();
        self.commands
            .send(ClientCommand::OpenUdp { target, result })
            .map_err(|_| not_connected("Young client worker 已退出"))?;
        let opened = receiver
            .await
            .map_err(|_| not_connected("Young client worker 未返回 UDP 结果"))??;
        Ok(YoungUdpChannel {
            association_id: opened.association_id,
            target: opened.target,
            commands: self.commands.clone(),
            incoming: Mutex::new(opened.incoming),
            closed: AtomicBool::new(false),
        })
    }
}

pub struct YoungUdpChannel {
    association_id: u64,
    target: Target,
    commands: mpsc::UnboundedSender<ClientCommand>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    closed: AtomicBool,
}

impl fmt::Debug for YoungUdpChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungUdpChannel")
            .field("association_id", &self.association_id)
            .field("target", &self.target)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish()
    }
}

impl YoungUdpChannel {
    #[must_use]
    pub const fn target(&self) -> &Target {
        &self.target
    }

    pub async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(not_connected("Young UDP association 已关闭"));
        }
        self.commands
            .send(ClientCommand::SendUdp {
                association_id: self.association_id,
                payload: payload.to_vec(),
            })
            .map_err(|_| not_connected("Young client worker 已退出"))?;
        Ok(payload.len())
    }

    pub async fn recv(&self, output: &mut [u8]) -> io::Result<usize> {
        let payload = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| not_connected("Young UDP association 已结束"))?;
        if payload.len() > output.len() {
            return Err(invalid_input("Young UDP 接收缓冲区过小"));
        }
        output[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }

    pub fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.commands
                .send(ClientCommand::CloseUdp {
                    association_id: self.association_id,
                })
                .map_err(|_| not_connected("Young client worker 已退出"))?;
        }
        Ok(())
    }
}

impl Drop for YoungUdpChannel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct OpenedUdp {
    association_id: u64,
    target: Target,
    incoming: mpsc::Receiver<Vec<u8>>,
}

enum ClientCommand {
    OpenTcp {
        target: Target,
        result: oneshot::Sender<io::Result<DuplexStream>>,
    },
    OpenUdp {
        target: Target,
        result: oneshot::Sender<io::Result<OpenedUdp>>,
    },
    SendStream {
        stream_id: StreamId,
        payload: Vec<u8>,
    },
    FinishStream {
        stream_id: StreamId,
    },
    SendUdp {
        association_id: u64,
        payload: Vec<u8>,
    },
    CloseUdp {
        association_id: u64,
    },
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

enum OpenResult {
    Tcp {
        result: oneshot::Sender<io::Result<DuplexStream>>,
        application: DuplexStream,
    },
    Udp {
        result: oneshot::Sender<io::Result<OpenedUdp>>,
        incoming: mpsc::Receiver<Vec<u8>>,
    },
}

struct ClientFlow {
    flow_id: u64,
    kind: FlowKind,
    target: Target,
    response: Vec<u8>,
    result: Option<OpenResult>,
    to_application: Option<mpsc::Sender<Vec<u8>>>,
    bridge_task: Option<tokio::task::JoinHandle<()>>,
    writes: VecDeque<PendingWrite>,
    queued_write_bytes: usize,
    finish_after_writes: bool,
    send_finished: bool,
    receive_finished: bool,
}

struct ClientDriver {
    config: YoungClientConfig,
    receiver: mpsc::UnboundedReceiver<ClientCommand>,
    commands: mpsc::UnboundedSender<ClientCommand>,
    client: Option<Http3Client>,
    socket: Option<UdpSocket>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    session_id: Option<StreamId>,
    session_key: Option<SessionKey>,
    client_nonce: Option<[u8; 16]>,
    session_started: bool,
    pending: VecDeque<ClientCommand>,
    flows: HashMap<StreamId, ClientFlow>,
    udp_streams: HashMap<u64, StreamId>,
    udp_reassembler: UdpReassembler,
    next_packet_id: u32,
}

impl ClientDriver {
    fn new(
        config: YoungClientConfig,
        receiver: mpsc::UnboundedReceiver<ClientCommand>,
        commands: mpsc::UnboundedSender<ClientCommand>,
    ) -> Self {
        Self {
            config,
            receiver,
            commands,
            client: None,
            socket: None,
            local_addr: None,
            remote_addr: None,
            session_id: None,
            session_key: None,
            client_nonce: None,
            session_started: false,
            pending: VecDeque::new(),
            flows: HashMap::new(),
            udp_streams: HashMap::new(),
            udp_reassembler: UdpReassembler::default(),
            next_packet_id: OsRng.next_u32(),
        }
    }

    async fn run(mut self) {
        if let Err(error) = self.initialize().await {
            self.fail_all(format!("Young Neqo client 初始化失败：{error}"));
            return;
        }
        loop {
            if let Err(error) = self.process_events().await {
                self.fail_all(error.to_string());
                return;
            }
            let callback = match self.process_output().await {
                Ok(duration) => duration,
                Err(error) => {
                    self.fail_all(error.to_string());
                    return;
                }
            };
            let Some(socket) = self.socket.as_ref() else {
                self.fail_all("Young UDP socket 不存在".into());
                return;
            };
            let mut packet = vec![0; 65_535];
            let sleep_for = if callback.is_zero() {
                Duration::from_millis(250)
            } else {
                callback
            };
            tokio::select! {
                command = self.receiver.recv() => {
                    let Some(command) = command else {
                        return;
                    };
                    if let Err(error) = self.handle_command(command).await {
                        debug!(%error, "Young client command 被拒绝");
                    }
                }
                received = socket.recv_from(&mut packet) => {
                    match received {
                        Ok((length, source)) => {
                            if Some(source) == self.remote_addr {
                                let local = self.local_addr.expect("initialized");
                                let datagram = Datagram::new(source, local, Tos::default(), packet[..length].to_vec());
                                self.client.as_mut().expect("initialized").process_input(datagram, Instant::now());
                            }
                        }
                        Err(error) => {
                            self.fail_all(format!("Young UDP recv 失败：{error}"));
                            return;
                        }
                    }
                }
                () = tokio::time::sleep(sleep_for) => {}
            }
        }
    }

    async fn initialize(&mut self) -> io::Result<()> {
        nss::init().map_err(|error| io::Error::other(format!("NSS 初始化失败：{error}")))?;
        let remote_addr = tokio::net::lookup_host((self.config.server.as_str(), self.config.port))
            .await?
            .next()
            .ok_or_else(|| not_connected("Young server DNS 没有可用地址"))?;
        let bind = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind).await?;
        let local_addr = socket.local_addr()?;
        let connection_parameters = ConnectionParameters::default()
            .idle_timeout(self.config.idle_timeout)
            .max_streams(StreamType::BiDi, self.config.max_streams)
            .max_streams(StreamType::UniDi, 16);
        let parameters = Http3Parameters::default()
            .connection_parameters(connection_parameters)
            .webtransport(true)
            .http3_datagram(true);
        let client = Http3Client::new(
            self.config.server_name.clone(),
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10))),
            local_addr,
            remote_addr,
            parameters,
            Instant::now(),
        )
        .map_err(neqo_error)?;
        self.socket = Some(socket);
        self.local_addr = Some(local_addr);
        self.remote_addr = Some(remote_addr);
        self.client = Some(client);
        Ok(())
    }

    async fn process_output(&mut self) -> io::Result<Duration> {
        loop {
            match self
                .client
                .as_mut()
                .expect("initialized")
                .process_output(Instant::now())
            {
                Output::Datagram(datagram) => {
                    self.socket
                        .as_ref()
                        .expect("initialized")
                        .send_to(datagram.as_ref(), datagram.destination())
                        .await?;
                }
                Output::Callback(duration) => return Ok(duration),
                Output::None => return Ok(Duration::from_millis(250)),
            }
        }
    }

    async fn process_events(&mut self) -> io::Result<()> {
        while let Some(event) = self.client.as_mut().expect("initialized").next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => self.authenticate_certificate()?,
                Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::RequestsCreatable
                | Http3ClientEvent::WebTransport(WebTransportEvent::Negotiated(true)) => {
                    self.maybe_start_session()?;
                }
                Http3ClientEvent::WebTransport(WebTransportEvent::NewSession {
                    stream_id,
                    status,
                    headers,
                }) => self.finish_session(stream_id, status, &headers)?,
                Http3ClientEvent::WebTransport(WebTransportEvent::NewStream {
                    stream_id, ..
                }) => {
                    self.client
                        .as_mut()
                        .expect("initialized")
                        .cancel_fetch(stream_id, neqo_http3::Error::HttpRequestRejected.code())
                        .map_err(neqo_error)?;
                }
                Http3ClientEvent::WebTransport(WebTransportEvent::Datagram {
                    session_id,
                    datagram,
                }) if Some(session_id) == self.session_id => {
                    self.handle_udp_datagram(datagram.as_ref()).await?;
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    self.read_stream(stream_id).await?;
                }
                Http3ClientEvent::DataWritable { stream_id } => {
                    self.flush_stream(stream_id)?;
                }
                Http3ClientEvent::Reset { stream_id, .. }
                | Http3ClientEvent::StopSending { stream_id, .. } => {
                    self.fail_flow(stream_id, "Young WebTransport stream 被对端重置");
                }
                Http3ClientEvent::WebTransport(WebTransportEvent::SessionClosed {
                    stream_id,
                    ..
                }) if Some(stream_id) == self.session_id => {
                    return Err(not_connected("Young WebTransport session 已关闭"));
                }
                Http3ClientEvent::StateChange(Http3State::Closing(reason))
                | Http3ClientEvent::StateChange(Http3State::Closed(reason)) => {
                    return Err(not_connected(format!("Young QUIC 连接关闭：{reason:?}")));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn authenticate_certificate(&mut self) -> io::Result<()> {
        let certificate = self
            .client
            .as_ref()
            .expect("initialized")
            .peer_certificate()
            .and_then(|certificates| certificates.iter().next().map(ToOwned::to_owned));
        let accepted = certificate.is_some_and(|der| {
            let digest: [u8; 32] = Sha256::digest(der).into();
            bool::from(subtle::ConstantTimeEq::ct_eq(
                digest.as_slice(),
                self.config.certificate_sha256.as_slice(),
            ))
        });
        self.client.as_mut().expect("initialized").authenticated(
            if accepted {
                AuthenticationStatus::Ok
            } else {
                AuthenticationStatus::CertUntrusted
            },
            Instant::now(),
        );
        if accepted {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Young server 证书 SHA-256 pin 不匹配",
            ))
        }
    }

    fn maybe_start_session(&mut self) -> io::Result<()> {
        if self.session_started
            || !self
                .client
                .as_ref()
                .expect("initialized")
                .webtransport_enabled()
        {
            return Ok(());
        }
        let now = unix_time_secs()?;
        let path = derive_rotating_path(&self.config.key, &self.config.path, now);
        let (authorization, nonce) = create_authorization(
            &self.config.key,
            &self.config.authority,
            &path,
            CAP_TCP | CAP_UDP,
        )?;
        let headers = [
            Header::new("authorization", format!("Bearer {authorization}")),
            Header::new(
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
            ),
            Header::new("cache-control", "no-cache"),
        ];
        let session_id = self
            .client
            .as_mut()
            .expect("initialized")
            .webtransport_create_session(
                Instant::now(),
                ("https", self.config.authority.as_str(), path.as_str()),
                &headers,
            )
            .map_err(neqo_error)?;
        self.session_started = true;
        self.session_id = Some(session_id);
        self.client_nonce = Some(nonce);
        Ok(())
    }

    fn finish_session(
        &mut self,
        stream_id: StreamId,
        status: u16,
        headers: &[Header],
    ) -> io::Result<()> {
        if Some(stream_id) != self.session_id || status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Young WebTransport session 被拒绝，HTTP {status}"),
            ));
        }
        let proof = headers
            .find_header("sec-young-accept")
            .and_then(|header| header.value_utf8().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Young server 缺少 accept proof",
                )
            })?;
        let nonce = self.client_nonce.expect("session started");
        verify_server_accept_proof(&self.config.key, nonce, proof)?;
        let mut exporter = [0; 32];
        self.client
            .as_ref()
            .expect("initialized")
            .webtransport_export_keying_material(
                stream_id,
                EXPORTER_LABEL,
                EXPORTER_CONTEXT,
                &mut exporter,
            )
            .map_err(neqo_error)?;
        self.session_key = Some(derive_session_key(&self.config.key, &exporter, nonce));
        while let Some(command) = self.pending.pop_front() {
            self.handle_ready_command(command)?;
        }
        Ok(())
    }

    async fn handle_command(&mut self, command: ClientCommand) -> io::Result<()> {
        if self.session_key.is_none() {
            match command {
                ClientCommand::OpenTcp { .. } | ClientCommand::OpenUdp { .. } => {
                    self.pending.push_back(command);
                    return Ok(());
                }
                _ => return Err(not_connected("Young session 尚未就绪")),
            }
        }
        self.handle_ready_command(command)
    }

    fn handle_ready_command(&mut self, command: ClientCommand) -> io::Result<()> {
        match command {
            ClientCommand::OpenTcp { target, result } => {
                self.open_flow(FlowKind::Tcp, target, Some(result), None)
            }
            ClientCommand::OpenUdp { target, result } => {
                self.open_flow(FlowKind::Udp, target, None, Some(result))
            }
            ClientCommand::SendStream { stream_id, payload } => {
                let mut reset = false;
                if let Some(flow) = self.flows.get_mut(&stream_id) {
                    if flow.queued_write_bytes.saturating_add(payload.len())
                        > MAX_FLOW_WRITE_BUFFER_BYTES
                    {
                        reset = true;
                    } else {
                        flow.queued_write_bytes += payload.len();
                        flow.writes.push_back(PendingWrite {
                            bytes: payload,
                            offset: 0,
                        });
                    }
                }
                if reset {
                    let _ = self
                        .client
                        .as_mut()
                        .expect("initialized")
                        .cancel_fetch(stream_id, neqo_http3::Error::HttpRequestRejected.code());
                    self.abort_flow(stream_id);
                } else {
                    self.flush_stream(stream_id)?;
                }
                Ok(())
            }
            ClientCommand::FinishStream { stream_id } => {
                if let Some(flow) = self.flows.get_mut(&stream_id) {
                    flow.finish_after_writes = true;
                    self.flush_stream(stream_id)?;
                }
                Ok(())
            }
            ClientCommand::SendUdp {
                association_id,
                payload,
            } => self.send_udp(association_id, &payload),
            ClientCommand::CloseUdp { association_id } => {
                if let Some(stream_id) = self.udp_streams.remove(&association_id) {
                    self.client
                        .as_mut()
                        .expect("initialized")
                        .stream_close_send(stream_id, Instant::now())
                        .map_err(neqo_error)?;
                    self.remove_flow(stream_id);
                }
                Ok(())
            }
        }
    }

    fn open_flow(
        &mut self,
        kind: FlowKind,
        target: Target,
        tcp_result: Option<oneshot::Sender<io::Result<DuplexStream>>>,
        udp_result: Option<oneshot::Sender<io::Result<OpenedUdp>>>,
    ) -> io::Result<()> {
        let session_id = self
            .session_id
            .ok_or_else(|| not_connected("Young session 缺失"))?;
        let stream_id = self
            .client
            .as_mut()
            .expect("initialized")
            .webtransport_create_stream(session_id, StreamType::BiDi)
            .map_err(neqo_error)?;
        let mut flow_id = OsRng.next_u64();
        while flow_id == 0 || self.udp_streams.contains_key(&flow_id) {
            flow_id = OsRng.next_u64();
        }
        let padding = if self.config.padding_min == self.config.padding_max {
            self.config.padding_min
        } else {
            OsRng.gen_range(self.config.padding_min..=self.config.padding_max)
        };
        let frame = encode_flow_open(
            self.session_key.as_ref().expect("ready"),
            &FlowOpen {
                kind,
                flow_id,
                target: target.clone(),
            },
            usize::from(padding),
        )?;
        let (result, to_application, bridge_task) = match kind {
            FlowKind::Tcp => {
                let result = tcp_result.expect("TCP result");
                let (application, bridge) = tokio::io::duplex(STREAM_BUFFER_BYTES);
                let (incoming, incoming_rx) = mpsc::channel(64);
                let bridge_task = tokio::task::spawn_local(stream_bridge(
                    bridge,
                    incoming_rx,
                    stream_id,
                    self.commands.clone(),
                ));
                (
                    OpenResult::Tcp {
                        result,
                        application,
                    },
                    Some(incoming),
                    Some(bridge_task),
                )
            }
            FlowKind::Udp => {
                let result = udp_result.expect("UDP result");
                let (incoming, incoming_rx) = mpsc::channel(256);
                self.udp_streams.insert(flow_id, stream_id);
                (
                    OpenResult::Udp {
                        result,
                        incoming: incoming_rx,
                    },
                    Some(incoming),
                    None,
                )
            }
        };
        let queued_write_bytes = frame.len();
        self.flows.insert(
            stream_id,
            ClientFlow {
                flow_id,
                kind,
                target,
                response: Vec::new(),
                result: Some(result),
                to_application,
                bridge_task,
                writes: VecDeque::from([PendingWrite {
                    bytes: frame,
                    offset: 0,
                }]),
                queued_write_bytes,
                finish_after_writes: false,
                send_finished: false,
                receive_finished: false,
            },
        );
        self.flush_stream(stream_id)
    }

    fn flush_stream(&mut self, stream_id: StreamId) -> io::Result<()> {
        let mut remove_after_flush = false;
        {
            let Some(flow) = self.flows.get_mut(&stream_id) else {
                return Ok(());
            };
            while let Some(front) = flow.writes.front_mut() {
                let written = self
                    .client
                    .as_mut()
                    .expect("initialized")
                    .send_data(stream_id, &front.bytes[front.offset..], Instant::now())
                    .map_err(neqo_error)?;
                if written == 0 {
                    break;
                }
                flow.queued_write_bytes = flow.queued_write_bytes.saturating_sub(written);
                front.offset += written;
                if front.offset == front.bytes.len() {
                    flow.writes.pop_front();
                }
            }
            if flow.writes.is_empty() && flow.finish_after_writes {
                flow.finish_after_writes = false;
                self.client
                    .as_mut()
                    .expect("initialized")
                    .stream_close_send(stream_id, Instant::now())
                    .map_err(neqo_error)?;
                flow.send_finished = true;
                remove_after_flush = flow.receive_finished;
            }
        }
        if remove_after_flush {
            self.remove_flow(stream_id);
        }
        Ok(())
    }

    async fn read_stream(&mut self, stream_id: StreamId) -> io::Result<()> {
        loop {
            let mut buffer = vec![0; STREAM_CHUNK_BYTES];
            let (length, fin) = self
                .client
                .as_mut()
                .expect("initialized")
                .read_data(Instant::now(), stream_id, &mut buffer)
                .map_err(neqo_error)?;
            if length > 0 {
                buffer.truncate(length);
                self.consume_stream_data(stream_id, buffer).await?;
            }
            if fin || length == 0 {
                if fin {
                    let remove_after_read = self.flows.get_mut(&stream_id).is_some_and(|flow| {
                        flow.receive_finished = true;
                        flow.to_application.take();
                        flow.send_finished
                    });
                    if remove_after_read {
                        self.remove_flow(stream_id);
                    }
                }
                break;
            }
        }
        Ok(())
    }

    async fn consume_stream_data(
        &mut self,
        stream_id: StreamId,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let Some(flow) = self.flows.get_mut(&stream_id) else {
            return Ok(());
        };
        let mut reset_after_delivery = false;
        if flow.result.is_some() {
            flow.response.extend_from_slice(&payload);
            let Some((response, consumed)) =
                decode_flow_response(self.session_key.as_ref().expect("ready"), &flow.response)?
            else {
                return Ok(());
            };
            if response.flow_id != flow.flow_id {
                return Err(invalid_data("Young flow response id 不匹配"));
            }
            let remaining = flow.response.split_off(consumed);
            flow.response.clear();
            let result = flow.result.take().expect("checked");
            if response.status != Status::Ok {
                let error = status_error(response.status);
                match result {
                    OpenResult::Tcp { result, .. } => {
                        let _ = result.send(Err(error));
                    }
                    OpenResult::Udp { result, .. } => {
                        let _ = result.send(Err(error));
                    }
                }
                self.client
                    .as_mut()
                    .expect("initialized")
                    .stream_close_send(stream_id, Instant::now())
                    .map_err(neqo_error)?;
                self.abort_flow(stream_id);
                return Ok(());
            }
            match result {
                OpenResult::Tcp {
                    result,
                    application,
                } => {
                    let _ = result.send(Ok(application));
                }
                OpenResult::Udp { result, incoming } => {
                    let _ = result.send(Ok(OpenedUdp {
                        association_id: flow.flow_id,
                        target: flow.target.clone(),
                        incoming,
                    }));
                }
            }
            if !remaining.is_empty()
                && flow.kind == FlowKind::Tcp
                && let Some(sender) = &flow.to_application
            {
                reset_after_delivery = sender.try_send(remaining).is_err();
            }
        } else if flow.kind == FlowKind::Tcp
            && let Some(sender) = &flow.to_application
        {
            reset_after_delivery = sender.try_send(payload).is_err();
        }
        if reset_after_delivery {
            let _ = self
                .client
                .as_mut()
                .expect("initialized")
                .cancel_fetch(stream_id, neqo_http3::Error::HttpRequestRejected.code());
            self.abort_flow(stream_id);
        }
        Ok(())
    }

    fn send_udp(&mut self, association_id: u64, payload: &[u8]) -> io::Result<()> {
        if !self.udp_streams.contains_key(&association_id) {
            return Err(not_connected("Young UDP association 不存在"));
        }
        let session_id = self.session_id.expect("ready");
        let max_size = usize::try_from(
            self.client
                .as_ref()
                .expect("initialized")
                .webtransport_max_datagram_size(session_id)
                .map_err(neqo_error)?,
        )
        .map_err(|_| invalid_input("WebTransport datagram size 超过 usize"))?;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        for fragment in encode_udp_fragments(
            self.session_key.as_ref().expect("ready"),
            association_id,
            self.next_packet_id,
            payload,
            max_size,
        )? {
            self.client
                .as_mut()
                .expect("initialized")
                .webtransport_send_datagram(session_id, &fragment, None, Instant::now())
                .map_err(neqo_error)?;
        }
        Ok(())
    }

    async fn handle_udp_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        let fragment = decode_udp_fragment(self.session_key.as_ref().expect("ready"), datagram)?;
        let association_id = fragment.association_id;
        let Some(stream_id) = self.udp_streams.get(&association_id).copied() else {
            return Ok(());
        };
        if let Some(payload) = self.udp_reassembler.push(fragment, Instant::now())?
            && let Some(sender) = self
                .flows
                .get(&stream_id)
                .and_then(|flow| flow.to_application.as_ref())
        {
            let _ = sender.try_send(payload);
        }
        Ok(())
    }

    fn fail_flow(&mut self, stream_id: StreamId, message: &str) {
        if let Some(mut flow) = self.abort_flow(stream_id)
            && let Some(result) = flow.result.take()
        {
            match result {
                OpenResult::Tcp { result, .. } => {
                    let _ = result.send(Err(not_connected(message)));
                }
                OpenResult::Udp { result, .. } => {
                    let _ = result.send(Err(not_connected(message)));
                }
            }
        }
    }

    fn remove_flow(&mut self, stream_id: StreamId) -> Option<ClientFlow> {
        let flow = self.flows.remove(&stream_id)?;
        if flow.kind == FlowKind::Udp {
            self.udp_streams.remove(&flow.flow_id);
        }
        Some(flow)
    }

    fn abort_flow(&mut self, stream_id: StreamId) -> Option<ClientFlow> {
        let mut flow = self.remove_flow(stream_id)?;
        if let Some(task) = flow.bridge_task.take() {
            task.abort();
        }
        Some(flow)
    }

    fn fail_all(&mut self, message: String) {
        while let Some(command) = self.pending.pop_front() {
            match command {
                ClientCommand::OpenTcp { result, .. } => {
                    let _ = result.send(Err(not_connected(message.clone())));
                }
                ClientCommand::OpenUdp { result, .. } => {
                    let _ = result.send(Err(not_connected(message.clone())));
                }
                _ => {}
            }
        }
        let stream_ids: Vec<_> = self.flows.keys().copied().collect();
        for stream_id in stream_ids {
            self.fail_flow(stream_id, &message);
        }
    }
}

async fn stream_bridge(
    stream: DuplexStream,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    stream_id: StreamId,
    commands: mpsc::UnboundedSender<ClientCommand>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0; STREAM_CHUNK_BYTES];
    let mut local_send_open = true;
    let mut remote_send_open = true;
    while local_send_open || remote_send_open {
        tokio::select! {
            read = reader.read(&mut buffer), if local_send_open => {
                match read {
                    Ok(0) => {
                        local_send_open = false;
                        let _ = commands.send(ClientCommand::FinishStream { stream_id });
                    }
                    Ok(length) => {
                        let _ = commands.send(ClientCommand::SendStream {
                            stream_id,
                            payload: buffer[..length].to_vec(),
                        });
                    }
                    Err(_) => {
                        local_send_open = false;
                        let _ = commands.send(ClientCommand::FinishStream { stream_id });
                    }
                }
            }
            payload = incoming.recv(), if remote_send_open => {
                match payload {
                    Some(payload) if writer.write_all(&payload).await.is_ok() => {}
                    Some(_) => {
                        remote_send_open = false;
                        incoming.close();
                        let _ = writer.shutdown().await;
                    }
                    None => {
                        remote_send_open = false;
                        let _ = writer.shutdown().await;
                    }
                }
            }
        }
    }
}

fn neqo_error(error: impl fmt::Display) -> io::Error {
    io::Error::other(format!("Neqo：{error}"))
}

fn status_error(status: Status) -> io::Error {
    let (kind, message) = match status {
        Status::Ok => (io::ErrorKind::Other, "unexpected OK"),
        Status::BadRequest => (io::ErrorKind::InvalidData, "请求格式无效"),
        Status::Unauthorized => (io::ErrorKind::PermissionDenied, "未授权"),
        Status::ConnectFailed => (io::ErrorKind::ConnectionRefused, "目标连接失败"),
        Status::Unsupported => (io::ErrorKind::Unsupported, "命令不受支持"),
        Status::ResourceLimit => (io::ErrorKind::OutOfMemory, "服务端资源限制"),
    };
    io::Error::new(kind, format!("Young server 拒绝 flow：{message}"))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn not_connected(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, message.into())
}
