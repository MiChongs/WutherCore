use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    rc::Rc,
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

use neqo_common::{Datagram, Header, Tos, header::HeadersExt as _};
use neqo_http3::{
    Http3OrWebTransportStream, Http3Parameters, Http3Server, Http3ServerEvent, SessionAcceptAction,
    webtransport::{ServerEvent, ServerSession},
};
use neqo_transport::{
    ConnectionParameters, Output, RandomConnectionIdGenerator, StreamId, StreamType,
};
use nss::AntiReplay;
use rand::{RngCore, rngs::OsRng};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
};
use tracing::{debug, warn};

use crate::codec::{
    FlowKind, FlowResponse, KeyRing, ReplayCache, SessionKey, Status, Target, UdpReassembler,
    decode_flow_open, decode_udp_fragment, derive_rotating_path, derive_session_key,
    encode_flow_response, encode_udp_fragments, server_accept_proof, unix_time_secs,
    verify_authorization,
};

const STREAM_CHUNK_BYTES: usize = 32 * 1024;
const MAX_FLOW_WRITE_BUFFER_BYTES: usize = 1024 * 1024;
const EXPORTER_LABEL: &[u8] = b"young-session-v1";
const EXPORTER_CONTEXT: &[u8] = b"wuther-core";
const NSS_ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(10);
static NSS_DATABASE: OnceLock<PathBuf> = OnceLock::new();

#[derive(Clone)]
pub struct YoungServerConfig {
    pub listen: SocketAddr,
    pub nss_database: PathBuf,
    pub certificate_nickname: String,
    pub authority: String,
    pub path: String,
    pub keys: KeyRing,
    pub clock_skew: Duration,
    pub idle_timeout: Duration,
    pub max_streams: u64,
    pub max_sessions: usize,
    pub max_flows_per_session: usize,
    pub decoy_status: u16,
    pub decoy_body: Vec<u8>,
}

impl fmt::Debug for YoungServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungServerConfig")
            .field("listen", &self.listen)
            .field("nss_database", &self.nss_database)
            .field("certificate_nickname", &self.certificate_nickname)
            .field("authority", &self.authority)
            .field("path", &self.path)
            .field("key_count", &self.keys.len())
            .field("clock_skew", &self.clock_skew)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_streams", &self.max_streams)
            .field("max_sessions", &self.max_sessions)
            .field("max_flows_per_session", &self.max_flows_per_session)
            .field("decoy_status", &self.decoy_status)
            .field("decoy_body_bytes", &self.decoy_body.len())
            .finish()
    }
}

impl YoungServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        if !self.nss_database.is_dir() {
            return Err(invalid_input(format!(
                "Young server NSS database 目录不存在：{}",
                self.nss_database.display()
            )));
        }
        if self.certificate_nickname.trim().is_empty()
            || self.authority.trim().is_empty()
            || self.path.trim().is_empty()
        {
            return Err(invalid_input(
                "Young server certificate_nickname、authority、path 不能为空",
            ));
        }
        if self.max_streams == 0 || self.max_sessions == 0 || self.max_flows_per_session == 0 {
            return Err(invalid_input("Young server 资源上限必须大于 0"));
        }
        if !(100..=599).contains(&self.decoy_status) {
            return Err(invalid_input(
                "Young server decoy_status 必须是 HTTP 状态码",
            ));
        }
        Ok(())
    }
}

pub struct YoungServerHandle {
    local_addr: SocketAddr,
    commands: mpsc::UnboundedSender<ServerCommand>,
}

impl fmt::Debug for YoungServerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungServerHandle")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl YoungServerHandle {
    pub fn start(config: YoungServerConfig) -> io::Result<Self> {
        config.validate()?;
        if let Some(existing) = NSS_DATABASE.get() {
            if existing != &config.nss_database {
                return Err(invalid_input(format!(
                    "同一进程只能使用一个 NSS database；已使用 {}，收到 {}",
                    existing.display(),
                    config.nss_database.display()
                )));
            }
        } else {
            let _ = NSS_DATABASE.set(config.nss_database.clone());
        }

        let (commands, receiver) = mpsc::unbounded_channel();
        let worker_commands = commands.clone();
        let (ready, ready_receiver) = std::sync::mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("young-neqo-server-{}", config.listen.port()))
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(format!("Tokio runtime 创建失败：{error}")));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    match ServerDriver::initialize(config, receiver, worker_commands).await {
                        Ok(mut driver) => {
                            let _ = ready.send(Ok(driver.local_addr));
                            if let Err(error) = driver.run().await {
                                warn!(%error, "Young Neqo server 退出");
                            }
                        }
                        Err(error) => {
                            let _ = ready.send(Err(error.to_string()));
                        }
                    }
                });
            })
            .map_err(|error| io::Error::other(format!("Young server worker 启动失败：{error}")))?;
        let local_addr = ready_receiver
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Young server 启动超时"))?
            .map_err(io::Error::other)?;
        Ok(Self {
            local_addr,
            commands,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.commands
            .send(ServerCommand::Shutdown)
            .map_err(|_| not_connected("Young server 已退出"))
    }
}

impl Drop for YoungServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

struct ServerStream {
    stream: Http3OrWebTransportStream,
    session_id: StreamId,
    open_buffer: Vec<u8>,
    opened: bool,
    kind: Option<FlowKind>,
    flow_id: Option<u64>,
    target_input: Option<mpsc::Sender<Vec<u8>>>,
    target_task: Option<tokio::task::JoinHandle<()>>,
    writes: VecDeque<PendingWrite>,
    queued_write_bytes: usize,
    finish_after_writes: bool,
    send_finished: bool,
    receive_finished: bool,
}

struct DecoyStream {
    stream: Http3OrWebTransportStream,
    writes: VecDeque<PendingWrite>,
    finish_after_writes: bool,
    send_finished: bool,
    receive_finished: bool,
}

struct SessionState {
    session: ServerSession,
    session_key: SessionKey,
    reassembler: UdpReassembler,
    flow_count: usize,
}

enum ServerCommand {
    TcpOpened {
        stream_id: StreamId,
    },
    TcpFailed {
        stream_id: StreamId,
        message: String,
    },
    StreamOutput {
        stream_id: StreamId,
        payload: Vec<u8>,
    },
    StreamFinished {
        stream_id: StreamId,
    },
    UdpOpened {
        stream_id: StreamId,
        association_id: u64,
    },
    UdpFailed {
        stream_id: StreamId,
        message: String,
    },
    UdpOutput {
        session_id: StreamId,
        association_id: u64,
        packet_id: u32,
        payload: Vec<u8>,
    },
    UdpClosed {
        session_id: StreamId,
        association_id: u64,
    },
    Shutdown,
}

struct ServerDriver {
    config: YoungServerConfig,
    socket: UdpSocket,
    local_addr: SocketAddr,
    server: Http3Server,
    replay: ReplayCache,
    receiver: mpsc::UnboundedReceiver<ServerCommand>,
    commands: mpsc::UnboundedSender<ServerCommand>,
    sessions: HashMap<StreamId, SessionState>,
    streams: HashMap<StreamId, ServerStream>,
    decoys: HashMap<StreamId, DecoyStream>,
    udp_inputs: HashMap<(StreamId, u64), mpsc::Sender<Vec<u8>>>,
}

impl ServerDriver {
    async fn initialize(
        config: YoungServerConfig,
        receiver: mpsc::UnboundedReceiver<ServerCommand>,
        commands: mpsc::UnboundedSender<ServerCommand>,
    ) -> io::Result<Self> {
        nss::init_db(config.nss_database.clone())
            .map_err(|error| io::Error::other(format!("NSS database 初始化失败：{error}")))?;
        let socket = UdpSocket::bind(config.listen).await?;
        let local_addr = socket.local_addr()?;
        let connection_parameters = ConnectionParameters::default()
            .idle_timeout(config.idle_timeout)
            .max_streams(StreamType::BiDi, config.max_streams)
            .max_streams(StreamType::UniDi, 16);
        let parameters = Http3Parameters::default()
            .connection_parameters(connection_parameters)
            .webtransport(true)
            .http3_datagram(true);
        let server = Http3Server::new(
            Instant::now(),
            &[config.certificate_nickname.as_str()],
            &["h3"],
            AntiReplay::new(Instant::now(), NSS_ANTI_REPLAY_WINDOW, 7, 14)
                .map_err(|error| io::Error::other(format!("NSS anti-replay 创建失败：{error}")))?,
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10))),
            parameters,
            None,
        )
        .map_err(neqo_error)?;
        Ok(Self {
            config,
            socket,
            local_addr,
            server,
            replay: ReplayCache::default(),
            receiver,
            commands,
            sessions: HashMap::new(),
            streams: HashMap::new(),
            decoys: HashMap::new(),
            udp_inputs: HashMap::new(),
        })
    }

    async fn run(&mut self) -> io::Result<()> {
        let mut callback = Duration::ZERO;
        loop {
            self.process_events().await?;
            callback = self.process_output(callback).await?;
            let mut packet = vec![0; 65_535];
            let sleep_for = if callback.is_zero() {
                Duration::from_millis(250)
            } else {
                callback
            };
            tokio::select! {
                command = self.receiver.recv() => {
                    match command {
                        Some(ServerCommand::Shutdown) | None => return Ok(()),
                        Some(command) => self.handle_command(command).await?,
                    }
                }
                received = self.socket.recv_from(&mut packet) => {
                    let (length, source) = received?;
                    let datagram = Datagram::new(
                        source,
                        self.local_addr,
                        Tos::default(),
                        packet[..length].to_vec(),
                    );
                    let output = self.server.process(Some(datagram), Instant::now());
                    self.send_output(output).await?;
                }
                () = tokio::time::sleep(sleep_for) => {}
            }
        }
    }

    async fn process_output(&mut self, previous: Duration) -> io::Result<Duration> {
        loop {
            match self.server.process_output(Instant::now()) {
                Output::Datagram(datagram) => self.send_output(Output::Datagram(datagram)).await?,
                Output::Callback(duration) => return Ok(duration),
                Output::None => {
                    return Ok(if previous.is_zero() {
                        Duration::from_millis(250)
                    } else {
                        previous
                    });
                }
            }
        }
    }

    async fn send_output(&self, output: Output) -> io::Result<()> {
        if let Output::Datagram(datagram) = output {
            self.socket
                .send_to(datagram.as_ref(), datagram.destination())
                .await?;
        }
        Ok(())
    }

    async fn process_events(&mut self) -> io::Result<()> {
        while let Some(event) = self.server.next_event() {
            match event {
                Http3ServerEvent::WebTransport(ServerEvent::NewSession { session, headers }) => {
                    self.handle_new_session(session, &headers)?
                }
                Http3ServerEvent::WebTransport(ServerEvent::NewStream(stream)) => {
                    self.handle_new_stream(stream)?;
                }
                Http3ServerEvent::WebTransport(ServerEvent::Datagram { session, datagram }) => {
                    self.handle_datagram(session.stream_id(), datagram.as_ref())
                        .await?
                }
                Http3ServerEvent::WebTransport(ServerEvent::SessionClosed { session, .. }) => {
                    self.close_session(session.stream_id());
                }
                Http3ServerEvent::Data { stream, data, fin } => {
                    let stream_id = stream.stream_id();
                    if self.streams.contains_key(&stream_id) {
                        self.handle_stream_data(stream, data, fin).await?;
                    } else if self.decoys.contains_key(&stream_id) {
                        self.handle_decoy_data(stream_id, fin);
                    }
                }
                Http3ServerEvent::DataWritable { stream } => {
                    let stream_id = stream.stream_id();
                    if self.streams.contains_key(&stream_id) {
                        self.flush_stream(stream_id)?;
                    } else if self.decoys.contains_key(&stream_id) {
                        self.flush_decoy(stream_id)?;
                    }
                }
                Http3ServerEvent::Headers {
                    stream,
                    headers,
                    fin,
                } => self.handle_decoy(stream, &headers, fin)?,
                Http3ServerEvent::StreamReset { stream, .. }
                | Http3ServerEvent::StreamStopSending { stream, .. } => {
                    self.remove_stream(stream.stream_id());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn handle_new_session(&mut self, session: ServerSession, headers: &[Header]) -> io::Result<()> {
        if self.sessions.len() >= self.config.max_sessions {
            return self.reject_session(&session);
        }
        let authority = header_text(headers, ":authority").unwrap_or_default();
        let path = header_text(headers, ":path").unwrap_or_default();
        let authorization = header_text(headers, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let now = unix_time_secs()?;
        let verified = verify_authorization(
            authorization,
            authority,
            path,
            &self.config.keys,
            &self.replay,
            now,
            self.config.clock_skew.as_secs(),
        );
        let Ok((key, nonce, _capabilities)) = verified else {
            return self.reject_session(&session);
        };
        let path_valid = [now.saturating_sub(86_400), now, now.saturating_add(86_400)]
            .iter()
            .any(|time| derive_rotating_path(&key, &self.config.path, *time) == path);
        if authority != self.config.authority || !path_valid {
            return self.reject_session(&session);
        }
        let proof = server_accept_proof(&key, nonce);
        session
            .response(
                &SessionAcceptAction::AcceptWith(vec![Header::new("sec-young-accept", proof)]),
                Instant::now(),
            )
            .map_err(neqo_error)?;
        let mut exporter = [0; 32];
        session
            .export_keying_material(EXPORTER_LABEL, EXPORTER_CONTEXT, &mut exporter)
            .map_err(neqo_error)?;
        self.sessions.insert(
            session.stream_id(),
            SessionState {
                session,
                session_key: derive_session_key(&key, &exporter, nonce),
                reassembler: UdpReassembler::default(),
                flow_count: 0,
            },
        );
        Ok(())
    }

    fn reject_session(&self, session: &ServerSession) -> io::Result<()> {
        session
            .response(
                &SessionAcceptAction::Reject(vec![
                    Header::new(":status", self.config.decoy_status.to_string()),
                    Header::new("content-type", "text/html; charset=utf-8"),
                    Header::new("cache-control", "public, max-age=300"),
                ]),
                Instant::now(),
            )
            .map_err(neqo_error)
    }

    fn handle_new_stream(&mut self, stream: Http3OrWebTransportStream) -> io::Result<()> {
        let session_id = stream
            .stream_info
            .session_id()
            .ok_or_else(|| invalid_data("收到不属于 WebTransport session 的 Young stream"))?;
        let Some(session) = self.sessions.get_mut(&session_id) else {
            stream
                .stream_reset_send(neqo_http3::Error::HttpRequestRejected.code())
                .map_err(neqo_error)?;
            return Ok(());
        };
        if session.flow_count >= self.config.max_flows_per_session {
            let response = encode_flow_response(
                &session.session_key,
                FlowResponse {
                    status: Status::ResourceLimit,
                    flow_id: 0,
                },
            );
            let _ = stream.send_data(&response, Instant::now());
            let _ = stream.stream_close_send(Instant::now());
            return Ok(());
        }
        session.flow_count += 1;
        self.streams.insert(
            stream.stream_id(),
            ServerStream {
                stream,
                session_id,
                open_buffer: Vec::new(),
                opened: false,
                kind: None,
                flow_id: None,
                target_input: None,
                target_task: None,
                writes: VecDeque::new(),
                queued_write_bytes: 0,
                finish_after_writes: false,
                send_finished: false,
                receive_finished: false,
            },
        );
        Ok(())
    }

    async fn handle_stream_data(
        &mut self,
        stream: Http3OrWebTransportStream,
        data: Vec<u8>,
        fin: bool,
    ) -> io::Result<()> {
        let stream_id = stream.stream_id();
        let Some(flow) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        let mut reset_after_read = false;
        if !flow.opened {
            flow.open_buffer.extend_from_slice(&data);
            let session_key = &self
                .sessions
                .get(&flow.session_id)
                .ok_or_else(|| not_connected("Young session 已关闭"))?
                .session_key;
            let decoded = match decode_flow_open(session_key, &flow.open_buffer) {
                Ok(decoded) => decoded,
                Err(error) => {
                    debug!(%error, "丢弃无效 Young flow open");
                    if fin {
                        flow.receive_finished = true;
                        flow.target_input.take();
                    }
                    self.fail_stream(stream_id, Status::BadRequest)?;
                    return Ok(());
                }
            };
            let Some((open, consumed)) = decoded else {
                if fin {
                    flow.receive_finished = true;
                    flow.target_input.take();
                    self.fail_stream(stream_id, Status::BadRequest)?;
                }
                return Ok(());
            };
            let remaining = flow.open_buffer.split_off(consumed);
            flow.open_buffer.clear();
            flow.opened = true;
            flow.kind = Some(open.kind);
            flow.flow_id = Some(open.flow_id);
            if open.kind == FlowKind::Udp && !remaining.is_empty() {
                if fin {
                    flow.receive_finished = true;
                }
                self.fail_stream(stream_id, Status::BadRequest)?;
                return Ok(());
            }
            let (target_input, target_receiver) = mpsc::channel(128);
            flow.target_input = Some(target_input.clone());
            flow.target_task = Some(match open.kind {
                FlowKind::Tcp => tokio::task::spawn_local(tcp_target(
                    stream_id,
                    open.target,
                    target_receiver,
                    self.commands.clone(),
                )),
                FlowKind::Udp => tokio::task::spawn_local(udp_target(
                    flow.session_id,
                    stream_id,
                    open.flow_id,
                    open.target,
                    target_receiver,
                    self.commands.clone(),
                )),
            });
            if !remaining.is_empty() && target_input.try_send(remaining).is_err() {
                reset_after_read = true;
            }
        } else if flow.kind == Some(FlowKind::Udp) && !data.is_empty() {
            reset_after_read = true;
        } else if !data.is_empty()
            && let Some(target) = &flow.target_input
            && target.try_send(data).is_err()
        {
            reset_after_read = true;
        }
        if reset_after_read {
            flow.target_input.take();
            self.reset_stream(stream_id);
            return Ok(());
        }
        let remove_after_read = if fin {
            flow.target_input.take();
            flow.receive_finished = true;
            flow.send_finished
        } else {
            false
        };
        if remove_after_read {
            self.remove_stream(stream_id);
        }
        Ok(())
    }

    fn handle_decoy(
        &mut self,
        stream: Http3OrWebTransportStream,
        headers: &[Header],
        receive_finished: bool,
    ) -> io::Result<()> {
        let method = header_text(headers, ":method").unwrap_or("GET");
        let status = if matches!(method, "GET" | "HEAD") {
            self.config.decoy_status
        } else {
            405
        };
        let body = if method == "HEAD" {
            Vec::new()
        } else {
            self.config.decoy_body.clone()
        };
        stream
            .send_headers(&[
                Header::new(":status", status.to_string()),
                Header::new("content-type", "text/html; charset=utf-8"),
                Header::new("content-length", body.len().to_string()),
                Header::new("cache-control", "public, max-age=300"),
                Header::new("server", "nginx"),
            ])
            .map_err(neqo_error)?;
        let stream_id = stream.stream_id();
        self.decoys.insert(
            stream_id,
            DecoyStream {
                stream,
                writes: if body.is_empty() {
                    VecDeque::new()
                } else {
                    VecDeque::from([PendingWrite {
                        bytes: body,
                        offset: 0,
                    }])
                },
                finish_after_writes: true,
                send_finished: false,
                receive_finished,
            },
        );
        self.flush_decoy(stream_id)
    }

    fn handle_decoy_data(&mut self, stream_id: StreamId, fin: bool) {
        let remove = self.decoys.get_mut(&stream_id).is_some_and(|decoy| {
            decoy.receive_finished |= fin;
            decoy.receive_finished && decoy.send_finished
        });
        if remove {
            self.decoys.remove(&stream_id);
        }
    }

    async fn handle_datagram(&mut self, session_id: StreamId, data: &[u8]) -> io::Result<()> {
        let Some(session_key) = self
            .sessions
            .get(&session_id)
            .map(|session| session.session_key.clone())
        else {
            return Ok(());
        };
        let Ok(fragment) = decode_udp_fragment(&session_key, data) else {
            return Ok(());
        };
        let association_id = fragment.association_id;
        let Some(target) = self.udp_inputs.get(&(session_id, association_id)).cloned() else {
            return Ok(());
        };
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Ok(());
        };
        let Ok(payload) = session.reassembler.push(fragment, Instant::now()) else {
            return Ok(());
        };
        if let Some(payload) = payload {
            let _ = target.try_send(payload);
        }
        Ok(())
    }

    async fn handle_command(&mut self, command: ServerCommand) -> io::Result<()> {
        match command {
            ServerCommand::TcpOpened { stream_id } => self.respond_flow(stream_id, Status::Ok),
            ServerCommand::TcpFailed { stream_id, message } => {
                debug!(%message, "Young TCP 目标连接失败");
                self.fail_stream(stream_id, Status::ConnectFailed)
            }
            ServerCommand::StreamOutput { stream_id, payload } => {
                let mut reset = false;
                if let Some(flow) = self.streams.get_mut(&stream_id) {
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
                    self.reset_stream(stream_id);
                } else {
                    self.flush_stream(stream_id)?;
                }
                Ok(())
            }
            ServerCommand::StreamFinished { stream_id } => {
                if let Some(flow) = self.streams.get_mut(&stream_id) {
                    flow.finish_after_writes = true;
                    self.flush_stream(stream_id)?;
                }
                Ok(())
            }
            ServerCommand::UdpOpened {
                stream_id,
                association_id,
            } => {
                let Some(flow) = self.streams.get(&stream_id) else {
                    return Ok(());
                };
                if let Some(input) = &flow.target_input {
                    self.udp_inputs
                        .insert((flow.session_id, association_id), input.clone());
                }
                self.respond_flow(stream_id, Status::Ok)
            }
            ServerCommand::UdpFailed { stream_id, message } => {
                debug!(%message, "Young UDP 目标创建失败");
                self.fail_stream(stream_id, Status::ConnectFailed)
            }
            ServerCommand::UdpOutput {
                session_id,
                association_id,
                packet_id,
                payload,
            } => self.send_udp(session_id, association_id, packet_id, &payload),
            ServerCommand::UdpClosed {
                session_id,
                association_id,
            } => {
                self.udp_inputs.remove(&(session_id, association_id));
                Ok(())
            }
            ServerCommand::Shutdown => Ok(()),
        }
    }

    fn respond_flow(&mut self, stream_id: StreamId, status: Status) -> io::Result<()> {
        let flow = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| not_connected("Young stream 不存在"))?;
        let session = self
            .sessions
            .get(&flow.session_id)
            .ok_or_else(|| not_connected("Young session 不存在"))?;
        let response = encode_flow_response(
            &session.session_key,
            FlowResponse {
                status,
                flow_id: flow.flow_id.unwrap_or(0),
            },
        );
        flow.queued_write_bytes += response.len();
        flow.writes.push_front(PendingWrite {
            bytes: response.to_vec(),
            offset: 0,
        });
        self.flush_stream(stream_id)
    }

    fn fail_stream(&mut self, stream_id: StreamId, status: Status) -> io::Result<()> {
        self.respond_flow(stream_id, status)?;
        if let Some(flow) = self.streams.get_mut(&stream_id) {
            flow.finish_after_writes = true;
            self.flush_stream(stream_id)?;
        }
        Ok(())
    }

    fn flush_stream(&mut self, stream_id: StreamId) -> io::Result<()> {
        let mut remove_after_flush = false;
        {
            let Some(flow) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            while let Some(front) = flow.writes.front_mut() {
                let written = flow
                    .stream
                    .send_data(&front.bytes[front.offset..], Instant::now())
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
                flow.stream
                    .stream_close_send(Instant::now())
                    .map_err(neqo_error)?;
                flow.send_finished = true;
                remove_after_flush = flow.receive_finished;
            }
        }
        if remove_after_flush {
            self.remove_stream(stream_id);
        }
        Ok(())
    }

    fn flush_decoy(&mut self, stream_id: StreamId) -> io::Result<()> {
        let mut remove_after_flush = false;
        {
            let Some(decoy) = self.decoys.get_mut(&stream_id) else {
                return Ok(());
            };
            while let Some(front) = decoy.writes.front_mut() {
                let written = decoy
                    .stream
                    .send_data(&front.bytes[front.offset..], Instant::now())
                    .map_err(neqo_error)?;
                if written == 0 {
                    break;
                }
                front.offset += written;
                if front.offset == front.bytes.len() {
                    decoy.writes.pop_front();
                }
            }
            if decoy.writes.is_empty() && decoy.finish_after_writes {
                decoy.finish_after_writes = false;
                decoy
                    .stream
                    .stream_close_send(Instant::now())
                    .map_err(neqo_error)?;
                decoy.send_finished = true;
                remove_after_flush = decoy.receive_finished;
            }
        }
        if remove_after_flush {
            self.decoys.remove(&stream_id);
        }
        Ok(())
    }

    fn send_udp(
        &mut self,
        session_id: StreamId,
        association_id: u64,
        packet_id: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| not_connected("Young session 不存在"))?;
        let max_size = usize::try_from(session.session.max_datagram_size().map_err(neqo_error)?)
            .map_err(|_| invalid_input("WebTransport datagram size 超过 usize"))?;
        for fragment in encode_udp_fragments(
            &session.session_key,
            association_id,
            packet_id,
            payload,
            max_size,
        )? {
            session
                .session
                .send_datagram(&fragment, None, Instant::now())
                .map_err(neqo_error)?;
        }
        Ok(())
    }

    fn close_session(&mut self, session_id: StreamId) {
        self.sessions.remove(&session_id);
        let streams: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(id, stream)| (stream.session_id == session_id).then_some(*id))
            .collect();
        for stream_id in streams {
            self.remove_stream(stream_id);
        }
        self.udp_inputs
            .retain(|(candidate, _), _| *candidate != session_id);
    }

    fn remove_stream(&mut self, stream_id: StreamId) {
        if let Some(mut flow) = self.streams.remove(&stream_id) {
            if let Some(session) = self.sessions.get_mut(&flow.session_id) {
                session.flow_count = session.flow_count.saturating_sub(1);
            }
            if let Some(flow_id) = flow.flow_id {
                self.udp_inputs.remove(&(flow.session_id, flow_id));
            }
            if let Some(task) = flow.target_task.take() {
                task.abort();
            }
        }
        self.decoys.remove(&stream_id);
    }

    fn reset_stream(&mut self, stream_id: StreamId) {
        if let Some(flow) = self.streams.get_mut(&stream_id) {
            let _ = flow
                .stream
                .stream_reset_send(neqo_http3::Error::HttpRequestRejected.code());
        }
        self.remove_stream(stream_id);
    }
}

async fn tcp_target(
    stream_id: StreamId,
    target: Target,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    commands: mpsc::UnboundedSender<ServerCommand>,
) {
    let socket = match TcpStream::connect(target.authority()).await {
        Ok(socket) => socket,
        Err(error) => {
            let _ = commands.send(ServerCommand::TcpFailed {
                stream_id,
                message: error.to_string(),
            });
            return;
        }
    };
    let _ = socket.set_nodelay(true);
    let _ = commands.send(ServerCommand::TcpOpened { stream_id });
    let (mut target_reader, mut target_writer) = socket.into_split();
    let mut buffer = vec![0; STREAM_CHUNK_BYTES];
    let mut target_send_open = true;
    let mut client_send_open = true;
    while target_send_open || client_send_open {
        tokio::select! {
            read = target_reader.read(&mut buffer), if target_send_open => {
                match read {
                    Ok(0) | Err(_) => {
                        target_send_open = false;
                        let _ = commands.send(ServerCommand::StreamFinished { stream_id });
                    }
                    Ok(length) => {
                        let _ = commands.send(ServerCommand::StreamOutput {
                            stream_id,
                            payload: buffer[..length].to_vec(),
                        });
                    }
                }
            }
            payload = incoming.recv(), if client_send_open => {
                match payload {
                    Some(payload) => {
                        if target_writer.write_all(&payload).await.is_err() {
                            client_send_open = false;
                            incoming.close();
                            let _ = target_writer.shutdown().await;
                        }
                    }
                    None => {
                        client_send_open = false;
                        let _ = target_writer.shutdown().await;
                    }
                }
            }
        }
    }
}

async fn udp_target(
    session_id: StreamId,
    stream_id: StreamId,
    association_id: u64,
    target: Target,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    commands: mpsc::UnboundedSender<ServerCommand>,
) {
    let remote = match tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .ok()
        .and_then(|mut addresses| addresses.next())
    {
        Some(remote) => remote,
        None => {
            let _ = commands.send(ServerCommand::UdpFailed {
                stream_id,
                message: "目标 DNS 解析失败".into(),
            });
            return;
        }
    };
    let bind = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            let _ = commands.send(ServerCommand::UdpFailed {
                stream_id,
                message: error.to_string(),
            });
            return;
        }
    };
    if let Err(error) = socket.connect(remote).await {
        let _ = commands.send(ServerCommand::UdpFailed {
            stream_id,
            message: error.to_string(),
        });
        return;
    }
    let _ = commands.send(ServerCommand::UdpOpened {
        stream_id,
        association_id,
    });
    let mut packet_id = OsRng.next_u32();
    let mut buffer = vec![0; 65_535];
    loop {
        tokio::select! {
            read = socket.recv(&mut buffer) => {
                match read {
                    Ok(length) if length > 0 => {
                        packet_id = packet_id.wrapping_add(1);
                        let _ = commands.send(ServerCommand::UdpOutput {
                            session_id,
                            association_id,
                            packet_id,
                            payload: buffer[..length].to_vec(),
                        });
                    }
                    _ => break,
                }
            }
            payload = incoming.recv() => {
                match payload {
                    Some(payload) if socket.send(&payload).await.is_ok() => {}
                    _ => break,
                }
            }
        }
    }
    let _ = commands.send(ServerCommand::UdpClosed {
        session_id,
        association_id,
    });
    let _ = commands.send(ServerCommand::StreamFinished { stream_id });
}

fn header_text<'a>(headers: &'a [Header], name: &'a str) -> Option<&'a str> {
    headers.find_header(name)?.value_utf8().ok()
}

fn neqo_error(error: impl fmt::Display) -> io::Error {
    io::Error::other(format!("Neqo：{error}"))
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
