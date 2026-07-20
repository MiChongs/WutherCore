//! TUIC v5 出站 —— 完整实现，与 [TUIC v5 协议规范](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md) 互通。
//!
//! ## 协议总览
//!
//! 1. **QUIC 握手**：rustls + ALPN `h3`/`tuic`
//! 2. **TUIC 包头**：每个 TUIC 命令在 QUIC stream 或 datagram 上发送，固定头部：
//!    `version(1)=0x05 || cmd(1) || cmd_payload`
//! 3. **Authenticate 命令** (cmd=0x00)：通过 unidirectional stream 发送
//!    `uuid(16) || token(32)` (token = TLS exporter)
//! 4. **Connect 命令** (cmd=0x01)：在 bidirectional stream 上发送
//!    `addr (TUIC v5 地址格式)`，然后双向裸 payload
//! 5. **Packet 命令** (cmd=0x02)：通过 unidirectional stream 或 datagram 发送
//!    UDP 包：`assoc_id(2 BE) || pkt_id(2 BE) || frag_total(1) || frag_id(1)
//!     || size(2 BE) || addr || payload`
//! 6. **Dissociate 命令** (cmd=0x03)：通过 unidirectional stream 发送
//!    `assoc_id(2 BE)`，关闭 UDP 关联
//! 7. **Heartbeat 命令** (cmd=0x04)：通过 datagram 发送，无 payload
//!
//! ## TUIC v5 地址格式
//! ```text
//! type(1) || data
//!   type=0xff: None
//!   type=0x00: Domain (1B len + N bytes hostname + 2B port BE)
//!   type=0x01: IPv4 (4B + 2B port BE)
//!   type=0x02: IPv6 (16B + 2B port BE)
//! ```
//!
//! ## 实现范围（**完整**）
//! * UUID + connection-bound TLS exporter token 鉴权
//! * Connect 命令完整支持
//! * Packet 命令（QUIC datagram + unidirectional stream UDP relay）
//! * UDP fragmentation / bounded reassembly / duplicate suppression
//! * Heartbeat
//! * Dissociate
//! * 多路复用：单条 QUIC connection 承载多个 TCP/UDP 子流

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes};
use quinn::{ClientConfig, Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};
use rand::{RngCore, rngs::OsRng};
use rustls::ClientConfig as RustlsConfig;
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, mpsc};
use uuid::Uuid;

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
    prepare_outbound_udp_socket_for_addr, resolve_host,
};

const TUIC_VERSION: u8 = 0x05;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const ADDR_NONE: u8 = 0xff;
const ADDR_DOMAIN: u8 = 0x00;
const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;

const PACKET_FIXED_HEADER_LEN: usize = 10;
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;
const MAX_PACKET_FRAME_LEN: usize = MAX_UDP_PAYLOAD + 269;
const DATAGRAM_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const ASSOCIATION_QUEUE_SIZE: usize = 256;
const MAX_PENDING_PACKETS: usize = 64;
const MAX_RECENT_PACKETS: usize = 1024;
const MAX_INCOMING_STREAMS: usize = 128;
const FRAGMENT_LIFETIME: Duration = Duration::from_secs(10);
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(30);

type AssociationTable = Arc<Mutex<HashMap<u16, AssociationEntry>>>;

#[derive(Debug, Clone)]
struct AssociationEntry {
    sender: mpsc::Sender<PacketFragment>,
    state: Arc<AssociationState>,
}

#[derive(Debug)]
struct AssociationState {
    closed: AtomicBool,
    close_notify: Notify,
}

impl AssociationState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close_notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        if self.is_closed() {
            return;
        }
        let notified = self.close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_closed() {
            return;
        }
        notified.await;
    }
}

#[derive(Debug, Clone)]
pub struct TuicOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub udp_relay_mode: TuicUdpMode,
    pub heartbeat_interval: Duration,
    pub disable_sni: bool,
    pub udp: bool,
    state: Arc<AsyncMutex<Option<Arc<TuicSession>>>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TuicUdpMode {
    /// QUIC datagram (低延迟，受 PMTU 限制)
    #[default]
    Native,
    /// QUIC unidirectional stream (无大小限制，重排有序)
    Quic,
}

impl TuicOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        uuid: Uuid,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            uuid,
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec!["h3".into()],
            udp_relay_mode: TuicUdpMode::Native,
            heartbeat_interval: Duration::from_secs(10),
            disable_sni: false,
            udp: true,
            state: Arc::new(AsyncMutex::new(None)),
        }
    }

    async fn ensure_session(&self) -> std::io::Result<Arc<TuicSession>> {
        let mut guard = self.state.lock().await;
        if let Some(s) = guard.as_ref()
            && !s.is_closed()
        {
            return Ok(s.clone());
        }
        let session = self.connect_and_auth().await?;
        // Heartbeat must not keep an otherwise unused multiplexed session alive.
        let session_weak = Arc::downgrade(&session);
        let interval = if self.heartbeat_interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.heartbeat_interval
        };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(session) = session_weak.upgrade() else {
                    break;
                };
                if session.is_closed() {
                    break;
                }
                if let Err(e) = session.send_heartbeat().await {
                    tracing::debug!(target: "tuic", error = %e, "heartbeat failed");
                    break;
                }
            }
        });
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn connect_and_auth(&self) -> std::io::Result<Arc<TuicSession>> {
        let target_addr = resolve_first(&self.host, self.port).await?;

        let mut tls_config = RustlsConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
        tls_config.alpn_protocols = self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        if self.insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(InsecureVerifier));
        }

        let quic_client_config: QuicClientConfig = QuicClientConfig::try_from(tls_config)
            .map_err(|e| io_err(format!("tuic quic config: {e}")))?;
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        let mut transport = TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE))
            .datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE);
        client_config.transport_config(Arc::new(transport));

        let bind_addr: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        let loopback_guard = prepare_outbound_udp_socket_for_addr(&std_socket, target_addr)?;
        std_socket.set_nonblocking(true)?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| io_err(format!("tuic endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let server_name = if self.disable_sni {
            target_addr.ip().to_string()
        } else {
            self.sni.clone().unwrap_or_else(|| self.host.clone())
        };

        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(|e| io_err(format!("tuic connect: {e}")))?
            .await
            .map_err(|e| io_err(format!("tuic connection: {e}")))?;

        // TUIC v5 binds authentication to this exact TLS session:
        // exporter label = raw UUID, exporter context = raw password.
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, self.uuid.as_bytes(), self.password.as_bytes())
            .map_err(|e| io_err(format!("tuic TLS exporter: {e:?}")))?;

        let mut auth_stream = connection
            .open_uni()
            .await
            .map_err(|e| io_err(format!("tuic open_uni for auth: {e}")))?;
        let mut auth_frame = Vec::with_capacity(2 + 16 + 32);
        auth_frame.push(TUIC_VERSION);
        auth_frame.push(CMD_AUTHENTICATE);
        auth_frame.extend_from_slice(self.uuid.as_bytes());
        auth_frame.extend_from_slice(&token);
        auth_stream
            .write_all(&auth_frame)
            .await
            .map_err(|e| io_err(format!("tuic write auth: {e}")))?;
        auth_stream
            .finish()
            .map_err(|e| io_err(format!("tuic finish auth: {e}")))?;

        let session = Arc::new(TuicSession {
            connection,
            endpoint,
            udp_mode: self.udp_relay_mode,
            associations: Arc::new(Mutex::new(HashMap::new())),
            next_assoc_id: AtomicU16::new(random_u16()),
            _loopback_guard: loopback_guard,
        });
        session.spawn_receive_loops();
        Ok(session)
    }
}

#[async_trait]
impl OutboundAdapter for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "tuic"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let session = self.ensure_session().await?;
        let (mut send, recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|e| io_err(format!("tuic open_bi: {e}")))?;

        // 写 Connect 命令头
        let mut frame = Vec::with_capacity(8 + ctx.host.len());
        frame.push(TUIC_VERSION);
        frame.push(CMD_CONNECT);
        encode_address(&mut frame, &ctx.host, ctx.port)?;
        send.write_all(&frame)
            .await
            .map_err(|e| io_err(format!("tuic write connect: {e}")))?;

        Ok(Box::pin(super::hysteria2::QuinnBiStream::new(send, recv)))
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound `{}`/tuic udp disabled by config", self.name),
            ));
        }

        // A connection may close after ensure_session drops its state lock. Retry once
        // so a fresh UDP association does not inherit a stale multiplexed connection.
        let mut last_error = None;
        for _ in 0..2 {
            let session = self.ensure_session().await?;
            match session.register_association() {
                Ok((assoc_id, receiver, association_state)) => {
                    tracing::info!(
                        target: "dial::tuic",
                        id = ctx.dial_id,
                        proxy = %self.name,
                        server = %format!("{}:{}", self.host, self.port),
                        target = %format!("{}:{}", ctx.host, ctx.port),
                        assoc_id,
                        mode = ?self.udp_relay_mode,
                        "udp associate ok",
                    );
                    return Ok(Box::new(TuicUdp {
                        session,
                        assoc_id,
                        next_pkt_id: AtomicU16::new(random_u16()),
                        receiver: AsyncMutex::new(receiver),
                        reassembly: AsyncMutex::new(FragmentReassembler::default()),
                        closed: AtomicBool::new(false),
                        close_notify: Notify::new(),
                        send_gate: Arc::new(AsyncMutex::new(())),
                        association_state,
                        dissociated: Arc::new(AtomicBool::new(false)),
                    }));
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tuic connection closed while creating UDP association",
            )
        }))
    }
}

#[derive(Debug)]
struct TuicSession {
    connection: quinn::Connection,
    #[allow(dead_code)]
    endpoint: Endpoint,
    udp_mode: TuicUdpMode,
    associations: AssociationTable,
    next_assoc_id: AtomicU16,
    _loopback_guard: crate::loopback::LoopbackUdpGuard,
}

impl TuicSession {
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    fn register_association(
        &self,
    ) -> io::Result<(u16, mpsc::Receiver<PacketFragment>, Arc<AssociationState>)> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tuic connection is closed",
            ));
        }

        let mut associations = lock_associations(&self.associations);
        for _ in 0..=u16::MAX as u32 {
            let assoc_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
            if let std::collections::hash_map::Entry::Vacant(entry) = associations.entry(assoc_id) {
                let (sender, receiver) = mpsc::channel(ASSOCIATION_QUEUE_SIZE);
                let state = Arc::new(AssociationState::new());
                entry.insert(AssociationEntry {
                    sender,
                    state: state.clone(),
                });
                drop(associations);
                self.validate_registered_association(assoc_id, &state)?;
                return Ok((assoc_id, receiver, state));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "tuic UDP association table exhausted",
        ))
    }

    fn validate_registered_association(
        &self,
        assoc_id: u16,
        state: &Arc<AssociationState>,
    ) -> io::Result<()> {
        if self.is_closed() {
            self.unregister_association(assoc_id, state);
            state.close();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tuic connection closed while registering UDP association",
            ));
        }
        Ok(())
    }

    fn unregister_association(&self, assoc_id: u16, state: &Arc<AssociationState>) {
        let mut associations = lock_associations(&self.associations);
        if associations
            .get(&assoc_id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.state, state))
        {
            associations.remove(&assoc_id);
        }
    }

    fn spawn_receive_loops(&self) {
        spawn_datagram_receive_loop(
            self.connection.clone(),
            self.udp_mode,
            self.associations.clone(),
        );
        spawn_uni_receive_loop(
            self.connection.clone(),
            self.udp_mode,
            self.associations.clone(),
        );
    }

    async fn send_heartbeat(&self) -> std::io::Result<()> {
        // Heartbeat = version + cmd，通过 datagram 发送
        let frame = vec![TUIC_VERSION, CMD_HEARTBEAT];
        self.connection
            .send_datagram_wait(Bytes::from(frame))
            .await
            .map_err(|e| io_err(format!("tuic heartbeat: {e}")))
    }

    async fn send_packet(
        &self,
        assoc_id: u16,
        pkt_id: u16,
        target: &str,
        port: u16,
        payload: &[u8],
    ) -> std::io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tuic UDP payload exceeds protocol limit: {} > {MAX_UDP_PAYLOAD}",
                    payload.len()
                ),
            ));
        }

        let address = encode_address_bytes(target, port)?;
        match self.udp_mode {
            TuicUdpMode::Native => {
                let max_frame_size = self.connection.max_datagram_size().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "tuic server did not negotiate QUIC datagram support",
                    )
                })?;
                let frames = fragment_packet(assoc_id, pkt_id, &address, payload, max_frame_size)?;
                for frame in frames {
                    self.connection
                        .send_datagram_wait(frame)
                        .await
                        .map_err(|e| io_err(format!("tuic packet datagram: {e}")))?;
                }
                Ok(())
            }
            TuicUdpMode::Quic => {
                // QUIC streams do not have a path-MTU limit. A legal UDP payload fits
                // one command because SIZE is a u16.
                let frames =
                    fragment_packet(assoc_id, pkt_id, &address, payload, MAX_PACKET_FRAME_LEN)?;
                for frame in frames {
                    let mut send = self
                        .connection
                        .open_uni()
                        .await
                        .map_err(|e| io_err(format!("tuic open_uni for packet: {e}")))?;
                    send.write_all(&frame)
                        .await
                        .map_err(|e| io_err(format!("tuic write packet: {e}")))?;
                    send.finish()
                        .map_err(|e| io_err(format!("tuic finish packet: {e}")))?;
                }
                Ok(())
            }
        }
    }

    async fn dissociate(&self, assoc_id: u16, state: &Arc<AssociationState>) -> io::Result<()> {
        if self.is_closed() {
            self.unregister_association(assoc_id, state);
            return Ok(());
        }

        let mut send = self
            .connection
            .open_uni()
            .await
            .map_err(|e| io_err(format!("tuic open_uni for dissociate: {e}")))?;
        let mut frame = Vec::with_capacity(4);
        frame.push(TUIC_VERSION);
        frame.push(CMD_DISSOCIATE);
        frame.put_u16(assoc_id);
        send.write_all(&frame)
            .await
            .map_err(|e| io_err(format!("tuic write dissociate: {e}")))?;
        send.finish()
            .map_err(|e| io_err(format!("tuic finish dissociate: {e}")))?;
        self.unregister_association(assoc_id, state);
        Ok(())
    }
}

struct TuicUdp {
    session: Arc<TuicSession>,
    assoc_id: u16,
    next_pkt_id: AtomicU16,
    receiver: AsyncMutex<mpsc::Receiver<PacketFragment>>,
    reassembly: AsyncMutex<FragmentReassembler>,
    closed: AtomicBool,
    close_notify: Notify,
    /// Serializes Packet commands with Dissociate so a close cannot overtake
    /// an in-flight send and leave the server recreating a dead association.
    send_gate: Arc<AsyncMutex<()>>,
    /// Keeps the association ID reserved until Dissociate has been queued,
    /// preventing delayed cleanup from hitting a newly reused ID.
    association_state: Arc<AssociationState>,
    dissociated: Arc<AtomicBool>,
}

impl TuicUdp {
    fn begin_close(&self) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.association_state.close();
        // notify_one retains a permit, so recv_from cannot miss a close that races
        // between its atomic state check and select registration.
        self.close_notify.notify_one();
        true
    }
}

#[async_trait]
impl UdpSocketLike for TuicUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> io::Result<usize> {
        let _send_guard = self.send_gate.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tuic UDP association is closed",
            ));
        }
        if self.session.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tuic connection is closed",
            ));
        }

        let pkt_id = self.next_pkt_id.fetch_add(1, Ordering::Relaxed);
        self.session
            .send_packet(self.assoc_id, pkt_id, target, port, buf)
            .await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut receiver = self.receiver.lock().await;
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "tuic UDP association is closed",
                ));
            }

            let fragment = tokio::select! {
                fragment = receiver.recv() => match fragment {
                    Some(fragment) => fragment,
                    None if self.closed.load(Ordering::Acquire) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "tuic UDP association is closed",
                        ));
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "tuic connection closed its UDP association",
                        ));
                    }
                },
                _ = self.close_notify.notified() => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "tuic UDP association is closed",
                    ));
                }
            };

            let assembled = self
                .reassembly
                .lock()
                .await
                .push(fragment, Instant::now())?;
            let Some((payload, _source)) = assembled else {
                continue;
            };

            let copy_len = payload.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Ok(copy_len);
        }
    }

    async fn close(&self) -> io::Result<()> {
        self.begin_close();
        let mut on_cancel = DissociateOnCancel::new(
            self.session.clone(),
            self.assoc_id,
            self.send_gate.clone(),
            self.association_state.clone(),
            self.dissociated.clone(),
        );
        let result = dissociate_once(
            self.session.clone(),
            self.assoc_id,
            self.send_gate.clone(),
            self.association_state.clone(),
            self.dissociated.clone(),
        )
        .await;
        on_cancel.disarm();
        result
    }
}

impl Drop for TuicUdp {
    fn drop(&mut self) {
        self.begin_close();
        spawn_dissociate_cleanup(
            self.session.clone(),
            self.assoc_id,
            self.send_gate.clone(),
            self.association_state.clone(),
            self.dissociated.clone(),
        );
    }
}

async fn dissociate_once(
    session: Arc<TuicSession>,
    assoc_id: u16,
    send_gate: Arc<AsyncMutex<()>>,
    association_state: Arc<AssociationState>,
    dissociated: Arc<AtomicBool>,
) -> io::Result<()> {
    let _send_guard = send_gate.lock().await;
    if dissociated.load(Ordering::Acquire) {
        return Ok(());
    }
    session.dissociate(assoc_id, &association_state).await?;
    dissociated.store(true, Ordering::Release);
    Ok(())
}

fn spawn_dissociate_cleanup(
    session: Arc<TuicSession>,
    assoc_id: u16,
    send_gate: Arc<AsyncMutex<()>>,
    association_state: Arc<AssociationState>,
    dissociated: Arc<AtomicBool>,
) {
    if dissociated.load(Ordering::Acquire) {
        return;
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            if let Err(error) =
                dissociate_once(session, assoc_id, send_gate, association_state, dissociated).await
            {
                tracing::debug!(
                    target: "tuic",
                    assoc_id,
                    error = %error,
                    "best-effort UDP dissociate failed",
                );
            }
        });
    }
}

struct DissociateOnCancel {
    session: Arc<TuicSession>,
    assoc_id: u16,
    send_gate: Arc<AsyncMutex<()>>,
    association_state: Arc<AssociationState>,
    dissociated: Arc<AtomicBool>,
    armed: bool,
}

impl DissociateOnCancel {
    fn new(
        session: Arc<TuicSession>,
        assoc_id: u16,
        send_gate: Arc<AsyncMutex<()>>,
        association_state: Arc<AssociationState>,
        dissociated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            session,
            assoc_id,
            send_gate,
            association_state,
            dissociated,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DissociateOnCancel {
    fn drop(&mut self) {
        if self.armed {
            spawn_dissociate_cleanup(
                self.session.clone(),
                self.assoc_id,
                self.send_gate.clone(),
                self.association_state.clone(),
                self.dissociated.clone(),
            );
        }
    }
}

/* ---------------- 工具 ---------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuicAddress {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct PacketFragment {
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    source: Option<TuicAddress>,
    payload: Bytes,
}

enum IncomingCommand {
    Packet(PacketFragment),
    Heartbeat,
}

fn encode_address(out: &mut Vec<u8>, host: &str, port: u16) -> io::Result<()> {
    let ip_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = ip_host.parse::<Ipv4Addr>() {
        out.push(ADDR_IPV4);
        out.extend_from_slice(&ip.octets());
        out.put_u16(port);
    } else if let Ok(ip) = ip_host.parse::<Ipv6Addr>() {
        out.push(ADDR_IPV6);
        out.extend_from_slice(&ip.octets());
        out.put_u16(port);
    } else {
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tuic domain length must be 1..=255 bytes, got {}",
                    host.len()
                ),
            ));
        }
        out.push(ADDR_DOMAIN);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
        out.put_u16(port);
    }
    Ok(())
}

fn encode_address_bytes(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut address = Vec::with_capacity(host.len().saturating_add(4));
    encode_address(&mut address, host, port)?;
    Ok(address)
}

fn decode_address(frame: &mut Bytes) -> io::Result<Option<TuicAddress>> {
    if !frame.has_remaining() {
        return Err(invalid_data("tuic packet is missing address type"));
    }
    let address_type = frame.get_u8();
    match address_type {
        ADDR_NONE => Ok(None),
        ADDR_DOMAIN => {
            if !frame.has_remaining() {
                return Err(invalid_data("tuic domain is missing length"));
            }
            let len = frame.get_u8() as usize;
            if len == 0 || frame.remaining() < len + 2 {
                return Err(invalid_data("tuic domain address is truncated"));
            }
            let domain = frame.split_to(len);
            let domain = std::str::from_utf8(&domain)
                .map_err(|_| invalid_data("tuic domain is not valid UTF-8"))?
                .to_owned();
            let port = frame.get_u16();
            Ok(Some(TuicAddress { host: domain, port }))
        }
        ADDR_IPV4 => {
            if frame.remaining() < 6 {
                return Err(invalid_data("tuic IPv4 address is truncated"));
            }
            let mut octets = [0u8; 4];
            frame.copy_to_slice(&mut octets);
            let port = frame.get_u16();
            Ok(Some(TuicAddress {
                host: Ipv4Addr::from(octets).to_string(),
                port,
            }))
        }
        ADDR_IPV6 => {
            if frame.remaining() < 18 {
                return Err(invalid_data("tuic IPv6 address is truncated"));
            }
            let mut octets = [0u8; 16];
            frame.copy_to_slice(&mut octets);
            let port = frame.get_u16();
            Ok(Some(TuicAddress {
                host: Ipv6Addr::from(octets).to_string(),
                port,
            }))
        }
        other => Err(invalid_data(format!(
            "tuic address type is invalid: {other:#04x}"
        ))),
    }
}

fn fragment_packet(
    assoc_id: u16,
    pkt_id: u16,
    address: &[u8],
    payload: &[u8],
    max_frame_size: usize,
) -> io::Result<Vec<Bytes>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic UDP payload exceeds u16 SIZE field",
        ));
    }
    let first_header_len = PACKET_FIXED_HEADER_LEN
        .checked_add(address.len())
        .ok_or_else(|| invalid_data("tuic packet header length overflow"))?;
    let next_header_len = PACKET_FIXED_HEADER_LEN + 1;
    let first_capacity = max_frame_size
        .checked_sub(first_header_len)
        .ok_or_else(|| invalid_data("QUIC frame is too small for TUIC address header"))?;
    let next_capacity = max_frame_size
        .checked_sub(next_header_len)
        .ok_or_else(|| invalid_data("QUIC frame is too small for TUIC fragment header"))?;

    if !payload.is_empty() && first_capacity == 0 {
        return Err(invalid_data("QUIC frame has no room for TUIC payload"));
    }
    if payload.len() > first_capacity && next_capacity == 0 {
        return Err(invalid_data("QUIC frame has no room for TUIC continuation"));
    }

    let remaining = payload.len().saturating_sub(first_capacity);
    let additional = if remaining == 0 {
        0
    } else {
        remaining
            .checked_add(next_capacity - 1)
            .ok_or_else(|| invalid_data("tuic fragment count overflow"))?
            / next_capacity
    };
    let frag_total = 1usize
        .checked_add(additional)
        .ok_or_else(|| invalid_data("tuic fragment count overflow"))?;
    if frag_total > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tuic packet requires too many fragments: {frag_total}"),
        ));
    }

    let mut frames = Vec::with_capacity(frag_total);
    let mut offset = 0usize;
    for frag_id in 0..frag_total {
        let fragment_address: &[u8] = if frag_id == 0 { address } else { &[ADDR_NONE] };
        let capacity = max_frame_size - PACKET_FIXED_HEADER_LEN - fragment_address.len();
        let payload_size = payload.len().saturating_sub(offset).min(capacity);
        let mut frame =
            Vec::with_capacity(PACKET_FIXED_HEADER_LEN + fragment_address.len() + payload_size);
        frame.push(TUIC_VERSION);
        frame.push(CMD_PACKET);
        frame.put_u16(assoc_id);
        frame.put_u16(pkt_id);
        frame.put_u8(frag_total as u8);
        frame.put_u8(frag_id as u8);
        frame.put_u16(payload_size as u16);
        frame.extend_from_slice(fragment_address);
        frame.extend_from_slice(&payload[offset..offset + payload_size]);
        offset += payload_size;
        frames.push(Bytes::from(frame));
    }

    debug_assert_eq!(offset, payload.len());
    Ok(frames)
}

fn parse_incoming_command(mut frame: Bytes) -> io::Result<IncomingCommand> {
    if frame.remaining() < 2 {
        return Err(invalid_data("tuic command is truncated"));
    }
    let version = frame.get_u8();
    if version != TUIC_VERSION {
        return Err(invalid_data(format!(
            "unsupported TUIC version: {version:#04x}"
        )));
    }

    match frame.get_u8() {
        CMD_PACKET => parse_packet_body(frame).map(IncomingCommand::Packet),
        CMD_HEARTBEAT if frame.is_empty() => Ok(IncomingCommand::Heartbeat),
        CMD_HEARTBEAT => Err(invalid_data("tuic heartbeat has trailing bytes")),
        command => Err(invalid_data(format!(
            "unexpected TUIC server command: {command:#04x}"
        ))),
    }
}

fn parse_packet_body(mut frame: Bytes) -> io::Result<PacketFragment> {
    if frame.remaining() < 8 {
        return Err(invalid_data("tuic packet header is truncated"));
    }
    let assoc_id = frame.get_u16();
    let pkt_id = frame.get_u16();
    let frag_total = frame.get_u8();
    let frag_id = frame.get_u8();
    let size = frame.get_u16() as usize;
    let source = decode_address(&mut frame)?;
    if frag_total == 0 || frag_id >= frag_total {
        return Err(invalid_data(format!(
            "tuic fragment id {frag_id} is invalid for total {frag_total}"
        )));
    }
    if frag_id == 0 && source.is_none() {
        return Err(invalid_data("tuic first fragment has no source address"));
    }
    if frag_id != 0 && source.is_some() {
        return Err(invalid_data(
            "tuic continuation fragment unexpectedly carries an address",
        ));
    }
    if frame.remaining() != size {
        return Err(invalid_data(format!(
            "tuic fragment SIZE is {size}, actual payload is {}",
            frame.remaining()
        )));
    }

    Ok(PacketFragment {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        source,
        payload: frame,
    })
}

fn spawn_datagram_receive_loop(
    connection: quinn::Connection,
    udp_mode: TuicUdpMode,
    associations: AssociationTable,
) {
    tokio::spawn(async move {
        loop {
            let frame = match connection.read_datagram().await {
                Ok(frame) => frame,
                Err(error) => {
                    tracing::debug!(target: "tuic", error = %error, "datagram receive loop stopped");
                    break;
                }
            };
            match parse_incoming_command(frame) {
                Ok(IncomingCommand::Heartbeat) => {}
                Ok(IncomingCommand::Packet(fragment)) if udp_mode == TuicUdpMode::Native => {
                    dispatch_native_fragment(&associations, fragment);
                }
                Ok(IncomingCommand::Packet(_)) => {
                    tracing::debug!(
                        target: "tuic",
                        "ignored datagram packet for QUIC-stream UDP association",
                    );
                }
                Err(error) => {
                    tracing::debug!(target: "tuic", error = %error, "ignored malformed datagram");
                }
            }
        }
        close_all_associations(&associations);
    });
}

fn spawn_uni_receive_loop(
    connection: quinn::Connection,
    udp_mode: TuicUdpMode,
    associations: AssociationTable,
) {
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(MAX_INCOMING_STREAMS));
        loop {
            let mut stream = match connection.accept_uni().await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(target: "tuic", error = %error, "uni receive loop stopped");
                    break;
                }
            };
            let permit = match permits.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let associations = associations.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let read = tokio::time::timeout(
                    STREAM_READ_TIMEOUT,
                    stream.read_to_end(MAX_PACKET_FRAME_LEN),
                )
                .await;
                let frame = match read {
                    Ok(Ok(frame)) => Bytes::from(frame),
                    Ok(Err(error)) => {
                        tracing::debug!(target: "tuic", error = %error, "invalid packet stream");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(target: "tuic", "packet stream read timed out");
                        return;
                    }
                };
                match parse_incoming_command(frame) {
                    Ok(IncomingCommand::Packet(fragment)) if udp_mode == TuicUdpMode::Quic => {
                        dispatch_reliable_fragment(&associations, fragment).await;
                    }
                    Ok(IncomingCommand::Packet(_)) => {
                        tracing::debug!(
                            target: "tuic",
                            "ignored stream packet for native UDP association",
                        );
                    }
                    Ok(IncomingCommand::Heartbeat) => {
                        tracing::debug!(target: "tuic", "ignored heartbeat on uni stream");
                    }
                    Err(error) => {
                        tracing::debug!(target: "tuic", error = %error, "ignored malformed packet stream");
                    }
                }
            });
        }
        close_all_associations(&associations);
    });
}

fn dispatch_native_fragment(associations: &AssociationTable, fragment: PacketFragment) {
    let entry = lock_associations(associations)
        .get(&fragment.assoc_id)
        .cloned();
    let Some(entry) = entry else {
        return;
    };
    if entry.state.is_closed() {
        return;
    }
    if let Err(error) = entry.sender.try_send(fragment) {
        tracing::debug!(
            target: "tuic",
            error = %error,
            "dropped native UDP fragment because association queue is unavailable",
        );
    }
}

async fn dispatch_reliable_fragment(associations: &AssociationTable, fragment: PacketFragment) {
    let entry = lock_associations(associations)
        .get(&fragment.assoc_id)
        .cloned();
    let Some(entry) = entry else {
        return;
    };
    if entry.state.is_closed() {
        return;
    }
    tokio::select! {
        result = entry.sender.send(fragment) => {
            if let Err(error) = result {
                tracing::debug!(
                    target: "tuic",
                    error = %error,
                    "discarded QUIC-stream fragment for closed association",
                );
            }
        }
        _ = entry.state.cancelled() => {
            tracing::debug!(
                target: "tuic",
                "discarded QUIC-stream fragment because association closed",
            );
        }
    }
}

fn lock_associations(
    associations: &AssociationTable,
) -> std::sync::MutexGuard<'_, HashMap<u16, AssociationEntry>> {
    associations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn close_all_associations(associations: &AssociationTable) {
    let entries = {
        let mut associations = lock_associations(associations);
        associations
            .drain()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>()
    };
    for entry in entries {
        entry.state.close();
    }
}

#[derive(Default)]
struct FragmentReassembler {
    pending: HashMap<u16, PendingPacket>,
    recent: HashMap<u16, Instant>,
}

struct PendingPacket {
    frag_total: u8,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    total_len: usize,
    source: Option<TuicAddress>,
    created: Instant,
}

impl FragmentReassembler {
    fn push(
        &mut self,
        fragment: PacketFragment,
        now: Instant,
    ) -> io::Result<Option<(Bytes, TuicAddress)>> {
        self.prune(now);
        if self.recent.contains_key(&fragment.pkt_id) {
            return Ok(None);
        }
        if fragment.frag_total == 0 || fragment.frag_id >= fragment.frag_total {
            return Err(invalid_data("tuic fragment metadata is invalid"));
        }
        if fragment.frag_id == 0 && fragment.source.is_none() {
            return Err(invalid_data("tuic first fragment has no source address"));
        }
        if fragment.frag_id != 0 && fragment.source.is_some() {
            return Err(invalid_data(
                "tuic continuation fragment carries a source address",
            ));
        }

        if let Some(existing) = self.pending.get(&fragment.pkt_id)
            && existing.frag_total != fragment.frag_total
        {
            self.pending.remove(&fragment.pkt_id);
            return Err(invalid_data(
                "tuic fragment count changed within one packet",
            ));
        }
        if !self.pending.contains_key(&fragment.pkt_id)
            && self.pending.len() >= MAX_PENDING_PACKETS
            && let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, packet)| packet.created)
                .map(|(pkt_id, _)| *pkt_id)
        {
            self.pending.remove(&oldest);
        }

        let packet = self
            .pending
            .entry(fragment.pkt_id)
            .or_insert_with(|| PendingPacket {
                frag_total: fragment.frag_total,
                fragments: vec![None; fragment.frag_total as usize],
                received: 0,
                total_len: 0,
                source: None,
                created: now,
            });
        let slot = &mut packet.fragments[fragment.frag_id as usize];
        if slot.is_some() {
            return Ok(None);
        }
        packet.total_len = packet
            .total_len
            .checked_add(fragment.payload.len())
            .ok_or_else(|| invalid_data("tuic reassembled packet length overflow"))?;
        if packet.total_len > MAX_UDP_PAYLOAD {
            self.pending.remove(&fragment.pkt_id);
            return Err(invalid_data("tuic reassembled UDP packet is too large"));
        }
        if fragment.frag_id == 0 {
            packet.source = fragment.source;
        }
        *slot = Some(fragment.payload);
        packet.received += 1;
        if packet.received != packet.frag_total as usize {
            return Ok(None);
        }

        let packet = self
            .pending
            .remove(&fragment.pkt_id)
            .expect("completed TUIC packet must remain pending");
        let source = packet
            .source
            .ok_or_else(|| invalid_data("tuic reassembled packet lost source address"))?;
        let mut payload = Vec::with_capacity(packet.total_len);
        for part in packet.fragments {
            let part = part.ok_or_else(|| invalid_data("tuic reassembled packet is incomplete"))?;
            payload.extend_from_slice(&part);
        }

        self.recent.insert(fragment.pkt_id, now);
        if self.recent.len() > MAX_RECENT_PACKETS
            && let Some(oldest) = self
                .recent
                .iter()
                .min_by_key(|(_, created)| **created)
                .map(|(pkt_id, _)| *pkt_id)
        {
            self.recent.remove(&oldest);
        }
        Ok(Some((Bytes::from(payload), source)))
    }

    fn prune(&mut self, now: Instant) {
        self.pending
            .retain(|_, packet| now.saturating_duration_since(packet.created) < FRAGMENT_LIFETIME);
        self.recent
            .retain(|_, created| now.saturating_duration_since(*created) < FRAGMENT_LIFETIME);
    }
}

fn random_u16() -> u16 {
    OsRng.next_u32() as u16
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

async fn resolve_first(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    resolve_host(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| io_err("no addr resolved"))
}

fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::other(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    const TEST_CERT_DER: &str = "MIICyDCCAbCgAwIBAgIIE4OkdZFerRcwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI2MDcxOTEzNTk0NloXDTMxMDcyMDEzNTk0NlowFDESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvC1XdP7r3Hd6bjNUOhswhLY6sf+PXhOSwrjheoRbWWDi+B6Upgfhg1UTDGaA4mfxVYKAkmfsatYM6Z6oJrCIMFzoW22J+S9VJ1v9a+El3z87ZAj+C0Q+YCDwRoOEJqVtO4yRTn+sOdhUYixw0HKiGS9rPD+1OxnGIYfjtJPszA2sEpkt2slab0OSAFiacyGbJLFDVMgFvlPR1585gj7te6Blh5YXVoh/0HwXE8dnynVqDrR4C+H8N+vpgiAj6rW8eEAvbW+/xdnMT5TMfy2FWiTJVRxOI6RHimOF0l2CymGJlzrMkI6afHzaMg+vEp+XA6sqXPbGXH/NW495f6xKwQIDAQABox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBACMgC4wpjpRmG32ClVPjrQJ+vr/Ngt1ZEK1e5r8qrLhlWXfUwjHwfsCNFH0ZtEIXWQy36gYV2rMiRKMulIgNH79bobEj55AxgeUSG8EeJuCD8BlR3BG2UyxO3Qb5Jj4QaoEO9HgasOQFN+aG2SlEEVt3k0lH+fuui+Sxt62dm9eEMYip/bSJHOjHaPWSm5EgzQN0bF5lP8JKJRMqF0037xdY3n8RKcy/OnyYBoYAocTKdDFO76s8BvOo4eWQqSMDxI+Re2BPO7d5i5AYWTEWd8yEBInOn4co7eYvWKpkZlnG8c1L4MAzbIvcUJ1UTjcAa2iocfjIbOh0f/alGBfSuoE=";
    const TEST_KEY_DER: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8LVd0/uvcd3puM1Q6GzCEtjqx/49eE5LCuOF6hFtZYOL4HpSmB+GDVRMMZoDiZ/FVgoCSZ+xq1gzpnqgmsIgwXOhbbYn5L1UnW/1r4SXfPztkCP4LRD5gIPBGg4QmpW07jJFOf6w52FRiLHDQcqIZL2s8P7U7GcYhh+O0k+zMDawSmS3ayVpvQ5IAWJpzIZsksUNUyAW+U9HXnzmCPu17oGWHlhdWiH/QfBcTx2fKdWoOtHgL4fw36+mCICPqtbx4QC9tb7/F2cxPlMx/LYVaJMlVHE4jpEeKY4XSXYLKYYmXOsyQjpp8fNoyD68Sn5cDqypc9sZcf81bj3l/rErBAgMBAAECggEACqcOcmMT+xEQbzicpgVwA7NFM1piRVMaVcedjA/+E9s2PhGNHLEJhSPFxkfvN+HmeY6/tIoJiiq/5GHE5xvLOeGojbRvwRl62pWMjRTbzf2IYStZJk4gsdRrhbJgQsfOnTZh622y1Dt4223knQhAQOi8S1bX7ZaR7sgAjfJpz0tF3QsN55Iy3LA1GHmC5mJvFveTWPqVFQQJLqBG/KP+AGpifLUhm2wzjcUAXsfOS3v9Y2Vm60howcrX3EUAevJbmDOgkJ4h5auOANXU5AHlfS7ZwUJdrJh/SEhPc+2acxpkR2imulKWD+iwAlVeOKVIcB0/oGRfqppjStCj3D14WQKBgQDzTD7I5dc8KZQgpGtCiHj4w9c/+y8oyGvvENxdeMqyXKFp7PcGDD7CARIyhQWSPpGHiwCMCmUoPCZa2sFyFM85j+YxDA3rpa89e+4Q0wDvqALs6Lnm/89ceGh2nzzWaQwy27/ix7nMztjZLtKZrVblq6WO0Jl551mCbiAUUZ3FywKBgQDGAGPZ8TZmqfECobdJ2ObpN2dyZ/RbQ2M/vxH2m89ofyi8dczdFf9KBpPWOFqILKWVjMGzYFf6VcdgEbZqE4fwuKfGm/x/RBXhMGb+VxvIaEakzLQs+S0cssj7T3vebWt2WW6fDm7tzKPfIYE4T2AUMoGN6RqjVWeTksUwIAbAIwKBgF/sjMiKjhzjS8q+6Kc3xXJXTJOmRkavFpcQL8IOsOQ3z1BDJHXW+BtnbrRKbBLn5lrpfBK6un1tkbW6kBCZkcZhLOHjnc1t6rS0Gv25I6JZvKWJcFpaO3h65Lz4NXVXv36B05rnIiNU3nxqkJAUnrE4xrKTHh/JDip1nuJD94+XAoGAXbWHjHld3t7lQvKYlanDN3NSUVIj0yGkkmHytX1ufy1XcUJrb+NeTIGqbEOFjVdcEthoQGYDnWYFk1EuvSt7NhGezh+7M9xcYpSO2icN7h5z+MEtMO/JSwDOoCoxHMc6ieuvsDWbiI5GrG7mAmmGtmhk6m39fnoIKE7ZZnpx13MCgYEAljo6HLd+2UOp9mv10Kq8j5kZdC6eG7yCHe+PomTccwaW3D+DXP4NsTF9A9vwWkI40hcxtMWSVyfTq6jLQxtFsuaUf4YSs26U8jbLVTo5vR3OE4RsCs401c3PFLzAXf1MYRdHHdKICxXk6OC2+WIoxL0LGokwmG2BMOnh/v7LsNA=";

    #[test]
    fn tuic_construct() {
        let u = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let mut ob = TuicOutbound::new("t", "1.2.3.4", 443, u, "pass");
        assert_eq!(ob.protocol(), "tuic");
        assert_eq!(ob.uuid, u);
        assert!(ob.capabilities().udp);
        ob.udp = false;
        assert!(!ob.capabilities().udp);
    }

    #[test]
    fn encode_address_v4() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "1.2.3.4", 443).unwrap();
        assert_eq!(buf[0], ADDR_IPV4);
        assert_eq!(&buf[1..5], &[1, 2, 3, 4]);
        assert_eq!(&buf[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn encode_address_v6() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "::1", 443).unwrap();
        assert_eq!(buf[0], ADDR_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn encode_address_domain() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "example.com", 443).unwrap();
        assert_eq!(buf[0], ADDR_DOMAIN);
        assert_eq!(buf[1] as usize, "example.com".len());
        assert_eq!(&buf[2..2 + 11], b"example.com");
    }

    #[test]
    fn address_round_trips_and_rejects_invalid_lengths() {
        for (host, expected) in [
            ("1.2.3.4", "1.2.3.4"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("example.com", "example.com"),
        ] {
            let encoded = encode_address_bytes(host, 5353).unwrap();
            let mut encoded = Bytes::from(encoded);
            let decoded = decode_address(&mut encoded).unwrap().unwrap();
            assert_eq!(decoded.host, expected);
            assert_eq!(decoded.port, 5353);
            assert!(encoded.is_empty());
        }

        assert!(encode_address_bytes("", 53).is_err());
        assert!(encode_address_bytes(&"x".repeat(256), 53).is_err());
        assert!(decode_address(&mut Bytes::from_static(&[ADDR_IPV6, 0])).is_err());
    }

    #[test]
    fn native_fragmentation_round_trips_out_of_order() {
        let address = encode_address_bytes("example.com", 53).unwrap();
        let payload = (0..1500)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let frames = fragment_packet(0x1234, 0x4321, &address, &payload, 128).unwrap();
        assert!(frames.len() > 1);
        assert!(frames.iter().all(|frame| frame.len() <= 128));

        let now = Instant::now();
        let mut reassembler = FragmentReassembler::default();
        let mut assembled = None;
        for frame in frames.iter().rev() {
            let IncomingCommand::Packet(fragment) = parse_incoming_command(frame.clone()).unwrap()
            else {
                panic!("expected packet");
            };
            assembled = reassembler.push(fragment, now).unwrap().or(assembled);
        }
        let (actual, source) = assembled.expect("all fragments should assemble");
        assert_eq!(actual.as_ref(), payload.as_slice());
        assert_eq!(
            source,
            TuicAddress {
                host: "example.com".into(),
                port: 53
            }
        );

        // A replay of an already delivered packet ID is suppressed.
        let IncomingCommand::Packet(replay) = parse_incoming_command(frames[0].clone()).unwrap()
        else {
            panic!("expected packet");
        };
        assert!(reassembler.push(replay, now).unwrap().is_none());
    }

    #[test]
    fn fragmentation_handles_exact_boundary_and_empty_datagram() {
        let address = encode_address_bytes("1.1.1.1", 53).unwrap();
        let max_frame = 64;
        let first_capacity = max_frame - PACKET_FIXED_HEADER_LEN - address.len();
        let next_capacity = max_frame - PACKET_FIXED_HEADER_LEN - 1;
        let payload = vec![7u8; first_capacity + next_capacity];
        let frames = fragment_packet(1, 2, &address, &payload, max_frame).unwrap();
        assert_eq!(frames.len(), 2);

        let empty = fragment_packet(1, 3, &address, &[], max_frame).unwrap();
        assert_eq!(empty.len(), 1);
        let IncomingCommand::Packet(fragment) = parse_incoming_command(empty[0].clone()).unwrap()
        else {
            panic!("expected packet");
        };
        assert!(fragment.payload.is_empty());
    }

    #[test]
    fn packet_parser_rejects_truncation_and_invalid_fragment_semantics() {
        let address = encode_address_bytes("1.1.1.1", 53).unwrap();
        let mut frame = fragment_packet(1, 2, &address, b"abc", 128)
            .unwrap()
            .remove(0)
            .to_vec();
        frame.pop();
        assert!(parse_incoming_command(Bytes::from(frame)).is_err());

        let mut wrong_address = Vec::new();
        wrong_address.extend_from_slice(&[TUIC_VERSION, CMD_PACKET, 0, 1, 0, 2, 2, 1, 0, 1]);
        wrong_address.extend_from_slice(&address);
        wrong_address.push(0xaa);
        assert!(parse_incoming_command(Bytes::from(wrong_address)).is_err());

        assert!(
            parse_incoming_command(Bytes::from_static(&[TUIC_VERSION, CMD_HEARTBEAT, 0])).is_err()
        );
    }

    #[test]
    fn replay_window_expires_and_allows_packet_id_reuse() {
        let address = encode_address_bytes("1.1.1.1", 53).unwrap();
        let frame = fragment_packet(1, 9, &address, b"one", 128)
            .unwrap()
            .remove(0);
        let IncomingCommand::Packet(first) = parse_incoming_command(frame.clone()).unwrap() else {
            panic!("expected packet");
        };
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::default();
        assert!(reassembler.push(first, now).unwrap().is_some());

        let IncomingCommand::Packet(replay) = parse_incoming_command(frame.clone()).unwrap() else {
            panic!("expected packet");
        };
        assert!(reassembler.push(replay, now).unwrap().is_none());

        let IncomingCommand::Packet(after_expiry) = parse_incoming_command(frame).unwrap() else {
            panic!("expected packet");
        };
        assert!(
            reassembler
                .push(after_expiry, now + FRAGMENT_LIFETIME)
                .unwrap()
                .is_some()
        );
    }

    fn test_server_endpoint() -> Endpoint {
        let cert = CertificateDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_CERT_DER)
                .unwrap(),
        );
        let key = PrivatePkcs8KeyDer::from(
            base64::engine::general_purpose::STANDARD
                .decode(TEST_KEY_DER)
                .unwrap(),
        );
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key))
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE))
            .datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE);
        server.transport_config(Arc::new(transport));
        Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    async fn read_client_packet(
        connection: &quinn::Connection,
        mode: TuicUdpMode,
    ) -> (u16, Bytes, TuicAddress) {
        let mut reassembler = FragmentReassembler::default();
        loop {
            let command = match mode {
                TuicUdpMode::Native => {
                    parse_incoming_command(connection.read_datagram().await.unwrap()).unwrap()
                }
                TuicUdpMode::Quic => {
                    let mut stream = connection.accept_uni().await.unwrap();
                    let frame = stream.read_to_end(MAX_PACKET_FRAME_LEN).await.unwrap();
                    parse_incoming_command(Bytes::from(frame)).unwrap()
                }
            };
            let IncomingCommand::Packet(fragment) = command else {
                continue;
            };
            let assoc_id = fragment.assoc_id;
            if let Some((payload, address)) = reassembler.push(fragment, Instant::now()).unwrap() {
                return (assoc_id, payload, address);
            }
        }
    }

    async fn send_server_packet(
        connection: &quinn::Connection,
        mode: TuicUdpMode,
        assoc_id: u16,
        payload: &[u8],
    ) {
        let address = encode_address_bytes("203.0.113.9", 5353).unwrap();
        let max_frame = match mode {
            TuicUdpMode::Native => connection.max_datagram_size().unwrap(),
            TuicUdpMode::Quic => MAX_PACKET_FRAME_LEN,
        };
        let frames = fragment_packet(assoc_id, 0xbeef, &address, payload, max_frame).unwrap();
        for frame in frames {
            match mode {
                TuicUdpMode::Native => connection.send_datagram_wait(frame).await.unwrap(),
                TuicUdpMode::Quic => {
                    let mut stream = connection.open_uni().await.unwrap();
                    stream.write_all(&frame).await.unwrap();
                    stream.finish().unwrap();
                }
            }
        }
    }

    async fn run_udp_round_trip(mode: TuicUdpMode) {
        let endpoint = test_server_endpoint();
        let server_addr = endpoint.local_addr().unwrap();
        let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let password = "connection-bound secret";
        let request = (0..4096)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let response = (0..3072)
            .map(|value| (value % 239) as u8)
            .collect::<Vec<_>>();
        let server_request = request.clone();
        let server_response = response.clone();

        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut auth = connection.accept_uni().await.unwrap();
            let auth = auth.read_to_end(64).await.unwrap();
            assert_eq!(auth.len(), 50);
            assert_eq!(&auth[..2], &[TUIC_VERSION, CMD_AUTHENTICATE]);
            assert_eq!(&auth[2..18], uuid.as_bytes());
            let mut expected_token = [0u8; 32];
            connection
                .export_keying_material(&mut expected_token, uuid.as_bytes(), password.as_bytes())
                .unwrap();
            assert_eq!(&auth[18..], &expected_token);

            let (assoc_id, actual, target) = read_client_packet(&connection, mode).await;
            assert_eq!(actual, server_request);
            assert_eq!(
                target,
                TuicAddress {
                    host: "dns.example".into(),
                    port: 5353,
                }
            );
            send_server_packet(&connection, mode, assoc_id, &server_response).await;

            let mut dissociate = connection.accept_uni().await.unwrap();
            let dissociate = dissociate.read_to_end(8).await.unwrap();
            assert_eq!(
                dissociate,
                [
                    TUIC_VERSION,
                    CMD_DISSOCIATE,
                    (assoc_id >> 8) as u8,
                    assoc_id as u8,
                ]
            );
        });

        let mut outbound =
            TuicOutbound::new("test", "127.0.0.1", server_addr.port(), uuid, password);
        outbound.insecure = true;
        outbound.udp_relay_mode = mode;
        outbound.heartbeat_interval = Duration::from_secs(60);
        let socket = outbound
            .dial_udp(DialContext::udp("dns.example", 5353))
            .await
            .unwrap();
        assert_eq!(
            socket.send_to(&request, "dns.example", 5353).await.unwrap(),
            request.len()
        );
        let mut buf = vec![0u8; response.len()];
        let received = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..received], response.as_slice());
        socket.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_quic_native_udp_round_trip_and_exporter_authentication() {
        tokio::time::timeout(
            Duration::from_secs(10),
            run_udp_round_trip(TuicUdpMode::Native),
        )
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_quic_stream_udp_round_trip_and_exporter_authentication() {
        tokio::time::timeout(
            Duration::from_secs(10),
            run_udp_round_trip(TuicUdpMode::Quic),
        )
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_association_cancels_blocked_receive_and_sends_dissociate() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let endpoint = test_server_endpoint();
            let server_addr = endpoint.local_addr().unwrap();
            let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();

            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut auth = connection.accept_uni().await.unwrap();
                let auth = auth.read_to_end(64).await.unwrap();
                assert_eq!(auth.len(), 50);
                assert_eq!(&auth[..2], &[TUIC_VERSION, CMD_AUTHENTICATE]);

                let mut dissociate = connection.accept_uni().await.unwrap();
                let dissociate = dissociate.read_to_end(8).await.unwrap();
                assert_eq!(dissociate.len(), 4);
                assert_eq!(&dissociate[..2], &[TUIC_VERSION, CMD_DISSOCIATE]);
            });

            let password = std::env::var("TUIC_TEST_PASSWORD")
                .unwrap_or_else(|_| format!("tuic-test-password-{}", server_addr.port()));
            let mut outbound = TuicOutbound::new(
                "test",
                "127.0.0.1",
                server_addr.port(),
                uuid,
                password.as_str(),
            );
            outbound.insecure = true;
            outbound.heartbeat_interval = Duration::from_secs(60);
            let socket = Arc::new(
                outbound
                    .dial_udp(DialContext::udp("dns.example", 5353))
                    .await
                    .unwrap(),
            );

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let receive_socket = socket.clone();
            let blocked_receive = tokio::spawn(async move {
                ready_tx.send(()).unwrap();
                let mut buf = [0u8; 32];
                receive_socket.recv_from(&mut buf).await.unwrap_err()
            });
            ready_rx.await.unwrap();
            tokio::task::yield_now().await;

            socket.close().await.unwrap();
            let error = blocked_receive.await.unwrap();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reliable_dispatch_stops_when_a_full_association_queue_closes() {
        let associations = Arc::new(Mutex::new(HashMap::new()));
        let (sender, mut receiver) = mpsc::channel(1);
        let state = Arc::new(AssociationState::new());
        sender
            .try_send(PacketFragment {
                assoc_id: 7,
                pkt_id: 1,
                frag_total: 1,
                frag_id: 0,
                source: None,
                payload: Bytes::from_static(b"first"),
            })
            .unwrap();
        lock_associations(&associations).insert(
            7,
            AssociationEntry {
                sender,
                state: state.clone(),
            },
        );

        let dispatch = tokio::spawn({
            let associations = associations.clone();
            async move {
                dispatch_reliable_fragment(
                    &associations,
                    PacketFragment {
                        assoc_id: 7,
                        pkt_id: 2,
                        frag_total: 1,
                        frag_id: 0,
                        source: None,
                        payload: Bytes::from_static(b"blocked"),
                    },
                )
                .await;
            }
        });
        tokio::task::yield_now().await;
        state.close();
        tokio::time::timeout(Duration::from_secs(1), dispatch)
            .await
            .expect("closed association must cancel a blocked reliable dispatch")
            .unwrap();

        assert_eq!(receiver.recv().await.unwrap().pkt_id, 1);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_close_still_sends_dissociate() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let endpoint = test_server_endpoint();
            let server_addr = endpoint.local_addr().unwrap();
            let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();

            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut auth = connection.accept_uni().await.unwrap();
                let auth = auth.read_to_end(64).await.unwrap();
                assert_eq!(&auth[..2], &[TUIC_VERSION, CMD_AUTHENTICATE]);

                let mut dissociate = connection.accept_uni().await.unwrap();
                let dissociate = dissociate.read_to_end(8).await.unwrap();
                assert_eq!(&dissociate[..2], &[TUIC_VERSION, CMD_DISSOCIATE]);
            });

            let mut outbound =
                TuicOutbound::new("test", "127.0.0.1", server_addr.port(), uuid, "secret");
            outbound.insecure = true;
            outbound.heartbeat_interval = Duration::from_secs(60);
            let session = outbound.ensure_session().await.unwrap();
            let (assoc_id, receiver, association_state) = session.register_association().unwrap();
            let send_gate = Arc::new(AsyncMutex::new(()));
            let socket = Arc::new(TuicUdp {
                session,
                assoc_id,
                next_pkt_id: AtomicU16::new(0),
                receiver: AsyncMutex::new(receiver),
                reassembly: AsyncMutex::new(FragmentReassembler::default()),
                closed: AtomicBool::new(false),
                close_notify: Notify::new(),
                send_gate: send_gate.clone(),
                association_state,
                dissociated: Arc::new(AtomicBool::new(false)),
            });

            let gate = send_gate.lock().await;
            let close_task = tokio::spawn({
                let socket = socket.clone();
                async move { socket.close().await }
            });
            while !socket.closed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            close_task.abort();
            assert!(close_task.await.unwrap_err().is_cancelled());
            drop(gate);

            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_cleanup_cannot_remove_a_reused_association_id() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let endpoint = test_server_endpoint();
            let server_addr = endpoint.local_addr().unwrap();
            let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut auth = connection.accept_uni().await.unwrap();
                let auth = auth.read_to_end(64).await.unwrap();
                assert_eq!(&auth[..2], &[TUIC_VERSION, CMD_AUTHENTICATE]);
                ready_tx.send(()).unwrap();
                connection.closed().await;
            });

            let mut outbound =
                TuicOutbound::new("test", "127.0.0.1", server_addr.port(), uuid, "secret");
            outbound.insecure = true;
            outbound.heartbeat_interval = Duration::from_secs(60);
            let session = outbound.ensure_session().await.unwrap();
            ready_rx.await.unwrap();

            let (old_id, _old_receiver, old_state) = session.register_association().unwrap();
            old_state.close();
            session.next_assoc_id.store(old_id, Ordering::Relaxed);
            let (reserved_id, _reserved_receiver, reserved_state) =
                session.register_association().unwrap();
            assert_ne!(
                reserved_id, old_id,
                "closed IDs stay reserved during cleanup"
            );

            session.unregister_association(old_id, &old_state);
            session.next_assoc_id.store(old_id, Ordering::Relaxed);
            let (reused_id, _reused_receiver, reused_state) =
                session.register_association().unwrap();
            assert_eq!(reused_id, old_id);
            session.unregister_association(old_id, &old_state);
            let entry = lock_associations(&session.associations)
                .get(&old_id)
                .cloned()
                .expect("stale cleanup must not remove the replacement association");
            assert!(Arc::ptr_eq(&entry.state, &reused_state));

            session.unregister_association(reused_id, &reused_state);
            session.unregister_association(reserved_id, &reserved_state);
            session.connection.close(0u32.into(), b"test complete");
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registering_on_a_closed_session_fails_without_leaking_an_entry() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let endpoint = test_server_endpoint();
            let server_addr = endpoint.local_addr().unwrap();
            let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut auth = connection.accept_uni().await.unwrap();
                let _ = auth.read_to_end(64).await.unwrap();
                ready_tx.send(()).unwrap();
                connection.closed().await;
            });

            let mut outbound =
                TuicOutbound::new("test", "127.0.0.1", server_addr.port(), uuid, "secret");
            outbound.insecure = true;
            let session = outbound.ensure_session().await.unwrap();
            ready_rx.await.unwrap();
            session.connection.close(0u32.into(), b"test close");
            let error = session.register_association().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert!(lock_associations(&session.associations).is_empty());
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn udp_mode_default() {
        assert_eq!(TuicUdpMode::default(), TuicUdpMode::Native);
    }
}
