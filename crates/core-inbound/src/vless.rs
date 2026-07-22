//! Reusable authenticated VLESS inbound over any asynchronous byte stream.
//!
//! The transport (REALITY, gRPC, WebSocket, or another listener) is responsible
//! for establishing a trusted stream and choosing the logical source address.
//! This module owns VLESS authentication, commands 1/2/3, fixed-destination UDP,
//! mux.cool, XUDP, resource bounds, half-close, routing and accounting.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use core_observe::ConnectionGuard;
use core_outbound::adapter::UdpSocketLike;
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::debug;
use uuid::Uuid;

const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;
const VLESS_COMMAND_MUX: u8 = 3;
const MUX_STATUS_NEW: u8 = 1;
const MUX_STATUS_KEEP: u8 = 2;
const MUX_STATUS_END: u8 = 3;
const MUX_STATUS_KEEPALIVE: u8 = 4;
const MUX_OPTION_DATA: u8 = 1;
const MUX_OPTION_ERROR: u8 = 2;
const MUX_NETWORK_TCP: u8 = 1;
const MUX_NETWORK_UDP: u8 = 2;
const MAX_MUX_METADATA_BYTES: usize = 512;
const MAX_MUX_PAYLOAD_BYTES: usize = 8 * 1024;
const MAX_VLESS_UDP_PAYLOAD_BYTES: usize = MAX_MUX_PAYLOAD_BYTES - 2;
const MAX_XUDP_TARGETS_PER_SESSION: usize = 64;
const MUX_INPUT_QUEUE_DEPTH: usize = 32;

/// Validated VLESS authentication and resource policy, independent of the
/// outer transport.
#[derive(Clone)]
pub struct VlessInboundConfig {
    users: Arc<Vec<[u8; 16]>>,
    handshake_timeout: Duration,
    max_mux_sessions: usize,
}

impl VlessInboundConfig {
    pub fn new(
        users: Vec<[u8; 16]>,
        handshake_timeout: Duration,
        max_mux_sessions: usize,
    ) -> io::Result<Self> {
        let config = Self {
            users: Arc::new(users),
            handshake_timeout,
            max_mux_sessions,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn from_uuid_strings<I, S>(
        users: I,
        handshake_timeout: Duration,
        max_mux_sessions: usize,
    ) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let users = users
            .into_iter()
            .map(|user| {
                Uuid::parse_str(user.as_ref())
                    .map(|uuid| *uuid.as_bytes())
                    .map_err(|error| invalid_input(format!("invalid VLESS user UUID: {error}")))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::new(users, handshake_timeout, max_mux_sessions)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.users.is_empty() {
            return Err(invalid_input("VLESS requires at least one authorized UUID"));
        }
        if self.handshake_timeout.is_zero() {
            return Err(invalid_input("VLESS handshake timeout must be non-zero"));
        }
        if self.max_mux_sessions == 0 {
            return Err(invalid_input("VLESS max mux sessions must be non-zero"));
        }
        Ok(())
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn max_mux_sessions(&self) -> usize {
        self.max_mux_sessions
    }
}

impl fmt::Debug for VlessInboundConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VlessInboundConfig")
            .field("user_count", &self.users.len())
            .field("handshake_timeout", &self.handshake_timeout)
            .field("max_mux_sessions", &self.max_mux_sessions)
            .finish()
    }
}

/// Transport-supplied connection identity. `source` may be a physical peer or
/// a logical address derived from a trusted forwarded header; validation of
/// that header belongs to the outer transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlessConnectionContext {
    pub source: SocketAddr,
    pub local: SocketAddr,
}

/// Authenticate and serve a complete VLESS connection over an arbitrary
/// bidirectional asynchronous byte stream.
pub async fn serve_vless_stream<S>(
    stream: S,
    context: VlessConnectionContext,
    config: Arc<VlessInboundConfig>,
    runtime: Arc<Runtime>,
    cancellation: CancellationToken,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.validate()?;
    tokio::select! {
        _ = cancellation.cancelled() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "VLESS connection cancelled",
        )),
        result = serve_vless(
            stream,
            context.source,
            context.local,
            config.users.clone(),
            runtime,
            config.handshake_timeout,
            config.max_mux_sessions,
        ) => result,
    }
}

async fn serve_vless<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    users: Arc<Vec<[u8; 16]>>,
    runtime: Arc<Runtime>,
    handshake_timeout: Duration,
    max_mux_sessions: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = tokio::time::timeout(
        handshake_timeout,
        read_vless_request(&mut stream, users.as_ref()),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS handshake timed out"))??;
    let handler = ListenerHandler::new(runtime);
    match request.command {
        VLESS_COMMAND_TCP => {
            let target = request
                .target
                .ok_or_else(|| invalid_data("VLESS TCP request has no target"))?;
            let metadata =
                InboundMetadata::tcp("vless", "VLESS", peer, local, target.host, target.port);
            let prepared = handler.prepare_tcp(metadata).await?;
            stream.write_all(&[0, 0]).await?;
            stream.flush().await?;
            handler.relay_prepared_tcp(stream, prepared).await
        }
        VLESS_COMMAND_UDP => {
            let target = request
                .target
                .ok_or_else(|| invalid_data("VLESS UDP request has no target"))?;
            serve_vless_udp(stream, peer, local, target, handler).await
        }
        VLESS_COMMAND_MUX => {
            stream.write_all(&[0, 0]).await?;
            stream.flush().await?;
            serve_vless_mux(stream, peer, local, handler, max_mux_sessions.max(1)).await
        }
        command => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported VLESS command {command}"),
        )),
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VlessTarget {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct VlessRequest {
    command: u8,
    target: Option<VlessTarget>,
}

async fn read_vless_request<S>(stream: &mut S, users: &[[u8; 16]]) -> io::Result<VlessRequest>
where
    S: AsyncRead + Unpin,
{
    let mut fixed = [0u8; 18];
    stream.read_exact(&mut fixed).await?;
    if fixed[0] != 0 {
        return Err(invalid_data(format!(
            "unsupported VLESS version {}",
            fixed[0]
        )));
    }
    let authenticated = users.iter().fold(0u8, |matched, user| {
        matched | user.ct_eq(&fixed[1..17]).unwrap_u8()
    });
    if authenticated == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS UUID is not authorized",
        ));
    }
    let mut addons = vec![0u8; fixed[17] as usize];
    stream.read_exact(&mut addons).await?;
    if !addons.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VLESS request addons (including XTLS Vision flow) are not enabled for this listener",
        ));
    }
    let command = stream.read_u8().await?;
    let target = match command {
        VLESS_COMMAND_TCP | VLESS_COMMAND_UDP => Some(read_vless_target(stream).await?),
        VLESS_COMMAND_MUX => None,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported VLESS command {command}"),
            ));
        }
    };
    Ok(VlessRequest { command, target })
}

async fn read_vless_target<S>(stream: &mut S) -> io::Result<VlessTarget>
where
    S: AsyncRead + Unpin,
{
    let port = stream.read_u16().await?;
    if port == 0 {
        return Err(invalid_data("VLESS destination port is zero"));
    }
    let address_type = stream.read_u8().await?;
    let host = match address_type {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            IpAddr::from(address).to_string()
        }
        2 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid_data("VLESS destination domain is empty"));
            }
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = std::str::from_utf8(&domain)
                .map_err(|_| invalid_data("VLESS destination domain is not UTF-8"))?;
            normalize_domain(domain)?
        }
        3 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            IpAddr::from(address).to_string()
        }
        kind => {
            return Err(invalid_data(format!(
                "unsupported VLESS address type {kind}"
            )));
        }
    };
    Ok(VlessTarget { host, port })
}

async fn serve_vless_udp<S>(
    mut stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    target: VlessTarget,
    handler: ListenerHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let metadata = InboundMetadata::udp(
        "vless",
        "VLESS",
        peer,
        Some(local),
        target.host,
        target.port,
    );
    let prepared = handler.prepare_udp(metadata).await?;
    stream.write_all(&[0, 0]).await?;
    stream.flush().await?;
    let socket: Arc<dyn UdpSocketLike> = Arc::from(prepared.socket);
    let guard = prepared.guard;
    let target_host = prepared.target_host;
    let target_port = prepared.target_port;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send_socket = socket.clone();
    let send_handler = handler.clone();
    let send = async {
        loop {
            let length = match reader.read_u16().await {
                Ok(length) => usize::from(length),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            if length == 0 || length > MAX_VLESS_UDP_PAYLOAD_BYTES {
                return Err(invalid_data(format!(
                    "VLESS UDP packet length {length} is outside 1..={MAX_VLESS_UDP_PAYLOAD_BYTES}"
                )));
            }
            let mut payload = vec![0u8; length];
            reader.read_exact(&mut payload).await?;
            let sent = send_socket
                .send_to(&payload, &target_host, target_port)
                .await?;
            if sent != payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "VLESS UDP outbound truncated a datagram",
                ));
            }
            send_handler.record_upload(&guard, sent as u64);
        }
    };
    let recv_socket = socket.clone();
    let recv_handler = handler.clone();
    let recv = async {
        let mut payload = vec![0u8; MAX_VLESS_UDP_PAYLOAD_BYTES];
        loop {
            let length = recv_socket.recv_from(&mut payload).await?;
            if length == 0 {
                continue;
            }
            let length_u16 = u16::try_from(length)
                .map_err(|_| invalid_data("VLESS UDP response exceeds u16 length"))?;
            writer.write_all(&length_u16.to_be_bytes()).await?;
            writer.write_all(&payload[..length]).await?;
            writer.flush().await?;
            recv_handler.record_download(&guard, length as u64);
        }
    };
    let result = tokio::select! {
        result = send => result,
        result = recv => result,
    };
    let _ = socket.close().await;
    result
}

#[derive(Debug)]
struct MuxFrame {
    session_id: u16,
    status: u8,
    network: Option<u8>,
    target: Option<VlessTarget>,
    payload: Option<Vec<u8>>,
}

#[derive(Debug)]
struct MuxInput {
    target: Option<VlessTarget>,
    payload: Vec<u8>,
}

async fn serve_vless_mux<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    handler: ListenerHandler,
    max_sessions: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let mut sessions: HashMap<u16, mpsc::Sender<MuxInput>> = HashMap::new();
    let mut tasks = JoinSet::new();

    while let Some(frame) = read_mux_frame(&mut reader).await? {
        sessions.retain(|_, sender| !sender.is_closed());
        match frame.status {
            MUX_STATUS_KEEPALIVE => {}
            MUX_STATUS_END => {
                sessions.remove(&frame.session_id);
            }
            MUX_STATUS_NEW => {
                if sessions.contains_key(&frame.session_id) {
                    return Err(invalid_data(format!(
                        "duplicate VLESS mux session {}",
                        frame.session_id
                    )));
                }
                if sessions.len() >= max_sessions {
                    write_mux_frame(
                        &writer,
                        frame.session_id,
                        MUX_STATUS_END,
                        MUX_OPTION_ERROR,
                        None,
                        None,
                    )
                    .await?;
                    continue;
                }
                let network = frame
                    .network
                    .ok_or_else(|| invalid_data("new VLESS mux session has no network"))?;
                let target = frame
                    .target
                    .clone()
                    .ok_or_else(|| invalid_data("new VLESS mux session has no target"))?;
                let (sender, receiver) = mpsc::channel(MUX_INPUT_QUEUE_DEPTH);
                sessions.insert(frame.session_id, sender.clone());
                let session_writer = writer.clone();
                let session_handler = handler.clone();
                let session_id = frame.session_id;
                match network {
                    MUX_NETWORK_TCP => tasks.spawn(async move {
                        run_mux_tcp_session(
                            session_id,
                            target,
                            peer,
                            local,
                            session_handler,
                            session_writer,
                            receiver,
                        )
                        .await
                    }),
                    MUX_NETWORK_UDP => tasks.spawn(async move {
                        run_mux_udp_session(
                            session_id,
                            target,
                            peer,
                            local,
                            session_handler,
                            session_writer,
                            receiver,
                        )
                        .await
                    }),
                    _ => unreachable!("validated mux network"),
                };
                if let Some(payload) = frame.payload {
                    if sender
                        .send(MuxInput {
                            target: frame.target,
                            payload,
                        })
                        .await
                        .is_err()
                    {
                        sessions.remove(&frame.session_id);
                    }
                }
            }
            MUX_STATUS_KEEP => {
                if let Some(payload) = frame.payload {
                    if let Some(sender) = sessions.get(&frame.session_id) {
                        if sender
                            .send(MuxInput {
                                target: frame.target,
                                payload,
                            })
                            .await
                            .is_err()
                        {
                            sessions.remove(&frame.session_id);
                        }
                    } else {
                        write_mux_frame(
                            &writer,
                            frame.session_id,
                            MUX_STATUS_END,
                            MUX_OPTION_ERROR,
                            None,
                            None,
                        )
                        .await?;
                    }
                }
            }
            _ => unreachable!("validated mux status"),
        }
    }

    drop(sessions);
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Err(error)) => debug!(error = %error, "VLESS mux sub-session failed"),
            Err(error) => debug!(error = %error, "VLESS mux sub-session panicked"),
        }
    }
    Ok(())
}

async fn run_mux_tcp_session<W>(
    session_id: u16,
    target: VlessTarget,
    peer: SocketAddr,
    local: SocketAddr,
    handler: ListenerHandler,
    writer: Arc<Mutex<W>>,
    mut receiver: mpsc::Receiver<MuxInput>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let metadata = InboundMetadata::tcp(
        "vless-mux",
        "VLESS+MUX",
        peer,
        local,
        target.host,
        target.port,
    );
    let prepared = match handler.prepare_tcp(metadata).await {
        Ok(prepared) => prepared,
        Err(error) => {
            write_mux_frame(
                &writer,
                session_id,
                MUX_STATUS_END,
                MUX_OPTION_ERROR,
                None,
                None,
            )
            .await?;
            return Err(error);
        }
    };
    let (relay_side, mux_side) = tokio::io::duplex(64 * 1024);
    let relay_handler = handler.clone();
    let relay =
        tokio::spawn(async move { relay_handler.relay_prepared_tcp(relay_side, prepared).await });
    let (mut outbound_reader, mut outbound_writer) = tokio::io::split(mux_side);
    let mut inbound_open = true;
    let mut buffer = vec![0u8; MAX_MUX_PAYLOAD_BYTES];
    loop {
        if inbound_open {
            tokio::select! {
                input = receiver.recv() => {
                    match input {
                        Some(input) => outbound_writer.write_all(&input.payload).await?,
                        None => {
                            outbound_writer.shutdown().await?;
                            inbound_open = false;
                        }
                    }
                }
                read = outbound_reader.read(&mut buffer) => {
                    let length = read?;
                    if length == 0 {
                        break;
                    }
                    write_mux_frame(
                        &writer,
                        session_id,
                        MUX_STATUS_KEEP,
                        MUX_OPTION_DATA,
                        None,
                        Some(&buffer[..length]),
                    ).await?;
                }
            }
        } else {
            let length = outbound_reader.read(&mut buffer).await?;
            if length == 0 {
                break;
            }
            write_mux_frame(
                &writer,
                session_id,
                MUX_STATUS_KEEP,
                MUX_OPTION_DATA,
                None,
                Some(&buffer[..length]),
            )
            .await?;
        }
    }
    write_mux_frame(&writer, session_id, MUX_STATUS_END, 0, None, None).await?;
    match relay.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(io::Error::other(format!(
            "VLESS mux relay task failed: {error}"
        ))),
    }
}

#[derive(Clone)]
struct MuxUdpAssociation {
    socket: Arc<dyn UdpSocketLike>,
    guard: Arc<ConnectionGuard>,
    target_host: String,
    target_port: u16,
}

async fn run_mux_udp_session<W>(
    session_id: u16,
    initial_target: VlessTarget,
    peer: SocketAddr,
    local: SocketAddr,
    handler: ListenerHandler,
    writer: Arc<Mutex<W>>,
    mut receiver: mpsc::Receiver<MuxInput>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let cancellation = CancellationToken::new();
    let mut associations: HashMap<VlessTarget, MuxUdpAssociation> = HashMap::new();
    let mut receive_tasks: Vec<JoinHandle<io::Result<()>>> = Vec::new();
    let mut session_result = Ok(());

    while let Some(input) = receiver.recv().await {
        let target = input.target.unwrap_or_else(|| initial_target.clone());
        if !associations.contains_key(&target) {
            if associations.len() >= MAX_XUDP_TARGETS_PER_SESSION {
                session_result = Err(invalid_data(format!(
                    "VLESS XUDP session exceeds {MAX_XUDP_TARGETS_PER_SESSION} targets"
                )));
                break;
            }
            let metadata = InboundMetadata::udp(
                "vless-mux",
                "VLESS+XUDP",
                peer,
                Some(local),
                target.host.clone(),
                target.port,
            );
            let prepared = match handler.prepare_udp(metadata).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    session_result = Err(error);
                    break;
                }
            };
            let association = MuxUdpAssociation {
                socket: Arc::from(prepared.socket),
                guard: Arc::new(prepared.guard),
                target_host: prepared.target_host,
                target_port: prepared.target_port,
            };
            let receive_socket = association.socket.clone();
            let receive_guard = association.guard.clone();
            let receive_writer = writer.clone();
            let receive_handler = handler.clone();
            let receive_target = target.clone();
            let receive_cancellation = cancellation.clone();
            receive_tasks.push(tokio::spawn(async move {
                let mut payload = vec![0u8; MAX_MUX_PAYLOAD_BYTES];
                loop {
                    let length = tokio::select! {
                        () = receive_cancellation.cancelled() => return Ok(()),
                        result = receive_socket.recv_from(&mut payload) => result?,
                    };
                    if length == 0 {
                        continue;
                    }
                    receive_handler.record_download(&receive_guard, length as u64);
                    write_mux_frame(
                        &receive_writer,
                        session_id,
                        MUX_STATUS_KEEP,
                        MUX_OPTION_DATA,
                        Some((MUX_NETWORK_UDP, &receive_target)),
                        Some(&payload[..length]),
                    )
                    .await?;
                }
            }));
            associations.insert(target.clone(), association);
        }
        let Some(association) = associations.get(&target) else {
            session_result = Err(io::Error::other(
                "VLESS XUDP association disappeared after insertion",
            ));
            break;
        };
        let sent = association
            .socket
            .send_to(
                &input.payload,
                &association.target_host,
                association.target_port,
            )
            .await?;
        if sent != input.payload.len() {
            session_result = Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "VLESS XUDP outbound truncated a datagram",
            ));
            break;
        }
        handler.record_upload(&association.guard, sent as u64);
    }

    cancellation.cancel();
    for association in associations.values() {
        let _ = association.socket.close().await;
    }
    for task in receive_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if session_result.is_ok() => session_result = Err(error),
            Ok(Err(_)) => {}
            Err(error) if session_result.is_ok() => {
                session_result = Err(io::Error::other(format!(
                    "VLESS XUDP receive task failed: {error}"
                )));
            }
            Err(_) => {}
        }
    }
    let end_option = if session_result.is_ok() {
        0
    } else {
        MUX_OPTION_ERROR
    };
    write_mux_frame(&writer, session_id, MUX_STATUS_END, end_option, None, None).await?;
    session_result
}

async fn read_mux_frame<R>(reader: &mut R) -> io::Result<Option<MuxFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut encoded_length = [0u8; 2];
    let first = reader.read(&mut encoded_length[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut encoded_length[1..]).await?;
    let metadata_length = usize::from(u16::from_be_bytes(encoded_length));
    if !(4..=MAX_MUX_METADATA_BYTES).contains(&metadata_length) {
        return Err(invalid_data(format!(
            "VLESS mux metadata length {metadata_length} is outside 4..={MAX_MUX_METADATA_BYTES}"
        )));
    }
    let mut metadata = vec![0u8; metadata_length];
    reader.read_exact(&mut metadata).await?;
    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let option = metadata[3];
    if !matches!(
        status,
        MUX_STATUS_NEW | MUX_STATUS_KEEP | MUX_STATUS_END | MUX_STATUS_KEEPALIVE
    ) {
        return Err(invalid_data(format!("unknown VLESS mux status {status}")));
    }
    if option & !(MUX_OPTION_DATA | MUX_OPTION_ERROR) != 0 {
        return Err(invalid_data(format!(
            "unknown VLESS mux option bits {option:#04x}"
        )));
    }
    let (network, target) = if status == MUX_STATUS_NEW {
        let network = *metadata
            .get(4)
            .ok_or_else(|| invalid_data("new VLESS mux frame has no network"))?;
        if !matches!(network, MUX_NETWORK_TCP | MUX_NETWORK_UDP) {
            return Err(invalid_data(format!(
                "unknown VLESS mux target network {network}"
            )));
        }
        let (target, _) = decode_mux_target(&metadata, 5)?;
        (Some(network), Some(target))
    } else if status == MUX_STATUS_KEEP && metadata.get(4).copied() == Some(MUX_NETWORK_UDP) {
        let (target, _) = decode_mux_target(&metadata, 5)?;
        (Some(MUX_NETWORK_UDP), Some(target))
    } else {
        (None, None)
    };
    let payload = if option & MUX_OPTION_DATA != 0 {
        let length = usize::from(reader.read_u16().await?);
        if length > MAX_MUX_PAYLOAD_BYTES {
            return Err(invalid_data(format!(
                "VLESS mux payload length {length} exceeds {MAX_MUX_PAYLOAD_BYTES}"
            )));
        }
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;
        Some(payload)
    } else {
        None
    };
    Ok(Some(MuxFrame {
        session_id,
        status,
        network,
        target,
        payload,
    }))
}

fn decode_mux_target(metadata: &[u8], offset: usize) -> io::Result<(VlessTarget, usize)> {
    if metadata.len() < offset + 3 {
        return Err(invalid_data("VLESS mux target metadata is truncated"));
    }
    let port = u16::from_be_bytes([metadata[offset], metadata[offset + 1]]);
    if port == 0 {
        return Err(invalid_data("VLESS mux target port is zero"));
    }
    let address_type = metadata[offset + 2];
    let address_offset = offset + 3;
    let (host, consumed) = match address_type {
        1 => {
            let bytes = metadata
                .get(address_offset..address_offset + 4)
                .ok_or_else(|| invalid_data("VLESS mux IPv4 target is truncated"))?;
            (
                IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
                4,
            )
        }
        2 => {
            let length = usize::from(
                *metadata
                    .get(address_offset)
                    .ok_or_else(|| invalid_data("VLESS mux domain length is missing"))?,
            );
            if length == 0 {
                return Err(invalid_data("VLESS mux target domain is empty"));
            }
            let bytes = metadata
                .get(address_offset + 1..address_offset + 1 + length)
                .ok_or_else(|| invalid_data("VLESS mux domain target is truncated"))?;
            let domain = std::str::from_utf8(bytes)
                .map_err(|_| invalid_data("VLESS mux target domain is not UTF-8"))?;
            (normalize_domain(domain)?, length + 1)
        }
        3 => {
            let bytes = metadata
                .get(address_offset..address_offset + 16)
                .ok_or_else(|| invalid_data("VLESS mux IPv6 target is truncated"))?;
            let address: [u8; 16] = bytes
                .try_into()
                .map_err(|_| invalid_data("VLESS mux IPv6 target is invalid"))?;
            (IpAddr::from(address).to_string(), 16)
        }
        kind => {
            return Err(invalid_data(format!(
                "unsupported VLESS mux address type {kind}"
            )));
        }
    };
    Ok((VlessTarget { host, port }, address_offset + consumed))
}

async fn write_mux_frame<W>(
    writer: &Arc<Mutex<W>>,
    session_id: u16,
    status: u8,
    option: u8,
    target: Option<(u8, &VlessTarget)>,
    payload: Option<&[u8]>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&session_id.to_be_bytes());
    metadata.push(status);
    metadata.push(option);
    if let Some((network, target)) = target {
        metadata.push(network);
        encode_mux_target(target, &mut metadata)?;
    }
    let metadata_length = u16::try_from(metadata.len())
        .map_err(|_| invalid_data("VLESS mux response metadata is too large"))?;
    let mut writer = writer.lock().await;
    writer.write_all(&metadata_length.to_be_bytes()).await?;
    writer.write_all(&metadata).await?;
    if let Some(payload) = payload {
        if payload.len() > MAX_MUX_PAYLOAD_BYTES {
            return Err(invalid_data("VLESS mux response payload is too large"));
        }
        let length = u16::try_from(payload.len())
            .map_err(|_| invalid_data("VLESS mux response payload exceeds u16"))?;
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(payload).await?;
    }
    writer.flush().await
}

fn encode_mux_target(target: &VlessTarget, output: &mut Vec<u8>) -> io::Result<()> {
    output.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(address) = target.host.parse::<IpAddr>() {
        match address {
            IpAddr::V4(address) => {
                output.push(1);
                output.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                output.push(3);
                output.extend_from_slice(&address.octets());
            }
        }
    } else {
        let length = u8::try_from(target.host.len())
            .map_err(|_| invalid_data("VLESS mux response domain is too long"))?;
        output.push(2);
        output.push(length);
        output.extend_from_slice(target.host.as_bytes());
    }
    Ok(())
}

fn normalize_domain(value: &str) -> io::Result<String> {
    let domain = value.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
        || domain.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(invalid_data("invalid VLESS destination domain"));
    }
    Ok(domain)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_config_validates_users_and_bounds_without_reality() {
        let config = VlessInboundConfig::from_uuid_strings(
            ["11111111-1111-1111-1111-111111111111"],
            Duration::from_secs(3),
            32,
        )
        .unwrap();
        assert_eq!(config.user_count(), 1);
        assert_eq!(config.handshake_timeout(), Duration::from_secs(3));
        assert_eq!(config.max_mux_sessions(), 32);
        assert!(!format!("{config:?}").contains("11111111"));

        assert!(VlessInboundConfig::new(Vec::new(), Duration::from_secs(1), 1).is_err());
        assert!(VlessInboundConfig::new(vec![[1; 16]], Duration::ZERO, 1).is_err());
        assert!(VlessInboundConfig::new(vec![[1; 16]], Duration::from_secs(1), 0).is_err());
        assert!(
            VlessInboundConfig::from_uuid_strings(["not-a-uuid"], Duration::from_secs(1), 1,)
                .is_err()
        );
    }

    #[test]
    fn public_stream_contract_accepts_generic_duplex_streams() {
        fn assert_compatible<S>()
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
        }
        assert_compatible::<tokio::io::DuplexStream>();
    }

    #[test]
    fn domain_normalization_rejects_ambiguous_forms() {
        assert_eq!(normalize_domain("Example.COM.").unwrap(), "example.com");
        for invalid in ["", ".", "a..b", "-a.example", "a-.example", "exa_mple.com"] {
            assert!(normalize_domain(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn authentication_and_mux_request_header_stop_after_command_like_xray() {
        let user = [0x11; 16];
        let mut wire = vec![0];
        wire.extend_from_slice(&user);
        wire.extend_from_slice(&[0, VLESS_COMMAND_MUX]);
        let mut input = wire.as_slice();
        let request = read_vless_request(&mut input, &[user]).await.unwrap();
        assert_eq!(request.command, VLESS_COMMAND_MUX);
        assert!(request.target.is_none());
        assert!(input.is_empty());

        let mut unauthorized = wire.as_slice();
        assert_eq!(
            read_vless_request(&mut unauthorized, &[[0x22; 16]])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn reads_pinned_xray_xudp_new_frame() {
        let wire = [
            0x00,
            0x14,
            0x00,
            0x00,
            MUX_STATUS_NEW,
            MUX_OPTION_DATA,
            MUX_NETWORK_UDP,
            0x00,
            0x35,
            0x01,
            0x7f,
            0x00,
            0x00,
            0x01,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            0x00,
            0x01,
            b'q',
        ];
        let mut input = wire.as_slice();
        let frame = read_mux_frame(&mut input).await.unwrap().unwrap();
        assert_eq!(frame.session_id, 0);
        assert_eq!(frame.status, MUX_STATUS_NEW);
        assert_eq!(frame.network, Some(MUX_NETWORK_UDP));
        assert_eq!(
            frame.target,
            Some(VlessTarget {
                host: "127.0.0.1".into(),
                port: 53,
            })
        );
        assert_eq!(frame.payload.as_deref(), Some(b"q".as_slice()));
    }

    #[tokio::test]
    async fn writes_pinned_xray_xudp_keep_frame() {
        let (writer_side, mut reader_side) = tokio::io::duplex(128);
        let writer = Arc::new(Mutex::new(writer_side));
        let target = VlessTarget {
            host: "127.0.0.1".into(),
            port: 53,
        };
        write_mux_frame(
            &writer,
            7,
            MUX_STATUS_KEEP,
            MUX_OPTION_DATA,
            Some((MUX_NETWORK_UDP, &target)),
            Some(b"answer"),
        )
        .await
        .unwrap();
        let expected = [
            0x00,
            0x0c,
            0x00,
            0x07,
            MUX_STATUS_KEEP,
            MUX_OPTION_DATA,
            MUX_NETWORK_UDP,
            0x00,
            0x35,
            0x01,
            0x7f,
            0x00,
            0x00,
            0x01,
            0x00,
            0x06,
            b'a',
            b'n',
            b's',
            b'w',
            b'e',
            b'r',
        ];
        let mut actual = vec![0u8; expected.len()];
        reader_side.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn mux_frame_limits_and_unknown_bits_fail_closed() {
        for wire in [
            vec![0x02, 0x01],
            vec![0, 4, 0, 1, 0xff, 0],
            vec![0, 4, 0, 1, MUX_STATUS_KEEP, 0x80],
            vec![0, 4, 0, 1, MUX_STATUS_KEEP, MUX_OPTION_DATA, 0x20, 0x01],
        ] {
            let mut input = wire.as_slice();
            assert!(read_mux_frame(&mut input).await.is_err());
        }
    }
}
