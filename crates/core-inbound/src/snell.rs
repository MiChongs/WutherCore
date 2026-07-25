//! Complete Snell v1-v5 inbound.
//!
//! The listener shares the authenticated record layer and simple-obfs
//! implementation with the outbound, supports TCP, v3+ UDP and the sequential
//! connection reuse negotiated by command 5.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use core_config::{model::SnellObfsListen, runtime_plan::SnellListenPlan};
use core_outbound::{
    adapter::{BoxedStream, UdpSocketLike},
    proto::{
        snell::{
            SnellRequest, encode_udp_response, error_reply, parse_request_header,
            parse_udp_request, pong_reply, tunnel_reply,
        },
        snell_codec::{
            MAX_FRAME_LENGTH, SnellFrameEvent, SnellReadHalf, SnellStream, SnellVersion,
            SnellWriteHalf,
        },
    },
    transport::simple_obfs::{SimpleObfsMode, SimpleObfsStream},
};
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const MAX_UDP_TARGETS: usize = 64;
const UDP_QUEUE_DEPTH: usize = 32;

#[derive(Clone)]
struct SnellServerConfig {
    password: Arc<[u8]>,
    version: SnellVersion,
    udp: bool,
    obfs: Option<SimpleObfsMode>,
    handshake_timeout: std::time::Duration,
    tag: String,
}

pub struct SnellListenerHandle {
    tag: String,
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl SnellListenerHandle {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.cancel();
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await
            .map_err(|error| io::Error::other(format!("Snell listener task failed: {error}")))?
    }
}

impl Drop for SnellListenerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn start_snell_listeners(
    plans: &[SnellListenPlan],
    runtime: Arc<Runtime>,
) -> io::Result<Vec<SnellListenerHandle>> {
    let mut handles = Vec::new();
    for plan in plans.iter().filter(|plan| plan.enabled) {
        match start_snell_listener(plan, Arc::clone(&runtime)).await {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                for handle in &mut handles {
                    let _ = handle.shutdown().await;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("Snell listener `{}` startup failed: {error}", plan.tag),
                ));
            }
        }
    }
    Ok(handles)
}

pub async fn start_snell_listener(
    plan: &SnellListenPlan,
    runtime: Arc<Runtime>,
) -> io::Result<SnellListenerHandle> {
    validate_plan(plan)?;
    let address = plan
        .socket_addr()
        .map_err(|error| invalid_input(error.to_string()))?;
    let listener = TcpListener::bind(address).await?;
    let local_addr = listener.local_addr()?;
    let config = Arc::new(SnellServerConfig {
        password: Arc::from(plan.psk.as_bytes()),
        version: SnellVersion::parse(plan.version).map_err(invalid_input)?,
        udp: plan.udp,
        obfs: plan
            .obfs
            .as_ref()
            .map(|obfs| server_obfs(obfs, plan.port))
            .transpose()?,
        handshake_timeout: plan.handshake_timeout,
        tag: plan.tag.clone(),
    });
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_listener(
        listener,
        config,
        runtime,
        Arc::new(Semaphore::new(plan.max_connections)),
        shutdown.clone(),
    ));
    info!(
        target: "inbound::snell",
        tag = %plan.tag,
        addr = %local_addr,
        version = plan.version,
        udp = plan.udp,
        obfs = plan.obfs.as_ref().map(|value| value.mode.as_str()).unwrap_or("none"),
        "Snell listener ready"
    );
    Ok(SnellListenerHandle {
        tag: plan.tag.clone(),
        local_addr,
        shutdown,
        task: Some(task),
    })
}

fn validate_plan(plan: &SnellListenPlan) -> io::Result<()> {
    if !plan.enabled {
        return Err(invalid_input("cannot start a disabled Snell listener"));
    }
    if plan.psk.is_empty() {
        return Err(invalid_input("Snell listener PSK must not be empty"));
    }
    let version = SnellVersion::parse(plan.version).map_err(invalid_input)?;
    if plan.udp && !version.supports_udp() {
        return Err(invalid_input(format!(
            "Snell v{} does not support UDP",
            version.number()
        )));
    }
    if plan.handshake_timeout.is_zero() {
        return Err(invalid_input("Snell handshake timeout must be non-zero"));
    }
    if plan.max_connections == 0 {
        return Err(invalid_input(
            "Snell max connections must be greater than zero",
        ));
    }
    Ok(())
}

fn server_obfs(obfs: &SnellObfsListen, port: u16) -> io::Result<SimpleObfsMode> {
    match obfs.mode.to_ascii_lowercase().as_str() {
        "http" => Ok(SimpleObfsMode::Http {
            host: obfs.host.clone(),
            port,
        }),
        "tls" => Ok(SimpleObfsMode::Tls {
            host: obfs.host.clone(),
        }),
        mode => Err(invalid_input(format!(
            "unsupported Snell simple-obfs mode `{mode}`"
        ))),
    }
}

async fn run_listener(
    listener: TcpListener,
    config: Arc<SnellServerConfig>,
    runtime: Arc<Runtime>,
    permits: Arc<Semaphore>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => debug!(target: "inbound::snell", %error, "Snell connection closed with error"),
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => warn!(target: "inbound::snell", %error, "Snell connection task failed"),
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(target: "inbound::snell", %peer, "Snell connection rejected by limit");
                        drop(stream);
                        continue;
                    }
                };
                let local = stream.local_addr()?;
                let config = Arc::clone(&config);
                let runtime = Arc::clone(&runtime);
                let connection_shutdown = shutdown.child_token();
                connections.spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = connection_shutdown.cancelled() => Ok(()),
                        result = serve_connection(stream, peer, local, config, runtime) => result,
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    config: Arc<SnellServerConfig>,
    runtime: Arc<Runtime>,
) -> io::Result<()> {
    let stream: BoxedStream = Box::pin(stream);
    let stream: BoxedStream = match &config.obfs {
        Some(mode) => Box::pin(SimpleObfsStream::server(stream, mode.clone())),
        None => stream,
    };
    let mut stream = SnellStream::new(stream, config.password.clone(), config.version, false)?;
    let first = tokio::time::timeout(config.handshake_timeout, stream.read_event())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Snell handshake timed out"))??;
    let (reader, writer) = stream.into_split();
    let first = match first {
        SnellFrameEvent::Data(frame) => frame,
        SnellFrameEvent::End | SnellFrameEvent::TransportEof => {
            return Err(invalid_data("Snell connection ended before command header"));
        }
    };
    serve_commands(
        reader,
        writer,
        Some(first),
        peer,
        local,
        config,
        ListenerHandler::new(runtime),
    )
    .await
}

async fn serve_commands(
    mut reader: SnellReadHalf,
    mut writer: SnellWriteHalf,
    mut first: Option<Vec<u8>>,
    peer: SocketAddr,
    local: SocketAddr,
    config: Arc<SnellServerConfig>,
    handler: ListenerHandler,
) -> io::Result<()> {
    loop {
        let frame = if let Some(frame) = first.take() {
            frame
        } else {
            match reader.read_event().await? {
                SnellFrameEvent::Data(frame) => frame,
                SnellFrameEvent::End | SnellFrameEvent::TransportEof => return Ok(()),
            }
        };
        let request = match parse_request_header(&frame) {
            Ok(request) => request,
            Err(error) => {
                let _ = writer
                    .write_frame(&error_reply(1, &error.to_string()))
                    .await;
                let _ = writer.write_end().await;
                return Err(error);
            }
        };
        match request {
            SnellRequest::Ping => {
                writer.write_frame(&pong_reply()).await?;
            }
            SnellRequest::Udp => {
                if !config.udp {
                    writer
                        .write_frame(&error_reply(2, "UDP is disabled on this listener"))
                        .await?;
                    writer.write_end().await?;
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Snell UDP is disabled",
                    ));
                }
                return serve_udp(&mut reader, writer, peer, local, &config, handler).await;
            }
            SnellRequest::Tcp { host, port, reuse } => {
                let reusable = reuse && config.version.supports_reuse();
                if let Err(error) = serve_tcp(
                    &mut reader,
                    &mut writer,
                    peer,
                    local,
                    &config.tag,
                    &host,
                    port,
                    &handler,
                )
                .await
                {
                    let _ = writer
                        .write_frame(&error_reply(3, &error.to_string()))
                        .await;
                    let _ = writer.write_end().await;
                    if !reusable {
                        return Err(error);
                    }
                }
                if !reusable {
                    return Ok(());
                }
            }
        }
    }
}

async fn serve_tcp(
    reader: &mut SnellReadHalf,
    writer: &mut SnellWriteHalf,
    peer: SocketAddr,
    local: SocketAddr,
    tag: &str,
    host: &str,
    port: u16,
    handler: &ListenerHandler,
) -> io::Result<()> {
    let metadata = InboundMetadata::tcp(tag, "Snell", peer, local, host, port);
    let prepared = handler.prepare_tcp(metadata).await?;
    writer.write_frame(&tunnel_reply()).await?;
    handler.runtime().metrics.inc_connection();
    let (mut target_read, mut target_write) = tokio::io::split(prepared.result.stream);
    let guard = &prepared.guard;
    let upload = async {
        loop {
            match reader.read_event().await? {
                SnellFrameEvent::Data(frame) => {
                    target_write.write_all(&frame).await?;
                    handler.record_upload(guard, frame.len() as u64);
                }
                SnellFrameEvent::End => {
                    target_write.shutdown().await?;
                    return Ok(());
                }
                SnellFrameEvent::TransportEof => {
                    let _ = target_write.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Snell transport closed before logical request end",
                    ));
                }
            }
        }
    };
    let download = async {
        let mut buffer = vec![0u8; MAX_FRAME_LENGTH];
        loop {
            let length = target_read.read(&mut buffer).await?;
            if length == 0 {
                writer.write_end().await?;
                return Ok(());
            }
            writer.write_all(&buffer[..length]).await?;
            writer.flush().await?;
            handler.record_download(guard, length as u64);
        }
    };
    let result = tokio::try_join!(upload, download).map(|_| ());
    handler.runtime().metrics.dec_connection();
    result
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct UdpTarget {
    host: String,
    port: u16,
}

async fn serve_udp(
    reader: &mut SnellReadHalf,
    mut writer: SnellWriteHalf,
    peer: SocketAddr,
    local: SocketAddr,
    config: &SnellServerConfig,
    handler: ListenerHandler,
) -> io::Result<()> {
    if config.version.uses_v4_records() {
        writer.write_frame(&tunnel_reply()).await?;
    }
    let writer = Arc::new(Mutex::new(writer));
    let mut sessions = HashMap::<UdpTarget, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::new();
    let result = loop {
        let frame = match reader.read_event().await {
            Ok(SnellFrameEvent::Data(frame)) => frame,
            Ok(SnellFrameEvent::End | SnellFrameEvent::TransportEof) => break Ok(()),
            Err(error) => break Err(error),
        };
        let request = match parse_udp_request(&frame) {
            Ok(request) => request,
            Err(error) => break Err(error),
        };
        let target = UdpTarget {
            host: request.host,
            port: request.port,
        };
        if !sessions.contains_key(&target) {
            if sessions.len() >= MAX_UDP_TARGETS {
                break Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Snell UDP target limit exceeded",
                ));
            }
            let metadata = InboundMetadata::udp(
                &config.tag,
                "Snell",
                peer,
                Some(local),
                target.host.clone(),
                target.port,
            );
            let prepared = match handler.prepare_udp(metadata).await {
                Ok(prepared) => prepared,
                Err(error) => break Err(error),
            };
            let fallback_source = match resolve_udp_source(&target).await {
                Ok(source) => source,
                Err(error) => break Err(error),
            };
            let (sender, receiver) = mpsc::channel(UDP_QUEUE_DEPTH);
            sessions.insert(target.clone(), sender);
            tasks.spawn(run_udp_target(
                prepared.socket.into(),
                prepared.guard,
                target.clone(),
                fallback_source,
                receiver,
                Arc::clone(&writer),
                handler.clone(),
            ));
        }
        let Some(sender) = sessions.get(&target) else {
            break Err(io::Error::other(
                "Snell UDP target session registration was lost",
            ));
        };
        if sender.send(request.payload.to_vec()).await.is_err() {
            sessions.remove(&target);
            break Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Snell UDP target session stopped",
            ));
        }
    };
    drop(sessions);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn resolve_udp_source(target: &UdpTarget) -> io::Result<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, target.port));
    }
    tokio::net::lookup_host((target.host.as_str(), target.port))
        .await?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Snell UDP target {}:{} resolved no address",
                    target.host, target.port
                ),
            )
        })
}

async fn run_udp_target(
    socket: Arc<dyn UdpSocketLike>,
    guard: core_observe::ConnectionGuard,
    target: UdpTarget,
    fallback_source: SocketAddr,
    mut packets: mpsc::Receiver<Vec<u8>>,
    writer: Arc<Mutex<SnellWriteHalf>>,
    handler: ListenerHandler,
) -> io::Result<()> {
    let mut response = vec![0u8; MAX_FRAME_LENGTH];
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else { break };
                let sent = socket.send_to(&packet, &target.host, target.port).await?;
                if sent != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Snell UDP outbound truncated a datagram",
                    ));
                }
                handler.record_upload(&guard, sent as u64);
            }
            received = socket.recv_from_endpoint(&mut response) => {
                let (length, source) = received?;
                if length == 0 {
                    continue;
                }
                let source = source.unwrap_or(fallback_source);
                let frame = encode_udp_response(source.ip(), source.port(), &response[..length])?;
                let mut writer = writer.lock().await;
                writer.write_frame(&frame).await?;
                handler.record_download(&guard, length as u64);
            }
        }
    }
    socket.close().await
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use core_outbound::{
        proto::{
            snell::{encode_udp_request, parse_udp_response},
            snell_codec::SnellVersion,
        },
        transport::simple_obfs::{SimpleObfsMode, SimpleObfsStream},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };

    use super::*;

    async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(stream);
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (address, task)
    }

    async fn udp_echo() -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0u8; 65_535];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut packet).await else {
                    break;
                };
                if socket.send_to(&packet[..length], peer).await.is_err() {
                    break;
                }
            }
        });
        (address, task)
    }

    async fn runtime() -> Arc<Runtime> {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: server
listen: {panel: false}
route: {preset: direct, final: direct}
"#,
        )
        .unwrap();
        Arc::new(Runtime::build(plan).unwrap())
    }

    async fn listener(
        version: SnellVersion,
        udp: bool,
        obfs: Option<(&str, &str)>,
    ) -> (SnellListenerHandle, Arc<Runtime>) {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let runtime = runtime().await;
        let plan = SnellListenPlan {
            enabled: true,
            address: "127.0.0.1".into(),
            port,
            psk: "test-password".into(),
            version: version.number(),
            udp,
            obfs: obfs.map(|(mode, host)| SnellObfsListen {
                mode: mode.into(),
                host: host.into(),
            }),
            handshake_timeout: std::time::Duration::from_secs(2),
            max_connections: 32,
            tag: format!("test-v{}", version.number()),
        };
        let handle = start_snell_listener(&plan, Arc::clone(&runtime))
            .await
            .unwrap();
        (handle, runtime)
    }

    async fn client(
        address: SocketAddr,
        version: SnellVersion,
        obfs: Option<SimpleObfsMode>,
        expect_reply: bool,
    ) -> SnellStream {
        let stream: BoxedStream = Box::pin(TcpStream::connect(address).await.unwrap());
        let stream: BoxedStream = match obfs {
            Some(mode) => Box::pin(SimpleObfsStream::client(stream, mode)),
            None => stream,
        };
        SnellStream::new(
            stream,
            Arc::from(&b"test-password"[..]),
            version,
            expect_reply,
        )
        .unwrap()
    }

    fn tcp_header(target: SocketAddr, reuse: bool) -> Vec<u8> {
        let host = target.ip().to_string();
        let mut header = vec![1, if reuse { 5 } else { 1 }, 0, host.len() as u8];
        header.extend_from_slice(host.as_bytes());
        header.extend_from_slice(&target.port().to_be_bytes());
        header
    }

    async fn logical_echo(stream: &mut SnellStream, target: SocketAddr, reuse: bool, text: &[u8]) {
        stream
            .write_frame(&tcp_header(target, reuse))
            .await
            .unwrap();
        stream.write_all(text).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; text.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, text);
        stream.write_end().await.unwrap();
        assert_eq!(stream.read_event().await.unwrap(), SnellFrameEvent::End);
    }

    #[tokio::test]
    async fn every_version_relays_tcp_and_reuse_keeps_one_transport() {
        let (target, echo_task) = tcp_echo().await;
        for version in [
            SnellVersion::V1,
            SnellVersion::V2,
            SnellVersion::V3,
            SnellVersion::V4,
            SnellVersion::V5,
        ] {
            let (mut listener, runtime) = listener(version, false, None).await;
            let reusable = version.supports_reuse();
            let mut stream = client(listener.local_addr(), version, None, true).await;
            logical_echo(&mut stream, target, reusable, b"first").await;
            if reusable {
                logical_echo(&mut stream, target, true, b"second").await;
            }
            drop(stream);
            listener.shutdown().await.unwrap();
            runtime.shutdown().await;
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn http_and_tls_simple_obfs_relay_real_snell_sessions() {
        let (target, echo_task) = tcp_echo().await;
        for (mode, client_mode) in [
            (
                "http",
                SimpleObfsMode::Http {
                    host: "cdn.example.com".into(),
                    port: 443,
                },
            ),
            (
                "tls",
                SimpleObfsMode::Tls {
                    host: "cdn.example.com".into(),
                },
            ),
        ] {
            let (mut listener, runtime) =
                listener(SnellVersion::V4, false, Some((mode, "cdn.example.com"))).await;
            let mut stream = client(
                listener.local_addr(),
                SnellVersion::V4,
                Some(client_mode),
                true,
            )
            .await;
            logical_echo(&mut stream, target, false, mode.as_bytes()).await;
            listener.shutdown().await.unwrap();
            runtime.shutdown().await;
        }
        echo_task.abort();
    }

    #[tokio::test]
    async fn udp_v3_and_v5_preserve_multiple_target_datagrams() {
        let (first_target, first_echo) = udp_echo().await;
        let (second_target, second_echo) = udp_echo().await;
        for version in [SnellVersion::V3, SnellVersion::V5] {
            let (mut listener, runtime) = listener(version, true, None).await;
            let mut stream = client(
                listener.local_addr(),
                version,
                None,
                version.uses_v4_records(),
            )
            .await;
            stream.write_frame(&[1, 6, 0]).await.unwrap();
            stream
                .write_frame(
                    &encode_udp_request(
                        &first_target.ip().to_string(),
                        first_target.port(),
                        b"one",
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            stream
                .write_frame(
                    &encode_udp_request(
                        &second_target.ip().to_string(),
                        second_target.port(),
                        b"two",
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let mut payloads = BTreeSet::new();
            for _ in 0..2 {
                let frame = stream.read_frame().await.unwrap().unwrap();
                let (_, _, payload) = parse_udp_response(&frame).unwrap();
                payloads.insert(payload.to_vec());
            }
            assert_eq!(payloads, BTreeSet::from([b"one".to_vec(), b"two".to_vec()]));
            stream.write_end().await.unwrap();
            drop(stream);
            listener.shutdown().await.unwrap();
            runtime.shutdown().await;
        }
        first_echo.abort();
        second_echo.abort();
    }
}
