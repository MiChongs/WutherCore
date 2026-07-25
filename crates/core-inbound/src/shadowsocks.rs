//! Complete Shadowsocks TCP/UDP inbound backed by shadowsocks-rust 1.24.

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use core_config::runtime_plan::ShadowsocksListenPlan;
use core_outbound::adapter::UdpSocketLike;
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};
use shadowsocks::{
    config::{Mode, ServerAddr, ServerConfig, ServerType, ServerUser, ServerUserManager},
    context::{Context, SharedContext},
    net::UdpSocket as ShadowUdpSocket,
    plugin::{Plugin, PluginConfig, PluginMode},
    relay::{
        socks5::Address,
        tcprelay::proxy_stream::server::ProxyServerStream,
        udprelay::{
            options::UdpSocketControlData,
            proxy_socket::{ProxySocket, UdpSocketType},
        },
    },
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const UDP_PACKET_SIZE: usize = 65_536;
const UDP_QUEUE_DEPTH: usize = 64;

pub struct ShadowsocksListenerHandle {
    tag: String,
    tcp_addr: Option<SocketAddr>,
    udp_addr: Option<SocketAddr>,
    shutdown: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    plugin: Option<Plugin>,
}

impl ShadowsocksListenerHandle {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.cancel();
        let mut first_error = None;
        for task in self.tasks.drain(..) {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(error) if !error.is_cancelled() && first_error.is_none() => {
                    first_error = Some(io::Error::other(format!(
                        "Shadowsocks listener task failed: {error}"
                    )));
                }
                _ => {}
            }
        }
        self.plugin.take();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for ShadowsocksListenerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

pub async fn start_shadowsocks_listeners(
    plans: &[ShadowsocksListenPlan],
    runtime: Arc<Runtime>,
) -> io::Result<Vec<ShadowsocksListenerHandle>> {
    let mut handles = Vec::new();
    for plan in plans.iter().filter(|plan| plan.enabled) {
        match start_shadowsocks_listener(plan, Arc::clone(&runtime)).await {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                for handle in &mut handles {
                    let _ = handle.shutdown().await;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "Shadowsocks listener `{}` startup failed: {error}",
                        plan.tag
                    ),
                ));
            }
        }
    }
    Ok(handles)
}

pub async fn start_shadowsocks_listener(
    plan: &ShadowsocksListenPlan,
    runtime: Arc<Runtime>,
) -> io::Result<ShadowsocksListenerHandle> {
    let public_address = plan
        .socket_addr()
        .map_err(|error| invalid_input(error.to_string()))?;
    let mut plugin = if let Some(executable) = plan.plugin.as_ref() {
        let plugin_mode = parse_mode(plan.plugin_mode.as_deref().unwrap_or(&plan.mode))?;
        Some(Plugin::start(
            &PluginConfig {
                plugin: executable.clone(),
                plugin_opts: plan.plugin_opts.clone(),
                plugin_args: plan.plugin_args.clone(),
                plugin_mode,
            },
            &ServerAddr::SocketAddr(public_address),
            PluginMode::Server,
        )?)
    } else {
        None
    };
    let listen_address = plugin
        .as_ref()
        .map(Plugin::local_addr)
        .unwrap_or(public_address);
    let server = Arc::new(build_server_config(plan, listen_address)?);
    let context = Context::new_shared(ServerType::Server);

    // Bind every requested carrier before spawning either task. This makes a
    // tcp_and_udp listener transactional and prevents a half-started server.
    let tcp = if plan.enable_tcp() {
        Some(TcpListener::bind(listen_address).await?)
    } else {
        None
    };
    let udp = if plan.enable_udp() {
        match ShadowUdpSocket::listen(&listen_address).await {
            Ok(socket) => Some(socket),
            Err(error) => {
                drop(tcp);
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Some(process) = plugin.as_ref()
        && !process.wait_started(plan.plugin_startup_timeout).await
    {
        drop(tcp);
        drop(udp);
        plugin.take();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "Shadowsocks SIP003 plugin `{}` startup timed out",
                plan.plugin.as_deref().unwrap_or_default()
            ),
        ));
    }
    let tcp_addr = plan.enable_tcp().then_some(public_address);
    let udp_addr = plan.enable_udp().then_some(public_address);
    let shutdown = CancellationToken::new();
    let mut tasks = Vec::with_capacity(2);
    if let Some(listener) = tcp {
        tasks.push(tokio::spawn(run_tcp_listener(
            listener,
            Arc::clone(&server),
            context.clone(),
            Arc::clone(&runtime),
            Arc::new(Semaphore::new(plan.max_connections)),
            plan.handshake_timeout,
            plan.tag.clone(),
            public_address,
            shutdown.child_token(),
        )));
    }
    if let Some(socket) = udp {
        tasks.push(tokio::spawn(run_udp_listener(
            socket,
            Arc::clone(&server),
            context,
            runtime,
            plan.udp_timeout,
            plan.max_udp_associations,
            plan.tag.clone(),
            public_address,
            shutdown.child_token(),
        )));
    }
    info!(
        target: "inbound::shadowsocks",
        tag = %plan.tag,
        tcp = ?tcp_addr,
        udp = ?udp_addr,
        method = %plan.method,
        users = plan.users.len(),
        "Shadowsocks listener ready"
    );
    Ok(ShadowsocksListenerHandle {
        tag: plan.tag.clone(),
        tcp_addr,
        udp_addr,
        shutdown,
        tasks,
        plugin,
    })
}

fn parse_mode(mode: &str) -> io::Result<Mode> {
    match mode {
        "tcp_only" => Ok(Mode::TcpOnly),
        "udp_only" => Ok(Mode::UdpOnly),
        "tcp_and_udp" => Ok(Mode::TcpAndUdp),
        mode => Err(invalid_input(format!("invalid Shadowsocks mode `{mode}`"))),
    }
}

fn build_server_config(
    plan: &ShadowsocksListenPlan,
    address: SocketAddr,
) -> io::Result<ServerConfig> {
    let method = plan
        .method
        .parse()
        .map_err(|_| invalid_input(format!("unsupported Shadowsocks cipher `{}`", plan.method)))?;
    let mut server = ServerConfig::new(
        ServerAddr::SocketAddr(address),
        plan.password.clone(),
        method,
    )
    .map_err(|error| invalid_input(error.to_string()))?;
    server.set_mode(parse_mode(&plan.mode)?);
    server.set_timeout(plan.udp_timeout);
    if !plan.users.is_empty() {
        let mut manager = ServerUserManager::new();
        for user in &plan.users {
            let parsed_user = ServerUser::with_encoded_key(&user.name, &user.key)
                .map_err(|error| invalid_input(error.to_string()))?;
            if parsed_user.key().len() != method.key_len() {
                return Err(invalid_input(format!(
                    "Shadowsocks 2022 EIH user `{}` key must decode to {} bytes, got {} bytes",
                    user.name,
                    method.key_len(),
                    parsed_user.key().len()
                )));
            }
            manager.add_user(parsed_user);
        }
        server.set_user_manager(manager);
    }
    Ok(server)
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_listener(
    listener: TcpListener,
    server: Arc<ServerConfig>,
    context: SharedContext,
    runtime: Arc<Runtime>,
    permits: Arc<Semaphore>,
    handshake_timeout: Duration,
    tag: String,
    reported_local: SocketAddr,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Ok(Err(error)) = result {
                    debug!(target: "inbound::shadowsocks", %error, "Shadowsocks TCP connection closed");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(target: "inbound::shadowsocks", %peer, "Shadowsocks TCP connection rejected by limit");
                        continue;
                    }
                };
                let server = Arc::clone(&server);
                let context = context.clone();
                let runtime = Arc::clone(&runtime);
                let tag = tag.clone();
                let connection_shutdown = shutdown.child_token();
                connections.spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = connection_shutdown.cancelled() => Ok(()),
                        result = serve_tcp(stream, peer, reported_local, server, context, runtime, handshake_timeout, tag) => result,
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_tcp(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    server: Arc<ServerConfig>,
    context: SharedContext,
    runtime: Arc<Runtime>,
    handshake_timeout: Duration,
    tag: String,
) -> io::Result<()> {
    let mut stream = ProxyServerStream::from_stream_with_user_manager(
        context,
        stream,
        server.method(),
        server.key(),
        server.clone_user_manager(),
    );
    let target = tokio::time::timeout(handshake_timeout, stream.handshake())
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "Shadowsocks handshake timed out")
        })??;
    let (host, port) = address_parts(&target);
    let handler = ListenerHandler::new(runtime);
    let mut prepared = handler
        .prepare_tcp(InboundMetadata::tcp(
            &tag,
            "Shadowsocks",
            peer,
            local,
            host,
            port,
        ))
        .await?;
    handler.runtime().metrics.inc_connection();
    let guard = &prepared.guard;
    let result = copy_bidirectional(&mut stream, &mut prepared.result.stream).await;
    if let Ok((upload, download)) = result {
        handler.record_upload(guard, upload);
        handler.record_download(guard, download);
    }
    handler.runtime().metrics.dec_connection();
    result.map(|_| ())
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct AssociationKey {
    client: SocketAddr,
    session: u64,
    target: Address,
}

struct AssociationPacket {
    payload: Vec<u8>,
    control: UdpSocketControlData,
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_listener(
    socket: ShadowUdpSocket,
    server: Arc<ServerConfig>,
    context: SharedContext,
    runtime: Arc<Runtime>,
    timeout: Duration,
    max_associations: usize,
    tag: String,
    reported_local: SocketAddr,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let proxy = Arc::new(ProxySocket::from_socket(
        UdpSocketType::Server,
        context,
        &server,
        socket,
    ));
    let handler = ListenerHandler::new(runtime);
    let mut associations = HashMap::<AssociationKey, mpsc::Sender<AssociationPacket>>::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0u8; UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Ok(Err(error)) = result {
                    debug!(target: "inbound::shadowsocks", %error, "Shadowsocks UDP association closed");
                }
                associations.retain(|_, sender| !sender.is_closed());
            }
            received = proxy.recv_from_with_ctrl(&mut buffer) => {
                let (length, client, target, _, control) = match received {
                    Ok(packet) => packet,
                    Err(error) => {
                        debug!(target: "inbound::shadowsocks", %error, "rejected invalid Shadowsocks UDP packet");
                        continue;
                    }
                };
                let control = control.unwrap_or_default();
                let key = AssociationKey {
                    client,
                    session: control.client_session_id,
                    target: target.clone(),
                };
                if !associations.contains_key(&key) {
                    associations.retain(|_, sender| !sender.is_closed());
                    if associations.len() >= max_associations {
                        debug!(target: "inbound::shadowsocks", %client, "Shadowsocks UDP association rejected by limit");
                        continue;
                    }
                    let (host, port) = address_parts(&target);
                    let prepared = match handler.prepare_udp(InboundMetadata::udp(
                        &tag,
                        "Shadowsocks",
                        client,
                        Some(reported_local),
                        host.clone(),
                        port,
                    )).await {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            debug!(target: "inbound::shadowsocks", %error, "Shadowsocks UDP route rejected");
                            continue;
                        }
                    };
                    let (sender, receiver) = mpsc::channel(UDP_QUEUE_DEPTH);
                    associations.insert(key.clone(), sender);
                    tasks.spawn(run_udp_association(
                        prepared.socket.into(),
                        prepared.guard,
                        host,
                        port,
                        client,
                        target.clone(),
                        receiver,
                        Arc::clone(&proxy),
                        handler.clone(),
                        timeout,
                    ));
                }
                if let Some(sender) = associations.get(&key)
                    && sender.send(AssociationPacket {
                        payload: buffer[..length].to_vec(),
                        control,
                    }).await.is_err()
                {
                    associations.remove(&key);
                }
            }
        }
    }
    drop(associations);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_association(
    socket: Arc<dyn UdpSocketLike>,
    guard: core_observe::ConnectionGuard,
    host: String,
    port: u16,
    client: SocketAddr,
    target: Address,
    mut packets: mpsc::Receiver<AssociationPacket>,
    proxy: Arc<ProxySocket<ShadowUdpSocket>>,
    handler: ListenerHandler,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut response = vec![0u8; UDP_PACKET_SIZE];
    let mut response_control = UdpSocketControlData::default();
    response_control.server_session_id = rand::random();
    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            _ = &mut idle => break,
            packet = packets.recv() => {
                let Some(packet) = packet else { break };
                response_control.client_session_id = packet.control.client_session_id;
                response_control.user = packet.control.user;
                let sent = socket.send_to(&packet.payload, &host, port).await?;
                if sent != packet.payload.len() {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "Shadowsocks UDP outbound truncated a datagram"));
                }
                handler.record_upload(&guard, sent as u64);
            }
            received = socket.recv_from_endpoint(&mut response) => {
                let (length, source) = received?;
                if length == 0 {
                    continue;
                }
                let source = source.map(Address::SocketAddress).unwrap_or_else(|| target.clone());
                proxy.send_to_with_ctrl(client, &source, &response_control, &response[..length])
                    .await
                    .map_err(io::Error::other)?;
                response_control.packet_id = response_control.packet_id.wrapping_add(1);
                handler.record_download(&guard, length as u64);
            }
        }
    }
    socket.close().await
}

fn address_parts(address: &Address) -> (String, u16) {
    match address {
        Address::SocketAddress(address) => (address.ip().to_string(), address.port()),
        Address::DomainNameAddress(host, port) => (host.clone(), *port),
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::ShadowsocksUser;
    use shadowsocks::{
        config::ServerConfig,
        net::{ConnectOpts, UdpSocket as ShadowUdpSocket},
        relay::{
            tcprelay::proxy_stream::client::ProxyClientStream,
            udprelay::proxy_socket::{ProxySocket, UdpSocketType},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };

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

    async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
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
            while let Ok((length, peer)) = socket.recv_from(&mut packet).await {
                let _ = socket.send_to(&packet[..length], peer).await;
            }
        });
        (address, task)
    }

    #[test]
    fn sip003_server_plugin_helper() {
        let Ok(remote_host) = std::env::var("SS_REMOTE_HOST") else {
            return;
        };
        let Ok(remote_port) = std::env::var("SS_REMOTE_PORT") else {
            return;
        };
        let local_host = std::env::var("SS_LOCAL_HOST").unwrap();
        let local_port = std::env::var("SS_LOCAL_PORT").unwrap();
        assert_eq!(
            std::env::var("SS_PLUGIN_OPTIONS").as_deref(),
            Ok("integration=true")
        );
        let listener = std::net::TcpListener::bind(format!("{remote_host}:{remote_port}")).unwrap();
        for inbound in listener.incoming() {
            let mut inbound = inbound.unwrap();
            let mut outbound =
                std::net::TcpStream::connect(format!("{local_host}:{local_port}")).unwrap();
            let mut inbound_read = inbound.try_clone().unwrap();
            let mut outbound_write = outbound.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut inbound_read, &mut outbound_write);
            });
            let _ = std::io::copy(&mut outbound, &mut inbound);
        }
    }

    fn plan(port: u16, method: &str, password: &str, mode: &str) -> ShadowsocksListenPlan {
        ShadowsocksListenPlan {
            enabled: true,
            address: "127.0.0.1".into(),
            port,
            method: method.into(),
            password: password.into(),
            mode: mode.into(),
            plugin: None,
            plugin_opts: None,
            plugin_args: Vec::new(),
            plugin_mode: None,
            plugin_startup_timeout: Duration::from_secs(2),
            users: Vec::<ShadowsocksUser>::new(),
            handshake_timeout: Duration::from_secs(2),
            udp_timeout: Duration::from_secs(2),
            max_connections: 16,
            max_udp_associations: 16,
            tag: "test-ss".into(),
        }
    }

    async fn free_port() -> u16 {
        loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
                drop(udp);
                drop(tcp);
                return port;
            }
        }
    }

    #[tokio::test]
    async fn official_clients_interoperate_with_tcp_cipher_families() {
        let (target, target_task) = tcp_echo().await;
        for (method, server_password, client_password, user_key) in [
            ("aes-256-gcm", "classic-password", "classic-password", None),
            ("aes-256-cfb", "stream-password", "stream-password", None),
            (
                "2022-blake3-aes-128-gcm",
                "MDEyMzQ1Njc4OWFiY2RlZg==",
                "MDEyMzQ1Njc4OWFiY2RlZg==",
                None,
            ),
            (
                "2022-blake3-aes-128-gcm",
                "MDEyMzQ1Njc4OWFiY2RlZg==",
                "MDEyMzQ1Njc4OWFiY2RlZg==:YWJjZGVmZ2hpamtsbW5vcA==",
                Some("YWJjZGVmZ2hpamtsbW5vcA=="),
            ),
        ] {
            let port = free_port().await;
            let mut listener_plan = plan(port, method, server_password, "tcp_only");
            if let Some(key) = user_key {
                listener_plan.users.push(ShadowsocksUser {
                    name: "alice".into(),
                    key: key.into(),
                });
            }
            let mut listener = start_shadowsocks_listener(&listener_plan, runtime().await)
                .await
                .unwrap();
            let server_addr = listener.tcp_addr().unwrap();
            let method = method.parse().unwrap();
            let config =
                ServerConfig::new(ServerAddr::SocketAddr(server_addr), client_password, method)
                    .unwrap();
            let transport = TcpStream::connect(server_addr).await.unwrap();
            let mut client = ProxyClientStream::from_stream(
                Context::new_shared(ServerType::Local),
                transport,
                &config,
                Address::SocketAddress(target),
            );
            client.write_all(b"shadowsocks-tcp").await.unwrap();
            let mut response = [0u8; 15];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"shadowsocks-tcp");
            listener.shutdown().await.unwrap();
        }
        target_task.abort();
    }

    #[tokio::test]
    async fn sip003_server_plugin_is_managed_and_forwards_official_client_tcp() {
        let (target, target_task) = tcp_echo().await;
        let port = free_port().await;
        let mut listener_plan = plan(port, "aes-256-gcm", "plugin-password", "tcp_only");
        listener_plan.plugin = Some(
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        listener_plan.plugin_opts = Some("integration=true".into());
        listener_plan.plugin_args = vec![
            "--exact".into(),
            "shadowsocks::tests::sip003_server_plugin_helper".into(),
            "--nocapture".into(),
        ];
        listener_plan.plugin_mode = Some("tcp_only".into());
        let mut listener = start_shadowsocks_listener(&listener_plan, runtime().await)
            .await
            .unwrap();
        let server_addr = listener.tcp_addr().unwrap();
        let mut transport = None;
        for _ in 0..100 {
            match TcpStream::connect(server_addr).await {
                Ok(stream) => {
                    transport = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let config = ServerConfig::new(
            ServerAddr::SocketAddr(server_addr),
            "plugin-password",
            "aes-256-gcm".parse().unwrap(),
        )
        .unwrap();
        let mut client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            transport.expect("SIP003 server plugin did not bind its public TCP address"),
            &config,
            Address::SocketAddress(target),
        );
        client.write_all(b"sip003-server").await.unwrap();
        let mut response = [0u8; 13];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"sip003-server");
        listener.shutdown().await.unwrap();
        target_task.abort();
    }

    #[tokio::test]
    async fn official_client_interoperates_with_udp_and_reuses_association() {
        let (target, target_task) = udp_echo().await;
        for (method, password) in [
            ("aes-128-gcm", "udp-password"),
            ("2022-blake3-aes-128-gcm", "MDEyMzQ1Njc4OWFiY2RlZg=="),
        ] {
            let port = free_port().await;
            let mut listener = start_shadowsocks_listener(
                &plan(port, method, password, "tcp_and_udp"),
                runtime().await,
            )
            .await
            .unwrap();
            let server_addr = listener.udp_addr().unwrap();
            let config = ServerConfig::new(
                ServerAddr::SocketAddr(server_addr),
                password,
                method.parse().unwrap(),
            )
            .unwrap();
            let socket = ShadowUdpSocket::connect_with_opts(&server_addr, &ConnectOpts::default())
                .await
                .unwrap();
            let proxy = ProxySocket::from_socket(
                UdpSocketType::Client,
                Context::new_shared(ServerType::Local),
                &config,
                socket,
            );
            for payload in [b"udp-one".as_slice(), b"udp-two".as_slice()] {
                proxy
                    .send(&Address::SocketAddress(target), payload)
                    .await
                    .unwrap();
                let mut response = [0u8; 128];
                let (length, source, _) = proxy.recv(&mut response).await.unwrap();
                assert_eq!(source, Address::SocketAddress(target));
                assert_eq!(&response[..length], payload);
            }
            listener.shutdown().await.unwrap();
        }
        target_task.abort();
    }
}
