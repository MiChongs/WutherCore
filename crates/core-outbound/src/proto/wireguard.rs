//! WireGuard 用户态客户端与 peer/server 数据面。
//!
//! 密码学、Cookie、握手重传、密钥轮换、重放窗口和计数器全部委托给固定版本
//! `boringtun`。本模块只负责异步 UDP 生命周期、AllowedIPs 路由以及把解密后的
//! IP 包接入真实 `smoltcp` TCP/UDP socket，禁止再出现手写近似握手或永久 Pending。

pub mod config;
mod device;
mod dns;
mod fragment;
mod netstack;
mod server;

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use ipnet::IpNet;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex as AsyncMutex,
};

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike, resolve_host,
};

pub use config::{WireGuardConfig, WireGuardPeerConfig};
use device::WireGuardDevice;
pub use device::WireGuardPeerStats;
use dns::DnsCache;
use netstack::{WireGuardTcpStream, WireGuardUdpSocket};
pub use server::{
    WireGuardReceivedPacket, WireGuardServer, WireGuardServerConfig, WireGuardServerPeerConfig,
    WireGuardServerPeerStats,
};

#[derive(Clone)]
pub struct WireGuardOutbound {
    name: String,
    config: WireGuardConfig,
    device: Arc<AsyncMutex<Option<WireGuardDevice>>>,
    dns_cache: Arc<DnsCache>,
}

impl std::fmt::Debug for WireGuardOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardOutbound")
            .field("name", &self.name)
            .field("local_addresses", &self.config.local_addresses)
            .field("peers", &self.config.peers.len())
            .field("mtu", &self.config.mtu)
            .field("tcp", &self.config.tcp)
            .field("udp", &self.config.udp)
            .field("workers", &self.config.workers)
            .finish_non_exhaustive()
    }
}

impl WireGuardOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
    ) -> Self {
        let peer = WireGuardPeerConfig::new(host, port, peer_public_key);
        Self::from_config(name, WireGuardConfig::new(private_key, peer))
    }

    pub fn from_config(name: impl Into<String>, config: WireGuardConfig) -> Self {
        Self {
            name: name.into(),
            config,
            device: Arc::new(AsyncMutex::new(None)),
            dns_cache: DnsCache::new(),
        }
    }

    pub fn config(&self) -> &WireGuardConfig {
        &self.config
    }

    pub fn with_preshared_key(mut self, key: [u8; 32]) -> Self {
        if let Some(peer) = self.config.peers.first_mut() {
            peer.preshared_key = Some(key);
        }
        self.reset_runtime();
        self
    }

    pub fn with_local_address(mut self, address: IpAddr) -> Self {
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        self.config
            .local_addresses
            .push(IpNet::new(address, prefix).expect("host prefix is valid"));
        self.reset_runtime();
        self
    }

    fn reset_runtime(&mut self) {
        // Builder methods may be called on a clone after another clone has
        // already started. Never reuse a device whose crypto state was built
        // from the previous configuration.
        self.device = Arc::new(AsyncMutex::new(None));
        self.dns_cache = DnsCache::new();
    }

    async fn ensure_device(&self) -> std::io::Result<WireGuardDevice> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(device.clone());
        }
        let device = WireGuardDevice::start(self.config.clone()).await?;
        *guard = Some(device.clone());
        Ok(device)
    }

    async fn resolve_target(
        &self,
        device: &WireGuardDevice,
        host: &str,
        port: u16,
    ) -> std::io::Result<SocketAddr> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return self
                .config
                .route_peer(address)
                .map(|_| SocketAddr::new(address, port))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("wireguard target {host}:{port} is not covered by allowed-ips"),
                    )
                });
        }
        let addresses = if self.config.remote_dns_resolve {
            self.dns_cache.resolve(device, host, port).await?
        } else {
            resolve_host(host, port).await?
        };
        addresses
            .into_iter()
            .find(|address| self.config.route_peer(address.ip()).is_some())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("wireguard target {host}:{port} has no address covered by allowed-ips"),
                )
            })
    }

    pub async fn stats(&self) -> Vec<WireGuardPeerStats> {
        self.device
            .lock()
            .await
            .as_ref()
            .map(WireGuardDevice::stats)
            .unwrap_or_default()
    }
}

#[async_trait]
impl OutboundAdapter for WireGuardOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "wireguard"
    }

    fn capabilities(&self) -> Capabilities {
        let ipv6 = self
            .config
            .local_addresses
            .iter()
            .any(|address| address.addr().is_ipv6())
            && self
                .config
                .peers
                .iter()
                .flat_map(|peer| &peer.allowed_ips)
                .any(|network| network.addr().is_ipv6());
        Capabilities {
            tcp: self.config.tcp,
            udp: self.config.udp,
            ipv6,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, context: DialContext) -> std::io::Result<BoxedStream> {
        if !self.config.tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "wireguard TCP is disabled by network configuration",
            ));
        }
        let device = self.ensure_device().await?;
        let target = self
            .resolve_target(&device, &context.host, context.port)
            .await?;
        let mut stream = device.stack().open_tcp(target)?;
        device.stack().notify();
        stream
            .wait_connected(device.config().connect_timeout)
            .await?;
        Ok(Box::pin(WireGuardTcpAssociation {
            stream,
            _device: device,
        }))
    }

    async fn dial_udp(&self, context: DialContext) -> std::io::Result<BoxedUdp> {
        if !self.config.udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "wireguard UDP is disabled by network configuration",
            ));
        }
        let device = self.ensure_device().await?;
        let target = self
            .resolve_target(&device, &context.host, context.port)
            .await?;
        let socket =
            device
                .stack()
                .open_udp(target, context.host, device.config().udp_idle_timeout)?;
        device.stack().notify();
        Ok(Box::new(WireGuardUdpAssociation {
            socket,
            _device: device,
        }))
    }
}

struct WireGuardTcpAssociation {
    stream: WireGuardTcpStream,
    // Keep the tunnel driver alive even if a runtime reload removes the
    // originating outbound adapter while this stream is still active.
    _device: WireGuardDevice,
}

impl AsyncRead for WireGuardTcpAssociation {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for WireGuardTcpAssociation {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct WireGuardUdpAssociation {
    socket: WireGuardUdpSocket,
    _device: WireGuardDevice,
}

#[async_trait]
impl UdpSocketLike for WireGuardUdpAssociation {
    async fn send_to(&self, buffer: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        self.socket.send_to(buffer, target, port).await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.socket.recv_from(buffer).await
    }

    async fn close(&self) -> std::io::Result<()> {
        self.socket.close();
        Ok(())
    }
}

pub(super) fn io_err(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::{
        noise::Tunn,
        x25519::{PublicKey, StaticSecret},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn capability_claims_match_enabled_networks() {
        let mut config = WireGuardConfig::new(
            [1; 32],
            WireGuardPeerConfig::new("127.0.0.1", 51_820, [2; 32]),
        );
        config.local_addresses = vec!["10.0.0.2/32".parse().unwrap()];
        config.udp = false;
        let outbound = WireGuardOutbound::from_config("wg", config);
        let capabilities = outbound.capabilities();
        assert!(capabilities.tcp);
        assert!(!capabilities.udp);
        assert!(!capabilities.ipv6);
    }

    #[tokio::test]
    async fn missing_local_address_fails_before_network_io() {
        let outbound = WireGuardOutbound::new("wg", "127.0.0.1", 51_820, [1; 32], [2; 32]);
        let error = match outbound.ensure_device().await {
            Ok(_) => panic!("invalid WireGuard config unexpectedly started"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("local address"));
    }

    #[tokio::test]
    async fn multi_peer_routes_over_independent_crypto_workers() {
        let client_private = [89; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
        let server_a_private = [91; 32];
        let server_b_private = [93; 32];
        let server_a_public = *PublicKey::from(&StaticSecret::from(server_a_private)).as_bytes();
        let server_b_public = *PublicKey::from(&StaticSecret::from(server_b_private)).as_bytes();

        let server_a = WireGuardServer::bind(WireGuardServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_a_private,
            WireGuardServerPeerConfig::new(client_public, vec!["10.9.0.2/32".parse().unwrap()]),
        ))
        .await
        .unwrap();
        let server_b = WireGuardServer::bind(WireGuardServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_b_private,
            WireGuardServerPeerConfig::new(client_public, vec!["10.9.0.2/32".parse().unwrap()]),
        ))
        .await
        .unwrap();

        let endpoint_a = server_a.local_addr().unwrap();
        let endpoint_b = server_b.local_addr().unwrap();
        let mut peer_a = WireGuardPeerConfig::new(
            endpoint_a.ip().to_string(),
            endpoint_a.port(),
            server_a_public,
        );
        peer_a.allowed_ips = vec!["10.1.0.0/16".parse().unwrap()];
        let mut peer_b = WireGuardPeerConfig::new(
            endpoint_b.ip().to_string(),
            endpoint_b.port(),
            server_b_public,
        );
        peer_b.allowed_ips = vec!["10.2.0.0/16".parse().unwrap()];
        let mut config = WireGuardConfig::new(client_private, peer_a);
        config.peers.push(peer_b);
        config.local_addresses = vec!["10.9.0.2/32".parse().unwrap()];
        config.workers = 2;
        let device = WireGuardDevice::start(config).await.unwrap();

        let udp_a = device
            .stack()
            .open_udp(
                "10.1.2.3:9001".parse().unwrap(),
                "10.1.2.3".into(),
                std::time::Duration::from_secs(30),
            )
            .unwrap();
        let udp_b = device
            .stack()
            .open_udp(
                "10.2.3.4:9002".parse().unwrap(),
                "10.2.3.4".into(),
                std::time::Duration::from_secs(30),
            )
            .unwrap();
        udp_a.send_to(b"peer-a", "10.1.2.3", 9001).await.unwrap();
        udp_b.send_to(b"peer-b", "10.2.3.4", 9002).await.unwrap();

        let packet_a =
            tokio::time::timeout(std::time::Duration::from_secs(5), server_a.recv_packet())
                .await
                .unwrap()
                .unwrap();
        let packet_b =
            tokio::time::timeout(std::time::Duration::from_secs(5), server_b.recv_packet())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            Tunn::dst_address(&packet_a.packet),
            Some("10.1.2.3".parse().unwrap())
        );
        assert_eq!(
            Tunn::dst_address(&packet_b.packet),
            Some("10.2.3.4".parse().unwrap())
        );

        udp_a.close();
        udp_b.close();
        drop(device);
        server_a.close().await;
        server_b.close().await;
    }

    #[tokio::test]
    async fn tcp_udp_ipv4_ipv6_and_fragmentation_cross_real_tunnel() {
        let client_private = [81; 32];
        let server_private = [83; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();
        let server = Arc::new(
            WireGuardServer::bind(WireGuardServerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                server_private,
                WireGuardServerPeerConfig::new(
                    client_public,
                    vec![
                        "10.99.0.2/32".parse().unwrap(),
                        "fd99::2/128".parse().unwrap(),
                    ],
                ),
            ))
            .await
            .unwrap(),
        );
        let endpoint = server.local_addr().unwrap();
        let mut peer =
            WireGuardPeerConfig::new(endpoint.ip().to_string(), endpoint.port(), server_public);
        peer.allowed_ips = vec![
            "10.99.0.0/24".parse().unwrap(),
            "fd99::/64".parse().unwrap(),
        ];
        let mut client_config = WireGuardConfig::new(client_private, peer);
        client_config.local_addresses = vec![
            "10.99.0.2/32".parse().unwrap(),
            "fd99::2/128".parse().unwrap(),
        ];
        client_config.mtu = 1_280;
        client_config.remote_dns_resolve = true;
        client_config.dns = vec!["10.99.0.1".parse().unwrap()];
        let outbound = WireGuardOutbound::from_config("wg-e2e", client_config);

        let mut service_config =
            WireGuardConfig::new([85; 32], WireGuardPeerConfig::new("127.0.0.1", 1, [87; 32]));
        service_config.local_addresses = vec![
            "10.99.0.1/32".parse().unwrap(),
            "fd99::1/128".parse().unwrap(),
        ];
        service_config.mtu = 1_280;
        let service_stack = netstack::StackShared::new(&service_config).unwrap();
        let services = service_stack.open_echo_services(32_080, 32_081).unwrap();
        let cancellation = CancellationToken::new();
        let bridge_server = server.clone();
        let bridge_stack = service_stack.clone();
        let bridge_cancellation = cancellation.clone();
        let bridge = tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_millis(2));
            loop {
                tokio::select! {
                    _ = bridge_cancellation.cancelled() => break,
                    received = bridge_server.recv_packet() => {
                        let received = received.unwrap();
                        bridge_stack.inject(received.packet).unwrap();
                    }
                    _ = timer.tick() => {}
                }
                for packet in bridge_stack.poll_echo_and_drain(services) {
                    bridge_server.send_packet(&packet).await.unwrap();
                }
            }
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut stream = outbound
                .dial_tcp(DialContext::tcp("10.99.0.1", 32_080))
                .await?;
            let udp = outbound
                .dial_udp(DialContext::udp("echo.wireguard.test", 32_081))
                .await?;
            let udp6 = outbound
                .dial_udp(DialContext::udp("fd99::1", 32_081))
                .await?;
            // Active associations must own the driver lifetime independently
            // of registry reloads dropping the originating adapter.
            drop(outbound);
            let tcp_payload = vec![0x5a; 48 * 1_024];
            stream.write_all(&tcp_payload).await?;
            // `shutdown` must flush all buffered data before emitting FIN; do
            // not call `flush` here so the half-close path is exercised.
            stream.shutdown().await?;
            let mut echoed = vec![0; tcp_payload.len()];
            stream.read_exact(&mut echoed).await?;
            assert_eq!(echoed, tcp_payload);
            let mut after_fin = [0_u8; 1];
            assert_eq!(stream.read(&mut after_fin).await?, 0);

            let udp_payload = vec![0x6b; 4_096];
            assert_eq!(
                udp.send_to(&udp_payload, "echo.wireguard.test", 32_081)
                    .await?,
                udp_payload.len()
            );
            let mut echoed = vec![0; udp_payload.len()];
            let received = udp.recv_from(&mut echoed).await?;
            assert_eq!(&echoed[..received], udp_payload);
            udp.close().await?;

            let udp6_payload = vec![0x7c; 3_072];
            udp6.send_to(&udp6_payload, "fd99::1", 32_081).await?;
            let mut echoed6 = vec![0; udp6_payload.len()];
            let received6 = udp6.recv_from(&mut echoed6).await?;
            assert_eq!(&echoed6[..received6], udp6_payload);
            udp6.close().await?;
            Ok::<_, std::io::Error>(())
        })
        .await;
        cancellation.cancel();
        bridge.await.unwrap();
        server.close().await;
        result
            .expect("WireGuard full data-plane test timed out")
            .unwrap();
    }
}
