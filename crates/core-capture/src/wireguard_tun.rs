//! WireGuard 服务端与 capture 用户态 TCP/IP 栈之间的包设备适配。

use std::sync::Arc;

use async_trait::async_trait;
use core_outbound::proto::wireguard::WireGuardServer;

use crate::{TunIo, TunIoError};

/// 将已经过 WireGuard 认证/解密的裸 IP 包暴露成 [`TunIo`]。
///
/// 读取方向是对端 → WutherCore netstack；写入方向由服务端按目标地址最长前缀
/// 匹配回对应 peer，并完成加密与 UDP 发送。
pub struct WireGuardTunIo {
    server: Arc<WireGuardServer>,
    name: String,
    mtu: u32,
}

impl std::fmt::Debug for WireGuardTunIo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardTunIo")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl WireGuardTunIo {
    pub fn new(server: Arc<WireGuardServer>, name: impl Into<String>, mtu: u32) -> Self {
        Self {
            server,
            name: name.into(),
            mtu,
        }
    }

    pub fn server(&self) -> &Arc<WireGuardServer> {
        &self.server
    }
}

#[async_trait]
impl TunIo for WireGuardTunIo {
    async fn read_packet(&self, buffer: &mut [u8]) -> Result<usize, TunIoError> {
        let received = self.server.recv_packet().await.map_err(TunIoError::Read)?;
        if received.packet.len() > buffer.len() {
            return Err(TunIoError::Read(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "WireGuard packet length {} exceeds TUN buffer {}",
                    received.packet.len(),
                    buffer.len()
                ),
            )));
        }
        buffer[..received.packet.len()].copy_from_slice(&received.packet);
        Ok(received.packet.len())
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<usize, TunIoError> {
        self.server
            .send_packet(packet)
            .await
            .map_err(TunIoError::Write)?;
        Ok(packet.len())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn is_preconfigured(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<(), TunIoError> {
        self.server.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use boringtun::x25519::{PublicKey, StaticSecret};
    use core_outbound::{
        DialContext, OutboundAdapter,
        proto::wireguard::{
            WireGuardConfig, WireGuardOutbound, WireGuardPeerConfig, WireGuardServerConfig,
            WireGuardServerPeerConfig,
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{CapturePlan, EimNatTable, NatTable, NetstackDispatcher, noop_ipset_provider};

    #[tokio::test]
    #[ignore = "timing-sensitive end-to-end test; run explicitly"]
    async fn authenticated_peer_reaches_runtime_tcp_and_udp() {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = tcp_listener.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });

        let udp_echo = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_target = udp_echo.local_addr().unwrap();
        let udp_task = {
            let socket = udp_echo.clone();
            tokio::spawn(async move {
                let mut buffer = [0_u8; 2_048];
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..length], peer).await.unwrap();
            })
        };

        let client_private = [41; 32];
        let server_private = [43; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();
        let server = Arc::new(
            WireGuardServer::bind(WireGuardServerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                server_private,
                WireGuardServerPeerConfig::new(
                    client_public,
                    vec!["10.77.0.2/32".parse().unwrap()],
                ),
            ))
            .await
            .unwrap(),
        );

        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: server
route: {preset: direct}
"#,
        )
        .unwrap();
        let runtime = Arc::new(core_runtime::Runtime::build(plan.clone()).unwrap());
        let mut capture_plan = CapturePlan::from_config(&plan.capture).unwrap();
        capture_plan.mtu = 1_420;
        capture_plan.allow_loopback_destination = true;
        let dispatcher = Arc::new(NetstackDispatcher::new(
            capture_plan.clone(),
            Arc::new(NatTable::default()),
            Arc::new(EimNatTable::new(capture_plan.udp_timeout)),
            runtime
                .resolver
                .fake_pool()
                .unwrap_or_else(|| Arc::new(core_resolver::FakeIpPool::default())),
            runtime.dns_service.clone(),
            noop_ipset_provider(),
        ));
        let device = Arc::new(WireGuardTunIo::new(
            server.clone(),
            "wireguard-runtime-test",
            1_420,
        ));
        let handles = dispatcher.start(device, runtime.clone());

        let endpoint = server.local_addr().unwrap();
        let mut peer =
            WireGuardPeerConfig::new(endpoint.ip().to_string(), endpoint.port(), server_public);
        peer.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        let mut client_config = WireGuardConfig::new(client_private, peer);
        client_config.local_addresses = vec!["10.77.0.2/32".parse().unwrap()];
        let client = WireGuardOutbound::from_config("wireguard-runtime-test", client_config);

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut tcp = client
                .dial_tcp(DialContext::tcp(
                    tcp_target.ip().to_string(),
                    tcp_target.port(),
                ))
                .await
                .unwrap();
            tcp.write_all(b"wireguard runtime tcp").await.unwrap();
            tcp.flush().await.unwrap();
            let mut echoed = [0_u8; 21];
            tcp.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"wireguard runtime tcp");

            let udp = client
                .dial_udp(DialContext::udp(
                    udp_target.ip().to_string(),
                    udp_target.port(),
                ))
                .await
                .unwrap();
            udp.send_to(
                b"wireguard runtime udp",
                &udp_target.ip().to_string(),
                udp_target.port(),
            )
            .await
            .unwrap();
            let mut buffer = [0_u8; 128];
            let length = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"wireguard runtime udp");
            udp.close().await.unwrap();
        })
        .await
        .expect("WireGuard runtime TCP/UDP integration timed out");

        handles.stop();
        server.close().await;
        runtime.shutdown().await;
        tcp_echo.abort();
        udp_task.abort();
        drop(udp_echo);
    }
}
