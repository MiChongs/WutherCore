use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::{
    adapter::{
        BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
        prepare_outbound_udp_socket_for_addr, resolve_host_for_direct,
    },
    transport::{Transport, tcp::TcpTransport},
};

#[derive(Debug, Default)]
pub struct DirectOutbound;

impl DirectOutbound {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl OutboundAdapter for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }
    fn protocol(&self) -> &'static str {
        "direct"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplex: false,
        }
    }
    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // DIRECT 出站：解析走 direct-nameserver group，避开 fake-ip / 业务策略；
        // SO_MARK 绕 TUN（与代理出站共用同一套防自循环路径）。
        TcpTransport::for_direct()
            .connect(&ctx.host, ctx.port)
            .await
    }

    /// UDP direct 通道 —— 先解析目标，再按目标地址族创建 socket。
    ///
    /// 不能在不知道目标前固定 bind `0.0.0.0:0`：
    /// * IPv4 socket 无法连接 IPv6 目标；
    /// * 本地/LAN/排除地址不应打 outbound mark，否则会绕错路由表。
    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        let addrs = resolve_host_for_direct(&ctx.host, ctx.port).await?;
        let mut last_err: Option<std::io::Error> = None;
        for addr in addrs {
            match open_direct_udp_socket(addr) {
                Ok((sock, loopback_guard)) => {
                    tracing::debug!(
                        target: "dial::udp",
                        id = ctx.dial_id,
                        host = %ctx.host,
                        port = ctx.port,
                        peer = %addr,
                        local = %sock.local_addr().map(|v| v.to_string()).unwrap_or_else(|_| "-".into()),
                        "direct udp connected",
                    );
                    return Ok(Box::new(DirectUdp {
                        sock: Arc::new(sock),
                        peer: addr,
                        loopback_guard,
                    }));
                }
                Err(e) => {
                    tracing::debug!(
                        target: "dial::udp",
                        id = ctx.dial_id,
                        host = %ctx.host,
                        port = ctx.port,
                        peer = %addr,
                        error = %e,
                        "direct udp candidate failed",
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!(
                    "udp direct: no usable address for {}:{}",
                    ctx.host, ctx.port
                ),
            )
        }))
    }
}

struct DirectUdp {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    loopback_guard: crate::loopback::LoopbackUdpGuard,
}

fn open_direct_udp_socket(
    peer: SocketAddr,
) -> std::io::Result<(UdpSocket, crate::loopback::LoopbackUdpGuard)> {
    let (std_sock, guard) = crate::adapter::create_outbound_udp_socket(peer)?;
    Ok((UdpSocket::from_std(std_sock)?, guard))
}

#[async_trait]
impl UdpSocketLike for DirectUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        if target != self.peer.ip().to_string() || port != self.peer.port() {
            tracing::trace!(
                target: "dial::udp",
                peer = %self.peer,
                send_target = %target,
                send_port = port,
                "send via connected direct udp socket"
            );
        }
        self.sock.send(buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = &self.loopback_guard;
        self.sock.recv(buf).await
    }
}
