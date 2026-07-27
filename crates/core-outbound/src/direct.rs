use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::net::UdpSocket;

use crate::{
    adapter::{
        BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
        resolve_host_for_direct,
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
                    let resolved = DashMap::new();
                    resolved.insert(cache_key(&ctx.host, ctx.port), addr);
                    return Ok(Box::new(DirectUdp {
                        sock: Arc::new(sock),
                        resolved,
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
    resolved: DashMap<(String, u16), SocketAddr>,
    loopback_guard: crate::loopback::LoopbackUdpGuard,
}

fn open_direct_udp_socket(
    peer: SocketAddr,
) -> std::io::Result<(UdpSocket, crate::loopback::LoopbackUdpGuard)> {
    let (std_sock, guard) = crate::adapter::create_outbound_udp_association(peer)?;
    Ok((UdpSocket::from_std(std_sock)?, guard))
}

#[async_trait]
impl UdpSocketLike for DirectUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        let family_is_v4 = self.sock.local_addr()?.is_ipv4();
        let key = cache_key(target, port);
        if let Some(address) = self.resolved.get(&key).map(|entry| *entry)
            && address.is_ipv4() == family_is_v4
        {
            match self.sock.send_to(buf, address).await {
                Ok(length) => return Ok(length),
                Err(_) => {
                    self.resolved.remove(&key);
                }
            }
        }
        let addresses = resolve_host_for_direct(target, port).await?;
        let mut last_error = None;
        for address in addresses
            .into_iter()
            .filter(|address| address.is_ipv4() == family_is_v4)
        {
            match self.sock.send_to(buf, address).await {
                Ok(length) => {
                    self.resolved.insert(key, address);
                    return Ok(length);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no usable UDP address for {target}:{port}"),
            )
        }))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = &self.loopback_guard;
        self.sock.recv_from(buf).await.map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Option<SocketAddr>)> {
        let (length, source) = self.sock.recv_from(buf).await?;
        Ok((length, Some(source)))
    }

    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.sock.local_addr().map(Some)
    }

    fn supports_multi_target(&self) -> bool {
        true
    }
}

fn cache_key(host: &str, port: u16) -> (String, u16) {
    (
        host.trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_udp_association_keeps_one_local_endpoint_for_multiple_targets() {
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        let outbound = DirectOutbound
            .dial_udp(DialContext::udp("127.0.0.1", first_addr.port()))
            .await
            .unwrap();
        let local = outbound.local_addr().unwrap().unwrap();

        outbound
            .send_to(b"one", "127.0.0.1", first_addr.port())
            .await
            .unwrap();
        outbound
            .send_to(b"two", "127.0.0.1", second_addr.port())
            .await
            .unwrap();

        let mut buffer = [0u8; 8];
        let (first_len, first_peer) = first.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..first_len], b"one");
        assert_eq!(first_peer.port(), local.port());
        let (second_len, second_peer) = second.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..second_len], b"two");
        assert_eq!(second_peer.port(), local.port());
        first.send_to(b"r1", first_peer).await.unwrap();
        second.send_to(b"r2", second_peer).await.unwrap();

        let mut sources = std::collections::HashSet::new();
        for _ in 0..2 {
            let (_, source) = outbound.recv_from_endpoint(&mut buffer).await.unwrap();
            sources.insert(source.unwrap());
        }
        assert_eq!(sources, [first_addr, second_addr].into_iter().collect());
    }
}
