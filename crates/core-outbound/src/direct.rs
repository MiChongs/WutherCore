use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::adapter::{
    apply_outbound_mark, resolve_host, BoxedStream, BoxedUdp, Capabilities, DialContext,
    OutboundAdapter, UdpSocketLike,
};
use crate::transport::tcp::TcpTransport;
use crate::transport::Transport;

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
        // 走 TcpTransport：自带 RPKernel resolver + SO_MARK 绕 TUN。
        TcpTransport::default().connect(&ctx.host, ctx.port).await
    }

    /// UDP direct 通道 —— `tokio::net::UdpSocket` bind 到 0.0.0.0/任意端口，
    /// 配合 SO_MARK 让出包绕开 TUN 路由表。每次 send_to 都现场解析目标 host。
    async fn dial_udp(&self, _ctx: DialContext) -> std::io::Result<BoxedUdp> {
        // 用 std::net::UdpSocket 创建 + apply_outbound_mark + 转 tokio
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        // SO_MARK 让回包路由绕开 TUN（与 TCP outbound 一致）
        if let Err(e) = apply_outbound_mark(&socket2::SockRef::from(&sock)) {
            tracing::debug!(target: "dial::udp", error = %e, "apply SO_MARK failed (non-fatal)");
        }
        sock.set_nonblocking(true)?;
        let async_sock = UdpSocket::from_std(sock)?;
        Ok(Box::new(DirectUdp {
            sock: Arc::new(async_sock),
            peer: tokio::sync::OnceCell::new(),
        }))
    }
}

struct DirectUdp {
    sock: Arc<UdpSocket>,
    /// 缓存第一次 send_to 解析的 peer：同 5-tuple 后续包不再 resolve。
    /// 配合 TUN 侧 [`UdpSessionTable`]——同一个 session 只走 1 次 DNS 解析。
    peer: tokio::sync::OnceCell<SocketAddr>,
}

#[async_trait]
impl UdpSocketLike for DirectUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        // 已缓存 peer → 直接 send_to，跳过 resolver
        if let Some(addr) = self.peer.get() {
            return self.sock.send_to(buf, *addr).await;
        }
        // 第一次：resolver 解析（IP literal 直接返回；hostname 走 RPKernel resolver）
        let addrs = resolve_host(target, port).await?;
        let mut last_err: Option<std::io::Error> = None;
        for addr in addrs {
            match self.sock.send_to(buf, addr).await {
                Ok(n) => {
                    let _ = self.peer.set(addr);
                    return Ok(n);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no usable target")
        }))
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (n, _from): (usize, SocketAddr) = self.sock.recv_from(buf).await?;
        Ok(n)
    }
}
