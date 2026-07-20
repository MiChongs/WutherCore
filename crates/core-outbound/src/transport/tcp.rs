use std::time::{Duration, Instant};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::{
    adapter::{
        BoxedStream, apply_outbound_mark_for_addr, protect_socket, resolve_host,
        resolve_host_for_direct,
    },
    loopback::{LoopbackTcpGuard, TrackedTcpStream, register_tcp},
    transport::Transport,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpTransport {
    /// 若为 true，解析走 `resolve_host_for_direct`（mihomo `DirectHostResolver`），
    /// 避开 fake-ip / 业务 policy；用于 DIRECT 出站。
    for_direct: bool,
}

impl TcpTransport {
    /// DIRECT 出站专用：解析走 direct-nameserver group。
    pub fn for_direct() -> Self {
        Self { for_direct: true }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let started = Instant::now();
        debug!(target: "dial::tcp", %host, port, for_direct = self.for_direct, "begin");
        let addrs = if self.for_direct {
            resolve_host_for_direct(host, port).await?
        } else {
            resolve_host(host, port).await?
        };
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        for addr in &addrs {
            tried += 1;
            let t = Instant::now();
            match marked_connect(*addr, Duration::from_secs(10)).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    info!(
                        target: "dial::tcp",
                        %host, port,
                        peer = %addr,
                        attempt = tried,
                        connect_ms = t.elapsed().as_millis() as u64,
                        total_ms = started.elapsed().as_millis() as u64,
                        "connected",
                    );
                    return Ok(Box::pin(s));
                }
                Err(e) => {
                    debug!(
                        target: "dial::tcp",
                        %host, port,
                        peer = %addr,
                        attempt = tried,
                        error = %e,
                        "connect attempt failed",
                    );
                    last_err = Some(e);
                }
            }
        }
        let total_ms = started.elapsed().as_millis() as u64;
        warn!(
            target: "dial::tcp",
            %host, port,
            tried, total_ms,
            "all candidates failed",
        );
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("connect: no usable address for {host}:{port}"),
            )
        }))
    }
}

/// 用 socket2 创建 socket → 应用 SO_MARK → connect（同步，带 spawn_blocking 包裹）→ 包成 tokio TcpStream。
///
/// SO_MARK 让 SYN 包带 mark，配合 root TUN 启动时探测出的默认网络路由表，
/// 绕开 TUN 自身路由表，避免 dial 时的"connect IP 又被 TUN 截走"的死循环。
pub async fn marked_connect(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> std::io::Result<TrackedTcpStream<TcpStream>> {
    let (stream, guard) = marked_connect_raw(addr, timeout).await?;
    Ok(TrackedTcpStream::with_guard(stream, guard))
}

/// 与 [`marked_connect`] 相同地应用 socket 保护、路由标记和接口绑定，
/// 但把裸 Tokio TCP 流与自抓回环 guard 分开返回。需要接管真实 TCP 类型的
/// REALITY TLS 引擎使用此入口，并必须把 guard 保留到最终流被丢弃。
pub async fn marked_connect_raw(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> std::io::Result<(TcpStream, LoopbackTcpGuard)> {
    let std_stream =
        tokio::task::spawn_blocking(move || -> std::io::Result<std::net::TcpStream> {
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            protect_socket(&sock)?;
            apply_outbound_mark_for_addr(&sock, addr)?;
            // 跨平台 OS 级出站接口绑定 —— Linux/Android SO_BINDTODEVICE +
            // Windows IP_UNICAST_IF + macOS IP_BOUND_IF。让 socket 绕开
            // TUN 默认路由直走物理出口，杜绝 dial 自循环。
            crate::adapter::bind_outbound_socket(&sock, addr)?;
            sock.connect_timeout(&addr.into(), timeout)?;
            sock.set_nonblocking(true)?;
            Ok(sock.into())
        })
        .await
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("spawn_blocking: {e}"))
        })??;
    let stream = TcpStream::from_std(std_stream)?;
    let local = stream.local_addr()?;
    Ok((stream, register_tcp(local)))
}
