use std::time::{Duration, Instant};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::adapter::{apply_outbound_mark_for_addr, resolve_host, BoxedStream};
use crate::transport::Transport;

#[derive(Debug, Default)]
pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let started = Instant::now();
        debug!(target: "dial::tcp", %host, port, "begin");
        let addrs = resolve_host(host, port).await?;
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
/// SO_MARK 让 SYN 包带 mark，配合 `ip rule fwmark <out_mark> lookup main`
/// 直接走主路由表，绕开 TUN 自身路由表，避免 dial 时的"connect IP 又被 TUN 截走"的死循环。
pub async fn marked_connect(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let std_stream = tokio::task::spawn_blocking(move || -> std::io::Result<std::net::TcpStream> {
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        apply_outbound_mark_for_addr(&sock, addr)?;
        sock.connect_timeout(&addr.into(), timeout)?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    })
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("spawn_blocking: {e}")))??;
    TcpStream::from_std(std_stream)
}
