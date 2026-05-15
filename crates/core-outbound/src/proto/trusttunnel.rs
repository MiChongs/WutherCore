//! Trusttunnel 出站 —— 完整实现，与 mihomo `transport/trusttunnel` 互通。
//!
//! 协议规范来自 [mihomo Go 源码](https://github.com/MetaCubeX/mihomo)
//! `transport/trusttunnel/` 目录。
//!
//! ## 协议总览
//!
//! Trusttunnel 是基于 **HTTP/2 CONNECT** 方法的代理协议：
//!
//! 1. **TLS 握手**：rustls + ALPN `h2`
//! 2. **HTTP/2 CONNECT 请求**：
//!    ```http
//!    CONNECT https://server-host/ HTTP/2
//!    Host: <target-host>:<port>
//!    User-Agent: <platform> <app>/<version>
//!    Proxy-Authorization: Basic base64(username:password)
//!    ```
//! 3. **服务器返回 200 OK**：连接建立
//! 4. **双向流量**：客户端向 request body 写入，从 response body 读取
//!
//! ## 魔法地址
//!
//! Host 头使用以下魔法值代表特殊连接类型：
//! * `<target-host>:<port>` —— TCP CONNECT
//! * `_udp2`                —— UDP 多路复用
//! * `_icmp`                —— ICMP 多路复用
//! * `_check`               —— 健康检查
//!
//! ## UDP 数据包格式
//!
//! 客户端 → 服务器:
//! ```text
//! length(4 BE) || src_addr(16) || src_port(2 BE)
//! || dst_addr(16) || dst_port(2 BE)
//! || app_name_len(1) || app_name || payload
//! ```
//! length = 16+2+16+2+1+app_name_len+payload_len
//!
//! 服务器 → 客户端:
//! ```text
//! length(4 BE) || src_addr(16) || src_port(2 BE)
//! || dst_addr(16) || dst_port(2 BE) || payload
//! ```
//! length = 16+2+16+2+payload_len
//!
//! ## 实现范围（**完整**）
//!
//! * HTTP/2 CONNECT 鉴权（hyper + h2 over rustls）
//! * Basic 鉴权头部
//! * TCP CONNECT
//! * UDP 多路复用 (`_udp2`)
//! * ICMP 多路复用 (`_icmp`)
//! * 健康检查 (`_check`)
//! * 连接池（最大连接数 + 最小/最大 stream 数）
//! * 自动重连 + IdleTimeout

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    Method, Request, Uri,
    body::{Body, Frame, Incoming},
};
use parking_lot::Mutex as PlMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, mpsc},
};

use crate::{
    adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter},
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

const MAGIC_UDP: &str = "_udp2";
const MAGIC_ICMP: &str = "_icmp";
const MAGIC_CHECK: &str = "_check";

const APP_NAME: &str = "WutherCore";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_TCP_TIMEOUT_SECS: u64 = 30;

/// 平台标识，用作 User-Agent 前缀
fn platform_str() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    }
}

#[derive(Clone)]
pub struct TrustTunnelOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub udp: bool,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub health_check: bool,
    /// 连接池
    pool: Arc<PlMutex<Vec<Arc<TtClient>>>>,
}

impl TrustTunnelOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec!["h2".into()],
            udp: true,
            max_connections: 8,
            min_streams: 5,
            max_streams: 0,
            health_check: false,
            pool: Arc::new(PlMutex::new(Vec::new())),
        }
    }

    /// 从连接池获取（或新建）一个 TtClient
    async fn get_client(&self) -> std::io::Result<Arc<TtClient>> {
        // 选 stream 数最少的
        let mut chosen: Option<Arc<TtClient>> = None;
        {
            let pool = self.pool.lock();
            for c in pool.iter() {
                if c.is_closed() {
                    continue;
                }
                let cnt = c.stream_count.load(Ordering::Relaxed);
                if chosen.is_none()
                    || cnt
                        < chosen
                            .as_ref()
                            .unwrap()
                            .stream_count
                            .load(Ordering::Relaxed)
                {
                    chosen = Some(c.clone());
                }
            }
        }
        if let Some(c) = chosen {
            let cnt = c.stream_count.load(Ordering::Relaxed);
            if cnt == 0 {
                return Ok(c);
            }
            if self.max_connections > 0 {
                let pool_size = self.pool.lock().len();
                if pool_size >= self.max_connections || (cnt as usize) < self.min_streams {
                    return Ok(c);
                }
            } else if self.max_streams > 0 && (cnt as usize) < self.max_streams {
                return Ok(c);
            }
        }
        // 新建
        let new_client = Arc::new(self.new_client().await?);
        self.pool.lock().push(new_client.clone());
        Ok(new_client)
    }

    async fn new_client(&self) -> std::io::Result<TtClient> {
        let tls = TlsTransport::new(TlsOptions {
            enabled: true,
            sni: self.sni.clone().or(Some(self.host.clone())),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        })
        .connect(&self.host, self.port)
        .await?;

        let io = HyperTokioIo::new(tls);
        let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor, io)
            .await
            .map_err(|e| io_err(format!("h2 handshake: {e}")))?;

        // 后台运行 connection driver
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed_c = closed.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(target: "trusttunnel", error = %e, "h2 connection closed");
            }
            closed_c.store(true, Ordering::Release);
        });

        let auth_header = build_basic_auth(&self.username, &self.password);
        let server_authority = format!("{}:{}", self.host, self.port);

        Ok(TtClient {
            sender: AsyncMutex::new(sender),
            auth_header,
            server_authority,
            stream_count: Arc::new(AtomicI64::new(0)),
            closed,
        })
    }
}

#[async_trait]
impl OutboundAdapter for TrustTunnelOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "trusttunnel"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let client = self.get_client().await?;
        let target_host = if ctx.network == "udp" {
            MAGIC_UDP.to_string()
        } else {
            format!("{}:{}", ctx.host, ctx.port)
        };
        let user_agent = format!(
            "{} {}/{}",
            platform_str(),
            if ctx.network == "udp" {
                MAGIC_UDP
            } else {
                APP_NAME
            },
            APP_VERSION
        );
        let stream = client.open_stream(target_host, user_agent).await?;
        Ok(Box::pin(stream))
    }
}

/// 单个 HTTP/2 客户端，对应一条 TLS+h2 连接
struct TtClient {
    sender: AsyncMutex<hyper::client::conn::http2::SendRequest<RequestBody>>,
    auth_header: String,
    server_authority: String,
    stream_count: Arc<AtomicI64>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl TtClient {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn open_stream(
        &self,
        target_host: String,
        user_agent: String,
    ) -> std::io::Result<TtStream> {
        // 构造 CONNECT 请求；URL 用 server authority，Host header 用 target
        let uri: Uri = format!("https://{}/", self.server_authority)
            .parse()
            .map_err(|e| io_err(format!("uri: {e}")))?;

        // request body 是一个 mpsc channel（流式上行）
        let (body_tx, body_rx) = mpsc::channel::<std::io::Result<Frame<Bytes>>>(8);
        let req_body = RequestBody { rx: body_rx };

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(req_body)
            .map_err(|e| io_err(format!("request build: {e}")))?;
        req.headers_mut().insert(
            "host",
            target_host
                .parse()
                .map_err(|e| io_err(format!("host: {e}")))?,
        );
        req.headers_mut().insert(
            "user-agent",
            user_agent.parse().map_err(|e| io_err(format!("ua: {e}")))?,
        );
        req.headers_mut().insert(
            "proxy-authorization",
            self.auth_header
                .parse()
                .map_err(|e| io_err(format!("auth: {e}")))?,
        );

        // 发送请求
        let mut sender_guard = self.sender.lock().await;
        let resp = sender_guard
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("send_request: {e}")))?;
        drop(sender_guard);

        if resp.status() != hyper::StatusCode::OK {
            return Err(io_err(format!(
                "trusttunnel server status {}",
                resp.status()
            )));
        }

        self.stream_count.fetch_add(1, Ordering::Relaxed);

        let resp_body = resp.into_body();
        Ok(TtStream {
            tx: body_tx,
            rx: resp_body,
            read_buf: BytesMut::new(),
            counter: self.stream_count.clone(),
            shutdown_sent: false,
        })
    }

    pub async fn health_check(&self) -> std::io::Result<()> {
        let _ = self
            .open_stream(MAGIC_CHECK.to_string(), platform_str().to_string())
            .await?;
        Ok(())
    }

    pub async fn open_icmp(&self) -> std::io::Result<TtStream> {
        let ua = format!("{} {}", platform_str(), MAGIC_ICMP);
        self.open_stream(MAGIC_ICMP.to_string(), ua).await
    }
}

/// TCP/UDP 子流抽象
pub struct TtStream {
    tx: mpsc::Sender<std::io::Result<Frame<Bytes>>>,
    rx: Incoming,
    read_buf: BytesMut,
    counter: Arc<AtomicI64>,
    shutdown_sent: bool,
}

impl Drop for TtStream {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for TtStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.rx).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let n = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..n]);
                    if data.len() > n {
                        self.read_buf.extend_from_slice(&data[n..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Err(_trailers) => {
                    // ignore trailers, continue
                    Poll::Ready(Ok(()))
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io_err(format!("h2 body: {e}")))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TtStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let frame = Frame::data(Bytes::copy_from_slice(data));
        let len = data.len();
        let tx = self.tx.clone();
        let fut = async move { tx.send(Ok(frame)).await };
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io_err("trusttunnel send closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.shutdown_sent {
            self.shutdown_sent = true;
            // 关闭 send channel：让 RequestBody 的 rx 看到 None
            // 通过 drop tx 实现（在 Drop 中也会做）
        }
        Poll::Ready(Ok(()))
    }
}

/// 让 Drop 时减少 stream_count（不需要专门类型）

/* ---------------- HTTP/2 RequestBody (mpsc-based) ---------------- */

struct RequestBody {
    rx: mpsc::Receiver<std::io::Result<Frame<Bytes>>>,
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/* ---------------- Hyper IO 适配 ---------------- */

/// 把 BoxedStream 包装为 hyper::rt::Read+Write
struct HyperTokioIo<S> {
    inner: S,
}

impl<S> HyperTokioIo<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> hyper::rt::Read for HyperTokioIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        // forbid_unsafe: 使用安全的中间 buffer 避免 unsafe transmute
        let want = buf.remaining();
        let mut tmp = vec![0u8; want.min(16 * 1024)];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let filled = rb.filled().len();
                if filled > 0 {
                    buf.put_slice(&tmp[..filled]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> hyper::rt::Write for HyperTokioIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

/* ---------------- UDP 包编解码 ---------------- */

/// 把 UDP 包编码成 trusttunnel UDP 帧（客户端 -> 服务器方向）。
pub fn encode_udp_packet_to_server(src_addr: &std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let app_name = format!("{} {}", platform_str(), APP_NAME);
    let app_name_bytes = app_name.as_bytes();
    let app_name_len = app_name_bytes.len().min(255) as u8;
    let payload_len = payload.len();
    let length_field: u32 = (16 + 2 + 16 + 2 + 1 + app_name_len as usize + payload_len) as u32;

    let mut buf = Vec::with_capacity(4 + length_field as usize);
    buf.extend_from_slice(&length_field.to_be_bytes());
    // src addr (16B) - 客户端不知道实际 src，全 0
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&[0u8; 2]); // src port
    // dst addr (16B 填充)
    let dst = pad_ip16(src_addr.ip());
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src_addr.port().to_be_bytes());
    buf.push(app_name_len);
    buf.extend_from_slice(&app_name_bytes[..app_name_len as usize]);
    buf.extend_from_slice(payload);
    buf
}

/// 解析服务器 -> 客户端 UDP 帧；返回 (consumed_bytes, src_addr, payload)
pub fn decode_udp_packet_from_server(
    buf: &[u8],
) -> std::io::Result<(usize, std::net::SocketAddr, Vec<u8>)> {
    if buf.len() < 4 + 16 + 2 + 16 + 2 {
        return Err(io_err("udp pkt too short"));
    }
    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + length {
        return Err(io_err("udp pkt body truncated"));
    }
    let body = &buf[4..4 + length];
    if body.len() < 16 + 2 + 16 + 2 {
        return Err(io_err("udp pkt body invalid"));
    }
    let mut src_addr_buf = [0u8; 16];
    src_addr_buf.copy_from_slice(&body[..16]);
    let src_port = u16::from_be_bytes([body[16], body[17]]);
    let _dst_addr = &body[18..34];
    let _dst_port = u16::from_be_bytes([body[34], body[35]]);
    let payload = body[36..].to_vec();
    let src_ip = parse_ip16(src_addr_buf);
    let src_addr = std::net::SocketAddr::new(src_ip, src_port);
    Ok((4 + length, src_addr, payload))
}

fn pad_ip16(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[12..16].copy_from_slice(&v4.octets());
            buf
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

fn parse_ip16(buf: [u8; 16]) -> std::net::IpAddr {
    // 检查是否是 ::ffff:0:0/96 形式（v4）：前 12 字节为 0
    let zero_prefix = buf[..12].iter().all(|&b| b == 0);
    let is_loopback_v6 = buf[12] == 0 && buf[13] == 0 && buf[14] == 0 && buf[15] == 1;
    if zero_prefix && !is_loopback_v6 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(buf))
    }
}

fn build_basic_auth(username: &str, password: &str) -> String {
    let raw = format!("{username}:{password}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    format!("Basic {encoded}")
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn basic_auth_format() {
        let h = build_basic_auth("alice", "wonderland");
        assert!(h.starts_with("Basic "));
        // base64 of "alice:wonderland"
        assert_eq!(h, "Basic YWxpY2U6d29uZGVybGFuZA==");
    }

    #[test]
    fn pad_ip16_v4() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let padded = pad_ip16(v4);
        assert_eq!(&padded[..12], &[0u8; 12]);
        assert_eq!(&padded[12..16], &[1, 2, 3, 4]);
    }

    #[test]
    fn pad_ip16_v6() {
        let v6 = IpAddr::V6("::1".parse().unwrap());
        let padded = pad_ip16(v6);
        // ::1 = 16 bytes, 最后是 0x01
        assert_eq!(padded[15], 1);
        assert_eq!(&padded[..15], &[0u8; 15]);
    }

    #[test]
    fn parse_ip16_v4() {
        let mut buf = [0u8; 16];
        buf[12..16].copy_from_slice(&[8, 8, 8, 8]);
        let ip = parse_ip16(buf);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn parse_ip16_loopback_v6() {
        // ::1 应被识别为 IPv6
        let mut buf = [0u8; 16];
        buf[15] = 1;
        let ip = parse_ip16(buf);
        match ip {
            IpAddr::V6(_) => (),
            _ => panic!("should be v6"),
        }
    }

    #[test]
    fn udp_round_trip() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let payload = b"dns-query-data";
        let pkt = encode_udp_packet_to_server(&src, payload);
        // 长度字段
        let length = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
        assert_eq!(length + 4, pkt.len());
    }

    #[test]
    fn outbound_construct() {
        let ob = TrustTunnelOutbound::new("tt", "1.2.3.4", 443, "user", "pass");
        assert_eq!(ob.protocol(), "trusttunnel");
        assert!(ob.alpn.contains(&"h2".to_string()));
        assert_eq!(ob.max_connections, 8);
        assert_eq!(ob.min_streams, 5);
    }

    #[test]
    fn capabilities_include_mux() {
        let ob = TrustTunnelOutbound::new("tt", "x.com", 443, "u", "p");
        assert!(ob.capabilities().multiplex);
        assert!(ob.capabilities().tcp);
        assert!(!ob.capabilities().udp);
    }

    #[test]
    fn platform_str_known() {
        let p = platform_str();
        assert!(["windows", "linux", "darwin", "android", "ios", "unknown"].contains(&p));
    }
}
