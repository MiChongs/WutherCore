//! XHTTP Client —— 完整实现 stream-one / stream-up / packet-up 三种模式。
//!
//! 与 mihomo `transport/xhttp/client.go` 等价。
//!
//! 客户端基于 hyper http2 客户端 + TLS（rustls + ALPN h2）。
//!
//! - **stream-one**：一条 POST 长连接，request body 与 response body 同时双向流式传输
//! - **stream-up**：上行 POST + 独立下行 GET（两条 stream，session_id 关联）
//! - **packet-up**：上行多次 POST（packet 写入 PacketUpWriter 自动批量），下行 GET 长连接

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as HyperBody, Frame};
use parking_lot::Mutex as PlMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, mpsc},
};

use super::{
    config::Config,
    conn::{PipeWriter, WaitReader, WaitReaderHandle, XConn, new_session_id},
    request::{PreparedRequest, fill_download_request, fill_packet_request, fill_stream_request},
};
use crate::{
    adapter::BoxedStream,
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

/// 统一 body：支持流式（mpsc）或一次性（单 chunk）
pub enum XhttpBody {
    Stream(RequestBody),
    OneShot(OneShotBody),
    Empty,
}

impl HyperBody for XhttpBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.get_mut() {
            XhttpBody::Stream(s) => Pin::new(s).poll_frame(cx),
            XhttpBody::OneShot(o) => Pin::new(o).poll_frame(cx),
            XhttpBody::Empty => Poll::Ready(None),
        }
    }
}

/// XHTTP 客户端 —— 一个 outbound 实例对应一个 Client，可生成多个 dial 的子流
pub struct XhttpClient {
    pub cfg: Arc<Config>,
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    /// 缓存的 hyper http2 sender（首次 dial 建立）
    h2_sender: AsyncMutex<Option<hyper::client::conn::http2::SendRequest<XhttpBody>>>,
}

impl XhttpClient {
    pub fn new(cfg: Config, host: impl Into<String>, port: u16) -> Self {
        Self {
            cfg: Arc::new(cfg),
            host: host.into(),
            port,
            sni: None,
            insecure: false,
            alpn: vec!["h2".into()],
            h2_sender: AsyncMutex::new(None),
        }
    }

    /// 获取（必要时建立）hyper http2 sender
    async fn get_or_init_h2(
        &self,
    ) -> std::io::Result<hyper::client::conn::http2::SendRequest<XhttpBody>> {
        let mut guard = self.h2_sender.lock().await;
        if let Some(s) = guard.as_ref() {
            if !s.is_closed() {
                return Ok(s.clone());
            }
        }
        let tls = TlsTransport::new(TlsOptions {
            enabled: true,
            sni: self.sni.clone().or(Some(self.host.clone())),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        })
        .connect(&self.host, self.port)
        .await?;
        let io = HyperTokioIo::new(tls);
        let (sender, conn) =
            hyper::client::conn::http2::handshake::<_, _, XhttpBody>(TokioExecutor, io)
                .await
                .map_err(|e| io_err(format!("h2 handshake: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        *guard = Some(sender.clone());
        Ok(sender)
    }

    /// 客户端入口：根据模式分发
    pub async fn dial(&self, has_reality: bool) -> std::io::Result<BoxedStream> {
        match self.cfg.effective_mode(has_reality) {
            "stream-one" => self.dial_stream_one().await,
            "stream-up" => self.dial_stream_up().await,
            "packet-up" => self.dial_packet_up().await,
            other => Err(io_err(format!("xhttp mode {other} not supported"))),
        }
    }

    async fn dial_stream_one(&self) -> std::io::Result<BoxedStream> {
        let mut sender = self.get_or_init_h2().await?;
        let url = format!(
            "https://{}{}",
            self.host_authority(),
            self.cfg.normalized_path()
        );
        let mut prep = PreparedRequest::new(
            self.cfg.normalized_uplink_http_method(),
            &url,
            &self.host_authority(),
        );
        fill_stream_request(&self.cfg, &mut prep, "").map_err(io_err)?;

        // 上行 body channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let body = XhttpBody::Stream(RequestBody { rx, eof: false });
        let req = build_h2_request_unified(prep, body)?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("send_request: {e}")))?;
        if !resp.status().is_success() {
            return Err(io_err(format!(
                "xhttp stream-one bad status: {}",
                resp.status()
            )));
        }
        let body = resp.into_body();

        let reader = WaitReader::new();
        reader.handle().set(body);
        let writer = PipeWriter::new(tx);
        Ok(Box::pin(XConn::new(reader, writer)))
    }

    async fn dial_stream_up(&self) -> std::io::Result<BoxedStream> {
        let mut sender_up = self.get_or_init_h2().await?;
        let mut sender_down = sender_up.clone();
        let session = new_session_id();

        // 下行 GET
        let download_cfg: &Config = self.cfg.download_config.as_deref().unwrap_or(&self.cfg);
        let download_url = format!(
            "https://{}{}",
            self.host_authority(),
            download_cfg.normalized_path()
        );
        let mut dprep = PreparedRequest::new("GET", &download_url, &self.host_authority());
        fill_download_request(download_cfg, &mut dprep, &session).map_err(io_err)?;
        let dreq = build_h2_request_unified(dprep, XhttpBody::Empty)?;
        let dresp = sender_down
            .send_request(dreq)
            .await
            .map_err(|e| io_err(format!("download send_request: {e}")))?;
        if !dresp.status().is_success() {
            return Err(io_err(format!(
                "xhttp stream-up download bad status: {}",
                dresp.status()
            )));
        }
        let dbody = dresp.into_body();
        let reader = WaitReader::new();
        reader.handle().set(dbody);

        // 上行 POST stream
        let upload_url = format!(
            "https://{}{}",
            self.host_authority(),
            self.cfg.normalized_path()
        );
        let mut uprep = PreparedRequest::new(
            self.cfg.normalized_uplink_http_method(),
            &upload_url,
            &self.host_authority(),
        );
        fill_stream_request(&self.cfg, &mut uprep, &session).map_err(io_err)?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let ureq =
            build_h2_request_unified(uprep, XhttpBody::Stream(RequestBody { rx, eof: false }))?;
        // 异步发送 upload；不阻塞 dial 返回
        tokio::spawn(async move {
            let _ = sender_up.send_request(ureq).await;
        });

        let writer = PipeWriter::new(tx);
        Ok(Box::pin(XConn::new(reader, writer)))
    }

    async fn dial_packet_up(&self) -> std::io::Result<BoxedStream> {
        let sender = self.get_or_init_h2().await?;
        let session = new_session_id();

        // 下行 GET
        let download_cfg: &Config = self.cfg.download_config.as_deref().unwrap_or(&self.cfg);
        let download_url = format!(
            "https://{}{}",
            self.host_authority(),
            download_cfg.normalized_path()
        );
        let mut dprep = PreparedRequest::new("GET", &download_url, &self.host_authority());
        fill_download_request(download_cfg, &mut dprep, &session).map_err(io_err)?;
        let dreq = build_h2_request_unified(dprep, XhttpBody::Empty)?;
        let mut sender_d = sender.clone();
        let dresp = sender_d
            .send_request(dreq)
            .await
            .map_err(|e| io_err(format!("download send_request: {e}")))?;
        if !dresp.status().is_success() {
            return Err(io_err(format!(
                "xhttp packet-up download bad status: {}",
                dresp.status()
            )));
        }
        let dbody = dresp.into_body();
        let reader = WaitReader::new();
        reader.handle().set(dbody);

        // 上行 PacketUpWriter
        let writer = PacketUpWriter::new(self.cfg.clone(), session, self.host_authority(), sender)?;
        Ok(Box::pin(XConn::new(reader, writer)))
    }

    fn host_authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// PacketUpWriter 内部状态（用 Arc 包装以避免 unsafe lifetime extension）
struct PacketUpInner {
    cfg: Arc<Config>,
    session_id: String,
    host: String,
    sender: AsyncMutex<hyper::client::conn::http2::SendRequest<XhttpBody>>,
    sc_max_each_post_bytes: usize,
    sc_min_posts_interval_ms: super::config::Range,
    seq: AtomicU64,
    pending_buf: PlMutex<Vec<u8>>,
    flush_err: PlMutex<Option<std::io::Error>>,
}

impl PacketUpInner {
    async fn flush(self: Arc<Self>) -> std::io::Result<()> {
        let buf = {
            let mut g = self.pending_buf.lock();
            std::mem::take(&mut *g)
        };
        if buf.is_empty() {
            return Ok(());
        }
        self.write_one(&buf).await
    }

    async fn write_one(self: Arc<Self>, data: &[u8]) -> std::io::Result<()> {
        let url = format!("https://{}{}", self.host, self.cfg.normalized_path());
        let mut prep =
            PreparedRequest::new(self.cfg.normalized_uplink_http_method(), &url, &self.host);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let seq_s = seq.to_string();
        fill_packet_request(&self.cfg, &mut prep, &self.session_id, &seq_s, data)
            .map_err(io_err)?;

        let body_bytes = prep.body.clone().unwrap_or_default();
        let body_len = body_bytes.len();
        let body = OneShotBody::new(body_bytes);
        let mut req = build_h2_request_with_oneshot(prep, body)?;
        if body_len == 0 {
            req.headers_mut()
                .insert("content-length", http::HeaderValue::from_static("0"));
        }
        let mut sender = self.sender.lock().await;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("packet send_request: {e}")))?;
        drop(sender);
        if !resp.status().is_success() {
            return Err(io_err(format!(
                "xhttp packet-up bad status: {}",
                resp.status()
            )));
        }
        // 消费 body
        let _ = resp.into_body().collect().await;
        Ok(())
    }
}

/// PacketUpWriter —— 与 mihomo PacketUpWriter 等价
pub struct PacketUpWriter {
    inner: Arc<PacketUpInner>,
    pending_flush: Option<Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>>,
}

impl PacketUpWriter {
    pub fn new(
        cfg: Arc<Config>,
        session_id: String,
        host: String,
        sender: hyper::client::conn::http2::SendRequest<XhttpBody>,
    ) -> std::io::Result<Self> {
        let max_each = cfg
            .normalized_sc_max_each_post_bytes()
            .map_err(io_err)?
            .rand();
        let interval = cfg.normalized_sc_min_posts_interval_ms().map_err(io_err)?;
        Ok(Self {
            inner: Arc::new(PacketUpInner {
                cfg,
                session_id,
                host,
                sender: AsyncMutex::new(sender),
                sc_max_each_post_bytes: max_each,
                sc_min_posts_interval_ms: interval,
                seq: AtomicU64::new(0),
                pending_buf: PlMutex::new(Vec::new()),
                flush_err: PlMutex::new(None),
            }),
            pending_flush: None,
        })
    }
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(e) = self.inner.flush_err.lock().take() {
            return Poll::Ready(Err(e));
        }
        let should_flush;
        {
            let mut buf = self.inner.pending_buf.lock();
            buf.extend_from_slice(data);
            should_flush = buf.len() >= self.inner.sc_max_each_post_bytes;
        }
        if !should_flush && self.pending_flush.is_none() {
            return Poll::Ready(Ok(data.len()));
        }
        // 启动 flush future（如果没在飞）
        if self.pending_flush.is_none() {
            let inner = self.inner.clone();
            self.pending_flush = Some(Box::pin(async move { inner.flush().await }));
        }
        // poll flush future
        let fut = self.pending_flush.as_mut().unwrap();
        match Future::poll(fut.as_mut(), cx) {
            Poll::Ready(Ok(())) => {
                self.pending_flush = None;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(e)) => {
                self.pending_flush = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_flush.is_none() {
            let inner = self.inner.clone();
            self.pending_flush = Some(Box::pin(async move { inner.flush().await }));
        }
        let fut = self.pending_flush.as_mut().unwrap();
        match Future::poll(fut.as_mut(), cx) {
            Poll::Ready(r) => {
                self.pending_flush = None;
                Poll::Ready(r)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/* ---------------- hyper Body & request helpers ---------------- */

pub struct RequestBody {
    rx: mpsc::Receiver<Vec<u8>>,
    eof: bool,
}

impl HyperBody for RequestBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        if self.eof {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(data))))),
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct OneShotBody {
    data: Option<Bytes>,
}

impl OneShotBody {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Some(Bytes::from(data)),
        }
    }
}

impl HyperBody for OneShotBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.data.take() {
            Some(d) if !d.is_empty() => Poll::Ready(Some(Ok(Frame::data(d)))),
            _ => Poll::Ready(None),
        }
    }
}

fn build_h2_request_unified(
    prep: PreparedRequest,
    body: XhttpBody,
) -> std::io::Result<hyper::Request<XhttpBody>> {
    let mut req = hyper::Request::builder()
        .method(prep.method.as_str())
        .uri(prep.url.as_str())
        .body(body)
        .map_err(|e| io_err(format!("request build: {e}")))?;
    apply_prepared_headers(&prep, &mut req);
    Ok(req)
}

fn build_h2_request_with_oneshot(
    prep: PreparedRequest,
    body: OneShotBody,
) -> std::io::Result<hyper::Request<XhttpBody>> {
    build_h2_request_unified(prep, XhttpBody::OneShot(body))
}

fn apply_prepared_headers<B>(prep: &PreparedRequest, req: &mut hyper::Request<B>) {
    use http::{HeaderName, HeaderValue};
    if let Ok(v) = HeaderValue::from_str(&prep.host) {
        req.headers_mut().insert(HeaderName::from_static("host"), v);
    }
    for (k, v) in &prep.headers {
        if let (Ok(name), Ok(val)) = (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v)) {
            req.headers_mut().insert(name, val);
        }
    }
    if !prep.cookies.is_empty() {
        let joined = prep
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(val) = HeaderValue::from_str(&joined) {
            req.headers_mut()
                .insert(HeaderName::from_static("cookie"), val);
        }
    }
}

/* ---------------- Hyper IO 适配（与 trusttunnel 一致） ---------------- */

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

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_authority_default_port() {
        let cfg = Config::default();
        let c = XhttpClient::new(cfg, "example.com", 443);
        assert_eq!(c.host_authority(), "example.com");
    }

    #[test]
    fn host_authority_custom_port() {
        let cfg = Config::default();
        let c = XhttpClient::new(cfg, "example.com", 8443);
        assert_eq!(c.host_authority(), "example.com:8443");
    }

    #[test]
    fn xhttp_client_default_alpn() {
        let cfg = Config::default();
        let c = XhttpClient::new(cfg, "x", 443);
        assert_eq!(c.alpn, vec!["h2"]);
    }
}
