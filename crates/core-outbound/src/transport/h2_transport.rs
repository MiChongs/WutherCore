//! HTTP/2 传输层 —— 与 mihomo `transport/vmess/h2.go` (StreamH2Conn) 等价。
//!
//! 把 VLESS/VMess/Trojan 的字节流封装在 HTTP/2 双向流中：
//! 1. TLS+ALPN h2 连接
//! 2. 客户端发起 PUT/POST 请求，body 是双向 stream
//! 3. 协议字节作为 request body 写入 / response body 读出

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request as HttpRequest};
use http_body_util::BodyExt;
use hyper::body::{Body as HyperBody, Frame, Incoming};
use parking_lot::Mutex as PlMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, mpsc},
};

use crate::{
    adapter::BoxedStream,
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

#[derive(Debug, Clone, Default)]
pub struct H2Options {
    pub enabled: bool,
    pub host: Vec<String>, // ":authority" 候选；mihomo 随机选
    pub path: String,
    pub method: String, // 默认 PUT
}

pub struct H2Transport {
    opts: H2Options,
    tls: TlsOptions,
    sender: AsyncMutex<Option<hyper::client::conn::http2::SendRequest<H2Body>>>,
}

impl H2Transport {
    pub fn new(opts: H2Options, tls: TlsOptions) -> Self {
        Self {
            opts,
            tls,
            sender: AsyncMutex::new(None),
        }
    }
}

#[async_trait]
impl Transport for H2Transport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        // 1) TLS+ALPN h2 + hyper http2 handshake（缓存 sender）
        let mut sender = {
            let mut guard = self.sender.lock().await;
            if let Some(s) = guard.as_ref() {
                if !s.is_closed() {
                    s.clone()
                } else {
                    let s = init_h2(host, port, &self.tls).await?;
                    *guard = Some(s.clone());
                    s
                }
            } else {
                let s = init_h2(host, port, &self.tls).await?;
                *guard = Some(s.clone());
                s
            }
        };

        // 2) 选 authority + path
        let authority = if !self.opts.host.is_empty() {
            self.opts.host[rand::random::<usize>() % self.opts.host.len()].clone()
        } else {
            host.to_string()
        };
        let path = if self.opts.path.is_empty() {
            "/".to_string()
        } else {
            self.opts.path.clone()
        };
        let method = if self.opts.method.is_empty() {
            "PUT".to_string()
        } else {
            self.opts.method.clone()
        };

        // 3) 构造 request：body 是双向 channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let body = H2Body::Stream(rx);
        let uri = format!("https://{authority}{path}");
        let req = HttpRequest::builder()
            .method(method.as_str())
            .uri(uri.as_str())
            .body(body)
            .map_err(|e| io_err(format!("h2 request: {e}")))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("h2 send_request: {e}")))?;
        if !resp.status().is_success() {
            return Err(io_err(format!("h2 server status {}", resp.status())));
        }
        let resp_body = resp.into_body();
        Ok(Box::pin(H2Stream {
            tx,
            rx_body: resp_body,
            leftover: Vec::new(),
            _authority: authority,
        }))
    }
}

async fn init_h2(
    host: &str,
    port: u16,
    tls_opts: &TlsOptions,
) -> std::io::Result<hyper::client::conn::http2::SendRequest<H2Body>> {
    // 构造启用 ALPN h2 的 TlsOptions
    let mut tls = tls_opts.clone();
    tls.enabled = true;
    if !tls.alpn.iter().any(|a| a == "h2") {
        tls.alpn.push("h2".into());
    }
    let stream = TlsTransport::new(tls).connect(host, port).await?;
    let io = HyperTokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http2::handshake::<_, _, H2Body>(TokioExecutor, io)
        .await
        .map_err(|e| io_err(format!("h2 handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

pub enum H2Body {
    Stream(mpsc::Receiver<Vec<u8>>),
}

impl HyperBody for H2Body {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.get_mut() {
            H2Body::Stream(rx) => match rx.poll_recv(cx) {
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(d))))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

struct H2Stream {
    tx: mpsc::Sender<Vec<u8>>,
    rx_body: Incoming,
    leftover: Vec<u8>,
    _authority: String,
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.leftover.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.leftover.len());
            buf.put_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.rx_body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let n = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..n]);
                    if data.len() > n {
                        self.leftover.extend_from_slice(&data[n..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Err(_) => Poll::Ready(Ok(())),
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io_err(format!("h2 body: {e}")))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let chunk = data.to_vec();
        let n = chunk.len();
        let tx = self.tx.clone();
        let mut fut = Box::pin(async move { tx.send(chunk).await });
        match std::future::Future::poll(fut.as_mut(), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/* ---------------- Hyper IO 适配 ---------------- */

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
    fn options_default() {
        let o = H2Options::default();
        assert!(!o.enabled);
        assert_eq!(o.path, "");
        assert_eq!(o.method, "");
    }

    #[test]
    fn h2_transport_construct() {
        let opts = H2Options {
            enabled: true,
            host: vec!["www.example.com".into()],
            path: "/".into(),
            method: "PUT".into(),
        };
        let _t = H2Transport::new(opts, TlsOptions::default());
    }
}
