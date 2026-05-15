//! gRPC (gun) 传输层 —— 与 mihomo `transport/gun/gun.go` 等价。
//!
//! 把 VLESS/VMess/Trojan 的字节流封装在 gRPC 双向流中：
//! 1. TLS+ALPN h2
//! 2. POST `/<service-name>/Tun` （或自定义）
//! 3. Content-Type: application/grpc
//! 4. body 是一系列 gRPC frame：`flag(1) || length(4 BE) || data`
//!    - flag=0：普通帧
//! 5. 双向都按这个 frame 格式 read/write

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Request as HttpRequest};
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
pub struct GrpcOptions {
    pub enabled: bool,
    pub service_name: String,
    pub user_agent: String,
    pub host: String, // ":authority"
}

pub struct GrpcTransport {
    opts: GrpcOptions,
    tls: TlsOptions,
    sender: AsyncMutex<Option<hyper::client::conn::http2::SendRequest<GrpcBody>>>,
}

impl GrpcTransport {
    pub fn new(opts: GrpcOptions, tls: TlsOptions) -> Self {
        Self {
            opts,
            tls,
            sender: AsyncMutex::new(None),
        }
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        // 复用 / 建立 h2 连接
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

        let service = if self.opts.service_name.is_empty() {
            "GunService"
        } else {
            &self.opts.service_name
        };
        let path = format!("/{service}/Tun");
        let authority = if self.opts.host.is_empty() {
            host.to_string()
        } else {
            self.opts.host.clone()
        };
        let user_agent = if self.opts.user_agent.is_empty() {
            format!("grpc-go/{}", env!("CARGO_PKG_VERSION"))
        } else {
            self.opts.user_agent.clone()
        };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let body = GrpcBody::Stream(rx);
        let uri = format!("https://{authority}{path}");
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(uri.as_str())
            .body(body)
            .map_err(|e| io_err(format!("grpc request: {e}")))?;
        req.headers_mut().insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/grpc"),
        );
        req.headers_mut().insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_str(&user_agent).map_err(|e| io_err(format!("ua: {e}")))?,
        );
        req.headers_mut().insert(
            HeaderName::from_static("te"),
            HeaderValue::from_static("trailers"),
        );

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("grpc send_request: {e}")))?;
        if !resp.status().is_success() {
            return Err(io_err(format!("grpc server status {}", resp.status())));
        }
        Ok(Box::pin(GrpcStream {
            tx,
            rx_body: resp.into_body(),
            recv_buf: BytesMut::new(),
            plain_buf: BytesMut::new(),
        }))
    }
}

async fn init_h2(
    host: &str,
    port: u16,
    tls_opts: &TlsOptions,
) -> std::io::Result<hyper::client::conn::http2::SendRequest<GrpcBody>> {
    let mut tls = tls_opts.clone();
    tls.enabled = true;
    if !tls.alpn.iter().any(|a| a == "h2") {
        tls.alpn.push("h2".into());
    }
    let stream = TlsTransport::new(tls).connect(host, port).await?;
    let io = HyperTokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http2::handshake::<_, _, GrpcBody>(TokioExecutor, io)
        .await
        .map_err(|e| io_err(format!("grpc h2 handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

pub enum GrpcBody {
    Stream(mpsc::Receiver<Vec<u8>>),
}

impl HyperBody for GrpcBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.get_mut() {
            GrpcBody::Stream(rx) => match rx.poll_recv(cx) {
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(d))))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

struct GrpcStream {
    tx: mpsc::Sender<Vec<u8>>,
    rx_body: Incoming,
    recv_buf: BytesMut,  // 来自网络的原始 gRPC frame 字节
    plain_buf: BytesMut, // 已解析的明文 payload
}

impl GrpcStream {
    /// 尝试从 recv_buf 解一个 gRPC frame
    /// frame: flag(1) || length(4 BE) || data(length)
    fn try_decode_one(&mut self) -> bool {
        if self.recv_buf.len() < 5 {
            return false;
        }
        let length = u32::from_be_bytes([
            self.recv_buf[1],
            self.recv_buf[2],
            self.recv_buf[3],
            self.recv_buf[4],
        ]) as usize;
        if self.recv_buf.len() < 5 + length {
            return false;
        }
        let _flag = self.recv_buf[0];
        self.recv_buf.advance(5);
        let data = self.recv_buf.split_to(length);
        // gun 协议在 data 前还有一个 protobuf field marker 0x0a + varint len
        // mihomo 实现里 read 时跳过这两个字节（具体 0x0a + 1 byte len，因 payload < 128）
        let payload = if data.len() >= 2 && data[0] == 0x0a {
            // 解析 varint len（最多 5 字节）
            let mut idx = 1usize;
            let mut len_val: usize = 0;
            let mut shift = 0;
            while idx < data.len() {
                let b = data[idx];
                len_val |= ((b & 0x7f) as usize) << shift;
                idx += 1;
                if (b & 0x80) == 0 {
                    break;
                }
                shift += 7;
                if shift > 28 {
                    return false; // 过长 varint
                }
            }
            if data.len() < idx + len_val {
                return false;
            }
            &data[idx..idx + len_val]
        } else {
            &data[..]
        };
        self.plain_buf.extend_from_slice(payload);
        true
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.plain_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.plain_buf.len());
                buf.put_slice(&self.plain_buf[..n]);
                self.plain_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.try_decode_one() {
                continue;
            }
            // 读更多
            match Pin::new(&mut self.rx_body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        self.recv_buf.extend_from_slice(&data);
                        continue;
                    }
                    Err(_) => return Poll::Ready(Ok(())),
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io_err(format!("grpc body: {e}"))));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 编码为 gRPC frame: flag(0) || length(4 BE) || (0x0a varint(len) data)
        let mut payload = Vec::with_capacity(data.len() + 5);
        payload.push(0x0a);
        write_varint(&mut payload, data.len() as u64);
        payload.extend_from_slice(data);
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0u8); // flag
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        let n = data.len();
        let tx = self.tx.clone();
        let mut fut = Box::pin(async move { tx.send(frame).await });
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

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/* ---------------- Hyper IO 适配（与 h2_transport 等价） ---------------- */

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
    fn varint_round_trip() {
        for v in [0u64, 1, 127, 128, 16383, 16384, 1 << 30] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut idx = 0;
            let mut decoded: u64 = 0;
            let mut shift = 0;
            loop {
                let b = buf[idx];
                idx += 1;
                decoded |= ((b & 0x7f) as u64) << shift;
                if (b & 0x80) == 0 {
                    break;
                }
                shift += 7;
            }
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn options_default() {
        let o = GrpcOptions::default();
        assert!(!o.enabled);
        assert_eq!(o.service_name, "");
    }
}
