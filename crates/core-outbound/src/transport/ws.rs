//! WebSocket 传输层 —— 把 ws/wss 帧封装为字节流。
//!
//! 通过 tokio-tungstenite 完成 HTTP Upgrade，然后包装成 AsyncRead/AsyncWrite。

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use futures::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderValue, protocol::Message,
};

use crate::{
    adapter::BoxedStream,
    transport::{Transport, WsOptions},
};

#[derive(Debug, Clone)]
pub struct WsTransport {
    pub options: WsOptions,
    pub tls: bool,
}

impl WsTransport {
    pub fn new(options: WsOptions, tls: bool) -> Self {
        Self { options, tls }
    }
}

#[async_trait]
impl Transport for WsTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let scheme = if self.tls { "wss" } else { "ws" };
        let host_header = self.options.host.as_deref().unwrap_or(host);
        let path = if self.options.path.is_empty() {
            "/"
        } else {
            self.options.path.as_str()
        };
        let url = format!("{scheme}://{host}:{port}{path}");
        let mut req = url.into_client_request().map_err(io_other)?;
        let headers = req.headers_mut();
        headers.insert(
            "Host",
            HeaderValue::from_str(host_header).map_err(io_other)?,
        );
        for (k, v) in &self.options.headers {
            if let (Ok(name), Ok(val)) = (
                tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }

        let (ws, _resp) = tokio_tungstenite::connect_async(req)
            .await
            .map_err(io_other)?;
        Ok(Box::pin(WsStream::new(ws)))
    }
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

pin_project! {
    pub struct WsStream<S> {
        #[pin]
        inner: tokio_tungstenite::WebSocketStream<S>,
        read_buf: BytesMut,
        eof: bool,
    }
}

impl<S> WsStream<S> {
    pub fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(4096),
            eof: false,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        // 先把 read_buf 中残留的数据塞进 buf
        if !this.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        if *this.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let n = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..n]);
                    if data.len() > n {
                        this.read_buf.extend_from_slice(&data[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Text(t)))) => {
                    let bytes = t.into_bytes();
                    let n = std::cmp::min(buf.remaining(), bytes.len());
                    buf.put_slice(&bytes[..n]);
                    if bytes.len() > n {
                        this.read_buf.extend_from_slice(&bytes[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    *this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Frame(_)))) => continue,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_other(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io_other(e))),
            Poll::Ready(Ok(())) => {}
        }
        let msg = Message::Binary(data.to_vec());
        match this.inner.as_mut().start_send(msg) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(e) => Poll::Ready(Err(io_other(e))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        this.inner.as_mut().poll_flush(cx).map_err(io_other)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        this.inner.as_mut().poll_close(cx).map_err(io_other)
    }
}
