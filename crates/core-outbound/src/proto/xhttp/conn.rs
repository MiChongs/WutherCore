//! XHTTP Conn —— `writer + reader + onClose` 抽象，与 mihomo `transport/xhttp/conn.go` 等价。
//!
//! 客户端三种模式都返回这个统一的 BoxedStream-like Conn：
//! - **stream-one** / **stream-up**：reader = response body, writer = request body pipe
//! - **packet-up**：reader = response body, writer = PacketUpWriter（序列化 POST）

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use hyper::body::{Body as HyperBody, Incoming};
use parking_lot::Mutex as PlMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

/// WaitReader：阻塞 read 直到底层 reader 被 set
pub struct WaitReader {
    inner: Arc<PlMutex<WaitState>>,
    notify: Arc<tokio::sync::Notify>,
}

enum WaitState {
    Pending,
    Ready(Incoming, BytesMut),
    Error(std::io::Error),
    Closed,
}

impl WaitReader {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PlMutex::new(WaitState::Pending)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn handle(&self) -> WaitReaderHandle {
        WaitReaderHandle {
            inner: self.inner.clone(),
            notify: self.notify.clone(),
        }
    }
}

#[derive(Clone)]
pub struct WaitReaderHandle {
    inner: Arc<PlMutex<WaitState>>,
    notify: Arc<tokio::sync::Notify>,
}

impl WaitReaderHandle {
    pub fn set(&self, body: Incoming) {
        let mut g = self.inner.lock();
        if matches!(*g, WaitState::Closed) {
            return;
        }
        *g = WaitState::Ready(body, BytesMut::new());
        self.notify.notify_waiters();
    }

    pub fn fail(&self, err: std::io::Error) {
        let mut g = self.inner.lock();
        if matches!(*g, WaitState::Closed | WaitState::Ready(_, _)) {
            return;
        }
        *g = WaitState::Error(err);
        self.notify.notify_waiters();
    }

    pub fn close(&self) {
        let mut g = self.inner.lock();
        *g = WaitState::Closed;
        self.notify.notify_waiters();
    }
}

impl AsyncRead for WaitReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut g = self.inner.lock();
        // 取出 incoming 的可变借用 + leftover，需要小心处理
        // 这里把 state 的 match 拆分以便释放锁
        match &mut *g {
            WaitState::Pending => {
                drop(g);
                let notify = self.notify.clone();
                let mut fut = Box::pin(async move { notify.notified().await });
                match Future::poll(fut.as_mut(), cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => Poll::Ready(Ok(())),
                }
            }
            WaitState::Ready(incoming, leftover) => {
                if !leftover.is_empty() {
                    let n = std::cmp::min(buf.remaining(), leftover.len());
                    buf.put_slice(&leftover[..n]);
                    leftover.advance(n);
                    return Poll::Ready(Ok(()));
                }
                match Pin::new(incoming).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => {
                            let n = std::cmp::min(buf.remaining(), data.len());
                            buf.put_slice(&data[..n]);
                            if data.len() > n {
                                leftover.extend_from_slice(&data[n..]);
                            }
                            Poll::Ready(Ok(()))
                        }
                        Err(_) => Poll::Ready(Ok(())),
                    },
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("xhttp body: {e}"),
                    ))),
                    Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
                    Poll::Pending => Poll::Pending,
                }
            }
            WaitState::Error(e) => {
                let kind = e.kind();
                let msg = e.to_string();
                Poll::Ready(Err(std::io::Error::new(kind, msg)))
            }
            WaitState::Closed => Poll::Ready(Ok(())),
        }
    }
}

/// PipeWriter：把 write 转发到 mpsc channel（被 hyper request body 消费）
pub struct PipeWriter {
    tx: mpsc::Sender<Vec<u8>>,
    closed: bool,
}

impl PipeWriter {
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx, closed: false }
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let chunk = data.to_vec();
        let n = chunk.len();
        let tx = self.tx.clone();
        let mut fut = Box::pin(async move { tx.send(chunk).await });
        match Future::poll(fut.as_mut(), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// XConn：组合 reader + writer + on_close
pub struct XConn<R, W> {
    pub reader: R,
    pub writer: W,
    pub on_close: Option<Box<dyn FnOnce() + Send>>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> XConn<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            on_close: None,
        }
    }

    pub fn with_on_close(mut self, f: impl FnOnce() + Send + 'static) -> Self {
        self.on_close = Some(Box::new(f));
        self
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for XConn<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for XConn<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl<R, W> Drop for XConn<R, W> {
    fn drop(&mut self) {
        if let Some(f) = self.on_close.take() {
            f();
        }
    }
}

/// 生成 16-byte hex session id
pub fn new_session_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
