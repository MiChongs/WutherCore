//! XHTTP 双向流适配。
//!
//! HTTP/1.1、HTTP/2 与 HTTP/3 的响应体最终都汇入一个有界 channel，
//! 因而这里不依赖具体 HTTP 实现。写端同样先取得 channel permit 再复制
//! 调用者的缓冲区，严格遵守 `AsyncWrite::poll_write` 的重试语义并提供背压。

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
};

/// 可跨异步任务复制的 I/O 错误。
#[derive(Clone, Debug)]
pub struct IoFailure {
    kind: std::io::ErrorKind,
    message: Arc<str>,
}

impl IoFailure {
    /// 创建可复制的 I/O 错误。
    pub fn new(kind: std::io::ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Arc::from(message.into()),
        }
    }

    /// 创建 `Other` 类型错误。
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(std::io::ErrorKind::Other, message)
    }

    /// 还原为标准 I/O 错误。
    pub fn to_io_error(&self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message.to_string())
    }
}

impl From<std::io::Error> for IoFailure {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.kind(), value.to_string())
    }
}

/// 同一条 XHTTP 逻辑流的取消与首个错误状态。
#[derive(Debug, Default)]
pub struct IoState {
    cancelled: AtomicBool,
    first_error: Mutex<Option<IoFailure>>,
    notify: Notify,
}

impl IoState {
    /// 创建共享状态。
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 记录首个错误并取消流。
    pub fn fail(&self, failure: IoFailure) {
        let mut error = self.first_error.lock();
        if error.is_none() {
            *error = Some(failure);
        }
        drop(error);
        self.cancel();
    }

    /// 取消流并唤醒所有等待者。
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    /// 流是否已取消。
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// 返回首个错误的副本。
    pub fn error(&self) -> Option<std::io::Error> {
        self.first_error.lock().as_ref().map(IoFailure::to_io_error)
    }

    /// 不丢唤醒的取消等待：先注册 waiter，再检查标志。
    pub async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// 响应 channel 中的数据帧或终止错误。
pub type ResponseItem = Result<Bytes, IoFailure>;

/// 协议无关的响应体读取端。
pub struct ResponseReader {
    rx: mpsc::Receiver<ResponseItem>,
    leftover: Bytes,
    eof: bool,
    state: Arc<IoState>,
}

impl ResponseReader {
    /// 创建读取端与对应的有界发送端。
    pub fn channel(capacity: usize, state: Arc<IoState>) -> (Self, mpsc::Sender<ResponseItem>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                rx,
                leftover: Bytes::new(),
                eof: false,
                state,
            },
            tx,
        )
    }
}

impl AsyncRead for ResponseReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.leftover.is_empty() {
            let len = dst.remaining().min(self.leftover.len());
            dst.put_slice(&self.leftover[..len]);
            self.leftover.advance(len);
            return Poll::Ready(Ok(()));
        }
        if self.eof || dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let len = dst.remaining().min(data.len());
                dst.put_slice(&data[..len]);
                if len < data.len() {
                    self.leftover = data.slice(len..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => {
                self.eof = true;
                Poll::Ready(Err(error.to_io_error()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                if let Some(error) = self.state.error() {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

type ReserveFuture = Pin<Box<dyn Future<Output = Result<mpsc::OwnedPermit<Bytes>, ()>> + Send>>;

/// 把代理协议写入有界请求体 channel。
///
/// `reserve_owned` future 会跨 poll 保存；Pending 时不会复制数据，也不会产生
/// 重复消息。取得 permit 后才复制当前 `data`，所以完全符合 `AsyncWrite` 契约。
pub struct PipeWriter {
    tx: Option<mpsc::Sender<Bytes>>,
    reserve: Option<ReserveFuture>,
    state: Arc<IoState>,
}

impl PipeWriter {
    /// 创建写入端与对应的请求体接收端。
    pub fn channel(capacity: usize, state: Arc<IoState>) -> (Self, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx: Some(tx),
                reserve: None,
                state,
            },
            rx,
        )
    }

    /// 用现有有界 channel 发送端构造写端。
    pub fn from_sender(tx: mpsc::Sender<Bytes>, state: Arc<IoState>) -> Self {
        Self {
            tx: Some(tx),
            reserve: None,
            state,
        }
    }
}

impl AsyncWrite for PipeWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(error) = self.state.error() {
            return Poll::Ready(Err(error));
        }
        if self.state.is_cancelled() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp stream cancelled",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(tx) = self.tx.as_ref() else {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        };

        if self.reserve.is_none() {
            let tx = tx.clone();
            let state = self.state.clone();
            self.reserve = Some(Box::pin(async move {
                tokio::select! {
                    permit = tx.reserve_owned() => permit.map_err(|_| ()),
                    _ = state.cancelled() => Err(()),
                }
            }));
        }
        let reserve = self.reserve.as_mut().expect("reserve initialized");
        match Future::poll(reserve.as_mut(), cx) {
            Poll::Ready(Ok(permit)) => {
                self.reserve = None;
                if let Some(error) = self.state.error() {
                    return Poll::Ready(Err(error));
                }
                if self.state.is_cancelled() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "xhttp stream cancelled",
                    )));
                }
                permit.send(Bytes::copy_from_slice(data));
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(_)) => {
                self.reserve = None;
                Poll::Ready(Err(self.state.error().unwrap_or_else(|| {
                    let message = if self.state.is_cancelled() {
                        "xhttp stream cancelled"
                    } else {
                        "xhttp request body closed"
                    };
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, message)
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(error) = self.state.error() {
            Poll::Ready(Err(error))
        } else if self.state.is_cancelled() {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp stream cancelled",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.reserve = None;
        self.tx = None;
        if let Some(error) = self.state.error() {
            Poll::Ready(Err(error))
        } else if self.state.is_cancelled() {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp stream cancelled",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

/// 组合响应读取端与请求写入端。
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

    pub fn with_on_close(mut self, callback: impl FnOnce() + Send + 'static) -> Self {
        self.on_close = Some(Box::new(callback));
        self
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for XConn<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, dst)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for XConn<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
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
        if let Some(callback) = self.on_close.take() {
            callback();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn pipe_writer_backpressures_without_duplicate_data() {
        let state = IoState::shared();
        let (mut writer, mut rx) = PipeWriter::channel(1, state);
        writer.write_all(b"one").await.unwrap();

        let blocked = tokio::time::timeout(Duration::from_millis(20), writer.write_all(b"two"));
        assert!(blocked.await.is_err());
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"one"));

        writer.write_all(b"two").await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"two"));
    }

    #[tokio::test]
    async fn cancellation_reaches_writer() {
        let state = IoState::shared();
        let (mut writer, _rx) = PipeWriter::channel(1, state.clone());
        state.fail(IoFailure::other("remote upload failed"));
        let error = writer.write_all(b"x").await.unwrap_err();
        assert!(error.to_string().contains("remote upload failed"));
    }

    #[tokio::test]
    async fn cancellation_wakes_writer_waiting_for_channel_capacity() {
        let state = IoState::shared();
        let (mut writer, _rx) = PipeWriter::channel(1, state.clone());
        writer.write_all(b"one").await.unwrap();
        let blocked = tokio::spawn(async move { writer.write_all(b"two").await });
        tokio::task::yield_now().await;
        state.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("cancelled writer remained blocked")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn response_reader_propagates_body_error() {
        let state = IoState::shared();
        let (mut reader, tx) = ResponseReader::channel(1, state);
        tx.send(Err(IoFailure::other("bad response body")))
            .await
            .unwrap();
        drop(tx);
        let mut byte = [0_u8; 1];
        let error = reader.read(&mut byte).await.unwrap_err();
        assert!(error.to_string().contains("bad response body"));
    }
}
