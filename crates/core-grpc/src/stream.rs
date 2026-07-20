use std::{
    collections::VecDeque,
    future::Future,
    io,
    io::IoSlice,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot, watch},
    task::AbortHandle,
};
use tokio_stream::wrappers::{ReceiverStream, WatchStream};
use tokio_util::sync::PollSender;
use tonic::Streaming;

use crate::MIN_MESSAGE_SIZE;
use crate::proto::{Hunk, MultiHunk};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    Tun,
    TunMulti,
}

#[derive(Debug)]
struct Queued<M> {
    sequence: u64,
    message: M,
}

/// A request/response stream that acknowledges a message after tonic has
/// consumed it from the protobuf source stream.  This gives AsyncWrite::flush
/// a meaningful userspace boundary instead of returning while the item is
/// still waiting in an mpsc queue.
pub(crate) struct AcknowledgedStream<M> {
    inner: ReceiverStream<Queued<M>>,
    acknowledgements: watch::Sender<u64>,
    pending_acknowledgement: Option<u64>,
}

impl<M> Stream for AcknowledgedStream<M> {
    type Item = M;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<M>> {
        if let Some(sequence) = self.pending_acknowledgement.take() {
            self.acknowledgements.send_replace(sequence);
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(queued)) => {
                self.pending_acknowledgement = Some(queued.sequence);
                Poll::Ready(Some(queued.message))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<M> Drop for AcknowledgedStream<M> {
    fn drop(&mut self) {
        if let Some(sequence) = self.pending_acknowledgement.take() {
            self.acknowledgements.send_replace(sequence);
        }
    }
}

pub(crate) struct MessageSender<M> {
    sender: PollSender<Queued<M>>,
    acknowledgements: WatchStream<u64>,
    next_sequence: u64,
    last_sequence: u64,
    acknowledged_sequence: u64,
    closed: bool,
}

impl<M: Send> MessageSender<M> {
    fn pair(capacity: usize) -> (Self, AcknowledgedStream<M>) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let (acknowledgements, acknowledgement_rx) = watch::channel(0);
        (
            Self {
                sender: PollSender::new(sender),
                acknowledgements: WatchStream::new(acknowledgement_rx),
                next_sequence: 1,
                last_sequence: 0,
                acknowledged_sequence: 0,
                closed: false,
            },
            AcknowledgedStream {
                inner: ReceiverStream::new(receiver),
                acknowledgements,
                pending_acknowledgement: None,
            },
        )
    }

    fn poll_reserve(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.sender
            .poll_reserve(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn send_reserved(&mut self, message: M) -> io::Result<()> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("gRPC hunk sequence exhausted"))?;
        self.sender
            .send_item(Queued { sequence, message })
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.last_sequence = sequence;
        Ok(())
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.acknowledged_sequence < self.last_sequence {
            match self.acknowledgements.poll_next_unpin(cx) {
                Poll::Ready(Some(sequence)) => self.acknowledged_sequence = sequence,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "gRPC protobuf body closed before queued data was consumed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.sender.close();
        }
    }
}

pub(crate) enum OutboundMessages {
    Hunk(MessageSender<Hunk>),
    Multi(MessageSender<MultiHunk>),
}

pub(crate) enum InboundMessages {
    Hunk(Streaming<Hunk>),
    Multi(Streaming<MultiHunk>),
    HunkPending(oneshot::Receiver<io::Result<Streaming<Hunk>>>),
    MultiPending(oneshot::Receiver<io::Result<Streaming<MultiHunk>>>),
}

pub(crate) fn hunk_outbound(capacity: usize) -> (OutboundMessages, AcknowledgedStream<Hunk>) {
    let (sender, stream) = MessageSender::pair(capacity);
    (OutboundMessages::Hunk(sender), stream)
}

pub(crate) fn multi_hunk_outbound(
    capacity: usize,
) -> (OutboundMessages, AcknowledgedStream<MultiHunk>) {
    let (sender, stream) = MessageSender::pair(capacity);
    (OutboundMessages::Multi(sender), stream)
}

/// Async byte-stream view of Xray's Hunk/TunMulti protobuf streams.
pub struct GrpcTunnelStream {
    inbound: InboundMessages,
    outbound: OutboundMessages,
    read_queue: VecDeque<Bytes>,
    current_read: Bytes,
    max_message_size: usize,
    read_eof: bool,
    write_shutdown: bool,
    response_task: Option<AbortHandle>,
}

impl std::fmt::Debug for GrpcTunnelStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcTunnelStream")
            .field("mode", &self.mode())
            .field("queued_reads", &self.read_queue.len())
            .field("current_read", &self.current_read.len())
            .field("max_message_size", &self.max_message_size)
            .field("read_eof", &self.read_eof)
            .field("write_shutdown", &self.write_shutdown)
            .field("has_response_task", &self.response_task.is_some())
            .finish()
    }
}

impl GrpcTunnelStream {
    pub(crate) fn new(
        inbound: InboundMessages,
        outbound: OutboundMessages,
        max_message_size: usize,
    ) -> Self {
        Self {
            inbound,
            outbound,
            read_queue: VecDeque::new(),
            current_read: Bytes::new(),
            max_message_size: max_message_size.max(MIN_MESSAGE_SIZE),
            read_eof: false,
            write_shutdown: false,
            response_task: None,
        }
    }

    pub(crate) fn with_response_task(mut self, task: AbortHandle) -> Self {
        self.response_task = Some(task);
        self
    }

    pub fn mode(&self) -> TunnelMode {
        match self.inbound {
            InboundMessages::Hunk(_) | InboundMessages::HunkPending(_) => TunnelMode::Tun,
            InboundMessages::Multi(_) | InboundMessages::MultiPending(_) => TunnelMode::TunMulti,
        }
    }

    fn validate_inbound(&self, data: Vec<u8>) -> io::Result<Option<Bytes>> {
        if bytes_field_encoded_len(data.len()) > self.max_message_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "gRPC encoded hunk exceeds configured limit: {} > {}",
                    bytes_field_encoded_len(data.len()),
                    self.max_message_size
                ),
            ));
        }
        Ok((!data.is_empty()).then(|| Bytes::from(data)))
    }

    fn poll_next_payload(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        loop {
            if let Some(data) = self.read_queue.pop_front() {
                return Poll::Ready(Ok(Some(data)));
            }
            if self.read_eof {
                return Poll::Ready(Ok(None));
            }
            match &mut self.inbound {
                InboundMessages::Hunk(stream) => match Pin::new(stream).poll_next(cx) {
                    Poll::Ready(Some(Ok(hunk))) => {
                        if let Some(data) = self.validate_inbound(hunk.data)? {
                            return Poll::Ready(Ok(Some(data)));
                        }
                    }
                    Poll::Ready(Some(Err(status))) => {
                        return Poll::Ready(Err(status_to_io(status)));
                    }
                    Poll::Ready(None) => self.read_eof = true,
                    Poll::Pending => return Poll::Pending,
                },
                InboundMessages::Multi(stream) => match Pin::new(stream).poll_next(cx) {
                    Poll::Ready(Some(Ok(hunks))) => {
                        for hunk in hunks.data {
                            if let Some(data) = self.validate_inbound(hunk)? {
                                self.read_queue.push_back(data);
                            }
                        }
                    }
                    Poll::Ready(Some(Err(status))) => {
                        return Poll::Ready(Err(status_to_io(status)));
                    }
                    Poll::Ready(None) => self.read_eof = true,
                    Poll::Pending => return Poll::Pending,
                },
                InboundMessages::HunkPending(response) => match Pin::new(response).poll(cx) {
                    Poll::Ready(Ok(Ok(stream))) => {
                        self.response_task = None;
                        self.inbound = InboundMessages::Hunk(stream);
                    }
                    Poll::Ready(Ok(Err(error))) => {
                        self.response_task = None;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Err(_)) => {
                        self.response_task = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "gRPC response task ended before response headers",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                InboundMessages::MultiPending(response) => match Pin::new(response).poll(cx) {
                    Poll::Ready(Ok(Ok(stream))) => {
                        self.response_task = None;
                        self.inbound = InboundMessages::Multi(stream);
                    }
                    Poll::Ready(Ok(Err(error))) => {
                        self.response_task = None;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Err(_)) => {
                        self.response_task = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "gRPC response task ended before response headers",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }

    fn poll_outbound_reserve(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.outbound {
            OutboundMessages::Hunk(sender) => sender.poll_reserve(cx),
            OutboundMessages::Multi(sender) => sender.poll_reserve(cx),
        }
    }

    fn send_reserved(&mut self, chunks: Vec<Vec<u8>>) -> io::Result<()> {
        match &mut self.outbound {
            OutboundMessages::Hunk(sender) => {
                let total = chunks.iter().map(Vec::len).sum();
                let mut data = Vec::with_capacity(total);
                for chunk in chunks {
                    data.extend_from_slice(&chunk);
                }
                sender.send_reserved(Hunk { data })
            }
            OutboundMessages::Multi(sender) => sender.send_reserved(MultiHunk { data: chunks }),
        }
    }

    fn poll_outbound_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.outbound {
            OutboundMessages::Hunk(sender) => sender.poll_flush(cx),
            OutboundMessages::Multi(sender) => sender.poll_flush(cx),
        }
    }

    fn close_outbound(&mut self) {
        match &mut self.outbound {
            OutboundMessages::Hunk(sender) => sender.close(),
            OutboundMessages::Multi(sender) => sender.close(),
        }
    }
}

impl AsyncRead for GrpcTunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.current_read.is_empty() {
                let count = output.remaining().min(self.current_read.len());
                output.put_slice(&self.current_read.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match self.poll_next_payload(cx) {
                Poll::Ready(Ok(Some(data))) => self.current_read = data,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcTunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        match self.poll_outbound_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let count = input
                    .len()
                    .min(max_bytes_field_payload(self.max_message_size));
                self.send_reserved(vec![input[..count].to_vec()])?;
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let total_available = inputs.iter().map(|input| input.len()).sum::<usize>();
        if total_available == 0 {
            return Poll::Ready(Ok(0));
        }
        match self.poll_outbound_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let (chunks, written) = if matches!(&self.outbound, OutboundMessages::Multi(_)) {
                    bounded_multi_chunks(inputs, self.max_message_size)
                } else {
                    let mut remaining = max_bytes_field_payload(self.max_message_size);
                    let mut chunks = Vec::new();
                    let mut written = 0;
                    for input in inputs {
                        if remaining == 0 {
                            break;
                        }
                        let count = remaining.min(input.len());
                        if count != 0 {
                            chunks.push(input[..count].to_vec());
                            written += count;
                            remaining -= count;
                        }
                    }
                    (chunks, written)
                };
                self.send_reserved(chunks)?;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_outbound_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_shutdown {
            self.write_shutdown = true;
            self.close_outbound();
        }
        self.poll_outbound_flush(cx)
    }
}

impl Drop for GrpcTunnelStream {
    fn drop(&mut self) {
        self.close_outbound();
        if let Some(task) = self.response_task.take() {
            task.abort();
        }
    }
}

fn protobuf_varint_len(mut value: usize) -> usize {
    let mut bytes = 1;
    while value >= 0x80 {
        value >>= 7;
        bytes += 1;
    }
    bytes
}

fn bytes_field_encoded_len(payload_len: usize) -> usize {
    if payload_len == 0 {
        0
    } else {
        1 + protobuf_varint_len(payload_len) + payload_len
    }
}

fn max_bytes_field_payload(encoded_limit: usize) -> usize {
    let mut lower = 0;
    let mut upper = encoded_limit;
    while lower < upper {
        let middle = lower + (upper - lower).div_ceil(2);
        if bytes_field_encoded_len(middle) <= encoded_limit {
            lower = middle;
        } else {
            upper = middle - 1;
        }
    }
    lower
}

fn bounded_multi_chunks(inputs: &[IoSlice<'_>], encoded_limit: usize) -> (Vec<Vec<u8>>, usize) {
    let mut encoded = 0;
    let mut chunks = Vec::new();
    let mut written = 0;
    for input in inputs {
        if input.is_empty() {
            continue;
        }
        let remaining = encoded_limit.saturating_sub(encoded);
        let count = input.len().min(max_bytes_field_payload(remaining));
        if count == 0 {
            break;
        }
        chunks.push(input[..count].to_vec());
        written += count;
        encoded += bytes_field_encoded_len(count);
        if count < input.len() {
            break;
        }
    }
    (chunks, written)
}

fn status_to_io(status: tonic::Status) -> io::Error {
    let kind = match status.code() {
        tonic::Code::Cancelled => io::ErrorKind::ConnectionAborted,
        tonic::Code::DeadlineExceeded => io::ErrorKind::TimedOut,
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => {
            io::ErrorKind::InvalidData
        }
        tonic::Code::NotFound => io::ErrorKind::NotFound,
        tonic::Code::AlreadyExists => io::ErrorKind::AlreadyExists,
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            io::ErrorKind::PermissionDenied
        }
        tonic::Code::ResourceExhausted => io::ErrorKind::OutOfMemory,
        tonic::Code::Unimplemented => io::ErrorKind::Unsupported,
        tonic::Code::Unavailable => io::ErrorKind::ConnectionRefused,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("gRPC stream: {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use prost::Message;

    #[tokio::test]
    async fn flush_waits_until_tonic_side_consumes_message() {
        let (mut sender, mut stream) = MessageSender::<Hunk>::pair(1);
        futures::future::poll_fn(|cx| sender.poll_reserve(cx))
            .await
            .unwrap();
        sender
            .send_reserved(Hunk {
                data: b"payload".to_vec(),
            })
            .unwrap();

        let mut flush = std::pin::pin!(futures::future::poll_fn(|cx| sender.poll_flush(cx)));
        assert!(poll!(&mut flush).is_pending());
        assert_eq!(stream.next().await.unwrap().data, b"payload");
        // Ack is emitted on the next body poll, mirroring hyper asking whether
        // more request data is available.
        assert!(poll!(stream.next()).is_pending());
        flush.await.unwrap();
    }

    #[tokio::test]
    async fn closing_body_acknowledges_last_consumed_message() {
        let (mut sender, mut stream) = MessageSender::<Hunk>::pair(1);
        futures::future::poll_fn(|cx| sender.poll_reserve(cx))
            .await
            .unwrap();
        sender
            .send_reserved(Hunk {
                data: b"last".to_vec(),
            })
            .unwrap();
        assert_eq!(stream.next().await.unwrap().data, b"last");
        drop(stream);
        futures::future::poll_fn(|cx| sender.poll_flush(cx))
            .await
            .unwrap();
    }

    #[test]
    fn write_bound_accounts_for_protobuf_overhead_exactly() {
        for limit in MIN_MESSAGE_SIZE..=65_536 {
            let payload = max_bytes_field_payload(limit);
            assert!(payload > 0);
            assert!(bytes_field_encoded_len(payload) <= limit);
            assert!(bytes_field_encoded_len(payload + 1) > limit);
            assert!(
                Hunk {
                    data: vec![0; payload]
                }
                .encoded_len()
                    <= limit
            );
        }
    }

    #[test]
    fn tun_multi_vectored_write_never_exceeds_encoded_limit() {
        let a = vec![1_u8; 127];
        let b = vec![2_u8; 16_384];
        let c = vec![3_u8; 17];
        let inputs = [IoSlice::new(&a), IoSlice::new(&b), IoSlice::new(&c)];

        for limit in [3, 127, 128, 255, 16_384, 65_535] {
            let (chunks, written) = bounded_multi_chunks(&inputs, limit);
            assert!(written > 0);
            assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), written);
            assert!(MultiHunk { data: chunks }.encoded_len() <= limit);
        }
    }

    #[tokio::test]
    async fn dropping_unopened_tunnel_aborts_pending_response_task() {
        let (_response_tx, response_rx) = oneshot::channel();
        let (outbound, _request_stream) = hunk_outbound(1);
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        let tunnel = GrpcTunnelStream::new(
            InboundMessages::HunkPending(response_rx),
            outbound,
            crate::DEFAULT_MAX_MESSAGE_SIZE,
        )
        .with_response_task(abort.clone());
        drop(tunnel);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
        let _ = task.await;
    }
}
