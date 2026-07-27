//! Ordered, bounded upload reassembly for XHTTP `packet-up`.
//!
//! Every POST carries a monotonically increasing sequence number, while HTTP
//! multiplexing is free to deliver those POSTs out of order.  This queue turns
//! them back into one asynchronous byte stream without ever blocking a Tokio
//! worker thread.

use std::{
    collections::BTreeMap,
    future::poll_fn,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Notify,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub seq: u64,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencePosition {
    Past,
    Next,
    Future,
}

#[derive(Debug)]
struct QueueError {
    kind: io::ErrorKind,
    message: String,
}

impl QueueError {
    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[derive(Debug, Default)]
struct Inner {
    packets: BTreeMap<u64, Bytes>,
    next_seq: u64,
    current: Bytes,
    current_offset: usize,
    closed: bool,
    error: Option<QueueError>,
}

/// Shared producer side of a packet-up session.
#[derive(Debug)]
pub struct UploadQueue {
    inner: Mutex<Inner>,
    reader_waker: AtomicWaker,
    sequence_changed: Notify,
    max_packets: usize,
}

impl UploadQueue {
    pub fn new(max_packets: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            reader_waker: AtomicWaker::new(),
            sequence_changed: Notify::new(),
            // A zero-sized HTTP reassembly window cannot make progress. Xray's
            // normalized default is 30, while this defensive floor keeps the
            // primitive safe when used before config normalization.
            max_packets: max_packets.max(1),
        })
    }

    /// Return an independently owned asynchronous reader for this session.
    pub fn reader(self: &Arc<Self>) -> UploadQueueReader {
        UploadQueueReader {
            queue: Arc::clone(self),
        }
    }

    /// Insert one complete HTTP upload.
    ///
    /// Duplicate, already-consumed, and over-window sequence numbers are
    /// rejected instead of silently replacing bytes. This is important because
    /// a retried POST must not corrupt an established proxy stream.
    pub fn push(&self, packet: Packet) -> io::Result<()> {
        let mut inner = self.inner.lock();
        if let Some(error) = &inner.error {
            return Err(error.to_io_error());
        }
        if inner.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP upload queue is closed",
            ));
        }
        if packet.seq < inner.next_seq || inner.packets.contains_key(&packet.seq) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("duplicate XHTTP upload sequence {}", packet.seq),
            ));
        }
        // Keep the out-of-order window bounded, but never reject the exact
        // sequence that unblocks the reader.  A strict `len >= max` check here
        // deadlocks a full window containing only future packets: the missing
        // packet could never enter the queue to drain that window.
        if inner.packets.len() >= self.max_packets && packet.seq != inner.next_seq {
            let error = QueueError {
                kind: io::ErrorKind::OutOfMemory,
                message: format!(
                    "XHTTP upload reassembly exceeded {} buffered POSTs",
                    self.max_packets
                ),
            };
            let result = Err(error.to_io_error());
            inner.error = Some(error);
            clear_payloads(&mut inner);
            drop(inner);
            self.reader_waker.wake();
            return result;
        }

        inner.packets.insert(packet.seq, packet.payload);
        drop(inner);
        self.reader_waker.wake();
        Ok(())
    }

    /// Finish the byte stream after all consecutive queued packets are read.
    pub fn close(&self) {
        self.inner.lock().closed = true;
        self.reader_waker.wake();
    }

    /// Abort the byte stream and propagate a meaningful error to its reader.
    pub fn fail(&self, kind: io::ErrorKind, message: impl Into<String>) {
        let mut inner = self.inner.lock();
        if inner.error.is_none() {
            inner.error = Some(QueueError {
                kind,
                message: message.into(),
            });
        }
        inner.closed = true;
        clear_payloads(&mut inner);
        drop(inner);
        self.reader_waker.wake();
    }

    pub fn pending_packets(&self) -> usize {
        self.inner.lock().packets.len()
    }

    pub fn next_sequence(&self) -> u64 {
        self.inner.lock().next_seq
    }

    pub fn sequence_position(&self, sequence: u64) -> SequencePosition {
        let next = self.inner.lock().next_seq;
        if sequence < next {
            SequencePosition::Past
        } else if sequence == next {
            SequencePosition::Next
        } else {
            SequencePosition::Future
        }
    }

    /// Wait until `next_seq` differs from `observed`.
    ///
    /// The waiter is enabled before the state is rechecked, so an advancement
    /// between observation and suspension cannot be lost.
    pub async fn wait_for_sequence_change(&self, observed: u64) -> u64 {
        loop {
            let changed = self.sequence_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let current = self.next_sequence();
            if current != observed {
                return current;
            }
            changed.await;
        }
    }

    /// Convenience method retained for callers which do not need `AsyncRead`.
    pub async fn read(&self, dst: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_read_slice(cx, dst)).await
    }

    fn poll_read_slice(&self, cx: &mut Context<'_>, dst: &mut [u8]) -> Poll<io::Result<usize>> {
        if dst.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            {
                let mut inner = self.inner.lock();
                if let Some(error) = &inner.error {
                    return Poll::Ready(Err(error.to_io_error()));
                }

                if inner.current_offset < inner.current.len() {
                    let remaining = &inner.current[inner.current_offset..];
                    let len = remaining.len().min(dst.len());
                    dst[..len].copy_from_slice(&remaining[..len]);
                    inner.current_offset += len;
                    if inner.current_offset == inner.current.len() {
                        inner.current = Bytes::new();
                        inner.current_offset = 0;
                    }
                    return Poll::Ready(Ok(len));
                }

                let next_seq = inner.next_seq;
                if let Some(payload) = inner.packets.remove(&next_seq) {
                    inner.next_seq = inner.next_seq.saturating_add(1);
                    self.sequence_changed.notify_waiters();
                    inner.current = payload;
                    inner.current_offset = 0;
                    // Empty POSTs still consume their sequence number.
                    if inner.current.is_empty() {
                        continue;
                    }
                    continue;
                }

                if inner.closed {
                    // Preserve clean-close draining for the consecutive prefix,
                    // then release packets beyond the first permanent gap.
                    clear_payloads(&mut inner);
                    return Poll::Ready(Ok(0));
                }
            }

            // Register after the first observation, then observe once more to
            // close the classic notification race between the lock and waker.
            self.reader_waker.register(cx.waker());
            let inner = self.inner.lock();
            let ready = inner.error.is_some()
                || inner.closed
                || inner.packets.contains_key(&inner.next_seq);
            drop(inner);
            if ready {
                continue;
            }
            return Poll::Pending;
        }
    }
}

fn clear_payloads(inner: &mut Inner) {
    inner.packets.clear();
    inner.current = Bytes::new();
    inner.current_offset = 0;
}

/// `AsyncRead` view over an [`UploadQueue`].
#[derive(Debug, Clone)]
pub struct UploadQueueReader {
    queue: Arc<UploadQueue>,
}

impl AsyncRead for UploadQueueReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match self.queue.poll_read_slice(cx, unfilled) {
            Poll::Ready(Ok(read)) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use tokio::io::AsyncReadExt;

    use super::*;

    #[derive(Debug)]
    struct TrackedPayload {
        data: &'static [u8],
        dropped: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for TrackedPayload {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }

    impl Drop for TrackedPayload {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn tracked_payload(data: &'static [u8]) -> (Bytes, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        (
            Bytes::from_owner(TrackedPayload {
                data,
                dropped: dropped.clone(),
            }),
            dropped,
        )
    }

    #[tokio::test]
    async fn reassembles_out_of_order_and_partial_reads() {
        let queue = UploadQueue::new(16);
        let mut reader = queue.reader();
        queue
            .push(Packet {
                seq: 2,
                payload: Bytes::from_static(b"!"),
            })
            .unwrap();
        queue
            .push(Packet {
                seq: 0,
                payload: Bytes::from_static(b"hello "),
            })
            .unwrap();
        queue
            .push(Packet {
                seq: 1,
                payload: Bytes::from_static(b"world"),
            })
            .unwrap();
        queue.close();

        let mut output = Vec::new();
        let mut tiny = [0_u8; 2];
        loop {
            let read = reader.read(&mut tiny).await.unwrap();
            if read == 0 {
                break;
            }
            output.extend_from_slice(&tiny[..read]);
        }
        assert_eq!(output, b"hello world!");
        assert_eq!(queue.next_sequence(), 3);
    }

    #[tokio::test]
    async fn reader_waits_without_blocking_runtime() {
        let queue = UploadQueue::new(4);
        let mut reader = queue.reader();
        let producer = Arc::clone(&queue);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            producer
                .push(Packet {
                    seq: 0,
                    payload: Bytes::from_static(b"ready"),
                })
                .unwrap();
            producer.close();
        });

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"ready");
    }

    #[tokio::test]
    async fn retry_and_conflict_drop_incoming_payload_without_replacing_original() {
        let queue = UploadQueue::new(4);
        let (original, original_dropped) = tracked_payload(b"first");
        queue
            .push(Packet {
                seq: 0,
                payload: original,
            })
            .unwrap();

        let (retry, retry_dropped) = tracked_payload(b"first");
        let retry_error = queue
            .push(Packet {
                seq: 0,
                payload: retry,
            })
            .unwrap_err();
        assert_eq!(retry_error.kind(), ErrorKind::AlreadyExists);
        assert!(retry_dropped.load(Ordering::Acquire));

        let (conflict, conflict_dropped) = tracked_payload(b"replacement");
        let conflict_error = queue
            .push(Packet {
                seq: 0,
                payload: conflict,
            })
            .unwrap_err();
        assert_eq!(conflict_error.kind(), ErrorKind::AlreadyExists);
        assert!(conflict_dropped.load(Ordering::Acquire));
        assert!(!original_dropped.load(Ordering::Acquire));

        queue.fail(ErrorKind::ConnectionAborted, "test complete");
        assert!(original_dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn over_window_failure_releases_all_payloads_and_reaches_reader() {
        let queue = UploadQueue::new(1);
        let (pending, pending_dropped) = tracked_payload(b"pending");
        queue
            .push(Packet {
                seq: 2,
                payload: pending,
            })
            .unwrap();
        let (rejected, rejected_dropped) = tracked_payload(b"rejected");
        let error = queue
            .push(Packet {
                seq: 3,
                payload: rejected,
            })
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfMemory);
        assert_eq!(queue.pending_packets(), 0);
        assert!(pending_dropped.load(Ordering::Acquire));
        assert!(rejected_dropped.load(Ordering::Acquire));

        let mut byte = [0_u8; 1];
        let error = queue.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfMemory);
    }

    #[tokio::test]
    async fn full_out_of_order_window_still_accepts_missing_sequence() {
        let queue = UploadQueue::new(2);
        queue
            .push(Packet {
                seq: 2,
                payload: Bytes::from_static(b"two"),
            })
            .unwrap();
        queue
            .push(Packet {
                seq: 1,
                payload: Bytes::from_static(b"one"),
            })
            .unwrap();
        queue
            .push(Packet {
                seq: 0,
                payload: Bytes::from_static(b"zero"),
            })
            .unwrap();
        queue.close();

        let mut reader = queue.reader();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"zeroonetwo");
    }

    #[tokio::test]
    async fn close_signals_eof() {
        let queue = UploadQueue::new(16);
        queue.close();
        let mut output = [0_u8; 1];
        assert_eq!(queue.read(&mut output).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn partial_read_keeps_payload_until_last_byte_is_consumed() {
        let queue = UploadQueue::new(4);
        let (payload, dropped) = tracked_payload(b"abc");
        queue.push(Packet { seq: 0, payload }).unwrap();

        let mut one = [0_u8; 1];
        assert_eq!(queue.read(&mut one).await.unwrap(), 1);
        assert_eq!(&one, b"a");
        assert!(!dropped.load(Ordering::Acquire));

        let mut rest = [0_u8; 2];
        assert_eq!(queue.read(&mut rest).await.unwrap(), 2);
        assert_eq!(&rest, b"bc");
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn fail_releases_current_and_pending_payloads_immediately() {
        let queue = UploadQueue::new(4);
        let (current, current_dropped) = tracked_payload(b"current");
        let (pending, pending_dropped) = tracked_payload(b"pending");
        queue
            .push(Packet {
                seq: 0,
                payload: current,
            })
            .unwrap();
        queue
            .push(Packet {
                seq: 2,
                payload: pending,
            })
            .unwrap();
        let mut one = [0_u8; 1];
        queue.read(&mut one).await.unwrap();
        assert!(!current_dropped.load(Ordering::Acquire));
        assert!(!pending_dropped.load(Ordering::Acquire));

        queue.fail(ErrorKind::ConnectionAborted, "cancelled");

        assert!(current_dropped.load(Ordering::Acquire));
        assert!(pending_dropped.load(Ordering::Acquire));
        assert_eq!(queue.pending_packets(), 0);
        assert_eq!(
            queue.read(&mut one).await.unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test]
    async fn clean_close_keeps_payload_until_reader_drains_it() {
        let queue = UploadQueue::new(4);
        let (payload, dropped) = tracked_payload(b"drain");
        let (after_gap, after_gap_dropped) = tracked_payload(b"unreachable");
        queue.push(Packet { seq: 0, payload }).unwrap();
        queue
            .push(Packet {
                seq: 2,
                payload: after_gap,
            })
            .unwrap();
        queue.close();
        assert!(!dropped.load(Ordering::Acquire));
        assert!(!after_gap_dropped.load(Ordering::Acquire));

        let mut reader = queue.reader();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, b"drain");
        assert!(dropped.load(Ordering::Acquire));
        assert!(after_gap_dropped.load(Ordering::Acquire));
        assert_eq!(queue.pending_packets(), 0);
    }

    #[tokio::test]
    async fn sequence_change_waiter_cannot_miss_advancement() {
        let queue = UploadQueue::new(4);
        assert_eq!(queue.sequence_position(0), SequencePosition::Next);
        assert_eq!(queue.sequence_position(1), SequencePosition::Future);

        // Construct the waiter before advancing but do not poll it yet. Its
        // state recheck must observe the advancement even without a permit.
        let late_waiter = queue.wait_for_sequence_change(0);
        queue
            .push(Packet {
                seq: 0,
                payload: Bytes::from_static(b"a"),
            })
            .unwrap();
        let mut byte = [0_u8; 1];
        queue.read(&mut byte).await.unwrap();
        assert_eq!(late_waiter.await, 1);
        assert_eq!(queue.sequence_position(0), SequencePosition::Past);
        assert_eq!(queue.sequence_position(1), SequencePosition::Next);

        // Also cover a waiter which is already suspended on Notify.
        let registered_waiter = {
            let queue = queue.clone();
            tokio::spawn(async move { queue.wait_for_sequence_change(1).await })
        };
        tokio::task::yield_now().await;
        queue
            .push(Packet {
                seq: 1,
                payload: Bytes::from_static(b"b"),
            })
            .unwrap();
        queue.read(&mut byte).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), registered_waiter)
                .await
                .expect("sequence waiter was not notified")
                .expect("sequence waiter panicked"),
            2
        );
    }
}
