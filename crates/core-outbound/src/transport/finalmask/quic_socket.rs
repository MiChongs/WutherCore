//! Bounded async bridge from the project's packet abstraction to Quinn.
//!
//! Quinn's socket API is readiness based and synchronous at `try_send`, while
//! finalmask stages may expand a packet and await timers or carrier I/O. A
//! bounded worker queue is therefore the only correct bridge: it keeps Quinn's
//! reactor non-blocking, preserves datagram boundaries (including GSO input),
//! and exposes backpressure through a dedicated `UdpPoller`.

use std::{
    collections::VecDeque,
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, UdpPoller, udp};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

use crate::adapter::{BoxedUdp, UdpSocketLike};

const SEND_QUEUE_PACKETS: usize = 256;
const RECEIVE_QUEUE_PACKETS: usize = 256;
const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Open an endpoint-aware, unconnected UDP carrier. Unlike the public DIRECT
/// association this deliberately accepts literal alternate destinations used
/// by xdns and UDP hopping, while still mapping the configured hostname to its
/// already-resolved address and applying the complete socket policy first.
pub(crate) fn open_direct_carrier(
    target_host: String,
    peer: SocketAddr,
) -> io::Result<(BoxedUdp, SocketAddr)> {
    let bind_addr: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().expect("IPv4 wildcard")
    } else {
        "[::]:0".parse().expect("IPv6 wildcard")
    };
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    let guard = crate::adapter::prepare_outbound_udp_socket_for_addr(&socket, peer)?;
    socket.set_nonblocking(true)?;
    let local = socket.local_addr()?;
    guard.observe_local_addr(local);
    Ok((
        Box::new(DirectCarrier {
            socket: tokio::net::UdpSocket::from_std(socket)?,
            peer,
            target_host,
            guard,
        }),
        local,
    ))
}

struct DirectCarrier {
    socket: tokio::net::UdpSocket,
    peer: SocketAddr,
    target_host: String,
    guard: crate::loopback::LoopbackUdpGuard,
}

/// Adapt an already-bound inbound Tokio UDP socket to the packet abstraction
/// consumed by the FinalMask manager.  Source endpoints are retained so a
/// single QUIC listener can serve multiple clients.
pub fn inbound_udp_carrier(socket: UdpSocket) -> BoxedUdp {
    Box::new(InboundCarrier { socket })
}

struct InboundCarrier {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl UdpSocketLike for InboundCarrier {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        self.socket
            .send_to(payload, (normalize_host(target), port))
            .await
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        let (length, source) = self.socket.recv_from(output).await?;
        Ok((length, Some(source)))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

#[async_trait::async_trait]
impl UdpSocketLike for DirectCarrier {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        let target = if normalize_host(target)
            .eq_ignore_ascii_case(normalize_host(&self.target_host))
            && port == self.peer.port()
        {
            self.peer
        } else {
            let ip = normalize_host(target).parse::<IpAddr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "raw UDP carrier requires a resolved literal destination, got {target}"
                    ),
                )
            })?;
            let addr = SocketAddr::new(ip, port);
            if addr.is_ipv4() != self.peer.is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "raw UDP carrier address family differs: peer={}, alternate={addr}",
                        self.peer
                    ),
                ));
            }
            addr
        };
        let _ = &self.guard;
        self.socket.send_to(payload, target).await
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        let (length, source) = self.socket.recv_from(output).await?;
        Ok((length, Some(source)))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

fn normalize_host(host: &str) -> &str {
    host.trim()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| host.trim())
        .trim_end_matches('.')
}

#[derive(Debug)]
struct SendPacket {
    payload: Vec<u8>,
    destination: SocketAddr,
}

struct ReceivedPacket {
    payload: Vec<u8>,
    source: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
struct ErrorRecord {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl ErrorRecord {
    fn from_error(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string().into(),
        }
    }

    fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

/// Quinn-compatible socket over a fully composed `UdpSocketLike` carrier.
pub struct QuinnUdpSocket {
    logical_peer: Option<SocketAddr>,
    local_addr: SocketAddr,
    target_host: Option<Arc<str>>,
    target_port: u16,
    send_queue: Arc<Mutex<VecDeque<SendPacket>>>,
    send_work: Arc<Notify>,
    send_ready: Arc<Notify>,
    receive: Mutex<mpsc::Receiver<Result<ReceivedPacket, ErrorRecord>>>,
    terminal: Arc<Mutex<Option<ErrorRecord>>>,
    closed: Arc<AtomicBool>,
    carrier_ready_notify: Arc<Notify>,
}

impl fmt::Debug for QuinnUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuinnUdpSocket")
            .field("logical_peer", &self.logical_peer)
            .field("local_addr", &self.local_addr)
            .field("target_host", &self.target_host)
            .field("target_port", &self.target_port)
            .field("send_queue_len", &self.send_queue.lock().len())
            .finish_non_exhaustive()
    }
}

impl QuinnUdpSocket {
    pub fn new(
        inner: BoxedUdp,
        local_addr: SocketAddr,
        logical_peer: SocketAddr,
        target_host: String,
        target_port: u16,
    ) -> Arc<Self> {
        Self::build(
            inner,
            local_addr,
            Some(logical_peer),
            Some(target_host),
            target_port,
        )
    }

    /// Build a multi-peer Quinn socket for a FinalMask-wrapped server carrier.
    /// Unlike the client association, each receive record retains its source
    /// and each Quinn transmit supplies its own destination.
    pub fn new_server(inner: BoxedUdp, local_addr: SocketAddr) -> Arc<Self> {
        Self::build(inner, local_addr, None, None, 0)
    }

    fn build(
        inner: BoxedUdp,
        local_addr: SocketAddr,
        logical_peer: Option<SocketAddr>,
        target_host: Option<String>,
        target_port: u16,
    ) -> Arc<Self> {
        let inner: Arc<dyn crate::adapter::UdpSocketLike> = Arc::from(inner);
        let send_queue = Arc::new(Mutex::new(VecDeque::<SendPacket>::new()));
        let send_work = Arc::new(Notify::new());
        let send_ready = Arc::new(Notify::new());
        let terminal = Arc::new(Mutex::new(None));
        let closed = Arc::new(AtomicBool::new(false));
        // Client standalone headers perform a request/reply exchange in the
        // send path and must win the first read.  A server has no initiating
        // write, so its receive worker must start immediately.
        let carrier_ready = Arc::new(AtomicBool::new(logical_peer.is_none()));
        let carrier_ready_notify = Arc::new(Notify::new());
        let (receive_tx, receive_rx) = mpsc::channel(RECEIVE_QUEUE_PACKETS);

        spawn_send_worker(
            inner.clone(),
            send_queue.clone(),
            send_work.clone(),
            send_ready.clone(),
            terminal.clone(),
            closed.clone(),
            target_host.clone(),
            target_port,
            carrier_ready.clone(),
            carrier_ready_notify.clone(),
        );
        spawn_receive_worker(
            inner,
            receive_tx,
            terminal.clone(),
            closed.clone(),
            carrier_ready,
            carrier_ready_notify.clone(),
        );

        Arc::new(Self {
            logical_peer,
            local_addr,
            target_host: target_host.map(Into::into),
            target_port,
            send_queue,
            send_work,
            send_ready,
            receive: Mutex::new(receive_rx),
            terminal,
            closed,
            carrier_ready_notify,
        })
    }

    fn terminal_error(&self) -> Option<io::Error> {
        self.terminal.lock().as_ref().map(ErrorRecord::to_error)
    }
}

impl Drop for QuinnUdpSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.send_work.notify_waiters();
        self.send_ready.notify_waiters();
        self.carrier_ready_notify.notify_waiters();
    }
}

impl AsyncUdpSocket for QuinnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SendPoller {
            queue: self.send_queue.clone(),
            notify: self.send_ready.clone(),
            terminal: self.terminal.clone(),
            waiter: None,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if self
            .logical_peer
            .is_some_and(|logical_peer| transmit.destination != logical_peer)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "QUIC finalmask association is bound to {}, got {}",
                    self.logical_peer.expect("checked client peer"),
                    transmit.destination
                ),
            ));
        }
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len().max(1));
        let count = transmit.contents.len().div_ceil(segment).max(1);
        let mut queue = self.send_queue.lock();
        if queue.len() + count > SEND_QUEUE_PACKETS {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if transmit.contents.is_empty() {
            queue.push_back(SendPacket {
                payload: Vec::new(),
                destination: transmit.destination,
            });
        } else {
            for payload in transmit.contents.chunks(segment) {
                queue.push_back(SendPacket {
                    payload: payload.to_vec(),
                    destination: transmit.destination,
                });
            }
        }
        drop(queue);
        self.send_work.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        buffers: &mut [io::IoSliceMut<'_>],
        metadata: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let limit = buffers.len().min(metadata.len());
        if limit == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut receive = self.receive.lock();
        let mut count = 0;
        loop {
            match receive.poll_recv(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    if packet.payload.len() > buffers[count].len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "decoded finalmask datagram is {} bytes, Quinn supplied {}",
                                packet.payload.len(),
                                buffers[count].len()
                            ),
                        )));
                    }
                    let source = match self.logical_peer.or(packet.source) {
                        Some(source) => source,
                        None => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "server FinalMask carrier did not report a datagram source",
                            )));
                        }
                    };
                    buffers[count][..packet.payload.len()].copy_from_slice(&packet.payload);
                    metadata[count] = udp::RecvMeta {
                        addr: source,
                        len: packet.payload.len(),
                        stride: packet.payload.len(),
                        ecn: None,
                        dst_ip: local_ip(self.local_addr.ip()),
                    };
                    count += 1;
                    if count == limit {
                        return Poll::Ready(Ok(count));
                    }
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error.to_error())),
                Poll::Ready(None) => {
                    return Poll::Ready(match self.terminal_error() {
                        Some(error) => Err(error),
                        None if count > 0 => Ok(count),
                        None => Err(io::ErrorKind::NotConnected.into()),
                    });
                }
                Poll::Pending if count > 0 => return Poll::Ready(Ok(count)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

fn spawn_send_worker(
    inner: Arc<dyn crate::adapter::UdpSocketLike>,
    queue: Arc<Mutex<VecDeque<SendPacket>>>,
    work: Arc<Notify>,
    ready: Arc<Notify>,
    terminal: Arc<Mutex<Option<ErrorRecord>>>,
    closed: Arc<AtomicBool>,
    target: Option<String>,
    port: u16,
    carrier_ready: Arc<AtomicBool>,
    carrier_ready_notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        loop {
            loop {
                let packet = { queue.lock().pop_front() };
                let Some(packet) = packet else {
                    break;
                };
                ready.notify_waiters();
                let (target, port) = match target.as_deref() {
                    Some(target) => (target.to_owned(), port),
                    None => (
                        packet.destination.ip().to_string(),
                        packet.destination.port(),
                    ),
                };
                if let Err(error) = inner.send_to(&packet.payload, &target, port).await {
                    *terminal.lock() = Some(ErrorRecord::from_error(error));
                    closed.store(true, Ordering::Release);
                    ready.notify_waiters();
                    carrier_ready_notify.notify_waiters();
                    return;
                }
                // A standalone header-custom send performs its request/reply
                // authentication inside `send_to`.  Do not let the receive
                // worker race that exchange and hold MaskedUdp's receive gate.
                if !carrier_ready.swap(true, Ordering::AcqRel) {
                    carrier_ready_notify.notify_waiters();
                }
            }
            if closed.load(Ordering::Acquire) {
                let _ = inner.close().await;
                return;
            }
            work.notified().await;
        }
    });
}

fn spawn_receive_worker(
    inner: Arc<dyn crate::adapter::UdpSocketLike>,
    output: mpsc::Sender<Result<ReceivedPacket, ErrorRecord>>,
    terminal: Arc<Mutex<Option<ErrorRecord>>>,
    closed: Arc<AtomicBool>,
    carrier_ready: Arc<AtomicBool>,
    carrier_ready_notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        while !carrier_ready.load(Ordering::Acquire) {
            let notified = carrier_ready_notify.notified();
            if carrier_ready.load(Ordering::Acquire) || closed.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
        if closed.load(Ordering::Acquire) {
            return;
        }
        let mut buffer = vec![0; MAX_DATAGRAM];
        loop {
            if closed.load(Ordering::Acquire) {
                return;
            }
            match inner.recv_from_endpoint(&mut buffer).await {
                Ok((length, source)) if length <= buffer.len() => {
                    if output
                        .send(Ok(ReceivedPacket {
                            payload: buffer[..length].to_vec(),
                            source,
                        }))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok((length, _)) => {
                    let error = ErrorRecord {
                        kind: io::ErrorKind::InvalidData,
                        message: format!(
                            "UDP carrier returned {length} bytes for a {} byte buffer",
                            buffer.len()
                        )
                        .into(),
                    };
                    *terminal.lock() = Some(error.clone());
                    let _ = output.send(Err(error)).await;
                    return;
                }
                Err(error) => {
                    let error = ErrorRecord::from_error(error);
                    *terminal.lock() = Some(error.clone());
                    let _ = output.send(Err(error)).await;
                    return;
                }
            }
        }
    });
}

fn local_ip(ip: IpAddr) -> Option<IpAddr> {
    (!ip.is_unspecified()).then_some(ip)
}

struct SendPoller {
    queue: Arc<Mutex<VecDeque<SendPacket>>>,
    notify: Arc<Notify>,
    terminal: Arc<Mutex<Option<ErrorRecord>>>,
    waiter: Option<Pin<Box<tokio::sync::futures::OwnedNotified>>>,
}

impl fmt::Debug for SendPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalMaskSendPoller")
            .field("queue_len", &self.queue.lock().len())
            .finish_non_exhaustive()
    }
}

impl UdpPoller for SendPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if let Some(error) = self.terminal.lock().as_ref() {
            return Poll::Ready(Err(error.to_error()));
        }
        if self.waiter.is_none() {
            self.waiter = Some(Box::pin(self.notify.clone().notified_owned()));
        }
        let pending = self.waiter.as_mut().expect("waiter initialized");
        if pending.as_mut().poll(cx).is_ready() {
            self.waiter = None;
        }
        // Check capacity only after registering the notification to avoid a
        // lost wake if the worker pops between the check and registration.
        if self.queue.lock().len() < SEND_QUEUE_PACKETS {
            self.waiter = None;
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use futures::future::poll_fn;
    use tokio::sync::mpsc;

    use crate::adapter::UdpSocketLike;

    use super::*;

    struct EchoUdp {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    struct InlineHandshakeUdp {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        first: AtomicBool,
    }

    struct EndpointUdp {
        sent: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
        received: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait]
    impl UdpSocketLike for EndpointUdp {
        async fn send_to(&self, packet: &[u8], target: &str, port: u16) -> io::Result<usize> {
            let target = SocketAddr::new(
                target
                    .parse()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
                port,
            );
            self.sent
                .send((packet.to_vec(), target))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(packet.len())
        }

        async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
            self.recv_from_endpoint(output)
                .await
                .map(|(length, _)| length)
        }

        async fn recv_from_endpoint(
            &self,
            output: &mut [u8],
        ) -> io::Result<(usize, Option<SocketAddr>)> {
            let (packet, source) = self
                .received
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            output[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), Some(source)))
        }
    }

    #[async_trait]
    impl UdpSocketLike for InlineHandshakeUdp {
        async fn send_to(&self, packet: &[u8], _: &str, _: u16) -> io::Result<usize> {
            if !self.first.swap(true, Ordering::AcqRel) {
                self.tx
                    .send(b"standalone-ack".to_vec())
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
                let ack = tokio::time::timeout(
                    std::time::Duration::from_millis(250),
                    self.rx.lock().await.recv(),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake reply stolen"))?
                .ok_or(io::ErrorKind::UnexpectedEof)?;
                if ack != b"standalone-ack" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected standalone acknowledgement",
                    ));
                }
            }
            self.tx
                .send(packet.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(packet.len())
        }

        async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            output[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    #[async_trait]
    impl UdpSocketLike for EchoUdp {
        async fn send_to(&self, packet: &[u8], _: &str, _: u16) -> io::Result<usize> {
            self.tx
                .send(packet.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(packet.len())
        }

        async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            output[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    #[tokio::test]
    async fn preserves_gso_datagram_boundaries_and_backpressure_bridge() {
        let (tx, rx) = mpsc::unbounded_channel();
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let socket = QuinnUdpSocket::new(
            Box::new(EchoUdp {
                tx,
                rx: tokio::sync::Mutex::new(rx),
            }),
            "127.0.0.1:12345".parse().unwrap(),
            peer,
            "127.0.0.1".into(),
            443,
        );
        socket
            .try_send(&udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"aaaabbbb",
                segment_size: Some(4),
                src_ip: None,
            })
            .unwrap();

        let mut first = [0; 16];
        let mut second = [0; 16];
        let mut buffers = [
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
        ];
        let mut meta = [udp::RecvMeta::default(), udp::RecvMeta::default()];
        let count = poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
            .await
            .unwrap();
        assert!(count >= 1);
        assert_eq!(&first[..meta[0].len], b"aaaa");
        if count == 1 {
            let mut buffer = [0; 16];
            let mut buffers = [io::IoSliceMut::new(&mut buffer)];
            let mut meta = [udp::RecvMeta::default()];
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                .await
                .unwrap();
            assert_eq!(&buffer[..meta[0].len], b"bbbb");
        } else {
            assert_eq!(&second[..meta[1].len], b"bbbb");
        }
    }

    #[tokio::test]
    async fn receive_worker_waits_for_inline_standalone_handshake() {
        let (tx, rx) = mpsc::unbounded_channel();
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let socket = QuinnUdpSocket::new(
            Box::new(InlineHandshakeUdp {
                tx,
                rx: tokio::sync::Mutex::new(rx),
                first: AtomicBool::new(false),
            }),
            "127.0.0.1:12345".parse().unwrap(),
            peer,
            "127.0.0.1".into(),
            443,
        );
        // Give the receive task a chance to race. It must remain parked until
        // the first send (and its inline request/reply handshake) completes.
        tokio::task::yield_now().await;
        socket
            .try_send(&udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"quic-initial",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let mut buffer = [0; 64];
        let mut buffers = [io::IoSliceMut::new(&mut buffer)];
        let mut metadata = [udp::RecvMeta::default()];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata)),
        )
        .await
        .expect("standalone carrier deadlocked")
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&buffer[..metadata[0].len], b"quic-initial");
    }

    #[tokio::test]
    async fn server_bridge_preserves_each_peer_and_routes_replies() {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
        let local: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let first_peer: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let second_peer: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let socket = QuinnUdpSocket::new_server(
            Box::new(EndpointUdp {
                sent: outgoing_tx,
                received: tokio::sync::Mutex::new(incoming_rx),
            }),
            local,
        );
        incoming_tx.send((b"one".to_vec(), first_peer)).unwrap();
        incoming_tx.send((b"two".to_vec(), second_peer)).unwrap();

        let mut observed = Vec::new();
        while observed.len() < 2 {
            let mut first = [0; 16];
            let mut second = [0; 16];
            let mut buffers = [
                io::IoSliceMut::new(&mut first),
                io::IoSliceMut::new(&mut second),
            ];
            let mut metadata = [udp::RecvMeta::default(), udp::RecvMeta::default()];
            let count = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata)),
            )
            .await
            .expect("server receive bridge stalled")
            .unwrap();
            for index in 0..count {
                observed.push((
                    metadata[index].addr,
                    buffers[index][..metadata[index].len].to_vec(),
                ));
            }
        }
        assert_eq!(observed[0], (first_peer, b"one".to_vec()));
        assert_eq!(observed[1], (second_peer, b"two".to_vec()));

        socket
            .try_send(&udp::Transmit {
                destination: second_peer,
                ecn: None,
                contents: b"reply",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();
        let sent = tokio::time::timeout(std::time::Duration::from_secs(1), outgoing_rx.recv())
            .await
            .expect("server send bridge stalled")
            .expect("server send worker exited");
        assert_eq!(sent, (b"reply".to_vec(), second_peer));
    }
}
