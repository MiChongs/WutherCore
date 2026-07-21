//! XHTTP 2026 server-side transport.
//!
//! The implementation follows Xray's `splithttp` server semantics: a logical
//! byte stream is carried by `stream-one`, `stream-up`, or `packet-up` HTTP
//! requests. HTTP request tasks never run proxy protocol parsing themselves;
//! completed logical streams are delivered through an accepted-stream channel.

use std::{
    collections::{HashMap, VecDeque, hash_map::RandomState},
    convert::Infallible,
    error::Error as StdError,
    future::Future,
    hash::{BuildHasher, Hash, Hasher},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine;
use bytes::{Buf, Bytes};
use core_config::model::XHTTP_MAX_ACCEPT_QUEUE;
use core_outbound::{
    BoxedStream,
    proto::xhttp::{
        Config, Range,
        config::{
            PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH,
            PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER,
        },
        conn::{IoFailure, IoState, PipeWriter, ResponseItem, ResponseReader, XConn},
        upload_queue::{Packet, SequencePosition, UploadQueue},
        xpadding::{PaddingMethod, generate_padding, is_padding_valid},
    },
};
use h3::error::{Code, StreamError};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE},
};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as AutoBuilder,
};
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    xhttp_body_budget::{PacketBodyBudget, PacketBodyPermit},
    xhttp_cors::CorsPolicy,
};

const SESSION_TTL: Duration = Duration::from_secs(30);
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(4);
const PACKET_BODY_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const H3_ACCEPT_PROBE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_SESSIONS: usize = 4096;
const BODY_CHANNEL_CAPACITY: usize = 16;
const ACCEPT_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 128;
const DEFAULT_MAX_ACTIVE_HTTP_STREAMS: usize = 1024;
const DEFAULT_HTTP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const HTTP_OVERLOAD_REJECTION_TIMEOUT: Duration = Duration::from_secs(1);

type BoxedReader = Pin<Box<dyn AsyncRead + Send + Unpin>>;

struct HeaderTimeoutWatch {
    state: Mutex<HeaderTimeoutState>,
    changed: Notify,
    http_idle_timeout: Duration,
}

struct HeaderTimeoutState {
    generation: u64,
    armed: bool,
    deadline: tokio::time::Instant,
    deadline_kind: ConnectionTimeoutKind,
    h2_active_requests: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionTimeoutKind {
    RequestHeader,
    HttpIdle,
}

#[derive(Debug, Clone, Copy)]
enum RequestTimeoutToken {
    Http1 { generation: u64 },
    Http2,
}

struct RequestTimeoutGuard {
    watch: Arc<HeaderTimeoutWatch>,
    token: Option<RequestTimeoutToken>,
}

impl RequestTimeoutGuard {
    fn into_finish_callback(mut self) -> impl FnOnce() + Send + 'static {
        let watch = Arc::clone(&self.watch);
        let token = self
            .token
            .take()
            .expect("XHTTP request timeout guard token already consumed");
        move || watch.request_finished(token)
    }
}

impl Drop for RequestTimeoutGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.watch.request_finished(token);
        }
    }
}

impl HeaderTimeoutWatch {
    fn new(header_timeout: Duration, http_idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HeaderTimeoutState {
                generation: 0,
                armed: true,
                deadline: tokio::time::Instant::now() + header_timeout,
                deadline_kind: ConnectionTimeoutKind::RequestHeader,
                h2_active_requests: 0,
            }),
            changed: Notify::new(),
            http_idle_timeout,
        })
    }

    fn request_started(self: &Arc<Self>, version: Version) -> RequestTimeoutGuard {
        let mut state = self.state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.armed = false;
        let token = if version == Version::HTTP_2 {
            state.h2_active_requests = state.h2_active_requests.saturating_add(1);
            RequestTimeoutToken::Http2
        } else {
            RequestTimeoutToken::Http1 {
                generation: state.generation,
            }
        };
        drop(state);
        self.changed.notify_waiters();
        RequestTimeoutGuard {
            watch: Arc::clone(self),
            token: Some(token),
        }
    }

    fn request_finished(&self, token: RequestTimeoutToken) {
        let mut state = self.state.lock();
        match token {
            RequestTimeoutToken::Http1 { generation } => {
                if state.generation != generation {
                    return;
                }
            }
            RequestTimeoutToken::Http2 => {
                if state.h2_active_requests == 0 {
                    return;
                }
                state.h2_active_requests -= 1;
                if state.h2_active_requests != 0 {
                    return;
                }
                state.generation = state.generation.wrapping_add(1);
            }
        }
        state.armed = true;
        state.deadline = tokio::time::Instant::now() + self.http_idle_timeout;
        state.deadline_kind = ConnectionTimeoutKind::HttpIdle;
        drop(state);
        self.changed.notify_waiters();
    }

    async fn wait_for_timeout(&self) -> ConnectionTimeoutKind {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let snapshot = {
                let state = self.state.lock();
                state
                    .armed
                    .then_some((state.generation, state.deadline, state.deadline_kind))
            };
            let Some((generation, deadline, deadline_kind)) = snapshot else {
                changed.await;
                continue;
            };
            tokio::select! {
                _ = &mut changed => {}
                _ = tokio::time::sleep_until(deadline) => {
                    let state = self.state.lock();
                    if state.armed
                        && state.generation == generation
                        && tokio::time::Instant::now() >= state.deadline
                    {
                        return deadline_kind;
                    }
                }
            }
        }
    }
}

/// HTTP version which carried an accepted logical XHTTP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpVersion {
    Http1,
    Http2,
    Http3,
}

/// HTTP versions which a TCP XHTTP frontend is allowed to serve.
///
/// Low-level callers default to [`Self::HTTP1_AND_HTTP2`] for backwards
/// compatibility. Configured listeners use an explicit policy so Hyper's
/// protocol auto-detection cannot bypass the listener's ALPN allow-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpVersionPolicy {
    Http1Only,
    Http2Only,
    Http1AndHttp2,
}

impl HttpVersionPolicy {
    pub(crate) const HTTP1_AND_HTTP2: Self = Self::Http1AndHttp2;

    pub(crate) const fn from_allowances(allow_http1: bool, allow_http2: bool) -> Option<Self> {
        match (allow_http1, allow_http2) {
            (true, false) => Some(Self::Http1Only),
            (false, true) => Some(Self::Http2Only),
            (true, true) => Some(Self::Http1AndHttp2),
            (false, false) => None,
        }
    }

    const fn allows(self, version: Version) -> bool {
        match self {
            Self::Http1Only => matches!(version, Version::HTTP_11),
            Self::Http2Only => matches!(version, Version::HTTP_2),
            Self::Http1AndHttp2 => matches!(version, Version::HTTP_11 | Version::HTTP_2),
        }
    }

    fn from_negotiated_alpn(self, alpn: Option<&[u8]>) -> io::Result<Self> {
        match alpn {
            Some(b"http/1.1") if self.allows(Version::HTTP_11) => Ok(Self::Http1Only),
            Some(b"h2") if self.allows(Version::HTTP_2) => Ok(Self::Http2Only),
            Some(value) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "XHTTP TLS negotiated unsupported ALPN `{}`",
                    String::from_utf8_lossy(value)
                ),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XHTTP TLS requires a negotiated HTTP ALPN",
            )),
        }
    }
}

/// One logical proxy byte stream accepted from XHTTP.
pub struct AcceptedXhttpStream {
    pub stream: BoxedStream,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub session_id: Option<String>,
    pub mode: &'static str,
    pub version: XhttpVersion,
}

/// Receiver side exposed to the proxy-protocol inbound layer.
pub struct XhttpAcceptReceiver {
    rx: mpsc::Receiver<AcceptedXhttpStream>,
}

impl XhttpAcceptReceiver {
    pub async fn accept(&mut self) -> Option<AcceptedXhttpStream> {
        self.rx.recv().await
    }

    /// Receive only the logical byte stream when transport metadata is not
    /// needed by the outer proxy protocol.
    pub async fn accept_stream(&mut self) -> Option<BoxedStream> {
        self.accept().await.map(|accepted| accepted.stream)
    }

    pub fn close(&mut self) {
        self.rx.close();
    }
}

/// Cloneable server state shared by HTTP/1.1, HTTP/2 and HTTP/3 frontends.
#[derive(Clone)]
pub struct XhttpServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    config: Config,
    host: String,
    path: String,
    cors_policy: CorsPolicy,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    sessions_changed: Notify,
    packet_body_budget: PacketBodyBudget,
    accepted: mpsc::Sender<AcceptedXhttpStream>,
    accept_delivery_timeout: Duration,
    connection_slots: Arc<Semaphore>,
    max_concurrent_streams: u32,
    http_stream_slots: Arc<Semaphore>,
    http_idle_timeout: Duration,
    cancelled: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadKind {
    Unset,
    Packet,
    Stream,
}

struct Session {
    id: String,
    source_kind: Mutex<UploadKind>,
    source_tx: Mutex<Option<oneshot::Sender<BoxedReader>>>,
    source_rx: Mutex<Option<oneshot::Receiver<BoxedReader>>>,
    upload_queue: Arc<UploadQueue>,
    packet_retry_history: Mutex<PacketRetryHistory>,
    packet_hashers: [RandomState; 2],
    io_state: Arc<IoState>,
    cancelled: CancellationToken,
    fully_connected: AtomicBool,
    fully_connected_notify: Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacketFingerprint {
    len: usize,
    hashes: [u64; 2],
}

struct PacketRetryHistory {
    fingerprints: HashMap<u64, PacketFingerprint>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl Session {
    fn new(id: String, max_buffered_posts: usize) -> Arc<Self> {
        let (source_tx, source_rx) = oneshot::channel();
        // Keep enough consumed sequence fingerprints to cover four complete
        // configured reassembly windows. A fixed 256-entry cap made an
        // identical HTTP retry turn into a false conflict whenever
        // scMaxBufferedPosts was configured above 64.
        let retry_history_capacity = max_buffered_posts.saturating_mul(4).max(64);
        Arc::new(Self {
            id,
            source_kind: Mutex::new(UploadKind::Unset),
            source_tx: Mutex::new(Some(source_tx)),
            source_rx: Mutex::new(Some(source_rx)),
            upload_queue: UploadQueue::new(max_buffered_posts),
            packet_retry_history: Mutex::new(PacketRetryHistory {
                // Do not preallocate from a trusted-but-unbounded config
                // integer; grow only as real packet history arrives.
                fingerprints: HashMap::new(),
                order: VecDeque::new(),
                capacity: retry_history_capacity,
            }),
            packet_hashers: [RandomState::new(), RandomState::new()],
            io_state: IoState::shared(),
            cancelled: CancellationToken::new(),
            fully_connected: AtomicBool::new(false),
            fully_connected_notify: Notify::new(),
        })
    }

    fn select_packet_source(&self) -> io::Result<()> {
        let mut kind = self.source_kind.lock();
        match *kind {
            UploadKind::Packet => return Ok(()),
            UploadKind::Stream => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "XHTTP session already uses stream-up",
                ));
            }
            UploadKind::Unset => *kind = UploadKind::Packet,
        }
        drop(kind);
        self.publish_source(Box::pin(self.upload_queue.reader()))
    }

    fn select_stream_source(&self) -> io::Result<mpsc::Sender<ResponseItem>> {
        let mut kind = self.source_kind.lock();
        if *kind != UploadKind::Unset {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "XHTTP upload source already exists",
            ));
        }
        *kind = UploadKind::Stream;
        drop(kind);

        let (reader, sender) =
            ResponseReader::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&self.io_state));
        self.publish_source(Box::pin(reader))?;
        Ok(sender)
    }

    fn push_packet(&self, seq: u64, payload: Bytes) -> io::Result<()> {
        let fingerprint = PacketFingerprint {
            len: payload.len(),
            hashes: self
                .packet_hashers
                .each_ref()
                .map(|builder| hash_packet_payload(builder, &payload)),
        };
        let mut history = self.packet_retry_history.lock();
        if let Some(previous) = history.fingerprints.get(&seq) {
            return if *previous == fingerprint {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("XHTTP upload sequence {seq} was retried with different payload"),
                ))
            };
        }

        self.upload_queue.push(Packet { seq, payload })?;
        history.fingerprints.insert(seq, fingerprint);
        history.order.push_back(seq);
        while history.order.len() > history.capacity {
            if let Some(expired) = history.order.pop_front() {
                history.fingerprints.remove(&expired);
            }
        }
        Ok(())
    }

    fn publish_source(&self, reader: BoxedReader) -> io::Result<()> {
        let Some(sender) = self.source_tx.lock().take() else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "XHTTP upload source already published",
            ));
        };
        sender.send(reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP logical stream closed before upload arrived",
            )
        })
    }

    fn take_reader(&self) -> io::Result<DeferredReader> {
        let Some(receiver) = self.source_rx.lock().take() else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "XHTTP download request already attached",
            ));
        };
        Ok(DeferredReader {
            receiver,
            reader: None,
            state: Arc::clone(&self.io_state),
        })
    }

    fn mark_fully_connected(&self) {
        if !self.fully_connected.swap(true, Ordering::AcqRel) {
            self.fully_connected_notify.notify_waiters();
        }
    }

    fn cancel(&self, reason: &'static str) {
        self.cancelled.cancel();
        self.io_state
            .fail(IoFailure::new(io::ErrorKind::ConnectionAborted, reason));
        self.upload_queue
            .fail(io::ErrorKind::ConnectionAborted, reason);
        self.source_tx.lock().take();
    }

    /// Close a fully-established session without turning an ordinary peer
    /// shutdown into an application I/O error.
    fn close_clean(&self) {
        self.cancelled.cancel();
        self.io_state.cancel();
        self.upload_queue.close();
        self.source_tx.lock().take();
    }
}

struct DeferredReader {
    receiver: oneshot::Receiver<BoxedReader>,
    reader: Option<BoxedReader>,
    state: Arc<IoState>,
}

impl AsyncRead for DeferredReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(reader) = self.reader.as_mut() {
                return reader.as_mut().poll_read(cx, dst);
            }
            match Pin::new(&mut self.receiver).poll(cx) {
                Poll::Ready(Ok(reader)) => self.reader = Some(reader),
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(self.state.error().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "XHTTP session expired before upload arrived",
                        )
                    })));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Hyper response body backed by the logical stream's downlink channel.
pub struct XhttpBody {
    rx: Option<mpsc::Receiver<Bytes>>,
    one: Option<Bytes>,
    state: Option<Arc<IoState>>,
    on_finish: Option<Box<dyn FnOnce() + Send>>,
}

impl XhttpBody {
    fn empty() -> Self {
        Self {
            rx: None,
            one: None,
            state: None,
            on_finish: None,
        }
    }

    fn once(bytes: impl Into<Bytes>) -> Self {
        Self {
            rx: None,
            one: Some(bytes.into()),
            state: None,
            on_finish: None,
        }
    }

    fn channel(rx: mpsc::Receiver<Bytes>, state: Arc<IoState>) -> Self {
        Self {
            rx: Some(rx),
            one: None,
            state: Some(state),
            on_finish: None,
        }
    }

    fn with_on_finish(mut self, callback: impl FnOnce() + Send + 'static) -> Self {
        let previous = self.on_finish.take();
        self.on_finish = Some(Box::new(move || {
            if let Some(previous) = previous {
                previous();
            }
            callback();
        }));
        self
    }

    fn finish(&mut self) {
        self.rx = None;
        if let Some(callback) = self.on_finish.take() {
            callback();
        }
    }
}

impl Body for XhttpBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.one.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        let Some(receiver) = self.rx.as_mut() else {
            self.finish();
            return Poll::Ready(None);
        };
        match receiver.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.one {
            Some(bytes) => SizeHint::with_exact(bytes.len() as u64),
            None if self.rx.is_none() => SizeHint::with_exact(0),
            None => SizeHint::default(),
        }
    }
}

impl Drop for XhttpBody {
    fn drop(&mut self) {
        if self.rx.is_some() {
            if let Some(state) = &self.state {
                state.cancel();
            }
        }
        self.finish();
    }
}

impl XhttpServer {
    /// Validate and construct a server plus its accepted-stream receiver.
    pub fn new(
        config: Config,
        accept_capacity: Option<usize>,
    ) -> io::Result<(Self, XhttpAcceptReceiver)> {
        Self::new_with_cors(config, accept_capacity, CorsPolicy::XrayCompatible)
    }

    pub(crate) fn new_with_cors(
        config: Config,
        accept_capacity: Option<usize>,
        cors_policy: CorsPolicy,
    ) -> io::Result<(Self, XhttpAcceptReceiver)> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = config
            .resolved()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let keepalive = config
            .normalized_sc_stream_up_server_secs()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if keepalive.max > 0 && keepalive.min == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scStreamUpServerSecs cannot start at zero when keepalive is enabled",
            ));
        }
        let host = config.host.clone();
        let path = normalized_server_path(&config);
        let packet_body_budget = PacketBodyBudget::new(
            config
                .normalized_sc_max_each_post_bytes()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
                .max,
            config.normalized_sc_max_buffered_posts(),
        )?;
        let accept_capacity = accept_capacity.unwrap_or(ACCEPT_CHANNEL_CAPACITY).max(1);
        if accept_capacity > XHTTP_MAX_ACCEPT_QUEUE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("XHTTP accept capacity cannot exceed {XHTTP_MAX_ACCEPT_QUEUE}"),
            ));
        }
        let (accepted, rx) = mpsc::channel(accept_capacity);
        Ok((
            Self {
                inner: Arc::new(ServerInner {
                    config,
                    host,
                    path,
                    cors_policy,
                    sessions: Mutex::new(HashMap::new()),
                    sessions_changed: Notify::new(),
                    packet_body_budget,
                    accepted,
                    accept_delivery_timeout: ACCEPT_DELIVERY_TIMEOUT,
                    connection_slots: Arc::new(Semaphore::new(DEFAULT_MAX_ACTIVE_CONNECTIONS)),
                    max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
                    http_stream_slots: Arc::new(Semaphore::new(DEFAULT_MAX_ACTIVE_HTTP_STREAMS)),
                    http_idle_timeout: DEFAULT_HTTP_IDLE_TIMEOUT,
                    cancelled: CancellationToken::new(),
                }),
            },
            XhttpAcceptReceiver { rx },
        ))
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub(crate) fn configure_listener_resources(
        &mut self,
        max_active_connections: usize,
        max_concurrent_streams: u32,
        max_active_http_streams: usize,
        http_idle_timeout: Duration,
    ) -> io::Result<()> {
        if max_active_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP max-active-connections must be greater than zero",
            ));
        }
        if max_active_connections > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "XHTTP max-active-connections cannot exceed {}",
                    Semaphore::MAX_PERMITS
                ),
            ));
        }
        if max_concurrent_streams == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP max-concurrent-streams must be greater than zero",
            ));
        }
        if max_active_http_streams == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP max-active-http-streams must be greater than zero",
            ));
        }
        if max_active_http_streams > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "XHTTP max-active-http-streams cannot exceed {}",
                    Semaphore::MAX_PERMITS
                ),
            ));
        }
        if http_idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP http-idle-timeout must be greater than zero",
            ));
        }
        let inner = Arc::get_mut(&mut self.inner).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "XHTTP listener resources must be configured before the server is shared",
            )
        })?;
        inner.connection_slots = Arc::new(Semaphore::new(max_active_connections));
        inner.max_concurrent_streams = max_concurrent_streams;
        inner.http_stream_slots = Arc::new(Semaphore::new(max_active_http_streams));
        inner.http_idle_timeout = http_idle_timeout;
        Ok(())
    }

    fn try_acquire_http_stream(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.inner.http_stream_slots)
            .try_acquire_owned()
            .ok()
    }

    pub fn close(&self) {
        self.inner.cancelled.cancel();
        let sessions: Vec<_> = self.inner.sessions.lock().drain().map(|(_, v)| v).collect();
        self.inner.sessions_changed.notify_waiters();
        for session in sessions {
            session.cancel("XHTTP server closed");
        }
    }

    fn upsert_session(&self, id: &str) -> io::Result<Arc<Session>> {
        validate_session_id(id)?;
        if let Some(session) = self.inner.sessions.lock().get(id).cloned() {
            return Ok(session);
        }

        let session = Session::new(
            id.to_owned(),
            self.inner.config.normalized_sc_max_buffered_posts(),
        );
        {
            let mut sessions = self.inner.sessions.lock();
            if let Some(current) = sessions.get(id) {
                return Ok(Arc::clone(current));
            }
            if sessions.len() >= MAX_SESSIONS {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "XHTTP session limit reached",
                ));
            }
            sessions.insert(id.to_owned(), Arc::clone(&session));
        }
        self.inner.sessions_changed.notify_waiters();

        spawn_session_reaper(
            Arc::downgrade(&self.inner),
            Arc::clone(&session),
            SESSION_TTL,
        );
        Ok(session)
    }

    fn find_session(&self, id: &str) -> Option<Arc<Session>> {
        self.inner.sessions.lock().get(id).cloned()
    }

    async fn reserve_packet_body(
        &self,
        session_id: &str,
        sequence: u64,
        timeout: Duration,
    ) -> Result<PacketBodyPermit, RequestError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut normal_only = false;

        loop {
            // Register before reading the map. `notify_waiters` does not retain
            // a permit, so enabling first closes the insert/remove race.
            let sessions_changed = self.inner.sessions_changed.notified();
            tokio::pin!(sessions_changed);
            sessions_changed.as_mut().enable();

            let session = self.find_session(session_id);
            let position = session.as_ref().map_or_else(
                || {
                    if sequence == 0 {
                        SequencePosition::Next
                    } else {
                        SequencePosition::Future
                    }
                },
                |session| session.upload_queue.sequence_position(sequence),
            );
            let observed_sequence = session
                .as_ref()
                .map(|session| session.upload_queue.next_sequence());
            let sequence_changed =
                wait_for_packet_sequence_change(session.clone(), observed_sequence);
            tokio::pin!(sequence_changed);

            if normal_only || position != SequencePosition::Next {
                let cancelled =
                    packet_request_cancelled(self.inner.cancelled.clone(), session.clone());
                let acquire = self.inner.packet_body_budget.acquire_normal(cancelled);
                tokio::pin!(acquire);
                tokio::select! {
                    biased;
                    result = &mut acquire => return result.map_err(packet_budget_error),
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(packet_budget_timeout());
                    }
                    _ = &mut sessions_changed => {}
                    _ = &mut sequence_changed, if position == SequencePosition::Future => {}
                }
                continue;
            }

            // Poll normal first. With a free normal slot this preserves the
            // configured concurrent POST capacity; priority is used only when
            // normal is currently unable to satisfy the complete reservation.
            let normal_cancelled =
                packet_request_cancelled(self.inner.cancelled.clone(), session.clone());
            let priority_cancelled =
                packet_request_cancelled(self.inner.cancelled.clone(), session.clone());
            let normal = self
                .inner
                .packet_body_budget
                .acquire_normal(normal_cancelled);
            let priority = self
                .inner
                .packet_body_budget
                .acquire_priority(priority_cancelled);
            tokio::pin!(normal);
            tokio::pin!(priority);
            let priority_permit = tokio::select! {
                biased;
                result = &mut normal => return result.map_err(packet_budget_error),
                result = &mut priority => Some(result.map_err(packet_budget_error)?),
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(packet_budget_timeout());
                }
                _ = &mut sessions_changed => None,
                _ = &mut sequence_changed => None,
            };
            let Some(priority_permit) = priority_permit else {
                continue;
            };

            // The reader may have advanced while the priority semaphore was
            // being acquired. Priority is valid only for the exact missing
            // sequence; a now-past retry must release it and use normal.
            let current_position = self.find_session(session_id).map_or_else(
                || {
                    if sequence == 0 {
                        SequencePosition::Next
                    } else {
                        SequencePosition::Future
                    }
                },
                |session| session.upload_queue.sequence_position(sequence),
            );
            match current_position {
                SequencePosition::Next => return Ok(priority_permit),
                SequencePosition::Past => {
                    drop(priority_permit);
                    normal_only = true;
                }
                SequencePosition::Future => drop(priority_permit),
            }
        }
    }

    fn finish_packet_upload(
        &self,
        session_id: &str,
        sequence: u64,
        payload: Bytes,
    ) -> Result<(), RequestError> {
        let session = self.upsert_session(session_id).map_err(|error| {
            RequestError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
        })?;
        session
            .select_packet_source()
            .map_err(|error| RequestError::new(StatusCode::CONFLICT, error.to_string()))?;
        session.push_packet(sequence, payload).map_err(|error| {
            let status = match error.kind() {
                io::ErrorKind::AlreadyExists => StatusCode::CONFLICT,
                io::ErrorKind::OutOfMemory => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            RequestError::new(status, error.to_string())
        })
    }

    fn accepted_session_mode(&self, session: &Session) -> &'static str {
        match self.inner.config.normalized_mode() {
            "stream-one" => "stream-one",
            "stream-up" => "stream-up",
            "packet-up" => "packet-up",
            _ => match *session.source_kind.lock() {
                UploadKind::Stream => "stream-up",
                UploadKind::Packet => "packet-up",
                UploadKind::Unset => "auto",
            },
        }
    }
}

async fn packet_request_cancelled(server: CancellationToken, session: Option<Arc<Session>>) {
    packet_cancellation_tokens_cancelled(server, session.map(|session| session.cancelled.clone()))
        .await;
}

async fn packet_cancellation_tokens_cancelled(
    server: CancellationToken,
    session: Option<CancellationToken>,
) {
    if let Some(session) = session {
        tokio::select! {
            _ = server.cancelled() => {}
            _ = session.cancelled() => {}
        }
    } else {
        server.cancelled().await;
    }
}

async fn wait_for_packet_sequence_change(session: Option<Arc<Session>>, observed: Option<u64>) {
    match (session, observed) {
        (Some(session), Some(observed)) => {
            session
                .upload_queue
                .wait_for_sequence_change(observed)
                .await;
        }
        _ => std::future::pending::<()>().await,
    }
}

fn packet_budget_timeout() -> RequestError {
    RequestError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "XHTTP packet body budget wait timed out",
    )
}

fn packet_budget_error(error: io::Error) -> RequestError {
    let status = match error.kind() {
        io::ErrorKind::Interrupted | io::ErrorKind::BrokenPipe => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    RequestError::new(status, error.to_string())
}

fn packet_body_idle_timeout() -> RequestError {
    RequestError::new(
        StatusCode::REQUEST_TIMEOUT,
        "XHTTP packet request body was idle for too long",
    )
}

fn packet_body_cancelled_error() -> RequestError {
    RequestError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "XHTTP packet request body cancelled",
    )
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use http_body_util::{BodyExt as _, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        task::JoinHandle,
    };

    use super::*;

    fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    struct PendingBody;

    impl Body for PendingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    fn test_config(mode: &str) -> Config {
        let mut config = Config::default();
        config.host = "127.0.0.1".into();
        config.path = "/x".into();
        config.mode = mode.into();
        config.x_padding_bytes = "4".into();
        config.sc_max_each_post_bytes = "1024".into();
        config.sc_max_buffered_posts = 4;
        config
    }

    #[test]
    fn http_version_policy_is_exactly_http11_and_http2() {
        let both = HttpVersionPolicy::HTTP1_AND_HTTP2;
        assert!(both.allows(Version::HTTP_11));
        assert!(both.allows(Version::HTTP_2));
        assert!(!both.allows(Version::HTTP_09));
        assert!(!both.allows(Version::HTTP_10));
        assert!(!both.allows(Version::HTTP_3));

        let http1 = HttpVersionPolicy::from_allowances(true, false).unwrap();
        assert!(http1.allows(Version::HTTP_11));
        assert!(!http1.allows(Version::HTTP_2));

        let http2 = HttpVersionPolicy::from_allowances(false, true).unwrap();
        assert!(!http2.allows(Version::HTTP_11));
        assert!(http2.allows(Version::HTTP_2));
        assert!(HttpVersionPolicy::from_allowances(false, false).is_none());
    }

    async fn start_server(
        mode: &str,
    ) -> (
        XhttpServer,
        XhttpAcceptReceiver,
        SocketAddr,
        CancellationToken,
        JoinHandle<io::Result<()>>,
    ) {
        start_server_with_accept_timeout(mode, 8, ACCEPT_DELIVERY_TIMEOUT).await
    }

    async fn start_server_with_accept_timeout(
        mode: &str,
        accept_capacity: usize,
        accept_delivery_timeout: Duration,
    ) -> (
        XhttpServer,
        XhttpAcceptReceiver,
        SocketAddr,
        CancellationToken,
        JoinHandle<io::Result<()>>,
    ) {
        let (mut server, receiver) =
            XhttpServer::new(test_config(mode), Some(accept_capacity)).unwrap();
        Arc::get_mut(&mut server.inner)
            .expect("new XHTTP server unexpectedly shared its inner state")
            .accept_delivery_timeout = accept_delivery_timeout;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_listener(listener, shutdown).await })
        };
        (server, receiver, address, shutdown, serving)
    }

    async fn start_single_h2_server(
        mode: &str,
        http_idle_timeout: Duration,
    ) -> (
        XhttpServer,
        XhttpAcceptReceiver,
        SocketAddr,
        CancellationToken,
        JoinHandle<io::Result<()>>,
    ) {
        start_single_h2_server_with_options(
            mode,
            http_idle_timeout,
            8,
            ACCEPT_DELIVERY_TIMEOUT,
            DEFAULT_MAX_CONCURRENT_STREAMS,
            DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
        )
        .await
    }

    async fn start_single_h2_server_with_options(
        mode: &str,
        http_idle_timeout: Duration,
        accept_capacity: usize,
        accept_delivery_timeout: Duration,
        max_concurrent_streams: u32,
        max_active_http_streams: usize,
    ) -> (
        XhttpServer,
        XhttpAcceptReceiver,
        SocketAddr,
        CancellationToken,
        JoinHandle<io::Result<()>>,
    ) {
        let (mut server, receiver) =
            XhttpServer::new(test_config(mode), Some(accept_capacity)).unwrap();
        server
            .configure_listener_resources(
                DEFAULT_MAX_ACTIVE_CONNECTIONS,
                max_concurrent_streams,
                max_active_http_streams,
                http_idle_timeout,
            )
            .unwrap();
        Arc::get_mut(&mut server.inner)
            .expect("new XHTTP server unexpectedly shared its inner state")
            .accept_delivery_timeout = accept_delivery_timeout;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let (stream, peer_addr) = listener.accept().await?;
                let local_addr = stream.local_addr()?;
                server
                    .serve_io_until_with_header_timeout(
                        stream,
                        peer_addr,
                        local_addr,
                        shutdown,
                        Duration::from_secs(1),
                        HttpVersionPolicy::Http2Only,
                    )
                    .await
            })
        };
        (server, receiver, address, shutdown, serving)
    }

    fn fill_accept_queue(server: &XhttpServer) -> tokio::io::DuplexStream {
        let (placeholder, peer) = tokio::io::duplex(1);
        server
            .inner
            .accepted
            .try_send(AcceptedXhttpStream {
                stream: Box::pin(placeholder),
                peer_addr: "127.0.0.1:1".parse().unwrap(),
                local_addr: "127.0.0.1:2".parse().unwrap(),
                session_id: None,
                mode: "accept-queue-placeholder",
                version: XhttpVersion::Http1,
            })
            .expect("failed to fill the XHTTP accept queue");
        peer
    }

    fn assert_only_accept_placeholder(receiver: &mut XhttpAcceptReceiver) {
        let placeholder = receiver
            .rx
            .try_recv()
            .expect("accept queue placeholder disappeared");
        assert_eq!(placeholder.mode, "accept-queue-placeholder");
        assert!(
            matches!(
                receiver.rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "backpressured request leaked a logical accepted stream"
        );
    }

    async fn wait_for_available_connection_slots(server: &XhttpServer, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if server.inner.connection_slots.available_permits() == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "XHTTP connection slots did not reach {expected}; current={}",
                server.inner.connection_slots.available_permits()
            )
        });
    }

    async fn stop_server(
        server: XhttpServer,
        shutdown: CancellationToken,
        serving: JoinHandle<io::Result<()>>,
    ) {
        shutdown.cancel();
        server.close();
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("server did not stop")
            .expect("server task panicked")
            .expect("server returned an error");
    }

    fn raw_request(method: &str, path: &str, address: SocketAddr, body: &[u8]) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nReferer: http://127.0.0.1/x/?x_padding=XXXX\r\nContent-Length: {}\r\n\r\n",
            address.port(),
            body.len()
        )
        .bytes()
        .chain(body.iter().copied())
        .collect()
    }

    async fn open_raw(address: SocketAddr, method: &str, path: &str, body: &[u8]) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&raw_request(method, path, address, body))
            .await
            .unwrap();
        stream
    }

    async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut output = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "response ended before expected bytes");
                output.extend_from_slice(&chunk[..read]);
                if output.windows(needle.len()).any(|window| window == needle) {
                    return output;
                }
            }
        })
        .await
        .expect("response timed out")
    }

    async fn post_and_read_headers(address: SocketAddr, path: &str, body: &[u8]) -> Vec<u8> {
        let mut stream = open_raw(address, "POST", path, body).await;
        read_until(&mut stream, b"\r\n\r\n").await
    }

    #[test]
    fn placement_extracts_path_query_header_and_cookie() {
        let mut config = test_config("packet-up");
        config.session_placement = "header".into();
        config.session_key = "X-Session-ID".into();
        config.seq_placement = "cookie".into();
        config.seq_key = "seq_no".into();
        let request = Request::builder()
            .uri("/x/?unused=1")
            .header("X-Session-ID", "session-a")
            .header(COOKIE, "other=x; seq_no=17")
            .body(())
            .unwrap();
        assert_eq!(
            extract_meta(&config, request.uri(), request.headers(), "/x/").unwrap(),
            ("session-a".into(), "17".into())
        );

        config.session_placement = "path".into();
        config.seq_placement = "query".into();
        config.seq_key = "sequence".into();
        let request = Request::builder()
            .uri("/x/path+session?sequence=23")
            .body(())
            .unwrap();
        assert_eq!(
            extract_meta(&config, request.uri(), request.headers(), "/x/").unwrap(),
            ("path+session".into(), "23".into())
        );

        let malformed_path = Request::builder()
            .uri("/x/%ZZ?sequence=23")
            .body(())
            .unwrap();
        assert!(
            extract_meta(
                &config,
                malformed_path.uri(),
                malformed_path.headers(),
                "/x/"
            )
            .is_err()
        );

        config.session_placement = "path".into();
        config.seq_placement = "path".into();
        let empty_session = Request::builder().uri("/x//17").body(()).unwrap();
        assert_eq!(
            extract_meta(&config, empty_session.uri(), empty_session.headers(), "/x/").unwrap(),
            (String::new(), "17".into())
        );
        let encoded_separator = Request::builder().uri("/x/session%2F29").body(()).unwrap();
        assert_eq!(
            extract_meta(
                &config,
                encoded_separator.uri(),
                encoded_separator.headers(),
                "/x/"
            )
            .unwrap(),
            ("session".into(), "29".into())
        );
        config.session_placement = "query".into();
        config.session_key = "session".into();
        let malformed_query = Request::builder()
            .uri("/x/?session=%ZZ&sequence=23")
            .body(())
            .unwrap();
        assert_eq!(
            extract_meta(
                &config,
                malformed_query.uri(),
                malformed_query.headers(),
                "/x/"
            )
            .unwrap(),
            (String::new(), String::new())
        );
    }

    #[test]
    fn go_query_parser_skips_bad_pairs_preserves_first_duplicate_and_decodes_plus() {
        let request = Request::builder()
            .uri("/x/?sid=bad%ZZ&sid=first+value&sid=second&raw;bad=x&bare&tilde=%7e")
            .body(())
            .unwrap();
        assert_eq!(
            query_value(request.uri(), "sid").as_deref(),
            Some("first value")
        );
        assert_eq!(query_value(request.uri(), "bare").as_deref(), Some(""));
        assert_eq!(query_value(request.uri(), "tilde").as_deref(), Some("~"));
        assert_eq!(query_value(request.uri(), "raw"), None);
    }

    #[test]
    fn go_query_parser_returns_no_values_above_10000_pairs() {
        let oversized = std::iter::repeat_n("sid=value", 10_001)
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(go_query_value(&oversized, "sid"), None);

        let at_limit = std::iter::repeat_n("other=x", 9_999)
            .chain(std::iter::once("sid=value"))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(go_query_value(&at_limit, "sid").as_deref(), Some("value"));
    }

    #[test]
    fn go_cookie_parser_accepts_add_cookie_golden_header_and_unquotes_value() {
        let request = Request::builder()
            .uri("/x/")
            .header(
                COOKIE,
                "user=1; data_0=-_8; pad=XXXX; sid=\"a b,cde%\"; seq=7",
            )
            .body(())
            .unwrap();
        assert_eq!(
            cookie_value(request.headers(), "sid").as_deref(),
            Some("a b,cde%")
        );
        assert_eq!(cookie_value(request.headers(), "seq").as_deref(), Some("7"));
        assert_eq!(
            cookie_chunks(request.headers(), "data").unwrap(),
            [0xfb, 0xff]
        );
    }

    #[test]
    fn go_cookie_parser_skips_invalid_same_name_and_accepts_empty_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_bytes(b"sid=bad\\value; sid=\"good value\"; empty; =ignored")
                .unwrap(),
        );
        assert_eq!(cookie_value(&headers, "sid").as_deref(), Some("good value"));
        assert_eq!(cookie_value(&headers, "empty").as_deref(), Some(""));
    }

    #[test]
    fn go_cookie_parser_enforces_the_3000_item_limit_across_headers() {
        let at_limit = std::iter::once("sid=kept")
            .chain(std::iter::repeat_n("x=", 2_999))
            .collect::<Vec<_>>()
            .join("; ");
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(&at_limit).unwrap());
        assert_eq!(cookie_value(&headers, "sid").as_deref(), Some("kept"));

        headers.append(COOKIE, HeaderValue::from_static("overflow=1"));
        assert_eq!(cookie_value(&headers, "sid"), None);
        assert!(go_request_cookies(&headers).is_empty());
    }

    #[test]
    fn host_matching_handles_ports_and_bracketed_ipv6() {
        assert!(host_matches("Example.COM:443", "example.com"));
        assert!(host_matches("example.com", "example.com:8443"));
        assert!(host_matches("[::1]:443", "::1"));
        assert!(host_matches("[::1]", "[::1]:8443"));
        assert!(!host_matches("[::1]:443", "::2"));
        assert!(!host_matches("example.net:443", "example.com"));
        assert!(!host_matches("[::1]attacker.example", "::1"));
        assert!(!host_matches("[::1]:not-a-port", "::1"));
        assert!(!host_matches("example.com:99999", "example.com"));
        assert!(!host_matches("user@example.com", "example.com"));
    }

    #[test]
    fn authority_is_authoritative_and_conflicting_host_headers_are_rejected() {
        let (server, _receiver) = XhttpServer::new(test_config("packet-up"), Some(1)).unwrap();
        let matching = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri("https://127.0.0.1:443/x/session/0")
            .header(HOST, "127.0.0.1:8443")
            .header("referer", "https://127.0.0.1/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        assert!(validate_head(&server.inner, &matching).is_ok());

        for version in [Version::HTTP_2, Version::HTTP_3] {
            let conflicting = Request::builder()
                .method(Method::POST)
                .version(version)
                .uri("https://wrong.example/x/session/0")
                .header(HOST, "127.0.0.1")
                .body(())
                .unwrap();
            assert_eq!(
                validate_route(&server.inner, &conflicting)
                    .unwrap_err()
                    .status,
                StatusCode::BAD_REQUEST
            );
        }

        let mut duplicate = Request::builder()
            .uri("/x/")
            .header(HOST, "127.0.0.1")
            .body(())
            .unwrap();
        duplicate
            .headers_mut()
            .append(HOST, HeaderValue::from_static("127.0.0.1"));
        assert_eq!(
            validate_route(&server.inner, &duplicate)
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn h2_normal_response_cancellation_is_a_clean_streaming_eof() {
        let cancelled = h2::Error::from(h2::Reason::CANCEL);
        let no_error = h2::Error::from(h2::Reason::NO_ERROR);
        let protocol_error = h2::Error::from(h2::Reason::PROTOCOL_ERROR);

        assert!(is_clean_h2_streaming_end(&cancelled));
        assert!(is_clean_h2_streaming_end(&no_error));
        assert!(!is_clean_h2_streaming_end(&protocol_error));
    }

    #[test]
    fn zero_based_keepalive_range_is_rejected_and_runtime_is_defensive() {
        let mut config = test_config("stream-up");
        config.sc_stream_up_server_secs = "0-2".into();
        let result = XhttpServer::new(config, Some(1));
        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert_eq!(keepalive_delay(Range::new(0, 0)), Duration::from_millis(1));
    }

    #[test]
    fn route_padding_header_limit_and_payload_placements_are_enforced() {
        let (server, _receiver) = XhttpServer::new(test_config("packet-up"), Some(1)).unwrap();
        let valid = Request::builder()
            .method(Method::POST)
            .uri("/x/session/0")
            .header(HOST, "127.0.0.1:443")
            .header("referer", "https://127.0.0.1/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        assert!(validate_head(&server.inner, &valid).is_ok());

        let encoded_prefix = Request::builder()
            .method(Method::POST)
            .uri("/%78/session/0")
            .header(HOST, "127.0.0.1:443")
            .header("referer", "https://127.0.0.1/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        assert!(validate_head(&server.inner, &encoded_prefix).is_ok());

        let malformed_path = Request::builder()
            .uri("/x/%ZZ")
            .header(HOST, "127.0.0.1")
            .body(())
            .unwrap();
        assert_eq!(
            validate_route(&server.inner, &malformed_path)
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );

        let bad_padding = Request::builder()
            .method(Method::POST)
            .uri("/x/session/0")
            .header(HOST, "127.0.0.1")
            .header("referer", "https://127.0.0.1/x/?x_padding=XXX")
            .body(())
            .unwrap();
        assert_eq!(
            validate_head(&server.inner, &bad_padding)
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );

        let oversized = Request::builder()
            .uri("/x/")
            .header(HOST, "127.0.0.1")
            .header("x-large", "A".repeat(9000))
            .body(())
            .unwrap();
        assert_eq!(
            validate_route(&server.inner, &oversized)
                .unwrap_err()
                .status,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"payload");
        let mut headers = HeaderMap::new();
        headers.insert("x-data-0", HeaderValue::from_str(&encoded).unwrap());
        assert_eq!(header_chunks(&headers, "").unwrap(), b"payload");
        headers.clear();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("x_data_0={encoded}")).unwrap(),
        );
        assert_eq!(cookie_chunks(&headers, "").unwrap(), b"payload");
    }

    #[tokio::test]
    async fn malformed_and_oversized_packets_never_consume_session_slots() {
        let mut header_config = test_config("packet-up");
        header_config.uplink_data_placement = PLACEMENT_HEADER.into();
        let (header_server, _receiver) = XhttpServer::new(header_config, Some(1)).unwrap();
        let mut malformed_headers = HeaderMap::new();
        malformed_headers.insert("x-data-0", HeaderValue::from_static("!"));

        for index in 0..=MAX_SESSIONS {
            let session_id = format!("malformed-{index}");
            let permit = header_server
                .reserve_packet_body(&session_id, 0, Duration::ZERO)
                .await
                .expect("malformed request reservation should remain reusable");
            let error = decode_packet_payload(
                &header_server.inner.config,
                &malformed_headers,
                Full::new(Bytes::new()),
                header_server.inner.cancelled.clone(),
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            drop(permit);
        }
        assert!(header_server.inner.sessions.lock().is_empty());

        let session_id = "malformed-0";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"valid");
        let mut valid_headers = HeaderMap::new();
        valid_headers.insert("x-data-0", HeaderValue::from_str(&encoded).unwrap());
        let permit = header_server
            .reserve_packet_body(session_id, 0, Duration::ZERO)
            .await
            .unwrap();
        let payload = decode_packet_payload(
            &header_server.inner.config,
            &valid_headers,
            Full::new(Bytes::new()),
            header_server.inner.cancelled.clone(),
            None,
        )
        .await
        .unwrap();
        let payload = permit.attach(payload).unwrap();
        header_server
            .finish_packet_upload(session_id, 0, payload)
            .unwrap();
        assert!(header_server.inner.sessions.lock().contains_key(session_id));

        let mut body_config = test_config("packet-up");
        body_config.uplink_data_placement = PLACEMENT_BODY.into();
        let (body_server, _receiver) = XhttpServer::new(body_config, Some(1)).unwrap();
        let permit = body_server
            .reserve_packet_body("oversized", 0, Duration::ZERO)
            .await
            .unwrap();
        let error = decode_packet_payload(
            &body_server.inner.config,
            &HeaderMap::new(),
            Full::new(Bytes::from(vec![0; 1025])),
            body_server.inner.cancelled.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        drop(permit);
        assert!(body_server.inner.sessions.lock().is_empty());
    }

    #[tokio::test]
    async fn pending_packet_body_times_out_and_returns_its_full_budget() {
        let mut config = test_config("packet-up");
        config.sc_max_buffered_posts = 1;
        let (server, _receiver) = XhttpServer::new(config, Some(1)).unwrap();
        let permit = server
            .reserve_packet_body("pending", 1, Duration::ZERO)
            .await
            .unwrap();
        let error = read_hyper_body_limited_with_timeout(
            PendingBody,
            1024,
            Duration::ZERO,
            server.inner.cancelled.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::REQUEST_TIMEOUT);
        drop(permit);
        assert!(server.inner.sessions.lock().is_empty());

        // Sequence 1 on a missing session is Future and therefore cannot use
        // priority. Immediate reacquisition proves the full normal reservation
        // was returned by the failed request.
        server
            .reserve_packet_body("pending", 1, Duration::ZERO)
            .await
            .expect("timed-out body leaked its normal budget");
    }

    #[tokio::test]
    async fn next_packet_can_use_priority_when_future_fills_normal_budget() {
        let mut config = test_config("packet-up");
        config.sc_max_buffered_posts = 1;
        let (server, _receiver) = XhttpServer::new(config, Some(1)).unwrap();

        let future = server
            .reserve_packet_body("priority", 1, Duration::ZERO)
            .await
            .expect("future packet should acquire normal budget");
        let next = server
            .reserve_packet_body("priority", 0, Duration::ZERO)
            .await
            .expect("next packet should acquire isolated priority budget");
        drop((future, next));
    }

    #[tokio::test]
    async fn future_waiter_promotes_when_reader_advances_to_its_sequence() {
        let mut config = test_config("packet-up");
        config.sc_max_buffered_posts = 1;
        let (server, _receiver) = XhttpServer::new(config, Some(1)).unwrap();
        let normal = server
            .reserve_packet_body("normal-holder", 1, Duration::ZERO)
            .await
            .unwrap();
        let session = server.upsert_session("promote").unwrap();

        let waiter = server.reserve_packet_body("promote", 1, Duration::from_secs(1));
        tokio::pin!(waiter);
        assert!(futures::poll!(waiter.as_mut()).is_pending());

        session
            .upload_queue
            .push(Packet {
                seq: 0,
                payload: Bytes::from_static(b"x"),
            })
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(session.upload_queue.read(&mut byte).await.unwrap(), 1);
        assert_eq!(&byte, b"x");

        let promoted = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("future waiter missed sequence advancement")
            .expect("promoted waiter failed to acquire priority");
        drop((normal, promoted));
    }

    #[test]
    fn long_session_id_is_limited_by_request_header_budget_not_an_arbitrary_cap() {
        let session_id = "s".repeat(700);
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/x/{session_id}/0"))
            .header(HOST, "127.0.0.1")
            .header("referer", "https://127.0.0.1/x/?x_padding=XXXX")
            .body(())
            .unwrap();

        let (server, _receiver) = XhttpServer::new(test_config("packet-up"), Some(1)).unwrap();
        let head = validate_head(&server.inner, &request).expect("700-byte session id is valid");
        assert_eq!(head.session_id, session_id);

        let mut constrained = test_config("packet-up");
        constrained.server_max_header_bytes = 600;
        let (server, _receiver) = XhttpServer::new(constrained, Some(1)).unwrap();
        assert_eq!(
            validate_head(&server.inner, &request).unwrap_err().status,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn natural_response_body_eof_does_not_cancel_session() {
        let state = IoState::shared();
        let (sender, receiver) = mpsc::channel(1);
        let mut body = XhttpBody::channel(receiver, Arc::clone(&state));
        sender.send(Bytes::from_static(b"x")).await.unwrap();
        drop(sender);
        assert!(body.frame().await.is_some());
        assert!(body.frame().await.is_none());
        drop(body);
        assert!(!state.is_cancelled());

        let (sender, receiver) = mpsc::channel(1);
        let body = XhttpBody::channel(receiver, Arc::clone(&state));
        drop(body);
        assert!(state.is_cancelled());
        drop(sender);
    }

    #[tokio::test]
    async fn disconnected_session_is_reaped_and_cancelled() {
        let (server, _receiver) = XhttpServer::new(test_config("packet-up"), Some(1)).unwrap();
        let session = server.upsert_session("expires").unwrap();
        spawn_session_reaper(
            Arc::downgrade(&server.inner),
            Arc::clone(&session),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!server.inner.sessions.lock().contains_key("expires"));
        assert!(session.cancelled.is_cancelled());
    }

    #[tokio::test]
    async fn clean_session_close_drains_packet_upload_without_io_error() {
        let session = Session::new("clean-close".into(), 8);
        session.select_packet_source().unwrap();
        let mut reader = session.take_reader().unwrap();
        session
            .push_packet(0, Bytes::from_static(b"complete-before-close"))
            .unwrap();

        session.close_clean();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), reader.read_to_end(&mut received))
            .await
            .expect("clean packet session close did not wake its reader")
            .expect("clean packet session close became an I/O error");
        assert_eq!(received, b"complete-before-close");
        assert!(session.io_state.is_cancelled());
        assert!(
            session.io_state.error().is_none(),
            "clean close must not record ConnectionAborted"
        );
    }

    #[tokio::test]
    async fn retry_history_scales_with_the_configured_reassembly_window() {
        let session = Session::new("wide-retry-window".into(), 300);
        let mut byte = [0_u8; 1];
        for sequence in 0..300_u64 {
            let payload = Bytes::from(vec![(sequence % 251) as u8]);
            session.push_packet(sequence, payload).unwrap();
            assert_eq!(session.upload_queue.read(&mut byte).await.unwrap(), 1);
        }
        assert_eq!(session.upload_queue.next_sequence(), 300);

        session
            .push_packet(0, Bytes::from_static(b"\0"))
            .expect("an identical retry inside the configured history must remain idempotent");
        let conflict = session
            .push_packet(0, Bytes::from_static(b"different"))
            .unwrap_err();
        assert_eq!(conflict.kind(), io::ErrorKind::AlreadyExists);
    }

    #[tokio::test]
    async fn accepted_mode_prefers_explicit_config_and_auto_tracks_upload_source() {
        for mode in ["stream-one", "stream-up", "packet-up"] {
            let (server, _receiver) = XhttpServer::new(test_config(mode), Some(1)).unwrap();
            let session = server.upsert_session("configured").unwrap();
            assert_eq!(server.accepted_session_mode(&session), mode);
        }

        let (server, _receiver) = XhttpServer::new(test_config("auto"), Some(1)).unwrap();
        let session = server.upsert_session("automatic").unwrap();
        assert_eq!(server.accepted_session_mode(&session), "auto");
        session.select_packet_source().unwrap();
        assert_eq!(server.accepted_session_mode(&session), "packet-up");
    }

    #[tokio::test]
    async fn h1_stream_one_loopback_is_bidirectional() {
        let (server, mut receiver, address, shutdown, serving) = start_server("stream-one").await;
        let mut client = open_raw(address, "POST", "/x/", b"ping").await;
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
        assert_eq!(accepted.mode, "stream-one");
        assert_eq!(accepted.version, XhttpVersion::Http1);
        let mut upload = [0_u8; 4];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"ping");
        accepted.stream.write_all(b"pong").await.unwrap();
        accepted.stream.flush().await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);

        let response = read_until(&mut client, b"pong").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let response_text = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(response_text.contains("content-type: text/event-stream"));
        assert!(response_text.contains("access-control-allow-origin: *"));
        assert!(response_text.contains("x-padding: xxxx"));
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_stream_one_accept_backpressure_returns_503_without_leaking() {
        let accept_timeout = Duration::from_millis(75);
        let (server, mut receiver, address, shutdown, serving) =
            start_server_with_accept_timeout("stream-one", 1, accept_timeout).await;
        let _placeholder_peer = fill_accept_queue(&server);

        let started = tokio::time::Instant::now();
        let mut client = open_raw(address, "POST", "/x/", b"").await;
        let response = read_until(&mut client, b"\r\n\r\n").await;
        assert!(
            started.elapsed() >= accept_timeout,
            "HTTP/1.1 request bypassed the accept-capacity deadline"
        );
        assert!(
            response.starts_with(b"HTTP/1.1 503"),
            "unexpected HTTP/1.1 backpressure response: {}",
            String::from_utf8_lossy(&response)
        );
        assert_only_accept_placeholder(&mut receiver);
        stop_server(server, shutdown, serving).await;
    }

    async fn assert_h1_streaming_upload_close_is_clean_eof(mode: &str) {
        let (server, mut receiver, address, shutdown, serving) = start_server(mode).await;
        let _download = if mode == "stream-up" {
            Some(open_raw(address, "GET", "/x/clean-eof", b"").await)
        } else {
            None
        };
        let path = if mode == "stream-up" {
            "/x/clean-eof"
        } else {
            "/x/"
        };
        let mut upload = TcpStream::connect(address).await.unwrap();
        upload
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
                     Referer: http://127.0.0.1/x/?x_padding=XXXX\r\n\
                     Transfer-Encoding: chunked\r\n\r\n4\r\nping\r\n",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        upload.flush().await.unwrap();

        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
        let mut payload = [0_u8; 4];
        accepted.stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        // Xray's H1 streaming client can close without the terminal zero-size
        // chunk. Hyper reports `incomplete_message`, but the logical proxy
        // stream must expose a clean EOF and let copy finish successfully.
        upload.shutdown().await.unwrap();
        let copied = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::copy(&mut accepted.stream, &mut tokio::io::sink()),
        )
        .await
        .expect("logical upload did not reach EOF")
        .expect("streaming client close must be a clean logical EOF");
        assert_eq!(copied, 0);

        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        drop(upload);
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_stream_one_incomplete_http_body_is_clean_logical_eof() {
        assert_h1_streaming_upload_close_is_clean_eof("stream-one").await;
    }

    #[tokio::test]
    async fn h1_stream_up_incomplete_http_body_is_clean_logical_eof() {
        assert_h1_streaming_upload_close_is_clean_eof("stream-up").await;
    }

    #[test]
    fn accept_capacity_above_business_limit_returns_an_error_instead_of_panicking() {
        let result = XhttpServer::new(test_config("stream-one"), Some(XHTTP_MAX_ACCEPT_QUEUE + 1));
        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn listener_resource_configuration_rejects_invalid_or_late_values() {
        let (mut zero_connections, _receiver) =
            XhttpServer::new(test_config("stream-one"), Some(1)).unwrap();
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    0,
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    1,
                    0,
                    DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    1,
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    0,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    1,
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    Semaphore::MAX_PERMITS.saturating_add(1),
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    1,
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                    Duration::ZERO,
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            zero_connections
                .configure_listener_resources(
                    Semaphore::MAX_PERMITS.saturating_add(1),
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let (mut shared, _receiver) = XhttpServer::new(test_config("stream-one"), Some(1)).unwrap();
        let _clone = shared.clone();
        assert_eq!(
            shared
                .configure_listener_resources(
                    1,
                    DEFAULT_MAX_CONCURRENT_STREAMS,
                    DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                    Duration::from_secs(1),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[tokio::test]
    async fn h2_request_guards_rearm_idle_only_after_every_stream_finishes() {
        let idle_timeout = Duration::from_millis(20);
        let watch = HeaderTimeoutWatch::new(Duration::from_secs(1), idle_timeout);
        let first = watch.request_started(Version::HTTP_2);
        let second = watch.request_started(Version::HTTP_2);
        drop(first);
        assert!(
            tokio::time::timeout(idle_timeout * 2, watch.wait_for_timeout())
                .await
                .is_err(),
            "dropping one of two H2 request guards armed the idle timer early"
        );

        drop(second);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), watch.wait_for_timeout())
                .await
                .expect("dropping the last H2 request guard did not arm idle timeout"),
            ConnectionTimeoutKind::HttpIdle
        );
    }

    #[tokio::test]
    async fn plaintext_connection_limit_queues_n_plus_one_until_a_slot_is_released() {
        let (mut server, _receiver) = XhttpServer::new(test_config("stream-one"), Some(1)).unwrap();
        server
            .configure_listener_resources(
                2,
                DEFAULT_MAX_CONCURRENT_STREAMS,
                DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                Duration::from_secs(1),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_listener(listener, shutdown).await })
        };

        let blocker_one = TcpStream::connect(address).await.unwrap();
        wait_for_available_connection_slots(&server, 1).await;
        let blocker_two = TcpStream::connect(address).await.unwrap();
        wait_for_available_connection_slots(&server, 0).await;

        let mut queued = open_raw(address, "OPTIONS", "/x/", b"").await;
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(75), queued.read(&mut byte))
                .await
                .is_err(),
            "N+1 plaintext connection was served without a connection slot"
        );

        drop(blocker_one);
        let response = read_until(&mut queued, b"\r\n\r\n").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        drop(blocker_two);
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_configured_idle_timeout_rearms_after_keepalive_response() {
        let (mut server, _receiver) = XhttpServer::new(test_config("stream-one"), Some(1)).unwrap();
        let idle_timeout = Duration::from_millis(50);
        server
            .configure_listener_resources(
                DEFAULT_MAX_ACTIVE_CONNECTIONS,
                DEFAULT_MAX_CONCURRENT_STREAMS,
                DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                idle_timeout,
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let (stream, peer_addr) = listener.accept().await?;
                let local_addr = stream.local_addr()?;
                server
                    .serve_io_until_with_header_timeout(
                        stream,
                        peer_addr,
                        local_addr,
                        shutdown,
                        Duration::from_secs(1),
                        HttpVersionPolicy::HTTP1_AND_HTTP2,
                    )
                    .await
            })
        };

        let mut client = open_raw(address, "OPTIONS", "/x/", b"").await;
        let response = read_until(&mut client, b"\r\n\r\n").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        client
            .write_all(b"GET /x/ HTTP/1.1\r\nHost: 127.0.0.1")
            .await
            .unwrap();

        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("idle/partial second request was not timed out")
            .expect("HTTP task panicked")
            .expect_err("partial second request unexpectedly completed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "H1 keepalive used the one-second header timeout instead of configured idle timeout"
        );
        server.close();
    }

    #[tokio::test]
    async fn tls_handshake_timeout_releases_idle_tcp_client() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let tls_config = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client.unwrap();
        let (stream, _) = accepted.unwrap();

        let error =
            match accept_tls_with_timeout(&acceptor, stream, Duration::from_millis(20)).await {
                Err(error) => error,
                Ok(_) => panic!("idle TCP client unexpectedly completed a TLS handshake"),
            };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn tls_connection_limit_includes_handshakes_and_releases_the_next_client() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use tokio_rustls::TlsConnector;

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_tls));

        let (mut server, _receiver) = XhttpServer::new(test_config("stream-one"), Some(1)).unwrap();
        server
            .configure_listener_resources(
                1,
                DEFAULT_MAX_CONCURRENT_STREAMS,
                DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                Duration::from_secs(1),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                server
                    .serve_tls_listener(listener, acceptor, shutdown)
                    .await
            })
        };

        let blocker = TcpStream::connect(address).await.unwrap();
        wait_for_available_connection_slots(&server, 0).await;
        let queued_tcp = TcpStream::connect(address).await.unwrap();
        let handshake = connector.connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            queued_tcp,
        );
        tokio::pin!(handshake);
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut handshake)
                .await
                .is_err(),
            "N+1 TLS handshake ran without a connection slot"
        );

        drop(blocker);
        let tls_stream = tokio::time::timeout(Duration::from_secs(2), &mut handshake)
            .await
            .expect("queued TLS handshake did not start after a slot was released")
            .expect("queued TLS handshake failed");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_ref())
        );
        drop(tls_stream);
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_packet_up_reorders_posts_before_proxy_read() {
        let (server, mut receiver, address, shutdown, serving) = start_server("packet-up").await;
        let mut download = open_raw(address, "GET", "/x/session-p", b"").await;
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
        assert_eq!(accepted.mode, "packet-up");

        let response_one = post_and_read_headers(address, "/x/session-p/1", b"world").await;
        assert!(response_one.starts_with(b"HTTP/1.1 200"));
        let response_zero = post_and_read_headers(address, "/x/session-p/0", b"hello ").await;
        assert!(response_zero.starts_with(b"HTTP/1.1 200"));

        let mut upload = [0_u8; 11];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"hello world");
        accepted.stream.write_all(b"ordered").await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        let response = read_until(&mut download, b"ordered").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_packet_up_retry_is_idempotent_but_payload_replacement_conflicts() {
        let (server, mut receiver, address, shutdown, serving) = start_server("packet-up").await;
        let mut download = open_raw(address, "GET", "/x/session-retry", b"").await;
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");

        let first = post_and_read_headers(address, "/x/session-retry/0", b"once").await;
        assert!(first.starts_with(b"HTTP/1.1 200"));
        let mut upload = [0_u8; 4];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"once");

        let retry = post_and_read_headers(address, "/x/session-retry/0", b"once").await;
        assert!(retry.starts_with(b"HTTP/1.1 200"));
        let replacement = post_and_read_headers(address, "/x/session-retry/0", b"changed").await;
        assert!(replacement.starts_with(b"HTTP/1.1 409"));

        let next = post_and_read_headers(address, "/x/session-retry/1", b"next").await;
        assert!(next.starts_with(b"HTTP/1.1 200"));
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"next");

        accepted.stream.write_all(b"ok").await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        let response = read_until(&mut download, b"ok").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h1_stream_up_pairs_upload_and_download_requests() {
        let (server, mut receiver, address, shutdown, serving) = start_server("stream-up").await;
        let mut download = open_raw(address, "GET", "/x/session-s", b"").await;
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
        assert_eq!(accepted.mode, "stream-up");
        let _upload_response = open_raw(address, "POST", "/x/session-s", b"ping").await;
        let mut upload = [0_u8; 4];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"ping");
        accepted.stream.write_all(b"pong").await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        let response = read_until(&mut download, b"pong").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h2c_stream_one_loopback_uses_same_accept_path() {
        let (server, mut receiver, address, shutdown, serving) = start_server("stream-one").await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::from_static(b"ping")))
            .unwrap();
        let response_task = tokio::spawn(async move {
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.into_body().collect().await.unwrap().to_bytes()
        });
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
        assert_eq!(accepted.version, XhttpVersion::Http2);
        let mut upload = [0_u8; 4];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"ping");
        accepted.stream.write_all(b"pong").await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        let response = tokio::time::timeout(Duration::from_secs(2), response_task)
            .await
            .expect("HTTP/2 response timed out")
            .unwrap();
        assert_eq!(response, Bytes::from_static(b"pong"));
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h2c_idle_timeout_closes_connection_after_last_response_finishes() {
        let idle_timeout = Duration::from_millis(50);
        let (server, _receiver, address, _shutdown, serving) =
            start_single_h2_server("stream-one", idle_timeout).await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("idle HTTP/2 connection was not closed")
            .expect("HTTP/2 server task panicked")
            .expect_err("idle HTTP/2 connection unexpectedly stayed open");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= idle_timeout,
            "HTTP/2 connection closed before the configured idle timeout"
        );
        server.close();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("HTTP/2 client driver did not stop")
            .expect("HTTP/2 client driver panicked");
    }

    #[tokio::test]
    async fn h2c_active_downlink_prevents_idle_timeout_until_body_finishes() {
        let idle_timeout = Duration::from_millis(50);
        let (server, mut receiver, address, _shutdown, serving) =
            start_single_h2_server("stream-one", idle_timeout).await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::from_static(b"ping")))
            .unwrap();

        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = response.into_body();
        let mut accepted = tokio::time::timeout(Duration::from_secs(1), receiver.accept())
            .await
            .expect("active HTTP/2 downlink was not accepted")
            .expect("HTTP/2 accept channel closed");

        tokio::time::sleep(idle_timeout * 3).await;
        assert!(
            !serving.is_finished(),
            "active HTTP/2 downlink was closed by the idle timeout"
        );
        let probe = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let probe = sender.send_request(probe).await.unwrap();
        assert_eq!(probe.status(), StatusCode::OK);
        probe.into_body().collect().await.unwrap();

        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        tokio::time::timeout(Duration::from_secs(1), response_body.collect())
            .await
            .expect("HTTP/2 downlink response did not finish")
            .expect("HTTP/2 downlink body failed");
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("HTTP/2 connection did not become idle after downlink completion")
            .expect("HTTP/2 server task panicked")
            .expect_err("HTTP/2 connection stayed open after becoming idle");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        server.close();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("HTTP/2 client driver did not stop")
            .expect("HTTP/2 client driver panicked");
    }

    #[tokio::test]
    async fn h2c_per_connection_stream_limit_holds_n_plus_one_until_release() {
        let (server, mut receiver, address, shutdown, serving) =
            start_single_h2_server_with_options(
                "stream-one",
                Duration::from_secs(5),
                8,
                ACCEPT_DELIVERY_TIMEOUT,
                1,
                8,
            )
            .await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let first = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::from_static(b"first")))
            .unwrap();
        let first = sender.send_request(first).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = first.into_body();
        let mut accepted = tokio::time::timeout(Duration::from_secs(1), receiver.accept())
            .await
            .expect("first limited HTTP/2 stream was not accepted")
            .expect("HTTP/2 accept channel closed");

        let second = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let mut second = Box::pin(sender.send_request(second));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut second)
                .await
                .is_err(),
            "max-concurrent-streams=1 admitted a second open HTTP/2 stream"
        );

        accepted.stream.shutdown().await.unwrap();
        drop(accepted);
        tokio::time::timeout(Duration::from_secs(1), first_body.collect())
            .await
            .expect("first limited HTTP/2 body did not finish")
            .expect("first limited HTTP/2 body failed");
        let second = tokio::time::timeout(Duration::from_secs(1), &mut second)
            .await
            .expect("second HTTP/2 stream was not released after capacity returned")
            .expect("second HTTP/2 request failed");
        assert_eq!(second.status(), StatusCode::OK);
        second.into_body().collect().await.unwrap();

        server.close();
        shutdown.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("limited HTTP/2 server did not stop")
            .expect("limited HTTP/2 server task panicked")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("limited HTTP/2 client driver did not stop")
            .expect("limited HTTP/2 client driver panicked");
    }

    #[tokio::test]
    async fn h2c_global_http_stream_limit_rejects_n_plus_one_and_recovers_after_reset() {
        let (server, mut receiver, address, shutdown, serving) =
            start_single_h2_server_with_options(
                "stream-one",
                Duration::from_secs(5),
                8,
                ACCEPT_DELIVERY_TIMEOUT,
                2,
                1,
            )
            .await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        let first = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::from_static(b"first")))
            .unwrap();
        let first = sender.send_request(first).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = first.into_body();
        let accepted = tokio::time::timeout(Duration::from_secs(1), receiver.accept())
            .await
            .expect("first globally limited HTTP/2 stream was not accepted")
            .expect("HTTP/2 accept channel closed");
        assert_eq!(server.inner.http_stream_slots.available_permits(), 0);

        let overloaded = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let overloaded = sender.send_request(overloaded).await.unwrap();
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        overloaded.into_body().collect().await.unwrap();
        assert_eq!(server.inner.http_stream_slots.available_permits(), 0);

        drop(first_body);
        drop(accepted);
        tokio::time::timeout(Duration::from_secs(1), async {
            while server.inner.http_stream_slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reset HTTP/2 response leaked the global stream permit");

        let recovered = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://{address}/x/"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let recovered = sender.send_request(recovered).await.unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        recovered.into_body().collect().await.unwrap();
        assert_eq!(server.inner.http_stream_slots.available_permits(), 1);

        server.close();
        shutdown.cancel();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("globally limited HTTP/2 server did not stop")
            .expect("globally limited HTTP/2 server task panicked")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("globally limited HTTP/2 client driver did not stop")
            .expect("globally limited HTTP/2 client driver panicked");
    }

    #[tokio::test]
    async fn h2c_reset_before_response_rearms_idle_and_cleans_pending_session() {
        let idle_timeout = Duration::from_millis(50);
        let accept_delivery_timeout = Duration::from_secs(5);
        let session_id = "h2-reset-before-response";
        let (server, mut receiver, address, _shutdown, serving) =
            start_single_h2_server_with_options(
                "packet-up",
                idle_timeout,
                1,
                accept_delivery_timeout,
                DEFAULT_MAX_CONCURRENT_STREAMS,
                DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
            )
            .await;
        let _placeholder_peer = fill_accept_queue(&server);
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{address}/x/{session_id}"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let mut response_future = Box::pin(sender.send_request(request));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                tokio::select! {
                    response = &mut response_future => {
                        panic!("backpressured H2 request unexpectedly completed: {response:?}");
                    }
                    _ = tokio::task::yield_now() => {}
                }
                if server.inner.sessions.lock().contains_key(session_id) {
                    break;
                }
            }
        })
        .await
        .expect("H2 request did not reach the backpressured session handler");

        let reset_at = tokio::time::Instant::now();
        drop(response_future);
        let error = tokio::time::timeout(Duration::from_secs(1), serving)
            .await
            .expect("reset H2 stream kept the connection active")
            .expect("HTTP/2 server task panicked")
            .expect_err("H2 connection stayed open after the reset stream became idle");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            reset_at.elapsed() < accept_delivery_timeout,
            "H2 reset waited for accept delivery timeout instead of cancelling the request"
        );
        assert!(
            !server.inner.sessions.lock().contains_key(session_id),
            "reset H2 request leaked its provisional session"
        );
        assert_eq!(
            server.inner.http_stream_slots.available_permits(),
            DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
            "reset H2 service future leaked its global HTTP stream permit"
        );
        assert_only_accept_placeholder(&mut receiver);

        server.close();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), connection_task)
            .await
            .expect("HTTP/2 client driver did not stop")
            .expect("HTTP/2 client driver panicked");
    }

    #[tokio::test]
    async fn h2c_session_accept_backpressure_returns_503_and_removes_session() {
        let accept_timeout = Duration::from_millis(75);
        let (server, mut receiver, address, shutdown, serving) =
            start_server_with_accept_timeout("packet-up", 1, accept_timeout).await;
        let _placeholder_peer = fill_accept_queue(&server);
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{address}/x/h2-accept-backpressure"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let started = tokio::time::Instant::now();
        let response = tokio::time::timeout(Duration::from_secs(2), sender.send_request(request))
            .await
            .expect("HTTP/2 backpressure response timed out")
            .expect("HTTP/2 backpressure request failed");
        assert!(
            started.elapsed() >= accept_timeout,
            "HTTP/2 request bypassed the accept-capacity deadline"
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        response.into_body().collect().await.unwrap();
        assert!(
            !server
                .inner
                .sessions
                .lock()
                .contains_key("h2-accept-backpressure"),
            "timed-out HTTP/2 session remained registered"
        );
        assert_only_accept_placeholder(&mut receiver);
        drop(sender);
        stop_server(server, shutdown, serving).await;
    }

    #[tokio::test]
    async fn h2c_packet_upload_uses_the_shared_budgeted_handler() {
        let (server, _receiver, address, shutdown, serving) = start_server("packet-up").await;
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let conflicting = Request::builder()
            .method(Method::OPTIONS)
            .uri("http://wrong.example/x/")
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = sender.send_request(conflicting).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        response.into_body().collect().await.unwrap();

        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{address}/x/h2-packet/0"))
            .header(HOST, format!("127.0.0.1:{}", address.port()))
            .header("referer", "http://127.0.0.1/x/?x_padding=XXXX")
            .body(Full::new(Bytes::from_static(b"packet")))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
        assert!(server.inner.sessions.lock().contains_key("h2-packet"));
        stop_server(server, shutdown, serving).await;
    }

    async fn assert_h3_cancel_before_response_is_not_accepted(
        mode: &str,
        request_path: &str,
        session_id: Option<&str>,
        cancel_after_response: bool,
        expected_error_context: &str,
    ) {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_quic = QuicServerConfig::try_from(server_tls).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_quic)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = server_endpoint.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_quic = QuicClientConfig::try_from(client_tls).unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_quic)));

        let connecting = client_endpoint.connect(address, "localhost").unwrap();
        let accepting = async {
            server_endpoint
                .accept()
                .await
                .expect("server endpoint closed before accepting QUIC")
                .await
                .expect("server QUIC handshake failed")
        };
        let (client_connection, server_connection) =
            tokio::time::timeout(Duration::from_secs(2), async {
                let (client, server) = tokio::join!(connecting, accepting);
                (client.expect("client QUIC handshake failed"), server)
            })
            .await
            .expect("QUIC handshake timed out");

        let mut h3_server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server_connection.clone()))
            .await
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(client_connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let mut config = test_config(mode);
        config.host = "localhost".into();
        let (server, mut receiver) =
            XhttpServer::new(config, Some(if cancel_after_response { 1 } else { 8 })).unwrap();
        let _placeholder_peer = if cancel_after_response {
            let (placeholder, peer) = tokio::io::duplex(1);
            server
                .inner
                .accepted
                .try_send(AcceptedXhttpStream {
                    stream: Box::pin(placeholder),
                    peer_addr: "127.0.0.1:1".parse().unwrap(),
                    local_addr: "127.0.0.1:2".parse().unwrap(),
                    session_id: None,
                    mode: "accept-queue-placeholder",
                    version: XhttpVersion::Http3,
                })
                .expect("failed to fill the XHTTP accept queue");
            Some(peer)
        } else {
            None
        };
        let session = session_id.map(|id| {
            let session = server.upsert_session(id).unwrap();
            assert!(server.inner.sessions.lock().contains_key(id));
            session
        });

        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("https://localhost{request_path}"))
            .header(HOST, "localhost")
            .header("referer", "https://localhost/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        let mut request_stream = sender.send_request(request).await.unwrap();
        request_stream.finish().await.unwrap();

        // Parse the complete, valid request but deliberately do not enter the
        // XHTTP handler until the client has cancelled the response direction.
        let resolver = tokio::time::timeout(Duration::from_secs(2), h3_server.accept())
            .await
            .expect("HTTP/3 server did not receive the request")
            .expect("HTTP/3 request accept failed")
            .expect("HTTP/3 connection closed before the request");
        let (request, stream) = resolver.resolve_request().await.unwrap();

        let peer_addr = server_connection.remote_address();
        let local_addr = server_endpoint.local_addr().unwrap();
        let handler = server.handle_h3(request, stream, peer_addr, local_addr);
        tokio::pin!(handler);
        if cancel_after_response {
            let response = tokio::select! {
                result = &mut handler => {
                    panic!("HTTP/3 handler returned before accept backpressure was released: {result:?}")
                }
                response = request_stream.recv_response() => {
                    response.expect("HTTP/3 response headers failed before accept backpressure")
                }
            };
            assert_eq!(response.status(), StatusCode::OK);
        }

        request_stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        let cancellation_barrier = Bytes::from_static(b"response-cancelled");
        client_connection
            .send_datagram(cancellation_barrier.clone())
            .expect("HTTP/3 cancellation barrier datagram was rejected");
        let observed_barrier =
            tokio::time::timeout(Duration::from_secs(2), server_connection.read_datagram())
                .await
                .expect("HTTP/3 cancellation barrier timed out")
                .expect("HTTP/3 cancellation barrier read failed");
        assert_eq!(observed_barrier, cancellation_barrier);

        let error = tokio::time::timeout(Duration::from_secs(2), &mut handler)
            .await
            .expect("HTTP/3 handler hung after the response was cancelled")
            .expect_err("HTTP/3 response unexpectedly started after client cancellation");
        assert!(
            error.to_string().contains(expected_error_context),
            "unexpected HTTP/3 response failure: {error}"
        );
        if cancel_after_response {
            let placeholder = receiver
                .rx
                .try_recv()
                .expect("accept queue placeholder disappeared");
            assert_eq!(placeholder.mode, "accept-queue-placeholder");
        }
        assert!(
            matches!(
                receiver.rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "cancelled HTTP/3 request leaked a logical accepted stream"
        );

        if let Some(session) = session {
            let id = session.id.clone();
            assert!(
                !session.fully_connected.load(Ordering::Acquire),
                "cancelled HTTP/3 session was marked fully connected"
            );
            assert!(
                !server.inner.sessions.lock().contains_key(&id),
                "cancelled HTTP/3 session remained registered"
            );
            tokio::time::timeout(Duration::from_millis(100), session.cancelled.cancelled())
                .await
                .expect("cancelled HTTP/3 session left a waiter hanging");
            assert!(
                session.io_state.is_cancelled(),
                "cancelled HTTP/3 session left its I/O state active"
            );
        }

        drop(request_stream);
        drop(sender);
        drop(h3_server);
        client_connection.close(quinn::VarInt::from_u32(0), b"test complete");
        server_connection.close(quinn::VarInt::from_u32(0), b"test complete");
        client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        server_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        server.close();
        tokio::time::timeout(Duration::from_secs(2), driver_task)
            .await
            .expect("HTTP/3 client driver did not stop")
            .expect("HTTP/3 client driver task panicked");
    }

    #[tokio::test]
    async fn h3_stream_one_cancel_before_response_is_not_accepted() {
        assert_h3_cancel_before_response_is_not_accepted(
            "stream-one",
            "/x/",
            None,
            false,
            "XHTTP/3 stream-one response",
        )
        .await;
    }

    #[tokio::test]
    async fn h3_session_cancel_before_response_is_removed_and_not_accepted() {
        assert_h3_cancel_before_response_is_not_accepted(
            "packet-up",
            "/x/cancel-before-response",
            Some("cancel-before-response"),
            false,
            "XHTTP/3 download response",
        )
        .await;
    }

    #[tokio::test]
    async fn h3_stream_one_reset_while_accept_backpressured_is_not_accepted() {
        assert_h3_cancel_before_response_is_not_accepted(
            "stream-one",
            "/x/",
            None,
            true,
            "accept capacity",
        )
        .await;
    }

    #[tokio::test]
    async fn h3_session_reset_while_accept_backpressured_is_removed_and_not_accepted() {
        assert_h3_cancel_before_response_is_not_accepted(
            "packet-up",
            "/x/reset-while-backpressured",
            Some("reset-while-backpressured"),
            true,
            "accept capacity",
        )
        .await;
    }

    #[tokio::test]
    async fn h3_connection_limit_queues_n_plus_one_until_a_slot_is_released() {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_quic = QuicServerConfig::try_from(server_tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_quic)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_quic = QuicClientConfig::try_from(client_tls).unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_quic)));

        let mut config = test_config("stream-one");
        config.host = "localhost".into();
        let (mut server, _receiver) = XhttpServer::new(config, Some(8)).unwrap();
        server
            .configure_listener_resources(
                1,
                DEFAULT_MAX_CONCURRENT_STREAMS,
                DEFAULT_MAX_ACTIVE_HTTP_STREAMS,
                Duration::from_secs(1),
            )
            .unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_h3_endpoint(endpoint, shutdown).await })
        };

        let blocker = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        wait_for_available_connection_slots(&server, 0).await;

        let queued_request = async {
            let connection = client_endpoint
                .connect(address, "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut driver, mut sender) =
                h3::client::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let driver_task = tokio::spawn(async move {
                let _ = driver.wait_idle().await;
            });
            let request = Request::builder()
                .method(Method::OPTIONS)
                .uri("https://localhost/x/")
                .header(HOST, "localhost")
                .body(())
                .unwrap();
            let mut stream = sender.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            let status = stream.recv_response().await.unwrap().status();
            connection.close(quinn::VarInt::from_u32(0), b"queued request complete");
            drop(sender);
            tokio::time::timeout(Duration::from_secs(1), driver_task)
                .await
                .expect("queued HTTP/3 driver did not stop")
                .expect("queued HTTP/3 driver panicked");
            status
        };
        tokio::pin!(queued_request);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut queued_request)
                .await
                .is_err(),
            "N+1 HTTP/3 connection was served without a connection slot"
        );

        blocker.close(quinn::VarInt::from_u32(0), b"release connection slot");
        let status = tokio::time::timeout(Duration::from_secs(2), &mut queued_request)
            .await
            .expect("queued HTTP/3 request did not run after a slot was released");
        assert_eq!(status, StatusCode::OK);

        client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        shutdown.cancel();
        server.close();
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("HTTP/3 server did not stop")
            .expect("HTTP/3 server task panicked")
            .expect("HTTP/3 server returned an error");
    }

    #[tokio::test]
    async fn h3_stream_one_loopback_negotiates_tls_and_is_bidirectional() {
        use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_quic =
            QuicServerConfig::try_from(server_tls).expect("valid QUIC server TLS config");
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_quic)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_quic =
            QuicClientConfig::try_from(client_tls).expect("valid QUIC client TLS config");
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_quic)));

        let mut config = test_config("stream-one");
        config.host = "localhost".into();
        let (server, mut receiver) = XhttpServer::new(config, Some(8)).unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_h3_endpoint(endpoint, shutdown).await })
        };

        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .expect("trusted certificate must complete the QUIC handshake");
        let handshake = connection
            .handshake_data()
            .expect("rustls handshake data")
            .downcast::<HandshakeData>()
            .expect("rustls handshake type");
        assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_ref()));

        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/x/")
            .header(HOST, "localhost")
            .header("referer", "https://localhost/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        let mut request_stream = sender.send_request(request).await.unwrap();
        request_stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .unwrap();
        request_stream.finish().await.unwrap();

        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("HTTP/3 accept timed out")
            .expect("accept channel closed");
        assert_eq!(accepted.version, XhttpVersion::Http3);
        let mut upload = [0_u8; 4];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"ping");
        accepted.stream.write_all(b"pong").await.unwrap();
        accepted.stream.flush().await.unwrap();
        accepted.stream.shutdown().await.unwrap();
        drop(accepted);

        let response = request_stream.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut downlink = Vec::new();
        while let Some(mut data) = request_stream.recv_data().await.unwrap() {
            let remaining = data.remaining();
            downlink.extend_from_slice(&data.copy_to_bytes(remaining));
        }
        assert_eq!(downlink, b"pong");

        connection.close(quinn::VarInt::from_u32(0), b"test complete");
        client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        shutdown.cancel();
        server.close();
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("HTTP/3 server did not stop")
            .expect("HTTP/3 server task panicked")
            .expect("HTTP/3 server returned an error");
        tokio::time::timeout(Duration::from_secs(2), driver_task)
            .await
            .expect("HTTP/3 driver did not stop")
            .expect("HTTP/3 driver task panicked");
    }

    #[tokio::test]
    async fn h3_global_http_stream_limit_rejects_n_plus_one_and_recovers_after_cancel() {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_quic =
            QuicServerConfig::try_from(server_tls).expect("valid QUIC server TLS config");
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_quic)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_quic =
            QuicClientConfig::try_from(client_tls).expect("valid QUIC client TLS config");
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_quic)));

        let mut config = test_config("stream-one");
        config.host = "localhost".into();
        config.sc_stream_up_server_secs = "1-1".into();
        let (mut server, mut receiver) = XhttpServer::new(config, Some(8)).unwrap();
        server
            .configure_listener_resources(
                DEFAULT_MAX_ACTIVE_CONNECTIONS,
                4,
                1,
                DEFAULT_HTTP_IDLE_TIMEOUT,
            )
            .unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_h3_endpoint(endpoint, shutdown).await })
        };

        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .expect("trusted certificate must complete the QUIC handshake");
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        // A raw client-initiated bidi stream that never sends its HEADERS frame
        // must not retain the listener-global HTTP stream permit forever.
        let (mut slow_send, slow_recv) = connection.open_bi().await.unwrap();
        // HEADERS frame type without its length keeps the request resolver
        // waiting while still making the QUIC stream visible to the server.
        slow_send.write_all(&[0x01]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.inner.http_stream_slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("incomplete HTTP/3 request did not acquire the global stream permit");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver.accept())
                .await
                .is_err(),
            "incomplete HTTP/3 HEADERS unexpectedly reached the logical accept queue"
        );
        tokio::time::timeout(READ_HEADER_TIMEOUT + Duration::from_secs(2), async {
            while server.inner.http_stream_slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP/3 request header timeout leaked the global stream permit");
        assert_eq!(server.inner.http_stream_slots.available_permits(), 1);
        drop(slow_send);
        drop(slow_recv);

        let first = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/x/")
            .header(HOST, "localhost")
            .header("referer", "https://localhost/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        let mut first_stream = sender.send_request(first).await.unwrap();
        first_stream
            .send_data(Bytes::from_static(b"first"))
            .await
            .unwrap();
        first_stream.finish().await.unwrap();
        let first_response = first_stream.recv_response().await.unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);

        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("first globally limited HTTP/3 stream was not accepted")
            .expect("HTTP/3 accept channel closed");
        let mut upload = [0_u8; 5];
        accepted.stream.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"first");
        assert_eq!(server.inner.http_stream_slots.available_permits(), 0);

        let overloaded = Request::builder()
            .method(Method::OPTIONS)
            .uri("https://localhost/x/")
            .header(HOST, "localhost")
            .body(())
            .unwrap();
        let mut overloaded_stream = sender.send_request(overloaded).await.unwrap();
        overloaded_stream.finish().await.unwrap();
        let overloaded_response = overloaded_stream.recv_response().await.unwrap();
        assert_eq!(
            overloaded_response.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        while overloaded_stream.recv_data().await.unwrap().is_some() {}
        assert_eq!(server.inner.http_stream_slots.available_permits(), 0);

        first_stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        tokio::time::timeout(Duration::from_secs(3), async {
            while server.inner.http_stream_slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled HTTP/3 response leaked the global stream permit");
        assert_eq!(server.inner.http_stream_slots.available_permits(), 1);

        let recovered = Request::builder()
            .method(Method::OPTIONS)
            .uri("https://localhost/x/")
            .header(HOST, "localhost")
            .body(())
            .unwrap();
        let mut recovered_stream = sender.send_request(recovered).await.unwrap();
        recovered_stream.finish().await.unwrap();
        let recovered_response = recovered_stream.recv_response().await.unwrap();
        assert_eq!(recovered_response.status(), StatusCode::OK);
        while recovered_stream.recv_data().await.unwrap().is_some() {}
        assert_eq!(server.inner.http_stream_slots.available_permits(), 1);

        drop(accepted);
        connection.close(quinn::VarInt::from_u32(0), b"test complete");
        client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        shutdown.cancel();
        server.close();
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("HTTP/3 server did not stop")
            .expect("HTTP/3 server task panicked")
            .expect("HTTP/3 server returned an error");
        tokio::time::timeout(Duration::from_secs(2), driver_task)
            .await
            .expect("HTTP/3 driver did not stop")
            .expect("HTTP/3 driver task panicked");
    }

    #[tokio::test]
    async fn h3_packet_downlink_stop_closes_logical_upload_cleanly() {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut server_tls = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_quic = QuicServerConfig::try_from(server_tls).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_quic)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_quic = QuicClientConfig::try_from(client_tls).unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_quic)));

        let mut config = test_config("packet-up");
        config.host = "localhost".into();
        // Keep the production default at its low-frequency 20–80 seconds,
        // while this lifecycle test explicitly requests a one-second probe.
        config.sc_stream_up_server_secs = "1-1".into();
        let (server, mut receiver) = XhttpServer::new(config, Some(8)).unwrap();
        let shutdown = CancellationToken::new();
        let serving = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_h3_endpoint(endpoint, shutdown).await })
        };

        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let download_request = Request::builder()
            .method(Method::GET)
            .uri("https://localhost/x/clean-packet")
            .header(HOST, "localhost")
            .header("referer", "https://localhost/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        let mut download = sender.send_request(download_request).await.unwrap();
        download.finish().await.unwrap();
        assert_eq!(
            download.recv_response().await.unwrap().status(),
            StatusCode::OK
        );

        let mut accepted = tokio::time::timeout(Duration::from_secs(2), receiver.accept())
            .await
            .expect("HTTP/3 packet logical accept timed out")
            .expect("HTTP/3 packet accept channel closed");
        assert_eq!(accepted.version, XhttpVersion::Http3);
        assert_eq!(accepted.mode, "packet-up");

        let upload_request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/x/clean-packet/0")
            .header(HOST, "localhost")
            .header("referer", "https://localhost/x/?x_padding=XXXX")
            .body(())
            .unwrap();
        let mut upload = sender.send_request(upload_request).await.unwrap();
        upload
            .send_data(Bytes::from_static(b"packet"))
            .await
            .unwrap();
        upload.finish().await.unwrap();
        assert_eq!(
            upload.recv_response().await.unwrap().status(),
            StatusCode::OK
        );
        while upload.recv_data().await.unwrap().is_some() {}

        let mut packet = [0_u8; 6];
        accepted.stream.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"packet");

        // Closing the response body emits STOP_SENDING. The server's next
        // configured zero-length DATA probe must observe it and close the
        // logical upload without exposing a proxy byte or an I/O error.
        download.stop_sending(Code::H3_REQUEST_CANCELLED);
        let trailing = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::io::copy(&mut accepted.stream, &mut tokio::io::sink()),
        )
        .await
        .expect("HTTP/3 STOP_SENDING did not close packet upload")
        .expect("HTTP/3 normal response cancellation became an I/O error");
        assert_eq!(trailing, 0);
        drop(accepted);

        connection.close(quinn::VarInt::from_u32(0), b"test complete");
        client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        shutdown.cancel();
        server.close();
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("HTTP/3 server did not stop")
            .expect("HTTP/3 server task panicked")
            .expect("HTTP/3 server returned an error");
        tokio::time::timeout(Duration::from_secs(2), driver_task)
            .await
            .expect("HTTP/3 driver did not stop")
            .expect("HTTP/3 driver task panicked");
    }
}

fn spawn_session_reaper(inner: Weak<ServerInner>, session: Arc<Session>, ttl: Duration) {
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(ttl) => {
                if !session.fully_connected.load(Ordering::Acquire) {
                    remove_session(&inner, &session);
                    session.cancel("XHTTP session timed out before download attached");
                }
            }
            _ = session.fully_connected_notify.notified() => {}
            _ = session.cancelled.cancelled() => {}
        }
    });
}

type H3BidiStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

fn h3_error(context: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("{context}: {error}"),
    )
}

fn h3_response(status: StatusCode, headers: HeaderMap) -> Response<()> {
    let mut response = Response::new(());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

async fn send_h3_simple(
    stream: &mut H3BidiStream,
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
) -> io::Result<()> {
    stream
        .send_response(h3_response(status, headers))
        .await
        .map_err(|error| h3_error("XHTTP/3 response headers", error))?;
    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .map_err(|error| h3_error("XHTTP/3 response body", error))?;
    }
    stream
        .finish()
        .await
        .map_err(|error| h3_error("XHTTP/3 response finish", error))
}

async fn send_h3_request_error(
    stream: &mut H3BidiStream,
    error: RequestError,
    headers: HeaderMap,
) -> io::Result<()> {
    send_h3_simple(stream, error.status, headers, Bytes::from(error.message)).await
}

async fn read_h3_body_limited(
    stream: &mut H3BidiStream,
    limit: usize,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError> {
    read_h3_body_limited_with_timeout(
        stream,
        limit,
        PACKET_BODY_TIMEOUT,
        server_cancelled,
        session_cancelled,
    )
    .await
}

async fn read_h3_body_limited_with_timeout(
    stream: &mut H3BidiStream,
    limit: usize,
    idle_timeout: Duration,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError> {
    let mut output = Vec::new();
    loop {
        let cancelled = packet_cancellation_tokens_cancelled(
            server_cancelled.clone(),
            session_cancelled.clone(),
        );
        let data = tokio::select! {
            biased;
            _ = cancelled => return Err(packet_body_cancelled_error()),
            _ = tokio::time::sleep(idle_timeout) => {
                return Err(packet_body_idle_timeout());
            }
            data = stream.recv_data() => data
                .map_err(|error| {
                    RequestError::bad_request(format!("HTTP/3 request body: {error}"))
                })?,
        };
        let Some(mut data) = data else {
            break;
        };
        if output.len().saturating_add(data.remaining()) > limit {
            return Err(RequestError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "XHTTP upload exceeds scMaxEachPostBytes",
            ));
        }
        let remaining = data.remaining();
        output.extend_from_slice(&data.copy_to_bytes(remaining));
    }
    Ok(output)
}

async fn decode_h3_packet_payload(
    config: &Config,
    headers: &HeaderMap,
    stream: &mut H3BidiStream,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError> {
    let limit = config
        .normalized_sc_max_each_post_bytes()
        .map_err(RequestError::bad_request)?
        .max;
    let placement = normalized_server_uplink_data_placement(config);
    let header = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_HEADER) {
        header_chunks(headers, &config.uplink_data_key)?
    } else {
        Vec::new()
    };
    let cookie = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_COOKIE) {
        cookie_chunks(headers, &config.uplink_data_key)?
    } else {
        Vec::new()
    };
    let body = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_BODY) {
        read_h3_body_limited(stream, limit, server_cancelled, session_cancelled).await?
    } else {
        Vec::new()
    };
    combine_packet_payload(placement, header, cookie, body, limit)
}

async fn pump_h3_body(
    mut stream: H3RecvStream,
    sender: mpsc::Sender<ResponseItem>,
    state: Arc<IoState>,
) {
    loop {
        tokio::select! {
            _ = state.cancelled() => break,
            data = stream.recv_data() => {
                match data {
                    Ok(Some(mut data)) => {
                        let remaining = data.remaining();
                        if remaining > 0
                            && sender
                                .send(Ok(data.copy_to_bytes(remaining)))
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let failure = IoFailure::other(format!("XHTTP/3 request body: {error}"));
                        state.fail(failure.clone());
                        let _ = sender.send(Err(failure)).await;
                        break;
                    }
                }
            }
        }
    }
}

async fn send_h3_downlink(
    mut stream: H3SendStream,
    mut receiver: mpsc::Receiver<Bytes>,
    state: Arc<IoState>,
    peer_probe_interval: Duration,
) -> io::Result<()> {
    let mut peer_probe = tokio::time::interval(peer_probe_interval);
    peer_probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval`'s first tick is immediate; consume it so an idle downlink is
    // probed only after the configured grace period.
    peer_probe.tick().await;
    loop {
        if let Ok(data) = receiver.try_recv() {
            if !send_h3_downlink_data(&mut stream, data).await? {
                state.cancel();
                return Ok(());
            }
            continue;
        }
        if state.is_cancelled() {
            break;
        }
        let next = tokio::select! {
            biased;
            data = receiver.recv() => data,
            _ = state.cancelled() => None,
            _ = peer_probe.tick() => {
                // h3 0.0.8 does not expose Quinn's `SendStream::stopped`.
                // A zero-length DATA frame is a legal HTTP/3 frame which
                // carries no proxy bytes but makes a pending STOP_SENDING or
                // clean stream reset observable while the application is idle.
                if !send_h3_downlink_data(&mut stream, Bytes::new()).await? {
                    state.cancel();
                    return Ok(());
                }
                continue;
            }
        };
        let Some(data) = next else {
            break;
        };
        if !send_h3_downlink_data(&mut stream, data).await? {
            state.cancel();
            return Ok(());
        }
    }
    match stream.finish().await {
        Ok(()) => Ok(()),
        Err(error) if is_clean_h3_peer_close(&error) => {
            state.cancel();
            Ok(())
        }
        Err(error) => Err(h3_error("XHTTP/3 downlink finish", error)),
    }
}

async fn send_h3_downlink_data(stream: &mut H3SendStream, data: Bytes) -> io::Result<bool> {
    match stream.send_data(data).await {
        Ok(()) => Ok(true),
        Err(error) if is_clean_h3_peer_close(&error) => Ok(false),
        Err(error) => Err(h3_error("XHTTP/3 downlink", error)),
    }
}

async fn reserve_and_send_hyper_accepted(
    sender: &mpsc::Sender<AcceptedXhttpStream>,
    accepted: AcceptedXhttpStream,
    state: &Arc<IoState>,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
    accept_delivery_timeout: Duration,
) -> Result<(), RequestError> {
    let reserve = sender.reserve();
    tokio::pin!(reserve);
    let deadline = tokio::time::sleep(accept_delivery_timeout);
    tokio::pin!(deadline);
    let cancelled =
        packet_cancellation_tokens_cancelled(server_cancelled.clone(), session_cancelled.clone());
    tokio::pin!(cancelled);

    let permit = tokio::select! {
        biased;
        _ = state.cancelled() => {
            return Err(RequestError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "XHTTP logical stream was cancelled before acceptance",
            ));
        }
        _ = &mut cancelled => {
            return Err(RequestError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "XHTTP server or session was cancelled before acceptance",
            ));
        }
        _ = &mut deadline => {
            return Err(RequestError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "XHTTP timed out waiting for accept capacity",
            ));
        }
        result = &mut reserve => {
            result.map_err(|_| {
                RequestError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "XHTTP accept channel is closed",
                )
            })?
        }
    };

    // `reserve` holds capacity while cancellation is checked a final time.
    // There is no await between this check and `send`, so acceptance has a
    // single, explicit commit point and cannot leak a half-delivered stream.
    if state.is_cancelled()
        || server_cancelled.is_cancelled()
        || session_cancelled
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    {
        return Err(RequestError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "XHTTP server or session was cancelled before acceptance",
        ));
    }
    permit.send(accepted);
    Ok(())
}

async fn reserve_and_send_h3_accepted(
    sender: &mpsc::Sender<AcceptedXhttpStream>,
    accepted: AcceptedXhttpStream,
    stream: &mut H3SendStream,
    state: &Arc<IoState>,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
    accept_delivery_timeout: Duration,
) -> io::Result<()> {
    let reserve = sender.reserve();
    tokio::pin!(reserve);
    let deadline = tokio::time::sleep(accept_delivery_timeout);
    tokio::pin!(deadline);
    let mut peer_probe = tokio::time::interval(H3_ACCEPT_PROBE_INTERVAL);
    peer_probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let cancelled =
        packet_cancellation_tokens_cancelled(server_cancelled.clone(), session_cancelled.clone());
    tokio::pin!(cancelled);

    let permit = loop {
        let result = tokio::select! {
            biased;
            _ = state.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "XHTTP/3 logical stream was cancelled before acceptance",
                ));
            }
            _ = &mut cancelled => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "XHTTP/3 server or session was cancelled before acceptance",
                ));
            }
            _ = &mut deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "XHTTP/3 timed out waiting for XHTTP accept capacity",
                ));
            }
            result = &mut reserve => Some(result),
            _ = peer_probe.tick() => None,
        };
        if let Some(result) = result {
            break result.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "XHTTP accept channel is closed after HTTP/3 response started",
                )
            })?;
        }

        let peer_alive = tokio::time::timeout(
            H3_ACCEPT_PROBE_INTERVAL,
            send_h3_downlink_data(stream, Bytes::new()),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "XHTTP/3 peer probe stalled while waiting for XHTTP accept capacity",
            )
        })??;
        if !peer_alive {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP/3 peer closed while waiting for XHTTP accept capacity",
            ));
        }
    };

    // `reserve` is cancellation-safe and holds queue capacity while this final
    // liveness probe runs. That prevents a cancelled stream from being
    // committed merely because capacity became available at the same instant.
    if state.is_cancelled()
        || server_cancelled.is_cancelled()
        || session_cancelled
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "XHTTP/3 server or session was cancelled before acceptance",
        ));
    }
    let peer_alive = tokio::time::timeout(
        H3_ACCEPT_PROBE_INTERVAL,
        send_h3_downlink_data(stream, Bytes::new()),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "XHTTP/3 final peer probe stalled before acceptance",
        )
    })??;
    if !peer_alive {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "XHTTP/3 peer closed before logical stream acceptance",
        ));
    }
    if state.is_cancelled()
        || server_cancelled.is_cancelled()
        || session_cancelled
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "XHTTP/3 server or session was cancelled before acceptance",
        ));
    }
    permit.send(accepted);
    Ok(())
}

fn is_clean_h3_peer_close(error: &StreamError) -> bool {
    error.is_h3_no_error()
        || matches!(
            error,
            StreamError::RemoteTerminate { code, .. }
                if *code == Code::H3_NO_ERROR || *code == Code::H3_REQUEST_CANCELLED
        )
}

fn h3_peer_probe_interval(config: &Config) -> Duration {
    // Reuse Xray's randomized 20–80 second stream-up server cadence by
    // default. Operators who need faster dead-peer discovery can explicitly
    // configure scStreamUpServerSecs; the lower bound stays at one second so
    // malformed zero ranges cannot create a busy loop.
    let seconds = config
        .normalized_sc_stream_up_server_secs()
        .unwrap_or_else(|_| Range::new(20, 80))
        .rand()
        .max(1);
    Duration::from_secs(seconds as u64)
}

async fn acquire_connection_slot(
    slots: Arc<Semaphore>,
    shutdown: &CancellationToken,
    server_cancelled: &CancellationToken,
) -> Option<OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => None,
        _ = server_cancelled.cancelled() => None,
        permit = slots.acquire_owned() => permit.ok(),
    }
}

impl XhttpServer {
    /// Serve all QUIC connections accepted from an already-configured endpoint.
    ///
    /// The endpoint's server TLS configuration must advertise `h3`.
    pub async fn serve_h3_endpoint(
        &self,
        endpoint: quinn::Endpoint,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        let local_addr = endpoint.local_addr()?;
        let mut connections = JoinSet::new();
        loop {
            while let Some(completed) = connections.try_join_next() {
                if let Err(error) = completed {
                    tracing::debug!(%error, "XHTTP/3 task failed");
                }
            }
            let Some(connection_slot) = acquire_connection_slot(
                Arc::clone(&self.inner.connection_slots),
                &shutdown,
                &self.inner.cancelled,
            )
            .await
            else {
                break;
            };
            let incoming = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.inner.cancelled.cancelled() => break,
                incoming = endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                break;
            };
            let server = self.clone();
            let connection_shutdown = shutdown.child_token();
            connections.spawn(async move {
                let _connection_slot = connection_slot;
                match incoming.await {
                    Ok(connection) => {
                        let peer_addr = connection.remote_address();
                        if let Err(error) = server
                            .serve_h3_connection_until(
                                connection,
                                peer_addr,
                                local_addr,
                                connection_shutdown,
                            )
                            .await
                        {
                            tracing::debug!(%peer_addr, %error, "XHTTP/3 connection ended");
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "XHTTP/3 QUIC handshake rejected");
                    }
                }
            });
        }
        endpoint.close(quinn::VarInt::from_u32(0), b"XHTTP server shutdown");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    /// Serve one established QUIC connection as HTTP/3.
    pub async fn serve_h3_connection(
        &self,
        connection: quinn::Connection,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> io::Result<()> {
        self.serve_h3_connection_until(
            connection,
            peer_addr,
            local_addr,
            self.inner.cancelled.child_token(),
        )
        .await
    }

    /// Serve one established QUIC connection with explicit cancellation.
    pub async fn serve_h3_connection_until(
        &self,
        connection: quinn::Connection,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        let mut builder = h3::server::builder();
        builder
            .max_field_section_size(self.inner.config.normalized_server_max_header_bytes() as u64);
        let mut connection = builder
            .build::<_, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .map_err(|error| h3_error("XHTTP/3 connection setup", error))?;
        let mut requests = JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = connection.shutdown(0).await;
                    break;
                }
                _ = self.inner.cancelled.cancelled() => {
                    let _ = connection.shutdown(0).await;
                    break;
                }
                accepted = connection.accept() => {
                    match accepted.map_err(|error| h3_error("XHTTP/3 accept request", error))? {
                        Some(resolver) => {
                            let Some(http_stream_permit) = self.try_acquire_http_stream() else {
                                let resolved = tokio::select! {
                                    _ = shutdown.cancelled() => break,
                                    _ = self.inner.cancelled.cancelled() => break,
                                    resolved = tokio::time::timeout(
                                        HTTP_OVERLOAD_REJECTION_TIMEOUT,
                                        resolver.resolve_request(),
                                    ) => resolved,
                                };
                                match resolved {
                                    Ok(Ok((request, mut stream))) => {
                                        let headers = response_headers(&self.inner, &request);
                                        if let Err(error) = send_h3_simple(
                                            &mut stream,
                                            StatusCode::SERVICE_UNAVAILABLE,
                                            headers,
                                            Bytes::from_static(b"XHTTP server is at its active HTTP stream limit"),
                                        )
                                        .await
                                        {
                                            tracing::debug!(
                                                %peer_addr,
                                                %error,
                                                "XHTTP/3 overload response ended"
                                            );
                                        }
                                    }
                                    Ok(Err(error)) => {
                                        tracing::debug!(
                                            %peer_addr,
                                            %error,
                                            "XHTTP/3 overloaded request headers rejected"
                                        );
                                    }
                                    Err(_) => {
                                        tracing::debug!(
                                            %peer_addr,
                                            "XHTTP/3 overloaded request header timeout"
                                        );
                                    }
                                }
                                continue;
                            };
                            let server = self.clone();
                            let request_shutdown = shutdown.clone();
                            requests.spawn(async move {
                                let _http_stream_permit = http_stream_permit;
                                let resolved = tokio::select! {
                                    _ = request_shutdown.cancelled() => return,
                                    _ = server.inner.cancelled.cancelled() => return,
                                    resolved = tokio::time::timeout(
                                        READ_HEADER_TIMEOUT,
                                        resolver.resolve_request(),
                                    ) => resolved,
                                };
                                match resolved {
                                    Ok(Ok((request, stream))) => {
                                        if let Err(error) = server
                                            .handle_h3(request, stream, peer_addr, local_addr)
                                            .await
                                        {
                                            tracing::debug!(%peer_addr, %error, "XHTTP/3 request ended");
                                        }
                                    }
                                    Ok(Err(error)) => {
                                        tracing::debug!(%peer_addr, %error, "XHTTP/3 request headers rejected");
                                    }
                                    Err(_) => {
                                        // Dropping the resolver drops the underlying Quinn
                                        // bidi stream, which resets the response half and
                                        // stops the peer's unfinished request body.
                                        tracing::debug!(%peer_addr, "XHTTP/3 request header timeout");
                                    }
                                }
                            });
                        }
                        None => break,
                    }
                }
                completed = requests.join_next(), if !requests.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::debug!(%error, "XHTTP/3 request task failed");
                    }
                }
            }
        }
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle_h3(
        &self,
        request: Request<()>,
        mut stream: H3BidiStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> io::Result<()> {
        if let Err(error) = validate_route(&self.inner, &request) {
            return send_h3_request_error(&mut stream, error, HeaderMap::new()).await;
        }
        let mut headers = response_headers(&self.inner, &request);
        if request.method() == Method::OPTIONS {
            return send_h3_simple(&mut stream, StatusCode::OK, headers, Bytes::new()).await;
        }
        let head = match validate_head(&self.inner, &request) {
            Ok(head) => head,
            Err(error) => return send_h3_request_error(&mut stream, error, headers).await,
        };
        let method = request.method().clone();
        let is_uplink = method != Method::GET || !head.sequence.is_empty();

        if head.session_id.is_empty()
            && !matches!(
                self.inner.config.normalized_mode(),
                "auto" | "stream-one" | "stream-up"
            )
        {
            return send_h3_request_error(
                &mut stream,
                RequestError::bad_request("stream-one mode is not allowed"),
                headers,
            )
            .await;
        }

        if is_uplink && !head.session_id.is_empty() {
            if head.sequence.is_empty() {
                return self
                    .handle_h3_stream_up(request, stream, head, headers)
                    .await;
            }
            return self
                .handle_h3_packet_up(request, &mut stream, head, headers)
                .await;
        }

        if method == Method::GET || head.session_id.is_empty() {
            headers = streaming_response_headers(&self.inner.config, headers);
            return self
                .handle_h3_downlink(request, stream, head, peer_addr, local_addr, headers)
                .await;
        }

        send_h3_request_error(
            &mut stream,
            RequestError::new(StatusCode::METHOD_NOT_ALLOWED, "unsupported XHTTP method"),
            headers,
        )
        .await
    }

    async fn handle_h3_stream_up(
        &self,
        request: Request<()>,
        mut stream: H3BidiStream,
        head: ValidatedHead,
        mut headers: HeaderMap,
    ) -> io::Result<()> {
        if !matches!(self.inner.config.normalized_mode(), "auto" | "stream-up") {
            return send_h3_request_error(
                &mut stream,
                RequestError::bad_request("stream-up mode is not allowed"),
                headers,
            )
            .await;
        }
        let session = match self.upsert_session(&head.session_id) {
            Ok(session) => session,
            Err(error) => {
                return send_h3_request_error(
                    &mut stream,
                    RequestError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
                    headers,
                )
                .await;
            }
        };
        let upload_sender = match session.select_stream_source() {
            Ok(sender) => sender,
            Err(error) => {
                return send_h3_request_error(
                    &mut stream,
                    RequestError::new(StatusCode::CONFLICT, error.to_string()),
                    headers,
                )
                .await;
            }
        };

        insert_header(&mut headers, "x-accel-buffering", "no");
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        stream
            .send_response(h3_response(StatusCode::OK, headers))
            .await
            .map_err(|error| h3_error("XHTTP/3 stream-up response", error))?;
        let (mut send, receive) = stream.split();
        let state = Arc::clone(&session.io_state);
        let upload_state = Arc::clone(&state);
        let upload_done = CancellationToken::new();
        let done_after_upload = upload_done.clone();
        tokio::spawn(async move {
            pump_h3_body(receive, upload_sender, upload_state).await;
            done_after_upload.cancel();
        });

        let keepalive_range = self.inner.config.normalized_sc_stream_up_server_secs().ok();
        let padding_range = self.inner.config.normalized_x_padding_bytes().ok();
        let use_keepalive = (head.padding_obfs_accepted
            || request.headers().contains_key("referer"))
            && keepalive_range.as_ref().is_some_and(|range| range.max > 0);
        if use_keepalive {
            let keepalive_range = keepalive_range.expect("checked");
            let padding_range =
                padding_range.unwrap_or_else(|| core_outbound::proto::xhttp::Range::new(100, 1000));
            loop {
                let delay = keepalive_delay(keepalive_range);
                tokio::select! {
                    _ = upload_done.cancelled() => break,
                    _ = session.cancelled.cancelled() => break,
                    _ = tokio::time::sleep(delay) => {
                        if let Err(error) = send
                            .send_data(Bytes::from(vec![b'X'; padding_range.rand()]))
                            .await
                        {
                            state.fail(IoFailure::other(format!("XHTTP/3 keepalive: {error}")));
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                _ = upload_done.cancelled() => {}
                _ = session.cancelled.cancelled() => {}
            }
        }
        send.finish()
            .await
            .map_err(|error| h3_error("XHTTP/3 stream-up finish", error))
    }

    async fn handle_h3_packet_up(
        &self,
        request: Request<()>,
        stream: &mut H3BidiStream,
        head: ValidatedHead,
        mut headers: HeaderMap,
    ) -> io::Result<()> {
        if !matches!(self.inner.config.normalized_mode(), "auto" | "packet-up") {
            return send_h3_request_error(
                stream,
                RequestError::bad_request("packet-up mode is not allowed"),
                headers,
            )
            .await;
        }
        let sequence = match head.sequence.parse::<u64>() {
            Ok(sequence) => sequence,
            Err(error) => {
                return send_h3_request_error(
                    stream,
                    RequestError::bad_request(format!("invalid XHTTP sequence: {error}")),
                    headers,
                )
                .await;
            }
        };
        let permit = match self
            .reserve_packet_body(&head.session_id, sequence, PACKET_BODY_TIMEOUT)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                return send_h3_request_error(stream, error, headers).await;
            }
        };
        let session_cancelled = self
            .find_session(&head.session_id)
            .map(|session| session.cancelled.clone());
        let payload = match decode_h3_packet_payload(
            &self.inner.config,
            request.headers(),
            stream,
            self.inner.cancelled.clone(),
            session_cancelled,
        )
        .await
        {
            Ok(payload) => payload,
            Err(error) => return send_h3_request_error(stream, error, headers).await,
        };
        let payload = match permit.attach(payload) {
            Ok(payload) => payload,
            Err(error) => {
                return send_h3_request_error(
                    stream,
                    RequestError::new(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()),
                    headers,
                )
                .await;
            }
        };
        if let Err(error) = self.finish_packet_upload(&head.session_id, sequence, payload) {
            return send_h3_request_error(stream, error, headers).await;
        }
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        send_h3_simple(stream, StatusCode::OK, headers, Bytes::new()).await
    }

    async fn handle_h3_downlink(
        &self,
        _request: Request<()>,
        mut stream: H3BidiStream,
        head: ValidatedHead,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        headers: HeaderMap,
    ) -> io::Result<()> {
        let peer_probe_interval = h3_peer_probe_interval(&self.inner.config);
        if head.session_id.is_empty() {
            let state = IoState::shared();
            let (reader, upload_sender) =
                ResponseReader::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
            let (writer, downlink_rx) =
                PipeWriter::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
            let close_state = Arc::clone(&state);
            let logical: BoxedStream =
                Box::pin(XConn::new(reader, writer).with_on_close(move || close_state.cancel()));
            let accepted = AcceptedXhttpStream {
                stream: logical,
                peer_addr,
                local_addr,
                session_id: None,
                mode: "stream-one",
                version: XhttpVersion::Http3,
            };
            if let Err(error) = stream
                .send_response(h3_response(StatusCode::OK, headers))
                .await
            {
                state.cancel();
                return Err(h3_error("XHTTP/3 stream-one response", error));
            }
            let (mut send, receive) = stream.split();
            let pump_state = Arc::clone(&state);
            tokio::spawn(async move {
                pump_h3_body(receive, upload_sender, pump_state).await;
            });
            if let Err(error) = reserve_and_send_h3_accepted(
                &self.inner.accepted,
                accepted,
                &mut send,
                &state,
                self.inner.cancelled.clone(),
                None,
                self.inner.accept_delivery_timeout,
            )
            .await
            {
                state.cancel();
                return Err(error);
            }
            return send_h3_downlink(send, downlink_rx, state, peer_probe_interval).await;
        }

        let session = match self.upsert_session(&head.session_id) {
            Ok(session) => session,
            Err(error) => {
                return send_h3_request_error(
                    &mut stream,
                    RequestError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
                    headers,
                )
                .await;
            }
        };
        let reader = match session.take_reader() {
            Ok(reader) => reader,
            Err(error) => {
                return send_h3_request_error(
                    &mut stream,
                    RequestError::new(StatusCode::CONFLICT, error.to_string()),
                    headers,
                )
                .await;
            }
        };
        let state = Arc::clone(&session.io_state);
        let (writer, downlink_rx) = PipeWriter::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
        let weak = Arc::downgrade(&self.inner);
        let close_session = Arc::clone(&session);
        let logical: BoxedStream = Box::pin(XConn::new(reader, writer).with_on_close(move || {
            remove_session(&weak, &close_session);
            close_session.cancel("XHTTP/3 logical stream closed");
        }));
        let accepted = AcceptedXhttpStream {
            stream: logical,
            peer_addr,
            local_addr,
            session_id: Some(head.session_id),
            mode: self.accepted_session_mode(&session),
            version: XhttpVersion::Http3,
        };
        if let Err(error) = stream
            .send_response(h3_response(StatusCode::OK, headers))
            .await
        {
            remove_session(&Arc::downgrade(&self.inner), &session);
            session.cancel("XHTTP/3 download response headers failed");
            return Err(h3_error("XHTTP/3 download response", error));
        }
        let (mut send, receive) = stream.split();
        drop(receive);
        if let Err(error) = reserve_and_send_h3_accepted(
            &self.inner.accepted,
            accepted,
            &mut send,
            &state,
            self.inner.cancelled.clone(),
            Some(session.cancelled.clone()),
            self.inner.accept_delivery_timeout,
        )
        .await
        {
            remove_session(&Arc::downgrade(&self.inner), &session);
            session.cancel("XHTTP/3 logical stream was not accepted");
            return Err(error);
        }
        session.mark_fully_connected();
        let result = send_h3_downlink(send, downlink_rx, state, peer_probe_interval).await;
        remove_session(&Arc::downgrade(&self.inner), &session);
        if result.is_ok() {
            session.close_clean();
        } else {
            session.cancel("XHTTP/3 download response failed");
        }
        result
    }
}

fn remove_session(inner: &Weak<ServerInner>, session: &Arc<Session>) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let mut sessions = inner.sessions.lock();
    if sessions
        .get(&session.id)
        .is_some_and(|current| Arc::ptr_eq(current, session))
    {
        sessions.remove(&session.id);
        drop(sessions);
        inner.sessions_changed.notify_waiters();
    }
}

fn normalized_server_path(config: &Config) -> String {
    let mut path = config
        .path
        .split_once('?')
        .map_or(config.path.as_str(), |v| v.0)
        .to_owned();
    if path.is_empty() {
        path.push('/');
    } else if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if (config.normalized_session_placement() == PLACEMENT_PATH
        || config.normalized_seq_placement() == PLACEMENT_PATH)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

fn validate_session_id(id: &str) -> io::Result<()> {
    if id.is_empty() || id.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid XHTTP session id",
        ));
    }
    Ok(())
}

fn hash_packet_payload(builder: &RandomState, payload: &[u8]) -> u64 {
    let mut hasher = builder.build_hasher();
    payload.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug)]
struct RequestError {
    status: StatusCode,
    message: String,
}

impl RequestError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

#[derive(Debug)]
struct ValidatedHead {
    session_id: String,
    sequence: String,
    padding_obfs_accepted: bool,
}

fn request_header_size<B>(request: &Request<B>) -> usize {
    let start_line = request.method().as_str().len() + request.uri().to_string().len() + 16;
    request
        .headers()
        .iter()
        .fold(start_line, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(4)
        })
}

fn host_matches(request: &str, configured: &str) -> bool {
    if configured.is_empty() {
        return true;
    }
    matches!(
        (
            canonical_http_host(request),
            canonical_http_host(configured)
        ),
        (Some(request), Some(configured)) if request == configured
    )
}

fn canonical_http_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // A configured bare IP is valid, including bare IPv6. HTTP Host headers
    // normally bracket IPv6, but accepting the canonical bare form preserves
    // Xray configuration compatibility.
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return Some(address.to_string());
    }

    if let Some(bracketed) = value.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        if suffix.is_empty() {
            // no port
        } else {
            let port = suffix.strip_prefix(':')?;
            if port.is_empty() || port.parse::<u16>().is_err() {
                return None;
            }
        }
        let address = host.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(address.to_string());
    }

    if value.contains(['[', ']', '@', '/', '?', '#'])
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    match value.matches(':').count() {
        0 => {}
        1 => {
            let (host, port) = value.rsplit_once(':')?;
            if host.is_empty() || port.is_empty() || port.parse::<u16>().is_err() {
                return None;
            }
        }
        _ => return None,
    }
    let authority = value.parse::<http::uri::Authority>().ok()?;
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Some(address.to_string());
    }
    Some(host.to_ascii_lowercase())
}

fn request_host<B>(request: &Request<B>) -> Result<&str, RequestError> {
    let mut host_headers = request.headers().get_all(HOST).iter();
    let host_header = host_headers
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| RequestError::bad_request("invalid XHTTP Host header"))
        })
        .transpose()?;
    if host_headers.next().is_some() {
        return Err(RequestError::bad_request(
            "multiple XHTTP Host headers are not allowed",
        ));
    }

    let authority = request.uri().authority().map(|value| value.as_str());
    match (authority, host_header) {
        (Some(authority), Some(host)) => {
            let authority = canonical_http_host(authority)
                .ok_or_else(|| RequestError::bad_request("invalid XHTTP authority"))?;
            let host = canonical_http_host(host)
                .ok_or_else(|| RequestError::bad_request("invalid XHTTP Host header"))?;
            if authority != host {
                return Err(RequestError::bad_request(
                    "conflicting XHTTP authority and Host header",
                ));
            }
            Ok(request
                .uri()
                .authority()
                .expect("authority was checked above")
                .as_str())
        }
        (Some(authority), None) => {
            canonical_http_host(authority)
                .ok_or_else(|| RequestError::bad_request("invalid XHTTP authority"))?;
            Ok(authority)
        }
        (None, Some(host)) => {
            canonical_http_host(host)
                .ok_or_else(|| RequestError::bad_request("invalid XHTTP Host header"))?;
            Ok(host)
        }
        (None, None) => Ok(""),
    }
}

fn query_value(uri: &Uri, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    go_query_value(uri.query()?, key)
}

fn strict_query_value(uri: &Uri, key: &str) -> Result<Option<String>, ()> {
    if key.is_empty() {
        return Ok(None);
    }
    Ok(uri.query().and_then(|query| go_query_value(query, key)))
}

fn query_value_from_url(value: &str, key: &str) -> Option<String> {
    let query = value.split_once('?')?.1.split('#').next().unwrap_or("");
    go_query_value(query, key)
}

/// Match Go 1.26 `url.ParseQuery`, whose errors are intentionally ignored by
/// `URL.Query`: invalid pairs are skipped, valid duplicates retain their
/// order, and an over-limit query produces an empty map.
fn go_query_value(raw_query: &str, key: &str) -> Option<String> {
    const MAX_QUERY_PARAMS: usize = 10_000;
    if raw_query.bytes().filter(|byte| *byte == b'&').count() + 1 > MAX_QUERY_PARAMS {
        return None;
    }

    let wanted = key.as_bytes();
    for pair in raw_query.as_bytes().split(|byte| *byte == b'&') {
        if pair.is_empty() || pair.contains(&b';') {
            continue;
        }
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(pair.len());
        let (raw_name, raw_value) = if separator == pair.len() {
            (pair, &[][..])
        } else {
            (&pair[..separator], &pair[separator + 1..])
        };
        let (Some(name), Some(value)) = (
            query_unescape_bytes(raw_name),
            query_unescape_bytes(raw_value),
        ) else {
            continue;
        };
        if name == wanted {
            return String::from_utf8(value).ok();
        }
    }
    None
}

fn query_unescape_bytes(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut offset = 0;
    while offset < value.len() {
        match value[offset] {
            b'%' if offset + 2 < value.len() => {
                let high = hex_nibble(value[offset + 1])?;
                let low = hex_nibble(value[offset + 2])?;
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'%' => return None,
            b'+' => {
                decoded.push(b' ');
                offset += 1;
            }
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    Some(decoded)
}

fn percent_decode(value: &str, plus_as_space: bool) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'%' if offset + 2 < bytes.len() => {
                let high = hex_nibble(bytes[offset + 1]).ok_or(())?;
                let low = hex_nibble(bytes[offset + 2]).ok_or(())?;
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'%' => return Err(()),
            b'+' if plus_as_space => {
                decoded.push(b' ');
                offset += 1;
            }
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn cookie_value(headers: &HeaderMap, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    go_request_cookies(headers)
        .into_iter()
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn strict_cookie_value(headers: &HeaderMap, key: &str) -> Result<Option<String>, ()> {
    Ok(cookie_value(headers, key))
}

/// Mirror Go 1.26 `net/http.readCookies`, including its all-or-nothing 3000
/// item limit and its skip-invalid-then-continue lookup semantics.
fn go_request_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    const MAX_COOKIES: usize = 3_000;
    let cookie_headers = headers.get_all(COOKIE).iter().collect::<Vec<_>>();
    let count = cookie_headers
        .iter()
        .map(|header| {
            header
                .as_bytes()
                .iter()
                .filter(|byte| **byte == b';')
                .count()
                + 1
        })
        .sum::<usize>();
    if count > MAX_COOKIES {
        return Vec::new();
    }

    let mut cookies = Vec::new();
    for header in cookie_headers {
        for part in header.as_bytes().split(|byte| *byte == b';') {
            let part = trim_ascii_space(part);
            if part.is_empty() {
                continue;
            }
            let separator = part
                .iter()
                .position(|byte| *byte == b'=')
                .unwrap_or(part.len());
            let name = trim_ascii_space(&part[..separator]);
            if !is_http_token(name) {
                continue;
            }
            let mut value = if separator == part.len() {
                &[][..]
            } else {
                &part[separator + 1..]
            };
            if value.len() > 1 && value.first() == Some(&b'"') && value.last() == Some(&b'"') {
                value = &value[1..value.len() - 1];
            }
            if !value.iter().copied().all(valid_cookie_value_byte) {
                continue;
            }
            cookies.push((
                String::from_utf8(name.to_vec()).expect("HTTP token is ASCII"),
                String::from_utf8(value.to_vec()).expect("cookie value is ASCII"),
            ));
        }
    }
    cookies
}

fn trim_ascii_space(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_http_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().copied().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_cookie_value_byte(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte) && !matches!(byte, b'"' | b';' | b'\\')
}

fn placement_value(
    placement: &str,
    key: &str,
    uri: &Uri,
    headers: &HeaderMap,
    path_segments: &mut impl Iterator<Item = Result<String, ()>>,
) -> Result<String, ()> {
    match placement {
        PLACEMENT_PATH => path_segments
            .next()
            .transpose()
            .map(Option::unwrap_or_default),
        PLACEMENT_QUERY => strict_query_value(uri, key).map(Option::unwrap_or_default),
        PLACEMENT_HEADER => headers.get(key).map_or(Ok(String::new()), |value| {
            value.to_str().map(str::to_owned).map_err(|_| ())
        }),
        PLACEMENT_COOKIE => strict_cookie_value(headers, key).map(Option::unwrap_or_default),
        _ => Ok(String::new()),
    }
}

fn extract_meta(
    config: &Config,
    uri: &Uri,
    headers: &HeaderMap,
    path: &str,
) -> Result<(String, String), ()> {
    // Go's `net/http` exposes the once-unescaped `URL.Path`, and pinned Xray
    // splits that decoded path. Decode before splitting so `%2F` creates the
    // same segment boundary instead of becoming a literal slash inside one
    // metadata value.
    let decoded_path = percent_decode(uri.path(), false)?;
    let suffix = decoded_path.strip_prefix(path).unwrap_or("");
    let mut path_segments = suffix.split('/').map(|segment| Ok(segment.to_owned()));
    let session = placement_value(
        config.normalized_session_placement(),
        config.normalized_session_key(),
        uri,
        headers,
        &mut path_segments,
    )?;
    let sequence = placement_value(
        config.normalized_seq_placement(),
        config.normalized_seq_key(),
        uri,
        headers,
        &mut path_segments,
    )?;
    Ok((session, sequence))
}

fn extract_padding(config: &Config, uri: &Uri, headers: &HeaderMap) -> String {
    if !config.x_padding_obfs_mode {
        if let Some(referer) = headers.get("referer").and_then(|value| value.to_str().ok()) {
            return query_value_from_url(referer, "x_padding").unwrap_or_default();
        }
        return query_value(uri, "x_padding").unwrap_or_default();
    }

    let key = &config.x_padding_key;
    if let Some(value) = cookie_value(headers, key) {
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(value) = headers
        .get(config.x_padding_header.as_str())
        .and_then(|value| value.to_str().ok())
    {
        if config.x_padding_placement == PLACEMENT_HEADER {
            return value.to_owned();
        }
        if let Some(value) = query_value_from_url(value, key) {
            return value;
        }
    }
    query_value(uri, key).unwrap_or_default()
}

fn validate_head<B>(
    inner: &ServerInner,
    request: &Request<B>,
) -> Result<ValidatedHead, RequestError> {
    validate_route(inner, request)?;
    let padding = extract_padding(&inner.config, request.uri(), request.headers());
    let range = inner
        .config
        .normalized_x_padding_bytes()
        .map_err(RequestError::bad_request)?;
    if !is_padding_valid(
        PaddingMethod::parse(&inner.config.x_padding_method),
        &padding,
        range.min,
        range.max,
    ) {
        return Err(RequestError::bad_request("invalid XHTTP padding"));
    }

    let (session_id, sequence) =
        extract_meta(&inner.config, request.uri(), request.headers(), &inner.path)
            .map_err(|_| RequestError::bad_request("invalid XHTTP metadata encoding"))?;
    if !session_id.is_empty() {
        validate_session_id(&session_id)
            .map_err(|error| RequestError::bad_request(error.to_string()))?;
    }
    Ok(ValidatedHead {
        session_id,
        sequence,
        padding_obfs_accepted: inner.config.x_padding_obfs_mode && !padding.is_empty(),
    })
}

fn validate_route<B>(inner: &ServerInner, request: &Request<B>) -> Result<(), RequestError> {
    if request_header_size(request) > inner.config.normalized_server_max_header_bytes() {
        return Err(RequestError::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "XHTTP request headers exceed serverMaxHeaderBytes",
        ));
    }
    if !host_matches(request_host(request)?, &inner.host) {
        return Err(RequestError::new(
            StatusCode::NOT_FOUND,
            "XHTTP host mismatch",
        ));
    }
    let decoded_path = percent_decode(request.uri().path(), false)
        .map_err(|_| RequestError::bad_request("invalid XHTTP path encoding"))?;
    if !decoded_path.starts_with(&inner.path) {
        return Err(RequestError::new(
            StatusCode::NOT_FOUND,
            "XHTTP path mismatch",
        ));
    }
    Ok(())
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

fn normalized_server_uplink_data_placement(config: &Config) -> &str {
    if config.uplink_data_placement.is_empty() {
        PLACEMENT_BODY
    } else {
        &config.uplink_data_placement
    }
}

fn keepalive_delay(range: Range) -> Duration {
    let seconds = range.rand() as u64;
    if seconds == 0 {
        Duration::from_millis(1)
    } else {
        Duration::from_secs(seconds)
    }
}

fn apply_response_padding(config: &Config, headers: &mut HeaderMap) {
    let Ok(range) = config.normalized_x_padding_bytes() else {
        return;
    };
    let padding = generate_padding(
        if config.x_padding_obfs_mode {
            PaddingMethod::parse(&config.x_padding_method)
        } else {
            PaddingMethod::RepeatX
        },
        range.rand(),
    );
    if padding.is_empty() {
        return;
    }
    if !config.x_padding_obfs_mode {
        if let Ok(value) = HeaderValue::from_str(&padding) {
            headers.insert(HeaderName::from_static("x-padding"), value);
        }
        return;
    }

    match config.x_padding_placement.as_str() {
        PLACEMENT_HEADER => {
            let name = if config.x_padding_header.is_empty() {
                "X-Padding"
            } else {
                &config.x_padding_header
            };
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&padding),
            ) {
                headers.insert(name, value);
            }
        }
        PLACEMENT_QUERY_IN_HEADER => {
            let name = if config.x_padding_header.is_empty() {
                "Referer"
            } else {
                &config.x_padding_header
            };
            let key = if config.x_padding_key.is_empty() {
                "x_padding"
            } else {
                &config.x_padding_key
            };
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&format!("?{key}={padding}")),
            ) {
                headers.insert(name, value);
            }
        }
        PLACEMENT_COOKIE => {
            let key = if config.x_padding_key.is_empty() {
                "x_padding"
            } else {
                &config.x_padding_key
            };
            if let Ok(value) = HeaderValue::from_str(&format!("{key}={padding}; Path=/")) {
                headers.append(SET_COOKIE, value);
            }
        }
        _ => {}
    }
}

fn response_headers<B>(inner: &ServerInner, request: &Request<B>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    inner
        .cors_policy
        .apply(&inner.config, request, &mut headers);
    apply_response_padding(&inner.config, &mut headers);
    headers
}

fn response_with_headers(
    status: StatusCode,
    headers: HeaderMap,
    body: XhttpBody,
) -> Response<XhttpBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn error_response(error: RequestError, headers: HeaderMap) -> Response<XhttpBody> {
    response_with_headers(
        error.status,
        headers,
        XhttpBody::once(error.message.into_bytes()),
    )
}

fn streaming_response_headers(config: &Config, mut headers: HeaderMap) -> HeaderMap {
    insert_header(&mut headers, "x-accel-buffering", "no");
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if !config.no_sse_header {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    }
    headers
}

fn request_version(version: Version) -> XhttpVersion {
    match version {
        Version::HTTP_2 => XhttpVersion::Http2,
        Version::HTTP_3 => XhttpVersion::Http3,
        _ => XhttpVersion::Http1,
    }
}

fn header_chunks(headers: &HeaderMap, key: &str) -> Result<Vec<u8>, RequestError> {
    let key = if key.is_empty() { "X-Data" } else { key };
    let mut encoded = String::new();
    for index in 0usize.. {
        let name = HeaderName::from_bytes(format!("{key}-{index}").as_bytes())
            .map_err(|_| RequestError::bad_request("invalid uplinkDataKey"))?;
        let Some(value) = headers.get(name) else {
            break;
        };
        encoded.push_str(
            value
                .to_str()
                .map_err(|_| RequestError::bad_request("non-ASCII XHTTP header payload"))?,
        );
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| RequestError::bad_request(format!("invalid header payload: {error}")))
}

fn cookie_chunks(headers: &HeaderMap, key: &str) -> Result<Vec<u8>, RequestError> {
    let key = if key.is_empty() { "x_data" } else { key };
    let cookies = go_request_cookies(headers);
    let mut encoded = String::new();
    for index in 0usize.. {
        let name = format!("{key}_{index}");
        let Some(value) = cookies
            .iter()
            .find_map(|(cookie_name, value)| (cookie_name == &name).then_some(value))
        else {
            break;
        };
        encoded.push_str(value);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| RequestError::bad_request(format!("invalid cookie payload: {error}")))
}

async fn read_hyper_body_limited<B>(body: B, limit: usize) -> Result<Vec<u8>, RequestError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    read_hyper_body_limited_with_timeout(
        body,
        limit,
        PACKET_BODY_TIMEOUT,
        CancellationToken::new(),
        None,
    )
    .await
}

async fn read_hyper_packet_body_limited<B>(
    body: B,
    limit: usize,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    read_hyper_body_limited_with_timeout(
        body,
        limit,
        PACKET_BODY_TIMEOUT,
        server_cancelled,
        session_cancelled,
    )
    .await
}

async fn read_hyper_body_limited_with_timeout<B>(
    mut body: B,
    limit: usize,
    idle_timeout: Duration,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if body
        .size_hint()
        .upper()
        .is_some_and(|upper| upper > limit as u64)
    {
        return Err(RequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "XHTTP upload exceeds scMaxEachPostBytes",
        ));
    }
    let mut output = Vec::new();
    loop {
        let cancelled = packet_cancellation_tokens_cancelled(
            server_cancelled.clone(),
            session_cancelled.clone(),
        );
        let frame = tokio::select! {
            biased;
            _ = cancelled => return Err(packet_body_cancelled_error()),
            _ = tokio::time::sleep(idle_timeout) => {
                return Err(packet_body_idle_timeout());
            }
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            break;
        };
        let frame =
            frame.map_err(|error| RequestError::bad_request(format!("request body: {error}")))?;
        if let Some(data) = frame.data_ref() {
            if output.len().saturating_add(data.len()) > limit {
                return Err(RequestError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "XHTTP upload exceeds scMaxEachPostBytes",
                ));
            }
            output.extend_from_slice(data);
        }
    }
    Ok(output)
}

async fn decode_packet_payload<B>(
    config: &Config,
    headers: &HeaderMap,
    body: B,
    server_cancelled: CancellationToken,
    session_cancelled: Option<CancellationToken>,
) -> Result<Vec<u8>, RequestError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let limit = config
        .normalized_sc_max_each_post_bytes()
        .map_err(RequestError::bad_request)?
        .max;
    let placement = normalized_server_uplink_data_placement(config);
    let header = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_HEADER) {
        header_chunks(headers, &config.uplink_data_key)?
    } else {
        Vec::new()
    };
    let cookie = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_COOKIE) {
        cookie_chunks(headers, &config.uplink_data_key)?
    } else {
        Vec::new()
    };
    let body = if matches!(placement, PLACEMENT_AUTO | PLACEMENT_BODY) {
        read_hyper_packet_body_limited(body, limit, server_cancelled, session_cancelled).await?
    } else {
        Vec::new()
    };
    combine_packet_payload(placement, header, cookie, body, limit)
}

fn combine_packet_payload(
    placement: &str,
    header: Vec<u8>,
    cookie: Vec<u8>,
    body: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, RequestError> {
    let mut payload = match placement {
        PLACEMENT_HEADER => header,
        PLACEMENT_COOKIE => cookie,
        PLACEMENT_BODY => body,
        PLACEMENT_AUTO => {
            let mut output = Vec::with_capacity(header.len() + cookie.len() + body.len());
            output.extend_from_slice(&header);
            output.extend_from_slice(&cookie);
            output.extend_from_slice(&body);
            output
        }
        _ => return Err(RequestError::bad_request("unsupported uplinkDataPlacement")),
    };
    if payload.len() > limit {
        payload.clear();
        return Err(RequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "XHTTP upload exceeds scMaxEachPostBytes",
        ));
    }
    Ok(payload)
}

async fn pump_hyper_body(
    mut body: Incoming,
    sender: mpsc::Sender<ResponseItem>,
    state: Arc<IoState>,
    allow_streaming_eof: bool,
) {
    loop {
        tokio::select! {
            _ = state.cancelled() => break,
            frame = body.frame() => {
                let Some(frame) = frame else {
                    break;
                };
                match frame {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            if !data.is_empty() && sender.send(Ok(data.clone())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        // Xray's streaming upload may close the request side
                        // without Hyper exposing a final body marker. HTTP/1
                        // reports an incomplete/UnexpectedEof chain; HTTP/2
                        // can surface the peer's RST_STREAM(CANCEL) while
                        // Hyper is polling trailers. For the two indefinite
                        // upload modes these are logical byte-stream EOF.
                        //
                        // `packet-up` does not call this pump: its finite request
                        // body remains strictly decoded by
                        // `read_hyper_body_limited`.
                        // Hyper 1.x may expose this either as
                        // `IncompleteMessage` or as a Body wrapper whose
                        // typed source is `io::ErrorKind::UnexpectedEof`.
                        // The caller enables this compatibility only for
                        // stream-one/stream-up; finite packet-up bodies never
                        // enter this pump.
                        if allow_streaming_eof && is_hyper_streaming_eof(&error) {
                            break;
                        }
                        let failure = IoFailure::other(format!("XHTTP request body: {error}"));
                        state.fail(failure.clone());
                        let _ = sender.send(Err(failure)).await;
                        break;
                    }
                }
            }
        }
    }
}

fn is_hyper_streaming_eof(error: &hyper::Error) -> bool {
    if error.is_incomplete_message() {
        return true;
    }
    let mut source = error.source();
    while let Some(current) = source {
        if current
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
        {
            return true;
        }
        if current
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
        {
            return true;
        }
        if is_clean_h2_streaming_end(current) {
            return true;
        }
        source = current.source();
    }
    false
}

fn is_clean_h2_streaming_end(error: &(dyn StdError + 'static)) -> bool {
    error.downcast_ref::<h2::Error>().is_some_and(|error| {
        matches!(
            error.reason(),
            Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL)
        )
    })
}

async fn accept_tls_with_timeout(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    timeout: Duration,
) -> io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    tokio::time::timeout(timeout, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP TLS handshake timed out"))?
}

impl XhttpServer {
    /// Serve one already-established plaintext or TLS stream with automatic
    /// HTTP/1.1 and HTTP/2 detection.
    pub async fn serve_io<I>(
        &self,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> io::Result<()>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_io_until(
            io,
            peer_addr,
            local_addr,
            self.inner.cancelled.child_token(),
        )
        .await
    }

    /// Like [`Self::serve_io`], with a per-connection cancellation token.
    pub async fn serve_io_until<I>(
        &self,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        shutdown: CancellationToken,
    ) -> io::Result<()>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_io_until_with_header_timeout(
            io,
            peer_addr,
            local_addr,
            shutdown,
            READ_HEADER_TIMEOUT,
            HttpVersionPolicy::HTTP1_AND_HTTP2,
        )
        .await
    }

    /// Like [`Self::serve_io_until`], with an explicit HTTP version policy.
    pub(crate) async fn serve_io_until_with_policy<I>(
        &self,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        shutdown: CancellationToken,
        policy: HttpVersionPolicy,
    ) -> io::Result<()>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_io_until_with_header_timeout(
            io,
            peer_addr,
            local_addr,
            shutdown,
            READ_HEADER_TIMEOUT,
            policy,
        )
        .await
    }

    async fn serve_io_until_with_header_timeout<I>(
        &self,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        shutdown: CancellationToken,
        header_timeout: Duration,
        policy: HttpVersionPolicy,
    ) -> io::Result<()>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let header_watch = HeaderTimeoutWatch::new(header_timeout, self.inner.http_idle_timeout);
        let header_watch_for_service = Arc::clone(&header_watch);
        let server = self.clone();
        let service = service_fn(move |request| {
            let server = server.clone();
            let header_watch = Arc::clone(&header_watch_for_service);
            async move {
                let version = request.version();
                if !policy.allows(version) {
                    return Ok::<_, Infallible>(response_with_headers(
                        StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                        HeaderMap::new(),
                        XhttpBody::empty(),
                    ));
                }
                let timeout_guard = header_watch.request_started(version);
                let Some(http_stream_permit) = server.try_acquire_http_stream() else {
                    let headers = response_headers(&server.inner, &request);
                    let body =
                        XhttpBody::empty().with_on_finish(timeout_guard.into_finish_callback());
                    return Ok(response_with_headers(
                        StatusCode::SERVICE_UNAVAILABLE,
                        headers,
                        body,
                    ));
                };
                let response = server.handle_hyper(request, peer_addr, local_addr).await;
                let (parts, body) = response.into_parts();
                let body = body.with_on_finish(timeout_guard.into_finish_callback());
                let body = body.with_on_finish(move || drop(http_stream_permit));
                Ok(Response::from_parts(parts, body))
            }
        });
        let max_header_bytes = self.inner.config.normalized_server_max_header_bytes();
        let mut builder = AutoBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .half_close(true)
            .max_buf_size(max_header_bytes.max(8192));
        builder
            .http2()
            .max_concurrent_streams(self.inner.max_concurrent_streams)
            .max_header_list_size(max_header_bytes.min(u32::MAX as usize) as u32);
        let connection = builder.serve_connection(TokioIo::new(io), service);
        tokio::pin!(connection);
        let header_timeout_elapsed = header_watch.wait_for_timeout();
        tokio::pin!(header_timeout_elapsed);
        tokio::select! {
            result = &mut connection => result.map_err(|error| {
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("XHTTP HTTP connection: {error}"))
            }),
            _ = shutdown.cancelled() => Ok(()),
            _ = self.inner.cancelled.cancelled() => Ok(()),
            timeout_kind = &mut header_timeout_elapsed => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                match timeout_kind {
                    ConnectionTimeoutKind::RequestHeader => "XHTTP HTTP request header timed out",
                    ConnectionTimeoutKind::HttpIdle => "XHTTP HTTP connection idle timed out",
                },
            )),
        }
    }

    /// Accept and serve plaintext HTTP/1.1 or h2c connections.
    pub async fn serve_listener(
        &self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        self.serve_listener_with_policy(listener, shutdown, HttpVersionPolicy::HTTP1_AND_HTTP2)
            .await
    }

    /// Accept and serve plaintext connections under an explicit HTTP version
    /// policy.
    pub(crate) async fn serve_listener_with_policy(
        &self,
        listener: TcpListener,
        shutdown: CancellationToken,
        policy: HttpVersionPolicy,
    ) -> io::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            while let Some(completed) = connections.try_join_next() {
                if let Err(error) = completed {
                    tracing::debug!(%error, "XHTTP HTTP task failed");
                }
            }
            let Some(connection_slot) = acquire_connection_slot(
                Arc::clone(&self.inner.connection_slots),
                &shutdown,
                &self.inner.cancelled,
            )
            .await
            else {
                break;
            };
            let accepted = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.inner.cancelled.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer_addr) = accepted?;
            let local_addr = stream.local_addr()?;
            let server = self.clone();
            let connection_shutdown = shutdown.child_token();
            connections.spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(error) = server
                    .serve_io_until_with_policy(
                        stream,
                        peer_addr,
                        local_addr,
                        connection_shutdown,
                        policy,
                    )
                    .await
                {
                    tracing::debug!(%peer_addr, %error, "XHTTP HTTP connection ended");
                }
            });
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    /// Bind and serve a plaintext HTTP/1.1+h2c listener.
    pub async fn listen(&self, address: SocketAddr, shutdown: CancellationToken) -> io::Result<()> {
        self.serve_listener(TcpListener::bind(address).await?, shutdown)
            .await
    }

    /// Accept TLS connections and serve negotiated HTTP/1.1 or HTTP/2.
    pub async fn serve_tls_listener(
        &self,
        listener: TcpListener,
        acceptor: TlsAcceptor,
        shutdown: CancellationToken,
    ) -> io::Result<()> {
        self.serve_tls_listener_with_policy(
            listener,
            acceptor,
            shutdown,
            HttpVersionPolicy::HTTP1_AND_HTTP2,
        )
        .await
    }

    /// Accept TLS connections, require an exact negotiated HTTP ALPN and serve
    /// only the HTTP version selected by that ALPN.
    pub(crate) async fn serve_tls_listener_with_policy(
        &self,
        listener: TcpListener,
        acceptor: TlsAcceptor,
        shutdown: CancellationToken,
        allowed_policy: HttpVersionPolicy,
    ) -> io::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            while let Some(completed) = connections.try_join_next() {
                if let Err(error) = completed {
                    tracing::debug!(%error, "XHTTP TLS task failed");
                }
            }
            let Some(connection_slot) = acquire_connection_slot(
                Arc::clone(&self.inner.connection_slots),
                &shutdown,
                &self.inner.cancelled,
            )
            .await
            else {
                break;
            };
            let accepted = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.inner.cancelled.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer_addr) = accepted?;
            let local_addr = stream.local_addr()?;
            let server = self.clone();
            let acceptor = acceptor.clone();
            let connection_shutdown = shutdown.child_token();
            connections.spawn(async move {
                let _connection_slot = connection_slot;
                match accept_tls_with_timeout(&acceptor, stream, READ_HEADER_TIMEOUT).await {
                    Ok(stream) => {
                        let negotiated_policy = match allowed_policy
                            .from_negotiated_alpn(stream.get_ref().1.alpn_protocol())
                        {
                            Ok(policy) => policy,
                            Err(error) => {
                                tracing::debug!(
                                    %peer_addr,
                                    %error,
                                    "XHTTP TLS ALPN rejected"
                                );
                                return;
                            }
                        };
                        if let Err(error) = server
                            .serve_io_until_with_policy(
                                stream,
                                peer_addr,
                                local_addr,
                                connection_shutdown,
                                negotiated_policy,
                            )
                            .await
                        {
                            tracing::debug!(%peer_addr, %error, "XHTTP TLS connection ended");
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%peer_addr, %error, "XHTTP TLS handshake ended");
                    }
                }
            });
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    /// BoringSSL-backed listener used when the configured server needs a
    /// capability rustls does not provide (legacy TLS/P-521/server ECH).
    pub(crate) async fn serve_boring_tls_listener_with_policy(
        &self,
        listener: TcpListener,
        acceptor: boring::ssl::SslAcceptor,
        shutdown: CancellationToken,
        allowed_policy: HttpVersionPolicy,
    ) -> io::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            while let Some(completed) = connections.try_join_next() {
                if let Err(error) = completed {
                    tracing::debug!(%error, "XHTTP BoringSSL task failed");
                }
            }
            let Some(connection_slot) = acquire_connection_slot(
                Arc::clone(&self.inner.connection_slots),
                &shutdown,
                &self.inner.cancelled,
            )
            .await
            else {
                break;
            };
            let accepted = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.inner.cancelled.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer_addr) = accepted?;
            let local_addr = stream.local_addr()?;
            let server = self.clone();
            let acceptor = acceptor.clone();
            let connection_shutdown = shutdown.child_token();
            connections.spawn(async move {
                let _connection_slot = connection_slot;
                let handshake = tokio::time::timeout(
                    READ_HEADER_TIMEOUT,
                    tokio_boring::accept(&acceptor, stream),
                )
                .await;
                match handshake {
                    Ok(Ok(stream)) => {
                        let negotiated_policy = match allowed_policy
                            .from_negotiated_alpn(stream.ssl().selected_alpn_protocol())
                        {
                            Ok(policy) => policy,
                            Err(error) => {
                                tracing::debug!(%peer_addr, %error, "XHTTP BoringSSL ALPN rejected");
                                return;
                            }
                        };
                        if let Err(error) = server
                            .serve_io_until_with_policy(
                                stream,
                                peer_addr,
                                local_addr,
                                connection_shutdown,
                                negotiated_policy,
                            )
                            .await
                        {
                            tracing::debug!(%peer_addr, %error, "XHTTP BoringSSL connection ended");
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(%peer_addr, %error, "XHTTP BoringSSL handshake ended");
                    }
                    Err(_) => {
                        tracing::debug!(%peer_addr, "XHTTP BoringSSL handshake timed out");
                    }
                }
            });
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle_hyper(
        &self,
        request: Request<Incoming>,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Response<XhttpBody> {
        if let Err(error) = validate_route(&self.inner, &request) {
            return error_response(error, HeaderMap::new());
        }
        let mut headers = response_headers(&self.inner, &request);
        if request.method() == Method::OPTIONS {
            return response_with_headers(StatusCode::OK, headers, XhttpBody::empty());
        }
        let head = match validate_head(&self.inner, &request) {
            Ok(head) => head,
            Err(error) => return error_response(error, headers),
        };
        let version = request_version(request.version());
        let method = request.method().clone();
        let is_uplink = method != Method::GET || !head.sequence.is_empty();

        if head.session_id.is_empty()
            && !matches!(
                self.inner.config.normalized_mode(),
                "auto" | "stream-one" | "stream-up"
            )
        {
            return error_response(
                RequestError::bad_request("stream-one mode is not allowed"),
                headers,
            );
        }

        if is_uplink && !head.session_id.is_empty() {
            if head.sequence.is_empty() {
                return self
                    .handle_hyper_stream_up(request, head, peer_addr, local_addr, headers)
                    .await;
            }
            return self.handle_hyper_packet_up(request, head, headers).await;
        }

        if method == Method::GET || head.session_id.is_empty() {
            headers = streaming_response_headers(&self.inner.config, headers);
            return self
                .handle_hyper_downlink(request, head, peer_addr, local_addr, version, headers)
                .await;
        }

        error_response(
            RequestError::new(StatusCode::METHOD_NOT_ALLOWED, "unsupported XHTTP method"),
            headers,
        )
    }

    async fn handle_hyper_stream_up(
        &self,
        request: Request<Incoming>,
        head: ValidatedHead,
        _peer_addr: SocketAddr,
        _local_addr: SocketAddr,
        mut headers: HeaderMap,
    ) -> Response<XhttpBody> {
        if !matches!(self.inner.config.normalized_mode(), "auto" | "stream-up") {
            return error_response(
                RequestError::bad_request("stream-up mode is not allowed"),
                headers,
            );
        }
        let session = match self.upsert_session(&head.session_id) {
            Ok(session) => session,
            Err(error) => {
                return error_response(
                    RequestError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
                    headers,
                );
            }
        };
        let upload_sender = match session.select_stream_source() {
            Ok(sender) => sender,
            Err(error) => {
                return error_response(
                    RequestError::new(StatusCode::CONFLICT, error.to_string()),
                    headers,
                );
            }
        };

        insert_header(&mut headers, "x-accel-buffering", "no");
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        let (keepalive_tx, keepalive_rx) = mpsc::channel(BODY_CHANNEL_CAPACITY);
        let had_referer = request.headers().contains_key("referer");
        let state = Arc::clone(&session.io_state);
        let body_state = Arc::clone(&state);
        let upload_done = CancellationToken::new();
        let done_after_upload = upload_done.clone();
        let session_cancelled = session.cancelled.clone();
        let allow_streaming_eof = matches!(request.version(), Version::HTTP_11 | Version::HTTP_2);
        tokio::spawn(async move {
            pump_hyper_body(
                request.into_body(),
                upload_sender,
                state,
                allow_streaming_eof,
            )
            .await;
            done_after_upload.cancel();
        });

        let keepalive_range = self.inner.config.normalized_sc_stream_up_server_secs().ok();
        let padding_range = self.inner.config.normalized_x_padding_bytes().ok();
        let use_keepalive = (head.padding_obfs_accepted || had_referer)
            && keepalive_range.as_ref().is_some_and(|range| range.max > 0);
        tokio::spawn(async move {
            if use_keepalive {
                let keepalive_range = keepalive_range.expect("checked");
                let padding_range = padding_range
                    .unwrap_or_else(|| core_outbound::proto::xhttp::Range::new(100, 1000));
                loop {
                    let delay = keepalive_delay(keepalive_range);
                    tokio::select! {
                        _ = upload_done.cancelled() => break,
                        _ = session_cancelled.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {
                            let padding = Bytes::from(vec![b'X'; padding_range.rand()]);
                            if keepalive_tx.send(padding).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = upload_done.cancelled() => {}
                    _ = session_cancelled.cancelled() => {}
                }
            }
        });
        let weak = Arc::downgrade(&self.inner);
        let close_session = Arc::clone(&session);
        let finish_state = Arc::clone(&body_state);
        let body = XhttpBody::channel(keepalive_rx, body_state).with_on_finish(move || {
            if finish_state.is_cancelled() && !close_session.fully_connected.load(Ordering::Acquire)
            {
                remove_session(&weak, &close_session);
                close_session.cancel("XHTTP stream-up response closed");
            }
        });
        response_with_headers(StatusCode::OK, headers, body)
    }

    async fn handle_hyper_packet_up(
        &self,
        request: Request<Incoming>,
        head: ValidatedHead,
        mut headers: HeaderMap,
    ) -> Response<XhttpBody> {
        if !matches!(self.inner.config.normalized_mode(), "auto" | "packet-up") {
            return error_response(
                RequestError::bad_request("packet-up mode is not allowed"),
                headers,
            );
        }
        let sequence = match head.sequence.parse::<u64>() {
            Ok(sequence) => sequence,
            Err(error) => {
                return error_response(
                    RequestError::bad_request(format!("invalid XHTTP sequence: {error}")),
                    headers,
                );
            }
        };
        let permit = match self
            .reserve_packet_body(&head.session_id, sequence, PACKET_BODY_TIMEOUT)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                return error_response(error, headers);
            }
        };
        let session_cancelled = self
            .find_session(&head.session_id)
            .map(|session| session.cancelled.clone());
        let request_headers = request.headers().clone();
        let payload = match decode_packet_payload(
            &self.inner.config,
            &request_headers,
            request.into_body(),
            self.inner.cancelled.clone(),
            session_cancelled,
        )
        .await
        {
            Ok(payload) => payload,
            Err(error) => return error_response(error, headers),
        };
        let payload = match permit.attach(payload) {
            Ok(payload) => payload,
            Err(error) => {
                return error_response(
                    RequestError::new(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()),
                    headers,
                );
            }
        };
        if let Err(error) = self.finish_packet_upload(&head.session_id, sequence, payload) {
            return error_response(error, headers);
        }
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response_with_headers(StatusCode::OK, headers, XhttpBody::empty())
    }

    async fn handle_hyper_downlink(
        &self,
        request: Request<Incoming>,
        head: ValidatedHead,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        version: XhttpVersion,
        headers: HeaderMap,
    ) -> Response<XhttpBody> {
        if head.session_id.is_empty() {
            let state = IoState::shared();
            let (reader, upload_sender) =
                ResponseReader::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
            let (writer, downlink_rx) =
                PipeWriter::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
            let close_state = Arc::clone(&state);
            let stream: BoxedStream =
                Box::pin(XConn::new(reader, writer).with_on_close(move || close_state.cancel()));
            let accepted = AcceptedXhttpStream {
                stream,
                peer_addr,
                local_addr,
                session_id: None,
                mode: "stream-one",
                version,
            };
            if let Err(error) = reserve_and_send_hyper_accepted(
                &self.inner.accepted,
                accepted,
                &state,
                self.inner.cancelled.clone(),
                None,
                self.inner.accept_delivery_timeout,
            )
            .await
            {
                state.cancel();
                return error_response(error, headers);
            }
            let pump_state = Arc::clone(&state);
            let allow_streaming_eof =
                matches!(request.version(), Version::HTTP_11 | Version::HTTP_2);
            tokio::spawn(async move {
                pump_hyper_body(
                    request.into_body(),
                    upload_sender,
                    pump_state,
                    allow_streaming_eof,
                )
                .await;
            });
            return response_with_headers(
                StatusCode::OK,
                headers,
                XhttpBody::channel(downlink_rx, state),
            );
        }

        let session = match self.upsert_session(&head.session_id) {
            Ok(session) => session,
            Err(error) => {
                return error_response(
                    RequestError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
                    headers,
                );
            }
        };
        let reader = match session.take_reader() {
            Ok(reader) => reader,
            Err(error) => {
                return error_response(
                    RequestError::new(StatusCode::CONFLICT, error.to_string()),
                    headers,
                );
            }
        };
        let state = Arc::clone(&session.io_state);
        let (writer, downlink_rx) = PipeWriter::channel(BODY_CHANNEL_CAPACITY, Arc::clone(&state));
        let weak = Arc::downgrade(&self.inner);
        let close_session = Arc::clone(&session);
        let stream: BoxedStream = Box::pin(XConn::new(reader, writer).with_on_close(move || {
            remove_session(&weak, &close_session);
            close_session.cancel("XHTTP logical stream closed");
        }));
        let accepted = AcceptedXhttpStream {
            stream,
            peer_addr,
            local_addr,
            session_id: Some(head.session_id),
            mode: self.accepted_session_mode(&session),
            version,
        };
        if let Err(error) = reserve_and_send_hyper_accepted(
            &self.inner.accepted,
            accepted,
            &state,
            self.inner.cancelled.clone(),
            Some(session.cancelled.clone()),
            self.inner.accept_delivery_timeout,
        )
        .await
        {
            remove_session(&Arc::downgrade(&self.inner), &session);
            session.cancel("XHTTP logical stream was not accepted");
            return error_response(error, headers);
        }
        session.mark_fully_connected();
        tokio::spawn(async move {
            let _ = read_hyper_body_limited(request.into_body(), 0).await;
        });
        let weak = Arc::downgrade(&self.inner);
        let close_session = Arc::clone(&session);
        let body = XhttpBody::channel(downlink_rx, state).with_on_finish(move || {
            remove_session(&weak, &close_session);
            if close_session.fully_connected.load(Ordering::Acquire) {
                close_session.close_clean();
            } else {
                close_session.cancel("XHTTP download response closed before session connected");
            }
        });
        response_with_headers(StatusCode::OK, headers, body)
    }
}
