//! Xray 26.7.11 Realm UDP rendezvous and NAT traversal.
//!
//! This is wire-compatible with `transport/internet/finalmask/realm`: STUN
//! discovery uses the carrier socket itself, the rendezvous control plane uses
//! `/v1/{realm}/connect`, symmetric-NAT ports are expanded with Xray's bounds,
//! and authenticated hello/ack packets use the exact SHA-256 XOR construction.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use core_config::RealmMaskConfig;
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    adapter::{BoxedUdp, UdpSocketLike, resolve_host},
    transport::{TlsOptions, Transport, tcp::TcpTransport, tls::TlsTransport},
};

const STUN_TIMEOUT: Duration = Duration::from_secs(4);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const MAX_PUNCH_PADDING: usize = 1024;
const PUNCH_SALT_LEN: usize = 8;
const PUNCH_HEADER_LEN: usize = 25;
const PUNCH_MIN_WIRE_LEN: usize = PUNCH_SALT_LEN + PUNCH_HEADER_LEN;
const PUNCH_MAX_WIRE_LEN: usize = PUNCH_MIN_WIRE_LEN + MAX_PUNCH_PADDING;
const MAX_CONTROL_BODY: usize = 1024 * 1024;
const STUN_MAGIC: u32 = 0x2112_a442;
const PUNCH_MAGIC: &[u8; 8] = b"HYRLMv1\0";

pub(super) async fn wrap_client(
    inner: BoxedUdp,
    config: &RealmMaskConfig,
    remote: Option<SocketAddr>,
) -> io::Result<BoxedUdp> {
    let parsed = ParsedRealm::parse(config)?;
    let family = remote.map(|address| address.ip());
    let stun_servers = resolve_stun_servers(&parsed.stun_servers, family).await?;
    if stun_servers.is_empty() {
        return Err(invalid(
            "realm resolved no STUN servers for the carrier family",
        ));
    }
    let locals = discover(&*inner, &stun_servers).await?;
    if locals.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "realm STUN discovery returned no mapped addresses",
        ));
    }

    let metadata = PunchMetadata::random();
    let response = RealmHttpClient::new(&parsed)
        .connect(
            &parsed.realm_id,
            &parsed.token,
            ConnectRequest {
                addresses: address_strings(&locals),
                metadata: metadata.clone(),
            },
        )
        .await?;
    let peers = parse_addresses(&response.addresses);
    let (candidates, mut seen) = candidate_punch_addresses(&locals, &peers);
    let candidates = expand_symmetric_nat_candidates(candidates, &mut seen);
    if candidates.is_empty() {
        return Err(invalid(
            "realm rendezvous returned no usable peer addresses",
        ));
    }
    let peer = punch(&*inner, &metadata, &candidates).await?;
    tracing::debug!(%peer, realm_id = %parsed.realm_id, "realm UDP peer established");
    Ok(Box::new(RealmClient { inner, peer }))
}

/// Build the long-lived server side. It registers the discovered addresses,
/// maintains heartbeat/SSE state, answers connect events and filters STUN and
/// punch control packets out of the QUIC data stream.
pub(super) async fn wrap_server(inner: BoxedUdp, config: &RealmMaskConfig) -> io::Result<BoxedUdp> {
    let parsed = Arc::new(ParsedRealm::parse(config)?);
    let inner: Arc<dyn UdpSocketLike> = Arc::from(inner);
    let closed = Arc::new(AtomicBool::new(false));
    let (data_tx, data_rx) = tokio::sync::mpsc::channel(1024);
    let (stun_tx, stun_rx) = tokio::sync::mpsc::channel(16);
    let punch_events = Arc::new(Mutex::new(HashMap::new()));
    let dispatcher = tokio::spawn(dispatch_server_packets(
        inner.clone(),
        data_tx,
        stun_tx,
        punch_events.clone(),
        closed.clone(),
    ));
    let control = tokio::spawn(run_server_control(
        parsed,
        inner.clone(),
        stun_rx,
        punch_events,
        closed.clone(),
    ));
    Ok(Box::new(RealmServer {
        inner,
        data: Mutex::new(data_rx),
        closed,
        tasks: Mutex::new(vec![dispatcher, control]),
    }))
}

struct ReceivedData {
    bytes: Vec<u8>,
    source: Option<SocketAddr>,
}

#[derive(Debug)]
struct StunEvent {
    transaction: [u8; 12],
    mapped: SocketAddr,
}

#[derive(Debug)]
struct PunchPacketEvent {
    source: SocketAddr,
    kind: PunchType,
}

type PunchRoutes = Arc<Mutex<HashMap<PunchMetadata, tokio::sync::mpsc::Sender<PunchPacketEvent>>>>;

struct RealmServer {
    inner: Arc<dyn UdpSocketLike>,
    data: Mutex<tokio::sync::mpsc::Receiver<io::Result<ReceivedData>>>,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

#[async_trait]
impl UdpSocketLike for RealmServer {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        self.inner.send_to(payload, target, port).await
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
        let packet = self
            .data
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)??;
        if packet.bytes.len() > output.len() {
            return Err(invalid(format!(
                "realm server datagram is {} bytes, buffer is {}",
                packet.bytes.len(),
                output.len()
            )));
        }
        output[..packet.bytes.len()].copy_from_slice(&packet.bytes);
        Ok((packet.bytes.len(), packet.source))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    async fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _ = self.inner.close().await;
        for mut task in self.tasks.lock().await.drain(..) {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
        Ok(())
    }
}

async fn dispatch_server_packets(
    inner: Arc<dyn UdpSocketLike>,
    data: tokio::sync::mpsc::Sender<io::Result<ReceivedData>>,
    stun: tokio::sync::mpsc::Sender<StunEvent>,
    punch_routes: PunchRoutes,
    closed: Arc<AtomicBool>,
) {
    let mut buffer = vec![0; 4096];
    while !closed.load(Ordering::Acquire) {
        let received = tokio::select! {
            value = inner.recv_from_endpoint(&mut buffer) => value,
            () = wait_until_closed(closed.clone()) => return,
        };
        let (length, source) = match received {
            Ok(value) => value,
            Err(error) => {
                let _ = data.send(Err(error)).await;
                return;
            }
        };
        let packet = &buffer[..length];
        if let Ok((transaction, mapped)) = parse_stun_binding_response(packet) {
            let _ = stun.try_send(StunEvent {
                transaction,
                mapped,
            });
            continue;
        }
        if let Some(source) = source {
            let routes = punch_routes.lock().await;
            let mut consumed = false;
            for (metadata, route) in routes.iter() {
                if let Ok(kind) = decode_punch(packet, metadata) {
                    let _ = route.try_send(PunchPacketEvent { source, kind });
                    consumed = true;
                    break;
                }
            }
            drop(routes);
            if consumed {
                continue;
            }
        }
        if data
            .send(Ok(ReceivedData {
                bytes: packet.to_vec(),
                source,
            }))
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn run_server_control(
    config: Arc<ParsedRealm>,
    inner: Arc<dyn UdpSocketLike>,
    mut stun: tokio::sync::mpsc::Receiver<StunEvent>,
    punch_routes: PunchRoutes,
    closed: Arc<AtomicBool>,
) {
    let http = RealmHttpClient::new(&config);
    let mut backoff = Duration::from_secs(1);
    while !closed.load(Ordering::Acquire) {
        let family = inner.local_addr().ok().flatten().map(|addr| addr.ip());
        let servers = match resolve_stun_servers(&config.stun_servers, family).await {
            Ok(servers) => servers,
            Err(error) => {
                tracing::debug!(%error, "realm server STUN resolution failed");
                if wait_or_closed(backoff, closed.clone()).await {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        let locals = match discover_dispatched(&*inner, &servers, &mut stun).await {
            Ok(locals) if !locals.is_empty() => locals,
            Ok(_) => {
                tracing::debug!("realm server STUN discovery returned no addresses");
                if wait_or_closed(backoff, closed.clone()).await {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
            Err(error) => {
                tracing::debug!(%error, "realm server STUN discovery failed");
                if wait_or_closed(backoff, closed.clone()).await {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        let register = match http
            .register(&config.realm_id, &config.token, address_strings(&locals))
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%error, "realm server registration failed");
                if wait_or_closed(backoff, closed.clone()).await {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_secs(1);
        tracing::debug!(
            realm_id = %config.realm_id,
            session_id = %register.session_id,
            ttl = register.ttl,
            "realm server registered"
        );
        let session_lost = run_registered_session(
            &config,
            &http,
            &inner,
            &mut stun,
            &punch_routes,
            locals,
            &register,
            closed.clone(),
        )
        .await;
        if closed.load(Ordering::Acquire) {
            let _ = http
                .deregister(&config.realm_id, &register.session_id)
                .await;
            return;
        }
        if let Err(error) = session_lost {
            tracing::debug!(%error, "realm server session ended; registering again");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_registered_session(
    config: &ParsedRealm,
    http: &RealmHttpClient,
    inner: &Arc<dyn UdpSocketLike>,
    stun: &mut tokio::sync::mpsc::Receiver<StunEvent>,
    punch_routes: &PunchRoutes,
    mut locals: Vec<SocketAddr>,
    register: &RegisterResponse,
    closed: Arc<AtomicBool>,
) -> io::Result<()> {
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
    let mut events_task = tokio::spawn(stream_events_loop(
        http.clone(),
        config.realm_id.clone(),
        register.session_id.clone(),
        Duration::from_secs(register.ttl.max(0) as u64),
        event_tx,
        closed.clone(),
    ));
    let mut ttl = register.ttl;
    let heartbeat_seconds = heartbeat_interval(ttl).as_secs();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(heartbeat_seconds));
    let mut last_heartbeat = Instant::now();
    heartbeat.tick().await;
    loop {
        tokio::select! {
            () = wait_until_closed(closed.clone()) => {
                events_task.abort();
                return Ok(());
            }
            _ = heartbeat.tick() => {
                let family = inner.local_addr().ok().flatten().map(|addr| addr.ip());
                let discovered = match resolve_stun_servers(&config.stun_servers, family).await {
                    Ok(servers) => match discover_dispatched(&**inner, &servers, stun).await {
                        Ok(discovered) => discovered,
                        Err(error) => {
                            // Xray heartbeats use the last cached STUN result. A
                            // transient refresh failure must not discard a live
                            // control-plane session.
                            tracing::debug!(%error, "realm heartbeat STUN discovery failed; retaining cached addresses");
                            Vec::new()
                        }
                    },
                    Err(error) => {
                        tracing::debug!(%error, "realm heartbeat STUN resolution failed; retaining cached addresses");
                        Vec::new()
                    }
                };
                let changed = !discovered.is_empty() && discovered != locals;
                if changed {
                    locals = discovered;
                }
                let started = Instant::now();
                match http.heartbeat(
                    &config.realm_id,
                    &register.session_id,
                    changed.then(|| address_strings(&locals)),
                ).await {
                    Ok(response) => {
                        last_heartbeat = started;
                        if response.ttl > 0 && response.ttl != ttl {
                            ttl = response.ttl;
                            heartbeat.reset_after(heartbeat_interval(ttl));
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        events_task.abort();
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("realm session is invalid: {error}")));
                    }
                    Err(error) if session_expired(last_heartbeat, ttl) => {
                        events_task.abort();
                        return Err(io::Error::new(io::ErrorKind::TimedOut, format!("realm heartbeat session expired after transient errors: {error}")));
                    }
                    Err(error) => {
                        tracing::debug!(%error, "realm heartbeat failed within TTL; retaining session");
                    }
                }
            }
            result = &mut events_task => {
                return result
                    .map_err(|error| io::Error::other(format!("realm SSE task: {error}")))?;
            }
            Some(event) = event_rx.recv() => {
                let http = http.clone();
                let realm_id = config.realm_id.clone();
                let session_id = register.session_id.clone();
                let inner = inner.clone();
                let routes = punch_routes.clone();
                let locals = locals.clone();
                let closed = closed.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_punch_event(
                        http, realm_id, session_id, inner, routes, locals, event, closed,
                    ).await {
                        tracing::debug!(%error, "realm punch event failed");
                    }
                });
            }
        }
    }
}

async fn stream_events_loop(
    http: RealmHttpClient,
    realm_id: String,
    session_id: String,
    ttl: Duration,
    output: tokio::sync::mpsc::Sender<PunchEvent>,
    closed: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut backoff = Duration::from_secs(1);
    let mut last_open = Instant::now();
    while !closed.load(Ordering::Acquire) {
        let started = Instant::now();
        match http.events(&realm_id, &session_id).await {
            Ok(body) => {
                backoff = Duration::from_secs(1);
                last_open = started;
                match consume_sse(body, &output, closed.clone()).await {
                    Ok(()) => return Ok(()),
                    Err(error) => tracing::debug!(%error, "realm SSE stream interrupted"),
                }
                // Xray immediately reopens a stream that ended after a
                // successful response; exponential backoff is only for open
                // failures.
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("realm event session is invalid: {error}"),
                ));
            }
            Err(error) if last_open.elapsed() > ttl => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("realm event session expired after transient errors: {error}"),
                ));
            }
            Err(error) => tracing::debug!(%error, "realm SSE open failed within TTL"),
        }
        if wait_or_closed(backoff, closed.clone()).await {
            return Ok(());
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
    Ok(())
}

fn heartbeat_interval(ttl: i64) -> Duration {
    if ttl > 0 {
        Duration::from_secs((ttl / 2).max(1) as u64)
    } else {
        Duration::from_secs(15)
    }
}

fn session_expired(last_success: Instant, ttl: i64) -> bool {
    last_success.elapsed() > Duration::from_secs(ttl.max(0) as u64)
}

async fn consume_sse(
    mut body: Incoming,
    output: &tokio::sync::mpsc::Sender<PunchEvent>,
    closed: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut pending = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(http_error)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        pending.extend_from_slice(&data);
        if pending.len() > MAX_CONTROL_BODY {
            return Err(invalid("realm SSE event exceeds size limit"));
        }
        while let Some(end) = sse_event_end(&pending) {
            let block = pending.drain(..end).collect::<Vec<_>>();
            while pending
                .first()
                .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
            {
                pending.remove(0);
            }
            if let Some(event) = parse_sse_event(&block)?
                && output.send(event).await.is_err()
            {
                return Ok(());
            }
        }
        if closed.load(Ordering::Acquire) {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "realm SSE response ended",
    ))
}

fn sse_event_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| index + 2)
        .or_else(|| {
            bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
        })
}

fn parse_sse_event(block: &[u8]) -> io::Result<Option<PunchEvent>> {
    let text = std::str::from_utf8(block).map_err(|_| invalid("realm SSE is not UTF-8"))?;
    let mut event_name = "";
    let mut data = String::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event_name = value,
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
            }
            _ => {}
        }
    }
    if event_name != "punch" {
        return Ok(None);
    }
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|error| invalid(format!("invalid realm punch SSE event: {error}")))
}

#[allow(clippy::too_many_arguments)]
async fn handle_punch_event(
    http: RealmHttpClient,
    realm_id: String,
    session_id: String,
    inner: Arc<dyn UdpSocketLike>,
    routes: PunchRoutes,
    locals: Vec<SocketAddr>,
    event: PunchEvent,
    closed: Arc<AtomicBool>,
) -> io::Result<()> {
    let peers = parse_addresses(&event.addresses);
    let (candidates, mut seen) = candidate_punch_addresses(&locals, &peers);
    let candidates = expand_symmetric_nat_candidates(candidates, &mut seen);
    if candidates.is_empty() {
        return Err(invalid("realm punch event has no usable peers"));
    }
    http.connect_response(
        &realm_id,
        &session_id,
        &event.metadata.nonce,
        address_strings(&locals),
    )
    .await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    {
        let mut routes = routes.lock().await;
        if routes.len() >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many concurrent realm punch events",
            ));
        }
        if routes.insert(event.metadata.clone(), tx).is_some() {
            return Err(invalid("duplicate realm punch nonce"));
        }
    }
    let result = punch_server(&*inner, &event.metadata, &candidates, &mut rx, closed).await;
    routes.lock().await.remove(&event.metadata);
    result
}

async fn punch_server(
    socket: &dyn UdpSocketLike,
    metadata: &PunchMetadata,
    peers: &[SocketAddr],
    events: &mut tokio::sync::mpsc::Receiver<PunchPacketEvent>,
    closed: Arc<AtomicBool>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + PUNCH_TIMEOUT;
    let mut ticker = tokio::time::interval(PUNCH_INTERVAL);
    loop {
        tokio::select! {
            () = wait_until_closed(closed.clone()) => return Ok(()),
            _ = tokio::time::sleep_until(deadline) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "realm server punch timed out"));
            }
            _ = ticker.tick() => {
                for peer in peers {
                    let hello = encode_punch(PunchType::Hello, metadata)?;
                    let _ = socket.send_to(&hello, &peer.ip().to_string(), peer.port()).await;
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                };
                if event.kind == PunchType::Hello {
                    let ack = encode_punch(PunchType::Ack, metadata)?;
                    socket.send_to(&ack, &event.source.ip().to_string(), event.source.port()).await?;
                }
                return Ok(());
            }
        }
    }
}

async fn discover_dispatched(
    socket: &dyn UdpSocketLike,
    servers: &[SocketAddr],
    events: &mut tokio::sync::mpsc::Receiver<StunEvent>,
) -> io::Result<Vec<SocketAddr>> {
    let mut outstanding = HashSet::new();
    for server in servers {
        let (request, transaction) = stun_binding_request();
        outstanding.insert(transaction);
        socket
            .send_to(&request, &server.ip().to_string(), server.port())
            .await?;
    }
    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    let mut results = Vec::new();
    while !outstanding.is_empty() {
        let received = tokio::time::timeout_at(deadline, events.recv()).await;
        let Ok(Some(event)) = received else {
            break;
        };
        if outstanding.remove(&event.transaction) {
            results.push(event.mapped);
        }
    }
    results.sort_by_key(ToString::to_string);
    results.dedup();
    Ok(results)
}

async fn wait_until_closed(closed: Arc<AtomicBool>) {
    while !closed.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_or_closed(duration: Duration, closed: Arc<AtomicBool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        () = wait_until_closed(closed) => true,
    }
}

struct RealmClient {
    inner: BoxedUdp,
    peer: SocketAddr,
}

#[async_trait]
impl UdpSocketLike for RealmClient {
    async fn send_to(&self, payload: &[u8], _target: &str, _port: u16) -> io::Result<usize> {
        self.inner
            .send_to(payload, &self.peer.ip().to_string(), self.peer.port())
            .await
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.recv_from(output).await
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        self.inner.recv_from_endpoint(output).await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[derive(Debug)]
struct ParsedRealm {
    scheme: &'static str,
    host: String,
    port: u16,
    token: String,
    realm_id: String,
    stun_servers: Vec<String>,
    tls: TlsOptions,
}

impl ParsedRealm {
    fn parse(config: &RealmMaskConfig) -> io::Result<Self> {
        let url = url::Url::parse(&config.url)
            .map_err(|error| invalid(format!("invalid realm URL: {error}")))?;
        let (scheme, default_port) = match url.scheme() {
            "realm" => ("https", 443),
            "realm+http" => ("http", 80),
            scheme => return Err(invalid(format!("invalid realm URL scheme `{scheme}`"))),
        };
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| invalid("realm URL has no host"))?
            .to_string();
        let port = url.port().unwrap_or(default_port);
        let mut token = percent_decode_str(url.username())
            .decode_utf8()
            .map_err(|_| invalid("realm token is not UTF-8"))?
            .into_owned();
        if let Some(password) = url.password() {
            token.push(':');
            token.push_str(
                &percent_decode_str(password)
                    .decode_utf8()
                    .map_err(|_| invalid("realm token password is not UTF-8"))?,
            );
        }
        if token.is_empty() {
            return Err(invalid("realm URL has an empty token"));
        }
        let realm_id = percent_decode_str(url.path().trim_start_matches('/'))
            .decode_utf8()
            .map_err(|_| invalid("realm ID is not UTF-8"))?
            .into_owned();
        if realm_id.is_empty() {
            return Err(invalid("realm URL has an empty ID"));
        }
        if config.stun_servers.is_empty() {
            return Err(invalid("realm stunServers is empty"));
        }

        let tls = if scheme == "https" {
            let mut settings = config.tls_config.clone().unwrap_or_default();
            if settings
                .server_name
                .as_deref()
                .is_none_or(|server_name| server_name.is_empty())
            {
                settings.server_name = Some(host.clone());
            }
            if settings.alpn.as_ref().is_none_or(Vec::is_empty) {
                settings.alpn = Some(vec!["h2".into(), "http/1.1".into()]);
            }
            TlsOptions::from_xray_settings(settings).map_err(|error| {
                io::Error::new(error.kind(), format!("invalid realm tlsConfig: {error}"))
            })?
        } else {
            if config.tls_config.is_some() {
                return Err(invalid(
                    "realm tlsConfig is invalid with realm+http because no TLS transport executes it",
                ));
            }
            TlsOptions::default()
        };
        Ok(Self {
            scheme,
            host,
            port,
            token,
            realm_id,
            stun_servers: config.stun_servers.clone(),
            tls,
        })
    }
}

#[derive(Clone)]
struct RealmHttpClient {
    scheme: &'static str,
    host: String,
    port: u16,
    tls: TlsOptions,
}

impl RealmHttpClient {
    fn new(config: &ParsedRealm) -> Self {
        Self {
            scheme: config.scheme,
            host: config.host.clone(),
            port: config.port,
            tls: config.tls.clone(),
        }
    }

    async fn connect(
        &self,
        realm_id: &str,
        token: &str,
        request: ConnectRequest,
    ) -> io::Result<ConnectResponse> {
        self.json(
            Method::POST,
            realm_id,
            "connect",
            token,
            Some(&request),
            StatusCode::OK,
        )
        .await
    }

    async fn register(
        &self,
        realm_id: &str,
        token: &str,
        addresses: Vec<String>,
    ) -> io::Result<RegisterResponse> {
        self.json(
            Method::POST,
            realm_id,
            "",
            token,
            Some(&AddressRequest { addresses }),
            StatusCode::OK,
        )
        .await
    }

    async fn heartbeat(
        &self,
        realm_id: &str,
        session_id: &str,
        addresses: Option<Vec<String>>,
    ) -> io::Result<HeartbeatResponse> {
        self.json(
            Method::POST,
            realm_id,
            "heartbeat",
            session_id,
            Some(&HeartbeatRequest { addresses }),
            StatusCode::OK,
        )
        .await
    }

    async fn connect_response(
        &self,
        realm_id: &str,
        session_id: &str,
        nonce: &str,
        addresses: Vec<String>,
    ) -> io::Result<()> {
        self.empty(
            Method::POST,
            realm_id,
            &format!("connects/{}", utf8_percent_encode(nonce, NON_ALPHANUMERIC)),
            session_id,
            Some(&AddressRequest { addresses }),
            StatusCode::NO_CONTENT,
        )
        .await
    }

    async fn deregister(&self, realm_id: &str, session_id: &str) -> io::Result<()> {
        self.empty::<serde_json::Value>(
            Method::DELETE,
            realm_id,
            "",
            session_id,
            None,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    async fn events(&self, realm_id: &str, session_id: &str) -> io::Result<Incoming> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(self.uri(&realm_path(realm_id, "events"))?)
            .header("authorization", format!("Bearer {session_id}"))
            .header("accept", "text/event-stream")
            .body(Full::new(Bytes::new()))
            .map_err(|error| invalid(format!("realm events request: {error}")))?;
        let response = self.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(realm_status_error(
                response.status(),
                ErrorResponse::default(),
            ));
        }
        Ok(response.into_body())
    }

    #[allow(clippy::too_many_arguments)]
    async fn empty<I: Serialize + ?Sized>(
        &self,
        method: Method,
        realm_id: &str,
        subpath: &str,
        token: &str,
        input: Option<&I>,
        expected: StatusCode,
    ) -> io::Result<()> {
        let body = input
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| invalid(format!("realm JSON encode: {error}")))?
            .unwrap_or_default();
        let mut builder = Request::builder()
            .method(method)
            .uri(self.uri(&realm_path(realm_id, subpath))?);
        if !token.is_empty() {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if input.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let response = self
            .send(
                builder
                    .body(Full::new(Bytes::from(body)))
                    .map_err(|error| invalid(format!("realm HTTP request: {error}")))?,
            )
            .await?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_CONTROL_BODY)
            .collect()
            .await
            .map_err(|error| invalid(format!("realm HTTP response body: {error}")))?
            .to_bytes();
        if status != expected {
            let details = serde_json::from_slice::<ErrorResponse>(&body).unwrap_or_default();
            return Err(realm_status_error(status, details));
        }
        Ok(())
    }

    async fn json<I: Serialize + ?Sized, O: DeserializeOwned>(
        &self,
        method: Method,
        realm_id: &str,
        subpath: &str,
        token: &str,
        input: Option<&I>,
        expected: StatusCode,
    ) -> io::Result<O> {
        let path = realm_path(realm_id, subpath);
        let body = input
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| invalid(format!("realm JSON encode: {error}")))?
            .unwrap_or_default();
        let mut builder = Request::builder().method(method).uri(self.uri(&path)?);
        if !token.is_empty() {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if input.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| invalid(format!("realm HTTP request: {error}")))?;
        let response = self.send(request).await?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_CONTROL_BODY)
            .collect()
            .await
            .map_err(|error| invalid(format!("realm HTTP response body: {error}")))?
            .to_bytes();
        if status != expected {
            let details = serde_json::from_slice::<ErrorResponse>(&body).unwrap_or_default();
            return Err(realm_status_error(status, details));
        }
        serde_json::from_slice(&body)
            .map_err(|error| invalid(format!("realm JSON response: {error}")))
    }

    fn uri(&self, path: &str) -> io::Result<Uri> {
        let authority = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        format!("{}://{}{}", self.scheme, authority, path)
            .parse()
            .map_err(|error| invalid(format!("realm HTTP URI: {error}")))
    }

    async fn send(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> io::Result<http::Response<Incoming>> {
        let (stream, alpn) = crate::socket_policy::without_finalmask(async {
            if self.scheme == "https" {
                TlsTransport::new(self.tls.clone())
                    .connect_negotiated(&self.host, self.port)
                    .await
            } else {
                TcpTransport::default()
                    .connect(&self.host, self.port)
                    .await
                    .map(|stream| (stream, None))
            }
        })
        .await?;
        let io = TokioIo::new(stream);
        if alpn.as_deref() == Some(b"h2") {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
                    TokioExecutor::new(),
                    io,
                )
                .await
                .map_err(http_error)?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, "realm HTTP/2 connection ended");
                }
            });
            sender.send_request(request).await.map_err(http_error)
        } else {
            prepare_http1_request(&mut request)?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
                    .await
                    .map_err(http_error)?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, "realm HTTP/1.1 connection ended");
                }
            });
            sender.send_request(request).await.map_err(http_error)
        }
    }
}

fn prepare_http1_request(request: &mut Request<Full<Bytes>>) -> io::Result<()> {
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| invalid("realm HTTP/1.1 URI has no authority"))?
        .as_str()
        .to_string();
    if !request.headers().contains_key(http::header::HOST) {
        request.headers_mut().insert(
            http::header::HOST,
            authority
                .parse()
                .map_err(|error| invalid(format!("realm HTTP Host header: {error}")))?,
        );
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .parse::<Uri>()
        .map_err(|error| invalid(format!("realm HTTP origin-form URI: {error}")))?;
    *request.uri_mut() = path;
    Ok(())
}

fn realm_status_error(status: StatusCode, details: ErrorResponse) -> io::Error {
    // Xray only invalidates the registration immediately for 401/404. Other
    // HTTP failures are transient and are tolerated until the advertised TTL.
    let kind = if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND) {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(
        kind,
        format!(
            "realm server returned {status}: {}: {}",
            details.error, details.message
        ),
    )
}

fn realm_path(realm_id: &str, subpath: &str) -> String {
    let realm_id = utf8_percent_encode(realm_id.trim_matches('/'), NON_ALPHANUMERIC);
    if subpath.trim_matches('/').is_empty() {
        format!("/v1/{realm_id}")
    } else {
        format!("/v1/{realm_id}/{}", subpath.trim_matches('/'))
    }
}

fn http_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct PunchMetadata {
    nonce: String,
    obfs: String,
}

impl PunchMetadata {
    fn random() -> Self {
        let mut nonce = [0; 16];
        let mut obfs = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        rand::rngs::OsRng.fill_bytes(&mut obfs);
        Self {
            nonce: hex::encode(nonce),
            obfs: hex::encode(obfs),
        }
    }
}

#[derive(Serialize)]
struct ConnectRequest {
    addresses: Vec<String>,
    #[serde(flatten)]
    metadata: PunchMetadata,
}

#[derive(Deserialize)]
struct ConnectResponse {
    addresses: Vec<String>,
    #[allow(dead_code)]
    nonce: String,
    #[allow(dead_code)]
    obfs: String,
}

#[derive(Serialize)]
struct AddressRequest {
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct HeartbeatRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RegisterResponse {
    session_id: String,
    ttl: i64,
}

#[derive(Deserialize)]
struct HeartbeatResponse {
    ttl: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct PunchEvent {
    addresses: Vec<String>,
    #[serde(flatten)]
    metadata: PunchMetadata,
}

#[derive(Default, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

async fn resolve_stun_servers(
    servers: &[String],
    carrier_family: Option<IpAddr>,
) -> io::Result<Vec<SocketAddr>> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for server in servers {
        let (host, port) = parse_host_port(server)?;
        let addresses = resolve_host(&host, port).await?;
        if let Some(address) = addresses.into_iter().find(|address| {
            carrier_family.is_none_or(|family| family.is_ipv4() == address.is_ipv4())
        }) && seen.insert(address)
        {
            output.push(address);
        }
    }
    Ok(output)
}

fn parse_host_port(input: &str) -> io::Result<(String, u16)> {
    let url = url::Url::parse(&format!("udp://{input}"))
        .map_err(|error| invalid(format!("invalid STUN server `{input}`: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid(format!("invalid STUN host `{input}`")))?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| invalid(format!("STUN server `{input}` has no port")))?;
    Ok((host, port))
}

async fn discover(
    socket: &dyn UdpSocketLike,
    servers: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    let mut outstanding = HashSet::new();
    for server in servers {
        let (request, transaction) = stun_binding_request();
        outstanding.insert(transaction);
        socket
            .send_to(&request, &server.ip().to_string(), server.port())
            .await?;
    }
    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    let mut buffer = [0; 1500];
    let mut results = Vec::new();
    while !outstanding.is_empty() {
        let received =
            tokio::time::timeout_at(deadline, socket.recv_from_endpoint(&mut buffer)).await;
        let Ok(Ok((length, _))) = received else {
            break;
        };
        if let Ok((transaction, mapped)) = parse_stun_binding_response(&buffer[..length])
            && outstanding.remove(&transaction)
        {
            results.push(mapped);
        }
    }
    results.sort_by_key(ToString::to_string);
    results.dedup();
    Ok(results)
}

fn stun_binding_request() -> (Vec<u8>, [u8; 12]) {
    let mut transaction = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut transaction);
    let mut packet = vec![0; 20];
    packet[..2].copy_from_slice(&1_u16.to_be_bytes());
    packet[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    packet[8..20].copy_from_slice(&transaction);
    (packet, transaction)
}

fn parse_stun_binding_response(packet: &[u8]) -> io::Result<([u8; 12], SocketAddr)> {
    if packet.len() < 20
        || u16::from_be_bytes([packet[0], packet[1]]) != 0x0101
        || u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != STUN_MAGIC
    {
        return Err(invalid("not a STUN binding success response"));
    }
    let body_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if packet.len() < 20 + body_length {
        return Err(invalid("truncated STUN response"));
    }
    let mut transaction = [0; 12];
    transaction.copy_from_slice(&packet[8..20]);
    let mut offset = 20;
    let end = 20 + body_length;
    let mut mapped = None;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset += 4;
        if offset + length > end {
            return Err(invalid("truncated STUN attribute"));
        }
        if kind == 0x0020 || (kind == 0x0001 && mapped.is_none()) {
            mapped = Some(parse_stun_address(
                &packet[offset..offset + length],
                kind == 0x0020,
                &transaction,
            )?);
            if kind == 0x0020 {
                break;
            }
        }
        offset += (length + 3) & !3;
    }
    mapped
        .map(|address| (transaction, address))
        .ok_or_else(|| invalid("STUN mapped address is absent"))
}

fn parse_stun_address(value: &[u8], xor: bool, transaction: &[u8; 12]) -> io::Result<SocketAddr> {
    if value.len() < 8 {
        return Err(invalid("truncated STUN address"));
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (STUN_MAGIC >> 16) as u16;
    }
    let ip = match value[1] {
        1 if value.len() >= 8 => {
            let mut octets = [0; 4];
            octets.copy_from_slice(&value[4..8]);
            if xor {
                for (byte, mask) in octets.iter_mut().zip(STUN_MAGIC.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            IpAddr::from(octets)
        }
        2 if value.len() >= 20 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                let mut mask = [0; 16];
                mask[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
                mask[4..].copy_from_slice(transaction);
                for (byte, mask) in octets.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            IpAddr::from(octets)
        }
        _ => return Err(invalid("invalid STUN address family")),
    };
    if port == 0 {
        return Err(invalid("invalid zero STUN mapped port"));
    }
    Ok(SocketAddr::new(ip, port))
}

async fn punch(
    socket: &dyn UdpSocketLike,
    metadata: &PunchMetadata,
    peers: &[SocketAddr],
) -> io::Result<SocketAddr> {
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut next_send = Instant::now();
    let mut buffer = vec![0; PUNCH_MAX_WIRE_LEN];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "realm punch timed out",
            ));
        }
        if now >= next_send {
            for peer in peers {
                let packet = encode_punch(PunchType::Hello, metadata)?;
                let _ = socket
                    .send_to(&packet, &peer.ip().to_string(), peer.port())
                    .await;
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let until = next_send
            .min(deadline)
            .saturating_duration_since(Instant::now());
        let received = tokio::time::timeout(until, socket.recv_from_endpoint(&mut buffer)).await;
        let Ok(Ok((length, Some(source)))) = received else {
            continue;
        };
        let Ok(packet_type) = decode_punch(&buffer[..length], metadata) else {
            continue;
        };
        if packet_type == PunchType::Hello {
            let ack = encode_punch(PunchType::Ack, metadata)?;
            socket
                .send_to(&ack, &source.ip().to_string(), source.port())
                .await?;
        }
        return Ok(source);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchType {
    Hello = 1,
    Ack = 2,
}

fn encode_punch(kind: PunchType, metadata: &PunchMetadata) -> io::Result<Vec<u8>> {
    let (nonce, obfs) = decode_metadata(metadata)?;
    let padding = rand::thread_rng().gen_range(0..=MAX_PUNCH_PADDING);
    let mut plain = vec![0; PUNCH_HEADER_LEN + padding];
    plain[..8].copy_from_slice(PUNCH_MAGIC);
    plain[8] = kind as u8;
    plain[9..25].copy_from_slice(&nonce);
    rand::rngs::OsRng.fill_bytes(&mut plain[PUNCH_HEADER_LEN..]);
    let mut packet = vec![0; PUNCH_SALT_LEN + plain.len()];
    rand::rngs::OsRng.fill_bytes(&mut packet[..PUNCH_SALT_LEN]);
    packet[PUNCH_SALT_LEN..].copy_from_slice(&plain);
    let (salt, encrypted) = packet.split_at_mut(PUNCH_SALT_LEN);
    xor_punch(encrypted, &obfs, salt);
    Ok(packet)
}

fn decode_punch(packet: &[u8], metadata: &PunchMetadata) -> io::Result<PunchType> {
    if !(PUNCH_MIN_WIRE_LEN..=PUNCH_MAX_WIRE_LEN).contains(&packet.len()) {
        return Err(invalid("invalid realm punch packet length"));
    }
    let (nonce, obfs) = decode_metadata(metadata)?;
    let mut plain = packet[PUNCH_SALT_LEN..].to_vec();
    xor_punch(&mut plain, &obfs, &packet[..PUNCH_SALT_LEN]);
    if &plain[..8] != PUNCH_MAGIC || plain[9..25] != nonce {
        return Err(invalid("realm punch authentication failed"));
    }
    match plain[8] {
        1 => Ok(PunchType::Hello),
        2 => Ok(PunchType::Ack),
        _ => Err(invalid("unknown realm punch packet type")),
    }
}

fn decode_metadata(metadata: &PunchMetadata) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let nonce = hex::decode(&metadata.nonce).map_err(|_| invalid("invalid realm punch nonce"))?;
    let obfs = hex::decode(&metadata.obfs).map_err(|_| invalid("invalid realm punch key"))?;
    if nonce.len() != 16 || obfs.len() != 32 {
        return Err(invalid("invalid realm punch metadata length"));
    }
    Ok((nonce, obfs))
}

fn xor_punch(packet: &mut [u8], key: &[u8], salt: &[u8]) {
    let mask = Sha256::new()
        .chain_update(key)
        .chain_update(salt)
        .finalize();
    for (index, byte) in packet.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
}

fn parse_addresses(addresses: &[String]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn address_strings(addresses: &[SocketAddr]) -> Vec<String> {
    addresses.iter().map(ToString::to_string).collect()
}

fn candidate_punch_addresses(
    locals: &[SocketAddr],
    peers: &[SocketAddr],
) -> (Vec<SocketAddr>, HashSet<SocketAddr>) {
    let allow4 = locals.iter().any(SocketAddr::is_ipv4);
    let allow6 = locals.iter().any(SocketAddr::is_ipv6);
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for peer in peers.iter().copied() {
        if ((peer.is_ipv4() && allow4) || (peer.is_ipv6() && allow6)) && seen.insert(peer) {
            candidates.push(peer);
        }
    }
    (candidates, seen)
}

fn expand_symmetric_nat_candidates(
    mut candidates: Vec<SocketAddr>,
    seen: &mut HashSet<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for candidate in &candidates {
        if candidate.is_ipv4() {
            ports_by_ip
                .entry(candidate.ip())
                .or_default()
                .push(candidate.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|pair| pair[1] - pair[0] > 4) {
            continue;
        }
        let end = u32::from(*ports.last().unwrap())
            .saturating_add(4)
            .min(u32::from(u16::MAX));
        let mut added = 0;
        for port in u32::from(ports[0])..=end {
            let candidate = SocketAddr::new(ip, port as u16);
            if seen.insert(candidate) {
                candidates.push(candidate);
                added += 1;
                if added == 32 {
                    break;
                }
            }
        }
    }
    candidates.sort_by_key(ToString::to_string);
    candidates
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn parses_official_realm_url_shape() {
        let parsed = ParsedRealm::parse(&RealmMaskConfig {
            url: "realm://token%3Asecret@example.com:8443/a%2Fb".into(),
            stun_servers: vec!["stun.example:3478".into()],
            tls_config: None,
        })
        .unwrap();
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.token, "token:secret");
        assert_eq!(parsed.realm_id, "a/b");
        assert_eq!(parsed.port, 8443);
        assert_eq!(realm_path(&parsed.realm_id, ""), "/v1/a%2Fb");
        assert_eq!(realm_path(&parsed.realm_id, "connect"), "/v1/a%2Fb/connect");

        // Go's url.Userinfo.String() keeps the username/password separator,
        // then Xray applies PathUnescape to the complete value.  The URL crate
        // exposes the two components separately, so both spellings need to
        // reconstruct the exact same bearer token.
        let separated = ParsedRealm::parse(&RealmMaskConfig {
            url: "realm://token:secret@example.com/a%2Fb".into(),
            stun_servers: vec!["stun.example:3478".into()],
            tls_config: None,
        })
        .unwrap();
        assert_eq!(separated.token, parsed.token);
    }

    #[test]
    fn session_status_and_timers_match_xray_recovery_rules() {
        assert_eq!(heartbeat_interval(0), Duration::from_secs(15));
        assert_eq!(heartbeat_interval(1), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(30), Duration::from_secs(15));

        for status in [StatusCode::UNAUTHORIZED, StatusCode::NOT_FOUND] {
            assert_eq!(
                realm_status_error(status, ErrorResponse::default()).kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert_eq!(
            realm_status_error(StatusCode::INTERNAL_SERVER_ERROR, ErrorResponse::default()).kind(),
            io::ErrorKind::Other
        );
    }

    #[tokio::test]
    async fn client_connect_uses_the_official_connect_route_and_bearer_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let length = stream.read(&mut chunk).await.unwrap();
                assert_ne!(length, 0);
                request.extend_from_slice(&chunk[..length]);
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(
                head.starts_with("post /v1/realm%2fid/connect http/1.1\r\n"),
                "unexpected realm request head: {head:?}"
            );
            assert!(head.contains("authorization: bearer secret\r\n"));
            assert!(head.contains("content-type: application/json\r\n"));
            assert!(head.contains(&format!("host: 127.0.0.1:{port}\r\n")));

            let body = r#"{"addresses":["192.0.2.1:443"],"nonce":"00","obfs":"11"}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let parsed = ParsedRealm::parse(&RealmMaskConfig {
            url: format!("realm+http://secret@127.0.0.1:{port}/realm%2Fid"),
            stun_servers: vec!["127.0.0.1:3478".into()],
            tls_config: None,
        })
        .unwrap();
        let response = RealmHttpClient::new(&parsed)
            .connect(
                &parsed.realm_id,
                &parsed.token,
                ConnectRequest {
                    addresses: vec!["198.51.100.2:40000".into()],
                    metadata: PunchMetadata {
                        nonce: "00".repeat(16),
                        obfs: "11".repeat(32),
                    },
                },
            )
            .await
            .unwrap();
        assert_eq!(response.addresses, ["192.0.2.1:443"]);
        server.await.unwrap();
    }

    #[test]
    fn typed_tls_config_uses_the_complete_shared_xray_executor() {
        let parsed = ParsedRealm::parse(&RealmMaskConfig {
            url: "realm://token@example.com/id".into(),
            stun_servers: vec!["stun.example:3478".into()],
            tls_config: Some(core_config::model::XhttpDownloadTlsSettings {
                server_name: Some("control.example".into()),
                alpn: Some(vec!["h2".into(), "http/1.1".into()]),
                enable_session_resumption: Some(true),
                min_version: Some("1.2".into()),
                max_version: Some("1.3".into()),
                fingerprint: Some("chrome".into()),
                pinned_peer_cert_sha256: Some("11".repeat(32)),
                verify_peer_cert_by_name: Some("control.example,127.0.0.1".into()),
                ech_config_list: Some("https://ech.example/config".into()),
                ..Default::default()
            }),
        })
        .unwrap();
        assert_eq!(parsed.tls.sni.as_deref(), Some("control.example"));
        assert_eq!(parsed.tls.alpn, ["h2", "http/1.1"]);
        assert!(parsed.tls.enable_session_resumption);
        assert_eq!(parsed.tls.fingerprint, "chrome");
        assert_eq!(parsed.tls.pinned_peer_cert_sha256.len(), 1);
        assert_eq!(
            parsed.tls.verify_peer_cert_by_name,
            ["control.example", "127.0.0.1"]
        );
        let source = parsed.tls.xray_settings.as_ref().unwrap();
        assert_eq!(source.min_version.as_deref(), Some("1.2"));
        assert_eq!(source.max_version.as_deref(), Some("1.3"));
        assert_eq!(
            source.ech_config_list.as_deref(),
            Some("https://ech.example/config")
        );

        let error = ParsedRealm::parse(&RealmMaskConfig {
            url: "realm://token@example.com/id".into(),
            stun_servers: vec!["stun.example:3478".into()],
            tls_config: Some(core_config::model::XhttpDownloadTlsSettings {
                min_version: Some("1.3".into()),
                max_version: Some("1.2".into()),
                ..Default::default()
            }),
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("minVersion"));

        let error = ParsedRealm::parse(&RealmMaskConfig {
            url: "realm+http://token@example.com/id".into(),
            stun_servers: vec!["stun.example:3478".into()],
            tls_config: Some(Default::default()),
        })
        .unwrap_err();
        assert!(error.to_string().contains("realm+http"));
    }

    #[test]
    fn sse_parser_handles_crlf_comments_multiline_data_and_event_filtering() {
        let block = b": keepalive\r\nevent: punch\r\ndata: {\"addresses\":[\"192.0.2.1:1234\"],\r\ndata: \"nonce\":\"0011\",\"obfs\":\"2233\"}\r\n\r\n";
        assert_eq!(sse_event_end(block), Some(block.len()));
        let event = parse_sse_event(block).unwrap().unwrap();
        assert_eq!(event.addresses, ["192.0.2.1:1234"]);
        assert_eq!(event.metadata.nonce, "0011");
        assert_eq!(event.metadata.obfs, "2233");
        assert!(
            parse_sse_event(b"event: heartbeat\ndata: {}\n\n")
                .unwrap()
                .is_none()
        );
        assert!(parse_sse_event(b"event: punch\ndata: not-json\n\n").is_err());
    }

    #[test]
    fn punch_wire_roundtrip_and_tamper_rejection() {
        let metadata = PunchMetadata {
            nonce: "00".repeat(16),
            obfs: "11".repeat(32),
        };
        let packet = encode_punch(PunchType::Hello, &metadata).unwrap();
        assert_eq!(decode_punch(&packet, &metadata).unwrap(), PunchType::Hello);
        let mut corrupt = packet;
        corrupt[20] ^= 1;
        assert!(decode_punch(&corrupt, &metadata).is_err());
    }

    #[test]
    fn stun_xor_mapped_ipv4_decodes() {
        let transaction = [7; 12];
        let address: SocketAddr = "203.0.113.9:54321".parse().unwrap();
        let mut response = vec![0; 32];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        response[8..20].copy_from_slice(&transaction);
        response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
        response[22..24].copy_from_slice(&8_u16.to_be_bytes());
        response[25] = 1;
        response[26..28]
            .copy_from_slice(&(address.port() ^ (STUN_MAGIC >> 16) as u16).to_be_bytes());
        let ip = match address.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        for index in 0..4 {
            response[28 + index] = ip[index] ^ STUN_MAGIC.to_be_bytes()[index];
        }
        assert_eq!(
            parse_stun_binding_response(&response).unwrap(),
            (transaction, address)
        );
    }

    #[test]
    fn symmetric_nat_expansion_is_bounded_and_family_filtered() {
        let locals = ["192.0.2.1:1".parse().unwrap()];
        let peers = [
            "198.51.100.1:4000".parse().unwrap(),
            "198.51.100.1:4002".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
        ];
        let (candidates, mut seen) = candidate_punch_addresses(&locals, &peers);
        let expanded = expand_symmetric_nat_candidates(candidates, &mut seen);
        assert!(expanded.iter().all(SocketAddr::is_ipv4));
        assert!(expanded.contains(&"198.51.100.1:4006".parse().unwrap()));
        assert!(expanded.len() <= 34);
    }
}
