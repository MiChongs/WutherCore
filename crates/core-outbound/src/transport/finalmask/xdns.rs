//! Xray 26.7.11 xdns UDP carrier.
//!
//! The wire format follows `transport/internet/finalmask/xdns` at commit
//! `6e3322d219140a025285ded1114fe17a5edb74d8`: client payloads are embedded in
//! lower-case base32 query labels and server payloads are length-framed in
//! TXT/A/AAAA answers. Hickory handles RFC 1035 compression and malformed-name
//! rejection; all xdns-specific bounds remain explicit here.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use core_config::XdnsMaskConfig;
use data_encoding::BASE32_NOPAD;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, TXT},
    },
};
use rand::RngCore;
use tokio::sync::{Mutex, Notify, mpsc};

use crate::adapter::{BoxedUdp, UdpSocketLike};

const QUERY_PAYLOAD_LIMIT: usize = 223;
const MAX_DNS_DATAGRAM: usize = 1232;
const QUEUE_LIMIT: usize = 256;
const INITIAL_POLL_DELAY: Duration = Duration::from_millis(500);
const MAX_POLL_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct Resolver {
    domain: Name,
    address: SocketAddr,
    record_type: RecordType,
}

#[derive(Debug, Clone)]
struct DomainSpec {
    domain: Name,
    record_type: Option<RecordType>,
}

pub(super) fn wrap_client(inner: BoxedUdp, config: &XdnsMaskConfig) -> io::Result<BoxedUdp> {
    if config.resolvers.is_empty() {
        return Err(invalid("xdns client requires at least one resolver"));
    }
    let resolvers = config
        .resolvers
        .iter()
        .map(|resolver| parse_resolver(resolver))
        .collect::<io::Result<Vec<_>>>()?;
    let mut client_id = [0; 8];
    rand::rngs::OsRng.fill_bytes(&mut client_id);
    let inner: Arc<dyn UdpSocketLike> = Arc::from(inner);
    let (write_tx, write_rx) = mpsc::channel(QUEUE_LIMIT);
    let (read_tx, read_rx) = mpsc::channel(QUEUE_LIMIT);
    let response = Arc::new(Notify::new());
    let closed = Arc::new(AtomicBool::new(false));
    let resolver_index = Arc::new(AtomicUsize::new(0));

    spawn_sender(
        inner.clone(),
        resolvers.clone(),
        client_id,
        write_rx,
        response.clone(),
        closed.clone(),
        resolver_index.clone(),
    );
    spawn_receiver(
        inner.clone(),
        resolvers.clone(),
        read_tx,
        response,
        closed.clone(),
    );

    Ok(Box::new(XdnsClient {
        inner,
        write: write_tx,
        read: Mutex::new(read_rx),
        closed,
    }))
}

pub(super) fn wrap_server(inner: BoxedUdp, config: &XdnsMaskConfig) -> io::Result<BoxedUdp> {
    if config.domains.is_empty() {
        return Err(invalid("xdns server requires at least one domain"));
    }
    // Compile eagerly so malformed domain/method settings fail before the
    // background dispatcher owns the carrier.
    let domains = config
        .domains
        .iter()
        .map(|domain| parse_domain_spec(domain, None))
        .collect::<io::Result<Vec<_>>>()?;
    let inner: Arc<dyn UdpSocketLike> = Arc::from(inner);
    let clients = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let (read_tx, read_rx) = mpsc::channel(512);
    let closed = Arc::new(AtomicBool::new(false));
    let permits = Arc::new(tokio::sync::Semaphore::new(256));
    let task = tokio::spawn(server_dispatch(
        inner.clone(),
        domains,
        clients.clone(),
        read_tx,
        permits,
        closed.clone(),
    ));
    Ok(Box::new(XdnsServer {
        inner,
        clients,
        read: Mutex::new(read_rx),
        closed,
        task: Mutex::new(Some(task)),
    }))
}

struct XdnsClientQueue {
    send: mpsc::Sender<Vec<u8>>,
    receive: Mutex<mpsc::Receiver<Vec<u8>>>,
    stash: Mutex<Option<Vec<u8>>>,
    last: parking_lot::Mutex<std::time::Instant>,
}

impl XdnsClientQueue {
    fn new() -> Arc<Self> {
        let (send, receive) = mpsc::channel(512);
        Arc::new(Self {
            send,
            receive: Mutex::new(receive),
            stash: Mutex::new(None),
            last: parking_lot::Mutex::new(std::time::Instant::now()),
        })
    }

    fn touch(&self) {
        *self.last.lock() = std::time::Instant::now();
    }
}

struct XdnsServer {
    inner: Arc<dyn UdpSocketLike>,
    clients: Arc<Mutex<std::collections::HashMap<SocketAddr, Arc<XdnsClientQueue>>>>,
    read: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    closed: Arc<AtomicBool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[async_trait]
impl UdpSocketLike for XdnsServer {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        let target = parse_synthetic_address(target, port)?;
        let queue = self
            .clients
            .lock()
            .await
            .get(&target)
            .cloned()
            .ok_or_else(|| invalid(format!("unknown xdns client `{target}`")))?;
        queue.touch();
        queue
            .send
            .try_send(payload.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
                mpsc::error::TrySendError::Closed(_) => io::Error::from(io::ErrorKind::BrokenPipe),
            })?;
        Ok(payload.len())
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
            .read
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if packet.len() > output.len() {
            return Err(invalid(format!(
                "xdns decoded packet is {} bytes, receive buffer is {}",
                packet.len(),
                output.len()
            )));
        }
        output[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), Some(source)))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    async fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel)
            && let Some(task) = self.task.lock().await.take()
        {
            task.abort();
        }
        self.inner.close().await
    }
}

async fn server_dispatch(
    inner: Arc<dyn UdpSocketLike>,
    domains: Vec<DomainSpec>,
    clients: Arc<Mutex<std::collections::HashMap<SocketAddr, Arc<XdnsClientQueue>>>>,
    output: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    permits: Arc<tokio::sync::Semaphore>,
    closed: Arc<AtomicBool>,
) {
    let mut buffer = vec![0; u16::MAX as usize];
    let mut cleanup = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = cleanup.tick() => {
                let now = std::time::Instant::now();
                clients.lock().await.retain(|_, queue| {
                    now.duration_since(*queue.last.lock()) < Duration::from_secs(10)
                });
            }
            received = inner.recv_from_endpoint(&mut buffer) => {
                let (length, Some(source)) = (match received {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(%error, "xdns server carrier ended");
                        return;
                    }
                }) else {
                    tracing::debug!("xdns server requires a source-aware carrier");
                    return;
                };
                let query = match decode_server_request(&buffer[..length], &domains) {
                    Ok(ServerRequest::Query(query)) => query,
                    Ok(ServerRequest::Response(response)) => {
                        if let Err(error) = inner
                            .send_to(&response, &source.ip().to_string(), source.port())
                            .await
                        {
                            tracing::debug!(%error, %source, "xdns error response failed");
                        }
                        continue;
                    }
                    Ok(ServerRequest::Drop) => continue,
                    Err(error) => {
                        tracing::debug!(%error, %source, "xdns ignored undecodable query");
                        continue;
                    }
                };
                let synthetic = client_id_to_address(query.client_id);
                let queue = {
                    let mut clients = clients.lock().await;
                    if clients.len() >= 1024 && !clients.contains_key(&synthetic) {
                        tracing::debug!("xdns client map full");
                        continue;
                    }
                    clients.entry(synthetic).or_insert_with(XdnsClientQueue::new).clone()
                };
                queue.touch();
                for packet in &query.packets {
                    if output.try_send((packet.clone(), synthetic)).is_err() {
                        break;
                    }
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = answer_query(inner, source, query, queue).await {
                        tracing::debug!(%error, %source, "xdns response failed");
                    }
                });
            }
        }
        if closed.load(Ordering::Acquire) {
            return;
        }
    }
}

async fn answer_query(
    inner: Arc<dyn UdpSocketLike>,
    source: SocketAddr,
    query: ServerQuery,
    queue: Arc<XdnsClientQueue>,
) -> io::Result<()> {
    let mut packets = Vec::new();
    let mut receive = queue.receive.lock().await;
    let first = if let Some(packet) = queue.stash.lock().await.take() {
        Some(packet)
    } else {
        tokio::time::timeout(Duration::from_secs(1), receive.recv())
            .await
            .ok()
            .flatten()
    };
    if let Some(packet) = first {
        packets.push(packet);
        while let Ok(packet) = receive.try_recv() {
            let mut candidate = packets.clone();
            candidate.push(packet.clone());
            if encode_server_response(&query, &candidate).is_err() {
                *queue.stash.lock().await = Some(packet);
                break;
            }
            packets = candidate;
        }
    }
    drop(receive);
    // Drop an individually oversized application packet just like Xray, but
    // still answer the poll so the client's backoff state progresses.
    if encode_server_response(&query, &packets).is_err() {
        packets.clear();
    }
    let response = encode_server_response(&query, &packets)?;
    inner
        .send_to(&response, &source.ip().to_string(), source.port())
        .await?;
    Ok(())
}

fn client_id_to_address(client_id: [u8; 8]) -> SocketAddr {
    let mut octets = [0; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[8..].copy_from_slice(&client_id);
    SocketAddr::new(std::net::Ipv6Addr::from(octets).into(), 0)
}

fn parse_synthetic_address(target: &str, port: u16) -> io::Result<SocketAddr> {
    let target = target
        .trim()
        .strip_prefix('[')
        .and_then(|target| target.strip_suffix(']'))
        .unwrap_or_else(|| target.trim());
    let ip = target
        .parse()
        .map_err(|_| invalid(format!("invalid xdns client address `{target}`")))?;
    Ok(SocketAddr::new(ip, port))
}

struct XdnsClient {
    inner: Arc<dyn UdpSocketLike>,
    write: mpsc::Sender<Vec<u8>>,
    read: Mutex<mpsc::Receiver<Vec<u8>>>,
    closed: Arc<AtomicBool>,
}

#[async_trait]
impl UdpSocketLike for XdnsClient {
    async fn send_to(&self, payload: &[u8], _: &str, _: u16) -> io::Result<usize> {
        if payload.len() > QUERY_PAYLOAD_LIMIT {
            return Err(invalid(format!(
                "xdns query payload is {} bytes; maximum is {QUERY_PAYLOAD_LIMIT}",
                payload.len()
            )));
        }
        self.write
            .try_send(payload.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
                mpsc::error::TrySendError::Closed(_) => io::Error::from(io::ErrorKind::BrokenPipe),
            })?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .read
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if packet.len() > output.len() {
            return Err(invalid(format!(
                "xdns decoded packet is {} bytes, receive buffer is {}",
                packet.len(),
                output.len()
            )));
        }
        output[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::Release);
        self.inner.close().await
    }
}

fn spawn_sender(
    inner: Arc<dyn UdpSocketLike>,
    resolvers: Vec<Resolver>,
    client_id: [u8; 8],
    mut input: mpsc::Receiver<Vec<u8>>,
    response: Arc<Notify>,
    closed: Arc<AtomicBool>,
    resolver_index: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        let mut delay = INITIAL_POLL_DELAY;
        loop {
            let packet = tokio::select! {
                biased;
                packet = input.recv() => match packet {
                    Some(packet) => {
                        delay = INITIAL_POLL_DELAY;
                        Some(packet)
                    }
                    None => return,
                },
                _ = response.notified() => {
                    delay = INITIAL_POLL_DELAY;
                    None
                },
                _ = tokio::time::sleep(delay) => {
                    delay = (delay * 2).min(MAX_POLL_DELAY);
                    None
                },
            };
            if closed.load(Ordering::Acquire) {
                return;
            }
            let index = resolver_index.fetch_add(1, Ordering::AcqRel) % resolvers.len();
            let resolver = &resolvers[index];
            let payload = packet.as_deref().unwrap_or_default();
            let wire = match encode_query(payload, &client_id, resolver) {
                Ok(wire) => wire,
                Err(error) => {
                    tracing::debug!(%error, "xdns encode query failed");
                    continue;
                }
            };
            let _ = inner
                .send_to(
                    &wire,
                    &resolver.address.ip().to_string(),
                    resolver.address.port(),
                )
                .await;
        }
    });
}

fn spawn_receiver(
    inner: Arc<dyn UdpSocketLike>,
    resolvers: Vec<Resolver>,
    output: mpsc::Sender<Vec<u8>>,
    response: Arc<Notify>,
    closed: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0; u16::MAX as usize];
        while !closed.load(Ordering::Acquire) {
            let length = match inner.recv_from(&mut buffer).await {
                Ok(length) if length <= buffer.len() => length,
                Ok(_) => return,
                Err(error) => {
                    tracing::debug!(%error, "xdns carrier receive failed");
                    return;
                }
            };
            let packets = match decode_response(&buffer[..length], &resolvers) {
                Ok(packets) => packets,
                Err(error) => {
                    tracing::debug!(%error, "xdns ignored malformed response");
                    continue;
                }
            };
            if !packets.is_empty() {
                response.notify_one();
            }
            for packet in packets {
                if output.try_send(packet).is_err() {
                    break;
                }
            }
        }
    });
}

fn parse_resolver(input: &str) -> io::Result<Resolver> {
    let (head, server) = input
        .split_once("+udp://")
        .ok_or_else(|| invalid("xdns resolver must use domain[:method]+udp://IP:port"))?;
    let spec = parse_domain_spec(head, Some(RecordType::TXT))?;
    let address = server.parse::<SocketAddr>().map_err(|_| {
        invalid(format!(
            "xdns resolver `{server}` is not an IP socket address"
        ))
    })?;
    Ok(Resolver {
        domain: spec.domain,
        address,
        record_type: spec.record_type.expect("default record type"),
    })
}

fn parse_domain_spec(input: &str, default: Option<RecordType>) -> io::Result<DomainSpec> {
    let (domain, method) = match input.rsplit_once(':') {
        Some((domain, method)) => (domain, Some(method)),
        None => (input, None),
    };
    if domain.is_empty() {
        return Err(invalid("xdns domain is empty"));
    }
    let mut domain = Name::from_ascii(domain).map_err(invalid)?;
    domain.set_fqdn(true);
    let record_type = match method {
        Some(method) => Some(parse_method(method)?),
        None => default,
    };
    Ok(DomainSpec {
        domain,
        record_type,
    })
}

fn parse_method(input: &str) -> io::Result<RecordType> {
    match input.to_ascii_lowercase().as_str() {
        "" | "txt" => Ok(RecordType::TXT),
        "a" => Ok(RecordType::A),
        "aaaa" => Ok(RecordType::AAAA),
        _ => Err(invalid(format!("unsupported xdns method `{input}`"))),
    }
}

fn encode_query(payload: &[u8], client_id: &[u8; 8], resolver: &Resolver) -> io::Result<Vec<u8>> {
    if payload.len() > QUERY_PAYLOAD_LIMIT {
        return Err(invalid("xdns payload exceeds query limit"));
    }
    let padding_length = if payload.is_empty() { 8 } else { 3 };
    let mut decoded = Vec::with_capacity(10 + padding_length + payload.len());
    decoded.extend_from_slice(client_id);
    decoded.push(224 + padding_length as u8);
    let mut padding = vec![0; padding_length];
    rand::rngs::OsRng.fill_bytes(&mut padding);
    decoded.extend_from_slice(&padding);
    if !payload.is_empty() {
        decoded.push(payload.len() as u8);
        decoded.extend_from_slice(payload);
    }
    let encoded = BASE32_NOPAD.encode(&decoded).to_ascii_lowercase();
    let prefix = Name::from_labels(encoded.as_bytes().chunks(63)).map_err(invalid)?;
    let query_name = prefix.append_name(&resolver.domain).map_err(invalid)?;

    let mut message = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(query_name, resolver.record_type));
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    message.set_edns(edns);
    message.to_vec().map_err(invalid)
}

fn decode_response(wire: &[u8], resolvers: &[Resolver]) -> io::Result<Vec<Vec<u8>>> {
    let message = Message::from_vec(wire).map_err(invalid)?;
    if message.metadata.message_type != MessageType::Response
        || message.metadata.response_code != ResponseCode::NoError
        || message.answers.is_empty()
    {
        return Err(invalid("xdns response flags or answers are invalid"));
    }
    for answer in &message.answers {
        if !resolvers
            .iter()
            .any(|resolver| resolver.domain.zone_of(&answer.name))
        {
            return Err(invalid(
                "xdns response answer is outside configured domains",
            ));
        }
    }
    let payload = decode_answer_payload(&message.answers)?;
    decode_frames(&payload)
}

fn decode_answer_payload(answers: &[Record]) -> io::Result<Vec<u8>> {
    let first = &answers
        .first()
        .ok_or_else(|| invalid("xdns answer has no rdata"))?
        .data;
    match first {
        RData::TXT(txt) => {
            if answers.len() != 1 {
                return Err(invalid("xdns TXT response must contain one answer"));
            }
            Ok(txt
                .txt_data
                .iter()
                .flat_map(|part| part.iter().copied())
                .collect())
        }
        RData::A(_) => decode_ip_answers(answers, RecordType::A, 4),
        RData::AAAA(_) => decode_ip_answers(answers, RecordType::AAAA, 16),
        _ => Err(invalid("xdns answer type is unsupported")),
    }
}

fn decode_ip_answers(
    answers: &[Record],
    record_type: RecordType,
    width: usize,
) -> io::Result<Vec<u8>> {
    if answers.len() > 256 {
        return Err(invalid("xdns IP response has too many answers"));
    }
    let mut parts = vec![None; answers.len()];
    for answer in answers {
        if answer.record_type() != record_type {
            return Err(invalid("xdns response mixes answer types"));
        }
        let bytes = match &answer.data {
            RData::A(address) => address.0.octets().to_vec(),
            RData::AAAA(address) => address.0.octets().to_vec(),
            _ => return Err(invalid("xdns IP answer has invalid rdata")),
        };
        if bytes.len() != width {
            return Err(invalid("xdns IP answer width is invalid"));
        }
        let index = bytes[0] as usize;
        let length = bytes[1] as usize;
        if index >= parts.len() || length > width - 2 || parts[index].is_some() {
            return Err(invalid("xdns IP answer chunk header is invalid"));
        }
        parts[index] = Some(bytes[2..2 + length].to_vec());
    }
    let mut output = Vec::new();
    for part in parts {
        output.extend(part.ok_or_else(|| invalid("xdns IP answer chunk is missing"))?);
    }
    Ok(output)
}

fn decode_frames(mut payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();
    while !payload.is_empty() {
        if payload.len() < 2 {
            return Err(invalid("xdns response frame length is truncated"));
        }
        let length = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        payload = &payload[2..];
        if payload.len() < length {
            return Err(invalid("xdns response frame is truncated"));
        }
        packets.push(payload[..length].to_vec());
        payload = &payload[length..];
    }
    Ok(packets)
}

/// Server-side query decoder used by the inbound carrier.
#[derive(Debug, Clone)]
pub(crate) struct ServerQuery {
    message: Message,
    question_name: Name,
    record_type: RecordType,
    pub(crate) client_id: [u8; 8],
    pub(crate) packets: Vec<Vec<u8>>,
}

enum ServerRequest {
    Query(ServerQuery),
    Response(Vec<u8>),
    Drop,
}

pub(crate) fn decode_server_query(
    wire: &[u8],
    configured_domains: &[String],
) -> io::Result<ServerQuery> {
    let domains = configured_domains
        .iter()
        .map(|domain| parse_domain_spec(domain, None))
        .collect::<io::Result<Vec<_>>>()?;
    match decode_server_request(wire, &domains)? {
        ServerRequest::Query(query) => Ok(query),
        ServerRequest::Response(_) => Err(invalid("xdns query requires an error response")),
        ServerRequest::Drop => Err(invalid("xdns server ignores DNS responses")),
    }
}

fn decode_server_request(wire: &[u8], domains: &[DomainSpec]) -> io::Result<ServerRequest> {
    let message = Message::from_vec(wire).map_err(invalid)?;
    if message.metadata.message_type != MessageType::Query {
        return Ok(ServerRequest::Drop);
    }
    if message.version() != 0 {
        return error_server_response(&message, false, ResponseCode::BADVERS);
    }
    if message.queries.len() != 1 {
        return error_server_response(&message, false, ResponseCode::FormErr);
    }
    let question = &message.queries[0];
    let matched = domains
        .iter()
        .find(|domain| domain.domain.zone_of(question.name()));
    let Some(matched) = matched else {
        return error_server_response(&message, false, ResponseCode::NXDomain);
    };
    if message.metadata.op_code != OpCode::Query {
        return error_server_response(&message, true, ResponseCode::NotImp);
    }
    if !matches!(
        question.query_type(),
        RecordType::TXT | RecordType::A | RecordType::AAAA
    ) || matched
        .record_type
        .is_some_and(|record_type| record_type != question.query_type())
    {
        return error_server_response(&message, true, ResponseCode::NXDomain);
    }
    let prefix_count = usize::from(question.name().num_labels() - matched.domain.num_labels());
    let encoded = question
        .name()
        .iter()
        .take(prefix_count)
        .flat_map(|label| label.iter().copied())
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let decoded = match BASE32_NOPAD.decode(&encoded) {
        Ok(decoded) => decoded,
        Err(_) => return error_server_response(&message, true, ResponseCode::NXDomain),
    };
    if message.max_payload() < MAX_DNS_DATAGRAM as u16 {
        return error_server_response(&message, true, ResponseCode::FormErr);
    }
    if decoded.len() < 8 {
        return error_server_response(&message, true, ResponseCode::NXDomain);
    }
    let mut client_id = [0; 8];
    client_id.copy_from_slice(&decoded[..8]);
    let packets = decode_query_packets(&decoded[8..]);
    let question_name = question.name().clone();
    let record_type = question.query_type();
    Ok(ServerRequest::Query(ServerQuery {
        message,
        question_name,
        record_type,
        client_id,
        packets,
    }))
}

fn error_server_response(
    query: &Message,
    authoritative: bool,
    response_code: ResponseCode,
) -> io::Result<ServerRequest> {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.authoritative = authoritative;
    response.metadata.response_code = response_code;
    response.add_queries(query.queries.iter().cloned());
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        response.set_edns(edns);
    }
    Ok(ServerRequest::Response(response.to_vec().map_err(invalid)?))
}

fn decode_query_packets(mut payload: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while !payload.is_empty() {
        let prefix = payload[0];
        payload = &payload[1..];
        if prefix >= 224 {
            let padding = usize::from(prefix - 224);
            if payload.len() < padding {
                break;
            }
            payload = &payload[padding..];
            continue;
        }
        let length = usize::from(prefix);
        if payload.len() < length {
            break;
        }
        packets.push(payload[..length].to_vec());
        payload = &payload[length..];
    }
    packets
}

pub(crate) fn encode_server_response(
    query: &ServerQuery,
    packets: &[Vec<u8>],
) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    for packet in packets {
        let length = u16::try_from(packet.len())
            .map_err(|_| invalid("xdns server packet exceeds u16 length"))?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(packet);
    }
    let mut response = Message::new(
        query.message.metadata.id,
        MessageType::Response,
        query.message.metadata.op_code,
    );
    response.metadata.authoritative = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(query.message.queries[0].clone());
    let answers = encode_answers(query.question_name.clone(), query.record_type, &payload)?;
    response.add_answers(answers);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    response.set_edns(edns);
    let wire = response.to_vec().map_err(invalid)?;
    if wire.len() > MAX_DNS_DATAGRAM {
        return Err(invalid(format!(
            "xdns response is {} bytes; maximum is {MAX_DNS_DATAGRAM}",
            wire.len()
        )));
    }
    Ok(wire)
}

fn encode_answers(name: Name, kind: RecordType, payload: &[u8]) -> io::Result<Vec<Record>> {
    match kind {
        RecordType::TXT => {
            let chunks = payload.chunks(255).collect::<Vec<_>>();
            Ok(vec![Record::from_rdata(
                name,
                60,
                RData::TXT(TXT::from_bytes(if chunks.is_empty() {
                    vec![&[]]
                } else {
                    chunks
                })),
            )])
        }
        RecordType::A | RecordType::AAAA => {
            let width = if kind == RecordType::A { 4 } else { 16 };
            let chunk = width - 2;
            let count = payload.len().div_ceil(chunk).max(1);
            if count > 256 {
                return Err(invalid("xdns IP response needs more than 256 answers"));
            }
            let mut answers = Vec::with_capacity(count);
            for index in 0..count {
                let offset = index * chunk;
                let part = payload.get(offset..).unwrap_or_default();
                let part = &part[..part.len().min(chunk)];
                let mut bytes = vec![0; width];
                bytes[0] = index as u8;
                bytes[1] = part.len() as u8;
                bytes[2..2 + part.len()].copy_from_slice(part);
                let data = if kind == RecordType::A {
                    RData::A(A(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(bytes).unwrap(),
                    )))
                } else {
                    RData::AAAA(AAAA(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes).unwrap(),
                    )))
                };
                answers.push(Record::from_rdata(name.clone(), 60, data));
            }
            Ok(answers)
        }
        _ => Err(invalid("xdns answer type is unsupported")),
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(kind: RecordType) -> Resolver {
        Resolver {
            domain: Name::from_ascii("t.example.").unwrap(),
            address: "127.0.0.1:53".parse().unwrap(),
            record_type: kind,
        }
    }

    fn classify_response(message: &Message, domains: &[&str]) -> Message {
        let domains = domains
            .iter()
            .map(|domain| parse_domain_spec(domain, None).unwrap())
            .collect::<Vec<_>>();
        let wire = message.to_vec().unwrap();
        let ServerRequest::Response(response) = decode_server_request(&wire, &domains).unwrap()
        else {
            panic!("expected xdns error response");
        };
        Message::from_vec(&response).unwrap()
    }

    #[test]
    fn client_query_and_server_decoder_are_bidirectionally_compatible() {
        let resolver = resolver(RecordType::TXT);
        let id = *b"12345678";
        let wire = encode_query(b"quic", &id, &resolver).unwrap();
        let query = decode_server_query(&wire, &["t.example:txt".into()]).unwrap();
        assert_eq!(query.client_id, id);
        assert_eq!(query.packets, [b"quic".to_vec()]);
    }

    #[test]
    fn server_answers_decode_for_all_official_record_modes() {
        for kind in [RecordType::TXT, RecordType::A, RecordType::AAAA] {
            let resolver = resolver(kind);
            let query_wire = encode_query(b"request", b"abcdefgh", &resolver).unwrap();
            let query = decode_server_query(
                &query_wire,
                &[format!(
                    "t.example:{}",
                    match kind {
                        RecordType::A => "a",
                        RecordType::AAAA => "aaaa",
                        _ => "txt",
                    }
                )],
            )
            .unwrap();
            let response =
                encode_server_response(&query, &[b"first".to_vec(), b"second packet".to_vec()])
                    .unwrap();
            assert_eq!(
                decode_response(&response, std::slice::from_ref(&resolver)).unwrap(),
                [b"first".to_vec(), b"second packet".to_vec()]
            );
        }
    }

    #[test]
    fn rejects_truncation_wrong_domain_and_oversize_query() {
        let resolver = resolver(RecordType::TXT);
        assert!(encode_query(&vec![0; 224], b"abcdefgh", &resolver).is_err());
        let wire = encode_query(b"ok", b"abcdefgh", &resolver).unwrap();
        assert!(decode_server_query(&wire[..wire.len() - 1], &["t.example".into()]).is_err());
        assert!(decode_server_query(&wire, &["other.example".into()]).is_err());
    }

    #[test]
    fn server_returns_xray_dns_error_codes_instead_of_dropping_queries() {
        let resolver = resolver(RecordType::TXT);
        let valid =
            Message::from_vec(&encode_query(b"ok", b"abcdefgh", &resolver).unwrap()).unwrap();

        let wrong_domain = classify_response(&valid, &["other.example"]);
        assert_eq!(wrong_domain.metadata.response_code, ResponseCode::NXDomain);
        assert!(!wrong_domain.metadata.authoritative);

        let mut unsupported_opcode = valid.clone();
        unsupported_opcode.metadata.op_code = OpCode::Status;
        let unsupported_opcode = classify_response(&unsupported_opcode, &["t.example:txt"]);
        assert_eq!(
            unsupported_opcode.metadata.response_code,
            ResponseCode::NotImp
        );
        assert!(unsupported_opcode.metadata.authoritative);

        let mut unsupported_type = valid.clone();
        unsupported_type.queries[0].set_query_type(RecordType::MX);
        let unsupported_type = classify_response(&unsupported_type, &["t.example"]);
        assert_eq!(
            unsupported_type.metadata.response_code,
            ResponseCode::NXDomain
        );
        assert!(unsupported_type.metadata.authoritative);

        let mut bad_version = valid.clone();
        bad_version.edns.as_mut().unwrap().set_version(1);
        let bad_version = classify_response(&bad_version, &["t.example:txt"]);
        // Hickory names numeric RCODE 16 `BADSIG` when decoding because the
        // number is shared with BADVERS. An OPT response makes it BADVERS.
        assert_eq!(u16::from(bad_version.metadata.response_code), 16);
        assert_eq!(
            bad_version.edns.as_ref().unwrap().rcode_high(),
            ResponseCode::BADVERS.high()
        );
        assert!(!bad_version.metadata.authoritative);
        assert_eq!(bad_version.version(), 0);

        let mut undersized_edns = valid;
        undersized_edns.edns.as_mut().unwrap().set_max_payload(512);
        let undersized_edns = classify_response(&undersized_edns, &["t.example:txt"]);
        assert_eq!(
            undersized_edns.metadata.response_code,
            ResponseCode::FormErr
        );
        assert!(undersized_edns.metadata.authoritative);

        let no_question = Message::new(7, MessageType::Query, OpCode::Query);
        let no_question = classify_response(&no_question, &["t.example"]);
        assert_eq!(no_question.metadata.response_code, ResponseCode::FormErr);
        assert!(!no_question.metadata.authoritative);
    }

    #[test]
    fn server_keeps_complete_packets_before_a_truncated_query_frame() {
        assert_eq!(
            decode_query_packets(&[2, b'o', b'k', 4, b'x']),
            [b"ok".to_vec()]
        );
        assert_eq!(
            decode_query_packets(&[225, 0xaa, 3, b'a', b'b', b'c']),
            [b"abc".to_vec()]
        );
    }
}
