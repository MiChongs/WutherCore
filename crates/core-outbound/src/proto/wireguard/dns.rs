use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{device::WireGuardDevice, io_err};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CACHE_ENTRIES: usize = 1_024;
const MAX_CACHE_TTL: Duration = Duration::from_secs(3_600);
const MIN_CACHE_TTL: Duration = Duration::from_secs(1);
const MAX_DNS_TCP_MESSAGE: usize = u16::MAX as usize;

#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

#[derive(Debug, Default)]
pub(super) struct DnsCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl DnsCache {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(super) async fn resolve(
        &self,
        device: &WireGuardDevice,
        host: &str,
        port: u16,
    ) -> std::io::Result<Vec<SocketAddr>> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(addresses) = self.cached(&key) {
            return Ok(addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port))
                .collect());
        }
        let name = Name::from_ascii(&key)
            .map_err(|error| io_err(format!("wireguard DNS name is invalid: {error}")))?;
        let config = device.config();
        let wants_v4 = config
            .local_addresses
            .iter()
            .any(|address| address.addr().is_ipv4());
        let wants_v6 = config
            .local_addresses
            .iter()
            .any(|address| address.addr().is_ipv6());
        let mut addresses = Vec::new();
        let mut ttl = MAX_CACHE_TTL;
        let mut last_error = None;
        for record_type in [RecordType::A, RecordType::AAAA] {
            if (record_type == RecordType::A && !wants_v4)
                || (record_type == RecordType::AAAA && !wants_v6)
            {
                continue;
            }
            let mut resolved_type = false;
            for dns in &config.dns {
                match query(device, *dns, name.clone(), record_type).await {
                    Ok((records, record_ttl)) => {
                        addresses.extend(records);
                        ttl = ttl.min(record_ttl);
                        resolved_type = true;
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if !resolved_type {
                tracing::debug!(
                    target: "wireguard::dns",
                    host = %key,
                    ?record_type,
                    "no configured in-tunnel DNS server answered this record type"
                );
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        addresses.retain(|address| config.route_peer(*address).is_some());
        if addresses.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("wireguard in-tunnel DNS returned no routed address for {key}"),
                )
            }));
        }
        self.insert(key, addresses.clone(), ttl);
        Ok(addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect())
    }

    fn cached(&self, key: &str) -> Option<Vec<IpAddr>> {
        let mut entries = self.entries.lock();
        let entry = entries.get(key)?;
        if entry.expires <= Instant::now() {
            entries.remove(key);
            return None;
        }
        Some(entry.addresses.clone())
    }

    fn insert(&self, key: String, addresses: Vec<IpAddr>, ttl: Duration) {
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| entry.expires > Instant::now());
        if entries.len() >= MAX_CACHE_ENTRIES
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(
            key,
            CacheEntry {
                addresses,
                expires: Instant::now() + ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL),
            },
        );
    }
}

async fn query(
    device: &WireGuardDevice,
    dns: IpAddr,
    name: Name,
    record_type: RecordType,
) -> std::io::Result<(Vec<IpAddr>, Duration)> {
    let id = rand::thread_rng().r#gen::<u16>();
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(name, record_type));
    let request = request
        .to_bytes()
        .map_err(|error| io_err(format!("wireguard DNS encode failed: {error}")))?;
    let target = SocketAddr::new(dns, 53);
    let socket = device
        .stack()
        .open_udp(target, dns.to_string(), DNS_TIMEOUT.saturating_mul(2))?;
    device.stack().notify();
    socket.send_to(&request, &dns.to_string(), 53).await?;
    let mut response = vec![0; 65_535];
    let length = match tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response)).await {
        Ok(result) => result?,
        Err(_) => {
            socket.close();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("wireguard DNS UDP query to {dns} timed out"),
            ));
        }
    };
    socket.close();
    response.truncate(length);
    let message = Message::from_bytes(&response)
        .map_err(|error| io_err(format!("wireguard DNS response is malformed: {error}")))?;
    if message.metadata.id != id || message.metadata.message_type != MessageType::Response {
        return Err(io_err("wireguard DNS response id/type mismatch"));
    }
    if message.metadata.truncation {
        return query_tcp(device, dns, id, request, record_type).await;
    }
    parse_response(message, record_type)
}

async fn query_tcp(
    device: &WireGuardDevice,
    dns: IpAddr,
    id: u16,
    request: Vec<u8>,
    record_type: RecordType,
) -> std::io::Result<(Vec<IpAddr>, Duration)> {
    let mut stream = device.stack().open_tcp(SocketAddr::new(dns, 53))?;
    device.stack().notify();
    stream.wait_connected(DNS_TIMEOUT).await?;
    let length = u16::try_from(request.len())
        .map_err(|_| io_err("wireguard DNS request exceeds TCP framing limit"))?;
    tokio::time::timeout(DNS_TIMEOUT, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        let response_length = stream.read_u16().await? as usize;
        if response_length == 0 || response_length > MAX_DNS_TCP_MESSAGE {
            return Err(io_err("wireguard DNS TCP response length is invalid"));
        }
        let mut response = vec![0; response_length];
        stream.read_exact(&mut response).await?;
        let message = Message::from_bytes(&response)
            .map_err(|error| io_err(format!("wireguard DNS TCP response is malformed: {error}")))?;
        if message.metadata.id != id || message.metadata.message_type != MessageType::Response {
            return Err(io_err("wireguard DNS TCP response id/type mismatch"));
        }
        parse_response(message, record_type)
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("wireguard DNS TCP query to {dns} timed out"),
        )
    })?
}

fn parse_response(
    message: Message,
    record_type: RecordType,
) -> std::io::Result<(Vec<IpAddr>, Duration)> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("wireguard DNS returned {}", message.metadata.response_code),
        ));
    }
    let mut addresses = Vec::new();
    let mut ttl = MAX_CACHE_TTL;
    for answer in &message.answers {
        match &answer.data {
            RData::A(address) if record_type == RecordType::A => {
                addresses.push(IpAddr::V4((*address).into()));
                ttl = ttl.min(Duration::from_secs(u64::from(answer.ttl)));
            }
            RData::AAAA(address) if record_type == RecordType::AAAA => {
                addresses.push(IpAddr::V6((*address).into()));
                ttl = ttl.min(Duration::from_secs(u64::from(answer.ttl)));
            }
            _ => {}
        }
    }
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("wireguard DNS response contained no {record_type} records"),
        ));
    }
    Ok((addresses, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        RData, Record,
        rdata::{A, AAAA},
    };

    #[test]
    fn response_parser_accepts_a_and_aaaa() {
        let name = Name::from_ascii("example.test").unwrap();
        let mut v4 = Message::response(0, OpCode::Query);
        v4.add_answer(Record::from_rdata(
            name.clone(),
            30,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let (addresses, ttl) = parse_response(v4, RecordType::A).unwrap();
        assert_eq!(addresses, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, Duration::from_secs(30));

        let mut v6 = Message::response(0, OpCode::Query);
        v6.add_answer(Record::from_rdata(
            name,
            60,
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ));
        let (addresses, ttl) = parse_response(v6, RecordType::AAAA).unwrap();
        assert_eq!(addresses, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[test]
    fn cache_is_bounded_and_expires() {
        let cache = DnsCache::default();
        cache.insert(
            "example.test".into(),
            vec!["192.0.2.1".parse().unwrap()],
            Duration::from_secs(10),
        );
        assert_eq!(cache.cached("example.test").unwrap().len(), 1);
    }
}
