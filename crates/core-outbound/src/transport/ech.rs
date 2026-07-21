//! Xray-compatible ECHConfigList discovery.
//!
//! Direct base64 is decoded by the TLS builder.  URL sources perform an HTTPS
//! RR (type 65) query over DoH (`https://`), prior-knowledge HTTP/2 (`h2c://`),
//! or DNS-over-UDP (`udp://`) and extract SvcParamKey `ech` (5).

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use tokio::sync::Mutex;
use url::Url;

use super::{TlsOptions, Transport, tcp::TcpTransport, tls::TlsTransport};
use crate::adapter::{prepare_outbound_udp_socket_for_addr, resolve_host};

const DNS_TYPE_HTTPS: u16 = 65;
const SVC_PARAM_ECH: u16 = 5;
const MAX_DNS_MESSAGE: usize = 65_535;
const CACHE_CAPACITY: usize = 256;
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_STALE: Duration = Duration::from_secs(4 * 60 * 60);
const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const DOH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct CacheEntry {
    config: Vec<u8>,
    expires: Instant,
    fetched: Instant,
}

#[derive(Default)]
struct Cache {
    values: HashMap<String, CacheEntry>,
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

fn cache() -> &'static Mutex<Cache> {
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

/// Resolve URL-backed ECH configuration. `None` means ECH is absent or uses a
/// direct base64 value that the synchronous TLS builder can consume itself.
pub(crate) async fn resolve_ech_config(
    options: &TlsOptions,
    default_domain: &str,
) -> io::Result<Option<Vec<u8>>> {
    let Some(settings) = options.xray_settings.as_ref() else {
        return Ok(None);
    };
    let Some(source) = settings.ech_config_list.as_deref() else {
        return Ok(None);
    };
    if !source.contains("://") {
        return Ok(None);
    }

    let (domain, endpoint) = parse_source(source, default_domain)?;
    let sockopt = settings
        .ech_socket_settings
        .as_ref()
        .map(|value| serde_json::to_string(value))
        .transpose()
        .map_err(|error| invalid(format!("serialize echSockopt cache key: {error}")))?
        .unwrap_or_default();
    let key = format!("{endpoint}|{domain}|{sockopt}");
    let now = Instant::now();
    let cached = cache().lock().await.values.get(&key).cloned();
    if let Some(entry) = cached {
        if now < entry.expires {
            return Ok(Some(entry.config));
        }
        if now.duration_since(entry.fetched) <= MAX_STALE {
            let stale = entry.config;
            let key = key.clone();
            tokio::spawn(async move {
                if let Ok((config, ttl)) = query_endpoint(&endpoint, &domain).await {
                    insert_cache(key, config, ttl).await;
                }
            });
            return Ok(Some(stale));
        }
    }

    let (config, ttl) = query_endpoint(&endpoint, &domain).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("resolve ECH config for {domain} through {endpoint}: {error}"),
        )
    })?;
    insert_cache(key, config.clone(), ttl).await;
    Ok(Some(config))
}

async fn insert_cache(key: String, config: Vec<u8>, ttl: Duration) {
    let now = Instant::now();
    let ttl = ttl.clamp(MIN_TTL, MAX_TTL);
    let mut cache = cache().lock().await;
    if cache.values.len() >= CACHE_CAPACITY && !cache.values.contains_key(&key) {
        if let Some(oldest) = cache
            .values
            .iter()
            .min_by_key(|(_, entry)| entry.fetched)
            .map(|(key, _)| key.clone())
        {
            cache.values.remove(&oldest);
        }
    }
    cache.values.insert(
        key,
        CacheEntry {
            config,
            expires: now + ttl,
            fetched: now,
        },
    );
}

fn parse_source(source: &str, default_domain: &str) -> io::Result<(String, String)> {
    let scheme = source
        .find("://")
        .ok_or_else(|| invalid("ECH DNS source has no URL scheme"))?;
    let prefix = &source[..scheme];
    let (domain, endpoint) = if let Some(plus) = prefix.find('+') {
        let domain = source[..plus].trim();
        if domain.is_empty() {
            return Err(invalid("ECH DNS source has an empty domain override"));
        }
        (domain, &source[plus + 1..])
    } else {
        (default_domain.trim(), source)
    };
    if domain.is_empty() || domain.parse::<IpAddr>().is_ok() {
        return Err(invalid(
            "ECH DNS discovery requires a DNS name or an explicit domain+URL source",
        ));
    }
    let endpoint_url =
        Url::parse(endpoint).map_err(|error| invalid(format!("invalid ECH DNS URL: {error}")))?;
    if !matches!(endpoint_url.scheme(), "https" | "h2c" | "udp") {
        return Err(invalid("ECH DNS URL scheme must be https, h2c, or udp"));
    }
    Ok((canonical_domain(domain)?, endpoint_url.to_string()))
}

fn canonical_domain(domain: &str) -> io::Result<String> {
    let url = Url::parse(&format!("https://{domain}/"))
        .map_err(|error| invalid(format!("invalid ECH DNS name {domain:?}: {error}")))?;
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("invalid ECH DNS name {domain:?}")))
}

async fn query_endpoint(endpoint: &str, domain: &str) -> io::Result<(Vec<u8>, Duration)> {
    let endpoint =
        Url::parse(endpoint).map_err(|error| invalid(format!("invalid ECH DNS URL: {error}")))?;
    let id = rand::thread_rng().r#gen::<u16>();
    let query = build_query(id, domain)?;
    let response = match endpoint.scheme() {
        "udp" => query_udp(&endpoint, &query).await?,
        "https" | "h2c" => query_doh(&endpoint, query).await?,
        _ => return Err(invalid("unsupported ECH DNS URL scheme")),
    };
    parse_https_answer(&response, id)
}

fn build_query(id: u16, domain: &str) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(64 + domain.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    let domain = domain.trim_end_matches('.');
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(invalid(format!("invalid DNS label in {domain:?}")));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

async fn query_udp(endpoint: &Url, query: &[u8]) -> io::Result<Vec<u8>> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| invalid("ECH UDP URL has no host"))?;
    let port = endpoint.port().unwrap_or(53);
    let addresses = resolve_host(host, port).await?;
    let mut last_error = None;
    for address in addresses {
        match query_udp_one(address, query).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "ECH UDP resolver has no address",
        )
    }))
}

async fn query_udp_one(address: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let bind = if address.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    let _loopback_guard = prepare_outbound_udp_socket_for_addr(&socket, address)?;
    socket.connect(address)?;
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    tokio::time::timeout(UDP_TIMEOUT, async {
        socket.send(query).await?;
        let mut response = vec![0_u8; MAX_DNS_MESSAGE];
        let length = socket.recv(&mut response).await?;
        response.truncate(length);
        Ok(response)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ECH UDP DNS query timed out"))?
}

async fn query_doh(endpoint: &Url, query: Vec<u8>) -> io::Result<Vec<u8>> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| invalid("ECH DoH URL has no host"))?;
    let tls = endpoint.scheme() == "https";
    let port = endpoint.port().unwrap_or(if tls { 443 } else { 80 });
    let stream = if tls {
        TlsTransport::new(TlsOptions {
            enabled: true,
            sni: Some(host.to_owned()),
            alpn: vec!["h2".into()],
            ..TlsOptions::default()
        })
        .connect(host, port)
        .await?
    } else {
        TcpTransport::default().connect(host, port).await?
    };
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| io::Error::other(format!("ECH DoH HTTP/2 handshake: {error}")))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(target: "dial::ech", %error, "DoH connection closed");
        }
    });
    let path = match endpoint.path() {
        "" | "/" => "/dns-query",
        path => path,
    };
    let path = if let Some(query) = endpoint.query() {
        format!("{path}?{query}")
    } else {
        path.to_owned()
    };
    let authority = endpoint
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::from(query)))
        .map_err(|error| invalid(format!("build ECH DoH request: {error}")))?;
    let response = tokio::time::timeout(DOH_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ECH DoH query timed out"))?
        .map_err(|error| io::Error::other(format!("ECH DoH request: {error}")))?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "ECH DoH returned HTTP {}",
            response.status()
        )));
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            !value
                .to_ascii_lowercase()
                .starts_with("application/dns-message")
        })
    {
        return Err(invalid("ECH DoH response has an unexpected content-type"));
    }
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| io::Error::other(format!("read ECH DoH response: {error}")))?
        .to_bytes();
    if body.len() > MAX_DNS_MESSAGE {
        return Err(invalid("ECH DoH DNS response exceeds 65535 bytes"));
    }
    Ok(body.to_vec())
}

fn parse_https_answer(packet: &[u8], expected_id: u16) -> io::Result<(Vec<u8>, Duration)> {
    if packet.len() < 12 || read_u16(packet, 0)? != expected_id {
        return Err(invalid(
            "ECH DNS response has an invalid header or transaction id",
        ));
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || flags & 0x000f != 0 {
        return Err(invalid(format!(
            "ECH DNS response flags reject query: 0x{flags:04x}"
        )));
    }
    let questions = usize::from(read_u16(packet, 4)?);
    let answers = usize::from(read_u16(packet, 6)?);
    let mut offset = 12;
    for _ in 0..questions {
        offset += encoded_name_len(packet, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= packet.len())
            .ok_or_else(|| invalid("truncated ECH DNS question"))?;
    }
    let mut best: Option<(Vec<u8>, u32, u16)> = None;
    for _ in 0..answers {
        offset += encoded_name_len(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(invalid("truncated ECH DNS answer"));
        }
        let record_type = read_u16(packet, offset)?;
        let class = read_u16(packet, offset + 2)?;
        let ttl = read_u32(packet, offset + 4)?;
        let length = usize::from(read_u16(packet, offset + 8)?);
        offset += 10;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| invalid("truncated ECH DNS RDATA"))?;
        if record_type == DNS_TYPE_HTTPS && class == 1 {
            let priority = read_u16(packet, offset)?;
            let mut cursor = offset + 2;
            cursor += encoded_name_len(packet, cursor)?;
            let mut previous = None;
            while cursor < end {
                if cursor + 4 > end {
                    return Err(invalid("truncated HTTPS SvcParam"));
                }
                let key = read_u16(packet, cursor)?;
                let value_len = usize::from(read_u16(packet, cursor + 2)?);
                cursor += 4;
                let value_end = cursor
                    .checked_add(value_len)
                    .filter(|value_end| *value_end <= end)
                    .ok_or_else(|| invalid("truncated HTTPS SvcParam value"))?;
                if previous.is_some_and(|previous| key <= previous) {
                    return Err(invalid("HTTPS SvcParam keys are not strictly increasing"));
                }
                previous = Some(key);
                if key == SVC_PARAM_ECH && value_len > 0 {
                    let candidate = packet[cursor..value_end].to_vec();
                    if best
                        .as_ref()
                        .is_none_or(|(_, _, best_priority)| priority < *best_priority)
                    {
                        best = Some((candidate, ttl, priority));
                    }
                }
                cursor = value_end;
            }
        }
        offset = end;
    }
    let (config, ttl, _) = best.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HTTPS DNS answer contains no ech SvcParam",
        )
    })?;
    Ok((config, Duration::from_secs(u64::from(ttl))))
}

fn encoded_name_len(packet: &[u8], start: usize) -> io::Result<usize> {
    let mut offset = start;
    loop {
        let length = *packet
            .get(offset)
            .ok_or_else(|| invalid("truncated DNS name"))?;
        if length & 0xc0 == 0xc0 {
            if packet.get(offset + 1).is_none() {
                return Err(invalid("truncated DNS compression pointer"));
            }
            return Ok(offset + 2 - start);
        }
        if length & 0xc0 != 0 {
            return Err(invalid("invalid DNS name label"));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset - start);
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|offset| *offset <= packet.len())
            .ok_or_else(|| invalid("truncated DNS name label"))?;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes: [u8; 2] = packet
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated DNS u16"))?
        .try_into()
        .expect("slice has checked length");
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(packet: &[u8], offset: usize) -> io::Result<u32> {
    let bytes: [u8; 4] = packet
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("truncated DNS u32"))?
        .try_into()
        .expect("slice has checked length");
    Ok(u32::from_be_bytes(bytes))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xray_domain_override() {
        let (domain, endpoint) =
            parse_source("hidden.example+https://1.1.1.1/dns-query", "outer.example").unwrap();
        assert_eq!(domain, "hidden.example");
        assert_eq!(endpoint, "https://1.1.1.1/dns-query");
    }

    #[test]
    fn extracts_ech_svc_param_and_ttl() {
        let id = 0x1234;
        let mut packet = build_query(id, "example.com").unwrap();
        packet[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0xc00c_u16.to_be_bytes());
        packet.extend_from_slice(&DNS_TYPE_HTTPS.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        let ech = [0, 4, 0xfe, 0x0d, 0, 0];
        let rdata_len = 2 + 1 + 2 + 2 + ech.len();
        packet.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.push(0);
        packet.extend_from_slice(&SVC_PARAM_ECH.to_be_bytes());
        packet.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ech);
        let (actual, ttl) = parse_https_answer(&packet, id).unwrap();
        assert_eq!(actual, ech);
        assert_eq!(ttl, Duration::from_secs(120));
    }
}
