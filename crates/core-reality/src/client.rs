use std::collections::HashSet;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL, COOKIE, LOCATION, REFERER, USER_AGENT};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use xray_transport::reality_connector::{
    RealityClientHelloRequest, RealityConnector, RealityHandshakeContext, RealityTlsSessionOutcome,
    RealityTlsSessionProvider,
};
use xray_transport::{
    BoxedTransportStream, RealityClientConfig as XrayRealityClientConfig,
    RustlsRealityTlsSessionProvider,
};
use zeroize::Zeroize;

/// Xray-core 26.7.11 (`6e3322d`) wire version used in the authenticated
/// REALITY session ID. It intentionally is not the WutherCore package version:
/// current Xray servers default to a minimum client version of 26.3.27.
pub const XRAY_REALITY_WIRE_VERSION: [u8; 3] = [26, 7, 11];

const SPIDER_MAX_PADDING_BYTES: i64 = 4 * 1024;
const SPIDER_MAX_CONCURRENCY: i64 = 16;
const SPIDER_MAX_TIMES: i64 = 16;
const SPIDER_MAX_DELAY_MS: i64 = 60_000;
const SPIDER_MAX_BODY_BYTES: usize = 1024 * 1024;
const SPIDER_MAX_PATHS: usize = 256;
const SPIDER_MAX_PATH_BYTES: usize = 2048;
const SPIDER_MAX_REDIRECTS: usize = 10;
const SPIDER_CONNECTION_RETENTION: Duration = Duration::from_secs(5 * 60);

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
    pub mldsa65_verify: Option<Vec<u8>>,
    pub handshake_timeout: Duration,
    pub wire_version: [u8; 3],
}

impl Default for RealityClientConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            fingerprint: "chrome".into(),
            public_key: [0; 32],
            short_id: Vec::new(),
            spider_x: "/".into(),
            mldsa65_verify: None,
            handshake_timeout: Duration::from_secs(10),
            wire_version: XRAY_REALITY_WIRE_VERSION,
        }
    }
}

impl fmt::Debug for RealityClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClientConfig")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("public_key", &"<redacted>")
            .field("short_id", &"<redacted>")
            .field("spider_x", &self.spider_x)
            .field(
                "mldsa65_verify_len",
                &self.mldsa65_verify.as_ref().map(Vec::len),
            )
            .field("handshake_timeout", &self.handshake_timeout)
            .field("wire_version", &self.wire_version)
            .finish()
    }
}

impl Drop for RealityClientConfig {
    fn drop(&mut self) {
        self.public_key.zeroize();
        self.short_id.zeroize();
        if let Some(verify) = &mut self.mldsa65_verify {
            verify.zeroize();
        }
    }
}

impl RealityClientConfig {
    pub fn validate(&self) -> Result<(), RealityClientError> {
        if self.server_name.trim().is_empty() {
            return Err(RealityClientError::Configuration(
                "serverName is empty".into(),
            ));
        }
        if xray_utls::normalize_reality_supported_fingerprint(&self.fingerprint).is_none() {
            return Err(RealityClientError::Configuration(format!(
                "unknown or REALITY-incapable fingerprint `{}`",
                self.fingerprint
            )));
        }
        if self.public_key.iter().all(|byte| *byte == 0) {
            return Err(RealityClientError::Configuration(
                "public key is all zero".into(),
            ));
        }
        if self.short_id.len() > 8 {
            return Err(RealityClientError::Configuration(
                "shortId exceeds 8 bytes".into(),
            ));
        }
        if let Some(verify) = &self.mldsa65_verify
            && verify.len() != 1952
        {
            return Err(RealityClientError::Configuration(
                "mldsa65Verify must contain 1952 bytes".into(),
            ));
        }
        if !self.spider_x.starts_with('/') {
            return Err(RealityClientError::Configuration(
                "spiderX must start with '/'".into(),
            ));
        }
        parse_spider_x(&self.spider_x)?;
        if self.handshake_timeout.is_zero() {
            return Err(RealityClientError::Configuration(
                "handshake timeout is zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySpiderPolicy {
    pub path: String,
    pub padding: (i64, i64),
    pub concurrency: (i64, i64),
    pub times: (i64, i64),
    pub interval_ms: (i64, i64),
    pub return_ms: (i64, i64),
}

/// Parse Xray's `spiderX` query controls (`p/c/t/i/r`). The controls are kept
/// separate from the normalized cover path just like Xray's `SpiderX/SpiderY`.
pub fn parse_spider_x(value: &str) -> Result<RealitySpiderPolicy, RealityClientError> {
    if !value.starts_with('/') {
        return Err(RealityClientError::Configuration(
            "spiderX must start with '/'".into(),
        ));
    }
    let mut url = url::Url::parse(&format!("https://reality.invalid{value}"))
        .map_err(|error| RealityClientError::Configuration(format!("invalid spiderX: {error}")))?;
    let mut query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let take_range = |name: &str| -> (i64, i64) {
        let value = query
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .next()
            .unwrap_or_default();
        if value.is_empty() {
            return (0, 0);
        }
        let values = value.split('-').collect::<Vec<_>>();
        let minimum = values[0].parse::<i64>().unwrap_or(0);
        let maximum = if values.len() == 1 {
            minimum
        } else {
            values[1].parse::<i64>().unwrap_or(0)
        };
        (minimum, maximum)
    };
    let padding = take_range("p");
    let concurrency = take_range("c");
    let times = take_range("t");
    let interval_ms = take_range("i");
    let return_ms = take_range("r");
    query.retain(|(key, _)| !matches!(key.as_str(), "p" | "c" | "t" | "i" | "r"));
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        for (key, value) in query {
            pairs.append_pair(&key, &value);
        }
    }
    let mut path = url.path().to_owned();
    if let Some(query) = url.query()
        && !query.is_empty()
    {
        path.push('?');
        path.push_str(query);
    }
    let policy = RealitySpiderPolicy {
        path,
        padding,
        concurrency,
        times,
        interval_ms,
        return_ms,
    };
    policy.validate_bounds()?;
    Ok(policy)
}

impl RealitySpiderPolicy {
    fn validate_bounds(&self) -> Result<(), RealityClientError> {
        for (name, range, maximum) in [
            ("p", self.padding, SPIDER_MAX_PADDING_BYTES),
            ("c", self.concurrency, SPIDER_MAX_CONCURRENCY),
            ("t", self.times, SPIDER_MAX_TIMES),
            ("i", self.interval_ms, SPIDER_MAX_DELAY_MS),
            ("r", self.return_ms, SPIDER_MAX_DELAY_MS),
        ] {
            if range.0 < 0 || range.1 < 0 || range.0 > maximum || range.1 > maximum {
                return Err(RealityClientError::Configuration(format!(
                    "spiderX query `{name}` must stay within 0..={maximum}"
                )));
            }
        }
        if self.path.len() > SPIDER_MAX_PATH_BYTES {
            return Err(RealityClientError::Configuration(format!(
                "spiderX path exceeds {SPIDER_MAX_PATH_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealityClientError {
    #[error("REALITY client configuration error: {0}")]
    Configuration(String),
    #[error("REALITY client handshake timed out")]
    HandshakeTimeout,
    #[error("REALITY client handshake failed: {0}")]
    Handshake(String),
    #[error("REALITY received a real certificate and started the spiderX cover flow")]
    InvalidConnectionProcessed,
}

/// An optional owner token whose lifetime must match the authenticated carrier
/// or the same-socket spiderX cover flow. The outbound layer uses this to keep
/// its loop-prevention registration alive after the handshake returns.
pub type RealityConnectionLifetime = Arc<dyn Send + Sync + 'static>;

#[derive(Clone)]
pub struct RealityClient {
    config: Arc<RealityClientConfig>,
    provider: RustlsRealityTlsSessionProvider,
    spider_paths: Arc<Mutex<HashSet<String>>>,
}

impl fmt::Debug for RealityClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClient")
            .field("config", &self.config)
            .finish()
    }
}

impl RealityClient {
    pub fn new(config: RealityClientConfig) -> Result<Self, RealityClientError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            provider: RustlsRealityTlsSessionProvider::new(),
            spider_paths: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn config(&self) -> &RealityClientConfig {
        &self.config
    }

    /// Complete a REALITY handshake over an already connected, policy-aware
    /// TCP socket. The returned stream is the authenticated TLS application
    /// stream on the original connection, matching Xray's `uConn` behavior.
    pub async fn connect(
        &self,
        stream: TcpStream,
    ) -> Result<RealityClientStream, RealityClientError> {
        self.connect_with_lifetime(stream, None).await
    }

    pub async fn connect_with_lifetime(
        &self,
        stream: TcpStream,
        lifetime: Option<RealityConnectionLifetime>,
    ) -> Result<RealityClientStream, RealityClientError> {
        let normalized_fingerprint =
            xray_utls::normalize_reality_supported_fingerprint(&self.config.fingerprint)
                .expect("configuration was validated");
        let xray_config = XrayRealityClientConfig {
            server_name: self.config.server_name.clone(),
            fingerprint: normalized_fingerprint.to_owned(),
            public_key: self.config.public_key,
            short_id: self.config.short_id.clone(),
            spider_x: self.config.spider_x.clone(),
            mldsa65_verify: self.config.mldsa65_verify.clone(),
        };
        let connector = RealityConnector::new(xray_config.clone());
        let session = self
            .provider
            .create_session(RealityClientHelloRequest {
                server_name: &xray_config.server_name,
                fingerprint: &xray_config.fingerprint,
            })
            .map_err(|error| RealityClientError::Handshake(error.to_string()))?;
        let prepared_client_hello = session
            .prepared_client_hello()
            .map_err(|error| RealityClientError::Handshake(error.to_string()))?;
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(u32::MAX as u64) as u32);
        let prepared = connector
            .prepare_handshake_with_client_hello(
                prepared_client_hello,
                RealityHandshakeContext {
                    version: self.config.wire_version,
                    unix_time,
                },
            )
            .map_err(|error| RealityClientError::Handshake(error.to_string()))?;
        let complete =
            session.complete_with_outcome(stream, prepared, xray_config.mldsa65_verify.clone());
        let completion = tokio::time::timeout(self.config.handshake_timeout, complete)
            .await
            .map_err(|_| RealityClientError::HandshakeTimeout)?;
        match completion {
            Ok(RealityTlsSessionOutcome::Verified(inner)) => Ok(RealityClientStream {
                inner,
                _lifetime: lifetime,
            }),
            Ok(RealityTlsSessionOutcome::NotReality(inner)) => {
                let policy =
                    parse_spider_x(&self.config.spider_x).expect("configuration validated spiderX");
                let server_name = self.config.server_name.clone();
                let paths = self.spider_paths.clone();
                let crawler_policy = policy.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        crawl_cover_site(inner, &server_name, crawler_policy, paths, lifetime).await
                    {
                        tracing::debug!(
                            target: "reality::spider",
                            %error,
                            "REALITY spiderX cover flow ended"
                        );
                    }
                });
                let return_delay = sample_xray_range(policy.return_ms);
                if return_delay != 0 {
                    tokio::time::sleep(Duration::from_millis(return_delay)).await;
                }
                Err(RealityClientError::InvalidConnectionProcessed)
            }
            Err(error) => Err(RealityClientError::Handshake(error.to_string())),
        }
    }
}

fn sample_xray_range(range: (i64, i64)) -> u64 {
    let (minimum, maximum) = if range.0 <= range.1 {
        range
    } else {
        (range.1, range.0)
    };
    let sampled = if minimum == maximum {
        minimum
    } else {
        rand::random_range(minimum..maximum)
    };
    u64::try_from(sampled).expect("validated spider range is non-negative")
}

async fn crawl_cover_site(
    tls_stream: BoxedTransportStream,
    server_name: &str,
    policy: RealitySpiderPolicy,
    paths: Arc<Mutex<HashSet<String>>>,
    lifetime: Option<RealityConnectionLifetime>,
) -> io::Result<()> {
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tls_stream))
        .await
        .map_err(|error| io::Error::other(format!("spiderX HTTP/2 handshake: {error}")))?;
    let keepalive_sender = sender.clone();
    tokio::spawn(async move {
        // Xray deliberately does not close a non-REALITY connection after its
        // cover requests. Retain the HTTP/2 sender and outbound owner token for
        // a bounded interval so malformed peers cannot leak resources forever.
        let _keepalive_sender = keepalive_sender;
        let _lifetime = lifetime;
        match tokio::time::timeout(SPIDER_CONNECTION_RETENTION, connection).await {
            Ok(Err(error)) => {
                tracing::debug!(
                    target: "reality::spider",
                    %error,
                    "spiderX HTTP/2 connection closed"
                );
            }
            Ok(Ok(())) | Err(_) => {}
        }
    });

    {
        let mut known = paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        known.insert(policy.path.clone());
    }
    let first_path = policy.path.clone();
    spider_request_series(
        sender.clone(),
        server_name.to_owned(),
        first_path.clone(),
        first_path.clone(),
        true,
        policy.clone(),
        paths.clone(),
    )
    .await?;

    let concurrency = sample_xray_range(policy.concurrency) as usize;
    for _ in 0..concurrency {
        let sender = sender.clone();
        let server_name = server_name.to_owned();
        let policy = policy.clone();
        let paths = paths.clone();
        let first_path = first_path.clone();
        let start_path = choose_spider_path(&paths);
        tokio::spawn(async move {
            if let Err(error) = spider_request_series(
                sender,
                server_name,
                first_path,
                start_path,
                false,
                policy,
                paths,
            )
            .await
            {
                tracing::debug!(
                    target: "reality::spider",
                    %error,
                    "spiderX worker ended"
                );
            }
        });
    }
    Ok(())
}

async fn spider_request_series(
    mut sender: http2::SendRequest<Empty<Bytes>>,
    server_name: String,
    first_path: String,
    mut path: String,
    first: bool,
    policy: RealitySpiderPolicy,
    paths: Arc<Mutex<HashSet<String>>>,
) -> io::Result<()> {
    let times = if first {
        1
    } else {
        sample_xray_range(policy.times) as usize
    };
    let mut referer = (!first).then(|| absolute_spider_uri(&server_name, &first_path));
    for _ in 0..times {
        let padding = sample_xray_range(policy.padding) as usize;
        let current_uri = absolute_spider_uri(&server_name, &path);
        let request = spider_request(&current_uri, referer.as_deref(), padding)?;
        sender
            .ready()
            .await
            .map_err(|error| io::Error::other(format!("spiderX HTTP/2 sender: {error}")))?;
        let (response_path, body) =
            send_spider_request_with_redirects(&mut sender, request, &server_name, path.clone())
                .await?;
        discover_spider_paths(&server_name, &body, &paths);
        referer = Some(absolute_spider_uri(&server_name, &response_path));
        path = choose_spider_path(&paths);
        if !first {
            let interval = sample_xray_range(policy.interval_ms);
            if interval != 0 {
                tokio::time::sleep(Duration::from_millis(interval)).await;
            }
        }
    }
    Ok(())
}

fn spider_request(
    uri: &str,
    referer: Option<&str>,
    padding: usize,
) -> io::Result<Request<Empty<Bytes>>> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        )
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(CACHE_CONTROL, "max-age=0")
        .header("upgrade-insecure-requests", "1")
        .header(
            ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        )
        .header("sec-fetch-site", "none")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-user", "?1")
        .header("sec-fetch-dest", "document")
        .header("priority", "u=0, i")
        .header("dnt", "1")
        .header(COOKIE, format!("padding={}", "0".repeat(padding)));
    if let Some(referer) = referer {
        builder = builder.header(REFERER, referer);
    }
    builder
        .body(Empty::new())
        .map_err(|error| invalid_input(format!("invalid spiderX request: {error}")))
}

async fn send_spider_request_with_redirects(
    sender: &mut http2::SendRequest<Empty<Bytes>>,
    mut request: Request<Empty<Bytes>>,
    server_name: &str,
    mut current_path: String,
) -> io::Result<(String, Vec<u8>)> {
    for redirects in 0..=SPIDER_MAX_REDIRECTS {
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| io::Error::other(format!("spiderX request: {error}")))?;
        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = read_spider_body(response.into_body()).await?;
        if !is_redirect_status(status) {
            return Ok((current_path, body));
        }
        if redirects == SPIDER_MAX_REDIRECTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spiderX redirect limit exceeded",
            ));
        }
        let location = location
            .ok_or_else(|| invalid_data("spiderX redirect response has no Location header"))?;
        current_path = same_origin_spider_path(server_name, &current_path, &location)?;
        request = spider_request(&absolute_spider_uri(server_name, &current_path), None, 0)?;
    }
    unreachable!("redirect loop returns within configured bound")
}

async fn read_spider_body(mut body: hyper::body::Incoming) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| io::Error::other(format!("spiderX body: {error}")))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if output.len().saturating_add(data.len()) > SPIDER_MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("spiderX response exceeds {SPIDER_MAX_BODY_BYTES} bytes"),
            ));
        }
        output.extend_from_slice(&data);
    }
    Ok(output)
}

fn discover_spider_paths(server_name: &str, body: &[u8], paths: &Arc<Mutex<HashSet<String>>>) {
    let expression = Regex::new(r#"href="([/h].*?)""#).expect("static spiderX href regex");
    let prefix = format!("https://{server_name}");
    let mut paths = paths
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if paths.len() >= SPIDER_MAX_PATHS {
        return;
    }
    for capture in expression.captures_iter(body) {
        let Some(captured) = capture.get(1) else {
            continue;
        };
        let Ok(captured) = std::str::from_utf8(captured.as_bytes()) else {
            continue;
        };
        let candidate = captured.strip_prefix(&prefix).unwrap_or(captured);
        if !candidate.starts_with('/')
            || candidate.contains('.')
            || candidate.len() > SPIDER_MAX_PATH_BYTES
        {
            continue;
        }
        paths.insert(candidate.to_owned());
        if paths.len() >= SPIDER_MAX_PATHS {
            break;
        }
    }
}

fn choose_spider_path(paths: &Arc<Mutex<HashSet<String>>>) -> String {
    let paths = paths
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if paths.is_empty() {
        return "/".to_owned();
    }
    let index = if paths.len() == 1 {
        0
    } else {
        rand::random_range(0..paths.len())
    };
    paths
        .iter()
        .nth(index)
        .cloned()
        .unwrap_or_else(|| "/".to_owned())
}

fn absolute_spider_uri(server_name: &str, path: &str) -> String {
    format!("https://{server_name}{path}")
}

fn same_origin_spider_path(
    server_name: &str,
    current_path: &str,
    location: &str,
) -> io::Result<String> {
    let base = url::Url::parse(&absolute_spider_uri(server_name, current_path))
        .map_err(|error| invalid_data(format!("invalid spiderX redirect base: {error}")))?;
    let redirect = base
        .join(location)
        .map_err(|error| invalid_data(format!("invalid spiderX redirect: {error}")))?;
    if redirect.scheme() != "https"
        || redirect.host_str() != Some(server_name)
        || !matches!(redirect.port(), None | Some(443))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "spiderX refused a cross-origin redirect",
        ));
    }
    let mut path = redirect.path().to_owned();
    if let Some(query) = redirect.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.len() > SPIDER_MAX_PATH_BYTES {
        return Err(invalid_data("spiderX redirect path is too long"));
    }
    Ok(path)
}

fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// Authenticated REALITY application stream. Like Xray's `uConn`, inner
/// VLESS/XHTTP bytes remain TLS application data after the REALITY-specific
/// certificate binding succeeds.
pub struct RealityClientStream {
    inner: BoxedTransportStream,
    _lifetime: Option<RealityConnectionLifetime>,
}

impl fmt::Debug for RealityClientStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClientStream")
            .finish_non_exhaustive()
    }
}

impl AsyncRead for RealityClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for RealityClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spider_x_controls_are_removed_from_cover_path() {
        let policy = parse_spider_x("/news?a=b&p=10-20&c=2&t=3&i=40&r=5").unwrap();
        assert_eq!(policy.path, "/news?a=b");
        assert_eq!(policy.padding, (10, 20));
        assert_eq!(policy.concurrency, (2, 2));
        assert_eq!(policy.times, (3, 3));
        assert_eq!(policy.interval_ms, (40, 40));
        assert_eq!(policy.return_ms, (5, 5));
    }

    #[test]
    fn spider_x_parser_matches_xray_first_value_and_parse_zero_behavior() {
        let policy = parse_spider_x("/x?p=bad&p=4&c=8-2&t=3-9-extra").unwrap();
        assert_eq!(policy.path, "/x");
        assert_eq!(policy.padding, (0, 0));
        assert_eq!(policy.concurrency, (8, 2));
        assert_eq!(policy.times, (3, 9));
        for _ in 0..32 {
            let value = sample_xray_range(policy.concurrency);
            assert!((2..8).contains(&value));
        }
    }

    #[test]
    fn spider_x_resource_bounds_fail_at_configuration_time() {
        for value in ["/?p=4097", "/?c=17", "/?t=17", "/?i=60001", "/?r=60001"] {
            assert!(parse_spider_x(value).is_err(), "{value}");
        }
    }

    #[test]
    fn spider_discovers_only_bounded_same_origin_extensionless_paths() {
        let paths = Arc::new(Mutex::new(HashSet::new()));
        discover_spider_paths(
            "example.com",
            br#"<a href="/news">ok</a><a href="https://example.com/docs">ok</a><a href="/app.js">no</a><a href="https://evil.test/x">no</a>"#,
            &paths,
        );
        let paths = paths.lock().unwrap();
        assert!(paths.contains("/news"));
        assert!(paths.contains("/docs"));
        assert!(!paths.contains("/app.js"));
        assert!(!paths.iter().any(|path| path.contains("evil")));
    }

    #[test]
    fn spider_redirects_are_same_origin_and_https_only() {
        assert_eq!(
            same_origin_spider_path("example.com", "/a/start", "../next?q=1").unwrap(),
            "/next?q=1"
        );
        assert!(same_origin_spider_path("example.com", "/", "https://evil.test/").is_err());
        assert!(same_origin_spider_path("example.com", "/", "http://example.com/").is_err());
    }

    #[test]
    fn config_rejects_known_non_reality_fingerprint() {
        let mut config = RealityClientConfig::default();
        config.server_name = "example.com".into();
        config.fingerprint = "android".into();
        config.public_key = [1; 32];
        assert!(matches!(
            config.validate(),
            Err(RealityClientError::Configuration(_))
        ));
    }

    #[test]
    fn config_debug_redacts_key_material() {
        let mut config = RealityClientConfig::default();
        config.server_name = "example.com".into();
        config.public_key = [7; 32];
        config.short_id = vec![1, 2, 3];
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[7, 7, 7"));
    }
}
