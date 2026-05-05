//! core-fetch —— WutherCore 内置 HTTP/1.1 GET client。
//!
//! ## 为什么自研而不是 reqwest
//! reqwest 0.12 暴露的 `ClientBuilder::interface(name)` 仅在 Linux/Android/
//! macOS/iOS 等启用，Windows 没暴露 `IP_UNICAST_IF` / `IPV6_UNICAST_IF` 注入点
//! ——也没暴露任何能替换 socket 创建路径的钩子（`connector_layer` 只能包装
//! 现有 connector，无法拦截到 TCP 创建）。结果：Windows 上订阅 / 规则集
//! 拉取的 TCP socket 全部经 TUN，再被 `is_inner_source` 安全网捕获回流，
//! 多 2 段 user-stack 中转，每个字节绕远路。
//!
//! 本 crate 直接走 hyper 1.x 的 `client::conn::http1::handshake` + 自己的
//! TCP/TLS 创建逻辑：socket 一开局就调 `core_outbound::bind_outbound_socket`，
//! 把 IP_UNICAST_IF / IP_BOUND_IF / SO_BINDTODEVICE 全打齐，四大平台都真正
//! 绕过 TUN，不依赖 safety net。
//!
//! ## 范围
//! 订阅 / 规则集拉取场景的最小子集：HTTP/1.1 GET（with redirects）、
//! HTTPS via tokio-rustls、超时、自定义 header、gzip / br 解压。
//! 不实现：HTTP/2、cookies、连接池（per-request 临时连接已够用，订阅 /
//! 规则集是低频拉取）、proxy。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

const DEFAULT_MAX_REDIRECTS: u8 = 5;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 一次拉取的输入。`headers` 顺序保留，用于服务器对 header 顺序敏感的场景。
#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub user_agent: String,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_redirects: u8,
    pub headers: Vec<(String, String)>,
    /// `Accept-Encoding: gzip, br` —— 关掉就让上游不压缩，省掉本地解压。
    pub accept_encoding: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            user_agent: format!("WutherCore-fetch/{}", env!("CARGO_PKG_VERSION")),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            headers: Vec::new(),
            accept_encoding: true,
        }
    }
}

/// 一次拉取的输出。`headers` 已经按 lower-case key 去重 —— 调用者 lookup 不
/// 需要再 to_ascii_lowercase。`bytes` 已经按 Content-Encoding 解压。
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub status: u16,
    pub final_url: String,
    pub headers: HashMap<String, String>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("不支持的 scheme: {0}")]
    UnsupportedScheme(String),
    #[error("DNS 解析失败: {0}")]
    Resolve(#[source] std::io::Error),
    #[error("TCP connect 失败: {0}")]
    Connect(#[source] std::io::Error),
    #[error("TLS handshake 失败: {0}")]
    Tls(String),
    #[error("HTTP 协议错误: {0}")]
    Http(String),
    #[error("非 2xx 状态: {0}")]
    Status(u16),
    #[error("超时")]
    Timeout,
    #[error("超过最大重定向次数 ({0})")]
    TooManyRedirects(u8),
    #[error("解压失败: {0}")]
    Decompress(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

/// 顶层入口：抓取一个 URL，返回最终响应（已自动 follow 重定向、解压）。
///
/// 任何 5xx / 4xx 都会以 `FetchError::Status(code)` 返回；调用方需要拿原始
/// status 时改用 [`fetch_raw`]。
pub async fn fetch(url: &str, opts: &FetchOptions) -> Result<FetchResult, FetchError> {
    let r = fetch_raw(url, opts).await?;
    let code = r.status;
    if !(200..300).contains(&code) {
        return Err(FetchError::Status(code));
    }
    Ok(r)
}

/// 同 [`fetch`]，但任何 status 都返回 `Ok` —— 调用方自己判断。
pub async fn fetch_raw(url: &str, opts: &FetchOptions) -> Result<FetchResult, FetchError> {
    let total = opts.timeout;
    tokio::time::timeout(total, fetch_inner(url, opts))
        .await
        .map_err(|_| FetchError::Timeout)?
}

async fn fetch_inner(url: &str, opts: &FetchOptions) -> Result<FetchResult, FetchError> {
    let mut current = url.to_string();
    for hop in 0..opts.max_redirects {
        debug!(target: "fetch", url = %current, hop, "GET");
        let parsed = url::Url::parse(&current).map_err(|e| FetchError::BadUrl(e.to_string()))?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(FetchError::UnsupportedScheme(scheme.to_string()));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| FetchError::BadUrl("missing host".into()))?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| FetchError::BadUrl("unknown port for scheme".into()))?;
        let is_https = scheme == "https";

        // 1) 解析 host —— 走 core_outbound 的全局 DialResolver（避开 fake-IP 自循环）。
        let addrs = core_outbound::resolve_host(&host, port)
            .await
            .map_err(FetchError::Resolve)?;
        let peer = *addrs
            .first()
            .ok_or_else(|| FetchError::Resolve(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address resolved",
            )))?;

        // 2) 开 TCP 走 bind_outbound_socket —— 这才是本 crate 存在的核心理由。
        let tcp = tokio::time::timeout(opts.connect_timeout, connect_tcp_outbound_bound(peer))
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(FetchError::Connect)?;

        // 3) HTTPS 时套 rustls。
        let resp_parts = if is_https {
            let connector = TlsConnector::from(tls_config());
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| FetchError::Tls(format!("invalid SNI: {e}")))?;
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            send_request(TokioIo::new(tls), &parsed, &host, opts).await?
        } else {
            send_request(TokioIo::new(tcp), &parsed, &host, opts).await?
        };

        let status = resp_parts.status;
        if (300..400).contains(&status) && status != 304 {
            if let Some(loc) = resp_parts.headers.get("location") {
                // 解决相对 URL：以当前 URL 为 base。
                let base =
                    url::Url::parse(&current).map_err(|e| FetchError::BadUrl(e.to_string()))?;
                let next = base
                    .join(loc)
                    .map_err(|e| FetchError::BadUrl(format!("redirect target invalid: {e}")))?
                    .to_string();
                debug!(target: "fetch", from = %current, to = %next, status, hop, "redirect");
                current = next;
                continue;
            }
        }
        return Ok(FetchResult {
            status,
            final_url: current,
            headers: resp_parts.headers,
            bytes: resp_parts.body,
        });
    }
    Err(FetchError::TooManyRedirects(opts.max_redirects))
}

/// 把已建好的 TLS / TCP stream 走 hyper http1 handshake，发一次 GET，
/// 收完整 body，按 Content-Encoding 解压，返回 (status, headers, body)。
async fn send_request<S>(
    io: TokioIo<S>,
    parsed: &url::Url,
    host: &str,
    opts: &FetchOptions,
) -> Result<RawResp, FetchError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .map_err(|e| FetchError::Http(format!("handshake: {e}")))?;
    // hyper 把 IO loop 留给调用方驱动。spawn 后丢手；handshake 完成的 conn
    // 在 sender drop / EOF 时自然退出。
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(target: "fetch", error = %e, "hyper conn ended");
        }
    });

    // 构造 request URI —— path + query。host 走 Host header 而不是 absolute URI。
    let path_query = parsed
        .path()
        .to_string()
        + parsed.query().map(|q| format!("?{q}")).unwrap_or_default().as_str();
    let uri: Uri = path_query
        .parse()
        .map_err(|e: http::uri::InvalidUri| FetchError::BadUrl(e.to_string()))?;

    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::HOST, host_header)
        .header(header::USER_AGENT, &opts.user_agent)
        .header(header::CONNECTION, "close");
    if opts.accept_encoding {
        req = req.header(header::ACCEPT_ENCODING, "gzip, br");
    }
    for (k, v) in &opts.headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| FetchError::Http(format!("bad header name {k}: {e}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|e| FetchError::Http(format!("bad header value {v}: {e}")))?;
        req = req.header(name, value);
    }
    let request = req
        .body(Empty::<Bytes>::new())
        .map_err(|e| FetchError::Http(format!("build request: {e}")))?;

    let resp = sender
        .send_request(request)
        .await
        .map_err(|e| FetchError::Http(format!("send_request: {e}")))?;
    let status = resp.status().as_u16();
    let headers = response_headers_lower(resp.headers());
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| FetchError::Http(format!("read body: {e}")))?;
    let raw = collected.to_bytes().to_vec();
    let body = decode_body(&raw, headers.get("content-encoding").map(String::as_str))?;
    Ok(RawResp {
        status,
        headers,
        body,
    })
}

struct RawResp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn response_headers_lower(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(headers.len());
    for (name, value) in headers {
        // 只取 valid UTF-8 的 header value；非 UTF-8 的（罕见）忽略，
        // 反正 fetcher 用得到的 ETag / Content-Type / Subscription-Userinfo
        // 全部是 ASCII。
        if let Ok(s) = value.to_str() {
            out.insert(name.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    out
}

fn decode_body(raw: &[u8], encoding: Option<&str>) -> Result<Vec<u8>, FetchError> {
    use std::io::Read;
    match encoding.map(|s| s.trim().to_ascii_lowercase()) {
        Some(ref enc) if enc == "gzip" => {
            let mut out = Vec::with_capacity(raw.len() * 4);
            flate2::read::GzDecoder::new(raw)
                .read_to_end(&mut out)
                .map_err(|e| FetchError::Decompress(format!("gzip: {e}")))?;
            Ok(out)
        }
        Some(ref enc) if enc == "br" => {
            let mut out = Vec::with_capacity(raw.len() * 4);
            brotli::Decompressor::new(raw, 4096)
                .read_to_end(&mut out)
                .map_err(|e| FetchError::Decompress(format!("brotli: {e}")))?;
            Ok(out)
        }
        Some(ref enc) if enc == "identity" || enc.is_empty() => Ok(raw.to_vec()),
        Some(other) => {
            warn!(target: "fetch", encoding = %other, "unknown content-encoding, returning raw");
            Ok(raw.to_vec())
        }
        None => Ok(raw.to_vec()),
    }
}

/// 创建 outbound TCP —— 关键点：bind_outbound_socket 在 connect 之前调用，
/// 把 IP_UNICAST_IF / IP_BOUND_IF / SO_BINDTODEVICE 一齐打上。
///
/// 流程：
/// 1. socket2 创建 socket 并打好 ifindex / mark / protect
/// 2. set_nonblocking
/// 3. socket2 connect（nonblocking 模式，立即返回 EINPROGRESS / WOULDBLOCK）
/// 4. 把裸 socket 交给 tokio TcpStream，等 WRITABLE 就绪
/// 5. 检 SO_ERROR 区分"连上了"与"被拒"
async fn connect_tcp_outbound_bound(
    peer: std::net::SocketAddr,
) -> std::io::Result<TcpStream> {
    use socket2::SockAddr;
    use std::io::ErrorKind;
    use tokio::io::Interest;

    let domain = if peer.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    core_outbound::protect_socket(&sock)?;
    if let Err(e) = core_outbound::apply_outbound_mark_for_addr(&sock, peer) {
        // SO_MARK 失败在没配 fwmark 的 Windows / macOS 上是预期；降级 debug。
        debug!(target: "fetch", error = %e, peer = %peer, "apply_outbound_mark non-fatal");
    }
    if let Err(e) = core_outbound::bind_outbound_socket(&sock, peer) {
        debug!(target: "fetch", error = %e, peer = %peer, "bind_outbound_socket non-fatal");
    }
    sock.set_nonblocking(true)?;
    match sock.connect(&SockAddr::from(peer)) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        // Unix 平台 EINPROGRESS；Windows 已被 socket2 映射成 WouldBlock 上面捕获。
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)?;
    // 等 socket WRITABLE —— 等价于 connect 完成。
    let _ = stream.ready(Interest::WRITABLE).await?;
    // 检 SO_ERROR 区分连上 / 被拒。
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}

/// rustls 客户端 config —— webpki-roots 静态 CA。Lazy 初始化，进程内一份。
fn tls_config() -> Arc<ClientConfig> {
    use once_cell::sync::Lazy;
    static CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    });
    CONFIG.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_options_default_values() {
        let o = FetchOptions::default();
        assert!(o.user_agent.starts_with("WutherCore-fetch/"));
        assert_eq!(o.max_redirects, 5);
        assert_eq!(o.timeout, Duration::from_secs(30));
        assert!(o.accept_encoding);
    }

    #[test]
    fn decode_identity_returns_input() {
        let raw = b"hello world";
        let out = decode_body(raw, None).unwrap();
        assert_eq!(out, raw);
        let out = decode_body(raw, Some("identity")).unwrap();
        assert_eq!(out, raw);
        let out = decode_body(raw, Some("")).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn decode_unknown_encoding_returns_raw() {
        let raw = b"compressed-by-aliens";
        let out = decode_body(raw, Some("zstd")).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn decode_gzip_round_trips() {
        use std::io::Write;
        let payload = b"some text that is sufficiently long to compress reasonably";
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(payload).unwrap();
        let compressed = e.finish().unwrap();
        let decoded = decode_body(&compressed, Some("gzip")).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn response_headers_are_lowercased_and_deduped() {
        use http::HeaderName;
        let mut h = HeaderMap::new();
        h.insert(HeaderName::from_static("etag"), "\"abc\"".parse().unwrap());
        h.insert(HeaderName::from_static("content-type"), "text/plain".parse().unwrap());
        let map = response_headers_lower(&h);
        assert_eq!(map.get("etag"), Some(&"\"abc\"".to_string()));
        assert_eq!(map.get("content-type"), Some(&"text/plain".to_string()));
    }
}
