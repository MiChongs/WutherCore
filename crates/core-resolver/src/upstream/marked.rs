//! 带 SO_MARK 的 DNS 上游 —— 替代 hickory-resolver 原生 socket。
//!
//! mihomo 的 DNS client 全部经过自定义 `DNSDialer`，可以 `setsockopt(SO_MARK)`
//! 让 TUN auto_route 的 fwmark 规则正确生效。hickory-resolver 内部创建 raw tokio
//! socket，无注入点，无法打 mark —— TUN 启用后 DNS 出站被 catch-all 截走导致
//! 解析超时或自循环。本模块用 `hickory_resolver::proto` 编解码 + 自建 marked
//! socket 完成同样功能，与 mihomo `dns/client.go` 对齐。

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, Record, RecordType},
    serialize::binary::BinDecodable,
};
use tokio::net::UdpSocket;

use super::{DnsError, DnsUpstream};

const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_MAX_RESPONSE: usize = 4096;

/// 由调用方注入：创建已打 SO_MARK + protect + SO_BINDTODEVICE 的 socket。
/// `core-runtime` 启动时把 `core-outbound` 的 dialer 桥接进来，
/// `core-resolver` 本身不依赖 `core-outbound`。
pub trait DnsSocketFactory: Send + Sync + 'static {
    fn create_udp(&self, peer: SocketAddr) -> std::io::Result<std::net::UdpSocket>;

    fn create_tcp(&self, peer: SocketAddr) -> std::io::Result<std::net::TcpStream>;
}

static SOCKET_FACTORY: std::sync::OnceLock<Arc<dyn DnsSocketFactory>> = std::sync::OnceLock::new();

pub fn set_dns_socket_factory(f: Arc<dyn DnsSocketFactory>) {
    let _ = SOCKET_FACTORY.set(f);
}

fn create_marked_udp(peer: SocketAddr) -> std::io::Result<UdpSocket> {
    let factory = SOCKET_FACTORY.get();
    let std_sock = if let Some(f) = factory {
        f.create_udp(peer)?
    } else {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        std::net::UdpSocket::bind(bind)?
    };
    std_sock.connect(peer)?;
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

fn create_marked_tcp(peer: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let factory = SOCKET_FACTORY.get();
    let std_sock = if let Some(f) = factory {
        f.create_tcp(peer)?
    } else {
        let sock = std::net::TcpStream::connect(peer)?;
        sock
    };
    std_sock.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(std_sock)
}

fn build_query(host: &str, qtype: RecordType) -> Result<Vec<u8>, DnsError> {
    let name = Name::from_ascii(host.trim_end_matches('.'))
        .map_err(|e| DnsError::Failed(format!("invalid DNS name: {e}")))?;
    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, qtype));
    msg.to_vec()
        .map_err(|e| DnsError::Failed(format!("DNS encode: {e}")))
}

fn parse_response(buf: &[u8], qtype: RecordType) -> Result<Vec<IpAddr>, DnsError> {
    let msg = Message::from_bytes(buf).map_err(|e| DnsError::Failed(format!("DNS decode: {e}")))?;
    let mut ips = Vec::new();
    for answer in msg.answers() {
        match (qtype, answer.data()) {
            (RecordType::A, Some(RData::A(a))) => ips.push(IpAddr::V4(a.0)),
            (RecordType::AAAA, Some(RData::AAAA(a))) => ips.push(IpAddr::V6(a.0)),
            _ => {}
        }
    }
    if ips.is_empty() {
        Err(DnsError::Empty)
    } else {
        Ok(ips)
    }
}

fn parse_records(buf: &[u8]) -> Result<Vec<Record>, DnsError> {
    let msg = Message::from_bytes(buf).map_err(|e| DnsError::Failed(format!("DNS decode: {e}")))?;
    let records = msg.answers().to_vec();
    if records.is_empty() {
        Err(DnsError::Empty)
    } else {
        Ok(records)
    }
}

fn rand_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    n ^ (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16)
}

#[derive(Debug, Clone)]
pub struct MarkedDnsUpstream {
    name: String,
    addr: SocketAddr,
    client_subnet: Option<ipnet::IpNet>,
}

impl MarkedDnsUpstream {
    pub fn new(name: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            addr,
            client_subnet: None,
        }
    }

    pub fn with_client_subnet(mut self, net: ipnet::IpNet) -> Self {
        self.client_subnet = Some(net);
        self
    }

    async fn exchange(&self, qtype: RecordType, host: &str) -> Result<Vec<u8>, DnsError> {
        let query_buf = build_query(host, qtype)?;
        let sock = create_marked_udp(self.addr)
            .map_err(|e| DnsError::Failed(format!("DNS socket: {e}")))?;
        sock.send(&query_buf)
            .await
            .map_err(|e| DnsError::Failed(format!("DNS send: {e}")))?;
        let mut buf = vec![0u8; DNS_MAX_RESPONSE];
        let n = match tokio::time::timeout(DNS_QUERY_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(DnsError::Failed(format!("DNS recv: {e}"))),
            Err(_) => return Err(DnsError::Timeout),
        };
        Ok(buf[..n].to_vec())
    }
}

#[async_trait]
impl DnsUpstream for MarkedDnsUpstream {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "udp-marked"
    }
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.client_subnet
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let resp = self.exchange(RecordType::A, host).await?;
        parse_response(&resp, RecordType::A)
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let resp = self.exchange(RecordType::AAAA, host).await?;
        parse_response(&resp, RecordType::AAAA)
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let resp = self.exchange(record_type, host).await?;
        parse_records(&resp)
    }
}

/// TCP DNS 上游（plain TCP 或 DoT）—— 使用 marked TCP socket。
///
/// DNS-over-TCP 协议：2 字节 big-endian 长度前缀 + DNS message。
/// DoT 在 TCP 之上加 TLS（由 `tls_name` 参数控制）。
/// DoT 模式支持连接池复用以减少 TLS 握手开销。
pub struct MarkedTcpDnsUpstream {
    name: String,
    addr: SocketAddr,
    tls_name: Option<String>,
    client_subnet: Option<ipnet::IpNet>,
    pool: Option<Arc<DotConnectionPool>>,
}

impl std::fmt::Debug for MarkedTcpDnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkedTcpDnsUpstream")
            .field("name", &self.name)
            .field("addr", &self.addr)
            .field("tls_name", &self.tls_name)
            .field("pooled", &self.pool.is_some())
            .finish()
    }
}

struct DotConnectionPool {
    connections: tokio::sync::Mutex<std::collections::VecDeque<PooledTlsConn>>,
    max_idle: usize,
    max_age: Duration,
}

impl DotConnectionPool {
    /// Drop all pooled connections — called on network interface change
    /// to force re-establishment on the new interface.
    async fn drain(&self) {
        let mut conns = self.connections.lock().await;
        conns.clear();
    }
}

struct PooledTlsConn {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    created: std::time::Instant,
}

impl DotConnectionPool {
    fn new(max_idle: usize, max_age: Duration) -> Self {
        Self {
            connections: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
            max_idle,
            max_age,
        }
    }

    async fn acquire(&self) -> Option<PooledTlsConn> {
        let mut conns = self.connections.lock().await;
        while let Some(conn) = conns.pop_back() {
            if conn.created.elapsed() < self.max_age {
                return Some(conn);
            }
            // Stale connection, drop it
        }
        None
    }

    async fn release(&self, conn: PooledTlsConn) {
        if conn.created.elapsed() >= self.max_age {
            return;
        }
        let mut conns = self.connections.lock().await;
        if conns.len() < self.max_idle {
            conns.push_back(conn);
        }
    }
}

impl MarkedTcpDnsUpstream {
    pub fn tcp(name: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            addr,
            tls_name: None,
            client_subnet: None,
            pool: None,
        }
    }

    pub fn dot(name: impl Into<String>, addr: SocketAddr, sni: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            addr,
            tls_name: Some(sni.into()),
            client_subnet: None,
            pool: Some(Arc::new(DotConnectionPool::new(8, Duration::from_secs(90)))),
        }
    }

    pub fn dot_no_pool(name: impl Into<String>, addr: SocketAddr, sni: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            addr,
            tls_name: Some(sni.into()),
            client_subnet: None,
            pool: None,
        }
    }

    pub fn with_client_subnet(mut self, net: ipnet::IpNet) -> Self {
        self.client_subnet = Some(net);
        self
    }

    async fn exchange(&self, qtype: RecordType, host: &str) -> Result<Vec<u8>, DnsError> {
        let query_buf = build_query(host, qtype)?;

        if let Some(ref sni) = self.tls_name {
            if sni.is_empty() {
                return Err(DnsError::Failed("DoT SNI is empty".into()));
            }

            // Try pooled connection first
            if let Some(pool) = &self.pool {
                if let Some(mut conn) = pool.acquire().await {
                    match self.exchange_on_stream(&mut conn.stream, &query_buf).await {
                        Ok(resp) => {
                            pool.release(conn).await;
                            return Ok(resp);
                        }
                        Err(_) => {
                            // Pooled connection failed; fall through to new connection
                        }
                    }
                }
            }

            // Create new TLS connection
            let tcp = create_marked_tcp(self.addr)
                .map_err(|e| DnsError::Failed(format!("DNS TCP connect: {e}")))?;
            let connector = build_tls_connector();
            let server_name = rustls::pki_types::ServerName::try_from(sni.as_str())
                .map_err(|e| DnsError::Failed(format!("DoT SNI '{sni}': {e}")))?
                .to_owned();
            let mut stream = tokio_rustls::TlsConnector::from(connector)
                .connect(server_name, tcp)
                .await
                .map_err(|e| DnsError::Failed(format!("DoT TLS handshake: {e}")))?;
            let result = self.exchange_on_stream(&mut stream, &query_buf).await;

            // Return connection to pool on success
            if result.is_ok() {
                if let Some(pool) = &self.pool {
                    let conn = PooledTlsConn {
                        stream,
                        created: std::time::Instant::now(),
                    };
                    pool.release(conn).await;
                }
            }

            return result;
        }

        // Plain TCP (no pooling)
        let tcp = create_marked_tcp(self.addr)
            .map_err(|e| DnsError::Failed(format!("DNS TCP connect: {e}")))?;
        let mut stream = tcp;
        self.exchange_on_stream(&mut stream, &query_buf).await
    }

    async fn exchange_on_stream<S>(
        &self,
        stream: &mut S,
        query_buf: &[u8],
    ) -> Result<Vec<u8>, DnsError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // DNS-over-TCP: 2 字节长度前缀
        let len = (query_buf.len() as u16).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| DnsError::Failed(format!("DNS TCP write len: {e}")))?;
        stream
            .write_all(&query_buf)
            .await
            .map_err(|e| DnsError::Failed(format!("DNS TCP write: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| DnsError::Failed(format!("DNS TCP flush: {e}")))?;

        let mut resp_len_buf = [0u8; 2];
        match tokio::time::timeout(DNS_QUERY_TIMEOUT, stream.read_exact(&mut resp_len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(DnsError::Failed(format!("DNS TCP read len: {e}"))),
            Err(_) => return Err(DnsError::Timeout),
        }
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        if resp_len > DNS_MAX_RESPONSE {
            return Err(DnsError::Failed(format!(
                "DNS TCP response too large: {resp_len}"
            )));
        }
        let mut buf = vec![0u8; resp_len];
        match tokio::time::timeout(DNS_QUERY_TIMEOUT, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(DnsError::Failed(format!("DNS TCP read: {e}"))),
            Err(_) => return Err(DnsError::Timeout),
        }
        Ok(buf)
    }
}

fn build_tls_connector() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

#[async_trait]
impl DnsUpstream for MarkedTcpDnsUpstream {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        if self.tls_name.is_some() {
            "dot-marked"
        } else {
            "tcp-marked"
        }
    }
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.client_subnet
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let resp = self.exchange(RecordType::A, host).await?;
        parse_response(&resp, RecordType::A)
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let resp = self.exchange(RecordType::AAAA, host).await?;
        parse_response(&resp, RecordType::AAAA)
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let resp = self.exchange(record_type, host).await?;
        parse_records(&resp)
    }

    async fn reset_connections(&self) {
        if let Some(pool) = &self.pool {
            pool.drain().await;
        }
    }
}
