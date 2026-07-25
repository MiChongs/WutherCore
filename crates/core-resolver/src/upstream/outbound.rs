//! 通过指定代理节点访问同一个 DNS endpoint。
//!
//! DNS 服务冗余由 `resolver.groups` 表达；本模块只解决同一服务经不同代理
//! 出口访问的链路冗余。出口选择与 RTT 学习复用 [`crate::group::DnsGroup`]。

use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use bytes::Bytes;
use hickory_resolver::proto::rr::{Record, RecordType};
use http::{Request, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{DnsError, DnsUpstream, marked, quic};

pub trait DnsProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DnsProxyStream for T {}
pub type BoxedDnsProxyStream = Pin<Box<dyn DnsProxyStream>>;

/// 由 `core-runtime` 注入，将 DNS 连接绑定到命名的代理节点。
#[async_trait]
pub trait DnsOutboundProvider: Send + Sync + 'static {
    async fn dial_tcp(
        &self,
        outbound: &str,
        host: &str,
        port: u16,
    ) -> io::Result<BoxedDnsProxyStream>;

    async fn exchange_udp(
        &self,
        outbound: &str,
        host: &str,
        port: u16,
        request: &[u8],
    ) -> io::Result<Vec<u8>>;
}

static OUTBOUND_PROVIDER: OnceLock<RwLock<Option<Arc<dyn DnsOutboundProvider>>>> = OnceLock::new();

pub fn set_dns_outbound_provider(provider: Arc<dyn DnsOutboundProvider>) {
    *OUTBOUND_PROVIDER.get_or_init(|| RwLock::new(None)).write() = Some(provider);
}

fn outbound_provider() -> Result<Arc<dyn DnsOutboundProvider>, DnsError> {
    OUTBOUND_PROVIDER
        .get_or_init(|| RwLock::new(None))
        .read()
        .clone()
        .ok_or_else(|| DnsError::Failed("DNS 代理出口尚未由 runtime 初始化".into()))
}

#[derive(Debug, Clone)]
enum Transport {
    Doh {
        host: String,
        port: u16,
        path: String,
        sni: String,
        skip_cert_verify: bool,
    },
    Dot {
        host: String,
        port: u16,
        sni: String,
        skip_cert_verify: bool,
    },
    Tcp {
        host: String,
        port: u16,
    },
    Udp {
        host: String,
        port: u16,
    },
}

#[derive(Debug, Clone)]
pub struct OutboundDnsUpstream {
    name: String,
    outbound: String,
    transport: Transport,
}

impl OutboundDnsUpstream {
    pub fn new(
        name: impl Into<String>,
        endpoint: &str,
        outbound: impl Into<String>,
    ) -> Result<Self, DnsError> {
        Ok(Self {
            name: name.into(),
            outbound: outbound.into(),
            transport: parse_transport(endpoint)?,
        })
    }

    async fn exchange(&self, host: &str, record_type: RecordType) -> Result<Vec<u8>, DnsError> {
        let provider = outbound_provider()?;
        self.exchange_with_provider(provider.as_ref(), host, record_type)
            .await
    }

    async fn exchange_with_provider(
        &self,
        provider: &dyn DnsOutboundProvider,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<u8>, DnsError> {
        let request = marked::build_query(host, record_type)?;
        match &self.transport {
            Transport::Doh {
                host,
                port,
                path,
                sni,
                skip_cert_verify,
            } => {
                let stream = provider
                    .dial_tcp(&self.outbound, host, *port)
                    .await
                    .map_err(outbound_error(&self.outbound))?;
                exchange_doh(stream, host, *port, path, sni, *skip_cert_verify, request).await
            }
            Transport::Dot {
                host,
                port,
                sni,
                skip_cert_verify,
            } => {
                let stream = provider
                    .dial_tcp(&self.outbound, host, *port)
                    .await
                    .map_err(outbound_error(&self.outbound))?;
                let stream = tls_stream(stream, sni, *skip_cert_verify, &[]).await?;
                exchange_tcp(stream, request).await
            }
            Transport::Tcp { host, port } => {
                let stream = provider
                    .dial_tcp(&self.outbound, host, *port)
                    .await
                    .map_err(outbound_error(&self.outbound))?;
                exchange_tcp(stream, request).await
            }
            Transport::Udp { host, port } => provider
                .exchange_udp(&self.outbound, host, *port, &request)
                .await
                .map_err(outbound_error(&self.outbound)),
        }
    }
}

#[async_trait]
impl DnsUpstream for OutboundDnsUpstream {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "outbound-routed"
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        marked::parse_response(&self.exchange(host, RecordType::A).await?, RecordType::A)
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        marked::parse_response(
            &self.exchange(host, RecordType::AAAA).await?,
            RecordType::AAAA,
        )
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        marked::parse_records(&self.exchange(host, record_type).await?)
    }
}

fn parse_transport(endpoint: &str) -> Result<Transport, DnsError> {
    let endpoint = endpoint.trim();
    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("https://") {
        let url = url::Url::parse(endpoint)
            .map_err(|error| DnsError::Failed(format!("无效 DoH endpoint: {error}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| DnsError::Failed("DoH endpoint 缺少 host".into()))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let sni = parameter(&url, "sni").unwrap_or_else(|| host.clone());
        let skip_cert_verify =
            bool_parameter(&url, "skip-cert-verify") || bool_parameter(&url, "skip_cert_verify");
        let path = if url.path().is_empty() || url.path() == "/" {
            "/dns-query".to_string()
        } else {
            url.path().to_string()
        };
        return Ok(Transport::Doh {
            host,
            port,
            path,
            sni,
            skip_cert_verify,
        });
    }

    for (scheme, default_port, tls) in [("tls://", 853, true), ("tcp://", 53, false)] {
        if lower.starts_with(scheme) {
            let url = url::Url::parse(endpoint)
                .map_err(|error| DnsError::Failed(format!("无效 DNS endpoint: {error}")))?;
            let host = url
                .host_str()
                .ok_or_else(|| DnsError::Failed("DNS endpoint 缺少 host".into()))?
                .to_string();
            let port = url.port().unwrap_or(default_port);
            if tls {
                let sni = parameter(&url, "sni").unwrap_or_else(|| host.clone());
                let skip_cert_verify = bool_parameter(&url, "skip-cert-verify")
                    || bool_parameter(&url, "skip_cert_verify");
                return Ok(Transport::Dot {
                    host,
                    port,
                    sni,
                    skip_cert_verify,
                });
            }
            return Ok(Transport::Tcp { host, port });
        }
    }

    if lower.starts_with("udp://") {
        let url = url::Url::parse(endpoint)
            .map_err(|error| DnsError::Failed(format!("无效 UDP DNS endpoint: {error}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| DnsError::Failed("UDP DNS endpoint 缺少 host".into()))?
            .to_string();
        return Ok(Transport::Udp {
            host,
            port: url.port().unwrap_or(53),
        });
    }

    if lower.starts_with("quic://") {
        return Err(DnsError::Failed(
            "DoQ 暂不支持经命名代理出口承载；请使用 DoH/DoT/TCP/UDP endpoint".into(),
        ));
    }
    if lower == "system" || lower == "system://" {
        return Err(DnsError::Failed(
            "system resolver 不能绑定代理出口，请配置明确的 DNS endpoint".into(),
        ));
    }
    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
        return Ok(Transport::Udp {
            host: addr.ip().to_string(),
            port: addr.port(),
        });
    }
    if let Ok(ip) = endpoint.parse::<IpAddr>() {
        return Ok(Transport::Udp {
            host: ip.to_string(),
            port: 53,
        });
    }
    Err(DnsError::Failed(format!(
        "代理出口模式不支持 DNS endpoint: {endpoint}"
    )))
}

fn parameter(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.into_owned())
        .or_else(|| {
            url.fragment().and_then(|fragment| {
                url::form_urlencoded::parse(fragment.as_bytes())
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.into_owned())
            })
        })
}

fn bool_parameter(url: &url::Url, name: &str) -> bool {
    parameter(url, name)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn outbound_error(outbound: &str) -> impl FnOnce(io::Error) -> DnsError + '_ {
    move |error| DnsError::Failed(format!("DNS 出口 `{outbound}` 连接失败: {error}"))
}

async fn exchange_tcp<S>(mut stream: S, request: Vec<u8>) -> Result<Vec<u8>, DnsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let length = u16::try_from(request.len())
        .map_err(|_| DnsError::Failed("DNS request 超过 TCP 帧长度限制".into()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TCP write length: {error}")))?;
    stream
        .write_all(&request)
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TCP write body: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TCP flush: {error}")))?;

    let response_len = stream
        .read_u16()
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TCP read length: {error}")))?
        as usize;
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TCP read body: {error}")))?;
    Ok(response)
}

async fn exchange_doh(
    stream: BoxedDnsProxyStream,
    host: &str,
    port: u16,
    path: &str,
    sni: &str,
    skip_cert_verify: bool,
    request: Vec<u8>,
) -> Result<Vec<u8>, DnsError> {
    let tls = tls_stream(stream, sni, skip_cert_verify, &[b"h2"]).await?;
    let io = TokioIo::new(tls);
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), io)
            .await
            .map_err(|error| DnsError::Failed(format!("DoH HTTP/2 handshake: {error}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let request = Request::post(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::from(request)))
        .map_err(|error| DnsError::Failed(format!("构造 DoH request 失败: {error}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| DnsError::Failed(format!("DoH request 失败: {error}")))?;
    if !response.status().is_success() {
        return Err(DnsError::Failed(format!(
            "DoH HTTP status {}",
            response.status()
        )));
    }
    response
        .into_body()
        .collect()
        .await
        .map(|body| body.to_bytes().to_vec())
        .map_err(|error| DnsError::Failed(format!("读取 DoH response 失败: {error}")))
}

async fn tls_stream(
    stream: BoxedDnsProxyStream,
    sni: &str,
    skip_cert_verify: bool,
    alpn: &[&[u8]],
) -> Result<tokio_rustls::client::TlsStream<BoxedDnsProxyStream>, DnsError> {
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|error| DnsError::Failed(format!("无效 DNS TLS SNI `{sni}`: {error}")))?;
    let config = quic::build_tls_config_with_alpn(skip_cert_verify, alpn);
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(|error| DnsError::Failed(format!("DNS TLS handshake 失败: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Mutex};

    use hickory_resolver::proto::{
        op::{Message, MessageType, ResponseCode},
        rr::{Name, RData, Record, rdata::A},
        serialize::binary::BinDecodable,
    };
    use hyper::{Response, service::service_fn};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[derive(Default)]
    struct FakeProvider {
        calls: Mutex<Vec<(String, String, u16)>>,
    }

    #[derive(Default)]
    struct FakeDohProvider {
        calls: Mutex<Vec<(String, String, u16)>>,
    }

    #[async_trait]
    impl DnsOutboundProvider for FakeProvider {
        async fn dial_tcp(
            &self,
            _outbound: &str,
            _host: &str,
            _port: u16,
        ) -> io::Result<BoxedDnsProxyStream> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used by UDP test",
            ))
        }

        async fn exchange_udp(
            &self,
            outbound: &str,
            host: &str,
            port: u16,
            request: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls
                .lock()
                .unwrap()
                .push((outbound.to_string(), host.to_string(), port));
            dns_response(request)
        }
    }

    #[async_trait]
    impl DnsOutboundProvider for FakeDohProvider {
        async fn dial_tcp(
            &self,
            outbound: &str,
            host: &str,
            port: u16,
        ) -> io::Result<BoxedDnsProxyStream> {
            self.calls
                .lock()
                .unwrap()
                .push((outbound.to_string(), host.to_string(), port));
            let (client, server) = tokio::io::duplex(64 * 1024);
            let acceptor = TlsAcceptor::from(test_h2_server_config());
            tokio::spawn(async move {
                let tls = acceptor.accept(server).await.unwrap();
                let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async {
                    assert_eq!(request.uri().path(), "/dns-query");
                    let request = request.into_body().collect().await.unwrap().to_bytes();
                    let response = dns_response(&request).unwrap();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::CONTENT_TYPE, "application/dns-message")
                            .body(Full::new(Bytes::from(response)))
                            .unwrap(),
                    )
                });
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await
                    .unwrap();
            });
            Ok(Box::pin(client))
        }

        async fn exchange_udp(
            &self,
            _outbound: &str,
            _host: &str,
            _port: u16,
            _request: &[u8],
        ) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not used by DoH test",
            ))
        }
    }

    fn test_h2_server_config() -> Arc<rustls::ServerConfig> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    fn dns_response(request: &[u8]) -> io::Result<Vec<u8>> {
        let query = Message::from_bytes(request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut response = Message::new();
        response
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for question in query.queries() {
            response.add_query(question.clone());
        }
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        response
            .to_vec()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    #[test]
    fn parses_single_doh_endpoint_for_named_outbound() {
        let upstream = OutboundDnsUpstream::new(
            "cf@node-a",
            "https://1.1.1.1/dns-query?sni=cloudflare-dns.com",
            "node-a",
        )
        .unwrap();
        assert_eq!(upstream.outbound, "node-a");
        assert!(matches!(
            upstream.transport,
            Transport::Doh {
                port: 443,
                ref path,
                ..
            } if path == "/dns-query"
        ));
    }

    #[test]
    fn rejects_doq_and_system_for_named_outbound() {
        assert!(OutboundDnsUpstream::new("x", "quic://1.1.1.1", "node").is_err());
        assert!(OutboundDnsUpstream::new("x", "system", "node").is_err());
    }

    #[tokio::test]
    async fn same_endpoint_is_queried_through_distinct_nodes() {
        let provider = FakeProvider::default();
        let node_a = OutboundDnsUpstream::new("cf@node-a", "udp://9.9.9.9", "node-a").unwrap();
        let node_b = OutboundDnsUpstream::new("cf@node-b", "udp://9.9.9.9", "node-b").unwrap();

        let first = node_a
            .exchange_with_provider(&provider, "example.com", RecordType::A)
            .await
            .unwrap();
        let second = node_b
            .exchange_with_provider(&provider, "example.com", RecordType::A)
            .await
            .unwrap();
        assert!(!marked::parse_records(&first).unwrap().is_empty());
        assert!(!marked::parse_records(&second).unwrap().is_empty());
        assert_eq!(
            provider.calls.lock().unwrap().as_slice(),
            [
                ("node-a".into(), "9.9.9.9".into(), 53),
                ("node-b".into(), "9.9.9.9".into(), 53),
            ]
        );
    }

    #[tokio::test]
    async fn doh_request_uses_the_named_proxy_stream() {
        let provider = FakeDohProvider::default();
        let upstream = OutboundDnsUpstream::new(
            "cf@node-a",
            "https://dns.example/dns-query?skip-cert-verify=true",
            "node-a",
        )
        .unwrap();

        let response = upstream
            .exchange_with_provider(&provider, "example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(marked::parse_records(&response).unwrap().len(), 1);
        assert_eq!(
            provider.calls.lock().unwrap().as_slice(),
            [("node-a".into(), "dns.example".into(), 443)]
        );
    }
}
