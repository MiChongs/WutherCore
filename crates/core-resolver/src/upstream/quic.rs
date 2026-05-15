//! DNS-over-QUIC (DoQ) upstream per RFC 9250.
//!
//! Uses persistent QUIC connections with stream-per-query multiplexing.
//! DNS message ID is set to 0 (RFC 9250 §4.2.1). Each query opens a new
//! bidirectional stream with a 2-byte length prefix (same as DNS-over-TCP).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::sync::Mutex;
use tracing::debug;

use super::{DnsError, DnsUpstream};

const DOQ_ALPN: &[&[u8]] = &[b"doq"];
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct QuicDnsUpstream {
    name: String,
    addr: SocketAddr,
    sni: String,
    tls_config: Arc<rustls::ClientConfig>,
    conn: Mutex<Option<quinn::Connection>>,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    client_subnet: Option<ipnet::IpNet>,
}

impl QuicDnsUpstream {
    pub fn new(
        name: impl Into<String>,
        addr: SocketAddr,
        sni: impl Into<String>,
        skip_cert_verify: bool,
    ) -> Self {
        let tls_config = build_tls_config(skip_cert_verify);
        Self {
            name: name.into(),
            addr,
            sni: sni.into(),
            tls_config: Arc::new(tls_config),
            conn: Mutex::new(None),
            endpoint: Mutex::new(None),
            client_subnet: None,
        }
    }

    pub fn with_client_subnet(mut self, net: ipnet::IpNet) -> Self {
        self.client_subnet = Some(net);
        self
    }

    async fn exchange(&self, query_buf: Vec<u8>) -> Result<Vec<u8>, DnsError> {
        let result = tokio::time::timeout(QUERY_TIMEOUT, self.exchange_inner(&query_buf)).await;
        match result {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DnsError::Timeout),
        }
    }

    async fn exchange_inner(&self, query_buf: &[u8]) -> Result<Vec<u8>, DnsError> {
        // Try existing connection first
        let conn = self.get_or_connect().await?;
        match self.query_on_connection(&conn, query_buf).await {
            Ok(resp) => Ok(resp),
            Err(_) => {
                // Reconnect and retry once
                debug!(target: "resolver::doq", name = %self.name, "retrying with fresh connection");
                self.close_connection().await;
                let conn = self.get_or_connect().await?;
                self.query_on_connection(&conn, query_buf).await
            }
        }
    }

    async fn query_on_connection(
        &self,
        conn: &quinn::Connection,
        query_buf: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| DnsError::Failed(format!("DoQ open stream: {e}")))?;

        // Write 2-byte length prefix + DNS message
        let len = query_buf.len() as u16;
        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| DnsError::Failed(format!("DoQ write len: {e}")))?;
        send.write_all(query_buf)
            .await
            .map_err(|e| DnsError::Failed(format!("DoQ write msg: {e}")))?;
        send.finish()
            .map_err(|e| DnsError::Failed(format!("DoQ finish: {e}")))?;

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| DnsError::Failed(format!("DoQ read len: {e}")))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 65535 {
            return Err(DnsError::Failed("DoQ invalid response length".into()));
        }

        // Read response
        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf)
            .await
            .map_err(|e| DnsError::Failed(format!("DoQ read resp: {e}")))?;

        Ok(resp_buf)
    }

    async fn get_or_connect(&self) -> Result<quinn::Connection, DnsError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        let conn = self.connect().await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn connect(&self) -> Result<quinn::Connection, DnsError> {
        let endpoint = self.get_or_create_endpoint().await?;

        let connect_fut = endpoint.connect(self.addr, &self.sni);
        let connecting =
            connect_fut.map_err(|e| DnsError::Failed(format!("DoQ connect start: {e}")))?;

        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Failed(format!("DoQ connect: {e}")))?;

        debug!(
            target: "resolver::doq",
            name = %self.name,
            addr = %self.addr,
            "DoQ connection established"
        );
        Ok(conn)
    }

    async fn get_or_create_endpoint(&self) -> Result<quinn::Endpoint, DnsError> {
        let mut guard = self.endpoint.lock().await;
        if let Some(ep) = guard.as_ref() {
            return Ok(ep.clone());
        }

        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(self.tls_config.clone())
                .map_err(|e| DnsError::Failed(format!("DoQ TLS config: {e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("valid idle timeout"),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport));

        let bind_addr: SocketAddr = if self.addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| DnsError::Failed(format!("DoQ bind: {e}")))?;
        endpoint.set_default_client_config(client_config);

        *guard = Some(endpoint.clone());
        Ok(endpoint)
    }

    async fn close_connection(&self) {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.take() {
            conn.close(0u32.into(), b"reconnecting");
        }
    }
}

#[async_trait]
impl DnsUpstream for QuicDnsUpstream {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "doq"
    }

    fn default_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.client_subnet
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let buf = build_dns_query(host, RecordType::A)?;
        let resp = self.exchange(buf).await?;
        parse_dns_response(&resp, RecordType::A)
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let buf = build_dns_query(host, RecordType::AAAA)?;
        let resp = self.exchange(buf).await?;
        parse_dns_response(&resp, RecordType::AAAA)
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let buf = build_dns_query(host, record_type)?;
        let resp = self.exchange(buf).await?;
        parse_dns_records(&resp, host, record_type)
    }

    async fn reset_connections(&self) {
        // Close QUIC connection so next query reconnects on the new interface
        self.close_connection().await;
        // Also drop the endpoint so a fresh socket is bound to the new interface
        let mut ep_guard = self.endpoint.lock().await;
        if let Some(ep) = ep_guard.take() {
            ep.close(0u32.into(), b"interface-change");
        }
    }
}

fn build_tls_config(skip_cert_verify: bool) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store())
        .with_no_client_auth();
    config.alpn_protocols = DOQ_ALPN.iter().map(|a| a.to_vec()).collect();
    if skip_cert_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }
    config
}

fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/* ---------- DNS Wire Format Helpers ---------- */

fn build_dns_query(host: &str, record_type: RecordType) -> Result<Vec<u8>, DnsError> {
    use hickory_resolver::proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::DNSClass,
        serialize::binary::BinEncodable,
    };

    let name = Name::from_ascii(host.trim_end_matches('.'))
        .map_err(|e| DnsError::Failed(format!("invalid domain: {e}")))?;

    let mut msg = Message::new();
    msg.set_id(0); // RFC 9250: ID MUST be 0
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_bytes()
        .map_err(|e| DnsError::Failed(format!("DNS encode: {e}")))
}

fn parse_dns_response(buf: &[u8], record_type: RecordType) -> Result<Vec<IpAddr>, DnsError> {
    use hickory_resolver::proto::{op::Message, serialize::binary::BinDecodable};

    let msg = Message::from_bytes(buf).map_err(|e| DnsError::Failed(format!("DNS decode: {e}")))?;

    let ips: Vec<IpAddr> = msg
        .answers()
        .iter()
        .filter_map(|r| {
            let data = r.data()?;
            match (record_type, data) {
                (RecordType::A, RData::A(a)) => Some(IpAddr::V4(a.0)),
                (RecordType::AAAA, RData::AAAA(a)) => Some(IpAddr::V6(a.0)),
                _ => None,
            }
        })
        .collect();

    if ips.is_empty() {
        Err(DnsError::Empty)
    } else {
        Ok(ips)
    }
}

fn parse_dns_records(
    buf: &[u8],
    _host: &str,
    _record_type: RecordType,
) -> Result<Vec<Record>, DnsError> {
    use hickory_resolver::proto::{op::Message, serialize::binary::BinDecodable};

    let msg = Message::from_bytes(buf).map_err(|e| DnsError::Failed(format!("DNS decode: {e}")))?;

    let records: Vec<Record> = msg.answers().to_vec();
    if records.is_empty() {
        Err(DnsError::Empty)
    } else {
        Ok(records)
    }
}
