//! rustls + webpki-roots 的 TLS 客户端。

use std::sync::Arc;

use async_trait::async_trait;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{
    adapter::{BoxedStream, resolve_host},
    loopback::TrackedTcpStream,
    transport::{TlsOptions, Transport, tcp::marked_connect},
};

#[derive(Debug, Clone)]
pub struct TlsTransport {
    pub options: TlsOptions,
    config: Arc<ClientConfig>,
}

impl TlsTransport {
    pub fn new(options: TlsOptions) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // 显式指定 ring provider，避免 0.23 多 feature 引入时全局默认歧义导致 panic。
        let mut cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("rustls ring default protocols")
                .with_root_certificates(roots)
                .with_no_client_auth();

        if !options.alpn.is_empty() {
            cfg.alpn_protocols = options.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }
        if options.insecure {
            cfg.dangerous().set_certificate_verifier(Arc::new(NoVerify));
        }
        Self {
            options,
            config: Arc::new(cfg),
        }
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let started = std::time::Instant::now();
        // SNI 优先级：配置的 sni > host（仅当 host 是域名时）。
        // host 是 IP 时不能作为 SNI（rustls 拒绝 IP 字符串作为 ServerName）。
        // 对标 mihomo：IP 目标 + 无 sni 配置 → 用 insecure 模式（不发 SNI）。
        let sni_str: String = self
            .options
            .sni
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    String::new()
                } else {
                    host.to_string()
                }
            });
        tracing::debug!(
            target: "dial::tls",
            %host, port,
            sni = %sni_str,
            insecure = self.options.insecure,
            alpn = ?self.options.alpn,
            "begin",
        );
        let dns: ServerName<'static> = if sni_str.is_empty() {
            // 无 SNI：用 IP 直连（需要 insecure 或服务器不验证 SNI）
            ServerName::try_from(host.to_string()).unwrap_or_else(|_| {
                // IP 地址无法作为 ServerName，用 "localhost" 占位 + insecure
                ServerName::try_from("localhost".to_string()).unwrap()
            })
        } else {
            ServerName::try_from(sni_str.clone()).map_err(|e| {
                tracing::warn!(target: "dial::tls", sni = %sni_str, error = %e, "invalid SNI");
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("非法 SNI: {sni_str} ({e})"),
                )
            })?
        };
        // 同 TcpTransport：先 resolve 走 WutherCore resolver，避免 TUN 死循环。
        let addrs = resolve_host(host, port).await?;
        let mut last_err: Option<std::io::Error> = None;
        let mut tried = 0usize;
        let tcp = {
            let mut chosen: Option<TrackedTcpStream<TcpStream>> = None;
            let mut chosen_peer: Option<std::net::SocketAddr> = None;
            for addr in addrs {
                tried += 1;
                let t = std::time::Instant::now();
                match marked_connect(addr, std::time::Duration::from_secs(10)).await {
                    Ok(s) => {
                        tracing::debug!(
                            target: "dial::tls",
                            %host, port, peer = %addr,
                            attempt = tried,
                            connect_ms = t.elapsed().as_millis() as u64,
                            "tcp ok, begin TLS handshake",
                        );
                        chosen = Some(s);
                        chosen_peer = Some(addr);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(
                            target: "dial::tls",
                            %host, port, peer = %addr,
                            attempt = tried, error = %e,
                            "tcp connect failed",
                        );
                        last_err = Some(e);
                    }
                }
            }
            let _ = chosen_peer;
            chosen.ok_or_else(|| {
                tracing::warn!(target: "dial::tls", %host, port, tried, "all candidates failed (tcp)");
                last_err.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("tls connect: no usable address for {host}:{port}"),
                    )
                })
            })?
        };
        let _ = tcp.set_nodelay(true);
        let connector = TlsConnector::from(self.config.clone());
        let handshake_start = std::time::Instant::now();
        let stream = connector.connect(dns, tcp).await.map_err(|e| {
            tracing::warn!(
                target: "dial::tls",
                %host, port,
                sni = %sni_str,
                handshake_ms = handshake_start.elapsed().as_millis() as u64,
                error = %e,
                "TLS handshake failed",
            );
            std::io::Error::new(std::io::ErrorKind::Other, format!("TLS handshake: {e}"))
        })?;
        tracing::info!(
            target: "dial::tls",
            %host, port,
            sni = %sni_str,
            handshake_ms = handshake_start.elapsed().as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "TLS handshake ok",
        );
        Ok(Box::pin(stream))
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
