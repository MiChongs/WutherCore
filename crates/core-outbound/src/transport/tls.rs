//! rustls + 操作系统/自定义根证书库的 TLS 客户端。

use std::{
    fmt,
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Cursor, Write},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use base64::Engine as _;
use core_config::model::{XhttpDownloadTlsCertificate, XhttpTlsCertificateUsage};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    client::{EchConfig, EchMode, ResolvesClientCert, WebPkiServerVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName, UnixTime},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};
use tokio::{net::TcpStream, sync::OnceCell};
use tokio_rustls::TlsConnector;

use crate::{
    adapter::BoxedStream,
    transport::{
        TlsOptions, Transport,
        tcp::connect_boxed,
        utls::{
            fingerprint_is_per_connection_randomized, validate_xray_fingerprint,
            xray_client_hello_settings,
        },
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TlsTransport {
    pub options: TlsOptions,
    config: Arc<OnceCell<Arc<ClientConfig>>>,
    boring_config: Arc<OnceCell<Arc<boring::ssl::SslConnector>>>,
}

impl TlsTransport {
    pub fn new(options: TlsOptions) -> Self {
        Self {
            options,
            config: Arc::new(OnceCell::new()),
            boring_config: Arc::new(OnceCell::new()),
        }
    }
}

/// 构造 TCP TLS 与 QUIC TLS 共用的客户端配置，确保 XHTTP H1/H2/H3
/// 使用相同的证书 pin、名称覆盖、ALPN 与会话恢复语义。Xray 的 QUIC/H3
/// 路径把标准 `crypto/tls.Config` 直接交给 quic-go，因此只校验 fingerprint
/// 配置，不把 TCP uTLS ClientHello 模板套到 QUIC TLS。
pub(crate) fn build_tls_client_config(options: &TlsOptions) -> io::Result<ClientConfig> {
    validate_alpn(&options.alpn)?;
    if let Some(settings) = &options.xray_settings {
        settings
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    let ech = configured_ech(options)?;
    let client_hello = if options.alpn == ["h3"] {
        validate_xray_fingerprint(&options.fingerprint)?;
        xray_client_hello_settings("unsafe", &options.alpn, ech.is_some())?
    } else {
        xray_client_hello_settings(&options.fingerprint, &options.alpn, ech.is_some())?
    };
    let roots = root_store(options)?;
    // aws-lc-rs 覆盖 Xray 当前 Chrome/PQ parrots 的 X25519MLKEM768 与
    // X25519Kyber768Draft00；显式 provider 也避免多 provider feature 歧义。
    let provider = Arc::new(configured_crypto_provider(options)?);
    let tls13_versions = [&rustls::version::TLS13, &rustls::version::TLS12];
    let tls12_versions = [&rustls::version::TLS12];
    let tls13_only = [&rustls::version::TLS13];
    let (min_version, max_version) = configured_version_range(options)?;
    if min_version < 12 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TLS 1.0/1.1 requires the BoringSSL compatibility backend",
        ));
    }
    let protocol_versions = if min_version == 13 {
        tls13_only.as_slice()
    } else if max_version == 12 || !client_hello.tls13 {
        tls12_versions.as_slice()
    } else {
        tls13_versions.as_slice()
    };
    if ech.is_some() && max_version < 13 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ECH requires TLS 1.3 but maxVersion excludes it",
        ));
    }
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = if let Some(ech) = ech {
        builder.with_ech(EchMode::Enable(ech)).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("construct ECH TLS config: {error}"),
            )
        })?
    } else {
        builder
            .with_protocol_versions(protocol_versions)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("construct rustls protocol versions: {error}"),
                )
            })?
    };
    let builder = builder.with_root_certificates(roots.clone());
    let client_certificates = load_client_certificates(options, &provider)?;
    let mut cfg = if client_certificates.is_empty() {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_resolver(Arc::new(XrayClientCertResolver {
            certificates: client_certificates,
        }))
    };

    cfg.alpn_protocols = client_hello.alpn_protocols;
    if !options.enable_session_resumption {
        cfg.resumption = rustls::client::Resumption::disabled();
    }
    cfg.client_hello_customizer = client_hello.customizer;
    if let Some(path) = options
        .xray_settings
        .as_ref()
        .and_then(|settings| settings.master_key_log.as_deref())
        .filter(|path| !path.eq_ignore_ascii_case("none"))
    {
        cfg.key_log = Arc::new(PathKeyLog::open(path)?);
    }
    if options.insecure {
        cfg.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    } else if !options.pinned_peer_cert_sha256.is_empty()
        || !options.verify_peer_cert_by_name.is_empty()
    {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(XrayServerCertVerifier::new(
                Arc::new(roots),
                provider,
                options.pinned_peer_cert_sha256.clone(),
                options.verify_peer_cert_by_name.clone(),
            )));
    }
    Ok(cfg)
}

fn configured_version_range(options: &TlsOptions) -> io::Result<(u8, u8)> {
    let settings = options.xray_settings.as_ref();
    let parse = |value: Option<&str>, default: u8| -> io::Result<u8> {
        match value.map(str::trim) {
            None | Some("") => Ok(default),
            Some("1.0") => Ok(10),
            Some("1.1") => Ok(11),
            Some("1.2") => Ok(12),
            Some("1.3") => Ok(13),
            Some(value) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported TLS version {value:?}"),
            )),
        }
    };
    let min = parse(settings.and_then(|value| value.min_version.as_deref()), 12)?;
    let max = parse(settings.and_then(|value| value.max_version.as_deref()), 13)?;
    if min > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS minVersion exceeds maxVersion",
        ));
    }
    Ok((min, max))
}

fn configured_crypto_provider(options: &TlsOptions) -> io::Result<CryptoProvider> {
    let mut provider = xray_crypto_provider();
    let Some(settings) = options.xray_settings.as_ref() else {
        return Ok(provider);
    };
    if let Some(configured) = settings.cipher_suites.as_deref() {
        let names = configured.split(':').map(str::trim).collect::<Vec<_>>();
        provider.cipher_suites.retain(|suite| {
            names
                .iter()
                .any(|name| *name == format!("{:?}", suite.suite()))
        });
        if provider.cipher_suites.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cipherSuites contains no suite supported by the rustls backend",
            ));
        }
    }
    if let Some(curves) = &settings.curve_preferences {
        let mut groups = Vec::with_capacity(curves.len());
        for curve in curves {
            let group = match curve.to_ascii_lowercase().as_str() {
                "x25519" => rustls::crypto::aws_lc_rs::kx_group::X25519,
                "curvep256" => rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                "curvep384" => rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
                "x25519mlkem768" => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                "secp256r1mlkem768" => rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
                "curvep521" | "secp384r1mlkem1024" => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("curve {curve:?} requires the BoringSSL compatibility backend"),
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown curve preference {curve:?}"),
                    ));
                }
            };
            groups.push(group);
        }
        provider.kx_groups = groups;
    }
    Ok(provider)
}

fn root_store(options: &TlsOptions) -> io::Result<RootCertStore> {
    let settings = options.xray_settings.as_ref();
    let mut roots = if settings.is_some_and(|value| value.disable_system_root.unwrap_or(false)) {
        RootCertStore::empty()
    } else {
        default_root_store()?
    };
    if let Some(settings) = settings {
        for (index, certificate) in settings.certificates.iter().enumerate() {
            for der in load_certificate_chain(certificate).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("tlsSettings.certificates[{index}]: {error}"),
                )
            })? {
                roots.add(der).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tlsSettings.certificates[{index}] root certificate: {error}"),
                    )
                })?;
            }
        }
    }
    Ok(roots)
}

fn load_client_certificates(
    options: &TlsOptions,
    provider: &CryptoProvider,
) -> io::Result<Vec<Arc<CertifiedKey>>> {
    let Some(settings) = options.xray_settings.as_ref() else {
        return Ok(Vec::new());
    };
    settings
        .certificates
        .iter()
        .enumerate()
        .filter(|(_, certificate)| {
            certificate
                .usage
                .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
                == XhttpTlsCertificateUsage::Encipherment
        })
        .map(|(index, certificate)| {
            let chain = load_certificate_chain(certificate)?;
            let key = load_private_key(certificate)?;
            CertifiedKey::from_der(chain, key, provider)
                .map(Arc::new)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tlsSettings.certificates[{index}] key pair: {error}"),
                    )
                })
        })
        .collect()
}

fn certificate_pem(certificate: &XhttpDownloadTlsCertificate) -> io::Result<Vec<u8>> {
    if let Some(path) = certificate.certificate_file.as_deref() {
        std::fs::read(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read certificate file {path:?}: {error}"),
            )
        })
    } else {
        Ok(certificate
            .certificate
            .as_ref()
            .map(|lines| lines.join("\n").into_bytes())
            .unwrap_or_default())
    }
}

fn key_pem(certificate: &XhttpDownloadTlsCertificate) -> io::Result<Vec<u8>> {
    if let Some(path) = certificate.key_file.as_deref() {
        std::fs::read(path).map_err(|error| {
            io::Error::new(error.kind(), format!("read key file {path:?}: {error}"))
        })
    } else {
        Ok(certificate
            .key
            .as_ref()
            .map(|lines| lines.join("\n").into_bytes())
            .unwrap_or_default())
    }
}

fn load_certificate_chain(
    certificate: &XhttpDownloadTlsCertificate,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = certificate_pem(certificate)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("parse PEM: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PEM contains no certificate",
        ));
    }
    Ok(certificates)
}

fn load_private_key(
    certificate: &XhttpDownloadTlsCertificate,
) -> io::Result<PrivateKeyDer<'static>> {
    let pem = key_pem(certificate)?;
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse PEM key: {error}"),
            )
        })?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PEM contains no private key"))
}

fn configured_ech(options: &TlsOptions) -> io::Result<Option<EchConfig>> {
    let Some(source) = options
        .xray_settings
        .as_ref()
        .and_then(|settings| settings.ech_config_list.as_deref())
    else {
        return Ok(None);
    };
    let bytes = if let Some(resolved) = &options.resolved_ech_config_list {
        resolved.clone()
    } else if source.contains("://") {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "ECH DNS source must be resolved before building TLS config",
        ));
    } else {
        decode_base64(source).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("decode echConfigList: {error}"),
            )
        })?
    };
    let ech = EchConfig::new(
        EchConfigListBytes::from(bytes),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ECH config list: {error}"),
        )
    })?;
    Ok(Some(ech))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
}

#[derive(Debug)]
struct XrayClientCertResolver {
    certificates: Vec<Arc<CertifiedKey>>,
}

impl ResolvesClientCert for XrayClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.certificates
            .iter()
            .find(|certificate| certificate.key.choose_scheme(sigschemes).is_some())
            .cloned()
    }

    fn has_certs(&self) -> bool {
        !self.certificates.is_empty()
    }
}

struct PathKeyLog {
    file: Mutex<File>,
}

impl PathKeyLog {
    fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| {
                io::Error::new(error.kind(), format!("open masterKeyLog {path:?}: {error}"))
            })?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl fmt::Debug for PathKeyLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PathKeyLog").finish_non_exhaustive()
    }
}

impl rustls::KeyLog for PathKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let _ = writeln!(
            file,
            "{label} {} {}",
            hex::encode(client_random),
            hex::encode(secret)
        );
    }
}

static NATIVE_ROOT_STORE: OnceLock<Result<RootCertStore, String>> = OnceLock::new();

fn default_root_store() -> io::Result<RootCertStore> {
    NATIVE_ROOT_STORE
        .get_or_init(load_native_root_store)
        .as_ref()
        .cloned()
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message.clone()))
}

fn load_native_root_store() -> Result<RootCertStore, String> {
    let result = rustls_native_certs::load_native_certs();
    if !result.errors.is_empty() {
        return Err(format!(
            "failed to load the complete native TLS root store: {:?}",
            result.errors
        ));
    }
    if result.certs.is_empty() {
        return Err("native TLS root store is empty".into());
    }

    let mut roots = RootCertStore::empty();
    for certificate in result.certs {
        roots
            .add(certificate)
            .map_err(|error| format!("native TLS root certificate is invalid: {error}"))?;
    }
    Ok(roots)
}

fn validate_alpn(protocols: &[String]) -> io::Result<()> {
    let mut encoded_len = 2_usize;
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > usize::from(u8::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TLS ALPN id must contain 1..=255 bytes: {protocol:?}"),
            ));
        }
        encoded_len = encoded_len.checked_add(1 + protocol.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "TLS ALPN list is too large")
        })?;
    }
    if encoded_len > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS ALPN list exceeds the 65535-byte wire limit",
        ));
    }
    Ok(())
}

pub(super) fn xray_crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519KYBER768DRAFT00,
        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    provider
}

/// Xray 26.7.11 的证书验证语义：
///
/// - pin 命中叶证书时直接信任该叶证书；
/// - pin 命中链中的 CA 时，仅以该证书为锚，再执行名称/有效期/链验证；
/// - `verifyPeerCertByName` 非空时依次尝试这些名称，而不是拨号 SNI；
/// - 配置了 pin 但链中无匹配项时必须失败，不能回退系统根。
#[derive(Debug)]
struct XrayServerCertVerifier {
    default_verifier: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    pins: Vec<[u8; 32]>,
    verify_names: Vec<String>,
}

impl XrayServerCertVerifier {
    fn new(
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        pins: Vec<[u8; 32]>,
        verify_names: Vec<String>,
    ) -> Self {
        let default_verifier = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .expect("bundled web PKI roots are non-empty");
        Self {
            default_verifier,
            provider,
            pins,
            verify_names,
        }
    }

    fn hash_matches_pin(&self, certificate: &CertificateDer<'_>) -> bool {
        let digest = Sha256::digest(certificate.as_ref());
        self.pins
            .iter()
            .any(|pin| constant_time_eq_32(pin, digest.as_ref()))
    }

    fn verify_with_names(
        &self,
        verifier: &WebPkiServerVerifier,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        fallback_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.verify_names.is_empty() {
            return verifier.verify_server_cert(
                end_entity,
                intermediates,
                fallback_name,
                ocsp_response,
                now,
            );
        }

        let mut last_error = None;
        for name in &self.verify_names {
            let candidate = match ServerName::try_from(name.clone()) {
                Ok(candidate) => candidate,
                Err(error) => {
                    last_error = Some(rustls::Error::General(format!(
                        "invalid verifyPeerCertByName value {name:?}: {error}"
                    )));
                    continue;
                }
            };
            match verifier.verify_server_cert(
                end_entity,
                intermediates,
                &candidate,
                ocsp_response,
                now,
            ) {
                Ok(verified) => return Ok(verified),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            rustls::Error::General("verifyPeerCertByName contains no usable names".into())
        }))
    }
}

impl ServerCertVerifier for XrayServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.pins.is_empty() {
            return self.verify_with_names(
                &self.default_verifier,
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }

        if self.hash_matches_pin(end_entity) {
            return Ok(ServerCertVerified::assertion());
        }

        let Some(pinned_ca_index) = intermediates
            .iter()
            .position(|certificate| self.hash_matches_pin(certificate))
        else {
            return Err(rustls::Error::General(
                "peer certificate chain does not match pinnedPeerCertSha256".into(),
            ));
        };

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                intermediates[pinned_ca_index].as_ref().to_vec(),
            ))
            .map_err(|error| {
                rustls::Error::General(format!(
                    "pinnedPeerCertSha256 matched an unusable CA certificate: {error}"
                ))
            })?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|error| {
                    rustls::Error::General(format!(
                        "cannot construct pinnedPeerCertSha256 verifier: {error}"
                    ))
                })?;
        let remaining_intermediates = intermediates
            .iter()
            .enumerate()
            .filter_map(|(index, certificate)| {
                (index != pinned_ca_index).then_some(certificate.clone())
            })
            .collect::<Vec<_>>();
        self.verify_with_names(
            &verifier,
            end_entity,
            &remaining_intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.default_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.default_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.default_verifier.supported_verify_schemes()
    }
}

fn constant_time_eq_32(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(actual) {
        difference |= left ^ right;
    }
    difference == 0
}

impl TlsTransport {
    /// Establish TLS and expose the negotiated ALPN before erasing the stream
    /// type. Realm uses this to choose HTTP/2 versus HTTP/1.1 with the same
    /// complete Xray TLS/ECH executor as XHTTP.
    pub(crate) async fn connect_negotiated(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<(BoxedStream, Option<Vec<u8>>)> {
        if super::boring_tls::is_required(&self.options) {
            let connector = self
                .boring_config
                .get_or_try_init(|| async {
                    super::boring_tls::build_connector(&self.options).map(Arc::new)
                })
                .await?
                .clone();
            return super::boring_tls::connect_negotiated(connector, &self.options, host, port)
                .await;
        }
        let cached_config = self
            .config
            .get_or_try_init(|| async {
                let mut options = self.options.clone();
                options.resolved_ech_config_list =
                    super::ech::resolve_ech_config(&options, host).await?;
                build_tls_client_config(&options).map(Arc::new)
            })
            .await?
            .clone();
        let config = if fingerprint_is_per_connection_randomized(&self.options.fingerprint) {
            let mut options = self.options.clone();
            options.resolved_ech_config_list =
                super::ech::resolve_ech_config(&options, host).await?;
            let mut fresh = build_tls_client_config(&options)?;
            // Keep the same shared session store while regenerating the
            // per-connection uTLS seed/profile.
            fresh.resumption = cached_config.resumption.clone();
            Arc::new(fresh)
        } else {
            cached_config.clone()
        };
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
        // Node socket policy and FinalMask wrap the raw carrier before TLS,
        // matching Xray's tcp.Dial ordering.
        let tcp = connect_boxed(host, port, false).await?;
        let connector = TlsConnector::from(config);
        let handshake_start = std::time::Instant::now();
        let stream =
            match tls_handshake_with_timeout(CONNECT_TIMEOUT, connector.connect(dns, tcp)).await {
                Ok(stream) => stream,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    tracing::warn!(
                        target: "dial::tls",
                        %host, port,
                        sni = %sni_str,
                        handshake_ms = handshake_start.elapsed().as_millis() as u64,
                        timeout_secs = CONNECT_TIMEOUT.as_secs(),
                        "TLS handshake timed out",
                    );
                    return Err(error);
                }
                Err(error) => {
                    tracing::warn!(
                        target: "dial::tls",
                        %host, port,
                        sni = %sni_str,
                        handshake_ms = handshake_start.elapsed().as_millis() as u64,
                        error = %error,
                        "TLS handshake failed",
                    );
                    return Err(error);
                }
            };
        tracing::info!(
            target: "dial::tls",
            %host, port,
            sni = %sni_str,
            handshake_ms = handshake_start.elapsed().as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "TLS handshake ok",
        );
        let negotiated = stream.get_ref().1.alpn_protocol().map(ToOwned::to_owned);
        Ok((Box::pin(stream), negotiated))
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        self.connect_negotiated(host, port)
            .await
            .map(|(stream, _)| stream)
    }
}

async fn tls_handshake_with_timeout<T, E>(
    timeout: Duration,
    handshake: impl Future<Output = Result<T, E>>,
) -> io::Result<T>
where
    E: std::fmt::Display,
{
    match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(io::Error::other(format!("TLS handshake: {error}"))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("TLS handshake timed out after {timeout:?}"),
        )),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resumption_debug(transport: &TlsTransport) -> String {
        format!(
            "{:?}",
            build_tls_client_config(&transport.options)
                .unwrap()
                .resumption
        )
    }

    #[test]
    fn session_resumption_is_disabled_by_default_and_only_enabled_explicitly() {
        let disabled = TlsTransport::new(TlsOptions::default());
        let enabled = TlsTransport::new(TlsOptions {
            enable_session_resumption: true,
            ..Default::default()
        });

        assert!(resumption_debug(&disabled).contains("NoClientSessionStorage"));
        assert!(resumption_debug(&disabled).contains("Disabled"));
        assert!(resumption_debug(&enabled).contains("ClientSessionMemoryCache"));
    }

    #[test]
    fn configured_xhttp_alpn_is_the_actual_rustls_offer() {
        let transport = TlsTransport::new(TlsOptions {
            alpn: vec!["h2".into(), "http/1.1".into()],
            ..Default::default()
        });

        assert_eq!(
            build_tls_client_config(&transport.options)
                .unwrap()
                .alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn default_is_xray_chrome_auto_and_unsafe_is_ordinary_rustls() {
        let shaped = build_tls_client_config(&TlsOptions::default()).unwrap();
        assert!(shaped.client_hello_customizer.is_some());
        assert_eq!(
            shaped.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        let ordinary = build_tls_client_config(&TlsOptions {
            fingerprint: "unsafe".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(ordinary.client_hello_customizer.is_none());
        assert!(ordinary.alpn_protocols.is_empty());
    }

    #[test]
    fn invalid_or_non_lowercase_fingerprint_fails_closed() {
        for fingerprint in ["HelloChrome_133", "not-a-real-fingerprint"] {
            let error = build_tls_client_config(&TlsOptions {
                fingerprint: fingerprint.into(),
                ..Default::default()
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn legacy_tls12_profile_can_omit_supported_versions() {
        let config = build_tls_client_config(&TlsOptions {
            fingerprint: "360".into(),
            ..Default::default()
        })
        .unwrap();
        let server_name = ServerName::try_from("example.com".to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut records = Vec::new();
        while connection.wants_write() {
            connection.write_tls(&mut records).unwrap();
        }
        assert!(!records.is_empty());
    }

    #[test]
    fn h3_uses_standard_quic_tls_instead_of_tcp_utls_shaping() {
        for fingerprint in ["", "chrome", "360"] {
            let config = build_tls_client_config(&TlsOptions {
                fingerprint: fingerprint.into(),
                alpn: vec!["h3".into()],
                ..Default::default()
            })
            .unwrap();
            assert_eq!(config.alpn_protocols, [b"h3".to_vec()]);
            assert!(
                config.client_hello_customizer.is_none(),
                "Xray ignores TCP uTLS fingerprint {fingerprint:?} on QUIC"
            );
        }

        let error = build_tls_client_config(&TlsOptions {
            fingerprint: "not-a-real-fingerprint".into(),
            alpn: vec!["h3".into()],
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn silent_tcp_peer_times_out_tls_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            std::future::pending::<()>().await;
            drop(socket);
        });

        let tcp = TcpStream::connect(address).await.unwrap();
        accepted_rx.await.unwrap();
        let transport = TlsTransport::new(TlsOptions {
            insecure: true,
            ..Default::default()
        });
        let connector = TlsConnector::from(Arc::new(
            build_tls_client_config(&transport.options).unwrap(),
        ));
        let server_name = ServerName::try_from("localhost".to_string()).unwrap();

        let error = tls_handshake_with_timeout(Duration::ZERO, connector.connect(server_name, tcp))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("TLS handshake timed out"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn handshake_error_is_not_reported_as_timeout() {
        let error = tls_handshake_with_timeout(Duration::from_secs(1), async {
            Err::<(), _>("synthetic handshake failure")
        })
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("synthetic handshake failure"));
    }
}
