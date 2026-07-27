//! Complete XHTTP listener TLS configuration and backend selection.

use std::{
    collections::HashMap,
    fmt,
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Cursor, Write},
    str,
    sync::{Arc, Mutex, RwLock, Weak},
    time::{Duration, Instant},
};

use base64::Engine as _;
use boring::{
    hpke::HpkeKey,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{
        AlpnError, NameType, SelectCertError, Ssl, SslAcceptor, SslEchKeys, SslMethod, SslOptions,
        SslSessionCacheMode, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use core_config::{
    model::{
        XhttpDownloadTlsCertificate, XhttpDownloadTlsSettings, XhttpListenAlpn,
        XhttpTlsCertificateUsage,
    },
    runtime_plan::XhttpListenTlsPlan,
};
use ocsp_stapler::Client as OcspClient;
use rasn_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus, ResponderId};
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use x509_parser::{
    asn1_rs::BitString as X509BitString,
    prelude::{FromDer, X509Certificate as ParsedX509Certificate},
    x509::AlgorithmIdentifier as X509AlgorithmIdentifier,
};

const ISSUED_CERTIFICATE_CACHE_CAPACITY: usize = 1024;
const ISSUED_CERTIFICATE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CERTIFICATE_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone)]
struct CertificateRefresh {
    certificate_path: String,
    key_path: String,
    interval: Duration,
    fetch_ocsp: bool,
}

impl CertificateRefresh {
    fn from_certificate(certificate: &XhttpDownloadTlsCertificate) -> Option<Self> {
        // Xray forces inline PEM to one-time loading. File-backed entries are
        // refreshed hourly by default, or at ocspStapling seconds when enabled.
        let certificate_path = certificate.certificate_file.as_ref()?.clone();
        let key_path = certificate.key_file.as_ref()?.clone();
        if certificate.one_time_loading.unwrap_or(false) {
            return None;
        }
        let ocsp_seconds = certificate.ocsp_stapling.unwrap_or(0);
        Some(Self {
            certificate_path,
            key_path,
            interval: if ocsp_seconds == 0 {
                CERTIFICATE_RELOAD_INTERVAL
            } else {
                Duration::from_secs(ocsp_seconds)
            },
            fetch_ocsp: ocsp_seconds != 0,
        })
    }
}

#[derive(Debug)]
struct RefreshLifetime {
    shutdown: Arc<tokio::sync::Notify>,
}

impl RefreshLifetime {
    fn new() -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        let shutdown = Arc::new(tokio::sync::Notify::new());
        (
            Arc::new(Self {
                shutdown: Arc::clone(&shutdown),
            }),
            shutdown,
        )
    }
}

impl Drop for RefreshLifetime {
    fn drop(&mut self) {
        // There is exactly one refresh task per lifetime. `notify_one` retains
        // a permit when the task has not reached `notified()` yet, avoiding a
        // shutdown race during listener construction or destruction.
        self.shutdown.notify_one();
    }
}

async fn wait_for_refresh(interval: Duration, shutdown: &tokio::sync::Notify) -> bool {
    tokio::select! {
        () = tokio::time::sleep(interval) => true,
        () = shutdown.notified() => false,
    }
}

fn spawn_refresh_task<F>(name: &str, future: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future);
        return Ok(());
    }

    std::thread::Builder::new()
        .name(format!("wuther-{name}"))
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(runtime) => runtime.block_on(future),
                Err(error) => tracing::error!(
                    target: "inbound::xhttp::tls",
                    %error,
                    "failed to create certificate refresh runtime"
                ),
            }
        })
        .map(|_| ())
        .map_err(|error| invalid(format!("spawn certificate refresh task: {error}")))
}

async fn fetch_ocsp_response(
    client: &OcspClient,
    leaf: &[u8],
    issuer: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    let issuer = issuer.ok_or_else(|| {
        invalid("ocspStapling requires the issuing certificate in the configured chain")
    })?;
    let response = client
        .query(leaf, issuer)
        .await
        .map_err(|error| invalid(format!("fetch OCSP response: {error:#}")))?;
    if !response
        .ocsp_validity
        .valid(chrono::Utc::now().fixed_offset())
    {
        return Err(invalid("OCSP response is outside its validity window"));
    }
    validate_ocsp_response(&response.raw, leaf, issuer)?;
    Ok(response.raw)
}

fn validate_ocsp_response(response: &[u8], leaf: &[u8], issuer: &[u8]) -> io::Result<()> {
    use sha1::{Digest as _, Sha1};

    let outer: OcspResponse = rasn::der::decode(response)
        .map_err(|error| invalid(format!("decode OCSP response: {error:#}")))?;
    if outer.status != OcspResponseStatus::Successful {
        return Err(invalid(format!(
            "OCSP responder returned {:?}",
            outer.status
        )));
    }
    let response_bytes = outer
        .bytes
        .ok_or_else(|| invalid("OCSP response has no responseBytes"))?;
    if response_bytes.r#type.to_string() != "1.3.6.1.5.5.7.48.1.1" {
        return Err(invalid("OCSP response is not id-pkix-ocsp-basic"));
    }
    let basic: BasicOcspResponse = rasn::der::decode(response_bytes.response.as_ref())
        .map_err(|error| invalid(format!("decode BasicOCSPResponse: {error:#}")))?;
    if basic.tbs_response_data.responses.len() != 1 {
        return Err(invalid(
            "OCSP response must contain exactly one SingleResponse",
        ));
    }

    let (_, leaf_certificate) = ParsedX509Certificate::from_der(leaf)
        .map_err(|error| invalid(format!("parse OCSP leaf certificate: {error}")))?;
    let (_, issuer_certificate) = ParsedX509Certificate::from_der(issuer)
        .map_err(|error| invalid(format!("parse OCSP issuer certificate: {error}")))?;
    if leaf_certificate.issuer() != issuer_certificate.subject() {
        return Err(invalid(
            "OCSP issuer certificate subject does not match the leaf issuer",
        ));
    }
    leaf_certificate
        .verify_signature(Some(issuer_certificate.public_key()))
        .map_err(|error| invalid(format!("verify leaf certificate with OCSP issuer: {error}")))?;

    let single = &basic.tbs_response_data.responses[0];
    if single.cert_id.hash_algorithm.algorithm.to_string() != "1.3.14.3.2.26" {
        return Err(invalid(
            "OCSP CertID did not use the SHA-1 algorithm requested by Xray",
        ));
    }
    let leaf_serial =
        x509_parser::num_bigint::BigUint::from_bytes_be(leaf_certificate.raw_serial());
    if single.cert_id.serial_number.to_string() != leaf_serial.to_string() {
        return Err(invalid("OCSP CertID serial number does not match the leaf"));
    }
    let expected_name_hash = Sha1::digest(leaf_certificate.issuer().as_raw());
    if single.cert_id.issuer_name_hash.as_ref() != expected_name_hash.as_slice() {
        return Err(invalid("OCSP CertID issuerNameHash mismatch"));
    }
    let expected_key_hash = Sha1::digest(
        issuer_certificate
            .public_key()
            .subject_public_key
            .data
            .as_ref(),
    );
    if single.cert_id.issuer_key_hash.as_ref() != expected_key_hash.as_slice() {
        return Err(invalid("OCSP CertID issuerKeyHash mismatch"));
    }

    let mut signer_certificates = basic
        .certs
        .as_ref()
        .map(|certificates| {
            certificates
                .iter()
                .map(|certificate| {
                    rasn::der::encode(certificate).map_err(|error| {
                        invalid(format!(
                            "encode embedded OCSP signer certificate: {error:#}"
                        ))
                    })
                })
                .collect::<io::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    signer_certificates.push(issuer.to_vec());
    let signer_der = signer_certificates
        .iter()
        .find(|certificate| {
            ParsedX509Certificate::from_der(certificate).is_ok_and(|(_, certificate)| {
                ocsp_responder_matches(&basic.tbs_response_data.responder_id, &certificate)
                    .unwrap_or(false)
            })
        })
        .ok_or_else(|| invalid("OCSP response contains no matching responder certificate"))?;
    let (_, signer) = ParsedX509Certificate::from_der(signer_der)
        .map_err(|error| invalid(format!("parse OCSP signer certificate: {error}")))?;
    if signer_der.as_slice() != issuer {
        signer
            .verify_signature(Some(issuer_certificate.public_key()))
            .map_err(|error| invalid(format!("verify delegated OCSP signer: {error}")))?;
        if !signer.validity().is_valid() {
            return Err(invalid(
                "delegated OCSP signer certificate is not valid now",
            ));
        }
        let extended_key_usage = signer
            .extended_key_usage()
            .map_err(|error| invalid(format!("parse OCSP signer EKU: {error}")))?
            .ok_or_else(|| invalid("delegated OCSP signer has no extended key usage"))?;
        if !extended_key_usage.value.ocsp_signing {
            return Err(invalid(
                "delegated OCSP signer lacks id-kp-OCSPSigning usage",
            ));
        }
        if signer
            .key_usage()
            .map_err(|error| invalid(format!("parse OCSP signer key usage: {error}")))?
            .is_some_and(|usage| !usage.value.digital_signature())
        {
            return Err(invalid(
                "delegated OCSP signer key usage lacks digitalSignature",
            ));
        }
    }

    let signature_algorithm = rasn::der::encode(&basic.signature_algorithm)
        .map_err(|error| invalid(format!("encode OCSP signature algorithm: {error:#}")))?;
    let (remaining, signature_algorithm) = X509AlgorithmIdentifier::from_der(&signature_algorithm)
        .map_err(|error| invalid(format!("parse OCSP signature algorithm: {error}")))?;
    if !remaining.is_empty() || basic.signature.len() % 8 != 0 {
        return Err(invalid("OCSP signature has a non-canonical DER encoding"));
    }
    let signed_data = rasn::der::encode(&basic.tbs_response_data)
        .map_err(|error| invalid(format!("encode OCSP signed response data: {error:#}")))?;
    let signature = X509BitString::new(0, basic.signature.as_raw_slice());
    x509_parser::verify::verify_signature(
        signer.public_key(),
        &signature_algorithm,
        &signature,
        &signed_data,
    )
    .map_err(|error| invalid(format!("verify OCSP response signature: {error}")))
}

fn ocsp_responder_matches(
    responder_id: &ResponderId,
    certificate: &ParsedX509Certificate<'_>,
) -> io::Result<bool> {
    use sha1::{Digest as _, Sha1};

    match responder_id {
        ResponderId::ByName(name) => rasn::der::encode(name)
            .map(|encoded| encoded == certificate.subject().as_raw())
            .map_err(|error| invalid(format!("encode OCSP responder name: {error:#}"))),
        ResponderId::ByKey(key_hash) => Ok(key_hash.as_ref()
            == Sha1::digest(certificate.public_key().subject_public_key.data.as_ref()).as_slice()),
    }
}

fn new_ocsp_client() -> OcspClient {
    // ocsp-stapler deliberately builds reqwest with rustls's "no provider"
    // feature so applications with more than one crypto backend choose the
    // process-wide provider. WutherCore normally installs ring at startup, but
    // this reusable acceptor can also be constructed directly by a library or
    // test, so make the same idempotent choice here before reqwest is built.
    let _ = rustls::crypto::ring::default_provider().install_default();
    OcspClient::new()
}

pub(crate) enum PreparedTlsAcceptor {
    Rustls(TlsAcceptor),
    Boring(SslAcceptor),
}

/// Backend-neutral encrypted carrier returned by [`XrayServerTlsAcceptor`].
///
/// The concrete stream is either tokio-rustls or tokio-boring.  Keeping that
/// detail behind one trait object lets HTTP, gRPC, WebSocket and future TCP
/// listeners share the complete Xray TLS implementation without selecting or
/// duplicating a TLS backend.
pub trait XrayServerTlsStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> XrayServerTlsStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A backend-neutral TLS server stream suitable for protocol parsers such as
/// hyper or tonic.
pub type XrayServerTlsCarrier = Box<dyn XrayServerTlsStream>;

/// Prepared Xray-compatible server TLS configuration.
///
/// [`Self::from_xray_settings`] is the reusable public entry point.  It honors
/// the full typed settings object, including certificate sources, SNI routing,
/// mTLS roots, protocol/cipher/curve constraints, dynamic `usage=issue`, key
/// logging, session resumption and BoringSSL-backed ECH/TLS-1.0 compatibility.
pub struct XrayServerTlsAcceptor {
    inner: PreparedTlsAcceptor,
}

impl XrayServerTlsAcceptor {
    /// Validate and prepare a TCP TLS acceptor from the canonical Xray settings.
    ///
    /// ALPN is taken from `settings.alpn`.  Callers such as gRPC should set it
    /// explicitly to `["h2"]`; an absent ALPN list is valid for protocols that
    /// negotiate outside TLS.  `require_client_certificate` makes every client
    /// present a chain rooted in a `usage=verify` certificate.
    pub fn from_xray_settings(
        settings: XhttpDownloadTlsSettings,
        require_client_certificate: bool,
    ) -> io::Result<Self> {
        let alpn = settings.alpn.clone().unwrap_or_default();
        let plan = XhttpListenTlsPlan {
            cert_path: None,
            key_path: None,
            settings,
            require_client_certificate,
        };
        build_for_alpn(&plan, &alpn, false).map(|inner| Self { inner })
    }

    /// Complete a TLS handshake over any Tokio bidirectional byte stream.
    ///
    /// This accepts ordinary `TcpStream`s as well as wrapped/test transports;
    /// no socket ownership or listener type is imposed by the TLS layer.
    pub async fn accept<S>(&self, stream: S) -> io::Result<XrayServerTlsCarrier>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match &self.inner {
            PreparedTlsAcceptor::Rustls(acceptor) => acceptor
                .accept(stream)
                .await
                .map(|stream| Box::new(stream) as XrayServerTlsCarrier)
                .map_err(|error| invalid(format!("TLS server handshake: {error}"))),
            PreparedTlsAcceptor::Boring(acceptor) => tokio_boring::accept(acceptor, stream)
                .await
                .map(|stream| Box::new(stream) as XrayServerTlsCarrier)
                .map_err(|error| invalid(format!("BoringSSL server handshake: {error}"))),
        }
    }
}

pub(crate) fn build(
    tls: &XhttpListenTlsPlan,
    alpn: &[XhttpListenAlpn],
    http3: bool,
) -> io::Result<PreparedTlsAcceptor> {
    let alpn = alpn
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    build_for_alpn(tls, &alpn, http3)
}

fn build_for_alpn(
    tls: &XhttpListenTlsPlan,
    alpn: &[String],
    http3: bool,
) -> io::Result<PreparedTlsAcceptor> {
    tls.settings
        .validate()
        .map_err(|error| invalid(format!("TLS settings: {error}")))?;
    validate_alpn(alpn)?;
    validate_server_only_fields(tls)?;
    if requires_boring(tls) {
        if http3 {
            return Err(unsupported(
                "HTTP/3 listener cannot use TLS 1.0/1.1, P-521, legacy ciphers, or echServerKeys with Quinn's rustls QUIC backend",
            ));
        }
        return build_boring(tls, alpn).map(PreparedTlsAcceptor::Boring);
    }
    build_rustls(tls, alpn)
        .map(|config| PreparedTlsAcceptor::Rustls(TlsAcceptor::from(Arc::new(config))))
}

pub(crate) fn build_quic(
    tls: &XhttpListenTlsPlan,
    alpn: &[XhttpListenAlpn],
) -> io::Result<ServerConfig> {
    let alpn = alpn
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    tls.settings
        .validate()
        .map_err(|error| invalid(format!("TLS settings: {error}")))?;
    validate_alpn(&alpn)?;
    validate_server_only_fields(tls)?;
    if requires_boring(tls) {
        return Err(unsupported(
            "HTTP/3 listener TLS settings require a backend that cannot be composed with Quinn",
        ));
    }
    build_rustls(tls, &alpn)
}

fn validate_server_only_fields(tls: &XhttpListenTlsPlan) -> io::Result<()> {
    let settings = &tls.settings;
    if settings.ech_config_list.is_some() {
        return Err(invalid(
            "listener tls.echConfigList is client-only; configure echServerKeys on a server",
        ));
    }
    if settings
        .fingerprint
        .as_deref()
        .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("unsafe"))
    {
        return Err(invalid("listener tls.fingerprint is client-only"));
    }
    if settings
        .pinned_peer_cert_sha256
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || settings
            .verify_peer_cert_by_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(invalid(
            "listener certificate pins/name overrides are client-only; use requireClientCertificate with usage=verify roots for mTLS",
        ));
    }
    if !tls.require_client_certificate && settings.disable_system_root.unwrap_or(false) {
        return Err(invalid(
            "listener disableSystemRoot only has meaning with requireClientCertificate=true",
        ));
    }
    Ok(())
}

fn requires_boring(tls: &XhttpListenTlsPlan) -> bool {
    let settings = &tls.settings;
    settings.ech_server_keys.is_some()
        || settings
            .min_version
            .as_deref()
            .is_some_and(|value| matches!(value.trim(), "1.0" | "1.1"))
        || settings.curve_preferences.as_ref().is_some_and(|curves| {
            curves
                .iter()
                .any(|curve| curve.eq_ignore_ascii_case("curvep521"))
        })
        || settings
            .cipher_suites
            .as_deref()
            .is_some_and(|suites| suites.split(':').map(str::trim).any(is_boring_only_cipher))
}

#[derive(Debug, Clone)]
struct DynamicIssuer {
    material: Arc<RwLock<IssuerMaterial>>,
    build_chain: bool,
    _refresh_lifetime: Option<Arc<RefreshLifetime>>,
}

#[derive(Debug, Clone)]
struct IssuerMaterial {
    certificate_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl DynamicIssuer {
    fn issue(&self, domain: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if domain.is_empty() {
            return Err(invalid("usage=issue requires a non-empty TLS SNI"));
        }
        let material = self
            .material
            .read()
            .map_err(|_| invalid("usage=issue CA refresh lock is poisoned"))?;
        let ca_pem = str::from_utf8(&material.certificate_pem)
            .map_err(|error| invalid(format!("usage=issue CA is not UTF-8 PEM: {error}")))?;
        let key_pem = str::from_utf8(&material.key_pem)
            .map_err(|error| invalid(format!("usage=issue key is not UTF-8 PEM: {error}")))?;
        let ca_key = KeyPair::from_pem(key_pem)
            .map_err(|error| invalid(format!("parse usage=issue CA key: {error}")))?;
        let ca_params = CertificateParams::from_ca_cert_pem(ca_pem)
            .map_err(|error| invalid(format!("parse usage=issue CA certificate: {error}")))?;
        let ca_certificate = ca_params
            .self_signed(&ca_key)
            .map_err(|error| invalid(format!("materialize usage=issue CA: {error}")))?;

        let leaf_key = KeyPair::generate()
            .map_err(|error| invalid(format!("generate usage=issue leaf key: {error}")))?;
        let mut leaf_params = CertificateParams::new(vec![domain.to_owned()])
            .map_err(|error| invalid(format!("invalid usage=issue SNI {domain:?}: {error}")))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, domain);
        leaf_params.distinguished_name = distinguished_name;
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .map_err(|error| invalid(format!("sign usage=issue leaf for {domain:?}: {error}")))?;

        let mut certificate = leaf.pem().into_bytes();
        if self.build_chain {
            if !certificate.ends_with(b"\n") {
                certificate.push(b'\n');
            }
            certificate.extend_from_slice(&material.certificate_pem);
        }
        Ok((certificate, leaf_key.serialize_pem().into_bytes()))
    }
}

fn load_dynamic_issuers(tls: &XhttpListenTlsPlan) -> io::Result<Vec<DynamicIssuer>> {
    tls.settings
        .certificates
        .iter()
        .filter(|certificate| certificate.usage == Some(XhttpTlsCertificateUsage::Issue))
        .map(|certificate| {
            let material = IssuerMaterial {
                certificate_pem: certificate_pem(certificate)?,
                key_pem: key_pem(certificate)?,
            };
            validate_dynamic_issuer_material(&material)?;
            let material = Arc::new(RwLock::new(material));
            let refresh_lifetime =
                if let Some(refresh) = CertificateRefresh::from_certificate(certificate) {
                    let (lifetime, shutdown) = RefreshLifetime::new();
                    spawn_dynamic_issuer_refresh(Arc::downgrade(&material), refresh, shutdown)?;
                    Some(lifetime)
                } else {
                    None
                };
            Ok(DynamicIssuer {
                material,
                build_chain: certificate.build_chain.unwrap_or(false),
                _refresh_lifetime: refresh_lifetime,
            })
        })
        .collect()
}

fn validate_dynamic_issuer_material(material: &IssuerMaterial) -> io::Result<()> {
    let certificate_pem = str::from_utf8(&material.certificate_pem)
        .map_err(|error| invalid(format!("usage=issue CA is not UTF-8 PEM: {error}")))?;
    let key_pem = str::from_utf8(&material.key_pem)
        .map_err(|error| invalid(format!("usage=issue key is not UTF-8 PEM: {error}")))?;
    let params = CertificateParams::from_ca_cert_pem(certificate_pem)
        .map_err(|error| invalid(format!("parse usage=issue CA certificate: {error}")))?;
    if !matches!(params.is_ca, IsCa::Ca(_)) {
        return Err(invalid(
            "usage=issue certificate must have CA basic constraints",
        ));
    }
    KeyPair::from_pem(key_pem)
        .map_err(|error| invalid(format!("parse usage=issue CA key: {error}")))?;

    let certificate = X509::stack_from_pem(&material.certificate_pem)
        .map_err(|error| invalid(format!("parse usage=issue X.509 certificate: {error}")))?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("usage=issue certificate chain is empty"))?;
    let certificate_key = certificate
        .public_key()
        .map_err(|error| invalid(format!("read usage=issue CA public key: {error}")))?;
    let private_key = PKey::private_key_from_pem(&material.key_pem)
        .map_err(|error| invalid(format!("parse usage=issue private key: {error}")))?;
    if !certificate_key.public_eq(&private_key) {
        return Err(invalid("usage=issue certificate/private key mismatch"));
    }
    Ok(())
}

fn spawn_dynamic_issuer_refresh(
    material: Weak<RwLock<IssuerMaterial>>,
    refresh: CertificateRefresh,
    shutdown: Arc<tokio::sync::Notify>,
) -> io::Result<()> {
    spawn_refresh_task("tls-issuer-refresh", async move {
        loop {
            let Some(material) = material.upgrade() else {
                break;
            };
            let refreshed = async {
                let certificate_pem =
                    tokio::fs::read(&refresh.certificate_path)
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "read usage=issue certificate {:?}: {error}",
                                    refresh.certificate_path
                                ),
                            )
                        })?;
                let key_pem = tokio::fs::read(&refresh.key_path).await.map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("read usage=issue key {:?}: {error}", refresh.key_path),
                    )
                })?;
                let candidate = IssuerMaterial {
                    certificate_pem,
                    key_pem,
                };
                validate_dynamic_issuer_material(&candidate)?;
                Ok::<_, io::Error>(candidate)
            }
            .await;
            match refreshed {
                Ok(candidate) => {
                    if let Ok(mut current) = material.write()
                        && (current.certificate_pem != candidate.certificate_pem
                            || current.key_pem != candidate.key_pem)
                    {
                        *current = candidate;
                        tracing::info!(
                            target: "inbound::xhttp::tls",
                            "reloaded usage=issue certificate authority"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    target: "inbound::xhttp::tls",
                    %error,
                    "failed to refresh usage=issue certificate authority"
                ),
            }
            drop(material);
            if !wait_for_refresh(refresh.interval, &shutdown).await {
                break;
            }
        }
    })
}

fn insert_bounded_cache<T>(
    cache: &mut HashMap<String, (Arc<T>, Instant)>,
    domain: String,
    value: Arc<T>,
) {
    if cache.len() >= ISSUED_CERTIFICATE_CACHE_CAPACITY && !cache.contains_key(&domain) {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (_, created))| *created)
            .map(|(domain, _)| domain.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(domain, (value, Instant::now()));
}

#[derive(Debug)]
struct RustlsIdentity {
    current: RwLock<RustlsIdentityState>,
    _refresh_lifetime: Option<Arc<RefreshLifetime>>,
}

#[derive(Debug)]
struct RustlsIdentityState {
    names: Vec<String>,
    key: Arc<CertifiedKey>,
}

impl RustlsIdentity {
    fn for_server_name(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().and_then(|current| {
            current
                .names
                .iter()
                .any(|name| dns_name_matches(name, sni))
                .then(|| Arc::clone(&current.key))
        })
    }

    fn key(&self) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .ok()
            .map(|current| Arc::clone(&current.key))
    }
}

#[derive(Debug)]
struct RustlsResolver {
    identities: Vec<Arc<RustlsIdentity>>,
    issuers: Vec<DynamicIssuer>,
    issued: Mutex<HashMap<String, (Arc<CertifiedKey>, Instant)>>,
    provider: Arc<CryptoProvider>,
    reject_unknown_sni: bool,
}

impl ResolvesServerCert for RustlsResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name();
        let key = sni.and_then(|sni| {
            self.identities
                .iter()
                .find_map(|item| item.for_server_name(sni))
        });
        if let Some(key) = key {
            return key
                .key
                .choose_scheme(hello.signature_schemes())
                .map(|_| key);
        }

        if let Some(sni) = sni.filter(|sni| !sni.is_empty()) {
            if let Some(key) = self.cached_or_issue(sni) {
                if key.key.choose_scheme(hello.signature_schemes()).is_some() {
                    return Some(key);
                }
            }
        }

        let identity = (!self.reject_unknown_sni)
            .then(|| self.identities.first())
            .flatten()?;
        let key = identity.key()?;
        key.key
            .choose_scheme(hello.signature_schemes())
            .map(|_| key)
    }
}

impl RustlsResolver {
    fn cached_or_issue(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let domain = domain.to_ascii_lowercase();
        let now = Instant::now();
        if let Ok(mut issued) = self.issued.lock() {
            if let Some((key, created)) = issued.get(&domain) {
                if now.duration_since(*created) < ISSUED_CERTIFICATE_CACHE_TTL {
                    return Some(Arc::clone(key));
                }
                issued.remove(&domain);
            }
        }

        for issuer in &self.issuers {
            let result = issuer.issue(&domain).and_then(|(certificate, key)| {
                let (chain, key, _) = parse_server_certificate(&certificate, &key)?;
                CertifiedKey::from_der(chain, key, &self.provider).map_err(|error| {
                    invalid(format!("build usage=issue leaf for {domain:?}: {error}"))
                })
            });
            match result {
                Ok(key) => {
                    let key = Arc::new(key);
                    if let Ok(mut issued) = self.issued.lock() {
                        insert_bounded_cache(&mut issued, domain.clone(), Arc::clone(&key));
                    }
                    return Some(key);
                }
                Err(error) => tracing::warn!(
                    target: "inbound::xhttp::tls",
                    %error,
                    %domain,
                    "dynamic TLS certificate issuance failed"
                ),
            }
        }
        None
    }
}

fn build_rustls(tls: &XhttpListenTlsPlan, alpn: &[String]) -> io::Result<ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    configure_rustls_provider(&mut provider, tls)?;
    let provider = Arc::new(provider);
    let versions = rustls_versions(tls)?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&versions)
        .map_err(|error| invalid(format!("XHTTP TLS versions: {error}")))?;
    let builder = if tls.require_client_certificate {
        let roots = client_auth_roots(tls)?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|error| invalid(format!("XHTTP mTLS roots: {error}")))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let identities = load_rustls_identities(tls, Arc::clone(&provider))?;
    let issuers = load_dynamic_issuers(tls)?;
    let mut config = builder.with_cert_resolver(Arc::new(RustlsResolver {
        identities,
        issuers,
        issued: Mutex::new(HashMap::new()),
        provider,
        reject_unknown_sni: tls.settings.reject_unknown_sni.unwrap_or(false),
    }));
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    if !tls.settings.enable_session_resumption.unwrap_or(false) {
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }
    if let Some(path) = key_log_path(tls) {
        config.key_log = Arc::new(PathKeyLog::open(path)?);
    }
    Ok(config)
}

fn rustls_versions(
    tls: &XhttpListenTlsPlan,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let (min, max) = version_range(tls)?;
    if min < 12 {
        return Err(unsupported("TLS 1.0/1.1 requires BoringSSL"));
    }
    let mut versions = Vec::new();
    if max >= 13 && min <= 13 {
        versions.push(&rustls::version::TLS13);
    }
    if max >= 12 && min <= 12 {
        versions.push(&rustls::version::TLS12);
    }
    Ok(versions)
}

fn configure_rustls_provider(
    provider: &mut CryptoProvider,
    tls: &XhttpListenTlsPlan,
) -> io::Result<()> {
    if let Some(configured) = tls.settings.cipher_suites.as_deref() {
        let names = configured.split(':').map(str::trim).collect::<Vec<_>>();
        provider.cipher_suites.retain(|suite| {
            names
                .iter()
                .any(|name| *name == format!("{:?}", suite.suite()))
        });
        if provider.cipher_suites.is_empty() {
            return Err(unsupported(
                "listener cipherSuites contains no rustls-supported suite",
            ));
        }
    }
    if let Some(curves) = &tls.settings.curve_preferences {
        provider.kx_groups = curves
            .iter()
            .map(|curve| match curve.to_ascii_lowercase().as_str() {
                "x25519" => Ok(rustls::crypto::aws_lc_rs::kx_group::X25519),
                "curvep256" => Ok(rustls::crypto::aws_lc_rs::kx_group::SECP256R1),
                "curvep384" => Ok(rustls::crypto::aws_lc_rs::kx_group::SECP384R1),
                "x25519mlkem768" => Ok(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768),
                "secp256r1mlkem768" => Ok(rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768),
                value => Err(unsupported(format!(
                    "listener curve {value:?} requires an unavailable TLS backend"
                ))),
            })
            .collect::<io::Result<Vec<_>>>()?;
    }
    Ok(())
}

fn load_rustls_identities(
    tls: &XhttpListenTlsPlan,
    provider: Arc<CryptoProvider>,
) -> io::Result<Vec<Arc<RustlsIdentity>>> {
    let mut identities = Vec::new();
    if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
        let certificate = std::fs::read(cert_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read XHTTP certificate {cert_path:?}: {error}"),
            )
        })?;
        let key = std::fs::read(key_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read XHTTP private key {key_path:?}: {error}"),
            )
        })?;
        let state = rustls_identity_state(
            &certificate,
            &key,
            tls.settings.server_name.as_deref(),
            &provider,
            "listener certificate",
        )?;
        identities.push(Arc::new(RustlsIdentity {
            current: RwLock::new(state),
            _refresh_lifetime: None,
        }));
        return Ok(identities);
    }

    for (index, certificate) in tls
        .settings
        .certificates
        .iter()
        .filter(|certificate| {
            certificate
                .usage
                .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
                == XhttpTlsCertificateUsage::Encipherment
        })
        .enumerate()
    {
        let state = rustls_identity_state(
            &certificate_pem(certificate)?,
            &key_pem(certificate)?,
            tls.settings.server_name.as_deref(),
            &provider,
            &format!("certificates[{index}]"),
        )?;
        let refresh = CertificateRefresh::from_certificate(certificate);
        let (refresh_lifetime, shutdown) = refresh
            .as_ref()
            .map(|_| RefreshLifetime::new())
            .map_or((None, None), |(lifetime, shutdown)| {
                (Some(lifetime), Some(shutdown))
            });
        let identity = Arc::new(RustlsIdentity {
            current: RwLock::new(state),
            _refresh_lifetime: refresh_lifetime,
        });
        if let Some(refresh) = refresh {
            spawn_rustls_identity_refresh(
                Arc::downgrade(&identity),
                refresh,
                Arc::clone(&provider),
                tls.settings.server_name.clone(),
                shutdown.expect("refresh shutdown is created with refresh settings"),
            )?;
        }
        identities.push(identity);
    }
    Ok(identities)
}

type ServerCertificate = (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<String>,
);

fn parse_server_certificate(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<ServerCertificate> {
    let chain = rustls_pemfile::certs(&mut Cursor::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid(format!("parse XHTTP certificate PEM: {error}")))?;
    if chain.is_empty() {
        return Err(invalid("XHTTP certificate PEM contains no certificate"));
    }
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
        .map_err(|error| invalid(format!("parse XHTTP private key PEM: {error}")))?
        .ok_or_else(|| invalid("XHTTP private key PEM contains no supported key"))?;
    let names = certificate_names(chain[0].as_ref())?;
    Ok((chain, key, names))
}

fn rustls_identity_state(
    cert_pem: &[u8],
    key_pem: &[u8],
    configured_name: Option<&str>,
    provider: &CryptoProvider,
    label: &str,
) -> io::Result<RustlsIdentityState> {
    let (chain, key, mut names) = parse_server_certificate(cert_pem, key_pem)?;
    if let Some(server_name) = configured_name.filter(|name| !name.is_empty())
        && !names.iter().any(|name| name == server_name)
    {
        names.push(server_name.to_ascii_lowercase());
    }
    let key = CertifiedKey::from_der(chain, key, provider)
        .map_err(|error| invalid(format!("XHTTP TLS {label} key mismatch: {error}")))?;
    Ok(RustlsIdentityState {
        names,
        key: Arc::new(key),
    })
}

fn spawn_rustls_identity_refresh(
    identity: Weak<RustlsIdentity>,
    refresh: CertificateRefresh,
    provider: Arc<CryptoProvider>,
    configured_name: Option<String>,
    shutdown: Arc<tokio::sync::Notify>,
) -> io::Result<()> {
    spawn_refresh_task("tls-certificate-refresh", async move {
        let ocsp = refresh.fetch_ocsp.then(new_ocsp_client);
        loop {
            let Some(identity) = identity.upgrade() else {
                break;
            };
            let refreshed = async {
                let certificate =
                    tokio::fs::read(&refresh.certificate_path)
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "read XHTTP certificate {:?}: {error}",
                                    refresh.certificate_path
                                ),
                            )
                        })?;
                let key = tokio::fs::read(&refresh.key_path).await.map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("read XHTTP key {:?}: {error}", refresh.key_path),
                    )
                })?;
                let mut state = rustls_identity_state(
                    &certificate,
                    &key,
                    configured_name.as_deref(),
                    &provider,
                    "reloaded certificate",
                )?;
                if let Some(client) = &ocsp {
                    match fetch_ocsp_response(
                        client,
                        state.key.cert[0].as_ref(),
                        state.key.cert.get(1).map(AsRef::as_ref),
                    )
                    .await
                    {
                        Ok(response) => {
                            Arc::get_mut(&mut state.key)
                                .expect("newly constructed certified key is uniquely owned")
                                .ocsp = Some(response)
                        }
                        Err(error) => tracing::warn!(
                            target: "inbound::xhttp::tls",
                            %error,
                            "failed to refresh OCSP staple"
                        ),
                    }
                }
                Ok::<_, io::Error>(state)
            }
            .await;
            match refreshed {
                Ok(state) => {
                    if let Ok(mut current) = identity.current.write() {
                        *current = state;
                    }
                }
                Err(error) => tracing::warn!(
                    target: "inbound::xhttp::tls",
                    %error,
                    "failed to refresh XHTTP TLS certificate"
                ),
            }
            drop(identity);
            if !wait_for_refresh(refresh.interval, &shutdown).await {
                break;
            }
        }
    })
}

fn certificate_names(der: &[u8]) -> io::Result<Vec<String>> {
    let certificate = X509::from_der(der)
        .map_err(|error| invalid(format!("parse XHTTP leaf certificate: {error}")))?;
    let mut names = Vec::new();
    for common_name in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(common_name) = common_name.data().as_utf8() {
            let common_name = common_name.to_string();
            if !common_name.is_empty() {
                names.push(common_name.to_ascii_lowercase());
            }
        }
    }
    if let Some(alternative_names) = certificate.subject_alt_names() {
        for name in alternative_names {
            if let Some(name) = name.dnsname() {
                let name = name.to_ascii_lowercase();
                if !names.iter().any(|current| current == &name) {
                    names.push(name);
                }
            }
        }
    }
    Ok(names)
}

fn client_auth_roots(tls: &XhttpListenTlsPlan) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in tls
        .settings
        .certificates
        .iter()
        .filter(|certificate| certificate.usage == Some(XhttpTlsCertificateUsage::Verify))
    {
        let pem = certificate_pem(certificate)?;
        for certificate in rustls_pemfile::certs(&mut Cursor::new(pem)) {
            roots
                .add(certificate.map_err(|error| invalid(format!("parse mTLS CA: {error}")))?)
                .map_err(|error| invalid(format!("add mTLS CA: {error}")))?;
        }
    }
    Ok(roots)
}

fn dns_name_matches(pattern: &str, actual: &str) -> bool {
    if pattern.eq_ignore_ascii_case(actual) {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    actual
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.'))
}

#[derive(Clone)]
struct BoringIdentity {
    names: Vec<String>,
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
    ocsp: Option<Vec<u8>>,
}

struct BoringIdentitySlot {
    current: RwLock<BoringIdentity>,
    _refresh_lifetime: Option<Arc<RefreshLifetime>>,
}

impl BoringIdentitySlot {
    fn for_server_name(&self, sni: &str) -> Option<Arc<BoringIdentity>> {
        self.current.read().ok().and_then(|current| {
            current
                .names
                .iter()
                .any(|name| dns_name_matches(name, sni))
                .then(|| Arc::new(current.clone()))
        })
    }

    fn snapshot(&self) -> Option<Arc<BoringIdentity>> {
        self.current
            .read()
            .ok()
            .map(|current| Arc::new(current.clone()))
    }
}

fn build_boring(tls: &XhttpListenTlsPlan, alpn: &[String]) -> io::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|error| invalid(format!("create BoringSSL acceptor: {error}")))?;
    let (min, max) = version_range(tls)?;
    if min < 12 {
        builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    }
    builder
        .set_min_proto_version(Some(ssl_version(min)))
        .map_err(|error| invalid(format!("set listener minVersion: {error}")))?;
    builder
        .set_max_proto_version(Some(ssl_version(max)))
        .map_err(|error| invalid(format!("set listener maxVersion: {error}")))?;
    apply_boring_ciphers(&mut builder, tls.settings.cipher_suites.as_deref(), min)?;
    apply_boring_curves(&mut builder, tls.settings.curve_preferences.as_deref())?;

    let identities = Arc::new(load_boring_identities(tls)?);
    let issuers = Arc::new(load_dynamic_issuers(tls)?);
    let ocsp_enabled = tls.settings.certificates.iter().any(|certificate| {
        certificate
            .usage
            .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
            == XhttpTlsCertificateUsage::Encipherment
            && CertificateRefresh::from_certificate(certificate)
                .is_some_and(|refresh| refresh.fetch_ocsp)
    });
    let selected_identity_index = ocsp_enabled
        .then(Ssl::new_ex_index::<Arc<BoringIdentity>>)
        .transpose()
        .map_err(|error| invalid(format!("allocate listener OCSP identity slot: {error}")))?;
    if let Some(first) = identities.first() {
        let first = first
            .snapshot()
            .ok_or_else(|| invalid("XHTTP TLS certificate refresh lock is poisoned"))?;
        install_boring_identity_on_context(&mut builder, &first)?;
    } else if issuers.is_empty() {
        return Err(invalid(
            "XHTTP TLS listener has no encipherment certificate or usage=issue CA",
        ));
    }
    if !identities.is_empty() || !issuers.is_empty() {
        let reject_unknown = tls.settings.reject_unknown_sni.unwrap_or(false);
        let issued = Arc::new(Mutex::new(
            HashMap::<String, (Arc<BoringIdentity>, Instant)>::new(),
        ));
        builder.set_select_certificate_callback(move |mut hello| {
            let sni = hello
                .servername(NameType::HOST_NAME)
                .map(|value| value.to_ascii_lowercase());
            let static_identity = sni.as_deref().and_then(|sni| {
                identities
                    .iter()
                    .find_map(|identity| identity.for_server_name(sni))
            });
            let dynamic_identity = if static_identity.is_none() {
                sni.as_deref().and_then(|sni| {
                    cached_or_issue_boring(sni, &issuers, &issued)
                        .map_err(|error| {
                            tracing::warn!(
                                target: "inbound::xhttp::tls",
                                %error,
                                %sni,
                                "dynamic BoringSSL certificate issuance failed"
                            );
                            error
                        })
                        .ok()
                })
            } else {
                None
            };
            let identity = static_identity
                .or(dynamic_identity)
                .or_else(|| {
                    (!reject_unknown)
                        .then(|| identities.first().and_then(|identity| identity.snapshot()))
                        .flatten()
                })
                .ok_or(SelectCertError::ERROR)?;
            let ssl = hello.ssl_mut();
            if let Some(index) = selected_identity_index {
                ssl.set_ex_data(index, Arc::clone(&identity));
            }
            install_boring_identity_on_ssl(ssl, &identity).map_err(|_| SelectCertError::ERROR)
        });
    }

    if let Some(index) = selected_identity_index {
        builder
            .set_status_callback(move |ssl| {
                let response = ssl
                    .ex_data(index)
                    .and_then(|identity| identity.ocsp.clone());
                let Some(response) = response else {
                    return Ok(false);
                };
                ssl.set_ocsp_status(&response)?;
                Ok(true)
            })
            .map_err(|error| invalid(format!("enable listener OCSP stapling: {error}")))?;
    }

    let server_alpn = encode_alpn(alpn)?;
    builder.set_alpn_select_callback(move |_ssl, client| {
        select_server_alpn(&server_alpn, client).ok_or(AlpnError::ALERT_FATAL)
    });

    configure_boring_client_auth(&mut builder, tls)?;
    if !tls.settings.enable_session_resumption.unwrap_or(false) {
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    } else {
        builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
        builder.set_session_cache_size(256);
    }
    if let Some(path) = key_log_path(tls) {
        let file = Arc::new(Mutex::new(open_key_log(path)?));
        builder.set_keylog_callback(move |_ssl, line| {
            let Ok(mut file) = file.lock() else { return };
            let _ = writeln!(file, "{line}");
        });
    }
    if let Some(keys) = tls.settings.ech_server_keys.as_deref() {
        let keys = parse_ech_server_keys(keys)?;
        builder
            .set_ech_keys(&keys)
            .map_err(|error| invalid(format!("install echServerKeys: {error}")))?;
    }
    Ok(builder.build())
}

fn cached_or_issue_boring(
    domain: &str,
    issuers: &[DynamicIssuer],
    issued: &Mutex<HashMap<String, (Arc<BoringIdentity>, Instant)>>,
) -> io::Result<Arc<BoringIdentity>> {
    let domain = domain.to_ascii_lowercase();
    let now = Instant::now();
    if let Ok(mut cache) = issued.lock() {
        if let Some((identity, created)) = cache.get(&domain) {
            if now.duration_since(*created) < ISSUED_CERTIFICATE_CACHE_TTL {
                return Ok(Arc::clone(identity));
            }
            cache.remove(&domain);
        }
    }

    let mut last_error = None;
    for issuer in issuers {
        match issuer
            .issue(&domain)
            .and_then(|(certificate, key)| parse_boring_identity(&certificate, &key, Some(&domain)))
        {
            Ok(identity) => {
                let identity = Arc::new(identity);
                if let Ok(mut cache) = issued.lock() {
                    insert_bounded_cache(&mut cache, domain, Arc::clone(&identity));
                }
                return Ok(identity);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| invalid("no usage=issue CA is configured")))
}

/// Selects the first server-preferred ALPN while returning the slice borrowed
/// from the ClientHello. BoringSSL's callback ABI requires the selected value
/// to remain tied to the client's input buffer, so a dynamically owned server
/// list cannot be passed to `ssl::select_next_proto` directly.
fn select_server_alpn<'a>(server: &[u8], client: &'a [u8]) -> Option<&'a [u8]> {
    let mut server_offset = 0;
    while server_offset < server.len() {
        let server_len = *server.get(server_offset)? as usize;
        server_offset += 1;
        let server_protocol = server.get(server_offset..server_offset.checked_add(server_len)?)?;
        server_offset += server_len;

        let mut client_offset = 0;
        while client_offset < client.len() {
            let client_len = *client.get(client_offset)? as usize;
            client_offset += 1;
            let client_protocol =
                client.get(client_offset..client_offset.checked_add(client_len)?)?;
            client_offset += client_len;
            if server_protocol == client_protocol {
                return Some(client_protocol);
            }
        }
    }
    None
}

fn load_boring_identities(tls: &XhttpListenTlsPlan) -> io::Result<Vec<Arc<BoringIdentitySlot>>> {
    let mut identities = Vec::new();
    if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
        identities.push(Arc::new(BoringIdentitySlot {
            current: RwLock::new(parse_boring_identity(
                &std::fs::read(cert_path)?,
                &std::fs::read(key_path)?,
                tls.settings.server_name.as_deref(),
            )?),
            _refresh_lifetime: None,
        }));
        return Ok(identities);
    }
    for certificate in tls.settings.certificates.iter().filter(|certificate| {
        certificate
            .usage
            .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
            == XhttpTlsCertificateUsage::Encipherment
    }) {
        let refresh = CertificateRefresh::from_certificate(certificate);
        let (refresh_lifetime, shutdown) = refresh
            .as_ref()
            .map(|_| RefreshLifetime::new())
            .map_or((None, None), |(lifetime, shutdown)| {
                (Some(lifetime), Some(shutdown))
            });
        let identity = Arc::new(BoringIdentitySlot {
            current: RwLock::new(parse_boring_identity(
                &certificate_pem(certificate)?,
                &key_pem(certificate)?,
                tls.settings.server_name.as_deref(),
            )?),
            _refresh_lifetime: refresh_lifetime,
        });
        if let Some(refresh) = refresh {
            spawn_boring_identity_refresh(
                Arc::downgrade(&identity),
                refresh,
                tls.settings.server_name.clone(),
                shutdown.expect("refresh shutdown is created with refresh settings"),
            )?;
        }
        identities.push(identity);
    }
    Ok(identities)
}

fn spawn_boring_identity_refresh(
    identity: Weak<BoringIdentitySlot>,
    refresh: CertificateRefresh,
    configured_name: Option<String>,
    shutdown: Arc<tokio::sync::Notify>,
) -> io::Result<()> {
    spawn_refresh_task("boring-certificate-refresh", async move {
        let ocsp = refresh.fetch_ocsp.then(new_ocsp_client);
        loop {
            let Some(identity) = identity.upgrade() else {
                break;
            };
            let refreshed = async {
                let certificate =
                    tokio::fs::read(&refresh.certificate_path)
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "read XHTTP certificate {:?}: {error}",
                                    refresh.certificate_path
                                ),
                            )
                        })?;
                let key = tokio::fs::read(&refresh.key_path).await.map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("read XHTTP key {:?}: {error}", refresh.key_path),
                    )
                })?;
                let mut state =
                    parse_boring_identity(&certificate, &key, configured_name.as_deref())?;
                if let Some(client) = &ocsp {
                    let leaf = state
                        .leaf
                        .to_der()
                        .map_err(|error| invalid(format!("encode XHTTP certificate: {error}")))?;
                    let issuer = state
                        .chain
                        .first()
                        .map(|certificate| certificate.to_der())
                        .transpose()
                        .map_err(|error| {
                            invalid(format!("encode XHTTP issuing certificate: {error}"))
                        })?;
                    match fetch_ocsp_response(client, &leaf, issuer.as_deref()).await {
                        Ok(response) => state.ocsp = Some(response),
                        Err(error) => tracing::warn!(
                            target: "inbound::xhttp::tls",
                            %error,
                            "failed to refresh OCSP staple"
                        ),
                    }
                }
                Ok::<_, io::Error>(state)
            }
            .await;
            match refreshed {
                Ok(state) => {
                    if let Ok(mut current) = identity.current.write() {
                        *current = state;
                    }
                }
                Err(error) => tracing::warn!(
                    target: "inbound::xhttp::tls",
                    %error,
                    "failed to refresh XHTTP BoringSSL certificate"
                ),
            }
            drop(identity);
            if !wait_for_refresh(refresh.interval, &shutdown).await {
                break;
            }
        }
    })
}

fn parse_boring_identity(
    cert_pem: &[u8],
    key_pem: &[u8],
    configured_name: Option<&str>,
) -> io::Result<BoringIdentity> {
    let mut certificates = X509::stack_from_pem(cert_pem)
        .map_err(|error| invalid(format!("parse XHTTP certificate PEM: {error}")))?
        .into_iter();
    let leaf = certificates
        .next()
        .ok_or_else(|| invalid("XHTTP certificate chain is empty"))?;
    let mut names = certificate_names(
        &leaf
            .to_der()
            .map_err(|error| invalid(format!("encode XHTTP certificate: {error}")))?,
    )?;
    if let Some(name) = configured_name.filter(|name| !name.is_empty()) {
        if !names.iter().any(|current| current == name) {
            names.push(name.to_ascii_lowercase());
        }
    }
    let key = PKey::private_key_from_pem(key_pem)
        .map_err(|error| invalid(format!("parse XHTTP private key PEM: {error}")))?;
    Ok(BoringIdentity {
        names,
        leaf,
        chain: certificates.collect(),
        key,
        ocsp: None,
    })
}

fn install_boring_identity_on_context(
    builder: &mut boring::ssl::SslAcceptorBuilder,
    identity: &BoringIdentity,
) -> io::Result<()> {
    builder
        .set_certificate(&identity.leaf)
        .map_err(|error| invalid(format!("set XHTTP certificate: {error}")))?;
    builder
        .set_private_key(&identity.key)
        .map_err(|error| invalid(format!("set XHTTP private key: {error}")))?;
    for intermediate in &identity.chain {
        builder
            .add_extra_chain_cert(intermediate.to_owned())
            .map_err(|error| invalid(format!("set XHTTP certificate chain: {error}")))?;
    }
    builder
        .check_private_key()
        .map_err(|error| invalid(format!("XHTTP certificate/key mismatch: {error}")))
}

fn install_boring_identity_on_ssl(
    ssl: &mut boring::ssl::SslRef,
    identity: &BoringIdentity,
) -> io::Result<()> {
    ssl.set_certificate(&identity.leaf)
        .map_err(|error| invalid(format!("set selected XHTTP certificate: {error}")))?;
    ssl.set_private_key(&identity.key)
        .map_err(|error| invalid(format!("set selected XHTTP private key: {error}")))?;
    for intermediate in &identity.chain {
        ssl.add_chain_cert(intermediate)
            .map_err(|error| invalid(format!("set selected XHTTP certificate chain: {error}")))?;
    }
    Ok(())
}

fn configure_boring_client_auth(
    builder: &mut boring::ssl::SslAcceptorBuilder,
    tls: &XhttpListenTlsPlan,
) -> io::Result<()> {
    if !tls.require_client_certificate {
        return Ok(());
    }
    for certificate in tls
        .settings
        .certificates
        .iter()
        .filter(|certificate| certificate.usage == Some(XhttpTlsCertificateUsage::Verify))
    {
        for certificate in X509::stack_from_pem(&certificate_pem(certificate)?)
            .map_err(|error| invalid(format!("parse XHTTP mTLS CA: {error}")))?
        {
            let _ = builder.cert_store_mut().add_cert(certificate);
        }
    }
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    Ok(())
}

fn parse_ech_server_keys(value: &str) -> io::Result<SslEchKeys> {
    let bytes =
        decode_base64(value).map_err(|error| invalid(format!("decode echServerKeys: {error}")))?;
    let mut cursor = 0_usize;
    let mut builder = SslEchKeys::builder()
        .map_err(|error| invalid(format!("create ECH server key set: {error}")))?;
    let mut count = 0_usize;
    while cursor < bytes.len() {
        let key_len = read_len(&bytes, &mut cursor, "ECH private key")?;
        let key = take(&bytes, &mut cursor, key_len, "ECH private key")?;
        let config_len = read_len(&bytes, &mut cursor, "ECH config")?;
        let config = take(&bytes, &mut cursor, config_len, "ECH config")?;
        let key = HpkeKey::dhkem_p256_sha256(key)
            .map_err(|error| invalid(format!("parse ECH HPKE private key: {error}")))?;
        // Go's `EncryptedClientHelloKey.SendAsRetry` defaults to false in the
        // Xray framing, while BoringSSL requires the installed set to expose at
        // least one retry config. Promote the first configured key; this does
        // not change decryption and gives rejected clients the same config list.
        builder
            .add_key(count == 0, config, key)
            .map_err(|error| invalid(format!("add ECH server key: {error}")))?;
        count += 1;
    }
    if count == 0 {
        return Err(invalid("echServerKeys contains no key"));
    }
    Ok(builder.build())
}

fn read_len(bytes: &[u8], cursor: &mut usize, label: &str) -> io::Result<usize> {
    let raw = take(bytes, cursor, 2, label)?;
    Ok(usize::from(u16::from_be_bytes([raw[0], raw[1]])))
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    label: &str,
) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| invalid(format!("truncated {label}")))?;
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn version_range(tls: &XhttpListenTlsPlan) -> io::Result<(u8, u8)> {
    let parse = |value: Option<&str>, default| match value.map(str::trim) {
        None | Some("") => Ok(default),
        Some("1.0") => Ok(10),
        Some("1.1") => Ok(11),
        Some("1.2") => Ok(12),
        Some("1.3") => Ok(13),
        Some(value) => Err(invalid(format!("unsupported TLS version {value:?}"))),
    };
    let min = parse(tls.settings.min_version.as_deref(), 12)?;
    let max = parse(tls.settings.max_version.as_deref(), 13)?;
    if min > max {
        return Err(invalid("TLS minVersion exceeds maxVersion"));
    }
    Ok((min, max))
}

fn ssl_version(version: u8) -> SslVersion {
    match version {
        10 => SslVersion::TLS1,
        11 => SslVersion::TLS1_1,
        12 => SslVersion::TLS1_2,
        13 => SslVersion::TLS1_3,
        _ => unreachable!("validated TLS version"),
    }
}

fn encode_alpn(protocols: &[String]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        let length = u8::try_from(protocol.len())
            .map_err(|_| invalid(format!("TLS ALPN id is too long: {protocol:?}")))?;
        if length == 0 {
            return Err(invalid("TLS ALPN id cannot be empty"));
        }
        wire.push(length);
        wire.extend_from_slice(protocol.as_bytes());
    }
    Ok(wire)
}

fn validate_alpn(protocols: &[String]) -> io::Result<()> {
    let mut seen = std::collections::HashSet::with_capacity(protocols.len());
    for protocol in protocols {
        if protocol.is_empty() {
            return Err(invalid("TLS ALPN id cannot be empty"));
        }
        if protocol.len() > usize::from(u8::MAX) {
            return Err(invalid(format!("TLS ALPN id is too long: {protocol:?}")));
        }
        if !seen.insert(protocol.as_str()) {
            return Err(invalid(format!("duplicate TLS ALPN id: {protocol:?}")));
        }
    }
    Ok(())
}

fn apply_boring_ciphers(
    builder: &mut boring::ssl::SslAcceptorBuilder,
    configured: Option<&str>,
    min_version: u8,
) -> io::Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    let list = configured
        .split(':')
        .map(str::trim)
        .filter_map(boring_cipher_name)
        .collect::<Vec<_>>();
    if list.is_empty() && min_version < 13 {
        return Err(unsupported(
            "listener cipherSuites contains no configurable pre-TLS-1.3 BoringSSL suite",
        ));
    }
    if !list.is_empty() {
        builder
            .set_cipher_list(&list.join(":"))
            .map_err(|error| invalid(format!("set listener cipherSuites: {error}")))?;
    }
    Ok(())
}

fn apply_boring_curves(
    builder: &mut boring::ssl::SslAcceptorBuilder,
    configured: Option<&[String]>,
) -> io::Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    let curves = configured
        .iter()
        .map(|curve| match curve.to_ascii_lowercase().as_str() {
            "curvep256" => Ok("P-256"),
            "curvep384" => Ok("P-384"),
            "curvep521" => Ok("P-521"),
            "x25519" => Ok("X25519"),
            "x25519mlkem768" | "secp256r1mlkem768" => Err(unsupported(
                "post-quantum curve preferences cannot be mixed with a BoringSSL-only listener setting",
            )),
            value => Err(unsupported(format!(
                "listener curve {value:?} is unavailable in pinned BoringSSL"
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    builder
        .set_curves_list(&curves.join(":"))
        .map_err(|error| invalid(format!("set listener curvePreferences: {error}")))
}

fn is_boring_only_cipher(cipher: &str) -> bool {
    boring_cipher_name(cipher).is_some()
        && !matches!(
            cipher,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        )
}

fn boring_cipher_name(cipher: &str) -> Option<&'static str> {
    Some(match cipher {
        "TLS_RSA_WITH_RC4_128_SHA" => "RC4-SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA" => "DES-CBC3-SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA" => "AES128-SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA" => "AES256-SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA256" => "AES128-SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => "AES128-GCM-SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => "AES256-GCM-SHA384",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" => "ECDHE-ECDSA-RC4-SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => "ECDHE-ECDSA-AES128-SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => "ECDHE-ECDSA-AES256-SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA" => "ECDHE-RSA-RC4-SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" => "ECDHE-RSA-DES-CBC3-SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => "ECDHE-RSA-AES128-SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => "ECDHE-RSA-AES256-SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => "ECDHE-ECDSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => "ECDHE-RSA-AES128-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-RSA-CHACHA20-POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-ECDSA-CHACHA20-POLY1305",
        _ => return None,
    })
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

fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
}

fn key_log_path(tls: &XhttpListenTlsPlan) -> Option<&str> {
    tls.settings
        .master_key_log
        .as_deref()
        .filter(|path| !path.eq_ignore_ascii_case("none"))
}

struct PathKeyLog {
    file: Mutex<File>,
}

impl PathKeyLog {
    fn open(path: &str) -> io::Result<Self> {
        Ok(Self {
            file: Mutex::new(open_key_log(path)?),
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

fn open_key_log(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            io::Error::new(error.kind(), format!("open masterKeyLog {path:?}: {error}"))
        })
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::hash::{MessageDigest, hash};
    use boring::sign::Signer;
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, StatusType};
    use core_outbound::transport::{TlsOptions, Transport, tls::TlsTransport};
    use rasn::types::{BitString, Integer, ObjectIdentifier, OctetString};
    use rasn_ocsp::{CertId, CertStatus, ResponseBytes, ResponseData, SingleResponse, Version};
    use rasn_pkix::AlgorithmIdentifier;
    use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x509_parser::num_bigint::{BigInt, Sign};

    const ECH_CONFIG_LIST: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";
    const ECH_SERVER_KEYS: &str = "ACCfHeuM9VY1sx9pq24z7wCeitcoGS2rEjeUS8d8P6kfggA+/g0AOgAAIAAguy8p4+MFfgQZ1S/F9EEYd2+NthzqT992B5uTYGxaYkgACAABAAEAAQADAAdlY2guY29tAAA=";

    fn pem_lines(value: &str) -> Vec<String> {
        value.lines().map(str::to_owned).collect()
    }

    fn certificate_authority() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "WutherCore test CA");
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate, key)
    }

    fn signed_identity(
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        name: &str,
    ) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.signed_by(&key, ca, ca_key).unwrap();
        (certificate, key)
    }

    fn oid(arcs: &'static [u32]) -> ObjectIdentifier {
        ObjectIdentifier::new(arcs).expect("valid test OID")
    }

    fn signed_ocsp_response(
        leaf: &rcgen::Certificate,
        issuer: &rcgen::Certificate,
        responder: &rcgen::Certificate,
        responder_key: &KeyPair,
        embed_responder: bool,
    ) -> Vec<u8> {
        use sha1::{Digest as _, Sha1};

        let (_, leaf_certificate) = ParsedX509Certificate::from_der(leaf.der().as_ref()).unwrap();
        let (_, issuer_certificate) =
            ParsedX509Certificate::from_der(issuer.der().as_ref()).unwrap();
        let (_, responder_certificate) =
            ParsedX509Certificate::from_der(responder.der().as_ref()).unwrap();
        let now = chrono::Utc::now().fixed_offset();
        let cert_id = CertId {
            hash_algorithm: AlgorithmIdentifier {
                algorithm: oid(&[1, 3, 14, 3, 2, 26]),
                parameters: None,
            },
            issuer_name_hash: OctetString::from(
                Sha1::digest(leaf_certificate.issuer().as_raw()).to_vec(),
            ),
            issuer_key_hash: OctetString::from(
                Sha1::digest(
                    issuer_certificate
                        .public_key()
                        .subject_public_key
                        .data
                        .as_ref(),
                )
                .to_vec(),
            ),
            serial_number: Integer::from(BigInt::from_bytes_be(
                Sign::Plus,
                leaf_certificate.raw_serial(),
            )),
        };
        let tbs_response_data = ResponseData {
            version: Version::ZERO,
            responder_id: ResponderId::ByKey(OctetString::from(
                Sha1::digest(
                    responder_certificate
                        .public_key()
                        .subject_public_key
                        .data
                        .as_ref(),
                )
                .to_vec(),
            )),
            produced_at: now,
            responses: vec![SingleResponse {
                cert_id,
                cert_status: CertStatus::Good,
                this_update: now - chrono::TimeDelta::minutes(1),
                next_update: Some(now + chrono::TimeDelta::hours(1)),
                single_extensions: None,
            }],
            response_extensions: None,
        };
        let signed_data = rasn::der::encode(&tbs_response_data).unwrap();
        let private_key =
            PKey::private_key_from_pem(responder_key.serialize_pem().as_bytes()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
        signer.update(&signed_data).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let certs = embed_responder.then(|| {
            vec![rasn::der::decode::<rasn_pkix::Certificate>(responder.der().as_ref()).unwrap()]
        });
        let basic = BasicOcspResponse {
            tbs_response_data,
            signature_algorithm: AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 10045, 4, 3, 2]),
                parameters: None,
            },
            signature: BitString::from_vec(signature),
            certs,
        };
        let outer = OcspResponse {
            status: OcspResponseStatus::Successful,
            bytes: Some(ResponseBytes {
                r#type: oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
                response: OctetString::from(rasn::der::encode(&basic).unwrap()),
            }),
        };
        rasn::der::encode(&outer).unwrap()
    }

    fn static_plan(
        certificate: &rcgen::Certificate,
        key: &KeyPair,
        mut settings: core_config::model::XhttpDownloadTlsSettings,
    ) -> XhttpListenTlsPlan {
        settings.certificates.insert(
            0,
            XhttpDownloadTlsCertificate {
                certificate: Some(pem_lines(&certificate.pem())),
                key: Some(pem_lines(&key.serialize_pem())),
                usage: Some(XhttpTlsCertificateUsage::Encipherment),
                ..Default::default()
            },
        );
        XhttpListenTlsPlan {
            cert_path: None,
            key_path: None,
            settings,
            require_client_certificate: false,
        }
    }

    fn rustls_client_builder(
        roots: RootCertStore,
    ) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert> {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
    }

    #[test]
    fn parses_xray_ech_server_key_framing_strictly() {
        let malformed = base64::engine::general_purpose::STANDARD.encode([0, 4, 1]);
        assert!(parse_ech_server_keys(&malformed).is_err());
    }

    #[test]
    fn wildcard_only_matches_one_label() {
        assert!(dns_name_matches("*.example.com", "a.example.com"));
        assert!(!dns_name_matches("*.example.com", "a.b.example.com"));
    }

    #[test]
    fn certificate_sni_names_include_legacy_common_name() {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "legacy-cn.example");
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        assert_eq!(
            certificate_names(certificate.der()).unwrap(),
            vec!["legacy-cn.example"]
        );
    }

    #[test]
    fn certificate_refresh_policy_matches_xray_semantics() {
        let inline = XhttpDownloadTlsCertificate {
            certificate: Some(vec!["certificate".into()]),
            key: Some(vec!["key".into()]),
            ocsp_stapling: Some(15),
            one_time_loading: Some(false),
            ..Default::default()
        };
        assert!(
            CertificateRefresh::from_certificate(&inline).is_none(),
            "inline material is always one-time loaded by Xray"
        );

        let file_backed = XhttpDownloadTlsCertificate {
            certificate_file: Some("certificate.pem".into()),
            key_file: Some("key.pem".into()),
            ..Default::default()
        };
        let refresh = CertificateRefresh::from_certificate(&file_backed).unwrap();
        assert_eq!(refresh.interval, CERTIFICATE_RELOAD_INTERVAL);
        assert!(!refresh.fetch_ocsp);

        let with_ocsp = XhttpDownloadTlsCertificate {
            ocsp_stapling: Some(15),
            ..file_backed.clone()
        };
        let refresh = CertificateRefresh::from_certificate(&with_ocsp).unwrap();
        assert_eq!(refresh.interval, Duration::from_secs(15));
        assert!(refresh.fetch_ocsp);

        let one_time = XhttpDownloadTlsCertificate {
            one_time_loading: Some(true),
            ..file_backed
        };
        assert!(CertificateRefresh::from_certificate(&one_time).is_none());
    }

    #[tokio::test]
    async fn certificate_refresh_wait_stops_when_listener_lifetime_ends() {
        let (lifetime, shutdown) = RefreshLifetime::new();
        let waiter =
            tokio::spawn(
                async move { wait_for_refresh(Duration::from_secs(60 * 60), &shutdown).await },
            );

        // Drop before the spawned task is guaranteed to have polled
        // `Notify::notified()`. `notify_one` must retain the shutdown permit.
        drop(lifetime);
        let elapsed = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("refresh wait must not linger until the hourly timer")
            .expect("refresh wait task must finish cleanly");
        assert!(!elapsed, "shutdown is distinct from a refresh interval");
    }

    #[test]
    fn validates_ocsp_signature_and_certificate_binding() {
        let (ca, ca_key) = certificate_authority();
        let (leaf, _) = signed_identity(&ca, &ca_key, "ocsp-leaf.example");
        let response = signed_ocsp_response(&leaf, &ca, &ca, &ca_key, false);
        validate_ocsp_response(&response, leaf.der().as_ref(), ca.der().as_ref()).unwrap();

        let (other_leaf, _) = signed_identity(&ca, &ca_key, "other-leaf.example");
        let error = validate_ocsp_response(&response, other_leaf.der().as_ref(), ca.der().as_ref())
            .unwrap_err();
        assert!(error.to_string().contains("serial number"));

        let mut outer: OcspResponse = rasn::der::decode(&response).unwrap();
        let response_bytes = outer.bytes.as_mut().unwrap();
        let mut basic: BasicOcspResponse =
            rasn::der::decode(response_bytes.response.as_ref()).unwrap();
        let bit = basic.signature[0];
        basic.signature.set(0, !bit);
        response_bytes.response = OctetString::from(rasn::der::encode(&basic).unwrap());
        let tampered = rasn::der::encode(&outer).unwrap();
        assert!(
            validate_ocsp_response(&tampered, leaf.der().as_ref(), ca.der().as_ref())
                .unwrap_err()
                .to_string()
                .contains("signature")
        );
    }

    #[test]
    fn validates_authorized_delegated_ocsp_responder() {
        let (ca, ca_key) = certificate_authority();
        let (leaf, _) = signed_identity(&ca, &ca_key, "delegated-ocsp-leaf.example");
        let responder_key = KeyPair::generate().unwrap();
        let mut responder_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        responder_params
            .distinguished_name
            .push(DnType::CommonName, "WutherCore test OCSP responder");
        responder_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        responder_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        let responder = responder_params
            .signed_by(&responder_key, &ca, &ca_key)
            .unwrap();
        let response = signed_ocsp_response(&leaf, &ca, &responder, &responder_key, true);
        validate_ocsp_response(&response, leaf.der().as_ref(), ca.der().as_ref()).unwrap();

        let (unauthorized, unauthorized_key) =
            signed_identity(&ca, &ca_key, "unauthorized-ocsp.example");
        let unauthorized_response =
            signed_ocsp_response(&leaf, &ca, &unauthorized, &unauthorized_key, true);
        assert!(
            validate_ocsp_response(
                &unauthorized_response,
                leaf.der().as_ref(),
                ca.der().as_ref(),
            )
            .unwrap_err()
            .to_string()
            .contains("extended key usage")
        );
    }

    #[test]
    fn usage_issue_rejects_non_ca_and_mismatched_private_key() {
        let rcgen::CertifiedKey {
            cert: leaf,
            key_pair: leaf_key,
        } = rcgen::generate_simple_self_signed(vec!["not-a-ca.example".into()]).unwrap();
        let non_ca = IssuerMaterial {
            certificate_pem: leaf.pem().into_bytes(),
            key_pem: leaf_key.serialize_pem().into_bytes(),
        };
        assert!(
            validate_dynamic_issuer_material(&non_ca)
                .unwrap_err()
                .to_string()
                .contains("CA basic constraints")
        );

        let (ca, _) = certificate_authority();
        let (_, wrong_key) = certificate_authority();
        let mismatched = IssuerMaterial {
            certificate_pem: ca.pem().into_bytes(),
            key_pem: wrong_key.serialize_pem().into_bytes(),
        };
        assert!(
            validate_dynamic_issuer_material(&mismatched)
                .unwrap_err()
                .to_string()
                .contains("mismatch")
        );
    }

    #[tokio::test]
    async fn rustls_and_boring_reload_file_backed_certificates() {
        let (ca, ca_key) = certificate_authority();
        let (old_certificate, old_key) = signed_identity(&ca, &ca_key, "reload.example");
        let (new_certificate, new_key) = signed_identity(&ca, &ca_key, "reload.example");
        let directory = std::env::temp_dir().join(format!(
            "wuther-xhttp-certificate-refresh-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let certificate_path = directory.join("certificate.pem");
        let key_path = directory.join("key.pem");
        let old_chain = format!("{}\n{}", old_certificate.pem(), ca.pem());
        std::fs::write(&certificate_path, old_chain).unwrap();
        std::fs::write(&key_path, old_key.serialize_pem()).unwrap();

        let plan = XhttpListenTlsPlan {
            cert_path: None,
            key_path: None,
            settings: core_config::model::XhttpDownloadTlsSettings {
                certificates: vec![XhttpDownloadTlsCertificate {
                    certificate_file: Some(certificate_path.to_string_lossy().into_owned()),
                    key_file: Some(key_path.to_string_lossy().into_owned()),
                    usage: Some(XhttpTlsCertificateUsage::Encipherment),
                    // Xray uses this value as both the OCSP and certificate
                    // refresh interval. The test CA has no OCSP responder, so
                    // the soft-failure path is deterministic and offline.
                    ocsp_stapling: Some(1),
                    ..Default::default()
                }],
                ..Default::default()
            },
            require_client_certificate: false,
        };
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let rustls = load_rustls_identities(&plan, provider).unwrap();
        let boring = load_boring_identities(&plan).unwrap();

        let new_chain = format!("{}\n{}", new_certificate.pem(), ca.pem());
        std::fs::write(&certificate_path, new_chain).unwrap();
        std::fs::write(&key_path, new_key.serialize_pem()).unwrap();
        let expected = new_certificate.der().as_ref().to_vec();

        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let rustls_reloaded = rustls[0]
                    .key()
                    .is_some_and(|key| key.cert[0].as_ref() == expected);
                let boring_reloaded = boring[0].snapshot().is_some_and(|identity| {
                    identity.leaf.to_der().is_ok_and(|der| der == expected)
                });
                if rustls_reloaded && boring_reloaded {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("both TLS backends must publish the refreshed certificate");

        drop(rustls);
        drop(boring);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn public_xray_acceptor_wraps_arbitrary_bidirectional_io() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["public-api.example".into()]).unwrap();
        let settings = core_config::model::XhttpDownloadTlsSettings {
            alpn: Some(vec!["h2".into()]),
            certificates: vec![XhttpDownloadTlsCertificate {
                certificate: Some(pem_lines(&cert.pem())),
                key: Some(pem_lines(&key_pair.serialize_pem())),
                usage: Some(XhttpTlsCertificateUsage::Encipherment),
                ..Default::default()
            }],
            ..Default::default()
        };
        let acceptor = XrayServerTlsAcceptor::from_xray_settings(settings, false).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls_client_builder(roots).with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let name = ServerName::try_from("public-api.example").unwrap();

        let server = async {
            let mut carrier = acceptor.accept(server_io).await.unwrap();
            let mut request = [0_u8; 4];
            carrier.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            carrier.write_all(b"pong").await.unwrap();
        };
        let client = async {
            let mut carrier = connector.connect(name, client_io).await.unwrap();
            assert_eq!(carrier.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            carrier.write_all(b"ping").await.unwrap();
            let mut response = [0_u8; 4];
            carrier.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
        };
        tokio::join!(server, client);
    }

    #[tokio::test]
    async fn usage_issue_performs_a_verified_dynamic_sni_handshake() {
        let (ca, ca_key) = certificate_authority();
        let plan = XhttpListenTlsPlan {
            cert_path: None,
            key_path: None,
            settings: core_config::model::XhttpDownloadTlsSettings {
                certificates: vec![XhttpDownloadTlsCertificate {
                    certificate: Some(pem_lines(&ca.pem())),
                    key: Some(pem_lines(&ca_key.serialize_pem())),
                    usage: Some(XhttpTlsCertificateUsage::Issue),
                    build_chain: Some(true),
                    ..Default::default()
                }],
                ..Default::default()
            },
            require_client_certificate: false,
        };
        plan.settings.validate().unwrap();
        let server = build_rustls(&plan, &["h2".into()]).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let mut client = rustls_client_builder(roots).with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let name = ServerName::try_from("dynamic.example").unwrap();
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(name, client_io)
        );
        let server = server.expect("dynamic server handshake");
        let client = client.expect("verified dynamic client handshake");
        assert_eq!(server.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(
            client
                .get_ref()
                .1
                .peer_certificates()
                .expect("issued chain")
                .len(),
            2,
            "buildChain=true must send the issuing CA"
        );
    }

    #[tokio::test]
    async fn rustls_listener_requires_and_verifies_client_certificate() {
        let (ca, ca_key) = certificate_authority();
        let (server_certificate, server_key) = signed_identity(&ca, &ca_key, "server.example");
        let (client_certificate, client_key) = signed_identity(&ca, &ca_key, "client.example");
        let mut plan = static_plan(
            &server_certificate,
            &server_key,
            core_config::model::XhttpDownloadTlsSettings {
                certificates: vec![XhttpDownloadTlsCertificate {
                    certificate: Some(pem_lines(&ca.pem())),
                    usage: Some(XhttpTlsCertificateUsage::Verify),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        plan.require_client_certificate = true;
        let server = build_rustls(&plan, &["h2".into()]).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));
        let mut client = rustls_client_builder(roots)
            .with_client_auth_cert(vec![client_certificate.der().clone()], client_key)
            .unwrap();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let (server_result, client_result) = tokio::join!(
            TlsAcceptor::from(Arc::new(server)).accept(server_io),
            tokio_rustls::TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("server.example").unwrap(), client_io,)
        );
        assert!(
            server_result.is_ok(),
            "server must accept trusted client cert"
        );
        assert!(client_result.is_ok(), "client mTLS handshake must complete");
    }

    #[tokio::test]
    async fn boring_listener_negotiates_real_tls10() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["legacy.example".into()]).unwrap();
        let plan = static_plan(
            &cert,
            &key_pair,
            core_config::model::XhttpDownloadTlsSettings {
                min_version: Some("1.0".into()),
                max_version: Some("1.0".into()),
                cipher_suites: Some("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into()),
                ..Default::default()
            },
        );
        let acceptor = build_boring(&plan, &["h2".into()]).unwrap();

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector
            .set_min_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        connector
            .set_max_proto_version(Some(SslVersion::TLS1))
            .unwrap();
        connector.set_cipher_list("ECDHE-ECDSA-AES128-SHA").unwrap();
        connector.set_alpn_protos(b"\x02h2").unwrap();
        let connector = connector.build();
        let configuration = connector
            .configure()
            .unwrap()
            .verify_hostname(false)
            .use_server_name_indication(true);
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let (server, client) = tokio::join!(
            tokio_boring::accept(&acceptor, server_io),
            tokio_boring::connect(configuration, "legacy.example", client_io)
        );
        let server = server.expect("BoringSSL TLS 1.0 server handshake");
        let client = client.expect("BoringSSL TLS 1.0 client handshake");
        assert_eq!(server.ssl().version_str(), "TLSv1");
        assert_eq!(client.ssl().version_str(), "TLSv1");
    }

    #[tokio::test]
    async fn boring_listener_staples_selected_identity_ocsp_response() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["ocsp.example".into()]).unwrap();
        let mut identity = parse_boring_identity(
            cert.pem().as_bytes(),
            key_pair.serialize_pem().as_bytes(),
            None,
        )
        .unwrap();
        let expected = b"wuther-test-ocsp-response".to_vec();
        identity.ocsp = Some(expected.clone());
        let identity = Arc::new(identity);

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        install_boring_identity_on_context(&mut builder, &identity).unwrap();
        let selected_identity_index = Ssl::new_ex_index::<Arc<BoringIdentity>>().unwrap();
        let selected = Arc::clone(&identity);
        builder.set_select_certificate_callback(move |mut hello| {
            let ssl = hello.ssl_mut();
            ssl.set_ex_data(selected_identity_index, Arc::clone(&selected));
            install_boring_identity_on_ssl(ssl, &selected).map_err(|_| SelectCertError::ERROR)
        });
        builder
            .set_status_callback(move |ssl| {
                let response = ssl
                    .ex_data(selected_identity_index)
                    .and_then(|identity| identity.ocsp.clone());
                let Some(response) = response else {
                    return Ok(false);
                };
                ssl.set_ocsp_status(&response)?;
                Ok(true)
            })
            .unwrap();
        let acceptor = builder.build();

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let mut configuration = connector
            .build()
            .configure()
            .unwrap()
            .verify_hostname(false)
            .use_server_name_indication(true);
        configuration.set_status_type(StatusType::OCSP).unwrap();
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let (server, client) = tokio::join!(
            tokio_boring::accept(&acceptor, server_io),
            tokio_boring::connect(configuration, "ocsp.example", client_io)
        );
        server.expect("OCSP stapling server handshake");
        let client = client.expect("OCSP stapling client handshake");
        assert_eq!(client.ssl().ocsp_status(), Some(expected.as_slice()));
    }

    #[tokio::test]
    async fn boring_listener_accepts_xray_framed_ech_server_keys() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["foobar.com".into()]).unwrap();
        let plan = static_plan(
            &cert,
            &key_pair,
            core_config::model::XhttpDownloadTlsSettings {
                min_version: Some("1.3".into()),
                max_version: Some("1.3".into()),
                ech_server_keys: Some(ECH_SERVER_KEYS.into()),
                ..Default::default()
            },
        );
        let acceptor = build_boring(&plan, &["h2".into()]).unwrap();

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_alpn_protos(b"\x02h2").unwrap();
        let connector = connector.build();
        let mut configuration = connector
            .configure()
            .unwrap()
            .verify_hostname(false)
            .use_server_name_indication(true);
        configuration
            .set_ech_config_list(&decode_base64(ECH_CONFIG_LIST).unwrap())
            .unwrap();
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let (server, client) = tokio::join!(
            tokio_boring::accept(&acceptor, server_io),
            tokio_boring::connect(configuration, "foobar.com", client_io)
        );
        server.expect("ECH server handshake");
        let client = client.expect("ECH client handshake");
        assert!(
            client.ssl().ech_accepted(),
            "server must decrypt ClientHelloInner"
        );
    }

    #[tokio::test]
    async fn shaped_rustls_client_and_boring_server_interoperate_with_real_ech() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["foobar.com".into()]).unwrap();
        let plan = static_plan(
            &cert,
            &key_pair,
            core_config::model::XhttpDownloadTlsSettings {
                min_version: Some("1.3".into()),
                max_version: Some("1.3".into()),
                ech_server_keys: Some(ECH_SERVER_KEYS.into()),
                ..Default::default()
            },
        );
        let acceptor = build_boring(&plan, &["h2".into()]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_boring::accept(&acceptor, stream)
                .await
                .expect("BoringSSL ECH server handshake");
            assert!(
                stream.ssl().ech_accepted(),
                "server must accept ClientHelloInner"
            );
        });

        let pin = hex::encode(hash(MessageDigest::sha256(), cert.der().as_ref()).unwrap());
        let options =
            TlsOptions::from_xray_settings(core_config::model::XhttpDownloadTlsSettings {
                server_name: Some("foobar.com".into()),
                alpn: Some(vec!["h2".into()]),
                min_version: Some("1.3".into()),
                max_version: Some("1.3".into()),
                fingerprint: Some("chrome".into()),
                pinned_peer_cert_sha256: Some(pin),
                ech_config_list: Some(ECH_CONFIG_LIST.into()),
                ..Default::default()
            })
            .unwrap();
        let client = TlsTransport::new(options)
            .connect("127.0.0.1", port)
            .await
            .expect("shaped rustls ECH client handshake");
        drop(client);
        server.await.unwrap();
    }
}
