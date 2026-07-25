//! BoringSSL compatibility path for ordinary (`fingerprint=unsafe`) TLS.
//!
//! rustls intentionally does not implement TLS 1.0/1.1 or several legacy Go
//! cipher suites. This backend is selected only for settings rustls cannot
//! execute; shaped/uTLS and modern ECH traffic stay on shaped rustls.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{TlsOptions, tcp::connect_boxed};
use crate::adapter::BoxedStream;
use boring::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode, SslVersion},
    stack::Stack,
    x509::{
        X509, X509Ref, X509StoreContext,
        store::{X509StoreBuilder, X509StoreRef},
    },
};
use core_config::model::{XhttpDownloadTlsCertificate, XhttpTlsCertificateUsage};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn is_required(options: &TlsOptions) -> bool {
    let Some(settings) = options.xray_settings.as_ref() else {
        return false;
    };
    settings
        .min_version
        .as_deref()
        .is_some_and(|version| matches!(version.trim(), "1.0" | "1.1"))
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

pub(crate) fn build_connector(options: &TlsOptions) -> io::Result<SslConnector> {
    if !options.fingerprint.eq_ignore_ascii_case("unsafe") {
        return Err(unsupported(
            "TLS 1.0/1.1、P-521 或旧密码套件要求 fingerprint=unsafe；BoringSSL ClientHello 不能冒充 Xray uTLS 指纹",
        ));
    }
    let settings = options
        .xray_settings
        .as_ref()
        .ok_or_else(|| invalid("BoringSSL backend selected without tlsSettings"))?;
    if settings.ech_config_list.is_some() {
        return Err(invalid(
            "ECH is TLS 1.3-only and cannot be combined with the legacy BoringSSL backend",
        ));
    }
    if settings.curve_preferences.as_ref().is_some_and(|curves| {
        curves
            .iter()
            .any(|curve| curve.eq_ignore_ascii_case("secp384r1mlkem1024"))
    }) {
        return Err(unsupported(
            "secp384r1mlkem1024 is unavailable in both pinned TLS backends",
        ));
    }

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|error| crypto_error("create BoringSSL connector", error))?;
    let (min, max) = version_range(options)?;
    builder
        .set_min_proto_version(Some(ssl_version(min)))
        .map_err(|error| crypto_error("set TLS minVersion", error))?;
    builder
        .set_max_proto_version(Some(ssl_version(max)))
        .map_err(|error| crypto_error("set TLS maxVersion", error))?;

    let alpn = encode_alpn(&options.alpn)?;
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(&alpn)
            .map_err(|error| crypto_error("set TLS ALPN", error))?;
    }

    if settings.disable_system_root.unwrap_or(false) {
        builder.set_cert_store_builder(
            X509StoreBuilder::new()
                .map_err(|error| crypto_error("create custom TLS root store", error))?,
        );
    } else {
        add_native_roots(&mut builder)?;
    }
    for (index, certificate) in settings.certificates.iter().enumerate() {
        for root in parse_certificates(certificate).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("tlsSettings.certificates[{index}]: {error}"),
            )
        })? {
            // Xray appends every configured certificate to the root pool,
            // regardless of usage. Duplicate roots are harmless.
            let _ = builder.cert_store_mut().add_cert(root);
        }
    }

    let client_certificates = settings
        .certificates
        .iter()
        .filter(|certificate| {
            certificate
                .usage
                .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
                == XhttpTlsCertificateUsage::Encipherment
        })
        .collect::<Vec<_>>();
    if client_certificates.len() > 1 {
        return Err(unsupported(
            "BoringSSL compatibility backend cannot safely select among multiple mTLS client certificates",
        ));
    }
    if let Some(certificate) = client_certificates.first() {
        install_client_certificate(&mut builder, certificate)?;
    }

    apply_cipher_suites(&mut builder, settings.cipher_suites.as_deref(), min)?;
    apply_curves(&mut builder, settings.curve_preferences.as_deref())?;

    if !options.enable_session_resumption {
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    } else {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.set_session_cache_size(128);
    }

    if let Some(path) = settings
        .master_key_log
        .as_deref()
        .filter(|path| !path.eq_ignore_ascii_case("none"))
    {
        let file = Arc::new(Mutex::new(open_key_log(path)?));
        builder.set_keylog_callback(move |_ssl, line| {
            let Ok(mut file) = file.lock() else { return };
            let _ = writeln!(file, "{line}");
        });
    }

    if options.insecure
        || !options.pinned_peer_cert_sha256.is_empty()
        || !options.verify_peer_cert_by_name.is_empty()
    {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

pub(crate) async fn connect_negotiated(
    connector: Arc<SslConnector>,
    options: &TlsOptions,
    host: &str,
    port: u16,
) -> io::Result<(BoxedStream, Option<Vec<u8>>)> {
    let domain = options
        .sni
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(host);
    let mut configuration = connector
        .configure()
        .map_err(|error| crypto_error("configure BoringSSL connection", error))?;
    if options.insecure
        || !options.pinned_peer_cert_sha256.is_empty()
        || !options.verify_peer_cert_by_name.is_empty()
    {
        configuration.set_verify_hostname(false);
    }

    // Keep the node socket policy and FinalMask below TLS, exactly like the
    // shaped-rustls backend.
    let tcp = connect_boxed(host, port, false).await?;
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_boring::connect(configuration, domain, tcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "BoringSSL handshake timed out"))?
    .map_err(|error| io::Error::other(format!("BoringSSL handshake: {error}")))?;
    if !options.insecure {
        verify_peer(&stream, connector.as_ref(), options, domain)?;
    }
    let negotiated = stream.ssl().selected_alpn_protocol().map(ToOwned::to_owned);
    Ok((Box::pin(stream), negotiated))
}

fn verify_peer<S>(
    stream: &tokio_boring::SslStream<S>,
    connector: &SslConnector,
    options: &TlsOptions,
    domain: &str,
) -> io::Result<()> {
    if options.pinned_peer_cert_sha256.is_empty() && options.verify_peer_cert_by_name.is_empty() {
        // Normal chain and name verification already ran during the handshake.
        return Ok(());
    }
    let leaf = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| invalid("TLS peer sent no certificate"))?;
    if hash_matches(&leaf, &options.pinned_peer_cert_sha256)? {
        return Ok(());
    }

    let mut chain = Stack::new().map_err(|error| crypto_error("create peer chain", error))?;
    let leaf_der = leaf
        .to_der()
        .map_err(|error| crypto_error("encode peer leaf certificate", error))?;
    let mut pinned_ca = None;
    if let Some(peer_chain) = stream.ssl().peer_cert_chain() {
        for certificate in peer_chain {
            let der = certificate
                .to_der()
                .map_err(|error| crypto_error("encode peer certificate", error))?;
            if der != leaf_der {
                if pinned_ca.is_none()
                    && hash_matches(certificate, &options.pinned_peer_cert_sha256)?
                {
                    pinned_ca = Some(certificate.to_owned());
                }
                chain
                    .push(certificate.to_owned())
                    .map_err(|error| crypto_error("copy peer certificate chain", error))?;
            }
        }
    }
    if !options.pinned_peer_cert_sha256.is_empty() && pinned_ca.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer certificate chain does not match pinnedPeerCertSha256",
        ));
    }
    let names = if options.verify_peer_cert_by_name.is_empty() {
        vec![domain.to_owned()]
    } else {
        options.verify_peer_cert_by_name.clone()
    };
    if let Some(pinned_ca) = pinned_ca {
        let mut store = X509StoreBuilder::new()
            .map_err(|error| crypto_error("create pinned CA store", error))?;
        store
            .add_cert(pinned_ca)
            .map_err(|error| crypto_error("add pinned CA", error))?;
        verify_names(store.build().as_ref(), &leaf, &chain, &names)
    } else {
        verify_names(connector.context().cert_store(), &leaf, &chain, &names)
    }
}

fn verify_names(
    store: &X509StoreRef,
    leaf: &X509Ref,
    chain: &Stack<X509>,
    names: &[String],
) -> io::Result<()> {
    let mut errors = Vec::new();
    for name in names {
        let mut context = X509StoreContext::new()
            .map_err(|error| crypto_error("create certificate verifier", error))?;
        let result = context.init(store, leaf, chain, |context| {
            if let Ok(ip) = name.parse::<IpAddr>() {
                context.verify_param_mut().set_ip(ip)?;
            } else {
                context.verify_param_mut().set_host(name)?;
            }
            context.verify_cert()
        });
        match result {
            Ok(true) => return Ok(()),
            Ok(false) => errors.push(format!("{name}: {:?}", context.verify_result())),
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "peer certificate failed verifyPeerCertByName: {}",
            errors.join("; ")
        ),
    ))
}

fn hash_matches(certificate: &X509Ref, pins: &[[u8; 32]]) -> io::Result<bool> {
    if pins.is_empty() {
        return Ok(false);
    }
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| crypto_error("hash peer certificate", error))?;
    Ok(pins
        .iter()
        .any(|pin| constant_time_eq(pin, digest.as_ref())))
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn add_native_roots(builder: &mut boring::ssl::SslConnectorBuilder) -> io::Result<()> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("load native TLS roots for BoringSSL: {:?}", native.errors),
        ));
    }
    for certificate in native.certs {
        let certificate = X509::from_der(certificate.as_ref())
            .map_err(|error| crypto_error("parse native TLS root", error))?;
        let _ = builder.cert_store_mut().add_cert(certificate);
    }
    Ok(())
}

fn install_client_certificate(
    builder: &mut boring::ssl::SslConnectorBuilder,
    certificate: &XhttpDownloadTlsCertificate,
) -> io::Result<()> {
    let mut chain = parse_certificates(certificate)?.into_iter();
    let leaf = chain
        .next()
        .ok_or_else(|| invalid("mTLS certificate chain is empty"))?;
    builder
        .set_certificate(&leaf)
        .map_err(|error| crypto_error("set mTLS client certificate", error))?;
    for intermediate in chain {
        builder
            .add_extra_chain_cert(intermediate)
            .map_err(|error| crypto_error("set mTLS intermediate certificate", error))?;
    }
    let key = parse_private_key(certificate)?;
    builder
        .set_private_key(&key)
        .map_err(|error| crypto_error("set mTLS private key", error))?;
    builder
        .check_private_key()
        .map_err(|error| crypto_error("mTLS certificate/private-key mismatch", error))
}

fn parse_certificates(certificate: &XhttpDownloadTlsCertificate) -> io::Result<Vec<X509>> {
    let pem = certificate_pem(certificate)?;
    X509::stack_from_pem(&pem).map_err(|error| crypto_error("parse certificate PEM", error))
}

fn parse_private_key(certificate: &XhttpDownloadTlsCertificate) -> io::Result<PKey<Private>> {
    let pem = key_pem(certificate)?;
    PKey::private_key_from_pem(&pem).map_err(|error| crypto_error("parse private key PEM", error))
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

fn version_range(options: &TlsOptions) -> io::Result<(u8, u8)> {
    let settings = options.xray_settings.as_ref();
    let parse = |value: Option<&str>, default| match value.map(str::trim) {
        None | Some("") => Ok(default),
        Some("1.0") => Ok(10),
        Some("1.1") => Ok(11),
        Some("1.2") => Ok(12),
        Some("1.3") => Ok(13),
        Some(value) => Err(invalid(format!("unsupported TLS version {value:?}"))),
    };
    let min = parse(
        settings.and_then(|settings| settings.min_version.as_deref()),
        12,
    )?;
    let max = parse(
        settings.and_then(|settings| settings.max_version.as_deref()),
        13,
    )?;
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

fn apply_cipher_suites(
    builder: &mut boring::ssl::SslConnectorBuilder,
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
            "cipherSuites contains no configurable pre-TLS-1.3 BoringSSL suite",
        ));
    }
    if !list.is_empty() {
        builder
            .set_cipher_list(&list.join(":"))
            .map_err(|error| crypto_error("set TLS cipherSuites", error))?;
    }
    Ok(())
}

fn apply_curves(
    builder: &mut boring::ssl::SslConnectorBuilder,
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
                "post-quantum curve preferences cannot be mixed with a BoringSSL-only TLS setting",
            )),
            value => Err(unsupported(format!(
                "curve preference {value:?} is unavailable in pinned BoringSSL"
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    builder
        .set_curves_list(&curves.join(":"))
        .map_err(|error| crypto_error("set TLS curvePreferences", error))
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
        // BoringSSL deliberately does not expose TLS 1.3 suite selection.
        _ => return None,
    })
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

fn crypto_error(stage: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{stage}: {error}"))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

#[cfg(test)]
mod tests {
    use core_config::model::XhttpDownloadTlsSettings;

    use super::*;

    #[test]
    fn legacy_versions_select_real_compatibility_backend() {
        let options = TlsOptions {
            fingerprint: "unsafe".into(),
            xray_settings: Some(XhttpDownloadTlsSettings {
                min_version: Some("1.0".into()),
                max_version: Some("1.1".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_required(&options));
        build_connector(&options).unwrap();
    }

    #[test]
    fn shaped_fingerprint_and_legacy_backend_conflict_is_explicit() {
        let options = TlsOptions {
            fingerprint: "chrome".into(),
            xray_settings: Some(XhttpDownloadTlsSettings {
                min_version: Some("1.0".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = build_connector(&options).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
