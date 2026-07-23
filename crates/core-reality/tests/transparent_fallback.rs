use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use core_reality::{
    FallbackLimit, ProxyProtocolVersion, RealityServer, RealityServerConfig, RealityServerError,
    RealityServerLimits,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::RootCertStore;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const SERVER_NAME: &str = "fallback.example";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PAYLOAD: &[u8] = b"transparent-fallback-ok";

fn tls13_server_config() -> (
    Arc<rustls::ServerConfig>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![SERVER_NAME.into()]).unwrap();
    let certificate = cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    (Arc::new(config), certificate)
}

fn tls13_client_config(
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

fn reality_config(target: SocketAddr) -> RealityServerConfig {
    let limits = RealityServerLimits {
        handshake_timeout: Duration::from_secs(3),
        target_handshake_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        ..RealityServerLimits::default()
    };
    RealityServerConfig {
        camouflage_target: target.to_string(),
        private_key: [0x42; 32],
        server_names: HashSet::from([SERVER_NAME.into()]),
        short_ids: vec![[0x13; 8]],
        min_client_version: None,
        max_client_version: None,
        max_time_difference: Some(Duration::from_secs(60)),
        mldsa65_seed: None,
        cipher_suites: Vec::new(),
        proxy_protocol: ProxyProtocolVersion::None,
        fallback_upload: FallbackLimit::default(),
        fallback_download: FallbackLimit::default(),
        limits,
    }
}

#[tokio::test]
async fn ordinary_tls_probe_is_transparently_forwarded_to_camouflage_target() {
    let (target_config, certificate) = tls13_server_config();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (stream, _) = target_listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(target_config)
            .accept(stream)
            .await
            .unwrap();
        let mut payload = vec![0; PAYLOAD.len()];
        tls.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, PAYLOAD);
        tls.write_all(&payload).await.unwrap();
        tls.flush().await.unwrap();
    });

    let reality_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reality_address = reality_listener.local_addr().unwrap();
    let reality = RealityServer::new(reality_config(target_address)).unwrap();
    let reality_task = tokio::spawn(async move {
        let (stream, peer) = reality_listener.accept().await.unwrap();
        let local = stream.local_addr().unwrap();
        let result = reality
            .accept(stream, peer, local, CancellationToken::new())
            .await;
        assert!(matches!(
            result,
            Err(RealityServerError::FallbackStarted { .. })
        ));
    });

    let connector = TlsConnector::from(tls13_client_config(certificate));
    let stream = TcpStream::connect(reality_address).await.unwrap();
    let name = ServerName::try_from(SERVER_NAME).unwrap().to_owned();
    let mut tls = timeout(TEST_TIMEOUT, connector.connect(name, stream))
        .await
        .expect("fallback TLS handshake timed out")
        .expect("fallback TLS handshake failed");
    tls.write_all(PAYLOAD).await.unwrap();
    tls.flush().await.unwrap();
    let mut echoed = vec![0; PAYLOAD.len()];
    timeout(TEST_TIMEOUT, tls.read_exact(&mut echoed))
        .await
        .expect("fallback echo timed out")
        .expect("fallback echo failed");
    assert_eq!(echoed, PAYLOAD);
    let _ = tls.shutdown().await;

    timeout(TEST_TIMEOUT, reality_task)
        .await
        .expect("REALITY accept task timed out")
        .expect("REALITY accept task panicked");
    timeout(TEST_TIMEOUT, target_task)
        .await
        .expect("camouflage target timed out")
        .expect("camouflage target panicked");
}
