use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use core_reality::{
    RealityClient, RealityClientConfig, RealityClientError, generate_x25519_keypair,
};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const SERVER_NAME: &str = "spider.example";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct ObservedRequest {
    path: String,
    cookie: Option<String>,
}

fn ordinary_h2_server_config() -> Arc<rustls::ServerConfig> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![SERVER_NAME.into()]).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
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

#[tokio::test]
async fn not_reality_spider_get_reuses_the_original_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let (request_tx, mut request_rx) = mpsc::unbounded_channel();
    let acceptor = TlsAcceptor::from(ordinary_h2_server_config());
    let server_accepts = accepts.clone();
    let server_task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            server_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let request_tx = request_tx.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let request_tx = request_tx.clone();
                    async move {
                        let observed = ObservedRequest {
                            path: request
                                .uri()
                                .path_and_query()
                                .map_or_else(|| "/".to_owned(), ToString::to_string),
                            cookie: request
                                .headers()
                                .get(http::header::COOKIE)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned),
                        };
                        let _ = request_tx.send(observed);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            br#"<a href="/next">next</a>"#,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    let (_, public_key) = generate_x25519_keypair().unwrap();
    let client = RealityClient::new(RealityClientConfig {
        server_name: SERVER_NAME.into(),
        fingerprint: "chrome".into(),
        public_key,
        short_id: Vec::new(),
        spider_x: "/cover?p=8&c=0&t=0&i=0&r=1".into(),
        mldsa65_verify: None,
        handshake_timeout: Duration::from_secs(5),
        ..RealityClientConfig::default()
    })
    .unwrap();
    let stream = TcpStream::connect(address).await.unwrap();
    let result = timeout(TEST_TIMEOUT, client.connect(stream))
        .await
        .expect("REALITY invalid-certificate flow timed out");
    assert!(matches!(
        result,
        Err(RealityClientError::InvalidConnectionProcessed)
    ));

    let observed = timeout(TEST_TIMEOUT, request_rx.recv())
        .await
        .expect("spiderX GET timed out")
        .expect("spiderX request channel closed");
    assert_eq!(observed.path, "/cover");
    assert_eq!(observed.cookie.as_deref(), Some("padding=00000000"));

    // Give a forbidden reconnect enough time to reach the local listener.
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "spiderX must reuse the TLS connection that received the real certificate"
    );
    server_task.abort();
}
