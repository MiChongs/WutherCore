//! XHTTP TLS/HTTP2/HTTP3 与固定官方 Xray 版本的双向互操作测试。
//!
//! 每个传输版本、方向和 XHTTP mode 都使用全新的服务端、客户端池及
//! Xray 进程，避免连接复用掩盖协议协商或会话初始化问题。HTTP/3 的
//! readiness 由真实 QUIC/H3/XHTTP 拨号完成，不能用 TCP 端口探测替代。
//!
//! 这组测试需要外部官方 Xray 二进制，因此默认忽略。运行方式：
//!
//! ```text
//! XRAY_BIN=/path/to/xray cargo test -p tests-e2e --test e2e_xhttp_xray_tls -- --ignored
//! ```

use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_inbound::xhttp::{XhttpAcceptReceiver, XhttpServer, XhttpVersion};
use core_outbound::{
    adapter::{BoxedStream, DialContext, OutboundAdapter},
    proto::{
        trojan::TrojanOutbound,
        xhttp::{Config, XhttpClient},
    },
    transport::XhttpOptions,
};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const XRAY_PINNED_VERSION: &str = "26.7.11";
const XRAY_PINNED_COMMIT: &str = "50231ea";
const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const NEGATIVE_ACCEPT_WINDOW: Duration = Duration::from_millis(750);
const XRAY_UUID: &str = "11111111-1111-1111-1111-111111111111";
const TROJAN_PASSWORD: &str = "wuthercore-xhttp-trojan-password";
const INTEROP_PATH: &str = "/official-tls-interop?source=wuthercore";
const MODES: [&str; 3] = ["stream-one", "stream-up", "packet-up"];
const ECH_CONFIG_LIST: &str =
    "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";
const ECH_SERVER_KEYS: &str = "ACCfHeuM9VY1sx9pq24z7wCeitcoGS2rEjeUS8d8P6kfggA+/g0AOgAAIAAguy8p4+MFfgQZ1S/F9EEYd2+NthzqT992B5uTYGxaYkgACAABAAEAAQADAAdlY2guY29tAAA=";

#[derive(Debug, Clone, Copy)]
enum HttpFlavor {
    H1,
    H2,
    H3,
}

impl HttpFlavor {
    fn label(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }

    fn alpn(self) -> &'static str {
        match self {
            Self::H1 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }

    fn accepted_version(self) -> XhttpVersion {
        match self {
            Self::H1 => XhttpVersion::Http1,
            Self::H2 => XhttpVersion::Http2,
            Self::H3 => XhttpVersion::Http3,
        }
    }
}

struct XrayProcess {
    child: Child,
    config: PathBuf,
}

impl XrayProcess {
    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("query official Xray status") {
            panic!("official Xray exited before interoperability completed: {status}");
        }
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
    }
}

struct TestIdentity {
    directory: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    pin_sha256: String,
}

impl TestIdentity {
    fn generate(name: &str) -> Self {
        let directory = unique_temp_path(&format!("identity-{name}"), "");
        fs::create_dir_all(&directory).expect("create TLS identity directory");
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate localhost test certificate");
        let cert_der = cert.der().clone();
        let key_der = key_pair.serialize_der();
        fs::write(&cert_path, cert.pem()).expect("write PEM certificate");
        fs::write(&key_path, key_pair.serialize_pem()).expect("write PEM private key");
        let pin_sha256 = hex::encode(Sha256::digest(cert_der.as_ref()));
        Self {
            directory,
            cert_path,
            key_path,
            cert_der,
            key_der,
            pin_sha256,
        }
    }

    fn rustls_server_config(&self, flavor: HttpFlavor) -> rustls::ServerConfig {
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("construct explicit XHTTP test TLS version set")
        .with_no_client_auth()
        .with_single_cert(vec![self.cert_der.clone()], private_key)
        .expect("certificate and private key must match");
        config.alpn_protocols = vec![flavor.alpn().as_bytes().to_vec()];
        config
    }
}

impl Drop for TestIdentity {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct EchoServer {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct RunningWutherServer {
    address: SocketAddr,
    server: XhttpServer,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl RunningWutherServer {
    async fn stop(mut self) {
        self.shutdown.cancel();
        self.server.close();
        let task = self.task.take().expect("WutherCore server task");
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("WutherCore XHTTP server shutdown timeout")
            .expect("join WutherCore XHTTP server")
            .expect("serve WutherCore XHTTP");
    }
}

impl Drop for RunningWutherServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.server.close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_client_to_official_xray_server_h2_all_modes() {
    run_wuthercore_client_to_official_xray(HttpFlavor::H2).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_shaped_ech_client_to_official_xray_server_h2() {
    let binary = xray_binary();
    let identity = TestIdentity::generate("wuther-ech-client-h2");
    let echo = spawn_echo().await;
    let xray_port = reserve_tcp_port().await;
    let config = xray_ech_server_config(xray_port, echo.address, &identity);
    let mut xray = spawn_xray(&binary, "wuther-ech-client-h2", config);
    let (client, mut stream) =
        dial_official_xray_with_ech(xray_port, &identity.pin_sha256, &mut xray).await;

    let payload = test_payload("wuthercore-ech-client", HttpFlavor::H2, "stream-one");
    stream
        .write_all(&payload)
        .await
        .expect("write ECH/XHTTP payload");
    stream.flush().await.expect("flush ECH/XHTTP payload");
    let mut echoed = vec![0; payload.len()];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("official Xray ECH echo timeout")
        .expect("read official Xray ECH echoed payload");
    assert_eq!(echoed, payload);

    drop(stream);
    drop(client);
    drop(xray);
    drop(echo);
    drop(identity);
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_client_to_wuthercore_server_h2_all_modes() {
    run_official_xray_client_to_wuthercore(HttpFlavor::H2).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_default_tls_alpn_to_wuthercore_server_h2_all_modes() {
    run_official_xray_client_to_wuthercore_with_alpn(HttpFlavor::H2, false).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_client_to_official_xray_server_h3_all_modes() {
    run_wuthercore_client_to_official_xray(HttpFlavor::H3).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_client_to_wuthercore_server_h3_all_modes() {
    run_official_xray_client_to_wuthercore(HttpFlavor::H3).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_trojan_client_to_official_xray_server_all_versions_and_modes() {
    let binary = xray_binary();
    for flavor in [HttpFlavor::H1, HttpFlavor::H2, HttpFlavor::H3] {
        for mode in MODES {
            eprintln!(
                "interop: WutherCore Trojan/XHTTP client -> official Xray server, transport={}, mode={mode}",
                flavor.label()
            );
            let identity = TestIdentity::generate(&format!("trojan-{}-{mode}", flavor.label()));
            let echo = spawn_echo().await;
            let xray_port = reserve_transport_port(flavor).await;
            let config = xray_trojan_server_config(flavor, mode, xray_port, &identity);
            let mut xray = spawn_xray(
                &binary,
                &format!("trojan-{}-{mode}", flavor.label()),
                config,
            );
            let mut stream = dial_official_xray_with_trojan(
                flavor,
                mode,
                xray_port,
                echo.address,
                &identity.pin_sha256,
                &mut xray,
            )
            .await;

            let payload = test_payload("wuthercore-trojan", flavor, mode);
            stream
                .write_all(&payload)
                .await
                .expect("write Trojan-over-XHTTP payload");
            stream
                .flush()
                .await
                .expect("flush Trojan-over-XHTTP payload");
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
                .await
                .expect("Trojan-over-XHTTP echo timeout")
                .expect("read Trojan-over-XHTTP echoed payload");
            assert_eq!(echoed, payload, "transport={}, mode={mode}", flavor.label());
        }
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_rejects_wrong_wuthercore_server_certificate_pin() {
    let binary = xray_binary();
    let identity = TestIdentity::generate("wrong-pin-h2");
    let (running, mut accepted) =
        start_wuthercore_server(HttpFlavor::H2, "stream-one", &identity).await;
    let socks_port = reserve_tcp_port().await;
    let wrong_pin = "00".repeat(32);
    assert_ne!(
        wrong_pin, identity.pin_sha256,
        "negative pin must differ from the generated certificate"
    );
    let config = xray_client_config(
        HttpFlavor::H2,
        "stream-one",
        socks_port,
        running.address.port(),
        &wrong_pin,
        true,
    );
    let mut xray = spawn_xray(&binary, "wrong-pin-h2", config);

    // The authenticated SOCKS connection below is itself the readiness
    // operation. Do not open a throw-away TCP probe whose EOF could be
    // confused with the certificate-verification failure under test.
    let mut socks = open_socks_when_ready(socks_port, &mut xray).await;
    send_socks_connect(&mut socks).await;
    let optimistic_connect = match timeout(TEST_TIMEOUT, read_socks_reply_code(&mut socks)).await {
        Ok(Ok(code)) => code == 0,
        Ok(Err(_)) => false,
        Err(_) => panic!("wrong certificate pin did not finish SOCKS CONNECT in time"),
    };
    if optimistic_connect {
        // Xray can acknowledge SOCKS CONNECT before the lazy VLESS/XHTTP
        // transport has performed TLS verification. Application bytes force
        // the outbound dial; success is decided by the resulting byte stream,
        // never by the optimistic SOCKS status alone.
        let write_result = async {
            socks.write_all(b"force-wrong-pin-tls-handshake").await?;
            socks.flush().await
        }
        .await;
        if write_result.is_ok() {
            let mut byte = [0_u8; 1];
            tokio::select! {
                read = timeout(TEST_TIMEOUT, socks.read(&mut byte)) => {
                    match read {
                        Ok(Ok(0)) | Ok(Err(_)) => {}
                        Ok(Ok(read)) => panic!(
                            "wrong certificate pin delivered {read} downstream byte(s)"
                        ),
                        Err(_) => panic!(
                            "wrong certificate pin left the application stream open"
                        ),
                    }
                }
                logical = accepted.accept() => {
                    match logical {
                        Some(_) => panic!(
                            "wrong certificate pin still delivered an XHTTP logical stream"
                        ),
                        None => panic!(
                            "WutherCore accept channel closed during wrong-pin test"
                        ),
                    }
                }
            }
        }
    }

    match timeout(NEGATIVE_ACCEPT_WINDOW, accepted.accept()).await {
        Err(_) => {}
        Ok(Some(_)) => panic!("wrong certificate pin still delivered an XHTTP logical stream"),
        Ok(None) => panic!("WutherCore accept channel closed during wrong-pin test"),
    }

    drop(socks);
    drop(xray);
    running.stop().await;
}

async fn run_wuthercore_client_to_official_xray(flavor: HttpFlavor) {
    let binary = xray_binary();
    for mode in MODES {
        eprintln!(
            "interop: WutherCore client -> official Xray server, transport={}, mode={mode}",
            flavor.label()
        );
        let identity = TestIdentity::generate(&format!("wuther-client-{}-{mode}", flavor.label()));
        let echo = spawn_echo().await;
        let xray_port = reserve_transport_port(flavor).await;
        let config = xray_server_config(flavor, mode, xray_port, echo.address, &identity);
        let mut xray = spawn_xray(
            &binary,
            &format!("wuther-client-{}-{mode}", flavor.label()),
            config,
        );

        // This is intentionally the readiness check as well as the test dial.
        // In particular, HTTP/3 is proved ready only after a real UDP,
        // QUIC, TLS, H3 and XHTTP exchange succeeds.
        let (client, mut stream) =
            dial_official_xray(flavor, mode, xray_port, &identity.pin_sha256, &mut xray).await;
        let payload = test_payload("wuthercore-client", flavor, mode);
        stream
            .write_all(&payload)
            .await
            .expect("write WutherCore XHTTP payload");
        stream
            .flush()
            .await
            .expect("flush WutherCore XHTTP payload");
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
            .await
            .expect("official Xray echo timeout")
            .expect("read official Xray echoed payload");
        assert_eq!(echoed, payload, "transport={}, mode={mode}", flavor.label());

        drop(stream);
        drop(client);
        drop(xray);
        drop(echo);
        drop(identity);
    }
}

async fn run_official_xray_client_to_wuthercore(flavor: HttpFlavor) {
    run_official_xray_client_to_wuthercore_with_alpn(flavor, true).await;
}

async fn run_official_xray_client_to_wuthercore_with_alpn(flavor: HttpFlavor, explicit_alpn: bool) {
    let binary = xray_binary();
    for mode in MODES {
        eprintln!(
            "interop: official Xray client -> WutherCore server, transport={}, mode={mode}",
            flavor.label()
        );
        let identity = TestIdentity::generate(&format!("xray-client-{}-{mode}", flavor.label()));
        let (running, accepted) = start_wuthercore_server(flavor, mode, &identity).await;
        let payload = test_payload("official-xray-client", flavor, mode);
        let logical_payload = payload.clone();
        let logical_task = tokio::spawn(serve_one_vless_echo(
            accepted,
            mode,
            flavor.accepted_version(),
            logical_payload,
        ));

        let socks_port = reserve_tcp_port().await;
        let config = xray_client_config(
            flavor,
            mode,
            socks_port,
            running.address.port(),
            &identity.pin_sha256,
            explicit_alpn,
        );
        let mut xray = spawn_xray(
            &binary,
            &format!("xray-client-{}-{mode}", flavor.label()),
            config,
        );

        let mut socks = open_socks_when_ready(socks_port, &mut xray).await;
        establish_socks_connect(&mut socks).await;
        socks
            .write_all(&payload)
            .await
            .expect("write official Xray SOCKS payload");
        socks
            .flush()
            .await
            .expect("flush official Xray SOCKS payload");
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
            .await
            .expect("official Xray SOCKS echo timeout")
            .expect("read official Xray SOCKS echoed payload");
        assert_eq!(echoed, payload, "transport={}, mode={mode}", flavor.label());

        drop(socks);
        timeout(TEST_TIMEOUT, logical_task)
            .await
            .expect("WutherCore logical stream task timeout")
            .expect("join WutherCore logical stream task");
        drop(xray);
        running.stop().await;
        drop(identity);
    }
}

async fn start_wuthercore_server(
    flavor: HttpFlavor,
    mode: &str,
    identity: &TestIdentity,
) -> (RunningWutherServer, XhttpAcceptReceiver) {
    let (server, accepted) =
        XhttpServer::new(xhttp_config(mode), Some(16)).expect("construct WutherCore XHTTP server");
    let shutdown = CancellationToken::new();
    let (address, task) = match flavor {
        HttpFlavor::H1 | HttpFlavor::H2 => {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind WutherCore TLS/H2 listener");
            let address = listener.local_addr().expect("WutherCore H2 address");
            let acceptor = TlsAcceptor::from(Arc::new(identity.rustls_server_config(flavor)));
            let task = {
                let server = server.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    server
                        .serve_tls_listener(listener, acceptor, shutdown)
                        .await
                })
            };
            (address, task)
        }
        HttpFlavor::H3 => {
            let server_tls = identity.rustls_server_config(flavor);
            let quic_crypto = QuicServerConfig::try_from(server_tls)
                .expect("convert WutherCore TLS identity to QUIC server config");
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)),
                "127.0.0.1:0".parse().expect("loopback QUIC address"),
            )
            .expect("bind WutherCore QUIC/H3 endpoint");
            let address = endpoint.local_addr().expect("WutherCore H3 address");
            let task = {
                let server = server.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move { server.serve_h3_endpoint(endpoint, shutdown).await })
            };
            (address, task)
        }
    };
    (
        RunningWutherServer {
            address,
            server,
            shutdown,
            task: Some(task),
        },
        accepted,
    )
}

async fn serve_one_vless_echo(
    mut accepted: XhttpAcceptReceiver,
    expected_mode: &'static str,
    expected_version: XhttpVersion,
    payload: Vec<u8>,
) {
    let mut accepted = timeout(TEST_TIMEOUT, accepted.accept())
        .await
        .expect("WutherCore logical XHTTP accept timeout")
        .expect("WutherCore logical XHTTP stream");
    assert_eq!(accepted.mode, expected_mode);
    assert_eq!(accepted.version, expected_version);
    read_vless_request(&mut accepted.stream).await;
    accepted
        .stream
        .write_all(&[0, 0])
        .await
        .expect("write VLESS response");
    accepted.stream.flush().await.expect("flush VLESS response");
    let mut received = vec![0; payload.len()];
    timeout(TEST_TIMEOUT, accepted.stream.read_exact(&mut received))
        .await
        .expect("VLESS application payload timeout")
        .expect("read VLESS application payload");
    assert_eq!(received, payload);
    accepted
        .stream
        .write_all(&received)
        .await
        .expect("echo VLESS application payload");
    accepted
        .stream
        .flush()
        .await
        .expect("flush VLESS application payload");

    // The caller drops the SOCKS stream before joining this task. Reaching a
    // zero-byte clean EOF here proves that the H2/H3 upload shutdown itself
    // closes the logical XHTTP byte stream; server cancellation is deliberately
    // performed only after this assertion.
    let trailing = timeout(
        TEST_TIMEOUT,
        tokio::io::copy(&mut accepted.stream, &mut tokio::io::sink()),
    )
    .await
    .expect("logical XHTTP stream did not observe client close")
    .expect("H2/H3 client close must be a clean logical EOF");
    assert_eq!(
        trailing, 0,
        "logical XHTTP stream delivered bytes after the echoed payload"
    );
}

fn xray_binary() -> PathBuf {
    let binary = env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .expect("set XRAY_BIN to the pinned official Xray executable");
    assert_pinned_xray(&binary);
    binary
}

fn assert_pinned_xray(binary: &Path) {
    let output = Command::new(binary)
        .arg("version")
        .output()
        .expect("run `xray version` for pin verification");
    assert!(
        output.status.success(),
        "`xray version` failed for {}",
        binary.display()
    );
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(
        version.contains(&format!("Xray {XRAY_PINNED_VERSION}"))
            && version.contains(XRAY_PINNED_COMMIT),
        "XRAY_BIN must be pinned to Xray {XRAY_PINNED_VERSION} ({XRAY_PINNED_COMMIT}); got: {version}"
    );
}

fn spawn_xray(binary: &Path, name: &str, config: Value) -> XrayProcess {
    let config_path = unique_temp_path(&format!("xray-{name}"), ".json");
    let body = serde_json::to_vec_pretty(&config).expect("serialize official Xray config");
    fs::write(&config_path, body).expect("write official Xray config");
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start official Xray");
    XrayProcess {
        child,
        config: config_path,
    }
}

fn unique_temp_path(name: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "wuthercore-xhttp-tls-{name}-{}-{nonce}{suffix}",
        std::process::id()
    ))
}

async fn reserve_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve loopback TCP port");
    listener.local_addr().expect("reserved TCP address").port()
}

async fn reserve_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("reserve loopback UDP port");
    socket.local_addr().expect("reserved UDP address").port()
}

async fn reserve_transport_port(flavor: HttpFlavor) -> u16 {
    match flavor {
        HttpFlavor::H1 | HttpFlavor::H2 => reserve_tcp_port().await,
        HttpFlavor::H3 => reserve_udp_port().await,
    }
}

async fn dial_official_xray(
    flavor: HttpFlavor,
    mode: &str,
    port: u16,
    pin_sha256: &str,
    process: &mut XrayProcess,
) -> (XhttpClient, BoxedStream) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_error = "not attempted".to_owned();
    loop {
        process.assert_running();
        let mut client = XhttpClient::new(xhttp_config(mode), "127.0.0.1", port);
        client.tls = true;
        client.sni = Some("localhost".into());
        client.insecure = false;
        client.alpn = vec![flavor.alpn().into()];
        client.pinned_peer_cert_sha256 = vec![
            hex::decode(pin_sha256)
                .expect("generated pin is hex")
                .try_into()
                .expect("generated pin is SHA-256"),
        ];
        client.verify_peer_cert_by_name = vec!["localhost".into()];

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "official Xray {} XHTTP readiness timeout, last error: {last_error}",
                flavor.label()
            );
        }
        match timeout(DIAL_ATTEMPT_TIMEOUT.min(remaining), client.dial(false)).await {
            Ok(Ok(stream)) => return (client, stream),
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "individual XHTTP dial attempt timed out".into(),
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn dial_official_xray_with_ech(
    port: u16,
    pin_sha256: &str,
    process: &mut XrayProcess,
) -> (XhttpClient, BoxedStream) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_error = "not attempted".to_owned();
    loop {
        process.assert_running();
        let mut client = XhttpClient::new(xhttp_config("stream-one"), "127.0.0.1", port);
        client.tls = true;
        client.tls_settings = Some(core_config::model::XhttpDownloadTlsSettings {
            server_name: Some("localhost".into()),
            alpn: Some(vec!["h2".into()]),
            min_version: Some("1.3".into()),
            max_version: Some("1.3".into()),
            fingerprint: Some("chrome".into()),
            pinned_peer_cert_sha256: Some(pin_sha256.into()),
            verify_peer_cert_by_name: Some("localhost".into()),
            ech_config_list: Some(ECH_CONFIG_LIST.into()),
            ..Default::default()
        });

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("official Xray H2/ECH readiness timeout, last error: {last_error}");
        }
        match timeout(DIAL_ATTEMPT_TIMEOUT.min(remaining), client.dial(false)).await {
            Ok(Ok(stream)) => return (client, stream),
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "individual H2/ECH dial attempt timed out".into(),
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn dial_official_xray_with_trojan(
    flavor: HttpFlavor,
    mode: &str,
    port: u16,
    target: SocketAddr,
    pin_sha256: &str,
    process: &mut XrayProcess,
) -> BoxedStream {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_error = "not attempted".to_owned();
    loop {
        process.assert_running();
        let mut outbound = TrojanOutbound::new("official-xray", "127.0.0.1", port, TROJAN_PASSWORD);
        outbound.sni = Some("localhost".into());
        outbound.insecure = false;
        outbound.alpn = vec![flavor.alpn().into()];
        outbound.xhttp = Some(XhttpOptions {
            enabled: true,
            config: xhttp_config(mode),
            tls: true,
            sni: outbound.sni.clone(),
            insecure: outbound.insecure,
            alpn: outbound.alpn.clone(),
            pinned_peer_cert_sha256: vec![
                hex::decode(pin_sha256)
                    .expect("generated pin is hex")
                    .try_into()
                    .expect("generated pin is SHA-256"),
            ],
            verify_peer_cert_by_name: vec!["localhost".into()],
            ..Default::default()
        });

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "official Xray {} Trojan/XHTTP readiness timeout, last error: {last_error}",
                flavor.label()
            );
        }
        match timeout(
            DIAL_ATTEMPT_TIMEOUT.min(remaining),
            outbound.dial_tcp(DialContext::tcp(target.ip().to_string(), target.port())),
        )
        .await
        {
            Ok(Ok(stream)) => return stream,
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "individual Trojan/XHTTP dial attempt timed out".into(),
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn spawn_echo() -> EchoServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP echo listener");
    let address = listener.local_addr().expect("TCP echo address");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    EchoServer { address, task }
}

fn xhttp_config(mode: &str) -> Config {
    Config {
        path: INTEROP_PATH.into(),
        mode: mode.into(),
        x_padding_bytes: "100-100".into(),
        sc_max_each_post_bytes: "1024-1024".into(),
        sc_min_posts_interval_ms: "1".into(),
        sc_stream_up_server_secs: "1-1".into(),
        ..Default::default()
    }
}

fn xhttp_json(mode: &str) -> Value {
    json!({
        "path": INTEROP_PATH,
        "mode": mode,
        "xPaddingBytes": "100-100",
        "scMaxEachPostBytes": "1024-1024",
        "scMinPostsIntervalMs": "1",
        "scStreamUpServerSecs": "1-1"
    })
}

fn xray_server_config(
    flavor: HttpFlavor,
    mode: &str,
    listen_port: u16,
    echo: SocketAddr,
    identity: &TestIdentity,
) -> Value {
    let certificate_file = identity.cert_path.to_string_lossy().into_owned();
    let key_file = identity.key_path.to_string_lossy().into_owned();
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": listen_port,
            "protocol": "dokodemo-door",
            "settings": {
                "address": echo.ip().to_string(),
                "port": echo.port(),
                "network": "tcp"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [flavor.alpn()],
                    "certificates": [{
                        "certificateFile": certificate_file,
                        "keyFile": key_file
                    }]
                },
                "xhttpSettings": xhttp_json(mode)
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    })
}

fn xray_ech_server_config(listen_port: u16, echo: SocketAddr, identity: &TestIdentity) -> Value {
    let mut config = xray_server_config(HttpFlavor::H2, "stream-one", listen_port, echo, identity);
    let tls = &mut config["inbounds"][0]["streamSettings"]["tlsSettings"];
    tls["echServerKeys"] = json!(ECH_SERVER_KEYS);
    // The outer ECH public name is `ech.com`, while the encrypted inner SNI is
    // `localhost`. Rejecting unknown SNI makes this test fail if the client
    // silently omits ECH or the server cannot decrypt ClientHelloInner.
    tls["rejectUnknownSni"] = json!(true);
    tls["minVersion"] = json!("1.3");
    tls["maxVersion"] = json!("1.3");
    config
}

fn xray_trojan_server_config(
    flavor: HttpFlavor,
    mode: &str,
    listen_port: u16,
    identity: &TestIdentity,
) -> Value {
    let certificate_file = identity.cert_path.to_string_lossy().into_owned();
    let key_file = identity.key_path.to_string_lossy().into_owned();
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": listen_port,
            "protocol": "trojan",
            "settings": {
                "clients": [{
                    "password": TROJAN_PASSWORD,
                    "email": "wuthercore-xhttp-interop"
                }]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": [flavor.alpn()],
                    "certificates": [{
                        "certificateFile": certificate_file,
                        "keyFile": key_file
                    }]
                },
                "xhttpSettings": xhttp_json(mode)
            }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": {
                "finalRules": [{ "action": "allow" }]
            }
        }]
    })
}

fn xray_client_config(
    flavor: HttpFlavor,
    mode: &str,
    socks_port: u16,
    server_port: u16,
    pin_sha256: &str,
    explicit_alpn: bool,
) -> Value {
    let mut tls_settings = json!({
        "serverName": "localhost",
        "pinnedPeerCertSha256": pin_sha256,
        "verifyPeerCertByName": "localhost"
    });
    if explicit_alpn {
        tls_settings
            .as_object_mut()
            .expect("TLS settings object")
            .insert("alpn".into(), json!([flavor.alpn()]));
    }
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "users": [{
                        "id": XRAY_UUID,
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": tls_settings,
                "xhttpSettings": xhttp_json(mode)
            }
        }]
    })
}

fn test_payload(direction: &str, flavor: HttpFlavor, mode: &str) -> Vec<u8> {
    let marker = format!("{direction}-{}-{mode}|", flavor.label()).into_bytes();
    let mut payload = Vec::with_capacity(16 * 1024);
    while payload.len() < 16 * 1024 {
        payload.extend_from_slice(&marker);
        for index in 0..251_u16 {
            payload.push(((index * 37 + mode.len() as u16) % 251) as u8);
        }
    }
    payload.truncate(16 * 1024);
    payload
}

async fn try_open_socks_connection(port: u16) -> io::Result<TcpStream> {
    let mut socks = TcpStream::connect(("127.0.0.1", port)).await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("official Xray SOCKS no-auth greeting was {:02x?}", greeting),
        ));
    }
    Ok(socks)
}

async fn open_socks_when_ready(port: u16, process: &mut XrayProcess) -> TcpStream {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_error = "not attempted".to_owned();
    loop {
        process.assert_running();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("official Xray SOCKS readiness timeout, last error: {last_error}");
        }
        match timeout(
            DIAL_ATTEMPT_TIMEOUT.min(remaining),
            try_open_socks_connection(port),
        )
        .await
        {
            Ok(Ok(socks)) => return socks,
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "individual SOCKS greeting attempt timed out".into(),
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn send_socks_connect(socks: &mut TcpStream) {
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .expect("write SOCKS CONNECT");
}

async fn establish_socks_connect(socks: &mut TcpStream) {
    send_socks_connect(socks).await;
    let code = timeout(TEST_TIMEOUT, read_socks_reply_code(socks))
        .await
        .expect("SOCKS CONNECT timeout")
        .expect("read SOCKS CONNECT response");
    assert_eq!(code, 0, "SOCKS CONNECT failed with code {code}");
}

async fn read_socks_reply_code(stream: &mut TcpStream) -> io::Result<u8> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected SOCKS version {}", head[0]),
        ));
    }
    let address_length = match head[3] {
        1 => 4,
        3 => stream.read_u8().await? as usize,
        4 => 16,
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SOCKS address type {atyp}"),
            ));
        }
    };
    let mut tail = vec![0; address_length + 2];
    stream.read_exact(&mut tail).await?;
    Ok(head[1])
}

async fn read_vless_request(stream: &mut (impl AsyncRead + Unpin)) {
    let mut fixed = [0_u8; 18];
    stream
        .read_exact(&mut fixed)
        .await
        .expect("read VLESS version, UUID and addons length");
    assert_eq!(fixed[0], 0, "VLESS version");
    assert_ne!(&fixed[1..17], &[0; 16], "VLESS UUID must be present");
    let addons_length = fixed[17] as usize;
    let mut addons = vec![0; addons_length];
    stream
        .read_exact(&mut addons)
        .await
        .expect("read VLESS addons");

    let mut command_port_type = [0_u8; 4];
    stream
        .read_exact(&mut command_port_type)
        .await
        .expect("read VLESS command and destination");
    assert_eq!(command_port_type[0], 1, "VLESS TCP command");
    match command_port_type[3] {
        1 => {
            let mut address = [0; 4];
            stream
                .read_exact(&mut address)
                .await
                .expect("read VLESS IPv4");
        }
        2 => {
            let length = stream.read_u8().await.expect("read VLESS domain length");
            let mut address = vec![0; length as usize];
            stream
                .read_exact(&mut address)
                .await
                .expect("read VLESS domain");
        }
        3 => {
            let mut address = [0; 16];
            stream
                .read_exact(&mut address)
                .await
                .expect("read VLESS IPv6");
        }
        other => panic!("unsupported VLESS address type {other}"),
    }
}
