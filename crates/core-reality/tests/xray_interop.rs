//! Official Xray client -> Rust REALITY server interoperability.
//!
//! Run with the pinned binary:
//! `XRAY_BIN=/path/to/xray cargo test -p core-reality --test xray_interop -- --ignored --nocapture`

use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use core_reality::{
    FallbackLimit, ProxyProtocolVersion, RealityClient, RealityClientConfig, RealityServer,
    RealityServerConfig, RealityServerLimits, x25519_public_key,
};
use rcgen::{
    CertificateParams, CertifiedKey, CustomExtension, KeyPair, generate_simple_self_signed,
};
use rustls::crypto::aws_lc_rs::kx_group::{X25519, X25519MLKEM768};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const XRAY_PINNED_VERSION: &str = "26.7.11";
const XRAY_PINNED_COMMIT: &str = "6e3322d";
const XRAY_UUID: &str = "11111111-1111-1111-1111-111111111111";
const SERVER_NAME: &str = "www.example.com";
const SHORT_ID: [u8; 8] = [1, 35, 69, 103, 137, 171, 205, 239];
static XRAY_INTEROP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct XrayProcess {
    child: Child,
    config: PathBuf,
    cleanup: Vec<PathBuf>,
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
        for path in &self.cleanup {
            let _ = fs::remove_file(path);
        }
    }
}

fn xray_binary() -> PathBuf {
    let binary = env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .expect("set XRAY_BIN to the pinned official Xray executable");
    let output = Command::new(&binary)
        .arg("version")
        .output()
        .expect("run xray version");
    assert!(output.status.success());
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(
        version.contains(&format!("Xray {XRAY_PINNED_VERSION}"))
            && version.contains(XRAY_PINNED_COMMIT),
        "unexpected Xray build: {version}"
    );
    binary
}

fn temp_config(body: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "wuthercore-reality-{}-{nonce}.json",
        std::process::id()
    ));
    fs::write(&path, body).expect("write Xray config");
    path
}

fn temp_artifact(suffix: &str, body: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "wuthercore-reality-{}-{nonce}-{suffix}",
        std::process::id()
    ));
    fs::write(&path, body).expect("write Xray test artifact");
    path
}

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).unwrap());
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output.into_bytes()
}

fn spawn_xray(binary: &Path, config: String) -> XrayProcess {
    spawn_xray_with_cleanup(binary, config, Vec::new())
}

fn spawn_xray_with_cleanup(binary: &Path, config: String, cleanup: Vec<PathBuf>) -> XrayProcess {
    let config = temp_config(&config);
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Xray");
    XrayProcess {
        child,
        config,
        cleanup,
    }
}

async fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_listener(port: u16, process: &mut XrayProcess) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(status) = process.child.try_wait().expect("query Xray") {
                panic!("Xray exited early: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Xray listener timeout");
}

async fn spawn_camouflage_target(hybrid: bool) -> (SocketAddr, JoinHandle<()>) {
    let mut params = CertificateParams::new(vec![SERVER_NAME.into()]).unwrap();
    // A one-certificate rcgen flight is otherwise smaller than Xray's
    // encrypted-flight detection threshold. Real public sites have a larger
    // certificate chain; padding this deterministic fixture gives both Xray
    // and this implementation the same realistic, self-delimiting template.
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 2],
            {
                let mut state = 0x9e37_79b9_7f4a_7c15u64;
                (0..if hybrid { 4096 } else { 2048 })
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect()
            },
        ));
    let signing_key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&signing_key).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if hybrid {
        vec![X25519MLKEM768]
    } else {
        vec![X25519]
    };
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            // REALITY intentionally abandons this target handshake after using
            // the first server flight as its wire-shape template.
            let _ = acceptor.accept(stream).await;
        }
    });
    (address, task)
}

async fn spawn_xray_tls_camouflage_target(
    binary: &Path,
    hybrid: bool,
) -> (SocketAddr, XrayProcess) {
    let CertifiedKey { cert, signing_key } = if hybrid {
        let mut params = CertificateParams::new(vec![SERVER_NAME.into()]).unwrap();
        // ML-DSA-65 adds a large certificate extension. Xray preserves the
        // target site's TLS record shape, so the camouflage certificate record
        // needs enough room for that extension instead of negative padding.
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55555, 1],
                vec![0; 4096],
            ));
        let signing_key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&signing_key).unwrap();
        CertifiedKey { cert, signing_key }
    } else {
        generate_simple_self_signed(vec![SERVER_NAME.into()]).unwrap()
    };
    let certificate_path =
        temp_artifact("certificate.pem", &pem("CERTIFICATE", cert.der().as_ref()));
    let key_path = temp_artifact(
        "private-key.pem",
        &pem("PRIVATE KEY", &signing_key.serialize_der()),
    );
    let certificate_json = format!("{:?}", certificate_path.to_string_lossy());
    let key_json = format!("{:?}", key_path.to_string_lossy());
    let port = reserve_port().await;
    let curve = if hybrid { "X25519MLKEM768" } else { "X25519" };
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {port},
    "protocol": "http",
    "settings": {{}},
    "streamSettings": {{
      "network": "raw",
      "security": "tls",
      "tlsSettings": {{
        "minVersion": "1.3",
        "maxVersion": "1.3",
        "curvePreferences": ["{curve}"],
        "certificates": [{{
          "certificateFile": {certificate_json},
          "keyFile": {key_json}
        }}]
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{ "finalRules": [{{ "action": "allow" }}] }}
  }}]
}}"#
    );
    let mut process = spawn_xray_with_cleanup(binary, config, vec![certificate_path, key_path]);
    wait_for_listener(port, &mut process).await;
    (format!("127.0.0.1:{port}").parse().unwrap(), process)
}

fn server_config(target: SocketAddr, hybrid_mldsa: bool) -> RealityServerConfig {
    RealityServerConfig {
        camouflage_target: target.to_string(),
        private_key: [0x42; 32],
        server_names: HashSet::from([SERVER_NAME.into()]),
        short_ids: vec![SHORT_ID],
        min_client_version: Some([26, 3, 27]),
        max_client_version: None,
        max_time_difference: Some(Duration::from_secs(60)),
        mldsa65_seed: hybrid_mldsa.then_some([0x24; 32]),
        cipher_suites: Vec::new(),
        proxy_protocol: ProxyProtocolVersion::None,
        fallback_upload: FallbackLimit::default(),
        fallback_download: FallbackLimit::default(),
        limits: RealityServerLimits::default(),
    }
}

async fn spawn_reality_server(
    config: RealityServerConfig,
    payload: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = RealityServer::new(config).unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept Xray REALITY client");
        let local = stream.local_addr().unwrap();
        let mut accepted = timeout(
            TEST_TIMEOUT,
            server.accept(stream, peer, local, CancellationToken::new()),
        )
        .await
        .expect("REALITY accept timeout")
        .expect("authenticate official Xray client");
        read_vless_request(&mut accepted).await;
        accepted.write_all(&[0, 0]).await.expect("VLESS response");
        accepted.flush().await.unwrap();
        let mut received = vec![0; payload.len()];
        accepted
            .read_exact(&mut received)
            .await
            .expect("VLESS application payload");
        assert_eq!(received, payload);
        accepted.write_all(&received).await.expect("echo response");
        accepted.flush().await.unwrap();
    });
    (address, task)
}

fn xray_config(
    socks_port: u16,
    reality_addr: SocketAddr,
    public_key: &[u8; 32],
    mldsa_verify: Option<&[u8]>,
) -> String {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    let mldsa = mldsa_verify
        .map(|key| {
            format!(
                ",\n          \"mldsa65Verify\": \"{}\"",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
            )
        })
        .unwrap_or_default();
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": false }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {},
        "users": [{{ "id": "{XRAY_UUID}", "encryption": "none" }}]
      }}]
    }},
    "streamSettings": {{
      "network": "raw",
      "security": "reality",
      "realitySettings": {{
        "serverName": "{SERVER_NAME}",
        "fingerprint": "chrome",
        "password": "{public_key}",
        "shortId": "0123456789abcdef",
        "spiderX": "/"{mldsa}
      }}
    }}
  }}]
}}"#,
        reality_addr.port()
    )
}

async fn run_case(hybrid_mldsa: bool) {
    let binary = xray_binary();
    let (target, target_task) = spawn_camouflage_target(hybrid_mldsa).await;
    let config = server_config(target, hybrid_mldsa);
    let verify = config.mldsa65_verify_key().unwrap();
    let public_key = x25519_public_key(&config.private_key).unwrap();
    let payload = if hybrid_mldsa {
        b"xray-hybrid-mldsa".to_vec()
    } else {
        b"xray-x25519".to_vec()
    };
    let (reality_addr, server_task) = spawn_reality_server(config, payload.clone()).await;
    let socks_port = reserve_port().await;
    let mut xray = spawn_xray(
        &binary,
        xray_config(socks_port, reality_addr, &public_key, verify.as_deref()),
    );
    wait_for_listener(socks_port, &mut xray).await;

    let mut socks = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    read_socks_reply(&mut socks).await;
    socks.write_all(&payload).await.unwrap();
    socks.flush().await.unwrap();
    let mut echoed = vec![0; payload.len()];
    timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
        .await
        .expect("SOCKS echo timeout")
        .expect("SOCKS echo");
    assert_eq!(echoed, payload);

    timeout(TEST_TIMEOUT, server_task)
        .await
        .expect("server task timeout")
        .expect("join server");
    let _ = timeout(TEST_TIMEOUT, target_task).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to Xray 26.7.11 (6e3322d)"]
async fn official_xray_client_interoperates_over_x25519() {
    let _guard = XRAY_INTEROP_LOCK.lock().await;
    run_case(false).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to Xray 26.7.11 (6e3322d)"]
async fn official_xray_client_interoperates_over_x25519_mlkem768_and_mldsa65() {
    let _guard = XRAY_INTEROP_LOCK.lock().await;
    run_case(true).await;
}

fn xray_reality_server_config(
    reality_port: u16,
    camouflage: SocketAddr,
    private_key: &[u8; 32],
    mldsa65_seed: Option<&[u8; 32]>,
) -> String {
    let private_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private_key);
    let mldsa65_seed = mldsa65_seed
        .map(|seed| {
            format!(
                ",\n        \"mldsa65Seed\": \"{}\"",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)
            )
        })
        .unwrap_or_default();
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {reality_port},
    "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{XRAY_UUID}" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "raw",
      "security": "reality",
      "realitySettings": {{
        "target": "{camouflage}",
        "serverNames": ["{SERVER_NAME}"],
        "privateKey": "{private_key}",
        "shortIds": ["0123456789abcdef"]{mldsa65_seed}
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{ "finalRules": [{{ "action": "allow" }}] }}
  }}]
}}"#
    )
}

async fn spawn_tcp_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("echo accept");
        let mut buffer = [0u8; 4096];
        loop {
            let length = match stream.read(&mut buffer).await {
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("echo read: {error}"),
            };
            if length == 0 {
                break;
            }
            stream
                .write_all(&buffer[..length])
                .await
                .expect("echo write");
            stream.flush().await.expect("echo flush");
        }
    });
    (address, task)
}

async fn write_vless_tcp_request(stream: &mut (impl AsyncWrite + Unpin), destination: SocketAddr) {
    let mut request = Vec::with_capacity(26);
    request.push(0); // protocol version
    request.extend_from_slice(&[0x11; 16]); // XRAY_UUID
    request.push(0); // addons length
    request.push(1); // TCP command
    request.extend_from_slice(&destination.port().to_be_bytes());
    match destination.ip() {
        std::net::IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(3);
            request.extend_from_slice(&address.octets());
        }
    }
    stream.write_all(&request).await.expect("VLESS request");
    stream.flush().await.expect("VLESS request flush");
}

async fn run_project_client_case(hybrid_mldsa: bool) {
    let binary = xray_binary();
    let (camouflage, camouflage_process) =
        spawn_xray_tls_camouflage_target(&binary, hybrid_mldsa).await;
    let (echo, echo_task) = spawn_tcp_echo().await;
    let private_key = [0x42; 32];
    let public_key = x25519_public_key(&private_key).unwrap();
    let mldsa65_seed = hybrid_mldsa.then_some([0x24; 32]);
    let verify = server_config(camouflage, hybrid_mldsa)
        .mldsa65_verify_key()
        .unwrap();
    let reality_port = reserve_port().await;
    let mut xray = spawn_xray(
        &binary,
        xray_reality_server_config(
            reality_port,
            camouflage,
            &private_key,
            mldsa65_seed.as_ref(),
        ),
    );
    wait_for_listener(reality_port, &mut xray).await;

    let client = RealityClient::new(RealityClientConfig {
        server_name: SERVER_NAME.into(),
        fingerprint: "chrome".into(),
        public_key,
        short_id: SHORT_ID.to_vec(),
        spider_x: "/".into(),
        mldsa65_verify: verify,
        handshake_timeout: TEST_TIMEOUT,
        ..RealityClientConfig::default()
    })
    .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", reality_port))
        .await
        .unwrap();
    let mut reality = timeout(TEST_TIMEOUT, client.connect(tcp))
        .await
        .expect("WutherCore REALITY client timeout")
        .expect("WutherCore client authenticates official Xray server");
    write_vless_tcp_request(&mut reality, echo).await;

    let payload: &[u8] = if hybrid_mldsa {
        b"wuther-client-hybrid-mldsa"
    } else {
        b"wuther-client-x25519"
    };
    reality.write_all(payload).await.unwrap();
    reality.flush().await.unwrap();
    let mut response_header = [0u8; 2];
    timeout(TEST_TIMEOUT, reality.read_exact(&mut response_header))
        .await
        .expect("VLESS response timeout")
        .expect("VLESS response header");
    assert_eq!(response_header[0], 0);
    let mut addons = vec![0; response_header[1] as usize];
    reality.read_exact(&mut addons).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    timeout(TEST_TIMEOUT, reality.read_exact(&mut echoed))
        .await
        .expect("official Xray echo timeout")
        .expect("official Xray echo");
    assert_eq!(echoed, payload);

    drop(reality);
    drop(xray);
    timeout(TEST_TIMEOUT, echo_task)
        .await
        .expect("echo task timeout")
        .expect("echo task join");
    drop(camouflage_process);
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to Xray 26.7.11 (6e3322d)"]
async fn wuthercore_client_interoperates_with_official_xray_server_over_x25519() {
    let _guard = XRAY_INTEROP_LOCK.lock().await;
    run_project_client_case(false).await;
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to Xray 26.7.11 (6e3322d)"]
async fn wuthercore_client_interoperates_with_official_xray_server_over_hybrid_mldsa65() {
    let _guard = XRAY_INTEROP_LOCK.lock().await;
    run_project_client_case(true).await;
}

async fn read_vless_request(stream: &mut (impl AsyncRead + Unpin)) {
    let mut fixed = [0u8; 18];
    stream
        .read_exact(&mut fixed)
        .await
        .expect("VLESS request header");
    assert_eq!(fixed[0], 0);
    let mut addons = vec![0; fixed[17] as usize];
    stream.read_exact(&mut addons).await.expect("VLESS addons");
    let mut destination = [0u8; 4];
    stream
        .read_exact(&mut destination)
        .await
        .expect("VLESS destination header");
    assert_eq!(destination[0], 1, "VLESS TCP command");
    match destination[3] {
        1 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await.unwrap();
        }
        2 => {
            let len = stream.read_u8().await.unwrap();
            let mut address = vec![0; len as usize];
            stream.read_exact(&mut address).await.unwrap();
        }
        3 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await.unwrap();
        }
        kind => panic!("unexpected VLESS address kind {kind}"),
    }
}

async fn read_socks_reply(stream: &mut TcpStream) {
    let mut head = [0u8; 4];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut head))
        .await
        .expect("SOCKS reply timeout")
        .expect("SOCKS reply");
    assert_eq!(&head[..2], &[5, 0]);
    let address_length = match head[3] {
        1 => 4,
        3 => stream.read_u8().await.unwrap() as usize,
        4 => 16,
        kind => panic!("unexpected SOCKS address kind {kind}"),
    };
    let mut tail = vec![0; address_length + 2];
    stream.read_exact(&mut tail).await.unwrap();
}
