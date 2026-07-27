//! Real tonic/prost gRPC transport interoperability against pinned Xray-core.
//!
//! Run explicitly with:
//!
//! ```text
//! XRAY_BIN=/path/to/xray cargo test -p tests-e2e --test e2e_grpc_xray -- --ignored
//! ```

use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, Once},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use core_config::{
    model::{XhttpDownloadTlsCertificate, XhttpDownloadTlsSettings, XhttpTlsCertificateUsage},
    node_uri::{NodeProtocol, ParsedNode, parse_uri},
};
use core_grpc::server::{GrpcRequestContext, GrpcServerConfig, TunnelHandler, serve_connection};
use core_inbound::{GrpcListener, run_grpc};
use core_outbound::{
    adapter::DialContext,
    registry::build_outbound,
    transport::{GrpcOptions, GrpcTransport, TlsOptions, Transport},
};
use core_runtime::Runtime;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::{crypto::aws_lc_rs::kx_group::X25519, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const XRAY_UUID: &str = "11111111-1111-1111-1111-111111111111";
const XRAY_PINNED_VERSION: &str = "26.7.11";
const XRAY_PINNED_COMMIT: &str = "50231ea";
const SERVICE_NAME: &str = "wuthercore-grpc-interop";
const CUSTOM_SERVER_SERVICE: &str = "/wuther/core/Tun X|Tun Multi X";
const CUSTOM_TUN_SERVICE: &str = "/wuther/core/Tun X";
const CUSTOM_MULTI_SERVICE: &str = "/wuther/core/Tun Multi X";
const ESCAPED_LEGACY_SERVICE: &str = "Gun Service/一";
const REALITY_SERVER_NAME: &str = "grpc-reality.example";
const REALITY_SHORT_ID: &str = "0123456789abcdef";

fn init_test_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("core_inbound=debug,core_grpc=debug")
            .with_test_writer()
            .try_init();
    });
}

#[derive(Clone, Copy)]
struct InteropCase {
    label: &'static str,
    multi_mode: bool,
    server_service: &'static str,
    client_service: &'static str,
}

const INTEROP_CASES: [InteropCase; 8] = [
    InteropCase {
        label: "empty-tun",
        multi_mode: false,
        server_service: "",
        client_service: "",
    },
    InteropCase {
        label: "empty-tun-multi",
        multi_mode: true,
        server_service: "",
        client_service: "",
    },
    InteropCase {
        label: "tun",
        multi_mode: false,
        server_service: SERVICE_NAME,
        client_service: SERVICE_NAME,
    },
    InteropCase {
        label: "escaped-legacy-tun",
        multi_mode: false,
        server_service: ESCAPED_LEGACY_SERVICE,
        client_service: ESCAPED_LEGACY_SERVICE,
    },
    InteropCase {
        label: "escaped-legacy-tun-multi",
        multi_mode: true,
        server_service: ESCAPED_LEGACY_SERVICE,
        client_service: ESCAPED_LEGACY_SERVICE,
    },
    InteropCase {
        label: "tun-multi",
        multi_mode: true,
        server_service: SERVICE_NAME,
        client_service: SERVICE_NAME,
    },
    InteropCase {
        label: "custom-tun",
        multi_mode: false,
        server_service: CUSTOM_SERVER_SERVICE,
        client_service: CUSTOM_TUN_SERVICE,
    },
    InteropCase {
        label: "custom-tun-multi",
        multi_mode: true,
        server_service: CUSTOM_SERVER_SERVICE,
        client_service: CUSTOM_MULTI_SERVICE,
    },
];

struct XrayProcess {
    child: Child,
    config: PathBuf,
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
    }
}

struct BackgroundTask(JoinHandle<()>);

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct TestCertificate {
    certificate_path: PathBuf,
    key_path: PathBuf,
    certificate_pem: String,
}

impl TestCertificate {
    fn generate(name: &str) -> Self {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()])
                .expect("generate gRPC TLS test certificate");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let prefix = env::temp_dir().join(format!(
            "wuthercore-grpc-tls-{}-{nonce}",
            std::process::id()
        ));
        let certificate_path = prefix.with_extension("crt.pem");
        let key_path = prefix.with_extension("key.pem");
        let certificate_pem = cert.pem();
        fs::write(&certificate_path, &certificate_pem).expect("write gRPC TLS test certificate");
        fs::write(&key_path, key_pair.serialize_pem()).expect("write gRPC TLS test key");
        Self {
            certificate_path,
            key_path,
            certificate_pem,
        }
    }

    fn certificate_json(&self) -> String {
        serde_json::to_string(&self.certificate_path.to_string_lossy())
            .expect("serialize certificate path")
    }

    fn key_json(&self) -> String {
        serde_json::to_string(&self.key_path.to_string_lossy()).expect("serialize key path")
    }

    fn certificate_yaml(&self) -> String {
        self.certificate_path.to_string_lossy().replace('\'', "''")
    }

    fn key_yaml(&self) -> String {
        self.key_path.to_string_lossy().replace('\'', "''")
    }
}

impl Drop for TestCertificate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.certificate_path);
        let _ = fs::remove_file(&self.key_path);
    }
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
        "XRAY_BIN must be pinned to Xray {XRAY_PINNED_VERSION} \
         ({XRAY_PINNED_COMMIT}); got: {version}"
    );
}

fn temp_config(name: &str, body: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "wuthercore-grpc-{name}-{}-{nonce}.json",
        std::process::id()
    ));
    fs::write(&path, body).expect("write Xray gRPC interoperability config");
    path
}

fn spawn_xray(binary: &Path, name: &str, config: String) -> XrayProcess {
    let config = temp_config(name, &config);
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start official Xray");
    XrayProcess { child, config }
}

async fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve loopback port");
    listener.local_addr().expect("reserved address").port()
}

async fn wait_for_listener(port: u16, process: &mut XrayProcess) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(status) = process.child.try_wait().expect("query Xray status") {
                panic!("Xray exited before becoming ready: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Xray listener readiness timeout");
}

async fn spawn_echo_server() -> (SocketAddr, BackgroundTask) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let address = listener.local_addr().expect("echo address");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (address, BackgroundTask(task))
}

async fn spawn_reality_camouflage_target() -> (SocketAddr, BackgroundTask) {
    let mut params = CertificateParams::new(vec![REALITY_SERVER_NAME.into()])
        .expect("build REALITY camouflage certificate");
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 3],
            {
                let mut state = 0x9e37_79b9_7f4a_7c15_u64;
                (0..2048)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect()
            },
        ));
    let signing_key = KeyPair::generate().expect("generate camouflage key");
    let certificate = params
        .self_signed(&signing_key)
        .expect("sign camouflage certificate");
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![X25519];
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("build TLS 1.3 camouflage provider")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .expect("install camouflage certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind REALITY camouflage target");
    let address = listener.local_addr().expect("camouflage address");
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // REALITY consumes only the target's first TLS server flight.
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    (address, BackgroundTask(task))
}

fn grpc_options(case: InteropCase) -> GrpcOptions {
    GrpcOptions {
        enabled: true,
        authority: "authority.grpc.example".into(),
        service_name: case.client_service.into(),
        multi_mode: case.multi_mode,
        idle_timeout: Duration::from_secs(30),
        health_check_timeout: Duration::from_secs(5),
        permit_without_stream: true,
        initial_window_size: Some(1 << 20),
        user_agent: "wuthercore-grpc-interop/1".into(),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_tonic_client_to_official_xray_server_tun_and_tun_multi() {
    let binary = xray_binary();
    for case in INTEROP_CASES {
        let (echo, _echo_task) = spawn_echo_server().await;
        let xray_port = reserve_port().await;
        let config = format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "dokodemo-door",
    "settings": {{
      "address": "127.0.0.1",
      "port": {},
      "network": "tcp"
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "none",
      "grpcSettings": {{
        "serviceName": "{}",
        "idle_timeout": 30,
        "health_check_timeout": 5,
        "initial_windows_size": 1048576
      }}
    }}
  }}],
  "outbounds": [{{ "protocol": "freedom" }}]
}}"#,
            echo.port(),
            case.server_service
        );
        let mut xray = spawn_xray(&binary, &format!("rust-client-{}", case.label), config);
        wait_for_listener(xray_port, &mut xray).await;

        let transport = GrpcTransport::new(grpc_options(case), TlsOptions::default());
        let mut stream = timeout(TEST_TIMEOUT, transport.connect("127.0.0.1", xray_port))
            .await
            .expect("Rust gRPC dial timeout")
            .expect("Rust tonic client dials official Xray");
        let payload = interop_payload(case.multi_mode);
        stream
            .write_all(&payload)
            .await
            .expect("write gRPC payload");
        stream.flush().await.expect("flush gRPC payload");
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
            .await
            .expect("gRPC echo timeout")
            .expect("read gRPC echo");
        assert_eq!(echoed, payload, "case={}", case.label);
        stream.shutdown().await.expect("shutdown gRPC tunnel");
    }
}

fn interop_payload(multi_mode: bool) -> Vec<u8> {
    let marker = if multi_mode {
        b"official-grpc-tun-multi|" as &[u8]
    } else {
        b"official-grpc-tun|"
    };
    let mut payload = Vec::with_capacity(256 * 1024 + 17);
    while payload.len() < 256 * 1024 + 17 {
        payload.extend_from_slice(marker);
        payload.extend(0_u8..=250);
    }
    payload.truncate(256 * 1024 + 17);
    payload
}

async fn spawn_grpc_vless_server(
    service_name: &str,
) -> (
    SocketAddr,
    BackgroundTask,
    Arc<Mutex<Vec<GrpcRequestContext>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Rust gRPC server");
    let address = listener.local_addr().expect("Rust gRPC server address");
    let config = GrpcServerConfig {
        service_name: service_name.into(),
        idle_timeout: Duration::from_secs(30),
        health_check_timeout: Duration::from_secs(5),
        initial_window_size: Some(1 << 20),
        ..Default::default()
    };
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let handler_contexts = contexts.clone();
    let handler: TunnelHandler = Arc::new(move |mut stream, context| {
        let contexts = handler_contexts.clone();
        Box::pin(async move {
            contexts.lock().unwrap().push(context);
            read_vless_request(&mut stream).await?;
            stream.write_all(&[0, 0]).await?;
            stream.flush().await?;
            echo_until_eof(&mut stream).await
        })
    });
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let config = config.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let _ = serve_connection(stream, peer, config, handler).await;
            });
        }
    });
    (address, BackgroundTask(task), contexts)
}

async fn read_vless_request<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 18];
    stream.read_exact(&mut fixed).await?;
    if fixed[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "official Xray sent a non-VLESS-v0 request",
        ));
    }
    let addon_len = fixed[17] as usize;
    let mut addon = vec![0; addon_len];
    stream.read_exact(&mut addon).await?;

    let mut command_and_port = [0_u8; 3];
    stream.read_exact(&mut command_and_port).await?;
    if command_and_port[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "official Xray VLESS request is not TCP",
        ));
    }
    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    match address_type[0] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
        }
        2 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut address = vec![0; usize::from(length[0])];
            stream.read_exact(&mut address).await?;
        }
        3 => {
            let mut address = [0_u8; 16];
            stream.read_exact(&mut address).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VLESS address type: {other}"),
            ));
        }
    }
    Ok(())
}

async fn echo_until_eof<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            stream.shutdown().await?;
            return Ok(());
        }
        stream.write_all(&buffer[..count]).await?;
        stream.flush().await?;
    }
}

async fn socks5_connect(port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected SOCKS5 auth reply: {method:?}"),
        ));
    }
    let target = b"example.com";
    let mut request = vec![5, 1, 0, 3, target.len() as u8];
    request.extend_from_slice(target);
    request.extend_from_slice(&443_u16.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed: {response:?}"),
        ));
    }
    match response[3] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut rest = vec![0; usize::from(length[0]) + 2];
            stream.read_exact(&mut rest).await?;
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 reply address type: {other}"),
            ));
        }
    }
    Ok(stream)
}

async fn spawn_udp_echo_server() -> (SocketAddr, BackgroundTask) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP echo server");
    let address = socket.local_addr().expect("UDP echo address");
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..length], peer).await.is_err() {
                break;
            }
        }
    });
    (address, BackgroundTask(task))
}

async fn socks5_connect_target(port: u16, target: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected SOCKS5 auth reply: {method:?}"),
        ));
    }
    let mut request = vec![5, 1, 0];
    match target.ip() {
        std::net::IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed: {response:?}"),
        ));
    }
    match response[3] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut rest = vec![0; usize::from(length[0]) + 2];
            stream.read_exact(&mut rest).await?;
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 reply address type: {other}"),
            ));
        }
    }
    Ok(stream)
}

async fn socks5_udp_associate(port: u16) -> io::Result<(TcpStream, UdpSocket, SocketAddr)> {
    let mut control = TcpStream::connect(("127.0.0.1", port)).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected SOCKS5 auth reply: {method:?}"),
        ));
    }
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut response = [0_u8; 4];
    control.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 UDP ASSOCIATE failed: {response:?}"),
        ));
    }
    let relay_ip = match response[3] {
        1 => {
            let mut address = [0_u8; 4];
            control.read_exact(&mut address).await?;
            let address = std::net::Ipv4Addr::from(address);
            std::net::IpAddr::V4(if address.is_unspecified() {
                std::net::Ipv4Addr::LOCALHOST
            } else {
                address
            })
        }
        4 => {
            let mut address = [0_u8; 16];
            control.read_exact(&mut address).await?;
            let address = std::net::Ipv6Addr::from(address);
            std::net::IpAddr::V6(if address.is_unspecified() {
                std::net::Ipv6Addr::LOCALHOST
            } else {
                address
            })
        }
        3 => {
            let mut length = [0_u8; 1];
            control.read_exact(&mut length).await?;
            let mut domain = vec![0_u8; usize::from(length[0])];
            control.read_exact(&mut domain).await?;
            let domain = std::str::from_utf8(&domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid relay domain"))?;
            tokio::net::lookup_host((domain, 0))
                .await?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "relay domain unresolved"))?
                .ip()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 relay address type: {other}"),
            ));
        }
    };
    let mut port_bytes = [0_u8; 2];
    control.read_exact(&mut port_bytes).await?;
    let relay = SocketAddr::new(relay_ip, u16::from_be_bytes(port_bytes));
    let bind = if relay.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    Ok((control, socket, relay))
}

fn socks5_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match target.ip() {
        std::net::IpAddr::V4(address) => {
            packet.push(1);
            packet.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            packet.push(4);
            packet.extend_from_slice(&address.octets());
        }
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn socks5_udp_payload(packet: &[u8]) -> io::Result<&[u8]> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP header",
        ));
    }
    let address_length = match packet[3] {
        1 => 4,
        4 => 16,
        3 => {
            let length = *packet.get(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SOCKS5 domain")
            })?;
            1 + usize::from(length)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 UDP address type: {other}"),
            ));
        }
    };
    let payload_offset = 4 + address_length + 2;
    packet
        .get(payload_offset..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SOCKS5 UDP packet"))
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_client_to_wuthercore_tonic_server_tun_and_tun_multi() {
    let binary = xray_binary();
    for case in INTEROP_CASES {
        let (server, _server_task, contexts) = spawn_grpc_vless_server(case.server_service).await;
        let socks_port = reserve_port().await;
        let config = format!(
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
      "network": "grpc",
      "security": "none",
      "grpcSettings": {{
        "authority": "authority.grpc.example",
        "serviceName": "{}",
        "multiMode": {},
        "idle_timeout": 30,
        "health_check_timeout": 5,
        "permit_without_stream": true,
        "initial_windows_size": 1048576,
        "user_agent": "wuthercore-xray-interop/1"
      }}
    }}
  }}]
}}"#,
            server.port(),
            case.client_service,
            case.multi_mode
        );
        let mut xray = spawn_xray(&binary, &format!("xray-client-{}", case.label), config);
        wait_for_listener(socks_port, &mut xray).await;

        let mut socks = timeout(TEST_TIMEOUT, socks5_connect(socks_port))
            .await
            .expect("SOCKS5 handshake timeout")
            .expect("SOCKS5 CONNECT through official Xray");
        let payload = interop_payload(case.multi_mode);
        socks
            .write_all(&payload)
            .await
            .expect("write SOCKS payload");
        socks.flush().await.expect("flush SOCKS payload");
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
            .await
            .expect("official Xray client echo timeout")
            .expect("read official Xray client echo");
        assert_eq!(echoed, payload, "case={}", case.label);
        let contexts = contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(
            contexts[0].authority.as_deref(),
            Some("authority.grpc.example")
        );
        assert_eq!(
            contexts[0].user_agent.as_deref(),
            Some("wuthercore-xray-interop/1")
        );
        let paths = core_grpc::grpc_method_paths(case.client_service);
        assert_eq!(
            contexts[0].method_path,
            if case.multi_mode {
                paths.tun_multi_path()
            } else {
                paths.tun_path()
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_client_to_registered_wuthercore_grpc_vless_inbound() {
    let binary = xray_binary();
    for multi_mode in [false, true] {
        let (echo, _echo_task) = spawn_echo_server().await;
        let (udp_echo, _udp_echo_task) = spawn_udp_echo_server().await;
        let grpc_port = reserve_port().await;
        let service = if multi_mode {
            "registered-inbound-multi"
        } else {
            "registered-inbound-tun"
        };
        let yaml = format!(
            r#"
version: 1
profile: server
name: grpc-inbound-interop
listen:
  panel: false
  grpc:
    - host: 127.0.0.1
      port: {grpc_port}
      protocol: vless
      users: [{XRAY_UUID}]
      grpcSettings:
        serviceName: {service}
        multiMode: {multi_mode}
        idle_timeout: 30
        health_check_timeout: 5
        permit_without_stream: true
        initial_windows_size: 1048576
        max_message_size: 8388608
        queue_capacity: 16
      handshakeTimeout: 10s
      maxMuxSessions: 128
      maxConnections: 256
      maxConcurrentStreams: 128
      maxHeaderListSize: 65536
route:
  preset: direct
"#
        );
        let plan =
            core_config::loader::load_from_str(&yaml).expect("compile registered gRPC inbound");
        let listener =
            GrpcListener::from_config(&plan.listen.grpc[0]).expect("build gRPC listener");
        let runtime = Arc::new(Runtime::build(plan).expect("build registered gRPC runtime"));
        let server_task = BackgroundTask(tokio::spawn(async move {
            run_grpc(listener, runtime)
                .await
                .expect("registered gRPC listener");
        }));
        sleep(Duration::from_millis(100)).await;

        let socks_port = reserve_port().await;
        let xray_config = format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {grpc_port},
        "users": [{{ "id": "{XRAY_UUID}", "encryption": "none" }}]
      }}]
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "none",
      "grpcSettings": {{
        "authority": "registered.grpc.example",
        "serviceName": "{service}",
        "multiMode": {multi_mode},
        "idle_timeout": 30,
        "health_check_timeout": 5,
        "permit_without_stream": true,
        "initial_windows_size": 1048576,
        "user_agent": "wuthercore-registered-inbound/1"
      }}
    }}
  }}]
}}"#
        );
        let mut xray = spawn_xray(
            &binary,
            if multi_mode {
                "registered-inbound-multi"
            } else {
                "registered-inbound-tun"
            },
            xray_config,
        );
        wait_for_listener(socks_port, &mut xray).await;

        let mut socks = timeout(TEST_TIMEOUT, socks5_connect_target(socks_port, echo))
            .await
            .expect("SOCKS5 target handshake timeout")
            .expect("official Xray connects to registered WutherCore gRPC inbound");
        let payload = interop_payload(multi_mode);
        socks.write_all(&payload).await.unwrap();
        socks.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
            .await
            .expect("registered gRPC inbound echo timeout")
            .expect("read registered gRPC inbound echo");
        assert_eq!(echoed, payload);
        socks.shutdown().await.unwrap();

        let (_udp_control, udp_socket, relay) =
            timeout(TEST_TIMEOUT, socks5_udp_associate(socks_port))
                .await
                .expect("SOCKS5 UDP ASSOCIATE timeout")
                .expect("official Xray opens UDP association");
        let udp_payload = if multi_mode {
            b"registered-inbound-udp-multi".as_slice()
        } else {
            b"registered-inbound-udp-tun".as_slice()
        };
        let packet = socks5_udp_packet(udp_echo, udp_payload);
        udp_socket.send_to(&packet, relay).await.unwrap();
        let mut response = [0_u8; 512];
        let (length, source) = timeout(TEST_TIMEOUT, udp_socket.recv_from(&mut response))
            .await
            .expect("registered gRPC inbound UDP echo timeout")
            .expect("receive SOCKS5 UDP response");
        assert_eq!(source, relay);
        assert_eq!(
            socks5_udp_payload(&response[..length]).unwrap(),
            udp_payload
        );
        drop(server_task);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_and_wuthercore_interoperate_over_registered_grpc_tls() {
    init_test_tracing();
    let binary = xray_binary();
    let certificate = TestCertificate::generate("grpc.example");

    for multi_mode in [false, true] {
        let mode = if multi_mode { "multi" } else { "tun" };

        // Official Xray client -> registered WutherCore TLS gRPC server.
        {
            let (echo, _echo_task) = spawn_echo_server().await;
            let grpc_port = reserve_port().await;
            let service = format!("registered-tls-inbound-{mode}");
            let yaml = format!(
                r#"
version: 1
profile: server
name: grpc-tls-inbound-interop
listen:
  panel: false
  grpc:
    - host: 127.0.0.1
      port: {grpc_port}
      protocol: vless
      users: [{XRAY_UUID}]
      security: tls
      tlsSettings:
        serverName: grpc.example
        alpn: [h2]
        certificates:
          - certificateFile: '{}'
            keyFile: '{}'
            usage: encipherment
      grpcSettings:
        serviceName: {service}
        multiMode: {multi_mode}
      handshakeTimeout: 10s
      maxMuxSessions: 128
      maxConnections: 256
      maxConcurrentStreams: 128
      maxHeaderListSize: 65536
route:
  preset: direct
"#,
                certificate.certificate_yaml(),
                certificate.key_yaml(),
            );
            let plan = core_config::loader::load_from_str(&yaml)
                .expect("compile registered TLS gRPC inbound");
            let listener =
                GrpcListener::from_config(&plan.listen.grpc[0]).expect("build TLS gRPC listener");
            let runtime =
                Arc::new(Runtime::build(plan).expect("build registered TLS gRPC runtime"));
            let server_task = BackgroundTask(tokio::spawn(async move {
                run_grpc(listener, runtime)
                    .await
                    .expect("registered TLS gRPC listener");
            }));
            sleep(Duration::from_millis(100)).await;

            let socks_port = reserve_port().await;
            let certificate_path = certificate.certificate_json();
            let xray_config = format!(
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
        "port": {grpc_port},
        "users": [{{ "id": "{XRAY_UUID}", "encryption": "none" }}]
      }}]
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "tls",
      "tlsSettings": {{
        "serverName": "grpc.example",
        "alpn": ["h2"],
        "disableSystemRoot": true,
        "certificates": [{{
          "certificateFile": {certificate_path},
          "usage": "verify"
        }}]
      }},
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}]
}}"#
            );
            let mut xray = spawn_xray(
                &binary,
                &format!("registered-tls-inbound-{mode}"),
                xray_config,
            );
            wait_for_listener(socks_port, &mut xray).await;
            let mut socks = timeout(TEST_TIMEOUT, socks5_connect_target(socks_port, echo))
                .await
                .expect("TLS gRPC SOCKS handshake timeout")
                .expect("official Xray reaches WutherCore TLS gRPC inbound");
            let payload = format!("official-xray-to-wuther-grpc-tls-{mode}").into_bytes();
            socks.write_all(&payload).await.unwrap();
            socks.flush().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
                .await
                .expect("TLS gRPC inbound echo timeout")
                .expect("read TLS gRPC inbound echo");
            assert_eq!(echoed, payload);
            drop(xray);
            drop(server_task);
        }

        // Registered WutherCore client -> official Xray TLS gRPC server.
        {
            let (echo, _echo_task) = spawn_echo_server().await;
            let xray_port = reserve_port().await;
            let service = format!("registered-tls-outbound-{mode}");
            let certificate_path = certificate.certificate_json();
            let key_path = certificate.key_json();
            let config = format!(
                r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{XRAY_UUID}" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "tls",
      "tlsSettings": {{
        "serverName": "grpc.example",
        "alpn": ["h2"],
        "certificates": [{{
          "certificateFile": {certificate_path},
          "keyFile": {key_path},
          "usage": "encipherment"
        }}]
      }},
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{
      "finalRules": [
        {{
          "action": "allow",
          "network": "tcp",
          "port": {},
          "ip": ["127.0.0.1/32"]
        }},
        {{ "action": "block" }}
      ]
    }}
  }}]
}}"#,
                echo.port()
            );
            let mut xray = spawn_xray(&binary, &format!("registered-tls-outbound-{mode}"), config);
            wait_for_listener(xray_port, &mut xray).await;

            let mut node = ParsedNode::new(
                format!("registered-tls-outbound-{mode}"),
                NodeProtocol::Vless,
                "127.0.0.1",
                xray_port,
            );
            node.uuid = Some(XRAY_UUID.into());
            node.transport = "grpc".into();
            node.tls = true;
            node.sni = Some("grpc.example".into());
            node.params.insert("serviceName".into(), service);
            node.params
                .insert("multiMode".into(), multi_mode.to_string());
            node.tls_settings = Some(XhttpDownloadTlsSettings {
                certificates: vec![XhttpDownloadTlsCertificate {
                    certificate: Some(
                        certificate
                            .certificate_pem
                            .lines()
                            .map(str::to_owned)
                            .collect(),
                    ),
                    usage: Some(XhttpTlsCertificateUsage::Verify),
                    ..XhttpDownloadTlsCertificate::default()
                }],
                server_name: Some("grpc.example".into()),
                alpn: Some(vec!["h2".into()]),
                ..XhttpDownloadTlsSettings::default()
            });
            let outbound = build_outbound(&node).expect("compile registered TLS gRPC outbound");
            let mut stream = timeout(
                TEST_TIMEOUT,
                outbound.dial_tcp(DialContext::tcp(echo.ip().to_string(), echo.port())),
            )
            .await
            .expect("registered TLS gRPC outbound dial timeout")
            .expect("WutherCore reaches official Xray TLS gRPC server");
            let payload = format!("wuther-to-official-xray-grpc-tls-{mode}").into_bytes();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
                .await
                .expect("TLS gRPC outbound echo timeout")
                .expect("read TLS gRPC outbound echo");
            assert_eq!(echoed, payload);
            stream.shutdown().await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_and_wuthercore_interoperate_over_grpc_reality() {
    init_test_tracing();
    let binary = xray_binary();
    let private_key = [0x42_u8; 32];
    let encoded_private = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private_key);
    let public_key =
        core_reality::x25519_public_key(&private_key).expect("derive REALITY public key");
    let encoded_public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);

    for multi_mode in [false, true] {
        let mode = if multi_mode { "multi" } else { "tun" };

        // Official Xray client -> registered WutherCore REALITY gRPC server.
        {
            let (camouflage, _camouflage_task) = spawn_reality_camouflage_target().await;
            let (echo, _echo_task) = spawn_echo_server().await;
            let grpc_port = reserve_port().await;
            let service = format!("registered-reality-inbound-{mode}");
            let yaml = format!(
                r#"
version: 1
profile: server
name: grpc-reality-inbound-interop
listen:
  panel: false
  grpc:
    - host: 127.0.0.1
      port: {grpc_port}
      protocol: vless
      users: [{XRAY_UUID}]
      security: reality
      realitySettings:
        target: {camouflage}
        serverNames: [{REALITY_SERVER_NAME}]
        privateKey: {encoded_private}
        shortIds: [{REALITY_SHORT_ID}]
      grpcSettings:
        serviceName: {service}
        multiMode: {multi_mode}
      handshakeTimeout: 10s
      maxMuxSessions: 128
      maxConnections: 256
      maxConcurrentStreams: 128
      maxHeaderListSize: 65536
route:
  preset: direct
"#
            );
            let plan = core_config::loader::load_from_str(&yaml)
                .expect("compile registered REALITY gRPC inbound");
            let listener = GrpcListener::from_config(&plan.listen.grpc[0])
                .expect("build REALITY gRPC listener");
            let runtime =
                Arc::new(Runtime::build(plan).expect("build registered REALITY gRPC runtime"));
            let server_task = BackgroundTask(tokio::spawn(async move {
                run_grpc(listener, runtime)
                    .await
                    .expect("registered REALITY gRPC listener");
            }));
            sleep(Duration::from_millis(100)).await;

            let socks_port = reserve_port().await;
            let xray_config = format!(
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
        "port": {grpc_port},
        "users": [{{ "id": "{XRAY_UUID}", "encryption": "none" }}]
      }}]
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "reality",
      "realitySettings": {{
        "serverName": "{REALITY_SERVER_NAME}",
        "fingerprint": "chrome",
        "password": "{encoded_public}",
        "shortId": "{REALITY_SHORT_ID}",
        "spiderX": "/"
      }},
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}]
}}"#
            );
            let mut xray = spawn_xray(
                &binary,
                &format!("registered-reality-inbound-{mode}"),
                xray_config,
            );
            wait_for_listener(socks_port, &mut xray).await;
            let mut socks = timeout(TEST_TIMEOUT, socks5_connect_target(socks_port, echo))
                .await
                .expect("REALITY gRPC SOCKS handshake timeout")
                .expect("official Xray reaches WutherCore REALITY gRPC inbound");
            let payload = format!("official-xray-to-wuther-grpc-reality-{mode}").into_bytes();
            socks.write_all(&payload).await.unwrap();
            socks.flush().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
                .await
                .expect("REALITY gRPC inbound echo timeout")
                .expect("read REALITY gRPC inbound echo");
            assert_eq!(echoed, payload);
            drop(xray);
            drop(server_task);
        }

        // Registered WutherCore client -> official Xray REALITY gRPC server.
        {
            let (camouflage, _camouflage_task) = spawn_reality_camouflage_target().await;
            let (echo, _echo_task) = spawn_echo_server().await;
            let xray_port = reserve_port().await;
            let service = format!("registered-reality-outbound-{mode}");
            let config = format!(
                r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{XRAY_UUID}" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "reality",
      "realitySettings": {{
        "target": "{camouflage}",
        "serverNames": ["{REALITY_SERVER_NAME}"],
        "privateKey": "{encoded_private}",
        "shortIds": ["{REALITY_SHORT_ID}"]
      }},
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{
      "finalRules": [
        {{
          "action": "allow",
          "network": "tcp",
          "port": {},
          "ip": ["127.0.0.1/32"]
        }},
        {{ "action": "block" }}
      ]
    }}
  }}]
}}"#,
                echo.port()
            );
            let mut xray = spawn_xray(
                &binary,
                &format!("registered-reality-outbound-{mode}"),
                config,
            );
            wait_for_listener(xray_port, &mut xray).await;

            let uri = format!(
                "vless://{XRAY_UUID}@127.0.0.1:{xray_port}?security=reality&sni={REALITY_SERVER_NAME}&fp=chrome&pbk={encoded_public}&sid={REALITY_SHORT_ID}&spx=%2F&type=grpc"
            );
            let mut node = parse_uri(&uri).expect("parse REALITY gRPC VLESS URI");
            node.name = format!("registered-reality-outbound-{mode}");
            node.params.insert("serviceName".into(), service);
            node.params
                .insert("multiMode".into(), multi_mode.to_string());
            let outbound = build_outbound(&node).expect("compile registered REALITY gRPC outbound");
            let mut stream = timeout(
                TEST_TIMEOUT,
                outbound.dial_tcp(DialContext::tcp(echo.ip().to_string(), echo.port())),
            )
            .await
            .expect("registered REALITY gRPC outbound dial timeout")
            .expect("WutherCore reaches official Xray REALITY gRPC server");
            let payload = format!("wuther-to-official-xray-grpc-reality-{mode}").into_bytes();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
                .await
                .expect("REALITY gRPC outbound echo timeout")
                .expect("read REALITY gRPC outbound echo");
            assert_eq!(echoed, payload);
            stream.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn registered_vless_vmess_and_trojan_clients_use_real_grpc_carrier() {
    let binary = xray_binary();
    for (protocol, settings, variant, vmess_security) in [
        (
            NodeProtocol::Vless,
            format!(r#"{{"clients":[{{"id":"{XRAY_UUID}"}}],"decryption":"none"}}"#),
            "default",
            None,
        ),
        (
            NodeProtocol::Vmess,
            format!(r#"{{"clients":[{{"id":"{XRAY_UUID}","alterId":0}}]}}"#),
            "aes",
            Some("aes-128-gcm"),
        ),
        (
            NodeProtocol::Vmess,
            format!(r#"{{"clients":[{{"id":"{XRAY_UUID}","alterId":0}}]}}"#),
            "chacha",
            Some("chacha20-poly1305"),
        ),
        (
            NodeProtocol::Trojan,
            r#"{"clients":[{"password":"grpc-secret"}]}"#.to_owned(),
            "default",
            None,
        ),
    ] {
        for multi_mode in [false, true] {
            let (echo, _echo_task) = spawn_echo_server().await;
            let echo_port = echo.port();
            let xray_port = reserve_port().await;
            let service = format!(
                "registered-{}-{variant}-{}",
                protocol.as_str(),
                if multi_mode { "multi" } else { "tun" }
            );
            let config = format!(
                r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "{}",
    "settings": {settings},
    "streamSettings": {{
      "network": "grpc",
      "security": "none",
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{
      "finalRules": [
        {{
          "action": "allow",
          "network": "tcp",
          "port": {echo_port},
          "ip": ["127.0.0.1/32"]
        }},
        {{ "action": "block" }}
      ]
    }}
  }}]
}}"#,
                protocol.as_str()
            );
            let label = format!(
                "registered-{}-{variant}-{}",
                protocol.as_str(),
                if multi_mode { "multi" } else { "tun" }
            );
            let mut xray = spawn_xray(&binary, &label, config);
            wait_for_listener(xray_port, &mut xray).await;

            let mut node = ParsedNode::new(&label, protocol.clone(), "127.0.0.1", xray_port);
            node.transport = "grpc".into();
            node.tls = false;
            node.params.insert("serviceName".into(), service);
            node.params
                .insert("multiMode".into(), multi_mode.to_string());
            match protocol {
                NodeProtocol::Vless | NodeProtocol::Vmess => {
                    node.uuid = Some(XRAY_UUID.into());
                    if let Some(security) = vmess_security {
                        node.params.insert("security".into(), security.into());
                    }
                }
                NodeProtocol::Trojan => {
                    node.password = Some("grpc-secret".into());
                    node.params.insert("security".into(), "none".into());
                }
                _ => unreachable!(),
            }
            let outbound = build_outbound(&node).expect("compile registered gRPC outbound");
            assert_eq!(
                outbound.protocol(),
                protocol.as_str(),
                "registered gRPC node became a stub"
            );
            let mut stream = timeout(
                TEST_TIMEOUT,
                outbound.dial_tcp(DialContext::tcp(echo.ip().to_string(), echo.port())),
            )
            .await
            .expect("registered gRPC outbound dial timeout")
            .expect("registered protocol dials through gRPC");
            let payload = interop_payload(multi_mode);
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
                .await
                .expect("registered gRPC outbound echo timeout")
                .expect("registered gRPC outbound read");
            assert_eq!(echoed, payload, "protocol={}", protocol.as_str());
            stream.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn registered_vless_client_sends_udp_datagrams_over_real_grpc_carrier() {
    let binary = xray_binary();
    for multi_mode in [false, true] {
        let (echo, _echo_task) = spawn_udp_echo_server().await;
        let xray_port = reserve_port().await;
        let service = if multi_mode {
            "registered-vless-udp-multi"
        } else {
            "registered-vless-udp-tun"
        };
        let config = format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{XRAY_UUID}" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "grpc",
      "security": "none",
      "grpcSettings": {{
        "serviceName": "{service}",
        "multiMode": {multi_mode}
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "settings": {{
      "finalRules": [
        {{
          "action": "allow",
          "network": "udp",
          "port": {},
          "ip": ["127.0.0.1/32"]
        }},
        {{ "action": "block" }}
      ]
    }}
  }}]
}}"#,
            echo.port()
        );
        let mut xray = spawn_xray(
            &binary,
            if multi_mode {
                "registered-vless-udp-multi"
            } else {
                "registered-vless-udp-tun"
            },
            config,
        );
        wait_for_listener(xray_port, &mut xray).await;

        let mut node = ParsedNode::new(
            if multi_mode {
                "registered-vless-udp-multi"
            } else {
                "registered-vless-udp-tun"
            },
            NodeProtocol::Vless,
            "127.0.0.1",
            xray_port,
        );
        node.uuid = Some(XRAY_UUID.into());
        node.transport = "grpc".into();
        node.tls = false;
        node.params.insert("serviceName".into(), service.into());
        node.params
            .insert("multiMode".into(), multi_mode.to_string());
        let outbound = build_outbound(&node).expect("compile registered gRPC UDP outbound");
        assert!(outbound.capabilities().udp);
        let udp = timeout(
            TEST_TIMEOUT,
            outbound.dial_udp(DialContext::udp(echo.ip().to_string(), echo.port())),
        )
        .await
        .expect("registered VLESS UDP dial timeout")
        .expect("registered VLESS opens UDP over gRPC");
        let payload = if multi_mode {
            b"vless-udp-over-grpc-tun-multi".as_slice()
        } else {
            b"vless-udp-over-grpc-tun".as_slice()
        };
        assert_eq!(
            udp.send_to(payload, &echo.ip().to_string(), echo.port())
                .await
                .unwrap(),
            payload.len()
        );
        let mut response = [0_u8; 128];
        let received = timeout(TEST_TIMEOUT, udp.recv_from(&mut response))
            .await
            .expect("registered VLESS UDP echo timeout")
            .expect("receive VLESS UDP response");
        assert_eq!(&response[..received], payload);
        udp.close().await.unwrap();
    }
}
