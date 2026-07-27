//! XHTTP 与固定 Xray-core 版本的双向互操作测试。
//!
//! 这组测试需要外部官方 Xray 二进制，因此默认忽略。运行方式：
//!
//! ```text
//! XRAY_BIN=/path/to/xray cargo test -p tests-e2e --test e2e_xhttp_xray -- --ignored
//! ```

use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_inbound::xhttp::{XhttpServer, XhttpVersion};
use core_outbound::proto::xhttp::{
    Config, XhttpClient,
    config::{DownloadSettings, DownloadTransportSettings},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const XRAY_UUID: &str = "11111111-1111-1111-1111-111111111111";
const XRAY_PINNED_VERSION: &str = "26.7.11";
const XRAY_PINNED_COMMIT: &str = "50231ea";

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

/// 只观察独立 downloadSettings 入口，随后把原始 TCP 字节转发到同一个
/// 官方 Xray XHTTP 入站。外层 upload endpoint 从不经过这里。
struct ObservedTcpForwarder {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl ObservedTcpForwarder {
    async fn spawn(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observed downloadSettings forwarder");
        let address = listener.local_addr().expect("download forwarder address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_by_task = accepted.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut download_side, _)) = listener.accept().await {
                accepted_by_task.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    let Ok(mut xray_side) = TcpStream::connect(target).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut download_side, &mut xray_side).await;
                });
            }
        });
        Self {
            address,
            accepted,
            task,
        }
    }

    fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }

    async fn wait_for_connection(&self, mode: &str) {
        timeout(TEST_TIMEOUT, async {
            while self.accepted_connections() == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "mode={mode}: download GET silently used the outer endpoint instead of the \
                 configured independent downloadSettings port"
            )
        });
    }
}

impl Drop for ObservedTcpForwarder {
    fn drop(&mut self) {
        self.task.abort();
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
        "XRAY_BIN must be pinned to Xray {XRAY_PINNED_VERSION} ({XRAY_PINNED_COMMIT}); got: {version}"
    );
}

fn temp_config(name: &str, body: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "wuthercore-xhttp-{name}-{}-{nonce}.json",
        std::process::id()
    ));
    fs::write(&path, body).expect("write Xray interoperability config");
    path
}

fn spawn_xray(binary: &Path, name: &str, config: String) -> XrayProcess {
    let config = temp_config(name, &config);
    let child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdin(Stdio::null())
        // These tests are explicitly diagnostic interop tests. Preserve the
        // pinned implementation's output so a protocol mismatch is
        // actionable instead of surfacing as an opaque timeout.
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
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Xray listener readiness timeout");
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let address = listener.local_addr().expect("echo address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    address
}

async fn spawn_finite_echo(expected: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind finite echo listener");
    let address = listener.local_addr().expect("finite echo address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept finite echo stream");
        let mut received = vec![0; expected.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("finite echo reads complete payload");
        assert_eq!(received, expected, "finite echo received corrupted payload");
        stream
            .write_all(&received)
            .await
            .expect("finite echo writes complete payload");
        stream.flush().await.expect("flush finite echo payload");
        stream.shutdown().await.expect("close finite echo response");
    });
    (address, task)
}

fn xhttp_config(mode: &str) -> Config {
    Config {
        path: "/official-interop?source=wuthercore".into(),
        mode: mode.into(),
        x_padding_bytes: "100-100".into(),
        sc_min_posts_interval_ms: "1".into(),
        ..Default::default()
    }
}

fn xhttp_config_with_independent_download(mode: &str, download_port: u16) -> Config {
    let mut download_xhttp = xhttp_config(mode);
    download_xhttp.sc_max_each_post_bytes = "1024-1024".into();
    download_xhttp.sc_stream_up_server_secs = "1-1".into();

    let mut config = xhttp_config(mode);
    config.sc_max_each_post_bytes = "1024-1024".into();
    config.sc_stream_up_server_secs = "1-1".into();
    config.download_settings = Some(Box::new(DownloadSettings {
        address: "127.0.0.1".into(),
        port: Some(download_port),
        method: "xhttp".into(),
        transport: Some(DownloadTransportSettings {
            kind: "xhttp".into(),
            xhttp: Some(Box::new(download_xhttp)),
            ..Default::default()
        }),
        security: "none".into(),
        ..Default::default()
    }));
    config
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_client_to_official_xray_server_all_h1_modes() {
    let binary = xray_binary();
    for mode in ["stream-one", "stream-up", "packet-up"] {
        eprintln!("interop: WutherCore client -> Xray server, mode={mode}");
        let echo = spawn_echo().await;
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
      "network": "xhttp",
      "security": "none",
      "xhttpSettings": {{
        "path": "/official-interop?source=wuthercore",
        "mode": "{mode}",
        "xPaddingBytes": "100-100",
        "scMinPostsIntervalMs": "1"
      }}
    }}
  }}],
  "outbounds": [{{ "protocol": "freedom" }}]
}}"#,
            echo.port()
        );
        let mut xray = spawn_xray(&binary, &format!("client-{mode}"), config);
        wait_for_listener(xray_port, &mut xray).await;

        let mut client = XhttpClient::new(xhttp_config(mode), "127.0.0.1", xray_port);
        client.tls = false;
        let mut stream = timeout(TEST_TIMEOUT, client.dial(false))
            .await
            .expect("XHTTP dial timeout")
            .expect("WutherCore client dials official Xray");
        let payload = format!("wuthercore-client-{mode}").into_bytes();
        stream
            .write_all(&payload)
            .await
            .expect("write XHTTP payload");
        stream.flush().await.expect("flush XHTTP payload");
        let mut echoed = vec![0; payload.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut echoed))
            .await
            .expect("XHTTP echo timeout")
            .expect("read echoed payload");
        assert_eq!(echoed, payload, "mode={mode}");
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn wuthercore_download_settings_uses_observed_independent_h1_endpoint() {
    let binary = xray_binary();
    for mode in ["stream-up", "packet-up"] {
        eprintln!("interop: WutherCore independent downloadSettings -> Xray server, mode={mode}");
        let marker = format!("independent-download-{mode}|").into_bytes();
        let mut payload = Vec::with_capacity(32 * 1024);
        while payload.len() < 32 * 1024 {
            payload.extend_from_slice(&marker);
            payload.extend(0_u8..=250);
        }
        payload.truncate(32 * 1024);
        let (echo, echo_task) = spawn_finite_echo(payload.clone()).await;
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
      "network": "xhttp",
      "security": "none",
      "xhttpSettings": {{
        "path": "/official-interop?source=wuthercore",
        "mode": "{mode}",
        "xPaddingBytes": "100-100",
        "scMaxEachPostBytes": "1024-1024",
        "scMinPostsIntervalMs": "1",
        "scStreamUpServerSecs": "1-1"
      }}
    }}
  }}],
  "outbounds": [{{ "protocol": "freedom" }}]
}}"#,
            echo.port()
        );
        let mut xray = spawn_xray(
            &binary,
            &format!("client-independent-download-{mode}"),
            config,
        );
        wait_for_listener(xray_port, &mut xray).await;

        let download_forwarder =
            ObservedTcpForwarder::spawn(SocketAddr::from(([127, 0, 0, 1], xray_port))).await;
        let mut client = XhttpClient::new(
            xhttp_config_with_independent_download(mode, download_forwarder.address.port()),
            "127.0.0.1",
            xray_port,
        );
        client.tls = false;
        let stream = timeout(TEST_TIMEOUT, client.dial(false))
            .await
            .expect("XHTTP independent downloadSettings dial timeout")
            .expect("WutherCore client dials official Xray");
        download_forwarder.wait_for_connection(mode).await;

        let upload_payload = payload.clone();
        let echoed = timeout(TEST_TIMEOUT, async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let upload = async move {
                writer.write_all(&upload_payload).await?;
                writer.flush().await?;
                writer.shutdown().await
            };
            let download = async move {
                let mut echoed = Vec::new();
                reader.read_to_end(&mut echoed).await?;
                Ok::<_, std::io::Error>(echoed)
            };
            let (_, echoed) = tokio::try_join!(upload, download)?;
            Ok::<_, std::io::Error>(echoed)
        })
        .await
        .expect("independent downloadSettings echo/EOF timeout")
        .expect("independent downloadSettings transfer");
        assert_eq!(
            echoed, payload,
            "mode={mode}: echo must be complete before a clean download EOF"
        );
        timeout(TEST_TIMEOUT, echo_task)
            .await
            .expect("finite echo task timeout")
            .expect("join finite echo task");
        assert!(
            download_forwarder.accepted_connections() >= 1,
            "mode={mode}: no connection reached the observed downloadSettings endpoint"
        );
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_client_to_wuthercore_server_all_h1_modes() {
    let binary = xray_binary();
    for mode in ["stream-one", "stream-up", "packet-up"] {
        eprintln!("interop: Xray client -> WutherCore server, mode={mode}");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WutherCore XHTTP server");
        let server_address = listener.local_addr().expect("XHTTP server address");
        let (server, mut accepted) =
            XhttpServer::new(xhttp_config(mode), Some(16)).expect("construct XHTTP server");
        let shutdown = CancellationToken::new();
        let server_task = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_listener(listener, shutdown).await })
        };
        let expected_payload = format!("official-xray-client-{mode}").into_bytes();
        let logical_expected = expected_payload.clone();
        let logical_task = tokio::spawn(async move {
            let mut accepted = timeout(TEST_TIMEOUT, accepted.accept())
                .await
                .expect("logical XHTTP accept timeout")
                .expect("logical XHTTP stream");
            assert_eq!(accepted.mode, mode);
            assert_eq!(accepted.version, XhttpVersion::Http1);
            read_vless_request(&mut accepted.stream).await;
            accepted
                .stream
                .write_all(&[0, 0])
                .await
                .expect("write VLESS response");
            accepted.stream.flush().await.expect("flush VLESS response");
            let mut received = vec![0; logical_expected.len()];
            timeout(TEST_TIMEOUT, accepted.stream.read_exact(&mut received))
                .await
                .expect("VLESS application payload timeout")
                .expect("read VLESS application payload");
            assert_eq!(received, logical_expected);
            accepted
                .stream
                .write_all(&received)
                .await
                .expect("echo VLESS application data");
            accepted
                .stream
                .flush()
                .await
                .expect("flush VLESS application data");
        });

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
      "network": "xhttp",
      "security": "none",
      "xhttpSettings": {{
        "path": "/official-interop?source=wuthercore",
        "mode": "{mode}",
        "xPaddingBytes": "100-100",
        "scMinPostsIntervalMs": "1"
      }}
    }}
  }}]
}}"#,
            server_address.port()
        );
        let mut xray = spawn_xray(&binary, &format!("server-{mode}"), config);
        wait_for_listener(socks_port, &mut xray).await;

        let mut socks = TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .expect("connect Xray SOCKS inbound");
        socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
        let mut greeting = [0; 2];
        socks
            .read_exact(&mut greeting)
            .await
            .expect("SOCKS greeting response");
        assert_eq!(greeting, [5, 0]);
        socks
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .expect("SOCKS CONNECT");
        read_socks_reply(&mut socks).await;

        socks
            .write_all(&expected_payload)
            .await
            .expect("SOCKS payload");
        socks.flush().await.expect("flush SOCKS payload");
        let mut echoed = vec![0; expected_payload.len()];
        timeout(TEST_TIMEOUT, socks.read_exact(&mut echoed))
            .await
            .expect("SOCKS echo timeout")
            .expect("SOCKS echoed payload");
        assert_eq!(echoed, expected_payload, "mode={mode}");

        drop(socks);
        timeout(TEST_TIMEOUT, logical_task)
            .await
            .expect("logical task timeout")
            .expect("join logical task");
        shutdown.cancel();
        server.close();
        timeout(TEST_TIMEOUT, server_task)
            .await
            .expect("XHTTP server shutdown timeout")
            .expect("join XHTTP server")
            .expect("serve XHTTP");
    }
}

#[tokio::test]
#[ignore = "requires XRAY_BIN pointing to the pinned official Xray binary"]
async fn official_xray_streaming_client_close_is_clean_logical_eof() {
    let binary = xray_binary();
    for mode in ["stream-one", "stream-up"] {
        eprintln!("interop: Xray streaming close -> WutherCore clean EOF, mode={mode}");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WutherCore XHTTP server");
        let server_address = listener.local_addr().expect("XHTTP server address");
        let (server, mut accepted) =
            XhttpServer::new(xhttp_config(mode), Some(16)).expect("construct XHTTP server");
        let shutdown = CancellationToken::new();
        let server_task = {
            let server = server.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.serve_listener(listener, shutdown).await })
        };
        let payload = format!("official-xray-clean-eof-{mode}").into_bytes();
        let expected_len = payload.len() as u64;
        let logical_task = tokio::spawn(async move {
            let mut accepted = timeout(TEST_TIMEOUT, accepted.accept())
                .await
                .expect("logical XHTTP accept timeout")
                .expect("logical XHTTP stream");
            assert_eq!(accepted.mode, mode);
            assert_eq!(accepted.version, XhttpVersion::Http1);
            read_vless_request(&mut accepted.stream).await;
            accepted
                .stream
                .write_all(&[0, 0])
                .await
                .expect("write VLESS response");
            accepted.stream.flush().await.expect("flush VLESS response");

            let copied = timeout(
                TEST_TIMEOUT,
                tokio::io::copy(&mut accepted.stream, &mut tokio::io::sink()),
            )
            .await
            .expect("logical copy did not observe client close")
            .expect("Xray streaming close must be a clean logical EOF");
            assert_eq!(copied, expected_len);
        });

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
      "network": "xhttp",
      "security": "none",
      "xhttpSettings": {{
        "path": "/official-interop?source=wuthercore",
        "mode": "{mode}",
        "xPaddingBytes": "100-100",
        "scMinPostsIntervalMs": "1"
      }}
    }}
  }}]
}}"#,
            server_address.port()
        );
        let mut xray = spawn_xray(&binary, &format!("clean-eof-{mode}"), config);
        wait_for_listener(socks_port, &mut xray).await;

        let mut socks = TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .expect("connect Xray SOCKS inbound");
        socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
        let mut greeting = [0; 2];
        socks
            .read_exact(&mut greeting)
            .await
            .expect("SOCKS greeting response");
        assert_eq!(greeting, [5, 0]);
        socks
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .expect("SOCKS CONNECT");
        read_socks_reply(&mut socks).await;
        socks.write_all(&payload).await.expect("SOCKS payload");
        socks.flush().await.expect("flush SOCKS payload");
        socks.shutdown().await.expect("close SOCKS upload");
        drop(socks);

        // The logical copy must finish before server cancellation. This proves
        // the client-side close itself supplies EOF rather than server.close()
        // masking a stuck or failed request-body pump.
        timeout(TEST_TIMEOUT, logical_task)
            .await
            .expect("logical EOF task timeout")
            .expect("join logical EOF task");
        shutdown.cancel();
        server.close();
        timeout(TEST_TIMEOUT, server_task)
            .await
            .expect("XHTTP server shutdown timeout")
            .expect("join XHTTP server")
            .expect("serve XHTTP");
    }
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

async fn read_socks_reply(stream: &mut TcpStream) {
    let mut head = [0_u8; 4];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut head))
        .await
        .expect("SOCKS CONNECT timeout")
        .expect("SOCKS CONNECT response");
    assert_eq!(head[0], 5);
    assert_eq!(head[1], 0, "SOCKS CONNECT failed with code {}", head[1]);
    let address_length = match head[3] {
        1 => 4,
        3 => stream.read_u8().await.expect("SOCKS domain length") as usize,
        4 => 16,
        atyp => panic!("unexpected SOCKS address type {atyp}"),
    };
    let mut tail = vec![0; address_length + 2];
    stream
        .read_exact(&mut tail)
        .await
        .expect("SOCKS bound address");
}
