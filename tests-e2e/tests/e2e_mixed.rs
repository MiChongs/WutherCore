//! 端到端：跑 Mixed 入站 + DIRECT 出口，验证 HTTP CONNECT 与 SOCKS5 都能贯通。

use std::{sync::Arc, time::Duration};

use core_inbound::{MixedListener, run_mixed};
use core_runtime::Runtime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const CONFIG: &str = r#"
version: 1
profile: desktop
name: "e2e"
listen:
  local: 0
  panel: false
route:
  preset: direct
"#;

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr.port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_through_mixed() {
    let echo_port = spawn_echo().await;

    // 监听 0 端口由 OS 选择，但本测试需要稳定端口；改为绑定后取地址。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mixed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let yaml = CONFIG.replace("local: 0", &format!("local: {mixed_port}"));
    let plan = core_config::loader::load_from_str(&yaml).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let listener = MixedListener {
        listen: format!("127.0.0.1:{mixed_port}").parse().unwrap(),
        auth: None,
    };
    tokio::spawn(run_mixed(listener, runtime.clone()));

    // 等监听就绪
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 客户端：HTTP CONNECT
    let mut s = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let target = format!("127.0.0.1:{echo_port}");
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).await.unwrap();
    let resp = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("200"), "expected 200, got: {resp:?}");

    // tunnel 已建立，echo 验证
    s.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    s.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");

    let snapshot = runtime.connections.manager_snapshot();
    let conn = snapshot
        .connections
        .iter()
        .find(|c| c.metadata.destination_port == echo_port.to_string())
        .expect("active mixed connection should be tracked with real metadata");
    assert_eq!(conn.metadata.network, "tcp");
    assert_eq!(conn.metadata.kind, "HTTP");
    assert_eq!(conn.metadata.source_ip, "127.0.0.1");
    assert_eq!(conn.metadata.destination_ip, "127.0.0.1");
    assert_eq!(conn.metadata.destination_port, echo_port.to_string());
    assert_eq!(conn.metadata.inbound_ip, "127.0.0.1");
    assert_eq!(conn.metadata.inbound_port, mixed_port.to_string());
    assert_eq!(conn.metadata.inbound_name, "http-connect");
    assert_eq!(conn.metadata.host, "127.0.0.1");
    assert_eq!(
        conn.metadata.remote_destination,
        format!("127.0.0.1:{echo_port}")
    );
    assert_eq!(conn.chains.as_slice(), ["DIRECT"]);
    assert!(conn.provider_chains.is_empty());
    assert_eq!(conn.rule, "MATCH");
    assert_eq!(conn.rule_payload, "preset:direct any");
    assert!(conn.upload >= 5);
    assert!(conn.download >= 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_connect_through_mixed() {
    let echo_port = spawn_echo().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mixed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let yaml = CONFIG.replace("local: 0", &format!("local: {mixed_port}"));
    let plan = core_config::loader::load_from_str(&yaml).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let listener = MixedListener {
        listen: format!("127.0.0.1:{mixed_port}").parse().unwrap(),
        auth: None,
    };
    tokio::spawn(run_mixed(listener, runtime));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut s = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    // greeting: VER NMETHODS METHODS(NO_AUTH)
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);
    // CONNECT 127.0.0.1:echo_port (IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo_port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "socks5 reply should be 0x00");
    // 跳过 BND.ADDR (IPv4) + BND.PORT
    let mut rest = [0u8; 6];
    s.read_exact(&mut rest).await.unwrap();

    s.write_all(b"abcd").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"abcd");
}
