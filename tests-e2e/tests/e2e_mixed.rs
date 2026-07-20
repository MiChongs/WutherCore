//! 端到端：跑 Mixed 入站 + DIRECT 出口，验证 HTTP CONNECT 与 SOCKS5 都能贯通。

use std::{sync::Arc, time::Duration};

use core_inbound::{MixedListener, run_mixed};
use core_runtime::Runtime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
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

async fn spawn_http_origin() -> (std::net::SocketAddr, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        let header_end = loop {
            let size = sock.read(&mut chunk).await.unwrap();
            assert_ne!(size, 0, "proxy closed before forwarding the HTTP header");
            request.extend_from_slice(&chunk[..size]);
            if let Some(start) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break start + 4;
            }
        };
        let head = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = head
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let chunked = head.split("\r\n").any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.trim().eq_ignore_ascii_case("chunked")
            })
        });
        let body_end = if chunked {
            loop {
                if let Some(start) = request[header_end..]
                    .windows(5)
                    .position(|window| window == b"0\r\n\r\n")
                {
                    break header_end + start + 5;
                }
                let size = sock.read(&mut chunk).await.unwrap();
                assert_ne!(size, 0, "proxy dropped the chunked HTTP request body");
                request.extend_from_slice(&chunk[..size]);
            }
        } else {
            while request.len() < header_end + content_length {
                let size = sock.read(&mut chunk).await.unwrap();
                assert_ne!(size, 0, "proxy dropped the prefetched HTTP request body");
                request.extend_from_slice(&chunk[..size]);
            }
            header_end + content_length
        };
        captured_tx.send(request[..body_end].to_vec()).unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    (addr, captured_rx)
}

async fn read_http_response_head(stream: &mut TcpStream) -> Vec<u8> {
    timeout(Duration::from_secs(5), async {
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                return head;
            }
        }
    })
    .await
    .expect("HTTP proxy response header timed out")
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
        udp: true,
    };
    tokio::spawn(run_mixed(listener, runtime.clone()));

    // 等监听就绪
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 客户端：HTTP CONNECT
    let mut s = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let target = format!("127.0.0.1:{echo_port}");
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    let mut first_flight = req.into_bytes();
    // Real TLS clients can optimistically coalesce ClientHello with CONNECT.
    // The mixed listener must not discard bytes already read past \r\n\r\n.
    first_flight.extend_from_slice(b"hello");
    s.write_all(&first_flight).await.unwrap();
    let response = read_http_response_head(&mut s).await;
    let resp = std::str::from_utf8(&response).unwrap();
    assert!(resp.contains("200"), "expected 200, got: {resp:?}");

    let mut echoed = [0u8; 5];
    timeout(Duration::from_secs(5), s.read_exact(&mut echoed))
        .await
        .expect("prefetched CONNECT payload was not relayed")
        .unwrap();
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
async fn http_absolute_post_preserves_body_and_rewrites_hop_headers() {
    let (origin, captured) = spawn_http_origin().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mixed_port = listener.local_addr().unwrap().port();
    drop(listener);
    let yaml = CONFIG.replace("local: 0", &format!("local: {mixed_port}"));
    let plan = core_config::loader::load_from_str(&yaml).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let listener = MixedListener {
        listen: format!("127.0.0.1:{mixed_port}").parse().unwrap(),
        auth: None,
        udp: true,
    };
    tokio::spawn(run_mixed(listener, runtime));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut client = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let request = format!(
        "POST http://{origin}/upload?x=1 HTTP/1.1\r\n\
         Host: wrong.invalid\r\n\
         Content-Length: 4\r\n\
         Proxy-Connection: keep-alive\r\n\
         Connection: close\r\n\r\nbody"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let captured = timeout(Duration::from_secs(5), captured)
        .await
        .expect("origin did not receive the request")
        .expect("origin capture task stopped");
    let captured = std::str::from_utf8(&captured).unwrap();
    assert!(captured.starts_with("POST /upload?x=1 HTTP/1.1\r\n"));
    assert!(captured.contains(&format!("\r\nHost: {origin}\r\n")));
    assert!(!captured.contains("wrong.invalid"));
    assert!(!captured.to_ascii_lowercase().contains("proxy-connection"));
    assert!(captured.ends_with("\r\n\r\nbody"));

    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .expect("HTTP origin response timed out")
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"\r\n\r\nok"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_absolute_chunked_post_stops_at_message_boundary() {
    let (origin, captured) = spawn_http_origin().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mixed_port = listener.local_addr().unwrap().port();
    drop(listener);
    let yaml = CONFIG.replace("local: 0", &format!("local: {mixed_port}"));
    let plan = core_config::loader::load_from_str(&yaml).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let listener = MixedListener {
        listen: format!("127.0.0.1:{mixed_port}").parse().unwrap(),
        auth: None,
        udp: true,
    };
    tokio::spawn(run_mixed(listener, runtime));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut client = TcpStream::connect(("127.0.0.1", mixed_port)).await.unwrap();
    let request = format!(
        "POST http://{origin}/chunked HTTP/1.1\r\n\
         Host: wrong.invalid\r\n\
         Transfer-Encoding: chunked\r\n\
         Proxy-Connection: keep-alive\r\n\r\n\
         4\r\nbody\r\n0\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let captured = timeout(Duration::from_secs(5), captured)
        .await
        .expect("origin did not receive the chunked request")
        .expect("origin capture task stopped");
    let captured = std::str::from_utf8(&captured).unwrap();
    assert!(captured.starts_with("POST /chunked HTTP/1.1\r\n"));
    assert!(captured.contains("\r\nTransfer-Encoding: chunked\r\n"));
    assert!(captured.contains("\r\nConnection: close\r\n"));
    assert!(captured.ends_with("\r\n\r\n4\r\nbody\r\n0\r\n\r\n"));

    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .expect("chunked HTTP origin response timed out")
        .unwrap();
    assert!(response.ends_with(b"\r\n\r\nok"));
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
        udp: true,
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
