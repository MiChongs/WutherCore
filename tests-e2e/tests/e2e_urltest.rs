//! URLTest 端到端：模拟一个返回 204 的 mini-HTTP，DIRECT 出口测速并写入 history。

use std::{sync::Arc, time::Duration};

use core_runtime::{Runtime, UrlTestConfig, UrlTester};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const CONFIG: &str = r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#FAKE-NODE"
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: direct
"#;

async fn spawn_204() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urltest_direct_succeeds() {
    let port = spawn_204().await;
    let plan = core_config::loader::load_from_str(CONFIG).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let tester = UrlTester::new(UrlTestConfig {
        default_url: format!("http://127.0.0.1:{port}/generate_204"),
        default_timeout: Duration::from_secs(2),
        max_parallel: 8,
        ..UrlTestConfig::default()
    });
    let ms = tester
        .test_node(&runtime, "DIRECT", None, None)
        .await
        .expect("delay should be Ok");
    assert!(ms < 2000, "expected delay < 2000ms, got {ms}");
    let history = runtime.smart.ensure_node("DIRECT").history();
    assert!(!history.is_empty(), "history should be recorded");
    assert_eq!(history.last().unwrap().delay_ms, ms);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urltest_unknown_node_yields_error() {
    let port = spawn_204().await;
    let plan = core_config::loader::load_from_str(CONFIG).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let tester = UrlTester::new(UrlTestConfig {
        default_url: format!("http://127.0.0.1:{port}/generate_204"),
        default_timeout: Duration::from_secs(2),
        max_parallel: 8,
        ..UrlTestConfig::default()
    });
    let r = tester.test_node(&runtime, "ghost-node", None, None).await;
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn urltest_test_many_concurrent() {
    let port = spawn_204().await;
    let plan = core_config::loader::load_from_str(CONFIG).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let tester = UrlTester::new(UrlTestConfig {
        default_url: format!("http://127.0.0.1:{port}/generate_204"),
        default_timeout: Duration::from_secs(2),
        max_parallel: 8,
        ..UrlTestConfig::default()
    });
    let nodes = vec!["DIRECT".to_string(); 16];
    let res = tester.test_many(&runtime, &nodes, None, None).await;
    assert_eq!(res.len(), 16);
    let ok = res.iter().filter(|(_, r)| r.is_ok()).count();
    assert!(ok >= 15, "concurrent test should mostly succeed: ok={ok}");
}
