//! 集成测试：UDP forwarder 端到端 happy-path。
//!
//! 启动一个 UDP echo 监听 → 通过 forwarder 把"TUN 内"流量发出去 →
//! 验证 echo 包能收到。同时验证 EIM-NAT 模式下复用同一 outbound socket。

use std::{sync::Arc, time::Duration};

use core_capture::{
    eim_nat::EimNatTable,
    udp_forwarder::{UdpForwarderConfig, send_one},
};
use tokio::net::UdpSocket;

async fn echo_server() -> (Arc<UdpSocket>, std::net::SocketAddr) {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = s.local_addr().unwrap();
    let s2 = s.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Ok((n, peer)) = s2.recv_from(&mut buf).await {
                let _ = s2.send_to(&buf[..n], peer).await;
            }
        }
    });
    (s, addr)
}

#[tokio::test]
async fn eim_mode_reuses_outbound_socket() {
    let (_srv, dst) = echo_server().await;
    let cfg = UdpForwarderConfig {
        endpoint_independent_nat: true,
        udp_timeout: Duration::from_secs(60),
    };
    let eim = Arc::new(EimNatTable::new(cfg.udp_timeout));
    let inner_src: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let s1 = send_one(&cfg, &eim, inner_src, dst, b"hello")
        .await
        .unwrap();
    let s2 = send_one(&cfg, &eim, inner_src, dst, b"world")
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&s1, &s2));
    let mut buf = vec![0u8; 1500];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(2), s1.recv_from(&mut buf))
        .await
        .expect("echo recv timeout")
        .unwrap();
    assert_eq!(peer, dst);
    assert!(n == b"hello".len() || n == b"world".len());
}

#[tokio::test]
async fn symmetric_mode_creates_separate_sockets() {
    let (_srv, dst) = echo_server().await;
    let cfg = UdpForwarderConfig {
        endpoint_independent_nat: false,
        udp_timeout: Duration::from_secs(60),
    };
    let eim = Arc::new(EimNatTable::new(cfg.udp_timeout));
    let inner_src: std::net::SocketAddr = "10.0.0.1:5001".parse().unwrap();
    let s1 = send_one(&cfg, &eim, inner_src, dst, b"a").await.unwrap();
    let s2 = send_one(&cfg, &eim, inner_src, dst, b"b").await.unwrap();
    // symmetric mode 不写 EIM 表 —— 每次 bind 新 socket。
    assert!(!Arc::ptr_eq(&s1, &s2));
    assert_eq!(eim.len(), 0);
}
