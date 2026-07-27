#![cfg(feature = "firefox-stack")]

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use core_young::{
    KeyRing, Target, YoungClient, YoungClientConfig, YoungKey, YoungServerConfig, YoungServerHandle,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
};

const TEST_CERTIFICATE_SHA256: [u8; 32] = [
    0xbf, 0xdb, 0xfc, 0x5a, 0xf1, 0x68, 0x7a, 0xc9, 0x08, 0x48, 0x53, 0x01, 0x44, 0xb9, 0xee, 0x94,
    0x28, 0x50, 0x2e, 0x4b, 0xa6, 0xb0, 0x67, 0x75, 0x21, 0xb7, 0x61, 0xd9, 0xfc, 0x1a, 0xa3, 0x91,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neqo_webtransport_tcp_and_udp_round_trip() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        stream.write_all(&request).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 65_535];
        loop {
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..length], peer).await.unwrap();
        }
    });

    let key = YoungKey::from_bytes([0x5a; 32]);
    let server = YoungServerHandle::start(YoungServerConfig {
        listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        nss_database: PathBuf::from(nss::TEST_FIXTURE_DB),
        certificate_nickname: "key".into(),
        authority: "example.com".into(),
        path: "/assets".into(),
        keys: KeyRing::new(vec![key.clone()]).unwrap(),
        clock_skew: Duration::from_secs(120),
        idle_timeout: Duration::from_secs(30),
        max_streams: 32,
        max_sessions: 8,
        max_flows_per_session: 16,
        decoy_status: 404,
        decoy_body: b"<html>not found</html>".to_vec(),
    })
    .unwrap();
    let client_config = YoungClientConfig {
        server: "127.0.0.1".into(),
        port: server.local_addr().port(),
        server_name: "example.com".into(),
        authority: "example.com".into(),
        path: "/assets".into(),
        key,
        certificate_sha256: TEST_CERTIFICATE_SHA256,
        idle_timeout: Duration::from_secs(30),
        max_streams: 32,
        padding_min: 17,
        padding_max: 79,
    };
    let mut rejected_config = client_config.clone();
    rejected_config.key = YoungKey::from_bytes([0x33; 32]);
    let rejected_client = YoungClient::start(rejected_config).unwrap();
    let rejected = tokio::time::timeout(
        Duration::from_secs(10),
        rejected_client.open_tcp(Target::new("127.0.0.1", 9).unwrap()),
    )
    .await
    .unwrap();
    assert!(rejected.is_err());

    let client = YoungClient::start(client_config).unwrap();

    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        client.open_tcp(Target::new(tcp_addr.ip().to_string(), tcp_addr.port()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(b"young-over-neqo").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut tcp_reply = [0; 15];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut tcp_reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&tcp_reply, b"young-over-neqo");

    let udp = tokio::time::timeout(
        Duration::from_secs(10),
        client.open_udp(Target::new(udp_addr.ip().to_string(), udp_addr.port()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let datagram = vec![0xa5; 5000];
    udp.send(&datagram).await.unwrap();
    let mut udp_reply = vec![0; 6000];
    let received = tokio::time::timeout(Duration::from_secs(10), udp.recv(&mut udp_reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&udp_reply[..received], &datagram);

    server.shutdown().unwrap();
}
