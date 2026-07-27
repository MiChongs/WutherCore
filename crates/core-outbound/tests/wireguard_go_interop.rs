use std::{path::PathBuf, process::Stdio, time::Duration};

use boringtun::x25519::{PublicKey, StaticSecret};
use core_outbound::proto::wireguard::{
    WireGuardServer, WireGuardServerConfig, WireGuardServerPeerConfig,
};

fn packet(source: [u8; 4], destination: [u8; 4], marker: u8) -> Vec<u8> {
    let mut packet = vec![0; 21];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(21u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20] = marker;
    packet
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
#[ignore = "requires the Go toolchain and downloads the fixed official wireguard-go module"]
async fn official_wireguard_go_peer_roundtrips_plaintext() {
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/wireguard-go-peer");
    let executable = std::env::temp_dir().join(format!(
        "rp-kernel-wireguard-interop-peer-{}{}",
        std::process::id(),
        if cfg!(windows) { ".exe" } else { "" }
    ));
    let status = std::process::Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&executable)
        .arg(".")
        .current_dir(&helper)
        .status()
        .expect("Go toolchain is required for this ignored interoperability test");
    assert!(
        status.success(),
        "official wireguard-go helper did not build"
    );

    let client_private = [71; 32];
    let server_private = [73; 32];
    let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
    let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();
    let server = WireGuardServer::bind(WireGuardServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        server_private,
        WireGuardServerPeerConfig::new(client_public, vec!["10.88.0.2/32".parse().unwrap()]),
    ))
    .await
    .unwrap();
    let marker = 0xa7;
    let child = std::process::Command::new(&executable)
        .args([
            server.local_addr().unwrap().to_string(),
            hex(&client_private),
            hex(&server_public),
            hex(&[marker]),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(10), server.recv_packet())
        .await
        .expect("wireguard-go did not establish a tunnel in time")
        .unwrap();
    assert_eq!(
        received.packet,
        packet([10, 88, 0, 2], [10, 88, 0, 1], marker)
    );
    server
        .send_packet(&packet([10, 88, 0, 1], [10, 88, 0, 2], marker))
        .await
        .unwrap();
    let output = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "wireguard-go helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(executable);
    server.close().await;
}
