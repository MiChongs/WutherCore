use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use boringtun::{
    noise::{Tunn, TunnResult, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::adapter::{create_outbound_udp_socket, resolve_host};

use super::{
    config::{WireGuardConfig, WireGuardPeerConfig},
    fragment::fragment_ip_packet,
    io_err,
    netstack::StackShared,
};

const NETWORK_BUFFER_SIZE: usize = 65_535 + 256;
const MAX_DRAIN_RESULTS: usize = 512;

#[derive(Debug, Clone)]
pub struct WireGuardPeerStats {
    pub endpoint: SocketAddr,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt_ms: Option<u32>,
}

pub(super) struct PeerCrypto {
    tunnel: Mutex<Tunn>,
    peer_config: WireGuardPeerConfig,
}

#[derive(Default)]
pub(super) struct CryptoOutput {
    pub network: Vec<Vec<u8>>,
    pub plaintext: Vec<Vec<u8>>,
}

impl PeerCrypto {
    pub(super) fn new(
        private_key: [u8; 32],
        peer_config: WireGuardPeerConfig,
        index: u32,
    ) -> std::io::Result<Self> {
        Self::new_with_rate_limiter(private_key, peer_config, index, None)
    }

    pub(super) fn new_with_rate_limiter(
        private_key: [u8; 32],
        peer_config: WireGuardPeerConfig,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> std::io::Result<Self> {
        let private = StaticSecret::from(private_key);
        let peer_public = PublicKey::from(peer_config.public_key);
        let tunnel = Tunn::new(
            private,
            peer_public,
            peer_config.preshared_key,
            peer_config.persistent_keepalive,
            index,
            rate_limiter,
        );
        Ok(Self {
            tunnel: Mutex::new(tunnel),
            peer_config,
        })
    }

    pub(super) fn encapsulate(&self, plaintext: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
        let mut tunnel = self.tunnel.lock();
        let mut destination = vec![0; plaintext.len().max(148) + 256];
        match tunnel.encapsulate(plaintext, &mut destination) {
            TunnResult::WriteToNetwork(packet) => Ok(vec![rewrite_outgoing_reserved(
                packet,
                self.peer_config.reserved,
            )?]),
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(error) => {
                Err(io_err(format!("wireguard encapsulation failed: {error:?}")))
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Err(io_err(
                "wireguard crypto returned plaintext while encapsulating",
            )),
        }
    }

    pub(super) fn decapsulate(
        &self,
        source_ip: Option<IpAddr>,
        datagram: &[u8],
    ) -> std::io::Result<CryptoOutput> {
        let normalized = normalize_incoming_reserved(datagram)?;
        let mut tunnel = self.tunnel.lock();
        let mut output = CryptoOutput::default();
        let mut first = true;
        for _ in 0..MAX_DRAIN_RESULTS {
            let mut destination = vec![0; NETWORK_BUFFER_SIZE];
            let input = if first { normalized.as_slice() } else { &[] };
            first = false;
            match tunnel.decapsulate(source_ip, input, &mut destination) {
                TunnResult::Done => return Ok(output),
                TunnResult::Err(error) => {
                    return Err(io_err(format!("wireguard decapsulation failed: {error:?}")));
                }
                TunnResult::WriteToNetwork(packet) => output.network.push(
                    rewrite_outgoing_reserved(packet, self.peer_config.reserved)?,
                ),
                TunnResult::WriteToTunnelV4(packet, source) => {
                    let source = IpAddr::V4(source);
                    if !self.peer_config.permits(source) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("wireguard peer sent source {source} outside its allowed-ips"),
                        ));
                    }
                    output.plaintext.push(packet.to_vec());
                }
                TunnResult::WriteToTunnelV6(packet, source) => {
                    let source = IpAddr::V6(source);
                    if !self.peer_config.permits(source) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("wireguard peer sent source {source} outside its allowed-ips"),
                        ));
                    }
                    output.plaintext.push(packet.to_vec());
                }
            }
        }
        Err(io_err(
            "wireguard crypto result drain exceeded its bounded iteration limit",
        ))
    }

    pub(super) fn update_timers(&self) -> std::io::Result<Vec<Vec<u8>>> {
        let mut tunnel = self.tunnel.lock();
        let mut destination = vec![0; NETWORK_BUFFER_SIZE];
        match tunnel.update_timers(&mut destination) {
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::WriteToNetwork(packet) => Ok(vec![rewrite_outgoing_reserved(
                packet,
                self.peer_config.reserved,
            )?]),
            TunnResult::Err(error) => {
                Err(io_err(format!("wireguard timer update failed: {error:?}")))
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Err(io_err(
                "wireguard crypto returned plaintext while updating timers",
            )),
        }
    }

    pub(super) fn raw_stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.tunnel.lock().stats()
    }

    fn stats(&self, endpoint: SocketAddr) -> WireGuardPeerStats {
        let (last_handshake, tx_bytes, rx_bytes, estimated_loss, estimated_rtt_ms) =
            self.raw_stats();
        WireGuardPeerStats {
            endpoint,
            last_handshake,
            tx_bytes,
            rx_bytes,
            estimated_loss,
            estimated_rtt_ms,
        }
    }
}

struct PeerRuntime {
    crypto: PeerCrypto,
    socket: Arc<tokio::net::UdpSocket>,
    endpoint: SocketAddr,
    _loopback_guard: crate::loopback::LoopbackUdpGuard,
}

struct DeviceInner {
    config: Arc<WireGuardConfig>,
    stack: Arc<StackShared>,
    peers: Vec<Arc<PeerRuntime>>,
    cancellation: CancellationToken,
}

impl Drop for DeviceInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone)]
pub(super) struct WireGuardDevice {
    inner: Arc<DeviceInner>,
}

impl WireGuardDevice {
    pub(super) async fn start(config: WireGuardConfig) -> std::io::Result<Self> {
        config.validate()?;
        let stack = StackShared::new(&config)?;
        let mut peers = Vec::with_capacity(config.peers.len());
        for (index, peer_config) in config.peers.iter().cloned().enumerate() {
            let (endpoint, socket, loopback_guard) = create_peer_socket(&peer_config).await?;
            let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
            let crypto = PeerCrypto::new(
                config.private_key,
                peer_config,
                u32::try_from(index + 1).map_err(|_| io_err("wireguard peer index overflow"))?,
            )?;
            peers.push(Arc::new(PeerRuntime {
                crypto,
                socket,
                endpoint,
                _loopback_guard: loopback_guard,
            }));
        }
        let cancellation = CancellationToken::new();
        let inner = Arc::new(DeviceInner {
            config: Arc::new(config),
            stack,
            peers,
            cancellation,
        });
        spawn_driver(&inner);
        Ok(Self { inner })
    }

    pub(super) fn stack(&self) -> &Arc<StackShared> {
        &self.inner.stack
    }

    pub(super) fn config(&self) -> &WireGuardConfig {
        &self.inner.config
    }

    pub(super) fn stats(&self) -> Vec<WireGuardPeerStats> {
        self.inner
            .peers
            .iter()
            .map(|peer| peer.crypto.stats(peer.endpoint))
            .collect()
    }
}

async fn create_peer_socket(
    peer: &WireGuardPeerConfig,
) -> std::io::Result<(
    SocketAddr,
    std::net::UdpSocket,
    crate::loopback::LoopbackUdpGuard,
)> {
    let addresses = resolve_host(&peer.endpoint_host, peer.endpoint_port).await?;
    let mut last_error = None;
    for address in addresses {
        match create_outbound_udp_socket(address) {
            Ok((socket, guard)) => return Ok((address, socket, guard)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io_err(format!(
            "wireguard endpoint did not resolve: {}:{}",
            peer.endpoint_host, peer.endpoint_port
        ))
    }))
}

struct DeviceDriver {
    config: Arc<WireGuardConfig>,
    stack: Arc<StackShared>,
    peers: Vec<Arc<PeerRuntime>>,
    cancellation: CancellationToken,
}

fn spawn_driver(inner: &DeviceInner) {
    let driver = DeviceDriver {
        config: inner.config.clone(),
        stack: inner.stack.clone(),
        peers: inner.peers.clone(),
        cancellation: inner.cancellation.clone(),
    };
    let worker_count = driver
        .config
        .workers
        .min(driver.peers.len())
        .min(driver.config.packet_queue)
        .max(1);
    let worker_capacity = (driver.config.packet_queue / worker_count).max(1);
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>(worker_capacity);
        workers.push(tx);
        tokio::spawn(run_crypto_worker(
            driver.peers.clone(),
            driver.stack.clone(),
            driver.cancellation.clone(),
            rx,
        ));
    }
    for (peer_index, peer) in driver.peers.iter().cloned().enumerate() {
        let tx = workers[peer_index % worker_count].clone();
        let cancellation = driver.cancellation.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0; NETWORK_BUFFER_SIZE];
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    received = peer.socket.recv(&mut buffer) => match received {
                        Ok(length) => {
                            let datagram = (peer_index, buffer[..length].to_vec());
                            let sent = tokio::select! {
                                _ = cancellation.cancelled() => break,
                                sent = tx.send(datagram) => sent,
                            };
                            if sent.is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "wireguard::udp",
                                endpoint = %peer.endpoint,
                                error = %error,
                                "wireguard UDP receive failed"
                            );
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }
            }
        });
    }
    drop(workers);
    tokio::spawn(run_driver(driver));
}

async fn run_crypto_worker(
    peers: Vec<Arc<PeerRuntime>>,
    stack: Arc<StackShared>,
    cancellation: CancellationToken,
    mut network_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) {
    loop {
        let datagram = tokio::select! {
            _ = cancellation.cancelled() => break,
            datagram = network_rx.recv() => match datagram {
                Some(datagram) => datagram,
                None => break,
            },
        };
        let (peer_index, datagram) = datagram;
        let peer = &peers[peer_index];
        match peer.crypto.decapsulate(Some(peer.endpoint.ip()), &datagram) {
            Ok(output) => {
                send_network(peer, output.network, &cancellation).await;
                for packet in output.plaintext {
                    if let Err(error) = stack.inject(packet) {
                        tracing::warn!(
                            target: "wireguard::stack",
                            endpoint = %peer.endpoint,
                            error = %error,
                            "wireguard plaintext queue rejected an inbound packet"
                        );
                    }
                }
            }
            Err(error) => tracing::debug!(
                target: "wireguard::crypto",
                endpoint = %peer.endpoint,
                error = %error,
                "wireguard rejected an inbound datagram"
            ),
        }
    }
}

async fn run_driver(driver: DeviceDriver) {
    let mut timers = tokio::time::interval(Duration::from_millis(100));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = driver.cancellation.cancelled() => break,
            _ = driver.stack.notified() => {
                pump_stack(&driver).await;
            }
            _ = timers.tick() => {
                for peer in &driver.peers {
                    match peer.crypto.update_timers() {
                        Ok(packets) => send_network(peer, packets, &driver.cancellation).await,
                        Err(error) => tracing::debug!(
                            target: "wireguard::timer",
                            endpoint = %peer.endpoint,
                            error = %error,
                            "wireguard peer timer reported an error"
                        ),
                    }
                }
                pump_stack(&driver).await;
            }
        }
    }
}

async fn pump_stack(driver: &DeviceDriver) {
    for _ in 0..64 {
        let packets = driver.stack.poll_and_drain();
        if packets.is_empty() {
            return;
        }
        for packet in packets {
            let Some(destination) = Tunn::dst_address(&packet) else {
                tracing::warn!(target: "wireguard::route", "dropping malformed plaintext IP packet");
                continue;
            };
            let Some(peer_index) = driver.config.route_peer(destination) else {
                tracing::warn!(
                    target: "wireguard::route",
                    destination = %destination,
                    "no WireGuard peer allows this destination"
                );
                continue;
            };
            let peer = &driver.peers[peer_index];
            match fragment_ip_packet(&packet, driver.config.mtu) {
                Ok(fragments) => {
                    for fragment in fragments {
                        match peer.crypto.encapsulate(&fragment) {
                            Ok(packets) => send_network(peer, packets, &driver.cancellation).await,
                            Err(error) => tracing::warn!(
                                target: "wireguard::crypto",
                                endpoint = %peer.endpoint,
                                error = %error,
                                "wireguard failed to encrypt an IP packet"
                            ),
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    target: "wireguard::fragment",
                    endpoint = %peer.endpoint,
                    error = %error,
                    "wireguard failed to apply the configured mtu"
                ),
            }
        }
    }
    tracing::warn!(
        target: "wireguard::stack",
        "wireguard stack pump hit its bounded iteration limit"
    );
}

async fn send_network(peer: &PeerRuntime, packets: Vec<Vec<u8>>, cancellation: &CancellationToken) {
    for packet in packets {
        let sent = tokio::select! {
            _ = cancellation.cancelled() => return,
            sent = peer.socket.send(&packet) => sent,
        };
        if let Err(error) = sent {
            tracing::warn!(
                target: "wireguard::udp",
                endpoint = %peer.endpoint,
                error = %error,
                "wireguard UDP send failed"
            );
        }
    }
}

fn rewrite_outgoing_reserved(packet: &[u8], reserved: [u8; 3]) -> std::io::Result<Vec<u8>> {
    let mut packet = packet.to_vec();
    if reserved == [0; 3] || packet.len() < 4 {
        return Ok(packet);
    }
    packet[1..4].copy_from_slice(&reserved);
    Ok(packet)
}

pub(super) fn normalize_incoming_reserved(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    if packet.len() < 4 {
        return Ok(packet.to_vec());
    }
    let mut normalized = packet.to_vec();
    normalized[1..4].fill(0);
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 253;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn exchange(
        source: &PeerCrypto,
        destination: &PeerCrypto,
        first: Vec<Vec<u8>>,
    ) -> std::io::Result<Vec<Vec<u8>>> {
        let mut pending = first;
        let mut plaintext = Vec::new();
        for _ in 0..32 {
            if pending.is_empty() {
                break;
            }
            let mut reverse = Vec::new();
            for packet in pending {
                let output = destination
                    .decapsulate(Some(IpAddr::V4("127.0.0.1".parse().unwrap())), &packet)?;
                reverse.extend(output.network);
                plaintext.extend(output.plaintext);
            }
            if !reverse.is_empty() {
                let mut forward = Vec::new();
                for packet in reverse {
                    let output = source
                        .decapsulate(Some(IpAddr::V4("127.0.0.1".parse().unwrap())), &packet)?;
                    forward.extend(output.network);
                    plaintext.extend(output.plaintext);
                }
                pending = forward;
            } else {
                break;
            }
        }
        Ok(plaintext)
    }

    #[test]
    fn boringtun_state_machine_is_bidirectionally_interoperable() {
        let private_a = [7; 32];
        let private_b = [9; 32];
        let public_a = *PublicKey::from(&StaticSecret::from(private_a)).as_bytes();
        let public_b = *PublicKey::from(&StaticSecret::from(private_b)).as_bytes();
        let mut peer_b = WireGuardPeerConfig::new("127.0.0.1", 1, public_b);
        peer_b.allowed_ips = vec!["10.0.0.0/24".parse().unwrap()];
        peer_b.preshared_key = Some([15; 32]);
        let mut peer_a = WireGuardPeerConfig::new("127.0.0.1", 1, public_a);
        peer_a.allowed_ips = vec!["10.0.0.0/24".parse().unwrap()];
        peer_a.preshared_key = Some([15; 32]);
        let a = PeerCrypto::new(private_a, peer_b, 1).unwrap();
        let b = PeerCrypto::new(private_b, peer_a, 2).unwrap();
        let packet = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
        let plaintext = exchange(&a, &b, a.encapsulate(&packet).unwrap()).unwrap();
        assert!(plaintext.iter().any(|received| received == &packet));

        let replay_protected = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 3]);
        let encrypted = a.encapsulate(&replay_protected).unwrap();
        assert_eq!(encrypted.len(), 1);
        let accepted = b
            .decapsulate(Some("127.0.0.1".parse().unwrap()), &encrypted[0])
            .unwrap();
        assert_eq!(accepted.plaintext, vec![replay_protected]);
        assert!(
            b.decapsulate(Some("127.0.0.1".parse().unwrap()), &encrypted[0])
                .is_err(),
            "WireGuard replay window accepted a duplicate transport counter"
        );

        let reverse = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        let plaintext = exchange(&b, &a, b.encapsulate(&reverse).unwrap()).unwrap();
        assert!(plaintext.iter().any(|received| received == &reverse));
    }

    #[test]
    fn reserved_bytes_follow_wireguard_go_bind_layer_semantics() {
        let private_a = [11; 32];
        let private_b = [13; 32];
        let public_a = *PublicKey::from(&StaticSecret::from(private_a)).as_bytes();
        let public_b = *PublicKey::from(&StaticSecret::from(private_b)).as_bytes();
        let mut peer_b = WireGuardPeerConfig::new("127.0.0.1", 1, public_b);
        peer_b.allowed_ips = vec!["10.0.0.0/24".parse().unwrap()];
        peer_b.reserved = [1, 2, 3];
        let mut peer_a = WireGuardPeerConfig::new("127.0.0.1", 1, public_a);
        peer_a.allowed_ips = vec!["10.0.0.0/24".parse().unwrap()];
        peer_a.reserved = [1, 2, 3];
        let a = PeerCrypto::new(private_a, peer_b, 1).unwrap();
        let b = PeerCrypto::new(private_b, peer_a, 2).unwrap();
        let packet = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);
        let first = a.encapsulate(&packet).unwrap();
        assert_eq!(&first[0][1..4], &[1, 2, 3]);
        let normalized = normalize_incoming_reserved(&first[0]).unwrap();
        assert_eq!(&normalized[1..4], &[0, 0, 0]);
        assert_eq!(&normalized[4..], &first[0][4..]);
        let plaintext = exchange(&a, &b, first).unwrap();
        assert!(plaintext.iter().any(|received| received == &packet));
    }
}
