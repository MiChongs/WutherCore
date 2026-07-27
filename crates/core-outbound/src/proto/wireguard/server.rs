use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use boringtun::{
    noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    x25519::{PublicKey, StaticSecret},
};
use ipnet::IpNet;
use parking_lot::RwLock;
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{
    config::{DEFAULT_MTU, DEFAULT_PACKET_QUEUE, MAX_MTU, MAX_PEERS, WireGuardPeerConfig},
    device::{PeerCrypto, normalize_incoming_reserved},
    fragment::fragment_ip_packet,
    io_err,
};

const NETWORK_BUFFER_SIZE: usize = 65_535 + 256;
const DEFAULT_HANDSHAKE_RATE_LIMIT: u64 = 100;

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardServerPeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub reserved: [u8; 3],
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for WireGuardServerPeerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardServerPeerConfig")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "<redacted>"),
            )
            .field("allowed_ips", &self.allowed_ips)
            .field("reserved", &self.reserved)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

impl WireGuardServerPeerConfig {
    pub fn new(public_key: [u8; 32], allowed_ips: Vec<IpNet>) -> Self {
        Self {
            public_key,
            preshared_key: None,
            allowed_ips,
            reserved: [0; 3],
            persistent_keepalive: None,
        }
    }

    fn as_crypto_config(&self) -> WireGuardPeerConfig {
        WireGuardPeerConfig {
            endpoint_host: "dynamic".into(),
            endpoint_port: 1,
            public_key: self.public_key,
            preshared_key: self.preshared_key,
            allowed_ips: self.allowed_ips.clone(),
            reserved: self.reserved,
            persistent_keepalive: self.persistent_keepalive,
        }
    }

    fn best_prefix_for(&self, address: IpAddr) -> Option<u8> {
        self.allowed_ips
            .iter()
            .filter(|network| network.contains(&address))
            .map(IpNet::prefix_len)
            .max()
    }
}

#[derive(Clone)]
pub struct WireGuardServerConfig {
    pub bind: SocketAddr,
    pub private_key: [u8; 32],
    pub peers: Vec<WireGuardServerPeerConfig>,
    pub mtu: usize,
    pub packet_queue: usize,
    pub handshake_rate_limit: u64,
}

impl std::fmt::Debug for WireGuardServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardServerConfig")
            .field("bind", &self.bind)
            .field("private_key", &"<redacted>")
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("packet_queue", &self.packet_queue)
            .field("handshake_rate_limit", &self.handshake_rate_limit)
            .finish()
    }
}

impl WireGuardServerConfig {
    pub fn new(bind: SocketAddr, private_key: [u8; 32], peer: WireGuardServerPeerConfig) -> Self {
        Self {
            bind,
            private_key,
            peers: vec![peer],
            mtu: DEFAULT_MTU,
            packet_queue: DEFAULT_PACKET_QUEUE,
            handshake_rate_limit: DEFAULT_HANDSHAKE_RATE_LIMIT,
        }
    }

    pub fn validate(&self) -> std::io::Result<()> {
        if self.private_key == [0; 32] {
            return Err(io_err("wireguard server private key cannot be all zero"));
        }
        if self.peers.is_empty() || self.peers.len() > MAX_PEERS {
            return Err(io_err(format!(
                "wireguard server peers must contain 1..={MAX_PEERS} entries"
            )));
        }
        if !(576..=MAX_MTU).contains(&self.mtu) {
            return Err(io_err(format!(
                "wireguard server mtu must be between 576 and {MAX_MTU}"
            )));
        }
        if self.mtu < 1_280
            && self
                .peers
                .iter()
                .flat_map(|peer| &peer.allowed_ips)
                .any(|network| network.addr().is_ipv6())
        {
            return Err(io_err("wireguard server IPv6 requires mtu >= 1280"));
        }
        if !(16..=65_536).contains(&self.packet_queue) {
            return Err(io_err(
                "wireguard server packet-queue must be between 16 and 65536",
            ));
        }
        if !(1..=1_000_000).contains(&self.handshake_rate_limit) {
            return Err(io_err(
                "wireguard server handshake-rate-limit must be between 1 and 1000000",
            ));
        }
        let local_public = *PublicKey::from(&StaticSecret::from(self.private_key)).as_bytes();
        let mut public_keys = HashSet::new();
        let mut exact_routes = HashSet::new();
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.public_key == [0; 32] || peer.public_key == local_public {
                return Err(io_err(format!(
                    "wireguard server peer[{index}] has an invalid public key"
                )));
            }
            if !public_keys.insert(peer.public_key) {
                return Err(io_err(format!(
                    "wireguard server peer[{index}] duplicates another public key"
                )));
            }
            if peer.allowed_ips.is_empty() {
                return Err(io_err(format!(
                    "wireguard server peer[{index}] requires allowed-ips"
                )));
            }
            for network in &peer.allowed_ips {
                if !exact_routes.insert(network.trunc()) {
                    return Err(io_err(format!(
                        "wireguard server allowed-ip {network} is assigned to more than one peer"
                    )));
                }
            }
        }
        Ok(())
    }

    fn route_peer(&self, address: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| peer.best_prefix_for(address).map(|prefix| (prefix, index)))
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, index)| index)
    }
}

#[derive(Debug, Clone)]
pub struct WireGuardReceivedPacket {
    pub peer_index: usize,
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WireGuardServerPeerStats {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt_ms: Option<u32>,
}

struct ServerPeer {
    config: WireGuardServerPeerConfig,
    crypto: PeerCrypto,
    endpoint: RwLock<Option<SocketAddr>>,
}

pub struct WireGuardServer {
    socket: Arc<tokio::net::UdpSocket>,
    config: Arc<WireGuardServerConfig>,
    peers: Arc<Vec<Arc<ServerPeer>>>,
    received: AsyncMutex<mpsc::Receiver<WireGuardReceivedPacket>>,
    cancellation: CancellationToken,
    driver: AsyncMutex<Option<JoinHandle<()>>>,
    dropped_packets: Arc<AtomicU64>,
}

impl std::fmt::Debug for WireGuardServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardServer")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("peers", &self.peers.len())
            .field("mtu", &self.config.mtu)
            .finish_non_exhaustive()
    }
}

impl WireGuardServer {
    pub async fn bind(config: WireGuardServerConfig) -> std::io::Result<Self> {
        config.validate()?;
        let socket = Arc::new(tokio::net::UdpSocket::bind(config.bind).await?);
        let private = StaticSecret::from(config.private_key);
        let public = PublicKey::from(&private);
        let rate_limiter = Arc::new(RateLimiter::new(&public, config.handshake_rate_limit));
        // Handshake initiation routing needs to recover the initiator static
        // key before selecting a peer Tunn. Verify MAC1 first so unauthenticated
        // garbage cannot force the more expensive anonymous NoiseIK operation.
        // The selected peer's shared limiter still performs authoritative
        // cookie/rate-limit verification afterwards.
        let routing_mac_verifier = Arc::new(RateLimiter::new(&public, u64::MAX));
        let mut peers = Vec::with_capacity(config.peers.len());
        for (index, peer) in config.peers.iter().cloned().enumerate() {
            let crypto = PeerCrypto::new_with_rate_limiter(
                config.private_key,
                peer.as_crypto_config(),
                u32::try_from(index + 1)
                    .map_err(|_| io_err("wireguard server peer index overflow"))?,
                Some(rate_limiter.clone()),
            )?;
            peers.push(Arc::new(ServerPeer {
                config: peer,
                crypto,
                endpoint: RwLock::new(None),
            }));
        }
        let config = Arc::new(config);
        let peers = Arc::new(peers);
        let cancellation = CancellationToken::new();
        let (received_tx, received_rx) = mpsc::channel(config.packet_queue);
        let dropped_packets = Arc::new(AtomicU64::new(0));
        let driver = tokio::spawn(run_server(ServerDriver {
            socket: socket.clone(),
            config: config.clone(),
            peers: peers.clone(),
            rate_limiter,
            routing_mac_verifier,
            received: received_tx,
            cancellation: cancellation.clone(),
            dropped_packets: dropped_packets.clone(),
        }));
        Ok(Self {
            socket,
            config,
            peers,
            received: AsyncMutex::new(received_rx),
            cancellation,
            driver: AsyncMutex::new(Some(driver)),
            dropped_packets,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn recv_packet(&self) -> std::io::Result<WireGuardReceivedPacket> {
        self.received.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "wireguard server is closed",
            )
        })
    }

    pub async fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        let destination = Tunn::dst_address(packet)
            .ok_or_else(|| io_err("wireguard server outbound packet is not valid IPv4/IPv6"))?;
        let peer_index = self.config.route_peer(destination).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("wireguard server has no peer route for {destination}"),
            )
        })?;
        self.send_packet_to_peer(peer_index, packet).await
    }

    pub async fn send_packet_to_peer(
        &self,
        peer_index: usize,
        packet: &[u8],
    ) -> std::io::Result<()> {
        let peer = self.peers.get(peer_index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("wireguard server peer index {peer_index} is out of range"),
            )
        })?;
        let destination = Tunn::dst_address(packet)
            .ok_or_else(|| io_err("wireguard server outbound packet is not valid IPv4/IPv6"))?;
        if peer.config.best_prefix_for(destination).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "wireguard server peer[{peer_index}] does not allow destination {destination}"
                ),
            ));
        }
        let endpoint = peer.endpoint.read().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("wireguard server peer[{peer_index}] has no authenticated endpoint"),
            )
        })?;
        for fragment in fragment_ip_packet(packet, self.config.mtu)? {
            let encrypted = peer.crypto.encapsulate(&fragment)?;
            send_datagrams(&self.socket, endpoint, encrypted, &self.cancellation).await?;
        }
        Ok(())
    }

    pub fn stats(&self) -> Vec<WireGuardServerPeerStats> {
        self.peers
            .iter()
            .map(|peer| {
                let (last_handshake, tx_bytes, rx_bytes, estimated_loss, estimated_rtt_ms) =
                    peer.crypto.raw_stats();
                WireGuardServerPeerStats {
                    public_key: peer.config.public_key,
                    endpoint: *peer.endpoint.read(),
                    last_handshake,
                    tx_bytes,
                    rx_bytes,
                    estimated_loss,
                    estimated_rtt_ms,
                }
            })
            .collect()
    }

    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    pub async fn close(&self) {
        self.cancellation.cancel();
        if let Some(driver) = self.driver.lock().await.take() {
            let _ = driver.await;
        }
    }
}

impl Drop for WireGuardServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct ServerDriver {
    socket: Arc<tokio::net::UdpSocket>,
    config: Arc<WireGuardServerConfig>,
    peers: Arc<Vec<Arc<ServerPeer>>>,
    rate_limiter: Arc<RateLimiter>,
    routing_mac_verifier: Arc<RateLimiter>,
    received: mpsc::Sender<WireGuardReceivedPacket>,
    cancellation: CancellationToken,
    dropped_packets: Arc<AtomicU64>,
}

async fn run_server(driver: ServerDriver) {
    let ServerDriver {
        socket,
        config,
        peers,
        rate_limiter,
        routing_mac_verifier,
        received,
        cancellation,
        dropped_packets,
    } = driver;
    let private = StaticSecret::from(config.private_key);
    let public = PublicKey::from(&private);
    let peer_by_key: HashMap<[u8; 32], usize> = peers
        .iter()
        .enumerate()
        .map(|(index, peer)| (peer.config.public_key, index))
        .collect();
    let mut buffer = vec![0; NETWORK_BUFFER_SIZE];
    let mut timers = tokio::time::interval(Duration::from_millis(100));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = timers.tick() => {
                rate_limiter.reset_count();
                routing_mac_verifier.reset_count();
                for peer in peers.iter() {
                    let endpoint = *peer.endpoint.read();
                    let Some(endpoint) = endpoint else { continue };
                    match peer.crypto.update_timers() {
                        Ok(packets) => {
                            if let Err(error) = send_datagrams(&socket, endpoint, packets, &cancellation).await {
                                tracing::debug!(target: "wireguard::server", %endpoint, %error, "timer packet send failed");
                            }
                        }
                        Err(error) => tracing::debug!(target: "wireguard::server", %endpoint, %error, "peer timer update failed"),
                    }
                }
            }
            result = socket.recv_from(&mut buffer) => {
                let (length, endpoint) = match result {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::warn!(target: "wireguard::server", %error, "UDP receive failed");
                        continue;
                    }
                };
                let datagram = &buffer[..length];
                let peer_index = match route_incoming(
                    datagram,
                    endpoint.ip(),
                    &private,
                    &public,
                    &peer_by_key,
                    &routing_mac_verifier,
                ) {
                    Ok(index) if index < peers.len() => index,
                    Ok(_) => continue,
                    Err(error) => {
                        tracing::debug!(target: "wireguard::server", %endpoint, %error, "unroutable WireGuard datagram rejected");
                        continue;
                    }
                };
                let peer = &peers[peer_index];
                match peer.crypto.decapsulate(Some(endpoint.ip()), datagram) {
                    Ok(output) => {
                        *peer.endpoint.write() = Some(endpoint);
                        if let Err(error) = send_datagrams(&socket, endpoint, output.network, &cancellation).await {
                            tracing::debug!(target: "wireguard::server", %endpoint, %error, "protocol response send failed");
                        }
                        for packet in output.plaintext {
                            let received_packet = WireGuardReceivedPacket {
                                peer_index,
                                peer_public_key: peer.config.public_key,
                                endpoint,
                                packet,
                            };
                            if received.try_send(received_packet).is_err() {
                                dropped_packets.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(target: "wireguard::server", %endpoint, "bounded plaintext queue is full; packet dropped");
                            }
                        }
                    }
                    Err(error) => tracing::debug!(target: "wireguard::server", %endpoint, %error, "authenticated WireGuard processing rejected datagram"),
                }
            }
        }
    }
}

fn route_incoming(
    datagram: &[u8],
    source_ip: IpAddr,
    private: &StaticSecret,
    public: &PublicKey,
    peer_by_key: &HashMap<[u8; 32], usize>,
    routing_mac_verifier: &RateLimiter,
) -> std::io::Result<usize> {
    let packet_type = datagram.first().copied().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "empty WireGuard datagram")
    })?;
    if packet_type == 1 {
        let normalized = normalize_incoming_reserved(datagram)?;
        let mut scratch = [0_u8; 64];
        let parsed =
            match routing_mac_verifier.verify_packet(Some(source_ip), &normalized, &mut scratch) {
                Ok(packet) => packet,
                Err(TunnResult::Err(error)) => {
                    return Err(io_err(format!(
                        "handshake MAC1 verification failed: {error:?}"
                    )));
                }
                Err(_) => return Err(io_err("handshake MAC1 verifier returned an invalid result")),
            };
        let Packet::HandshakeInit(handshake) = parsed else {
            return Err(io_err("WireGuard type/length mismatch"));
        };
        let half = parse_handshake_anon(private, public, &handshake)
            .map_err(|error| io_err(format!("handshake peer identification failed: {error:?}")))?;
        return peer_by_key
            .get(&half.peer_static_public)
            .copied()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "WireGuard handshake belongs to an unknown peer",
                )
            });
    }
    let receiver = match (packet_type, datagram.len()) {
        (2, 92) => u32::from_le_bytes(
            datagram[8..12]
                .try_into()
                .expect("length checked before receiver index"),
        ),
        (3, 64) | (4, 32..) => u32::from_le_bytes(
            datagram[4..8]
                .try_into()
                .expect("length checked before receiver index"),
        ),
        _ => return Err(io_err("invalid WireGuard packet type or length")),
    };
    usize::try_from(receiver >> 8)
        .ok()
        .and_then(|index| index.checked_sub(1))
        .ok_or_else(|| io_err("invalid WireGuard receiver index"))
}

async fn send_datagrams(
    socket: &tokio::net::UdpSocket,
    endpoint: SocketAddr,
    packets: Vec<Vec<u8>>,
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    for packet in packets {
        let sent = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "wireguard server is closed",
                ));
            }
            sent = socket.send_to(&packet, endpoint) => sent?,
        };
        if sent != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "wireguard UDP socket sent a partial datagram",
            ));
        }
    }
    Ok(())
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

    #[tokio::test]
    async fn server_authenticates_roams_and_routes_bidirectionally() {
        let client_private = [41; 32];
        let server_private = [43; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();
        let server_peer =
            WireGuardServerPeerConfig::new(client_public, vec!["10.77.0.2/32".parse().unwrap()]);
        let server = WireGuardServer::bind(WireGuardServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_private,
            server_peer,
        ))
        .await
        .unwrap();
        let endpoint = server.local_addr().unwrap();
        let mut client_peer =
            WireGuardPeerConfig::new(endpoint.ip().to_string(), endpoint.port(), server_public);
        client_peer.allowed_ips = vec!["10.77.0.1/32".parse().unwrap()];
        let client = PeerCrypto::new(client_private, client_peer, 1).unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = ipv4_packet([10, 77, 0, 2], [10, 77, 0, 1]);
        for packet in client.encapsulate(&outbound).unwrap() {
            socket.send_to(&packet, endpoint).await.unwrap();
        }
        let mut buffer = vec![0; NETWORK_BUFFER_SIZE];
        for _ in 0..16 {
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            let output = client
                .decapsulate(Some(endpoint.ip()), &buffer[..length])
                .unwrap();
            for packet in output.network {
                socket.send_to(&packet, endpoint).await.unwrap();
            }
            if let Ok(received) =
                tokio::time::timeout(Duration::from_millis(20), server.recv_packet()).await
            {
                let received = received.unwrap();
                assert_eq!(received.packet, outbound);
                assert_eq!(received.peer_public_key, client_public);
                break;
            }
        }
        let reverse = ipv4_packet([10, 77, 0, 1], [10, 77, 0, 2]);
        server.send_packet(&reverse).await.unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let output = client
            .decapsulate(Some(endpoint.ip()), &buffer[..length])
            .unwrap();
        assert!(output.plaintext.iter().any(|packet| packet == &reverse));
        assert_eq!(
            server.stats()[0].endpoint,
            Some(socket.local_addr().unwrap())
        );

        let roaming_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let roamed = ipv4_packet([10, 77, 0, 2], [10, 77, 0, 1]);
        for packet in client.encapsulate(&roamed).unwrap() {
            roaming_socket.send_to(&packet, endpoint).await.unwrap();
        }
        let received = tokio::time::timeout(Duration::from_secs(1), server.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.packet, roamed);
        assert_eq!(received.endpoint, roaming_socket.local_addr().unwrap());
        assert_eq!(
            server.stats()[0].endpoint,
            Some(roaming_socket.local_addr().unwrap())
        );
        server.send_packet(&reverse).await.unwrap();
        let (length, _) = tokio::time::timeout(
            Duration::from_secs(1),
            roaming_socket.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        let output = client
            .decapsulate(Some(endpoint.ip()), &buffer[..length])
            .unwrap();
        assert!(output.plaintext.iter().any(|packet| packet == &reverse));
        server.close().await;
    }

    #[test]
    fn server_config_rejects_ambiguous_routes() {
        let mut config = WireGuardServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            [1; 32],
            WireGuardServerPeerConfig::new([2; 32], vec!["10.0.0.2/32".parse().unwrap()]),
        );
        config.peers.push(WireGuardServerPeerConfig::new(
            [3; 32],
            vec!["10.0.0.2/32".parse().unwrap()],
        ));
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("more than one peer")
        );
    }

    #[tokio::test]
    async fn server_close_cancels_a_blocked_receiver() {
        let server = Arc::new(
            WireGuardServer::bind(WireGuardServerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                [101; 32],
                WireGuardServerPeerConfig::new([103; 32], vec!["10.0.0.2/32".parse().unwrap()]),
            ))
            .await
            .unwrap(),
        );
        let waiting_server = server.clone();
        let waiting = tokio::spawn(async move { waiting_server.recv_packet().await });
        tokio::task::yield_now().await;
        server.close().await;
        let error = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    }
}
