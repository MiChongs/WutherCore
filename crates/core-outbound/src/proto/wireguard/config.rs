use std::{collections::HashSet, net::IpAddr, time::Duration};

use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;

use super::io_err;

pub const DEFAULT_MTU: usize = 1_420;
pub const DEFAULT_TCP_BUFFER_SIZE: usize = 256 * 1024;
pub const DEFAULT_UDP_BUFFER_SIZE: usize = 256 * 1024;
pub const DEFAULT_MAX_TCP_SESSIONS: usize = 4_096;
pub const DEFAULT_MAX_UDP_SESSIONS: usize = 4_096;
pub const DEFAULT_PACKET_QUEUE: usize = 1_024;
pub const MAX_PEERS: usize = 4_096;
pub const MAX_LOCAL_ADDRESSES: usize = 8;
pub const MAX_MTU: usize = 65_475;

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, 64)
}

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub reserved: [u8; 3],
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for WireGuardPeerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardPeerConfig")
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
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

impl WireGuardPeerConfig {
    pub fn new(endpoint_host: impl Into<String>, endpoint_port: u16, public_key: [u8; 32]) -> Self {
        let endpoint_host = endpoint_host.into();
        let endpoint_host = endpoint_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(&endpoint_host)
            .to_owned();
        Self {
            endpoint_host,
            endpoint_port,
            public_key,
            preshared_key: None,
            allowed_ips: vec![
                "0.0.0.0/0".parse().expect("static IPv4 CIDR"),
                "::/0".parse().expect("static IPv6 CIDR"),
            ],
            reserved: [0; 3],
            persistent_keepalive: None,
        }
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        self.allowed_ips.iter().any(|network| network.contains(&ip))
    }

    pub fn best_prefix_for(&self, ip: IpAddr) -> Option<u8> {
        self.allowed_ips
            .iter()
            .filter(|network| network.contains(&ip))
            .map(IpNet::prefix_len)
            .max()
    }
}

#[derive(Clone)]
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub local_addresses: Vec<IpNet>,
    pub peers: Vec<WireGuardPeerConfig>,
    pub mtu: usize,
    pub dns: Vec<IpAddr>,
    pub remote_dns_resolve: bool,
    pub tcp: bool,
    pub udp: bool,
    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,
    pub max_tcp_sessions: usize,
    pub max_udp_sessions: usize,
    pub packet_queue: usize,
    pub workers: usize,
    pub connect_timeout: Duration,
    pub udp_idle_timeout: Duration,
}

impl std::fmt::Debug for WireGuardConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardConfig")
            .field("private_key", &"<redacted>")
            .field("local_addresses", &self.local_addresses)
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("dns", &self.dns)
            .field("remote_dns_resolve", &self.remote_dns_resolve)
            .field("tcp", &self.tcp)
            .field("udp", &self.udp)
            .field("tcp_buffer_size", &self.tcp_buffer_size)
            .field("udp_buffer_size", &self.udp_buffer_size)
            .field("max_tcp_sessions", &self.max_tcp_sessions)
            .field("max_udp_sessions", &self.max_udp_sessions)
            .field("packet_queue", &self.packet_queue)
            .field("workers", &self.workers)
            .field("connect_timeout", &self.connect_timeout)
            .field("udp_idle_timeout", &self.udp_idle_timeout)
            .finish()
    }
}

impl WireGuardConfig {
    pub fn new(private_key: [u8; 32], peer: WireGuardPeerConfig) -> Self {
        Self {
            private_key,
            local_addresses: Vec::new(),
            peers: vec![peer],
            mtu: DEFAULT_MTU,
            dns: Vec::new(),
            remote_dns_resolve: false,
            tcp: true,
            udp: true,
            tcp_buffer_size: DEFAULT_TCP_BUFFER_SIZE,
            udp_buffer_size: DEFAULT_UDP_BUFFER_SIZE,
            max_tcp_sessions: DEFAULT_MAX_TCP_SESSIONS,
            max_udp_sessions: DEFAULT_MAX_UDP_SESSIONS,
            packet_queue: DEFAULT_PACKET_QUEUE,
            workers: default_workers(),
            connect_timeout: Duration::from_secs(15),
            udp_idle_timeout: Duration::from_secs(300),
        }
    }

    pub fn validate(&self) -> std::io::Result<()> {
        if self.local_addresses.is_empty() {
            return Err(io_err("wireguard requires at least one local address"));
        }
        if self.local_addresses.len() > MAX_LOCAL_ADDRESSES {
            return Err(io_err(format!(
                "wireguard supports at most {MAX_LOCAL_ADDRESSES} local addresses"
            )));
        }
        if self.private_key == [0; 32] {
            return Err(io_err("wireguard private key cannot be all zero"));
        }
        if self.peers.is_empty() || self.peers.len() > MAX_PEERS {
            return Err(io_err(format!(
                "wireguard peers must contain 1..={MAX_PEERS} entries"
            )));
        }
        if !(576..=MAX_MTU).contains(&self.mtu) {
            return Err(io_err(format!(
                "wireguard mtu must be between 576 and {MAX_MTU}"
            )));
        }
        if self
            .local_addresses
            .iter()
            .any(|network| network.addr().is_ipv6())
            && self.mtu < 1_280
        {
            return Err(io_err("wireguard IPv6 requires mtu >= 1280"));
        }
        if !self.tcp && !self.udp {
            return Err(io_err("wireguard must enable tcp, udp, or both"));
        }
        validate_buffer("tcp-buffer-size", self.tcp_buffer_size)?;
        validate_buffer("udp-buffer-size", self.udp_buffer_size)?;
        validate_limit("max-tcp-sessions", self.max_tcp_sessions)?;
        validate_limit("max-udp-sessions", self.max_udp_sessions)?;
        if !(16..=65_536).contains(&self.packet_queue) {
            return Err(io_err(
                "wireguard packet-queue must be between 16 and 65536",
            ));
        }
        if !(1..=64).contains(&self.workers) {
            return Err(io_err("wireguard workers must be between 1 and 64"));
        }
        if self.connect_timeout.is_zero() || self.connect_timeout > Duration::from_secs(300) {
            return Err(io_err(
                "wireguard connect-timeout must be within (0s, 300s]",
            ));
        }
        if self.udp_idle_timeout < Duration::from_secs(5)
            || self.udp_idle_timeout > Duration::from_secs(86_400)
        {
            return Err(io_err("wireguard udp-timeout must be between 5s and 24h"));
        }

        let mut local_families = (false, false);
        let mut local_networks = HashSet::new();
        for network in &self.local_addresses {
            let ip = network.addr();
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(io_err(format!(
                    "wireguard local address must be unicast: {network}"
                )));
            }
            if !local_networks.insert(*network) {
                return Err(io_err(format!(
                    "wireguard local address is duplicated: {network}"
                )));
            }
            match ip {
                IpAddr::V4(_) => local_families.0 = true,
                IpAddr::V6(_) => local_families.1 = true,
            }
        }

        let mut public_keys = HashSet::new();
        let mut exact_routes = HashSet::new();
        let local_public = *PublicKey::from(&StaticSecret::from(self.private_key)).as_bytes();
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.endpoint_host.trim().is_empty() || peer.endpoint_port == 0 {
                return Err(io_err(format!(
                    "wireguard peer[{index}] requires a non-empty endpoint and non-zero port"
                )));
            }
            if let Ok(endpoint) = peer.endpoint_host.parse::<IpAddr>()
                && (endpoint.is_unspecified()
                    || endpoint.is_multicast()
                    || matches!(endpoint, IpAddr::V4(address) if address.is_broadcast()))
            {
                return Err(io_err(format!(
                    "wireguard peer[{index}] endpoint must be unicast: {endpoint}"
                )));
            }
            if peer.public_key == [0; 32] {
                return Err(io_err(format!(
                    "wireguard peer[{index}] has the forbidden all-zero public key"
                )));
            }
            if peer.public_key == local_public {
                return Err(io_err(format!(
                    "wireguard peer[{index}] public key equals the local public key"
                )));
            }
            if !public_keys.insert(peer.public_key) {
                return Err(io_err(format!(
                    "wireguard peer[{index}] duplicates another public key"
                )));
            }
            if peer.allowed_ips.is_empty() {
                return Err(io_err(format!(
                    "wireguard peer[{index}] requires allowed-ips"
                )));
            }
            for allowed in &peer.allowed_ips {
                let family_available = match allowed.addr() {
                    IpAddr::V4(_) => local_families.0,
                    IpAddr::V6(_) => local_families.1,
                };
                if !family_available {
                    return Err(io_err(format!(
                        "wireguard peer[{index}] route {allowed} has no matching local address"
                    )));
                }
                if !exact_routes.insert(allowed.trunc()) {
                    return Err(io_err(format!(
                        "wireguard allowed-ip {allowed} is assigned to more than one peer"
                    )));
                }
            }
        }
        if self.remote_dns_resolve && self.dns.is_empty() {
            return Err(io_err(
                "wireguard remote-dns-resolve requires at least one dns server",
            ));
        }
        for dns in &self.dns {
            let family_available = match dns {
                IpAddr::V4(_) => local_families.0,
                IpAddr::V6(_) => local_families.1,
            };
            if dns.is_unspecified() || dns.is_multicast() || !family_available {
                return Err(io_err(format!(
                    "wireguard dns address is unusable on this interface: {dns}"
                )));
            }
            if self.route_peer(*dns).is_none() {
                return Err(io_err(format!(
                    "wireguard dns address is not covered by any allowed-ip: {dns}"
                )));
            }
        }
        Ok(())
    }

    pub fn route_peer(&self, ip: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| peer.best_prefix_for(ip).map(|prefix| (prefix, index)))
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, index)| index)
    }
}

fn validate_buffer(name: &str, value: usize) -> std::io::Result<()> {
    if !(4_096..=16 * 1024 * 1024).contains(&value) {
        return Err(io_err(format!(
            "wireguard {name} must be between 4096 and 16777216"
        )));
    }
    Ok(())
}

fn validate_limit(name: &str, value: usize) -> std::io::Result<()> {
    if !(1..=65_535).contains(&value) {
        return Err(io_err(format!(
            "wireguard {name} must be between 1 and 65535"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> WireGuardConfig {
        let mut config = WireGuardConfig::new(
            [7; 32],
            WireGuardPeerConfig::new("127.0.0.1", 51_820, [9; 32]),
        );
        config.local_addresses = vec![
            "10.0.0.2/32".parse().unwrap(),
            "fd00::2/128".parse().unwrap(),
        ];
        config
    }

    #[test]
    fn longest_prefix_selects_peer() {
        let mut config = valid();
        config.peers[0].allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
        let mut second = WireGuardPeerConfig::new("127.0.0.1", 51_821, [8; 32]);
        second.allowed_ips = vec!["10.1.0.0/16".parse().unwrap()];
        config.peers.push(second);
        assert_eq!(config.route_peer("10.1.2.3".parse().unwrap()), Some(1));
        assert_eq!(config.route_peer("10.2.2.3".parse().unwrap()), Some(0));
    }

    #[test]
    fn duplicate_exact_route_fails_closed() {
        let mut config = valid();
        config.peers[0].allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        let mut second = WireGuardPeerConfig::new("127.0.0.1", 51_821, [8; 32]);
        second.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        config.peers.push(second);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("more than one peer")
        );
    }

    #[test]
    fn remote_dns_requires_routed_server() {
        let mut config = valid();
        config.peers[0].allowed_ips =
            vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
        config.remote_dns_resolve = true;
        config.dns = vec!["1.1.1.1".parse().unwrap()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("not covered")
        );
    }
}
