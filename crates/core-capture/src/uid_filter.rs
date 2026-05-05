//! Identity-based packet filter for root TUN mode (USER-SPACE FALLBACK).
//!
//! ## Architecture
//!
//! Identity-based bypass is implemented at TWO layers:
//!
//! 1. **Primary (kernel)**: `platform::linux_identity_bypass` installs
//!    iptables `-t mangle -A OUTPUT -m owner --uid-owner X -j MARK` rules so
//!    excluded packets never enter TUN — the kernel reroutes them via the
//!    physical NIC after MARK changes `skb->mark` (`ip_route_me_harder`). This
//!    is the only correct semantic for "bypass": traffic does not transit TUN.
//!
//! 2. **Fallback (user-space, this module)**: if kernel-level bypass cannot be
//!    installed (no iptables binary, kernel restrictions, package resolution
//!    miss), this filter classifies packets as they enter the dispatcher and
//!    forces DIRECT routing. Packets *did* enter TUN, so they take the slower
//!    user-space path; but at least they reach the destination via the proxy
//!    runtime's DIRECT outbound rather than the TUN proxy chain.
//!
//! In normal operation with iptables present, this module's `decide()` should
//! rarely reach `Bypass(_)` — kernel rules win first.
//!
//! ## Semantics (matches mihomo-smart)
//!
//! - **Excluded** match → packet bypasses proxy and goes DIRECT (PASS through).
//!   Never dropped — that would create a black hole for legit apps.
//! - **Included** lists are non-empty AND no rule matches → also bypass (PASS).
//! - All other packets → proxy normally.
//!
//! ## Source of truth
//!
//! - **UID**: parsed from `/proc/net/{tcp,tcp6,udp,udp6}` by source port
//! - **GID**: looked up via `/proc/<pid>/status` after finding pid by socket inode
//!   (Android shortcut: app GID == app UID for UIDs ≥ 10000)
//! - **Package**: `/data/system/packages.list` on Android, empty on Linux

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, trace};

/// Filter outcome for a single packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// Proxy as normal — no rule matched.
    Proxy,
    /// Bypass proxy — go DIRECT through physical NIC.
    Bypass(BypassCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassCause {
    UidExcluded,
    UidNotIncluded,
    GidExcluded,
    GidNotIncluded,
    PackageExcluded,
    PackageNotIncluded,
}

#[derive(Debug, Default, Clone)]
pub struct IdentityRules {
    pub include_uid: Vec<u32>,
    pub include_uid_range: Vec<(u32, u32)>,
    pub exclude_uid: Vec<u32>,
    pub exclude_uid_range: Vec<(u32, u32)>,
    pub include_gid: Vec<u32>,
    pub include_gid_range: Vec<(u32, u32)>,
    pub exclude_gid: Vec<u32>,
    pub exclude_gid_range: Vec<(u32, u32)>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
}

impl IdentityRules {
    pub fn is_empty(&self) -> bool {
        self.include_uid.is_empty()
            && self.include_uid_range.is_empty()
            && self.exclude_uid.is_empty()
            && self.exclude_uid_range.is_empty()
            && self.include_gid.is_empty()
            && self.include_gid_range.is_empty()
            && self.exclude_gid.is_empty()
            && self.exclude_gid_range.is_empty()
            && self.include_package.is_empty()
            && self.exclude_package.is_empty()
    }

    fn has_uid_filters(&self) -> bool {
        !self.include_uid.is_empty()
            || !self.include_uid_range.is_empty()
            || !self.exclude_uid.is_empty()
            || !self.exclude_uid_range.is_empty()
    }

    fn has_gid_filters(&self) -> bool {
        !self.include_gid.is_empty()
            || !self.include_gid_range.is_empty()
            || !self.exclude_gid.is_empty()
            || !self.exclude_gid_range.is_empty()
    }

    fn has_package_filters(&self) -> bool {
        !self.include_package.is_empty() || !self.exclude_package.is_empty()
    }
}

/// Per-app packet filter for root TUN mode.
#[derive(Debug)]
pub struct UidPacketFilter {
    rules: IdentityRules,
    /// UID → package name (refreshed from /data/system/packages.list)
    uid_to_pkg: RwLock<HashMap<u32, String>>,
    /// UID → primary GID (cached lookup of /proc/<pid>/status)
    uid_to_gid: RwLock<HashMap<u32, u32>>,
    last_pkg_refresh: RwLock<Instant>,
    last_gid_refresh: RwLock<Instant>,
}

impl UidPacketFilter {
    pub fn new(rules: IdentityRules) -> Self {
        let now = Instant::now();
        let stale = now - Duration::from_secs(3600);
        let filter = Self {
            rules,
            uid_to_pkg: RwLock::new(HashMap::new()),
            uid_to_gid: RwLock::new(HashMap::new()),
            last_pkg_refresh: RwLock::new(stale),
            last_gid_refresh: RwLock::new(stale),
        };
        filter.refresh_package_map();
        filter
    }

    /// Backward-compatible constructor for package-only configuration.
    pub fn from_packages(exclude: Vec<String>, include: Vec<String>) -> Self {
        Self::new(IdentityRules {
            exclude_package: exclude,
            include_package: include,
            ..Default::default()
        })
    }

    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Decide whether this packet should be proxied or bypassed.
    pub fn decide(&self, src: SocketAddr, is_tcp: bool) -> FilterDecision {
        if self.rules.is_empty() {
            return FilterDecision::Proxy;
        }

        // Resolve UID for this socket
        let uid = match lookup_uid_for_socket(src, is_tcp) {
            Some(u) => u,
            None => {
                trace!(
                    target: "capture::uid_filter",
                    src = %src,
                    is_tcp,
                    "could not resolve UID; defaulting to proxy"
                );
                return FilterDecision::Proxy;
            }
        };

        // Apply UID filters
        if self.rules.has_uid_filters() {
            if uid_in_set(uid, &self.rules.exclude_uid, &self.rules.exclude_uid_range) {
                debug!(target: "capture::uid_filter", uid, "exclude_uid match -> BYPASS");
                return FilterDecision::Bypass(BypassCause::UidExcluded);
            }
            if !self.rules.include_uid.is_empty() || !self.rules.include_uid_range.is_empty() {
                if !uid_in_set(uid, &self.rules.include_uid, &self.rules.include_uid_range) {
                    debug!(target: "capture::uid_filter", uid, "uid not in include_uid -> BYPASS");
                    return FilterDecision::Bypass(BypassCause::UidNotIncluded);
                }
            }
        }

        // Apply GID filters (resolve GID lazily)
        if self.rules.has_gid_filters() {
            if let Some(gid) = self.lookup_gid(uid) {
                if uid_in_set(gid, &self.rules.exclude_gid, &self.rules.exclude_gid_range) {
                    debug!(target: "capture::uid_filter", uid, gid, "exclude_gid match -> BYPASS");
                    return FilterDecision::Bypass(BypassCause::GidExcluded);
                }
                if !self.rules.include_gid.is_empty() || !self.rules.include_gid_range.is_empty() {
                    if !uid_in_set(gid, &self.rules.include_gid, &self.rules.include_gid_range) {
                        debug!(target: "capture::uid_filter", uid, gid, "gid not in include_gid -> BYPASS");
                        return FilterDecision::Bypass(BypassCause::GidNotIncluded);
                    }
                }
            }
        }

        // Apply package filters (Android)
        if self.rules.has_package_filters() && uid >= 10000 {
            self.maybe_refresh_packages();
            let pkg = self.uid_to_pkg.read().get(&uid).cloned();
            if let Some(pkg_name) = pkg {
                if self.rules.exclude_package.iter().any(|p| p == &pkg_name) {
                    debug!(target: "capture::uid_filter", uid, pkg = %pkg_name, "exclude_package match -> BYPASS");
                    return FilterDecision::Bypass(BypassCause::PackageExcluded);
                }
                if !self.rules.include_package.is_empty()
                    && !self.rules.include_package.iter().any(|p| p == &pkg_name)
                {
                    debug!(target: "capture::uid_filter", uid, pkg = %pkg_name, "pkg not in include_package -> BYPASS");
                    return FilterDecision::Bypass(BypassCause::PackageNotIncluded);
                }
            }
            // Unknown package + include rules set: be conservative, allow proxy
            // (matches mihomo: missing UID resolution defaults to PASS-through-proxy)
        }

        FilterDecision::Proxy
    }

    /// Legacy API used by callers that only need a yes/no decision.
    pub fn should_exclude(&self, src: SocketAddr, is_tcp: bool) -> bool {
        matches!(self.decide(src, is_tcp), FilterDecision::Bypass(_))
    }

    fn maybe_refresh_packages(&self) {
        let last = *self.last_pkg_refresh.read();
        if last.elapsed() > Duration::from_secs(60) {
            self.refresh_package_map();
        }
    }

    fn refresh_package_map(&self) {
        let map = load_android_packages();
        if !map.is_empty() {
            *self.uid_to_pkg.write() = map;
        }
        *self.last_pkg_refresh.write() = Instant::now();
    }

    fn lookup_gid(&self, uid: u32) -> Option<u32> {
        // Fast cache hit
        if let Some(&gid) = self.uid_to_gid.read().get(&uid) {
            return Some(gid);
        }

        // Periodic refresh of full map
        let last = *self.last_gid_refresh.read();
        let needs_refresh = last.elapsed() > Duration::from_secs(60);

        if needs_refresh {
            let map = load_uid_to_gid_map();
            if !map.is_empty() {
                *self.uid_to_gid.write() = map;
            }
            *self.last_gid_refresh.write() = Instant::now();
        }

        // Re-check after refresh
        if let Some(&gid) = self.uid_to_gid.read().get(&uid) {
            return Some(gid);
        }

        // Android fallback: app GID typically == UID for app UIDs (≥ 10000)
        #[cfg(target_os = "android")]
        if uid >= 10000 {
            return Some(uid);
        }

        None
    }
}

fn uid_in_set(value: u32, set: &[u32], ranges: &[(u32, u32)]) -> bool {
    if set.iter().any(|&v| v == value) {
        return true;
    }
    ranges.iter().any(|&(lo, hi)| value >= lo && value <= hi)
}

/// Look up the UID that owns a local socket by reading /proc/net/{tcp,udp}.
fn lookup_uid_for_socket(src: SocketAddr, is_tcp: bool) -> Option<u32> {
    let port = src.port();
    let ip = src.ip();
    let paths: &[&str] = match (ip, is_tcp) {
        (IpAddr::V4(_), true) => &["/proc/net/tcp"],
        (IpAddr::V6(_), true) => &["/proc/net/tcp6"],
        (IpAddr::V4(_), false) => &["/proc/net/udp"],
        (IpAddr::V6(_), false) => &["/proc/net/udp6"],
    };
    for path in paths {
        if let Some(uid) = search_proc_net(path, ip, port).map(|(uid, _inode)| uid) {
            return Some(uid);
        }
    }
    None
}

/// Parse /proc/net/{tcp,udp,tcp6,udp6} → (uid, inode) for a given local addr:port.
fn search_proc_net(path: &str, ip: IpAddr, port: u16) -> Option<(u32, u64)> {
    let content = std::fs::read_to_string(path).ok()?;
    let port_hex = format!("{:04X}", port);

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let local = fields[1];
        let parts: Vec<&str> = local.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        let (hex_ip, hex_port) = (parts[0], parts[1]);
        if !hex_port.eq_ignore_ascii_case(&port_hex) {
            continue;
        }
        if !ip_matches_hex(ip, hex_ip) {
            continue;
        }
        let uid = fields[7].parse::<u32>().ok()?;
        let inode = fields[9].parse::<u64>().unwrap_or(0);
        return Some((uid, inode));
    }
    None
}

fn ip_matches_hex(ip: IpAddr, hex: &str) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if hex.len() != 8 {
                return false;
            }
            let Ok(val) = u32::from_str_radix(hex, 16) else {
                return false;
            };
            let octets = v4.octets();
            let expected = u32::from_le_bytes(octets);
            val == expected
        }
        IpAddr::V6(v6) => {
            if hex.len() != 32 {
                return false;
            }
            let segments = v6.octets();
            for i in 0..4 {
                let group_hex = &hex[i * 8..(i + 1) * 8];
                let Ok(group_val) = u32::from_str_radix(group_hex, 16) else {
                    return false;
                };
                let start = i * 4;
                let expected = u32::from_le_bytes([
                    segments[start],
                    segments[start + 1],
                    segments[start + 2],
                    segments[start + 3],
                ]);
                if group_val != expected {
                    return false;
                }
            }
            true
        }
    }
}

/// Build a UID → primary GID map by scanning /proc/<pid>/status.
fn load_uid_to_gid_map() -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return map,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if !name_s.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let status_path = format!("/proc/{}/status", name_s);
        if let Some((uid, gid)) = parse_uid_gid_from_status(&status_path) {
            // Only insert if not already mapped (first hit wins; deterministic enough)
            map.entry(uid).or_insert(gid);
        }
    }
    map
}

fn parse_uid_gid_from_status(path: &str) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut uid = None;
    let mut gid = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|s| s.parse::<u32>().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest.split_whitespace().next().and_then(|s| s.parse::<u32>().ok());
        }
        if uid.is_some() && gid.is_some() {
            break;
        }
    }
    Some((uid?, gid?))
}

#[cfg(target_os = "android")]
fn load_android_packages() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let content = match std::fs::read_to_string("/data/system/packages.list") {
        Ok(c) => c,
        Err(_) => return map,
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 {
            let pkg = fields[0];
            if let Ok(uid) = fields[1].parse::<u32>() {
                map.insert(uid, pkg.to_string());
            }
        }
    }
    debug!(target: "capture::uid_filter", packages = map.len(), "loaded Android package map");
    map
}

#[cfg(not(target_os = "android"))]
fn load_android_packages() -> HashMap<u32, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ip_matches_hex_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(ip_matches_hex(ip, "0100007F"));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(ip_matches_hex(ip2, "6401A8C0"));
    }

    #[test]
    fn rules_empty_when_no_filters() {
        let rules = IdentityRules::default();
        assert!(rules.is_empty());
    }

    #[test]
    fn uid_in_set_basic() {
        assert!(uid_in_set(1000, &[500, 1000, 2000], &[]));
        assert!(!uid_in_set(1500, &[500, 1000, 2000], &[]));
        assert!(uid_in_set(1500, &[], &[(1000, 2000)]));
        assert!(!uid_in_set(2500, &[], &[(1000, 2000)]));
        assert!(uid_in_set(1000, &[], &[(1000, 1000)]));
    }

    #[test]
    fn empty_filter_proxies_all() {
        let filter = UidPacketFilter::new(IdentityRules::default());
        assert!(!filter.is_active());
        let src: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(filter.decide(src, true), FilterDecision::Proxy);
    }

    #[test]
    fn package_only_constructor_compat() {
        let filter = UidPacketFilter::from_packages(
            vec!["com.example.excluded".into()],
            vec![],
        );
        assert!(filter.is_active());
    }

    #[test]
    fn uid_exclude_range_overrides() {
        let rules = IdentityRules {
            exclude_uid_range: vec![(10000, 19999)],
            ..Default::default()
        };
        let _filter = UidPacketFilter::new(rules);
        // Cannot easily assert on packet decision here without /proc mocking,
        // but constructor should accept ranges.
    }

    #[test]
    fn parse_uid_gid_from_self() {
        let path = "/proc/self/status";
        if std::path::Path::new(path).exists() {
            let res = parse_uid_gid_from_status(path);
            assert!(res.is_some());
        }
    }
}
