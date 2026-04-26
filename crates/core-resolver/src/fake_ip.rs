//! Fake IP 池 —— §7.3 防泄漏要求：
//! * IPv4 默认 198.18.0.0/15（RFC 2544 benchmark），IPv6 默认 fc00:1::/64（ULA）。
//! * 同一域名多次请求返回同一 Fake 地址；TTL 到期后回收并可被复用。
//! * 反查：连接到来时由 capture/resolver 用 IP 还原原始域名。
//! * 回避：跳过 broadcast/network/保留地址；不覆盖 Tailnet/局域网。
//! * 双栈：A 查询给 IPv4，AAAA 查询给 IPv6；用户可关闭其中一族。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::Mutex;

#[derive(Debug, Clone, Copy)]
pub enum AddressFamily {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct FakeIpConfig {
    pub v4_cidr: Ipv4Net,
    pub v6_cidr: Ipv6Net,
    pub ttl: Duration,
    pub enable_v4: bool,
    pub enable_v6: bool,
    /// 不参与 Fake 分配的网段（Tailnet、局域网、回环、保留等）。
    pub avoid: Vec<IpNet>,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            v4_cidr: "198.18.0.0/15".parse().unwrap(),
            v6_cidr: "fc00:1::/64".parse().unwrap(),
            ttl: Duration::from_secs(10 * 60),
            enable_v4: true,
            enable_v6: true,
            avoid: [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "100.64.0.0/10",
                "::1/128",
                "fe80::/10",
                "fd7a:115c:a1e0::/48",
            ]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    ip: IpAddr,
    expire: Instant,
}

#[derive(Debug)]
pub struct FakeIpPool {
    cfg: FakeIpConfig,
    forward: DashMap<(String, AddressFamilyKey), Entry>,
    reverse: DashMap<IpAddr, (String, Instant)>,
    next_v4: Mutex<u32>,
    next_v6: Mutex<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFamilyKey {
    V4,
    V6,
}

impl From<AddressFamily> for AddressFamilyKey {
    fn from(f: AddressFamily) -> Self {
        match f {
            AddressFamily::V4 => Self::V4,
            AddressFamily::V6 => Self::V6,
        }
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new(FakeIpConfig::default())
    }
}

impl FakeIpPool {
    pub fn new(cfg: FakeIpConfig) -> Self {
        // V4 起始：跳过 network 地址；V6 起始：跳过 ::0。
        let v4_start = u32::from(cfg.v4_cidr.network()).saturating_add(1);
        let v6_start = u128::from(cfg.v6_cidr.network()).saturating_add(1);
        Self {
            cfg,
            forward: DashMap::new(),
            reverse: DashMap::new(),
            next_v4: Mutex::new(v4_start),
            next_v6: Mutex::new(v6_start),
        }
    }

    pub fn config(&self) -> &FakeIpConfig {
        &self.cfg
    }

    pub fn enabled_for(&self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::V4 => self.cfg.enable_v4,
            AddressFamily::V6 => self.cfg.enable_v6,
        }
    }

    /// 主入口：为某个 host + 协议族分配一个 Fake IP。
    /// 返回 None 表示该协议族被禁用或地址池耗尽。
    pub fn alloc(&self, host: &str, family: AddressFamily) -> Option<IpAddr> {
        if !self.enabled_for(family) {
            return None;
        }
        let key = (host.to_lowercase(), AddressFamilyKey::from(family));

        // 命中且未过期：续期返回。
        if let Some(mut entry) = self.forward.get_mut(&key) {
            if entry.expire > Instant::now() {
                entry.expire = Instant::now() + self.cfg.ttl;
                return Some(entry.ip);
            }
        }

        let ip = self.allocate_new(family)?;
        let expire = Instant::now() + self.cfg.ttl;
        self.forward.insert(key, Entry { ip, expire });
        self.reverse.insert(ip, (host.to_lowercase(), expire));
        Some(ip)
    }

    /// 反查：从 Fake IP 还原域名。仅返回未过期记录。
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let entry = self.reverse.get(&ip)?;
        if entry.1 > Instant::now() {
            Some(entry.0.clone())
        } else {
            None
        }
    }

    /// 给定 IP 是否落在 Fake 池范围内（可用于 capture 判断走 fake 路径）。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.cfg.v4_cidr.contains(&v4),
            IpAddr::V6(v6) => self.cfg.v6_cidr.contains(&v6),
        }
    }

    /// 周期性回收过期项；调用者按需 schedule（推荐 60s 一次）。
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut purged = 0;
        self.forward.retain(|_, e| {
            let alive = e.expire > now;
            if !alive {
                purged += 1;
            }
            alive
        });
        self.reverse.retain(|_, (_, exp)| *exp > now);
        purged
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Clash 兼容 `/cache/fakeip/flush` —— 清空全部映射。返回被清条数。
    pub fn clear(&self) -> usize {
        let n = self.forward.len();
        self.forward.clear();
        self.reverse.clear();
        n
    }

    fn allocate_new(&self, family: AddressFamily) -> Option<IpAddr> {
        match family {
            AddressFamily::V4 => self.next_v4_addr(),
            AddressFamily::V6 => self.next_v6_addr(),
        }
    }

    fn next_v4_addr(&self) -> Option<IpAddr> {
        let net = self.cfg.v4_cidr;
        let start = u32::from(net.network());
        let end = u32::from(net.broadcast());
        let mut g = self.next_v4.lock();
        let mut tries = 0u64;
        let span = (end - start).saturating_sub(1) as u64;
        while tries <= span {
            if *g >= end {
                *g = start.saturating_add(1); // 跳过 network 地址
            }
            let candidate = Ipv4Addr::from(*g);
            *g = g.saturating_add(1);
            tries += 1;
            if candidate == net.broadcast() {
                continue;
            }
            let ip = IpAddr::V4(candidate);
            if self.is_acceptable(ip) {
                return Some(ip);
            }
        }
        None
    }

    fn next_v6_addr(&self) -> Option<IpAddr> {
        let net = self.cfg.v6_cidr;
        let start = u128::from(net.network());
        // /64 范围太大，按 16-bit 子集做线性走，足够小型部署。
        let end = start.saturating_add(1 << 32);
        let mut g = self.next_v6.lock();
        let mut tries = 0u64;
        while tries < 1 << 16 {
            if *g >= end {
                *g = start.saturating_add(1);
            }
            let candidate = Ipv6Addr::from(*g);
            *g = g.saturating_add(1);
            tries += 1;
            let ip = IpAddr::V6(candidate);
            if self.is_acceptable(ip) {
                return Some(ip);
            }
        }
        None
    }

    fn is_acceptable(&self, ip: IpAddr) -> bool {
        if self.reverse.contains_key(&ip) {
            return false;
        }
        !self.cfg.avoid.iter().any(|n| n.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_v4_and_reverse() {
        let pool = FakeIpPool::default();
        let ip = pool.alloc("youtube.com", AddressFamily::V4).unwrap();
        assert!(matches!(ip, IpAddr::V4(_)));
        assert!(pool.contains(ip));
        assert_eq!(pool.lookup(ip).as_deref(), Some("youtube.com"));
        let ip2 = pool.alloc("youtube.com", AddressFamily::V4).unwrap();
        assert_eq!(ip, ip2, "同一域名应返回同一 Fake IP");
    }

    #[test]
    fn alloc_v6_returns_v6() {
        let pool = FakeIpPool::default();
        let ip = pool.alloc("netflix.com", AddressFamily::V6).unwrap();
        assert!(matches!(ip, IpAddr::V6(_)));
        assert_eq!(pool.lookup(ip).as_deref(), Some("netflix.com"));
    }

    #[test]
    fn dual_stack_independent() {
        let pool = FakeIpPool::default();
        let v4 = pool.alloc("github.com", AddressFamily::V4).unwrap();
        let v6 = pool.alloc("github.com", AddressFamily::V6).unwrap();
        assert!(v4.is_ipv4());
        assert!(v6.is_ipv6());
        assert_ne!(v4, v6);
    }

    #[test]
    fn disabled_family_returns_none() {
        let cfg = FakeIpConfig {
            enable_v6: false,
            ..FakeIpConfig::default()
        };
        let pool = FakeIpPool::new(cfg);
        assert!(pool.alloc("a.com", AddressFamily::V4).is_some());
        assert!(pool.alloc("a.com", AddressFamily::V6).is_none());
    }

    #[test]
    fn expired_entries_purged() {
        let cfg = FakeIpConfig {
            ttl: Duration::from_millis(20),
            ..FakeIpConfig::default()
        };
        let pool = FakeIpPool::new(cfg);
        let ip = pool.alloc("x.com", AddressFamily::V4).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(pool.lookup(ip), None);
        let purged = pool.purge_expired();
        assert!(purged >= 1);
    }

    #[test]
    fn avoid_lan_addresses() {
        let cfg = FakeIpConfig {
            v4_cidr: "192.168.0.0/16".parse().unwrap(), // 故意挑被 avoid 的网段
            ..FakeIpConfig::default()
        };
        let pool = FakeIpPool::new(cfg);
        assert!(pool.alloc("a.com", AddressFamily::V4).is_none());
    }
}
