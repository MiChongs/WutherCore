//! 把 TUN/TProxy 看到的"原始 dst"翻译成"出站可用 host" —— 与 mihomo
//! `tunnel/tunnel.go::preHandleMetadata`（L284-310）一一对齐。
//!
//! ## 为什么需要这一层
//! 用户启用 `resolver: hijack` 后，所有 DNS A 查询返回 Fake-IP（198.18.x.y）。
//! 浏览器 connect 到 Fake-IP，TUN 看到的 dst 是 198.18.0.5:443。
//! 如果直接把 "198.18.0.5" 作为 host 喂给 outbound（trojan/vmess/...），
//! 远端代理服务器收到的指令是 "替我连 198.18.0.5:443" —— 198.18/15 是 RFC 6890
//! 内部段，代理服务器立刻 ConnRefuse / Timeout。表象：URLTest 延迟正常（代理本身可联通）
//! 但应用流量永远走不出去。
//!
//! 修复 = mihomo 等价的"反查 + Host 字段"：
//! 1. 调用方明确给出 fake_host（事件路径自带）→ 直接用。
//! 2. `FakeIpPool::lookup(ip)` 命中 → host=domain。
//! 3. 落 fake-ip 段但 lookup 缺记录（缓存过期 / 客户端复用旧 IP）→ 标 missing，
//!    上层 abort 而不是默默把内部 IP 喂给代理。
//! 4. 真实 IP 段 → 原样字符串。

use std::net::{IpAddr, SocketAddr};

use core_resolver::FakeIpPool;

/// dashboard `metadata.dnsMode` —— 与 mihomo `constant/dns.go` 对齐。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    /// 真实 IP，未走 enhanced DNS。
    Normal,
    /// Fake-IP 反查命中（mihomo C.DNSFakeIP）。
    FakeIp,
    /// Hosts/Mapping 反查命中（mihomo C.DNSMapping）。
    DnsMapping,
}

impl DnsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::FakeIp => "fake-ip",
            Self::DnsMapping => "redir-host",
        }
    }
}

/// "TUN 看到的原始 dst" → "outbound 应该 connect 的目标"。
#[derive(Debug, Clone)]
pub struct DialTarget {
    /// 给 `Runtime::dial` 的 host 字符串：domain（fake-ip 反查命中）或 IP literal。
    pub host: String,
    /// 原始 dst IP（**不**清零，便于 dashboard `metadata.destinationIP` 显示）。
    pub original_dst_ip: IpAddr,
    pub original_dst_port: u16,
    pub dns_mode: DnsMode,
    /// `true` = dst 落 fake-ip 段但 lookup 缺记录 —— 调用方应 abort dial，
    /// 与 mihomo `fake DNS record %s missing` 行为对齐。
    pub fake_ip_missing: bool,
}

/// 构造 [`DialTarget`]。
///
/// `fake_host` 优先级最高（事件路径上 sniffer / DNS sniff 已经给出 SNI/Host）。
pub fn build_dial_target(
    pool: &FakeIpPool,
    original_dst: SocketAddr,
    fake_host: Option<&str>,
) -> DialTarget {
    let ip = original_dst.ip();
    let port = original_dst.port();

    // 1. 调用方明确给了 fake_host（事件路径快路径）
    if let Some(h) = fake_host.filter(|s| !s.is_empty()) {
        return DialTarget {
            host: h.to_string(),
            original_dst_ip: ip,
            original_dst_port: port,
            dns_mode: DnsMode::DnsMapping,
            fake_ip_missing: false,
        };
    }

    // 2. lookup 命中 → 用 domain；区分是 fake-ip 段还是真实 IP 的 mapping
    if let Some(domain) = pool.lookup(ip) {
        let mode = if pool.contains(ip) {
            DnsMode::FakeIp
        } else {
            DnsMode::DnsMapping
        };
        return DialTarget {
            host: domain,
            original_dst_ip: ip,
            original_dst_port: port,
            dns_mode: mode,
            fake_ip_missing: false,
        };
    }

    // 3. fake-ip 段内但 lookup 缺记录（缓存过期 / 客户端复用旧 IP）→ abort
    if pool.contains(ip) {
        return DialTarget {
            host: ip.to_string(),
            original_dst_ip: ip,
            original_dst_port: port,
            dns_mode: DnsMode::FakeIp,
            fake_ip_missing: true,
        };
    }

    // 4. 真实 IP，原样
    DialTarget {
        host: ip.to_string(),
        original_dst_ip: ip,
        original_dst_port: port,
        dns_mode: DnsMode::Normal,
        fake_ip_missing: false,
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use core_resolver::fake_ip::{AddressFamily, FakeIpConfig};
    use ipnet::{Ipv4Net, Ipv6Net};

    use super::*;

    fn fresh_pool() -> FakeIpPool {
        FakeIpPool::new(FakeIpConfig {
            v4_cidr: "198.18.0.0/15".parse::<Ipv4Net>().unwrap(),
            v6_cidr: "fc00:1::/64".parse::<Ipv6Net>().unwrap(),
            ..Default::default()
        })
    }

    fn sa(s: &str) -> SocketAddr {
        SocketAddr::from_str(s).unwrap()
    }

    #[test]
    fn explicit_fake_host_wins() {
        let p = fresh_pool();
        let t = build_dial_target(&p, sa("1.2.3.4:443"), Some("foo.com"));
        assert_eq!(t.host, "foo.com");
        assert_eq!(t.dns_mode, DnsMode::DnsMapping);
        assert!(!t.fake_ip_missing);
    }

    #[test]
    fn fake_ip_with_record_returns_domain() {
        let p = fresh_pool();
        let ip = p.alloc("bilibili.com", AddressFamily::V4).unwrap();
        let t = build_dial_target(&p, SocketAddr::new(ip, 443), None);
        assert_eq!(t.host, "bilibili.com");
        assert_eq!(t.dns_mode, DnsMode::FakeIp);
        assert!(!t.fake_ip_missing);
    }

    #[test]
    fn fake_ip_no_record_marks_missing() {
        let p = fresh_pool();
        // 198.18.0.5 在 fake 段内但没分配过
        let t = build_dial_target(&p, sa("198.18.0.5:443"), None);
        assert_eq!(t.dns_mode, DnsMode::FakeIp);
        assert!(t.fake_ip_missing);
    }

    #[test]
    fn real_ip_with_dns_mapping_returns_domain() {
        let p = fresh_pool();
        p.insert_mapping(
            "1.1.1.1".parse().unwrap(),
            "cloudflare-dns.com",
            Duration::from_secs(60),
        );

        let t = build_dial_target(&p, sa("1.1.1.1:443"), None);

        assert_eq!(t.host, "cloudflare-dns.com");
        assert_eq!(t.dns_mode, DnsMode::DnsMapping);
        assert!(!t.fake_ip_missing);
    }

    #[test]
    fn real_ip_passthrough() {
        let p = fresh_pool();
        let t = build_dial_target(&p, sa("1.1.1.1:443"), None);
        assert_eq!(t.host, "1.1.1.1");
        assert_eq!(t.dns_mode, DnsMode::Normal);
        assert!(!t.fake_ip_missing);
    }
}
