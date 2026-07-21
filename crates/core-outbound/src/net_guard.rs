//! 出站目标安全检查 —— 挡掉控制面 SSRF / 订阅 fetch 打到内网与云元数据的路径。
//!
//! 默认策略：只允许**全局单播**地址。以下一律拒绝：
//! * loopback / unspecified
//! * RFC1918、链路本地、CGNAT（100.64/10）、benchmark（198.18/15）
//! * IPv6 ULA / 链路本地 / 唯一本地
//! * 云元数据主机名（`metadata.google.internal` 等）与 `169.254.169.254`
//!
//! 这是 **default-deny private**。实验室若必须探测内网，应走独立诊断工具，
//! 而不是 URLTest / 订阅拉取。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 主机名或字面 IP 是否被策略禁止（在解析之前就能拦的部分）。
pub fn is_blocked_host_literal(host: &str) -> bool {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if host.is_empty() {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "metadata"
            | "metadata.google.internal"
            | "metadata.goog"
            | "instance-data"
    ) || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    false
}

/// 解析后的 IP 是否禁止作为 fetch / URLTest 目标。
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_link_local()
        || ip.is_private()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return true;
    }
    let o = ip.octets();
    // CGNAT 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return true;
    }
    // 0.0.0.0/8
    if o[0] == 0 {
        return true;
    }
    // 192.0.0.0/24 IETF protocol assignments (incl. some special-use)
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // 198.18.0.0/15 benchmark
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    // 云元数据链路本地常见地址
    if ip == Ipv4Addr::new(169, 254, 169, 254) {
        return true;
    }
    false
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    // IPv4-mapped：按内嵌 v4 判断
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    let seg = ip.segments();
    // fe80::/10 link-local
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 unique local
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // 2001:db8::/32 documentation
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return true;
    }
    false
}

/// 供 URLTest / fetch 使用的统一错误文案。
pub fn blocked_target_message(target: &str) -> String {
    format!(
        "refusing non-public target \"{target}\" (loopback/private/link-local/metadata blocked)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_metadata() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_host_literal("localhost"));
        assert!(is_blocked_host_literal("metadata.google.internal"));
        assert!(is_blocked_host_literal("169.254.169.254"));
        assert!(!is_blocked_host_literal("www.gstatic.com"));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
    }
}
