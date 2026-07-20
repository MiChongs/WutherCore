//! 语义保持的规则集 IR。
//!
//! sing-box source JSON 与后续 SRS 解码器都应产出这一结构，避免把一条复合规则
//! 展平为多个彼此独立的 classical 条目而丢失 AND / OR / invert 语义。

use std::net::IpAddr;

use ipnet::IpNet;
use regex::RegexSet;

/// 一条网络接口地址元数据。`is_own` 对齐 sing-box 对 tun/本机接口的排除语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetInterfaceAddress {
    pub interface_type: u8,
    pub address: IpNet,
    pub is_own: bool,
}

/// 一次规则集匹配所需的结构化上下文。
///
/// source 与 destination 字段刻意分槽。调用方没有相应元数据时传 `None`，
/// 对应 predicate 的结果就是 `false`，绝不能退化成匹配另一侧。
#[derive(Debug, Clone, Copy, Default)]
pub struct RulesetMatchContext<'a> {
    pub dst_host: &'a str,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub network: Option<&'a str>,
    pub process_name: Option<&'a str>,
    pub query_type: Option<u16>,
    pub process_path: Option<&'a str>,
    pub package_names: &'a [String],
    pub wifi_ssid: Option<&'a str>,
    pub wifi_bssid: Option<&'a str>,
    pub network_type: Option<u8>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub network_interface_addresses: &'a [RulesetInterfaceAddress],
    pub default_interface_addresses: &'a [IpNet],
}

/// 已校验的闭区间端口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    #[inline]
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// sing `common/domain` 的 succinct-set 解码结果。
///
/// child node id 恒为 `edge_index + 1`，所以只需 offsets + labels，无需为每个
/// edge 再保存目标 id。该结构同时供普通 domain matcher 与 AdGuard matcher 使用。
#[derive(Debug)]
pub struct CompactDomainSet {
    leaves: Vec<u64>,
    child_offsets: Vec<u32>,
    labels: Vec<u8>,
    terminal_count: usize,
}

impl CompactDomainSet {
    pub(crate) fn new(
        leaves: Vec<u64>,
        child_offsets: Vec<u32>,
        labels: Vec<u8>,
        terminal_count: usize,
    ) -> Self {
        Self {
            leaves,
            child_offsets,
            labels,
            terminal_count,
        }
    }

    fn terminal_count(&self) -> usize {
        self.terminal_count
    }

    fn is_leaf(&self, node: usize) -> bool {
        self.leaves
            .get(node / 64)
            .is_some_and(|word| word & (1u64 << (node % 64)) != 0)
    }

    fn children(&self, node: usize) -> std::ops::Range<usize> {
        let start = self.child_offsets[node] as usize;
        let end = self.child_offsets[node + 1] as usize;
        start..end
    }

    fn matches_domain(&self, domain: &str) -> bool {
        let key = reverse_domain(domain);
        let mut node = 0usize;
        for current in key.bytes() {
            let mut next_node = None;
            for edge in self.children(node) {
                let label = self.labels[edge];
                if label == b'\r' {
                    return true;
                }
                if label == b'\n' && current == b'.' && self.is_leaf(edge + 1) {
                    return true;
                }
                if label == current {
                    next_node = Some(edge + 1);
                    break;
                }
            }
            let Some(next) = next_node else {
                return false;
            };
            node = next;
        }
        if self.is_leaf(node) {
            return true;
        }
        self.children(node)
            .any(|edge| matches!(self.labels[edge], b'\r' | b'\n'))
    }

    fn matches_adguard(&self, domain: &str) -> bool {
        let mut key = reverse_domain(domain).into_bytes();
        let mut budget = 1_000_000usize;
        if self.adguard_has(&key, 0, 0, &mut budget) {
            return true;
        }
        loop {
            let mut suffix_key = Vec::with_capacity(key.len() + 1);
            suffix_key.push(b'\x08');
            suffix_key.extend_from_slice(&key);
            if self.adguard_has(&suffix_key, 0, 0, &mut budget) {
                return true;
            }
            let Some(index) = key.iter().position(|byte| *byte == b'.') else {
                return false;
            };
            key = key[index + 1..].to_vec();
        }
    }

    fn adguard_has(&self, key: &[u8], mut node: usize, depth: usize, budget: &mut usize) -> bool {
        const MAX_DEPTH: usize = 100;
        if depth > MAX_DEPTH || *budget == 0 {
            return false;
        }
        *budget -= 1;

        for (index, current) in key.iter().copied().enumerate() {
            let mut next_node = None;
            for edge in self.children(node) {
                let label = self.labels[edge];
                let child = edge + 1;
                if label == b'\r' {
                    return true;
                }
                if label == b'\n' && current == b'.' && self.is_leaf(child) {
                    return true;
                }
                if label == current {
                    next_node = Some(child);
                    break;
                }
                if matches!(label, b'*' | b'\x08') {
                    if self.adguard_has(&key[index..], child, depth + 1, budget) {
                        return true;
                    }
                    for next_index in index + 1..=key.len() {
                        if self.adguard_has(&key[next_index..], child, depth + 1, budget) {
                            return true;
                        }
                    }
                }
            }
            let Some(next) = next_node else {
                return false;
            };
            node = next;
        }
        if self.is_leaf(node) {
            return true;
        }
        for edge in self.children(node) {
            let label = self.labels[edge];
            if matches!(label, b'\r' | b'\n' | b'\x08') {
                return true;
            }
            if label == b'*' && self.adguard_has(&[], edge + 1, depth + 1, budget) {
                return true;
            }
        }
        false
    }
}

/// 已完成规范化或编译的叶子 predicate。
#[derive(Debug)]
pub enum RulesetPredicate {
    Domain(Vec<String>),
    DomainSuffix(Vec<String>),
    DomainKeyword(Vec<String>),
    DomainRegex(RegexSet),
    DstIpCidr(Vec<IpNet>),
    SrcIpCidr(Vec<IpNet>),
    DstPort(Vec<PortRange>),
    SrcPort(Vec<PortRange>),
    ProcessName(Vec<String>),
    Network(Vec<String>),
    SingboxDomainMatcher(CompactDomainSet),
    SingboxDomainKeyword(Vec<String>),
    SingboxDomainRegex(RegexSet),
    SingboxNetwork(Vec<String>),
    QueryType(Vec<u16>),
    ProcessPath(Vec<String>),
    ProcessPathRegex(RegexSet),
    PackageName(Vec<String>),
    PackageNameRegex(RegexSet),
    WifiSsid(Vec<String>),
    WifiBssid(Vec<String>),
    NetworkType(Vec<u8>),
    NetworkIsExpensive,
    NetworkIsConstrained,
    NetworkInterfaceAddress(Vec<(u8, Vec<IpNet>)>),
    DefaultInterfaceAddress(Vec<IpNet>),
    AdGuardDomainMatcher(CompactDomainSet),
}

impl RulesetPredicate {
    fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        match self {
            Self::Domain(domains) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && domains.iter().any(|domain| host == *domain)
            }
            Self::DomainSuffix(suffixes) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty()
                    && suffixes
                        .iter()
                        .any(|suffix| domain_has_suffix(&host, suffix))
            }
            Self::DomainKeyword(keywords) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && keywords.iter().any(|keyword| host.contains(keyword))
            }
            Self::DomainRegex(regex) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && regex.is_match(&host)
            }
            Self::DstIpCidr(networks) => destination_ip(ctx)
                .map(|ip| networks.iter().any(|network| network.contains(&ip)))
                .unwrap_or(false),
            Self::SrcIpCidr(networks) => ctx
                .src_ip
                .map(|ip| networks.iter().any(|network| network.contains(&ip)))
                .unwrap_or(false),
            Self::DstPort(ranges) => ctx
                .dst_port
                .map(|port| ranges.iter().any(|range| range.contains(port)))
                .unwrap_or(false),
            Self::SrcPort(ranges) => ctx
                .src_port
                .map(|port| ranges.iter().any(|range| range.contains(port)))
                .unwrap_or(false),
            Self::ProcessName(names) => ctx
                .process_name
                .map(|name| names.iter().any(|candidate| candidate == name))
                .unwrap_or(false),
            Self::Network(networks) => ctx
                .network
                .map(|network| {
                    networks
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(network))
                })
                .unwrap_or(false),
            Self::SingboxDomainMatcher(matcher) => {
                let host = singbox_domain(ctx.dst_host);
                !host.is_empty() && matcher.matches_domain(&host)
            }
            Self::SingboxDomainKeyword(keywords) => {
                let host = singbox_domain(ctx.dst_host);
                !host.is_empty() && keywords.iter().any(|keyword| host.contains(keyword))
            }
            Self::SingboxDomainRegex(regex) => {
                let host = singbox_domain(ctx.dst_host);
                !host.is_empty() && regex.is_match(&host)
            }
            Self::SingboxNetwork(networks) => ctx
                .network
                .map(|network| networks.iter().any(|candidate| candidate == network))
                .unwrap_or(false),
            Self::QueryType(types) => ctx
                .query_type
                .filter(|query_type| *query_type != 0)
                .map(|query_type| types.contains(&query_type))
                .unwrap_or(false),
            Self::ProcessPath(paths) => {
                ctx.process_path
                    .filter(|path| !path.is_empty())
                    .map(|path| paths.iter().any(|candidate| candidate == path))
                    .unwrap_or(false)
                    || (cfg!(target_os = "android")
                        && ctx
                            .package_names
                            .iter()
                            .any(|package| paths.contains(package)))
            }
            Self::ProcessPathRegex(regex) => ctx
                .process_path
                .filter(|path| !path.is_empty())
                .map(|path| regex.is_match(path))
                .unwrap_or(false),
            Self::PackageName(packages) => ctx
                .package_names
                .iter()
                .any(|package| packages.contains(package)),
            Self::PackageNameRegex(regex) => ctx
                .package_names
                .iter()
                .any(|package| regex.is_match(package)),
            Self::WifiSsid(values) => ctx
                .wifi_ssid
                .map(|ssid| values.iter().any(|candidate| candidate == ssid))
                .unwrap_or(false),
            Self::WifiBssid(values) => ctx
                .wifi_bssid
                .map(normalize_wifi_bssid)
                .map(|bssid| values.iter().any(|candidate| candidate == &bssid))
                .unwrap_or(false),
            Self::NetworkType(types) => ctx
                .network_type
                .map(|network_type| types.contains(&network_type))
                .unwrap_or(false),
            Self::NetworkIsExpensive => ctx.network_is_expensive == Some(true),
            Self::NetworkIsConstrained => ctx.network_is_constrained == Some(true),
            Self::NetworkInterfaceAddress(requirements) => {
                !ctx.network_interface_addresses.is_empty()
                    && requirements.iter().all(|(interface_type, prefixes)| {
                        ctx.network_interface_addresses.iter().any(|interface| {
                            !interface.is_own
                                && interface.interface_type == *interface_type
                                && prefixes
                                    .iter()
                                    .any(|prefix| ip_networks_overlap(prefix, &interface.address))
                        })
                    })
            }
            Self::DefaultInterfaceAddress(prefixes) => {
                !ctx.default_interface_addresses.is_empty()
                    && prefixes.iter().all(|prefix| {
                        ctx.default_interface_addresses
                            .iter()
                            .any(|address| ip_networks_overlap(prefix, address))
                    })
            }
            Self::AdGuardDomainMatcher(matcher) => {
                let host = singbox_domain(ctx.dst_host);
                !host.is_empty() && matcher.matches_adguard(&host)
            }
        }
    }

    fn item_count(&self) -> usize {
        match self {
            Self::Domain(items)
            | Self::DomainSuffix(items)
            | Self::DomainKeyword(items)
            | Self::ProcessName(items)
            | Self::Network(items)
            | Self::SingboxDomainKeyword(items)
            | Self::SingboxNetwork(items)
            | Self::ProcessPath(items)
            | Self::PackageName(items)
            | Self::WifiSsid(items)
            | Self::WifiBssid(items) => items.len(),
            Self::DomainRegex(items)
            | Self::SingboxDomainRegex(items)
            | Self::ProcessPathRegex(items)
            | Self::PackageNameRegex(items) => items.len(),
            Self::DstIpCidr(items) | Self::SrcIpCidr(items) => items.len(),
            Self::DstPort(items) | Self::SrcPort(items) => items.len(),
            Self::SingboxDomainMatcher(items) | Self::AdGuardDomainMatcher(items) => {
                items.terminal_count()
            }
            Self::QueryType(items) => items.len(),
            Self::NetworkType(items) => items.len(),
            Self::NetworkIsExpensive | Self::NetworkIsConstrained => 1,
            Self::NetworkInterfaceAddress(items) => {
                items.iter().map(|(_, prefixes)| prefixes.len()).sum()
            }
            Self::DefaultInterfaceAddress(items) => items.len(),
        }
    }
}

/// 可由 JSON、SRS 等前端共享的布尔表达式树。
#[derive(Debug)]
pub enum RulesetExpr {
    Any(Vec<RulesetExpr>),
    All(Vec<RulesetExpr>),
    Not(Box<RulesetExpr>),
    Predicate(RulesetPredicate),
}

impl RulesetExpr {
    pub fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        match self {
            Self::Any(children) => children.iter().any(|child| child.matches(ctx)),
            Self::All(children) => children.iter().all(|child| child.matches(ctx)),
            Self::Not(child) => !child.matches(ctx),
            Self::Predicate(predicate) => predicate.matches(ctx),
        }
    }

    /// 统计叶子值数量，用于 provider 状态展示。
    pub fn item_count(&self) -> usize {
        match self {
            Self::Any(children) | Self::All(children) => {
                children.iter().map(Self::item_count).sum()
            }
            Self::Not(child) => child.item_count(),
            Self::Predicate(predicate) => predicate.item_count(),
        }
    }
}

/// 一份完整、已校验且可直接求值的语义规则集。
#[derive(Debug)]
pub struct RulesetProgram {
    version: u8,
    rule_count: usize,
    root: RulesetExpr,
}

impl RulesetProgram {
    pub fn new(version: u8, rule_count: usize, root: RulesetExpr) -> Self {
        Self {
            version,
            rule_count,
            root,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn item_count(&self) -> usize {
        self.root.item_count()
    }

    pub fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        self.root.matches(ctx)
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn singbox_domain(value: &str) -> String {
    value.to_lowercase()
}

fn reverse_domain(value: &str) -> String {
    value.chars().rev().collect()
}

fn normalize_wifi_bssid(value: &str) -> String {
    let trimmed = value.trim();
    let compact = trimmed
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | '.'))
        .collect::<String>();
    if compact.len() == 12 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return compact
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| std::str::from_utf8(chunk).expect("ASCII hex"))
            .collect::<Vec<_>>()
            .join(":")
            .to_ascii_lowercase();
    }
    trimmed.to_owned()
}

fn ip_networks_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

fn domain_has_suffix(host: &str, suffix: &str) -> bool {
    // sing-box 以 leading dot 区分两种语义：
    // * example.com  => root + subdomain
    // * .example.com => 仅 subdomain
    if suffix.starts_with('.') {
        return suffix.len() > 1 && host.len() > suffix.len() && host.ends_with(suffix);
    }
    host == suffix
        || (host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

fn destination_ip(ctx: &RulesetMatchContext<'_>) -> Option<IpAddr> {
    ctx.dst_ip.or_else(|| ctx.dst_host.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_source_metadata_does_not_fall_back_to_destination() {
        let expression = RulesetExpr::Predicate(RulesetPredicate::SrcIpCidr(vec![
            "10.0.0.0/8".parse().unwrap(),
        ]));
        let ctx = RulesetMatchContext {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        assert!(!expression.matches(&ctx));
    }

    #[test]
    fn wifi_bssid_accepts_canonical_cisco_and_compact_forms() {
        let expression = RulesetExpr::Predicate(RulesetPredicate::WifiBssid(vec![
            "aa:bb:cc:dd:ee:ff".into(),
        ]));
        for bssid in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aabb.ccdd.eeff",
            "aabbccddeeff",
        ] {
            assert!(expression.matches(&RulesetMatchContext {
                wifi_bssid: Some(bssid),
                ..Default::default()
            }));
        }
    }
}
