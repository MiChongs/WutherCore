//! 高速规则匹配器：编译后的 trie / set / cidr / 关键字 / 正则 复合体。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use ahash::{AHashMap, AHashSet};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::RwLock;
use regex::RegexSet;
use thiserror::Error;
use tokio::sync::watch;

use crate::ir::{RulesetMatchContext, RulesetProgram};

const MAX_IP_PREFIX_SNAPSHOT_ITEMS: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RulesetPrefixError {
    #[error("destination IP ranges expand beyond the snapshot limit of {limit} prefixes")]
    TooManyPrefixes { limit: usize },
    #[error("destination IP prefix snapshot allocation failed")]
    AllocationFailed,
    #[error("destination {family} range starts after its end")]
    InvalidRange { family: &'static str },
}

/// How the published prefixes relate to the ruleset's full matching semantics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RulesetIpPrefixSemantics {
    /// The ruleset itself is exactly the union of the published destination prefixes.
    Exact,
    /// Prefixes were extracted with sing-box `RuleSet.ExtractIPSet` semantics.
    ///
    /// Surrounding logical conditions, inversion and non-IP predicates are not
    /// represented. This is intentionally compatible with sing-box
    /// `route_address_set`, but consumers that require an exact set (especially
    /// exclusion/bypass paths) can reject this status.
    Extracted,
    /// The loaded ruleset contains no destination-IP set.
    #[default]
    NotIpSet,
}

pub type RulesetDestinationPrefixes = (
    RulesetIpPrefixSemantics,
    Arc<Vec<Ipv4Net>>,
    Arc<Vec<Ipv6Net>>,
);

/// Readiness and safety status for one requested ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesetIpPrefixStatus {
    Ready {
        semantics: RulesetIpPrefixSemantics,
    },
    /// The manager knows this name but has not completed its first load.
    Pending,
    /// The first load failed and there is no last-known-good matcher.
    Unavailable,
    /// The name was never declared or loaded.
    Missing,
    TooManyPrefixes {
        limit: usize,
    },
    AllocationFailed,
    InvalidRange {
        family: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetIpPrefixSet {
    pub name: String,
    pub status: RulesetIpPrefixStatus,
    pub ipv4: Arc<Vec<Ipv4Net>>,
    pub ipv6: Arc<Vec<Ipv6Net>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetIpPrefixSnapshot {
    /// Monotonic index revision at which all sets in this snapshot were read.
    pub revision: u64,
    /// Requested sets in first-occurrence order. Duplicate names are removed.
    pub sets: Arc<Vec<RulesetIpPrefixSet>>,
}

/// classical 行解析后形态。
#[derive(Debug, Clone)]
pub struct ClassicalEntry {
    pub kind: ClassicalKind,
    pub value: String,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SrcIpCidr,
    DstPort,
    SrcPort,
    ProcessName,
}

impl ClassicalKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "DOMAIN" => Self::Domain,
            "DOMAIN-SUFFIX" => Self::DomainSuffix,
            "DOMAIN-KEYWORD" => Self::DomainKeyword,
            "DOMAIN-REGEX" => Self::DomainRegex,
            "IP-CIDR" | "IP-CIDR6" => Self::IpCidr,
            "SRC-IP-CIDR" => Self::SrcIpCidr,
            "DST-PORT" => Self::DstPort,
            "SRC-PORT" => Self::SrcPort,
            "PROCESS-NAME" => Self::ProcessName,
            _ => return None,
        })
    }
}

/// 单条规则集编译产物 —— 内部不可变 + 引用计数共享。
#[derive(Debug, Default)]
pub struct RulesetMatcher {
    pub name: String,
    /// 精确域名（已小写 + 去尾点）
    domains: AHashSet<String>,
    /// 后缀集合（转为反向 trie 查询）
    suffix_trie: SuffixTrie,
    /// 子串关键字
    keywords: Vec<String>,
    /// 正则集合
    regex_set: Option<RegexSet>,
    /// CIDR：v4 与 v6 分桶
    cidr_v4: Vec<ipnet::Ipv4Net>,
    cidr_v6: Vec<ipnet::Ipv6Net>,
    /// source CIDR 与 destination CIDR 严格分桶。
    src_cidr_v4: Vec<ipnet::Ipv4Net>,
    src_cidr_v6: Vec<ipnet::Ipv6Net>,
    /// 进程名（精确）
    processes: AHashSet<String>,
    /// 端口（单值或区间，u16..=u16）
    ports: Vec<(u16, u16)>,
    /// source 端口，不能退化为 destination 端口。
    src_ports: Vec<(u16, u16)>,
    /// 原始 classical 条目，便于 explain。
    pub classical_count: usize,

    /// mihomo MRS domain succinct trie —— 比 suffix_trie + domains 更紧凑、
    /// 自带 wildcard 语义，几十 MB 域名集亦能 O(|key|) 查询。
    mrs_domain_set: Option<Arc<crate::parser::mrs::MrsDomainSet>>,
    /// mihomo MRS ipcidr 闭区间 v4 列表（已按 from 升序排序，二分查找）。
    mrs_v4_ranges: Vec<(u32, u32)>,
    /// 同上，IPv6。
    mrs_v6_ranges: Vec<(u128, u128)>,
    /// MRS 原始统计（domain count 或 ipcidr range count）。
    mrs_count: usize,

    /// sing-box JSON / SRS 共享的语义规则程序。
    semantic_program: Option<RulesetProgram>,

    /// 可供 TUN `route_address_set` 原子快照的 destination-only IP 前缀。
    destination_prefixes_v4: Arc<Vec<Ipv4Net>>,
    destination_prefixes_v6: Arc<Vec<Ipv6Net>>,
    destination_prefix_semantics: RulesetIpPrefixSemantics,
    destination_prefix_error: Option<RulesetPrefixError>,
}

impl RulesetMatcher {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// 把 classical 条目集合编译为 matcher。
    pub fn compile(name: impl Into<String>, entries: Vec<ClassicalEntry>) -> Self {
        let mut m = RulesetMatcher::new(name);
        let mut regex_pats: Vec<String> = Vec::new();
        let mut saw_destination_prefix = false;
        let mut saw_non_destination_rule = false;
        m.classical_count = entries.len();
        for e in entries {
            match e.kind {
                ClassicalKind::Domain => {
                    saw_non_destination_rule = true;
                    m.domains.insert(normalize_domain(&e.value));
                }
                ClassicalKind::DomainSuffix => {
                    saw_non_destination_rule = true;
                    m.suffix_trie.insert(&e.value);
                }
                ClassicalKind::DomainKeyword => {
                    saw_non_destination_rule = true;
                    m.keywords.push(e.value.to_ascii_lowercase());
                }
                ClassicalKind::DomainRegex => {
                    saw_non_destination_rule = true;
                    regex_pats.push(e.value);
                }
                ClassicalKind::IpCidr => {
                    if let Ok(net) = e.value.parse::<IpNet>() {
                        saw_destination_prefix = true;
                        match net {
                            IpNet::V4(v4) => m.cidr_v4.push(v4),
                            IpNet::V6(v6) => m.cidr_v6.push(v6),
                        }
                    } else {
                        // Parsers normally reject malformed CIDRs. If a caller
                        // constructs entries directly, never label an ignored
                        // item as an exact IP set.
                        saw_non_destination_rule = true;
                    }
                }
                ClassicalKind::SrcIpCidr => {
                    saw_non_destination_rule = true;
                    if let Ok(net) = e.value.parse::<IpNet>() {
                        match net {
                            IpNet::V4(v4) => m.src_cidr_v4.push(v4),
                            IpNet::V6(v6) => m.src_cidr_v6.push(v6),
                        }
                    }
                }
                ClassicalKind::DstPort => {
                    saw_non_destination_rule = true;
                    if let Some(range) = parse_port_range(&e.value) {
                        m.ports.push(range);
                    }
                }
                ClassicalKind::SrcPort => {
                    saw_non_destination_rule = true;
                    if let Some(range) = parse_port_range(&e.value) {
                        m.src_ports.push(range);
                    }
                }
                ClassicalKind::ProcessName => {
                    saw_non_destination_rule = true;
                    m.processes.insert(e.value.to_ascii_lowercase());
                }
            }
        }
        if !regex_pats.is_empty() {
            if let Ok(rs) = RegexSet::new(&regex_pats) {
                m.regex_set = Some(rs);
            }
        }
        // 排序 CIDR 让长前缀优先（更精确）
        m.cidr_v4.sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.cidr_v6.sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.src_cidr_v4
            .sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        m.src_cidr_v6
            .sort_by_key(|n| std::cmp::Reverse(n.prefix_len()));
        let semantics = match (saw_destination_prefix, saw_non_destination_rule) {
            (true, false) => RulesetIpPrefixSemantics::Exact,
            (true, true) => RulesetIpPrefixSemantics::Extracted,
            (false, _) => RulesetIpPrefixSemantics::NotIpSet,
        };
        let prefixes = try_clone_prefixes(&m.cidr_v4, &m.cidr_v6)
            .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
        m.install_destination_prefixes(prefixes, semantics);
        m
    }

    /// 从纯 domain 列表（mihomo behavior=domain）编译：
    /// 项以 `+.` 开头视为后缀，否则视为精确。
    pub fn compile_domains(
        name: impl Into<String>,
        lines: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    return None;
                }
                if let Some(rest) = l.strip_prefix("+.") {
                    Some(ClassicalEntry {
                        kind: ClassicalKind::DomainSuffix,
                        value: rest.into(),
                        policy: None,
                    })
                } else if l.starts_with('.') {
                    Some(ClassicalEntry {
                        kind: ClassicalKind::DomainSuffix,
                        value: l[1..].into(),
                        policy: None,
                    })
                } else if l.starts_with('*') {
                    None // 简化：忽略复杂通配
                } else {
                    Some(ClassicalEntry {
                        kind: ClassicalKind::Domain,
                        value: l.into(),
                        policy: None,
                    })
                }
            })
            .collect();
        Self::compile(name, entries)
    }

    pub fn compile_ipcidr(
        name: impl Into<String>,
        lines: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    return None;
                }
                Some(ClassicalEntry {
                    kind: ClassicalKind::IpCidr,
                    value: l.into(),
                    policy: None,
                })
            })
            .collect();
        Self::compile(name, entries)
    }

    /// 把 [`crate::parser::RulesetCompiled`] 编译成 matcher。
    /// `Classical` 走老 [`Self::compile`] 路径；`Mrs` 把预编译产物挂到内部字段。
    pub fn compile_any(name: impl Into<String>, compiled: crate::parser::RulesetCompiled) -> Self {
        match compiled {
            crate::parser::RulesetCompiled::Classical(entries) => Self::compile(name, entries),
            crate::parser::RulesetCompiled::Semantic(program) => {
                Self::compile_semantic(name, program)
            }
            crate::parser::RulesetCompiled::Mrs(payload) => Self::compile_mrs(name, payload),
        }
    }

    pub fn compile_semantic(name: impl Into<String>, program: RulesetProgram) -> Self {
        let mut matcher = RulesetMatcher::new(name);
        let semantics = if program.is_exact_destination_ip_set() {
            RulesetIpPrefixSemantics::Exact
        } else {
            RulesetIpPrefixSemantics::Extracted
        };
        let prefixes = collect_program_prefixes(&program)
            .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
        let semantics = match &prefixes {
            Ok((ipv4, ipv6)) if ipv4.is_empty() && ipv6.is_empty() => {
                RulesetIpPrefixSemantics::NotIpSet
            }
            _ => semantics,
        };
        matcher.install_destination_prefixes(prefixes, semantics);
        matcher.semantic_program = Some(program);
        matcher
    }

    /// 把 mihomo MRS 预编译产物挂到 matcher。
    pub fn compile_mrs(name: impl Into<String>, payload: crate::parser::mrs::MrsPayload) -> Self {
        let mut m = RulesetMatcher::new(name);
        m.mrs_count = payload.count();
        match payload {
            crate::parser::mrs::MrsPayload::Domain { set, .. } => {
                m.mrs_domain_set = Some(set);
                m.install_destination_prefixes(
                    Ok((Vec::new(), Vec::new())),
                    RulesetIpPrefixSemantics::NotIpSet,
                );
            }
            crate::parser::mrs::MrsPayload::IpCidr { set, .. } => {
                // Arc<MrsIpCidrSet> → 拷贝一份排序好的 Vec 进 matcher 字段
                // （MrsIpCidrSet 内部已经排过序）。MrsIpCidrSet 不暴露所有权移动，
                // 直接 clone 出 v4/v6 ranges 即可。
                m.mrs_v4_ranges = set.v4_ranges.clone();
                m.mrs_v6_ranges = set.v6_ranges.clone();
                let prefixes = ranges_to_prefixes(&m.mrs_v4_ranges, &m.mrs_v6_ranges)
                    .and_then(|(ipv4, ipv6)| normalize_destination_prefixes(ipv4, ipv6));
                m.install_destination_prefixes(prefixes, RulesetIpPrefixSemantics::Exact);
            }
        }
        m
    }

    /// Return an immutable destination-prefix view for route-set consumers.
    ///
    /// The semantic label is essential: `Extracted` mirrors sing-box's
    /// `RuleSet.ExtractIPSet` compatibility behavior but is not equivalent to
    /// evaluating a conditional or inverted ruleset.
    pub fn destination_ip_prefixes(
        &self,
    ) -> Result<RulesetDestinationPrefixes, RulesetPrefixError> {
        if let Some(error) = &self.destination_prefix_error {
            return Err(error.clone());
        }
        Ok((
            self.destination_prefix_semantics,
            self.destination_prefixes_v4.clone(),
            self.destination_prefixes_v6.clone(),
        ))
    }

    fn install_destination_prefixes(
        &mut self,
        prefixes: Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError>,
        semantics: RulesetIpPrefixSemantics,
    ) {
        self.destination_prefix_semantics = semantics;
        match prefixes {
            Ok((ipv4, ipv6)) => {
                self.destination_prefixes_v4 = Arc::new(ipv4);
                self.destination_prefixes_v6 = Arc::new(ipv6);
                self.destination_prefix_error = None;
            }
            Err(error) => {
                self.destination_prefixes_v4 = Arc::new(Vec::new());
                self.destination_prefixes_v6 = Arc::new(Vec::new());
                self.destination_prefix_error = Some(error);
            }
        }
    }

    fn has_same_destination_prefixes(&self, other: &Self) -> bool {
        self.destination_prefix_semantics == other.destination_prefix_semantics
            && self.destination_prefix_error == other.destination_prefix_error
            && self.destination_prefixes_v4 == other.destination_prefixes_v4
            && self.destination_prefixes_v6 == other.destination_prefixes_v6
    }

    /// 主入口：判断 host/ip/port 是否命中。
    pub fn matches(
        &self,
        host: &str,
        ip: Option<IpAddr>,
        port: Option<u16>,
        process: Option<&str>,
    ) -> bool {
        self.matches_context(&RulesetMatchContext {
            dst_host: host,
            dst_ip: ip,
            dst_port: port,
            process_name: process,
            ..Default::default()
        })
    }

    /// 结构化匹配入口。新调用方应优先使用它，避免混淆 source / destination。
    pub fn matches_context(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        if let Some(program) = &self.semantic_program {
            return program.matches(ctx);
        }

        // 域名相关
        let host_lc = normalize_domain(ctx.dst_host);
        if !host_lc.is_empty() {
            if self.domains.contains(&host_lc) {
                return true;
            }
            if self.suffix_trie.matches(&host_lc) {
                return true;
            }
            for k in &self.keywords {
                if host_lc.contains(k) {
                    return true;
                }
            }
            if let Some(rs) = &self.regex_set {
                if rs.is_match(&host_lc) {
                    return true;
                }
            }
            // mihomo MRS domain succinct trie（含 wildcard 语义）
            if let Some(set) = &self.mrs_domain_set {
                if set.has(&host_lc) {
                    return true;
                }
            }
        }
        // IP / CIDR
        let resolved_ip = ctx.dst_ip.or_else(|| ctx.dst_host.parse::<IpAddr>().ok());
        if let Some(ip) = resolved_ip {
            match ip {
                IpAddr::V4(v) => {
                    if self.cidr_v4.iter().any(|n| n.contains(&v)) {
                        return true;
                    }
                    if !self.mrs_v4_ranges.is_empty()
                        && contains_range_v4(&self.mrs_v4_ranges, u32::from(v))
                    {
                        return true;
                    }
                }
                IpAddr::V6(v) => {
                    if self.cidr_v6.iter().any(|n| n.contains(&v)) {
                        return true;
                    }
                    if !self.mrs_v6_ranges.is_empty()
                        && contains_range_v6(&self.mrs_v6_ranges, u128::from(v))
                    {
                        return true;
                    }
                }
            }
        }
        if let Some(ip) = ctx.src_ip {
            match ip {
                IpAddr::V4(v) => {
                    if self.src_cidr_v4.iter().any(|n| n.contains(&v)) {
                        return true;
                    }
                }
                IpAddr::V6(v) => {
                    if self.src_cidr_v6.iter().any(|n| n.contains(&v)) {
                        return true;
                    }
                }
            }
        }
        // port
        if let Some(p) = ctx.dst_port {
            if self.ports.iter().any(|(lo, hi)| p >= *lo && p <= *hi) {
                return true;
            }
        }
        if let Some(p) = ctx.src_port {
            if self.src_ports.iter().any(|(lo, hi)| p >= *lo && p <= *hi) {
                return true;
            }
        }
        // process
        if let Some(name) = ctx.process_name {
            if self.processes.contains(&name.to_ascii_lowercase()) {
                return true;
            }
        }
        false
    }

    pub fn stats(&self) -> RulesetStats {
        // MRS domain set 的"domains"概念不能简单地映射到 self.domains.len()。
        // 我们把 mrs_count（header.count）记到一个独立字段，并在 cidr_* 里
        // 也累计 MRS v4/v6 ranges，便于 dashboard 总数显示。
        let domains_total = self.domains.len()
            + self
                .mrs_domain_set
                .as_ref()
                .map(|_| self.mrs_count)
                .unwrap_or(0);
        RulesetStats {
            domains: domains_total,
            suffixes: self.suffix_trie.len(),
            keywords: self.keywords.len(),
            regex: self.regex_set.as_ref().map(|r| r.len()).unwrap_or(0),
            cidr_v4: self.cidr_v4.len() + self.src_cidr_v4.len() + self.mrs_v4_ranges.len(),
            cidr_v6: self.cidr_v6.len() + self.src_cidr_v6.len() + self.mrs_v6_ranges.len(),
            processes: self.processes.len(),
            ports: self.ports.len() + self.src_ports.len(),
        }
    }
}

fn prefix_limit_error() -> RulesetPrefixError {
    RulesetPrefixError::TooManyPrefixes {
        limit: MAX_IP_PREFIX_SNAPSHOT_ITEMS,
    }
}

fn checked_prefix_total(v4: usize, v6: usize) -> Result<usize, RulesetPrefixError> {
    let total = v4.checked_add(v6).ok_or_else(prefix_limit_error)?;
    if total > MAX_IP_PREFIX_SNAPSHOT_ITEMS {
        return Err(prefix_limit_error());
    }
    Ok(total)
}

fn try_clone_prefixes(
    ipv4: &[Ipv4Net],
    ipv6: &[Ipv6Net],
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    checked_prefix_total(ipv4.len(), ipv6.len())?;
    let mut cloned_v4 = Vec::new();
    cloned_v4
        .try_reserve_exact(ipv4.len())
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    cloned_v4.extend_from_slice(ipv4);
    let mut cloned_v6 = Vec::new();
    cloned_v6
        .try_reserve_exact(ipv6.len())
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    cloned_v6.extend_from_slice(ipv6);
    Ok((cloned_v4, cloned_v6))
}

fn collect_program_prefixes(
    program: &RulesetProgram,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut error = None;
    let completed = program.visit_destination_ip_cidrs(|prefix| {
        let total = ipv4.len().saturating_add(ipv6.len());
        if total >= MAX_IP_PREFIX_SNAPSHOT_ITEMS {
            error = Some(prefix_limit_error());
            return false;
        }
        match prefix {
            IpNet::V4(prefix) => {
                if ipv4.try_reserve(1).is_err() {
                    error = Some(RulesetPrefixError::AllocationFailed);
                    return false;
                }
                ipv4.push(*prefix);
            }
            IpNet::V6(prefix) => {
                if ipv6.try_reserve(1).is_err() {
                    error = Some(RulesetPrefixError::AllocationFailed);
                    return false;
                }
                ipv6.push(*prefix);
            }
        }
        true
    });
    if !completed {
        return Err(error.unwrap_or_else(prefix_limit_error));
    }
    Ok((ipv4, ipv6))
}

fn normalize_destination_prefixes(
    mut ipv4: Vec<Ipv4Net>,
    mut ipv6: Vec<Ipv6Net>,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    checked_prefix_total(ipv4.len(), ipv6.len())?;
    for prefix in &mut ipv4 {
        *prefix = prefix.trunc();
    }
    for prefix in &mut ipv6 {
        *prefix = prefix.trunc();
    }
    aggregate_ipv4_in_place(&mut ipv4);
    aggregate_ipv6_in_place(&mut ipv6);
    Ok((ipv4, ipv6))
}

/// Aggregate sorted prefixes in their existing allocation. Besides avoiding
/// duplicate kernel-set entries, doing this in place prevents an untrusted
/// ruleset from forcing a second multi-million-item allocation.
fn aggregate_ipv4_in_place(prefixes: &mut Vec<Ipv4Net>) {
    prefixes.sort_unstable_by_key(|net| (u32::from(net.network()), net.prefix_len()));
    let original_len = prefixes.len();
    let mut write = 0usize;
    for read in 0..original_len {
        let mut candidate = prefixes[read];
        loop {
            if write == 0 {
                prefixes[write] = candidate;
                write += 1;
                break;
            }
            let previous = prefixes[write - 1];
            if previous.contains(&candidate) {
                break;
            }
            if candidate.contains(&previous) {
                write -= 1;
                continue;
            }
            let Some(parent) = previous.supernet() else {
                prefixes[write] = candidate;
                write += 1;
                break;
            };
            if previous.prefix_len() == candidate.prefix_len() && parent.contains(&candidate) {
                candidate = parent;
                write -= 1;
                continue;
            }
            prefixes[write] = candidate;
            write += 1;
            break;
        }
    }
    prefixes.truncate(write);
}

fn aggregate_ipv6_in_place(prefixes: &mut Vec<Ipv6Net>) {
    prefixes.sort_unstable_by_key(|net| (u128::from(net.network()), net.prefix_len()));
    let original_len = prefixes.len();
    let mut write = 0usize;
    for read in 0..original_len {
        let mut candidate = prefixes[read];
        loop {
            if write == 0 {
                prefixes[write] = candidate;
                write += 1;
                break;
            }
            let previous = prefixes[write - 1];
            if previous.contains(&candidate) {
                break;
            }
            if candidate.contains(&previous) {
                write -= 1;
                continue;
            }
            let Some(parent) = previous.supernet() else {
                prefixes[write] = candidate;
                write += 1;
                break;
            };
            if previous.prefix_len() == candidate.prefix_len() && parent.contains(&candidate) {
                candidate = parent;
                write -= 1;
                continue;
            }
            prefixes[write] = candidate;
            write += 1;
            break;
        }
    }
    prefixes.truncate(write);
}

fn ranges_to_prefixes(
    v4_ranges: &[(u32, u32)],
    v6_ranges: &[(u128, u128)],
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), RulesetPrefixError> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut total = 0usize;
    for &(start, end) in v4_ranges {
        append_ipv4_range(start, end, &mut ipv4, &mut total)?;
    }
    for &(start, end) in v6_ranges {
        append_ipv6_range(start, end, &mut ipv6, &mut total)?;
    }
    Ok((ipv4, ipv6))
}

fn reserve_prefix<T>(output: &mut Vec<T>, total: &mut usize) -> Result<(), RulesetPrefixError> {
    if *total >= MAX_IP_PREFIX_SNAPSHOT_ITEMS {
        return Err(prefix_limit_error());
    }
    output
        .try_reserve(1)
        .map_err(|_| RulesetPrefixError::AllocationFailed)?;
    *total += 1;
    Ok(())
}

fn append_ipv4_range(
    mut start: u32,
    end: u32,
    output: &mut Vec<Ipv4Net>,
    total: &mut usize,
) -> Result<(), RulesetPrefixError> {
    if start > end {
        return Err(RulesetPrefixError::InvalidRange { family: "IPv4" });
    }
    loop {
        let alignment_bits = start.trailing_zeros();
        let difference = end - start;
        let range_bits = if difference == u32::MAX {
            u32::BITS
        } else {
            u32::BITS - (difference + 1).leading_zeros() - 1
        };
        let host_bits = alignment_bits.min(range_bits);
        let prefix_len = (u32::BITS - host_bits) as u8;
        reserve_prefix(output, total)?;
        output.push(
            Ipv4Net::new(Ipv4Addr::from(start), prefix_len)
                .expect("computed IPv4 prefix length is valid"),
        );
        if host_bits == u32::BITS {
            break;
        }
        let block_size = 1u32 << host_bits;
        let Some(next) = start.checked_add(block_size) else {
            break;
        };
        if next > end {
            break;
        }
        start = next;
    }
    Ok(())
}

fn append_ipv6_range(
    mut start: u128,
    end: u128,
    output: &mut Vec<Ipv6Net>,
    total: &mut usize,
) -> Result<(), RulesetPrefixError> {
    if start > end {
        return Err(RulesetPrefixError::InvalidRange { family: "IPv6" });
    }
    loop {
        let alignment_bits = start.trailing_zeros();
        let difference = end - start;
        let range_bits = if difference == u128::MAX {
            u128::BITS
        } else {
            u128::BITS - (difference + 1).leading_zeros() - 1
        };
        let host_bits = alignment_bits.min(range_bits);
        let prefix_len = (u128::BITS - host_bits) as u8;
        reserve_prefix(output, total)?;
        output.push(
            Ipv6Net::new(Ipv6Addr::from(start), prefix_len)
                .expect("computed IPv6 prefix length is valid"),
        );
        if host_bits == u128::BITS {
            break;
        }
        let block_size = 1u128 << host_bits;
        let Some(next) = start.checked_add(block_size) else {
            break;
        };
        if next > end {
            break;
        }
        start = next;
    }
    Ok(())
}

#[inline]
fn contains_range_v4(ranges: &[(u32, u32)], ip: u32) -> bool {
    ranges
        .binary_search_by(|(from, to)| {
            if ip < *from {
                std::cmp::Ordering::Greater
            } else if ip > *to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[inline]
fn contains_range_v6(ranges: &[(u128, u128)], ip: u128) -> bool {
    ranges
        .binary_search_by(|(from, to)| {
            if ip < *from {
                std::cmp::Ordering::Greater
            } else if ip > *to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[derive(Debug, Clone, Default)]
pub struct RulesetStats {
    pub domains: usize,
    pub suffixes: usize,
    pub keywords: usize,
    pub regex: usize,
    pub cidr_v4: usize,
    pub cidr_v6: usize,
    pub processes: usize,
    pub ports: usize,
}

/* ---------------- 索引 ---------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesetAvailability {
    Pending,
    Unavailable,
}

#[derive(Debug, Default)]
struct RulesetIndexState {
    revision: u64,
    matchers: AHashMap<String, Arc<RulesetMatcher>>,
    availability: AHashMap<String, RulesetAvailability>,
}

/// 全局规则集索引；route 引擎查 `set:<name>` 时用它。
#[derive(Debug)]
pub struct RulesetIndex {
    state: RwLock<RulesetIndexState>,
    prefix_revisions: watch::Sender<u64>,
}

impl Default for RulesetIndex {
    fn default() -> Self {
        let (prefix_revisions, _receiver) = watch::channel(0);
        Self {
            state: RwLock::new(RulesetIndexState::default()),
            prefix_revisions,
        }
    }
}

impl RulesetIndex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Declare configured names before asynchronous loading starts.
    ///
    /// A destination-prefix consumer can therefore distinguish a pending
    /// provider from a misspelled/nonexistent set name.
    pub fn declare<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = {
            let mut state = self.state.write();
            let mut changed = false;
            for name in names {
                let name = name.into();
                if !state.matchers.contains_key(&name) && !state.availability.contains_key(&name) {
                    state
                        .availability
                        .insert(name, RulesetAvailability::Pending);
                    changed = true;
                }
            }
            changed.then(|| bump_prefix_revision(&mut state))
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    /// Mark an initial load failure without discarding a last-known-good set.
    pub fn mark_unavailable(&self, name: impl Into<String>) {
        let name = name.into();
        let revision = {
            let mut state = self.state.write();
            if state.matchers.contains_key(&name)
                || state.availability.get(&name) == Some(&RulesetAvailability::Unavailable)
            {
                None
            } else {
                state
                    .availability
                    .insert(name, RulesetAvailability::Unavailable);
                Some(bump_prefix_revision(&mut state))
            }
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    pub fn insert(&self, m: Arc<RulesetMatcher>) {
        let revision = {
            let mut state = self.state.write();
            let name = m.name.clone();
            let prefix_changed = match state.matchers.get(&name) {
                Some(previous) => !previous.has_same_destination_prefixes(&m),
                None => true,
            } || state.availability.contains_key(&name);
            state.matchers.insert(name.clone(), m);
            state.availability.remove(&name);
            prefix_changed.then(|| bump_prefix_revision(&mut state))
        };
        if let Some(revision) = revision {
            self.publish_prefix_revision(revision);
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<RulesetMatcher>> {
        self.state.read().matchers.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        self.state.read().matchers.keys().cloned().collect()
    }

    pub fn stats(&self) -> Vec<(String, RulesetStats)> {
        self.state
            .read()
            .matchers
            .iter()
            .map(|(k, v)| (k.clone(), v.stats()))
            .collect()
    }

    /// Current destination-prefix generation.
    pub fn ip_prefix_revision(&self) -> u64 {
        self.state.read().revision
    }

    /// Subscribe to desired-state changes. The receiver immediately contains
    /// the current generation; slow consumers may skip intermediate values and
    /// reconcile directly to the latest snapshot.
    pub fn subscribe_ip_prefix_updates(&self) -> watch::Receiver<u64> {
        self.prefix_revisions.subscribe()
    }

    /// Atomically read multiple named sets at one index generation.
    ///
    /// All requested names are represented, including pending, unavailable,
    /// missing and non-IP sets. Duplicate names are removed while preserving
    /// their first occurrence.
    pub fn ip_prefix_snapshot<S: AsRef<str>>(&self, names: &[S]) -> RulesetIpPrefixSnapshot {
        let state = self.state.read();
        build_ip_prefix_snapshot(&state, names)
    }

    /// Race-free initial read + update subscription.
    ///
    /// The receiver is created before the snapshot. Publication is monotonic,
    /// so an update racing either side is already visible in the snapshot or
    /// remains pending in the receiver. The two revision values may differ
    /// during that narrow window; consumers should immediately reconcile again
    /// when the receiver is newer.
    pub fn ip_prefix_snapshot_and_subscribe<S: AsRef<str>>(
        &self,
        names: &[S],
    ) -> (RulesetIpPrefixSnapshot, watch::Receiver<u64>) {
        let receiver = self.prefix_revisions.subscribe();
        let snapshot = self.ip_prefix_snapshot(names);
        (snapshot, receiver)
    }

    fn publish_prefix_revision(&self, revision: u64) {
        // Concurrent writers commit under the state RwLock but publish after
        // releasing it. Only move the watch value forward so a slower writer
        // can never overwrite a newer desired state.
        self.prefix_revisions.send_if_modified(|published| {
            if revision > *published {
                *published = revision;
                true
            } else {
                false
            }
        });
    }
}

fn bump_prefix_revision(state: &mut RulesetIndexState) -> u64 {
    state.revision = state
        .revision
        .checked_add(1)
        .expect("ruleset prefix revision exhausted");
    state.revision
}

fn build_ip_prefix_snapshot<S: AsRef<str>>(
    state: &RulesetIndexState,
    names: &[S],
) -> RulesetIpPrefixSnapshot {
    let mut seen = AHashSet::new();
    let mut sets = Vec::new();
    for requested in names {
        let name = requested.as_ref();
        if !seen.insert(name) {
            continue;
        }
        let (status, ipv4, ipv6) = if let Some(matcher) = state.matchers.get(name) {
            match matcher.destination_ip_prefixes() {
                Ok((semantics, ipv4, ipv6)) => {
                    (RulesetIpPrefixStatus::Ready { semantics }, ipv4, ipv6)
                }
                Err(RulesetPrefixError::TooManyPrefixes { limit }) => (
                    RulesetIpPrefixStatus::TooManyPrefixes { limit },
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
                Err(RulesetPrefixError::AllocationFailed) => (
                    RulesetIpPrefixStatus::AllocationFailed,
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
                Err(RulesetPrefixError::InvalidRange { family }) => (
                    RulesetIpPrefixStatus::InvalidRange { family },
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
            }
        } else {
            let status = match state.availability.get(name) {
                Some(RulesetAvailability::Pending) => RulesetIpPrefixStatus::Pending,
                Some(RulesetAvailability::Unavailable) => RulesetIpPrefixStatus::Unavailable,
                None => RulesetIpPrefixStatus::Missing,
            };
            (status, Arc::new(Vec::new()), Arc::new(Vec::new()))
        };
        sets.push(RulesetIpPrefixSet {
            name: name.to_string(),
            status,
            ipv4,
            ipv6,
        });
    }
    RulesetIpPrefixSnapshot {
        revision: state.revision,
        sets: Arc::new(sets),
    }
}

/* ---------------- 后缀 trie ---------------- */

#[derive(Debug, Default)]
struct SuffixTrie {
    root: TrieNode,
    count: usize,
}

#[derive(Debug, Default)]
struct TrieNode {
    /// 段 → 子节点（注意：插入时把域名按 '.' 反向切分）
    children: AHashMap<String, TrieNode>,
    /// 此节点是终止 —— 命中代表"以此后缀结尾"。
    terminal: bool,
}

impl SuffixTrie {
    fn insert(&mut self, suffix: &str) {
        let suffix = suffix.trim_matches('.').to_ascii_lowercase();
        if suffix.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        for seg in suffix.rsplit('.') {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.terminal = true;
        self.count += 1;
    }
    fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return false;
        }
        let mut node = &self.root;
        // 反向遍历：z.b.a 的后缀 a → b → z
        for seg in host.rsplit('.') {
            match node.children.get(seg) {
                Some(child) => {
                    if child.terminal {
                        return true;
                    }
                    node = child;
                }
                None => return false,
            }
        }
        node.terminal
    }
    fn len(&self) -> usize {
        self.count
    }
}

fn normalize_domain(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: ClassicalKind, v: &str) -> ClassicalEntry {
        ClassicalEntry {
            kind,
            value: v.into(),
            policy: None,
        }
    }

    #[test]
    fn suffix_and_exact_match() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DomainSuffix, "example.com"),
                entry(ClassicalKind::Domain, "exact.test"),
            ],
        );
        assert!(m.matches("a.example.com", None, None, None));
        assert!(m.matches("example.com", None, None, None));
        assert!(!m.matches("example.org", None, None, None));
        assert!(m.matches("exact.test", None, None, None));
        assert!(!m.matches("noexact.test", None, None, None));
    }

    #[test]
    fn keyword_and_regex() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DomainKeyword, "google"),
                entry(ClassicalKind::DomainRegex, r"^(?:.*\.)?facebook\.com$"),
            ],
        );
        assert!(m.matches("www.googleapis.com", None, None, None));
        assert!(m.matches("a.facebook.com", None, None, None));
        assert!(m.matches("facebook.com", None, None, None));
    }

    #[test]
    fn cidr_v4_v6() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::IpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::IpCidr, "fd00::/8"),
            ],
        );
        assert!(m.matches("", "10.1.2.3".parse().ok(), None, None));
        assert!(m.matches("", "fd11::1".parse().ok(), None, None));
        assert!(!m.matches("", "1.1.1.1".parse().ok(), None, None));
    }

    #[test]
    fn port_and_process() {
        let m = RulesetMatcher::compile(
            "t",
            vec![
                entry(ClassicalKind::DstPort, "443"),
                entry(ClassicalKind::DstPort, "1000-2000"),
                entry(ClassicalKind::ProcessName, "Code"),
            ],
        );
        assert!(m.matches("", None, Some(443), None));
        assert!(m.matches("", None, Some(1500), None));
        assert!(!m.matches("", None, Some(80), None));
        assert!(m.matches("", None, None, Some("code")));
        assert!(!m.matches("", None, None, Some("notepad")));
    }

    #[test]
    fn compile_domains_with_dot_prefix() {
        let m = RulesetMatcher::compile_domains(
            "geosite-cn",
            vec!["+.qq.com".into(), "baidu.com".into(), ".cn".into()],
        );
        assert!(m.matches("im.qq.com", None, None, None));
        assert!(m.matches("baidu.com", None, None, None));
        assert!(m.matches("a.b.cn", None, None, None));
    }

    #[test]
    fn classical_source_predicates_do_not_match_destination_fields() {
        let m = RulesetMatcher::compile(
            "source",
            vec![
                entry(ClassicalKind::SrcIpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::SrcPort, "1000-2000"),
            ],
        );
        let destination_only = RulesetMatchContext {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            dst_port: Some(1500),
            ..Default::default()
        };
        assert!(!m.matches_context(&destination_only));

        let source_ip = RulesetMatchContext {
            src_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        assert!(m.matches_context(&source_ip));

        let source_port = RulesetMatchContext {
            src_port: Some(1500),
            ..Default::default()
        };
        assert!(m.matches_context(&source_port));
    }

    #[test]
    fn classical_prefix_snapshot_is_canonical_and_labels_projection() {
        let exact = RulesetMatcher::compile(
            "exact",
            vec![
                entry(ClassicalKind::IpCidr, "10.128.0.0/9"),
                entry(ClassicalKind::IpCidr, "10.0.0.0/9"),
                entry(ClassicalKind::IpCidr, "10.1.0.0/16"),
                entry(ClassicalKind::IpCidr, "2001:db8::1234/32"),
            ],
        );
        let (semantics, ipv4, ipv6) = exact.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Exact);
        assert_eq!(ipv4.as_ref(), &["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(ipv6.as_ref(), &["2001:db8::/32".parse().unwrap()]);

        let projected = RulesetMatcher::compile(
            "projected",
            vec![
                entry(ClassicalKind::IpCidr, "192.0.2.123/24"),
                entry(ClassicalKind::SrcIpCidr, "10.0.0.0/8"),
                entry(ClassicalKind::DstPort, "443"),
            ],
        );
        let (semantics, ipv4, ipv6) = projected.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Extracted);
        assert_eq!(ipv4.as_ref(), &["192.0.2.0/24".parse().unwrap()]);
        assert!(ipv6.is_empty());

        let domains = RulesetMatcher::compile_domains("domain", ["example.com".into()]);
        let (semantics, ipv4, ipv6) = domains.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::NotIpSet);
        assert!(ipv4.is_empty());
        assert!(ipv6.is_empty());
    }

    #[test]
    fn semantic_snapshot_uses_singbox_extraction_but_marks_non_exact_rules() {
        use crate::ir::{RulesetExpr, RulesetPredicate};

        let program = RulesetProgram::new(
            5,
            1,
            RulesetExpr::All(vec![
                RulesetExpr::Predicate(RulesetPredicate::DstIpCidr(vec![
                    "203.0.113.0/24".parse().unwrap(),
                ])),
                RulesetExpr::Not(Box::new(RulesetExpr::Predicate(
                    RulesetPredicate::SrcIpCidr(vec!["10.0.0.0/8".parse().unwrap()]),
                ))),
                RulesetExpr::Predicate(RulesetPredicate::DstPort(vec![crate::ir::PortRange {
                    start: 443,
                    end: 443,
                }])),
            ]),
        );
        let matcher = RulesetMatcher::compile_semantic("srs", program);
        let (semantics, ipv4, ipv6) = matcher.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Extracted);
        assert_eq!(ipv4.as_ref(), &["203.0.113.0/24".parse().unwrap()]);
        assert!(ipv6.is_empty());
    }

    #[test]
    fn mrs_closed_ranges_convert_to_minimal_exact_prefixes() {
        use crate::parser::mrs::{MrsIpCidrSet, MrsPayload};

        let payload = MrsPayload::IpCidr {
            set: Arc::new(MrsIpCidrSet {
                v4_ranges: vec![(1, 6), (u32::MAX, u32::MAX)],
                v6_ranges: vec![(0, u128::MAX)],
            }),
            count: 3,
        };
        let matcher = RulesetMatcher::compile_mrs("mrs", payload);
        let (semantics, ipv4, ipv6) = matcher.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Exact);
        assert_eq!(
            ipv4.as_ref(),
            &[
                "0.0.0.1/32".parse().unwrap(),
                "0.0.0.2/31".parse().unwrap(),
                "0.0.0.4/31".parse().unwrap(),
                "0.0.0.6/32".parse().unwrap(),
                "255.255.255.255/32".parse().unwrap(),
            ]
        );
        assert_eq!(ipv6.as_ref(), &["::/0".parse().unwrap()]);
    }

    #[test]
    fn range_conversion_covers_exactly_every_small_interval_and_boundaries() {
        for start in 0u32..=32 {
            for end in start..=32 {
                let mut prefixes = Vec::new();
                let mut total = 0;
                append_ipv4_range(start, end, &mut prefixes, &mut total).unwrap();
                for candidate in 0u32..=40 {
                    let covered = prefixes
                        .iter()
                        .any(|prefix| prefix.contains(&Ipv4Addr::from(candidate)));
                    assert_eq!(
                        covered,
                        (start..=end).contains(&candidate),
                        "range {start}..={end}, candidate={candidate}, prefixes={prefixes:?}"
                    );
                }
            }
        }

        let mut v4 = Vec::new();
        let mut total = 0;
        append_ipv4_range(0, u32::MAX, &mut v4, &mut total).unwrap();
        assert_eq!(v4, vec!["0.0.0.0/0".parse().unwrap()]);

        let mut v6 = Vec::new();
        let mut total = 0;
        append_ipv6_range(u128::MAX, u128::MAX, &mut v6, &mut total).unwrap();
        assert_eq!(
            v6,
            vec![
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
                    .parse()
                    .unwrap()
            ]
        );

        let mut rejected = Vec::<Ipv4Net>::new();
        let mut at_limit = MAX_IP_PREFIX_SNAPSHOT_ITEMS;
        assert_eq!(
            reserve_prefix(&mut rejected, &mut at_limit),
            Err(RulesetPrefixError::TooManyPrefixes {
                limit: MAX_IP_PREFIX_SNAPSHOT_ITEMS
            })
        );
        assert!(rejected.is_empty());
    }

    #[test]
    fn in_place_aggregation_matches_ipnet_reference_implementation() {
        for seed in 0u64..64 {
            let mut state = seed.wrapping_add(1);
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for _ in 0..128 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let prefix_v4 = (state % 33) as u8;
                ipv4.push(
                    Ipv4Net::new(Ipv4Addr::from(state as u32), prefix_v4)
                        .unwrap()
                        .trunc(),
                );
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let address_v6 = (u128::from(state) << 64) | u128::from(state.rotate_left(17));
                let prefix_v6 = (state % 129) as u8;
                ipv6.push(
                    Ipv6Net::new(Ipv6Addr::from(address_v6), prefix_v6)
                        .unwrap()
                        .trunc(),
                );
            }

            let expected_v4 = Ipv4Net::aggregate(&ipv4);
            let expected_v6 = Ipv6Net::aggregate(&ipv6);
            aggregate_ipv4_in_place(&mut ipv4);
            aggregate_ipv6_in_place(&mut ipv6);
            assert_eq!(ipv4, expected_v4, "IPv4 seed {seed}");
            assert_eq!(ipv6, expected_v6, "IPv6 seed {seed}");
        }
    }

    #[tokio::test]
    async fn index_snapshot_status_and_watch_converge_without_spurious_updates() {
        let index = RulesetIndex::new();
        index.declare(["pending", "gone"]);
        index.mark_unavailable("gone");
        let names = ["pending", "gone", "missing", "pending"];
        let (initial, mut updates) = index.ip_prefix_snapshot_and_subscribe(&names);
        assert_eq!(initial.revision, *updates.borrow());
        assert_eq!(initial.sets.len(), 3);
        assert_eq!(initial.sets[0].status, RulesetIpPrefixStatus::Pending);
        assert_eq!(initial.sets[1].status, RulesetIpPrefixStatus::Unavailable);
        assert_eq!(initial.sets[2].status, RulesetIpPrefixStatus::Missing);

        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["10.0.0.0/8".into()],
        )));
        updates.changed().await.unwrap();
        let ready = index.ip_prefix_snapshot(&names);
        assert_eq!(ready.revision, *updates.borrow());
        assert_eq!(
            ready.sets[0].status,
            RulesetIpPrefixStatus::Ready {
                semantics: RulesetIpPrefixSemantics::Exact,
            }
        );

        let stable_revision = ready.revision;
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["10.1.2.3/9".into(), "10.200.3.4/9".into()],
        )));
        assert_eq!(index.ip_prefix_revision(), stable_revision);
        assert!(!updates.has_changed().unwrap());

        // Monotonic watch publication retains the newest desired state even if
        // no receiver existed at publication time.
        drop(updates);
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["192.0.2.0/24".into()],
        )));
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "pending",
            ["198.51.100.0/24".into()],
        )));
        let late = index.subscribe_ip_prefix_updates();
        assert_eq!(*late.borrow(), index.ip_prefix_revision());
        assert_eq!(
            index.ip_prefix_snapshot(&["pending"]).sets[0].ipv4.as_ref(),
            &["198.51.100.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn watch_publication_never_holds_the_index_state_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let index = RulesetIndex::new();
        let receiver = index.subscribe_ip_prefix_updates();
        let borrowed_revision = receiver.borrow();
        let completed = Arc::new(AtomicBool::new(false));
        let writer_index = index.clone();
        let writer_completed = completed.clone();
        let writer = std::thread::spawn(move || {
            writer_index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
                "geo",
                ["203.0.113.0/24".into()],
            )));
            writer_completed.store(true, Ordering::Release);
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while index.ip_prefix_revision() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "writer did not commit index state"
            );
            std::thread::yield_now();
        }
        // The writer may be waiting for the watch Ref above, but readers must
        // still be able to observe its committed full snapshot.
        assert_eq!(
            index.ip_prefix_snapshot(&["geo"]).sets[0].ipv4.as_ref(),
            &["203.0.113.0/24".parse().unwrap()]
        );
        drop(borrowed_revision);
        writer.join().unwrap();
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(*receiver.borrow(), index.ip_prefix_revision());
    }

    #[test]
    fn concurrent_writers_cannot_publish_revision_regressions() {
        let index = RulesetIndex::new();
        let receiver = index.subscribe_ip_prefix_updates();
        let mut writers = Vec::new();
        for i in 0..16u8 {
            let index = index.clone();
            writers.push(std::thread::spawn(move || {
                index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
                    format!("set-{i}"),
                    [format!("10.{i}.0.0/16")],
                )));
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(index.ip_prefix_revision(), 16);
        assert_eq!(*receiver.borrow(), 16);
        assert_eq!(index.names().len(), 16);
    }
}
