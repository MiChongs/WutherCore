//! 高速规则匹配器：编译后的 trie / set / cidr / 关键字 / 正则 复合体。

use std::net::IpAddr;
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use ipnet::IpNet;
use parking_lot::RwLock;
use regex::RegexSet;

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
    /// 进程名（精确）
    processes: AHashSet<String>,
    /// 端口（单值或区间，u16..=u16）
    ports: Vec<(u16, u16)>,
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
        m.classical_count = entries.len();
        for e in entries {
            match e.kind {
                ClassicalKind::Domain => {
                    m.domains.insert(normalize_domain(&e.value));
                }
                ClassicalKind::DomainSuffix => {
                    m.suffix_trie.insert(&e.value);
                }
                ClassicalKind::DomainKeyword => {
                    m.keywords.push(e.value.to_ascii_lowercase());
                }
                ClassicalKind::DomainRegex => {
                    regex_pats.push(e.value);
                }
                ClassicalKind::IpCidr | ClassicalKind::SrcIpCidr => {
                    if let Ok(net) = e.value.parse::<IpNet>() {
                        match net {
                            IpNet::V4(v4) => m.cidr_v4.push(v4),
                            IpNet::V6(v6) => m.cidr_v6.push(v6),
                        }
                    }
                }
                ClassicalKind::DstPort | ClassicalKind::SrcPort => {
                    if let Some(range) = parse_port_range(&e.value) {
                        m.ports.push(range);
                    }
                }
                ClassicalKind::ProcessName => {
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
        m
    }

    /// 从纯 domain 列表（mihomo behavior=domain）编译：
    /// 项以 `+.` 开头视为后缀，否则视为精确。
    pub fn compile_domains(name: impl Into<String>, lines: impl IntoIterator<Item = String>) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() { return None; }
                if let Some(rest) = l.strip_prefix("+.") {
                    Some(ClassicalEntry { kind: ClassicalKind::DomainSuffix, value: rest.into(), policy: None })
                } else if l.starts_with('.') {
                    Some(ClassicalEntry { kind: ClassicalKind::DomainSuffix, value: l[1..].into(), policy: None })
                } else if l.starts_with('*') {
                    None // 简化：忽略复杂通配
                } else {
                    Some(ClassicalEntry { kind: ClassicalKind::Domain, value: l.into(), policy: None })
                }
            })
            .collect();
        Self::compile(name, entries)
    }

    pub fn compile_ipcidr(name: impl Into<String>, lines: impl IntoIterator<Item = String>) -> Self {
        let entries = lines
            .into_iter()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() { return None; }
                Some(ClassicalEntry { kind: ClassicalKind::IpCidr, value: l.into(), policy: None })
            })
            .collect();
        Self::compile(name, entries)
    }

    /// 把 [`crate::parser::RulesetCompiled`] 编译成 matcher。
    /// `Classical` 走老 [`Self::compile`] 路径；`Mrs` 把预编译产物挂到内部字段。
    pub fn compile_any(
        name: impl Into<String>,
        compiled: crate::parser::RulesetCompiled,
    ) -> Self {
        match compiled {
            crate::parser::RulesetCompiled::Classical(entries) => Self::compile(name, entries),
            crate::parser::RulesetCompiled::Mrs(payload) => Self::compile_mrs(name, payload),
        }
    }

    /// 把 mihomo MRS 预编译产物挂到 matcher。
    pub fn compile_mrs(name: impl Into<String>, payload: crate::parser::mrs::MrsPayload) -> Self {
        let mut m = RulesetMatcher::new(name);
        m.mrs_count = payload.count();
        match payload {
            crate::parser::mrs::MrsPayload::Domain { set, .. } => {
                m.mrs_domain_set = Some(set);
            }
            crate::parser::mrs::MrsPayload::IpCidr { set, .. } => {
                // Arc<MrsIpCidrSet> → 拷贝一份排序好的 Vec 进 matcher 字段
                // （MrsIpCidrSet 内部已经排过序）。MrsIpCidrSet 不暴露所有权移动，
                // 直接 clone 出 v4/v6 ranges 即可。
                m.mrs_v4_ranges = set.v4_ranges.clone();
                m.mrs_v6_ranges = set.v6_ranges.clone();
            }
        }
        m
    }

    /// 主入口：判断 host/ip/port 是否命中。
    pub fn matches(&self, host: &str, ip: Option<IpAddr>, port: Option<u16>, process: Option<&str>) -> bool {
        // 域名相关
        let host_lc = normalize_domain(host);
        if !host_lc.is_empty() {
            if self.domains.contains(&host_lc) { return true; }
            if self.suffix_trie.matches(&host_lc) { return true; }
            for k in &self.keywords {
                if host_lc.contains(k) { return true; }
            }
            if let Some(rs) = &self.regex_set {
                if rs.is_match(&host_lc) { return true; }
            }
            // mihomo MRS domain succinct trie（含 wildcard 语义）
            if let Some(set) = &self.mrs_domain_set {
                if set.has(&host_lc) { return true; }
            }
        }
        // IP / CIDR
        let resolved_ip = ip.or_else(|| host.parse::<IpAddr>().ok());
        if let Some(ip) = resolved_ip {
            match ip {
                IpAddr::V4(v) => {
                    if self.cidr_v4.iter().any(|n| n.contains(&v)) { return true; }
                    if !self.mrs_v4_ranges.is_empty()
                        && contains_range_v4(&self.mrs_v4_ranges, u32::from(v))
                    {
                        return true;
                    }
                }
                IpAddr::V6(v) => {
                    if self.cidr_v6.iter().any(|n| n.contains(&v)) { return true; }
                    if !self.mrs_v6_ranges.is_empty()
                        && contains_range_v6(&self.mrs_v6_ranges, u128::from(v))
                    {
                        return true;
                    }
                }
            }
        }
        // port
        if let Some(p) = port {
            if self.ports.iter().any(|(lo, hi)| p >= *lo && p <= *hi) { return true; }
        }
        // process
        if let Some(name) = process {
            if self.processes.contains(&name.to_ascii_lowercase()) { return true; }
        }
        false
    }

    pub fn stats(&self) -> RulesetStats {
        // MRS domain set 的"domains"概念不能简单地映射到 self.domains.len()。
        // 我们把 mrs_count（header.count）记到一个独立字段，并在 cidr_* 里
        // 也累计 MRS v4/v6 ranges，便于 dashboard 总数显示。
        let domains_total =
            self.domains.len() + self.mrs_domain_set.as_ref().map(|_| self.mrs_count).unwrap_or(0);
        RulesetStats {
            domains: domains_total,
            suffixes: self.suffix_trie.len(),
            keywords: self.keywords.len(),
            regex: self.regex_set.as_ref().map(|r| r.len()).unwrap_or(0),
            cidr_v4: self.cidr_v4.len() + self.mrs_v4_ranges.len(),
            cidr_v6: self.cidr_v6.len() + self.mrs_v6_ranges.len(),
            processes: self.processes.len(),
            ports: self.ports.len(),
        }
    }
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

/// 全局规则集索引；route 引擎查 `set:<name>` 时用它。
#[derive(Debug, Default)]
pub struct RulesetIndex {
    inner: RwLock<AHashMap<String, Arc<RulesetMatcher>>>,
}

impl RulesetIndex {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }
    pub fn insert(&self, m: Arc<RulesetMatcher>) {
        self.inner.write().insert(m.name.clone(), m);
    }
    pub fn get(&self, name: &str) -> Option<Arc<RulesetMatcher>> {
        self.inner.read().get(name).cloned()
    }
    pub fn names(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }
    pub fn stats(&self) -> Vec<(String, RulesetStats)> {
        self.inner.read().iter().map(|(k, v)| (k.clone(), v.stats())).collect()
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
        if suffix.is_empty() { return; }
        let mut node = &mut self.root;
        for seg in suffix.rsplit('.') {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.terminal = true;
        self.count += 1;
    }
    fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.is_empty() { return false; }
        let mut node = &self.root;
        // 反向遍历：z.b.a 的后缀 a → b → z
        for seg in host.rsplit('.') {
            match node.children.get(seg) {
                Some(child) => {
                    if child.terminal { return true; }
                    node = child;
                }
                None => return false,
            }
        }
        node.terminal
    }
    fn len(&self) -> usize { self.count }
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
        ClassicalEntry { kind, value: v.into(), policy: None }
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
}
