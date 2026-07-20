//! DNS 策略 —— sing-box 兼容的顺序评估 + per-query 选项 + evaluate/respond/route 三动作。
//!
//! ## 与 sing-box DNS rules 对照
//!
//! | sing-box 字段 | 本仓库 |
//! |---|---|
//! | `action: route` | [`DnsAction::Route { server, opts }`] —— 终止评估 |
//! | `action: route-options` | [`DnsAction::Direct`] / [`DnsAction::Proxy`] / [`DnsAction::Reject`] / [`DnsAction::Accept`] / [`DnsAction::Fake`] |
//! | `action: evaluate` | [`DnsAction::Evaluate { server, opts }`] —— 不终止；保存 saved response 给后续 match_response 使用 |
//! | `action: respond` | [`DnsAction::Respond`] —— 终止；返回 saved response（无则报错） |
//! | `disable_cache` | [`QueryOptions::disable_cache`] |
//! | `disable_optimistic_cache` | [`QueryOptions::disable_optimistic_cache`] |
//! | `rewrite_ttl` | [`QueryOptions::rewrite_ttl`] |
//! | `client_subnet` | [`QueryOptions::client_subnet`] |
//! | `match_response: { ip_cidr: [...] }` | [`HostMatch::ResponseIpCidr`] —— 命中 saved response |
//!
//! ## 顺序评估
//!
//! `PolicyEngine::evaluate_rules` 按 `rules` 顺序逐条尝试匹配；
//! 命中后按动作的语义决定是否终止：
//! * Reject / Accept / Direct / Proxy / Fake / Route / Respond —— **terminal**
//! * Evaluate —— **non-terminal**，把上下文 saved response 更新后继续

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use ipnet::IpNet;
use parking_lot::Mutex;

/// per-query DNS 选项 —— 与 sing-box 字段一一对应。
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    /// 覆盖最终写入 cache 的 TTL（秒）。None = 用上游 TTL / 默认。
    pub rewrite_ttl: Option<u32>,
    /// EDNS0 client_subnet 提示。
    pub client_subnet: Option<IpNet>,
}

/// sing-box `reject.method`：默认返回 REFUSED；drop 不响应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMethod {
    /// `default` —— 返回 REFUSED 错误码。
    Default,
    /// `drop` —— 不发送响应（resolver 返回 [`crate::ResolveError::Dropped`]）。
    Drop,
}

/// sing-box `reject` action 选项。
#[derive(Debug, Clone)]
pub struct RejectOptions {
    pub method: RejectMethod,
    /// `false`（默认）：30s 内触发 50 次自动切 drop（DNS 洪水保护）；
    /// `true`：始终保持 method 不变。`method = Drop` 时本字段无意义。
    pub no_drop: bool,
}

impl Default for RejectOptions {
    fn default() -> Self {
        Self {
            method: RejectMethod::Default,
            no_drop: false,
        }
    }
}

/// sing-box `predefined.rcode`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreRcode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

impl PreRcode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "NOERROR" | "SUCCESS" => Self::NOERROR,
            "FORMERR" | "FORMAT_ERROR" => Self::FORMERR,
            "SERVFAIL" | "SERVER_FAILURE" => Self::SERVFAIL,
            "NXDOMAIN" | "NAME_ERROR" => Self::NXDOMAIN,
            "NOTIMP" | "NOT_IMPLEMENTED" => Self::NOTIMP,
            "REFUSED" => Self::REFUSED,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NOERROR => "NOERROR",
            Self::FORMERR => "FORMERR",
            Self::SERVFAIL => "SERVFAIL",
            Self::NXDOMAIN => "NXDOMAIN",
            Self::NOTIMP => "NOTIMP",
            Self::REFUSED => "REFUSED",
        }
    }
}

/// 单条 DNS 文本资源记录。
#[derive(Debug, Clone)]
pub struct DnsRR {
    /// 域名（含末尾点或不含都行）
    pub name: String,
    /// 类（一般 "IN"）
    pub class: String,
    /// 类型："A" / "AAAA" / "TXT" / "CNAME" / "MX" / ...
    pub rtype: String,
    /// 数据：A/AAAA = IP；TXT = 引号包裹的文本；CNAME = 域名；其它原样
    pub data: String,
    /// TTL（秒）；预定义可缺省
    pub ttl: Option<u32>,
}

impl DnsRR {
    /// 解析 mihomo / sing-box 文本格式：`hostname[.] [TTL] [IN] TYPE DATA`
    /// 以及简短形式 `TYPE hostname DATA`。
    pub fn parse(s: &str) -> Option<Self> {
        let line = s.trim();
        if line.is_empty() {
            return None;
        }
        let toks: Vec<&str> = line
            .splitn(5, char::is_whitespace)
            .filter(|t| !t.is_empty())
            .collect();
        if toks.len() < 3 {
            return None;
        }

        // 短写法：TYPE name data...
        let upper0 = toks[0].to_ascii_uppercase();
        let known_types = ["A", "AAAA", "CNAME", "TXT", "PTR", "MX", "NS", "SOA"];
        if known_types.contains(&upper0.as_str()) && toks.len() >= 3 {
            return Some(DnsRR {
                name: toks[1].trim_end_matches('.').to_string(),
                class: "IN".into(),
                rtype: upper0,
                data: toks[2..].join(" "),
                ttl: None,
            });
        }

        // 标准格式 `name [TTL] [IN] TYPE data`
        let mut idx = 1;
        let mut ttl: Option<u32> = None;
        if let Ok(n) = toks[idx].parse::<u32>() {
            ttl = Some(n);
            idx += 1;
        }
        if idx < toks.len() && toks[idx].eq_ignore_ascii_case("IN") {
            idx += 1;
        }
        if idx + 1 >= toks.len() {
            return None;
        }
        Some(DnsRR {
            name: toks[0].trim_end_matches('.').to_string(),
            class: "IN".into(),
            rtype: toks[idx].to_ascii_uppercase(),
            data: toks[idx + 1..].join(" "),
            ttl,
        })
    }
}

/// sing-box `predefined` action：固定的 DNS 响应包内容。
#[derive(Debug, Clone, Default)]
pub struct PredefinedResponse {
    pub rcode: Option<PreRcode>,
    pub answer: Vec<DnsRR>,
    pub ns: Vec<DnsRR>,
    pub extra: Vec<DnsRR>,
}

impl PredefinedResponse {
    /// 把 answer 中的 A / AAAA 记录提取为 IP 列表，供需要返回 IP 的接口使用。
    pub fn answer_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for r in &self.answer {
            match r.rtype.as_str() {
                "A" | "AAAA" => {
                    if let Ok(ip) = r.data.trim().parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
                _ => {}
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub enum DnsAction {
    /// 拒绝（默认 REFUSED；drop 不响应；可被 throttle 自动切 drop）。terminal。
    Reject(RejectOptions),
    /// 直接返回固定 IP（hosts file 风格）。terminal。
    Accept(Vec<IpAddr>),
    /// 走 group 解析 + 直连。terminal。
    Direct(String),
    /// 走 group 解析（业务语义"经代理出去"）。terminal。
    Proxy(String),
    /// 返回 fake-ip。terminal。
    Fake,
    /// sing-box: 路由到指定 group/server，并应用 per-query opts。terminal。
    Route { server: String, opts: QueryOptions },
    /// sing-box: 评估指定 server 并把响应保存到上下文，*不*终止评估。
    Evaluate { server: String, opts: QueryOptions },
    /// sing-box: 返回 saved response。terminal。
    Respond,
    /// sing-box: 预定义响应（含 rcode + answer/ns/extra 文本记录）。terminal。
    Predefined(PredefinedResponse),
}

impl DnsAction {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, DnsAction::Evaluate { .. })
    }
}

#[derive(Debug, Clone)]
pub enum HostMatch {
    Domain(String),
    Suffix(String),
    Keyword(String),
    Any,
    Set(String),
    /// sing-box `match_response.ip_cidr` —— 命中时检查上下文 saved response 的 IP 是否落入 CIDR。
    ResponseIpCidr(IpNet),
    Not(Box<HostMatch>),
    Or(Vec<HostMatch>),
    And(Vec<HostMatch>),
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub matcher: HostMatch,
    pub action: DnsAction,
    pub source: String,
}

/// 评估上下文 —— sing-box `match_response` / `respond` 共享。
#[derive(Debug, Default, Clone)]
pub struct EvalContext {
    /// 最近一次 evaluate 动作保存的响应。
    pub saved_response: Option<Vec<IpAddr>>,
    /// 最近一次 evaluate 使用的 opts（用于 respond 时保留 rewrite_ttl 等）。
    pub saved_opts: Option<QueryOptions>,
}

/// 评估结果。
#[derive(Debug, Clone)]
pub enum Decision {
    /// 已终止：执行此动作即可。
    Terminal(DnsAction),
    /// 默认动作（任何规则都没匹配上时）。
    Default(DnsAction),
}

/// reject 限流器 —— 同一 rule 30s 50 次后自动切 drop（与 sing-box 一致）。
#[derive(Debug)]
pub struct RejectThrottle {
    counts: DashMap<String, Mutex<(Instant, u32)>>,
    pub window: Duration,
    pub threshold: u32,
}

impl Default for RejectThrottle {
    fn default() -> Self {
        Self {
            counts: DashMap::new(),
            window: Duration::from_secs(30),
            threshold: 50,
        }
    }
}

impl RejectThrottle {
    pub fn new(window: Duration, threshold: u32) -> Self {
        Self {
            counts: DashMap::new(),
            window,
            threshold,
        }
    }

    /// 记录一次 reject 触发，返回是否应该升级为 drop。
    pub fn record_should_drop(&self, rule_source: &str) -> bool {
        let now = Instant::now();
        let entry = self
            .counts
            .entry(rule_source.to_string())
            .or_insert_with(|| Mutex::new((now, 0)));
        let mut g = entry.lock();
        if now.duration_since(g.0) > self.window {
            *g = (now, 1);
            false
        } else {
            g.1 = g.1.saturating_add(1);
            g.1 >= self.threshold
        }
    }

    pub fn reset(&self, rule_source: &str) {
        self.counts.remove(rule_source);
    }
}

#[derive(Debug, Default, Clone)]
pub struct PolicyEngine {
    pub rules: Vec<PolicyRule>,
    pub ruleset_index: Option<Arc<core_ruleset::RulesetIndex>>,
    pub default_action: Option<DnsAction>,
    pub throttle: Arc<RejectThrottle>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default(mut self, action: DnsAction) -> Self {
        self.default_action = Some(action);
        self
    }

    pub fn with_rulesets(mut self, idx: Arc<core_ruleset::RulesetIndex>) -> Self {
        self.ruleset_index = Some(idx);
        self
    }

    pub fn push(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// 友好 API：从 YAML 值读规则（接受字符串或 mapping）。
    ///
    /// ```yaml
    /// # 三种合法写法
    /// - "set:cn -> direct:cn-dns?ecs=1.2.3.0/24"          # 字符串 DSL
    /// - { suffix: bad.com, drop: true }                   # mapping：drop
    /// - { match: "set:gfw", proxy: global-dns, ttl: 60 }  # mapping：route 选项
    /// - { suffix: foo.com, ips: [1.2.3.4, ::1] }          # mapping：accept
    /// - { match_response: 1.1.1.0/24, respond: true }     # mapping：respond
    /// ```
    pub fn push_value(&mut self, v: &serde_yaml::Value) -> Option<()> {
        let rule = parse_rule_value(v)?;
        self.rules.push(rule);
        Some(())
    }
}

/// 把 yaml::Value（字符串或 mapping）转换为 PolicyRule —— 友好结构化入口。
pub fn parse_rule_value(v: &serde_yaml::Value) -> Option<PolicyRule> {
    if let Some(s) = v.as_str() {
        return parse_rule_line(s);
    }
    let m = v.as_mapping()?;

    let get_str = |k: &str| -> Option<String> {
        m.get(serde_yaml::Value::String(k.into()))
            .and_then(|x| x.as_str().map(String::from))
    };
    let get_bool = |k: &str| -> bool {
        m.get(serde_yaml::Value::String(k.into()))
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
    };
    let get_u64 = |k: &str| -> Option<u64> {
        m.get(serde_yaml::Value::String(k.into()))
            .and_then(|x| x.as_u64())
    };
    let get_seq = |k: &str| -> Option<Vec<String>> {
        m.get(serde_yaml::Value::String(k.into()))
            .and_then(|x| x.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
    };

    // ---------- LHS：拼匹配 ----------
    let matcher = if let Some(s) = get_str("match") {
        parse_lhs(&s)?
    } else if let Some(s) = get_str("domain") {
        HostMatch::Domain(s)
    } else if let Some(s) = get_str("suffix").or_else(|| get_str("host")) {
        HostMatch::Suffix(s)
    } else if let Some(s) = get_str("keyword") {
        HostMatch::Keyword(s)
    } else if let Some(s) = get_str("set")
        .or_else(|| get_str("geosite"))
        .or_else(|| get_str("geoip"))
        .or_else(|| get_str("ruleset"))
    {
        HostMatch::Set(s)
    } else if let Some(s) = get_str("match_response").or_else(|| get_str("response")) {
        HostMatch::ResponseIpCidr(s.parse().ok()?)
    } else {
        HostMatch::Any
    };

    // ---------- 选项 ----------
    let opts = QueryOptions {
        disable_cache: get_bool("no_cache") || get_bool("disable_cache") || get_bool("nocache"),
        disable_optimistic_cache: get_bool("no_optimistic_cache")
            || get_bool("disable_optimistic_cache")
            || get_bool("nooptcache"),
        rewrite_ttl: get_u64("ttl").map(|n| n as u32),
        client_subnet: get_str("client_subnet")
            .or_else(|| get_str("ecs"))
            .and_then(|s| {
                s.parse::<IpNet>().ok().or_else(|| {
                    s.parse::<IpAddr>().ok().map(|ip| match ip {
                        IpAddr::V4(_) => format!("{ip}/32").parse().unwrap(),
                        IpAddr::V6(_) => format!("{ip}/128").parse().unwrap(),
                    })
                })
            }),
    };

    // ---------- RHS（按优先级寻找第一个出现的动作字段） ----------
    // 1. drop / reject / refuse
    if get_bool("drop") {
        let action = DnsAction::Reject(RejectOptions {
            method: RejectMethod::Drop,
            no_drop: get_bool("no_drop"),
        });
        return Some(PolicyRule {
            matcher,
            action,
            source: format!("{v:?}"),
        });
    }
    if get_bool("reject") || get_bool("refuse") {
        let method = match get_str("method").as_deref() {
            Some("drop") => RejectMethod::Drop,
            _ => RejectMethod::Default,
        };
        let action = DnsAction::Reject(RejectOptions {
            method,
            no_drop: get_bool("no_drop"),
        });
        return Some(PolicyRule {
            matcher,
            action,
            source: format!("{v:?}"),
        });
    }
    // 2. predefined rcode 快捷
    for (k, code) in [
        ("nxdomain", PreRcode::NXDOMAIN),
        ("noerror", PreRcode::NOERROR),
        ("servfail", PreRcode::SERVFAIL),
        ("formerr", PreRcode::FORMERR),
        ("notimp", PreRcode::NOTIMP),
    ] {
        if get_bool(k) {
            return Some(PolicyRule {
                matcher,
                action: DnsAction::Predefined(PredefinedResponse {
                    rcode: Some(code),
                    ..Default::default()
                }),
                source: format!("{v:?}"),
            });
        }
    }
    // 3. accept / hosts / ips
    for k in ["accept", "hosts", "ips"] {
        if let Some(seq) = get_seq(k) {
            let ips: Vec<IpAddr> = seq.iter().filter_map(|s| s.parse().ok()).collect();
            if !ips.is_empty() {
                return Some(PolicyRule {
                    matcher,
                    action: DnsAction::Accept(ips),
                    source: format!("{v:?}"),
                });
            }
        }
        if let Some(s) = get_str(k) {
            let ips: Vec<IpAddr> = s.split(',').filter_map(|p| p.trim().parse().ok()).collect();
            if !ips.is_empty() {
                return Some(PolicyRule {
                    matcher,
                    action: DnsAction::Accept(ips),
                    source: format!("{v:?}"),
                });
            }
        }
    }
    // 4. fake / respond
    if get_bool("fake") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Fake,
            source: format!("{v:?}"),
        });
    }
    if get_bool("respond") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Respond,
            source: format!("{v:?}"),
        });
    }
    // 5. group: direct / proxy / route / evaluate
    if let Some(g) = get_str("evaluate") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Evaluate { server: g, opts },
            source: format!("{v:?}"),
        });
    }
    if let Some(g) = get_str("route") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Route { server: g, opts },
            source: format!("{v:?}"),
        });
    }
    if let Some(g) = get_str("direct") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Route { server: g, opts },
            source: format!("{v:?}"),
        });
    }
    if let Some(g) = get_str("proxy") {
        return Some(PolicyRule {
            matcher,
            action: DnsAction::Route { server: g, opts },
            source: format!("{v:?}"),
        });
    }
    None
}

impl PolicyEngine {
    /// 旧版 API：返回第一个 terminal action。**不支持 evaluate/respond**。
    pub fn decide(&self, host: &str) -> DnsAction {
        let mut ctx = EvalContext::default();
        let host_lc = host.trim_end_matches('.').to_lowercase();
        for r in &self.rules {
            if matches(&r.matcher, &host_lc, &ctx, self.ruleset_index.as_ref()) {
                if r.action.is_terminal() {
                    return r.action.clone();
                }
            }
        }
        let _ = &mut ctx;
        self.default_action
            .clone()
            .unwrap_or_else(|| DnsAction::Direct("default".into()))
    }

    /// 给定一个 reject 动作 + 对应规则源串，应用 throttle 后返回**最终生效的** method。
    pub fn apply_reject_throttle(&self, opts: &RejectOptions, rule_source: &str) -> RejectMethod {
        if matches!(opts.method, RejectMethod::Drop) || opts.no_drop {
            return opts.method;
        }
        if self.throttle.record_should_drop(rule_source) {
            RejectMethod::Drop
        } else {
            RejectMethod::Default
        }
    }
}

pub fn matches(
    m: &HostMatch,
    host: &str,
    ctx: &EvalContext,
    idx: Option<&Arc<core_ruleset::RulesetIndex>>,
) -> bool {
    match m {
        HostMatch::Any => true,
        HostMatch::Domain(d) => host == d.to_lowercase(),
        HostMatch::Suffix(s) => {
            let s = s.trim_start_matches('.').to_lowercase();
            host == s || host.ends_with(&format!(".{s}"))
        }
        HostMatch::Keyword(k) => host.contains(&k.to_lowercase()),
        HostMatch::Set(name) => idx
            .and_then(|i| i.get(name))
            .map(|m| m.matches(host, None, None, None))
            .unwrap_or(false),
        HostMatch::ResponseIpCidr(cidr) => ctx
            .saved_response
            .as_ref()
            .map(|ips| ips.iter().any(|ip| cidr.contains(ip)))
            .unwrap_or(false),
        HostMatch::Not(inner) => !matches(inner, host, ctx, idx),
        HostMatch::Or(list) => list.iter().any(|m| matches(m, host, ctx, idx)),
        HostMatch::And(list) => list.iter().all(|m| matches(m, host, ctx, idx)),
    }
}

/* ---------------- DSL 解析 ---------------- */

/// 解析 "lhs -> rhs" —— 已扩展到 sing-box 风格：
///
/// LHS：
///   * any / *
///   * domain:foo.com
///   * suffix:foo.com（裸字符串也按 suffix 处理）
///   * keyword:abc
///   * set:my-rs
///   * match_response:1.1.1.0/24
///
/// RHS：
///   * reject / block / fake / accept:1.2.3.4
///   * direct:GROUP / proxy:GROUP / GROUP（裸 group）
///   * **evaluate:GROUP**\[?opts\]    —— 非终止
///   * **respond**                     —— 终止，返回 saved
///   * **route:GROUP**\[?opts\]        —— 终止（与 direct/proxy 等价但显式）
///
/// per-query opts 紧跟问号：
///   * `evaluate:global-dns?nocache,nooptcache,ttl=60,ecs=1.2.3.0/24`
pub fn parse_rule_line(line: &str) -> Option<PolicyRule> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    let (lhs, rhs) = s.split_once("->")?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    let matcher = parse_lhs(lhs)?;
    let action = parse_rhs(rhs)?;
    Some(PolicyRule {
        matcher,
        action,
        source: line.to_string(),
    })
}

fn parse_lhs(lhs: &str) -> Option<HostMatch> {
    let lhs = lhs.trim();
    let m = match lhs {
        "any" | "*" | "final" | "" => HostMatch::Any,
        // 短写法：=foo.com 精确域名
        s if s.starts_with('=') => HostMatch::Domain(s[1..].into()),
        // 短写法：*.foo.com 后缀
        s if s.starts_with("*.") => HostMatch::Suffix(s[2..].into()),
        // 短写法：~regex 正则（host）
        s if s.starts_with('~') => HostMatch::Keyword(s[1..].into()), // 内部退化为 keyword 子串
        // 长写法
        s if s.starts_with("domain:") => HostMatch::Domain(s[7..].into()),
        s if s.starts_with("suffix:") => HostMatch::Suffix(s[7..].into()),
        s if s.starts_with("keyword:") => HostMatch::Keyword(s[8..].into()),
        s if s.starts_with("set:") => HostMatch::Set(s[4..].into()),
        // sing-box / mihomo 风格别名
        s if s.starts_with("geosite:") => HostMatch::Set(s[8..].into()),
        s if s.starts_with("geoip:") => HostMatch::Set(s[6..].into()),
        s if s.starts_with("ruleset:") => HostMatch::Set(s[8..].into()),
        s if s.starts_with("match_response:") => {
            let cidr: IpNet = s[15..].parse().ok()?;
            HostMatch::ResponseIpCidr(cidr)
        }
        s if s.starts_with("response:") => {
            let cidr: IpNet = s[9..].parse().ok()?;
            HostMatch::ResponseIpCidr(cidr)
        }
        s if s.starts_with("not:") => HostMatch::Not(Box::new(parse_lhs(&s[4..])?)),
        // 默认裸字符串 = 域名后缀（最常见）
        _ => HostMatch::Suffix(lhs.into()),
    };
    Some(m)
}

fn parse_rhs(rhs: &str) -> Option<DnsAction> {
    // 拆 ?opts
    let (head, opts) = match rhs.split_once('?') {
        Some((a, b)) => (a, parse_opts(b)),
        None => (rhs, QueryOptions::default()),
    };
    let head = head.trim();

    // reject?method=drop&no_drop
    if head == "reject" || head == "block" {
        let mut ro = RejectOptions::default();
        for kv in rhs.split(['?', ',', '&']).skip(1) {
            let kv = kv.trim();
            if kv == "no_drop" || kv == "no-drop" {
                ro.no_drop = true;
            } else if let Some(v) = kv.strip_prefix("method=") {
                match v.to_ascii_lowercase().as_str() {
                    "drop" => ro.method = RejectMethod::Drop,
                    "default" | "" => ro.method = RejectMethod::Default,
                    _ => {}
                }
            }
        }
        return Some(DnsAction::Reject(ro));
    }

    // predefined:NOERROR;A foo.com 1.2.3.4;AAAA foo.com ::1;TXT foo.com "Hello"
    if let Some(rest) = head.strip_prefix("predefined") {
        let body = rest.trim_start_matches(':');
        let mut pre = PredefinedResponse::default();
        let mut parts = body.split(';');
        if let Some(first) = parts.next() {
            let f = first.trim();
            if !f.is_empty() {
                if let Some(c) = PreRcode::parse(f) {
                    pre.rcode = Some(c);
                } else if let Some(rr) = DnsRR::parse(f) {
                    pre.answer.push(rr);
                }
            }
        }
        for p in parts {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            // 支持 ns:..., extra:... 前缀；默认进 answer
            if let Some(s) = p.strip_prefix("ns:") {
                if let Some(rr) = DnsRR::parse(s.trim()) {
                    pre.ns.push(rr);
                }
            } else if let Some(s) = p.strip_prefix("extra:") {
                if let Some(rr) = DnsRR::parse(s.trim()) {
                    pre.extra.push(rr);
                }
            } else if let Some(rr) = DnsRR::parse(p) {
                pre.answer.push(rr);
            }
        }
        return Some(DnsAction::Predefined(pre));
    }

    // ---------- 一字短动作（最友好） ----------
    if let Some(a) = match head {
        "fake" => Some(DnsAction::Fake),
        "respond" => Some(DnsAction::Respond),
        // reject 家族（不带任何参数的快捷写法）
        "drop" => Some(DnsAction::Reject(RejectOptions {
            method: RejectMethod::Drop,
            no_drop: false,
        })),
        "refuse" | "refused" => Some(DnsAction::Reject(RejectOptions::default())),
        // predefined rcode 快捷
        "nxdomain" => Some(DnsAction::Predefined(PredefinedResponse {
            rcode: Some(PreRcode::NXDOMAIN),
            ..Default::default()
        })),
        "noerror" | "empty" | "null" => Some(DnsAction::Predefined(PredefinedResponse {
            rcode: Some(PreRcode::NOERROR),
            ..Default::default()
        })),
        "servfail" => Some(DnsAction::Predefined(PredefinedResponse {
            rcode: Some(PreRcode::SERVFAIL),
            ..Default::default()
        })),
        "formerr" => Some(DnsAction::Predefined(PredefinedResponse {
            rcode: Some(PreRcode::FORMERR),
            ..Default::default()
        })),
        "notimp" => Some(DnsAction::Predefined(PredefinedResponse {
            rcode: Some(PreRcode::NOTIMP),
            ..Default::default()
        })),
        _ => None,
    } {
        return Some(a);
    }

    // ---------- hosts:1.2.3.4 或 hosts:1.2.3.4,::1 ----------
    if let Some(rest) = head
        .strip_prefix("hosts:")
        .or_else(|| head.strip_prefix("ip:"))
    {
        let ips: Vec<_> = rest
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
        if !ips.is_empty() {
            return Some(DnsAction::Accept(ips));
        }
    }

    Some(match head {
        "fake" => DnsAction::Fake,
        "respond" => DnsAction::Respond,
        s if s.starts_with("accept:") => {
            let ips: Vec<_> = s[7..]
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            if ips.is_empty() {
                return None;
            }
            DnsAction::Accept(ips)
        }
        s if s.starts_with("direct:") => DnsAction::Direct(s[7..].into()),
        s if s.starts_with("proxy:") => DnsAction::Proxy(s[6..].into()),
        s if s.starts_with("evaluate:") => DnsAction::Evaluate {
            server: s[9..].into(),
            opts,
        },
        s if s.starts_with("route:") => DnsAction::Route {
            server: s[6..].into(),
            opts,
        },
        "direct" => DnsAction::Direct("default".into()),
        "proxy" => DnsAction::Proxy("default".into()),
        // 兼容：裸 group 名按 Proxy
        other => DnsAction::Proxy(other.into()),
    })
}

fn parse_opts(s: &str) -> QueryOptions {
    let mut o = QueryOptions::default();
    for part in s.split(',') {
        let part = part.trim();
        match part {
            "" => {}
            "nocache" | "no-cache" | "disable_cache" => o.disable_cache = true,
            "nooptcache" | "no-optimistic" | "disable_optimistic_cache" => {
                o.disable_optimistic_cache = true
            }
            kv if kv.starts_with("ttl=") => {
                if let Ok(t) = kv[4..].parse::<u32>() {
                    o.rewrite_ttl = Some(t);
                }
            }
            kv if kv.starts_with("ecs=") || kv.starts_with("client_subnet=") => {
                let v = kv.split_once('=').map(|(_, b)| b).unwrap_or("");
                if let Ok(n) = v.parse::<IpNet>() {
                    o.client_subnet = Some(n);
                } else if let Ok(ip) = v.parse::<IpAddr>() {
                    let n = match ip {
                        IpAddr::V4(_) => format!("{ip}/32"),
                        IpAddr::V6(_) => format!("{ip}/128"),
                    };
                    if let Ok(parsed) = n.parse() {
                        o.client_subnet = Some(parsed);
                    }
                }
            }
            _ => {}
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_action_aliases() {
        // drop / refuse / nxdomain / noerror / hosts:
        let r = parse_rule_line("bad.com -> drop").unwrap();
        match r.action {
            DnsAction::Reject(o) => assert_eq!(o.method, RejectMethod::Drop),
            _ => panic!(),
        }
        let r = parse_rule_line("bad.com -> refuse").unwrap();
        match r.action {
            DnsAction::Reject(o) => assert_eq!(o.method, RejectMethod::Default),
            _ => panic!(),
        }
        let r = parse_rule_line("nx.com -> nxdomain").unwrap();
        match r.action {
            DnsAction::Predefined(p) => assert_eq!(p.rcode, Some(PreRcode::NXDOMAIN)),
            _ => panic!(),
        }
        let r = parse_rule_line("foo.com -> hosts:1.2.3.4,::1,5.6.7.8").unwrap();
        match r.action {
            DnsAction::Accept(ips) => {
                assert_eq!(ips.len(), 3);
                assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
                assert!(ips.contains(&"::1".parse().unwrap()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bare_direct_and_proxy_route_to_default_dns_group() {
        let r = parse_rule_line("any -> direct").unwrap();
        match r.action {
            DnsAction::Direct(g) => assert_eq!(g, "default"),
            other => panic!("expected direct default, got {other:?}"),
        }
        let r = parse_rule_line("any -> proxy").unwrap();
        match r.action {
            DnsAction::Proxy(g) => assert_eq!(g, "default"),
            other => panic!("expected proxy default, got {other:?}"),
        }
    }

    #[test]
    fn short_lhs_aliases() {
        // *.foo.com / =foo.com / geosite: / geoip:
        let r = parse_rule_line("*.foo.com -> direct:g").unwrap();
        match r.matcher {
            HostMatch::Suffix(s) => assert_eq!(s, "foo.com"),
            _ => panic!(),
        }
        let r = parse_rule_line("=foo.com -> direct:g").unwrap();
        match r.matcher {
            HostMatch::Domain(s) => assert_eq!(s, "foo.com"),
            _ => panic!(),
        }
        let r = parse_rule_line("geosite:cn -> direct:cn-dns").unwrap();
        match r.matcher {
            HostMatch::Set(s) => assert_eq!(s, "cn"),
            _ => panic!(),
        }
        let r = parse_rule_line("geoip:cn -> direct:cn-dns").unwrap();
        match r.matcher {
            HostMatch::Set(s) => assert_eq!(s, "cn"),
            _ => panic!(),
        }
    }

    #[test]
    fn yaml_object_form_drop() {
        let v: serde_yaml::Value =
            serde_yaml::from_str(r#"{ suffix: bad.com, drop: true }"#).unwrap();
        let r = parse_rule_value(&v).unwrap();
        match r.matcher {
            HostMatch::Suffix(s) => assert_eq!(s, "bad.com"),
            _ => panic!(),
        }
        match r.action {
            DnsAction::Reject(o) => assert_eq!(o.method, RejectMethod::Drop),
            _ => panic!(),
        }
    }

    #[test]
    fn yaml_object_form_with_options() {
        let v: serde_yaml::Value = serde_yaml::from_str(
            r#"{ set: cn-site, direct: cn-dns, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }"#,
        )
        .unwrap();
        let r = parse_rule_value(&v).unwrap();
        match r.matcher {
            HostMatch::Set(s) => assert_eq!(s, "cn-site"),
            _ => panic!(),
        }
        match r.action {
            DnsAction::Route { server, opts } => {
                assert_eq!(server, "cn-dns");
                assert!(opts.disable_cache);
                assert_eq!(opts.rewrite_ttl, Some(60));
                assert!(opts.client_subnet.is_some());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn yaml_object_form_hosts_array() {
        let v: serde_yaml::Value = serde_yaml::from_str(
            r#"
suffix: foo.com
ips: ["1.2.3.4", "5.6.7.8", "::1"]
"#,
        )
        .unwrap();
        let r = parse_rule_value(&v).unwrap();
        match r.action {
            DnsAction::Accept(ips) => {
                assert_eq!(ips.len(), 3);
                assert!(ips.iter().any(|ip| ip.is_ipv6()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn yaml_object_form_match_response_respond() {
        let v: serde_yaml::Value =
            serde_yaml::from_str(r#"{ match_response: 1.1.1.0/24, respond: true }"#).unwrap();
        let r = parse_rule_value(&v).unwrap();
        match r.matcher {
            HostMatch::ResponseIpCidr(c) => assert_eq!(c.to_string(), "1.1.1.0/24"),
            _ => panic!(),
        }
        assert!(matches!(r.action, DnsAction::Respond));
    }

    #[test]
    fn yaml_object_form_string_falls_back_to_dsl() {
        let v: serde_yaml::Value = serde_yaml::from_str(r#""bad.com -> drop""#).unwrap();
        let r = parse_rule_value(&v).unwrap();
        match r.action {
            DnsAction::Reject(o) => assert_eq!(o.method, RejectMethod::Drop),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_reject_with_method_and_no_drop() {
        let r = parse_rule_line("any -> reject?method=drop").unwrap();
        match r.action {
            DnsAction::Reject(o) => {
                assert_eq!(o.method, RejectMethod::Drop);
                assert!(!o.no_drop);
            }
            _ => panic!(),
        }
        let r = parse_rule_line("any -> reject?no_drop").unwrap();
        match r.action {
            DnsAction::Reject(o) => {
                assert_eq!(o.method, RejectMethod::Default);
                assert!(o.no_drop);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_predefined_full() {
        let r = parse_rule_line(
            "domain:foo.com -> predefined:NXDOMAIN;A foo.com 1.2.3.4;AAAA foo.com ::1;ns:NS foo.com ns1.foo.com",
        )
        .unwrap();
        match r.action {
            DnsAction::Predefined(p) => {
                assert_eq!(p.rcode, Some(PreRcode::NXDOMAIN));
                assert_eq!(p.answer.len(), 2);
                assert_eq!(p.answer[0].rtype, "A");
                assert_eq!(p.answer[0].data, "1.2.3.4");
                assert_eq!(p.answer[1].rtype, "AAAA");
                assert_eq!(p.ns.len(), 1);
                assert_eq!(
                    p.answer_ips(),
                    vec!["1.2.3.4".parse::<IpAddr>().unwrap(), "::1".parse().unwrap(),]
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn reject_throttle_kicks_in() {
        let mut e = PolicyEngine::new();
        // 替换为容量小的 throttle 便于测试
        e.throttle = Arc::new(RejectThrottle::new(Duration::from_secs(60), 3));
        let opts = RejectOptions::default();
        let m1 = e.apply_reject_throttle(&opts, "rule#1");
        let m2 = e.apply_reject_throttle(&opts, "rule#1");
        let m3 = e.apply_reject_throttle(&opts, "rule#1");
        let m4 = e.apply_reject_throttle(&opts, "rule#1");
        assert_eq!(m1, RejectMethod::Default);
        assert_eq!(m2, RejectMethod::Default);
        assert_eq!(m3, RejectMethod::Drop, "第三次（threshold=3）开始 drop");
        assert_eq!(m4, RejectMethod::Drop);
        // no_drop 关闭 throttle
        let opts_nd = RejectOptions {
            method: RejectMethod::Default,
            no_drop: true,
        };
        for _ in 0..10 {
            assert_eq!(
                e.apply_reject_throttle(&opts_nd, "rule#nd"),
                RejectMethod::Default
            );
        }
    }

    #[test]
    fn parse_evaluate_with_opts() {
        let r = parse_rule_line(
            "set:cn-site -> evaluate:global-dns?nocache,nooptcache,ttl=60,ecs=1.2.3.0/24",
        )
        .unwrap();
        match r.action {
            DnsAction::Evaluate { server, opts } => {
                assert_eq!(server, "global-dns");
                assert!(opts.disable_cache);
                assert!(opts.disable_optimistic_cache);
                assert_eq!(opts.rewrite_ttl, Some(60));
                assert!(opts.client_subnet.is_some());
            }
            _ => panic!("expected Evaluate"),
        }
    }

    #[test]
    fn parse_match_response_then_respond() {
        let r = parse_rule_line("match_response:1.1.1.0/24 -> respond").unwrap();
        match r.matcher {
            HostMatch::ResponseIpCidr(c) => assert_eq!(c.to_string(), "1.1.1.0/24"),
            _ => panic!(),
        }
        assert!(matches!(r.action, DnsAction::Respond));
    }

    #[test]
    fn match_response_uses_saved() {
        let m = HostMatch::ResponseIpCidr("1.1.1.0/24".parse().unwrap());
        let mut ctx = EvalContext::default();
        assert!(!matches(&m, "x", &ctx, None));
        ctx.saved_response = Some(vec!["1.1.1.5".parse().unwrap()]);
        assert!(matches(&m, "x", &ctx, None));
        ctx.saved_response = Some(vec!["8.8.8.8".parse().unwrap()]);
        assert!(!matches(&m, "x", &ctx, None));
    }

    #[test]
    fn evaluate_is_non_terminal() {
        let a = DnsAction::Evaluate {
            server: "g".into(),
            opts: Default::default(),
        };
        assert!(!a.is_terminal());
        assert!(DnsAction::Reject(Default::default()).is_terminal());
        assert!(DnsAction::Respond.is_terminal());
    }
}
