//! 路由匹配引擎。
//!
//! 输入：[`FlowContext`] —— 一次连接的目标（域名/IP/端口/网络/进程）。
//! 输出：[`RouteDecision`] —— direct / block / group("xxx")。

use std::{net::IpAddr, sync::Arc};

use core_config::runtime_plan::{RouteAction, RouteMatcher, RoutePlan};
use core_ruleset::{RulesetIndex, RulesetInterfaceAddress, RulesetMatchContext};
use ipnet::IpNet;

use crate::builtin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

impl NetworkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// sing-box 规则集可选元数据。
///
/// 这些值只在调用方确实掌握时填写；`None`/空集合不会回退到连接协议、
/// 目标地址或其他近似字段，对应 predicate 会安全地返回 false。
#[derive(Debug, Clone)]
pub struct FlowRulesetMetadata {
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub query_type: Option<u16>,
    pub process_path: Option<String>,
    pub package_names: Vec<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_type: Option<u8>,
    pub network_is_expensive: Option<bool>,
    pub network_is_constrained: Option<bool>,
    pub network_interface_addresses: Vec<RulesetInterfaceAddress>,
    pub default_interface_addresses: Vec<IpNet>,
}

impl Default for FlowRulesetMetadata {
    fn default() -> Self {
        Self {
            source_ip: None,
            source_port: None,
            query_type: None,
            process_path: None,
            package_names: Vec::new(),
            wifi_ssid: None,
            wifi_bssid: None,
            network_type: None,
            network_is_expensive: None,
            network_is_constrained: None,
            network_interface_addresses: Vec::new(),
            default_interface_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: NetworkKind,
    pub process: Option<String>,
    /// sing-box 规则集专用的、可选的系统/连接元数据。
    pub ruleset: FlowRulesetMetadata,
    /// L7 协议指纹 —— 由 inbound/capture 嗅探首包后写入；用于 `proto:` 规则。
    pub protocol: Option<crate::sniff::L7Proto>,
}

impl FlowContext {
    pub fn for_domain(host: impl Into<String>, port: u16, network: NetworkKind) -> Self {
        Self {
            host: host.into(),
            ip: None,
            port,
            network,
            process: None,
            ruleset: FlowRulesetMetadata::default(),
            protocol: None,
        }
    }

    pub fn for_ip(ip: IpAddr, port: u16, network: NetworkKind) -> Self {
        Self {
            host: ip.to_string(),
            ip: Some(ip),
            port,
            network,
            process: None,
            ruleset: FlowRulesetMetadata::default(),
            protocol: None,
        }
    }

    fn ruleset_match_context(&self) -> RulesetMatchContext<'_> {
        RulesetMatchContext {
            dst_host: &self.host,
            dst_ip: self.ip,
            dst_port: Some(self.port),
            src_ip: self.ruleset.source_ip,
            src_port: self.ruleset.source_port,
            network: Some(self.network.as_str()),
            process_name: self.process.as_deref(),
            query_type: self.ruleset.query_type,
            process_path: self.ruleset.process_path.as_deref(),
            package_names: &self.ruleset.package_names,
            wifi_ssid: self.ruleset.wifi_ssid.as_deref(),
            wifi_bssid: self.ruleset.wifi_bssid.as_deref(),
            network_type: self.ruleset.network_type,
            network_is_expensive: self.ruleset.network_is_expensive,
            network_is_constrained: self.ruleset.network_is_constrained,
            network_interface_addresses: &self.ruleset.network_interface_addresses,
            default_interface_addresses: &self.ruleset.default_interface_addresses,
        }
    }

    /// 链式：附加嗅探到的协议；SNI 场景自动把 host 同步为 SNI 域名。
    pub fn with_protocol(mut self, p: crate::sniff::L7Proto) -> Self {
        if let crate::sniff::L7Proto::Sni(sni) = &p {
            if !sni.is_empty() && self.host.parse::<std::net::IpAddr>().is_ok() {
                self.host = sni.clone();
            }
        }
        self.protocol = Some(p);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Block,
    Group(String),
}

impl RouteDecision {
    pub fn from_action(a: &RouteAction) -> Self {
        match a {
            RouteAction::Direct => RouteDecision::Direct,
            RouteAction::Block => RouteDecision::Block,
            RouteAction::Group(g) => RouteDecision::Group(g.clone()),
        }
    }
}

/// 路由引擎；按 [`RoutePlan::steps`] 顺序匹配。
#[derive(Debug, Clone)]
pub struct RouteEngine {
    plan: Arc<RoutePlan>,
    extra_cidrs: Vec<IpNet>,
    rulesets: Option<Arc<RulesetIndex>>,
}

impl RouteEngine {
    pub fn new(plan: RoutePlan) -> Self {
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: None,
        }
    }

    pub fn with_rulesets(plan: RoutePlan, rulesets: Arc<RulesetIndex>) -> Self {
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: Some(rulesets),
        }
    }

    pub fn plan(&self) -> &RoutePlan {
        &self.plan
    }

    pub fn rulesets(&self) -> Option<Arc<RulesetIndex>> {
        self.rulesets.clone()
    }

    pub fn decide(&self, ctx: &FlowContext) -> (RouteDecision, &'static str, String) {
        for step in &self.plan.steps {
            if step_matches(
                &step.matcher,
                ctx,
                &self.extra_cidrs,
                self.rulesets.as_ref(),
            ) {
                return (
                    RouteDecision::from_action(&step.action),
                    matcher_kind(&step.matcher),
                    step.source.clone(),
                );
            }
        }
        (RouteDecision::Direct, "fallback", "implicit-direct".into())
    }
}

fn matcher_kind(m: &RouteMatcher) -> &'static str {
    match m {
        RouteMatcher::Any => "any",
        RouteMatcher::Home => "home",
        RouteMatcher::Cn => "cn",
        RouteMatcher::Ads => "ads",
        RouteMatcher::Service(_) => "service",
        RouteMatcher::Domain(_) => "domain",
        RouteMatcher::Suffix(_) => "suffix",
        RouteMatcher::Keyword(_) => "keyword",
        RouteMatcher::Cidr(_) => "ip",
        RouteMatcher::Port(_) => "port",
        RouteMatcher::PortRange(_, _) => "port_range",
        RouteMatcher::And(_) => "and",
        RouteMatcher::Or(_) => "or",
        RouteMatcher::Network(_) => "network",
        RouteMatcher::Process(_) => "process",
        RouteMatcher::Set(_) => "set",
        RouteMatcher::Proto(_) => "proto",
    }
}

fn step_matches(
    m: &RouteMatcher,
    ctx: &FlowContext,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
) -> bool {
    match m {
        RouteMatcher::Any => true,
        RouteMatcher::Home => match_home(ctx),
        RouteMatcher::Cn => match_cn(ctx),
        RouteMatcher::Ads => match_suffix_list(&ctx.host, builtin::ADS_SUFFIXES),
        RouteMatcher::Service(name) => {
            match_suffix_list(&ctx.host, builtin::service_suffixes(name))
        }
        RouteMatcher::Domain(d) => host_eq(&ctx.host, d),
        RouteMatcher::Suffix(s) => host_suffix(&ctx.host, s),
        RouteMatcher::Keyword(k) => host_contains(&ctx.host, k),
        RouteMatcher::Cidr(s) => match_cidr(ctx, s, extra_cidrs),
        RouteMatcher::Port(p) => ctx.port == *p,
        RouteMatcher::PortRange(lo, hi) => ctx.port >= *lo && ctx.port <= *hi,
        RouteMatcher::Network(n) => n.eq_ignore_ascii_case(ctx.network.as_str()),
        RouteMatcher::Process(name) => ctx
            .process
            .as_ref()
            .map(|p| p.eq_ignore_ascii_case(name))
            .unwrap_or(false),
        RouteMatcher::Set(name) => match rulesets {
            Some(idx) => idx
                .get(name)
                .map(|m| m.matches_context(&ctx.ruleset_match_context()))
                .unwrap_or(false),
            None => false,
        },
        RouteMatcher::Proto(name) => ctx
            .protocol
            .as_ref()
            .map(|p| crate::sniff::proto_name_matches(name, p))
            .unwrap_or(false),
        // `.all` / `.any` 都是短路求值 —— 任一 child 决定结果就立刻退出，
        // 不会把整个 children 列表跑完。这是 typed-key object 形式相对"展开为
        // 多条独立规则"的主要性能优势：N 条 OR 写法只产生 1 条 RouteStep，
        // step_matches 这一层只调一次。
        RouteMatcher::And(parts) => parts
            .iter()
            .all(|m| step_matches(m, ctx, extra_cidrs, rulesets)),
        RouteMatcher::Or(parts) => parts
            .iter()
            .any(|m| step_matches(m, ctx, extra_cidrs, rulesets)),
    }
}

fn host_eq(host: &str, target: &str) -> bool {
    host.eq_ignore_ascii_case(target)
}

fn host_suffix(host: &str, suffix: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let s = suffix.trim_start_matches('.').to_ascii_lowercase();
    h == s || h.ends_with(&format!(".{s}"))
}

/// mihomo `DOMAIN-KEYWORD,foo` —— host 含子串 `foo`（大小写不敏感）。
fn host_contains(host: &str, keyword: &str) -> bool {
    host.to_ascii_lowercase()
        .contains(&keyword.to_ascii_lowercase())
}

fn match_suffix_list(host: &str, list: &[&str]) -> bool {
    list.iter().any(|s| host_suffix(host, s))
}

fn match_home(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::HOME_SUFFIXES) {
        return true;
    }
    if let Some(ip) = ctx.ip {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    if let Ok(ip) = ctx.host.parse::<IpAddr>() {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cn(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::CN_SUFFIXES) {
        return true;
    }
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        return builtin::CN_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cidr(ctx: &FlowContext, cidr: &str, extra: &[IpNet]) -> bool {
    let net: IpNet = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        if net.contains(&ip) {
            return true;
        }
        return extra.iter().any(|n| n.contains(&ip));
    }
    false
}

#[cfg(test)]
mod tests {
    use core_config::runtime_plan::{RoutePlan, RouteStep};
    use core_ruleset::{RulesetFormat, RulesetIndex, RulesetMatcher, parse_ruleset_compiled};

    use super::*;

    fn plan_cn_smart() -> RoutePlan {
        let mut p = RoutePlan {
            preset: "cn_smart".into(),
            r#final: "main".into(),
            steps: vec![],
            sets: Default::default(),
        };
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Home,
            action: RouteAction::Direct,
            source: "preset:home".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Cn,
            action: RouteAction::Direct,
            source: "preset:cn".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Any,
            action: RouteAction::Group("main".into()),
            source: "preset:any".into(),
        });
        p
    }

    #[test]
    fn cn_domain_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.qq.com", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn lan_ip_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_ip("192.168.1.10".parse().unwrap(), 22, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn unknown_goes_main() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.example.org", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Group("main".into()));
    }

    #[test]
    fn host_suffix_case_insensitive() {
        assert!(super::host_suffix("Mail.QQ.com", "qq.com"));
        assert!(!super::host_suffix("noqq.com", "qq.com"));
    }

    #[test]
    fn flow_ruleset_metadata_is_mapped_without_loss() {
        let interface_address = RulesetInterfaceAddress {
            interface_type: 3,
            address: "192.168.0.0/16".parse().unwrap(),
            is_own: false,
        };
        let default_address: IpNet = "10.0.0.0/8".parse().unwrap();
        let mut flow = FlowContext::for_domain("dns.example", 53, NetworkKind::Udp);
        flow.ip = Some("203.0.113.8".parse().unwrap());
        flow.process = Some("resolver".into());
        flow.ruleset = FlowRulesetMetadata {
            source_ip: Some("192.0.2.7".parse().unwrap()),
            source_port: Some(53000),
            query_type: Some(28),
            process_path: Some("/usr/bin/resolver".into()),
            package_names: vec!["com.example.resolver".into()],
            wifi_ssid: Some("office".into()),
            wifi_bssid: Some("00:11:22:33:44:55".into()),
            network_type: Some(3),
            network_is_expensive: Some(true),
            network_is_constrained: Some(false),
            network_interface_addresses: vec![interface_address.clone()],
            default_interface_addresses: vec![default_address],
        };

        let ruleset = flow.ruleset_match_context();
        assert_eq!(ruleset.dst_host, "dns.example");
        assert_eq!(ruleset.dst_ip, flow.ip);
        assert_eq!(ruleset.dst_port, Some(53));
        assert_eq!(ruleset.src_ip, flow.ruleset.source_ip);
        assert_eq!(ruleset.src_port, Some(53000));
        assert_eq!(ruleset.network, Some("udp"));
        assert_eq!(ruleset.process_name, Some("resolver"));
        assert_eq!(ruleset.query_type, Some(28));
        assert_eq!(ruleset.process_path, Some("/usr/bin/resolver"));
        assert_eq!(ruleset.package_names, ["com.example.resolver"]);
        assert_eq!(ruleset.wifi_ssid, Some("office"));
        assert_eq!(ruleset.wifi_bssid, Some("00:11:22:33:44:55"));
        assert_eq!(ruleset.network_type, Some(3));
        assert_eq!(ruleset.network_is_expensive, Some(true));
        assert_eq!(ruleset.network_is_constrained, Some(false));
        assert_eq!(ruleset.network_interface_addresses, [interface_address]);
        assert_eq!(ruleset.default_interface_addresses, [default_address]);
    }

    /// `Or([Port(53), Port(5353)])` 应该在端口为 53 或 5353 时命中，其它时不命中。
    /// 单条规则覆盖多个端口，避免在步表里展开成 N 条独立 step。
    #[test]
    fn or_matcher_short_circuits_on_first_match() {
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Or(vec![
                        RouteMatcher::Port(53),
                        RouteMatcher::Port(5353),
                    ]),
                    action: RouteAction::Group("hijack".into()),
                    source: "or-test".into(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
            sets: Default::default(),
        };
        let eng = RouteEngine::new(plan);
        let (d53, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Udp));
        let (d5353, _, _) = eng.decide(&FlowContext::for_domain("a.com", 5353, NetworkKind::Udp));
        let (d80, _, _) = eng.decide(&FlowContext::for_domain("a.com", 80, NetworkKind::Tcp));
        assert_eq!(d53, RouteDecision::Group("hijack".into()));
        assert_eq!(d5353, RouteDecision::Group("hijack".into()));
        assert_eq!(d80, RouteDecision::Group("main".into()));
    }

    /// `And([Port(53), Network(udp)])` 只在端口和协议同时命中时触发。
    #[test]
    fn and_matcher_requires_all_clauses() {
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::And(vec![
                        RouteMatcher::Port(53),
                        RouteMatcher::Network("udp".into()),
                    ]),
                    action: RouteAction::Group("hijack".into()),
                    source: "and-test".into(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
            sets: Default::default(),
        };
        let eng = RouteEngine::new(plan);
        // 53/udp 命中
        let (d_udp, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Udp));
        assert_eq!(d_udp, RouteDecision::Group("hijack".into()));
        // 53/tcp 不命中（端口对，网络不对）
        let (d_tcp, _, _) = eng.decide(&FlowContext::for_domain("a.com", 53, NetworkKind::Tcp));
        assert_eq!(d_tcp, RouteDecision::Group("main".into()));
        // 80/udp 不命中（网络对，端口不对）
        let (d_other, _, _) = eng.decide(&FlowContext::for_domain("a.com", 80, NetworkKind::Udp));
        assert_eq!(d_other, RouteDecision::Group("main".into()));
    }

    #[test]
    fn set_matcher_receives_network_context() {
        let compiled = parse_ruleset_compiled(
            RulesetFormat::SingboxJson,
            br#"{"version":1,"rules":[{"domain":"dns.example","network":"udp"}]}"#,
        )
        .unwrap();
        let index = RulesetIndex::new();
        index.insert(Arc::new(RulesetMatcher::compile_any("dns", compiled)));
        let plan = RoutePlan {
            preset: "custom".into(),
            r#final: "main".into(),
            steps: vec![
                RouteStep {
                    matcher: RouteMatcher::Set("dns".into()),
                    action: RouteAction::Group("hijack".into()),
                    source: "set-network".into(),
                },
                RouteStep {
                    matcher: RouteMatcher::Any,
                    action: RouteAction::Group("main".into()),
                    source: "any".into(),
                },
            ],
            sets: Default::default(),
        };
        let engine = RouteEngine::with_rulesets(plan, index);
        let udp = engine.decide(&FlowContext::for_domain(
            "dns.example",
            53,
            NetworkKind::Udp,
        ));
        let tcp = engine.decide(&FlowContext::for_domain(
            "dns.example",
            53,
            NetworkKind::Tcp,
        ));
        assert_eq!(udp.0, RouteDecision::Group("hijack".into()));
        assert_eq!(tcp.0, RouteDecision::Group("main".into()));
    }
}
