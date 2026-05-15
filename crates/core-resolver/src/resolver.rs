//! Resolver —— sing-box 兼容的顺序评估 + 缓存持久化 + per-query 选项。
//!
//! 评估流程（[`Resolver::resolve`]）：
//!
//! ```text
//!   for rule in policy.rules:
//!     if rule.matcher matches (host, saved_response):
//!       match rule.action:
//!         Reject  | Accept | Direct | Proxy | Fake | Route | Respond
//!             → 执行并 return（terminal）
//!         Evaluate { server, opts }
//!             → 调 group(server) 解析；保存到 saved_response；继续下一条规则
//!   else if no terminal triggered:
//!     return default_action 的解析结果
//! ```
//!
//! 缓存持久化：
//! * 启动时 [`Resolver::attach_store`] 一次性把 `dns_cache` 表灌进内存；
//! * 运行时缓存写入立刻 enqueue 到 [`AsyncWriter`]，200ms / 256 项触发批量提交；
//! * shutdown 时 [`Resolver::flush_to_store`] 整体快照 + 等待 writer 落盘。

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use core_config::model::{
    FakeMode, Resolver as ResolverCfg, ResolverFallbackFilter as ResolverFallbackFilterCfg,
    ResolverMode,
};
use core_store::{AsyncWriter, Store, store::BatchOp};
use hickory_resolver::proto::rr::{Record, RecordType};
use thiserror::Error;
use tracing::{debug, warn};

use crate::{
    cache::{CacheConfig, DnsCache, Hit, QType},
    fake_ip::{AddressFamily, FakeIpPool},
    group::{DnsGroup, GroupStrategy},
    policy::{
        DnsAction, EvalContext, HostMatch, PolicyEngine, QueryOptions, RejectMethod, matches,
        parse_rule_value,
    },
    upstream::DnsError,
};

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("解析失败: {0}")]
    Failed(String),
    #[error("空响应: {0}")]
    Empty(String),
    #[error("被拒绝: {0}")]
    Rejected(String),
    /// sing-box `reject.method=drop`：不响应。
    #[error("已丢弃 (drop): {0}")]
    Dropped(String),
}

impl From<DnsError> for ResolveError {
    fn from(e: DnsError) -> Self {
        match e {
            DnsError::Empty => ResolveError::Empty(String::new()),
            DnsError::Rejected(s) => ResolveError::Rejected(s),
            other => ResolveError::Failed(other.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum ResolverConfigError {
    #[error("{0}")]
    Invalid(String),
}

impl ResolverConfigError {
    fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAnswer {
    pub ips: Vec<IpAddr>,
    pub stale: bool,
}

impl ResolveAnswer {
    fn live(ips: Vec<IpAddr>) -> Self {
        Self { ips, stale: false }
    }

    fn stale(ips: Vec<IpAddr>) -> Self {
        Self { ips, stale: true }
    }
}

#[derive(Clone)]
pub struct Resolver {
    cfg: ResolverCfg,
    cache: Arc<DnsCache>,
    groups: Arc<HashMap<String, Arc<DnsGroup>>>,
    policy: Arc<PolicyEngine>,
    bootstrap: Arc<DnsGroup>,
    bootstrap_policy: Arc<PolicyEngine>,
    fallback_group: Option<String>,
    fallback_filter: RuntimeFallbackFilter,
    fake_pool: Option<Arc<FakeIpPool>>,
    fake_filter: Option<Arc<crate::fake_ip::FakeIpFilter>>,
    hosts: Option<Arc<crate::hosts::HostsTable>>,
    mapping: Arc<crate::mapping::IpHostMapping>,
    singleflight: Arc<crate::singleflight::Singleflight<(String, crate::cache::QType)>>,
    ipv6_enabled: bool,
    ipv6_timeout: Duration,
    optimistic: bool,
    default_ttl: Duration,
    writer: Option<Arc<AsyncWriter>>,
    /// 全局默认 ECS —— sing-box `dns.client_subnet` 等价。
    /// 优先级最低：rule.opts.client_subnet > server.default_client_subnet > 此 global。
    global_client_subnet: Option<ipnet::IpNet>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("groups", &self.groups.keys().collect::<Vec<_>>())
            .field("fallback_group", &self.fallback_group)
            .field("bootstrap_rules", &self.bootstrap_policy.rules.len())
            .field("ipv6_enabled", &self.ipv6_enabled)
            .field("hosts", &self.hosts.as_ref().map(|h| h.len()))
            .field("fake_filter", &self.fake_filter.is_some())
            .field("optimistic", &self.optimistic)
            .field("cache_len", &self.cache.len())
            .field("persisted", &self.writer.is_some())
            .field("global_client_subnet", &self.global_client_subnet)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
struct RuntimeFallbackFilter {
    ip_cidrs: Vec<ipnet::IpNet>,
    domain_matchers: Vec<HostMatch>,
    geoip: Option<RuntimeGeoIpFilter>,
    missing_geoip_logged: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct RuntimeGeoIpFilter {
    code: String,
    ruleset_candidates: Vec<String>,
}

impl RuntimeFallbackFilter {
    fn try_from_config(cfg: &ResolverFallbackFilterCfg) -> Result<Self, ResolverConfigError> {
        let mut filter = Self::default();
        for (idx, cidr) in cfg.ipcidr.iter().enumerate() {
            let net = cidr.parse::<ipnet::IpNet>().map_err(|e| {
                ResolverConfigError::invalid(format!(
                    "resolver fallback-filter.ipcidr[{idx}] invalid `{cidr}`: {e}"
                ))
            })?;
            filter.ip_cidrs.push(net);
        }
        for (idx, domain) in cfg.domain.iter().enumerate() {
            let matcher = policy_key_to_matcher(domain).map_err(|e| {
                ResolverConfigError::invalid(format!(
                    "resolver fallback-filter.domain[{idx}] invalid `{domain}`: {e}"
                ))
            })?;
            filter.domain_matchers.push(matcher);
        }
        for geosite in &cfg.geosite {
            filter
                .domain_matchers
                .push(set_alias_matcher("geosite", geosite));
        }
        if cfg.geoip {
            filter.geoip = Some(RuntimeGeoIpFilter {
                code: cfg.geoip_code.trim().to_ascii_lowercase(),
                ruleset_candidates: ruleset_name_candidates("geoip", &cfg.geoip_code),
            });
        }
        Ok(filter)
    }

    fn matches_domain(
        &self,
        host: &str,
        rulesets: Option<&Arc<core_ruleset::RulesetIndex>>,
    ) -> bool {
        if self.domain_matchers.is_empty() {
            return false;
        }
        let ctx = EvalContext::default();
        self.domain_matchers
            .iter()
            .any(|m| matches(m, host, &ctx, rulesets))
    }

    fn should_ip_fallback(
        &self,
        ip: IpAddr,
        rulesets: Option<&Arc<core_ruleset::RulesetIndex>>,
    ) -> bool {
        if is_lan_or_special_ip(ip) {
            return false;
        }
        if self.ip_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            return true;
        }
        let Some(geoip) = &self.geoip else {
            return false;
        };
        if geoip.code == "lan" {
            return !is_lan_or_special_ip(ip);
        }
        let Some(idx) = rulesets else {
            self.log_missing_geoip_once(&geoip.ruleset_candidates);
            return false;
        };
        for name in &geoip.ruleset_candidates {
            if let Some(matcher) = idx.get(name) {
                return !matcher.matches("", Some(ip), None, None);
            }
        }
        self.log_missing_geoip_once(&geoip.ruleset_candidates);
        false
    }

    fn log_missing_geoip_once(&self, candidates: &[String]) {
        if self
            .missing_geoip_logged
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            warn!(
                target: "resolver::fallback",
                candidates = ?candidates,
                "fallback-filter.geoip enabled but no matching geoip ruleset is loaded; geoip fallback is inactive until ruleset data is available"
            );
        }
    }
}

fn is_lan_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn qtype_matches_ip(ip: &IpAddr, qtype: QType) -> bool {
    match qtype {
        QType::A => ip.is_ipv4(),
        QType::AAAA => ip.is_ipv6(),
        QType::Both => true,
    }
}

fn filter_ips_for_qtype(ips: Vec<IpAddr>, qtype: QType) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| qtype_matches_ip(ip, qtype))
        .collect()
}

fn family_for_qtype(qtype: QType) -> AddressFamily {
    match qtype {
        QType::AAAA => AddressFamily::V6,
        QType::A | QType::Both => AddressFamily::V4,
    }
}

fn qtype_store_label(qtype: QType) -> &'static str {
    match qtype {
        QType::A => "A",
        QType::AAAA => "AAAA",
        QType::Both => "BOTH",
    }
}

impl Resolver {
    /// 从 Friendly resolver 配置构造运行时 resolver。
    ///
    /// 非 `system` 模式必须优先使用配置里的 IP-literal DoH/DoT/UDP/TCP server，
    /// 否则 TUN 接管后节点域名解析会落回系统 DNS 并自循环。
    pub fn new(cfg: ResolverCfg) -> Self {
        Self::try_new(cfg).expect("resolver config invalid")
    }

    pub fn try_new(cfg: ResolverCfg) -> Result<Self, ResolverConfigError> {
        Self::try_new_with_rulesets(cfg, None)
    }

    pub fn try_new_with_rulesets(
        cfg: ResolverCfg,
        rulesets: Option<Arc<core_ruleset::RulesetIndex>>,
    ) -> Result<Self, ResolverConfigError> {
        let system_group = system_group();
        let mut groups = HashMap::new();
        groups.insert("system".into(), system_group.clone());

        for (name, spec) in &cfg.servers {
            let group = configured_group(name, spec).map_err(|e| {
                ResolverConfigError::invalid(format!(
                    "resolver server `{name}` invalid: {spec}: {e}"
                ))
            })?;
            groups.insert(name.clone(), group);
        }

        if matches!(cfg.mode, ResolverMode::Fake) && matches!(cfg.fake, FakeMode::Off) {
            return Err(ResolverConfigError::invalid(
                "resolver mode fake conflicts with fake: off",
            ));
        }

        let default_group = if !cfg.nameserver.is_empty() {
            register_composite_group(
                &mut groups,
                "default",
                &cfg.nameserver,
                GroupStrategy::Fastest,
            )?
        } else if matches!(cfg.mode, ResolverMode::System) {
            system_group.clone()
        } else {
            return Err(ResolverConfigError::invalid(format!(
                "resolver mode {:?} requires nameserver",
                cfg.mode
            )));
        };
        groups.insert("default".into(), default_group.clone());

        let fallback_group = if cfg.fallback.is_empty() {
            None
        } else {
            register_composite_group(
                &mut groups,
                "fallback",
                &cfg.fallback,
                GroupStrategy::Fastest,
            )?;
            Some("fallback".to_string())
        };

        if !cfg.direct_nameserver.is_empty() {
            register_composite_group(
                &mut groups,
                "direct-nameserver",
                &cfg.direct_nameserver,
                GroupStrategy::Fastest,
            )?;
        }

        if !cfg.default_nameserver.is_empty() {
            register_composite_group(
                &mut groups,
                "default-nameserver",
                &cfg.default_nameserver,
                GroupStrategy::Fastest,
            )?;
        }
        if !cfg.proxy_server_nameserver.is_empty() {
            register_composite_group(
                &mut groups,
                "proxy-server-nameserver",
                &cfg.proxy_server_nameserver,
                GroupStrategy::Fastest,
            )?;
        }
        let bootstrap_group_name = if groups.contains_key("proxy-server-nameserver") {
            "proxy-server-nameserver"
        } else if groups.contains_key("default-nameserver") {
            "default-nameserver"
        } else {
            "default"
        }
        .to_string();
        let bootstrap = groups
            .get(&bootstrap_group_name)
            .cloned()
            .unwrap_or_else(|| default_group.clone());

        let fake_pool = if matches!(cfg.fake, FakeMode::Off) {
            None
        } else {
            Some(Arc::new(FakeIpPool::default()))
        };
        let default_action = default_dns_action(&cfg);
        let mut policy = PolicyEngine::new().with_default(default_action);
        if let Some(idx) = rulesets {
            policy = policy.with_rulesets(idx);
        }
        apply_nameserver_policy(&cfg, &mut groups, &mut policy)?;
        let mut bootstrap_policy =
            PolicyEngine::new().with_default(DnsAction::Direct(bootstrap_group_name.clone()));
        if let Some(idx) = policy.ruleset_index.clone() {
            bootstrap_policy = bootstrap_policy.with_rulesets(idx);
        }
        apply_nameserver_policy_map(
            "proxy-server-nameserver-policy",
            &cfg.proxy_server_nameserver_policy,
            &mut groups,
            &mut bootstrap_policy,
        )?;
        for (idx, value) in cfg.rules.iter().enumerate() {
            let rule = parse_rule_value(value).ok_or_else(|| {
                ResolverConfigError::invalid(format!("resolver rule[{idx}] invalid: {:?}", value))
            })?;
            policy.push(rule);
        }
        let fallback_filter = RuntimeFallbackFilter::try_from_config(&cfg.fallback_filter)?;
        validate_policy(&policy, &groups, fake_pool.is_some())?;
        validate_policy(&bootstrap_policy, &groups, fake_pool.is_some())?;

        // Build hosts table
        let hosts = {
            let mut table = crate::hosts::HostsTable::new();
            if cfg.use_system_hosts {
                table.merge(crate::hosts::HostsTable::load_system());
            }
            if cfg.use_hosts && !cfg.hosts.is_empty() {
                table.merge(crate::hosts::HostsTable::load_mapping(&cfg.hosts));
            }
            if table.is_empty() {
                None
            } else {
                Some(Arc::new(table))
            }
        };

        // Build fake-ip filter
        let fake_filter = if cfg.fake_ip_filter.is_empty() {
            None
        } else {
            Some(Arc::new(crate::fake_ip::FakeIpFilter::new(
                cfg.fake_ip_filter.clone(),
                cfg.fake_ip_filter_mode,
            )))
        };

        let ipv6_enabled = cfg.ipv6;
        let ipv6_timeout = cfg.ipv6_timeout;

        let group_names = groups.keys().cloned().collect::<Vec<_>>().join(",");
        debug!(
            target: "resolver",
            mode = ?cfg.mode,
            bootstrap = %bootstrap.name,
            fallback = ?fallback_group,
            default_action = ?policy.default_action,
            rules = policy.rules.len(),
            groups = %group_names,
            ipv6 = ipv6_enabled,
            hosts_entries = hosts.as_ref().map(|h| h.len()).unwrap_or(0),
            fake_ip_filter = fake_filter.is_some(),
            "resolver configured"
        );

        Ok(Self {
            default_ttl: cfg.cache,
            cfg,
            cache: Arc::new(DnsCache::new(CacheConfig::default())),
            groups: Arc::new(groups),
            policy: Arc::new(policy),
            bootstrap,
            bootstrap_policy: Arc::new(bootstrap_policy),
            fallback_group,
            fallback_filter,
            fake_pool,
            fake_filter,
            hosts,
            mapping: Arc::new(crate::mapping::IpHostMapping::default()),
            singleflight: Arc::new(crate::singleflight::Singleflight::new()),
            ipv6_enabled,
            ipv6_timeout,
            optimistic: true,
            writer: None,
            global_client_subnet: None,
        })
    }

    pub fn cfg(&self) -> &ResolverCfg {
        &self.cfg
    }
    pub fn cache(&self) -> Arc<DnsCache> {
        self.cache.clone()
    }
    pub fn mode(&self) -> ResolverMode {
        self.cfg.mode
    }
    pub fn groups(&self) -> Arc<HashMap<String, Arc<DnsGroup>>> {
        self.groups.clone()
    }
    pub fn fake_pool(&self) -> Option<Arc<FakeIpPool>> {
        self.fake_pool.clone()
    }
    pub fn fake_filter(&self) -> Option<Arc<crate::fake_ip::FakeIpFilter>> {
        self.fake_filter.clone()
    }
    pub fn hosts(&self) -> Option<Arc<crate::hosts::HostsTable>> {
        self.hosts.clone()
    }
    pub fn mapping(&self) -> Arc<crate::mapping::IpHostMapping> {
        self.mapping.clone()
    }
    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled
    }
    pub fn ipv6_timeout(&self) -> Duration {
        self.ipv6_timeout
    }

    /// Reset all persistent DNS connections (DoT pools, DoQ sessions).
    /// Called when the physical network interface changes to force reconnection
    /// on the new interface. Also clears the DNS cache since cached results
    /// may be invalid on the new network.
    pub async fn reset_connections(&self) {
        for group in self.groups.values() {
            group.reset_connections().await;
        }
        self.bootstrap.reset_connections().await;
        self.cache.clear();
        debug!(
            target: "resolver",
            "all DNS connections reset + cache cleared (network interface change)"
        );
    }

    /// Reverse-lookup: find hostname by IP (checks fake pool first, then mapping cache).
    pub fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
        if let Some(pool) = &self.fake_pool {
            if let Some(h) = pool.lookup(ip) {
                return Some(h);
            }
        }
        self.mapping.find_host(ip)
    }

    /// Clash dashboard `/cache/fakeip/flush` —— 清空 fake-ip 池；返回被清条数。
    pub fn flush_fakeip(&self) -> usize {
        self.fake_pool.as_ref().map(|p| p.clear()).unwrap_or(0)
    }

    /// Clash dashboard `/dns/query?name=...&type=A|AAAA|CNAME|TXT|MX|NS`
    /// —— 调用 `resolve()` 拿到 v4/v6，按 qtype 包成 `[{name,type,TTL,data}]`。
    pub async fn resolve_compat(&self, name: &str, qtype: &str) -> serde_json::Value {
        let qtype_u = qtype.to_uppercase();
        let qtype_num: u16 = match qtype_u.as_str() {
            "A" => 1,
            "AAAA" => 28,
            "CNAME" => 5,
            "TXT" => 16,
            "MX" => 15,
            "NS" => 2,
            _ => 1,
        };
        let answers = match qtype_u.as_str() {
            "A" => match self.resolve_qtype(name, QType::A).await {
                Ok(ips) => ips,
                Err(_) => return serde_json::Value::Array(Vec::new()),
            },
            "AAAA" => match self.resolve_qtype(name, QType::AAAA).await {
                Ok(ips) => ips,
                Err(_) => return serde_json::Value::Array(Vec::new()),
            },
            _ => match self.resolve(name).await {
                Ok(ips) => ips,
                Err(_) => return serde_json::Value::Array(Vec::new()),
            },
        };
        let arr: Vec<serde_json::Value> = answers
            .into_iter()
            .filter(|ip| match qtype_u.as_str() {
                "A" => ip.is_ipv4(),
                "AAAA" => ip.is_ipv6(),
                _ => true,
            })
            .map(|ip| {
                serde_json::json!({
                    "name": name,
                    "type": qtype_num,
                    "TTL": 60,
                    "data": ip.to_string(),
                })
            })
            .collect();
        serde_json::Value::Array(arr)
    }
    pub fn policy(&self) -> Arc<PolicyEngine> {
        self.policy.clone()
    }
    pub fn global_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.global_client_subnet
    }

    /// 计算给定 (rule_opts, group_name) 下生效的 ECS：
    /// rule > group 内任一上游的 default > resolver global。
    /// 暴露为公共 API 便于 explain / 调试。
    pub fn effective_client_subnet(
        &self,
        rule_opts: Option<&QueryOptions>,
        group_name: &str,
    ) -> Option<ipnet::IpNet> {
        if let Some(o) = rule_opts {
            if o.client_subnet.is_some() {
                return o.client_subnet;
            }
        }
        if let Some(g) = self.groups.get(group_name) {
            if let Some(net) = g.members.iter().find_map(|u| u.default_client_subnet()) {
                return Some(net);
            }
        }
        self.global_client_subnet
    }

    /// 公开 per-query 入口 —— API 层直接传 [`QueryOptions`]。
    /// 遵循三层 fallback：rule > server > global。
    pub async fn resolve_with_opts(
        &self,
        host: &str,
        opts: &QueryOptions,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        // 复用业务路径 + 把 rule.opts 直接当作 route 选项；用默认 group。
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host_lc = host.trim_end_matches('.').to_lowercase();
        let group = self
            .policy
            .default_action
            .as_ref()
            .and_then(|a| match a {
                DnsAction::Direct(g) | DnsAction::Proxy(g) | DnsAction::Route { server: g, .. } => {
                    Some(g.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| "default".to_string());
        self.lookup_via_qtype(&host_lc, &group, opts, QType::A)
            .await
            .map(|a| a.ips)
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if !self.ipv6_enabled {
            // IPv6 disabled: only query A
            return self.resolve_qtype(host, QType::A).await;
        }
        // Concurrent A + AAAA with ipv6_timeout
        self.resolve_dual_with_timeout(host).await
    }

    async fn resolve_dual_with_timeout(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let host_owned = host.to_string();
        let self_clone = self.clone();
        let ipv6_handle = tokio::spawn({
            let host = host_owned.clone();
            let resolver = self_clone.clone();
            async move { resolver.resolve_qtype(&host, QType::AAAA).await }
        });

        // Resolve A first (blocking)
        let v4_result = self.resolve_qtype(host, QType::A).await;

        // Wait for AAAA with timeout
        let v6_ips = match tokio::time::timeout(self.ipv6_timeout, ipv6_handle).await {
            Ok(Ok(Ok(ips))) => ips,
            _ => Vec::new(),
        };

        match v4_result {
            Ok(mut v4_ips) => {
                v4_ips.extend(v6_ips);
                if v4_ips.is_empty() {
                    Err(ResolveError::Empty(host.to_string()))
                } else {
                    Ok(v4_ips)
                }
            }
            Err(_) if !v6_ips.is_empty() => Ok(v6_ips),
            Err(e) => Err(e),
        }
    }

    pub async fn resolve_qtype(
        &self,
        host: &str,
        qtype: QType,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        self.resolve_qtype_answer(host, qtype).await.map(|a| a.ips)
    }

    pub async fn resolve_qtype_answer(
        &self,
        host: &str,
        qtype: QType,
    ) -> Result<ResolveAnswer, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if qtype_matches_ip(&ip, qtype) {
                Ok(ResolveAnswer::live(vec![ip]))
            } else {
                Ok(ResolveAnswer::live(Vec::new()))
            };
        }
        let host_lc = host.trim_end_matches('.').to_lowercase();
        self.resolve_policy_qtype(&host_lc, qtype).await
    }

    pub async fn resolve_records_answer(
        &self,
        host: &str,
        qtype: u16,
    ) -> Result<Vec<Record>, ResolveError> {
        let host_lc = host.trim_end_matches('.').to_lowercase();
        let record_type = RecordType::from(qtype);
        let ctx = EvalContext::default();

        for rule in &self.policy.rules {
            if !matches(
                &rule.matcher,
                &host_lc,
                &ctx,
                self.policy.ruleset_index.as_ref(),
            ) {
                continue;
            }
            if let Some(records) = self
                .resolve_records_action(&host_lc, record_type, &rule.action, &rule.source)
                .await?
            {
                return Ok(records);
            }
        }

        let default = self
            .policy
            .default_action
            .clone()
            .unwrap_or_else(|| DnsAction::Direct("default".into()));
        self.resolve_records_action(&host_lc, record_type, &default, "<default>")
            .await?
            .ok_or_else(|| {
                ResolveError::Failed("non-terminal DNS action reached end of normal lookup".into())
            })
    }

    async fn resolve_records_action(
        &self,
        host: &str,
        record_type: RecordType,
        action: &DnsAction,
        source: &str,
    ) -> Result<Option<Vec<Record>>, ResolveError> {
        match action {
            DnsAction::Reject(opts) => {
                let method = self.policy.apply_reject_throttle(opts, source);
                match method {
                    RejectMethod::Default => Err(ResolveError::Rejected(host.to_string())),
                    RejectMethod::Drop => Err(ResolveError::Dropped(host.to_string())),
                }
            }
            DnsAction::Accept(_) | DnsAction::Predefined(_) | DnsAction::Fake => {
                Ok(Some(Vec::new()))
            }
            DnsAction::Direct(g) | DnsAction::Proxy(g) => self
                .lookup_records_via_group(host, g, &QueryOptions::default(), record_type)
                .await
                .map(Some),
            DnsAction::Route { server, opts } => self
                .lookup_records_via_group(host, server, opts, record_type)
                .await
                .map(Some),
            DnsAction::Evaluate { server, opts } => {
                let _ = self
                    .lookup_records_via_group(host, server, opts, record_type)
                    .await;
                Ok(None)
            }
            DnsAction::Respond => Err(ResolveError::Failed(
                "respond requires an address response and cannot synthesize arbitrary DNS records"
                    .into(),
            )),
        }
    }

    async fn resolve_policy_qtype(
        &self,
        host_lc: &str,
        qtype: QType,
    ) -> Result<ResolveAnswer, ResolveError> {
        // IPv6 disabled: short-circuit AAAA queries
        if !self.ipv6_enabled && qtype == QType::AAAA {
            return Ok(ResolveAnswer::live(Vec::new()));
        }

        // Hosts check: before policy rules
        if let Some(table) = &self.hosts {
            if let Some(ips) = table.lookup(host_lc, qtype) {
                return Ok(ResolveAnswer::live(ips));
            }
        }

        let mut ctx = EvalContext::default();

        for rule in &self.policy.rules {
            if !matches(
                &rule.matcher,
                host_lc,
                &ctx,
                self.policy.ruleset_index.as_ref(),
            ) {
                continue;
            }
            match rule.action.clone() {
                DnsAction::Reject(opts) => {
                    let method = self.policy.apply_reject_throttle(&opts, &rule.source);
                    return match method {
                        RejectMethod::Default => {
                            self.cache.put_negative(host_lc, qtype);
                            Err(ResolveError::Rejected(host_lc.to_string()))
                        }
                        RejectMethod::Drop => Err(ResolveError::Dropped(host_lc.to_string())),
                    };
                }
                DnsAction::Accept(ips) => {
                    return Ok(ResolveAnswer::live(filter_ips_for_qtype(ips, qtype)));
                }
                DnsAction::Predefined(pre) => {
                    let raw_ips = pre.answer_ips();
                    if raw_ips.is_empty() {
                        return match pre.rcode.unwrap_or(crate::policy::PreRcode::NOERROR) {
                            crate::policy::PreRcode::NXDOMAIN
                            | crate::policy::PreRcode::REFUSED
                            | crate::policy::PreRcode::SERVFAIL
                            | crate::policy::PreRcode::FORMERR
                            | crate::policy::PreRcode::NOTIMP => {
                                Err(ResolveError::Rejected(host_lc.to_string()))
                            }
                            crate::policy::PreRcode::NOERROR => Ok(ResolveAnswer::live(vec![])),
                        };
                    }
                    return Ok(ResolveAnswer::live(filter_ips_for_qtype(raw_ips, qtype)));
                }
                DnsAction::Fake => {
                    if let Some(filter) = &self.fake_filter {
                        if filter.should_skip(host_lc) {
                            return self
                                .lookup_via_qtype(
                                    host_lc,
                                    "default",
                                    &QueryOptions::default(),
                                    qtype,
                                )
                                .await;
                        }
                    }
                    if let Some(pool) = &self.fake_pool {
                        if let Some(ip) = pool.alloc(host_lc, family_for_qtype(qtype)) {
                            return Ok(ResolveAnswer::live(vec![ip]));
                        }
                    }
                    return Err(ResolveError::Failed("fake-ip pool 不可用".into()));
                }
                DnsAction::Direct(g) | DnsAction::Proxy(g) => {
                    return self
                        .lookup_via_qtype(host_lc, &g, &QueryOptions::default(), qtype)
                        .await;
                }
                DnsAction::Route { server, opts } => {
                    return self.lookup_via_qtype(host_lc, &server, &opts, qtype).await;
                }
                DnsAction::Evaluate { server, opts } => {
                    if let Ok(answer) = self.lookup_via_qtype(host_lc, &server, &opts, qtype).await
                    {
                        ctx.saved_response = Some(answer.ips);
                        ctx.saved_opts = Some(opts);
                    }
                    continue;
                }
                DnsAction::Respond => {
                    return ctx
                        .saved_response
                        .clone()
                        .map(ResolveAnswer::live)
                        .ok_or_else(|| {
                            ResolveError::Failed("respond 命中但无前序 evaluate 保存的响应".into())
                        });
                }
            }
        }

        // 默认动作
        let default = self
            .policy
            .default_action
            .clone()
            .unwrap_or_else(|| DnsAction::Direct("default".into()));
        match default {
            DnsAction::Reject(opts) => {
                let method = self.policy.apply_reject_throttle(&opts, "<default>");
                match method {
                    RejectMethod::Default => {
                        self.cache.put_negative(host_lc, qtype);
                        Err(ResolveError::Rejected(host_lc.to_string()))
                    }
                    RejectMethod::Drop => Err(ResolveError::Dropped(host_lc.to_string())),
                }
            }
            DnsAction::Accept(ips) => Ok(ResolveAnswer::live(filter_ips_for_qtype(ips, qtype))),
            DnsAction::Predefined(pre) => {
                let raw_ips = pre.answer_ips();
                if raw_ips.is_empty() {
                    Err(ResolveError::Rejected(host_lc.to_string()))
                } else {
                    Ok(ResolveAnswer::live(filter_ips_for_qtype(raw_ips, qtype)))
                }
            }
            DnsAction::Direct(g) | DnsAction::Proxy(g) | DnsAction::Route { server: g, .. } => {
                self.lookup_via_qtype(host_lc, &g, &QueryOptions::default(), qtype)
                    .await
            }
            DnsAction::Fake => {
                if let Some(filter) = &self.fake_filter {
                    if filter.should_skip(host_lc) {
                        return self
                            .lookup_via_qtype(host_lc, "default", &QueryOptions::default(), qtype)
                            .await;
                    }
                }
                if let Some(pool) = &self.fake_pool {
                    if let Some(ip) = pool.alloc(host_lc, family_for_qtype(qtype)) {
                        return Ok(ResolveAnswer::live(vec![ip]));
                    }
                }
                Err(ResolveError::Failed("fake-ip pool 不可用".into()))
            }
            DnsAction::Evaluate { .. } | DnsAction::Respond => Err(ResolveError::Failed(
                "default action 不可为 evaluate/respond".into(),
            )),
        }
    }

    /// 直连出站专用解析（mihomo `DirectHostResolver` 等价）。
    ///
    /// 优先级（对齐 mihomo `executor.go::updateDNS`）：
    /// 1. `direct-nameserver` group（若配置）—— 固定走该组，不应用 policy；
    /// 2. 否则回退到主 `default`/`nameserver` group —— 即 mihomo `r.Resolver`；
    ///
    /// **绝不**回退到 `proxy-server-nameserver` —— 该组用于解析代理节点 host，
    /// 与 DIRECT 出站目标无关，串错会导致 DIRECT 流量全部走代理 DNS（典型表现：
    /// 节点 DNS 失败时所有 DIRECT 站点解析失败）。
    ///
    /// 直连流量的解析必须避开 fake-ip / 业务策略链，否则 fake IP 会被直接发
    /// 到目标，造成不可路由的 198.18/15。
    pub async fn resolve_via_direct(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host_lc = host.trim_end_matches('.').to_lowercase();
        if let Some(table) = &self.hosts {
            let qtype = if self.ipv6_enabled {
                crate::cache::QType::Both
            } else {
                crate::cache::QType::A
            };
            if let Some(ips) = table.lookup(&host_lc, qtype) {
                if !ips.is_empty() {
                    return Ok(ips);
                }
            }
        }
        // direct-nameserver 优先；其次 default 主组（mihomo r.Resolver 等价）。
        // 注意：故意 NOT 回退到 bootstrap/proxy-server-nameserver。
        let group = self
            .groups
            .get("direct-nameserver")
            .cloned()
            .or_else(|| self.groups.get("default").cloned())
            .ok_or_else(|| {
                ResolveError::Failed(
                    "no direct-nameserver or default resolver group available".into(),
                )
            })?;
        self.resolve_via_group_dual(host, &group).await
    }

    /// 通过指定 group 解析 A，必要时再试 AAAA（IPv6 启用时）。
    /// 抽出供 `resolve_via_direct` 复用。
    async fn resolve_via_group_dual(
        &self,
        host: &str,
        group: &Arc<DnsGroup>,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let started = std::time::Instant::now();
        debug!(
            target: "resolver",
            host,
            group = %group.name,
            qtype = "A",
            "direct lookup begin"
        );
        match group.resolve(host, false).await {
            Ok(v) if !v.is_empty() => {
                debug!(
                    target: "resolver",
                    host,
                    group = %group.name,
                    qtype = "A",
                    count = v.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "direct lookup ok"
                );
                Ok(v)
            }
            Ok(_) if self.ipv6_enabled => {
                let ips = group.resolve(host, true).await?;
                Ok(ips)
            }
            Ok(_) => Ok(Vec::new()),
            Err(e) if self.ipv6_enabled => match group.resolve(host, true).await {
                Ok(ips) => Ok(ips),
                Err(_) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        }
    }

    pub async fn resolve_via_bootstrap(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host_lc = host.trim_end_matches('.').to_lowercase();
        let mut action = self
            .bootstrap_policy
            .default_action
            .clone()
            .unwrap_or_else(|| DnsAction::Direct(self.bootstrap.name.clone()));
        let ctx = EvalContext::default();
        for rule in &self.bootstrap_policy.rules {
            if matches(
                &rule.matcher,
                &host_lc,
                &ctx,
                self.bootstrap_policy.ruleset_index.as_ref(),
            ) {
                action = rule.action.clone();
                break;
            }
        }
        let group_name = match action {
            DnsAction::Direct(g) | DnsAction::Proxy(g) => g,
            DnsAction::Route { server, .. } => server,
            DnsAction::Accept(ips) => return Ok(ips),
            DnsAction::Reject(opts) => {
                let method = self
                    .bootstrap_policy
                    .apply_reject_throttle(&opts, "bootstrap");
                return match method {
                    RejectMethod::Default => Err(ResolveError::Rejected(host_lc)),
                    RejectMethod::Drop => Err(ResolveError::Dropped(host_lc)),
                };
            }
            DnsAction::Fake
            | DnsAction::Predefined(_)
            | DnsAction::Evaluate { .. }
            | DnsAction::Respond => {
                return Err(ResolveError::Failed(
                    "proxy-server-nameserver-policy action must route to a resolver group".into(),
                ));
            }
        };
        let group = self.groups.get(&group_name).cloned().ok_or_else(|| {
            ResolveError::Failed(format!("unknown bootstrap resolver group: {group_name}"))
        })?;
        let started = std::time::Instant::now();
        debug!(
            target: "resolver",
            host,
            group = %group.name,
            qtype = "A",
            "bootstrap lookup begin"
        );
        match group.resolve(host, false).await {
            Ok(v) if !v.is_empty() => {
                debug!(
                    target: "resolver",
                    host,
                    group = %group.name,
                    qtype = "A",
                    count = v.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "bootstrap lookup ok"
                );
                Ok(v)
            }
            Ok(_) => {
                debug!(
                    target: "resolver",
                    host,
                    group = %group.name,
                    qtype = "A",
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "bootstrap lookup empty, trying AAAA"
                );
                let ips = group.resolve(host, true).await?;
                debug!(
                    target: "resolver",
                    host,
                    group = %group.name,
                    qtype = "AAAA",
                    count = ips.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "bootstrap lookup ok"
                );
                Ok(ips)
            }
            Err(e) => {
                debug!(
                    target: "resolver",
                    host,
                    group = %group.name,
                    qtype = "A",
                    error = %e,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "bootstrap lookup failed, trying AAAA"
                );
                match group.resolve(host, true).await {
                    Ok(ips) => {
                        debug!(
                            target: "resolver",
                            host,
                            group = %group.name,
                            qtype = "AAAA",
                            count = ips.len(),
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "bootstrap lookup ok"
                        );
                        Ok(ips)
                    }
                    Err(e) => {
                        warn!(
                            target: "resolver",
                            host,
                            group = %group.name,
                            qtype = "AAAA",
                            error = %e,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "bootstrap lookup failed"
                        );
                        Err(e.into())
                    }
                }
            }
        }
    }

    async fn lookup_via_qtype(
        &self,
        host: &str,
        group_name: &str,
        opts: &QueryOptions,
        qtype: QType,
    ) -> Result<ResolveAnswer, ResolveError> {
        // 计算有效 ECS（rule > server > global）；当前层用于 trace + 后续 EDNS 发送。
        let effective_ecs = self.effective_client_subnet(Some(opts), group_name);
        if let Some(net) = effective_ecs {
            tracing::trace!(target: "resolver::ecs", host, group = group_name, %net, "effective client_subnet");
        }

        if !opts.disable_cache {
            let disable_optimistic = opts.disable_optimistic_cache || !self.optimistic;
            let (cached, hit, ticket) = self.cache.get_with(host, qtype, disable_optimistic);
            if let Some(ips) = cached {
                if hit == Hit::Stale {
                    if let Some(t) = ticket {
                        let rx = self.spawn_refresh(group_name.to_string(), opts.clone(), t, true);
                        match tokio::time::timeout(self.cache.config().client_response_timeout, rx)
                            .await
                        {
                            Ok(Ok(Ok(fresh))) if !fresh.is_empty() => {
                                return Ok(ResolveAnswer::live(fresh));
                            }
                            Ok(Ok(Err(e))) => {
                                debug!(
                                    target: "resolver::cache",
                                    host,
                                    group = %group_name,
                                    qtype = ?qtype,
                                    error = %e,
                                    "stale refresh failed; serving stale"
                                );
                            }
                            Ok(Err(_closed)) => {
                                debug!(
                                    target: "resolver::cache",
                                    host,
                                    group = %group_name,
                                    qtype = ?qtype,
                                    "stale refresh task ended without result; serving stale"
                                );
                            }
                            Err(_elapsed) => {
                                debug!(
                                    target: "resolver::cache",
                                    host,
                                    group = %group_name,
                                    qtype = ?qtype,
                                    timeout_ms = self.cache.config().client_response_timeout.as_millis() as u64,
                                    "stale refresh timed out; serving stale while refresh continues"
                                );
                            }
                            _ => {}
                        }
                    }
                } else if let Some(t) = ticket {
                    self.spawn_refresh(group_name.to_string(), opts.clone(), t, false);
                }
                if !ips.is_empty() {
                    return Ok(if hit == Hit::Stale {
                        ResolveAnswer::stale(ips)
                    } else {
                        ResolveAnswer::live(ips)
                    });
                }
                return Err(ResolveError::Rejected(format!("{host} (negative cache)")));
            }
        }

        // Singleflight: deduplicate concurrent uncached queries for the same (host, qtype)
        let sf_key = (host.to_string(), qtype);
        let this = self.clone();
        let host_owned = host.to_string();
        let group_owned = group_name.to_string();
        let ips_result = self
            .singleflight
            .do_once(sf_key, move || async move {
                if group_owned == "default" {
                    this.resolve_default_qtype_uncached(&host_owned, qtype)
                        .await
                        .map_err(|e| match e {
                            ResolveError::Failed(s) => crate::upstream::DnsError::Failed(s),
                            ResolveError::Empty(s) => crate::upstream::DnsError::Failed(s),
                            ResolveError::Rejected(s) => crate::upstream::DnsError::Rejected(s),
                            ResolveError::Dropped(s) => crate::upstream::DnsError::Rejected(s),
                        })
                } else {
                    let group = this.groups.get(&group_owned).cloned().ok_or_else(|| {
                        crate::upstream::DnsError::Failed(format!(
                            "unknown resolver server/group: {group_owned}"
                        ))
                    })?;
                    resolve_group_qtype(group, &host_owned, qtype).await
                }
            })
            .await;
        let ips = match ips_result {
            Ok(v) => v,
            Err(e) => {
                return Err(ResolveError::from((*e).clone()));
            }
        };

        if !opts.disable_cache && !ips.is_empty() {
            let ttl = match opts.rewrite_ttl {
                Some(s) => Duration::from_secs(s as u64),
                None => self.default_ttl,
            };
            self.cache.put(host, qtype, ips.clone(), ttl, "live");
            if let Some(w) = &self.writer {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = w.enqueue(BatchOp::PutDnsCache(
                    format!("{}|{}", host, qtype_store_label(qtype)),
                    core_store::DnsCacheBlob {
                        ips: ips.iter().map(|ip| ip.to_string()).collect(),
                        expire_secs: now_secs + ttl.as_secs(),
                        origin: "live".into(),
                    },
                ));
            }
        }
        Ok(ResolveAnswer::live(ips))
    }

    async fn resolve_default_qtype_uncached(
        &self,
        host: &str,
        qtype: QType,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        resolve_default_qtype_uncached_parts(
            self.groups.clone(),
            self.policy.clone(),
            self.fallback_group.clone(),
            self.fallback_filter.clone(),
            host,
            qtype,
        )
        .await
    }

    async fn lookup_records_via_group(
        &self,
        host: &str,
        group_name: &str,
        opts: &QueryOptions,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ResolveError> {
        let effective_ecs = self.effective_client_subnet(Some(opts), group_name);
        if let Some(net) = effective_ecs {
            tracing::trace!(target: "resolver::ecs", host, group = group_name, %net, "effective client_subnet");
        }
        let group = self.groups.get(group_name).cloned().ok_or_else(|| {
            ResolveError::Failed(format!("unknown resolver server/group: {group_name}"))
        })?;
        group
            .resolve_records(host, record_type)
            .await
            .map_err(Into::into)
    }

    fn spawn_refresh(
        &self,
        group_name: String,
        opts: QueryOptions,
        ticket: crate::cache::PrefetchTicket,
        notify: bool,
    ) -> tokio::sync::oneshot::Receiver<Result<Vec<IpAddr>, DnsError>> {
        let groups = self.groups.clone();
        let cache = self.cache.clone();
        let writer = self.writer.clone();
        let default_ttl = self.default_ttl;
        let policy = self.policy.clone();
        let fallback_group = self.fallback_group.clone();
        let fallback_filter = self.fallback_filter.clone();
        let host = ticket.host.clone();
        let qtype = ticket.qtype;
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = async {
                if group_name == "default" {
                    return resolve_default_qtype_uncached_parts(
                        groups.clone(),
                        policy,
                        fallback_group,
                        fallback_filter,
                        &host,
                        qtype,
                    )
                    .await
                    .map_err(|e| DnsError::Failed(e.to_string()));
                }
                let Some(group) = groups.get(&group_name).cloned() else {
                    return Err(DnsError::Failed(format!(
                        "unknown resolver group: {group_name}"
                    )));
                };
                resolve_group_qtype(group, &host, qtype).await
            }
            .await;

            match &result {
                Ok(v) if !v.is_empty() => {
                    ticket.mark_success();
                    let ttl = match opts.rewrite_ttl {
                        Some(s) => Duration::from_secs(s as u64),
                        None => default_ttl,
                    };
                    cache.put(&host, qtype, v.clone(), ttl, "prefetch");
                    if let Some(w) = &writer {
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = w.enqueue(BatchOp::PutDnsCache(
                            format!("{}|{}", host, qtype_store_label(qtype)),
                            core_store::DnsCacheBlob {
                                ips: v.iter().map(|ip| ip.to_string()).collect(),
                                expire_secs: now_secs + ttl.as_secs(),
                                origin: "prefetch".into(),
                            },
                        ));
                    }
                    debug!(
                        target: "resolver::prefetch",
                        host,
                        group = %group_name,
                        qtype = ?qtype,
                        "refreshed"
                    );
                }
                Ok(_) => {
                    ticket.mark_failure();
                    warn!(
                        target: "resolver::prefetch",
                        host,
                        group = %group_name,
                        qtype = ?qtype,
                        "refresh returned empty"
                    );
                }
                Err(e) => {
                    ticket.mark_failure();
                    warn!(
                        target: "resolver::prefetch",
                        host,
                        group = %group_name,
                        qtype = ?qtype,
                        error = %e,
                        "refresh failed"
                    );
                }
            }
            if notify {
                let _ = tx.send(result);
            }
            drop(ticket);
        });
        rx
    }

    pub fn attach_store(&mut self, store: Arc<Store>) {
        if let Ok(rows) = store.iter_json::<core_store::DnsCacheBlob>(core_store::schema::DNS_CACHE)
        {
            self.cache.load(rows);
        }
        let writer = AsyncWriter::spawn(store);
        self.writer = Some(writer);
    }

    pub async fn flush_to_store(&self) {
        if let Some(w) = &self.writer {
            let dump = self.cache.dump();
            let ops: Vec<BatchOp> = dump
                .into_iter()
                .map(|(k, v)| BatchOp::PutDnsCache(k, v))
                .collect();
            if !ops.is_empty() {
                let _ = w.enqueue_batch(ops);
            }
            w.shutdown().await;
        }
    }
}

async fn resolve_default_qtype_uncached_parts(
    groups: Arc<HashMap<String, Arc<DnsGroup>>>,
    policy: Arc<PolicyEngine>,
    fallback_group: Option<String>,
    fallback_filter: RuntimeFallbackFilter,
    host: &str,
    qtype: QType,
) -> Result<Vec<IpAddr>, ResolveError> {
    let main = groups
        .get("default")
        .cloned()
        .ok_or_else(|| ResolveError::Failed("unknown resolver server/group: default".into()))?;
    let Some(fallback_name) = fallback_group else {
        return resolve_group_qtype(main, host, qtype)
            .await
            .map_err(Into::into);
    };
    let fallback = groups.get(&fallback_name).cloned().ok_or_else(|| {
        ResolveError::Failed(format!("unknown resolver fallback group: {fallback_name}"))
    })?;

    if fallback_filter.matches_domain(host, policy.ruleset_index.as_ref()) {
        debug!(
            target: "resolver::fallback",
            host,
            fallback = %fallback.name,
            qtype = ?qtype,
            reason = "domain-filter",
            "query fallback nameserver only"
        );
        return resolve_group_qtype(fallback, host, qtype)
            .await
            .map_err(Into::into);
    }

    match resolve_group_qtype(main.clone(), host, qtype).await {
        Ok(ips) if !ips.is_empty() => {
            let should_fallback = ips
                .iter()
                .copied()
                .any(|ip| fallback_filter.should_ip_fallback(ip, policy.ruleset_index.as_ref()));
            if !should_fallback {
                debug!(
                    target: "resolver::fallback",
                    host,
                    main = %main.name,
                    qtype = ?qtype,
                    count = ips.len(),
                    "main nameserver accepted"
                );
                return Ok(ips);
            }
            debug!(
                target: "resolver::fallback",
                host,
                main = %main.name,
                fallback = %fallback.name,
                qtype = ?qtype,
                main_ips = ?ips,
                "main nameserver result matched fallback-filter; querying fallback"
            );
            resolve_group_qtype(fallback, host, qtype)
                .await
                .map_err(Into::into)
        }
        Ok(_) => {
            debug!(
                target: "resolver::fallback",
                host,
                main = %main.name,
                fallback = %fallback.name,
                qtype = ?qtype,
                "main nameserver returned empty; querying fallback"
            );
            resolve_group_qtype(fallback, host, qtype)
                .await
                .map_err(Into::into)
        }
        Err(e) => {
            debug!(
                target: "resolver::fallback",
                host,
                main = %main.name,
                fallback = %fallback.name,
                qtype = ?qtype,
                error = %e,
                "main nameserver failed; querying fallback"
            );
            resolve_group_qtype(fallback, host, qtype)
                .await
                .map_err(Into::into)
        }
    }
}

async fn resolve_group_qtype(
    group: Arc<DnsGroup>,
    host: &str,
    qtype: QType,
) -> Result<Vec<IpAddr>, DnsError> {
    match qtype {
        QType::A => group.resolve(host, false).await,
        QType::AAAA => group.resolve(host, true).await,
        QType::Both => {
            let mut out = Vec::new();
            let mut last_err = None;
            match group.resolve(host, false).await {
                Ok(v) => out.extend(v),
                Err(e) => last_err = Some(e),
            }
            match group.resolve(host, true).await {
                Ok(v) => out.extend(v),
                Err(e) => last_err = Some(e),
            }
            if out.is_empty() {
                Err(last_err.unwrap_or(DnsError::Empty))
            } else {
                Ok(out)
            }
        }
    }
}

fn system_group() -> Arc<DnsGroup> {
    let system_up = Arc::new(crate::upstream::system::SystemUpstream::new("system"));
    Arc::new(DnsGroup::new(
        "system",
        GroupStrategy::Fallback,
        vec![system_up as _],
    ))
}

fn register_composite_group(
    groups: &mut HashMap<String, Arc<DnsGroup>>,
    name: &str,
    specs: &[String],
    strategy: GroupStrategy,
) -> Result<Arc<DnsGroup>, ResolverConfigError> {
    let mut members = Vec::new();
    for (idx, spec) in specs.iter().enumerate() {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Some(group) = groups.get(spec) {
            members.extend(group.members.iter().cloned());
            continue;
        }
        let upstream_name = format!("{name}#{idx}");
        let upstream = configured_upstream(&upstream_name, spec).map_err(|e| {
            ResolverConfigError::invalid(format!(
                "resolver group `{name}` nameserver[{idx}] invalid `{spec}`: {e}"
            ))
        })?;
        members.push(upstream);
    }
    if members.is_empty() {
        return Err(ResolverConfigError::invalid(format!(
            "resolver group `{name}` has no usable nameserver"
        )));
    }
    let group = Arc::new(DnsGroup::new(name, strategy, members));
    groups.insert(name.to_string(), group.clone());
    Ok(group)
}

fn apply_nameserver_policy(
    cfg: &ResolverCfg,
    groups: &mut HashMap<String, Arc<DnsGroup>>,
    policy: &mut PolicyEngine,
) -> Result<(), ResolverConfigError> {
    apply_nameserver_policy_map("nameserver-policy", &cfg.nameserver_policy, groups, policy)
}

fn apply_nameserver_policy_map(
    label: &str,
    map: &serde_yaml::Mapping,
    groups: &mut HashMap<String, Arc<DnsGroup>>,
    policy: &mut PolicyEngine,
) -> Result<(), ResolverConfigError> {
    for (idx, (key, value)) in map.iter().enumerate() {
        let key = key.as_str().ok_or_else(|| {
            ResolverConfigError::invalid(format!("resolver {label}[{idx}] key must be string"))
        })?;
        let specs = nameserver_policy_value_to_vec(value).map_err(|e| {
            ResolverConfigError::invalid(format!(
                "resolver {label} `{key}` nameserver invalid: {e}"
            ))
        })?;
        let group_name = format!("{label}-{idx}");
        register_composite_group(groups, &group_name, &specs, GroupStrategy::Fastest)?;
        for matcher in expand_policy_key_matchers(key)? {
            policy.push(crate::policy::PolicyRule {
                matcher,
                action: DnsAction::Route {
                    server: group_name.clone(),
                    opts: QueryOptions::default(),
                },
                source: format!("{label}:{key}"),
            });
        }
    }
    Ok(())
}

fn nameserver_policy_value_to_vec(value: &serde_yaml::Value) -> Result<Vec<String>, String> {
    if let Some(s) = value.as_str() {
        return Ok(vec![s.to_string()]);
    }
    if let Some(seq) = value.as_sequence() {
        let mut out = Vec::with_capacity(seq.len());
        for (idx, item) in seq.iter().enumerate() {
            let Some(s) = item.as_str() else {
                return Err(format!("item[{idx}] must be string"));
            };
            out.push(s.to_string());
        }
        return Ok(out);
    }
    Err("value must be string or string list".into())
}

fn expand_policy_key_matchers(key: &str) -> Result<Vec<HostMatch>, ResolverConfigError> {
    let trimmed = key.trim();
    let lower = trimmed.to_ascii_lowercase();
    let mut out = Vec::new();
    if lower.starts_with("geosite:") {
        for part in trimmed[8..].split(',') {
            let part = part
                .trim()
                .strip_prefix("geosite:")
                .unwrap_or_else(|| part.trim());
            if !part.is_empty() {
                out.push(set_alias_matcher("geosite", part));
            }
        }
    } else if lower.starts_with("rule-set:") {
        for part in trimmed[9..].split(',') {
            let part = strip_ruleset_prefix(part.trim());
            if !part.is_empty() {
                out.push(HostMatch::Set(part.to_string()));
            }
        }
    } else if lower.starts_with("ruleset:") {
        for part in trimmed[8..].split(',') {
            let part = strip_ruleset_prefix(part.trim());
            if !part.is_empty() {
                out.push(HostMatch::Set(part.to_string()));
            }
        }
    } else {
        for part in trimmed.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                out.push(policy_key_to_matcher(part).map_err(|e| {
                    ResolverConfigError::invalid(format!(
                        "resolver nameserver-policy key `{key}` invalid: {e}"
                    ))
                })?);
            }
        }
    }
    if out.is_empty() {
        return Err(ResolverConfigError::invalid(
            "resolver nameserver-policy key is empty",
        ));
    }
    Ok(out)
}

fn strip_ruleset_prefix(s: &str) -> &str {
    s.strip_prefix("rule-set:")
        .or_else(|| s.strip_prefix("ruleset:"))
        .unwrap_or(s)
}

fn policy_key_to_matcher(key: &str) -> Result<HostMatch, String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("empty domain".into());
    }
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("geosite:") {
        return Ok(set_alias_matcher("geosite", &key[8..]));
    }
    if lower.starts_with("rule-set:") {
        return Ok(HostMatch::Set(key[9..].trim().to_string()));
    }
    if lower.starts_with("ruleset:") {
        return Ok(HostMatch::Set(key[8..].trim().to_string()));
    }
    if let Some(rest) = key.strip_prefix("+.") {
        return Ok(HostMatch::Suffix(rest.trim_start_matches('.').to_string()));
    }
    if let Some(rest) = key.strip_prefix("*.") {
        return Ok(HostMatch::Suffix(rest.trim_start_matches('.').to_string()));
    }
    if let Some(rest) = key.strip_prefix('.') {
        return Ok(HostMatch::Suffix(rest.trim_start_matches('.').to_string()));
    }
    if let Some(rest) = key.strip_prefix('=') {
        return Ok(HostMatch::Domain(rest.trim_end_matches('.').to_string()));
    }
    if key.contains('*') {
        let stripped = key.trim_start_matches('*').trim_start_matches('.');
        if stripped.is_empty() {
            return Err("wildcard domain has empty suffix".into());
        }
        return Ok(HostMatch::Suffix(stripped.to_string()));
    }
    Ok(HostMatch::Domain(key.trim_end_matches('.').to_string()))
}

fn set_alias_matcher(kind: &str, name: &str) -> HostMatch {
    let candidates = ruleset_name_candidates(kind, name);
    if candidates.len() == 1 {
        HostMatch::Set(candidates[0].clone())
    } else {
        HostMatch::Or(candidates.into_iter().map(HostMatch::Set).collect())
    }
}

fn ruleset_name_candidates(kind: &str, name: &str) -> Vec<String> {
    let raw = name.trim().trim_start_matches(':').to_ascii_lowercase();
    let mut out = Vec::<String>::new();
    let mut push = |s: String| {
        if !s.is_empty() && !out.iter().any(|old| old == &s) {
            out.push(s);
        }
    };
    push(raw.clone());
    push(format!("{kind}-{raw}"));
    match (kind, raw.as_str()) {
        ("geosite", "cn") => push("cn-domain".into()),
        ("geoip", "cn") => push("geoip-cn".into()),
        ("geoip", "private") => push("geoip-private".into()),
        _ => {}
    }
    out
}

fn default_dns_action(cfg: &ResolverCfg) -> DnsAction {
    if matches!(cfg.fake, FakeMode::Force) || matches!(cfg.mode, ResolverMode::Fake) {
        return DnsAction::Fake;
    }
    match cfg.mode {
        ResolverMode::System => DnsAction::Direct("system".into()),
        ResolverMode::Normal => DnsAction::Direct("default".into()),
        ResolverMode::Fake => DnsAction::Fake,
    }
}

fn validate_policy(
    policy: &PolicyEngine,
    groups: &HashMap<String, Arc<DnsGroup>>,
    fake_available: bool,
) -> Result<(), ResolverConfigError> {
    if let Some(action) = &policy.default_action {
        validate_action(action, groups, fake_available, "resolver default action")?;
    }
    for (idx, rule) in policy.rules.iter().enumerate() {
        validate_action(
            &rule.action,
            groups,
            fake_available,
            &format!("resolver rule[{idx}]"),
        )?;
    }
    Ok(())
}

fn validate_action(
    action: &DnsAction,
    groups: &HashMap<String, Arc<DnsGroup>>,
    fake_available: bool,
    context: &str,
) -> Result<(), ResolverConfigError> {
    let group = match action {
        DnsAction::Direct(name) | DnsAction::Proxy(name) => Some(name),
        DnsAction::Route { server, .. } | DnsAction::Evaluate { server, .. } => Some(server),
        _ => None,
    };
    if let Some(name) = group {
        if !groups.contains_key(name) {
            return Err(ResolverConfigError::invalid(format!(
                "{context} references unknown server/group `{name}`"
            )));
        }
    }
    if matches!(action, DnsAction::Fake) && !fake_available {
        return Err(ResolverConfigError::invalid(format!(
            "{context} uses fake action but fake is off"
        )));
    }
    Ok(())
}

fn configured_group(name: &str, spec: &str) -> Result<Arc<DnsGroup>, String> {
    let upstream = configured_upstream(name, spec)?;
    Ok(Arc::new(DnsGroup::new(
        name,
        GroupStrategy::Fallback,
        vec![upstream],
    )))
}

fn configured_upstream(
    name: &str,
    spec: &str,
) -> Result<Arc<dyn crate::upstream::DnsUpstream>, String> {
    let spec = spec.trim();
    let lower = spec.to_ascii_lowercase();
    if lower == "system" || lower == "system://" {
        return Ok(Arc::new(crate::upstream::system::SystemUpstream::new(name))
            as Arc<dyn crate::upstream::DnsUpstream>);
    }
    if lower.starts_with("https://") {
        // DoH: hickory + HTTP/2。SNI 默认用 host —— 与 mihomo
        // `tlsCfg.ServerName = host` 行为一致。
        // - host 是 IP literal → rustls 走 `ServerName::IpAddress`，跳过 SNI
        //   扩展，依赖 IP-SAN cert 验证（公共 DoH 服务都签了 IP SAN）。
        // - host 是域名 → 用域名做 SNI，按域名验证 cert。
        // 用户可通过 `?sni=...` 或 `#sni=...` 显式覆盖。
        let (host, port, sni) = parse_server_endpoint(spec, "https://", 443)?;
        let sni_name = sni
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone());
        let params = extract_upstream_params(spec);
        let upstream: Arc<dyn crate::upstream::DnsUpstream> = Arc::new(
            crate::upstream::hickory::HickoryUpstream::doh(name, &host, port, Some(sni_name))
                .map_err(|e| e.to_string())?,
        );
        return Ok(crate::upstream::FilteredUpstream::wrap_if_needed(
            upstream, &params,
        ));
    }
    if lower.starts_with("tls://") {
        // DoT: SNI 默认 host（IP 走 IP-SAN cert，域名走 DnsName）。
        let (host, port, sni) = parse_server_endpoint(spec, "tls://", 853)?;
        let addr = resolve_host_to_socket(&host, port, "DoT")?;
        let sni_name = sni
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone());
        let params = extract_upstream_params(spec);
        let upstream: Arc<dyn crate::upstream::DnsUpstream> = if params.disable_reuse {
            Arc::new(crate::upstream::marked::MarkedTcpDnsUpstream::dot_no_pool(
                name, addr, sni_name,
            ))
        } else {
            Arc::new(crate::upstream::marked::MarkedTcpDnsUpstream::dot(
                name, addr, sni_name,
            ))
        };
        return Ok(crate::upstream::FilteredUpstream::wrap_if_needed(
            upstream, &params,
        ));
    }
    if lower.starts_with("quic://") {
        // DoQ: SNI 默认 host。
        let (host, port, sni) = parse_server_endpoint(spec, "quic://", 853)?;
        let addr = resolve_host_to_socket(&host, port, "DoQ")?;
        let sni_name = sni
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone());
        let params = extract_upstream_params(spec);
        let upstream: Arc<dyn crate::upstream::DnsUpstream> =
            Arc::new(crate::upstream::quic::QuicDnsUpstream::new(
                name,
                addr,
                sni_name,
                params.skip_cert_verify,
            ));
        return Ok(crate::upstream::FilteredUpstream::wrap_if_needed(
            upstream, &params,
        ));
    }
    if lower.starts_with("udp://") {
        let (host, port, _) = parse_server_endpoint(spec, "udp://", 53)?;
        let addr = resolve_host_to_socket(&host, port, "UDP-DNS")?;
        return Ok(
            Arc::new(crate::upstream::marked::MarkedDnsUpstream::new(name, addr))
                as Arc<dyn crate::upstream::DnsUpstream>,
        );
    }
    if lower.starts_with("tcp://") {
        let (host, port, _) = parse_server_endpoint(spec, "tcp://", 53)?;
        let addr = resolve_host_to_socket(&host, port, "TCP-DNS")?;
        return Ok(
            Arc::new(crate::upstream::marked::MarkedDnsUpstream::new(name, addr))
                as Arc<dyn crate::upstream::DnsUpstream>,
        );
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(
            Arc::new(crate::upstream::marked::MarkedDnsUpstream::new(name, addr))
                as Arc<dyn crate::upstream::DnsUpstream>,
        );
    }
    let ip: IpAddr = spec
        .parse()
        .map_err(|_| format!("unsupported resolver server: {spec}"))?;
    Ok(Arc::new(crate::upstream::marked::MarkedDnsUpstream::new(
        name,
        SocketAddr::new(ip, 53),
    )) as Arc<dyn crate::upstream::DnsUpstream>)
}

fn parse_server_endpoint(
    spec: &str,
    scheme: &str,
    default_port: u16,
) -> Result<(String, u16, Option<String>), String> {
    if !spec.to_ascii_lowercase().starts_with(scheme) {
        return Err(format!("expected {scheme} endpoint: {spec}"));
    }
    let rest = &spec[scheme.len()..];
    // 先剥 fragment，再剥 query —— mihomo 用 fragment 传 sni/h3 等参数
    // (`#sni=foo&h3=true`)，WutherCore 同时兼容 query (`?sni=foo`)。
    let (rest, fragment) = rest
        .split_once('#')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((rest, None));
    let (without_query, query) = rest
        .split_once('?')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((rest, None));
    let authority = without_query.split('/').next().unwrap_or(without_query);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err(format!("missing resolver server host: {spec}"));
    }

    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, rest) = after_bracket
            .split_once(']')
            .ok_or_else(|| format!("invalid IPv6 endpoint: {spec}"))?;
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        match port.parse::<u16>() {
            Ok(port) => (host.to_string(), port),
            Err(_) => (authority.to_string(), default_port),
        }
    } else {
        (authority.to_string(), default_port)
    };

    fn extract_sni(s: &str) -> Option<String> {
        s.split('&').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            if k.eq_ignore_ascii_case("sni") || k.eq_ignore_ascii_case("host") {
                Some(v.to_string())
            } else {
                None
            }
        })
    }
    let sni = query
        .and_then(extract_sni)
        .or_else(|| fragment.and_then(extract_sni));
    Ok((host, port, sni))
}

/// host 是 IP literal → 直接组装；否则走 system DNS（mihomo bootstrap 等价）。
/// 用于 DoT/DoQ/UDP/TCP 上游构造时把 hostname 解析为可连接的 SocketAddr。
fn resolve_host_to_socket(host: &str, port: u16, kind_label: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let target = format!("{host}:{port}");
    target
        .to_socket_addrs()
        .map_err(|e| format!("{kind_label} host {host} 解析失败: {e}"))?
        .next()
        .ok_or_else(|| format!("{kind_label} host {host} 解析为空"))
}

fn extract_upstream_params(spec: &str) -> crate::upstream::UpstreamParams {
    // 兼容 query (`?k=v`) 与 fragment (`#k=v`) 两种风格 —— 后者是 mihomo 的 URL 习惯。
    let after_q = spec.split_once('?').map(|(_, q)| q).unwrap_or("");
    let after_q = after_q.split('#').next().unwrap_or(after_q);
    let after_h = spec.split_once('#').map(|(_, h)| h).unwrap_or("");
    let combined = if after_h.is_empty() {
        after_q.to_string()
    } else if after_q.is_empty() {
        after_h.to_string()
    } else {
        format!("{after_q}&{after_h}")
    };
    crate::upstream::UpstreamParams::parse(&combined)
}

#[derive(Default)]
pub struct ResolverBuilder {
    cfg: Option<ResolverCfg>,
    groups: HashMap<String, Arc<DnsGroup>>,
    policy: Option<PolicyEngine>,
    bootstrap_policy: Option<PolicyEngine>,
    bootstrap: Option<Arc<DnsGroup>>,
    fallback_group: Option<String>,
    fallback_filter: RuntimeFallbackFilter,
    fake_pool: Option<Arc<FakeIpPool>>,
    cache_cfg: Option<CacheConfig>,
    optimistic: bool,
    default_ttl: Duration,
    store: Option<Arc<Store>>,
    global_client_subnet: Option<ipnet::IpNet>,
}

impl ResolverBuilder {
    pub fn new() -> Self {
        Self {
            optimistic: true,
            default_ttl: Duration::from_secs(300),
            ..Default::default()
        }
    }
    pub fn cfg(mut self, c: ResolverCfg) -> Self {
        self.cfg = Some(c);
        self
    }
    pub fn group(mut self, name: impl Into<String>, g: Arc<DnsGroup>) -> Self {
        self.groups.insert(name.into(), g);
        self
    }
    pub fn policy(mut self, p: PolicyEngine) -> Self {
        self.policy = Some(p);
        self
    }
    #[cfg(test)]
    fn bootstrap_policy(mut self, p: PolicyEngine) -> Self {
        self.bootstrap_policy = Some(p);
        self
    }
    pub fn bootstrap(mut self, g: Arc<DnsGroup>) -> Self {
        self.bootstrap = Some(g);
        self
    }
    #[cfg(test)]
    fn fallback(mut self, group_name: impl Into<String>, filter: RuntimeFallbackFilter) -> Self {
        self.fallback_group = Some(group_name.into());
        self.fallback_filter = filter;
        self
    }
    pub fn fake_pool(mut self, p: Arc<FakeIpPool>) -> Self {
        self.fake_pool = Some(p);
        self
    }
    pub fn cache_cfg(mut self, c: CacheConfig) -> Self {
        self.cache_cfg = Some(c);
        self
    }
    pub fn optimistic(mut self, v: bool) -> Self {
        self.optimistic = v;
        self
    }
    pub fn default_ttl(mut self, d: Duration) -> Self {
        self.default_ttl = d;
        self
    }
    pub fn store(mut self, s: Arc<Store>) -> Self {
        self.store = Some(s);
        self
    }

    /// 设置全局默认 EDNS0 client_subnet —— sing-box `dns.client_subnet` 等价。
    /// 接受 IpNet 或 IpAddr（自动补 /32 /128）。
    pub fn client_subnet<T: TryInto<IpNetOrAddr>>(mut self, v: T) -> Self {
        if let Ok(x) = v.try_into() {
            self.global_client_subnet = Some(x.into_net());
        }
        self
    }

    /// 接受 yaml::Value（字符串 IP 或 CIDR），常用于配置加载路径。
    pub fn client_subnet_from_str(mut self, s: &str) -> Self {
        if let Ok(net) = s.parse::<ipnet::IpNet>() {
            self.global_client_subnet = Some(net);
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            self.global_client_subnet = Some(match ip {
                IpAddr::V4(_) => format!("{ip}/32").parse().unwrap(),
                IpAddr::V6(_) => format!("{ip}/128").parse().unwrap(),
            });
        }
        self
    }

    pub fn build(self) -> Resolver {
        let cfg = self.cfg.unwrap_or_default();
        let cache = Arc::new(DnsCache::new(self.cache_cfg.unwrap_or_default()));
        let policy = Arc::new(self.policy.unwrap_or_else(|| {
            PolicyEngine::new().with_default(DnsAction::Direct("default".into()))
        }));
        let bootstrap_policy = Arc::new(self.bootstrap_policy.unwrap_or_else(|| {
            PolicyEngine::new().with_default(DnsAction::Direct("default".into()))
        }));
        let mut groups = self.groups;
        let bootstrap = self.bootstrap.unwrap_or_else(|| {
            let up = Arc::new(crate::upstream::system::SystemUpstream::new("system"));
            Arc::new(DnsGroup::new(
                "bootstrap",
                crate::group::GroupStrategy::Fallback,
                vec![up as _],
            ))
        });
        groups
            .entry("default".into())
            .or_insert_with(|| bootstrap.clone());
        let mut r = Resolver {
            ipv6_enabled: cfg.ipv6,
            ipv6_timeout: cfg.ipv6_timeout,
            cfg,
            cache,
            groups: Arc::new(groups),
            policy,
            bootstrap,
            bootstrap_policy,
            fallback_group: self.fallback_group,
            fallback_filter: self.fallback_filter,
            fake_pool: self.fake_pool,
            fake_filter: None,
            hosts: None,
            mapping: Arc::new(crate::mapping::IpHostMapping::default()),
            singleflight: Arc::new(crate::singleflight::Singleflight::new()),
            optimistic: self.optimistic,
            default_ttl: self.default_ttl,
            writer: None,
            global_client_subnet: self.global_client_subnet,
        };
        if let Some(s) = self.store {
            r.attach_store(s);
        }
        r
    }
}

/// `IpAddr` 与 `IpNet` 的统一转换器（让 `client_subnet(...)` 同时接受两者）。
pub struct IpNetOrAddr(ipnet::IpNet);
impl IpNetOrAddr {
    pub fn into_net(self) -> ipnet::IpNet {
        self.0
    }
}
impl TryFrom<ipnet::IpNet> for IpNetOrAddr {
    type Error = ();
    fn try_from(v: ipnet::IpNet) -> Result<Self, Self::Error> {
        Ok(Self(v))
    }
}
impl TryFrom<IpAddr> for IpNetOrAddr {
    type Error = ();
    fn try_from(v: IpAddr) -> Result<Self, Self::Error> {
        let s = match v {
            IpAddr::V4(_) => format!("{v}/32"),
            IpAddr::V6(_) => format!("{v}/128"),
        };
        s.parse::<ipnet::IpNet>().map(Self).map_err(|_| ())
    }
}
impl TryFrom<&str> for IpNetOrAddr {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Ok(n) = s.parse::<ipnet::IpNet>() {
            return Ok(Self(n));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Self::try_from(ip);
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::{group::GroupStrategy, policy::HostMatch, upstream::DnsUpstream};

    #[derive(Debug)]
    struct CountingUp {
        n: AtomicU32,
        n_aaaa: AtomicU32,
        ip: IpAddr,
    }
    #[async_trait]
    impl DnsUpstream for CountingUp {
        fn name(&self) -> &str {
            "countup"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.n.fetch_add(1, Ordering::Relaxed);
            Ok(vec![self.ip])
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.n_aaaa.fetch_add(1, Ordering::Relaxed);
            Ok(vec!["::1".parse().unwrap()])
        }
    }

    fn group_with(ip: &str) -> (Arc<CountingUp>, Arc<DnsGroup>) {
        let up = Arc::new(CountingUp {
            n: AtomicU32::new(0),
            n_aaaa: AtomicU32::new(0),
            ip: ip.parse().unwrap(),
        });
        let g: Arc<DnsGroup> = Arc::new(DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![up.clone() as _],
        ));
        (up, g)
    }

    #[derive(Debug)]
    struct SequenceUp {
        n: AtomicU32,
    }
    #[async_trait]
    impl DnsUpstream for SequenceUp {
        fn name(&self) -> &str {
            "sequence"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            let n = self.n.fetch_add(1, Ordering::Relaxed);
            let ip = if n == 0 { "1.1.1.1" } else { "2.2.2.2" };
            Ok(vec![ip.parse().unwrap()])
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec!["2001:db8::1".parse().unwrap()])
        }
    }

    #[derive(Debug)]
    struct FailingAfterFirstUp {
        n: AtomicU32,
    }
    #[async_trait]
    impl DnsUpstream for FailingAfterFirstUp {
        fn name(&self) -> &str {
            "failing-after-first"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            let n = self.n.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Ok(vec!["1.1.1.1".parse().unwrap()])
            } else {
                Err(DnsError::Timeout)
            }
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Err(DnsError::Timeout)
        }
    }

    #[tokio::test]
    async fn ecs_three_level_fallback() {
        let (_up, g) = group_with("1.2.3.4");
        // server-级别 ECS 通过 SystemUpstream::with_client_subnet 注入；
        // 但我们的 group 用 CountingUp，下面专门构造一个有 server-ECS 的 group。
        let server_ecs: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let global_ecs: ipnet::IpNet = "100.0.0.0/24".parse().unwrap();
        let rule_ecs: ipnet::IpNet = "200.0.0.0/24".parse().unwrap();

        let with_server = Arc::new(
            crate::upstream::system::SystemUpstream::new("ali").with_client_subnet(server_ecs),
        );
        let g_server: Arc<DnsGroup> = Arc::new(DnsGroup::new(
            "with-server-ecs",
            GroupStrategy::Fallback,
            vec![with_server as _],
        ));

        let r = ResolverBuilder::new()
            .group("g", g.clone())                  // 无 server-ECS
            .group("g-server", g_server.clone())    // 有 server-ECS
            .bootstrap(g.clone())
            .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
            .client_subnet_from_str("100.0.0.0/24")  // global
            .build();

        // 1) 无 rule、无 server → global
        assert_eq!(r.effective_client_subnet(None, "g"), Some(global_ecs));

        // 2) server-ECS 存在 → server 优先于 global
        assert_eq!(
            r.effective_client_subnet(None, "g-server"),
            Some(server_ecs)
        );

        // 3) rule-opts 提供 → 最高优先级
        let rule_opts = QueryOptions {
            client_subnet: Some(rule_ecs),
            ..Default::default()
        };
        assert_eq!(
            r.effective_client_subnet(Some(&rule_opts), "g-server"),
            Some(rule_ecs)
        );
        assert_eq!(
            r.effective_client_subnet(Some(&rule_opts), "g"),
            Some(rule_ecs)
        );

        // 4) 都没有 → None
        let r2 = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
            .build();
        assert_eq!(r2.effective_client_subnet(None, "g"), None);
    }

    #[tokio::test]
    async fn builder_client_subnet_accepts_addr_or_cidr() {
        let (_up, g) = group_with("1.2.3.4");
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
            .client_subnet_from_str("8.8.8.8")
            .build();
        // bare IP → /32
        assert_eq!(
            r.global_client_subnet().map(|n| n.to_string()).as_deref(),
            Some("8.8.8.8/32")
        );

        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
            .client_subnet_from_str("2001:db8::1")
            .build();
        assert_eq!(
            r.global_client_subnet().map(|n| n.to_string()).as_deref(),
            Some("2001:db8::1/128")
        );
    }

    #[tokio::test]
    async fn cache_serves_repeated_queries() {
        let (up, g) = group_with("1.2.3.4");
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .build();
        let v1 = r.resolve("example.com").await.unwrap();
        let v2 = r.resolve("example.com").await.unwrap();
        assert_eq!(v1, v2);
        assert_eq!(up.n.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn optimistic_false_does_not_serve_stale_cache() {
        let (up, g) = group_with("1.2.3.4");
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .cache_cfg(CacheConfig {
                grace: Duration::from_secs(60),
                prefetch_threshold: Duration::from_millis(0),
                ..CacheConfig::default()
            })
            .default_ttl(Duration::from_millis(1))
            .optimistic(false)
            .build();

        let _ = r
            .resolve_qtype("stale.example.com", QType::A)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = r
            .resolve_qtype("stale.example.com", QType::A)
            .await
            .unwrap();

        assert_eq!(up.n.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn stale_cache_refreshes_before_serving_when_upstream_is_fast() {
        let up = Arc::new(SequenceUp {
            n: AtomicU32::new(0),
        });
        let g: Arc<DnsGroup> = Arc::new(DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![up.clone() as _],
        ));
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .cache_cfg(CacheConfig {
                grace: Duration::from_secs(60),
                prefetch_threshold: Duration::from_millis(0),
                ..CacheConfig::default()
            })
            .default_ttl(Duration::from_millis(1))
            .build();

        let first = r
            .resolve_qtype("refresh.example.com", QType::A)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = r
            .resolve_qtype("refresh.example.com", QType::A)
            .await
            .unwrap();

        assert_eq!(first, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(second, vec!["2.2.2.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(up.n.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn stale_refresh_failure_is_rate_limited() {
        let up = Arc::new(FailingAfterFirstUp {
            n: AtomicU32::new(0),
        });
        let g: Arc<DnsGroup> = Arc::new(DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![up.clone() as _],
        ));
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .cache_cfg(CacheConfig {
                grace: Duration::from_secs(60),
                prefetch_threshold: Duration::from_millis(0),
                client_response_timeout: Duration::from_millis(20),
                failure_recheck: Duration::from_secs(5),
                ..CacheConfig::default()
            })
            .default_ttl(Duration::from_millis(1))
            .build();

        let first = r
            .resolve_qtype("failure.example.com", QType::A)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = r
            .resolve_qtype("failure.example.com", QType::A)
            .await
            .unwrap();
        let third = r
            .resolve_qtype("failure.example.com", QType::A)
            .await
            .unwrap();

        assert_eq!(first, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(second, first);
        assert_eq!(third, first);
        assert_eq!(up.n.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn qtype_uses_separate_lookup_and_cache() {
        let (up, g) = group_with("1.2.3.4");
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .build();

        let a1 = r.resolve_qtype("dual.example.com", QType::A).await.unwrap();
        let a2 = r.resolve_qtype("dual.example.com", QType::A).await.unwrap();
        let aaaa1 = r
            .resolve_qtype("dual.example.com", QType::AAAA)
            .await
            .unwrap();
        let aaaa2 = r
            .resolve_qtype("dual.example.com", QType::AAAA)
            .await
            .unwrap();

        assert_eq!(a1, a2);
        assert_eq!(aaaa1, aaaa2);
        assert!(a1.iter().all(IpAddr::is_ipv4));
        assert!(aaaa1.iter().all(IpAddr::is_ipv6));
        assert_eq!(up.n.load(Ordering::Relaxed), 1);
        assert_eq!(up.n_aaaa.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn default_lookup_uses_fallback_when_main_ip_matches_filter() {
        let (main_up, main) = group_with("240.0.0.1");
        let (fallback_up, fallback) = group_with("8.8.8.8");
        let mut filter = RuntimeFallbackFilter::default();
        filter.ip_cidrs.push("240.0.0.0/4".parse().unwrap());
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("default".into()));
        let r = ResolverBuilder::new()
            .group("default", main)
            .group("fallback", fallback)
            .bootstrap(group_with("9.9.9.9").1)
            .fallback("fallback", filter)
            .policy(policy)
            .build();

        let ips = r
            .resolve_qtype("fallback.example.com", QType::A)
            .await
            .unwrap();

        assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(main_up.n.load(Ordering::Relaxed), 1);
        assert_eq!(fallback_up.n.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fallback_domain_filter_skips_main_nameserver() {
        let (main_up, main) = group_with("1.1.1.1");
        let (fallback_up, fallback) = group_with("8.8.8.8");
        let mut filter = RuntimeFallbackFilter::default();
        filter
            .domain_matchers
            .push(HostMatch::Suffix("google.com".into()));
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("default".into()));
        let r = ResolverBuilder::new()
            .group("default", main)
            .group("fallback", fallback)
            .bootstrap(group_with("9.9.9.9").1)
            .fallback("fallback", filter)
            .policy(policy)
            .build();

        let ips = r.resolve_qtype("www.google.com", QType::A).await.unwrap();

        assert_eq!(ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(main_up.n.load(Ordering::Relaxed), 0);
        assert_eq!(fallback_up.n.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn evaluate_then_respond_works() {
        let (_up, g) = group_with("1.2.3.4");
        let mut policy = PolicyEngine::new().with_default(DnsAction::Reject(Default::default()));
        policy.push(crate::policy::parse_rule_line("any -> evaluate:g").unwrap());
        policy
            .push(crate::policy::parse_rule_line("match_response:1.2.3.0/24 -> respond").unwrap());
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .build();
        let v = r.resolve("any.example.com").await.unwrap();
        assert_eq!(v, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn evaluate_no_match_falls_through_to_default() {
        let (_up1, g1) = group_with("8.8.8.8");
        let (_up2, g2) = group_with("9.9.9.9");
        let mut policy = PolicyEngine::new().with_default(DnsAction::Direct("g2".into()));
        // evaluate 用 nocache 避免污染后续路径（与 sing-box 推荐模式一致）
        policy.push(crate::policy::parse_rule_line("any -> evaluate:g1?nocache").unwrap());
        policy.push(crate::policy::parse_rule_line("match_response:1.0.0.0/8 -> respond").unwrap());
        let r = ResolverBuilder::new()
            .group("g1", g1.clone())
            .group("g2", g2.clone())
            .bootstrap(g1.clone())
            .policy(policy)
            .build();
        let v = r.resolve("any.example.com").await.unwrap();
        // resolve() returns A results (AAAA may also come back due to concurrent dual-stack)
        assert!(v.contains(&"9.9.9.9".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn disable_cache_skips_cache_read_and_write() {
        let (up, g) = group_with("1.2.3.4");
        let mut policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        policy.rules.clear();
        policy.push(crate::policy::parse_rule_line("any -> route:g?nocache").unwrap());
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(policy)
            .build();
        let _ = r.resolve("a.com").await.unwrap();
        let _ = r.resolve("a.com").await.unwrap();
        assert_eq!(up.n.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn cache_persists_across_restart() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-dns-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let store = Store::open(&path).unwrap();
            let (up, g) = group_with("9.9.9.9");
            let mut policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
            policy.rules.clear();
            policy.push(crate::policy::parse_rule_line("any -> direct:g").unwrap());
            let r = ResolverBuilder::new()
                .group("g", g.clone())
                .bootstrap(g.clone())
                .policy(policy)
                .store(store.clone())
                .default_ttl(Duration::from_secs(3600))
                .build();
            let _ = r.resolve("persist.example.com").await.unwrap();
            r.flush_to_store().await;
            assert_eq!(up.n.load(Ordering::Relaxed), 1);
            drop(r);
            drop(store);
        }
        {
            let store = Store::open(&path).unwrap();
            let (up, g) = group_with("0.0.0.0");
            let mut policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
            policy.rules.clear();
            policy.push(crate::policy::parse_rule_line("any -> direct:g").unwrap());
            let r = ResolverBuilder::new()
                .group("g", g.clone())
                .bootstrap(g.clone())
                .policy(policy)
                .store(store)
                .build();
            let v = r.resolve("persist.example.com").await.unwrap();
            assert!(v.contains(&"9.9.9.9".parse::<IpAddr>().unwrap()));
            // Cache hit: upstream not queried for A (AAAA may or may not be cached)
            assert!(up.n.load(Ordering::Relaxed) <= 1);
        }
    }

    #[tokio::test]
    async fn reject_action_returns_err_and_negative_cache() {
        let (up, g) = group_with("1.2.3.4");
        let mut policy = PolicyEngine::new().with_default(DnsAction::Direct("g".into()));
        policy.push(crate::policy::PolicyRule {
            matcher: HostMatch::Suffix("ad.example.com".into()),
            action: DnsAction::Reject(Default::default()),
            source: "test".into(),
        });
        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g)
            .policy(policy)
            .build();
        let r1 = r.resolve("ad.example.com").await;
        assert!(matches!(r1, Err(ResolveError::Rejected(_))));
        let _ = r.resolve("ad.example.com").await;
        assert_eq!(up.n.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn resolve_via_direct_uses_direct_nameserver_group_when_present() {
        // 设置 default group 走 1.1.1.1（业务 policy），direct-nameserver 走 9.9.9.9。
        // resolve_via_direct 必须选 direct-nameserver；resolve_via_bootstrap 仍走 default。
        let (default_up, default_g) = group_with("1.1.1.1");
        let (direct_up, direct_g) = group_with("9.9.9.9");
        let policy = PolicyEngine::new().with_default(DnsAction::Direct("default".into()));
        let r = ResolverBuilder::new()
            .group("default", default_g.clone())
            .group("direct-nameserver", direct_g.clone())
            .bootstrap(default_g.clone())
            .policy(policy)
            .build();
        let v = r.resolve_via_direct("foo.example").await.unwrap();
        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(direct_up.n.load(Ordering::Relaxed), 1);
        assert_eq!(default_up.n.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn resolve_via_direct_falls_back_to_default_group_not_proxy_server_nameserver() {
        // 关键回归：DIRECT 出站绝不应通过 proxy-server-nameserver 解析。
        // 历史 bug：fallback 走 resolve_via_bootstrap，而 bootstrap 选 proxy-server-nameserver；
        // 节点 DNS 一炸，所有 DIRECT 站点跟着炸。
        let (default_up, default_g) = group_with("9.9.9.9");
        let (proxy_up, proxy_g) = group_with("8.8.8.8");
        let r = ResolverBuilder::new()
            .group("default", default_g.clone())
            .group("proxy-server-nameserver", proxy_g.clone())
            .bootstrap(proxy_g.clone()) // 故意把 bootstrap 指到 proxy-server-nameserver
            .build();
        let v = r.resolve_via_direct("foo.example").await.unwrap();
        // 必须命中 default group（9.9.9.9），不能走 proxy-server-nameserver。
        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(default_up.n.load(Ordering::Relaxed), 1);
        assert_eq!(
            proxy_up.n.load(Ordering::Relaxed),
            0,
            "DIRECT must NOT touch proxy-server-nameserver"
        );
    }

    #[tokio::test]
    async fn bootstrap_isolated_from_policy() {
        let policy = PolicyEngine::new().with_default(DnsAction::Reject(Default::default()));
        let bootstrap_up = Arc::new(CountingUp {
            n: AtomicU32::new(0),
            n_aaaa: AtomicU32::new(0),
            ip: "9.9.9.9".parse().unwrap(),
        });
        let bootstrap_g: Arc<DnsGroup> = Arc::new(DnsGroup::new(
            "bs",
            GroupStrategy::Fallback,
            vec![bootstrap_up as _],
        ));
        let r = ResolverBuilder::new()
            .bootstrap(bootstrap_g.clone())
            .policy(policy)
            .build();
        assert!(matches!(
            r.resolve("any.example.com").await,
            Err(ResolveError::Rejected(_))
        ));
        let v = r.resolve_via_bootstrap("any.example.com").await.unwrap();
        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn bootstrap_policy_routes_proxy_server_nameserver() {
        let (default_up, default_group) = group_with("1.1.1.1");
        let (policy_up, policy_group) = group_with("9.9.9.9");
        let mut bootstrap_policy =
            PolicyEngine::new().with_default(DnsAction::Direct("default".into()));
        bootstrap_policy
            .push(crate::policy::parse_rule_line("suffix:node.example -> route:policy").unwrap());
        let r = ResolverBuilder::new()
            .group("default", default_group)
            .group("policy", policy_group)
            .bootstrap(group_with("8.8.8.8").1)
            .bootstrap_policy(bootstrap_policy)
            .policy(PolicyEngine::new().with_default(DnsAction::Reject(Default::default())))
            .build();

        let v = r.resolve_via_bootstrap("proxy.node.example").await.unwrap();

        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(default_up.n.load(Ordering::Relaxed), 0);
        assert_eq!(policy_up.n.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resolver_new_honors_configured_secure_servers() {
        let mut servers = std::collections::BTreeMap::new();
        servers.insert("ali".to_string(), "https://223.5.5.5/dns-query".to_string());
        servers.insert(
            "cloudflare".to_string(),
            "https://1.1.1.1/dns-query".to_string(),
        );
        let r = Resolver::new(ResolverCfg {
            mode: ResolverMode::Normal,
            nameserver: vec!["cloudflare".into()],
            fallback: Vec::new(),
            servers,
            ..ResolverCfg::default()
        });

        let groups = r.groups();
        assert!(groups.contains_key("ali"));
        assert!(groups.contains_key("cloudflare"));
        assert_eq!(groups["cloudflare"].members[0].kind(), "doh");
        assert_eq!(groups["default"].members[0].kind(), "doh");
        assert_eq!(r.bootstrap.name, "default");
    }

    #[test]
    fn resolver_new_rejects_invalid_configured_servers() {
        // 域名 host 现在被接受（mihomo bootstrap 风格）；改用未知 scheme 触发拒收。
        let mut servers = std::collections::BTreeMap::new();
        servers.insert("bad".to_string(), "gopher://1.2.3.4/dns-query".to_string());

        let err = Resolver::try_new(ResolverCfg {
            mode: ResolverMode::Normal,
            nameserver: vec!["bad".into()],
            fallback: Vec::new(),
            servers,
            ..ResolverCfg::default()
        })
        .unwrap_err();

        assert!(err.to_string().contains("bad"));
        assert!(err.to_string().contains("gopher"));
    }

    #[test]
    fn resolver_new_preserves_user_rules_without_legacy_aliases() {
        let mut servers = std::collections::BTreeMap::new();
        servers.insert("ali".to_string(), "https://223.5.5.5/dns-query".to_string());
        servers.insert(
            "cloudflare".to_string(),
            "https://1.1.1.1/dns-query".to_string(),
        );

        let r = Resolver::try_new(ResolverCfg {
            mode: ResolverMode::Normal,
            nameserver: vec!["ali".into()],
            fallback: vec!["cloudflare".into()],
            servers,
            rules: vec![
                serde_yaml::Value::String("suffix:cn -> direct".into()),
                serde_yaml::Value::String("any -> proxy".into()),
            ],
            ..ResolverCfg::default()
        })
        .unwrap();

        let groups = r.groups();
        assert!(!groups.contains_key("mainland"));
        assert!(!groups.contains_key("overseas"));
        assert!(groups.contains_key("default"));
        assert!(groups.contains_key("fallback"));
        assert_eq!(r.policy().rules.len(), 2);
    }

    #[test]
    fn smart_without_user_rules_does_not_inject_fake_cn_rules() {
        let r = Resolver::try_new(ResolverCfg {
            mode: ResolverMode::Normal,
            ..ResolverCfg::default()
        })
        .unwrap();

        let policy = r.policy();
        let sources = policy
            .rules
            .iter()
            .map(|rule| rule.source.as_str())
            .collect::<Vec<_>>();
        assert!(
            sources.is_empty(),
            "smart resolver must not invent mainland/overseas rules without configured data: {sources:?}"
        );
    }

    #[test]
    fn resolver_default_does_not_create_mainland_overseas_groups() {
        let r = Resolver::try_new(ResolverCfg::default()).unwrap();
        let groups = r.groups();

        assert!(groups.contains_key("default"));
        assert!(groups.contains_key("fallback"));
        assert!(!groups.contains_key("mainland"));
        assert!(!groups.contains_key("overseas"));
    }

    #[test]
    fn nameserver_policy_builds_real_policy_groups() {
        let cfg: ResolverCfg = serde_yaml::from_str(
            r#"
mode: smart
fake: off
cache: 1h
servers:
  ali: "udp://223.5.5.5"
  cloudflare: "udp://1.1.1.1"
nameserver: [ali]
nameserver-policy:
  "+.google.com": [cloudflare]
"#,
        )
        .unwrap();

        let r = Resolver::try_new(cfg).unwrap();
        let decision = r.policy().decide("www.google.com");

        let DnsAction::Route { server, .. } = decision else {
            panic!("expected nameserver-policy route");
        };
        assert_eq!(server, "nameserver-policy-0");
        assert!(r.groups().contains_key("nameserver-policy-0"));
    }

    #[test]
    fn resolver_new_rejects_rules_referencing_unknown_groups() {
        let mut servers = std::collections::BTreeMap::new();
        servers.insert("ali".to_string(), "https://223.5.5.5/dns-query".to_string());

        let err = Resolver::try_new(ResolverCfg {
            mode: ResolverMode::Normal,
            nameserver: vec!["ali".into()],
            fallback: Vec::new(),
            servers,
            rules: vec![serde_yaml::Value::String("any -> route:missing".into())],
            ..ResolverCfg::default()
        })
        .unwrap_err();

        assert!(err.to_string().contains("missing"));
    }
}
