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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_config::model::{Resolver as ResolverCfg, ResolverMode};
use core_store::{store::BatchOp, AsyncWriter, Store};
use thiserror::Error;
use tracing::{debug, warn};

use crate::cache::{CacheConfig, DnsCache, Hit, QType};
use crate::fake_ip::FakeIpPool;
use crate::group::DnsGroup;
use crate::policy::{matches, DnsAction, EvalContext, HostMatch, PolicyEngine, QueryOptions, RejectMethod};
use crate::upstream::DnsError;

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

#[derive(Clone)]
pub struct Resolver {
    cfg: ResolverCfg,
    cache: Arc<DnsCache>,
    groups: Arc<HashMap<String, Arc<DnsGroup>>>,
    policy: Arc<PolicyEngine>,
    bootstrap: Arc<DnsGroup>,
    fake_pool: Option<Arc<FakeIpPool>>,
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
            .field("optimistic", &self.optimistic)
            .field("cache_len", &self.cache.len())
            .field("persisted", &self.writer.is_some())
            .field("global_client_subnet", &self.global_client_subnet)
            .finish()
    }
}

impl Resolver {
    /// 旧的兼容构造：仅 system upstream + system fallback。
    pub fn new(cfg: ResolverCfg) -> Self {
        let system_up = Arc::new(crate::upstream::system::SystemUpstream::new("system"));
        let system_group = Arc::new(DnsGroup::new(
            "system",
            crate::group::GroupStrategy::Fallback,
            vec![system_up.clone() as _],
        ));
        let mut groups = HashMap::new();
        groups.insert("system".into(), system_group.clone());
        groups.insert("default".into(), system_group.clone());

        let policy = PolicyEngine::new().with_default(DnsAction::Direct("system".into()));

        Self {
            cfg,
            cache: Arc::new(DnsCache::new(CacheConfig::default())),
            groups: Arc::new(groups),
            policy: Arc::new(policy),
            bootstrap: system_group,
            fake_pool: None,
            optimistic: true,
            default_ttl: Duration::from_secs(300),
            writer: None,
            global_client_subnet: None,
        }
    }

    pub fn cfg(&self) -> &ResolverCfg { &self.cfg }
    pub fn cache(&self) -> Arc<DnsCache> { self.cache.clone() }
    pub fn mode(&self) -> ResolverMode { self.cfg.mode }
    pub fn groups(&self) -> Arc<HashMap<String, Arc<DnsGroup>>> { self.groups.clone() }
    pub fn fake_pool(&self) -> Option<Arc<FakeIpPool>> { self.fake_pool.clone() }

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
        let answers = match self.resolve(name).await {
            Ok(ips) => ips,
            Err(_) => return serde_json::Value::Array(Vec::new()),
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
    pub fn policy(&self) -> Arc<PolicyEngine> { self.policy.clone() }
    pub fn global_client_subnet(&self) -> Option<ipnet::IpNet> { self.global_client_subnet }

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
            if let Some(net) = g
                .members
                .iter()
                .find_map(|u| u.default_client_subnet())
            {
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
                DnsAction::Direct(g)
                | DnsAction::Proxy(g)
                | DnsAction::Route { server: g, .. } => Some(g.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "default".to_string());
        self.lookup_via(&host_lc, &group, opts).await
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host_lc = host.trim_end_matches('.').to_lowercase();
        let mut ctx = EvalContext::default();

        for rule in &self.policy.rules {
            if !matches(&rule.matcher, &host_lc, &ctx, self.policy.ruleset_index.as_ref()) {
                continue;
            }
            match rule.action.clone() {
                DnsAction::Reject(opts) => {
                    let method = self.policy.apply_reject_throttle(&opts, &rule.source);
                    return match method {
                        RejectMethod::Default => {
                            self.cache.put_negative(&host_lc, QType::A);
                            Err(ResolveError::Rejected(host_lc))
                        }
                        RejectMethod::Drop => Err(ResolveError::Dropped(host_lc)),
                    };
                }
                DnsAction::Accept(ips) => return Ok(ips),
                DnsAction::Predefined(pre) => {
                    let ips = pre.answer_ips();
                    if ips.is_empty() {
                        return match pre.rcode.unwrap_or(crate::policy::PreRcode::NOERROR) {
                            crate::policy::PreRcode::NXDOMAIN | crate::policy::PreRcode::REFUSED
                            | crate::policy::PreRcode::SERVFAIL | crate::policy::PreRcode::FORMERR
                            | crate::policy::PreRcode::NOTIMP => {
                                Err(ResolveError::Rejected(host_lc))
                            }
                            crate::policy::PreRcode::NOERROR => Ok(vec![]),
                        };
                    }
                    return Ok(ips);
                }
                DnsAction::Fake => {
                    if let Some(pool) = &self.fake_pool {
                        if let Some(ip) = pool.alloc(&host_lc, crate::fake_ip::AddressFamily::V4) {
                            return Ok(vec![ip]);
                        }
                    }
                    return Err(ResolveError::Failed("fake-ip pool 不可用".into()));
                }
                DnsAction::Direct(g) | DnsAction::Proxy(g) => {
                    return self.lookup_via(&host_lc, &g, &QueryOptions::default()).await;
                }
                DnsAction::Route { server, opts } => {
                    return self.lookup_via(&host_lc, &server, &opts).await;
                }
                DnsAction::Evaluate { server, opts } => {
                    if let Ok(ips) = self.lookup_via(&host_lc, &server, &opts).await {
                        ctx.saved_response = Some(ips);
                        ctx.saved_opts = Some(opts);
                    }
                    continue;
                }
                DnsAction::Respond => {
                    return ctx.saved_response.clone().ok_or_else(|| {
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
                        self.cache.put_negative(&host_lc, QType::A);
                        Err(ResolveError::Rejected(host_lc))
                    }
                    RejectMethod::Drop => Err(ResolveError::Dropped(host_lc)),
                }
            }
            DnsAction::Accept(ips) => Ok(ips),
            DnsAction::Predefined(pre) => {
                let ips = pre.answer_ips();
                if ips.is_empty() {
                    Err(ResolveError::Rejected(host_lc))
                } else {
                    Ok(ips)
                }
            }
            DnsAction::Direct(g) | DnsAction::Proxy(g) | DnsAction::Route { server: g, .. } => {
                self.lookup_via(&host_lc, &g, &QueryOptions::default()).await
            }
            DnsAction::Fake => {
                if let Some(pool) = &self.fake_pool {
                    if let Some(ip) = pool.alloc(&host_lc, crate::fake_ip::AddressFamily::V4) {
                        return Ok(vec![ip]);
                    }
                }
                Err(ResolveError::Failed("fake-ip pool 不可用".into()))
            }
            DnsAction::Evaluate { .. } | DnsAction::Respond => {
                Err(ResolveError::Failed("default action 不可为 evaluate/respond".into()))
            }
        }
    }

    pub async fn resolve_via_bootstrap(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        match self.bootstrap.resolve(host, false).await {
            Ok(v) if !v.is_empty() => Ok(v),
            _ => Ok(self.bootstrap.resolve(host, true).await?),
        }
    }

    async fn lookup_via(
        &self,
        host: &str,
        group_name: &str,
        opts: &QueryOptions,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let qtype = QType::A;

        // 计算有效 ECS（rule > server > global）；当前层用于 trace + 后续 EDNS 发送。
        let effective_ecs = self.effective_client_subnet(Some(opts), group_name);
        if let Some(net) = effective_ecs {
            tracing::trace!(target: "resolver::ecs", host, group = group_name, %net, "effective client_subnet");
        }

        if !opts.disable_cache {
            let (cached, hit, ticket) =
                self.cache.get_with(host, qtype, opts.disable_optimistic_cache);
            if let Some(ips) = cached {
                if hit == Hit::Stale || ticket.is_some() {
                    if let Some(t) = ticket {
                        self.spawn_prefetch(group_name.to_string(), opts.clone(), t);
                    }
                }
                if !ips.is_empty() {
                    return Ok(ips);
                }
                return Err(ResolveError::Rejected(format!("{host} (negative cache)")));
            }
        }

        let group = self
            .groups
            .get(group_name)
            .cloned()
            .unwrap_or_else(|| self.bootstrap.clone());
        let ips = match group.resolve(host, false).await {
            Ok(v) => v,
            Err(_) => group.resolve(host, true).await?,
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
                    format!("{host}|A"),
                    core_store::DnsCacheBlob {
                        ips: ips.iter().map(|ip| ip.to_string()).collect(),
                        expire_secs: now_secs + ttl.as_secs(),
                        origin: "live".into(),
                    },
                ));
            }
        }
        Ok(ips)
    }

    fn spawn_prefetch(
        &self,
        group_name: String,
        opts: QueryOptions,
        ticket: crate::cache::PrefetchTicket,
    ) {
        let groups = self.groups.clone();
        let bootstrap = self.bootstrap.clone();
        let cache = self.cache.clone();
        let writer = self.writer.clone();
        let default_ttl = self.default_ttl;
        let host = ticket.host.clone();
        let qtype = ticket.qtype;
        tokio::spawn(async move {
            let group = groups.get(&group_name).cloned().unwrap_or(bootstrap);
            let want_v6 = matches!(qtype, QType::AAAA);
            match group.resolve(&host, want_v6).await {
                Ok(v) if !v.is_empty() => {
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
                            format!("{host}|A"),
                            core_store::DnsCacheBlob {
                                ips: v.iter().map(|ip| ip.to_string()).collect(),
                                expire_secs: now_secs + ttl.as_secs(),
                                origin: "prefetch".into(),
                            },
                        ));
                    }
                    debug!(target: "resolver::prefetch", host, "refreshed");
                }
                Ok(_) | Err(_) => {
                    warn!(target: "resolver::prefetch", host, "prefetch returned empty/err");
                }
            }
            drop(ticket);
        });
    }

    pub fn attach_store(&mut self, store: Arc<Store>) {
        if let Ok(rows) = store.iter_json::<core_store::DnsCacheBlob>(core_store::schema::DNS_CACHE) {
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

#[derive(Default)]
pub struct ResolverBuilder {
    cfg: Option<ResolverCfg>,
    groups: HashMap<String, Arc<DnsGroup>>,
    policy: Option<PolicyEngine>,
    bootstrap: Option<Arc<DnsGroup>>,
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
    pub fn cfg(mut self, c: ResolverCfg) -> Self { self.cfg = Some(c); self }
    pub fn group(mut self, name: impl Into<String>, g: Arc<DnsGroup>) -> Self {
        self.groups.insert(name.into(), g);
        self
    }
    pub fn policy(mut self, p: PolicyEngine) -> Self { self.policy = Some(p); self }
    pub fn bootstrap(mut self, g: Arc<DnsGroup>) -> Self { self.bootstrap = Some(g); self }
    pub fn fake_pool(mut self, p: Arc<FakeIpPool>) -> Self { self.fake_pool = Some(p); self }
    pub fn cache_cfg(mut self, c: CacheConfig) -> Self { self.cache_cfg = Some(c); self }
    pub fn optimistic(mut self, v: bool) -> Self { self.optimistic = v; self }
    pub fn default_ttl(mut self, d: Duration) -> Self { self.default_ttl = d; self }
    pub fn store(mut self, s: Arc<Store>) -> Self { self.store = Some(s); self }

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
        let bootstrap = self.bootstrap.unwrap_or_else(|| {
            let up = Arc::new(crate::upstream::system::SystemUpstream::new("system"));
            Arc::new(DnsGroup::new(
                "bootstrap",
                crate::group::GroupStrategy::Fallback,
                vec![up as _],
            ))
        });
        let mut r = Resolver {
            cfg,
            cache,
            groups: Arc::new(self.groups),
            policy,
            bootstrap,
            fake_pool: self.fake_pool,
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
    pub fn into_net(self) -> ipnet::IpNet { self.0 }
}
impl TryFrom<ipnet::IpNet> for IpNetOrAddr {
    type Error = ();
    fn try_from(v: ipnet::IpNet) -> Result<Self, Self::Error> { Ok(Self(v)) }
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
    use super::*;
    use crate::group::GroupStrategy;
    use crate::upstream::DnsUpstream;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug)]
    struct CountingUp {
        n: AtomicU32,
        ip: IpAddr,
    }
    #[async_trait]
    impl DnsUpstream for CountingUp {
        fn name(&self) -> &str { "countup" }
        fn kind(&self) -> &'static str { "test" }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.n.fetch_add(1, Ordering::Relaxed);
            Ok(vec![self.ip])
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec!["::1".parse().unwrap()])
        }
    }

    fn group_with(ip: &str) -> (Arc<CountingUp>, Arc<DnsGroup>) {
        let up = Arc::new(CountingUp { n: AtomicU32::new(0), ip: ip.parse().unwrap() });
        let g: Arc<DnsGroup> = Arc::new(DnsGroup::new("g", GroupStrategy::Fallback, vec![up.clone() as _]));
        (up, g)
    }

    #[tokio::test]
    async fn ecs_three_level_fallback() {
        let (_up, g) = group_with("1.2.3.4");
        // server-级别 ECS 通过 SystemUpstream::with_client_subnet 注入；
        // 但我们的 group 用 CountingUp，下面专门构造一个有 server-ECS 的 group。
        let server_ecs: ipnet::IpNet = "10.0.0.0/24".parse().unwrap();
        let global_ecs: ipnet::IpNet = "100.0.0.0/24".parse().unwrap();
        let rule_ecs:   ipnet::IpNet = "200.0.0.0/24".parse().unwrap();

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
        assert_eq!(r.effective_client_subnet(None, "g-server"), Some(server_ecs));

        // 3) rule-opts 提供 → 最高优先级
        let rule_opts = QueryOptions {
            client_subnet: Some(rule_ecs),
            ..Default::default()
        };
        assert_eq!(r.effective_client_subnet(Some(&rule_opts), "g-server"), Some(rule_ecs));
        assert_eq!(r.effective_client_subnet(Some(&rule_opts), "g"), Some(rule_ecs));

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
        assert_eq!(r.global_client_subnet().map(|n| n.to_string()).as_deref(), Some("8.8.8.8/32"));

        let r = ResolverBuilder::new()
            .group("g", g.clone())
            .bootstrap(g.clone())
            .policy(PolicyEngine::new().with_default(DnsAction::Direct("g".into())))
            .client_subnet_from_str("2001:db8::1")
            .build();
        assert_eq!(r.global_client_subnet().map(|n| n.to_string()).as_deref(), Some("2001:db8::1/128"));
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
    async fn evaluate_then_respond_works() {
        let (_up, g) = group_with("1.2.3.4");
        let mut policy = PolicyEngine::new().with_default(DnsAction::Reject(Default::default()));
        policy.push(crate::policy::parse_rule_line("any -> evaluate:g").unwrap());
        policy.push(
            crate::policy::parse_rule_line("match_response:1.2.3.0/24 -> respond").unwrap(),
        );
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
        policy.push(
            crate::policy::parse_rule_line("match_response:1.0.0.0/8 -> respond").unwrap(),
        );
        let r = ResolverBuilder::new()
            .group("g1", g1.clone())
            .group("g2", g2.clone())
            .bootstrap(g1.clone())
            .policy(policy)
            .build();
        let v = r.resolve("any.example.com").await.unwrap();
        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
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
            "rpkernel-dns-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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
            assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
            assert_eq!(up.n.load(Ordering::Relaxed), 0);
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
    async fn bootstrap_isolated_from_policy() {
        let policy = PolicyEngine::new().with_default(DnsAction::Reject(Default::default()));
        let bootstrap_up = Arc::new(CountingUp { n: AtomicU32::new(0), ip: "9.9.9.9".parse().unwrap() });
        let bootstrap_g: Arc<DnsGroup> = Arc::new(DnsGroup::new("bs", GroupStrategy::Fallback, vec![bootstrap_up as _]));
        let r = ResolverBuilder::new()
            .bootstrap(bootstrap_g.clone())
            .policy(policy)
            .build();
        assert!(matches!(r.resolve("any.example.com").await, Err(ResolveError::Rejected(_))));
        let v = r.resolve_via_bootstrap("any.example.com").await.unwrap();
        assert_eq!(v, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }
}
