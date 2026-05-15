//! Runtime —— 启动 + 持有所有运行时组件 + 提供 dispatch 接口。

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
    time::Instant,
};

use core_config::{
    model::{ChooseStrategy, FeedDetail},
    node_uri::ParsedNode,
    runtime_plan::RuntimePlan,
};
use core_observe::{ConnectionTable, Metrics};
use core_outbound::{
    adapter::{DialContext, SharedOutbound},
    registry::{OutboundRegistry, register_nodes},
};
use core_resolver::Resolver;
use core_route::{FlowContext, NetworkKind, RouteDecision, RouteEngine};
use core_smart::SmartSelector;
use core_store::{Store, schema::GROUP_MANUAL};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::group_selector::GroupSelector;

const DIAL_MAX_RETRIES: usize = 10;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("配置错误: {0}")]
    Config(#[from] core_config::ConfigError),
    #[error("出站不存在: {0}")]
    UnknownOutbound(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Runtime {
    pub plan: RuntimePlan,
    pub outbounds: parking_lot::RwLock<OutboundRegistry>,
    pub groups: parking_lot::RwLock<BTreeMap<String, Arc<GroupSelector>>>,
    node_info: parking_lot::RwLock<BTreeMap<String, RuntimeNodeInfo>>,
    pub route: RouteEngine,
    pub resolver: Arc<Resolver>,
    /// 本机 DNS 服务 —— capture DNS hijack、`type: dns` 出站、独立 listener
    /// 共用同一份；与 [`Self::resolver`] 完全等价（fake-ip / cache 共享）。
    pub dns_service: Arc<core_resolver::DnsService>,
    pub smart: Arc<SmartSelector>,
    pub metrics: Arc<Metrics>,
    pub connections: Arc<ConnectionTable>,
    pub store: Option<Arc<Store>>,
    /// Clash `/logs` 兼容总线 —— tracing layer 把事件推这里。
    pub logs: Arc<core_observe::LogBus>,
    /// 运行时可调字段（mode / log-level / allow-lan 等）—— `PUT /configs` 修改。
    pub mutable: parking_lot::RwLock<MutableConfig>,
    /// URLTest 实例 —— main.rs 在创建后通过 `set_urltest` 注入。
    /// `pick_in_group` 把它传给 `GroupSelector::pick` 让 URLTest/Fallback/LB 走死节点感知。
    pub urltest: parking_lot::RwLock<Option<Arc<crate::health::UrlTester>>>,
    /// 进程反查 —— 与 mihomo `find-process-mode` 1:1。
    /// `None` 表示 mode=off（默认）；`Some(finder)` 表示 strict 或 always。
    /// strict 模式下调用方判定路由用到 process 字段才查；always 则每条都查。
    pub process_finder: Option<Arc<dyn core_process::ProcessFinder>>,
}

#[derive(Debug, Clone)]
struct RuntimeNodeInfo {
    provider: Option<String>,
    remote_destination: String,
}

impl RuntimeNodeInfo {
    fn from_node(provider: Option<String>, node: &ParsedNode) -> Self {
        Self {
            provider,
            remote_destination: format_host_port(&node.host, node.port),
        }
    }
}

/// 运行期可热改的配置子集 —— Clash dashboard `/configs` 写入的目标。
#[derive(Debug, Clone)]
pub struct MutableConfig {
    pub mode: String,      // rule / global / direct
    pub log_level: String, // debug / info / warning / error / silent
    pub allow_lan: bool,
    pub ipv6: bool,
    pub tun_enable: bool,
}

impl Default for MutableConfig {
    fn default() -> Self {
        Self {
            mode: "rule".into(),
            log_level: "info".into(),
            allow_lan: false,
            ipv6: true,
            tun_enable: false,
        }
    }
}

impl Runtime {
    /// 从 [`RuntimePlan`] 构造 Runtime，但不启动任何监听。
    pub fn build(plan: RuntimePlan) -> Self {
        Self::build_with(plan, None, None)
    }

    /// 同 [`Runtime::build`]，但带持久化 store —— Smart 评分、group 手选、
    /// pin/avoid 等数据会从 store 加载并由后台 writer 异步落盘。
    pub fn build_with_store(plan: RuntimePlan, store: Option<Arc<Store>>) -> Self {
        Self::build_with(plan, store, None)
    }

    /// 完整版构造：同时接受 store + RulesetIndex。
    ///
    /// `rulesets` 必须由 main 在创建 Runtime 之前先 `RulesetIndex::new()` 并传入，
    /// 这样 [`RouteEngine`] 才能在 `set:<name>` 规则评估时查到外部规则集；
    /// 同一个 `Arc<RulesetIndex>` 应同时传给 [`core_capture`] 的
    /// `RulesetIpSetProvider`，保证 route + capture 共用同一份索引。
    pub fn build_with(
        plan: RuntimePlan,
        store: Option<Arc<Store>>,
        rulesets: Option<Arc<core_ruleset::RulesetIndex>>,
    ) -> Self {
        let mut reg = OutboundRegistry::new();
        register_nodes(&mut reg, &plan.nodes);

        let mut groups = BTreeMap::new();
        for (name, g) in &plan.groups {
            groups.insert(name.clone(), Arc::new(GroupSelector::new(g.clone())));
        }

        // RouteEngine：有 RulesetIndex 时走 `with_rulesets`，否则退化到 None
        // （`set:<name>` 规则会全部 fallthrough）。
        let route = match rulesets.clone() {
            Some(idx) => RouteEngine::with_rulesets(plan.route.clone(), idx),
            None => RouteEngine::new(plan.route.clone()),
        };
        let mut resolver = Resolver::try_new_with_rulesets(plan.resolver.clone(), rulesets.clone())
            .unwrap_or_else(|e| panic!("resolver config invalid: {e}"));
        if let Some(store) = store.clone() {
            resolver.attach_store(store);
        }
        let resolver = Arc::new(resolver);
        // 把 resolver 注入到 core-outbound 的全局，让 TcpTransport / TlsTransport
        // 等所有协议出站在 connect 之前先用 WutherCore 自己的 resolver 解析节点 host —— 否则
        // tokio 默认 getaddrinfo 走系统 DNS，TUN 接管后会自循环死锁。
        core_outbound::set_global_dial_resolver(Arc::new(ResolverAdapter {
            resolver: resolver.clone(),
        }));
        // DnsService 注入到 core-outbound：让 type=dns 的 DnsHijackOutbound
        // 能拿到本机 service（fake-ip / cache / nameserver-policy 与 capture
        // / standalone listener 共享同一份）。
        let dns_service = Arc::new(core_resolver::DnsService::new(resolver.clone()));
        core_outbound::set_global_dns_responder(Arc::new(DnsResponderAdapter {
            service: dns_service.clone(),
        }));
        // 注入 outbound fwmark：对齐 mihomo `dialer.DefaultRoutingMark`。
        // 默认值必须是 0（禁用），否则普通 Mixed/Direct 在无 CAP_NET_ADMIN 的
        // Linux 环境会因 SO_MARK=EPERM 直接无法出站。只有显式配置
        // auto_redirect_output_mark、TUN auto_route、或 TPROXY iptables 接管时，
        // 才使用 mark 绕过 redirect/tproxy chain。
        let out_mark = outbound_fwmark_for_plan(&plan);
        core_outbound::set_outbound_fwmark(out_mark);
        core_resolver::upstream::marked::set_dns_socket_factory(Arc::new(OutboundDnsSocketFactory));
        // 订阅 / 规则集拉取的 HTTP client 由 core-fetch 自管理：内部直接走
        // hyper + tokio-rustls + bind_outbound_socket，net_monitor 同步的
        // 出站 ifindex / 接口名对它即时生效，不需要 client rebuild。
        // engine 启动时也不需要"初始 client"。
        let smart = if let Some(store) = store.clone() {
            Arc::new(SmartSelector::with_store(
                plan.smart.goal,
                plan.smart.sticky,
                store,
            ))
        } else {
            Arc::new(SmartSelector::new(plan.smart.goal, plan.smart.sticky))
        };

        // Smart 节点初始化
        for n in &plan.nodes {
            smart.ensure_node(&n.name);
        }

        // 恢复 group manual 选择
        if let Some(store) = &store {
            if let Ok(rows) = store.iter_string(GROUP_MANUAL) {
                for (group_name, picked) in rows {
                    if let Some(g) = groups.get(&group_name) {
                        if g.members().iter().any(|m| m == &picked) {
                            g.set_manual(picked);
                        }
                    }
                }
            }
        }

        let mutable = MutableConfig {
            tun_enable: plan.capture.on,
            ipv6: true,
            ..MutableConfig::default()
        };
        let node_info = initial_node_info(&plan);
        let process_finder = if plan.find_process_mode.is_enabled() {
            Some(core_process::create_finder())
        } else {
            None
        };
        Self {
            plan,
            outbounds: parking_lot::RwLock::new(reg),
            groups: parking_lot::RwLock::new(groups),
            node_info: parking_lot::RwLock::new(node_info),
            route,
            resolver,
            dns_service,
            smart,
            metrics: Metrics::new(),
            connections: ConnectionTable::new(),
            store,
            logs: Arc::new(core_observe::LogBus::new(512)),
            mutable: parking_lot::RwLock::new(mutable),
            urltest: parking_lot::RwLock::new(None),
            process_finder,
        }
    }

    /// 由 main.rs 在 UrlTester::new 之后注入，让策略组的 URLTest/Fallback/LB
    /// 能拿到 alive_for_url / pick_fast。
    pub fn set_urltest(&self, t: Arc<crate::health::UrlTester>) {
        *self.urltest.write() = Some(t);
    }

    /// 周期性把连接表聚合摘要打到日志（target="conntable", level=info）。
    /// `interval` ≤ 1s 视为禁用 —— 避免误配置导致的日志洪水。
    /// 每次 tick 输出：总数 / TCP-UDP 拆分 / top-N 目的地 / top-N 进程 /
    /// by-rule / by-outbound / 长连接清单。
    /// 非 `None` 句柄返回给调用方 —— 优雅停机时 `.abort()` 关 logger。
    pub fn spawn_conntable_logger(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if interval < std::time::Duration::from_secs(1) {
            return None;
        }
        let me = self.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // 第一次 tick 立刻触发；让用户启动后即时看到一条 baseline 摘要。
            ticker.tick().await;
            tracing::info!(
                target: "conntable",
                "logger started (interval={:?})", interval
            );
            loop {
                ticker.tick().await;
                let summary = me
                    .connections
                    .summary(10, std::time::Duration::from_secs(300));
                core_observe::log_connection_summary(&summary);
            }
        });
        Some(handle)
    }

    /// 把 group manual 选择写入 store（持久化跨重启）。
    pub fn set_group_manual(&self, group: &str, node: &str) {
        let groups = self.groups.read();
        if let Some(g) = groups.get(group) {
            // mihomo 兼容：空 node = 清除固定（PUT /proxies/<group> {"name":""}）
            if node.is_empty() {
                g.clear_manual();
            } else {
                g.set_manual(node);
            }
        }
        if let Some(store) = &self.store {
            let _ = store.put_json::<String>(
                core_store::schema::GROUP_MANUAL,
                group,
                &node.to_string(),
            );
            // 不用 JSON：直接存裸字符串。这里复用 put_json 会写入 "node" 带引号的 JSON。
            // 改为直接 batch put：
            let _ = store.write_batch(&[core_store::store::BatchOp::PutGroupManual(
                group.to_string(),
                node.to_string(),
            )]);
        }
    }

    /// 优雅停止：把 Smart writer 的内存数据 flush 到磁盘。
    pub async fn shutdown(&self) {
        self.smart.shutdown().await;
        self.resolver.flush_to_store().await;
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.read().keys().cloned().collect()
    }

    pub fn outbound_names(&self) -> Vec<String> {
        self.outbounds
            .read()
            .names()
            .map(|s| s.to_string())
            .collect()
    }

    /// 把订阅刷新得到的最新节点列表注入到 outbound registry，
    /// 同时把 group.members 中的 `feed:<name>` 占位符替换为真实节点名集合。
    pub fn apply_feed_nodes(&self, feed_name: &str, nodes: Vec<core_config::node_uri::ParsedNode>) {
        let mut new_names: Vec<String> = Vec::with_capacity(nodes.len());
        let static_nodes: BTreeSet<String> =
            self.plan.nodes.iter().map(|n| n.name.clone()).collect();
        let removed_names: Vec<String> = {
            let info = self.node_info.read();
            info.iter()
                .filter(|(name, v)| {
                    v.provider.as_deref() == Some(feed_name) && !static_nodes.contains(*name)
                })
                .map(|(name, _)| name.clone())
                .collect()
        };
        {
            let mut reg = self.outbounds.write();
            let mut info = self.node_info.write();
            for name in &removed_names {
                reg.remove(name);
            }
            info.retain(|name, v| {
                v.provider.as_deref() != Some(feed_name) || static_nodes.contains(name)
            });
            for n in &nodes {
                let ob = core_outbound::registry::build_outbound(n);
                reg.insert(n.name.clone(), ob);
                info.insert(
                    n.name.clone(),
                    RuntimeNodeInfo::from_node(Some(feed_name.to_string()), n),
                );
                new_names.push(n.name.clone());
                self.smart.ensure_node(&n.name);
            }
        }

        let provider_nodes = self.provider_nodes_by_name();
        // 重建受影响的 GroupSelector：对每个含 feed:<name> 占位符的分组，
        // 用所有已加载 provider 快照展开，而不是只展开本次刷新 feed。
        let plan_map = self.plan.groups.clone();
        let mut groups = self.groups.write();
        let mut updated_groups = 0usize;
        for (name, base_plan) in plan_map {
            if base_plan
                .members
                .iter()
                .any(|m| feed_member_name(m).is_some())
            {
                let mut new_members = Vec::new();
                for m in &base_plan.members {
                    if let Some(provider) = feed_member_name(m) {
                        if let Some(names) = provider_nodes.get(provider) {
                            for nn in names {
                                if !new_members.contains(nn) {
                                    new_members.push(nn.clone());
                                }
                            }
                        } else if !new_members.contains(m) {
                            new_members.push(m.clone());
                        }
                    } else if !new_members.contains(m) {
                        new_members.push(m.clone());
                    }
                }
                let (old_options, old_manual) = groups
                    .get(&name)
                    .map(|g| (g.options(), g.current_manual()))
                    .unwrap_or_default();
                let mut updated = base_plan.clone();
                updated.members = new_members;
                let selector = Arc::new(crate::group_selector::GroupSelector::with_options(
                    updated.clone(),
                    old_options,
                ));
                if let Some(manual) = old_manual {
                    if updated.members.iter().any(|m| m == &manual) {
                        selector.set_manual(manual);
                    }
                }
                groups.insert(name.clone(), selector);
                updated_groups += 1;
            }
        }
        tracing::info!(
            target: "feeds",
            feed = feed_name,
            registered = new_names.len(),
            removed = removed_names.len(),
            groups = updated_groups,
            "feed nodes applied to runtime"
        );
    }

    fn provider_nodes_by_name(&self) -> BTreeMap<String, Vec<String>> {
        let info = self.node_info.read();
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, node) in info.iter() {
            let Some(provider) = node.provider.as_ref() else {
                continue;
            };
            let names = out.entry(provider.clone()).or_default();
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        out
    }

    pub fn pick_outbound(&self, host: &str, port: u16, network: NetworkKind) -> RoutePick {
        let ip = host.parse().ok();
        let ctx = FlowContext {
            host: host.to_string(),
            ip,
            port,
            network,
            process: None,
            protocol: None,
        };
        self.pick_outbound_for_context(ctx)
    }

    pub fn pick_outbound_for_context(&self, ctx: FlowContext) -> RoutePick {
        self.metrics.inc_route();
        let (decision, kind, source) = self.route.decide(&ctx);
        debug!(
            target: "route",
            host = %ctx.host,
            port = ctx.port,
            network = ctx.network.as_str(),
            ?decision,
            kind,
            source = %source,
            "rule hit"
        );

        let (label, outbound) = match &decision {
            RouteDecision::Direct => ("DIRECT".into(), self.must_get("DIRECT")),
            RouteDecision::Block => ("BLOCK".into(), self.must_get("BLOCK")),
            RouteDecision::Group(name) => self.pick_in_group(name, &ctx),
        };
        RoutePick {
            decision,
            label,
            outbound,
            rule: route_rule_name(kind).into(),
            rule_payload: source,
        }
    }

    fn pick_in_group(&self, group: &str, ctx: &FlowContext) -> (String, SharedOutbound) {
        let groups = self.groups.read();
        let Some(g) = groups.get(group) else {
            warn!(target: "route", group, "未知分组，阻断流量避免回退 DIRECT");
            return ("BLOCK".into(), self.must_get("BLOCK"));
        };
        let mut meta = crate::group_selector::FlowMeta::for_host(
            ctx.host.clone(),
            ctx.port,
            ctx.network.as_str(),
        );
        meta.dst_ip = ctx.ip;
        let tester = self.urltest.read().clone();
        let registry = self.outbounds.read();
        let pick = if ctx.network == NetworkKind::Udp {
            g.pick_eligible(&meta, &self.smart, tester.as_ref(), |name| {
                registry
                    .get(name)
                    .map(|ob| ob.capabilities().udp)
                    .unwrap_or(false)
            })
            .or_else(|| g.pick(&meta, &self.smart, tester.as_ref()))
        } else {
            g.pick(&meta, &self.smart, tester.as_ref())
        };
        if let Some(name) = pick {
            if let Some(ob) = registry.get(&name) {
                return (name, ob);
            }
            warn!(target: "route", node = %name, "节点未注册，阻断流量避免回退 DIRECT");
        } else if g.has_unresolved_feed_placeholders() {
            warn!(target: "route", group, "订阅节点尚未加载或为空，阻断流量避免回退 DIRECT");
        }
        ("BLOCK".into(), self.must_get("BLOCK"))
    }

    fn must_get(&self, name: &str) -> SharedOutbound {
        self.outbounds
            .read()
            .get(name)
            .expect("DIRECT/BLOCK 必须存在")
    }

    /// 给 inbound 调用：根据 host:port 找出口并 dial。
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        network: NetworkKind,
    ) -> std::io::Result<DialResult> {
        let ip = host.parse().ok();
        let ctx = FlowContext {
            host: host.to_string(),
            ip,
            port,
            network,
            process: None,
            protocol: None,
        };
        self.dial_with_context(ctx).await
    }

    pub async fn dial_with_context(&self, ctx: FlowContext) -> std::io::Result<DialResult> {
        let dial_id = core_outbound::next_dial_id();
        let host = ctx.host.clone();
        let port = ctx.port;
        let network = ctx.network;
        let net_str = network.as_str();
        let started = Instant::now();
        info!(
            target: "dial",
            id = dial_id,
            %host, port, network = net_str,
            "begin",
        );
        let mut attempted = BTreeSet::new();
        let mut last_err: Option<std::io::Error> = None;
        for attempt in 1..=DIAL_MAX_RETRIES {
            let pick = self.pick_outbound_for_context(ctx.clone());
            info!(
                target: "dial",
                id = dial_id,
                attempt,
                %host, port,
                outbound = %pick.label,
                decision = ?pick.decision,
                protocol = pick.outbound.protocol(),
                "route picked",
            );
            if matches!(pick.decision, RouteDecision::Block) {
                info!(target: "dial", id = dial_id, attempt, %host, port, outbound = %pick.label, "blocked by rule");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "blocked",
                ));
            }
            if !attempted.insert(pick.label.clone()) {
                if let Some(err) = last_err {
                    debug!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        error = %err,
                        "retry stopped because group selected the same outbound again",
                    );
                    return Err(err);
                }
            }
            let dial_ctx = DialContext {
                host: host.to_string(),
                port,
                network: net_str,
                dial_id,
            };
            let dial_start = Instant::now();
            let res = pick.outbound.dial_tcp(dial_ctx).await;
            let elapsed = started.elapsed();
            let dial_ms = dial_start.elapsed().as_millis() as u64;
            let group_for_event = match &pick.decision {
                RouteDecision::Group(g) => Some(g.clone()),
                _ => None,
            };
            match res {
                Ok(stream) => {
                    info!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        dial_ms,
                        total_ms = elapsed.as_millis() as u64,
                        "ok",
                    );
                    if pick.label != "DIRECT" && pick.label != "BLOCK" {
                        self.smart.record_success(&pick.label, elapsed);
                    }
                    if let Some(name) = &group_for_event {
                        if let Some(g) = self.groups.read().get(name) {
                            g.on_dial_success();
                        }
                    }
                    let chain = build_chain(&pick.decision, &pick.label);
                    let provider_chains = self.provider_chains_for_chain(&chain);
                    let remote_destination =
                        self.remote_destination_for_outbound(&pick.label, &host, port);
                    let smart_target = self.smart_target_for_decision(&pick.decision, &host);
                    return Ok(DialResult {
                        stream,
                        outbound: pick.label,
                        decision: pick.decision,
                        elapsed,
                        chain,
                        provider_chains,
                        remote_destination,
                        smart_target,
                        rule: pick.rule,
                        rule_payload: pick.rule_payload,
                    });
                }
                Err(e) => {
                    warn!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        dial_ms,
                        total_ms = elapsed.as_millis() as u64,
                        error = %e,
                        "failed",
                    );
                    if pick.label != "DIRECT" && pick.label != "BLOCK" {
                        self.smart.record_failure(&pick.label, e.to_string());
                    }
                    if let Some(name) = &group_for_event {
                        if let Some(g) = self.groups.read().get(name).cloned() {
                            let tester = self.urltest.read().clone();
                            let err_str = e.to_string();
                            let g_name = g.name().to_string();
                            g.on_dial_failed(&err_str, move || {
                                // 健康检查最小动作：清 fast-pick 缓存。
                                // 真实重测延迟到下一次 spawn_periodic round（避免 dial 热路径阻塞）。
                                if let Some(t) = tester.clone() {
                                    t.invalidate_fast_pick(&g_name);
                                }
                            });
                        }
                    }
                    if !should_retry_dial(&pick, &e, network, attempt) {
                        return Err(e);
                    }
                    debug!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        next_attempt = attempt + 1,
                        max_attempts = DIAL_MAX_RETRIES,
                        %host, port,
                        "retry dial with next group candidate",
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "dial retry exhausted")
        }))
    }

    /// Bypass capture policy and dial through DIRECT while keeping real accounting metadata.
    ///
    /// TUN `route_exclude_address(_set)` and `route_address(_set)` are routing-layer
    /// capture controls in mihomo/sing-tun. If a packet has already reached the
    /// userspace TUN stack, dropping it would blackhole the flow; direct dialing is
    /// the closest equivalent to "do not capture".
    pub async fn dial_direct_with_context(
        &self,
        ctx: FlowContext,
        reason: impl Into<String>,
    ) -> std::io::Result<DialResult> {
        self.metrics.inc_route();
        let reason = reason.into();
        let dial_id = core_outbound::next_dial_id();
        let host = ctx.host.clone();
        let port = ctx.port;
        let network = ctx.network;
        let net_str = network.as_str();
        let started = Instant::now();
        info!(
            target: "dial",
            id = dial_id,
            %host, port, network = net_str,
            bypass = %reason,
            "begin direct bypass",
        );
        let direct = self.must_get("DIRECT");
        let dial_start = Instant::now();
        let res = direct
            .dial_tcp(DialContext {
                host: host.clone(),
                port,
                network: net_str,
                dial_id,
            })
            .await;
        let elapsed = started.elapsed();
        let dial_ms = dial_start.elapsed().as_millis() as u64;
        match &res {
            Ok(_) => info!(
                target: "dial",
                id = dial_id,
                %host, port,
                outbound = "DIRECT",
                dial_ms,
                total_ms = elapsed.as_millis() as u64,
                bypass = %reason,
                "ok",
            ),
            Err(e) => warn!(
                target: "dial",
                id = dial_id,
                %host, port,
                outbound = "DIRECT",
                dial_ms,
                total_ms = elapsed.as_millis() as u64,
                bypass = %reason,
                error = %e,
                "failed",
            ),
        }
        let stream = res?;
        let decision = RouteDecision::Direct;
        let chain = build_chain(&decision, "DIRECT");
        Ok(DialResult {
            stream,
            outbound: "DIRECT".into(),
            decision,
            elapsed,
            chain,
            provider_chains: Vec::new(),
            remote_destination: self.remote_destination_for_outbound("DIRECT", &host, port),
            smart_target: String::new(),
            rule: "TUN-BYPASS".into(),
            rule_payload: reason,
        })
    }

    /// 与 [`Self::dial`] 镜像：路由决策一致，但走 outbound 的 UDP 通道。
    ///
    /// 行为对齐 mihomo：
    /// * `RouteDecision::Block` —— 直接 `ConnectionAborted`，**不** fallback
    ///   DIRECT（mihomo 同样直接拒绝，否则黑名单 UDP 会偷偷走出去）。
    /// * outbound 返回 `ErrorKind::Unsupported` —— 直接返回错误；UDP 不应静默
    ///   fallback DIRECT，否则代理规则命中了不支持 UDP 的节点时会发生泄漏。
    pub async fn dial_udp(&self, host: &str, port: u16) -> std::io::Result<UdpDialResult> {
        let ip = host.parse().ok();
        let ctx = FlowContext {
            host: host.to_string(),
            ip,
            port,
            network: NetworkKind::Udp,
            process: None,
            protocol: None,
        };
        self.dial_udp_with_context(ctx).await
    }

    pub async fn dial_udp_with_context(&self, ctx: FlowContext) -> std::io::Result<UdpDialResult> {
        let started = Instant::now();
        let dial_id = core_outbound::next_dial_id();
        let host = ctx.host.clone();
        let port = ctx.port;
        debug!(
            target: "dial",
            id = dial_id,
            %host, port, network = "udp",
            "begin (udp)",
        );
        let mut attempted = BTreeSet::new();
        let mut last_err: Option<std::io::Error> = None;
        for attempt in 1..=DIAL_MAX_RETRIES {
            let pick = self.pick_outbound_for_context(ctx.clone());
            if matches!(pick.decision, RouteDecision::Block) {
                debug!(target: "dial", id = dial_id, attempt, %host, port, outbound = %pick.label, "udp blocked");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "blocked",
                ));
            }
            if !attempted.insert(pick.label.clone()) {
                if let Some(err) = last_err {
                    debug!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        error = %err,
                        "udp retry stopped because group selected the same outbound again",
                    );
                    return Err(err);
                }
            }
            if !pick.outbound.capabilities().udp {
                let err = std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "outbound `{}`/{} does not support UDP relay",
                        pick.label,
                        pick.outbound.protocol()
                    ),
                );
                warn_udp_unsupported_once(&pick.label);
                debug!(
                    target: "dial",
                    id = dial_id,
                    attempt,
                    %host, port,
                    outbound = %pick.label,
                    error = %err,
                    "udp unsupported by picked outbound"
                );
                return Err(err);
            }
            let dial_ctx = DialContext {
                host: host.to_string(),
                port,
                network: "udp",
                dial_id,
            };
            match pick.outbound.dial_udp(dial_ctx).await {
                Ok(socket) => {
                    let elapsed = started.elapsed();
                    let chain = build_chain(&pick.decision, &pick.label);
                    let provider_chains = self.provider_chains_for_chain(&chain);
                    let remote_destination =
                        self.remote_destination_for_outbound(&pick.label, &host, port);
                    let smart_target = self.smart_target_for_decision(&pick.decision, &host);
                    debug!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        total_ms = elapsed.as_millis() as u64,
                        "udp ok",
                    );
                    if pick.label != "DIRECT" && pick.label != "BLOCK" {
                        self.smart.record_success(&pick.label, elapsed);
                    }
                    return Ok(UdpDialResult {
                        socket,
                        outbound: pick.label,
                        decision: pick.decision,
                        elapsed,
                        chain,
                        provider_chains,
                        remote_destination,
                        smart_target,
                        rule: pick.rule,
                        rule_payload: pick.rule_payload,
                    });
                }
                Err(e) => {
                    debug!(
                        target: "dial",
                        id = dial_id,
                        attempt,
                        %host, port,
                        outbound = %pick.label,
                        error = %e,
                        "udp dial failed"
                    );
                    if pick.label != "DIRECT" && pick.label != "BLOCK" {
                        self.smart.record_failure(&pick.label, e.to_string());
                    }
                    if !should_retry_dial(&pick, &e, NetworkKind::Udp, attempt) {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "udp dial retry exhausted")
        }))
    }

    pub async fn dial_udp_direct_with_context(
        &self,
        mut ctx: FlowContext,
        reason: impl Into<String>,
    ) -> std::io::Result<UdpDialResult> {
        self.metrics.inc_route();
        ctx.network = NetworkKind::Udp;
        let reason = reason.into();
        let started = Instant::now();
        let dial_id = core_outbound::next_dial_id();
        let host = ctx.host.clone();
        let port = ctx.port;
        debug!(
            target: "dial",
            id = dial_id,
            %host, port, network = "udp",
            bypass = %reason,
            "begin direct bypass (udp)",
        );
        let direct = self.must_get("DIRECT");
        let socket = direct
            .dial_udp(DialContext {
                host: host.clone(),
                port,
                network: "udp",
                dial_id,
            })
            .await?;
        let elapsed = started.elapsed();
        let decision = RouteDecision::Direct;
        let chain = build_chain(&decision, "DIRECT");
        debug!(
            target: "dial",
            id = dial_id,
            %host, port,
            outbound = "DIRECT",
            total_ms = elapsed.as_millis() as u64,
            bypass = %reason,
            "udp ok",
        );
        Ok(UdpDialResult {
            socket,
            outbound: "DIRECT".into(),
            decision,
            elapsed,
            chain,
            provider_chains: Vec::new(),
            remote_destination: self.remote_destination_for_outbound("DIRECT", &host, port),
            smart_target: String::new(),
            rule: "TUN-BYPASS".into(),
            rule_payload: reason,
        })
    }

    fn provider_chains_for_chain(&self, chain: &[String]) -> Vec<String> {
        let info = self.node_info.read();
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for label in chain {
            let provider = info
                .get(label)
                .and_then(|v| v.provider.clone())
                .or_else(|| infer_provider_from_name(&self.plan.feeds, label));
            if let Some(provider) = provider {
                if !provider.is_empty() && seen.insert(provider.clone()) {
                    out.push(provider);
                }
            }
        }
        out
    }

    fn remote_destination_for_outbound(&self, label: &str, host: &str, port: u16) -> String {
        if label != "DIRECT" && label != "BLOCK" {
            if let Some(info) = self.node_info.read().get(label) {
                if !info.remote_destination.is_empty() {
                    return info.remote_destination.clone();
                }
            }
        }
        format_host_port(host, port)
    }

    fn smart_target_for_decision(&self, decision: &RouteDecision, host: &str) -> String {
        let RouteDecision::Group(group) = decision else {
            return String::new();
        };
        let Some(group) = self.plan.groups.get(group) else {
            return String::new();
        };
        if !matches!(group.choose, ChooseStrategy::Smart) {
            return String::new();
        }
        host.trim_end_matches('.').to_string()
    }
}

/// 同一个 outbound label 的 "UDP unsupported" 警告每分钟最多 1 次，避免高 QPS UDP
/// 流量（QUIC/STUN）每包 warn 把日志刷爆。
fn warn_udp_unsupported_once(label: &str) {
    use std::{
        collections::HashMap,
        sync::OnceLock,
        time::{Duration, Instant},
    };
    static LAST: OnceLock<parking_lot::Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let map = LAST.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));
    let now = Instant::now();
    let mut g = map.lock();
    let prev = g.get(label).copied();
    let should_warn = match prev {
        Some(t) if now.duration_since(t) < Duration::from_secs(60) => false,
        _ => true,
    };
    if should_warn {
        g.insert(label.to_string(), now);
        drop(g);
        warn!(
            target: "dial",
            outbound = label,
            "udp unsupported by outbound (rate-limited)"
        );
    }
}

fn initial_node_info(plan: &RuntimePlan) -> BTreeMap<String, RuntimeNodeInfo> {
    plan.nodes
        .iter()
        .map(|node| {
            let provider = infer_provider_from_name(&plan.feeds, &node.name);
            (
                node.name.clone(),
                RuntimeNodeInfo::from_node(provider, node),
            )
        })
        .collect()
}

fn infer_provider_from_name(
    feeds: &BTreeMap<String, FeedDetail>,
    node_name: &str,
) -> Option<String> {
    feeds.keys().find_map(|feed| {
        if node_name.starts_with(&format!("{feed}/")) || node_name.contains(&format!("[{feed}]")) {
            Some(feed.clone())
        } else {
            None
        }
    })
}

fn feed_member_name(member: &str) -> Option<&str> {
    member
        .strip_prefix("feed:")
        .filter(|provider| !provider.trim().is_empty())
}

fn format_host_port(host: &str, port: u16) -> String {
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) if !host.starts_with('[') => format!("[{host}]"),
        _ => host.to_string(),
    };
    format!("{host}:{port}")
}

fn route_rule_name(kind: &str) -> &'static str {
    match kind {
        "any" | "fallback" => "MATCH",
        "domain" => "DOMAIN",
        "suffix" | "ads" | "service" => "DOMAIN-SUFFIX",
        "home" | "ip" => "IP-CIDR",
        "cn" => "GEOIP",
        "port" => "DST-PORT",
        "network" | "proto" => "NETWORK",
        "process" => "PROCESS-NAME",
        "set" => "RULE-SET",
        _ => "MATCH",
    }
}

fn build_chain(decision: &RouteDecision, label: &str) -> Vec<String> {
    match decision {
        RouteDecision::Direct => vec!["DIRECT".to_string()],
        RouteDecision::Block => vec!["BLOCK".to_string()],
        RouteDecision::Group(g) => {
            if label != g {
                vec![g.clone(), label.to_string()]
            } else {
                vec![g.clone()]
            }
        }
    }
}

fn should_retry_dial(
    pick: &RoutePick,
    err: &std::io::Error,
    network: NetworkKind,
    attempt: usize,
) -> bool {
    if attempt >= DIAL_MAX_RETRIES {
        return false;
    }
    if !matches!(pick.decision, RouteDecision::Group(_)) {
        return false;
    }
    if pick.label == "DIRECT" || pick.label == "BLOCK" {
        return false;
    }
    !is_non_retryable_dial_error(err, network)
}

fn is_non_retryable_dial_error(err: &std::io::Error, network: NetworkKind) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::Unsupported
        | ErrorKind::InvalidInput
        | ErrorKind::AddrNotAvailable
        | ErrorKind::PermissionDenied
        | ErrorKind::ConnectionAborted => return true,
        _ => {}
    }

    let msg = err.to_string().to_ascii_lowercase();
    let resolver_ip_not_found = msg.contains("no address associated")
        || msg.contains("name or service not known")
        || msg.contains("no such host")
        || msg.contains("ip not found")
        || msg.contains("dns record not found");
    let ip_version_error = msg.contains("ip version")
        || msg.contains("address family")
        || msg.contains("ipv6 disabled")
        || msg.contains("ipv6 is disabled");
    let loopback_error = msg.contains("loopback") || msg.contains("self-capture");
    let udp_unsupported = network == NetworkKind::Udp
        && (msg.contains("does not support udp")
            || msg.contains("udp relay")
            || msg.contains("udp 通道")
            || msg.contains("不支持 udp"));

    resolver_ip_not_found || ip_version_error || loopback_error || udp_unsupported
}

pub struct RoutePick {
    pub decision: RouteDecision,
    pub label: String,
    pub outbound: SharedOutbound,
    pub rule: String,
    pub rule_payload: String,
}

pub struct DialResult {
    pub stream: core_outbound::adapter::BoxedStream,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
    /// 完整的代理链 —— Clash dashboard 的 connections.metadata.chains 字段。
    /// 直连/拦截：`["DIRECT"]` / `["BLOCK"]`；分组：`["<group>", "<picked-node>"]`。
    /// mihomo 主分支的 chain 通常是 `[outbound, group]` 倒序，本实现保持 `[group, node]`
    /// 顺序方便阅读，dashboard 两种顺序都能正确展示链路。
    pub chain: Vec<String>,
    pub provider_chains: Vec<String>,
    pub remote_destination: String,
    pub smart_target: String,
    pub rule: String,
    pub rule_payload: String,
}

pub struct UdpDialResult {
    pub socket: core_outbound::adapter::BoxedUdp,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
    pub chain: Vec<String>,
    pub provider_chains: Vec<String>,
    pub remote_destination: String,
    pub smart_target: String,
    pub rule: String,
    pub rule_payload: String,
}

/// "0x2024" / "8228" → u32。
fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn outbound_fwmark_for_plan(plan: &RuntimePlan) -> u32 {
    if let Some(mark) = plan
        .capture
        .tun
        .auto_redirect_output_mark
        .as_deref()
        .and_then(parse_hex_u32)
    {
        return mark;
    }
    if capture_uses_tun_auto_route(&plan.capture) {
        core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
    } else if plan.capture.on && capture_uses_tproxy(&plan.capture) {
        0x2d0
    } else {
        0
    }
}

fn capture_uses_tun_auto_route(capture: &core_config::model::Capture) -> bool {
    if !capture.on || !(capture.tun.auto_route || capture.tun.auto_redirect) {
        return false;
    }
    match capture.method {
        core_config::model::CaptureMethod::VirtualNic => true,
        core_config::model::CaptureMethod::Auto => {
            !cfg!(any(target_os = "linux", target_os = "android"))
        }
        _ => false,
    }
}

fn capture_uses_tproxy(capture: &core_config::model::Capture) -> bool {
    match capture.method {
        core_config::model::CaptureMethod::Tproxy => true,
        core_config::model::CaptureMethod::Auto => {
            cfg!(any(target_os = "linux", target_os = "android"))
        }
        _ => false,
    }
}

/// 把 [`core_resolver::Resolver`] 适配为 [`core_outbound::DialResolver`]，
/// 让所有 outbound 在 dial 前用 WutherCore resolver（IP-literal DoH）解析主机名，
/// 避开 TUN 自循环。
#[derive(Debug)]
struct ResolverAdapter {
    resolver: Arc<Resolver>,
}

/// 把 [`core_resolver::DnsService`] 桥到 [`core_outbound::DnsResponder`] —— 让
/// `type: dns` 出站和 capture DNS hijack 共享同一份 service。
#[derive(Debug)]
struct DnsResponderAdapter {
    service: Arc<core_resolver::DnsService>,
}

#[async_trait::async_trait]
impl core_outbound::DnsResponder for DnsResponderAdapter {
    async fn serve_packet(&self, req: &[u8]) -> Vec<u8> {
        self.service.serve_packet(req).await
    }
}

#[async_trait::async_trait]
impl core_outbound::DialResolver for ResolverAdapter {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        match self.resolver.resolve_via_bootstrap(host).await {
            Ok(ips) => Ok(ips),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("resolver: {e}"),
            )),
        }
    }

    async fn resolve_for_direct(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        match self.resolver.resolve_via_direct(host).await {
            Ok(ips) => Ok(ips),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("resolver: {e}"),
            )),
        }
    }

    fn ipv6_enabled(&self) -> bool {
        self.resolver.ipv6_enabled()
    }
}

struct OutboundDnsSocketFactory;

impl core_resolver::upstream::marked::DnsSocketFactory for OutboundDnsSocketFactory {
    fn create_udp(&self, peer: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        let bind_addr: std::net::SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = std::net::UdpSocket::bind(bind_addr)?;
        core_outbound::protect_socket(&sock)?;
        let s2 = socket2::SockRef::from(&sock);
        // SO_MARK: Linux/Android fwmark rule 路由到物理网卡
        if let Err(e) = core_outbound::apply_outbound_mark_for_addr(&s2, peer) {
            let mark = core_outbound::outbound_fwmark();
            if mark != 0 {
                tracing::warn!(target: "dial::dns", %peer, error = %e, "DNS UDP SO_MARK failed");
                return Err(e);
            }
        }
        // 跨平台 OS 级出站绑定：Linux/Android SO_BINDTODEVICE，
        // Windows IP_UNICAST_IF / IPV6_UNICAST_IF，
        // macOS / iOS IP_BOUND_IF / IPV6_BOUND_IF。
        // 这是 DNS 上游 socket 在 Windows / macOS 上唯一能跳过 TUN 默认路由的
        // 路径——之前只调 bind_to_device 等于这两个平台彻底无防护，DNS 包全
        // 走 TUN 自循环（safety net 兜得住但有 3 段 user-stack 中转）。
        if let Err(e) = core_outbound::bind_outbound_socket(&s2, peer) {
            tracing::debug!(target: "dial::dns", %peer, error = %e, "DNS UDP outbound bind failed (non-fatal)");
        }
        Ok(sock)
    }

    fn create_tcp(&self, peer: std::net::SocketAddr) -> std::io::Result<std::net::TcpStream> {
        let domain = if peer.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        core_outbound::protect_socket(&sock)?;
        // SO_MARK: Linux/Android fwmark rule 路由
        if let Err(e) = core_outbound::apply_outbound_mark_for_addr(&sock, peer) {
            let mark = core_outbound::outbound_fwmark();
            if mark != 0 {
                tracing::warn!(target: "dial::dns", %peer, error = %e, "DNS TCP SO_MARK failed");
                return Err(e);
            }
        }
        // 同 create_udp：跨平台 OS 级出站绑定，Windows / macOS 上是唯一防护。
        if let Err(e) = core_outbound::bind_outbound_socket(&sock, peer) {
            tracing::debug!(target: "dial::dns", %peer, error = %e, "DNS TCP outbound bind failed (non-fatal)");
        }
        sock.connect_timeout(&peer.into(), std::time::Duration::from_secs(10))?;
        Ok(sock.into())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use async_trait::async_trait;
    use core_outbound::DialResolver;
    use core_resolver::{DnsError, DnsGroup, DnsUpstream, GroupStrategy, QType, ResolverBuilder};

    use super::*;

    #[derive(Debug)]
    struct StaticDnsUpstream {
        ip: IpAddr,
    }

    #[async_trait]
    impl DnsUpstream for StaticDnsUpstream {
        fn name(&self) -> &str {
            "static"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec![self.ip])
        }
        async fn query_aaaa(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            Ok(Vec::new())
        }
    }

    fn load_plan(yaml: &str) -> RuntimePlan {
        core_config::loader::load_from_str(yaml).unwrap()
    }

    #[tokio::test]
    async fn dial_resolver_uses_bootstrap_not_business_policy() {
        let bootstrap = Arc::new(DnsGroup::new(
            "bootstrap",
            GroupStrategy::Fallback,
            vec![Arc::new(StaticDnsUpstream {
                ip: "9.9.9.9".parse().unwrap(),
            }) as _],
        ));
        let resolver = ResolverBuilder::new()
            .bootstrap(bootstrap)
            .policy(
                core_resolver::PolicyEngine::new()
                    .with_default(core_resolver::DnsAction::Reject(Default::default())),
            )
            .build();
        let adapter = ResolverAdapter {
            resolver: Arc::new(resolver),
        };

        let ips = adapter.resolve("node.example.com").await.unwrap();
        assert_eq!(ips, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn runtime_with_store_restores_dns_cache() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-runtime-dns-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = core_store::Store::open(&path).unwrap();
        let expire_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        store
            .write_batch(&[core_store::store::BatchOp::PutDnsCache(
                "persist-runtime.example.invalid|A".into(),
                core_store::DnsCacheBlob {
                    ips: vec!["9.9.9.9".into()],
                    expire_secs,
                    origin: "test".into(),
                },
            )])
            .unwrap();

        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
resolver:
  mode: system
  fake: off
route:
  preset: direct
"#,
        );
        let runtime = Runtime::build_with_store(plan, Some(store));

        let ips = runtime
            .resolver
            .resolve_qtype("persist-runtime.example.invalid", QType::A)
            .await
            .unwrap();

        assert_eq!(ips, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn runtime_leaves_outbound_fwmark_disabled_when_not_configured() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
route:
  preset: direct
"#,
        );

        assert_eq!(outbound_fwmark_for_plan(&plan), 0);
    }

    #[test]
    fn runtime_uses_auto_redirect_default_output_mark_only_when_enabled() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
capture:
  on: true
  method: virtual_nic
  tun:
    auto_redirect: true
route:
  preset: direct
"#,
        );

        assert_eq!(outbound_fwmark_for_plan(&plan), 0x2024);
    }

    #[test]
    fn runtime_uses_tun_auto_route_output_mark_without_auto_redirect() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
capture:
  on: true
  method: virtual_nic
  tun:
    auto_route: true
route:
  preset: direct
"#,
        );

        assert_eq!(outbound_fwmark_for_plan(&plan), 0x2024);
    }

    #[test]
    fn runtime_uses_mihomo_tproxy_mark_when_tproxy_capture_enabled() {
        let mut plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
route:
  preset: direct
"#,
        );
        plan.capture.on = true;
        plan.capture.method = core_config::model::CaptureMethod::Tproxy;

        assert_eq!(outbound_fwmark_for_plan(&plan), 0x2d0);
    }

    #[test]
    fn applied_feed_nodes_produce_real_provider_chain_and_remote_destination() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/sub.yaml"
groups:
  main:
    choose: manual
    use: [provider-a]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);
        runtime.apply_feed_nodes(
            "provider-a",
            vec![core_config::node_uri::ParsedNode::new(
                "provider-a/node-1",
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.10",
                10001,
            )],
        );

        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        let chain = build_chain(&pick.decision, &pick.label);

        assert_eq!(pick.label, "provider-a/node-1");
        assert_eq!(
            chain,
            vec!["main".to_string(), "provider-a/node-1".to_string()]
        );
        assert_eq!(
            runtime.provider_chains_for_chain(&chain),
            vec!["provider-a".to_string()]
        );
        assert_eq!(
            runtime.remote_destination_for_outbound(&pick.label, "www.google.com", 443),
            "203.0.113.10:10001"
        );
    }

    #[test]
    fn feed_updates_expand_all_loaded_providers_without_erasing_each_other() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/a.yaml"
  provider-b: "https://example.invalid/b.yaml"
groups:
  main:
    choose: manual
    use: [provider-a, provider-b]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);
        runtime.apply_feed_nodes(
            "provider-a",
            vec![core_config::node_uri::ParsedNode::new(
                "provider-a/node-1",
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.10",
                10001,
            )],
        );
        runtime.apply_feed_nodes(
            "provider-b",
            vec![core_config::node_uri::ParsedNode::new(
                "provider-b/node-1",
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.20",
                10002,
            )],
        );

        let groups = runtime.groups.read();
        let members = groups.get("main").unwrap().members();

        assert!(members.contains(&"provider-a/node-1".to_string()));
        assert!(members.contains(&"provider-b/node-1".to_string()));
        assert!(!members.contains(&"feed:provider-a".to_string()));
        assert!(!members.contains(&"feed:provider-b".to_string()));
    }

    #[test]
    fn feed_update_replaces_stale_provider_outbounds_for_new_tun_flows() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/sub.yaml"
groups:
  main:
    choose: manual
    use: [provider-a]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);
        runtime.apply_feed_nodes(
            "provider-a",
            vec![core_config::node_uri::ParsedNode::new(
                "provider-a/old",
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.10",
                10001,
            )],
        );
        runtime.apply_feed_nodes(
            "provider-a",
            vec![core_config::node_uri::ParsedNode::new(
                "provider-a/new",
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.20",
                10002,
            )],
        );

        let names = runtime.outbound_names();
        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);

        assert!(!names.contains(&"provider-a/old".to_string()));
        assert!(names.contains(&"provider-a/new".to_string()));
        assert_eq!(pick.label, "provider-a/new");
    }

    #[test]
    fn unresolved_feed_group_blocks_instead_of_falling_back_direct() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/sub.yaml"
groups:
  main:
    choose: manual
    use: [provider-a]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);

        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);

        assert_eq!(pick.label, "BLOCK");
    }

    #[test]
    fn process_finder_disabled_by_default() {
        // 与 mihomo 一致：未配置 find-process-mode 默认 off，process_finder 不构建。
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
"#,
        );
        let runtime = Runtime::build(plan);
        assert!(
            runtime.process_finder.is_none(),
            "find-process-mode 默认 off → finder 不应构建"
        );
    }

    #[test]
    fn process_finder_built_when_mode_enabled() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
find-process-mode: always
"#,
        );
        let runtime = Runtime::build(plan);
        assert!(
            runtime.process_finder.is_some(),
            "find-process-mode: always → finder 必须构建"
        );
    }

    #[test]
    fn process_finder_built_for_strict_mode() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
find-process-mode: strict
"#,
        );
        let runtime = Runtime::build(plan);
        assert!(
            runtime.process_finder.is_some(),
            "find-process-mode: strict → finder 必须构建"
        );
    }

    #[test]
    fn unresolved_feed_group_can_use_static_direct_fallback() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/sub.yaml"
nodes:
  - "direct://0.0.0.0:0#direct-fallback"
groups:
  main:
    choose: manual
    use: [provider-a, nodes]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);

        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);

        assert_eq!(pick.label, "direct-fallback");
    }

    #[test]
    fn retry_stop_conditions_match_mihomo_dialer() {
        assert!(is_non_retryable_dial_error(
            &std::io::Error::new(std::io::ErrorKind::Unsupported, "no udp"),
            NetworkKind::Udp,
        ));
        assert!(is_non_retryable_dial_error(
            &std::io::Error::new(
                std::io::ErrorKind::Other,
                "resolver: failed to lookup address information: No address associated with hostname",
            ),
            NetworkKind::Tcp,
        ));
        assert!(is_non_retryable_dial_error(
            &std::io::Error::new(std::io::ErrorKind::Other, "ipv6 disabled"),
            NetworkKind::Tcp,
        ));
        assert!(is_non_retryable_dial_error(
            &std::io::Error::new(std::io::ErrorKind::Other, "loopback self-capture"),
            NetworkKind::Udp,
        ));
        assert!(!is_non_retryable_dial_error(
            &std::io::Error::new(std::io::ErrorKind::TimedOut, "node timed out"),
            NetworkKind::Tcp,
        ));
        assert!(!is_non_retryable_dial_error(
            &std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "node refused"),
            NetworkKind::Tcp,
        ));
    }

    #[test]
    fn udp_group_pick_skips_members_without_udp_relay() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "http://127.0.0.1:8080#tcp-only"
  - "direct://0.0.0.0:0#udp-direct"
groups:
  main:
    choose: manual
    use: [tcp-only, udp-direct]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);

        let pick = runtime.pick_outbound("8.8.8.8", 53, NetworkKind::Udp);

        assert_eq!(pick.label, "udp-direct");
    }

    #[tokio::test]
    async fn udp_dial_returns_unsupported_when_group_has_no_udp_capable_node() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "http://127.0.0.1:8080#tcp-only"
groups:
  main:
    choose: manual
    use: [tcp-only]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);

        let err = match runtime.dial_udp("8.8.8.8", 53).await {
            Ok(_) => panic!("UDP dial unexpectedly succeeded through tcp-only outbound"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        let err_s = err.to_string();
        assert!(err_s.contains("tcp-only"));
        assert!(err_s.contains("http"));
    }

    #[test]
    fn smart_group_sets_smart_target_from_real_route_decision() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#smart-node"
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan);

        let pick = runtime.pick_outbound("Example.COM.", 443, NetworkKind::Tcp);

        assert!(matches!(pick.decision, RouteDecision::Group(ref group) if group == "main"));
        assert_eq!(
            runtime.smart_target_for_decision(&pick.decision, "Example.COM."),
            "Example.COM"
        );
    }

    #[test]
    fn runtime_ruleset_step_is_evaluated_before_preset_fallback() {
        let idx = core_ruleset::RulesetIndex::new();
        idx.insert(std::sync::Arc::new(
            core_ruleset::RulesetMatcher::compile_domains(
                "openai",
                vec!["+.openai.com".to_string()],
            ),
        ));
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#node-a"
groups:
  main:
    choose: manual
    use: [nodes]
  ai:
    choose: manual
    use: [nodes]
route:
  preset: cn_smart
  final: main
  steps:
    - "set:openai -> ai"
"#,
        );
        let runtime = Runtime::build_with(plan, None, Some(idx));

        let pick = runtime.pick_outbound("api.openai.com", 443, NetworkKind::Tcp);

        assert!(matches!(pick.decision, RouteDecision::Group(ref group) if group == "ai"));
        assert_eq!(pick.rule, "RULE-SET");
        assert_eq!(pick.rule_payload, "set:openai -> ai");
    }
}
