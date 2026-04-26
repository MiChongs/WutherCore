//! Runtime —— 启动 + 持有所有运行时组件 + 提供 dispatch 接口。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use core_config::runtime_plan::RuntimePlan;
use core_observe::{ConnectionTable, Metrics};
use core_outbound::{
    adapter::{DialContext, SharedOutbound},
    registry::{register_nodes, OutboundRegistry},
};
use core_resolver::Resolver;
use core_route::{FlowContext, NetworkKind, RouteDecision, RouteEngine};
use core_smart::SmartSelector;
use core_store::{schema::GROUP_MANUAL, Store};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::group_selector::GroupSelector;

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
    pub route: RouteEngine,
    pub resolver: Arc<Resolver>,
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
}

/// 运行期可热改的配置子集 —— Clash dashboard `/configs` 写入的目标。
#[derive(Debug, Clone)]
pub struct MutableConfig {
    pub mode: String,         // rule / global / direct
    pub log_level: String,    // debug / info / warning / error / silent
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
        let resolver = Arc::new(Resolver::new(plan.resolver.clone()));
        // 把 resolver 注入到 core-outbound 的全局，让 TcpTransport / TlsTransport
        // 等所有协议出站在 connect 之前先用 RPKernel 自己的 resolver 解析节点 host —— 否则
        // tokio 默认 getaddrinfo 走系统 DNS，TUN 接管后会自循环死锁。
        core_outbound::set_global_dial_resolver(Arc::new(ResolverAdapter {
            resolver: resolver.clone(),
        }));
        // 注入 outbound fwmark：对齐 mihomo `dialer.DefaultRoutingMark`。
        // 默认值必须是 0（禁用），否则普通 Mixed/Direct 在无 CAP_NET_ADMIN 的
        // Linux 环境会因 SO_MARK=EPERM 直接无法出站。只有显式配置
        // auto_redirect_output_mark，或启用 auto_redirect 时，才使用 mark 绕过
        // redirect chain。
        let out_mark = outbound_fwmark_for_plan(&plan);
        core_outbound::set_outbound_fwmark(out_mark);
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
        Self {
            plan,
            outbounds: parking_lot::RwLock::new(reg),
            groups: parking_lot::RwLock::new(groups),
            route,
            resolver,
            smart,
            metrics: Metrics::new(),
            connections: ConnectionTable::new(),
            store,
            logs: Arc::new(core_observe::LogBus::new(512)),
            mutable: parking_lot::RwLock::new(mutable),
            urltest: parking_lot::RwLock::new(None),
        }
    }

    /// 由 main.rs 在 UrlTester::new 之后注入，让策略组的 URLTest/Fallback/LB
    /// 能拿到 alive_for_url / pick_fast。
    pub fn set_urltest(&self, t: Arc<crate::health::UrlTester>) {
        *self.urltest.write() = Some(t);
    }

    /// 把 group manual 选择写入 store（持久化跨重启）。
    pub fn set_group_manual(&self, group: &str, node: &str) {
        let groups = self.groups.read();
        if let Some(g) = groups.get(group) {
            g.set_manual(node);
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
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.read().keys().cloned().collect()
    }

    pub fn outbound_names(&self) -> Vec<String> {
        self.outbounds.read().names().map(|s| s.to_string()).collect()
    }

    /// 把订阅刷新得到的最新节点列表注入到 outbound registry，
    /// 同时把 group.members 中的 `feed:<name>` 占位符替换为真实节点名集合。
    pub fn apply_feed_nodes(&self, feed_name: &str, nodes: Vec<core_config::node_uri::ParsedNode>) {
        let placeholder = format!("feed:{feed_name}");
        let mut new_names: Vec<String> = Vec::with_capacity(nodes.len());
        {
            let mut reg = self.outbounds.write();
            for n in &nodes {
                let ob = core_outbound::registry::build_outbound(n);
                reg.insert(n.name.clone(), ob);
                new_names.push(n.name.clone());
                self.smart.ensure_node(&n.name);
            }
        }
        // 重建受影响的 GroupSelector：对每个含 feed:<name> 占位符的分组，
        // 用 (原 members - 占位符 + 实际节点名) 重建一个新的 selector。
        let plan_map = self.plan.groups.clone();
        let mut groups = self.groups.write();
        for (name, base_plan) in plan_map {
            if base_plan.members.iter().any(|m| m == &placeholder) {
                let mut new_members = Vec::with_capacity(base_plan.members.len() + new_names.len());
                for m in &base_plan.members {
                    if m == &placeholder {
                        for nn in &new_names {
                            if !new_members.contains(nn) {
                                new_members.push(nn.clone());
                            }
                        }
                    } else if !new_members.contains(m) {
                        new_members.push(m.clone());
                    }
                }
                let mut updated = base_plan.clone();
                updated.members = new_members;
                groups.insert(
                    name.clone(),
                    Arc::new(crate::group_selector::GroupSelector::new(updated)),
                );
            }
        }
        tracing::info!(
            target: "feeds",
            feed = feed_name,
            registered = new_names.len(),
            "feed nodes applied to runtime"
        );
    }

    pub fn pick_outbound(&self, host: &str, port: u16, network: NetworkKind) -> (RouteDecision, String, SharedOutbound) {
        self.metrics.inc_route();
        let ip = host.parse().ok();
        let ctx = FlowContext {
            host: host.to_string(),
            ip,
            port,
            network,
            process: None,
            protocol: None,
        };
        let (decision, kind, source) = self.route.decide(&ctx);
        debug!(target: "route", host = %host, port, ?decision, kind, source = %source, "rule hit");

        let (label, ob) = match &decision {
            RouteDecision::Direct => ("DIRECT".into(), self.must_get("DIRECT")),
            RouteDecision::Block => ("BLOCK".into(), self.must_get("BLOCK")),
            RouteDecision::Group(name) => self.pick_in_group(name, host),
        };
        let _ = kind;
        let _ = source;
        (decision, label, ob)
    }

    fn pick_in_group(&self, group: &str, host: &str) -> (String, SharedOutbound) {
        let groups = self.groups.read();
        let Some(g) = groups.get(group) else {
            warn!(target: "route", group, "未知分组，回退 DIRECT");
            return ("DIRECT".into(), self.must_get("DIRECT"));
        };
        let meta = crate::group_selector::FlowMeta::for_host(host, 0, "tcp");
        let tester = self.urltest.read().clone();
        let pick = g.pick(&meta, &self.smart, tester.as_ref());
        if let Some(name) = pick {
            if let Some(ob) = self.outbounds.read().get(&name) {
                return (name, ob);
            }
            warn!(target: "route", node = %name, "节点未注册，回退 DIRECT");
        }
        ("DIRECT".into(), self.must_get("DIRECT"))
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
        let dial_id = core_outbound::next_dial_id();
        let net_str = match network {
            NetworkKind::Tcp => "tcp",
            NetworkKind::Udp => "udp",
        };
        let started = Instant::now();
        info!(
            target: "dial",
            id = dial_id,
            %host, port, network = net_str,
            "begin",
        );
        let (decision, label, ob) = self.pick_outbound(host, port, network);
        info!(
            target: "dial",
            id = dial_id,
            %host, port,
            outbound = %label,
            decision = ?decision,
            protocol = ob.protocol(),
            "route picked",
        );
        if matches!(decision, RouteDecision::Block) {
            info!(target: "dial", id = dial_id, %host, port, outbound = %label, "blocked by rule");
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "blocked",
            ));
        }
        let ctx = DialContext {
            host: host.to_string(),
            port,
            network: net_str,
            dial_id,
        };
        let dial_start = Instant::now();
        let res = ob.dial_tcp(ctx).await;
        let elapsed = started.elapsed();
        let dial_ms = dial_start.elapsed().as_millis() as u64;
        let group_for_event = match &decision {
            RouteDecision::Group(g) => Some(g.clone()),
            _ => None,
        };
        match &res {
            Ok(_) => {
                info!(
                    target: "dial",
                    id = dial_id,
                    %host, port,
                    outbound = %label,
                    dial_ms,
                    total_ms = elapsed.as_millis() as u64,
                    "ok",
                );
                if label != "DIRECT" && label != "BLOCK" {
                    self.smart.record_success(&label, elapsed);
                }
                if let Some(name) = &group_for_event {
                    if let Some(g) = self.groups.read().get(name) {
                        g.on_dial_success();
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "dial",
                    id = dial_id,
                    %host, port,
                    outbound = %label,
                    dial_ms,
                    total_ms = elapsed.as_millis() as u64,
                    error = %e,
                    "failed",
                );
                if label != "DIRECT" && label != "BLOCK" {
                    self.smart.record_failure(&label, e.to_string());
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
            }
        }
        let stream = res?;
        // chain：分组场景 ["<group>", "<picked-node>"]，否则 ["DIRECT"]/["BLOCK"]/["<node>"]
        let chain = build_chain(&decision, &label);
        Ok(DialResult {
            stream,
            outbound: label,
            decision,
            elapsed,
            chain,
        })
    }

    /// 与 [`Self::dial`] 镜像：路由决策一致，但走 outbound 的 UDP 通道。
    ///
    /// 行为对齐 mihomo：
    /// * `RouteDecision::Block` —— 直接 `ConnectionAborted`，**不** fallback
    ///   DIRECT（mihomo 同样直接拒绝，否则黑名单 UDP 会偷偷走出去）。
    /// * outbound 返回 `ErrorKind::Unsupported`（vmess/trojan 暂未实现 UDP 通道
    ///   的占位错误）—— fallback DIRECT，但用 once_cell 限流的 warn 避免每包刷屏。
    pub async fn dial_udp(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<UdpDialResult> {
        let started = Instant::now();
        let dial_id = core_outbound::next_dial_id();
        debug!(
            target: "dial",
            id = dial_id,
            %host, port, network = "udp",
            "begin (udp)",
        );
        let (decision, label, ob) = self.pick_outbound(host, port, NetworkKind::Udp);
        if matches!(decision, RouteDecision::Block) {
            debug!(target: "dial", id = dial_id, %host, port, outbound = %label, "udp blocked");
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "blocked",
            ));
        }
        let ctx = DialContext {
            host: host.to_string(),
            port,
            network: "udp",
            dial_id,
        };
        let res = ob.dial_udp(ctx.clone()).await;
        let socket = match res {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                warn_udp_unsupported_once(&label);
                // fallback DIRECT —— 不丢包，但 dashboard 仍标记"实际 outbound = DIRECT"
                let direct = self.must_get("DIRECT");
                direct.dial_udp(ctx).await?
            }
            Err(e) => {
                debug!(
                    target: "dial",
                    id = dial_id,
                    %host, port,
                    outbound = %label,
                    error = %e,
                    "udp dial failed"
                );
                return Err(e);
            }
        };
        let elapsed = started.elapsed();
        let chain = build_chain(&decision, &label);
        debug!(
            target: "dial",
            id = dial_id,
            %host, port,
            outbound = %label,
            total_ms = elapsed.as_millis() as u64,
            "udp ok",
        );
        Ok(UdpDialResult {
            socket,
            outbound: label,
            decision,
            elapsed,
            chain,
        })
    }
}

/// 同一个 outbound label 的 "UDP unsupported" 警告每分钟最多 1 次，避免高 QPS UDP
/// 流量（QUIC/STUN）每包 warn 把日志刷爆。
fn warn_udp_unsupported_once(label: &str) {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
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
            "udp unsupported by outbound; falling back to DIRECT (rate-limited)"
        );
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
}

pub struct UdpDialResult {
    pub socket: core_outbound::adapter::BoxedUdp,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
    pub chain: Vec<String>,
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
    if plan.capture.on && plan.capture.tun.auto_redirect {
        0x2024
    } else {
        0
    }
}

/// 把 [`core_resolver::Resolver`] 适配为 [`core_outbound::DialResolver`]，
/// 让所有 outbound 在 dial 前用 RPKernel resolver（IP-literal DoH）解析主机名，
/// 避开 TUN 自循环。
#[derive(Debug)]
struct ResolverAdapter {
    resolver: Arc<Resolver>,
}

#[async_trait::async_trait]
impl core_outbound::DialResolver for ResolverAdapter {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        match self.resolver.resolve(host).await {
            Ok(ips) => Ok(ips),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("resolver: {e}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static FWMARK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn load_plan(yaml: &str) -> RuntimePlan {
        core_config::loader::load_from_str(yaml).unwrap()
    }

    #[test]
    fn runtime_leaves_outbound_fwmark_disabled_when_not_configured() {
        let _guard = FWMARK_TEST_LOCK.lock().unwrap();
        core_outbound::set_outbound_fwmark(0x7bad);
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

        let _runtime = Runtime::build(plan);

        assert_eq!(core_outbound::outbound_fwmark(), 0);
    }

    #[test]
    fn runtime_uses_auto_redirect_default_output_mark_only_when_enabled() {
        let _guard = FWMARK_TEST_LOCK.lock().unwrap();
        core_outbound::set_outbound_fwmark(0);
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

        let _runtime = Runtime::build(plan);

        assert_eq!(core_outbound::outbound_fwmark(), 0x2024);
    }
}
