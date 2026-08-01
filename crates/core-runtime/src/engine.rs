//! Runtime —— 启动 + 持有所有运行时组件 + 提供 dispatch 接口。

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use arc_swap::ArcSwap;
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
use core_route::{
    DetailedRouteDecision, FlowContext, NetworkKind, RouteDecision, RouteEngine, RouteRuleHit,
};
use core_smart::SmartSelector;
use core_store::{
    GroupPinBlob, Store,
    schema::{GROUP_MANUAL, GROUP_PIN},
    store::BatchOp,
};
use smallvec::{SmallVec, smallvec};
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::group_selector::{GroupPin, GroupSelector, ManualProbeToken, PinSource};

const DIAL_MAX_RETRIES: usize = 10;
const GROUP_MAX_DEPTH: usize = 32;
pub type GroupChain = SmallVec<[String; 4]>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("配置错误: {0}")]
    Config(#[from] core_config::ConfigError),
    #[error("出站配置错误: {0}")]
    OutboundConfig(String),
    #[error("解析器配置错误: {0}")]
    ResolverConfig(String),
    #[error("出站不存在: {0}")]
    UnknownOutbound(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Runtime {
    pub plan: RuntimePlan,
    pub outbounds: Arc<parking_lot::RwLock<OutboundRegistry>>,
    /// provider 刷新时通过 ArcSwap 一次发布完整组快照，选路线程只做无锁读取。
    pub groups: Arc<ArcSwap<BTreeMap<String, Arc<GroupSelector>>>>,
    /// pin 是低频控制面事务。串行化内存状态与 Turso 提交，避免并发 API
    /// 更新造成数据库和运行时顺序分叉。
    group_pin_lock: tokio::sync::Mutex<()>,
    node_info: parking_lot::RwLock<BTreeMap<String, RuntimeNodeInfo>>,
    node_update_lock: parking_lot::Mutex<()>,
    node_revision: AtomicU64,
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
    pub urltest: Arc<parking_lot::RwLock<Option<Arc<crate::health::UrlTester>>>>,
    /// 规则集管理器 —— 周期任务、Clash API 手动刷新和路由数据面共享同一实例。
    pub ruleset_manager: parking_lot::RwLock<Option<Arc<core_ruleset::RulesetManager>>>,
    /// 进程反查 —— 与 mihomo `find-process-mode` 1:1。
    /// `None` 表示 mode=off；`Some(finder)` 表示 strict（默认）或 always。
    /// strict 模式下调用方判定路由用到 process 字段才查；always 则每条都查。
    pub process_finder: Option<Arc<dyn core_process::ProcessFinder>>,
}

#[derive(Debug, Clone)]
struct RuntimeNodeInfo {
    provider: Option<String>,
    remote_destination: String,
    udp: bool,
    node: ParsedNode,
}

impl RuntimeNodeInfo {
    fn from_node(provider: Option<String>, node: &ParsedNode) -> Self {
        Self {
            provider,
            remote_destination: node.host.trim_matches(['[', ']']).to_string(),
            udp: node.udp,
            node: node.clone(),
        }
    }
}

/// API and control-plane view of one activated outbound node.
///
/// Unlike [`RuntimePlan::nodes`], this snapshot includes provider nodes loaded
/// after startup and excludes provider nodes removed by a later refresh.
#[derive(Debug, Clone)]
pub struct RuntimeNodeSnapshot {
    pub provider: Option<String>,
    pub node: ParsedNode,
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
    pub fn build(plan: RuntimePlan) -> Result<Self, RuntimeError> {
        futures::executor::block_on(Self::build_with(plan, None, None))
    }

    /// 同 [`Runtime::build`]，但带持久化 store —— Smart 评分、group 手选、
    /// pin/avoid 等数据会从 store 加载并由后台 writer 异步落盘。
    pub async fn build_with_store(
        plan: RuntimePlan,
        store: Option<Arc<Store>>,
    ) -> Result<Self, RuntimeError> {
        Self::build_with(plan, store, None).await
    }

    /// 完整版构造：同时接受 store + RulesetIndex。
    ///
    /// `rulesets` 必须由 main 在创建 Runtime 之前先 `RulesetIndex::new()` 并传入，
    /// 这样 [`RouteEngine`] 才能在 `set:<name>` 规则评估时查到外部规则集；
    /// 同一个 `Arc<RulesetIndex>` 应同时传给 `core_capture` 的
    /// `RulesetIpSetProvider`，保证 route + capture 共用同一份索引。
    pub async fn build_with(
        plan: RuntimePlan,
        store: Option<Arc<Store>>,
        rulesets: Option<Arc<core_ruleset::RulesetIndex>>,
    ) -> Result<Self, RuntimeError> {
        let mut reg = OutboundRegistry::new();
        register_nodes(&mut reg, &plan.nodes).map_err(RuntimeError::OutboundConfig)?;
        let outbounds = Arc::new(parking_lot::RwLock::new(reg));

        let mut groups = BTreeMap::new();
        for (name, g) in &plan.groups {
            groups.insert(name.clone(), Arc::new(GroupSelector::new(g.clone())));
        }
        let groups = Arc::new(ArcSwap::from_pointee(groups));

        // RouteEngine：有 RulesetIndex 时走 `with_rulesets`，否则退化到 None
        // （`set:<name>` 规则会全部 fallthrough）。
        let route = match rulesets.clone() {
            Some(idx) => RouteEngine::with_rulesets(plan.route.clone(), idx),
            None => RouteEngine::new(plan.route.clone()),
        };
        let mut resolver = Resolver::try_new_with_rulesets(plan.resolver.clone(), rulesets.clone())
            .map_err(|error| RuntimeError::ResolverConfig(error.to_string()))?;
        if let Some(store) = store.clone() {
            resolver.attach_store(store).await;
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
        // Runtime 构造本身不能激活进程级 outbound fwmark：capture 可能稍后
        // 启动失败，甚至根本没有 supervisor。非零 mark 由 CaptureSupervisor
        // 在平台 ingress 启动前事务化持有，并在平台回滚成功后释放。
        core_resolver::upstream::marked::set_dns_socket_factory(Arc::new(OutboundDnsSocketFactory));
        // 订阅 / 规则集拉取的 HTTP client 由 core-fetch 自管理：内部直接走
        // hyper + tokio-rustls + bind_outbound_socket，net_monitor 同步的
        // 出站 ifindex / 接口名对它即时生效，不需要 client rebuild。
        // engine 启动时也不需要"初始 client"。
        let smart = if let Some(store) = store.clone() {
            Arc::new(SmartSelector::with_store(plan.smart.goal, plan.smart.sticky, store).await)
        } else {
            Arc::new(SmartSelector::new(plan.smart.goal, plan.smart.sticky))
        };
        let urltest = Arc::new(parking_lot::RwLock::new(None));
        core_resolver::upstream::outbound::set_dns_outbound_provider(Arc::new(
            RuntimeDnsOutboundProvider {
                outbounds: outbounds.clone(),
                groups: groups.clone(),
                smart: smart.clone(),
                urltest: urltest.clone(),
            },
        ));

        // Smart 节点初始化
        for n in &plan.nodes {
            smart.ensure_node(&n.name);
        }

        // 恢复完整 group pin。provider 节点可能要在启动后的订阅 bootstrap 才
        // 出现，因此不能以当前 members 是否包含节点为恢复条件。
        if let Some(store) = &store {
            if let Ok(rows) = store.iter_json::<GroupPinBlob>(GROUP_PIN).await {
                for (group_name, blob) in rows {
                    if blob.node.is_empty() {
                        continue;
                    }
                    if let Some(group) = groups.load().get(&group_name) {
                        group.restore_pin(GroupPin {
                            node: blob.node,
                            generation: blob.generation.max(1),
                            created_at_ms: blob.created_at_ms,
                            source: PinSource::parse(&blob.source),
                        });
                    }
                }
            }
            // v0.3.4 及更早只保存字符串。仅在新命名空间没有该组时回填；
            // 后续第一次写入会删除旧键。
            if let Ok(rows) = store.iter_string(GROUP_MANUAL).await {
                for (group_name, picked) in rows {
                    if let Some(g) = groups.load().get(&group_name) {
                        if g.current_pin().is_none() && !picked.is_empty() {
                            g.set_manual(picked);
                        }
                    }
                }
            }
        }

        let mutable = MutableConfig {
            // share=home/all 时 Mixed/API 绑定 0.0.0.0，与 Clash allow-lan 语义对齐。
            allow_lan: !matches!(plan.listen.share, core_config::model::Share::False),
            tun_enable: plan.capture.on,
            ipv6: plan.resolver.ipv6,
            ..MutableConfig::default()
        };
        let node_info = initial_node_info(&plan);
        let process_finder = if plan.find_process_mode.is_enabled() {
            Some(core_process::create_finder())
        } else {
            None
        };
        let connections = match store.clone() {
            Some(store) => ConnectionTable::with_store(store).await,
            None => ConnectionTable::new(),
        };
        Ok(Self {
            plan,
            outbounds,
            groups,
            group_pin_lock: tokio::sync::Mutex::new(()),
            node_info: parking_lot::RwLock::new(node_info),
            node_update_lock: parking_lot::Mutex::new(()),
            node_revision: AtomicU64::new(0),
            route,
            resolver,
            dns_service,
            smart,
            metrics: Metrics::new(),
            connections,
            store,
            logs: Arc::new(core_observe::LogBus::new(512)),
            mutable: parking_lot::RwLock::new(mutable),
            urltest,
            ruleset_manager: parking_lot::RwLock::new(None),
            process_finder,
        })
    }

    /// Capture 数据面运行期间需要持有的进程级 outbound fwmark。
    ///
    /// 此方法只计算配置结果，不修改全局 socket 状态；生命周期所有权由
    /// `core-capture` 的 supervisor 管理。
    pub fn capture_outbound_fwmark(&self) -> u32 {
        outbound_fwmark_for_plan(&self.plan)
    }

    /// 由 main.rs 在 UrlTester::new 之后注入，让策略组的 URLTest/Fallback/LB
    /// 能拿到 alive_for_url / pick_fast。
    pub fn set_urltest(&self, t: Arc<crate::health::UrlTester>) {
        // 不在启动时探测所有组。首次真实选路会 touch 对应计划，闲置组不会
        // 为海量 provider 节点创建连接和 future。
        *self.urltest.write() = Some(t);
    }

    pub fn set_ruleset_manager(&self, manager: Arc<core_ruleset::RulesetManager>) {
        *self.ruleset_manager.write() = Some(manager);
    }

    pub fn ruleset_manager(&self) -> Option<Arc<core_ruleset::RulesetManager>> {
        self.ruleset_manager.read().clone()
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

    /// 设置所有策略组通用的持久化 pin。
    pub async fn set_group_pin(&self, group: &str, node: &str, source: PinSource) -> bool {
        if node.is_empty() {
            return self.clear_group_pin(group).await;
        }
        let _commit = self.group_pin_lock.lock().await;
        let (selector, strategy) = {
            let groups = self.groups.load();
            let Some(selector) = groups.get(group) else {
                return false;
            };
            if !selector.members().iter().any(|member| member == node) {
                return false;
            }
            (selector.clone(), selector.plan().choose)
        };
        let previous_pin = selector.current_pin();
        let previous_pick = selector.last_pick();
        let pin = selector.set_pin(node.to_string(), source);
        if let Some(store) = &self.store {
            if let Err(error) = store
                .write_batch(&[
                    BatchOp::PutGroupPin(
                        group.to_string(),
                        GroupPinBlob {
                            node: pin.node.clone(),
                            strategy: group_strategy_name(strategy).to_string(),
                            generation: pin.generation,
                            created_at_ms: pin.created_at_ms,
                            source: pin.source.as_str().to_string(),
                        },
                    ),
                    BatchOp::Delete(GROUP_MANUAL.name(), group.to_string()),
                ])
                .await
            {
                selector.restore_pin_after_failed_commit(previous_pin, previous_pick);
                tracing::error!(
                    target: "group::pin",
                    group,
                    node,
                    error = %error,
                    "failed to persist group pin; runtime state rolled back"
                );
                return false;
            }
        }
        self.node_revision.fetch_add(1, Ordering::Release);
        true
    }

    /// 兼容旧内部调用，来源按 Clash API 处理。
    pub async fn set_group_manual(&self, group: &str, node: &str) {
        let _ = self.set_group_pin(group, node, PinSource::ClashApi).await;
    }

    pub async fn clear_group_pin(&self, group: &str) -> bool {
        let _commit = self.group_pin_lock.lock().await;
        let selector = {
            let groups = self.groups.load();
            let Some(selector) = groups.get(group) else {
                return false;
            };
            selector.clone()
        };
        if let Some(store) = &self.store {
            if let Err(error) = store
                .write_batch(&[
                    BatchOp::Delete(GROUP_PIN.name(), group.to_string()),
                    BatchOp::Delete(GROUP_MANUAL.name(), group.to_string()),
                ])
                .await
            {
                tracing::error!(
                    target: "group::pin",
                    group,
                    error = %error,
                    "failed to delete persisted group pin; runtime state kept"
                );
                return false;
            }
        }
        let existed = selector.clear_pin().is_some();
        if existed {
            self.node_revision.fetch_add(1, Ordering::Release);
        }
        true
    }

    /// 完成一次手动 Clash 组测速，并在世代仍一致时解除自动策略 pin。
    pub async fn complete_group_manual_probe(
        &self,
        group: &str,
        token: ManualProbeToken,
        any_success: bool,
    ) -> bool {
        let _commit = self.group_pin_lock.lock().await;
        let Some(selector) = self.groups.load().get(group).cloned() else {
            return false;
        };
        let previous_pin = selector.current_pin();
        let previous_pick = selector.last_pick();
        let released = selector.complete_manual_probe(token, any_success);
        if !released {
            return false;
        }
        if let Some(store) = &self.store {
            if let Err(error) = store
                .write_batch(&[
                    BatchOp::Delete(GROUP_PIN.name(), group.to_string()),
                    BatchOp::Delete(GROUP_MANUAL.name(), group.to_string()),
                ])
                .await
            {
                selector.restore_pin_after_failed_commit(previous_pin, previous_pick);
                tracing::error!(
                    target: "group::pin",
                    group,
                    error = %error,
                    "failed to persist probe unlock; group pin restored"
                );
                return false;
            }
        }
        self.node_revision.fetch_add(1, Ordering::Release);
        true
    }

    /// 优雅停止：把 Smart writer 的内存数据 flush 到磁盘。
    pub async fn shutdown(&self) {
        self.connections.shutdown().await;
        self.smart.shutdown().await;
        self.resolver.flush_to_store().await;
        if let Some(store) = &self.store {
            let _ = store.checkpoint().await;
        }
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.load().keys().cloned().collect()
    }

    /// 当前控制面选择链，顺序与连接表一致：实际节点、下级节点组、上层分流组。
    pub fn current_group_chain(&self, group: &str) -> GroupChain {
        let groups = self.groups.load();
        let mut outward = SmallVec::<[String; 4]>::new();
        let mut current = group.to_string();
        let mut visited = BTreeSet::new();
        for _ in 0..GROUP_MAX_DEPTH {
            if !visited.insert(current.clone()) {
                return smallvec!["BLOCK".to_string()];
            }
            let Some(selector) = groups.get(&current) else {
                outward.push(current);
                outward.reverse();
                return outward;
            };
            outward.push(current);
            let mut members = selector.filtered_members(|member| self.member_protocol(member));
            members.retain(|member| feed_member_name(member).is_none());
            if selector.plan().max_members > 0 && members.len() > selector.plan().max_members {
                members.truncate(selector.plan().max_members);
            }
            let next = selector
                .last_pick()
                .filter(|member| members.contains(member))
                .or_else(|| {
                    (!selector.plan().default_selected.is_empty()
                        && members.contains(&selector.plan().default_selected))
                    .then(|| selector.plan().default_selected.clone())
                })
                .or_else(|| members.first().cloned())
                .unwrap_or_else(|| selector.plan().empty_fallback.clone());
            current = match next.to_ascii_uppercase().as_str() {
                "REJECT" => "BLOCK".to_string(),
                _ => next,
            };
        }
        smallvec!["BLOCK".to_string()]
    }

    /// 递归展开组的实际叶子 outbound，供 Clash 组测速与控制面检查使用。
    pub fn group_leaf_members(&self, group: &str) -> Vec<String> {
        fn expand(
            runtime: &Runtime,
            group_name: &str,
            visiting: &mut BTreeSet<String>,
            depth: usize,
            leaves: &mut Vec<String>,
        ) {
            if depth >= GROUP_MAX_DEPTH || !visiting.insert(group_name.to_string()) {
                return;
            }
            if !runtime.groups.load().contains_key(group_name) {
                visiting.remove(group_name);
                return;
            }
            let members = runtime.group_visible_members(group_name);
            for member in members {
                if runtime.groups.load().contains_key(&member) {
                    expand(runtime, &member, visiting, depth + 1, leaves);
                } else if runtime.outbounds.read().get(&member).is_some()
                    && !leaves.contains(&member)
                {
                    leaves.push(member);
                }
            }
            visiting.remove(group_name);
        }

        let mut leaves = Vec::new();
        expand(self, group, &mut BTreeSet::new(), 0, &mut leaves);
        leaves
    }

    /// 控制面可见的直接成员。隐藏未展开 provider 占位符，并在空组或
    /// `min-members` 不满足时只暴露实际会执行的 empty-fallback。
    pub fn group_visible_members(&self, group: &str) -> Vec<String> {
        let Some(selector) = self.groups.load().get(group).cloned() else {
            return Vec::new();
        };
        let mut members = selector.filtered_members(|member| self.member_protocol(member));
        members.retain(|member| {
            feed_member_name(member).is_none()
                && (self.groups.load().contains_key(member)
                    || self.outbounds.read().get(member).is_some())
        });
        if selector.plan().max_members > 0 && members.len() > selector.plan().max_members {
            members.truncate(selector.plan().max_members);
        }
        if members.len() < selector.plan().min_members.max(1) {
            return vec![selector.plan().empty_fallback.clone()];
        }
        members
    }

    pub fn outbound_names(&self) -> Vec<String> {
        self.outbounds
            .read()
            .names()
            .map(|s| s.to_string())
            .collect()
    }

    pub fn node_provider(&self, name: &str) -> Option<String> {
        self.node_info
            .read()
            .get(name)
            .and_then(|node| node.provider.clone())
    }

    pub fn node_udp_enabled(&self, name: &str) -> Option<bool> {
        self.node_info.read().get(name).map(|node| node.udp)
    }

    /// Monotonic revision of the activated node and expanded group graph.
    ///
    /// Control-plane caches use this value so a provider refresh becomes
    /// visible immediately instead of waiting for a time-based cache expiry.
    pub fn node_revision(&self) -> u64 {
        self.node_revision.load(Ordering::Acquire)
    }

    /// Inspect the node, outbound and expanded group state while provider
    /// activation is paused.
    ///
    /// Control-plane code uses this for composite snapshots that read more
    /// than one runtime map. The callback must remain read-only.
    pub fn inspect_node_state<R>(&self, inspect: impl FnOnce() -> R) -> R {
        let _guard = self.node_update_lock.lock();
        inspect()
    }

    /// Snapshot every currently activated static and provider node.
    pub fn node_snapshots(&self) -> Vec<RuntimeNodeSnapshot> {
        self.node_info
            .read()
            .values()
            .map(|info| RuntimeNodeSnapshot {
                provider: info.provider.clone(),
                node: info.node.clone(),
            })
            .collect()
    }

    /// Snapshot the currently activated nodes owned by one provider.
    pub fn nodes_in_provider(&self, provider: &str) -> Vec<RuntimeNodeSnapshot> {
        self.node_info
            .read()
            .values()
            .filter(|info| info.provider.as_deref() == Some(provider))
            .map(|info| RuntimeNodeSnapshot {
                provider: info.provider.clone(),
                node: info.node.clone(),
            })
            .collect()
    }

    /// 把订阅刷新得到的最新节点列表注入到 outbound registry，
    /// 同时把 group.members 中的 `feed:<name>` 占位符替换为真实节点名集合。
    pub fn apply_feed_nodes(
        &self,
        feed_name: &str,
        nodes: Vec<core_config::node_uri::ParsedNode>,
    ) -> Result<(), RuntimeError> {
        if !self.plan.feeds.contains_key(feed_name) {
            return Err(RuntimeError::OutboundConfig(format!(
                "unknown feed `{feed_name}`"
            )));
        }
        // Every provider has its own refresh task. Serialize activation so the
        // cross-provider name check and the outbound, node and group commits
        // form one transaction instead of racing between provider tasks.
        let _update_guard = self.node_update_lock.lock();

        let static_nodes: BTreeSet<String> =
            self.plan.nodes.iter().map(|n| n.name.clone()).collect();
        let group_names: BTreeSet<String> = self.plan.groups.keys().cloned().collect();
        let mut incoming_names = BTreeSet::new();
        let current_info = self.node_info.read();
        for node in &nodes {
            let name = node.name.trim();
            if name.is_empty() {
                return Err(RuntimeError::OutboundConfig(format!(
                    "feed `{feed_name}` contains an empty node name"
                )));
            }
            if !incoming_names.insert(name.to_string()) {
                return Err(RuntimeError::OutboundConfig(format!(
                    "feed `{feed_name}` contains duplicate node name `{name}`"
                )));
            }
            if static_nodes.contains(name) {
                return Err(RuntimeError::OutboundConfig(format!(
                    "feed `{feed_name}` node `{name}` conflicts with a static node"
                )));
            }
            if group_names.contains(name)
                || matches!(
                    name.to_ascii_uppercase().as_str(),
                    "DIRECT" | "BLOCK" | "REJECT" | "GLOBAL"
                )
            {
                return Err(RuntimeError::OutboundConfig(format!(
                    "feed `{feed_name}` node `{name}` conflicts with a group or reserved Clash name"
                )));
            }
            if let Some(owner) = current_info
                .get(name)
                .and_then(|info| info.provider.as_deref())
                .filter(|owner| *owner != feed_name)
            {
                return Err(RuntimeError::OutboundConfig(format!(
                    "feed `{feed_name}` node `{name}` is already owned by feed `{owner}`"
                )));
            }
        }
        drop(current_info);

        // 先在锁外完成整批构建。任一节点无效时整批拒绝，旧 provider 快照保持不变，
        // 不会出现先删除旧节点、再因半途错误留下残缺 registry 的状态。
        let built_outbounds = nodes
            .iter()
            .map(|node| {
                core_outbound::registry::build_outbound(node).map_err(|error| {
                    RuntimeError::OutboundConfig(format!(
                        "feed `{feed_name}` node `{}`: {error}",
                        node.name
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut new_names: Vec<String> = Vec::with_capacity(nodes.len());
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
            for (n, ob) in nodes.iter().zip(built_outbounds) {
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
        let mut groups = (*self.groups.load_full()).clone();
        let mut updated_groups = 0usize;
        let mut updated_selectors = Vec::new();
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
                let (old_options, old_pin) = groups
                    .get(&name)
                    .map(|g| (g.options(), g.current_pin()))
                    .unwrap_or_default();
                let mut updated = base_plan.clone();
                updated.members = new_members;
                let selector = Arc::new(crate::group_selector::GroupSelector::with_options(
                    updated.clone(),
                    old_options,
                ));
                if let Some(pin) = old_pin {
                    // provider 暂时移除固定节点时仍保存用户意图，之后节点重新
                    // 出现即可自动恢复。
                    selector.restore_pin(pin);
                }
                groups.insert(name.clone(), selector.clone());
                updated_selectors.push(selector);
                updated_groups += 1;
            }
        }
        self.groups.store(Arc::new(groups));
        if let Some(tester) = self.urltest.read().clone() {
            tester.remove_nodes(removed_names.iter().map(String::as_str));
            for selector in updated_selectors {
                // 丢弃旧成员快照。活跃组的下一次真实选路会用新 selector
                // 立即重建计划，闲置组保持零后台开销。
                tester.remove_group_schedule(selector.name());
            }
        }
        self.node_revision.fetch_add(1, Ordering::Release);
        tracing::info!(
            target: "feeds",
            feed = feed_name,
            registered = new_names.len(),
            removed = removed_names.len(),
            groups = updated_groups,
            "feed nodes applied to runtime"
        );
        Ok(())
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
            ruleset: Default::default(),
            protocol: None,
        };
        self.pick_outbound_for_context(ctx)
    }

    pub fn pick_outbound_for_context(&self, ctx: FlowContext) -> RoutePick {
        self.metrics.inc_route();
        // Clash `/configs` mode：rule 走规则；global 强制 route.final 组；direct 强制 DIRECT。
        // 未接线前 dashboard 改 mode 是假热改；这里让 mode 真正影响选路。
        let mode = self.mutable.read().mode.clone();
        let route = match mode.to_ascii_lowercase().as_str() {
            "direct" => DetailedRouteDecision {
                decision: RouteDecision::Direct,
                matcher: "mode",
                hit: RouteRuleHit {
                    index: None,
                    rule: "MODE".into(),
                    payload: "direct".into(),
                    source: "mode:direct".into(),
                    action: "DIRECT".into(),
                    no_resolve: false,
                    no_log: false,
                    no_track: false,
                },
            },
            "global" => {
                let decision = global_mode_decision(&self.plan.route.r#final);
                DetailedRouteDecision {
                    hit: RouteRuleHit {
                        index: None,
                        rule: "MODE".into(),
                        payload: "global".into(),
                        source: "mode:global".into(),
                        action: decision_action(&decision),
                        no_resolve: false,
                        no_log: false,
                        no_track: false,
                    },
                    decision,
                    matcher: "mode",
                }
            }
            _ => self.route.decide_detailed(&ctx),
        };
        let DetailedRouteDecision {
            decision,
            matcher: kind,
            hit,
        } = route;
        if !hit.no_log {
            debug!(
                target: "route",
                host = %ctx.host,
                port = ctx.port,
                network = ctx.network.as_str(),
                mode = %mode,
                ?decision,
                kind,
                rule = %hit.rule,
                payload = %hit.payload,
                source = %hit.source,
                "rule hit"
            );
        }

        let resolved = match &decision {
            RouteDecision::Direct => ResolvedGroupPick {
                label: "DIRECT".into(),
                outbound: self.must_get("DIRECT"),
                chain: smallvec!["DIRECT".into()],
            },
            RouteDecision::Block => ResolvedGroupPick {
                label: "BLOCK".into(),
                outbound: self.must_get("BLOCK"),
                chain: smallvec!["BLOCK".into()],
            },
            RouteDecision::Group(name) => self.pick_in_group(name, &ctx),
        };
        RoutePick {
            decision,
            label: resolved.label,
            outbound: resolved.outbound,
            chain: resolved.chain,
            rule: hit.rule,
            rule_payload: hit.payload,
            rule_index: hit.index,
            rule_source: hit.source,
            rule_action: hit.action,
            no_log: hit.no_log,
            no_track: hit.no_track,
        }
    }

    /// Resolve a domain only when ordered route evaluation reaches a
    /// destination-IP matcher. Domain-only plans stay entirely on the hot
    /// in-memory path, while IP-CIDR/GEOIP/ipcidr-MRS get the same deferred
    /// resolution semantics as mihomo.
    async fn resolve_route_destination(&self, ctx: &mut FlowContext) {
        if !self.route.needs_destination_ip(ctx) {
            return;
        }
        match self.resolver.resolve(&ctx.host).await {
            Ok(addresses) => {
                if let Some(ip) = addresses.first().copied() {
                    ctx.ip = Some(ip);
                    trace!(
                        target: "route",
                        host = %ctx.host,
                        %ip,
                        "resolved destination for IP route rules"
                    );
                }
            }
            Err(error) => {
                debug!(
                    target: "route",
                    host = %ctx.host,
                    %error,
                    "destination resolution failed; unresolved IP rules do not match"
                );
            }
        }
    }

    fn pick_in_group(&self, group: &str, ctx: &FlowContext) -> ResolvedGroupPick {
        self.pick_in_group_inner(group, ctx, &mut BTreeSet::new(), 0)
    }

    fn pick_in_group_inner(
        &self,
        group: &str,
        ctx: &FlowContext,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> ResolvedGroupPick {
        if depth >= GROUP_MAX_DEPTH || !visiting.insert(group.to_string()) {
            warn!(target: "route", group, depth, "策略组递归超限或存在循环，阻断流量");
            return self.blocked_group_pick();
        }
        let Some(g) = self.groups.load().get(group).cloned() else {
            visiting.remove(group);
            warn!(target: "route", group, "未知分组，阻断流量避免回退 DIRECT");
            return self.blocked_group_pick();
        };
        let mut meta = crate::group_selector::FlowMeta::for_host(
            ctx.host.clone(),
            ctx.port,
            ctx.network.as_str(),
        );
        meta.dst_ip = ctx.ip;
        let tester = self.urltest.read().clone();
        let pick = g.pick_eligible_with_protocol(
            &meta,
            &self.smart,
            tester.as_ref(),
            |name| self.member_supports_network(name, ctx.network, visiting, depth + 1),
            |name| self.member_protocol(name),
        );
        if let Some(name) = pick {
            if let Some(outbound) = self.outbounds.read().get(&name) {
                visiting.remove(group);
                return ResolvedGroupPick {
                    label: name.clone(),
                    outbound,
                    chain: smallvec![name, group.to_string()],
                };
            }
            if self.groups.load().contains_key(&name) {
                let mut nested = self.pick_in_group_inner(&name, ctx, visiting, depth + 1);
                visiting.remove(group);
                nested.chain.push(group.to_string());
                return nested;
            }
            warn!(target: "route", node = %name, "节点未注册，阻断流量避免回退 DIRECT");
        } else if ctx.network == NetworkKind::Udp {
            // 没有任何 UDP 可用成员时返回组内第一个已注册成员作为错误载体。
            // dial_udp 会在真正拨号前检查 capabilities 并返回 Unsupported，
            // 既不产生流量泄漏，也能保留具体节点名和协议，避免伪装成 BLOCK。
            for member in g.filtered_members(|name| self.member_protocol(name)) {
                if let Some(mut fallback) =
                    self.first_resolvable_member(&member, visiting, depth + 1)
                {
                    visiting.remove(group);
                    fallback.chain.push(group.to_string());
                    return fallback;
                }
            }
        } else if g.has_unresolved_feed_placeholders() {
            warn!(target: "route", group, "订阅节点尚未加载或为空，阻断流量避免回退 DIRECT");
        }
        visiting.remove(group);
        self.empty_group_pick(&g, group)
    }

    fn blocked_group_pick(&self) -> ResolvedGroupPick {
        ResolvedGroupPick {
            label: "BLOCK".into(),
            outbound: self.must_get("BLOCK"),
            chain: smallvec!["BLOCK".into()],
        }
    }

    fn empty_group_pick(&self, group: &GroupSelector, group_name: &str) -> ResolvedGroupPick {
        let configured = group.plan().empty_fallback.as_str();
        let label = match configured.to_ascii_uppercase().as_str() {
            "REJECT" | "BLOCK" => "BLOCK",
            "DIRECT" => "DIRECT",
            _ => configured,
        };
        if let Some(outbound) = self.outbounds.read().get(label) {
            return ResolvedGroupPick {
                label: label.to_string(),
                outbound,
                chain: smallvec![label.to_string(), group_name.to_string()],
            };
        }
        warn!(
            target: "route",
            group = group_name,
            empty_fallback = configured,
            "策略组 empty-fallback 当前不可用，安全回退 BLOCK"
        );
        self.blocked_group_pick()
    }

    fn member_protocol(&self, name: &str) -> String {
        if self.groups.load().contains_key(name) {
            return "group".into();
        }
        self.outbounds
            .read()
            .get(name)
            .map(|outbound| outbound.protocol().to_string())
            .unwrap_or_default()
    }

    fn member_supports_network(
        &self,
        name: &str,
        network: NetworkKind,
        ancestors: &BTreeSet<String>,
        depth: usize,
    ) -> bool {
        if let Some(outbound) = self.outbounds.read().get(name) {
            return network != NetworkKind::Udp || outbound.capabilities().udp;
        }
        self.group_supports_network(name, network, &mut ancestors.clone(), depth)
    }

    fn group_supports_network(
        &self,
        group: &str,
        network: NetworkKind,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> bool {
        if depth >= GROUP_MAX_DEPTH || !visiting.insert(group.to_string()) {
            return false;
        }
        let Some(selector) = self.groups.load().get(group).cloned() else {
            visiting.remove(group);
            return false;
        };
        if network == NetworkKind::Udp && selector.plan().disable_udp {
            visiting.remove(group);
            return false;
        }
        let mut members = selector.filtered_members(|name| self.member_protocol(name));
        if selector.plan().max_members > 0 && members.len() > selector.plan().max_members {
            members.truncate(selector.plan().max_members);
        }
        let required = selector.plan().min_members.max(1);
        let supported = members
            .into_iter()
            .filter(|member| feed_member_name(member).is_none())
            .filter(|member| self.member_supports_network(member, network, visiting, depth + 1))
            .take(required)
            .count()
            >= required;
        visiting.remove(group);
        supported
            || self.fallback_supports_network(selector.plan().empty_fallback.as_str(), network)
    }

    fn fallback_supports_network(&self, fallback: &str, network: NetworkKind) -> bool {
        let fallback = match fallback.to_ascii_uppercase().as_str() {
            "REJECT" => "BLOCK",
            "DIRECT" => "DIRECT",
            "BLOCK" => "BLOCK",
            _ => fallback,
        };
        self.outbounds
            .read()
            .get(fallback)
            .is_some_and(|outbound| network != NetworkKind::Udp || outbound.capabilities().udp)
    }

    fn first_resolvable_member(
        &self,
        member: &str,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> Option<ResolvedGroupPick> {
        if let Some(outbound) = self.outbounds.read().get(member) {
            return Some(ResolvedGroupPick {
                label: member.to_string(),
                outbound,
                chain: smallvec![member.to_string()],
            });
        }
        if depth >= GROUP_MAX_DEPTH || !visiting.insert(member.to_string()) {
            return None;
        }
        let Some(selector) = self.groups.load().get(member).cloned() else {
            visiting.remove(member);
            return None;
        };
        for child in selector.filtered_members(|name| self.member_protocol(name)) {
            if feed_member_name(&child).is_some() {
                continue;
            }
            if let Some(mut resolved) = self.first_resolvable_member(&child, visiting, depth + 1) {
                visiting.remove(member);
                resolved.chain.push(member.to_string());
                return Some(resolved);
            }
        }
        visiting.remove(member);
        None
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
            ruleset: Default::default(),
            protocol: None,
        };
        self.dial_with_context(ctx).await
    }

    pub async fn dial_with_context(&self, mut ctx: FlowContext) -> std::io::Result<DialResult> {
        self.resolve_route_destination(&mut ctx).await;
        let dial_id = core_outbound::next_dial_id();
        let host = ctx.host.clone();
        let port = ctx.port;
        let network = ctx.network;
        let net_str = network.as_str();
        let started = Instant::now();
        trace!(
            target: "dial",
            id = dial_id,
            %host, port, network = net_str,
            "begin",
        );
        let mut attempted = BTreeSet::new();
        let mut last_err: Option<std::io::Error> = None;
        for attempt in 1..=DIAL_MAX_RETRIES {
            let pick = self.pick_outbound_for_context(ctx.clone());
            trace!(
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
                debug!(target: "dial", id = dial_id, attempt, %host, port, outbound = %pick.label, "blocked by rule");
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
            match res {
                Ok(stream) => {
                    trace!(
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
                    self.record_group_dial_success(&pick.chain);
                    let chain = pick.chain.clone();
                    let provider_chains = self.provider_chains_for_chain(&chain);
                    let remote_destination =
                        self.remote_destination_for_outbound(&pick.label, &host, port);
                    let smart_target = self.smart_target_for_chain(&chain, &host);
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
                        rule_index: pick.rule_index,
                        rule_source: pick.rule_source,
                        rule_action: pick.rule_action,
                        route_ip: ctx.ip,
                        no_log: pick.no_log,
                        no_track: pick.no_track,
                    });
                }
                Err(e) => {
                    let retry = should_retry_dial(&pick, &e, network, attempt);
                    if retry {
                        debug!(
                            target: "dial",
                            id = dial_id,
                            attempt,
                            %host, port,
                            outbound = %pick.label,
                            dial_ms,
                            total_ms = elapsed.as_millis() as u64,
                            error = %e,
                            "attempt failed",
                        );
                    } else {
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
                    }
                    if pick.label != "DIRECT" && pick.label != "BLOCK" {
                        self.smart.record_failure(&pick.label, e.to_string());
                    }
                    self.record_group_dial_failure(&pick.chain, &e.to_string());
                    if !retry {
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
        trace!(
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
            Ok(_) => trace!(
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
            rule_index: None,
            rule_source: "TUN-BYPASS".into(),
            rule_action: "DIRECT".into(),
            route_ip: ctx.ip,
            no_log: false,
            no_track: false,
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
            ruleset: Default::default(),
            protocol: None,
        };
        self.dial_udp_with_context(ctx).await
    }

    pub async fn dial_udp_with_context(
        &self,
        mut ctx: FlowContext,
    ) -> std::io::Result<UdpDialResult> {
        self.resolve_route_destination(&mut ctx).await;
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
                    let chain = pick.chain.clone();
                    let provider_chains = self.provider_chains_for_chain(&chain);
                    let remote_destination =
                        self.remote_destination_for_outbound(&pick.label, &host, port);
                    let smart_target = self.smart_target_for_chain(&chain, &host);
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
                    self.record_group_dial_success(&pick.chain);
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
                        rule_index: pick.rule_index,
                        rule_source: pick.rule_source,
                        rule_action: pick.rule_action,
                        route_ip: ctx.ip,
                        no_log: pick.no_log,
                        no_track: pick.no_track,
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
                    self.record_group_dial_failure(&pick.chain, &e.to_string());
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
            rule_index: None,
            rule_source: "TUN-BYPASS".into(),
            rule_action: "DIRECT".into(),
            route_ip: ctx.ip,
            no_log: false,
            no_track: false,
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

    fn remote_destination_for_outbound(&self, label: &str, host: &str, _port: u16) -> String {
        if label != "DIRECT" && label != "BLOCK" {
            if let Some(info) = self.node_info.read().get(label) {
                if !info.remote_destination.is_empty() {
                    return info.remote_destination.clone();
                }
            }
        }
        host.trim_matches(['[', ']']).to_string()
    }

    fn record_group_dial_success(&self, chain: &[String]) {
        for group_name in chain.iter().skip(1) {
            if let Some(group) = self.groups.load().get(group_name).cloned() {
                group.on_dial_success();
            }
        }
    }

    fn record_group_dial_failure(&self, chain: &[String], error: &str) {
        let tester = self.urltest.read().clone();
        for pair in chain.windows(2) {
            let member = &pair[0];
            let group_name = &pair[1];
            let Some(group) = self.groups.load().get(group_name).cloned() else {
                continue;
            };
            if !matches!(group.plan().choose, ChooseStrategy::Manual)
                && let Some(tester) = tester.as_ref()
            {
                group.mark_member_failed(member, tester, error);
            }
            let tester_for_invalidate = tester.clone();
            let group_for_invalidate = group_name.clone();
            group.on_dial_failed(error, move || {
                if let Some(tester) = &tester_for_invalidate {
                    tester.invalidate_fast_pick(&group_for_invalidate);
                }
            });
        }
    }

    fn smart_target_for_chain(&self, chain: &[String], host: &str) -> String {
        let has_smart_group = chain.iter().skip(1).any(|group_name| {
            self.plan
                .groups
                .get(group_name)
                .map(|group| matches!(group.choose, ChooseStrategy::Smart))
                .unwrap_or(false)
        });
        if !has_smart_group {
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

fn group_strategy_name(strategy: ChooseStrategy) -> &'static str {
    match strategy {
        ChooseStrategy::Manual => "manual",
        ChooseStrategy::Smart => "smart",
        ChooseStrategy::Fast => "fast",
        ChooseStrategy::Stable => "stable",
        ChooseStrategy::Spread => "spread",
        ChooseStrategy::Random => "random",
        ChooseStrategy::Weighted => "weighted",
        ChooseStrategy::Chain => "chain",
    }
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

/// Clash `mode=global`：全部流量进 `route.final`（组 / DIRECT / BLOCK）。
fn global_mode_decision(final_target: &str) -> RouteDecision {
    match final_target {
        "direct" | "DIRECT" => RouteDecision::Direct,
        "block" | "BLOCK" | "REJECT" | "reject" => RouteDecision::Block,
        other => RouteDecision::Group(other.to_string()),
    }
}

fn decision_action(decision: &RouteDecision) -> String {
    match decision {
        RouteDecision::Direct => "DIRECT".into(),
        RouteDecision::Block => "REJECT".into(),
        RouteDecision::Group(group) => group.clone(),
    }
}

fn build_chain(decision: &RouteDecision, label: &str) -> GroupChain {
    match decision {
        RouteDecision::Direct => smallvec!["DIRECT".to_string()],
        RouteDecision::Block => smallvec!["BLOCK".to_string()],
        RouteDecision::Group(g) => {
            if label != g {
                // Mihomo 的 Chain 按实际出站到外层策略组排列：
                // [picked-node, group]，Chain::Last() 即第一个实际出站。
                smallvec![label.to_string(), g.clone()]
            } else {
                smallvec![g.clone()]
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
    /// 从实际 outbound 到最外层分流策略组的完整选择链。
    pub chain: GroupChain,
    pub rule: String,
    pub rule_payload: String,
    pub rule_index: Option<usize>,
    pub rule_source: String,
    pub rule_action: String,
    pub no_log: bool,
    pub no_track: bool,
}

struct ResolvedGroupPick {
    label: String,
    outbound: SharedOutbound,
    chain: GroupChain,
}

pub struct DialResult {
    pub stream: core_outbound::adapter::BoxedStream,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
    /// 完整的代理链 —— Clash dashboard 的 connection.chains 顶层字段。
    /// 直连/拦截：`["DIRECT"]` / `["BLOCK"]`；分组遵循 Mihomo 的
    /// `["<picked-node>", "<region-group>", "<policy-group>"]` 顺序。
    pub chain: GroupChain,
    pub provider_chains: Vec<String>,
    pub remote_destination: String,
    pub smart_target: String,
    pub rule: String,
    pub rule_payload: String,
    pub rule_index: Option<usize>,
    pub rule_source: String,
    pub rule_action: String,
    pub route_ip: Option<IpAddr>,
    pub no_log: bool,
    pub no_track: bool,
}

pub struct UdpDialResult {
    pub socket: core_outbound::adapter::BoxedUdp,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
    pub chain: GroupChain,
    pub provider_chains: Vec<String>,
    pub remote_destination: String,
    pub smart_target: String,
    pub rule: String,
    pub rule_payload: String,
    pub rule_index: Option<usize>,
    pub rule_source: String,
    pub rule_action: String,
    pub route_ip: Option<IpAddr>,
    pub no_log: bool,
    pub no_track: bool,
}

fn outbound_fwmark_for_plan(plan: &RuntimePlan) -> u32 {
    if capture_uses_tun_auto_route(&plan.capture) {
        let default = if cfg!(target_os = "android") {
            core_config::model::ANDROID_DEFAULT_TUN_OUTPUT_MARK
        } else {
            core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
        };
        core_config::model::platform_tun_output_mark(
            core_config::model::normalize_auto_redirect_mark(
                plan.capture.tun.auto_redirect_output_mark.as_deref(),
                default,
            )
            // RuntimePlan normally came through validation. A manually-mutated plan
            // must still use the same safe default as CapturePlan instead of
            // silently disabling the loop-prevention mark.
            .unwrap_or(default),
        )
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

struct RuntimeDnsOutboundProvider {
    outbounds: Arc<parking_lot::RwLock<OutboundRegistry>>,
    groups: Arc<ArcSwap<BTreeMap<String, Arc<GroupSelector>>>>,
    smart: Arc<SmartSelector>,
    urltest: Arc<parking_lot::RwLock<Option<Arc<crate::health::UrlTester>>>>,
}

struct RuntimeDnsProxyStream(core_outbound::BoxedStream);

impl tokio::io::AsyncRead for RuntimeDnsProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().0.as_mut().poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for RuntimeDnsProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.get_mut().0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.get_mut().0.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.get_mut().0.as_mut().poll_shutdown(cx)
    }
}

impl RuntimeDnsOutboundProvider {
    fn pick(
        &self,
        outbound: &str,
        host: &str,
        port: u16,
        network: NetworkKind,
    ) -> std::io::Result<ResolvedGroupPick> {
        let normalized = match outbound.to_ascii_uppercase().as_str() {
            "REJECT" => "BLOCK",
            _ => outbound,
        };
        if let Some(adapter) = self.outbounds.read().get(normalized) {
            return Ok(ResolvedGroupPick {
                label: normalized.to_string(),
                outbound: adapter,
                chain: smallvec![normalized.to_string()],
            });
        }
        self.pick_group(normalized, host, port, network, &mut BTreeSet::new(), 0)
    }

    fn pick_group(
        &self,
        group_name: &str,
        host: &str,
        port: u16,
        network: NetworkKind,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> std::io::Result<ResolvedGroupPick> {
        if depth >= GROUP_MAX_DEPTH || !visiting.insert(group_name.to_string()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("DNS 出口策略组 `{group_name}` 存在循环或递归过深"),
            ));
        }
        let Some(group) = self.groups.load().get(group_name).cloned() else {
            visiting.remove(group_name);
            return Err(unknown_dns_outbound(group_name));
        };
        let meta =
            crate::group_selector::FlowMeta::for_host(host.to_string(), port, network.as_str());
        let tester = self.urltest.read().clone();
        let picked = group.pick_eligible_with_protocol(
            &meta,
            &self.smart,
            tester.as_ref(),
            |member| self.member_supports(member, network, visiting, depth + 1),
            |member| self.member_protocol(member),
        );
        if let Some(member) = picked {
            if let Some(adapter) = self.outbounds.read().get(&member) {
                visiting.remove(group_name);
                return Ok(ResolvedGroupPick {
                    label: member.clone(),
                    outbound: adapter,
                    chain: smallvec![member, group_name.to_string()],
                });
            }
            if self.groups.load().contains_key(&member) {
                let mut resolved =
                    self.pick_group(&member, host, port, network, visiting, depth + 1)?;
                visiting.remove(group_name);
                resolved.chain.push(group_name.to_string());
                return Ok(resolved);
            }
        }
        visiting.remove(group_name);
        let fallback = match group.plan().empty_fallback.to_ascii_uppercase().as_str() {
            "REJECT" | "BLOCK" => "BLOCK",
            "DIRECT" => "DIRECT",
            _ => group.plan().empty_fallback.as_str(),
        };
        let adapter = self
            .outbounds
            .read()
            .get(fallback)
            .ok_or_else(|| unknown_dns_outbound(fallback))?;
        Ok(ResolvedGroupPick {
            label: fallback.to_string(),
            outbound: adapter,
            chain: smallvec![fallback.to_string(), group_name.to_string()],
        })
    }

    fn member_protocol(&self, member: &str) -> String {
        if self.groups.load().contains_key(member) {
            return "group".into();
        }
        self.outbounds
            .read()
            .get(member)
            .map(|outbound| outbound.protocol().to_string())
            .unwrap_or_default()
    }

    fn member_supports(
        &self,
        member: &str,
        network: NetworkKind,
        ancestors: &BTreeSet<String>,
        depth: usize,
    ) -> bool {
        if let Some(outbound) = self.outbounds.read().get(member) {
            return network != NetworkKind::Udp || outbound.capabilities().udp;
        }
        self.group_supports(member, network, &mut ancestors.clone(), depth)
    }

    fn group_supports(
        &self,
        group_name: &str,
        network: NetworkKind,
        visiting: &mut BTreeSet<String>,
        depth: usize,
    ) -> bool {
        if depth >= GROUP_MAX_DEPTH || !visiting.insert(group_name.to_string()) {
            return false;
        }
        let Some(group) = self.groups.load().get(group_name).cloned() else {
            visiting.remove(group_name);
            return false;
        };
        if network == NetworkKind::Udp && group.plan().disable_udp {
            visiting.remove(group_name);
            return false;
        }
        let mut members = group.filtered_members(|member| self.member_protocol(member));
        if group.plan().max_members > 0 && members.len() > group.plan().max_members {
            members.truncate(group.plan().max_members);
        }
        let required = group.plan().min_members.max(1);
        let supported = members
            .iter()
            .filter(|member| feed_member_name(member).is_none())
            .filter(|member| self.member_supports(member, network, visiting, depth + 1))
            .take(required)
            .count()
            >= required;
        visiting.remove(group_name);
        supported || self.fallback_supports(group.plan().empty_fallback.as_str(), network)
    }

    fn fallback_supports(&self, fallback: &str, network: NetworkKind) -> bool {
        let fallback = match fallback.to_ascii_uppercase().as_str() {
            "REJECT" => "BLOCK",
            "DIRECT" => "DIRECT",
            "BLOCK" => "BLOCK",
            _ => fallback,
        };
        self.outbounds
            .read()
            .get(fallback)
            .is_some_and(|outbound| network != NetworkKind::Udp || outbound.capabilities().udp)
    }

    fn record_success(&self, pick: &ResolvedGroupPick, elapsed: std::time::Duration) {
        if !matches!(pick.label.as_str(), "DIRECT" | "BLOCK") {
            self.smart.record_success(&pick.label, elapsed);
        }
        for group_name in pick.chain.iter().skip(1) {
            if let Some(group) = self.groups.load().get(group_name) {
                group.on_dial_success();
            }
        }
    }

    fn record_failure(&self, pick: &ResolvedGroupPick, error: &str) {
        if !matches!(pick.label.as_str(), "DIRECT" | "BLOCK") {
            self.smart.record_failure(&pick.label, error.to_string());
        }
        let tester = self.urltest.read().clone();
        for pair in pick.chain.windows(2) {
            let Some(group) = self.groups.load().get(&pair[1]).cloned() else {
                continue;
            };
            if !matches!(group.plan().choose, ChooseStrategy::Manual)
                && let Some(tester) = tester.as_ref()
            {
                group.mark_member_failed(&pair[0], tester, error);
            }
            let tester_for_invalidate = tester.clone();
            let group_name = pair[1].clone();
            group.on_dial_failed(error, move || {
                if let Some(tester) = &tester_for_invalidate {
                    tester.invalidate_fast_pick(&group_name);
                }
            });
        }
    }
}

#[async_trait::async_trait]
impl core_resolver::upstream::outbound::DnsOutboundProvider for RuntimeDnsOutboundProvider {
    async fn dial_tcp(
        &self,
        outbound: &str,
        host: &str,
        port: u16,
    ) -> std::io::Result<core_resolver::upstream::outbound::BoxedDnsProxyStream> {
        let pick = self.pick(outbound, host, port, NetworkKind::Tcp)?;
        let started = Instant::now();
        let stream = pick
            .outbound
            .dial_tcp(DialContext::tcp(host, port).with_id(core_outbound::next_dial_id()))
            .await;
        match stream {
            Ok(stream) => {
                self.record_success(&pick, started.elapsed());
                Ok(Box::pin(RuntimeDnsProxyStream(stream)))
            }
            Err(error) => {
                self.record_failure(&pick, &error.to_string());
                Err(error)
            }
        }
    }

    async fn exchange_udp(
        &self,
        outbound: &str,
        host: &str,
        port: u16,
        request: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let pick = self.pick(outbound, host, port, NetworkKind::Udp)?;
        if !pick.outbound.capabilities().udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "DNS 出口 `{}`/{} 不支持 UDP",
                    pick.label,
                    pick.outbound.protocol()
                ),
            ));
        }
        let started = Instant::now();
        let socket = pick
            .outbound
            .dial_udp(DialContext::udp(host, port).with_id(core_outbound::next_dial_id()))
            .await
            .inspect_err(|error| self.record_failure(&pick, &error.to_string()))?;
        let written = match socket.send_to(request, host, port).await {
            Ok(written) => written,
            Err(error) => {
                self.record_failure(&pick, &error.to_string());
                let _ = socket.close().await;
                return Err(error);
            }
        };
        if written != request.len() {
            let error = std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "DNS 出口 `{outbound}` UDP 仅发送 {written}/{} bytes",
                    request.len()
                ),
            );
            self.record_failure(&pick, &error.to_string());
            let _ = socket.close().await;
            return Err(error);
        }
        let mut response = vec![0u8; 65_535];
        let length = match socket.recv_from(&mut response).await {
            Ok(length) => length,
            Err(error) => {
                self.record_failure(&pick, &error.to_string());
                let _ = socket.close().await;
                return Err(error);
            }
        };
        response.truncate(length);
        let _ = socket.close().await;
        self.record_success(&pick, started.elapsed());
        Ok(response)
    }
}

fn unknown_dns_outbound(outbound: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("DNS 配置引用了不存在的代理出口 `{outbound}`"),
    )
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
    use core_outbound::{
        BoxedStream, BoxedUdp, Capabilities, DialContext, DialResolver, OutboundAdapter,
    };
    use core_resolver::{DnsError, DnsGroup, DnsUpstream, GroupStrategy, QType, ResolverBuilder};

    use super::*;

    #[derive(Debug)]
    struct StaticDnsUpstream {
        ip: IpAddr,
    }

    #[derive(Debug)]
    struct TcpOnlyOutbound;

    #[async_trait]
    impl OutboundAdapter for TcpOnlyOutbound {
        fn name(&self) -> &str {
            "tcp-only"
        }

        fn protocol(&self) -> &'static str {
            "test-tcp-only"
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: true,
                udp: false,
                ipv6: true,
                multiplex: false,
            }
        }

        async fn dial_tcp(&self, _ctx: DialContext) -> std::io::Result<BoxedStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "test outbound",
            ))
        }

        async fn dial_udp(&self, _ctx: DialContext) -> std::io::Result<BoxedUdp> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test outbound has no UDP relay",
            ))
        }
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
        let store = core_store::Store::open(&path).await.unwrap();
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
            .await
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
        let runtime = Runtime::build_with_store(plan, Some(store)).await.unwrap();

        let ips = runtime
            .resolver
            .resolve_qtype("persist-runtime.example.invalid", QType::A)
            .await
            .unwrap();

        assert_eq!(ips, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn group_pin_survives_runtime_and_store_reopen() {
        const CONFIG: &str = r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "direct://0.0.0.0:0#node-a"
  - "direct://0.0.0.0:0#node-b"
groups:
  main:
    choose: fast
    use: [nodes]
route:
  preset: global
  final: main
"#;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let store = core_store::Store::open(&path).await.unwrap();
        let runtime = Runtime::build_with_store(load_plan(CONFIG), Some(store.clone()))
            .await
            .unwrap();

        assert!(
            runtime
                .set_group_pin("main", "node-b", PinSource::NativeApi)
                .await
        );
        let written = store
            .get_json::<GroupPinBlob>(GROUP_PIN, "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written.node, "node-b");
        assert_eq!(written.strategy, "fast");
        assert_eq!(written.source, "native_api");
        let generation = written.generation;
        drop(runtime);
        drop(store);

        let reopened = core_store::Store::open(&path).await.unwrap();
        let restored = Runtime::build_with_store(load_plan(CONFIG), Some(reopened))
            .await
            .unwrap();
        let pin = restored
            .groups
            .load()
            .get("main")
            .unwrap()
            .current_pin()
            .unwrap();
        assert_eq!(pin.node, "node-b");
        assert_eq!(pin.generation, generation);
        assert_eq!(pin.source, PinSource::Restored);
        assert_eq!(
            restored
                .pick_outbound("example.com", 443, NetworkKind::Tcp)
                .label,
            "node-b"
        );
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
        plan.capture.method = core_config::model::CaptureMethod::VirtualNic;
        plan.capture.tun.auto_route = true;
        plan.capture.tun.auto_redirect = true;

        assert_eq!(outbound_fwmark_for_plan(&plan), 0x2024);
    }

    #[test]
    fn runtime_normalizes_explicit_zero_auto_redirect_output_mark() {
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
        plan.capture.method = core_config::model::CaptureMethod::VirtualNic;
        plan.capture.tun.auto_route = true;
        plan.capture.tun.auto_redirect = true;
        plan.capture.tun.auto_redirect_output_mark = Some("0".into());

        assert_eq!(outbound_fwmark_for_plan(&plan), 0x2024);
        plan.capture.on = false;
        assert_eq!(outbound_fwmark_for_plan(&plan), 0);
    }

    #[test]
    fn runtime_ignores_dormant_explicit_output_mark() {
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
        plan.capture.tun.auto_redirect_output_mark = Some("0x5151".into());

        assert_eq!(outbound_fwmark_for_plan(&plan), 0);
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
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .apply_feed_nodes(
                "provider-a",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-a/node-1",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.10",
                    10001,
                )],
            )
            .unwrap();

        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        let chain = pick.chain.clone();

        assert_eq!(pick.label, "provider-a/node-1");
        assert_eq!(
            chain.as_slice(),
            vec!["provider-a/node-1".to_string(), "main".to_string()]
        );
        assert_eq!(
            runtime.provider_chains_for_chain(&chain),
            vec!["provider-a".to_string()]
        );
        assert_eq!(
            runtime.remote_destination_for_outbound(&pick.label, "www.google.com", 443),
            "203.0.113.10"
        );
        let snapshots = runtime.nodes_in_provider("provider-a");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].provider.as_deref(), Some("provider-a"));
        assert_eq!(snapshots[0].node.name, "provider-a/node-1");
        assert_eq!(snapshots[0].node.host, "203.0.113.10");
        assert_eq!(runtime.node_revision(), 1);
    }

    #[test]
    fn nested_policy_and_region_groups_resolve_to_a_full_route_chain() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - {name: HK-1, protocol: direct, address: "127.0.0.1:1"}
  - {name: US-1, protocol: direct, address: "127.0.0.1:1"}
groups:
  香港节点:
    choose: smart
    proxies: [HK-1]
  美国节点:
    choose: smart
    proxies: [US-1]
  节点选择:
    choose: manual
    proxies: [香港节点, 美国节点]
    default-selected: 香港节点
route:
  preset: global
  final: 节点选择
"#,
        );
        let runtime = Runtime::build(plan).unwrap();

        let pick = runtime.pick_outbound("www.example.com", 443, NetworkKind::Tcp);

        assert_eq!(pick.label, "HK-1");
        assert_eq!(
            pick.chain.as_slice(),
            &[
                "HK-1".to_string(),
                "香港节点".to_string(),
                "节点选择".to_string()
            ]
        );
        assert_eq!(runtime.current_group_chain("节点选择"), pick.chain);
    }

    #[test]
    fn nested_empty_group_keeps_the_full_chain_and_leaf_fallback() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - {name: HK-1, protocol: direct, address: "127.0.0.1:1"}
groups:
  美国节点:
    choose: smart
    proxies: [HK-1]
    filter: "^US-"
    empty-fallback: DIRECT
  节点选择:
    choose: manual
    proxies: [美国节点]
route:
  preset: global
  final: 节点选择
"#,
        );
        let runtime = Runtime::build(plan).unwrap();

        let pick = runtime.pick_outbound("www.example.com", 443, NetworkKind::Tcp);

        assert_eq!(pick.label, "DIRECT");
        assert_eq!(
            pick.chain.as_slice(),
            &[
                "DIRECT".to_string(),
                "美国节点".to_string(),
                "节点选择".to_string()
            ]
        );
        assert_eq!(
            runtime.group_leaf_members("节点选择"),
            vec!["DIRECT".to_string()]
        );
    }

    #[tokio::test]
    async fn provider_refresh_preserves_pin_across_temporary_node_removal() {
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
    choose: fast
    use: [provider-a]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        let node = |name: &str| {
            core_config::node_uri::ParsedNode::new(
                name,
                core_config::node_uri::NodeProtocol::Direct,
                "203.0.113.10",
                443,
            )
        };
        runtime
            .apply_feed_nodes("provider-a", vec![node("node-a"), node("node-b")])
            .unwrap();
        assert!(
            runtime
                .set_group_pin("main", "node-b", PinSource::ClashApi)
                .await
        );
        assert_eq!(
            runtime
                .pick_outbound("example.com", 443, NetworkKind::Tcp)
                .label,
            "node-b"
        );

        runtime
            .apply_feed_nodes("provider-a", vec![node("node-a")])
            .unwrap();
        assert_eq!(
            runtime
                .groups
                .load()
                .get("main")
                .unwrap()
                .current_manual()
                .as_deref(),
            Some("node-b")
        );
        assert_eq!(
            runtime
                .pick_outbound("example.com", 443, NetworkKind::Tcp)
                .label,
            "node-a"
        );

        runtime
            .apply_feed_nodes("provider-a", vec![node("node-a"), node("node-b")])
            .unwrap();
        assert_eq!(
            runtime
                .pick_outbound("example.com", 443, NetworkKind::Tcp)
                .label,
            "node-b"
        );
    }

    #[test]
    fn provider_xhttp_node_with_legacy_insecure_tls_activates_atomically() {
        if !core_outbound::registry::protocol_component_enabled(
            &core_config::node_uri::NodeProtocol::Vless,
        ) {
            return;
        }
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
        let runtime = Runtime::build(plan).unwrap();
        let mut node = core_config::node_uri::ParsedNode::new(
            "Provider-XHTTP",
            core_config::node_uri::NodeProtocol::Vless,
            "edge.example.com",
            443,
        );
        node.uuid = Some("2dd61d93-75d8-4da4-ac0e-6aece7eac365".into());
        node.tls = true;
        node.transport = "xhttp".into();
        node.params.insert("skip-cert-verify".into(), "true".into());
        node.params.insert("allowInsecure".into(), "1".into());

        runtime.apply_feed_nodes("provider-a", vec![node]).unwrap();

        assert_eq!(runtime.node_revision(), 1);
        assert_eq!(runtime.nodes_in_provider("provider-a").len(), 1);
        assert!(
            runtime
                .outbound_names()
                .contains(&"Provider-XHTTP".to_string())
        );
        assert_eq!(
            runtime
                .pick_outbound("www.example.com", 443, NetworkKind::Tcp)
                .label,
            "Provider-XHTTP"
        );
    }

    #[test]
    fn provider_reality_link_with_mihomo_tls_metadata_activates_atomically() {
        if !core_outbound::registry::protocol_component_enabled(
            &core_config::node_uri::NodeProtocol::Vless,
        ) {
            return;
        }
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  primary: "https://example.invalid/subscription"
groups:
  main:
    choose: manual
    use: [primary]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        let node = core_config::node_uri::parse_uri(
            "vless://11111111-1111-1111-1111-111111111111@192.0.2.10:443?security=reality&sni=cover.example&fp=chrome&pbk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&sid=0123456789abcdef&alpn=h2%2Chttp%2F1.1&allowInsecure=1&skip-cert-verify=true&ech=true&echConfigList=ignored#%5B%E8%AE%A2%E9%98%85%5D%20HK-D-1-0.2x",
        )
        .unwrap();

        runtime.apply_feed_nodes("primary", vec![node]).unwrap();

        assert_eq!(runtime.node_revision(), 1);
        assert_eq!(runtime.nodes_in_provider("primary").len(), 1);
        assert!(
            runtime
                .outbound_names()
                .contains(&"[订阅] HK-D-1-0.2x".to_string())
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
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .apply_feed_nodes(
                "provider-a",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-a/node-1",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.10",
                    10001,
                )],
            )
            .unwrap();
        runtime
            .apply_feed_nodes(
                "provider-b",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-b/node-1",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.20",
                    10002,
                )],
            )
            .unwrap();

        let groups = runtime.groups.load();
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
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .apply_feed_nodes(
                "provider-a",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-a/old",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.10",
                    10001,
                )],
            )
            .unwrap();
        runtime
            .apply_feed_nodes(
                "provider-a",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-a/new",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.20",
                    10002,
                )],
            )
            .unwrap();

        let names = runtime.outbound_names();
        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);

        assert!(!names.contains(&"provider-a/old".to_string()));
        assert!(names.contains(&"provider-a/new".to_string()));
        assert_eq!(pick.label, "provider-a/new");
        let snapshots = runtime.nodes_in_provider("provider-a");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].node.name, "provider-a/new");
        assert_eq!(runtime.node_revision(), 2);
    }

    #[test]
    fn feed_update_rejects_names_that_cannot_be_represented_in_clash_api() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
feeds:
  provider-a: "https://example.invalid/sub.yaml"
nodes:
  - name: local-node
    protocol: direct
    address: 127.0.0.1:1
groups:
  main:
    choose: manual
    use: [provider-a, nodes]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();

        for name in ["main", "GLOBAL", "BLOCK", "local-node"] {
            let error = runtime
                .apply_feed_nodes(
                    "provider-a",
                    vec![core_config::node_uri::ParsedNode::new(
                        name,
                        core_config::node_uri::NodeProtocol::Direct,
                        "203.0.113.10",
                        10001,
                    )],
                )
                .unwrap_err()
                .to_string();
            assert!(error.contains(name), "error={error}");
        }

        assert_eq!(runtime.node_revision(), 0);
        assert!(runtime.nodes_in_provider("provider-a").is_empty());
        assert_eq!(
            runtime.groups.load().get("main").unwrap().members(),
            vec!["feed:provider-a".to_string(), "local-node".to_string()]
        );
    }

    #[test]
    fn invalid_xhttp_feed_update_is_rejected_atomically() {
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
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .apply_feed_nodes(
                "provider-a",
                vec![core_config::node_uri::ParsedNode::new(
                    "provider-a/old",
                    core_config::node_uri::NodeProtocol::Direct,
                    "203.0.113.10",
                    10001,
                )],
            )
            .unwrap();

        let mut invalid = core_config::node_uri::ParsedNode::new(
            "provider-a/bad",
            core_config::node_uri::NodeProtocol::Vless,
            "origin.example",
            443,
        );
        invalid.transport = "xhttp".into();
        invalid.params.insert("mode".into(), "not-a-mode".into());
        let error = runtime
            .apply_feed_nodes("provider-a", vec![invalid])
            .unwrap_err()
            .to_string();
        assert!(error.contains("provider-a/bad"), "error={error}");
        assert!(
            error.contains("unsupported xhttp mode")
                || error.contains("protocol `vless` is not compiled in"),
            "error={error}"
        );

        let names = runtime.outbound_names();
        assert!(names.contains(&"provider-a/old".to_string()));
        assert!(!names.contains(&"provider-a/bad".to_string()));
        assert_eq!(
            runtime.groups.load().get("main").unwrap().members(),
            vec!["provider-a/old".to_string()]
        );
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
        let runtime = Runtime::build(plan).unwrap();

        let pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);

        assert_eq!(pick.label, "BLOCK");
    }

    #[test]
    fn process_finder_enabled_by_default_for_strict_mode() {
        // 与 mihomo 一致：未配置时默认 strict，按规则遍历惰性触发 finder。
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        assert!(
            runtime.process_finder.is_some(),
            "find-process-mode 默认 strict → finder 必须可用"
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
        let runtime = Runtime::build(plan).unwrap();
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
        let runtime = Runtime::build(plan).unwrap();
        assert!(
            runtime.process_finder.is_some(),
            "find-process-mode: strict → finder 必须构建"
        );
    }

    #[test]
    fn mutable_mode_direct_bypasses_rules() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes: ["direct://0.0.0.0:0#HK"]
groups:
  main:
    choose: manual
    use: [nodes]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        // rule 模式应进 main 组。
        let rule_pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        assert_eq!(rule_pick.label, "HK");

        runtime.mutable.write().mode = "direct".into();
        let direct_pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        assert_eq!(direct_pick.label, "DIRECT");
        assert_eq!(direct_pick.rule, "MODE");
    }
    #[test]
    fn mutable_mode_global_forces_final_group() {
        let plan = load_plan(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes: ["direct://0.0.0.0:0#HK"]
groups:
  main:
    choose: manual
    use: [nodes]
route:
  preset: direct
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        // direct preset 默认应 DIRECT。
        let rule_pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        assert_eq!(rule_pick.label, "DIRECT");

        runtime.mutable.write().mode = "global".into();
        let global_pick = runtime.pick_outbound("www.google.com", 443, NetworkKind::Tcp);
        assert_eq!(global_pick.label, "HK");
        assert_eq!(global_pick.rule, "MODE");
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
        let runtime = Runtime::build(plan).unwrap();

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
  - name: tcp-only
    protocol: direct
    address: 127.0.0.1:1
    network:
      udp: false
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
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .outbounds
            .write()
            .insert("tcp-only", Arc::new(TcpOnlyOutbound));

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
  - name: tcp-only
    protocol: direct
    address: 127.0.0.1:1
    network:
      udp: false
groups:
  main:
    choose: manual
    use: [tcp-only]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();
        runtime
            .outbounds
            .write()
            .insert("tcp-only", Arc::new(TcpOnlyOutbound));

        let err = match runtime.dial_udp("8.8.8.8", 53).await {
            Ok(_) => panic!("UDP dial unexpectedly succeeded through tcp-only outbound"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        let err_s = err.to_string();
        assert!(err_s.contains("tcp-only"));
        assert!(err_s.contains("test-tcp-only"));
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
  - "direct://0.0.0.0:0#smart-node"
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: global
  final: main
"#,
        );
        let runtime = Runtime::build(plan).unwrap();

        let pick = runtime.pick_outbound("Example.COM.", 443, NetworkKind::Tcp);

        assert!(matches!(pick.decision, RouteDecision::Group(ref group) if group == "main"));
        assert_eq!(
            runtime.smart_target_for_chain(&pick.chain, "Example.COM."),
            "Example.COM"
        );
    }

    #[tokio::test]
    async fn runtime_ruleset_step_is_evaluated_before_preset_fallback() {
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
  - "direct://0.0.0.0:0#node-a"
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
        let runtime = Runtime::build_with(plan, None, Some(idx)).await.unwrap();

        let pick = runtime.pick_outbound("api.openai.com", 443, NetworkKind::Tcp);

        assert!(matches!(pick.decision, RouteDecision::Group(ref group) if group == "ai"));
        assert_eq!(pick.rule, "RULE-SET");
        assert_eq!(pick.rule_payload, "openai");
        assert_eq!(pick.rule_source, "set:openai -> ai");
    }
}
