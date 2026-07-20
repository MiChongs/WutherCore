//! CaptureSupervisor —— 把 [`CaptureEngine`] 与 [`Runtime`] 串起来。
//!
//! 流程：
//! 1. 由配置生成 [`CapturePlan`]；
//! 2. 平台 `build_engine` 创建 engine；
//! 3. spawn 一条事件协程：每一个 [`CaptureEvent`] →
//!    a) 路由白/黑名单（`route_address(_set)` / `route_exclude_address(_set)`）→
//!    b) `loopback_address` 跳过 → c) NAT 写入（5-tuple 索引 + 可选 EIM）→
//!    d) 调用 `runtime.dial`（fake-host / fake-IP 还原）；
//! 4. （可选）启动 fake-dns server；
//! 5. 周期性 NAT / EIM purge（GC）。
//!
//! 通过 `CaptureSupervisor::with_ip_set_provider` 注入 `IpSetProvider`
//! 后，supervisor 会按集合名查询 ruleset（动态 IP 集）。

use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Weak,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use core_config::model::{Capture, Mesh};
use core_resolver::fake_ip::FakeIpPool;
use core_runtime::Runtime;
use parking_lot::RwLock;
use tokio::{
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use crate::{
    eim_nat::EimNatTable,
    engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind},
    ipset::{IpSetProvider, noop},
    nat::{NatEntry, NatTable},
    netstack_dispatch::{NetstackDispatcher, NetstackDispatcherHandles},
    sys_proxy::SystemProxyGuard,
    system_dispatch::{SystemDispatcher, SystemDispatcherHandles},
};

/// 跨 stack 的 dispatcher 句柄 —— supervisor 内部使用。
enum DispatcherHandles {
    /// sing-tun 风格 system stack（`stack=system/mixed/native`）。
    System(SystemDispatcherHandles),
    /// netstack-smoltcp 用户态 TCP 栈（`stack=gvisor/smoltcp`，对标 gVisor）。
    Netstack(NetstackDispatcherHandles),
}

impl DispatcherHandles {
    fn stop(self) {
        match self {
            Self::System(h) => h.stop(),
            Self::Netstack(h) => h.stop(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Lifecycle {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    CleanupFailed = 4,
}

impl Lifecycle {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Stopping,
            4 => Self::CleanupFailed,
            _ => Self::Stopped,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::CleanupFailed => "cleanup_failed",
        }
    }
}

/// Resource teardown is deliberately the exact reverse of startup.
///
/// Keeping the order as data makes rollback and ordinary stop share the same
/// implementation, and gives tests a stable contract to assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupStep {
    NetworkListener,
    PurgeTask,
    EventTask,
    Dispatcher,
    SystemProxy,
    Engine,
    DnsListener,
}

const CLEANUP_ORDER: [CleanupStep; 7] = [
    CleanupStep::NetworkListener,
    CleanupStep::PurgeTask,
    CleanupStep::EventTask,
    CleanupStep::Dispatcher,
    CleanupStep::SystemProxy,
    CleanupStep::Engine,
    CleanupStep::DnsListener,
];

#[derive(Default)]
struct SupervisorResources {
    event_stopper: Option<oneshot::Sender<()>>,
    event_handle: Option<JoinHandle<()>>,
    dns_listeners: Vec<core_runtime::DnsListener>,
    purge_handle: Option<JoinHandle<()>>,
    network_listener_handle: Option<JoinHandle<()>>,
    dispatcher: Option<DispatcherHandles>,
    sys_proxy: Option<SystemProxyGuard>,
}

impl SupervisorResources {
    async fn shutdown(
        &mut self,
        engine: Arc<dyn CaptureEngine>,
        stop_engine: bool,
    ) -> Result<(), CaptureError> {
        let mut engine_result = Ok(());
        for step in CLEANUP_ORDER {
            match step {
                CleanupStep::NetworkListener => {
                    abort_and_join(self.network_listener_handle.take()).await;
                }
                CleanupStep::PurgeTask => {
                    abort_and_join(self.purge_handle.take()).await;
                }
                CleanupStep::EventTask => {
                    if let Some(tx) = self.event_stopper.take() {
                        let _ = tx.send(());
                    }
                    stop_and_join(self.event_handle.take()).await;
                }
                CleanupStep::Dispatcher => {
                    if let Some(dispatcher) = self.dispatcher.take() {
                        dispatcher.stop();
                    }
                }
                CleanupStep::SystemProxy => {
                    if let Some(proxy) = self.sys_proxy.take() {
                        proxy.revert();
                    }
                }
                CleanupStep::Engine if stop_engine => {
                    engine_result = engine.clone().stop().await;
                }
                CleanupStep::Engine => {}
                CleanupStep::DnsListener => {
                    // If platform rollback failed, keep the resolver live while
                    // system DNS may still point at it. A later stop retry
                    // closes these listeners after engine cleanup succeeds.
                    if engine_result.is_ok() || !stop_engine {
                        while let Some(listener) = self.dns_listeners.pop() {
                            listener.shutdown().await;
                        }
                    }
                }
            }
        }
        engine_result
    }

    /// Cancellation fallback for a dropped start/stop future. Async engine
    /// cleanup is scheduled separately by [`CleanupTransaction::drop`].
    fn abort_sync(&mut self) {
        for handle in [
            self.network_listener_handle.take(),
            self.purge_handle.take(),
        ]
        .into_iter()
        .flatten()
        {
            handle.abort();
        }
        if let Some(tx) = self.event_stopper.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.event_handle.take() {
            handle.abort();
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            dispatcher.stop();
        }
        if let Some(proxy) = self.sys_proxy.take() {
            proxy.revert();
        }
    }
}

async fn abort_and_join(handle: Option<JoinHandle<()>>) {
    if let Some(handle) = handle {
        handle.abort();
        let _ = handle.await;
    }
}

async fn stop_and_join(handle: Option<JoinHandle<()>>) {
    let Some(mut handle) = handle else {
        return;
    };
    if tokio::time::timeout(Duration::from_secs(1), &mut handle)
        .await
        .is_err()
    {
        handle.abort();
        let _ = handle.await;
    }
}

/// Owns all not-yet-committed (or being-stopped) resources. If the caller
/// future is cancelled, `Drop` still aborts supervisor tasks and schedules the
/// engine cleanup instead of leaving the machine's routes/proxy half applied.
struct CleanupTransaction {
    owner: Weak<CaptureSupervisor>,
    engine: Arc<dyn CaptureEngine>,
    resources: Option<SupervisorResources>,
    stop_engine: bool,
    armed: bool,
}

impl CleanupTransaction {
    fn new(owner: &Arc<CaptureSupervisor>, resources: SupervisorResources) -> Self {
        Self {
            owner: Arc::downgrade(owner),
            engine: owner.engine.clone(),
            resources: Some(resources),
            stop_engine: false,
            armed: true,
        }
    }

    fn resources_mut(&mut self) -> &mut SupervisorResources {
        self.resources
            .as_mut()
            .expect("cleanup transaction resources already consumed")
    }

    fn mark_engine_started(&mut self) {
        // Set before awaiting engine.start: even an engine that returns an
        // error may have applied a subset of platform state.
        self.stop_engine = true;
    }

    async fn shutdown_to_stopped(mut self) -> Result<(), CaptureError> {
        let result = self
            .resources
            .as_mut()
            .expect("cleanup transaction resources already consumed")
            .shutdown(self.engine.clone(), self.stop_engine)
            .await;
        self.stop_engine = false;
        self.armed = false;
        if let Some(owner) = self.owner.upgrade() {
            if result.is_ok() {
                owner.finish_transition(Lifecycle::Stopped);
            } else {
                let resources = self
                    .resources
                    .take()
                    .expect("cleanup transaction resources already consumed");
                {
                    let mut slot = owner.resources.lock();
                    debug_assert!(
                        slot.is_none(),
                        "failed cleanup resources must have a single owner"
                    );
                    *slot = Some(resources);
                }
                owner.finish_transition(Lifecycle::CleanupFailed);
            }
        }
        result
    }

    fn commit(mut self) -> SupervisorResources {
        self.stop_engine = false;
        self.armed = false;
        self.resources
            .take()
            .expect("cleanup transaction resources already consumed")
    }
}

impl Drop for CleanupTransaction {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(resources) = self.resources.as_mut() {
            resources.abort_sync();
        }
        let dns_listeners = self
            .resources
            .as_mut()
            .map(|resources| std::mem::take(&mut resources.dns_listeners))
            .unwrap_or_default();

        let owner = self.owner.clone();
        if self.stop_engine {
            let engine = self.engine.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if let Err(error) = engine.stop().await {
                        warn!(
                            target: "capture",
                            %error,
                            "cancelled lifecycle transition: engine rollback failed"
                        );
                        if let Some(owner) = owner.upgrade() {
                            let recovery = SupervisorResources {
                                dns_listeners,
                                ..SupervisorResources::default()
                            };
                            {
                                let mut slot = owner.resources.lock();
                                *slot = Some(recovery);
                            }
                            owner.finish_transition(Lifecycle::CleanupFailed);
                        }
                        return;
                    }
                    for listener in dns_listeners.into_iter().rev() {
                        listener.shutdown().await;
                    }
                    if let Some(owner) = owner.upgrade() {
                        owner.finish_transition(Lifecycle::Stopped);
                    }
                });
                return;
            }
        }
        drop(dns_listeners);
        if let Some(owner) = owner.upgrade() {
            owner.finish_transition(Lifecycle::Stopped);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartFailpoint {
    Never,
    AfterEngine,
    AfterTasks,
}

pub struct CaptureSupervisor {
    pub plan: CapturePlan,
    pub engine: Arc<dyn CaptureEngine>,
    pub fake_pool: Arc<FakeIpPool>,
    pub nat: Arc<NatTable>,
    pub eim: Arc<EimNatTable>,
    ipset: RwLock<Arc<dyn IpSetProvider>>,
    lifecycle: AtomicU8,
    lifecycle_changed: Notify,
    /// Running resources are committed atomically only after every fallible
    /// startup step succeeds.
    resources: parking_lot::Mutex<Option<SupervisorResources>>,
}

impl CaptureSupervisor {
    /// 由 capture+mesh 配置 + Runtime 生成 supervisor。off 时返回 None。
    ///
    /// `ipv6_enabled` 来自 `Resolver.ipv6`：全局 IPv6 开关，关闭时 TUN
    /// dispatcher 直接丢弃所有 IPv6 包（mihomo `ipv6: false` 对齐）。
    pub fn build(
        capture: &Capture,
        _mesh: &Mesh,
        ipv6_enabled: bool,
    ) -> Result<Option<Arc<Self>>, CaptureError> {
        let mut plan = CapturePlan::from_config(capture)?;
        plan.ipv6_enabled = ipv6_enabled;
        if plan.kind == EngineKind::None {
            return Ok(None);
        }
        let engine = crate::platform::build_engine(plan.clone())?;
        // Fake-IP must use the dedicated synthetic ranges, not the TUN
        // interface CIDRs. Binding it to 172.19.0.1/30 makes allocation fail
        // because private ranges are intentionally avoided, so hijacked DNS
        // falls back to empty answers and later traffic loses DNS mapping.
        let pool = Arc::new(FakeIpPool::default());
        // udp_timeout 同步驱动 NAT + EIM-NAT TTL。
        let nat = Arc::new(NatTable::new(plan.udp_timeout));
        let eim = Arc::new(EimNatTable::new(plan.udp_timeout));
        Ok(Some(Arc::new(Self {
            plan,
            engine,
            fake_pool: pool,
            nat,
            eim,
            ipset: RwLock::new(noop()),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        })))
    }

    /// 注入 IP 集合 provider（main.rs 用 RulesetIndex 桥接）。
    pub fn set_ip_set_provider(&self, p: Arc<dyn IpSetProvider>) {
        *self.ipset.write() = p;
    }

    /// 综合判断：route_address(_set) + route_exclude_address(_set) + loopback。
    fn allow_ip(&self, ip: IpAddr) -> bool {
        // 1. loopback_address：明确不接管。
        if self.plan.is_loopback_ip(ip) {
            return false;
        }
        // 2. CIDR 黑名单
        if self
            .plan
            .route_exclude_addresses
            .iter()
            .any(|n| n.contains(&ip))
        {
            return false;
        }
        // 3. 动态 IP 集黑名单
        let ipset = self.ipset.read().clone();
        for set in &self.plan.route_exclude_address_set {
            if ipset.contains(set, ip) {
                return false;
            }
        }
        // 4. 白名单（CIDR + set 任一命中即可）。空白名单 = 全开放。
        if self.plan.route_addresses.is_empty() && self.plan.route_address_set.is_empty() {
            return true;
        }
        if self.plan.route_addresses.iter().any(|n| n.contains(&ip)) {
            return true;
        }
        for set in &self.plan.route_address_set {
            if ipset.contains(set, ip) {
                return true;
            }
        }
        false
    }

    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::from_raw(self.lifecycle.load(Ordering::Acquire))
    }

    fn finish_transition(&self, state: Lifecycle) {
        self.lifecycle.store(state as u8, Ordering::Release);
        self.lifecycle_changed.notify_waiters();
    }

    /// Claim the stopped -> starting transition. Concurrent callers wait for
    /// the active transition without holding a mutex across an await.
    async fn begin_start(self: &Arc<Self>) -> Result<bool, CaptureError> {
        loop {
            let notified = self.lifecycle_changed.notified();
            tokio::pin!(notified);
            // `notify_waiters` does not retain a permit. Register the waiter
            // before reading lifecycle so a transition between the state read
            // and `.await` cannot be lost.
            notified.as_mut().enable();
            match self.lifecycle() {
                Lifecycle::Running => return Ok(false),
                Lifecycle::Stopped => {
                    if self
                        .lifecycle
                        .compare_exchange(
                            Lifecycle::Stopped as u8,
                            Lifecycle::Starting as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return Ok(true);
                    }
                }
                Lifecycle::CleanupFailed => {
                    if self
                        .lifecycle
                        .compare_exchange(
                            Lifecycle::CleanupFailed as u8,
                            Lifecycle::Stopping as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        let resources = self.resources.lock().take().unwrap_or_default();
                        let mut transaction = CleanupTransaction::new(self, resources);
                        transaction.stop_engine = true;
                        transaction.shutdown_to_stopped().await?;
                    }
                }
                Lifecycle::Starting | Lifecycle::Stopping => notified.await,
            }
        }
    }

    /// Claim the running -> stopping transition. `false` means already stopped.
    async fn begin_stop(&self) -> bool {
        loop {
            let notified = self.lifecycle_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let lifecycle = self.lifecycle();
            match lifecycle {
                Lifecycle::Stopped => return false,
                Lifecycle::Running | Lifecycle::CleanupFailed => {
                    if self
                        .lifecycle
                        .compare_exchange(
                            lifecycle as u8,
                            Lifecycle::Stopping as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                Lifecycle::Starting | Lifecycle::Stopping => notified.await,
            }
        }
    }

    /// 启动 capture：让 engine 就绪，并把事件转发给 runtime.dial。
    pub async fn start(self: &Arc<Self>, runtime: Arc<Runtime>) -> Result<(), CaptureError> {
        self.start_with_failpoint(runtime, StartFailpoint::Never)
            .await
    }

    async fn start_with_failpoint(
        self: &Arc<Self>,
        runtime: Arc<Runtime>,
        failpoint: StartFailpoint,
    ) -> Result<(), CaptureError> {
        if !self.begin_start().await? {
            // Idempotent start: an already-running supervisor is success.
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<CaptureEvent>(1024);
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let mut transaction = CleanupTransaction::new(self, SupervisorResources::default());
        let dns_service = Arc::new(
            core_resolver::DnsService::new(runtime.resolver.clone())
                .with_fake_pool(self.fake_pool.clone()),
        );
        if self.plan.hijack_dns {
            for &listen_addr in fake_dns_listen_addrs() {
                let listener = core_runtime::spawn_dns_listener(listen_addr, dns_service.clone())
                    .await
                    .map_err(|error| {
                        CaptureError::DeviceFailed(format!(
                            "cannot start fake-DNS on {listen_addr}: {error}"
                        ))
                    })?;
                if listener.is_disabled() {
                    return Err(CaptureError::DeviceFailed(format!(
                        "fake-DNS listener unexpectedly disabled for {listen_addr}"
                    )));
                }
                transaction.resources_mut().dns_listeners.push(listener);
            }
        }
        transaction.mark_engine_started();

        let start_result: Result<(), CaptureError> = async {
            self.engine.clone().start(tx, runtime.clone()).await?;
            if failpoint == StartFailpoint::AfterEngine {
                return Err(CaptureError::DeviceFailed(
                    "injected supervisor failure after engine start".into(),
                ));
            }

            // platform.http_proxy 透传 —— 系统级 HTTP/HTTPS proxy 写入。
            if let Some(http_opts) = &self.plan.platform_http_proxy {
                transaction.resources_mut().sys_proxy = Some(SystemProxyGuard::install(http_opts));
            }

            // virtual_nic/TUN 的平台 packet_loop 只能发现流，不能转发 payload。
            // 必须由 dispatcher 独占 TUN 读写，否则只改路由不会有任何 TCP/UDP 出站。
            // 按 `plan.stack` 选派：
            //   对标 sing-tun：
            //   * `system` / `mixed` / `native` —— sing-tun 风格 OS NAT 栈：
            //     TCP 走内核 listener + NAT 改写，UDP 走 udp_handle 转发。
            //     sing-tun 的 Mixed = System(TCP) + gVisor(UDP)，WutherCore 没有 gVisor，
            //     所以 Mixed 与 System 行为一致（TCP NAT + UDP forwarder）。
            //   * `smoltcp` / `gvisor` —— smoltcp 用户态 TCP 栈（仅测试/备用）。
            if self.plan.kind == EngineKind::Tun {
                let tun_io = self.engine.tun_io().ok_or_else(|| {
                    CaptureError::DeviceFailed(
                        "TUN engine started without a packet I/O device".into(),
                    )
                })?;
                use core_config::model::CaptureStack;
                let use_system = matches!(
                    self.plan.stack,
                    CaptureStack::System | CaptureStack::Mixed | CaptureStack::Native
                );
                let handles = if use_system {
                    let disp = Arc::new(SystemDispatcher::new(
                        self.plan.clone(),
                        self.nat.clone(),
                        self.eim.clone(),
                        self.fake_pool.clone(),
                        dns_service.clone(),
                        self.ipset.read().clone(),
                    ));
                    let h = disp.start(tun_io, runtime.clone()).await?;
                    info!(
                        target: "capture",
                        stack = ?self.plan.stack,
                        "system dispatcher attached (sing-tun NAT + OS listener)"
                    );
                    DispatcherHandles::System(h)
                } else {
                    // gvisor / smoltcp → netstack-smoltcp 用户态 TCP 栈
                    let disp = Arc::new(NetstackDispatcher::new(
                        self.plan.clone(),
                        self.nat.clone(),
                        self.eim.clone(),
                        self.fake_pool.clone(),
                        dns_service.clone(),
                        self.ipset.read().clone(),
                    ));
                    let h = disp.start(tun_io, runtime.clone());
                    info!(
                        target: "capture",
                        stack = ?self.plan.stack,
                        "netstack dispatcher attached (netstack-smoltcp TCP + UDP forwarder)"
                    );
                    DispatcherHandles::Netstack(h)
                };
                transaction.resources_mut().dispatcher = Some(handles);
            }

            let pool = self.fake_pool.clone();
            let nat = self.nat.clone();
            let sup = self.clone();
            let handle = tokio::spawn(async move {
                // 本 loop 仅做 NAT 登记 + 调试日志：实际的 dial+splice 由
                //   * TUN+user-stack:  `TunDispatcher::run_accept_consumer`
                //   * TPROXY/Redirect: 平台 listener 自身（带 Arc<Runtime>，未来扩展）
                // 负责。绝对不能在此处 `runtime.dial(..).drop(stream)`。
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        event = rx.recv() => {
                            let Some(evt) = event else { break };
                            if !sup.allow_ip(evt.original_dst.ip()) {
                                tracing::debug!(
                                    target: "capture::dispatch",
                                    ip = %evt.original_dst.ip(),
                                    "skipped by route rules / loopback / ipset"
                                );
                                continue;
                            }
                            let now = Instant::now();
                            let nat_id = nat.insert(NatEntry {
                                source: evt.source,
                                original_dst: evt.original_dst,
                                fake_host: evt.fake_host.clone(),
                                network: evt.network,
                                created_at: now,
                                last_seen: now,
                            });
                            let target = crate::dial_meta::build_dial_target(
                                &pool,
                                evt.original_dst,
                                evt.fake_host.as_deref(),
                            );
                            if target.fake_ip_missing {
                                tracing::warn!(
                                    target: "capture::dispatch",
                                    ip = %evt.original_dst.ip(),
                                    "fake DNS record missing; skip dispatch"
                                );
                                continue;
                            }
                            let host = target.host;
                            debug!(
                                target: "capture::dispatch",
                                host = %host,
                                port = evt.original_dst.port(),
                                net = evt.network,
                                nat_id,
                                "flow seen (NAT registered; actual dial owned by stack/listener)"
                            );
                        }
                    }
                }
            });
            transaction.resources_mut().event_handle = Some(handle);
            transaction.resources_mut().event_stopper = Some(stop_tx);

            // NAT + EIM-NAT 周期性 purge：udp_timeout/2，下限 5s。
            let purge_period = std::cmp::max(Duration::from_secs(5), self.plan.udp_timeout / 2);
            let nat_for_gc = self.nat.clone();
            let eim_for_gc = self.eim.clone();
            let purge_handle = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(purge_period);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let r1 = nat_for_gc.purge();
                    let r2 = eim_for_gc.purge();
                    if r1 + r2 > 0 {
                        debug!(
                            target: "capture::nat",
                            nat_removed = r1,
                            eim_removed = r2,
                            nat_remaining = nat_for_gc.len(),
                            eim_remaining = eim_for_gc.len(),
                            "purge"
                        );
                    }
                }
            });
            transaction.resources_mut().purge_handle = Some(purge_handle);

            // Network change listener: reset all DNS connections on interface switch.
            let mut net_rx = crate::net_monitor::subscribe();
            let resolver = runtime.resolver.clone();
            let network_listener_handle = tokio::spawn(async move {
                while let Ok(event) = net_rx.recv().await {
                    info!(
                        target: "capture::net_monitor",
                        generation = event.generation,
                        interface = ?event.interface.name,
                        v4_index = ?event.interface.v4_index,
                        v6_index = ?event.interface.v6_index,
                        "network changed: resetting DNS connections"
                    );
                    resolver.reset_connections().await;
                }
            });
            transaction.resources_mut().network_listener_handle = Some(network_listener_handle);

            if failpoint == StartFailpoint::AfterTasks {
                return Err(CaptureError::DeviceFailed(
                    "injected supervisor failure after task startup".into(),
                ));
            }

            Ok(())
        }
        .await;

        if let Err(error) = start_result {
            if let Err(rollback_error) = transaction.shutdown_to_stopped().await {
                warn!(
                    target: "capture",
                    %rollback_error,
                    "capture startup rollback could not stop engine cleanly"
                );
            }
            return Err(error);
        }

        // This watcher is process-global and intentionally outlives a
        // supervisor instance. Repeated starts only update its shared exclusion
        // list. Run the synchronous initial probe while lifecycle is still
        // `Starting`, so a concurrent stop cannot overtake the final commit.
        let exclude =
            crate::default_iface::ExcludeList::from_plan_iface(self.plan.interface_name.clone());
        crate::net_monitor::start_watcher(exclude);

        let resources = transaction.commit();
        {
            let mut slot = self.resources.lock();
            debug_assert!(slot.is_none(), "running resources must be committed once");
            *slot = Some(resources);
        }
        self.finish_transition(Lifecycle::Running);

        info!(
            target: "capture",
            kind = ?self.plan.kind,
            iface = %self.plan.interface_name,
            mtu = self.plan.mtu,
            hijack_dns = self.plan.hijack_dns,
            eim_nat = self.plan.endpoint_independent_nat,
            "capture supervisor running"
        );
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) -> Result<(), CaptureError> {
        if !self.begin_stop().await {
            return Ok(());
        }

        let resources = self.resources.lock().take().unwrap_or_default();
        let transaction = CleanupTransaction::new(self, resources);
        let result = {
            let mut transaction = transaction;
            transaction.stop_engine = true;
            transaction.shutdown_to_stopped().await
        };
        if let Err(error) = &result {
            warn!(target: "capture", %error, "capture engine stop failed after local cleanup");
        }
        result
    }

    pub fn report(&self) -> serde_json::Value {
        let sys_proxy_active = self
            .resources
            .lock()
            .as_ref()
            .is_some_and(|resources| resources.sys_proxy.is_some());
        serde_json::json!({
            "engine": self.engine.report(),
            "lifecycle": self.lifecycle().as_str(),
            "fake_pool_size": self.fake_pool.len(),
            "nat_size": self.nat.len(),
            "eim_size": self.eim.len(),
            "exclude_cidrs": self.plan.exclude_cidrs.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            "route_address_sets": self.plan.route_address_set.clone(),
            "route_exclude_address_sets": self.plan.route_exclude_address_set.clone(),
            "ipset_known": self.ipset.read().names(),
            "hijack_dns": self.plan.hijack_dns,
            "endpoint_independent_nat": self.plan.endpoint_independent_nat,
            "host_pin_size": self.nat.host_pin.len(),
            "sys_proxy_active": sys_proxy_active,
        })
    }
}

fn fake_dns_listen_addrs() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        // WindowsTun points both IPv4 and IPv6 resolver families at these
        // loopback listeners.
        &["127.0.0.1:53", "[::1]:53"]
    } else {
        // Preserve the existing private capture listener on Unix platforms.
        &["127.0.0.1:5454"]
    }
}

/// 工具：把字符串地址解析。
pub fn first_addr(s: &str) -> Option<SocketAddr> {
    s.to_socket_addrs().ok().and_then(|mut it| it.next())
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::atomic::{AtomicBool, AtomicUsize},
    };

    use core_config::model::{
        Capture, CaptureExclude, CaptureMethod, CaptureResolver, CaptureStack, CaptureTraffic,
        Mesh, TunInboundOptions,
    };
    use core_resolver::fake_ip::{AddressFamily, FakeIpConfig};
    use tokio::sync::Semaphore;

    use super::*;

    fn capture() -> Capture {
        Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Off,
            stack: CaptureStack::System,
            mtu: None,
            offload: true,
            exclude: CaptureExclude::default(),
            tun: TunInboundOptions::default(),
        }
    }

    #[test]
    fn hijack_fake_pool_uses_reserved_fake_range_not_tun_interface_range() {
        let mut c = capture();
        c.resolver = CaptureResolver::Hijack;
        c.tun.address = vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()];

        let sup = CaptureSupervisor::build(&c, &Mesh::default(), true)
            .unwrap()
            .expect("capture enabled");
        let fake_ip = sup
            .fake_pool
            .alloc("www.example.com", AddressFamily::V4)
            .expect("fake-ip allocation must not use private TUN address range");

        assert_eq!(sup.fake_pool.config().v4_cidr.to_string(), "198.18.0.0/15");
        assert!(sup.fake_pool.contains(fake_ip));
        assert_eq!(
            sup.fake_pool.lookup(fake_ip).as_deref(),
            Some("www.example.com")
        );
    }

    #[derive(Debug)]
    struct FakeSet(Vec<(String, IpAddr)>);
    impl IpSetProvider for FakeSet {
        fn contains(&self, name: &str, ip: IpAddr) -> bool {
            self.0.iter().any(|(n, i)| n == name && *i == ip)
        }
    }

    #[test]
    fn allow_ip_loopback_blocked() {
        let mut c = capture();
        c.tun.loopback_address = vec!["10.7.0.1".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr.unwrap_or("fc00:1::/64".parse().unwrap()),
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(noop()),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        };
        assert!(!sup.allow_ip("10.7.0.1".parse().unwrap()));
        assert!(sup.allow_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn allow_ip_builtin_loopback_blocked_without_config() {
        let c = capture();
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr.unwrap_or("fc00:1::/64".parse().unwrap()),
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(noop()),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        };
        assert!(!sup.allow_ip("127.0.0.2".parse().unwrap()));
        assert!(!sup.allow_ip("::1".parse().unwrap()));
    }

    #[test]
    fn allow_ip_uses_ipset_blacklist() {
        let mut c = capture();
        c.tun.route_exclude_address_set = vec!["geoip-cn".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr.unwrap_or("fc00:1::/64".parse().unwrap()),
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(Arc::new(FakeSet(vec![(
                "geoip-cn".into(),
                "114.114.114.114".parse().unwrap(),
            )]))),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        };
        assert!(!sup.allow_ip("114.114.114.114".parse().unwrap()));
        assert!(sup.allow_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allow_ip_whitelist_via_ipset() {
        let mut c = capture();
        c.tun.route_address_set = vec!["geoip-cloudflare".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr.unwrap_or("fc00:1::/64".parse().unwrap()),
            ..FakeIpConfig::default()
        }));
        let sup = CaptureSupervisor {
            plan,
            engine: dummy_engine(),
            fake_pool: pool,
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
            ipset: RwLock::new(Arc::new(FakeSet(vec![(
                "geoip-cloudflare".into(),
                "1.1.1.1".parse().unwrap(),
            )]))),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        };
        assert!(sup.allow_ip("1.1.1.1".parse().unwrap()));
        assert!(!sup.allow_ip("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn virtual_nic_native_or_system_stack_starts_tun_dispatcher() {
        for stack in [
            CaptureStack::Native,
            CaptureStack::System,
            CaptureStack::Mixed,
        ] {
            let mut c = capture();
            c.stack = stack;
            let mut plan = CapturePlan::from_config(&c).unwrap();
            // System/Mixed/Native 都走 SystemDispatcher，bind 到 TUN 地址；
            // 测试环境下用 loopback 网段（127.0.0.1/30）避免地址不可用。
            let uses_system = matches!(
                stack,
                CaptureStack::System | CaptureStack::Mixed | CaptureStack::Native
            );
            if uses_system {
                plan.tun_v4_cidr = "127.0.0.1/30".parse().unwrap();
            }
            let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
                v4_cidr: plan.tun_v4_cidr,
                v6_cidr: plan.tun_v6_cidr.unwrap_or("fc00:1::/64".parse().unwrap()),
                ..FakeIpConfig::default()
            }));
            let sup = Arc::new(CaptureSupervisor {
                plan,
                engine: dummy_engine_with_tun_io(),
                fake_pool: pool,
                nat: Arc::new(NatTable::default()),
                eim: Arc::new(EimNatTable::new(std::time::Duration::from_secs(60))),
                ipset: RwLock::new(noop()),
                lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
                lifecycle_changed: Notify::new(),
                resources: parking_lot::Mutex::new(None),
            });
            let runtime = Arc::new(core_runtime::Runtime::build(
                core_config::loader::load_from_str(
                    r#"
version: 1
profile: desktop
listen:
  panel: false
route:
  preset: direct
"#,
                )
                .unwrap(),
            ));

            sup.start(runtime).await.unwrap();

            assert!(
                sup.resources
                    .lock()
                    .as_ref()
                    .is_some_and(|resources| resources.dispatcher.is_some()),
                "virtual_nic/{stack:?} must attach TunDispatcher; event-only packet loop cannot forward traffic"
            );
            sup.stop().await.unwrap();
        }
    }

    #[test]
    fn cleanup_order_is_reverse_startup_order() {
        assert_eq!(
            CLEANUP_ORDER,
            [
                CleanupStep::NetworkListener,
                CleanupStep::PurgeTask,
                CleanupStep::EventTask,
                CleanupStep::Dispatcher,
                CleanupStep::SystemProxy,
                CleanupStep::Engine,
                CleanupStep::DnsListener,
            ]
        );
    }

    #[test]
    fn windows_fake_dns_matches_system_dns_target() {
        if cfg!(target_os = "windows") {
            assert_eq!(fake_dns_listen_addrs(), ["127.0.0.1:53", "[::1]:53"]);
        } else {
            assert_eq!(fake_dns_listen_addrs(), ["127.0.0.1:5454"]);
        }
    }

    #[tokio::test]
    async fn failed_start_rolls_back_then_retry_and_repeated_stop_are_safe() {
        let engine = Arc::new(LifecycleEngine::new(false));
        let sup = lifecycle_supervisor(engine.clone());
        let runtime = lifecycle_runtime();

        let error = sup
            .start_with_failpoint(runtime.clone(), StartFailpoint::AfterTasks)
            .await
            .expect_err("injected failure must escape start");
        assert!(error.to_string().contains("injected supervisor failure"));
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
        assert!(sup.resources.lock().is_none());
        assert_eq!(engine.starts.load(Ordering::SeqCst), 1);
        assert_eq!(engine.stops.load(Ordering::SeqCst), 1);

        sup.start(runtime).await.expect("retry after rollback");
        assert_eq!(sup.lifecycle(), Lifecycle::Running);
        assert_eq!(engine.starts.load(Ordering::SeqCst), 2);

        sup.stop().await.expect("first stop");
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
        assert_eq!(engine.stops.load(Ordering::SeqCst), 2);
        sup.stop().await.expect("idempotent repeated stop");
        assert_eq!(
            engine.stops.load(Ordering::SeqCst),
            2,
            "already-stopped engine must not be stopped twice"
        );
    }

    #[tokio::test]
    async fn engine_stop_error_preserves_resources_for_direct_stop_retry() {
        let engine = Arc::new(LifecycleEngine::new(false));
        let sup = lifecycle_supervisor(engine.clone());
        let runtime = lifecycle_runtime();
        sup.start(runtime.clone()).await.unwrap();

        engine.fail_stop_once.store(true, Ordering::SeqCst);
        assert!(sup.stop().await.is_err());
        assert_eq!(sup.lifecycle(), Lifecycle::CleanupFailed);
        assert!(sup.resources.lock().is_some());
        assert_eq!(engine.stops.load(Ordering::SeqCst), 1);

        sup.stop().await.expect("direct cleanup retry succeeds");
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
        assert!(sup.resources.lock().is_none());
        assert_eq!(engine.stops.load(Ordering::SeqCst), 2);

        sup.start(runtime).await.expect("restart after cleanup");
        sup.stop().await.expect("clean stop after restart");
    }

    #[tokio::test]
    async fn tun_start_without_packet_io_fails_closed_and_rolls_back() {
        let engine = Arc::new(MissingTunIoEngine {
            plan: CapturePlan::from_config(&capture()).unwrap(),
            stops: AtomicUsize::new(0),
        });
        let sup = Arc::new(CaptureSupervisor {
            plan: engine.plan.clone(),
            engine: engine.clone(),
            fake_pool: Arc::new(FakeIpPool::default()),
            nat: Arc::new(NatTable::default()),
            eim: Arc::new(EimNatTable::new(Duration::from_secs(60))),
            ipset: RwLock::new(noop()),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        });

        let error = sup
            .start(lifecycle_runtime())
            .await
            .expect_err("missing TUN packet I/O must not publish a running supervisor");
        assert!(error.to_string().contains("without a packet I/O device"));
        assert_eq!(engine.stops.load(Ordering::SeqCst), 1);
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
        assert!(sup.resources.lock().is_none());
    }

    #[tokio::test]
    async fn stop_waits_for_start_transition_without_lost_wakeup() {
        let engine = Arc::new(LifecycleEngine::new(true));
        let sup = lifecycle_supervisor(engine.clone());
        let runtime = lifecycle_runtime();

        let start_task = {
            let sup = sup.clone();
            let runtime = runtime.clone();
            tokio::spawn(async move { sup.start(runtime).await })
        };
        engine
            .entered
            .acquire()
            .await
            .expect("start entry semaphore")
            .forget();
        assert_eq!(sup.lifecycle(), Lifecycle::Starting);

        let stop_task = {
            let sup = sup.clone();
            tokio::spawn(async move { sup.stop().await })
        };
        engine.release.add_permits(1);

        start_task.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), stop_task)
            .await
            .expect("stop waiter must be notified")
            .unwrap()
            .unwrap();
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
        assert!(sup.resources.lock().is_none());
    }

    #[tokio::test]
    async fn cancelled_start_schedules_engine_rollback_and_allows_retry() {
        let engine = Arc::new(LifecycleEngine::new(true));
        let sup = lifecycle_supervisor(engine.clone());
        let runtime = lifecycle_runtime();

        let start_task = {
            let sup = sup.clone();
            let runtime = runtime.clone();
            tokio::spawn(async move { sup.start(runtime).await })
        };
        engine
            .entered
            .acquire()
            .await
            .expect("start entry semaphore")
            .forget();
        start_task.abort();
        let _ = start_task.await;

        tokio::time::timeout(Duration::from_secs(2), async {
            while sup.lifecycle() != Lifecycle::Stopped || engine.stops.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled start rollback must finish");

        sup.start(runtime).await.expect("retry after cancellation");
        sup.stop().await.unwrap();
        assert_eq!(sup.lifecycle(), Lifecycle::Stopped);
    }

    struct LifecycleEngine {
        plan: CapturePlan,
        starts: AtomicUsize,
        stops: AtomicUsize,
        fail_stop_once: AtomicBool,
        block_start_once: AtomicBool,
        entered: Semaphore,
        release: Semaphore,
    }

    impl LifecycleEngine {
        fn new(block_start_once: bool) -> Self {
            let mut plan = CapturePlan::from_config(&capture()).unwrap();
            // Lifecycle tests exercise supervisor ownership and rollback only;
            // TUN dispatcher readiness is covered separately below.
            plan.kind = EngineKind::Tproxy;
            Self {
                plan,
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                fail_stop_once: AtomicBool::new(false),
                block_start_once: AtomicBool::new(block_start_once),
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl CaptureEngine for LifecycleEngine {
        fn kind(&self) -> EngineKind {
            self.plan.kind
        }

        fn plan(&self) -> &CapturePlan {
            &self.plan
        }

        async fn start(
            self: Arc<Self>,
            _events: mpsc::Sender<CaptureEvent>,
            _runtime: Arc<core_runtime::Runtime>,
        ) -> Result<(), CaptureError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if self.block_start_once.swap(false, Ordering::SeqCst) {
                self.entered.add_permits(1);
                self.release
                    .acquire()
                    .await
                    .expect("start release semaphore")
                    .forget();
            }
            Ok(())
        }

        async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            if self.fail_stop_once.swap(false, Ordering::SeqCst) {
                return Err(CaptureError::DeviceFailed(
                    "injected engine stop failure".into(),
                ));
            }
            Ok(())
        }
    }

    struct MissingTunIoEngine {
        plan: CapturePlan,
        stops: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CaptureEngine for MissingTunIoEngine {
        fn kind(&self) -> EngineKind {
            EngineKind::Tun
        }

        fn plan(&self) -> &CapturePlan {
            &self.plan
        }

        async fn start(
            self: Arc<Self>,
            _events: mpsc::Sender<CaptureEvent>,
            _runtime: Arc<core_runtime::Runtime>,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn lifecycle_supervisor(engine: Arc<LifecycleEngine>) -> Arc<CaptureSupervisor> {
        let plan = engine.plan.clone();
        Arc::new(CaptureSupervisor {
            plan: plan.clone(),
            engine,
            fake_pool: Arc::new(FakeIpPool::default()),
            nat: Arc::new(NatTable::new(plan.udp_timeout)),
            eim: Arc::new(EimNatTable::new(plan.udp_timeout)),
            ipset: RwLock::new(noop()),
            lifecycle: AtomicU8::new(Lifecycle::Stopped as u8),
            lifecycle_changed: Notify::new(),
            resources: parking_lot::Mutex::new(None),
        })
    }

    fn lifecycle_runtime() -> Arc<core_runtime::Runtime> {
        Arc::new(core_runtime::Runtime::build(
            core_config::loader::load_from_str(
                r#"
version: 1
profile: desktop
listen:
  panel: false
route:
  preset: direct
"#,
            )
            .unwrap(),
        ))
    }

    fn dummy_engine() -> Arc<dyn CaptureEngine> {
        struct Dummy;
        #[async_trait::async_trait]
        impl CaptureEngine for Dummy {
            fn kind(&self) -> EngineKind {
                EngineKind::Tun
            }
            fn plan(&self) -> &CapturePlan {
                panic!("not used in test")
            }
            async fn start(
                self: Arc<Self>,
                _events: mpsc::Sender<CaptureEvent>,
                _runtime: Arc<core_runtime::Runtime>,
            ) -> Result<(), CaptureError> {
                Ok(())
            }
            async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
                Ok(())
            }
        }
        Arc::new(Dummy)
    }

    fn dummy_engine_with_tun_io() -> Arc<dyn CaptureEngine> {
        struct Dummy;
        #[async_trait::async_trait]
        impl CaptureEngine for Dummy {
            fn kind(&self) -> EngineKind {
                EngineKind::Tun
            }
            fn plan(&self) -> &CapturePlan {
                panic!("not used in test")
            }
            fn tun_io(&self) -> Option<Arc<dyn crate::tun_io::TunIo>> {
                Some(crate::tun_io::NoopTun::new("tun-test", 1500))
            }
            async fn start(
                self: Arc<Self>,
                _events: mpsc::Sender<CaptureEvent>,
                _runtime: Arc<core_runtime::Runtime>,
            ) -> Result<(), CaptureError> {
                Ok(())
            }
            async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
                Ok(())
            }
        }
        Arc::new(Dummy)
    }
}
