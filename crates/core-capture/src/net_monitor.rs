//! 默认物理网卡变化监听 + 自动重新绑定。
//!
//! ## 探测层 vs 监听层
//! * 探测层 [`crate::default_iface::probe`] —— 跨平台单次拉取当前默认出口
//!   `(name, v4_index, v6_index)`。
//! * 监听层（本模块）—— 周期/事件触发探测，对比上次结果，发生变化时：
//!   1. 把新的 name 写进 [`core_outbound::set_outbound_interface`]
//!      （Linux/Android `SO_BINDTODEVICE` 名字绑定）
//!   2. 把新的 v4/v6 ifindex 写进 [`core_outbound::set_outbound_interface_index`]
//!      （Windows `IP_UNICAST_IF`、Darwin `IP_BOUND_IF`）
//!   3. 广播 [`NetworkChangeEvent`]，supervisor 拿来重置 DNS 持久连接 + 缓存
//!
//! ## 触发源
//! * 跨平台 polling watcher：每 [`POLL_INTERVAL`] 重新探测，对比变化。低开销
//!   兜底，所有平台可用。
//! * Linux/Android：netlink RTMGRP_IPV4_ROUTE / RTMGRP_LINK 订阅（事件驱动，
//!   后续迭代）。
//! * Windows：`NotifyRouteChange2` + `NotifyIpInterfaceChange` 回调（事件驱动，
//!   后续迭代）。
//! * Android VpnService：上层 `ConnectivityManager.NetworkCallback` 经 JNI
//!   调 [`notify_network_changed_full`] / [`notify_network_changed`]。
//! * 任意手动触发：[`notify_network_changed`] 兼容旧调用。
//!
//! ## 排除 TUN
//! 探测时通过 [`crate::default_iface::ExcludeList`] 把 plan.interface_name +
//! `utun*` / `tun*` / `wintun*` / `WutherCore` / `Meta` 一律剔除，
//! 避免 TUN 抢了默认路由后再探拿到自己 → 自循环。

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::default_iface::{DefaultInterface, ExcludeList, probe};

/// 跨平台 polling 间隔。事件驱动 watcher 会更快，但 polling 是兜底。
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

static MONITOR: once_cell::sync::Lazy<NetworkMonitor> =
    once_cell::sync::Lazy::new(NetworkMonitor::new);
static WATCHER_EXCLUDE: OnceCell<SharedExcludeList> = OnceCell::new();

/// The OS/poll watcher is process-global. Restarts update the exclusion list
/// used by the existing tasks instead of spawning another watcher pair.
pub(crate) type SharedExcludeList = Arc<RwLock<ExcludeList>>;

pub struct NetworkMonitor {
    generation: AtomicU64,
    tx: broadcast::Sender<NetworkChangeEvent>,
    last: RwLock<DefaultInterface>,
}

#[derive(Debug, Clone)]
pub struct NetworkChangeEvent {
    pub generation: u64,
    pub interface: DefaultInterface,
}

impl NetworkChangeEvent {
    pub fn new_interface(&self) -> Option<&str> {
        self.interface.name.as_deref()
    }
}

impl NetworkMonitor {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            generation: AtomicU64::new(0),
            tx,
            last: RwLock::new(DefaultInterface::default()),
        }
    }

    /// 接收当前最新的探测结果，与上次对比；若有差异则同步全局态 + 广播事件。
    /// 返回 `true` 表示发生了变化（被广播）。
    ///
    /// 一种特殊情况：`current.is_empty()`（探测不到任何默认接口）时，依然
    /// 更新内部 last 缓存 + 广播事件，但 **不** 覆盖 `core_outbound` 的全局
    /// 接口状态。常见触发场景是 macOS / BSD 的 utun 在 `route add 0.0.0.0/0
    /// -interface utunN` 后吃掉了物理默认路由，watcher 排除 TUN 后探到空 ——
    /// 这时把物理 ifindex 置 0 反而让出站 socket fall back 到系统默认（即
    /// TUN）形成自循环。保留 last-known-good 让现有 socket 继续可用，等用户
    /// 切回有效物理网络后再覆盖。
    pub fn submit(&self, current: DefaultInterface) -> bool {
        let changed = {
            let last = self.last.read();
            *last != current
        };
        if !changed {
            return false;
        }
        let gen_id = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last.write() = current.clone();
        if current.is_empty() {
            warn!(
                target: "capture::net_monitor",
                generation = gen_id,
                "no default interface detected — keeping last known outbound bind"
            );
        } else {
            info!(
                target: "capture::net_monitor",
                generation = gen_id,
                interface = ?current.name,
                v4_index = ?current.v4_index,
                v6_index = ?current.v6_index,
                "default interface changed — rebinding outbound (name + ifindex)"
            );
            // (1) name —— Linux/Android SO_BINDTODEVICE
            core_outbound::set_outbound_interface(current.name.clone());
            // (2) ifindex —— Windows IP_UNICAST_IF / Darwin IP_BOUND_IF
            core_outbound::set_outbound_interface_index(current.v4_index, current.v6_index);
        }
        // 广播 —— supervisor 收到后 reset DNS 持久连接 + 缓存。即便 current
        // 为空也广播，让订阅方知道发生了变化（例如把 DNS 置空闲态）。
        let _ = self.tx.send(NetworkChangeEvent {
            generation: gen_id,
            interface: current,
        });
        true
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkChangeEvent> {
        self.tx.subscribe()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn current(&self) -> DefaultInterface {
        self.last.read().clone()
    }

    pub fn default_interface(&self) -> Option<String> {
        self.last.read().name.clone()
    }
}

pub fn global() -> &'static NetworkMonitor {
    &MONITOR
}

pub fn subscribe() -> broadcast::Receiver<NetworkChangeEvent> {
    global().subscribe()
}

/// 上层（如 Android JNI ConnectivityManager.NetworkCallback）拿到新接口名后
/// 调本入口；本模块自动跑一次完整探测，把 ifindex 一起更新。
pub fn notify_network_changed(_iface_hint: Option<String>) {
    // 即便上层只给了名字，我们也走完整 probe —— 顺便把 ifindex 校准。exclude
    // 在这条路径上拿不到 plan.interface_name（jni 直接调），用空 exclude，
    // 反正上层自己调本接口就意味着系统层确实切了，不会拿到 TUN。
    let exclude = ExcludeList {
        names: Default::default(),
        prefixes: vec![
            "utun".into(),
            "tun".into(),
            "tap".into(),
            "wintun".into(),
            "wuthercore".into(),
            "meta".into(),
        ],
    };
    let cur = probe(&exclude);
    global().submit(cur);
}

/// 上层完整提交 (name, v4, v6) —— 用于 JNI 等已经拿到全部信息的场景，
/// 跳过本地探测。
pub fn notify_network_changed_full(snapshot: DefaultInterface) {
    global().submit(snapshot);
}

/// 启动 default-iface watcher：
/// * 跨平台 polling（2s 兜底）—— 永远启动，确保即便事件驱动注册失败也能工作。
/// * 平台事件驱动（Windows NotifyRouteChange2 / Linux netlink / macOS PF_ROUTE）
///   —— 把 ≤2s 响应延迟降到 ~ms。失败时静默回退到只 polling。
///
/// `exclude` 通常由 supervisor 传入：至少包含 plan.interface_name；
/// [`ExcludeList::from_plan_iface`] 会再叠加常见 TUN 前缀。
pub fn start_watcher(exclude: ExcludeList) {
    let (exclude, is_new) = register_watcher_exclude(&WATCHER_EXCLUDE, exclude);

    // 同步跑一次初值 + 写全局态 —— 必须在 spawn watcher 任务之前，
    // 否则 supervisor.start() 返回后 DNS socket 工厂可能立刻被调用，但
    // outbound_interface_index 还是 None，IP_UNICAST_IF 无效，DNS 包反进
    // TUN 自循环。这里同步落盘一次能把这个窗口压到 0。
    let initial_exclude = exclude.read().clone();
    let initial = probe(&initial_exclude);
    if !initial.is_empty() {
        info!(
            target: "capture::net_monitor",
            interface = ?initial.name,
            v4_index = ?initial.v4_index,
            v6_index = ?initial.v6_index,
            "initial default interface (sync probe)"
        );
        global().submit(initial);
    } else {
        warn!(
            target: "capture::net_monitor",
            "initial probe returned empty — outbound socket bind 将无 ifindex；\
             watcher 会在网络变化时补齐，但启动这段时间内部组件 (DNS 等) 可能落 TUN"
        );
    }
    if !is_new {
        info!(
            target: "capture::net_monitor",
            "default-interface watcher already active; exclusion list updated"
        );
        return;
    }

    crate::net_monitor_event::start(exclude.clone());
    tokio::spawn(poll_watcher(exclude));
}

fn register_watcher_exclude(
    cell: &OnceCell<SharedExcludeList>,
    exclude: ExcludeList,
) -> (SharedExcludeList, bool) {
    let candidate = Arc::new(RwLock::new(exclude));
    match cell.set(candidate.clone()) {
        Ok(()) => (candidate, true),
        Err(candidate) => {
            let established = cell
                .get()
                .expect("OnceCell must contain the winning watcher exclusion")
                .clone();
            *established.write() = candidate.read().clone();
            (established, false)
        }
    }
}

async fn poll_watcher(exclude: SharedExcludeList) {
    info!(
        target: "capture::net_monitor",
        interval_ms = POLL_INTERVAL.as_millis() as u64,
        "default-interface poll watcher started"
    );

    let mut tick = tokio::time::interval(POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let current_exclude = exclude.read().clone();
        let cur = probe(&current_exclude);
        global().submit(cur);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_iface(name: &str, v4: u32, v6: u32) -> DefaultInterface {
        DefaultInterface {
            name: Some(name.into()),
            v4_index: Some(v4),
            v6_index: Some(v6),
        }
    }

    #[test]
    fn submit_returns_false_when_unchanged() {
        let m = NetworkMonitor::new();
        let snap = fresh_iface("eth0", 2, 2);
        assert!(m.submit(snap.clone()));
        assert!(!m.submit(snap));
    }

    #[test]
    fn submit_increments_generation_on_change() {
        let m = NetworkMonitor::new();
        assert_eq!(m.generation(), 0);
        m.submit(fresh_iface("a", 1, 1));
        assert_eq!(m.generation(), 1);
        m.submit(fresh_iface("b", 2, 2));
        assert_eq!(m.generation(), 2);
        m.submit(fresh_iface("b", 2, 2)); // unchanged
        assert_eq!(m.generation(), 2);
    }

    #[test]
    fn submit_broadcasts_event_on_change() {
        let m = NetworkMonitor::new();
        let mut rx = m.subscribe();
        m.submit(fresh_iface("eth0", 3, 3));
        let evt = rx.try_recv().expect("event must fire");
        assert_eq!(evt.generation, 1);
        assert_eq!(evt.new_interface(), Some("eth0"));
        assert_eq!(evt.interface.v4_index, Some(3));
    }

    #[test]
    fn watcher_registration_is_singleton_and_updates_exclude() {
        let cell = OnceCell::new();
        let first_exclude = ExcludeList::from_plan_iface("tun-first");
        let (first, first_started) = register_watcher_exclude(&cell, first_exclude);
        assert!(first_started);

        let second_exclude = ExcludeList::from_plan_iface("tun-second");
        let (second, second_started) = register_watcher_exclude(&cell, second_exclude);
        assert!(!second_started);
        assert!(Arc::ptr_eq(&first, &second));

        let current = first.read();
        assert!(!current.names.contains("tun-first"));
        assert!(current.names.contains("tun-second"));
    }
}
