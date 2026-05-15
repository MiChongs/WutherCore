//! WebSocket 广播中心 —— 把"每客户端独立 1Hz tick"压缩为"全局单 producer +
//! 多 subscriber"。
//!
//! ## 为什么需要
//!
//! 旧实现每个 WS 客户端持有独立的 `tokio::time::interval`：每秒各自调
//! `connection_manager_traffic(&s)` / `connections_snapshot(&s)` 等，N 个
//! dashboard 同时连接 → N×snapshot/sec。在 1 万连接 + 5 dashboard 的工程化
//! 场景里，仅 `/connections` 一个端点每秒会做 5 次完整的 manager_snapshot +
//! JSON 序列化（每次 ~1 ms），仅 broadcast 这一项就吃 5% CPU。
//!
//! 现在改为：
//!
//! * 每个端点一个 [`WsHub`]：内部保留 [`tokio::sync::watch`] 通道。
//! * 第一个 subscriber 触发 producer 协程（lazy start），1Hz 调一次 producer
//!   闭包并把序列化字符串写入 watch；之后所有 subscriber 共享同一份 String。
//! * Subscriber 用 `watch::changed()` 等待新值；`borrow_and_update().clone()`
//!   拿到当前最新（首次连接立即得到、不用等下一拍）。
//! * Producer 闭包只捕获自己需要的 `Arc<...>`（避免捕获 `NativeState` 形成
//!   `Arc` 循环）。
//!
//! ## 生命周期 / 防泄漏（**重要**）
//!
//! 旧实现 `tokio::spawn(async move { me.run().await })` 把 `Arc<Self>` 强绑到
//! 任务内，造成 `Arc` 循环：hub 永远不会析构，子任务永远不会退出，进程退出
//! 前一直占内存；测试场景里多个 #[tokio::test] 串行跑时，第二个测试的
//! runtime drop 撞到第一个测试遗留的孤儿任务，整体卡死。
//!
//! 现在：
//!
//! * 子任务只持 [`Weak<Self>`]；每拍 `weak.upgrade()` 一下；upgrade 失败 →
//!   hub 已被 owner 释放 → 立即退出。
//! * 同时探测 `watch::Sender::is_closed()`：所有 receiver 都掉了之后，
//!   producer 进入"低成本心跳"分支，每 5×interval 才检查一次（不再 produce
//!   payload），避免 idle 时仍 1Hz 调 producer 闭包。新 subscriber 来了之后
//!   自动恢复 1Hz。
//! * 析构 [`WsHub`] 时通过 `shutdown` 一次性 cancel：[`AtomicBool`] 触发
//!   下一拍 break；测试场景里也能立刻收尾。
//!
//! ## 慢消费者保护
//!
//! `watch` 不堆消息：subscriber 慢的话只会丢掉中间帧，永远只看到最新的。
//! 与 `broadcast` 通道相比，没有"队列爆掉 → producer 拒绝写入 → 全员 lag"
//! 的风险，更适合 1Hz 监控类场景。

use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;

/// 单个 WS 端点的广播 hub。
pub struct WsHub {
    tx: watch::Sender<String>,
    started: AtomicBool,
    shutdown: AtomicBool,
    interval: Duration,
    /// 不可变：构造期一次性传入。`Box<dyn Fn>` 让我们能在 [`WsHubs`] 里收纳
    /// 不同 producer 的多个 hub。
    producer: Box<dyn Fn() -> String + Send + Sync>,
    /// 端点名 —— 仅用于 tracing 调试。
    label: &'static str,
}

impl WsHub {
    pub fn new<F>(label: &'static str, interval: Duration, producer: F) -> Arc<Self>
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        let (tx, _) = watch::channel(String::new());
        Arc::new(Self {
            tx,
            started: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            interval,
            producer: Box::new(producer),
            label,
        })
    }

    /// 订阅；首次订阅触发 producer 协程。
    pub fn subscribe(self: &Arc<Self>) -> watch::Receiver<String> {
        if !self.started.swap(true, Ordering::AcqRel) {
            // 子任务只拿 Weak —— 父 hub 析构后下一拍立即退出，不形成循环引用。
            let weak = Arc::downgrade(self);
            let label = self.label;
            tokio::spawn(async move {
                run(weak, label).await;
            });
        }
        self.tx.subscribe()
    }

    /// 立即同步取一份当前快照（不触发 producer 协程；为 HTTP 非 WS 路径用）。
    /// 如果还没有快照（hub 从未启动 producer），返回 None。
    pub fn current(&self) -> Option<String> {
        let s = self.tx.borrow();
        if s.is_empty() { None } else { Some(s.clone()) }
    }

    /// 强制就地刷新（同步，绕过 ticker）。HTTP 非 WS 调用 `/traffic`、
    /// `/memory` 等聚合 GET 时用，让响应永远反映“最新一拍”而不是 hub 上一拍。
    pub fn build_now(&self) -> String {
        let payload = (self.producer)();
        // 也写回 watch，让 WS subscriber 能少等一个 tick 拿到最新。
        let _ = self.tx.send(payload.clone());
        payload
    }

    /// 显式关停 —— 测试场景或优雅停机时调用，下一拍 producer 立刻 break。
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for WsHub {
    fn drop(&mut self) {
        // hub 析构 → 立即标记 shutdown，让 spawned 任务下一拍跳出 loop。
        // 另外 weak.upgrade() 在下一拍也会失败（self 已 drop），双保险。
        self.shutdown.store(true, Ordering::Release);
    }
}

/// Producer 协程实体 —— 持 [`Weak<WsHub>`]，每拍 upgrade 检查父 hub 是否还在。
/// 把 `run` 抽成自由函数（而不是 `WsHub` 的方法）是因为 Drop 顺序：函数体里
/// 不再隐式持 `Arc<Self>`，只在 upgrade 成功时短暂持有，确保 hub 引用计数能
/// 真正归零。
async fn run(weak: Weak<WsHub>, label: &'static str) {
    // 首拍立刻 produce，让早期连接的 subscriber 不用等 interval。
    let interval = match weak.upgrade() {
        Some(hub) => {
            let payload = (hub.producer)();
            let _ = hub.tx.send(payload);
            hub.interval
        }
        None => return,
    };

    let mut tick = tokio::time::interval(interval);
    // tick.tick() 第一次立即返回 —— 跳过它免得连续 tick 两次。
    tick.tick().await;
    // missed-tick 行为 = Skip：tick 落后时（producer 偶尔慢）合并到下一拍，
    // 不补打缺失的 tick。监控类场景永远只关心“最新值”。
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // idle backoff：所有 subscriber 都掉了之后，跳过 produce 节省 CPU；
    // 每 idle_skip_max 个空拍探测一次（仍走 watch idle，不动 producer）。
    let mut idle_skip = 0u32;
    const IDLE_SKIP_MAX: u32 = 5;
    loop {
        tick.tick().await;
        // upgrade 失败 = hub 已 drop = 父 owner 不再持有 = 立即退出。
        let Some(hub) = weak.upgrade() else {
            tracing::debug!(target: "api::ws_hub", label, "owner dropped; producer exiting");
            return;
        };
        // 显式 shutdown（owner 调 shutdown() 或 hub Drop 触发）= 立即退出。
        if hub.shutdown.load(Ordering::Acquire) {
            tracing::debug!(target: "api::ws_hub", label, "shutdown signalled; producer exiting");
            return;
        }
        // 没 subscriber 时进入低成本心跳：跳过 produce，节省 CPU。
        if hub.tx.is_closed() {
            idle_skip = idle_skip.saturating_add(1);
            if idle_skip < IDLE_SKIP_MAX {
                continue;
            }
            // idle_skip_max 拍后再探一次，避免长 idle 也烧 CPU。
            idle_skip = 0;
            continue;
        }
        idle_skip = 0;
        let payload = (hub.producer)();
        // 大对象送 watch 时，watch 的内部 Mutex 会序列化 readers；为了
        // 避免 producer 阻塞所有 readers，先 send 一次（写时拷贝）。
        let _ = hub.tx.send(payload);
        tracing::trace!(target: "api::ws_hub", label, "tick");
    }
}

/// 三个高频端点共享一个 [`WsHubs`]。NativeState 持 `Arc<WsHubs>`。
///
/// `Drop` 时把所有子 hub 也 shutdown —— 即使外部多持了一份 `Arc<WsHub>`，
/// producer 协程也会在下一拍退出，避免 NativeState 已落但 hub 协程还在跑
/// 的"幽灵任务"现象。
pub struct WsHubs {
    pub traffic: Arc<WsHub>,
    pub memory: Arc<WsHub>,
    pub connections: Arc<WsHub>,
}

impl WsHubs {
    /// 工厂：捕获 producer 需要的最小 Arc 集合（避免 NativeState ↔ WsHubs
    /// 形成循环引用）。
    pub fn new(runtime: Arc<core_runtime::Runtime>, connections_interval_ms: u64) -> Arc<Self> {
        let traffic_runtime = runtime.clone();
        let traffic = WsHub::new("traffic", Duration::from_secs(1), move || {
            let (up, down) = traffic_runtime.connections.now();
            serde_json::to_string(&serde_json::json!({"up": up, "down": down}))
                .unwrap_or_else(|_| String::from("{}"))
        });

        let memory_runtime = runtime.clone();
        let memory = WsHub::new("memory", Duration::from_secs(1), move || {
            let v = memory_runtime.metrics.clash_memory();
            serde_json::to_string(&v).unwrap_or_else(|_| String::from("{}"))
        });

        // /connections 默认 1000 ms；通过参数允许调慢以减负担（或调快做调试）。
        let conn_runtime = runtime.clone();
        let conn_interval = Duration::from_millis(connections_interval_ms.max(200));
        let connections = WsHub::new("connections", conn_interval, move || {
            serialize_connections(&conn_runtime)
        });

        Arc::new(Self {
            traffic,
            memory,
            connections,
        })
    }
}

impl Drop for WsHubs {
    fn drop(&mut self) {
        // 显式 shutdown 三个子 hub：即使外部还多持一份 Arc<WsHub>，spawn 任务
        // 下一拍也会因 shutdown 标记 break。
        self.traffic.shutdown();
        self.memory.shutdown();
        self.connections.shutdown();
    }
}

/// 把 `manager_snapshot` 直接序列化成与 `compat::connections_snapshot` 等价
/// 的 JSON 文本。复制一份在这里是为了让 producer 闭包不依赖 NativeState（避免
/// 循环引用）。
fn serialize_connections(runtime: &Arc<core_runtime::Runtime>) -> String {
    let manager = runtime.connections.manager_snapshot();
    let conns: Vec<serde_json::Value> = manager
        .connections
        .into_iter()
        .map(|conn| {
            serde_json::json!({
                "id": conn.id,
                "metadata": conn.metadata,
                "upload": conn.upload,
                "download": conn.download,
                "start": iso8601_secs(conn.start),
                "chains": conn.chains,
                "providerChains": conn.provider_chains,
                "rule": conn.rule,
                "rulePayload": conn.rule_payload,
                "maxUploadRate": conn.max_upload_rate,
                "maxDownloadRate": conn.max_download_rate,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "downloadTotal": manager.download_total,
        "uploadTotal": manager.upload_total,
        "connections": conns,
        "memory": manager.memory,
    }))
    .unwrap_or_else(|_| String::from("{}"))
}

fn iso8601_secs(ts_secs: u64) -> String {
    // 与 compat::iso8601 同算法；这里独立一份避免跨模块依赖（compat::iso8601
    // 是 module-private）。
    let days = (ts_secs / 86_400) as i64;
    let secs_of_day = (ts_secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, minute, second
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn lazy_start_only_after_first_subscribe() {
        let n = Arc::new(AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("test", Duration::from_millis(20), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("x")
        });
        // 没 subscribe 时 producer 不跑。
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(n.load(Ordering::Relaxed), 0, "producer should be lazy");

        let _rx = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let count = n.load(Ordering::Relaxed);
        assert!(count >= 2, "producer must tick at least 2 times in 80ms");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multiple_subscribers_share_one_producer() {
        let n = Arc::new(AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("test", Duration::from_millis(15), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("x")
        });
        let _r1 = hub.subscribe();
        let _r2 = hub.subscribe();
        let _r3 = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(60)).await;
        // 3 个 subscriber 不会触发 3 个 producer。
        let count = n.load(Ordering::Relaxed);
        assert!(
            count >= 2 && count <= 6,
            "expected 2..=6 ticks, got {count}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watch_receiver_sees_latest_immediately() {
        let hub = WsHub::new("test", Duration::from_millis(10), || {
            String::from("payload")
        });
        let mut rx = hub.subscribe();
        // 等 producer 至少一次 tick。
        tokio::time::sleep(Duration::from_millis(40)).await;
        let v = rx.borrow_and_update().clone();
        assert_eq!(v, "payload");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn producer_exits_when_hub_dropped() {
        // 关键回归：旧实现 producer 持 Arc<Self> → hub 永不析构 → 任务永不退出 →
        // tokio runtime drop 时挂起。新实现持 Weak<Self>，hub 一 drop 立即退出。
        let n = Arc::new(AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("dropme", Duration::from_millis(10), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("x")
        });
        let _rx = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let before_drop = n.load(Ordering::Relaxed);
        assert!(before_drop >= 2);

        drop(_rx);
        drop(hub);
        // 给 producer 几拍时间走完 Drop → shutdown → 下一拍 break 流程
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stable = n.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after = n.load(Ordering::Relaxed);
        assert_eq!(
            stable, after,
            "producer must stop ticking after hub drop (stable={stable}, after={after})"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_backoff_pauses_producer_when_no_subscribers() {
        // 所有 subscriber 都掉了之后，producer 应进入 idle 模式，不再 produce
        // payload；新 subscriber 加入又恢复。
        let n = Arc::new(AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("idle", Duration::from_millis(10), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("p")
        });
        let rx = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let active = n.load(Ordering::Relaxed);
        assert!(active >= 2);
        drop(rx);
        // idle 后再观察 80 ms，producer 至少进入低速节奏（IDLE_SKIP_MAX × 10ms 内
        // 一拍真 produce 都没有）
        tokio::time::sleep(Duration::from_millis(80)).await;
        let after_idle = n.load(Ordering::Relaxed);
        // active 之后应至多多 1 次 produce（idle 进入前那拍可能仍 produce）
        assert!(
            after_idle <= active + 1,
            "idle backoff failed: active={active}, after_idle={after_idle}"
        );
        // 新 subscriber 加入 → 立即恢复 produce
        let _rx2 = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let recovered = n.load(Ordering::Relaxed);
        assert!(
            recovered > after_idle,
            "subscriber wakeup failed: after_idle={after_idle}, recovered={recovered}"
        );
    }
}
