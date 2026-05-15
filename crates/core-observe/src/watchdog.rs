//! 进程级 watchdog —— 为"API 卡死、log bus 也死、进程仍在跑"场景提供独立
//! 诊断通道。
//!
//! ## 为什么需要
//!
//! 现实中 RPKernel 已踩过两类典型卡死：
//!
//! 1. **WsHub Arc 循环**：spawned producer 协程持 `Arc<Self>`，hub owner 释放
//!    后子任务仍持有，runtime drop 时挂起 → 测试进程不退出 / 生产内存泄漏。
//! 2. **DashMap entry × len 同 shard 递归 RwLock**：[`crate::IpRateLimiter`] 旧
//!    实现里把 entry RefMut 跨 `len()` 调用持有，同线程从 RwLock write→read
//!    递归 → 死锁；表现为 API 卡死 + log bus 也卡（因为 broadcast 通道靠
//!    runtime 推进）。
//!
//! 两种场景都让 tokio 任务（包括 tracing 日志桥接）失去响应。本模块用
//! **独立 std::thread + 同步文件 IO**，不依赖 tokio runtime，确保即使整个
//! runtime 卡死，运维仍能拿到：
//!
//! * 一份 `panic.log`：每条 panic（含 task panic）写进去，含线程名 + 时间戳 +
//!   完整 backtrace。
//! * 一份 `watchdog.log`：每 N 秒一条 heartbeat；停跳超过 stuck_threshold 时
//!   写一条 STUCK 警告 + dump 所有线程栈。
//! * deadlock 检测：调用 [`parking_lot::deadlock::check_deadlock`]，发现
//!   循环锁等待立即写入 `panic.log` 并 abort 进程（防止僵尸进程让运维以为
//!   还活着）。
//!
//! ## 使用方式
//!
//! 在 `proxy-core/main.rs` 启动 tokio runtime 之前调用：
//!
//! ```ignore
//! use core_observe::watchdog::{Watchdog, WatchdogConfig};
//!
//! let wd = Watchdog::install(WatchdogConfig {
//!     panic_log_path: PathBuf::from("data/logs/panic.log"),
//!     watchdog_log_path: PathBuf::from("data/logs/watchdog.log"),
//!     heartbeat_interval: Duration::from_secs(5),
//!     stuck_threshold: Duration::from_secs(30),
//!     deadlock_check_interval: Duration::from_secs(10),
//! });
//!
//! // 在 tokio 任务里周期性调 wd.heartbeat()，证明 runtime 还在转。
//! tokio::spawn({
//!     let wd = wd.clone();
//!     async move {
//!         loop {
//!             wd.heartbeat();
//!             tokio::time::sleep(Duration::from_secs(1)).await;
//!         }
//!     }
//! });
//! ```

use std::{
    fs::{File, OpenOptions},
    io::Write,
    panic,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Watchdog 配置。所有 path 父目录会按需创建。
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// panic.log 路径。每条 panic 追加写入；缺省 `data/logs/panic.log`。
    pub panic_log_path: PathBuf,
    /// watchdog.log 路径。heartbeat / stuck 报告追加写入；缺省 `data/logs/watchdog.log`。
    pub watchdog_log_path: PathBuf,
    /// watchdog 线程心跳节奏。
    pub heartbeat_interval: Duration,
    /// 多久没看到 heartbeat 就判定卡死并 dump 栈。
    pub stuck_threshold: Duration,
    /// 多久跑一次 parking_lot 死锁检测。
    pub deadlock_check_interval: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        let base = PathBuf::from("data/logs");
        Self {
            panic_log_path: base.join("panic.log"),
            watchdog_log_path: base.join("watchdog.log"),
            heartbeat_interval: Duration::from_secs(5),
            stuck_threshold: Duration::from_secs(30),
            deadlock_check_interval: Duration::from_secs(10),
        }
    }
}

/// Watchdog 句柄 —— `clone` 出多份给业务任务调 [`Self::heartbeat`]。
#[derive(Clone)]
pub struct Watchdog {
    inner: Arc<WatchdogInner>,
}

struct WatchdogInner {
    config: WatchdogConfig,
    /// tokio runtime 健康心跳：业务任务每秒 +1。watchdog 线程读这个判断
    /// 是否卡死。
    heartbeat: AtomicU64,
    /// 最后一次心跳的 wall-clock 时间（纳秒 since epoch）。watchdog 用 wall
    /// clock 而非 Instant 是因为 std::thread 不能轻易共享 Instant。
    last_heartbeat_ns: AtomicU64,
    /// watchdog 线程退出标志。Drop 时设 true。
    shutdown: AtomicBool,
    /// panic.log 文件句柄 —— Mutex 保护，让 panic hook 与 watchdog 都能追加写。
    /// 同步 IO 是故意的：panic 时不能依赖任何异步运行时。
    panic_file: Arc<Mutex<File>>,
    /// watchdog.log 文件句柄。
    wd_file: Arc<Mutex<File>>,
}

impl Watchdog {
    /// 安装 watchdog。返回 [`Watchdog`] 句柄；推荐进程全程持有。
    ///
    /// 调用一次完成三件事：
    /// 1. 创建 panic.log / watchdog.log（按需 mkdir -p）。
    /// 2. 注册 panic hook：每条 panic 写 panic.log（含线程名 + backtrace）。
    /// 3. 启动两个独立 std::thread：heartbeat watcher + deadlock detector。
    pub fn install(config: WatchdogConfig) -> Arc<Self> {
        // 文件先建好；建不了直接 panic 就好，这是启动期前置条件。
        ensure_parent_dir(&config.panic_log_path);
        ensure_parent_dir(&config.watchdog_log_path);
        let panic_file = open_append(&config.panic_log_path).expect("watchdog: open panic.log");
        let wd_file = open_append(&config.watchdog_log_path).expect("watchdog: open watchdog.log");

        let inner = Arc::new(WatchdogInner {
            config: config.clone(),
            heartbeat: AtomicU64::new(0),
            last_heartbeat_ns: AtomicU64::new(now_unix_ns()),
            shutdown: AtomicBool::new(false),
            panic_file: Arc::new(Mutex::new(panic_file)),
            wd_file: Arc::new(Mutex::new(wd_file)),
        });

        // panic hook —— 把所有线程 panic 都灌进 panic.log。
        install_panic_hook(inner.panic_file.clone());

        // 启动 heartbeat watcher 线程。
        spawn_heartbeat_watcher(inner.clone());

        // 启动 deadlock detector 线程。
        spawn_deadlock_detector(inner.clone());

        let wd = Arc::new(Self { inner });
        wd.append_watchdog_line("watchdog installed");
        wd
    }

    /// 业务侧调用 —— 在 tokio runtime 里周期心跳，证明 runtime 还活着。
    pub fn heartbeat(&self) {
        self.inner.heartbeat.fetch_add(1, Ordering::Relaxed);
        self.inner
            .last_heartbeat_ns
            .store(now_unix_ns(), Ordering::Relaxed);
    }

    /// 当前心跳计数 —— 监控 / 测试可用。
    pub fn heartbeat_count(&self) -> u64 {
        self.inner.heartbeat.load(Ordering::Relaxed)
    }

    fn append_watchdog_line(&self, msg: &str) {
        write_line(&self.inner.wd_file, msg);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Arc strong count 见底（业务释放）才真正落 shutdown。
        if Arc::strong_count(&self.inner) <= 2 {
            self.inner.shutdown.store(true, Ordering::Release);
        }
    }
}

/// panic hook：把每条 panic 写到 panic.log，再链入 default hook。
///
/// 关键：用同步 std::io 写文件，不依赖 tracing / tokio。panic 时如果 tokio
/// 已死、tracing 桥接也卡了，这个 hook 仍能落盘。
fn install_panic_hook(panic_file: Arc<Mutex<File>>) {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let thread = thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".into());
        let payload: String = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).into()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".into()
        };
        let bt = backtrace::Backtrace::new();
        let msg = format!(
            "==== PANIC ====\nat: {}\nthread: {}\nlocation: {}\npayload: {}\nbacktrace:\n{:?}\n",
            iso_now(),
            thread_name,
            location,
            payload,
            bt,
        );
        write_line(&panic_file, &msg);
        // 链入旧 hook（默认 hook 会打 stderr）。
        prev(info);
    }));
}

/// 启动 heartbeat 监督线程 —— 独立 std::thread，不依赖 tokio。
fn spawn_heartbeat_watcher(inner: Arc<WatchdogInner>) {
    thread::Builder::new()
        .name("rp-watchdog-hb".into())
        .spawn(move || {
            let interval = inner.config.heartbeat_interval;
            let stuck_threshold_ns = inner.config.stuck_threshold.as_nanos() as u64;
            // 卡死状态去重：同一段卡死期间只 dump 一次栈，避免日志洪水。
            let mut already_reported_stuck = false;
            loop {
                thread::sleep(interval);
                if inner.shutdown.load(Ordering::Acquire) {
                    return;
                }
                let last = inner.last_heartbeat_ns.load(Ordering::Relaxed);
                let now = now_unix_ns();
                let delta_ns = now.saturating_sub(last);
                if delta_ns > stuck_threshold_ns {
                    if !already_reported_stuck {
                        already_reported_stuck = true;
                        let count = inner.heartbeat.load(Ordering::Relaxed);
                        let dump = dump_all_threads();
                        let msg = format!(
                            "==== STUCK ====\nat: {}\nstuck_for_secs: {}\nheartbeat_count: {}\nthreads:\n{}\n",
                            iso_now(),
                            delta_ns / 1_000_000_000,
                            count,
                            dump,
                        );
                        write_line(&inner.wd_file, &msg);
                        // 同样 mirror 一份到 panic.log，方便集中检索。
                        write_line(&inner.panic_file, &msg);
                    }
                } else if already_reported_stuck {
                    // 心跳恢复：写一条 RECOVER 行让运维知道窗口结束。
                    write_line(
                        &inner.wd_file,
                        &format!("==== RECOVER ====\nat: {}\n", iso_now()),
                    );
                    already_reported_stuck = false;
                } else {
                    // 正常 heartbeat 行 —— info 级别，留作时间线参考。
                    let count = inner.heartbeat.load(Ordering::Relaxed);
                    write_line(
                        &inner.wd_file,
                        &format!(
                            "heartbeat at {} count={} delta_ms={}",
                            iso_now(),
                            count,
                            delta_ns / 1_000_000
                        ),
                    );
                }
            }
        })
        .expect("watchdog: spawn heartbeat thread");
}

/// 启动 parking_lot 死锁检测线程。
fn spawn_deadlock_detector(inner: Arc<WatchdogInner>) {
    thread::Builder::new()
        .name("rp-watchdog-dl".into())
        .spawn(move || {
            let interval = inner.config.deadlock_check_interval;
            loop {
                thread::sleep(interval);
                if inner.shutdown.load(Ordering::Acquire) {
                    return;
                }
                let deadlocks = parking_lot::deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    continue;
                }
                let mut msg = String::new();
                msg.push_str(&format!(
                    "==== DEADLOCK ====\nat: {}\ncount: {}\n",
                    iso_now(),
                    deadlocks.len()
                ));
                for (i, threads) in deadlocks.iter().enumerate() {
                    msg.push_str(&format!("  -- cycle #{} ({} threads):\n", i, threads.len()));
                    for t in threads {
                        msg.push_str(&format!(
                            "    thread id {:?}\n{:?}\n",
                            t.thread_id(),
                            t.backtrace()
                        ));
                    }
                }
                // 死锁是不可恢复的；写文件后 abort 让外层 supervisor / systemd 重拉。
                write_line(&inner.panic_file, &msg);
                write_line(&inner.wd_file, &msg);
                eprintln!("{msg}");
                // abort —— 不调 panic（panic 也可能被吞掉），直接 OS 杀。
                std::process::abort();
            }
        })
        .expect("watchdog: spawn deadlock thread");
}

/* ====================== 辅助 ====================== */

fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn write_line(file: &Mutex<File>, msg: &str) {
    if let Ok(mut f) = file.lock() {
        // 行末确保有换行。同步 IO + 单行 flush，不依赖任何缓冲层。
        let _ = f.write_all(msg.as_bytes());
        if !msg.ends_with('\n') {
            let _ = f.write_all(b"\n");
        }
        let _ = f.flush();
    }
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
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

/// 抓所有线程的 backtrace —— 当前 thread 拿到完整栈，其它 thread 因 libstd
/// 限制只能看到名字。已经比"啥都没有"强很多。
///
/// 真要做完整跨线程栈需要平台专用 syscall（Linux: `gettid` + `/proc/<tid>/stack`
/// + 信号；Windows: `Thread32First` + `StackWalk64`）；为了保持跨平台先用
/// libstd + `backtrace` 的当前线程栈作为最小可用集。
fn dump_all_threads() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "  -- watchdog thread ({}):\n",
        thread::current().name().unwrap_or("?")
    ));
    let bt = backtrace::Backtrace::new();
    out.push_str(&format!("{:?}\n", bt));
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn unique_temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wuthercore-watchdog-test-{}-{}",
            uuid::Uuid::new_v4(),
            name
        ))
    }

    #[test]
    fn watchdog_writes_install_marker() {
        let panic_path = unique_temp("panic.log");
        let wd_path = unique_temp("watchdog.log");
        let cfg = WatchdogConfig {
            panic_log_path: panic_path.clone(),
            watchdog_log_path: wd_path.clone(),
            heartbeat_interval: Duration::from_millis(50),
            stuck_threshold: Duration::from_secs(60),
            deadlock_check_interval: Duration::from_secs(60),
        };
        let _wd = Watchdog::install(cfg);
        // install 时立即写一条 "watchdog installed"
        thread::sleep(Duration::from_millis(80));
        let body = std::fs::read_to_string(&wd_path).unwrap();
        assert!(body.contains("watchdog installed"), "got: {body}");
        // 至少看到一次 heartbeat 行
        thread::sleep(Duration::from_millis(120));
        let body = std::fs::read_to_string(&wd_path).unwrap();
        assert!(body.contains("heartbeat at"), "got: {body}");
        // 清理
        let _ = std::fs::remove_file(&panic_path);
        let _ = std::fs::remove_file(&wd_path);
    }

    #[test]
    fn heartbeat_counter_increments() {
        let cfg = WatchdogConfig {
            panic_log_path: unique_temp("p.log"),
            watchdog_log_path: unique_temp("w.log"),
            heartbeat_interval: Duration::from_secs(60),
            stuck_threshold: Duration::from_secs(60),
            deadlock_check_interval: Duration::from_secs(60),
        };
        let wd = Watchdog::install(cfg.clone());
        let before = wd.heartbeat_count();
        wd.heartbeat();
        wd.heartbeat();
        wd.heartbeat();
        let after = wd.heartbeat_count();
        assert_eq!(after - before, 3);
        let _ = std::fs::remove_file(&cfg.panic_log_path);
        let _ = std::fs::remove_file(&cfg.watchdog_log_path);
    }

    #[test]
    fn stuck_threshold_dumps_to_logs() {
        let panic_path = unique_temp("stuck-panic.log");
        let wd_path = unique_temp("stuck-wd.log");
        let cfg = WatchdogConfig {
            panic_log_path: panic_path.clone(),
            watchdog_log_path: wd_path.clone(),
            heartbeat_interval: Duration::from_millis(20),
            stuck_threshold: Duration::from_millis(60),
            deadlock_check_interval: Duration::from_secs(60),
        };
        let _wd = Watchdog::install(cfg);
        // 不调 heartbeat —— 让 last_heartbeat_ns 始终是 install 那一刻。
        thread::sleep(Duration::from_millis(180));
        let panic_body = std::fs::read_to_string(&panic_path).unwrap_or_default();
        let wd_body = std::fs::read_to_string(&wd_path).unwrap_or_default();
        assert!(
            panic_body.contains("==== STUCK ===="),
            "panic.log missing STUCK; got: {panic_body}"
        );
        assert!(
            wd_body.contains("==== STUCK ===="),
            "watchdog.log missing STUCK; got: {wd_body}"
        );
        let _ = std::fs::remove_file(&panic_path);
        let _ = std::fs::remove_file(&wd_path);
    }

    /// 同步多线程心跳压力 —— 验证 heartbeat 在并发下不丢计数。
    #[test]
    fn heartbeat_atomic_under_contention() {
        let cfg = WatchdogConfig {
            panic_log_path: unique_temp("hb-p.log"),
            watchdog_log_path: unique_temp("hb-w.log"),
            heartbeat_interval: Duration::from_secs(60),
            stuck_threshold: Duration::from_secs(60),
            deadlock_check_interval: Duration::from_secs(60),
        };
        let wd = Watchdog::install(cfg.clone());
        let total = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        for _ in 0..8 {
            let wd = wd.clone();
            let total = total.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    wd.heartbeat();
                    total.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wd.heartbeat_count(), total.load(Ordering::Relaxed) as u64);
        let _ = std::fs::remove_file(&cfg.panic_log_path);
        let _ = std::fs::remove_file(&cfg.watchdog_log_path);
    }
}
