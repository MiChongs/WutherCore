use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

#[derive(Debug)]
pub struct Metrics {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub dns_queries: AtomicU64,
    pub route_decisions: AtomicU64,

    /// 上一次采样时刻 + 当时累计字节，用于算 up/down 速率（字节/秒），
    /// 兼容 Clash 的 `/traffic` WebSocket payload `{up, down}` 含义。
    last: Mutex<RateState>,
}

#[derive(Debug)]
struct RateState {
    when: Instant,
    bytes_up: u64,
    bytes_down: u64,
    last_up_rate: u64,
    last_down_rate: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            route_decisions: AtomicU64::new(0),
            last: Mutex::new(RateState {
                when: Instant::now(),
                bytes_up: 0,
                bytes_down: 0,
                last_up_rate: 0,
                last_down_rate: 0,
            }),
        }
    }
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_connection(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connection(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_dns(&self) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_route(&self) {
        self.route_decisions.fetch_add(1, Ordering::Relaxed);
    }

    /// 计算自上次调用以来的瞬时速率（字节/秒）；至少间隔 `min_ms`，否则返回上次值。
    pub fn sample_rate(&self, min_ms: u128) -> (u64, u64) {
        let now = Instant::now();
        let mut g = self.last.lock();
        let dt = now.saturating_duration_since(g.when).as_millis();
        let cur_up = self.bytes_up.load(Ordering::Relaxed);
        let cur_down = self.bytes_down.load(Ordering::Relaxed);
        if dt < min_ms {
            return (g.last_up_rate, g.last_down_rate);
        }
        let dt_secs = (dt as f64) / 1000.0;
        let up_rate = if dt_secs > 0.0 {
            (((cur_up.saturating_sub(g.bytes_up)) as f64) / dt_secs) as u64
        } else {
            0
        };
        let down_rate = if dt_secs > 0.0 {
            (((cur_down.saturating_sub(g.bytes_down)) as f64) / dt_secs) as u64
        } else {
            0
        };
        g.when = now;
        g.bytes_up = cur_up;
        g.bytes_down = cur_down;
        g.last_up_rate = up_rate;
        g.last_down_rate = down_rate;
        (up_rate, down_rate)
    }

    /// Clash 兼容 `/traffic` 单包 payload。
    pub fn clash_traffic(&self) -> serde_json::Value {
        let (up, down) = self.sample_rate(500);
        serde_json::json!({ "up": up, "down": down })
    }

    /// Clash 兼容 `/memory` 单包 payload —— RSS（字节，best-effort）。
    pub fn clash_memory(&self) -> serde_json::Value {
        let inuse = current_rss_bytes();
        serde_json::json!({ "inuse": inuse, "oslimit": 0u64 })
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "bytes_up": self.bytes_up.load(Ordering::Relaxed),
            "bytes_down": self.bytes_down.load(Ordering::Relaxed),
            "connections_total": self.connections_total.load(Ordering::Relaxed),
            "connections_active": self.connections_active.load(Ordering::Relaxed),
            "dns_queries": self.dns_queries.load(Ordering::Relaxed),
            "route_decisions": self.route_decisions.load(Ordering::Relaxed),
        })
    }
}

/// 取当前进程 RSS（字节），跨平台 best-effort。
pub fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()) {
                let page = page_size();
                return pages.saturating_mul(page);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // mach_task_basic_info 需 unsafe；core-observe 是 forbid_unsafe，跳过。
    }
    0
}

#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    // sysconf(_SC_PAGESIZE) 大多数 Linux 是 4096。
    4096
}
