use std::{
    collections::VecDeque,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use core_store::{HistoryEntry, NodeStatsBlob};
use parking_lot::RwLock;

const HISTORY_CAP: usize = 8;

/// 单节点的运行时统计 —— 用于评分。
#[derive(Debug)]
pub struct NodeStats {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default, Clone)]
struct Inner {
    samples: u32,
    success: f64,
    /// EWMA 成功率（0..=1）
    success_ewma: f64,
    p50_latency_ms: f64,
    jitter_ms: f64,
    timeout_rate: f64,
    last_failure: Option<Instant>,
    active_conn: u32,
    /// 最近一次失败原因（人类可读）。
    last_error: Option<String>,
    last_used: Option<Instant>,
    /// URLTest 历史（最近 8 条；env=Clash dashboard 使用）。
    history: VecDeque<HistoryEntry>,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner {
                success_ewma: 0.5,
                p50_latency_ms: 200.0,
                ..Default::default()
            }),
        }
    }
}

impl NodeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self, latency: Duration) {
        let mut g = self.inner.write();
        g.samples = g.samples.saturating_add(1);
        let lat = latency.as_secs_f64() * 1000.0;
        g.p50_latency_ms = ewma(g.p50_latency_ms, lat, 0.3);
        g.success_ewma = ewma(g.success_ewma, 1.0, 0.2);
        g.success = ewma(g.success, 1.0, 0.2);
        g.timeout_rate = ewma(g.timeout_rate, 0.0, 0.2);
        g.last_used = Some(Instant::now());
    }

    /// URLTest 探测专用：与 record_success 相同效果，但保证写一条 history。
    pub fn record_probe(&self, latency: Duration) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let lat_ms = latency.as_millis().min(u32::MAX as u128) as u32;
        let mut g = self.inner.write();
        g.samples = g.samples.saturating_add(1);
        let lat = latency.as_secs_f64() * 1000.0;
        g.p50_latency_ms = ewma(g.p50_latency_ms, lat, 0.3);
        g.success_ewma = ewma(g.success_ewma, 1.0, 0.2);
        g.success = ewma(g.success, 1.0, 0.2);
        g.timeout_rate = ewma(g.timeout_rate, 0.0, 0.2);
        g.last_used = Some(Instant::now());
        g.history.push_back(HistoryEntry {
            time_ms: now_ms,
            delay_ms: lat_ms,
        });
        while g.history.len() > HISTORY_CAP {
            g.history.pop_front();
        }
    }

    /// URLTest 探测失败：写 delay_ms = 0 的失败标记。
    pub fn record_probe_failure(&self, reason: impl Into<String>) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let r = reason.into();
        let mut g = self.inner.write();
        g.samples = g.samples.saturating_add(1);
        g.success_ewma = ewma(g.success_ewma, 0.0, 0.2);
        g.success = ewma(g.success, 0.0, 0.2);
        g.timeout_rate = ewma(g.timeout_rate, 1.0, 0.2);
        g.last_failure = Some(Instant::now());
        g.last_error = Some(r);
        g.history.push_back(HistoryEntry {
            time_ms: now_ms,
            delay_ms: 0,
        });
        while g.history.len() > HISTORY_CAP {
            g.history.pop_front();
        }
    }

    /// 拷贝 history（按插入顺序，最近的在末尾）。
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.inner.read().history.iter().cloned().collect()
    }

    pub fn record_failure(&self, reason: impl Into<String>) {
        let mut g = self.inner.write();
        g.samples = g.samples.saturating_add(1);
        g.success_ewma = ewma(g.success_ewma, 0.0, 0.2);
        g.success = ewma(g.success, 0.0, 0.2);
        g.timeout_rate = ewma(g.timeout_rate, 1.0, 0.2);
        g.last_failure = Some(Instant::now());
        g.last_error = Some(reason.into());
    }

    pub fn open_connection(&self) {
        let mut g = self.inner.write();
        g.active_conn = g.active_conn.saturating_add(1);
    }
    pub fn close_connection(&self) {
        let mut g = self.inner.write();
        g.active_conn = g.active_conn.saturating_sub(1);
    }

    pub fn snapshot(&self) -> NodeStatSnapshot {
        let g = self.inner.read();
        NodeStatSnapshot {
            samples: g.samples,
            success_rate: g.success_ewma,
            p50_latency_ms: g.p50_latency_ms,
            jitter_ms: g.jitter_ms,
            timeout_rate: g.timeout_rate,
            active_conn: g.active_conn,
            cooldown: g
                .last_failure
                .map(|t| t.elapsed())
                .unwrap_or(Duration::from_secs(3600)),
            last_error: g.last_error.clone(),
        }
    }

    /// 序列化为持久化格式。
    pub fn to_blob(&self) -> NodeStatsBlob {
        let g = self.inner.read();
        NodeStatsBlob {
            samples: g.samples,
            success_ewma: g.success_ewma,
            p50_latency_ms: g.p50_latency_ms,
            jitter_ms: g.jitter_ms,
            timeout_rate: g.timeout_rate,
            last_failure_secs: g.last_failure.and_then(|t| {
                let now_inst = Instant::now();
                let now_sys = SystemTime::now();
                let dur = now_inst.checked_duration_since(t)?;
                let sys = now_sys.checked_sub(dur)?;
                sys.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
            }),
            last_error: g.last_error.clone(),
            last_used_secs: g.last_used.and_then(|t| {
                let now_inst = Instant::now();
                let now_sys = SystemTime::now();
                let dur = now_inst.checked_duration_since(t)?;
                let sys = now_sys.checked_sub(dur)?;
                sys.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
            }),
            history: g.history.iter().cloned().collect(),
        }
    }

    /// 从持久化格式恢复（启动时使用）。
    pub fn from_blob(b: &NodeStatsBlob) -> Self {
        let now_inst = Instant::now();
        let now_sys = SystemTime::now();
        let restore_instant = |secs: Option<u64>| -> Option<Instant> {
            let s = secs?;
            let then = UNIX_EPOCH.checked_add(Duration::from_secs(s))?;
            let elapsed = now_sys.duration_since(then).ok()?;
            now_inst.checked_sub(elapsed)
        };
        Self {
            inner: RwLock::new(Inner {
                samples: b.samples,
                success: b.success_ewma,
                success_ewma: b.success_ewma,
                p50_latency_ms: b.p50_latency_ms,
                jitter_ms: b.jitter_ms,
                timeout_rate: b.timeout_rate,
                last_failure: restore_instant(b.last_failure_secs),
                active_conn: 0,
                last_error: b.last_error.clone(),
                last_used: restore_instant(b.last_used_secs),
                history: b.history.iter().cloned().collect(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeStatSnapshot {
    pub samples: u32,
    pub success_rate: f64,
    pub p50_latency_ms: f64,
    pub jitter_ms: f64,
    pub timeout_rate: f64,
    pub active_conn: u32,
    pub cooldown: Duration,
    pub last_error: Option<String>,
}

fn ewma(prev: f64, sample: f64, alpha: f64) -> f64 {
    prev * (1.0 - alpha) + sample * alpha
}
