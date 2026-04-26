//! Clash 兼容连接表 —— 1:1 对齐 mihomo `tunnel/statistic`。
//!
//! ## 数据模型
//! * [`ConnectionMeta`] —— 与 mihomo `constant.Metadata` 字段一一对应，能直接
//!   被 serde 序列化成 dashboard 期望的 metadata 子对象（包含 sourceIP /
//!   sourcePort / destinationIP / destinationPort / inboundIP / inboundPort /
//!   inboundName / inboundUser / host / dnsMode / process / processPath /
//!   specialProxy / specialRules / sniffHost / uuid / chains / rule /
//!   rulePayload）。
//! * [`ConnectionEntry`] —— 一条活跃连接的完整状态：immutable meta + 实时
//!   累计字节数（Arc<AtomicU64>，由 splice 路径在 copy loop 内自增）+ 取消
//!   信号（Arc<Notify>，DELETE /connections/:id 触发后让数据流主动 shutdown）+
//!   上一秒采样（用于计算 maxUploadRate / maxDownloadRate bps）。
//! * [`ConnectionGuard`] —— RAII：splice 任务持有 guard，drop 时自动从表移除，
//!   即便 panic / early-return 也不会漏关。
//!
//! ## DELETE 语义
//! * `close(id)` / `close_all()` 都会 **先** 调 `cancel.notify_waiters()` 再
//!   从表里 remove。这样即使 splice 任务还在 select! 里等数据，也能立刻收到
//!   取消信号开始 shutdown，而不是只在表里消失却继续传字节。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::Notify;
use uuid::Uuid;

/// 连接 metadata —— 完整 mihomo Metadata 字段集，serde 序列化后即 dashboard
/// 期望的 `metadata` 子对象。所有字符串字段默认空串而不是 null —— 与 mihomo
/// 行为一致（mihomo 的字段都是值类型 string，零值就是 ""）。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMeta {
    pub network: String, // "tcp" | "udp"
    #[serde(rename = "type")]
    pub kind: String, // "Mixed" | "HTTP" | "Socks5" | "TPROXY" | "Tun" | "Redirect"
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    pub source_port: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    pub destination_port: String,
    #[serde(rename = "inboundIP")]
    pub inbound_ip: String,
    pub inbound_port: String,
    pub inbound_name: String,
    pub inbound_user: String,
    pub host: String,
    pub dns_mode: String,
    pub process: String,
    pub process_path: String,
    pub special_proxy: String,
    pub special_rules: String,
    pub sniff_host: String,
    pub uuid: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

/// 速率采样窗口：连续两次 snapshot 间的字节差 / 时间差 = bps。
#[derive(Debug, Default, Clone, Copy)]
pub struct RateSample {
    pub up: u64,
    pub down: u64,
    pub at_ms: u64,
}

/// 一条活跃连接。字段都是 Arc/原子，方便从 splice 任务并发更新而无需锁。
#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    pub id: u64,
    pub meta: ConnectionMeta,
    pub started_at: u64, // unix seconds
    pub bytes_up: Arc<AtomicU64>,
    pub bytes_down: Arc<AtomicU64>,
    pub cancel: Arc<Notify>,
    pub last_sample: Arc<Mutex<RateSample>>,
}

/// snapshot() 每次返回的条目 —— 把 entry 与"上一次采样到现在"的瞬时速率配对。
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub entry: ConnectionEntry,
    pub up_rate_bps: u64,
    pub down_rate_bps: u64,
}

/// 全局连接表 —— Runtime 单例持有 `Arc<ConnectionTable>`。
#[derive(Debug, Default)]
pub struct ConnectionTable {
    next: AtomicU64,
    entries: DashMap<u64, ConnectionEntry>,
}

impl ConnectionTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 注册一条新连接，返回 RAII guard。drop 时自动从表移除。
    /// 推荐 splice 任务持有 guard 直至双向拷贝结束。
    pub fn open(self: &Arc<Self>, mut meta: ConnectionMeta) -> ConnectionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if meta.uuid.is_empty() {
            meta.uuid = Uuid::new_v4().to_string();
        }
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());
        let now_ms = now_millis();
        let last_sample = Arc::new(Mutex::new(RateSample {
            up: 0,
            down: 0,
            at_ms: now_ms,
        }));
        let entry = ConnectionEntry {
            id,
            meta,
            started_at: now_secs(),
            bytes_up: bytes_up.clone(),
            bytes_down: bytes_down.clone(),
            cancel: cancel.clone(),
            last_sample,
        };
        self.entries.insert(id, entry);
        ConnectionGuard {
            table: self.clone(),
            id,
            up: bytes_up,
            down: bytes_down,
            cancel,
        }
    }

    /// 触发取消信号 + 从表移除。被 DELETE /connections/:id 调用。
    pub fn close(&self, id: u64) -> bool {
        // 先取条目读 cancel，再 remove —— 避免移除后另一线程仍在 list() 看到。
        if let Some((_, entry)) = self.entries.remove(&id) {
            entry.cancel.notify_waiters();
            true
        } else {
            false
        }
    }

    /// 兼容字符串 id（mihomo 用 UUID 字符串作为 dashboard `id`）。
    pub fn close_by_uuid_or_numeric(&self, key: &str) -> bool {
        // 1) 先按 numeric id
        if let Ok(id) = key.parse::<u64>() {
            if self.close(id) {
                return true;
            }
        }
        // 2) 按 uuid 字符串扫
        let mut hit: Option<u64> = None;
        for r in self.entries.iter() {
            if r.value().meta.uuid == key {
                hit = Some(*r.key());
                break;
            }
        }
        if let Some(id) = hit {
            return self.close(id);
        }
        false
    }

    /// 一次性关闭所有 —— Clash `DELETE /connections`。返回关闭条数。
    pub fn close_all(&self) -> usize {
        // 先收集 entries → notify all → 再 clear。
        let snapshot: Vec<_> = self.entries.iter().map(|e| e.value().clone()).collect();
        for e in &snapshot {
            e.cancel.notify_waiters();
        }
        self.entries.clear();
        snapshot.len()
    }

    /// 仅由 [`ConnectionGuard::drop`] 调用：静默移除（不再 notify，因为 guard
    /// drop 意味着 splice 已经结束）。
    pub fn remove_silent(&self, id: u64) {
        self.entries.remove(&id);
    }

    /// 列出所有活跃连接（克隆）；不计算速率，留给 [`Self::snapshot`]。
    pub fn list(&self) -> Vec<ConnectionEntry> {
        self.entries.iter().map(|e| e.value().clone()).collect()
    }

    /// 同 list，但额外计算每条的瞬时上下行速率（bps）。同时把"现在"的累计
    /// 字节数刷新到 `last_sample` —— 下一次 snapshot 拿到的就是过去这一段
    /// 时间的增量速率，与 mihomo 1s 推送窗口一致。
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        let now_ms = now_millis();
        self.entries
            .iter()
            .map(|e| {
                let entry = e.value().clone();
                let up_now = entry.bytes_up.load(Ordering::Relaxed);
                let down_now = entry.bytes_down.load(Ordering::Relaxed);
                let (up_rate, down_rate) = {
                    let mut sample = entry.last_sample.lock();
                    let dt_ms = now_ms.saturating_sub(sample.at_ms).max(1);
                    let up_delta = up_now.saturating_sub(sample.up);
                    let down_delta = down_now.saturating_sub(sample.down);
                    // 字节 / 秒：mihomo 同样发 bytes/s（不是 bits/s）。
                    let u = (up_delta as u128 * 1000 / dt_ms as u128) as u64;
                    let d = (down_delta as u128 * 1000 / dt_ms as u128) as u64;
                    *sample = RateSample {
                        up: up_now,
                        down: down_now,
                        at_ms: now_ms,
                    };
                    (u, d)
                };
                ConnectionSnapshot {
                    entry,
                    up_rate_bps: up_rate,
                    down_rate_bps: down_rate,
                }
            })
            .collect()
    }

    pub fn get(&self, id: u64) -> Option<ConnectionEntry> {
        self.entries.get(&id).map(|e| e.value().clone())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// RAII guard：drop 时自动从表移除。所有 splice 路径都应该握住 guard
/// 直到双向拷贝结束 —— 即使任务 panic / early-return 也能保证表里不留死条目。
pub struct ConnectionGuard {
    table: Arc<ConnectionTable>,
    pub id: u64,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    pub cancel: Arc<Notify>,
}

impl ConnectionGuard {
    /// 在 splice 任务中读这两个 counter 的克隆（Arc 自带 Clone）。
    pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.up.clone(), self.down.clone())
    }
    pub fn cancel_token(&self) -> Arc<Notify> {
        self.cancel.clone()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.table.remove_silent(self.id);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_drop_removes_entry() {
        let t = ConnectionTable::new();
        {
            let _g = t.open(ConnectionMeta::default());
            assert_eq!(t.len(), 1);
        }
        // guard drop → 自动移除
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn close_triggers_cancel_and_removes() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta::default());
        let id = g.id;
        let cancel = g.cancel_token();
        // 把 guard forget 掉，模拟"由 close(id) 主动结束"路径
        std::mem::forget(g);
        assert_eq!(t.len(), 1);
        // notify_waiters 在没有等待者时是 noop —— 给一个等待者验证唤醒
        let notified = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let nf = notified.clone();
        let cancel_clone = cancel.clone();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                cancel_clone.notified().await;
                nf.store(true, std::sync::atomic::Ordering::Relaxed);
            });
        });
        // 让等待者先挂上去
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(t.close(id));
        handle.join().unwrap();
        assert!(notified.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn close_all_returns_count_and_cleans() {
        let t = ConnectionTable::new();
        let _g1 = t.open(ConnectionMeta::default());
        let _g2 = t.open(ConnectionMeta::default());
        let _g3 = t.open(ConnectionMeta::default());
        let n = t.close_all();
        assert_eq!(n, 3);
        assert_eq!(t.len(), 0);
        // guard drop 仍是 safe（remove_silent 对不存在的 id 无副作用）
    }

    #[test]
    fn close_by_uuid_works() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta::default());
        let uuid = {
            let e = t.get(g.id).unwrap();
            e.meta.uuid.clone()
        };
        assert!(!uuid.is_empty());
        std::mem::forget(g); // 不让 drop 提前清掉
        assert!(t.close_by_uuid_or_numeric(&uuid));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn snapshot_computes_rate() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta::default());
        // 第一次 snapshot 建立 baseline，速率可能是 0
        let _ = t.snapshot();
        // 累加一些字节
        g.up.store(1024 * 1024, Ordering::Relaxed);
        g.down.store(2 * 1024 * 1024, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let snap = t.snapshot();
        assert_eq!(snap.len(), 1);
        let s = &snap[0];
        // 100ms 内 1MiB 上行 → ≈ 10 MiB/s；允许宽松一点
        assert!(s.up_rate_bps > 5_000_000, "up_rate {}", s.up_rate_bps);
        assert!(s.down_rate_bps > 10_000_000, "down_rate {}", s.down_rate_bps);
    }
}
