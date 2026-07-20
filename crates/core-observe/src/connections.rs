//! Clash 兼容连接表 —— 高吞吐 / 低内存的活跃连接管理器。
//!
//! ## 数据模型
//! * [`ConnectionMeta`] —— Clash dashboard 的 metadata 子对象，与 `constant.Metadata`
//!   字段一一对应，能直接被 serde 序列化（包含 sourceIP / sourcePort / destinationIP /
//!   destinationPort / inboundIP / inboundPort / inboundName / inboundUser / host /
//!   dnsMode / process / processPath / specialProxy / specialRules / sniffHost / uuid /
//!   chains / rule / rulePayload；providerChains 是 tracker 顶层字段，随 meta 在内存
//!   中流转但不序列化进 metadata 子对象）。
//! * [`ConnectionEntry`] —— 一条活跃连接的完整状态：immutable `Arc<ConnectionMeta>` +
//!   实时累计字节数（`Arc<AtomicU64>`，由 splice 路径在 copy loop 内自增）+ 取消
//!   信号（`Arc<Notify>`，DELETE /connections/:id 触发后让数据流主动 shutdown）+
//!   smart-block 旗标（AtomicU8，flip 不需要重建 meta）。
//! * [`ConnectionGuard`] —— RAII：splice 任务持有 guard，drop 时自动从表移除，
//!   即便 panic / early-return 也不会漏关。
//!
//! ## 内存策略
//! * 字符串字段统一用 [`compact_str::CompactString`]：≤24 字节内联存储，clone
//!   只是 24 字节 memcpy；典型 IP / 端口 / 协议名 / dns 模式 全部命中内联。
//! * 列表字段（chains / geoip）用 `SmallVec<[CompactString; 4]>`：典型链路长度
//!   1-4，整个 SmallVec 在栈上，无堆分配。
//! * `meta` 字段在 entry 内是 `Arc<ConnectionMeta>`：clone 只是引用计数自增，
//!   snapshot 路径几千条连接也只复制几千个 8 字节指针。
//! * `smart_block` 是唯一可变字段，提到 entry 顶层做 atomic flag，meta 本身
//!   保持完全不可变 —— Arc 共享时不需要 make_mut clone。
//!
//! ## DELETE 语义
//! * `close(id)` / `close_all()` 都会 **先** 调 `cancel.notify_waiters()` 再
//!   从表里 remove。这样即使 splice 任务还在 select! 里等数据，也能立刻收到
//!   取消信号开始 shutdown，而不是只在表里消失却继续传字节。

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};

use compact_str::{CompactString, ToCompactString};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Serialize, Serializer};
use smallvec::SmallVec;
use tokio::sync::Notify;
use uuid::Uuid;

/// chains / geoip 类列表 —— 典型 1-4 项，内联保存避免堆分配。
pub type StringList = SmallVec<[CompactString; 4]>;

/// 把 `Vec<String>` / `&[String]` 等转成内联 SmallVec，外部 dial 路径用。
pub fn string_list_from<I, S>(iter: I) -> StringList
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    iter.into_iter()
        .map(|s| CompactString::new(s.as_ref()))
        .collect()
}

/// 连接 metadata —— Clash dashboard 期望的 metadata 子对象。
///
/// * 字符串字段统一 `CompactString`，短串完全内联（典型 IP / 端口 / 协议名 /
///   chain name 都 ≤24 字节），clone 不触堆。
/// * 列表字段统一 `StringList`（[`SmallVec<[CompactString; 4]>`]），长度 ≤4
///   完全在栈上。
/// * 整个 struct 设计为 immutable —— 进 [`ConnectionTable`] 后即被 [`Arc`]
///   包裹共享，不允许就地改写；smart-block 等可变态在 entry 顶层做 atomic
///   flag。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMeta {
    pub network: CompactString, // "tcp" | "udp"
    #[serde(rename = "type")]
    pub kind: CompactString, // "Mixed" | "HTTP" | "Socks5" | "TPROXY" | "Tun" | "Redirect"
    #[serde(rename = "sourceIP")]
    pub source_ip: CompactString,
    #[serde(rename = "sourceGeoIP")]
    pub source_geoip: StringList,
    #[serde(rename = "sourceIPASN")]
    pub source_ip_asn: CompactString,
    pub source_port: CompactString,
    #[serde(rename = "destinationIP")]
    pub destination_ip: CompactString,
    #[serde(rename = "destinationGeoIP")]
    pub destination_geoip: StringList,
    #[serde(rename = "destinationIPASN")]
    pub destination_ip_asn: CompactString,
    pub destination_port: CompactString,
    #[serde(rename = "inboundIP")]
    pub inbound_ip: CompactString,
    pub inbound_port: CompactString,
    pub inbound_name: CompactString,
    pub inbound_user: CompactString,
    pub host: CompactString,
    pub dns_mode: CompactString,
    pub uid: u32,
    pub process: CompactString,
    pub process_path: CompactString,
    pub special_proxy: CompactString,
    pub special_rules: CompactString,
    pub remote_destination: CompactString,
    pub dscp: u8,
    pub sniff_host: CompactString,
    #[serde(rename = "id")]
    pub uuid: CompactString,
    pub smart_target: CompactString,
    pub chains: StringList,
    #[serde(skip)]
    pub provider_chains: StringList,
    pub rule: CompactString,
    pub rule_payload: CompactString,
}

impl ConnectionMeta {
    pub fn normalize_for_tracking(&mut self) {
        if self.destination_ip.is_empty() {
            if let Ok(ip) = self.host.parse::<IpAddr>() {
                self.destination_ip = ip.to_compact_string();
            }
        }
        if self.remote_destination.is_empty() {
            let host: &str = if !self.host.is_empty() {
                self.host.as_ref()
            } else {
                self.destination_ip.as_ref()
            };
            if let Some(endpoint) = join_host_port(host, &self.destination_port) {
                self.remote_destination = endpoint;
            }
        }
    }
}

fn join_host_port(host: &str, port: &str) -> Option<CompactString> {
    let host = host.trim();
    let port = port.trim();
    if host.is_empty() || port.is_empty() {
        return None;
    }
    // IPv6 文本（带 :）必须裹方括号；其它情况直接拼。
    let need_brackets =
        matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) && !host.starts_with('[');
    let mut out = CompactString::default();
    if need_brackets {
        out.push('[');
        out.push_str(host);
        out.push(']');
    } else {
        out.push_str(host);
    }
    out.push(':');
    out.push_str(port);
    Some(out)
}

/// 速率采样窗口：连续两次 snapshot 间的字节差 / 时间差 = bytes/s。
#[derive(Debug, Default, Clone, Copy)]
pub struct RateSample {
    pub up: u64,
    pub down: u64,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct TimeBucket {
    start_ms: u64,
    bytes: u64,
}

/// 滑窗速率：保留最近 1 秒内每 100ms 桶，每次写入后返回窗口内最高 bytes/s。
/// 桶数组长度固定（10），用 SmallVec 内联存储避免堆分配。
#[derive(Debug)]
struct BucketWindow {
    buckets: SmallVec<[TimeBucket; 16]>,
    interval_ms: u64,
    window_ms: u64,
}

impl BucketWindow {
    fn new(bucket_count: usize, interval_ms: u64) -> Self {
        let mut buckets = SmallVec::with_capacity(bucket_count);
        buckets.resize(
            bucket_count,
            TimeBucket {
                start_ms: 0,
                bytes: 0,
            },
        );
        Self {
            buckets,
            interval_ms,
            window_ms: interval_ms.saturating_mul(bucket_count as u64),
        }
    }

    fn update_max_rate(&mut self, bytes: u64) -> u64 {
        if bytes == 0 || self.buckets.is_empty() || self.interval_ms == 0 {
            return 0;
        }
        let now_ms = now_millis();
        let bucket_start = (now_ms / self.interval_ms) * self.interval_ms;
        let idx = ((now_ms / self.interval_ms) % self.buckets.len() as u64) as usize;
        if self.buckets[idx].start_ms != bucket_start {
            self.buckets[idx].start_ms = bucket_start;
            self.buckets[idx].bytes = 0;
        }
        self.buckets[idx].bytes = self.buckets[idx].bytes.saturating_add(bytes);

        let window_start = now_ms.saturating_sub(self.window_ms);
        self.buckets
            .iter()
            .filter(|b| b.start_ms >= window_start && b.bytes > 0)
            .map(|b| b.bytes.saturating_mul(1000) / self.interval_ms)
            .max()
            .unwrap_or(0)
    }
}

/// smart-block 状态：用 AtomicU8 表示，便于在共享 Arc<ConnectionMeta> 之外
/// 单独 flip。0 = 未拦截，1 = 已拦截。序列化时映射回 "" / "blocked" 字符串。
const SMART_BLOCK_NONE: u8 = 0;
const SMART_BLOCK_BLOCKED: u8 = 1;

fn serialize_smart_block<S: Serializer>(state: &Arc<AtomicU8>, ser: S) -> Result<S::Ok, S::Error> {
    let s = if state.load(Ordering::Relaxed) == SMART_BLOCK_BLOCKED {
        "blocked"
    } else {
        ""
    };
    ser.serialize_str(s)
}

/// 一条活跃连接。字段都是 Arc / 原子，方便从 splice 任务并发更新而无需锁。
///
/// `meta` 为 [`Arc<ConnectionMeta>`]：进表后不可变，clone 只是引用计数 +1，
/// 千条连接 snapshot 也不会触发字符串深拷贝。
#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    pub id: u64,
    pub meta: Arc<ConnectionMeta>,
    pub started_at: u64, // unix seconds
    pub bytes_up: Arc<AtomicU64>,
    pub bytes_down: Arc<AtomicU64>,
    pub max_upload_rate: Arc<AtomicU64>,
    pub max_download_rate: Arc<AtomicU64>,
    pub cancel: Arc<Notify>,
    pub last_sample: Arc<Mutex<RateSample>>,
    pub smart_block: Arc<AtomicU8>,
}

impl ConnectionEntry {
    /// 是否被 smart-block 拦截。
    pub fn is_smart_blocked(&self) -> bool {
        self.smart_block.load(Ordering::Relaxed) == SMART_BLOCK_BLOCKED
    }

    /// 当前 smart-block 状态对应的 dashboard 字符串值。
    pub fn smart_block_str(&self) -> &'static str {
        if self.is_smart_blocked() {
            "blocked"
        } else {
            ""
        }
    }
}

/// snapshot() 每次返回的条目 —— 把 entry 与“上一次采样到现在”的瞬时速率配对。
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub entry: ConnectionEntry,
    pub up_rate_bps: u64,
    pub down_rate_bps: u64,
}

/// dashboard `/connections` 单条响应。`metadata` 用 [`Arc<ConnectionMeta>`]
/// 直传以避免一次完整深拷贝；serde 透明序列化 inner，dashboard 看不到差别。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    #[serde(rename = "id")]
    pub id: CompactString,
    pub metadata: Arc<ConnectionMeta>,
    pub upload: u64,
    pub download: u64,
    pub start: u64,
    pub chains: StringList,
    pub provider_chains: StringList,
    pub rule: CompactString,
    pub rule_payload: CompactString,
    pub max_upload_rate: u64,
    pub max_download_rate: u64,
    /// "" 或 "blocked"；序列化时由 `serialize_smart_block` 把原子状态映射成
    /// 字符串，与 dashboard 期望一致。
    #[serde(rename = "smartBlock", serialize_with = "serialize_smart_block")]
    pub smart_block: Arc<AtomicU8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionManagerSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Vec<ConnectionInfo>,
    pub memory: u64,
}

#[derive(Debug)]
struct ManagerRateState {
    at_ms: u64,
    upload_blip: u64,
    download_blip: u64,
    upload_seen: u64,
    download_seen: u64,
}

impl Default for ManagerRateState {
    fn default() -> Self {
        Self {
            at_ms: now_millis(),
            upload_blip: 0,
            download_blip: 0,
            upload_seen: 0,
            download_seen: 0,
        }
    }
}

/// 全局连接管理器 —— Runtime 单例持有 `Arc<ConnectionTable>`。
///
/// 名称保留 `ConnectionTable` 是为了兼容现有调用方；内部语义按 Clash 兼容
/// 的 `tunnel/statistic.Manager`：连接 join/leave、总流量、traffic blip、smart
/// target 索引、关闭控制都在这里收敛。
#[derive(Debug, Default)]
pub struct ConnectionTable {
    next: AtomicU64,
    entries: DashMap<u64, ConnectionEntry>,
    smart_target: DashMap<CompactString, Arc<Mutex<BTreeSet<CompactString>>>>,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    rate: Mutex<ManagerRateState>,
}

impl ConnectionTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 注册一条新连接，返回 RAII guard。drop 时自动从表移除。
    /// 推荐 splice 任务持有 guard 直至双向拷贝结束。
    pub fn open(self: &Arc<Self>, mut meta: ConnectionMeta) -> ConnectionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        meta.normalize_for_tracking();
        if meta.uuid.is_empty() {
            meta.uuid = Uuid::new_v4().to_compact_string();
        }
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let max_upload_rate = Arc::new(AtomicU64::new(0));
        let max_download_rate = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());
        let now_ms = now_millis();
        let last_sample = Arc::new(Mutex::new(RateSample {
            up: 0,
            down: 0,
            at_ms: now_ms,
        }));
        let upload_window = Arc::new(Mutex::new(BucketWindow::new(10, 100)));
        let download_window = Arc::new(Mutex::new(BucketWindow::new(10, 100)));
        let smart_block = Arc::new(AtomicU8::new(SMART_BLOCK_NONE));
        let meta = Arc::new(meta);
        let entry = ConnectionEntry {
            id,
            meta,
            started_at: now_secs(),
            bytes_up: bytes_up.clone(),
            bytes_down: bytes_down.clone(),
            max_upload_rate: max_upload_rate.clone(),
            max_download_rate: max_download_rate.clone(),
            cancel: cancel.clone(),
            last_sample,
            smart_block: smart_block.clone(),
        };
        self.join_indexes(&entry);
        self.entries.insert(id, entry.clone());
        ConnectionGuard {
            table: self.clone(),
            id,
            up: bytes_up,
            down: bytes_down,
            max_upload_rate,
            max_download_rate,
            cancel,
            upload_window,
            download_window,
            smart_block,
            tracked: true,
        }
    }

    /// 旁路 guard —— 给 inner / 自发起 / 不希望出现在 `/connections` API 的
    /// 连接（DNS resolver、ruleset fetcher、URLTest 等）用。
    ///
    /// 行为：
    /// * 不分配新的 connection id（统一用 0），不写 `Self::entries`；
    /// * counter / cancel token / window 仍可用 —— 上游 splice / accounting
    ///   代码不必分支判断；
    /// * Drop 时不调 `remove_silent`，因为根本没有 entry。
    ///
    /// 全局总流量（upload_total / download_total）依然累计 —— 内部连接也算
    /// 进程吞吐，传给 `/traffic` 的整体曲线可以反映真实负载。
    pub fn open_detached(self: &Arc<Self>) -> ConnectionGuard {
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let max_upload_rate = Arc::new(AtomicU64::new(0));
        let max_download_rate = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());
        let upload_window = Arc::new(Mutex::new(BucketWindow::new(10, 100)));
        let download_window = Arc::new(Mutex::new(BucketWindow::new(10, 100)));
        let smart_block = Arc::new(AtomicU8::new(SMART_BLOCK_NONE));
        ConnectionGuard {
            table: self.clone(),
            id: 0,
            up: bytes_up,
            down: bytes_down,
            max_upload_rate,
            max_download_rate,
            cancel,
            upload_window,
            download_window,
            smart_block,
            tracked: false,
        }
    }

    /// 触发取消信号 + 从表移除。被 DELETE /connections/:id 调用。
    pub fn close(&self, id: u64) -> bool {
        // 先取条目读 cancel，再 remove —— 避免移除后另一线程仍在 list() 看到。
        if let Some((_, entry)) = self.entries.remove(&id) {
            self.leave_indexes(&entry);
            entry.cancel.notify_waiters();
            true
        } else {
            false
        }
    }

    /// 兼容字符串 id（dashboard 用 UUID 字符串作为 `id` 字段）。
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
            if r.value().meta.uuid.as_str() == key {
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
            self.leave_indexes(e);
        }
        self.entries.clear();
        snapshot.len()
    }

    /// 仅由 [`ConnectionGuard::drop`] 调用：静默移除（不再 notify，因为 guard
    /// drop 意味着 splice 已经结束）。
    pub fn remove_silent(&self, id: u64) {
        if let Some((_, entry)) = self.entries.remove(&id) {
            self.leave_indexes(&entry);
        }
    }

    /// 列出所有活跃连接（克隆）；不计算速率，留给 [`Self::snapshot`]。
    pub fn list(&self) -> Vec<ConnectionEntry> {
        self.entries.iter().map(|e| e.value().clone()).collect()
    }

    /// 同 list，但额外计算每条的瞬时上下行速率（bps）。同时把“现在”的累计
    /// 字节数刷新到 `last_sample` —— 下一次 snapshot 拿到的就是过去这一段
    /// 时间的增量速率，与 dashboard 1s 推送窗口一致。
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
                    // 字节 / 秒：dashboard 同样发 bytes/s（不是 bits/s）。
                    let u = (up_delta as u128 * 1000 / dt_ms as u128) as u64;
                    let d = (down_delta as u128 * 1000 / dt_ms as u128) as u64;
                    *sample = RateSample {
                        up: up_now,
                        down: down_now,
                        at_ms: now_ms,
                    };
                    if u > entry.max_upload_rate.load(Ordering::Relaxed) {
                        entry.max_upload_rate.store(u, Ordering::Relaxed);
                    }
                    if d > entry.max_download_rate.load(Ordering::Relaxed) {
                        entry.max_download_rate.store(d, Ordering::Relaxed);
                    }
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

    /// 反查一条连接的 "process → host:port" 简标签 —— 给 relay log 用。
    /// process 字段为空时返回 `?`；host 为空时回退 destination_ip。
    pub fn label_for(&self, id: u64) -> String {
        let Some(e) = self.entries.get(&id) else {
            return format!("#{id}");
        };
        let m = &e.meta;
        let proc_label = if m.process.is_empty() {
            "?"
        } else {
            m.process.as_str()
        };
        let host = if !m.host.is_empty() {
            m.host.as_str()
        } else if !m.destination_ip.is_empty() {
            m.destination_ip.as_str()
        } else {
            "?"
        };
        format!("{proc_label} -> {host}:{}", m.destination_port)
    }

    /// 周期性聚合 —— 给“连接表怎么这么多”的诊断日志用。`top_n` 控制每个 bucket
    /// 取前几名；`long_lived` 是判定“长连接”的阈值（持续超过 N 秒就单独列出来）。
    pub fn summary(&self, top_n: usize, long_lived: std::time::Duration) -> ConnectionSummary {
        let entries: Vec<ConnectionEntry> =
            self.entries.iter().map(|e| e.value().clone()).collect();
        let total = entries.len();
        let tcp = entries
            .iter()
            .filter(|e| e.meta.network.as_str() == "tcp")
            .count();
        let udp = total.saturating_sub(tcp);

        let mut dst_hist: HashMap<String, usize> = HashMap::new();
        let mut proc_hist: HashMap<String, usize> = HashMap::new();
        let mut rule_hist: HashMap<String, usize> = HashMap::new();
        let mut chain_hist: HashMap<String, usize> = HashMap::new();
        for e in &entries {
            let m = &e.meta;
            let host: &str = if !m.host.is_empty() {
                m.host.as_str()
            } else {
                m.destination_ip.as_str()
            };
            *dst_hist
                .entry(format!("{host}:{}", m.destination_port))
                .or_default() += 1;
            let p = if m.process.is_empty() {
                "?".to_string()
            } else {
                m.process.to_string()
            };
            *proc_hist.entry(p).or_default() += 1;
            let r = if m.rule.is_empty() {
                "?".to_string()
            } else {
                m.rule.to_string()
            };
            *rule_hist.entry(r).or_default() += 1;
            let chain = m
                .chains
                .last()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string());
            *chain_hist.entry(chain).or_default() += 1;
        }
        let now_secs = now_secs();
        let threshold = long_lived.as_secs();
        let long_lived_entries: Vec<LongLivedEntry> = {
            let mut v: Vec<LongLivedEntry> = entries
                .iter()
                .filter(|e| now_secs.saturating_sub(e.started_at) >= threshold)
                .map(|e| LongLivedEntry {
                    id: e.id,
                    process: if e.meta.process.is_empty() {
                        "?".to_string()
                    } else {
                        e.meta.process.to_string()
                    },
                    host: if !e.meta.host.is_empty() {
                        e.meta.host.to_string()
                    } else {
                        e.meta.destination_ip.to_string()
                    },
                    destination_port: e.meta.destination_port.parse::<u16>().unwrap_or(0),
                    age_secs: now_secs.saturating_sub(e.started_at),
                    bytes_up: e.bytes_up.load(Ordering::Relaxed),
                    bytes_down: e.bytes_down.load(Ordering::Relaxed),
                    network: e.meta.network.to_string(),
                })
                .collect();
            v.sort_by(|a, b| b.age_secs.cmp(&a.age_secs));
            v.truncate(top_n);
            v
        };
        ConnectionSummary {
            total,
            tcp,
            udp,
            top_destinations: top_n_buckets(dst_hist, top_n),
            top_processes: top_n_buckets(proc_hist, top_n),
            by_rule: top_n_buckets(rule_hist, top_n),
            by_outbound: top_n_buckets(chain_hist, top_n),
            long_lived: long_lived_entries,
        }
    }

    pub fn get(&self, id: u64) -> Option<ConnectionEntry> {
        self.entries.get(&id).map(|e| e.value().clone())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn total(&self) -> (u64, u64) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    pub fn now(&self) -> (u64, u64) {
        let now_ms = now_millis();
        let upload = self.upload_total.load(Ordering::Relaxed);
        let download = self.download_total.load(Ordering::Relaxed);
        let mut rate = self.rate.lock();
        let dt = now_ms.saturating_sub(rate.at_ms);
        if dt >= 1000 {
            rate.upload_blip = upload.saturating_sub(rate.upload_seen);
            rate.download_blip = download.saturating_sub(rate.download_seen);
            rate.upload_seen = upload;
            rate.download_seen = download;
            rate.at_ms = now_ms;
        }
        (rate.upload_blip, rate.download_blip)
    }

    pub fn reset_statistic(&self) {
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
        let mut rate = self.rate.lock();
        *rate = ManagerRateState::default();
    }

    pub fn manager_snapshot(&self) -> ConnectionManagerSnapshot {
        let (upload_total, download_total) = self.total();
        let mut connections: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                let entry = e.value();
                ConnectionInfo {
                    id: entry.meta.uuid.clone(),
                    // Arc::clone —— 引用计数 +1，无字符串深拷贝。
                    metadata: Arc::clone(&entry.meta),
                    upload: entry.bytes_up.load(Ordering::Relaxed),
                    download: entry.bytes_down.load(Ordering::Relaxed),
                    start: entry.started_at,
                    chains: entry.meta.chains.clone(),
                    provider_chains: entry.meta.provider_chains.clone(),
                    rule: entry.meta.rule.clone(),
                    rule_payload: entry.meta.rule_payload.clone(),
                    max_upload_rate: entry.max_upload_rate.load(Ordering::Relaxed),
                    max_download_rate: entry.max_download_rate.load(Ordering::Relaxed),
                    smart_block: Arc::clone(&entry.smart_block),
                }
            })
            .collect();
        connections.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.id.cmp(&b.id)));
        ConnectionManagerSnapshot {
            download_total,
            upload_total,
            connections,
            memory: crate::current_rss_bytes(),
        }
    }

    pub fn close_by_chain(&self, chain: &str) -> usize {
        let ids: Vec<u64> = self
            .entries
            .iter()
            .filter_map(|e| {
                let meta = &e.value().meta;
                if meta.chains.iter().any(|c| c.as_str() == chain) {
                    Some(*e.key())
                } else {
                    None
                }
            })
            .collect();
        let mut closed = 0;
        for id in ids {
            if self.close(id) {
                closed += 1;
            }
        }
        closed
    }

    pub fn set_smart_block_and_close(&self, key: &str) -> bool {
        if let Ok(id) = key.parse::<u64>() {
            if self.mark_smart_block(id) {
                return self.close(id);
            }
        }
        let mut hit = None;
        for r in self.entries.iter() {
            if r.value().meta.uuid.as_str() == key {
                hit = Some(*r.key());
                break;
            }
        }
        if let Some(id) = hit {
            if self.mark_smart_block(id) {
                return self.close(id);
            }
        }
        false
    }

    pub fn get_smart_target_ids(&self, target: &str, asn: &str) -> BTreeSet<String> {
        let mut ids: BTreeSet<CompactString> = BTreeSet::new();
        self.extend_smart_target_ids(target, &mut ids);
        if !asn.is_empty() && asn != "unknown" {
            self.extend_smart_target_ids(asn, &mut ids);
        }
        ids.into_iter().map(Into::into).collect()
    }

    fn mark_smart_block(&self, id: u64) -> bool {
        if let Some(entry) = self.entries.get(&id) {
            entry
                .smart_block
                .store(SMART_BLOCK_BLOCKED, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn push_uploaded(&self, size: u64) {
        self.upload_total.fetch_add(size, Ordering::Relaxed);
    }

    fn push_downloaded(&self, size: u64) {
        self.download_total.fetch_add(size, Ordering::Relaxed);
    }

    fn join_indexes(&self, entry: &ConnectionEntry) {
        let target = entry.meta.smart_target.trim();
        if target.is_empty() {
            return;
        }
        self.add_smart_target_id(target, entry.meta.uuid.as_str());
        let asn = entry.meta.destination_ip_asn.trim();
        if !asn.is_empty() && asn != "unknown" {
            self.add_smart_target_id(asn, entry.meta.uuid.as_str());
        }
    }

    fn leave_indexes(&self, entry: &ConnectionEntry) {
        let target = entry.meta.smart_target.trim();
        if target.is_empty() {
            return;
        }
        self.remove_smart_target_id(target, entry.meta.uuid.as_str());
        let asn = entry.meta.destination_ip_asn.trim();
        if !asn.is_empty() && asn != "unknown" {
            self.remove_smart_target_id(asn, entry.meta.uuid.as_str());
        }
    }

    fn add_smart_target_id(&self, key: &str, uuid: &str) {
        let key = CompactString::new(key);
        let set = self
            .smart_target
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(BTreeSet::new())))
            .clone();
        set.lock().insert(CompactString::new(uuid));
    }

    fn remove_smart_target_id(&self, key: &str, uuid: &str) {
        let key = CompactString::new(key);
        let mut should_remove_key = false;
        if let Some(set) = self.smart_target.get(&key) {
            let mut ids = set.lock();
            ids.remove(uuid);
            should_remove_key = ids.is_empty();
        }
        if should_remove_key {
            self.smart_target.remove(&key);
        }
    }

    fn extend_smart_target_ids(&self, key: &str, out: &mut BTreeSet<CompactString>) {
        let key = CompactString::new(key);
        if let Some(set) = self.smart_target.get(&key) {
            out.extend(set.lock().iter().cloned());
        }
    }
}

/// RAII guard：drop 时自动从表移除。所有 splice 路径都应该握住 guard
/// 直到双向拷贝结束 —— 即使任务 panic / early-return 也能保证表里不留死条目。
///
/// `tracked` = false 时是 `ConnectionGuard::detached` 构造的“旁路 guard”：counter /
/// cancel / window 都仍正常工作（让上游 splice 代码不需要分支判断），
/// 但 Drop 时不去碰 `table` —— 适合 inner 连接（DNS resolver / ruleset
/// fetcher 等核心组件自身发起的连接），既不入 ConnectionTable 也不污染
/// `/connections` API。
pub struct ConnectionGuard {
    table: Arc<ConnectionTable>,
    pub id: u64,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
    max_upload_rate: Arc<AtomicU64>,
    max_download_rate: Arc<AtomicU64>,
    pub cancel: Arc<Notify>,
    upload_window: Arc<Mutex<BucketWindow>>,
    download_window: Arc<Mutex<BucketWindow>>,
    smart_block: Arc<AtomicU8>,
    /// 是否真的入了 ConnectionTable —— [`ConnectionTable::open`] 路径设 true，
    /// [`Self::detached`] 路径设 false。Drop 用它判断要不要触发 `remove_silent`。
    tracked: bool,
}

impl ConnectionGuard {
    /// 在 splice 任务中读这两个 counter 的克隆（Arc 自带 Clone）。
    pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.up.clone(), self.down.clone())
    }
    pub fn cancel_token(&self) -> Arc<Notify> {
        self.cancel.clone()
    }
    pub fn accounting(&self) -> ConnectionAccounting {
        ConnectionAccounting {
            table: self.table.clone(),
            up: self.up.clone(),
            down: self.down.clone(),
            max_upload_rate: self.max_upload_rate.clone(),
            max_download_rate: self.max_download_rate.clone(),
            cancel: self.cancel.clone(),
            upload_window: self.upload_window.clone(),
            download_window: self.download_window.clone(),
        }
    }
    pub fn record_upload(&self, size: u64) {
        self.accounting().record_upload(size);
    }
    pub fn record_download(&self, size: u64) {
        self.accounting().record_download(size);
    }

    /// 主动给当前连接打 smart-block 标 —— DELETE /smart-target 等管理路径用。
    pub fn mark_smart_blocked(&self) {
        self.smart_block
            .store(SMART_BLOCK_BLOCKED, Ordering::Relaxed);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.tracked {
            self.table.remove_silent(self.id);
        }
        // detached：从未入表，无需 remove。
    }
}

#[derive(Clone)]
pub struct ConnectionAccounting {
    table: Arc<ConnectionTable>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    max_upload_rate: Arc<AtomicU64>,
    max_download_rate: Arc<AtomicU64>,
    cancel: Arc<Notify>,
    upload_window: Arc<Mutex<BucketWindow>>,
    download_window: Arc<Mutex<BucketWindow>>,
}

impl ConnectionAccounting {
    pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.up.clone(), self.down.clone())
    }

    pub fn cancel_token(&self) -> Arc<Notify> {
        self.cancel.clone()
    }

    pub fn record_upload(&self, size: u64) {
        if size == 0 {
            return;
        }
        self.up.fetch_add(size, Ordering::Relaxed);
        self.table.push_uploaded(size);
        let rate = self.upload_window.lock().update_max_rate(size);
        if rate > self.max_upload_rate.load(Ordering::Relaxed) {
            self.max_upload_rate.store(rate, Ordering::Relaxed);
        }
    }

    pub fn record_download(&self, size: u64) {
        if size == 0 {
            return;
        }
        self.down.fetch_add(size, Ordering::Relaxed);
        self.table.push_downloaded(size);
        let rate = self.download_window.lock().update_max_rate(size);
        if rate > self.max_download_rate.load(Ordering::Relaxed) {
            self.max_download_rate.store(rate, Ordering::Relaxed);
        }
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

/* ========================================================================
诊断聚合 —— “连接表怎么这么多”日志的支撑结构。
======================================================================== */

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConnectionSummary {
    pub total: usize,
    pub tcp: usize,
    pub udp: usize,
    /// (host:port, count) 倒序，长度 ≤ top_n。
    pub top_destinations: Vec<(String, usize)>,
    /// (process_name, count) 倒序，长度 ≤ top_n。
    pub top_processes: Vec<(String, usize)>,
    pub by_rule: Vec<(String, usize)>,
    pub by_outbound: Vec<(String, usize)>,
    /// 按 age 倒序的长连接条目，长度 ≤ top_n。
    pub long_lived: Vec<LongLivedEntry>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LongLivedEntry {
    pub id: u64,
    pub process: String,
    pub host: String,
    pub destination_port: u16,
    pub age_secs: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub network: String,
}

fn top_n_buckets(map: HashMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// 把 [`ConnectionSummary`] 输出到日志。target=`"conntable"`，level=info。
/// 每个 bucket 一行，长连接每条一行 —— 不会因为大表把单条日志撑爆。
pub fn log_connection_summary(summary: &ConnectionSummary) {
    tracing::info!(
        target: "conntable",
        "active={} tcp={} udp={}",
        summary.total,
        summary.tcp,
        summary.udp
    );
    if !summary.top_destinations.is_empty() {
        let s = summary
            .top_destinations
            .iter()
            .map(|(k, v)| format!("{k}×{v}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!(target: "conntable", "top-dst: {s}");
    }
    if summary.top_processes.iter().any(|(k, _)| k != "?") {
        let s = summary
            .top_processes
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!(target: "conntable", "top-process: {s}");
    }
    if !summary.by_rule.is_empty() {
        let s = summary
            .by_rule
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!(target: "conntable", "by-rule: {s}");
    }
    if !summary.by_outbound.is_empty() {
        let s = summary
            .by_outbound
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!(target: "conntable", "by-outbound: {s}");
    }
    for e in &summary.long_lived {
        let mins = e.age_secs / 60;
        let secs = e.age_secs % 60;
        let up = format_bytes_short(e.bytes_up);
        let down = format_bytes_short(e.bytes_down);
        tracing::info!(
            target: "conntable",
            "long-lived #{} {} {}->{}:{} ({}m{:02}s, up {} down {})",
            e.id,
            e.network,
            e.process,
            e.host,
            e.destination_port,
            mins,
            secs,
            up,
            down,
        );
    }
}

fn format_bytes_short(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
        // 把 guard forget 掉，模拟“由 close(id) 主动结束”路径
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
    fn label_for_falls_back_when_process_blank() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            host: "example.com".into(),
            destination_port: "443".into(),
            ..ConnectionMeta::default()
        });
        let label = t.label_for(g.id);
        assert_eq!(label, "? -> example.com:443");
    }

    #[test]
    fn label_for_uses_process_when_present() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            host: "api.example.com".into(),
            destination_port: "443".into(),
            process: "chrome.exe".into(),
            ..ConnectionMeta::default()
        });
        let label = t.label_for(g.id);
        assert_eq!(label, "chrome.exe -> api.example.com:443");
    }

    #[test]
    fn label_for_unknown_id_returns_id_marker() {
        let t = ConnectionTable::new();
        // 表里什么都没有；任意 id 都查不到
        assert_eq!(t.label_for(42), "#42");
    }

    #[test]
    fn summary_buckets_by_destination_process_rule_outbound() {
        let t = ConnectionTable::new();
        let _g1 = t.open(ConnectionMeta {
            network: "tcp".into(),
            host: "cdn.example.com".into(),
            destination_port: "443".into(),
            process: "chrome.exe".into(),
            rule: "GEOIP".into(),
            chains: string_list_from(["main", "node-a"]),
            ..ConnectionMeta::default()
        });
        let _g2 = t.open(ConnectionMeta {
            network: "tcp".into(),
            host: "cdn.example.com".into(),
            destination_port: "443".into(),
            process: "chrome.exe".into(),
            rule: "GEOIP".into(),
            chains: string_list_from(["main", "node-a"]),
            ..ConnectionMeta::default()
        });
        let _g3 = t.open(ConnectionMeta {
            network: "udp".into(),
            host: "1.1.1.1".into(),
            destination_port: "53".into(),
            process: "WutherCore".into(),
            rule: "MATCH".into(),
            chains: string_list_from(["DIRECT"]),
            ..ConnectionMeta::default()
        });
        let s = t.summary(10, std::time::Duration::from_secs(300));
        assert_eq!(s.total, 3);
        assert_eq!(s.tcp, 2);
        assert_eq!(s.udp, 1);
        assert_eq!(s.top_destinations[0], ("cdn.example.com:443".into(), 2));
        assert!(
            s.top_processes
                .iter()
                .any(|(k, v)| k == "chrome.exe" && *v == 2)
        );
        assert!(
            s.top_processes
                .iter()
                .any(|(k, v)| k == "WutherCore" && *v == 1)
        );
        assert!(s.by_rule.iter().any(|(k, v)| k == "GEOIP" && *v == 2));
        assert!(s.by_outbound.iter().any(|(k, v)| k == "node-a" && *v == 2));
    }

    #[test]
    fn summary_long_lived_threshold_filters_recent() {
        let t = ConnectionTable::new();
        let _g = t.open(ConnectionMeta {
            host: "fresh.example.com".into(),
            destination_port: "443".into(),
            ..ConnectionMeta::default()
        });
        // 1s 阈值，新鲜连接（age ≈ 0s）应被过滤掉
        let s = t.summary(10, std::time::Duration::from_secs(1));
        assert!(s.long_lived.is_empty(), "新连接不该出现在 long-lived 清单");

        // 0s 阈值，所有连接都算长连接
        let s2 = t.summary(10, std::time::Duration::from_secs(0));
        assert_eq!(s2.long_lived.len(), 1);
        assert_eq!(s2.long_lived[0].host, "fresh.example.com");
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
        assert!(t.close_by_uuid_or_numeric(uuid.as_str()));
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
        assert!(
            s.down_rate_bps > 10_000_000,
            "down_rate {}",
            s.down_rate_bps
        );
    }

    #[test]
    fn manager_records_totals_and_connection_max_rates() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            network: "tcp".into(),
            kind: "HTTP".into(),
            host: "example.com".into(),
            chains: string_list_from(["Auto", "node-a"]),
            ..ConnectionMeta::default()
        });

        g.record_upload(512);
        g.record_download(1024);

        assert_eq!(t.total(), (512, 1024));
        let snap = t.manager_snapshot();
        assert_eq!(snap.upload_total, 512);
        assert_eq!(snap.download_total, 1024);
        assert_eq!(snap.connections.len(), 1);
        assert_eq!(snap.connections[0].upload, 512);
        assert_eq!(snap.connections[0].download, 1024);
        assert!(snap.connections[0].max_upload_rate >= 512);
        assert!(snap.connections[0].max_download_rate >= 1024);
    }

    #[test]
    fn open_preserves_runtime_provider_chain_and_normalizes_destination_fields() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            network: "tcp".into(),
            kind: "HTTP".into(),
            host: "example.com".into(),
            destination_port: "443".into(),
            smart_target: "example.com".into(),
            chains: string_list_from(["main", "provider-a/node-1"]),
            provider_chains: string_list_from(["provider-a"]),
            rule: "MATCH".into(),
            rule_payload: "preset:global any".into(),
            ..ConnectionMeta::default()
        });

        let entry = t.get(g.id).unwrap();
        assert_eq!(entry.meta.remote_destination.as_str(), "example.com:443");
        assert_eq!(entry.meta.smart_target.as_str(), "example.com");

        let snap = t.manager_snapshot();
        assert_eq!(snap.connections.len(), 1);
        assert_eq!(
            snap.connections[0].provider_chains.as_slice(),
            ["provider-a"]
        );
        assert_eq!(
            snap.connections[0].metadata.remote_destination.as_str(),
            "example.com:443"
        );
    }

    #[test]
    fn smart_target_index_follows_join_and_leave() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            smart_target: "example.com".into(),
            destination_ip_asn: "AS15169".into(),
            ..ConnectionMeta::default()
        });
        let uuid = t.get(g.id).unwrap().meta.uuid.to_string();

        let ids = t.get_smart_target_ids("example.com", "AS15169");
        assert!(ids.contains(&uuid));

        drop(g);
        assert!(t.get_smart_target_ids("example.com", "AS15169").is_empty());
    }

    #[test]
    fn close_by_chain_only_closes_matching_connections() {
        let t = ConnectionTable::new();
        let g1 = t.open(ConnectionMeta {
            chains: string_list_from(["ProviderA", "node-a"]),
            ..ConnectionMeta::default()
        });
        let g2 = t.open(ConnectionMeta {
            chains: string_list_from(["ProviderB", "node-b"]),
            ..ConnectionMeta::default()
        });
        let keep_id = g2.id;
        std::mem::forget(g1);
        std::mem::forget(g2);

        assert_eq!(t.close_by_chain("ProviderA"), 1);
        assert!(t.get(keep_id).is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn smart_block_flag_flips_atomically_and_serializes() {
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            uuid: "fixed-uuid".into(),
            ..ConnectionMeta::default()
        });
        let id = g.id;
        std::mem::forget(g);
        let entry = t.get(id).unwrap();
        assert!(!entry.is_smart_blocked());

        // 模拟管理路径：set_smart_block_and_close 会 mark 然后 close
        assert!(t.set_smart_block_and_close("fixed-uuid"));
        // close 之后 entry 已离表，但保留的 entry 句柄仍能看到 flag 已翻转
        assert!(entry.is_smart_blocked());

        let info = ConnectionInfo {
            id: entry.meta.uuid.clone(),
            metadata: entry.meta.clone(),
            upload: 0,
            download: 0,
            start: entry.started_at,
            chains: entry.meta.chains.clone(),
            provider_chains: entry.meta.provider_chains.clone(),
            rule: entry.meta.rule.clone(),
            rule_payload: entry.meta.rule_payload.clone(),
            max_upload_rate: 0,
            max_download_rate: 0,
            smart_block: entry.smart_block.clone(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"smartBlock\":\"blocked\""), "got {json}");
    }

    #[test]
    fn meta_clone_is_arc_bump_not_deep_copy() {
        // 验证 Arc<ConnectionMeta> 共享 —— 修改 meta 内容必须经 normalize 流程，
        // entry 之间不会出现“一个改了另一个看到”的情况，因为 Arc 是 immutable 共享。
        let t = ConnectionTable::new();
        let g = t.open(ConnectionMeta {
            host: "a.example.com".into(),
            destination_port: "443".into(),
            ..ConnectionMeta::default()
        });
        let entry = t.get(g.id).unwrap();
        let cloned = entry.clone();
        assert!(Arc::ptr_eq(&entry.meta, &cloned.meta));
    }

    #[test]
    fn open_detached_does_not_appear_in_table_or_snapshot() {
        // inner 流量旁路：detached guard 不分配 entry，list/snapshot/manager 全部不见。
        let t = ConnectionTable::new();
        let _g = t.open_detached();
        assert_eq!(t.len(), 0, "detached guard must not insert into table");
        assert!(
            t.list().is_empty(),
            "detached guard must not appear in list()"
        );
        assert!(
            t.snapshot().is_empty(),
            "detached guard must not appear in snapshot()"
        );
        let mgr = t.manager_snapshot();
        assert!(
            mgr.connections.is_empty(),
            "detached guard must not appear in manager_snapshot.connections"
        );
    }

    #[test]
    fn open_detached_drop_is_noop_safe() {
        // 反复开关 detached guard 不应造成表内任何副作用 —— 也不会触发
        // remove_silent 错误地动到真实 entry。
        let t = ConnectionTable::new();
        let real = t.open(ConnectionMeta {
            host: "real.example.com".into(),
            destination_port: "443".into(),
            ..ConnectionMeta::default()
        });
        let real_id = real.id;
        for _ in 0..16 {
            let _detached = t.open_detached();
        }
        assert_eq!(t.len(), 1);
        assert!(t.get(real_id).is_some());
        drop(real);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn open_detached_counters_still_usable_for_inner_accounting() {
        // detached guard 的 counter / cancel / window 仍然好用 —— 这样 splice
        // / accounting 代码不需要分支处理"是否旁路"。
        let t = ConnectionTable::new();
        let g = t.open_detached();
        g.record_upload(1024);
        g.record_download(2048);
        // 全局 total 仍然累计（内部连接也算进程吞吐）
        let (up, down) = t.total();
        assert_eq!(up, 1024);
        assert_eq!(down, 2048);
        // 但表里没有它
        assert_eq!(t.len(), 0);
    }
}
