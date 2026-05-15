//! DNS 缓存 —— 乐观缓存 (stale-while-revalidate) + LRU 上限。
//!
//! 命中模型：
//!
//! ```text
//!   now < expire                        → fresh:        直接返回，不刷新
//!   expire ≤ now < expire + grace        → stale:       返回旧值，并触发后台 prefetch
//!   expire + grace ≤ now                  → expired:     drop，按 miss 处理
//! ```
//!
//! 设计要点：
//! * **零拷贝读路径**：`get` 只走 DashMap，`Vec<IpAddr>` clone 一次返回。
//! * **prefetch 去重**：同一 host 并发触发时只跑一次，由 DashMap entry 内的
//!   `prefetching` 标志保护。
//! * **LRU 上限**：超过容量时按 last_used 时间淘汰，O(N) 触发；
//!   实现用 `parking_lot::RwLock<BTreeMap>` 保留 last_used 索引。
//! * **泛型 Key**：`(host, qtype)` 组合 key，支持 A / AAAA / 双栈分桶。

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use parking_lot::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    A,
    AAAA,
    Both,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub ips: Vec<IpAddr>,
    pub expire: Instant,
    pub last_used: Instant,
    pub origin: &'static str, // "system" / "doh:cloudflare" 等，便于 explain
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Fresh,
    Stale,
    Miss,
}

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub max_entries: usize,
    /// stale grace：过期后还能继续被返回的时长。0 表示禁用乐观缓存。
    pub grace: Duration,
    /// 触发后台 prefetch 的剩余时间阈值（fresh 末段）。
    pub prefetch_threshold: Duration,
    /// stale 命中时愿意等待刷新完成的时间；超时后先返回 stale，刷新继续后台完成。
    pub client_response_timeout: Duration,
    /// 刷新失败后的重试抑制时间，避免 stale 期间每个请求都打上游。
    pub failure_recheck: Duration,
    /// stale 数据返回给 DNS 客户端时使用的短 TTL。
    pub stale_answer_ttl: Duration,
    /// 负缓存（NXDOMAIN）TTL。
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            grace: Duration::from_secs(5 * 60),
            prefetch_threshold: Duration::from_secs(30),
            client_response_timeout: Duration::from_millis(1800),
            failure_recheck: Duration::from_secs(30),
            stale_answer_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
pub struct DnsCache {
    inner: DashMap<(String, QType), CachedSlot>,
    cfg: CacheConfig,
}

#[derive(Debug)]
struct CachedSlot {
    entry: Entry,
    /// 1 表示有协程正在后台 prefetch 此 key；其他协程不再触发。
    prefetching: Arc<AtomicBool>,
    last_refresh_failure: Arc<Mutex<Option<Instant>>>,
}

impl DnsCache {
    pub fn new(cfg: CacheConfig) -> Self {
        Self {
            inner: DashMap::new(),
            cfg,
        }
    }

    pub fn config(&self) -> &CacheConfig {
        &self.cfg
    }

    /// 取一条记录，返回（值, 命中状态, 是否需要后台 prefetch）。
    /// `disable_optimistic` 为 true 时，stale 视为 miss（与 sing-box `disable_optimistic_cache` 一致）。
    pub fn get_with(
        &self,
        host: &str,
        qtype: QType,
        disable_optimistic: bool,
    ) -> (Option<Vec<IpAddr>>, Hit, Option<PrefetchTicket>) {
        let (v, h, t) = self.get(host, qtype);
        if h == Hit::Stale && disable_optimistic {
            // 丢弃 ticket（不触发 prefetch），告诉调用方按 miss 处理
            drop(t);
            return (None, Hit::Miss, None);
        }
        (v, h, t)
    }

    /// 取一条记录，返回（值, 命中状态, 是否需要后台 prefetch）。
    pub fn get(
        &self,
        host: &str,
        qtype: QType,
    ) -> (Option<Vec<IpAddr>>, Hit, Option<PrefetchTicket>) {
        let key = (host.to_lowercase(), qtype);
        let now = Instant::now();
        if let Some(mut slot) = self.inner.get_mut(&key) {
            slot.entry.last_used = now;
            let entry = &slot.entry;
            if now < entry.expire {
                let remaining = entry.expire - now;
                let need_prefetch =
                    remaining < self.cfg.prefetch_threshold && refresh_allowed(&slot, &self.cfg);
                let ticket = if need_prefetch {
                    slot.prefetching.store(true, Ordering::Release);
                    Some(PrefetchTicket {
                        flag: slot.prefetching.clone(),
                        last_failure: slot.last_refresh_failure.clone(),
                        host: key.0.clone(),
                        qtype,
                    })
                } else {
                    None
                };
                return (Some(entry.ips.clone()), Hit::Fresh, ticket);
            }
            let stale_until = entry.expire + self.cfg.grace;
            if now < stale_until {
                let need_prefetch = refresh_allowed(&slot, &self.cfg);
                let ticket = if need_prefetch {
                    slot.prefetching.store(true, Ordering::Release);
                    Some(PrefetchTicket {
                        flag: slot.prefetching.clone(),
                        last_failure: slot.last_refresh_failure.clone(),
                        host: key.0.clone(),
                        qtype,
                    })
                } else {
                    None
                };
                return (Some(entry.ips.clone()), Hit::Stale, ticket);
            }
            // expired beyond grace —— 删除
            drop(slot);
            self.inner.remove(&key);
        }
        (None, Hit::Miss, None)
    }

    /// 写入/刷新一条记录。
    pub fn put(
        &self,
        host: &str,
        qtype: QType,
        ips: Vec<IpAddr>,
        ttl: Duration,
        origin: &'static str,
    ) {
        if ips.is_empty() {
            return;
        }
        let key = (host.to_lowercase(), qtype);
        let now = Instant::now();
        let entry = Entry {
            ips,
            expire: now + ttl,
            last_used: now,
            origin,
        };
        self.inner.insert(
            key,
            CachedSlot {
                entry,
                prefetching: Arc::new(AtomicBool::new(false)),
                last_refresh_failure: Arc::new(Mutex::new(None)),
            },
        );
        if self.inner.len() > self.cfg.max_entries {
            self.evict_lru();
        }
    }

    /// 写入负缓存（NXDOMAIN/SERVFAIL）—— 用空 ips + short ttl。
    pub fn put_negative(&self, host: &str, qtype: QType) {
        let key = (host.to_lowercase(), qtype);
        let now = Instant::now();
        self.inner.insert(
            key,
            CachedSlot {
                entry: Entry {
                    ips: Vec::new(),
                    expire: now + self.cfg.negative_ttl,
                    last_used: now,
                    origin: "negative",
                },
                prefetching: Arc::new(AtomicBool::new(false)),
                last_refresh_failure: Arc::new(Mutex::new(None)),
            },
        );
    }

    pub fn invalidate(&self, host: &str, qtype: QType) {
        self.inner.remove(&(host.to_lowercase(), qtype));
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn evict_lru(&self) {
        let target = self.cfg.max_entries.saturating_mul(9) / 10;
        let mut entries: Vec<((String, QType), Instant)> = self
            .inner
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().entry.last_used))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        for (k, _) in entries
            .into_iter()
            .take(self.inner.len().saturating_sub(target))
        {
            self.inner.remove(&k);
        }
    }

    /* ---------------- 持久化 ---------------- */

    /// 序列化所有 entry 为 (key, blob) 列表 —— 调用方写入 redb / 文件。
    /// key 形态：`"{host}|A"` / `"{host}|AAAA"` / `"{host}|BOTH"`。
    pub fn dump(&self) -> Vec<(String, core_store::DnsCacheBlob)> {
        let now_inst = std::time::Instant::now();
        let now_sys = std::time::SystemTime::now();
        let mut out = Vec::with_capacity(self.inner.len());
        for kv in self.inner.iter() {
            let (host, qtype) = kv.key();
            let entry = &kv.value().entry;
            let key = format!("{}|{}", host, qtype_label(*qtype));
            // 把 Instant 过期时间转为 epoch_secs（避免下次启动 Instant 不可比）
            let expire_secs = if entry.expire > now_inst {
                let dur = entry.expire - now_inst;
                now_sys
                    .checked_add(dur)
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            } else {
                0
            };
            out.push((
                key,
                core_store::DnsCacheBlob {
                    ips: entry.ips.iter().map(|ip| ip.to_string()).collect(),
                    expire_secs,
                    origin: entry.origin.to_string(),
                },
            ));
        }
        out
    }

    /// 从 redb / 文件恢复；过期项自动丢弃。
    pub fn load(&self, rows: Vec<(String, core_store::DnsCacheBlob)>) {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for (key, blob) in rows {
            if blob.expire_secs <= now_secs {
                continue;
            }
            let (host, qtype) = match parse_key(&key) {
                Some(x) => x,
                None => continue,
            };
            let ips: Vec<IpAddr> = blob.ips.iter().filter_map(|s| s.parse().ok()).collect();
            let ttl = std::time::Duration::from_secs(blob.expire_secs - now_secs);
            // origin 是 'static —— 持久化无法保留 'static；用统一标签
            self.put(&host, qtype, ips, ttl, "persisted");
        }
    }
}

fn refresh_allowed(slot: &CachedSlot, cfg: &CacheConfig) -> bool {
    if slot.prefetching.load(Ordering::Acquire) {
        return false;
    }
    let Some(last_failure) = *slot.last_refresh_failure.lock() else {
        return true;
    };
    last_failure.elapsed() >= cfg.failure_recheck
}

fn qtype_label(q: QType) -> &'static str {
    match q {
        QType::A => "A",
        QType::AAAA => "AAAA",
        QType::Both => "BOTH",
    }
}

fn parse_key(s: &str) -> Option<(String, QType)> {
    let (host, qstr) = s.rsplit_once('|')?;
    let q = match qstr {
        "A" => QType::A,
        "AAAA" => QType::AAAA,
        "BOTH" => QType::Both,
        _ => return None,
    };
    Some((host.to_string(), q))
}

/// 持有这个 ticket 的协程负责跑一次 prefetch；drop 时自动释放 prefetching 标志。
#[derive(Debug)]
pub struct PrefetchTicket {
    flag: Arc<AtomicBool>,
    last_failure: Arc<Mutex<Option<Instant>>>,
    pub host: String,
    pub qtype: QType,
}

impl PrefetchTicket {
    pub fn mark_success(&self) {
        *self.last_failure.lock() = None;
    }

    pub fn mark_failure(&self) {
        *self.last_failure.lock() = Some(Instant::now());
    }
}

impl Drop for PrefetchTicket {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fresh_then_stale_then_expired() {
        let cfg = CacheConfig {
            max_entries: 100,
            grace: Duration::from_millis(50),
            prefetch_threshold: Duration::from_millis(5),
            client_response_timeout: Duration::from_millis(10),
            failure_recheck: Duration::from_millis(10),
            stale_answer_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_millis(20),
        };
        let c = DnsCache::new(cfg);
        c.put(
            "a.com",
            QType::A,
            vec![ip("1.1.1.1")],
            Duration::from_millis(20),
            "test",
        );

        // 立刻 fresh
        let (v, hit, _) = c.get("a.com", QType::A);
        assert_eq!(hit, Hit::Fresh);
        assert!(v.is_some());

        // 等到过期但仍在 grace 区
        std::thread::sleep(Duration::from_millis(25));
        let (v, hit, ticket) = c.get("a.com", QType::A);
        assert_eq!(hit, Hit::Stale);
        assert!(v.is_some());
        assert!(ticket.is_some(), "stale 必须触发 prefetch ticket");

        // 第二次 stale 不再下发 ticket（去重）
        let (_, _, ticket2) = c.get("a.com", QType::A);
        assert!(ticket2.is_none());

        // grace 之后真过期
        std::thread::sleep(Duration::from_millis(60));
        let (v, hit, _) = c.get("a.com", QType::A);
        assert!(v.is_none());
        assert_eq!(hit, Hit::Miss);
    }

    #[test]
    fn prefetch_ticket_releases_on_drop() {
        let c = DnsCache::new(CacheConfig::default());
        c.put(
            "b.com",
            QType::A,
            vec![ip("1.2.3.4")],
            Duration::from_millis(0),
            "test",
        );
        std::thread::sleep(Duration::from_millis(1));
        let (_, _, t1) = c.get("b.com", QType::A);
        assert!(t1.is_some());
        // drop t1 —— 别的协程能再次拿到 ticket
        drop(t1);
        let (_, _, t2) = c.get("b.com", QType::A);
        assert!(t2.is_some());
    }

    #[test]
    fn lru_evicts_oldest_when_over_cap() {
        let cfg = CacheConfig {
            max_entries: 4,
            ..CacheConfig::default()
        };
        let c = DnsCache::new(cfg);
        for i in 0..6u32 {
            c.put(
                &format!("h{i}.com"),
                QType::A,
                vec![ip(&format!("10.0.0.{i}"))],
                Duration::from_secs(60),
                "test",
            );
            std::thread::sleep(Duration::from_millis(2)); // 让 last_used 单调
        }
        // 触发了一次 evict；保留最近 ~3-4 条
        assert!(c.len() <= 4, "len={}", c.len());
        // 最早的 h0/h1 已淘汰
        assert!(c.get("h0.com", QType::A).0.is_none());
    }

    #[test]
    fn negative_cache_returns_empty_then_expires() {
        let cfg = CacheConfig {
            negative_ttl: Duration::from_millis(15),
            grace: Duration::from_millis(0),
            ..CacheConfig::default()
        };
        let c = DnsCache::new(cfg);
        c.put_negative("nx.example.com", QType::A);
        let (v, hit, _) = c.get("nx.example.com", QType::A);
        assert_eq!(hit, Hit::Fresh);
        assert!(v.unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(20));
        let (v, hit, _) = c.get("nx.example.com", QType::A);
        assert!(v.is_none());
        assert_eq!(hit, Hit::Miss);
    }
}
