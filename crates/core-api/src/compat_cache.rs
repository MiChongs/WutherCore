//! Clash 兼容层的响应缓存 —— 多 dashboard 高并发的关键性能层。
//!
//! ## 为什么需要
//!
//! Yacd / metacubexd / clash-dashboard 等控制面板对 `/proxies` `/configs`
//! `/connections` 等"读热点"端点的轮询频率非常高（默认 1-5 Hz；多 tab 同时打开
//! 倍增）。每次请求都把 `RuntimePlan` + `UrlTester` + `SmartSelector` 状态
//! 序列化一遍，在百节点/十组的工程化场景中：
//!
//! * 每次 build 涉及 ~200 µs 的 JSON 序列化 + 数十次 lock acquire；
//! * N 个并发请求各自重建一次相同 JSON —— CPU 浪费 N 倍；
//! * 内存上每个请求线程独立持有一份 `Map<String, Value>`，垃圾回收抖动。
//!
//! ## 实现
//!
//! [`SnapshotCache`] 缓存 *两份* —— 字节级 [`bytes::Bytes`]（全量 JSON 响应）
//! 与解析后的 `Arc<Value>`（单条 lookup 用）。一次 build 同时填充两份，
//! 之后：
//!
//! * `/proxies`、`/configs` 直接拿 `Bytes`（zero-copy 写 socket）；
//! * `/proxies/:name`、`/configs/<key>` 从 `Arc<Value>` 提取单条，避免反复
//!   `serde_json::from_slice` 解析。
//!
//! ### 单飞 + 双重检查锁
//!
//! TTL 过期时：
//! 1. 取 build mutex（独占重建权）；
//! 2. 在 build mutex 持锁内**再次**读 inner —— 等 mutex 期间可能已被别的线程
//!    刷新过，此时直接返回；
//! 3. 否则跑 `build`（CPU-bound），完成后写回 inner。
//!
//! 100 个并发请求 → 1 次 build → 100 个共享同一份 `Bytes` / `Arc<Value>`。

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use serde_json::Value;

/// 缓存返回的复合体 —— 同时持 bytes 与 Arc<Value>。clone 都是 Arc bump，廉价。
#[derive(Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub value: Arc<Value>,
}

/// 一个端点的字节级 + 结构化双向缓存。
pub struct SnapshotCache {
    inner: RwLock<CacheState>,
    build_lock: Mutex<()>,
    ttl: Duration,
    hits: AtomicU64,
    builds: AtomicU64,
}

#[derive(Clone)]
struct CacheState {
    bytes: Option<Bytes>,
    value: Option<Arc<Value>>,
    last_built: Instant,
}

impl SnapshotCache {
    pub fn new(ttl: Duration) -> Self {
        let stale = Instant::now()
            .checked_sub(ttl)
            .and_then(|t| t.checked_sub(Duration::from_secs(1)))
            .unwrap_or_else(Instant::now);
        Self {
            inner: RwLock::new(CacheState {
                bytes: None,
                value: None,
                last_built: stale,
            }),
            build_lock: Mutex::new(()),
            ttl,
            hits: AtomicU64::new(0),
            builds: AtomicU64::new(0),
        }
    }

    /// 命中或重建。`build` 仅在缓存过期时调用 ≤1 次（其它并发线程在二次检查
    /// 处命中）。
    pub fn fetch<F>(&self, build: F) -> CacheEntry
    where
        F: FnOnce() -> Value,
    {
        if let Some(e) = self.read_fresh() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return e;
        }
        // 等 build mutex —— 其它线程在 build 时这里阻塞。
        let _guard = self.build_lock.lock();
        // 二次检查
        if let Some(e) = self.read_fresh() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return e;
        }
        let value = build();
        // 序列化 —— 这是 build 真正耗时的部分。
        let bytes = serde_json::to_vec(&value)
            .map(Bytes::from)
            .unwrap_or_else(|_| Bytes::from_static(b"{}"));
        let arc_value = Arc::new(value);
        self.builds.fetch_add(1, Ordering::Relaxed);
        let mut s = self.inner.write();
        s.bytes = Some(bytes.clone());
        s.value = Some(arc_value.clone());
        s.last_built = Instant::now();
        CacheEntry {
            bytes,
            value: arc_value,
        }
    }

    /// 仅取 bytes —— 路径只输出原始 JSON 响应时用。
    pub fn fetch_bytes<F>(&self, build: F) -> Bytes
    where
        F: FnOnce() -> Value,
    {
        self.fetch(build).bytes
    }

    /// 仅取 value —— 单条 lookup 路径用。
    pub fn fetch_value<F>(&self, build: F) -> Arc<Value>
    where
        F: FnOnce() -> Value,
    {
        self.fetch(build).value
    }

    fn read_fresh(&self) -> Option<CacheEntry> {
        let s = self.inner.read();
        if let (Some(b), Some(v)) = (&s.bytes, &s.value) {
            if s.last_built.elapsed() < self.ttl {
                return Some(CacheEntry {
                    bytes: b.clone(),
                    value: v.clone(),
                });
            }
        }
        None
    }

    /// 立即让缓存过期。下次 [`fetch`] 一定重建。
    pub fn invalidate(&self) {
        let mut s = self.inner.write();
        s.bytes = None;
        s.value = None;
        s.last_built = Instant::now()
            .checked_sub(self.ttl)
            .and_then(|t| t.checked_sub(Duration::from_secs(1)))
            .unwrap_or_else(Instant::now);
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
    pub fn builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }
}

/// 把所有缓存集中在一处；NativeState 持 `Arc<Caches>`。
pub struct Caches {
    /// `/proxies` —— 高频 (1-5 Hz)，TTL 250ms。
    pub proxy_map: SnapshotCache,
    /// `/configs` —— 低频，TTL 1s。
    pub configs: SnapshotCache,
    /// `/rules` —— 路由规则可能上千条；TTL 1s。
    pub rules: SnapshotCache,
    /// `/providers/proxies`
    pub providers_proxies: SnapshotCache,
    /// `/providers/rules`
    pub providers_rules: SnapshotCache,
    /// `/connections` —— 高频但变化也快；TTL 200ms（≤ dashboard 默认 1Hz/5）。
    pub connections: SnapshotCache,
}

impl Caches {
    pub fn new() -> Arc<Self> {
        let short = Duration::from_millis(250);
        let medium = Duration::from_millis(1000);
        Arc::new(Self {
            proxy_map: SnapshotCache::new(short),
            configs: SnapshotCache::new(medium),
            rules: SnapshotCache::new(medium),
            providers_proxies: SnapshotCache::new(short),
            providers_rules: SnapshotCache::new(medium),
            connections: SnapshotCache::new(Duration::from_millis(200)),
        })
    }

    /// PUT /proxies / DELETE /proxies 等写操作之后调用 —— 让下次 GET 立刻见
    /// 到新值，不等 TTL。
    pub fn invalidate_proxy_state(&self) {
        self.proxy_map.invalidate();
        self.providers_proxies.invalidate();
    }
    pub fn invalidate_config_state(&self) {
        self.configs.invalidate();
    }
    pub fn invalidate_rule_state(&self) {
        self.rules.invalidate();
        self.providers_rules.invalidate();
    }
    pub fn invalidate_connection_state(&self) {
        self.connections.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as O};

    use super::*;

    #[test]
    fn fresh_within_ttl_returns_cached() {
        let cache = SnapshotCache::new(Duration::from_secs(60));
        let n = AtomicUsize::new(0);
        let _e1 = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            serde_json::json!({"x": 1})
        });
        let _e2 = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            serde_json::json!({"x": 2})
        });
        assert_eq!(n.load(O::Relaxed), 1, "second read must hit cache");
    }

    #[test]
    fn invalidate_forces_rebuild() {
        let cache = SnapshotCache::new(Duration::from_secs(60));
        let n = AtomicUsize::new(0);
        let _ = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            Value::String("v1".into())
        });
        cache.invalidate();
        let _ = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            Value::String("v2".into())
        });
        assert_eq!(n.load(O::Relaxed), 2);
    }

    #[test]
    fn parallel_fanout_singleflights_build() {
        let cache = Arc::new(SnapshotCache::new(Duration::from_secs(60)));
        let n = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let n = n.clone();
            handles.push(std::thread::spawn(move || {
                cache.fetch(|| {
                    std::thread::sleep(Duration::from_millis(50));
                    n.fetch_add(1, O::Relaxed);
                    serde_json::json!({"k": "v"})
                })
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        assert_eq!(n.load(O::Relaxed), 1);
        assert_eq!(cache.builds(), 1);
    }

    #[test]
    fn ttl_expiry_triggers_rebuild() {
        let cache = SnapshotCache::new(Duration::from_millis(50));
        let n = AtomicUsize::new(0);
        let _ = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            Value::Null
        });
        std::thread::sleep(Duration::from_millis(80));
        let _ = cache.fetch(|| {
            n.fetch_add(1, O::Relaxed);
            Value::Null
        });
        assert_eq!(n.load(O::Relaxed), 2);
    }

    #[test]
    fn fetch_value_and_bytes_are_consistent() {
        let cache = SnapshotCache::new(Duration::from_secs(60));
        let entry = cache.fetch(|| serde_json::json!({"a": 1, "b": "two"}));
        let bytes = entry.bytes;
        let value = entry.value;
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, *value);
    }
}
