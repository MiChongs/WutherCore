//! NAT 表 —— TUN/TProxy 通用：连接 5-tuple ⇄ 原始目标 + Fake host 反查。
//!
//! §8.4 性能：sharded NAT（DashMap 已经分片）；老化使用 LRU + TTL。
//!
//! 支持两种主键：
//! * 自增 `id`：插入时分配，便于上层快速 touch / remove；
//! * 5-tuple `key`（network + src + dst）：用于 TUN 收到回包时反查会话。
//!
//! Fake host 池在 supervisor 层另行持有；本表只缓存"曾经走过"的 host。

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use dashmap::{DashMap, mapref::entry::Entry};

#[derive(Debug, Clone)]
pub struct NatEntry {
    pub source: SocketAddr,
    pub original_dst: SocketAddr,
    pub fake_host: Option<String>,
    pub network: &'static str,
    pub created_at: Instant,
    pub last_seen: Instant,
}

/// 5-tuple key —— 用于按"流"反查会话。
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub network: &'static str, // "tcp" / "udp"
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl FlowKey {
    pub fn from_entry(e: &NatEntry) -> Self {
        Self {
            network: e.network,
            src: e.source,
            dst: e.original_dst,
        }
    }
}

#[derive(Debug)]
pub struct NatTable {
    map: DashMap<u64, NatEntry>,
    /// flow-key → id，反查使用。
    by_flow: DashMap<FlowKey, u64>,
    /// host → 已选 outbound label；同一 host（fake-host / domain）在 udp_timeout
    /// 内复用同一 outbound，保证 STUN/QUIC/HTTP/3 的 5-tuple 稳定 —— Smart NAT
    /// pinning。
    pub host_pin: DashMap<String, HostPin>,
    ttl: Duration,
    next_id: parking_lot::Mutex<u64>,
}

#[derive(Debug, Clone)]
pub struct HostPin {
    pub outbound: String,
    pub last_seen: Instant,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(Duration::from_secs(120))
    }
}

impl NatTable {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: DashMap::new(),
            by_flow: DashMap::new(),
            host_pin: DashMap::new(),
            ttl,
            next_id: parking_lot::Mutex::new(1),
        }
    }

    /// Smart NAT pinning —— 把 host 与 outbound label 绑定一段时间。
    pub fn pin_host(&self, host: impl Into<String>, outbound: impl Into<String>) {
        self.host_pin.insert(
            host.into(),
            HostPin {
                outbound: outbound.into(),
                last_seen: Instant::now(),
            },
        );
    }

    /// 查询已 pin 的 outbound（命中即更新 last_seen）。
    pub fn lookup_pin(&self, host: &str) -> Option<String> {
        let mut e = self.host_pin.get_mut(host)?;
        e.last_seen = Instant::now();
        Some(e.outbound.clone())
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 插入或更新会话。
    ///
    /// 同一个 [`FlowKey`] 始终复用首次分配的 id，避免按包记账时不断产生孤立
    /// entry。更新会保留最早的 `created_at` 和已有的 fake-host，并把
    /// `last_seen` 单调推进到较新的时间。
    pub fn insert(&self, entry: NatEntry) -> u64 {
        let key = FlowKey::from_entry(&entry);
        match self.by_flow.entry(key) {
            Entry::Occupied(index) => {
                let id = *index.get();
                if let Some(mut current) = self.map.get_mut(&id) {
                    if entry.created_at < current.created_at {
                        current.created_at = entry.created_at;
                    }
                    if entry.last_seen > current.last_seen {
                        current.last_seen = entry.last_seen;
                    }
                    if entry.fake_host.is_some() {
                        current.fake_host = entry.fake_host;
                    }
                } else {
                    // 修复可能由旧版本或异常中断留下的悬空索引，同时继续复用 id。
                    self.map.insert(id, entry);
                }
                id
            }
            Entry::Vacant(index) => {
                let id = {
                    let mut g = self.next_id.lock();
                    let id = *g;
                    *g = g.wrapping_add(1);
                    id
                };
                // 持有 flow shard 的写锁时先写主表，再发布反向索引。这样 lookup
                // 不会观察到一个尚无 NatEntry 的新 id。
                self.map.insert(id, entry);
                index.insert(id);
                id
            }
        }
    }

    pub fn touch(&self, id: u64) {
        let Some(key) = self.map.get(&id).map(|e| FlowKey::from_entry(&e)) else {
            return;
        };
        if let Entry::Occupied(index) = self.by_flow.entry(key) {
            if *index.get() == id {
                if let Some(mut entry) = self.map.get_mut(&id) {
                    entry.last_seen = Instant::now();
                }
            }
        }
    }

    /// 通过 5-tuple 找会话，并 touch last_seen。
    pub fn lookup_flow(&self, key: &FlowKey) -> Option<NatEntry> {
        match self.by_flow.entry(*key) {
            Entry::Occupied(index) => {
                let id = *index.get();
                let Some(mut entry_ref) = self.map.get_mut(&id) else {
                    // 主表缺失时清理悬空索引，避免之后持续返回伪命中。
                    index.remove();
                    return None;
                };
                entry_ref.last_seen = Instant::now();
                Some(entry_ref.clone())
            }
            Entry::Vacant(_) => None,
        }
    }

    pub fn remove(&self, id: u64) -> Option<NatEntry> {
        let key = self.map.get(&id).map(|e| FlowKey::from_entry(&e))?;
        match self.by_flow.entry(key) {
            Entry::Occupied(index) => {
                let entry = self.map.remove(&id).map(|(_, value)| value);
                if *index.get() == id {
                    index.remove();
                }
                entry
            }
            Entry::Vacant(_) => self.map.remove(&id).map(|(_, value)| value),
        }
    }

    pub fn get(&self, id: u64) -> Option<NatEntry> {
        self.map.get(&id).map(|e| e.clone())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 周期性回收。返回被清理条数（含 host_pin）。
    pub fn purge(&self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;
        let candidates: Vec<(u64, FlowKey)> = self
            .map
            .iter()
            .filter_map(|entry| {
                (now.saturating_duration_since(entry.last_seen) >= ttl)
                    .then(|| (*entry.key(), FlowKey::from_entry(&entry)))
            })
            .collect();
        let mut removed = 0;
        for (id, key) in candidates {
            match self.by_flow.entry(key) {
                Entry::Occupied(index) => {
                    // insert/touch/lookup 同样先取得 flow shard，因此这里重新检查
                    // last_seen 后，旧候选无法误删刚刚 upsert 的活跃 entry。
                    let expired = self
                        .map
                        .get(&id)
                        .is_some_and(|entry| now.saturating_duration_since(entry.last_seen) >= ttl);
                    if expired && self.map.remove(&id).is_some() {
                        removed += 1;
                        // 仅当索引仍指向被删 id 时移除；兼容旧版本遗留的孤立 entry。
                        if *index.get() == id {
                            index.remove();
                        }
                    }
                }
                Entry::Vacant(_) => {
                    let expired = self
                        .map
                        .get(&id)
                        .is_some_and(|entry| now.saturating_duration_since(entry.last_seen) >= ttl);
                    if expired && self.map.remove(&id).is_some() {
                        removed += 1;
                    }
                }
            }
        }
        let pin_before = self.host_pin.len();
        self.host_pin
            .retain(|_, p| now.saturating_duration_since(p.last_seen) < ttl);
        let pin_removed = pin_before - self.host_pin.len();
        removed + pin_removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(src: &str, dst: &str, net: &'static str) -> NatEntry {
        NatEntry {
            source: src.parse().unwrap(),
            original_dst: dst.parse().unwrap(),
            fake_host: None,
            network: net,
            created_at: Instant::now(),
            last_seen: Instant::now(),
        }
    }

    fn key(src: &str, dst: &str, net: &'static str) -> FlowKey {
        FlowKey {
            network: net,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn insert_and_get() {
        let t = NatTable::default();
        let id = t.insert(entry("127.0.0.1:1000", "1.1.1.1:443", "tcp"));
        assert!(t.get(id).is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn lookup_by_flow_key() {
        let t = NatTable::default();
        let id = t.insert(entry("127.0.0.1:1000", "1.1.1.1:443", "tcp"));
        let key = FlowKey {
            network: "tcp",
            src: "127.0.0.1:1000".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
        };
        let found = t.lookup_flow(&key).expect("should find");
        assert_eq!(found.original_dst, "1.1.1.1:443".parse().unwrap());
        // remove invalidates flow lookup
        t.remove(id);
        assert!(t.lookup_flow(&key).is_none());
    }

    #[test]
    fn purge_expired_clears_flow_index() {
        let t = NatTable::new(Duration::from_millis(20));
        let _id = t.insert(entry("127.0.0.1:1000", "1.1.1.1:443", "udp"));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(t.purge(), 1);
        assert_eq!(t.len(), 0);
        let key = FlowKey {
            network: "udp",
            src: "127.0.0.1:1000".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
        };
        assert!(t.lookup_flow(&key).is_none());
    }

    #[test]
    fn same_flow_many_upserts_keep_stable_id_and_single_entry() {
        let t = NatTable::default();
        let template = entry("10.0.0.1:1000", "8.8.8.8:53", "udp");
        let id = t.insert(template.clone());
        for _ in 0..100_000 {
            let mut update = template.clone();
            update.last_seen = Instant::now();
            assert_eq!(t.insert(update), id);
        }

        let found = t
            .lookup_flow(&key("10.0.0.1:1000", "8.8.8.8:53", "udp"))
            .unwrap();
        assert_eq!(found.network, "udp");
        assert_eq!(t.len(), 1);
        assert!(t.get(id).is_some());
    }

    #[test]
    fn upsert_refreshes_expired_flow_without_old_candidate_removing_it() {
        let t = NatTable::new(Duration::from_secs(30));
        let stale_at = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        let mut stale = entry("10.0.0.1:1000", "8.8.8.8:53", "udp");
        stale.created_at = stale_at;
        stale.last_seen = stale_at;
        let id = t.insert(stale);

        let mut refreshed = entry("10.0.0.1:1000", "8.8.8.8:53", "udp");
        refreshed.fake_host = Some("dns.example".into());
        assert_eq!(t.insert(refreshed), id);

        assert_eq!(t.purge(), 0);
        assert_eq!(t.len(), 1);
        let current = t.get(id).unwrap();
        assert_eq!(current.created_at, stale_at);
        assert_eq!(current.fake_host.as_deref(), Some("dns.example"));
        assert!(
            t.lookup_flow(&key("10.0.0.1:1000", "8.8.8.8:53", "udp"))
                .is_some()
        );
    }

    #[test]
    fn distinct_flows_remain_independent() {
        let t = NatTable::default();
        let udp = t.insert(entry("10.0.0.1:1000", "8.8.8.8:53", "udp"));
        let tcp = t.insert(entry("10.0.0.1:1000", "8.8.8.8:53", "tcp"));
        let other_dst = t.insert(entry("10.0.0.1:1000", "1.1.1.1:53", "udp"));

        assert_ne!(udp, tcp);
        assert_ne!(udp, other_dst);
        assert_ne!(tcp, other_dst);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn purge_keeps_flow_index_consistent_with_main_table() {
        let t = NatTable::new(Duration::from_secs(30));
        let stale_at = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        let mut stale = entry("10.0.0.1:1000", "8.8.8.8:53", "udp");
        stale.created_at = stale_at;
        stale.last_seen = stale_at;
        let stale_id = t.insert(stale);
        let live_id = t.insert(entry("10.0.0.2:2000", "1.1.1.1:53", "udp"));

        assert_eq!(t.purge(), 1);
        assert!(t.get(stale_id).is_none());
        assert!(
            t.lookup_flow(&key("10.0.0.1:1000", "8.8.8.8:53", "udp"))
                .is_none()
        );
        assert_eq!(
            t.lookup_flow(&key("10.0.0.2:2000", "1.1.1.1:53", "udp"))
                .map(|entry| entry.original_dst),
            Some("1.1.1.1:53".parse().unwrap())
        );
        assert!(t.get(live_id).is_some());

        let replacement = t.insert(entry("10.0.0.1:1000", "8.8.8.8:53", "udp"));
        assert_ne!(replacement, stale_id);
        assert_eq!(t.len(), 2);
        assert!(
            t.lookup_flow(&key("10.0.0.1:1000", "8.8.8.8:53", "udp"))
                .is_some()
        );
    }
}
