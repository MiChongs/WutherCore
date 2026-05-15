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

use dashmap::DashMap;

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

    /// 插入新会话。如果同 flow 已存在则覆盖（旧 id 保留为孤立 entry，后续 purge 回收）。
    pub fn insert(&self, entry: NatEntry) -> u64 {
        let key = FlowKey::from_entry(&entry);
        let id = {
            let mut g = self.next_id.lock();
            let id = *g;
            *g = g.wrapping_add(1);
            id
        };
        self.by_flow.insert(key, id);
        self.map.insert(id, entry);
        id
    }

    pub fn touch(&self, id: u64) {
        if let Some(mut e) = self.map.get_mut(&id) {
            e.last_seen = Instant::now();
        }
    }

    /// 通过 5-tuple 找会话，并 touch last_seen。
    pub fn lookup_flow(&self, key: &FlowKey) -> Option<NatEntry> {
        let id = *self.by_flow.get(key)?;
        let mut entry_ref = self.map.get_mut(&id)?;
        entry_ref.last_seen = Instant::now();
        Some(entry_ref.clone())
    }

    pub fn remove(&self, id: u64) -> Option<NatEntry> {
        let entry = self.map.remove(&id).map(|(_, v)| v)?;
        self.by_flow.remove(&FlowKey::from_entry(&entry));
        Some(entry)
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
        let mut removed: Vec<FlowKey> = Vec::new();
        self.map.retain(|_id, e| {
            let alive = now.duration_since(e.last_seen) < ttl;
            if !alive {
                removed.push(FlowKey::from_entry(e));
            }
            alive
        });
        for k in &removed {
            self.by_flow.remove(k);
        }
        let pin_before = self.host_pin.len();
        self.host_pin
            .retain(|_, p| now.duration_since(p.last_seen) < ttl);
        let pin_removed = pin_before - self.host_pin.len();
        removed.len() + pin_removed
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
    fn duplicate_flow_overwrites_index() {
        let t = NatTable::default();
        let id1 = t.insert(entry("10.0.0.1:1000", "8.8.8.8:53", "udp"));
        let id2 = t.insert(entry("10.0.0.1:1000", "8.8.8.8:53", "udp"));
        let key = FlowKey {
            network: "udp",
            src: "10.0.0.1:1000".parse().unwrap(),
            dst: "8.8.8.8:53".parse().unwrap(),
        };
        let found = t.lookup_flow(&key).unwrap();
        assert_eq!(found.network, "udp");
        // 旧 entry 仍可通过 id1 取到（待 purge 回收）；新插入的 id2 正常
        assert!(t.get(id1).is_some());
        assert!(t.get(id2).is_some());
    }
}
