//! LRU + TTL cache for process lookups.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{NetworkProto, ProcessFinder, ProcessInfo};

type Key = (NetworkProto, IpAddr, u16);

#[derive(Debug, Clone)]
struct Entry {
    info: Option<ProcessInfo>,
    expires: Instant,
    /// Linked-list pointer: index of newer entry (LRU recency tracking).
    /// `usize::MAX` means newest.
    newer: usize,
    older: usize,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    ttl: Duration,
    /// `Key → slot index`.
    index: HashMap<Key, usize>,
    /// Slot storage; reused via `free` stack.
    slots: Vec<Option<(Key, Entry)>>,
    free: Vec<usize>,
    head: usize, // newest slot, MAX if empty
    tail: usize, // oldest slot, MAX if empty
}

const NIL: usize = usize::MAX;

impl Inner {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            index: HashMap::with_capacity(capacity),
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
        }
    }

    fn unlink(&mut self, idx: usize) {
        let (newer, older) = match &self.slots[idx] {
            Some((_, e)) => (e.newer, e.older),
            None => return,
        };
        if newer != NIL {
            if let Some((_, e)) = &mut self.slots[newer] {
                e.older = older;
            }
        } else {
            self.head = older;
        }
        if older != NIL {
            if let Some((_, e)) = &mut self.slots[older] {
                e.newer = newer;
            }
        } else {
            self.tail = newer;
        }
    }

    fn link_head(&mut self, idx: usize) {
        let prev_head = self.head;
        if let Some((_, e)) = &mut self.slots[idx] {
            e.newer = NIL;
            e.older = prev_head;
        }
        if prev_head != NIL {
            if let Some((_, e)) = &mut self.slots[prev_head] {
                e.newer = idx;
            }
        } else {
            self.tail = idx;
        }
        self.head = idx;
    }

    fn evict_oldest(&mut self) {
        let oldest = self.tail;
        if oldest == NIL {
            return;
        }
        self.unlink(oldest);
        if let Some((key, _)) = self.slots[oldest].take() {
            self.index.remove(&key);
        }
        self.free.push(oldest);
    }

    fn get(&mut self, key: &Key) -> Option<Option<ProcessInfo>> {
        let idx = *self.index.get(key)?;
        let now = Instant::now();
        let expired = match &self.slots[idx] {
            Some((_, e)) => e.expires <= now,
            None => return None,
        };
        if expired {
            self.unlink(idx);
            if let Some((k, _)) = self.slots[idx].take() {
                self.index.remove(&k);
            }
            self.free.push(idx);
            return None;
        }
        // Bump to head (MRU)
        self.unlink(idx);
        self.link_head(idx);
        self.slots[idx].as_ref().map(|(_, e)| e.info.clone())
    }

    fn insert(&mut self, key: Key, info: Option<ProcessInfo>) {
        if let Some(&idx) = self.index.get(&key) {
            self.unlink(idx);
            if let Some((_, e)) = &mut self.slots[idx] {
                e.info = info;
                e.expires = Instant::now() + self.ttl;
            }
            self.link_head(idx);
            return;
        }
        if self.index.len() >= self.capacity {
            self.evict_oldest();
        }
        let idx = if let Some(i) = self.free.pop() {
            i
        } else {
            self.slots.push(None);
            self.slots.len() - 1
        };
        self.slots[idx] = Some((
            key,
            Entry {
                info,
                expires: Instant::now() + self.ttl,
                newer: NIL,
                older: NIL,
            },
        ));
        self.index.insert(key, idx);
        self.link_head(idx);
    }
}

/// 给任意 [`ProcessFinder`] 加 LRU + TTL cache。
pub struct CachedFinder {
    inner: Arc<dyn ProcessFinder>,
    state: Mutex<Inner>,
}

impl std::fmt::Debug for CachedFinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedFinder").finish_non_exhaustive()
    }
}

impl CachedFinder {
    pub fn new(inner: Arc<dyn ProcessFinder>, capacity: usize, ttl: Duration) -> Self {
        Self {
            inner,
            state: Mutex::new(Inner::new(capacity.max(1), ttl)),
        }
    }
}

impl ProcessFinder for CachedFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        let key = (proto, src_ip, src_port);
        if let Some(cached) = self.state.lock().get(&key) {
            return cached;
        }
        // miss → real lookup outside锁
        let result = self.inner.find(proto, src_ip, src_port);
        self.state.lock().insert(key, result.clone());
        result
    }

    fn find_with_dst(
        &self,
        proto: NetworkProto,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<ProcessInfo> {
        // (src_ip, src_port) 唯一对应一个 socket → 一个进程；dst 不影响归属。
        // 因此 cache key 仍按 src 维度，dst 只在 miss 时透传给 inner。
        let key = (proto, src_ip, src_port);
        if let Some(cached) = self.state.lock().get(&key) {
            return cached;
        }
        let result = self
            .inner
            .find_with_dst(proto, src_ip, src_port, dst_ip, dst_port);
        self.state.lock().insert(key, result.clone());
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingFinder {
        calls: AtomicUsize,
        result: Option<ProcessInfo>,
    }

    impl ProcessFinder for CountingFinder {
        fn find(&self, _: NetworkProto, _: IpAddr, _: u16) -> Option<ProcessInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cache_returns_inner_result_and_dedupes() {
        let inner = Arc::new(CountingFinder {
            calls: AtomicUsize::new(0),
            result: Some(ProcessInfo {
                name: "x".into(),
                path: "/x".into(),
                uid: 1000,
            }),
        });
        let cached = CachedFinder::new(inner.clone(), 4, Duration::from_secs(10));
        for _ in 0..5 {
            let r = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 1234);
            assert_eq!(r.unwrap().name, "x");
        }
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "cached miss expected once"
        );
    }

    #[test]
    fn cache_invalidates_on_ttl() {
        let inner = Arc::new(CountingFinder {
            calls: AtomicUsize::new(0),
            result: None,
        });
        let cached = CachedFinder::new(inner.clone(), 4, Duration::from_millis(20));
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 1);
        std::thread::sleep(Duration::from_millis(40));
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 1);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cache_evicts_lru_when_full() {
        let inner = Arc::new(CountingFinder {
            calls: AtomicUsize::new(0),
            result: None,
        });
        let cached = CachedFinder::new(inner.clone(), 2, Duration::from_secs(10));
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 1);
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 2);
        // touch key1 → LRU is key2
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 1);
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 3); // should evict key2
        // key2 lookup should miss
        let before = inner.calls.load(Ordering::SeqCst);
        let _ = cached.find(NetworkProto::Tcp, ip("10.0.0.1"), 2);
        let after = inner.calls.load(Ordering::SeqCst);
        assert_eq!(after - before, 1, "key2 should have been evicted");
    }
}
