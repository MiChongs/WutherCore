//! IP→Hostname mapping cache for redir-host mode.
//!
//! Provides reverse lookup from resolved IPs back to hostnames, independent of
//! the Fake-IP pool. Used by TUN/capture to recover SNI when HTTPS is proxied.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use dashmap::DashMap;

#[derive(Debug)]
pub struct IpHostMapping {
    inner: DashMap<IpAddr, MappingEntry>,
    max_entries: usize,
}

#[derive(Debug, Clone)]
struct MappingEntry {
    host: String,
    expires: Instant,
}

impl IpHostMapping {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: DashMap::with_capacity(max_entries.min(1024)),
            max_entries,
        }
    }

    pub fn insert(&self, ip: IpAddr, host: &str, ttl: Duration) {
        let entry = MappingEntry {
            host: host.to_string(),
            expires: Instant::now() + ttl,
        };
        self.inner.insert(ip, entry);
        if self.inner.len() > self.max_entries {
            self.evict_expired();
        }
    }

    pub fn find_host(&self, ip: IpAddr) -> Option<String> {
        let entry = self.inner.get(&ip)?;
        if entry.expires < Instant::now() {
            drop(entry);
            self.inner.remove(&ip);
            return None;
        }
        Some(entry.host.clone())
    }

    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let before = self.inner.len();
        self.inner.retain(|_, v| v.expires > now);
        before - self.inner.len()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, v| v.expires > now);
    }
}

impl Default for IpHostMapping {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn insert_and_find() {
        let mapping = IpHostMapping::new(100);
        let ip: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        mapping.insert(ip, "example.com", Duration::from_secs(60));
        assert_eq!(mapping.find_host(ip), Some("example.com".to_string()));
    }

    #[test]
    fn expired_entry_returns_none() {
        let mapping = IpHostMapping::new(100);
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        mapping.insert(ip, "expired.com", Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(mapping.find_host(ip), None);
    }

    #[test]
    fn purge_removes_stale() {
        let mapping = IpHostMapping::new(100);
        mapping.insert(
            Ipv4Addr::new(1, 1, 1, 1).into(),
            "fresh.com",
            Duration::from_secs(60),
        );
        mapping.insert(
            Ipv4Addr::new(2, 2, 2, 2).into(),
            "stale.com",
            Duration::from_millis(0),
        );
        std::thread::sleep(Duration::from_millis(1));
        let purged = mapping.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(mapping.len(), 1);
    }

    #[test]
    fn ipv6_support() {
        let mapping = IpHostMapping::new(100);
        let ip: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        mapping.insert(ip, "v6.example.com", Duration::from_secs(60));
        assert_eq!(mapping.find_host(ip), Some("v6.example.com".to_string()));
    }

    #[test]
    fn eviction_on_overflow() {
        let mapping = IpHostMapping::new(5);
        for i in 0..10u8 {
            mapping.insert(
                Ipv4Addr::new(10, 0, 0, i).into(),
                &format!("host{i}.com"),
                if i < 5 {
                    Duration::from_millis(0)
                } else {
                    Duration::from_secs(60)
                },
            );
        }
        std::thread::sleep(Duration::from_millis(1));
        // After eviction of expired, should only have the fresh entries
        mapping.evict_expired();
        assert!(mapping.len() <= 5);
    }

    #[test]
    fn overwrite_existing() {
        let mapping = IpHostMapping::new(100);
        let ip: IpAddr = Ipv4Addr::new(5, 5, 5, 5).into();
        mapping.insert(ip, "old.com", Duration::from_secs(60));
        mapping.insert(ip, "new.com", Duration::from_secs(60));
        assert_eq!(mapping.find_host(ip), Some("new.com".to_string()));
    }
}
