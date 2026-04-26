//! Endpoint-Independent Mapping (EIM) NAT —— 全锥 NAT。
//!
//! 与 [`NatTable`] 的 5-tuple 模型不同：EIM-NAT 把同一内部 `(src_ip, src_port)`
//! 映射到 *同一个* 出站 socket，无论目标 (dst_ip, dst_port) 如何变化；
//! 反之，外部 *任意* 源都可以通过该出站 socket 给内部回包。
//!
//! 这是 STUN-friendly 的 UDP 行为，主要用于 P2P / WebRTC / VoIP / 游戏。
//! sing-box `endpoint_independent_nat: true` 触发本表参与 dispatch。
//!
//! 设计要点：
//! * key = `(network, src_addr)`，与目标完全无关；
//! * value 持有一个 `Arc<UdpSocket>` —— 外部源回包共用；
//! * 老化使用与 [`NatTable`] 相同的 `udp_timeout`。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EimKey {
    pub network: &'static str, // "udp"（保留扩展性）
    pub inner_src: SocketAddr,
}

#[derive(Clone)]
pub struct EimEntry {
    pub outbound: Arc<UdpSocket>,
    pub last_seen: Instant,
}

impl std::fmt::Debug for EimEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EimEntry")
            .field("outbound", &self.outbound.local_addr().ok())
            .field("last_seen", &self.last_seen)
            .finish()
    }
}

#[derive(Debug)]
pub struct EimNatTable {
    map: DashMap<EimKey, EimEntry>,
    ttl: Duration,
}

impl EimNatTable {
    pub fn new(ttl: Duration) -> Self {
        Self { map: DashMap::new(), ttl }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 取得或建立映射。`build` 闭包仅当 key 不存在时被调用（创建出站 socket）。
    pub fn get_or_insert_with<F>(&self, key: EimKey, build: F) -> std::io::Result<Arc<UdpSocket>>
    where
        F: FnOnce() -> std::io::Result<Arc<UdpSocket>>,
    {
        if let Some(mut e) = self.map.get_mut(&key) {
            e.last_seen = Instant::now();
            return Ok(e.outbound.clone());
        }
        let sock = build()?;
        let entry = EimEntry { outbound: sock.clone(), last_seen: Instant::now() };
        self.map.insert(key, entry);
        Ok(sock)
    }

    pub fn touch(&self, key: &EimKey) {
        if let Some(mut e) = self.map.get_mut(key) {
            e.last_seen = Instant::now();
        }
    }

    pub fn lookup(&self, key: &EimKey) -> Option<Arc<UdpSocket>> {
        self.map.get(key).map(|e| e.outbound.clone())
    }

    pub fn remove(&self, key: &EimKey) -> Option<Arc<UdpSocket>> {
        self.map.remove(key).map(|(_, v)| v.outbound)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 周期性清理（与 NatTable 共用 udp_timeout）。返回被清理条数。
    pub fn purge(&self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;
        let before = self.map.len();
        self.map.retain(|_, e| now.duration_since(e.last_seen) < ttl);
        before - self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> EimKey {
        EimKey { network: "udp", inner_src: s.parse().unwrap() }
    }

    /// 同步 bind —— 避免在 build 闭包里使用 async（block_on 在 tokio 运行时里 panic）。
    fn fake_socket() -> std::io::Result<Arc<UdpSocket>> {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock).map(Arc::new)
    }

    #[tokio::test]
    async fn shares_socket_across_destinations() {
        let table = EimNatTable::new(Duration::from_secs(60));
        let s1 = fake_socket().unwrap();
        let s1c = s1.clone();
        let r1 = table
            .get_or_insert_with(key("10.0.0.1:5000"), || Ok(s1c))
            .unwrap();
        let r2 = table
            .get_or_insert_with(key("10.0.0.1:5000"), || panic!("should not rebuild"))
            .unwrap();
        assert!(Arc::ptr_eq(&r1, &r2));
        assert!(Arc::ptr_eq(&r1, &s1));
        assert_eq!(table.len(), 1);
    }

    #[tokio::test]
    async fn different_inner_keys_different_sockets() {
        let table = EimNatTable::new(Duration::from_secs(60));
        let _ = table.get_or_insert_with(key("10.0.0.1:5000"), fake_socket);
        let _ = table.get_or_insert_with(key("10.0.0.2:6000"), fake_socket);
        assert_eq!(table.len(), 2);
    }

    #[tokio::test]
    async fn purge_drops_expired() {
        let table = EimNatTable::new(Duration::from_millis(10));
        let _ = table.get_or_insert_with(key("10.0.0.1:1000"), fake_socket);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(table.purge(), 1);
        assert!(table.is_empty());
    }
}
