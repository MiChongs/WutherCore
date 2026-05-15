//! TCP NAT 端口表 —— sing-tun system stack 等价物。
//!
//! ## 模型
//! - 客户端流 `(client_ip:client_port → real_dst:real_port)` 由 [`TcpNat::lookup`]
//!   分配一个 NAT 端口 P；改写后的 IP 包以 P 作为源端口、TUN-IP 作为目标，
//!   送到 OS listener 上。
//! - listener `accept` 后用 `conn.peer_addr().port()` 经 [`TcpNat::lookup_back`]
//!   反查到原始 (source, destination)，喂给 `ListenerHandler.prepare_tcp`。
//! - session 长时间无活动后由 [`TcpNat::purge_expired`] 周期清理；与
//!   `udp_session` 的 timeout 对齐（默认 5 分钟）。
//!
//! ## 端口分配
//! - 范围 `[PORT_RANGE_START, PORT_RANGE_END]`（30000~65535，约 35.5k 并发上限）。
//! - 起点单调推进（`AtomicU16` fetch_add + 回绕模运算），冲突时跳过；最多扫一圈。
//! - 已存在 (src, dst) 复用同一端口（命中 5-tuple 缓存）。

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use parking_lot::Mutex;

const PORT_RANGE_START: u16 = 30_000;
const PORT_RANGE_END: u16 = 65_535;
const PORT_RANGE_SPAN: u32 = (PORT_RANGE_END - PORT_RANGE_START) as u32 + 1;

/// 单条 NAT 会话。
#[derive(Debug)]
pub struct NatSession {
    /// 原始客户端套接字（TUN 内部 src）。
    pub source: SocketAddr,
    /// 原始目标套接字（真实 dst）。
    pub destination: SocketAddr,
    last_seen: Mutex<Instant>,
}

impl NatSession {
    fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
            last_seen: Mutex::new(Instant::now()),
        }
    }

    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    pub fn last_seen(&self) -> Instant {
        *self.last_seen.lock()
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct NatKey {
    source: SocketAddr,
    destination: SocketAddr,
}

/// TCP NAT 表。所有方法 lock-free 或 fine-grained lock，可在 packet 路径上直接调用。
#[derive(Debug)]
pub struct TcpNat {
    timeout: Duration,
    next_port: AtomicU16,
    /// natPort → session
    by_port: DashMap<u16, Arc<NatSession>>,
    /// (src, dst) → natPort
    by_5tuple: DashMap<NatKey, u16>,
}

impl TcpNat {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            next_port: AtomicU16::new(PORT_RANGE_START),
            by_port: DashMap::new(),
            by_5tuple: DashMap::new(),
        }
    }

    /// 为 `(source, destination)` 分配（或复用）一个 NAT 端口。
    /// 返回 `None` 表示端口范围耗尽。
    pub fn lookup(&self, source: SocketAddr, destination: SocketAddr) -> Option<u16> {
        let key = NatKey {
            source,
            destination,
        };

        if let Some(port) = self.by_5tuple.get(&key).map(|p| *p) {
            // 已分配：校验 by_port 一致，触新 last_seen 后返回。
            if let Some(session) = self.by_port.get(&port) {
                session.touch();
                return Some(port);
            }
            // 反向条目缺失（被清理过）—— 移除残留 5-tuple，重新分配。
            self.by_5tuple.remove(&key);
        }

        // 分配新端口：最多扫满整个 range 一次。
        for _ in 0..PORT_RANGE_SPAN {
            let raw = self.next_port.fetch_add(1, Ordering::Relaxed);
            let port = port_in_range(raw);
            // 占用检测：DashMap::entry 提供原子 insert-if-absent
            let entry = self.by_port.entry(port);
            match entry {
                dashmap::mapref::entry::Entry::Occupied(_) => continue,
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    let session = Arc::new(NatSession::new(source, destination));
                    slot.insert(session);
                    self.by_5tuple.insert(key, port);
                    return Some(port);
                }
            }
        }
        None
    }

    /// 反查：给定 NAT 端口，返回对应 session。
    pub fn lookup_back(&self, port: u16) -> Option<Arc<NatSession>> {
        let session = self.by_port.get(&port)?.clone();
        session.touch();
        Some(session)
    }

    /// 清理过期会话。建议由 supervisor 每 30s 触发一次。
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let timeout = self.timeout;
        let mut victims: Vec<(u16, NatKey)> = Vec::new();
        for entry in self.by_port.iter() {
            if now.duration_since(entry.value().last_seen()) > timeout {
                victims.push((
                    *entry.key(),
                    NatKey {
                        source: entry.value().source,
                        destination: entry.value().destination,
                    },
                ));
            }
        }
        let removed = victims.len();
        for (port, key) in victims {
            self.by_port.remove(&port);
            self.by_5tuple.remove(&key);
        }
        removed
    }

    /// 主动移除：连接关闭时调（accept_loop 收到 EOF / RST 后）。
    pub fn remove_by_port(&self, port: u16) {
        if let Some((_, session)) = self.by_port.remove(&port) {
            self.by_5tuple.remove(&NatKey {
                source: session.source,
                destination: session.destination,
            });
        }
    }

    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

fn port_in_range(raw: u16) -> u16 {
    PORT_RANGE_START + ((raw.wrapping_sub(PORT_RANGE_START) as u32) % PORT_RANGE_SPAN) as u16
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn sa(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    #[test]
    fn lookup_assigns_port_in_range() {
        let nat = TcpNat::new(Duration::from_secs(60));
        let port = nat
            .lookup(sa([10, 0, 0, 1], 12345), sa([1, 1, 1, 1], 443))
            .unwrap();
        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&port));
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn lookup_reuses_port_for_same_5tuple() {
        let nat = TcpNat::new(Duration::from_secs(60));
        let src = sa([10, 0, 0, 1], 12345);
        let dst = sa([1, 1, 1, 1], 443);
        let p1 = nat.lookup(src, dst).unwrap();
        let p2 = nat.lookup(src, dst).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn lookup_back_returns_original_session() {
        let nat = TcpNat::new(Duration::from_secs(60));
        let src = sa([10, 0, 0, 1], 12345);
        let dst = sa([1, 1, 1, 1], 443);
        let port = nat.lookup(src, dst).unwrap();
        let s = nat.lookup_back(port).unwrap();
        assert_eq!(s.source, src);
        assert_eq!(s.destination, dst);
    }

    #[test]
    fn lookup_back_unknown_port_returns_none() {
        let nat = TcpNat::new(Duration::from_secs(60));
        assert!(nat.lookup_back(40_000).is_none());
    }

    #[test]
    fn many_distinct_flows_get_unique_ports() {
        let nat = TcpNat::new(Duration::from_secs(60));
        let mut ports = std::collections::HashSet::new();
        for i in 0..1000u32 {
            let src = sa([10, 0, 0, 1], (i & 0xffff) as u16);
            let dst = sa([1, 1, 1, 1], 443);
            let p = nat
                .lookup(src, dst)
                .expect("port should be available within range");
            assert!(ports.insert(p), "port {p} reused for distinct flow");
        }
        assert_eq!(nat.len(), 1000);
    }

    #[test]
    fn remove_by_port_clears_both_indexes() {
        let nat = TcpNat::new(Duration::from_secs(60));
        let src = sa([10, 0, 0, 1], 12345);
        let dst = sa([1, 1, 1, 1], 443);
        let port = nat.lookup(src, dst).unwrap();
        nat.remove_by_port(port);
        assert!(nat.is_empty());
        // 移除后再 lookup 应得到一个端口（可能恰好是同一个，也可能不同；只要成功即可）
        assert!(nat.lookup(src, dst).is_some());
    }

    #[test]
    fn purge_expired_drops_old_sessions_only() {
        let nat = TcpNat::new(Duration::from_millis(10));
        let _p1 = nat
            .lookup(sa([10, 0, 0, 1], 1), sa([1, 1, 1, 1], 80))
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let p2 = nat
            .lookup(sa([10, 0, 0, 2], 2), sa([1, 1, 1, 1], 80))
            .unwrap();
        let removed = nat.purge_expired();
        assert_eq!(removed, 1, "only the old session should be purged");
        assert_eq!(nat.len(), 1);
        // 新的 session 仍可反查
        assert!(nat.lookup_back(p2).is_some());
    }

    #[test]
    fn port_in_range_wraps_correctly() {
        assert_eq!(port_in_range(PORT_RANGE_START), PORT_RANGE_START);
        assert_eq!(port_in_range(PORT_RANGE_END), PORT_RANGE_END);
        // u16 自然回绕到 0 后再次进入函数 —— 应映射回 START 附近
        let mapped = port_in_range(0);
        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&mapped));
    }
}
