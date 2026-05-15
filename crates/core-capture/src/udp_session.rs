//! TUN UDP 5-tuple ⇄ outbound socket 复用表 —— 与 mihomo `sing-tun` 的
//! `endpoint_independent_nat` / 5-tuple session 行为对齐。
//!
//! ## 核心问题
//! 旧实现（已废弃）每收到一个 UDP 包就 `runtime.dial_udp` + 新建 outbound
//! socket + spawn reverse loop。一个 QUIC stream 1s 内 50-200 包 → 同 5-tuple
//! 几十次 dial、dashboard `/connections` 被同来源条目淹没、STUN 5-tuple 不稳定。
//!
//! 本表把"同 5-tuple"的所有后续包路由到 *第一个* 包建立的 outbound socket：
//! 1. 第 1 包 → 查表未命中 → `dial_udp` + 注册 [`UdpSession`] + spawn 1 条
//!    reverse loop 长期持有这个 session。
//! 2. 第 N 包 → 查表命中 → `socket.send_to(...)` + 续 `last_seen`。
//! 3. 周期 `purge(idle)`（supervisor 调用）→ 移除超过 `udp_timeout` 没活动的
//!    session；`Arc<UdpSession>` 引用为 0 时 reverse loop 通过 `cancel.notify`
//!    或 `recv_from` EOF 自然退出，`ConnectionGuard` drop 时自动从
//!    `ConnectionTable` 移除（dashboard `/connections` 同步消失）。

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use core_observe::ConnectionGuard;
use core_outbound::adapter::BoxedUdp;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::mpsc;

/// 新 UDP flow 在 outbound dial 完成前最多缓存的 payload 数。
/// 与 mihomo NAT 首包入队语义对齐：TUN pump 只负责投递，不等待拨号。
pub const UDP_PENDING_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct UdpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub struct UdpSession {
    /// 持有 outbound 出站 socket —— 与 mihomo NAT entry 的"已分配 socket"等价。
    pub socket: BoxedUdp,
    /// 持有 ConnectionTable guard：dashboard 看到一条 long session（network=udp）。
    pub guard: ConnectionGuard,
    /// 解析后的目标 host 字符串（DirectUdp.send_to 时用；后续可缓存解析结果）。
    pub target_host: String,
    pub target_port: u16,
    /// 最近活动时间 —— purge 判定依据。
    pub last_seen: Mutex<Instant>,
}

impl UdpSession {
    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }
}

pub struct PendingUdpSession {
    sender: mpsc::Sender<Vec<u8>>,
    last_seen: Mutex<Instant>,
}

impl PendingUdpSession {
    pub fn new(capacity: usize) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Arc::new(Self {
                sender: tx,
                last_seen: Mutex::new(Instant::now()),
            }),
            rx,
        )
    }

    pub fn try_send(&self, payload: Vec<u8>) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.sender.try_send(payload)?;
        self.touch();
        Ok(())
    }

    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    fn last_seen(&self) -> Instant {
        *self.last_seen.lock()
    }
}

pub struct UdpSessionTable {
    inner: DashMap<UdpFlowKey, Arc<UdpSession>>,
    pending: DashMap<UdpFlowKey, Arc<PendingUdpSession>>,
    idle: Duration,
}

impl std::fmt::Debug for UdpSessionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionTable")
            .field("len", &self.inner.len())
            .field("pending_len", &self.pending.len())
            .field("idle", &self.idle)
            .finish()
    }
}

impl UdpSessionTable {
    pub fn new(idle: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            pending: DashMap::new(),
            idle,
        }
    }

    pub fn lookup(&self, key: &UdpFlowKey) -> Option<Arc<UdpSession>> {
        self.inner.get(key).map(|e| e.value().clone())
    }

    pub fn insert(&self, key: UdpFlowKey, session: Arc<UdpSession>) {
        self.inner.insert(key, session);
    }

    pub fn remove(&self, key: &UdpFlowKey) {
        if let Some((_, session)) = self.inner.remove(key) {
            session.guard.cancel.notify_waiters();
        }
    }

    pub fn lookup_pending(&self, key: &UdpFlowKey) -> Option<Arc<PendingUdpSession>> {
        self.pending.get(key).map(|e| e.value().clone())
    }

    pub fn insert_pending(&self, key: UdpFlowKey, session: Arc<PendingUdpSession>) {
        self.pending.insert(key, session);
    }

    pub fn remove_pending(&self, key: &UdpFlowKey) {
        self.pending.remove(key);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty() && self.pending.is_empty()
    }

    /// 周期 GC：移除超过 idle 没活动的 session。返回移除条数。
    /// 被移除的 session：
    /// * `Arc<UdpSession>` 计数减 1；如果 reverse loop 持有的引用是最后一个，
    ///   则 session drop 时连带 ConnectionGuard drop → ConnectionTable 自动清理。
    /// * 实际调用方（reverse loop）下一次 recv_from 出错或被 cancel 唤醒时退出。
    pub fn purge(&self) -> usize {
        let cutoff = Instant::now() - self.idle;
        let sessions_to_remove: Vec<UdpFlowKey> = self
            .inner
            .iter()
            .filter_map(|e| {
                let ls = *e.value().last_seen.lock();
                if ls < cutoff { Some(*e.key()) } else { None }
            })
            .collect();
        let pending_to_remove: Vec<UdpFlowKey> = self
            .pending
            .iter()
            .filter_map(|e| {
                if e.value().last_seen() < cutoff {
                    Some(*e.key())
                } else {
                    None
                }
            })
            .collect();
        let n = sessions_to_remove.len() + pending_to_remove.len();
        for k in sessions_to_remove {
            // 触发 cancel 让 reverse loop 退出；从表移除。
            if let Some((_, s)) = self.inner.remove(&k) {
                s.guard.cancel.notify_waiters();
            }
        }
        for k in pending_to_remove {
            self.pending.remove(&k);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_key(src_port: u16, dst_port: u16) -> UdpFlowKey {
        UdpFlowKey {
            src: format!("10.0.0.1:{src_port}").parse().unwrap(),
            dst: format!("8.8.8.8:{dst_port}").parse().unwrap(),
        }
    }

    #[test]
    fn empty_table() {
        let t = UdpSessionTable::new(Duration::from_secs(60));
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.lookup(&fake_key(1, 53)).is_none());
        assert_eq!(t.purge(), 0);
    }

    #[tokio::test]
    async fn pending_queue_buffers_packets_until_dial_worker_establishes_session() {
        let t = UdpSessionTable::new(Duration::from_secs(60));
        let key = fake_key(50000, 443);
        let (pending, mut rx) = super::PendingUdpSession::new(2);

        t.insert_pending(key, pending.clone());
        pending.try_send(vec![1, 2, 3]).unwrap();
        pending.try_send(vec![4, 5, 6]).unwrap();

        assert!(t.lookup_pending(&key).is_some());
        assert_eq!(rx.recv().await.unwrap(), vec![1, 2, 3]);
        assert_eq!(rx.recv().await.unwrap(), vec![4, 5, 6]);

        t.remove_pending(&key);
        assert!(t.lookup_pending(&key).is_none());
    }

    // 注：完整的 lookup/insert 单测需要构造 UdpSession（依赖 BoxedUdp + ConnectionGuard
    // 的 mock）。整链路验证放在 tests/tun_udp_reuse.rs。这里只覆盖空表与 GC 边界。
}
