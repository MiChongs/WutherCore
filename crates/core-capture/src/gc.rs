//! 派发器 NAT / session 表的周期清理任务。
//!
//! supervisor 已经为 `nat::NatTable` / `eim_nat::EimNatTable` 起了独立的 purge_handle；
//! 但 `tcp_nat::TcpNat`（system stack）和 `udp_session::UdpSessionTable`（两路派发器）
//! 是在 dispatcher 启动时才创建的，supervisor 不持有引用。所以由 dispatcher 自己起 GC。
//!
//! 周期与 supervisor 对齐：`max(udp_timeout / 2, 5s)`。

use std::{sync::Arc, time::Duration};

use tokio::{sync::oneshot, task::JoinHandle, time::MissedTickBehavior};
use tracing::debug;

use crate::{tcp_nat::TcpNat, udp_session::UdpSessionTable};

/// 计算 GC 周期：`max(udp_timeout/2, 5s)`，与 supervisor 一致。
pub fn purge_period(udp_timeout: Duration) -> Duration {
    std::cmp::max(Duration::from_secs(5), udp_timeout / 2)
}

/// SystemDispatcher 用 —— 同时清理 TCP NAT + UDP session。
///
/// 返回 `(JoinHandle, oneshot stop sender)`；调用方在 stop() 时先发停止信号再 abort。
pub fn spawn_system_gc(
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<UdpSessionTable>,
    udp_timeout: Duration,
) -> (JoinHandle<()>, oneshot::Sender<()>) {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let period = purge_period(udp_timeout);
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // 跳过首个立即 tick，避免启动瞬间空转。
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = ticker.tick() => {
                    let tcp_removed = tcp_nat.purge_expired();
                    let udp_removed = udp_sessions.purge();
                    if tcp_removed + udp_removed > 0 {
                        debug!(
                            target: "capture::system",
                            tcp_removed,
                            udp_removed,
                            tcp_remaining = tcp_nat.len(),
                            udp_remaining = udp_sessions.len(),
                            "system gc"
                        );
                    }
                }
            }
        }
    });
    (handle, stop_tx)
}

/// TunDispatcher 用 —— 仅清理 UDP session（TCP 状态由 smoltcp 自身回收）。
pub fn spawn_tun_gc(
    udp_sessions: Arc<UdpSessionTable>,
    udp_timeout: Duration,
) -> (JoinHandle<()>, oneshot::Sender<()>) {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let period = purge_period(udp_timeout);
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = ticker.tick() => {
                    let removed = udp_sessions.purge();
                    if removed > 0 {
                        debug!(
                            target: "capture::tun",
                            udp_removed = removed,
                            udp_remaining = udp_sessions.len(),
                            "tun gc"
                        );
                    }
                }
            }
        }
    });
    (handle, stop_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_period_floor_is_5s() {
        assert_eq!(purge_period(Duration::from_secs(0)), Duration::from_secs(5));
        assert_eq!(purge_period(Duration::from_secs(8)), Duration::from_secs(5));
    }

    #[test]
    fn purge_period_scales_with_udp_timeout() {
        assert_eq!(
            purge_period(Duration::from_secs(60)),
            Duration::from_secs(30)
        );
        assert_eq!(
            purge_period(Duration::from_secs(300)),
            Duration::from_secs(150)
        );
    }

    /// 起 GC，立即发停止信号，验证 stop_tx 能正常关闭任务（不卡死）。
    #[tokio::test(flavor = "current_thread")]
    async fn system_gc_stops_on_signal() {
        let tcp_nat = Arc::new(TcpNat::new(Duration::from_millis(10)));
        let udp_sessions = Arc::new(UdpSessionTable::new(Duration::from_millis(10)));
        let (handle, stop_tx) = spawn_system_gc(tcp_nat, udp_sessions, Duration::from_secs(60));
        stop_tx.send(()).expect("stop tx send");
        // GC 任务应在 stop_rx 触发后立即退出
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("gc task should exit within 2s")
            .expect("gc task did not panic");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_gc_stops_on_signal() {
        let udp_sessions = Arc::new(UdpSessionTable::new(Duration::from_millis(10)));
        let (handle, stop_tx) = spawn_tun_gc(udp_sessions, Duration::from_secs(60));
        stop_tx.send(()).expect("stop tx send");
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("gc task should exit within 2s")
            .expect("gc task did not panic");
    }
}
