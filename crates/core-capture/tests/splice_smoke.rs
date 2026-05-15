//! 集成测试：SpliceManager + SmolStream 在 user-stack 上的端到端可构造性。
//!
//! 真正 TCP 终结需要在 TUN 设备上注入 SYN 包，超出 cross-platform 范围；本测试
//! 仅验证：SpliceManager 能 spawn 一条 splice 任务并优雅关闭，且 abort_all
//! 不留悬挂。

use std::sync::Arc;

use core_capture::stack::{SpliceManager, UserSpaceStack};
use parking_lot::Mutex;
use smoltcp::{
    socket::tcp,
    wire::{Ipv4Address, Ipv6Address},
};
use tokio::{io::duplex, sync::Notify};

#[tokio::test]
async fn splice_manager_spawns_and_aborts() {
    let stack = Arc::new(Mutex::new(UserSpaceStack::new(
        1500,
        Ipv4Address::new(198, 18, 0, 1),
        Some(Ipv6Address::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
    )));
    let notify = Arc::new(Notify::new());
    let mgr = SpliceManager::new();
    // 创建 listener -> 拿到 SocketHandle
    let handle = {
        let mut s = stack.lock();
        let rx = tcp::SocketBuffer::new(vec![0u8; 1024]);
        let tx = tcp::SocketBuffer::new(vec![0u8; 1024]);
        s.sockets.add(tcp::Socket::new(rx, tx))
    };
    // outbound：tokio duplex pipe（一端给 splice，另一端我们模拟 echo）。
    let (a, _b) = duplex(64);
    mgr.spawn_splice(handle, stack.clone(), notify.clone(), a, None, None);
    assert_eq!(mgr.len(), 1);
    // 任务因 smoltcp 端 may_send=false（LISTEN 状态）会立刻 EOF；给它一点时间。
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    mgr.abort_all();
    assert!(mgr.is_empty());
}
