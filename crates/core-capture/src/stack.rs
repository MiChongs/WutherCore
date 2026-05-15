//! 用户态 TCP/UDP 栈 —— 把从 TUN 读到的 IP 包丢给 smoltcp，
//! 终结 TCP 流后通过 [`Runtime::dial`] splice 到 outbound；UDP 包旁路到
//! [`udp_forwarder`]（外部模块）。
//!
//! 架构：
//! ```text
//!     TUN device  ──read─► VirtualTunDevice (smoltcp::Device 实现)
//!                                ▲   │
//!                                │   ▼
//!     TUN device  ◄──write── pending tx queue
//!                                │
//!                          smoltcp Interface  (poll 驱动)
//!                                │
//!                          accept TCP socket（ESTABLISHED）
//!                                │
//!                                ▼
//!                       runtime.dial(host,port,Tcp)
//!                                │
//!                                ▼
//!                       splice (smoltcp socket ↔ outbound stream)
//! ```
//!
//! 工程要点：
//! * VirtualTunDevice 用 VecDeque 做 rx/tx 缓冲；poll 一次拉一批；
//! * UserSpaceStack 通过 tokio::sync::Notify 实现"poll 时机"通知；
//! * SpliceManager 跟踪每个 SocketHandle 的 outbound 任务，graceful close。

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, atomic::Ordering},
};

use parking_lot::Mutex;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv6Address},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};
use tracing::{info, warn};

/* ============================================================
VirtualTunDevice：smoltcp::phy::Device 实现
============================================================ */

pub struct VirtualTunDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    pub mtu: usize,
}

impl VirtualTunDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }
    pub fn inject(&mut self, pkt: Vec<u8>) {
        self.rx_queue.push_back(pkt);
    }
    pub fn drain_outbound(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.tx_queue.drain(..)
    }
}

pub struct VirtualRxToken {
    buf: Vec<u8>,
}
pub struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.buf)
    }
}
impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.queue.push_back(buf);
        r
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(VirtualRxToken, VirtualTxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { buf: pkt },
            VirtualTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }
    fn transmit(&mut self, _ts: SmolInstant) -> Option<VirtualTxToken<'_>> {
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/* ============================================================
UserSpaceStack：Interface + SocketSet + 监听 socket 池
============================================================ */

#[derive(Debug, Clone)]
pub struct AcceptedTcp {
    pub handle: SocketHandle,
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
    /// 客户端原本想去的目标 = TUN 内"虚拟服务端"的 endpoint。
    pub original_dst: std::net::SocketAddr,
}

pub struct UserSpaceStack {
    pub iface: Interface,
    pub device: VirtualTunDevice,
    pub sockets: SocketSet<'static>,
    /// 按目标端口维护 listener handle 池：同一端口可有多个 listener 同时存在
    /// 以并发接受同端口多条 SYN（smoltcp 一个 listening socket accept 后
    /// 进入 ESTABLISHED，必须再补一个 listener 才能继续接同端口的下一条流）。
    listeners_by_port: HashMap<u16, Vec<SocketHandle>>,
    /// 已上报过 accept 的 handle（避免重复）。
    accepted_set: HashSet<SocketHandle>,
}

impl UserSpaceStack {
    pub fn new(mtu: usize, v4: Ipv4Address, v6: Option<Ipv6Address>) -> Self {
        let mut device = VirtualTunDevice::new(mtu);
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(now_millis()));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            if let Some(v6_addr) = v6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6_addr), 128));
            }
        });
        // ⭐ 关键：TUN 上的真实包目标 IP 是任意 destination（如 1.2.3.4），
        // 不会等于本 iface 自身的 IP（198.18.0.1）。set_any_ip(true) 让 smoltcp
        // 接受发往任何 IP 的包，否则所有 SYN 都会因 destination address 不匹配
        // 被丢弃，user-stack 永远收不到连接 → 拨号路径完全死锁。
        iface.set_any_ip(true);
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            listeners_by_port: HashMap::new(),
            accepted_set: HashSet::new(),
        }
    }

    /// 为指定目标端口确保至少 `min` 个处于 Listen 状态的 socket。
    ///
    /// 注意：smoltcp 的 `listen(port=0)` 会返回 `ListenError::Unaddressable` —
    /// 这意味着旧的 `add_tcp_listener(0)` 实际上从未真正监听。新实现根据
    /// pump_loop 解析出的真实目标端口动态创建 listener。
    pub fn ensure_listener_for(&mut self, port: u16, min: usize) {
        if port == 0 {
            return;
        }
        // 清理已 accept 完毕（不再处于 Listen 状态）的 handle
        let entry = self.listeners_by_port.entry(port).or_default();
        entry.retain(|h| {
            let s = self.sockets.get::<tcp::Socket>(*h);
            matches!(s.state(), tcp::State::Listen)
        });
        while entry.len() < min {
            let rx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
            let tx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
            let mut sock = tcp::Socket::new(rx, tx);
            // addr=None + port=p：等价 0.0.0.0:p / [::]:p；配合 set_any_ip
            // 可接受任何目标 IP 的 SYN。
            let ep = IpListenEndpoint { addr: None, port };
            if sock.listen(ep).is_err() {
                break;
            }
            let handle = self.sockets.add(sock);
            entry.push(handle);
        }
    }

    pub fn poll(&mut self) -> bool {
        let now = SmolInstant::from_millis(now_millis());
        self.iface.poll(now, &mut self.device, &mut self.sockets)
    }
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_outbound().collect()
    }
    pub fn inject(&mut self, pkt: Vec<u8>) {
        self.device.inject(pkt);
    }

    /// 扫描所有 listener，发现 ESTABLISHED 的报上去；同一 handle 只报一次。
    pub fn drain_accepted(&mut self) -> Vec<AcceptedTcp> {
        let mut out = Vec::new();
        let handles: Vec<SocketHandle> = self
            .listeners_by_port
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        for h in handles {
            if self.accepted_set.contains(&h) {
                continue;
            }
            let s = self.sockets.get::<tcp::Socket>(h);
            if matches!(s.state(), tcp::State::Established) {
                if let (Some(local), Some(remote)) = (s.local_endpoint(), s.remote_endpoint()) {
                    if let (Some(l), Some(r)) = (endpoint_to_addr(local), endpoint_to_addr(remote))
                    {
                        out.push(AcceptedTcp {
                            handle: h,
                            local: l,
                            remote: r,
                            original_dst: l,
                        });
                        self.accepted_set.insert(h);
                    }
                }
            }
        }
        out
    }

    /// 强制关闭一条 socket（splice 任务收尾）。
    pub fn close_socket(&mut self, handle: SocketHandle) {
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        s.close();
    }

    /// 从 socket 收数据到 buf；返回收到字节数（0 = 关闭）。
    pub fn try_recv(&mut self, handle: SocketHandle, buf: &mut [u8]) -> Result<usize, ()> {
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        if !s.may_recv() {
            return Err(());
        }
        if !s.can_recv() {
            return Ok(0);
        }
        s.recv_slice(buf).map_err(|_| ())
    }

    /// 往 socket 写数据；返回写入字节数（0 = 缓冲已满，待下一轮 poll）。
    pub fn try_send(&mut self, handle: SocketHandle, buf: &[u8]) -> Result<usize, ()> {
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        if !s.may_send() {
            return Err(());
        }
        if !s.can_send() {
            return Ok(0);
        }
        s.send_slice(buf).map_err(|_| ())
    }

    pub fn socket_state(&mut self, handle: SocketHandle) -> tcp::State {
        self.sockets.get::<tcp::Socket>(handle).state()
    }
}

fn endpoint_to_addr(ep: smoltcp::wire::IpEndpoint) -> Option<std::net::SocketAddr> {
    let port = ep.port;
    match ep.addr {
        IpAddress::Ipv4(v4) => Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.0)),
            port,
        )),
        IpAddress::Ipv6(v6) => Some(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.0)),
            port,
        )),
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/* ============================================================
StackEngine：异步驱动 + accept 派发 + splice 管理
============================================================ */

/// 共享栈把柄：被 driver 任务和 splice 任务共用。
pub type SharedStack = Arc<Mutex<UserSpaceStack>>;

/// 栈级 notify —— 任何地方写过数据后调用 `notify_one`，driver 立刻 poll 一次。
pub type StackNotify = Arc<Notify>;

/// 默认 listener 池大小 —— 越大并发 SYN 接受能力越强，但内存增长。
pub const DEFAULT_LISTENER_POOL: usize = 32;

// 旧的 `run_user_stack` / `step` / `replenish_listeners(0, …)` / `add_tcp_listener(port)`
// 已删除：tun_dispatch::run_stack_driver + ensure_listener_for(port) 完全替代。
// 历史路径用"port=0 wildcard listener"在 smoltcp 上根本不会真正监听
// （smoltcp `listen(port=0)` → `ListenError::Unaddressable`），是个 silent bug。

/* ============================================================
smoltcp Socket ↔ tokio AsyncRead/AsyncWrite 桥
============================================================ */

/// 一条已 accept 的 smoltcp TCP socket，包装成 tokio Stream。
///
/// 实现策略：在每次 poll_read / poll_write 时获取 stack 锁，调用
/// `try_recv` / `try_send`；缓冲为空/满时返回 Pending 并安排 notify
/// 在下一次 stack poll 后唤醒（简化：用周期 timer 兜底）。
pub struct SmolStream {
    handle: SocketHandle,
    stack: SharedStack,
    notify: StackNotify,
    closed_read: bool,
    closed_write: bool,
}

impl SmolStream {
    pub fn new(handle: SocketHandle, stack: SharedStack, notify: StackNotify) -> Self {
        Self {
            handle,
            stack,
            notify,
            closed_read: false,
            closed_write: false,
        }
    }

    /// 由 splice 任务在收尾时调用。
    pub fn close(&mut self) {
        let mut s = self.stack.lock();
        s.close_socket(self.handle);
        self.notify.notify_one();
    }
}

impl AsyncRead for SmolStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.closed_read {
            return std::task::Poll::Ready(Ok(()));
        }
        let mut tmp = [0u8; 8192];
        let cap = tmp.len().min(buf.remaining());
        let n = {
            let mut s = me.stack.lock();
            match s.try_recv(me.handle, &mut tmp[..cap]) {
                Ok(n) => n,
                Err(()) => {
                    me.closed_read = true;
                    return std::task::Poll::Ready(Ok(())); // EOF
                }
            }
        };
        if n > 0 {
            buf.put_slice(&tmp[..n]);
            me.notify.notify_one();
            std::task::Poll::Ready(Ok(()))
        } else {
            // 安排一次唤醒：监听 stack notify
            let waker = cx.waker().clone();
            let notify = me.notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            std::task::Poll::Pending
        }
    }
}

impl AsyncWrite for SmolStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if me.closed_write {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "smoltcp send half closed",
            )));
        }
        let n = {
            let mut s = me.stack.lock();
            match s.try_send(me.handle, buf) {
                Ok(n) => n,
                Err(()) => {
                    me.closed_write = true;
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "smoltcp may_send=false",
                    )));
                }
            }
        };
        if n > 0 {
            me.notify.notify_one();
            std::task::Poll::Ready(Ok(n))
        } else {
            let waker = cx.waker().clone();
            let notify = me.notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            std::task::Poll::Pending
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // smoltcp 自动 flush；poll() 推动数据落到 device。
        self.notify.notify_one();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let mut s = me.stack.lock();
        s.close_socket(me.handle);
        me.closed_write = true;
        me.notify.notify_one();
        std::task::Poll::Ready(Ok(()))
    }
}

/* ============================================================
SpliceManager：管理 (smoltcp socket ↔ outbound stream) 转发任务
============================================================ */

pub struct SpliceManager {
    handles: Mutex<HashMap<SocketHandle, tokio::task::JoinHandle<()>>>,
}

impl Default for SpliceManager {
    fn default() -> Self {
        Self {
            handles: Mutex::new(HashMap::new()),
        }
    }
}

impl SpliceManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 创建一条双向 splice：smoltcp socket ↔ outbound `tokio` AsyncRead+AsyncWrite。
    ///
    /// `guard` 可选 —— 传入 [`core_observe::ConnectionGuard`] 后，splice 任务
    /// 会按 mihomo 兼容语义实时累加 per-conn upload/download，并响应
    /// `ConnectionGuard::cancel`（来自 dashboard DELETE /connections/:id）主动 shutdown。
    pub fn spawn_splice<S>(
        self: &Arc<Self>,
        handle: SocketHandle,
        stack: SharedStack,
        notify: StackNotify,
        outbound: S,
        guard: Option<core_observe::ConnectionGuard>,
        metrics: Option<Arc<core_observe::Metrics>>,
    ) where
        S: AsyncRead + AsyncWrite + Send + 'static + Unpin,
    {
        let mut smol = SmolStream::new(handle, stack.clone(), notify.clone());
        let mgr = self.clone();
        let task = tokio::spawn(async move {
            // 有 guard：走 counted copy（per-conn 流量 + cancel 信号）；
            // 无 guard：走原朴素双向拷贝（兼容老路径）。
            if let Some(g) = guard {
                let conn_id = g.id;
                let accounting = g.accounting();
                if let Some(m) = &metrics {
                    m.inc_connection();
                }
                let result = core_observe::copy_bidirectional_tracked(
                    &mut smol,
                    &mut Box::pin(outbound),
                    accounting,
                    metrics.clone(),
                )
                .await;
                if let Some(m) = &metrics {
                    m.dec_connection();
                }
                let up = g.up.load(Ordering::Relaxed);
                let down = g.down.load(Ordering::Relaxed);
                let up_s = crate::tun_pump::format_bytes(up);
                let down_s = crate::tun_pump::format_bytes(down);
                match &result {
                    Ok(_) => info!(
                        target: "capture::traffic",
                        "[TCP] #{conn_id} closed | up {up_s} down {down_s}"
                    ),
                    Err(e) => warn!(
                        target: "capture::traffic",
                        "[TCP] #{conn_id} error: {e} | up {up_s} down {down_s}"
                    ),
                }
                drop(g);
            } else {
                let (mut sr, mut sw) = tokio::io::split(outbound);
                let mut buf_in = vec![0u8; 32 * 1024];
                let mut buf_out = vec![0u8; 32 * 1024];
                loop {
                    tokio::select! {
                        r = smol.read(&mut buf_in) => {
                            let n = match r { Ok(n) => n, Err(_) => break };
                            if n == 0 { break }
                            if sw.write_all(&buf_in[..n]).await.is_err() { break }
                        }
                        r = sr.read(&mut buf_out) => {
                            let n = match r { Ok(n) => n, Err(_) => break };
                            if n == 0 { break }
                            if smol.write_all(&buf_out[..n]).await.is_err() { break }
                        }
                    }
                }
            }
            smol.close();
            mgr.handles.lock().remove(&handle);
        });
        self.handles.lock().insert(handle, task);
    }

    pub fn len(&self) -> usize {
        self.handles.lock().len()
    }
    pub fn is_empty(&self) -> bool {
        self.handles.lock().is_empty()
    }
    pub fn abort_all(&self) {
        for (_, t) in self.handles.lock().drain() {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_device_roundtrip() {
        let mut d = VirtualTunDevice::new(1500);
        d.inject(vec![1, 2, 3, 4]);
        let now = SmolInstant::from_millis(0);
        let (rx, _tx) = d.receive(now).expect("rx pending");
        let mut got = Vec::new();
        rx.consume(|buf| got.extend_from_slice(buf));
        assert_eq!(got, vec![1, 2, 3, 4]);
    }

    #[test]
    fn user_stack_creates_and_polls() {
        let mut stack = UserSpaceStack::new(
            1500,
            Ipv4Address::new(198, 18, 0, 1),
            Some(Ipv6Address::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        );
        stack.ensure_listener_for(443, 4);
        let _ = stack.poll();
        assert!(stack.drain_accepted().is_empty());
    }

    #[test]
    fn splice_manager_tracks_tasks() {
        let mgr = SpliceManager::new();
        assert!(mgr.is_empty());
    }
}
