//! Dynamic loopback/self-capture detector.
//!
//! Static loopback CIDR checks only reject traffic whose destination is
//! 127.0.0.0/8 or ::1. They do not catch the more damaging case where an
//! outbound socket opened by WutherCore is captured again by TUN/TPROXY and
//! re-enters ListenerHandler as a new inbound flow. This mirrors mihomo's
//! loopback detector: register outbound local endpoints, then reject inbound
//! metadata whose source endpoint matches those records.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

static DETECTOR: OnceLock<LoopbackDetector> = OnceLock::new();

fn detector() -> &'static LoopbackDetector {
    DETECTOR.get_or_init(LoopbackDetector::default)
}

#[derive(Default)]
struct LoopbackDetector {
    state: Mutex<LoopbackState>,
}

#[derive(Default)]
struct LoopbackState {
    tcp: HashMap<SocketAddr, usize>,
    udp_ports: HashMap<u16, usize>,
    udp_local_addrs: HashMap<SocketAddr, usize>,
}

#[derive(Debug)]
pub struct LoopbackTcpGuard {
    addr: SocketAddr,
}

#[derive(Debug)]
pub struct LoopbackUdpGuard {
    port: u16,
    observed: Mutex<Vec<IpAddr>>,
}

pub fn register_tcp(addr: SocketAddr) -> LoopbackTcpGuard {
    detector().incr_tcp(addr);
    tracing::trace!(target: "dial::loopback", local = %addr, "track outbound tcp local endpoint");
    LoopbackTcpGuard { addr }
}

pub fn register_udp(local: SocketAddr) -> LoopbackUdpGuard {
    let port = local.port();
    detector().incr_udp_port(port);
    let guard = LoopbackUdpGuard {
        port,
        observed: Mutex::new(Vec::new()),
    };
    guard.observe_local_addr(local);
    tracing::trace!(target: "dial::loopback", local = %local, "track outbound udp local port");
    guard
}

pub fn is_loopback_tcp_source(source: SocketAddr) -> bool {
    detector().contains_tcp(source)
}

pub fn is_loopback_udp_source(source: SocketAddr) -> bool {
    detector().contains_udp_source(source)
}

impl LoopbackUdpGuard {
    pub fn observe_local_addr(&self, local: SocketAddr) {
        let ip = local.ip();
        if local.port() != self.port || ip.is_unspecified() {
            return;
        }
        let mut observed = self.observed.lock();
        if observed.contains(&ip) {
            return;
        }
        observed.push(ip);
        detector().incr_udp_local_addr(SocketAddr::new(ip, self.port));
        tracing::trace!(target: "dial::loopback", local = %local, "track outbound udp local endpoint");
    }
}

impl Drop for LoopbackTcpGuard {
    fn drop(&mut self) {
        detector().decr_tcp(self.addr);
        tracing::trace!(target: "dial::loopback", local = %self.addr, "untrack outbound tcp local endpoint");
    }
}

impl Drop for LoopbackUdpGuard {
    fn drop(&mut self) {
        detector().decr_udp_port(self.port);
        for ip in self.observed.get_mut().drain(..) {
            detector().decr_udp_local_addr(SocketAddr::new(ip, self.port));
        }
        tracing::trace!(target: "dial::loopback", port = self.port, "untrack outbound udp local port");
    }
}

impl LoopbackDetector {
    fn incr_tcp(&self, addr: SocketAddr) {
        incr(&mut self.state.lock().tcp, addr);
    }

    fn decr_tcp(&self, addr: SocketAddr) {
        decr(&mut self.state.lock().tcp, &addr);
    }

    fn contains_tcp(&self, source: SocketAddr) -> bool {
        self.state.lock().tcp.contains_key(&source)
    }

    fn incr_udp_port(&self, port: u16) {
        incr(&mut self.state.lock().udp_ports, port);
    }

    fn decr_udp_port(&self, port: u16) {
        decr(&mut self.state.lock().udp_ports, &port);
    }

    fn incr_udp_local_addr(&self, addr: SocketAddr) {
        incr(&mut self.state.lock().udp_local_addrs, addr);
    }

    fn decr_udp_local_addr(&self, addr: SocketAddr) {
        decr(&mut self.state.lock().udp_local_addrs, &addr);
    }

    fn contains_udp_source(&self, source: SocketAddr) -> bool {
        let state = self.state.lock();
        if !state.udp_ports.contains_key(&source.port()) {
            return false;
        }
        // 与 mihomo `tunnel/safeguard.go` 对齐：只在源 IP 是 loopback（127.0.0.0/8 或 ::1）
        // 时，端口匹配才视为 self-capture；非 loopback 源必须 (IP, port) 精确命中
        // 我们 connect 后 observe_local_addr 记录的 udp_local_addrs。
        //
        // ⚠️ 不要再回落到“任意本机接口 IP + 端口”的宽匹配——这会把 ROOT TUN 上
        // 内核选 TUN gateway 作 source 的合法本地进程流量误判为自抓回环，结果就是
        // 99% 的 UDP 都被 reject_loopback_self_capture 卡死，整条链路完全不通。
        source.ip().is_loopback() || state.udp_local_addrs.contains_key(&source)
    }
}

fn incr<K>(map: &mut HashMap<K, usize>, key: K)
where
    K: std::cmp::Eq + std::hash::Hash,
{
    *map.entry(key).or_insert(0) += 1;
}

fn decr<K>(map: &mut HashMap<K, usize>, key: &K)
where
    K: std::cmp::Eq + std::hash::Hash,
{
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

pin_project! {
    pub struct TrackedTcpStream<S> {
        #[pin]
        inner: S,
        _guard: LoopbackTcpGuard,
    }
}

impl<S> TrackedTcpStream<S> {
    pub fn new(inner: S, local: SocketAddr) -> Self {
        Self {
            inner,
            _guard: register_tcp(local),
        }
    }

    pub fn with_guard(inner: S, guard: LoopbackTcpGuard) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl TrackedTcpStream<tokio::net::TcpStream> {
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl<S> AsyncRead for TrackedTcpStream<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TrackedTcpStream<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
