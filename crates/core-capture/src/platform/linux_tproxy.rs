//! Linux TCP/UDP TPROXY socket 与 TCP NAT REDIRECT listener。
//!
//! TPROXY socket 真正接管被 nftables / iptables `TPROXY` 标记并路由到本地
//! 端口的连接；普通 TCP REDIRECT listener 则供 TUN `auto_redirect` 的 NAT
//! 链使用，不设置 `IP_TRANSPARENT`。
//!
//! ## 工作流
//!
//! 1. nftables / iptables 已经在 prerouting 链插入 `tproxy ... to :7894 mark 1`；
//! 2. 路由表把 fwmark 1 的流量送到 lo；
//! 3. 本模块创建带 `IP_TRANSPARENT` 的 listening socket，监听 `:7894`；
//! 4. accept TCP / recv UDP；用 `getsockopt(SOL_IP, SO_ORIGINAL_DST)`
//!    （TCP redirect 模式）或 `IP_RECVORIGDSTADDR`（UDP TPROXY 模式）拿到
//!    *原始目标地址*；
//! 5. 把 (5-tuple, payload) 通过 [`CaptureEvent`] 推给 supervisor。
//!
//! ## unsafe 政策
//!
//! `unsafe` 仅用于 libc socket/setsockopt/bind/recvmsg 与地址结构转换；每个调用点
//! 都维持单一 fd 所有权并就地说明指针、缓冲区或结构体布局前提。

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use core_observe::ConnectionGuard;
use core_outbound::adapter::BoxedUdp;
use core_runtime::{InboundMetadata, ListenerHandler};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureError, CaptureEvent},
    udp_session::UdpFlowKey,
};

const SO_ORIGINAL_DST: libc::c_int = 80;

type TproxyUdpSessionTable = Arc<DashMap<UdpFlowKey, Arc<TproxyUdpSession>>>;

struct TproxyUdpSession {
    socket: BoxedUdp,
    guard: ConnectionGuard,
    return_socket: Arc<UdpSocket>,
    target_host: String,
    target_port: u16,
    peer: SocketAddr,
    last_seen: Mutex<Instant>,
}

impl TproxyUdpSession {
    fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }
}

pub(crate) struct TproxyListeners {
    tcp: TcpListener,
    udp: UdpSocket,
    bind: SocketAddr,
}

impl TproxyListeners {
    pub(crate) fn into_parts(self) -> (TcpListener, UdpSocket, SocketAddr) {
        (self.tcp, self.udp, self.bind)
    }
}

/// One ordinary TCP listener used by Linux NAT `REDIRECT`.
///
/// Unlike [`TproxyListeners`], this socket deliberately has neither
/// `IP_TRANSPARENT` nor either UDP original-destination socket option. The
/// kernel records the pre-NAT TCP destination in conntrack and the accept loop
/// retrieves it with `SO_ORIGINAL_DST`.
pub(crate) struct RedirectTcpListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl RedirectTcpListener {
    /// Return the address actually selected by the kernel for this family.
    ///
    /// Redirect listeners always bind port zero, so firewall rules must use
    /// this address's port rather than the requested bind address.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn into_parts(self) -> (TcpListener, SocketAddr) {
        (self.listener, self.local_addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransparentSocketKind {
    Tcp,
    Udp,
}

trait TransparentSocketOps {
    type Socket;

    fn socket(&mut self, addr: SocketAddr, kind: TransparentSocketKind)
    -> io::Result<Self::Socket>;
    fn set_ipv6_only(&mut self, socket: &Self::Socket) -> io::Result<()>;
    fn set_ip_transparent(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()>;
    fn set_recv_original_dst(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()>;
    fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()>;
    fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()>;
    fn listen(&mut self, socket: &Self::Socket) -> io::Result<()>;
}

fn configure_transparent_socket<O: TransparentSocketOps>(
    ops: &mut O,
    addr: SocketAddr,
    kind: TransparentSocketKind,
) -> io::Result<O::Socket> {
    let socket = ops.socket(addr, kind)?;
    if addr.is_ipv6() {
        // Linux defaults this from net.ipv6.bindv6only (normally false).
        // Make the listener's family explicit so a parallel 0.0.0.0 listener
        // can own the same TPROXY port without an address-in-use race.
        ops.set_ipv6_only(&socket)?;
    }
    ops.set_ip_transparent(&socket, addr)?;
    if kind == TransparentSocketKind::Udp {
        ops.set_recv_original_dst(&socket, addr)?;
    }
    ops.set_reuse_addr(&socket)?;
    ops.bind(&socket, addr)?;
    if kind == TransparentSocketKind::Tcp {
        ops.listen(&socket)?;
    }
    Ok(socket)
}

fn configure_redirect_tcp_socket<O: TransparentSocketOps>(
    ops: &mut O,
    addr: SocketAddr,
) -> io::Result<O::Socket> {
    let socket = ops.socket(addr, TransparentSocketKind::Tcp)?;
    if addr.is_ipv6() {
        // Keep IPv4 and IPv6 REDIRECT sockets independent even on hosts whose
        // net.ipv6.bindv6only sysctl defaults to zero.
        ops.set_ipv6_only(&socket)?;
    }
    // A NAT REDIRECT listener is an ordinary local TCP socket. In particular,
    // do not call set_ip_transparent or set_recv_original_dst here.
    ops.set_reuse_addr(&socket)?;
    ops.bind(&socket, addr)?;
    ops.listen(&socket)?;
    Ok(socket)
}

struct LibcTransparentSocketOps;

impl TransparentSocketOps for LibcTransparentSocketOps {
    type Socket = OwnedFd;

    #[allow(unsafe_code)]
    fn socket(
        &mut self,
        addr: SocketAddr,
        kind: TransparentSocketKind,
    ) -> io::Result<Self::Socket> {
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let socket_type = match kind {
            TransparentSocketKind::Tcp => libc::SOCK_STREAM,
            TransparentSocketKind::Udp => libc::SOCK_DGRAM,
        };
        let fd = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just returned by socket() and this OwnedFd is its sole owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn set_ipv6_only(&mut self, socket: &Self::Socket) -> io::Result<()> {
        set_ipv6_only(socket.as_raw_fd())
    }

    fn set_ip_transparent(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
        set_transparent(socket.as_raw_fd(), addr)
    }

    fn set_recv_original_dst(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
        set_ip_recvorigdstaddr(socket.as_raw_fd())?;
        if addr.is_ipv6() {
            set_ipv6_recvorigdstaddr(socket.as_raw_fd())?;
        }
        Ok(())
    }

    fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()> {
        set_reuse_addr(socket.as_raw_fd())
    }

    fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
        bind_socket_fd(socket.as_raw_fd(), addr)
    }

    #[allow(unsafe_code)]
    fn listen(&mut self, socket: &Self::Socket) -> io::Result<()> {
        let rc = unsafe { libc::listen(socket.as_raw_fd(), libc::SOMAXCONN) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(crate) fn ipv4_tproxy_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
}

pub(crate) fn ipv6_tproxy_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
}

fn tproxy_bind_addrs(port: u16, ipv6_enabled: bool) -> Vec<SocketAddr> {
    let mut binds = vec![ipv4_tproxy_bind_addr(port)];
    if ipv6_enabled {
        binds.push(ipv6_tproxy_bind_addr(port));
    }
    binds
}

pub(crate) fn bind_tproxy_listeners(bind: SocketAddr) -> Result<TproxyListeners, CaptureError> {
    let mut ops = LibcTransparentSocketOps;
    let tcp_fd =
        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).map_err(|e| {
            CaptureError::DeviceFailed(format!("prepare transparent TCP listener {bind}: {e}"))
        })?;
    let tcp_std: std::net::TcpListener = tcp_fd.into();
    tcp_std.set_nonblocking(true)?;
    let tcp = TcpListener::from_std(tcp_std)?;

    let udp_fd =
        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Udp).map_err(|e| {
            CaptureError::DeviceFailed(format!("prepare transparent UDP listener {bind}: {e}"))
        })?;
    let udp_std: std::net::UdpSocket = udp_fd.into();
    udp_std.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(udp_std)?;

    Ok(TproxyListeners { tcp, udp, bind })
}

fn bind_tproxy_listener_set_with<L>(
    port: u16,
    ipv6_enabled: bool,
    mut bind: impl FnMut(SocketAddr) -> Result<L, CaptureError>,
) -> Result<Vec<L>, CaptureError> {
    tproxy_bind_addrs(port, ipv6_enabled)
        .into_iter()
        .map(&mut bind)
        .collect()
}

pub(crate) fn bind_tproxy_listener_set(
    port: u16,
    ipv6_enabled: bool,
) -> Result<Vec<TproxyListeners>, CaptureError> {
    bind_tproxy_listener_set_with(port, ipv6_enabled, bind_tproxy_listeners)
}

fn redirect_tcp_bind_addrs(ipv6_enabled: bool) -> Vec<SocketAddr> {
    let mut binds = vec![ipv4_tproxy_bind_addr(0)];
    if ipv6_enabled {
        binds.push(ipv6_tproxy_bind_addr(0));
    }
    binds
}

fn bind_tcp_redirect_listener(bind: SocketAddr) -> Result<RedirectTcpListener, CaptureError> {
    let mut ops = LibcTransparentSocketOps;
    let fd = configure_redirect_tcp_socket(&mut ops, bind).map_err(|error| {
        CaptureError::DeviceFailed(format!("prepare TCP REDIRECT listener {bind}: {error}"))
    })?;
    let listener: std::net::TcpListener = fd.into();
    let local_addr = listener.local_addr().map_err(|error| {
        CaptureError::DeviceFailed(format!(
            "read TCP REDIRECT listener address for {bind}: {error}"
        ))
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        CaptureError::DeviceFailed(format!(
            "make TCP REDIRECT listener {local_addr} nonblocking: {error}"
        ))
    })?;
    let listener = TcpListener::from_std(listener).map_err(|error| {
        CaptureError::DeviceFailed(format!(
            "register TCP REDIRECT listener {local_addr} with Tokio: {error}"
        ))
    })?;
    Ok(RedirectTcpListener {
        listener,
        local_addr,
    })
}

fn bind_tcp_redirect_listener_set_with<L>(
    ipv6_enabled: bool,
    mut bind: impl FnMut(SocketAddr) -> Result<L, CaptureError>,
) -> Result<Vec<L>, CaptureError> {
    redirect_tcp_bind_addrs(ipv6_enabled)
        .into_iter()
        .map(&mut bind)
        .collect()
}

/// Pre-bind one ordinary, ephemeral TCP REDIRECT listener per enabled family.
///
/// IPv4 and IPv6 deliberately receive independent kernel-selected ports. The
/// caller must install each family's NAT rule with [`RedirectTcpListener::local_addr`]
/// before starting [`run_tcp_redirect`]. If any family fails, already-bound
/// listeners are dropped before this function returns.
pub(crate) fn bind_tcp_redirect_listener_set(
    ipv6_enabled: bool,
) -> Result<Vec<RedirectTcpListener>, CaptureError> {
    bind_tcp_redirect_listener_set_with(ipv6_enabled, bind_tcp_redirect_listener)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpInterceptMode {
    Tproxy,
    Redirect,
}

impl TcpInterceptMode {
    fn log_name(self) -> &'static str {
        match self {
            Self::Tproxy => "tproxy",
            Self::Redirect => "redirect",
        }
    }

    fn metadata(self) -> (&'static str, &'static str) {
        match self {
            Self::Tproxy => ("tproxy", "TPROXY"),
            Self::Redirect => ("redirect", "REDIRECT"),
        }
    }
}

/// 启动一个 TPROXY TCP listener；accept 后立即 dial 出站并双向 splice，
/// 同时推一条事件给 supervisor 用于 NAT / 调试日志。
///
/// 之前的实现 `drop(stream)` 是 bug：客户端跟我们建了 TCP，但我们从未把
/// 对应的入站字节流接到代理出站上 —— 表现为"拨号成功但应用收不到任何数据"。
pub(crate) async fn run_tcp_tproxy(
    listener: TcpListener,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    stop: oneshot::Receiver<()>,
) -> Result<(), CaptureError> {
    run_tcp_intercept(listener, events, runtime, stop, TcpInterceptMode::Tproxy).await
}

/// Run an ordinary TCP NAT REDIRECT listener.
///
/// The listener itself is not transparent. Every accepted connection must
/// have a distinct, valid `SO_ORIGINAL_DST`; direct access to the internal
/// ephemeral endpoint is rejected instead of being proxied recursively.
pub(crate) async fn run_tcp_redirect(
    listener: TcpListener,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    stop: oneshot::Receiver<()>,
) -> Result<(), CaptureError> {
    run_tcp_intercept(listener, events, runtime, stop, TcpInterceptMode::Redirect).await
}

async fn run_tcp_intercept(
    listener: TcpListener,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    mut stop: oneshot::Receiver<()>,
    mode: TcpInterceptMode,
) -> Result<(), CaptureError> {
    let bind = listener.local_addr()?;
    // JoinSet owns every accepted relay. Dropping this listener future aborts
    // all relays, while the explicit stop path closes the accept socket first
    // and then waits for every abort to finish.
    let mut connections = JoinSet::new();
    info!(
        target: "capture::tproxy",
        addr = %bind,
        mode = mode.log_name(),
        "tcp transparent listener started (dial+splice inline)"
    );

    loop {
        let accepted = tokio::select! {
            biased;
            _ = &mut stop => {
                break;
            }
            accepted = listener.accept() => Some(accepted),
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(
                        target: "capture::tproxy",
                        mode = mode.log_name(),
                        %error,
                        "tcp relay task ended unexpectedly"
                    );
                }
                None
            }
        };
        let Some(accepted) = accepted else {
            continue;
        };
        let (stream, peer) = match accepted {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    target: "capture::tproxy",
                    mode = mode.log_name(),
                    error = %e,
                    "accept failed"
                );
                continue;
            }
        };
        let accepted_local = match stream.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                warn!(
                    target: "capture::tproxy",
                    mode = mode.log_name(),
                    %peer,
                    %error,
                    "cannot read accepted TCP local address; closing inbound"
                );
                continue;
            }
        };
        let fd = stream.as_raw_fd();
        let original_dst = match resolve_tcp_original_dst(fd, accepted_local, bind, mode) {
            Ok(addr) => addr,
            Err(error) => {
                warn!(
                    target: "capture::tproxy",
                    mode = mode.log_name(),
                    %peer,
                    local = %accepted_local,
                    %error,
                    "cannot determine TCP original destination; closing inbound"
                );
                continue;
            }
        };
        let evt = CaptureEvent {
            original_dst,
            source: peer,
            network: "tcp",
            fake_host: None,
        };
        let _ = events.try_send(evt);

        let runtime = runtime.clone();
        let bind_local = bind;
        connections.spawn(async move {
            let host = original_dst.ip().to_string();
            let port = original_dst.port();
            let handler = ListenerHandler::new(runtime);
            let (inbound_tag, inbound_kind) = mode.metadata();
            let metadata = InboundMetadata::tcp(
                inbound_tag,
                inbound_kind,
                peer,
                bind_local,
                host.clone(),
                port,
            )
            .with_destination_ip(Some(original_dst.ip()))
            .with_route_ip(Some(original_dst.ip()));
            match handler.prepare_tcp(metadata).await {
                Ok(prepared) => {
                    let outbound = prepared.result.outbound.clone();
                    if let Err(e) = handler.relay_prepared_tcp(stream, prepared).await {
                        debug!(
                            target: "capture::tproxy",
                            mode = mode.log_name(),
                            %host, port, outbound = %outbound,
                            error = %e,
                            "splice ended (inbound/outbound EOF or error)"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        target: "capture::tproxy",
                        mode = mode.log_name(),
                        %host, port,
                        error = %e,
                        "transparent TCP dial failed; closing inbound"
                    );
                }
            }
        });
    }

    shutdown_tcp_listener(listener, &mut connections).await;
    Ok(())
}

async fn shutdown_tcp_listener(listener: TcpListener, connections: &mut JoinSet<()>) {
    // Close the ingress endpoint before waiting for accepted relays. This
    // makes stop externally visible immediately and prevents a final accept
    // racing with relay cancellation.
    drop(listener);
    connections.shutdown().await;
}

/// UDP TPROXY —— `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`，`recvmsg` 解析 cmsg
/// 拿到原始目标地址（`IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR`）。
pub(crate) async fn run_udp_tproxy(
    socket: UdpSocket,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), CaptureError> {
    let bind = socket.local_addr()?;
    let sock = Arc::new(socket);
    info!(target: "capture::tproxy", addr = %bind, "udp tproxy listening (handler.NewPacket)");

    let handler = ListenerHandler::new(runtime);
    let sessions: TproxyUdpSessionTable = Arc::new(DashMap::new());
    // Only this listener future owns the sender. Engine stop drops the future,
    // closing the channel and waking every per-flow return loop. This avoids
    // a sessions-map/task ownership cycle that would otherwise keep forwarding
    // UDP after `LinuxTproxy::stop` returned.
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut shutdown_tx = Some(shutdown_tx);
    let mut return_loops = JoinSet::new();
    let mut gc = tokio::time::interval(Duration::from_secs(30));
    gc.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut stop => {
                shutdown_udp_return_loops(
                    &mut shutdown_tx,
                    &mut return_loops,
                    &sessions,
                ).await;
                return Ok(());
            }
            joined = return_loops.join_next(), if !return_loops.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(target: "capture::tproxy", %error, "udp return task ended unexpectedly");
                }
            }
            _ = gc.tick() => {
                let removed = purge_tproxy_udp_sessions(&sessions, Duration::from_secs(90));
                if removed > 0 {
                    debug!(target: "capture::tproxy", removed, remaining = sessions.len(), "udp session gc");
                }
            }
            ready = sock.readable() => {
                ready?;
                let r = sock.try_io(tokio::io::Interest::READABLE, || {
                    recvmsg_with_origdst(sock.as_raw_fd(), &mut buf)
                });
                let (n, peer, original_dst) = match r {
                    Ok((n, peer, dst)) => match require_udp_original_dst(peer, dst) {
                        Ok(dst) => (n, peer, dst),
                        Err(error) => {
                            warn!(target: "capture::tproxy", %peer, %error, "dropping UDP packet");
                            continue;
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        warn!(target: "capture::tproxy", error = %e, "recvmsg failed");
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                let payload = buf[..n].to_vec();
                let evt = CaptureEvent {
                    original_dst,
                    source: peer,
                    network: "udp",
                    fake_host: None,
                };
                let _ = events.try_send(evt);

                let key = UdpFlowKey { src: peer, dst: original_dst };
                if let Some(session) = sessions.get(&key).map(|s| s.value().clone()) {
                    let Some(sent) = udp_operation_or_stop(
                        &mut stop,
                        session.socket.send_to(
                            &payload,
                            &session.target_host,
                            session.target_port,
                        ),
                    )
                    .await
                    else {
                        shutdown_udp_return_loops(
                            &mut shutdown_tx,
                            &mut return_loops,
                            &sessions,
                        )
                        .await;
                        return Ok(());
                    };
                    match sent {
                        Ok(_) => {
                            handler.record_upload(&session.guard, n as u64);
                            session.touch();
                        }
                        Err(e) => {
                            debug!(target: "capture::tproxy", error = %e, "udp reuse send failed; remove session");
                            remove_tproxy_udp_session(&sessions, &key);
                        }
                    }
                    continue;
                }

                let target_host = original_dst.ip().to_string();
                let target_port = original_dst.port();
                let metadata = InboundMetadata::udp(
                    "tproxy",
                    "TPROXY",
                    peer,
                    Some(bind),
                    target_host.clone(),
                    target_port,
                )
                .with_destination_ip(Some(original_dst.ip()))
                .with_route_ip(Some(original_dst.ip()));
                let Some(prepared_result) =
                    udp_operation_or_stop(&mut stop, handler.new_packet(metadata)).await
                else {
                    shutdown_udp_return_loops(
                        &mut shutdown_tx,
                        &mut return_loops,
                        &sessions,
                    )
                    .await;
                    return Ok(());
                };
                let prepared = match prepared_result {
                    Ok(prepared) => prepared,
                    Err(e) => {
                        debug!(
                            target: "capture::tproxy",
                            %target_host,
                            target_port,
                            error = %e,
                            "udp dial failed"
                        );
                        continue;
                    }
                };
                let return_socket = match bind_transparent_udp(original_dst) {
                    Ok(sock) => Arc::new(sock),
                    Err(e) => {
                        warn!(
                            target: "capture::tproxy",
                            %original_dst,
                            error = %e,
                            "udp transparent return socket bind failed"
                        );
                        continue;
                    }
                };
                let session = Arc::new(TproxyUdpSession {
                    socket: prepared.socket,
                    guard: prepared.guard,
                    return_socket,
                    target_host: prepared.target_host,
                    target_port: prepared.target_port,
                    peer,
                    last_seen: Mutex::new(Instant::now()),
                });
                sessions.insert(key, session.clone());
                spawn_tproxy_udp_return_loop(
                    &mut return_loops,
                    key,
                    sessions.clone(),
                    session.clone(),
                    handler.runtime().metrics.clone(),
                    shutdown_rx.clone(),
                );
                let Some(sent) = udp_operation_or_stop(
                    &mut stop,
                    session.socket.send_to(
                        &payload,
                        &session.target_host,
                        session.target_port,
                    ),
                )
                .await
                else {
                    shutdown_udp_return_loops(
                        &mut shutdown_tx,
                        &mut return_loops,
                        &sessions,
                    )
                    .await;
                    return Ok(());
                };
                match sent {
                    Ok(_) => {
                        handler.record_upload(&session.guard, n as u64);
                        session.touch();
                    }
                    Err(e) => {
                        debug!(
                            target: "capture::tproxy",
                            host = %session.target_host,
                            port = session.target_port,
                            error = %e,
                            "udp first send failed"
                        );
                        remove_tproxy_udp_session(&sessions, &key);
                    }
                }
            }
        }
    }
}

async fn udp_operation_or_stop<T>(
    stop: &mut oneshot::Receiver<()>,
    operation: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        _ = stop => None,
        output = operation => Some(output),
    }
}

async fn shutdown_udp_return_loops(
    shutdown_tx: &mut Option<watch::Sender<()>>,
    return_loops: &mut JoinSet<()>,
    sessions: &TproxyUdpSessionTable,
) {
    // Closing the watch channel wakes every return loop even if it has not yet
    // observed a value change. Join them before reporting the listener stopped.
    drop(shutdown_tx.take());
    while let Some(joined) = return_loops.join_next().await {
        if let Err(error) = joined {
            debug!(target: "capture::tproxy", %error, "udp return task ended unexpectedly");
        }
    }
    sessions.clear();
}

fn require_udp_original_dst(
    peer: SocketAddr,
    original_dst: Option<SocketAddr>,
) -> io::Result<SocketAddr> {
    original_dst.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing original-destination control message from {peer}"),
        )
    })
}

fn spawn_tproxy_udp_return_loop(
    return_loops: &mut JoinSet<()>,
    key: UdpFlowKey,
    sessions: TproxyUdpSessionTable,
    session: Arc<TproxyUdpSession>,
    metrics: Arc<core_observe::Metrics>,
    mut shutdown: watch::Receiver<()>,
) {
    return_loops.spawn(async move {
        metrics.inc_connection();
        let cancel = session.guard.cancel.clone();
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = cancel.notified() => break,
                r = session.socket.recv_from(&mut buf) => {
                    let n = match r {
                        Ok(n) => n,
                        Err(e) => {
                            debug!(target: "capture::tproxy", error = %e, "udp outbound recv ended");
                            break;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    let returned = tokio::select! {
                        _ = shutdown.changed() => break,
                        _ = cancel.notified() => break,
                        returned = session.return_socket.send_to(&buf[..n], session.peer) => returned,
                    };
                    if let Err(e) = returned {
                        warn!(
                            target: "capture::tproxy",
                            peer = %session.peer,
                            error = %e,
                            "udp transparent return failed"
                        );
                        break;
                    }
                    session.guard.record_download(n as u64);
                    metrics.add_down(n as u64);
                    session.touch();
                }
            }
        }
        remove_tproxy_udp_session(&sessions, &key);
        metrics.dec_connection();
    });
}

fn remove_tproxy_udp_session(sessions: &TproxyUdpSessionTable, key: &UdpFlowKey) {
    if let Some((_, session)) = sessions.remove(key) {
        // There is exactly one return loop per session. notify_one stores a
        // permit when the loop is between awaits, avoiding notify_waiters'
        // lost-wakeup race during purge or first-send failure.
        session.guard.cancel.notify_one();
    }
}

fn purge_tproxy_udp_sessions(sessions: &TproxyUdpSessionTable, idle: Duration) -> usize {
    let cutoff = Instant::now() - idle;
    let keys: Vec<UdpFlowKey> = sessions
        .iter()
        .filter_map(|entry| {
            let last_seen = *entry.value().last_seen.lock();
            if last_seen < cutoff {
                Some(*entry.key())
            } else {
                None
            }
        })
        .collect();
    let removed = keys.len();
    for key in keys {
        remove_tproxy_udp_session(sessions, &key);
    }
    removed
}

/* ---------------- unsafe 区 ---------------- */

#[allow(unsafe_code)]
fn bind_transparent_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        if addr.is_ipv6() {
            set_ipv6_only(fd)?;
        }
        set_reuse_addr_port(fd)?;
        set_transparent(fd, addr)?;
        bind_socket_fd(fd, addr)?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(e) = result {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

#[allow(unsafe_code)]
fn set_reuse_addr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_reuse_addr_port(fd: RawFd) -> std::io::Result<()> {
    set_reuse_addr(fd)?;
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn bind_socket_fd(fd: RawFd, addr: SocketAddr) -> std::io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ipv6_only(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_transparent(fd: RawFd, addr: SocketAddr) -> std::io::Result<()> {
    set_ip_transparent(fd)?;
    if addr.is_ipv6() {
        set_ipv6_transparent(fd)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ip_transparent(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt 平凡；指针指向栈上 c_int。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ipv6_transparent(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ipv6_recvorigdstaddr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt 平凡；指针指向栈上 c_int。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ip_recvorigdstaddr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: 同上。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `recvmsg` + `IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR` cmsg 解析。
#[repr(C, align(8))]
struct OrigDstControlBuffer([u8; 128]);

#[allow(unsafe_code)]
fn recvmsg_with_origdst(
    fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // 控制缓冲：足够装一个 IPv6 cmsg（IPv4 cmsg 更小），并按 cmsghdr
    // 在 Linux 32/64-bit ABI 上的最大对齐要求显式对齐。
    let mut control = OrigDstControlBuffer([0u8; 128]);
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = &mut name as *mut _ as *mut libc::c_void;
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = control.0.len() as libc::size_t;

    // SAFETY: msghdr 字段全部初始化；recvmsg 写入 name/iov/control 不超过提供长度。
    let n = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let peer = sockaddr_storage_to_socket_addr(&name)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad peer addr"))?;

    // 遍历 cmsg 找 IP_ORIGDSTADDR / IPV6_ORIGDSTADDR
    let original_dst = if hdr.msg_flags & libc::MSG_CTRUNC == 0 {
        unsafe { extract_origdst(&hdr) }
    } else {
        None
    };

    Ok((n as usize, peer, original_dst))
}

#[allow(unsafe_code)]
unsafe fn extract_origdst(hdr: &libc::msghdr) -> Option<SocketAddr> {
    // SAFETY: 调用方保证 hdr 指向 recvmsg 刚返回的有效 msghdr，cmsg 链由内核填写。
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let typ = unsafe { (*cmsg).cmsg_type };
        let cmsg_len = unsafe { (*cmsg).cmsg_len };
        if level == libc::SOL_IP
            && typ == libc::IP_ORIGDSTADDR
            && cmsg_len
                >= unsafe {
                    libc::CMSG_LEN(std::mem::size_of::<libc::sockaddr_in>() as libc::c_uint)
                } as usize
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in;
            let sa = unsafe { std::ptr::read_unaligned(data) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
        if level == libc::IPPROTO_IPV6
            && typ == libc::IPV6_ORIGDSTADDR
            && cmsg_len
                >= unsafe {
                    libc::CMSG_LEN(std::mem::size_of::<libc::sockaddr_in6>() as libc::c_uint)
                } as usize
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in6;
            let sa = unsafe { std::ptr::read_unaligned(data) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            return Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }
    None
}

#[allow(unsafe_code)]
fn sockaddr_storage_to_socket_addr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
    let family = s.ss_family as i32;
    if family == libc::AF_INET {
        // SAFETY: 当 ss_family=AF_INET 时 layout 是 sockaddr_in。
        let v4: &libc::sockaddr_in = unsafe { &*(s as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
        Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(v4.sin_port),
        )))
    } else if family == libc::AF_INET6 {
        // SAFETY: 同理。
        let v6: &libc::sockaddr_in6 = unsafe { &*(s as *const _ as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(v6.sin6_port),
            v6.sin6_flowinfo,
            v6.sin6_scope_id,
        )))
    } else {
        None
    }
}

fn resolve_tcp_original_dst(
    fd: RawFd,
    accepted_local: SocketAddr,
    listener_bind: SocketAddr,
    mode: TcpInterceptMode,
) -> std::io::Result<SocketAddr> {
    let socket_original = if accepted_local.is_ipv4() {
        get_orig_dst_v4(fd).map(SocketAddr::V4)
    } else {
        get_orig_dst_v6(fd).map(SocketAddr::V6)
    };
    match mode {
        TcpInterceptMode::Tproxy => {
            select_tcp_original_dst(socket_original, accepted_local, listener_bind)
        }
        TcpInterceptMode::Redirect => {
            select_tcp_redirect_original_dst(socket_original, accepted_local, listener_bind)
        }
    }
}

fn select_tcp_original_dst(
    socket_original: std::io::Result<SocketAddr>,
    accepted_local: SocketAddr,
    listener_bind: SocketAddr,
) -> std::io::Result<SocketAddr> {
    let option_failure = match socket_original {
        Ok(addr)
            if addr.is_ipv4() == listener_bind.is_ipv4()
                && !addr.ip().is_unspecified()
                && addr.port() != 0 =>
        {
            return Ok(addr);
        }
        Ok(addr) => format!("socket option returned unusable address {addr}"),
        Err(error) => error.to_string(),
    };

    // A true TPROXY TCP socket normally exposes the intercepted destination as
    // its accepted local address even when SO_ORIGINAL_DST is unavailable
    // (that option is primarily associated with REDIRECT/NAT). Accept that
    // kernel-provided address, but never fall back to the listener port: a
    // directly reachable wildcard listener would otherwise proxy back into
    // itself forever.
    if accepted_local.is_ipv4() == listener_bind.is_ipv4()
        && !accepted_local.ip().is_unspecified()
        && accepted_local.port() != 0
        && accepted_local.port() != listener_bind.port()
    {
        return Ok(accepted_local);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "original-destination socket option failed ({option_failure}); \
             accepted local address {accepted_local} is not a safe fallback"
        ),
    ))
}

fn select_tcp_redirect_original_dst(
    socket_original: std::io::Result<SocketAddr>,
    accepted_local: SocketAddr,
    listener_bind: SocketAddr,
) -> std::io::Result<SocketAddr> {
    let addr = socket_original.map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SO_ORIGINAL_DST failed for TCP REDIRECT: {error}"),
        )
    })?;
    if addr.is_ipv4() != listener_bind.is_ipv4() || addr.ip().is_unspecified() || addr.port() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SO_ORIGINAL_DST returned unusable TCP REDIRECT address {addr}"),
        ));
    }

    // A direct connection to the internal listener has no pre-NAT destination:
    // Linux reports that listener endpoint as SO_ORIGINAL_DST. Never feed it
    // back through routing. Compare IP and port rather than SocketAddr equality
    // so IPv6 flowinfo cannot disguise the same endpoint.
    if same_socket_endpoint(addr, accepted_local) || same_socket_endpoint(addr, listener_bind) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "SO_ORIGINAL_DST {addr} points at the internal TCP REDIRECT listener; \
                 direct listener access is not proxyable"
            ),
        ));
    }

    Ok(addr)
}

fn same_socket_endpoint(left: SocketAddr, right: SocketAddr) -> bool {
    left.ip() == right.ip() && left.port() == right.port()
}

#[allow(unsafe_code)]
fn get_orig_dst_v4(fd: RawFd) -> std::io::Result<SocketAddrV4> {
    // SAFETY: getsockopt 写入 sockaddr_in；len 初始化为结构体大小，调用后被内核更新。
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len < std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        || addr.sin_family as libc::c_int != libc::AF_INET
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SO_ORIGINAL_DST returned an invalid IPv4 sockaddr",
        ));
    }
    let ip = u32::from_be(addr.sin_addr.s_addr);
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

#[allow(unsafe_code)]
fn get_orig_dst_v6(fd: RawFd) -> std::io::Result<SocketAddrV6> {
    // SAFETY: getsockopt writes at most `len` bytes into the initialized
    // sockaddr_in6 storage, and `len` starts at the exact storage size.
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len < std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        || addr.sin6_family as libc::c_int != libc::AF_INET6
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IP6T_SO_ORIGINAL_DST returned an invalid IPv6 sockaddr",
        ));
    }
    Ok(SocketAddrV6::new(
        Ipv6Addr::from(addr.sin6_addr.s6_addr),
        u16::from_be(addr.sin6_port),
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SocketStep {
        Socket,
        Ipv6Only,
        Transparent,
        RecvOriginalDst,
        ReuseAddr,
        Bind,
        Listen,
    }

    #[derive(Default)]
    struct RecordingSocketOps {
        steps: Vec<SocketStep>,
    }

    impl TransparentSocketOps for RecordingSocketOps {
        type Socket = ();

        fn socket(
            &mut self,
            _addr: SocketAddr,
            _kind: TransparentSocketKind,
        ) -> io::Result<Self::Socket> {
            self.steps.push(SocketStep::Socket);
            Ok(())
        }

        fn set_ipv6_only(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::Ipv6Only);
            Ok(())
        }

        fn set_ip_transparent(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            self.steps.push(SocketStep::Transparent);
            Ok(())
        }

        fn set_recv_original_dst(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            self.steps.push(SocketStep::RecvOriginalDst);
            Ok(())
        }

        fn set_reuse_addr(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::ReuseAddr);
            Ok(())
        }

        fn bind(&mut self, _socket: &Self::Socket, _addr: SocketAddr) -> io::Result<()> {
            self.steps.push(SocketStep::Bind);
            Ok(())
        }

        fn listen(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::Listen);
            Ok(())
        }
    }

    struct UnprivilegedSocketOps {
        inner: LibcTransparentSocketOps,
    }

    impl TransparentSocketOps for UnprivilegedSocketOps {
        type Socket = OwnedFd;

        fn socket(
            &mut self,
            addr: SocketAddr,
            kind: TransparentSocketKind,
        ) -> io::Result<Self::Socket> {
            self.inner.socket(addr, kind)
        }

        fn set_ipv6_only(&mut self, socket: &Self::Socket) -> io::Result<()> {
            self.inner.set_ipv6_only(socket)
        }

        fn set_ip_transparent(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_recv_original_dst(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()> {
            self.inner.set_reuse_addr(socket)
        }

        fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
            self.inner.bind(socket, addr)
        }

        fn listen(&mut self, socket: &Self::Socket) -> io::Result<()> {
            self.inner.listen(socket)
        }
    }

    #[test]
    fn tcp_transparent_options_are_set_before_bind() {
        let bind = ipv4_tproxy_bind_addr(7894);
        let mut ops = RecordingSocketOps::default();

        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).unwrap();

        assert!(bind.ip().is_unspecified());
        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Transparent,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
                SocketStep::Listen,
            ]
        );
    }

    #[test]
    fn tcp_redirect_socket_never_enables_transparent_or_udp_original_dst_options() {
        let mut ops = RecordingSocketOps::default();

        configure_redirect_tcp_socket(&mut ops, ipv4_tproxy_bind_addr(0)).unwrap();

        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
                SocketStep::Listen,
            ]
        );
        assert!(!ops.steps.contains(&SocketStep::Transparent));
        assert!(!ops.steps.contains(&SocketStep::RecvOriginalDst));
    }

    #[test]
    fn ipv6_tcp_redirect_sets_v6only_before_bind_without_transparent_options() {
        let mut ops = RecordingSocketOps::default();

        configure_redirect_tcp_socket(&mut ops, ipv6_tproxy_bind_addr(0)).unwrap();

        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Ipv6Only,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
                SocketStep::Listen,
            ]
        );
        assert!(!ops.steps.contains(&SocketStep::Transparent));
        assert!(!ops.steps.contains(&SocketStep::RecvOriginalDst));
    }

    #[test]
    fn udp_transparent_options_are_set_before_bind() {
        let mut ops = RecordingSocketOps::default();

        configure_transparent_socket(
            &mut ops,
            ipv4_tproxy_bind_addr(7894),
            TransparentSocketKind::Udp,
        )
        .unwrap();

        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Transparent,
                SocketStep::RecvOriginalDst,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
            ]
        );
    }

    #[test]
    fn ipv6_only_and_transparent_options_are_set_before_bind() {
        let mut ops = RecordingSocketOps::default();

        configure_transparent_socket(
            &mut ops,
            ipv6_tproxy_bind_addr(7894),
            TransparentSocketKind::Udp,
        )
        .unwrap();

        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Ipv6Only,
                SocketStep::Transparent,
                SocketStep::RecvOriginalDst,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
            ]
        );
    }

    #[test]
    fn listener_set_contains_separate_ipv4_and_ipv6_wildcards() {
        assert_eq!(
            tproxy_bind_addrs(7894, true),
            [
                "0.0.0.0:7894".parse::<SocketAddr>().unwrap(),
                "[::]:7894".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            tproxy_bind_addrs(7894, false),
            ["0.0.0.0:7894".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn redirect_listener_set_uses_independent_ephemeral_family_binds() {
        assert_eq!(
            redirect_tcp_bind_addrs(true),
            [
                "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                "[::]:0".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            redirect_tcp_bind_addrs(false),
            ["0.0.0.0:0".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn ipv6_bind_failure_drops_the_already_bound_ipv4_listener() {
        struct DropProbe(Arc<AtomicBool>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let probe = dropped.clone();
        let result = bind_tproxy_listener_set_with(7894, true, |addr| {
            if addr.is_ipv4() {
                Ok(DropProbe(probe.clone()))
            } else {
                Err(CaptureError::DeviceFailed(
                    "injected IPv6 bind failure".into(),
                ))
            }
        });

        assert!(matches!(result, Err(CaptureError::DeviceFailed(_))));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn redirect_ipv6_bind_failure_drops_the_already_bound_ipv4_listener() {
        struct DropProbe(Arc<AtomicBool>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let probe = dropped.clone();
        let result = bind_tcp_redirect_listener_set_with(true, |addr| {
            if addr.is_ipv4() {
                Ok(DropProbe(probe.clone()))
            } else {
                Err(CaptureError::DeviceFailed(
                    "injected REDIRECT IPv6 bind failure".into(),
                ))
            }
        });

        assert!(matches!(result, Err(CaptureError::DeviceFailed(_))));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn redirect_listener_reports_the_kernel_selected_ephemeral_port() {
        let mut listeners = bind_tcp_redirect_listener_set(false).unwrap();
        assert_eq!(listeners.len(), 1);

        let listener = listeners.pop().unwrap();
        let local_addr = listener.local_addr();
        assert!(local_addr.is_ipv4());
        assert!(local_addr.ip().is_unspecified());
        assert_ne!(local_addr.port(), 0);

        let (socket, parts_addr) = listener.into_parts();
        assert_eq!(parts_addr, local_addr);
        assert_eq!(socket.local_addr().unwrap(), local_addr);
    }

    #[test]
    fn occupied_port_is_reported_without_requiring_transparent_socket_privileges() {
        let occupied = std::net::TcpListener::bind(ipv4_tproxy_bind_addr(0)).unwrap();
        let bind = occupied.local_addr().unwrap();
        let mut ops = UnprivilegedSocketOps {
            inner: LibcTransparentSocketOps,
        };

        let error =
            configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn udp_packet_without_original_destination_is_rejected() {
        let peer: SocketAddr = "192.0.2.10:54321".parse().unwrap();

        let error = require_udp_original_dst(peer, None).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("original-destination"));
    }

    #[test]
    fn tcp_ipv6_uses_accepted_local_destination_when_socket_option_is_unavailable() {
        let accepted_local: SocketAddr = "[2001:db8::10]:443".parse().unwrap();
        let listener_bind = ipv6_tproxy_bind_addr(7894);

        let selected = select_tcp_original_dst(
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no conntrack original destination",
            )),
            accepted_local,
            listener_bind,
        )
        .unwrap();

        assert_eq!(selected, accepted_local);
    }

    #[test]
    fn tcp_local_fallback_rejects_the_listener_port_to_prevent_a_loop() {
        let listener_bind = ipv6_tproxy_bind_addr(7894);
        let error = select_tcp_original_dst(
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no conntrack original destination",
            )),
            "[::1]:7894".parse().unwrap(),
            listener_bind,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("safe fallback"));
    }

    #[test]
    fn tcp_intercept_metadata_preserves_tproxy_and_distinguishes_redirect() {
        assert_eq!(TcpInterceptMode::Tproxy.metadata(), ("tproxy", "TPROXY"));
        assert_eq!(
            TcpInterceptMode::Redirect.metadata(),
            ("redirect", "REDIRECT")
        );
    }

    #[test]
    fn tcp_redirect_requires_so_original_dst_without_local_fallback() {
        let accepted_local: SocketAddr = "127.0.0.1:45123".parse().unwrap();
        let listener_bind = ipv4_tproxy_bind_addr(45123);

        let error = select_tcp_redirect_original_dst(
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no conntrack original destination",
            )),
            accepted_local,
            listener_bind,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("SO_ORIGINAL_DST failed"));
    }

    #[test]
    fn tcp_redirect_rejects_direct_access_to_its_internal_listener() {
        let internal: SocketAddr = "127.0.0.1:45123".parse().unwrap();

        let error =
            select_tcp_redirect_original_dst(Ok(internal), internal, ipv4_tproxy_bind_addr(45123))
                .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("internal TCP REDIRECT listener"));
    }

    #[test]
    fn tcp_redirect_accepts_a_distinct_valid_socket_original_destination() {
        let original: SocketAddr = "198.51.100.20:443".parse().unwrap();

        let selected = select_tcp_redirect_original_dst(
            Ok(original),
            "127.0.0.1:45123".parse().unwrap(),
            ipv4_tproxy_bind_addr(45123),
        )
        .unwrap();

        assert_eq!(selected, original);
    }

    #[tokio::test]
    async fn tcp_listener_shutdown_closes_ingress_and_aborts_all_relays() {
        struct RelayDropProbe(Arc<AtomicBool>);

        impl Drop for RelayDropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let mut listeners = bind_tcp_redirect_listener_set(false).unwrap();
        let (listener, local_addr) = listeners.pop().unwrap().into_parts();
        let connect_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_addr.port()));
        let relay_dropped = Arc::new(AtomicBool::new(false));
        let relay_probe = relay_dropped.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let mut connections = JoinSet::new();
        connections.spawn(async move {
            let _probe = RelayDropProbe(relay_probe);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        shutdown_tcp_listener(listener, &mut connections).await;

        assert!(relay_dropped.load(Ordering::SeqCst));
        assert!(connections.is_empty());
        let connect_result = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(connect_addr),
        )
        .await
        .expect("closed local listener must refuse promptly");
        assert!(connect_result.is_err());
    }

    #[tokio::test]
    async fn stop_interrupts_a_pending_udp_operation() {
        let (stop_tx, mut stop_rx) = oneshot::channel();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = stop_tx.send(());
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            udp_operation_or_stop(&mut stop_rx, std::future::pending::<()>()),
        )
        .await
        .expect("stop must interrupt a pending outbound operation");

        assert!(result.is_none());
    }
}
