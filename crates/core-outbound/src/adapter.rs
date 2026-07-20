use std::{
    pin::Pin,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// 协议能力 —— Smart 选择时使用。
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub tcp: bool,
    pub udp: bool,
    pub ipv6: bool,
    pub multiplex: bool,
}

#[derive(Debug, Clone)]
pub struct DialContext {
    pub host: String,
    pub port: u16,
    pub network: &'static str, // "tcp" or "udp"
    /// 单次 dial 的全局唯一 id —— 让 transport / 协议握手 / inbound relay 的
    /// 日志能串起来。0 = 匿名（兼容旧调用）。
    pub dial_id: u64,
}

impl DialContext {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: "tcp",
            dial_id: 0,
        }
    }

    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: "udp",
            dial_id: 0,
        }
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.dial_id = id;
        self
    }
}

/// 单调递增的全局 dial id —— 让分布式日志能 join。
pub fn next_dial_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/* ============================================================
Outbound fwmark —— 让代理出站套接字绕开 TUN 自身路由表。

背景：TUN 抢了 default route 后，所有 connect 出去的 SYN 都进 TUN，
再被 routing 转发到某个 group → group 选某个节点 → connect 节点 IP →
又进 TUN → 死循环（用户视角：URLTest 全部 5s 超时）。

解法（与 mihomo `routing-mark` 一致）：
* outbound socket 通过 `setsockopt(SOL_SOCKET, SO_MARK, mark)` 打标
* root TUN 启动时探测系统默认网络所在路由表，并写
  `ip rule fwmark <mark> lookup <default-table> priority N`，让带标的包
  走真实默认网络而不是 TUN 表

capture 的 `install_auto_route` 会自动写这条 rule（见 platform/linux.rs）。
============================================================ */

use std::sync::atomic::{AtomicU32, Ordering};

static OUTBOUND_FWMARK: AtomicU32 = AtomicU32::new(0);
static OUTBOUND_INTERFACE: RwLock<Option<String>> = RwLock::new(None);
/// 物理出站接口的 v4 / v6 ifindex —— Windows `IP_UNICAST_IF` /
/// `IPV6_UNICAST_IF`、macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` 都按 ifindex 绑定。
/// Linux/Android 仍走 `SO_BINDTODEVICE` 名字绑定，这两个值在那里可以为 0。
///
/// 为什么必须按 ifindex：在 TUN 创建之后，TUN 接口往往成为系统默认路由
/// （metric 最低）。若出站 socket 不显式选物理接口，内核就会把出站包送进
/// TUN，TUN 把它当成新的入站再走一次代理 → 死循环 / 全部出站超时。
/// Windows 没有 `SO_BINDTODEVICE` 等价物，只能用 `IP_UNICAST_IF`；macOS
/// 类似只能用 `IP_BOUND_IF`。
static OUTBOUND_IFACE_INDEX_V4: AtomicU32 = AtomicU32::new(0);
static OUTBOUND_IFACE_INDEX_V6: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedSocket {
    raw: i64,
}

impl ProtectedSocket {
    pub fn raw(self) -> i64 {
        self.raw
    }
}

pub trait AsProtectedSocket {
    fn protected_socket(&self) -> ProtectedSocket;
}

#[cfg(unix)]
impl<T> AsProtectedSocket for T
where
    T: std::os::fd::AsRawFd + ?Sized,
{
    fn protected_socket(&self) -> ProtectedSocket {
        ProtectedSocket {
            raw: self.as_raw_fd() as i64,
        }
    }
}

#[cfg(windows)]
impl<T> AsProtectedSocket for T
where
    T: std::os::windows::io::AsRawSocket + ?Sized,
{
    fn protected_socket(&self) -> ProtectedSocket {
        ProtectedSocket {
            raw: self.as_raw_socket() as i64,
        }
    }
}

/// Android VpnService socket protector hook.
///
/// In VpnService mode, every outbound socket created by the VPN process must be
/// protected before connect/send, otherwise it is captured by the same VPN and
/// loops back into TUN. Non-Android builds leave this unset.
pub trait SocketProtector: Send + Sync + 'static {
    fn protect(&self, socket: ProtectedSocket) -> std::io::Result<()>;
}

static SOCKET_PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

pub fn set_socket_protector(protector: Option<Arc<dyn SocketProtector>>) {
    let mut guard = SOCKET_PROTECTOR.write().unwrap_or_else(|e| e.into_inner());
    *guard = protector;
}

pub fn has_socket_protector() -> bool {
    SOCKET_PROTECTOR
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

pub fn protect_socket<S>(socket: &S) -> std::io::Result<()>
where
    S: AsProtectedSocket + ?Sized,
{
    let protector = SOCKET_PROTECTOR
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(protector) = protector {
        protector.protect(socket.protected_socket())?;
    }
    Ok(())
}

pub fn prepare_outbound_udp_socket(
    socket: &std::net::UdpSocket,
) -> std::io::Result<crate::loopback::LoopbackUdpGuard> {
    // 无 peer 信息（连接前 bind 阶段调用 / wildcard 出站）——只能上 SO_MARK + 名字绑定，
    // ifindex 绑定推迟到 connect 后通过 [`prepare_outbound_udp_socket_for_addr`] 重新加固。
    prepare_outbound_udp_socket_with(socket, apply_outbound_mark, None)
}

pub fn prepare_outbound_udp_socket_for_addr(
    socket: &std::net::UdpSocket,
    addr: std::net::SocketAddr,
) -> std::io::Result<crate::loopback::LoopbackUdpGuard> {
    prepare_outbound_udp_socket_with(
        socket,
        |sock| apply_outbound_mark_for_addr(sock, addr),
        Some(addr),
    )
}

fn prepare_outbound_udp_socket_with(
    socket: &std::net::UdpSocket,
    apply_mark: impl FnOnce(&socket2::Socket) -> std::io::Result<()>,
    peer: Option<std::net::SocketAddr>,
) -> std::io::Result<crate::loopback::LoopbackUdpGuard> {
    protect_socket(socket)?;
    let mark = outbound_fwmark();
    let sock = socket2::SockRef::from(socket);
    if let Err(e) = apply_mark(&sock) {
        if mark != 0 {
            tracing::warn!(
                target: "dial::udp",
                mark,
                error = %e,
                "apply SO_MARK failed; refusing unmarked outbound UDP socket",
            );
            return Err(e);
        }
        tracing::debug!(target: "dial::udp", error = %e, "apply SO_MARK failed (non-fatal)");
    }
    // 有 peer 时走完整 OS 级绑定（含 Windows / macOS ifindex），无 peer 时退化到
    // 名字绑定 —— 旧接口兼容 + dual-stack wildcard listen 场景。
    let bind_result = match peer {
        Some(p) => bind_outbound_socket(&sock, p),
        None => bind_to_device(&sock),
    };
    if let Err(e) = bind_result {
        tracing::debug!(target: "dial::udp", error = %e, "outbound interface bind failed (non-fatal)");
    }
    let local = socket.local_addr()?;
    Ok(crate::loopback::register_udp(local))
}

/// 统一 UDP 出站 socket 创建 —— 对标 mihomo `component/dialer` 的 control chain：
/// `protect_socket → SO_MARK → SO_BINDTODEVICE → connect`。
///
/// 所有协议的 UDP 出站（DIRECT / SS / SOCKS5 / Hysteria / TUIC / WireGuard 等）
/// 必须经此入口，确保 TUN auto_route 下的 fwmark bypass、Android VpnService
/// protect、接口绑定一致生效。
pub fn create_outbound_udp_socket(
    peer: std::net::SocketAddr,
) -> std::io::Result<(std::net::UdpSocket, crate::loopback::LoopbackUdpGuard)> {
    let bind_addr: std::net::SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = std::net::UdpSocket::bind(bind_addr)?;
    let guard = prepare_outbound_udp_socket_for_addr(&sock, peer)?;
    sock.connect(peer)?;
    if let Ok(local) = sock.local_addr() {
        guard.observe_local_addr(local);
    }
    sock.set_nonblocking(true)?;
    Ok((sock, guard))
}

/// 设置全局 outbound fwmark；0 = 禁用。
/// 与 mihomo `dialer.DefaultRoutingMark` 一致：默认禁用，只有显式 routing-mark
/// 或 TUN auto_redirect mark-mode 需要时才启用。
pub fn set_outbound_fwmark(mark: u32) {
    OUTBOUND_FWMARK.store(mark, Ordering::Release);
}

/// Atomically replace the process-wide outbound fwmark when it still equals
/// `current`.
///
/// Capture supervisors use this as a lease boundary: only one running
/// supervisor may own the non-zero mark, and cleanup must not overwrite a
/// newer owner.
pub fn compare_exchange_outbound_fwmark(current: u32, new: u32) -> Result<u32, u32> {
    OUTBOUND_FWMARK.compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
}

pub fn outbound_fwmark() -> u32 {
    OUTBOUND_FWMARK.load(Ordering::Acquire)
}

/// 设置全局出站接口名；对标 mihomo `DefaultInterface`。
/// TUN 启动时由 route_probe 探测物理默认网卡写入。
pub fn set_outbound_interface(iface: Option<String>) {
    let mut guard = OUTBOUND_INTERFACE
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *guard = iface;
}

pub fn outbound_interface() -> Option<String> {
    OUTBOUND_INTERFACE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// 设置物理出站接口的 v4 / v6 ifindex —— Windows / macOS 平台 setsockopt 必需。
/// 0 视为未设置；TUN 启动时按系统默认路由探测填入。
pub fn set_outbound_interface_index(v4: Option<u32>, v6: Option<u32>) {
    OUTBOUND_IFACE_INDEX_V4.store(v4.unwrap_or(0), Ordering::Release);
    OUTBOUND_IFACE_INDEX_V6.store(v6.unwrap_or(0), Ordering::Release);
}

pub fn outbound_interface_index_v4() -> Option<u32> {
    let v = OUTBOUND_IFACE_INDEX_V4.load(Ordering::Acquire);
    if v == 0 { None } else { Some(v) }
}

pub fn outbound_interface_index_v6() -> Option<u32> {
    let v = OUTBOUND_IFACE_INDEX_V6.load(Ordering::Acquire);
    if v == 0 { None } else { Some(v) }
}

/// 把 socket 绑定到全局出站接口（SO_BINDTODEVICE）。
/// 对应 Linux/Android `bindToDevice`。非 Linux 平台或未配置接口时为 no-op。
///
/// 注意：不检查目标地址——所有出站 socket 都绑定到物理接口，
/// 确保流量不被 TUN catch-all 截走。
pub fn bind_to_device(_sock: &socket2::Socket) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let guard = OUTBOUND_INTERFACE.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref iface) = *guard {
            _sock.bind_device(Some(iface.as_bytes()))?;
        }
    }
    Ok(())
}

/// **跨平台出站接口绑定** —— 把 socket 强制绑到物理出站接口，让出站
/// 包绕开 TUN 自循环。
///
/// * Linux/Android：`SO_BINDTODEVICE` （走 [`bind_to_device`]）+ 配套
///   `SO_MARK` + `ip rule fwmark`。
/// * Windows：`IP_UNICAST_IF` (level `IPPROTO_IP`, opt 31) /
///   `IPV6_UNICAST_IF` (level `IPPROTO_IPV6`, opt 31)。Windows 没有
///   `SO_BINDTODEVICE` 等价物，此 setsockopt 是唯一让 socket 跳过 TUN
///   metric 直走物理接口的方法。
/// * macOS / iOS：`IP_BOUND_IF` (`IPPROTO_IP`, opt 25) /
///   `IPV6_BOUND_IF` (`IPPROTO_IPV6`, opt 125)。darwin 同样无
///   `SO_BINDTODEVICE`。
///
/// `peer` 用来选择 v4 / v6 ifindex；非 global-unicast 目标（loopback /
/// 私网 / multicast 等）跳过绑定，避免本机 / LAN 流量被强迫走物理出口。
pub fn bind_outbound_socket(
    sock: &socket2::Socket,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    // Linux/Android 名字绑定 —— 不依赖 ifindex。
    bind_to_device(sock)?;

    // 仅 global-unicast 目标走 ifindex 绑定，本机 / 私网流量保持原状。
    if !should_mark_outbound_addr(peer.ip()) {
        return Ok(());
    }

    let _ = peer;
    let _ = sock;
    #[cfg(windows)]
    {
        let result = match peer.ip() {
            std::net::IpAddr::V4(_) => match outbound_interface_index_v4() {
                Some(idx) => set_unicast_if_v4_windows(sock, idx),
                None => Ok(()),
            },
            std::net::IpAddr::V6(_) => match outbound_interface_index_v6() {
                Some(idx) => set_unicast_if_v6_windows(sock, idx),
                None => Ok(()),
            },
        };
        if let Err(e) = result {
            tracing::debug!(
                target: "dial::bind",
                peer = %peer,
                error = %e,
                "windows IP_UNICAST_IF bind failed (non-fatal)"
            );
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let result = match peer.ip() {
            std::net::IpAddr::V4(_) => match outbound_interface_index_v4() {
                Some(idx) => set_bound_if_v4_darwin(sock, idx),
                None => Ok(()),
            },
            std::net::IpAddr::V6(_) => match outbound_interface_index_v6() {
                Some(idx) => set_bound_if_v6_darwin(sock, idx),
                None => Ok(()),
            },
        };
        if let Err(e) = result {
            tracing::debug!(
                target: "dial::bind",
                peer = %peer,
                error = %e,
                "darwin IP_BOUND_IF bind failed (non-fatal)"
            );
        }
    }
    Ok(())
}

/* ---------------- Windows IP_UNICAST_IF ---------------- */

#[cfg(windows)]
fn set_unicast_if_v4_windows(sock: &socket2::Socket, ifindex: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    // ifindex 必须以 host-byte-order 写在 network-byte-order 32-bit 整数里
    // —— 即对 LE 主机要 .to_be()。Windows IP Helper 文档明确这点。
    let value: u32 = ifindex.to_be();
    let raw = sock.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
    let ret = unsafe {
        windows_sys::Win32::Networking::WinSock::setsockopt(
            raw,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
            windows_sys::Win32::Networking::WinSock::IP_UNICAST_IF as i32,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn set_unicast_if_v6_windows(sock: &socket2::Socket, ifindex: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    // IPV6_UNICAST_IF 不需要字节序转换 —— 直接 host order u32。
    let value: u32 = ifindex;
    let raw = sock.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
    let ret = unsafe {
        windows_sys::Win32::Networking::WinSock::setsockopt(
            raw,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
            windows_sys::Win32::Networking::WinSock::IPV6_UNICAST_IF as i32,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/* ---------------- Darwin IP_BOUND_IF ---------------- */

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_bound_if_v4_darwin(sock: &socket2::Socket, ifindex: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // IP_BOUND_IF = 25 (IPPROTO_IP)
    const IP_BOUND_IF: libc::c_int = 25;
    let value: libc::c_uint = ifindex as libc::c_uint;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &value as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_bound_if_v6_darwin(sock: &socket2::Socket, ifindex: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // IPV6_BOUND_IF = 125 (IPPROTO_IPV6)
    const IPV6_BOUND_IF: libc::c_int = 125;
    let value: libc::c_uint = ifindex as libc::c_uint;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IPV6_BOUND_IF,
            &value as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 在 socket connect 之前打 SO_MARK；非 Linux/Android 平台为 no-op。
/// `socket2::Socket::set_mark` 是安全 API。
pub fn apply_outbound_mark(_sock: &socket2::Socket) -> std::io::Result<()> {
    let mark = outbound_fwmark();
    if mark == 0 {
        return Ok(());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return _sock.set_mark(mark);
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// TCP connect 专用：对齐 mihomo `bindMarkToControl`，非 global-unicast
/// 目标不打 mark，避免本机/LAN/组播等连接被路由标记污染。
pub fn apply_outbound_mark_for_addr(
    sock: &socket2::Socket,
    addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    let mark = outbound_fwmark();
    if mark == 0 {
        return Ok(());
    }
    if !should_mark_outbound_addr(addr.ip()) {
        tracing::trace!(
            target: "dial",
            peer = %addr,
            mark,
            "skip SO_MARK for non-global direct target"
        );
        return Ok(());
    }
    apply_outbound_mark(sock)
}

pub fn should_mark_outbound_addr(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] >= 240)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// 抽象出"读 + 写 + Send"的代理流。
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ProxyStream for T {}

pub type BoxedStream = Pin<Box<dyn ProxyStream>>;

/// UDP 代理通道 —— mihomo `C.PacketConn` 等价。
///
/// 各 OutboundAdapter 实现：
/// * Direct：`tokio::net::UdpSocket::bind` 后系统直送。
/// * 代理协议：只有覆盖 [`OutboundAdapter::dial_udp`] 并返回真实 [`BoxedUdp`]
///   的实现才能声明 `capabilities().udp = true`。
/// * Block：直接返回 ConnectionRefused。
///
/// `target` 是远端目标地址（域名或 IP）。
///
/// 当前 `recv_from` ABI 只返回 payload 长度，无法把响应源地址交还给调用方。
/// 因此基于 connected UDP socket 的实现必须对非初始目标 fail closed；在 ABI
/// 扩展为返回 endpoint 之前，不能伪装支持一个 association 上的多目标转发。
#[async_trait]
pub trait UdpSocketLike: Send + Sync {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// 关闭通道；某些协议需要发协议级断开。
    async fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

pub type BoxedUdp = Box<dyn UdpSocketLike>;

#[async_trait]
pub trait OutboundAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn protocol(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream>;

    /// UDP 通道 —— 默认未实现，调用方应回退到 Direct。
    /// 各代理协议按需重写：vmess/trojan/hy2/tuic/socks5/wireguard 等支持 UDP；
    /// http/ssh/snell-v1 等不支持。
    async fn dial_udp(&self, _ctx: DialContext) -> std::io::Result<BoxedUdp> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "outbound `{}`/{} 暂未实现 UDP 通道",
                self.name(),
                self.protocol()
            ),
        ))
    }
}

pub type SharedOutbound = Arc<dyn OutboundAdapter>;

/* ============================================================
   DialResolver —— 与 mihomo `resolver.ResolveIP` 等价。
   ============================================================

   背景：直接调 `tokio::net::TcpStream::connect((host, port))` 会让
   tokio 通过 `getaddrinfo` 走系统 DNS。当 TUN 接管所有流量后，
   系统 DNS 包又会进 TUN → user-stack → runtime.dial → 又要解析
   节点 host → 死循环 + 5s 超时。

   解决：所有 transport 在 connect 之前先调本 trait 走 WutherCore
   自己的 resolver（IP 直连 DoH，不经过 TUN），拿到 IP 字面再 connect。

   主进程（wuther-core/main.rs 或 core-runtime engine.rs）启动时调
   `set_global_dial_resolver(...)` 注入 Arc<dyn DialResolver>；
   未注入时 transport 退回 `TcpStream::connect((host, port))` 旧行为。
*/

#[async_trait]
pub trait DialResolver: Send + Sync + std::fmt::Debug {
    /// 解析 host 为 IP 列表（IP 字面直接返回；hostname 走 WutherCore resolver）。
    /// 用于代理出站：节点 host 走 bootstrap，避开 TUN 自循环。
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>>;

    /// DIRECT 出站专用解析（mihomo `DirectHostResolver` 等价）。
    ///
    /// 直连流量的解析必须避开 fake-ip / 业务策略链，否则 fake IP 会被
    /// 直接发到目标，造成不可路由的 198.18/15。默认实现回退到 [`Self::resolve`]，
    /// 实现者应当 override 走 `direct-nameserver` group。
    async fn resolve_for_direct(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        self.resolve(host).await
    }

    /// 全局 IPv6 开关 —— 与 `Resolver.ipv6` 同源。`false` 时 [`resolve_host`]
    /// 会丢掉所有 V6 IP（包括 host 是 V6 字面量的情况），让出站永远不连 V6。
    ///
    /// 默认 `true` 兼容老实现 / 测试 mock。生产 `ResolverAdapter` 透传 `Resolver`
    /// 的 `ipv6_enabled()`；mihomo `ipv6: false` 等价行为靠这个 + TUN 端 drop
    /// + DNS 端不返 AAAA 三层共同实现。
    fn ipv6_enabled(&self) -> bool {
        true
    }
}

static DIAL_RESOLVER: RwLock<Option<Arc<dyn DialResolver>>> = RwLock::new(None);

pub fn set_global_dial_resolver(r: Arc<dyn DialResolver>) {
    let mut guard = DIAL_RESOLVER.write().unwrap_or_else(|e| e.into_inner());
    *guard = Some(r);
}

pub fn global_dial_resolver() -> Option<Arc<dyn DialResolver>> {
    DIAL_RESOLVER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(test)]
fn clear_global_dial_resolver() {
    let mut guard = DIAL_RESOLVER.write().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// transport 通用辅助：解析 host 为 IP 列表。
/// host 已经是 IP literal → 直接返回；否则走 global DialResolver；
/// 没注入 resolver → 回退 tokio `lookup_host`（与旧行为兼容）。
pub async fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
    resolve_host_internal(host, port, false).await
}

/// DIRECT 出站专用解析（mihomo `DirectHostResolver` 等价）。
///
/// 与 [`resolve_host`] 区别：注入了 `direct-nameserver` 的环境会用
/// `direct-nameserver` group 解析，避开 fake-ip / 业务策略链；未注入时
/// 行为等价。
pub async fn resolve_host_for_direct(
    host: &str,
    port: u16,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    resolve_host_internal(host, port, true).await
}

async fn resolve_host_internal(
    host: &str,
    port: u16,
    for_direct: bool,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let started = std::time::Instant::now();
    // 全局 IPv6 开关：取自 DialResolver（代理 Resolver.ipv6）。本函数三处需要
    // 用到——literal v6 host 拒绝、resolver 返 v6 IP 过滤、空结果判定。
    let ipv6_enabled = global_dial_resolver()
        .as_ref()
        .map(|r| r.ipv6_enabled())
        .unwrap_or(true);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ipv6_enabled && ip.is_ipv6() {
            tracing::debug!(
                target: "dial::resolve",
                %host, port, for_direct,
                "literal IPv6 host rejected (ipv6 disabled)"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("ipv6 disabled, refusing to dial v6 literal {host}"),
            ));
        }
        tracing::debug!(target: "dial::resolve", %host, port, for_direct, "literal IP, no resolution");
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    if let Some(r) = global_dial_resolver() {
        let source = if for_direct {
            "wuthercore-resolver-direct"
        } else {
            "wuthercore-resolver"
        };
        tracing::debug!(target: "dial::resolve", %host, port, source, "begin");
        let res = if for_direct {
            r.resolve_for_direct(host).await
        } else {
            r.resolve(host).await
        };
        match res {
            Ok(mut ips) => {
                // ipv6 关闭时 strip V6 —— 同时覆盖以下三个来源：
                //   (a) 上游 resolver 没有遵守 ipv6_enabled
                //   (b) 自定义 DialResolver 返 v6（系统 DNS 等）
                //   (c) Hosts 表 / fake-ip pool 返 v6
                if !ipv6_enabled {
                    let before = ips.len();
                    ips.retain(|ip| ip.is_ipv4());
                    if ips.len() != before {
                        tracing::debug!(
                            target: "dial::resolve",
                            %host, port, for_direct,
                            stripped = before - ips.len(),
                            "filtered out IPv6 results (ipv6 disabled)"
                        );
                    }
                }
                if ips.is_empty() {
                    tracing::warn!(
                        target: "dial::resolve",
                        %host, port, for_direct,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "resolver returned 0 IP",
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("resolver returned no IP for {host}"),
                    ));
                }
                let ips_str: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
                tracing::info!(
                    target: "dial::resolve",
                    %host, port, for_direct,
                    count = ips.len(),
                    ips = %ips_str.join(","),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "resolved",
                );
                return Ok(ips
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, port))
                    .collect());
            }
            Err(e) => {
                tracing::warn!(
                    target: "dial::resolve",
                    %host, port, for_direct,
                    error = %e,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "wuthercore-resolver failed",
                );
                return Err(e);
            }
        }
    }
    tracing::debug!(target: "dial::resolve", %host, port, for_direct, source = "system-getaddrinfo", "begin");
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let collected: Vec<_> = addrs.collect();
    tracing::info!(
        target: "dial::resolve",
        %host, port, for_direct,
        count = collected.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "resolved (system)",
    );
    Ok(collected)
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::net::TcpListener;

    use super::*;
    use crate::{direct::DirectOutbound, transport::tcp::marked_connect};

    static TEST_PROTECTOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const NETWORK_TEST_TIMEOUT: Duration = Duration::from_secs(3);
    const NETWORK_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

    fn lock_test_protector() -> std::sync::MutexGuard<'static, ()> {
        TEST_PROTECTOR_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    async fn network_timeout<T>(label: &str, future: impl Future<Output = T>) -> T {
        tokio::time::timeout(NETWORK_TEST_TIMEOUT, future)
            .await
            .unwrap_or_else(|_| panic!("{label} timed out after {NETWORK_TEST_TIMEOUT:?}"))
    }

    /// Binding `[::1]` can succeed even when the host IPv6 data plane is
    /// disabled or intercepted. Probe with raw Tokio sockets so such hosts
    /// skip the Direct-specific assertion instead of hanging the whole suite.
    async fn ipv6_udp_loopback_available() -> bool {
        let server = match tokio::net::UdpSocket::bind("[::1]:0").await {
            Ok(socket) => socket,
            Err(_) => return false,
        };
        let client = match tokio::net::UdpSocket::bind("[::]:0").await {
            Ok(socket) => socket,
            Err(_) => return false,
        };
        let server_addr = match server.local_addr() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        match tokio::time::timeout(
            NETWORK_PROBE_TIMEOUT,
            client.send_to(b"ipv6-probe", server_addr),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => return false,
        }

        let mut request = [0u8; 32];
        let peer = match tokio::time::timeout(NETWORK_PROBE_TIMEOUT, server.recv_from(&mut request))
            .await
        {
            Ok(Ok((n, peer))) if &request[..n] == b"ipv6-probe" => peer,
            _ => return false,
        };

        match tokio::time::timeout(NETWORK_PROBE_TIMEOUT, server.send_to(b"ipv6-reply", peer)).await
        {
            Ok(Ok(_)) => {}
            _ => return false,
        }

        let mut response = [0u8; 32];
        matches!(
            tokio::time::timeout(
                NETWORK_PROBE_TIMEOUT,
                client.recv_from(&mut response),
            )
            .await,
            Ok(Ok((n, _))) if &response[..n] == b"ipv6-reply"
        )
    }

    struct CountingProtector {
        calls: Arc<AtomicUsize>,
    }

    impl SocketProtector for CountingProtector {
        fn protect(&self, socket: ProtectedSocket) -> std::io::Result<()> {
            assert!(socket.raw() != 0);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct StaticDialResolver;

    #[async_trait]
    impl DialResolver for StaticDialResolver {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            Ok(Vec::new())
        }
    }

    /// Mock resolver returning a fixed mixed v4+v6 list, with toggleable ipv6.
    #[derive(Debug)]
    struct MixedFamilyResolver {
        ipv6: bool,
    }

    #[async_trait]
    impl DialResolver for MixedFamilyResolver {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            Ok(vec![
                "1.2.3.4".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "5.6.7.8".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ])
        }
        fn ipv6_enabled(&self) -> bool {
            self.ipv6
        }
    }

    #[test]
    fn global_dial_resolver_can_be_replaced_on_runtime_reload() {
        let _guard = lock_test_protector();
        clear_global_dial_resolver();

        let first: Arc<dyn DialResolver> = Arc::new(StaticDialResolver);
        let second: Arc<dyn DialResolver> = Arc::new(StaticDialResolver);

        set_global_dial_resolver(first.clone());
        assert!(Arc::ptr_eq(&first, &global_dial_resolver().unwrap()));

        set_global_dial_resolver(second.clone());
        assert!(Arc::ptr_eq(&second, &global_dial_resolver().unwrap()));

        clear_global_dial_resolver();
    }

    /// `ipv6_enabled = false` 时混合解析结果里所有 V6 IP 应被剥离，只保留 V4。
    /// 与 mihomo `ipv6: false` 行为对齐：DNS 层即便漏放了 AAAA，dial 层也兜住。
    #[tokio::test]
    async fn resolve_host_filters_v6_when_ipv6_disabled() {
        let _guard = lock_test_protector();
        clear_global_dial_resolver();
        set_global_dial_resolver(Arc::new(MixedFamilyResolver { ipv6: false }));

        let result = resolve_host("example.com", 443).await.unwrap();
        let ips: Vec<std::net::IpAddr> = result.into_iter().map(|s| s.ip()).collect();
        assert!(ips.iter().all(|i| i.is_ipv4()), "left v6 IPs: {ips:?}");
        assert_eq!(ips.len(), 2, "should keep both v4 IPs");

        clear_global_dial_resolver();
    }

    /// `ipv6_enabled = true` 时混合结果原样透传，不应丢任何 IP。
    #[tokio::test]
    async fn resolve_host_keeps_v6_when_ipv6_enabled() {
        let _guard = lock_test_protector();
        clear_global_dial_resolver();
        set_global_dial_resolver(Arc::new(MixedFamilyResolver { ipv6: true }));

        let result = resolve_host("example.com", 443).await.unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result.iter().filter(|s| s.is_ipv6()).count(), 2);

        clear_global_dial_resolver();
    }

    /// `ipv6_enabled = false` 且 host 是 V6 字面量时直接拒绝（AddrNotAvailable），
    /// 不能默默落到 dial 后再炸——proxy 节点配错 v6 IP 应该报错可见。
    /// 注意 `[..]` 形式 `IpAddr::parse` 不识别（属于 SocketAddr 语法），所以
    /// 真实场景下 v6 字面量 host 不应带括号。
    #[tokio::test]
    async fn resolve_host_rejects_v6_literal_when_ipv6_disabled() {
        let _guard = lock_test_protector();
        clear_global_dial_resolver();
        set_global_dial_resolver(Arc::new(MixedFamilyResolver { ipv6: false }));

        let err = resolve_host("2001:db8::1", 443).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
        assert!(err.to_string().contains("ipv6 disabled"));

        clear_global_dial_resolver();
    }

    /// V4 字面量 host 不受 ipv6 开关影响。
    #[tokio::test]
    async fn resolve_host_passes_v4_literal_when_ipv6_disabled() {
        let _guard = lock_test_protector();
        clear_global_dial_resolver();
        set_global_dial_resolver(Arc::new(MixedFamilyResolver { ipv6: false }));

        let result = resolve_host("1.2.3.4", 443).await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ipv4());

        clear_global_dial_resolver();
    }

    #[tokio::test]
    async fn tcp_connect_invokes_socket_protector_before_dial() {
        let _guard = lock_test_protector();
        let calls = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Some(Arc::new(CountingProtector {
            calls: calls.clone(),
        })));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_accept, wait_release) = tokio::sync::oneshot::channel::<()>();
        let accept = tokio::spawn(async move {
            let Ok((_stream, _peer)) =
                network_timeout("socket protector TCP accept", listener.accept()).await
            else {
                return;
            };
            let _ = network_timeout("socket protector TCP release", wait_release).await;
        });

        let stream = network_timeout(
            "socket protector marked TCP connect",
            marked_connect(addr, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        drop(stream);
        let _ = release_accept.send(());
        network_timeout("socket protector TCP task", accept)
            .await
            .unwrap();

        set_socket_protector(None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn marked_tcp_connect_tracks_local_endpoint_until_stream_drops() {
        let _guard = lock_test_protector();
        set_socket_protector(None);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_accept, wait_release) = tokio::sync::oneshot::channel::<()>();
        let accept = tokio::spawn(async move {
            let Ok((_stream, _peer)) =
                network_timeout("tracked TCP accept", listener.accept()).await
            else {
                return;
            };
            let _ = network_timeout("tracked TCP release", wait_release).await;
        });

        let stream = network_timeout(
            "tracked marked TCP connect",
            marked_connect(addr, Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let local = stream.local_addr().unwrap();

        assert!(crate::loopback::is_loopback_tcp_source(local));

        drop(stream);
        let _ = release_accept.send(());
        network_timeout("tracked TCP task", accept).await.unwrap();
        assert!(!crate::loopback::is_loopback_tcp_source(local));
    }

    #[tokio::test]
    async fn direct_udp_invokes_socket_protector_when_channel_is_created() {
        let _guard = lock_test_protector();
        let calls = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Some(Arc::new(CountingProtector {
            calls: calls.clone(),
        })));

        let outbound = DirectOutbound::new();
        let udp = network_timeout(
            "protected Direct UDP dial",
            outbound.dial_udp(DialContext::udp("1.1.1.1", 53)),
        )
        .await
        .unwrap();
        drop(udp);

        set_socket_protector(None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn direct_udp_send_and_recv_use_connected_socket_after_first_peer() {
        let _guard = lock_test_protector();
        set_socket_protector(None);

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = network_timeout("IPv4 UDP echo receive", server.recv_from(&mut buf))
                .await
                .unwrap();
            assert_eq!(&buf[..n], b"ping");
            network_timeout("IPv4 UDP echo send", server.send_to(b"pong", peer))
                .await
                .unwrap();
        });

        let outbound = DirectOutbound::new();
        let udp = network_timeout(
            "IPv4 Direct UDP dial",
            outbound.dial_udp(DialContext::udp("127.0.0.1", server_addr.port())),
        )
        .await
        .unwrap();
        network_timeout(
            "IPv4 Direct UDP send",
            udp.send_to(b"ping", "127.0.0.1", server_addr.port()),
        )
        .await
        .unwrap();

        let mut buf = [0u8; 64];
        let n = network_timeout("IPv4 Direct UDP receive", udp.recv_from(&mut buf))
            .await
            .unwrap();

        assert_eq!(&buf[..n], b"pong");
        network_timeout("IPv4 UDP echo task", echo).await.unwrap();
    }

    #[tokio::test]
    async fn direct_udp_fails_closed_for_a_different_target() {
        let _guard = lock_test_protector();
        set_socket_protector(None);

        let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();

        let outbound = DirectOutbound::new();
        let udp = network_timeout(
            "fixed-target Direct UDP dial",
            outbound.dial_udp(DialContext::udp("127.0.0.1", first_addr.port())),
        )
        .await
        .unwrap();

        let same_family_err = udp
            .send_to(b"wrong-peer", "127.0.0.1", second_addr.port())
            .await
            .unwrap_err();
        assert_eq!(same_family_err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            same_family_err
                .to_string()
                .contains("multiple destinations")
        );

        let cross_family_err = udp
            .send_to(b"wrong-family", "::1", first_addr.port())
            .await
            .unwrap_err();
        assert_eq!(cross_family_err.kind(), std::io::ErrorKind::InvalidInput);

        let mut first_buf = [0u8; 64];
        let mut second_buf = [0u8; 64];
        let (first_receive, second_receive) = tokio::join!(
            tokio::time::timeout(NETWORK_PROBE_TIMEOUT, first.recv_from(&mut first_buf),),
            tokio::time::timeout(NETWORK_PROBE_TIMEOUT, second.recv_from(&mut second_buf),)
        );
        assert!(
            first_receive.is_err() && second_receive.is_err(),
            "a rejected Direct UDP send must not leak to either destination"
        );
    }

    #[tokio::test]
    async fn direct_udp_supports_ipv6_targets() {
        let _guard = lock_test_protector();
        set_socket_protector(None);

        let server = match network_timeout(
            "IPv6 UDP echo bind",
            tokio::net::UdpSocket::bind("[::1]:0"),
        )
        .await
        {
            Ok(server) => server,
            Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                eprintln!(
                    "skipping Direct IPv6 UDP assertion: host cannot bind IPv6 loopback: {error}"
                );
                return;
            }
            Err(error) => panic!("IPv6 UDP echo bind failed: {error}"),
        };
        let server_addr = server.local_addr().unwrap();

        let outbound = DirectOutbound::new();
        let udp = network_timeout(
            "IPv6 Direct UDP dial",
            outbound.dial_udp(DialContext::udp("::1", server_addr.port())),
        )
        .await
        .unwrap();

        if !ipv6_udp_loopback_available().await {
            eprintln!(
                "Direct created an IPv6 association, but the host IPv6 loopback data plane is \
                 unavailable; skipping datagram round-trip"
            );
            return;
        }

        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = network_timeout("IPv6 UDP echo receive", server.recv_from(&mut buf))
                .await
                .unwrap();
            assert_eq!(&buf[..n], b"ping6");
            network_timeout("IPv6 UDP echo send", server.send_to(b"pong6", peer))
                .await
                .unwrap();
        });

        network_timeout(
            "IPv6 Direct UDP send",
            udp.send_to(b"ping6", "::1", server_addr.port()),
        )
        .await
        .unwrap();

        let mut buf = [0u8; 64];
        let n = network_timeout("IPv6 Direct UDP receive", udp.recv_from(&mut buf))
            .await
            .unwrap();

        assert_eq!(&buf[..n], b"pong6");
        network_timeout("IPv6 UDP echo task", echo).await.unwrap();
    }

    #[test]
    fn prepare_udp_socket_tracks_local_port_until_guard_drops() {
        let _guard = lock_test_protector();
        set_socket_protector(None);
        set_outbound_fwmark(0);

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let guard = prepare_outbound_udp_socket(&socket).unwrap();
        let source = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local.port(),
        );

        assert!(crate::loopback::is_loopback_udp_source(source));

        drop(guard);
        assert!(!crate::loopback::is_loopback_udp_source(source));
    }

    #[test]
    fn prepare_udp_socket_requires_configured_mark_to_succeed() {
        let _guard = lock_test_protector();
        set_socket_protector(None);
        set_outbound_fwmark(0x2024);

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let source = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local.port(),
        );

        let err = prepare_outbound_udp_socket_with(
            &socket,
            |_sock| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "mock SO_MARK failure",
                ))
            },
            None,
        )
        .unwrap_err();

        set_outbound_fwmark(0);
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!crate::loopback::is_loopback_udp_source(source));
    }

    #[test]
    fn outbound_mark_policy_skips_local_and_lan_targets() {
        assert!(!should_mark_outbound_addr("127.0.0.1".parse().unwrap()));
        assert!(!should_mark_outbound_addr("192.168.1.1".parse().unwrap()));
        assert!(!should_mark_outbound_addr("10.0.0.1".parse().unwrap()));
        assert!(!should_mark_outbound_addr("fd00::1".parse().unwrap()));
        assert!(!should_mark_outbound_addr("::1".parse().unwrap()));
        assert!(should_mark_outbound_addr("8.8.8.8".parse().unwrap()));
        assert!(should_mark_outbound_addr(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn loopback_detector_rejects_tracked_tcp_source_until_guard_drops() {
        let source: std::net::SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let guard = crate::loopback::register_tcp(source);

        assert!(crate::loopback::is_loopback_tcp_source(source));

        drop(guard);
        assert!(!crate::loopback::is_loopback_tcp_source(source));
    }

    #[test]
    fn loopback_detector_rejects_tracked_udp_local_port_only_for_local_source() {
        let local: std::net::SocketAddr = "0.0.0.0:42000".parse().unwrap();
        let guard = crate::loopback::register_udp(local);

        assert!(crate::loopback::is_loopback_udp_source(
            "127.0.0.1:42000".parse().unwrap()
        ));
        assert!(!crate::loopback::is_loopback_udp_source(
            "8.8.8.8:42000".parse().unwrap()
        ));

        drop(guard);
        assert!(!crate::loopback::is_loopback_udp_source(
            "127.0.0.1:42000".parse().unwrap()
        ));
    }

    #[test]
    fn loopback_detector_does_not_flag_non_loopback_local_ip_without_observed_addr() {
        // ROOT TUN 触发场景：
        // - 出站 socket 绑定 0.0.0.0:port，未 connect 时 udp_local_addrs 还没有记录；
        // - 同时设备上某个本地进程发包，内核选 TUN gateway 作 source IP，
        //   端口正好跟我们出站 socket 撞了。
        // 期望：不把这种合法上行流量误判为 self-capture，否则整条 ROOT TUN 链路
        // 99% 的 UDP 会被 listener 直接拒掉。
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let local = socket.local_addr().unwrap();
        let _guard = crate::loopback::register_udp(local);
        let Some(ip) = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .map(|iface| iface.ip())
            .find(|ip| !ip.is_unspecified() && !ip.is_loopback())
        else {
            return;
        };
        let source = std::net::SocketAddr::new(ip, local.port());

        assert!(!crate::loopback::is_loopback_udp_source(source));
    }

    #[test]
    fn loopback_detector_flags_observed_local_addr_after_connect() {
        // connect 之后 local_addr 拿到具体出口 IP；observe_local_addr 把
        // (egress_ip, port) 写进 udp_local_addrs。该精确组合再次进站才算自抓。
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let guard = crate::loopback::register_udp(local);
        guard.observe_local_addr(local);

        assert!(crate::loopback::is_loopback_udp_source(local));

        drop(guard);
        assert!(!crate::loopback::is_loopback_udp_source(local));
    }

    #[test]
    fn outbound_interface_index_round_trips() {
        let _guard = lock_test_protector();
        set_outbound_interface_index(Some(7), Some(11));
        assert_eq!(outbound_interface_index_v4(), Some(7));
        assert_eq!(outbound_interface_index_v6(), Some(11));
        // 0 视为未设置
        set_outbound_interface_index(None, None);
        assert_eq!(outbound_interface_index_v4(), None);
        assert_eq!(outbound_interface_index_v6(), None);
    }

    #[test]
    fn bind_outbound_socket_skips_non_global_target() {
        let _guard = lock_test_protector();
        // 本机 / 私网 / multicast 等目标 → 不绑定 ifindex（避免本机或 LAN 流量
        // 被强迫走外网接口）。函数应返回 Ok 且不报错。
        set_outbound_interface_index(Some(1), Some(1));
        let sock =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        // 127.x 走旁路
        let r = bind_outbound_socket(&sock, "127.0.0.1:80".parse().unwrap());
        assert!(r.is_ok());
        // 私网走旁路
        let r = bind_outbound_socket(&sock, "192.168.1.1:80".parse().unwrap());
        assert!(r.is_ok());
        set_outbound_interface_index(None, None);
    }

    #[test]
    fn bind_outbound_socket_no_op_when_index_unset() {
        let _guard = lock_test_protector();
        // 未设置 ifindex 时即便目标是 global-unicast 也仅 SO_BINDTODEVICE，
        // 不应报错。
        set_outbound_interface_index(None, None);
        let sock =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        let r = bind_outbound_socket(&sock, "8.8.8.8:53".parse().unwrap());
        assert!(r.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn bind_outbound_socket_sets_unicast_if_on_windows() {
        use std::os::windows::io::AsRawSocket;
        let _guard = lock_test_protector();
        // 取一个真实存在的 ifindex —— loopback (lo) 在 Windows 上 ifindex=1
        // 通常存在。
        set_outbound_interface_index(Some(1), Some(1));
        let sock =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        // 用 global-unicast 目标触发 ifindex 绑定
        bind_outbound_socket(&sock, "8.8.8.8:53".parse().unwrap()).unwrap();
        // 通过 getsockopt 验证 IP_UNICAST_IF 已设置（值为 ifindex 的 BE u32）
        let mut value: u32 = 0;
        let mut len: i32 = std::mem::size_of::<u32>() as i32;
        let raw = sock.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
        let ret = unsafe {
            windows_sys::Win32::Networking::WinSock::getsockopt(
                raw,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                windows_sys::Win32::Networking::WinSock::IP_UNICAST_IF as i32,
                &mut value as *mut u32 as *mut u8,
                &mut len,
            )
        };
        assert_eq!(ret, 0, "getsockopt IP_UNICAST_IF failed");
        // setsockopt 写 network-byte-order；getsockopt 返回 host-byte-order
        // —— 直接 == ifindex 比较即可。
        assert_eq!(value, 1, "IP_UNICAST_IF should round-trip ifindex=1");
        set_outbound_interface_index(None, None);
    }
}
