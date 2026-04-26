use std::pin::Pin;
use std::sync::Arc;

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
   * 配 `ip rule fwmark <mark> lookup main priority N` 让带标的包走主路由表
     （主路由表的默认网关是物理 wlan0/eth0，不是 TUN）

   capture 的 `install_auto_route` 会自动写这条 rule（见 platform/linux.rs）。
   ============================================================ */

use std::sync::atomic::{AtomicU32, Ordering};

static OUTBOUND_FWMARK: AtomicU32 = AtomicU32::new(0);

/// 设置全局 outbound fwmark；0 = 禁用。
/// 与 mihomo `dialer.DefaultRoutingMark` 一致：默认禁用，只有显式 routing-mark
/// 或 TUN auto_redirect mark-mode 需要时才启用。
pub fn set_outbound_fwmark(mark: u32) {
    OUTBOUND_FWMARK.store(mark, Ordering::Release);
}

pub fn outbound_fwmark() -> u32 {
    OUTBOUND_FWMARK.load(Ordering::Acquire)
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
    if !is_global_unicast(addr.ip()) {
        return Ok(());
    }
    apply_outbound_mark(sock)
}

fn is_global_unicast(ip: std::net::IpAddr) -> bool {
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
/// * SOCKS5：UDP ASSOCIATE。
/// * VMess/Trojan/VLESS：协议级 UDP-over-TCP / UDP-over-WS。
/// * Hysteria2 / TUIC：协议原生 UDP。
/// * Block：直接返回 ConnectionRefused。
///
/// `target` 是远端目标地址（域名或 IP）；recv_from 返回的 SocketAddr
/// 可能是 NAT-mapped 后的 src，调用方一般忽略（TUN 转发只关心 payload）。
#[async_trait]
pub trait UdpSocketLike: Send + Sync {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// 关闭通道；某些协议需要发协议级断开。
    async fn close(&self) -> std::io::Result<()> { Ok(()) }
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
            format!("outbound `{}`/{} 暂未实现 UDP 通道", self.name(), self.protocol()),
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

   解决：所有 transport 在 connect 之前先调本 trait 走 RPKernel
   自己的 resolver（IP 直连 DoH，不经过 TUN），拿到 IP 字面再 connect。

   主进程（proxy-core/main.rs 或 core-runtime engine.rs）启动时调
   `set_global_dial_resolver(...)` 注入 Arc<dyn DialResolver>；
   未注入时 transport 退回 `TcpStream::connect((host, port))` 旧行为。
*/

use std::sync::OnceLock;

#[async_trait]
pub trait DialResolver: Send + Sync + std::fmt::Debug {
    /// 解析 host 为 IP 列表（IP 字面直接返回；hostname 走 RPKernel resolver）。
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>>;
}

static DIAL_RESOLVER: OnceLock<Arc<dyn DialResolver>> = OnceLock::new();

pub fn set_global_dial_resolver(r: Arc<dyn DialResolver>) {
    let _ = DIAL_RESOLVER.set(r);
}

pub fn global_dial_resolver() -> Option<Arc<dyn DialResolver>> {
    DIAL_RESOLVER.get().cloned()
}

/// transport 通用辅助：解析 host 为 IP 列表。
/// host 已经是 IP literal → 直接返回；否则走 global DialResolver；
/// 没注入 resolver → 回退 tokio `lookup_host`（与旧行为兼容）。
pub async fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
    let started = std::time::Instant::now();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        tracing::debug!(target: "dial::resolve", %host, port, "literal IP, no resolution");
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    if let Some(r) = global_dial_resolver() {
        tracing::debug!(target: "dial::resolve", %host, port, source = "rpkernel-resolver", "begin");
        match r.resolve(host).await {
            Ok(ips) => {
                if ips.is_empty() {
                    tracing::warn!(
                        target: "dial::resolve",
                        %host, port,
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
                    %host, port,
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
                    %host, port,
                    error = %e,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "rpkernel-resolver failed",
                );
                return Err(e);
            }
        }
    }
    tracing::debug!(target: "dial::resolve", %host, port, source = "system-getaddrinfo", "begin");
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let collected: Vec<_> = addrs.collect();
    tracing::info!(
        target: "dial::resolve",
        %host, port,
        count = collected.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "resolved (system)",
    );
    Ok(collected)
}
