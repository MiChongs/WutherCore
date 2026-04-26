//! core-capture —— 透明代理（TUN / TProxy / redirect）平台适配。
//!
//! §8 设计要点：
//! * Linux/Android：tproxy + redirect + native TUN（/dev/net/tun）。
//! * Windows：Wintun + 系统路由表（CreateUnicastIpv4Route）。
//! * macOS：utun + pf 防火墙。
//! * OpenWrt：检查 kmod-nft-tproxy / iptables-mod-tproxy。
//! * Tailscale：默认排除 100.64.0.0/10、fd7a:115c:a1e0::/48 与 tailscale0。
//!
//! 这个模块负责 *接管*（drag traffic into the kernel），抓到的连接交给
//! [`Runtime::dial`]。本实现遵循 §11.7：所有平台具体细节封装在
//! [`Engine`] trait 后面，跨平台代码用 [`CaptureSupervisor`] 协调。
//!
//! ## unsafe 政策
//!
//! 本 crate 是 syscall 胶水层（TUN ioctl、utun PF_SYSTEM、Wintun ABI）。
//! 全局 `deny(unsafe_code)` —— 平台子模块需要 raw syscall 的位置使用
//! `#[allow(unsafe_code)]` 局部覆盖，每处都必须配套安全注释。

#![deny(unsafe_code)]

pub mod android_caps;
pub mod dial_meta;
pub mod doctor;
pub mod eim_nat;
pub mod engine;
pub mod fakeip_dns;
pub mod ipset;
pub mod nat;
pub mod packet;
pub mod platform;
pub mod route_table;
pub mod stack;
pub mod supervisor;
pub mod sys_proxy;
pub mod tun;
pub mod tun_dispatch;
pub mod tun_io;
pub mod udp_forwarder;
pub mod udp_session;

pub use android_caps::{AndroidCapability, AndroidTier};
pub use dial_meta::{build_dial_target, DialTarget, DnsMode};

pub use doctor::{diagnose, DoctorReport};
pub use eim_nat::{EimEntry, EimKey, EimNatTable};
pub use engine::{
    AutoRedirectMarks, CaptureEngine, CaptureError, CaptureEvent, CaptureFilters, CapturePlan,
    EngineKind,
};
pub use ipset::{noop as noop_ipset_provider, IpSetProvider, NoopIpSetProvider};
pub use stack::{
    AcceptedTcp, SharedStack, SmolStream, SpliceManager, StackNotify, UserSpaceStack,
    VirtualTunDevice, DEFAULT_LISTENER_POOL,
};
pub use tun_dispatch::{TunDispatcher, TunDispatcherHandles};
pub use udp_forwarder::{run_return_loop, send_one as udp_send_one, UdpForwarderConfig};
pub use udp_session::{UdpFlowKey, UdpSession, UdpSessionTable};
pub use nat::{FlowKey, HostPin, NatEntry, NatTable};
pub use sys_proxy::SystemProxyGuard;
pub use packet::{IpHeader, IpVersion, L4, ParsedPacket, TcpFlags, TcpSummary, UdpSummary};
pub use route_table::{ManagedRoute, RouteBackend, RouteTable, SystemBackend};
pub use supervisor::CaptureSupervisor;
pub use tun::{TunConfig, TunDevice};
pub use tun_io::{open_tun_device, TunIo, TunIoError};
