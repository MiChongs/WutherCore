//! core-outbound —— 出站协议适配器。
//!
//! §11.2 关键 trait [`OutboundAdapter`]：所有出站使用统一接口。
//! 除 direct / block / HTTP / SOCKS5 外，也包含 VMess、VLESS、Trojan、
//! Hysteria、TUIC、WireGuard 等协议的真实数据面；各协议的精确能力以
//! [`proto`] 模块和注册器校验为准。

// 大多数模块禁 unsafe；adapter 里 Windows IP_UNICAST_IF / macOS IP_BOUND_IF
// 必须走 raw setsockopt，由 cfg 平台分支控制，按 module 粒度 allow（其它模块
// 仍受 deny 约束）。
#![deny(unsafe_code)]

#[allow(unsafe_code)]
pub mod adapter;
pub mod loopback;
pub mod registry;
#[allow(unsafe_code)]
pub mod socket_policy;

pub mod block;
pub mod direct;
pub mod dns_hijack;
pub mod http;
pub mod socks5;
pub mod stub;

pub mod proto;
pub mod transport;

pub use adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, DialResolver, OutboundAdapter,
    ProtectedSocket, ProxyStream, SocketProtector, UdpSocketLike, apply_outbound_mark,
    apply_outbound_mark_for_addr, bind_outbound_socket, bind_to_device,
    compare_exchange_outbound_fwmark, create_outbound_udp_socket, global_dial_resolver,
    has_socket_protector, next_dial_id, outbound_fwmark, outbound_interface,
    outbound_interface_index_v4, outbound_interface_index_v6, prepare_outbound_udp_socket,
    prepare_outbound_udp_socket_for_addr, protect_socket, resolve_host, set_global_dial_resolver,
    set_outbound_fwmark, set_outbound_interface, set_outbound_interface_index,
    set_socket_protector, should_mark_outbound_addr,
};
pub use dns_hijack::{
    DnsHijackOutbound, DnsResponder, global_dns_responder, set_global_dns_responder,
};
pub use loopback::{
    LoopbackTcpGuard, LoopbackUdpGuard, TrackedTcpStream, is_loopback_tcp_source,
    is_loopback_udp_source, register_tcp, register_udp,
};
pub use registry::{OutboundRegistry, ResolveFn};
