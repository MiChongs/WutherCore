//! core-outbound —— 出站协议适配器。
//!
//! §11.2 关键 trait [`OutboundAdapter`]：所有出站使用统一接口。
//! MVP 阶段实现 direct / block / http / socks5 / shadowsocks（基础 AEAD）。
//! 其它协议（vmess / vless / trojan / hysteria2 / tuic / wireguard / ssh）
//! 提供 stub 适配器，并在 dial 时返回"协议尚未实现"。

#![forbid(unsafe_code)]

pub mod adapter;
pub mod registry;

pub mod direct;
pub mod block;
pub mod http;
pub mod socks5;
pub mod stub;

pub mod transport;
pub mod proto;

pub use adapter::{
    apply_outbound_mark, apply_outbound_mark_for_addr, global_dial_resolver, next_dial_id,
    outbound_fwmark, resolve_host, set_global_dial_resolver, set_outbound_fwmark, BoxedStream,
    BoxedUdp, Capabilities, DialContext, DialResolver, OutboundAdapter, ProxyStream,
    UdpSocketLike,
};
pub use registry::{OutboundRegistry, ResolveFn};
