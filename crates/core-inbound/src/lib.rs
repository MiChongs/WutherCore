//! core-inbound —— 入站监听 / 协议解析 / 连接桥接。
//!
//! §8.1：listen.local 是用户唯一需要记住的入口，同一端口同时接收
//! HTTP CONNECT、HTTP 普通代理与 SOCKS5（CONNECT + UDP ASSOCIATE）。
//! TUN/TProxy 由 capture 模块单独承载。

#![forbid(unsafe_code)]

#[cfg(feature = "with_grpc")]
pub mod grpc;
pub mod listener;
pub mod mixed;
pub mod privilege;
#[cfg(feature = "with_reality")]
pub mod reality;
#[cfg(feature = "with_shadowsocks")]
pub mod shadowsocks;
pub mod vless;
#[cfg(feature = "with_xhttp")]
pub mod xhttp;
#[cfg(feature = "with_xhttp")]
mod xhttp_body_budget;
#[cfg(feature = "with_xhttp")]
mod xhttp_cors;
#[cfg(feature = "with_xhttp")]
pub mod xhttp_listener;
#[cfg(feature = "tls_inbound")]
mod xhttp_tls;

#[cfg(feature = "with_grpc")]
pub use grpc::{GrpcListener, run_grpc, run_grpc_with_cancellation};
pub use listener::{bind_with_fallback, select_bind_addr};
pub use mixed::{MixedListener, run_mixed};
pub use privilege::{
    PrivilegeLevel, PrivilegeReport, ensure_best_effort_privilege, try_request_root_android,
};
#[cfg(feature = "with_reality")]
pub use reality::{RealityListener, run_reality};
#[cfg(feature = "with_shadowsocks")]
pub use shadowsocks::{
    ShadowsocksListenerHandle, start_shadowsocks_listener, start_shadowsocks_listeners,
};
pub use vless::{VlessConnectionContext, VlessInboundConfig, serve_vless_stream};
#[cfg(feature = "with_xhttp")]
pub use xhttp_listener::{XhttpListenerHandle, start_xhttp_listener, start_xhttp_listeners};
#[cfg(feature = "tls_inbound")]
pub use xhttp_tls::{XrayServerTlsAcceptor, XrayServerTlsCarrier, XrayServerTlsStream};
