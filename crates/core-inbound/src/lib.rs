//! core-inbound —— 入站监听 / 协议解析 / 连接桥接。
//!
//! §8.1：listen.local 是用户唯一需要记住的入口，同一端口同时接收
//! HTTP CONNECT、HTTP 普通代理与 SOCKS5（CONNECT + UDP ASSOCIATE）。
//! TUN/TProxy 由 capture 模块单独承载。

#![forbid(unsafe_code)]

pub mod listener;
pub mod mixed;
pub mod privilege;
pub mod reality;
pub mod vless;

pub use listener::{bind_with_fallback, select_bind_addr};
pub use mixed::{MixedListener, run_mixed};
pub use privilege::{
    PrivilegeLevel, PrivilegeReport, ensure_best_effort_privilege, try_request_root_android,
};
pub use reality::{RealityListener, run_reality};
pub use vless::{VlessConnectionContext, VlessInboundConfig, serve_vless_stream};
