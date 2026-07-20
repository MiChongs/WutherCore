//! core-runtime —— 把 `RuntimePlan` 接成一张实际可工作的 graph。
//!
//! §11 模块划分：runtime 持有 selector + dispatcher + 资源生命周期。
//! 它不负责具体的 inbound/outbound 协议实现，只负责把它们粘起来。

#![forbid(unsafe_code)]

pub mod dns_listener;
pub mod engine;
pub mod group_selector;
pub mod health;
pub mod int_ranges;
pub mod listener_handler;

pub use dns_listener::{DnsListener, DnsListenerError, spawn_dns_listener};
pub use engine::{DialResult, RoutePick, Runtime, RuntimeError, UdpDialResult};
pub use group_selector::{FlowMeta, GroupOptions, GroupSelector, LbStrategy};
pub use health::{
    DEAD_DELAY, DelayError, FAST_PICK_TTL, HistoryEntry, NodeUrlStats, UrlTestConfig, UrlTestOpts,
    UrlTester, spawn_periodic,
};
pub use int_ranges::{IntRanges, Range};
pub use listener_handler::{InboundMetadata, ListenerHandler, PreparedTcp, PreparedUdpPacket};
