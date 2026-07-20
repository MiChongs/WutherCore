//! core-route —— 规则引擎。
//!
//! §5.7 / §11.3 要求：
//! * preset: cn_smart / global / direct / privacy / custom 必须在编译期展开为 steps。
//! * 域名/CIDR/端口/进程/网络规则可在热路径 O(1)~O(log n) 命中。
//! * 内置 home/cn/ads/service 别名集合，版本化维护。

#![forbid(unsafe_code)]

pub mod builtin;
pub mod engine;
pub mod sniff;

pub use engine::{FlowContext, FlowRulesetMetadata, NetworkKind, RouteDecision, RouteEngine};
pub use sniff::{L7Proto, proto_name_matches, sniff_tcp, sniff_udp};
