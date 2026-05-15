//! core-resolver —— DNS 解析（与 mihomo / Clash 等价 + 防泄漏）。
//!
//! ## 关键能力
//!
//! | 能力 | 实现 |
//! |---|---|
//! | **乐观缓存**（stale-while-revalidate） | [`cache::DnsCache`] |
//! | **多上游 group 并发**（fastest / fallback / all） | [`group::DnsGroup`] |
//! | **域名策略**（reject / accept / direct / proxy / fake） | [`policy::PolicyEngine`] |
//! | **节点 host 走 bootstrap** 防代理回环 | [`resolver::Resolver::resolve_via_bootstrap`] |
//! | **Fake IP 池**（双栈 + TTL + 保留地址回避） | [`fake_ip::FakeIpPool`] |
//! | **DoH / DoT / UDP / TCP 上游** | [`upstream::hickory`] |
//! | **系统 resolver fallback** | [`upstream::system`] |
//!
//! ## 防泄漏（§7.3）
//!
//! 1. capture 模式默认 hijack 53 端口（fake-ip）；
//! 2. DNS 默认路径使用 `nameserver`，按 `nameserver-policy` 与 `fallback-filter` 切换上游；
//! 3. 代理节点 host 通过 bootstrap，永不进入业务 policy 流；
//! 4. Tailnet / 局域网域名 → direct local；
//! 5. 失败时绝不静默回退到系统 DNS（除非 mode=system）。

#![forbid(unsafe_code)]

pub mod cache;
pub mod fake_ip;
pub mod group;
pub mod hosts;
pub mod mapping;
pub mod middleware;
pub mod packet;
pub mod policy;
pub mod resolver;
pub mod service;
pub mod singleflight;
pub mod upstream;

pub use cache::{CacheConfig, DnsCache, Hit, QType};
pub use fake_ip::{FakeIpFilter, FakeIpPool};
pub use group::{DnsGroup, GroupStrategy};
pub use hosts::HostsTable;
pub use mapping::IpHostMapping;
pub use policy::{
    DnsAction, DnsRR, EvalContext, HostMatch, PolicyEngine, PolicyRule, PreRcode,
    PredefinedResponse, QueryOptions, RejectMethod, RejectOptions, RejectThrottle, parse_rule_line,
};
pub use resolver::{ResolveAnswer, ResolveError, Resolver, ResolverBuilder, ResolverConfigError};
pub use service::DnsService;
pub use singleflight::Singleflight;
pub use upstream::{
    DnsError, DnsUpstream, FilteredUpstream, UpstreamParams,
    hickory::{HickoryKind, HickoryUpstream},
    system::SystemUpstream,
};
