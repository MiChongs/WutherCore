//! `route_address_set` / `route_exclude_address_set` 联动接口。
//!
//! sing-box 的两个集合字段引用 ruleset 名（如 `geoip-cn`）；本 crate 不直接
//! 依赖 core-ruleset（避免循环），而是定义最小 [`IpSetProvider`] trait。
//! 应用层（main.rs / supervisor 构建处）传入一个 `Arc<dyn IpSetProvider>`
//! 把 RulesetIndex 桥接进来。
//!
//! 不注入时使用 [`NoopIpSetProvider`] —— 行为：未知集合 = false（不命中）。

use std::net::IpAddr;
use std::sync::Arc;

pub trait IpSetProvider: Send + Sync + std::fmt::Debug {
    /// 集合 `name` 是否包含 `ip`。集合不存在或不是 IP 集合时返回 false。
    fn contains(&self, name: &str, ip: IpAddr) -> bool;

    /// 当前已加载的集合名（仅供 doctor / report）。
    fn names(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub struct NoopIpSetProvider;

impl IpSetProvider for NoopIpSetProvider {
    fn contains(&self, _name: &str, _ip: IpAddr) -> bool {
        false
    }
}

pub fn noop() -> Arc<dyn IpSetProvider> {
    Arc::new(NoopIpSetProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_returns_false() {
        let p = noop();
        assert!(!p.contains("geoip-cn", "1.1.1.1".parse().unwrap()));
        assert!(p.names().is_empty());
    }
}
