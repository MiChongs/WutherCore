//! `route_address_set` / `route_exclude_address_set` 联动接口。
//!
//! sing-box 的两个集合字段引用 ruleset 名（如 `geoip-cn`）；本 crate 不直接
//! 依赖 core-ruleset（避免循环），而是定义最小 [`IpSetProvider`] trait。
//! 应用层（main.rs / supervisor 构建处）传入一个 `Arc<dyn IpSetProvider>`
//! 把 RulesetIndex 桥接进来。
//!
//! 不注入时使用 [`NoopIpSetProvider`] —— 行为：未知集合 = false（不命中）。

use std::{net::IpAddr, sync::Arc};

use ipnet::{Ipv4Net, Ipv6Net};
use thiserror::Error;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSetPrefixSemantics {
    Exact,
    /// sing-box-compatible destination-IP extraction from a richer ruleset.
    Extracted,
    NotIpSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSetPrefixStatus {
    Ready { semantics: IpSetPrefixSemantics },
    Pending,
    Unavailable,
    Missing,
    TooManyPrefixes { limit: usize },
    AllocationFailed,
    InvalidRange { family: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetPrefixSet {
    pub name: String,
    pub status: IpSetPrefixStatus,
    pub ipv4: Arc<Vec<Ipv4Net>>,
    pub ipv6: Arc<Vec<Ipv6Net>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetPrefixSnapshot {
    pub revision: u64,
    pub sets: Arc<Vec<IpSetPrefixSet>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpSetSnapshotError {
    #[error("IP-set provider does not support prefix snapshots")]
    Unsupported,
    #[error("IP-set provider snapshot failed: {0}")]
    Provider(String),
}

pub trait IpSetProvider: Send + Sync + std::fmt::Debug {
    /// 集合 `name` 是否包含 `ip`。集合不存在或不是 IP 集合时返回 false。
    fn contains(&self, name: &str, ip: IpAddr) -> bool;

    /// 当前已加载的集合名（仅供 doctor / report）。
    fn names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Atomically read all requested sets at one provider revision.
    fn prefix_snapshot(
        &self,
        _names: &[String],
    ) -> Result<IpSetPrefixSnapshot, IpSetSnapshotError> {
        Err(IpSetSnapshotError::Unsupported)
    }

    /// Subscribe to desired-state revisions. `watch` intentionally coalesces
    /// intermediate revisions; consumers reconcile the latest full snapshot.
    fn subscribe_prefix_updates(&self) -> Option<watch::Receiver<u64>> {
        None
    }

    /// Race-free initial snapshot + subscription. Snapshot-capable providers
    /// should override this instead of composing the two methods above.
    fn prefix_snapshot_and_subscribe(
        &self,
        _names: &[String],
    ) -> Result<(IpSetPrefixSnapshot, watch::Receiver<u64>), IpSetSnapshotError> {
        Err(IpSetSnapshotError::Unsupported)
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
        assert_eq!(
            p.prefix_snapshot(&["geoip-cn".into()]),
            Err(IpSetSnapshotError::Unsupported)
        );
        assert!(p.subscribe_prefix_updates().is_none());
        assert!(matches!(
            p.prefix_snapshot_and_subscribe(&["geoip-cn".into()]),
            Err(IpSetSnapshotError::Unsupported)
        ));
    }
}
