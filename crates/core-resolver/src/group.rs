//! DNS 上游 group —— 多上游并发调度。
//!
//! 三种策略：
//! * **Fastest**：所有上游 join_set 并发，第一个返回非空答案的赢。
//! * **Fallback**：按顺序尝试，失败/空才到下一个。
//! * **All**：等所有上游，结果 IP 取并集（去重）。

use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

use hickory_resolver::proto::rr::{Record, RecordType};
use tokio::{task::JoinSet, time::timeout};

use crate::upstream::{DnsError, DnsUpstream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStrategy {
    Fastest,
    Fallback,
    All,
}

#[derive(Clone)]
pub struct DnsGroup {
    pub name: String,
    pub strategy: GroupStrategy,
    pub members: Vec<Arc<dyn DnsUpstream>>,
    pub timeout: Duration,
}

impl std::fmt::Debug for DnsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsGroup")
            .field("name", &self.name)
            .field("strategy", &self.strategy)
            .field(
                "members",
                &self
                    .members
                    .iter()
                    .map(|m| (m.name().to_string(), m.kind()))
                    .collect::<Vec<_>>(),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl DnsGroup {
    pub fn new(
        name: impl Into<String>,
        strategy: GroupStrategy,
        members: Vec<Arc<dyn DnsUpstream>>,
    ) -> Self {
        Self {
            name: name.into(),
            strategy,
            members,
            timeout: Duration::from_secs(5),
        }
    }

    /// Reset all persistent connections in this group's members.
    /// Called on network interface change to force reconnection on the new NIC.
    pub async fn reset_connections(&self) {
        for member in &self.members {
            member.reset_connections().await;
        }
    }

    pub async fn resolve(&self, host: &str, want_v6: bool) -> Result<Vec<IpAddr>, DnsError> {
        if self.members.is_empty() {
            return Err(DnsError::Failed(format!("group {} 无成员", self.name)));
        }
        match self.strategy {
            GroupStrategy::Fastest => self.run_fastest(host, want_v6).await,
            GroupStrategy::Fallback => self.run_fallback(host, want_v6).await,
            GroupStrategy::All => self.run_all(host, want_v6).await,
        }
    }

    pub async fn resolve_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        if self.members.is_empty() {
            return Err(DnsError::Failed(format!("group {} 无成员", self.name)));
        }
        match self.strategy {
            GroupStrategy::Fastest => self.run_fastest_records(host, record_type).await,
            GroupStrategy::Fallback => self.run_fallback_records(host, record_type).await,
            GroupStrategy::All => self.run_all_records(host, record_type).await,
        }
    }

    async fn run_fastest(&self, host: &str, want_v6: bool) -> Result<Vec<IpAddr>, DnsError> {
        let mut set = JoinSet::new();
        for up in &self.members {
            let up = up.clone();
            let host = host.to_string();
            let to = self.timeout;
            set.spawn(async move {
                let fut = if want_v6 {
                    up.query_aaaa(&host)
                } else {
                    up.query_a(&host)
                };
                match timeout(to, fut).await {
                    Ok(Ok(v)) if !v.is_empty() => Ok(v),
                    Ok(Ok(_)) => Err(DnsError::Empty),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(DnsError::Timeout),
                }
            });
        }
        let mut last_err: Option<DnsError> = None;
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Ok(ips)) => {
                    set.abort_all();
                    return Ok(ips);
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(DnsError::Failed(e.to_string())),
            }
        }
        Err(last_err.unwrap_or(DnsError::Empty))
    }

    async fn run_fallback(&self, host: &str, want_v6: bool) -> Result<Vec<IpAddr>, DnsError> {
        let mut last_err: Option<DnsError> = None;
        for up in &self.members {
            let fut = if want_v6 {
                up.query_aaaa(host)
            } else {
                up.query_a(host)
            };
            match timeout(self.timeout, fut).await {
                Ok(Ok(v)) if !v.is_empty() => return Ok(v),
                Ok(Ok(_)) => last_err = Some(DnsError::Empty),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(DnsError::Timeout),
            }
        }
        Err(last_err.unwrap_or(DnsError::Empty))
    }

    async fn run_all(&self, host: &str, want_v6: bool) -> Result<Vec<IpAddr>, DnsError> {
        let mut set = JoinSet::new();
        for up in &self.members {
            let up = up.clone();
            let host = host.to_string();
            let to = self.timeout;
            set.spawn(async move {
                let fut = if want_v6 {
                    up.query_aaaa(&host)
                } else {
                    up.query_a(&host)
                };
                match timeout(to, fut).await {
                    Ok(Ok(v)) => Ok(v),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(DnsError::Timeout),
                }
            });
        }
        let mut all = HashSet::new();
        let mut last_err: Option<DnsError> = None;
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Ok(v)) => {
                    for ip in v {
                        all.insert(ip);
                    }
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(DnsError::Failed(e.to_string())),
            }
        }
        if all.is_empty() {
            Err(last_err.unwrap_or(DnsError::Empty))
        } else {
            Ok(all.into_iter().collect())
        }
    }

    async fn run_fastest_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let mut set = JoinSet::new();
        for up in &self.members {
            let up = up.clone();
            let host = host.to_string();
            let to = self.timeout;
            set.spawn(async move {
                match timeout(to, up.query_records(&host, record_type)).await {
                    Ok(Ok(v)) if !v.is_empty() => Ok(v),
                    Ok(Ok(_)) => Err(DnsError::Empty),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(DnsError::Timeout),
                }
            });
        }
        let mut last_err: Option<DnsError> = None;
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Ok(records)) => {
                    set.abort_all();
                    return Ok(records);
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(DnsError::Failed(e.to_string())),
            }
        }
        Err(last_err.unwrap_or(DnsError::Empty))
    }

    async fn run_fallback_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let mut last_err: Option<DnsError> = None;
        for up in &self.members {
            match timeout(self.timeout, up.query_records(host, record_type)).await {
                Ok(Ok(v)) if !v.is_empty() => return Ok(v),
                Ok(Ok(_)) => last_err = Some(DnsError::Empty),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(DnsError::Timeout),
            }
        }
        Err(last_err.unwrap_or(DnsError::Empty))
    }

    async fn run_all_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let mut set = JoinSet::new();
        for up in &self.members {
            let up = up.clone();
            let host = host.to_string();
            let to = self.timeout;
            set.spawn(async move {
                match timeout(to, up.query_records(&host, record_type)).await {
                    Ok(Ok(v)) => Ok(v),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(DnsError::Timeout),
                }
            });
        }
        let mut all = Vec::new();
        let mut last_err: Option<DnsError> = None;
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Ok(v)) => all.extend(v),
                Ok(Err(e)) => last_err = Some(e),
                Err(e) => last_err = Some(DnsError::Failed(e.to_string())),
            }
        }
        if all.is_empty() {
            Err(last_err.unwrap_or(DnsError::Empty))
        } else {
            Ok(all)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::upstream::DnsUpstream;

    #[derive(Debug)]
    struct StaticUpstream {
        name: String,
        kind: &'static str,
        delay_ms: u64,
        result: Result<Vec<IpAddr>, DnsError>,
        calls: AtomicU32,
    }

    impl StaticUpstream {
        fn new(name: &str, delay_ms: u64, result: Result<Vec<IpAddr>, DnsError>) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                kind: "test",
                delay_ms,
                result,
                calls: AtomicU32::new(0),
            })
        }
    }

    #[async_trait]
    impl DnsUpstream for StaticUpstream {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> &'static str {
            self.kind
        }
        async fn query_a(&self, _: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            self.result.clone()
        }
        async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            self.query_a(host).await
        }
    }

    #[tokio::test]
    async fn fastest_returns_first_success() {
        let slow = StaticUpstream::new("slow", 80, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let fast = StaticUpstream::new("fast", 5, Ok(vec!["2.2.2.2".parse().unwrap()]));
        let g = DnsGroup::new(
            "g",
            GroupStrategy::Fastest,
            vec![slow.clone() as _, fast.clone() as _],
        );
        let v = g.resolve("any", false).await.unwrap();
        assert_eq!(v, vec!["2.2.2.2".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn fallback_skips_failed() {
        let bad = StaticUpstream::new("bad", 5, Err(DnsError::Failed("x".into())));
        let ok = StaticUpstream::new("ok", 5, Ok(vec!["3.3.3.3".parse().unwrap()]));
        let g = DnsGroup::new(
            "g",
            GroupStrategy::Fallback,
            vec![bad.clone() as _, ok.clone() as _],
        );
        let v = g.resolve("any", false).await.unwrap();
        assert_eq!(v, vec!["3.3.3.3".parse::<IpAddr>().unwrap()]);
        assert_eq!(bad.calls.load(Ordering::Relaxed), 1);
        assert_eq!(ok.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn all_unions_results() {
        let a = StaticUpstream::new("a", 5, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let b = StaticUpstream::new(
            "b",
            5,
            Ok(vec!["2.2.2.2".parse().unwrap(), "1.1.1.1".parse().unwrap()]),
        );
        let g = DnsGroup::new(
            "g",
            GroupStrategy::All,
            vec![a.clone() as _, b.clone() as _],
        );
        let mut v = g.resolve("any", false).await.unwrap();
        v.sort();
        assert_eq!(
            v,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2.2.2.2".parse().unwrap()
            ]
        );
    }
}
