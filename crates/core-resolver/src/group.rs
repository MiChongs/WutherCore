//! DNS 上游统一调度器。
//!
//! group 可以嵌套；每一层独立选择成员，因此外层并发不会自动展开成所有叶子
//! endpoint 的笛卡尔积。`Adaptive` 使用与 AdGuard dnsproxy load-balance
//! 相同的 `1 / average_rtt` 权重，并把失败按本组超时计入样本。

use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{StreamExt, stream};
use hickory_resolver::proto::rr::{Record, RecordType};
use parking_lot::Mutex;
use rand::{
    distributions::{Distribution, WeightedIndex},
    seq::SliceRandom,
};
use tokio::time::timeout;

use crate::upstream::{DnsError, DnsUpstream};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupStrategy {
    RoundRobin,
    Random,
    Parallel,
    Adaptive,
    Sequential,
    All,
    /// 旧 API 兼容：等价于 `Parallel`。
    Fastest,
    /// 旧 API 兼容：等价于 `Sequential`。
    Fallback,
}

impl GroupStrategy {
    pub fn parse(value: &str) -> Option<Self> {
        Some(
            match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
                "round-robin" | "roundrobin" | "rr" => Self::RoundRobin,
                "random" => Self::Random,
                "parallel" | "fastest" => Self::Parallel,
                "adaptive" | "load-balance" | "load-balance-adaptive" => Self::Adaptive,
                "sequential" | "fallback" => Self::Sequential,
                "all" => Self::All,
                _ => return None,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MemberStats {
    pub requests: u64,
    pub failures: u64,
    pub average_rtt: Duration,
}

#[derive(Debug, Clone, Copy, Default)]
struct RawMemberStats {
    requests: u64,
    failures: u64,
    rtt_sum_micros: f64,
}

impl RawMemberStats {
    fn record(&mut self, elapsed: Duration, success: bool) {
        self.requests = self.requests.saturating_add(1);
        if !success {
            self.failures = self.failures.saturating_add(1);
        }
        self.rtt_sum_micros += elapsed.as_micros().max(1) as f64;
    }

    fn weight(self) -> f64 {
        if self.requests == 0 || self.rtt_sum_micros == 0.0 {
            1.0
        } else {
            1.0 / (self.rtt_sum_micros / self.requests as f64)
        }
    }

    fn public(self) -> MemberStats {
        MemberStats {
            requests: self.requests,
            failures: self.failures,
            average_rtt: if self.requests == 0 {
                Duration::ZERO
            } else {
                Duration::from_micros(
                    (self.rtt_sum_micros / self.requests as f64)
                        .round()
                        .min(u64::MAX as f64) as u64,
                )
            },
        }
    }
}

#[derive(Debug, Default)]
struct GroupState {
    cursor: AtomicU64,
    stats: Mutex<Vec<RawMemberStats>>,
}

#[derive(Clone)]
pub struct DnsGroup {
    pub name: String,
    pub strategy: GroupStrategy,
    pub members: Vec<Arc<dyn DnsUpstream>>,
    pub timeout: Duration,
    pub max_parallel: usize,
    state: Arc<GroupState>,
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
            .field("max_parallel", &self.max_parallel)
            .finish()
    }
}

impl DnsGroup {
    pub fn new(
        name: impl Into<String>,
        strategy: GroupStrategy,
        members: Vec<Arc<dyn DnsUpstream>>,
    ) -> Self {
        let stats = vec![RawMemberStats::default(); members.len()];
        Self {
            name: name.into(),
            strategy,
            members,
            timeout: Duration::from_secs(5),
            max_parallel: 2,
            state: Arc::new(GroupState {
                cursor: AtomicU64::new(0),
                stats: Mutex::new(stats),
            }),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_millis(1));
        self
    }

    pub fn with_max_parallel(mut self, max_parallel: usize) -> Self {
        self.max_parallel = max_parallel.max(1);
        self
    }

    pub fn member_stats(&self) -> Vec<MemberStats> {
        self.state
            .stats
            .lock()
            .iter()
            .copied()
            .map(RawMemberStats::public)
            .collect()
    }

    /// Reset all persistent connections in this group's members.
    pub async fn reset_connections(&self) {
        for member in &self.members {
            member.reset_connections().await;
        }
    }

    pub async fn resolve(&self, host: &str, want_v6: bool) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve_with_strategy(host, want_v6, None).await
    }

    pub async fn resolve_with_strategy(
        &self,
        host: &str,
        want_v6: bool,
        strategy: Option<GroupStrategy>,
    ) -> Result<Vec<IpAddr>, DnsError> {
        self.ensure_members()?;
        let strategy = strategy.unwrap_or(self.strategy);
        match strategy {
            GroupStrategy::Parallel | GroupStrategy::Fastest => {
                self.run_parallel(host, want_v6, false).await
            }
            GroupStrategy::All => self.run_parallel(host, want_v6, true).await,
            _ => self.run_sequential(host, want_v6, strategy).await,
        }
    }

    pub async fn resolve_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        self.resolve_records_with_strategy(host, record_type, None)
            .await
    }

    pub async fn resolve_records_with_strategy(
        &self,
        host: &str,
        record_type: RecordType,
        strategy: Option<GroupStrategy>,
    ) -> Result<Vec<Record>, DnsError> {
        self.ensure_members()?;
        let strategy = strategy.unwrap_or(self.strategy);
        match strategy {
            GroupStrategy::Parallel | GroupStrategy::Fastest => {
                self.run_parallel_records(host, record_type, false).await
            }
            GroupStrategy::All => self.run_parallel_records(host, record_type, true).await,
            _ => {
                self.run_sequential_records(host, record_type, strategy)
                    .await
            }
        }
    }

    fn ensure_members(&self) -> Result<(), DnsError> {
        if self.members.is_empty() {
            Err(DnsError::Failed(format!("group {} 无成员", self.name)))
        } else {
            Ok(())
        }
    }

    fn ordered_indices(&self, strategy: GroupStrategy) -> Vec<usize> {
        let len = self.members.len();
        let mut indices = (0..len).collect::<Vec<_>>();
        match strategy {
            GroupStrategy::RoundRobin => {
                let start = self.state.cursor.fetch_add(1, Ordering::Relaxed) as usize % len;
                indices.rotate_left(start);
            }
            GroupStrategy::Random => indices.shuffle(&mut rand::thread_rng()),
            GroupStrategy::Adaptive
            | GroupStrategy::Parallel
            | GroupStrategy::Fastest
            | GroupStrategy::All => {
                let weights = self.selection_weights();
                let mut rng = rand::thread_rng();
                let mut remaining = indices;
                indices = Vec::with_capacity(len);
                let mut remaining_weights = weights;
                while !remaining.is_empty() {
                    let selected = WeightedIndex::new(&remaining_weights)
                        .map(|dist| dist.sample(&mut rng))
                        .unwrap_or(0);
                    indices.push(remaining.remove(selected));
                    remaining_weights.remove(selected);
                }
            }
            GroupStrategy::Sequential | GroupStrategy::Fallback => {}
        }
        indices
    }

    fn selection_weights(&self) -> Vec<f64> {
        self.state
            .stats
            .lock()
            .iter()
            .copied()
            .map(RawMemberStats::weight)
            .collect()
    }

    fn record_result(&self, index: usize, elapsed: Duration, success: bool) {
        let mut stats = self.state.stats.lock();
        if let Some(stat) = stats.get_mut(index) {
            stat.record(if success { elapsed } else { self.timeout }, success);
        }
    }

    async fn query_ip_member(
        &self,
        index: usize,
        host: &str,
        want_v6: bool,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let upstream = &self.members[index];
        let started = Instant::now();
        let query = if want_v6 {
            upstream.query_aaaa(host)
        } else {
            upstream.query_a(host)
        };
        let result = match timeout(self.timeout, query).await {
            Ok(Ok(values)) if !values.is_empty() => Ok(values),
            Ok(Ok(_)) => Err(DnsError::Empty),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(DnsError::Timeout),
        };
        self.record_result(index, started.elapsed(), result.is_ok());
        result
    }

    async fn query_record_member(
        &self,
        index: usize,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        let started = Instant::now();
        let result = match timeout(
            self.timeout,
            self.members[index].query_records(host, record_type),
        )
        .await
        {
            Ok(Ok(values)) if !values.is_empty() => Ok(values),
            Ok(Ok(_)) => Err(DnsError::Empty),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(DnsError::Timeout),
        };
        self.record_result(index, started.elapsed(), result.is_ok());
        result
    }

    async fn run_sequential(
        &self,
        host: &str,
        want_v6: bool,
        strategy: GroupStrategy,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut last_error = DnsError::Empty;
        for index in self.ordered_indices(strategy) {
            match self.query_ip_member(index, host, want_v6).await {
                Ok(values) => return Ok(values),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn run_sequential_records(
        &self,
        host: &str,
        record_type: RecordType,
        strategy: GroupStrategy,
    ) -> Result<Vec<Record>, DnsError> {
        let mut last_error = DnsError::Empty;
        for index in self.ordered_indices(strategy) {
            match self.query_record_member(index, host, record_type).await {
                Ok(values) => return Ok(values),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn run_parallel(
        &self,
        host: &str,
        want_v6: bool,
        collect_all: bool,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let indices = self.ordered_indices(GroupStrategy::Adaptive);
        let mut pending = stream::iter(indices)
            .map(|index| async move { self.query_ip_member(index, host, want_v6).await })
            .buffer_unordered(self.max_parallel.min(self.members.len()).max(1));
        let mut answers = HashSet::new();
        let mut last_error = DnsError::Empty;
        while let Some(result) = pending.next().await {
            match result {
                Ok(values) if !collect_all => return Ok(values),
                Ok(values) => answers.extend(values),
                Err(error) => last_error = error,
            }
        }
        if answers.is_empty() {
            Err(last_error)
        } else {
            Ok(answers.into_iter().collect())
        }
    }

    async fn run_parallel_records(
        &self,
        host: &str,
        record_type: RecordType,
        collect_all: bool,
    ) -> Result<Vec<Record>, DnsError> {
        let indices = self.ordered_indices(GroupStrategy::Adaptive);
        let mut pending = stream::iter(indices)
            .map(|index| async move { self.query_record_member(index, host, record_type).await })
            .buffer_unordered(self.max_parallel.min(self.members.len()).max(1));
        let mut answers = Vec::new();
        let mut last_error = DnsError::Empty;
        while let Some(result) = pending.next().await {
            match result {
                Ok(values) if !collect_all => return Ok(values),
                Ok(values) => answers.extend(values),
                Err(error) => last_error = error,
            }
        }
        if answers.is_empty() {
            Err(last_error)
        } else {
            Ok(answers)
        }
    }
}

#[async_trait]
impl DnsUpstream for DnsGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "group"
    }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve(host, false).await
    }

    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve(host, true).await
    }

    async fn query_records(
        &self,
        host: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, DnsError> {
        self.resolve_records(host, record_type).await
    }

    async fn reset_connections(&self) {
        DnsGroup::reset_connections(self).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[derive(Debug)]
    struct StaticUpstream {
        name: String,
        delay_ms: u64,
        result: Result<Vec<IpAddr>, DnsError>,
        calls: AtomicU32,
    }

    impl StaticUpstream {
        fn new(name: &str, delay_ms: u64, result: Result<Vec<IpAddr>, DnsError>) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
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
            "test"
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
    async fn parallel_returns_first_success() {
        let slow = StaticUpstream::new("slow", 80, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let fast = StaticUpstream::new("fast", 5, Ok(vec!["2.2.2.2".parse().unwrap()]));
        let group = DnsGroup::new(
            "g",
            GroupStrategy::Parallel,
            vec![slow.clone(), fast.clone()],
        );

        assert_eq!(
            group.resolve("example.test", false).await.unwrap(),
            vec!["2.2.2.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn round_robin_rotates_and_fails_over() {
        let first = StaticUpstream::new("first", 0, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let second = StaticUpstream::new("second", 0, Ok(vec!["2.2.2.2".parse().unwrap()]));
        let group = DnsGroup::new(
            "g",
            GroupStrategy::RoundRobin,
            vec![first.clone(), second.clone()],
        );

        let one = group.resolve("example.test", false).await.unwrap();
        let two = group.resolve("example.test", false).await.unwrap();
        assert_ne!(one, two);
        assert_eq!(first.calls.load(Ordering::Relaxed), 1);
        assert_eq!(second.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn per_query_strategy_overrides_group_strategy() {
        let first = StaticUpstream::new("first", 0, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let second = StaticUpstream::new("second", 0, Ok(vec!["2.2.2.2".parse().unwrap()]));
        let group = DnsGroup::new(
            "g",
            GroupStrategy::RoundRobin,
            vec![first.clone(), second.clone()],
        );

        for _ in 0..2 {
            let answer = group
                .resolve_with_strategy("example.test", false, Some(GroupStrategy::Sequential))
                .await
                .unwrap();
            assert_eq!(answer, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        }
        assert_eq!(first.calls.load(Ordering::Relaxed), 2);
        assert_eq!(second.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn all_unions_results_and_learns_rtt() {
        let slow = StaticUpstream::new("slow", 30, Ok(vec!["1.1.1.1".parse().unwrap()]));
        let fast = StaticUpstream::new("fast", 2, Ok(vec!["2.2.2.2".parse().unwrap()]));
        let group = DnsGroup::new("g", GroupStrategy::All, vec![slow.clone(), fast.clone()]);

        let mut values = group.resolve("example.test", false).await.unwrap();
        values.sort();
        assert_eq!(values.len(), 2);
        let stats = group.member_stats();
        assert_eq!(stats[0].requests, 1);
        assert_eq!(stats[1].requests, 1);
        assert!(stats[1].average_rtt < stats[0].average_rtt);
        assert!(group.selection_weights()[1] > group.selection_weights()[0]);
    }

    #[tokio::test]
    async fn nested_groups_do_not_expand_parallelism() {
        let cf = (0..5)
            .map(|index| {
                StaticUpstream::new(
                    &format!("cf-{index}"),
                    0,
                    Ok(vec!["1.1.1.1".parse().unwrap()]),
                )
            })
            .collect::<Vec<_>>();
        let google = (0..5)
            .map(|index| {
                StaticUpstream::new(
                    &format!("google-{index}"),
                    0,
                    Ok(vec!["8.8.8.8".parse().unwrap()]),
                )
            })
            .collect::<Vec<_>>();
        let cf_group = Arc::new(DnsGroup::new(
            "cf",
            GroupStrategy::Random,
            cf.iter().cloned().map(|up| up as _).collect(),
        ));
        let google_group = Arc::new(DnsGroup::new(
            "google",
            GroupStrategy::Random,
            google.iter().cloned().map(|up| up as _).collect(),
        ));
        let root = DnsGroup::new(
            "public",
            GroupStrategy::Parallel,
            vec![cf_group as _, google_group as _],
        );

        root.resolve("example.test", false).await.unwrap();
        let calls = cf
            .iter()
            .chain(&google)
            .map(|up| up.calls.load(Ordering::Relaxed))
            .sum::<u32>();
        assert_eq!(calls, 2);
    }
}
