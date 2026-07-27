//! Xray XHTTP XMUX 连接生命周期管理。
//!
//! 六个官方字段分别控制并发、连接数量、连接被选用次数、HTTP 请求数、
//! 可复用时长以及底层连接 keep-alive。这里管理的连接是独立 HTTP
//! transport/connection group，不是仅用于统计的标签。

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rand::Rng;
use tokio::sync::{Mutex as AsyncMutex, Notify};

/// 每个新 XMUX connection entry 都要重新采样的 Xray `[from, to)` 区间。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XmuxSampleRange {
    pub min: i64,
    pub max: i64,
}

impl XmuxSampleRange {
    pub const fn fixed(value: i64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn sample(self) -> i64 {
        if self.min == self.max {
            self.min
        } else {
            rand::thread_rng().gen_range(self.min..self.max)
        }
    }
}

/// XMUX 六字段归一化后的值/采样器。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XmuxLimits {
    pub max_concurrency: i64,
    pub max_connections: i64,
    pub c_max_reuse_times: XmuxSampleRange,
    pub h_max_request_times: XmuxSampleRange,
    pub h_max_reusable_secs: XmuxSampleRange,
    pub h_keep_alive_period: i64,
}

/// 可由 XMUX 管理的实际 HTTP connection group。
pub trait ManagedConnection: Send + Sync + 'static {
    fn is_closed(&self) -> bool;
    fn close(&self);
}

type FactoryFuture<C> = Pin<Box<dyn Future<Output = io::Result<Arc<C>>> + Send>>;
type ConnectionFactory<C> = dyn Fn() -> FactoryFuture<C> + Send + Sync;

struct Entry<C: ManagedConnection> {
    connection: Arc<C>,
    running: AtomicI64,
    left_usage: AtomicI64,
    left_requests: AtomicI64,
    unreusable_at: Option<Instant>,
    retired: AtomicBool,
}

impl<C: ManagedConnection> Entry<C> {
    fn stale(&self, now: Instant) -> bool {
        self.connection.is_closed()
            || self.left_usage.load(Ordering::Acquire) == 0
            || self.left_requests.load(Ordering::Acquire) == 0
            || self.unreusable_at.is_some_and(|deadline| now >= deadline)
    }

    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.close_if_idle();
    }

    /// 当前 lease 能否继续发送请求。`left_usage` 只限制后续 lease 选择，
    /// 不能让刚取得的最后一次 lease 立即失效。
    fn request_stale(&self, now: Instant) -> bool {
        self.connection.is_closed()
            || self.left_requests.load(Ordering::Acquire) == 0
            || self.unreusable_at.is_some_and(|deadline| now >= deadline)
    }

    fn close_if_idle(&self) {
        if self.retired.load(Ordering::Acquire) && self.running.load(Ordering::Acquire) <= 0 {
            self.connection.close();
        }
    }

    fn consume_request(&self) -> bool {
        loop {
            let current = self.left_requests.load(Ordering::Acquire);
            if current == i64::MAX {
                return true;
            }
            if current <= 0 {
                return false;
            }
            if self
                .left_requests
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// 一个正在使用的 XMUX connection lease。
pub struct XmuxLease<C: ManagedConnection> {
    entry: Arc<Entry<C>>,
    available: Arc<Notify>,
}

impl<C: ManagedConnection> XmuxLease<C> {
    pub fn connection(&self) -> &Arc<C> {
        &self.entry.connection
    }

    /// 为即将发出的 HTTP 请求扣减配额。返回 false 时调用方必须轮换 lease。
    pub fn consume_request(&self) -> bool {
        if self.entry.request_stale(Instant::now()) {
            return false;
        }
        self.entry.consume_request()
    }

    pub fn is_reusable(&self) -> bool {
        !self.entry.request_stale(Instant::now())
    }
}

impl<C: ManagedConnection> Drop for XmuxLease<C> {
    fn drop(&mut self) {
        self.entry.running.fetch_sub(1, Ordering::AcqRel);
        self.entry.close_if_idle();
        self.available.notify_waiters();
    }
}

/// A connection-factory slot reserved while holding the pool state lock.
///
/// Releasing the slot in `Drop` is essential: cancellation during DNS, TCP,
/// TLS, or QUIC setup must not permanently consume `maxConnections`.
struct CreationReservation {
    creating: Arc<AtomicUsize>,
    available: Arc<Notify>,
}

impl Drop for CreationReservation {
    fn drop(&mut self) {
        let previous = self.creating.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "XMUX creation reservation underflow");
        self.available.notify_waiters();
    }
}

/// 并发安全的 XMUX connection pool。
pub struct XmuxManager<C: ManagedConnection> {
    limits: XmuxLimits,
    factory: Arc<ConnectionFactory<C>>,
    entries: AsyncMutex<Vec<Arc<Entry<C>>>>,
    creating: Arc<AtomicUsize>,
    available: Arc<Notify>,
}

impl<C: ManagedConnection> XmuxManager<C> {
    pub fn new<F, Fut>(limits: XmuxLimits, factory: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<Arc<C>>> + Send + 'static,
    {
        Self {
            limits,
            factory: Arc::new(move || Box::pin(factory())),
            entries: AsyncMutex::new(Vec::new()),
            creating: Arc::new(AtomicUsize::new(0)),
            available: Arc::new(Notify::new()),
        }
    }

    pub fn limits(&self) -> XmuxLimits {
        self.limits
    }

    pub async fn acquire(&self) -> io::Result<XmuxLease<C>> {
        loop {
            // Create the waiter before observing state so a release between the
            // observation and `.await` cannot be missed.
            let available = self.available.notified();
            tokio::pin!(available);
            available.as_mut().enable();

            let now = Instant::now();
            let mut entries = self.entries.lock().await;
            entries.retain(|entry| {
                if entry.stale(now) {
                    entry.retire();
                    false
                } else {
                    true
                }
            });

            let creating = self.creating.load(Ordering::Acquire);
            let total = entries.len().saturating_add(creating);
            let below_connection_limit =
                self.limits.max_connections <= 0 || total < self.limits.max_connections as usize;
            // Without an explicit connection-count target, preserve the
            // historical one-at-a-time factory behavior. Waiters can reuse the
            // connection that is currently being created before deciding
            // whether maxConcurrency requires another one.
            let may_create_without_connection_limit = creating == 0;
            let may_create = below_connection_limit
                && (self.limits.max_connections > 0 || may_create_without_connection_limit);
            let create_for_connection_limit =
                self.limits.max_connections > 0 && total < self.limits.max_connections as usize;

            if (entries.is_empty() || create_for_connection_limit) && may_create {
                let reservation = self.reserve_creation();
                drop(entries);
                return self.create_reserved(reservation).await;
            }

            let candidates = entries
                .iter()
                .filter(|entry| {
                    self.limits.max_concurrency <= 0
                        || entry.running.load(Ordering::Acquire) < self.limits.max_concurrency
                })
                .cloned()
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                let selected =
                    candidates[rand::thread_rng().gen_range(0..candidates.len())].clone();
                decrement_if_positive(&selected.left_usage);
                selected.running.fetch_add(1, Ordering::AcqRel);
                return Ok(XmuxLease {
                    entry: selected,
                    available: Arc::clone(&self.available),
                });
            }

            if may_create {
                let reservation = self.reserve_creation();
                drop(entries);
                return self.create_reserved(reservation).await;
            }

            drop(entries);
            available.await;
        }
    }

    fn reserve_creation(&self) -> CreationReservation {
        self.creating.fetch_add(1, Ordering::AcqRel);
        CreationReservation {
            creating: Arc::clone(&self.creating),
            available: Arc::clone(&self.available),
        }
    }

    async fn create_reserved(&self, _reservation: CreationReservation) -> io::Result<XmuxLease<C>> {
        // Network setup must never hold `entries`: one stalled factory cannot
        // prevent another reserved connection from progressing.
        let connection = (self.factory)().await?;
        // 与 Xray 一致：后三个范围不是 manager 级固定值，而是每个新
        // XmuxClient 独立采样。
        let reuse_times = self.limits.c_max_reuse_times.sample();
        let request_times = self.limits.h_max_request_times.sample();
        let reusable_secs = self.limits.h_max_reusable_secs.sample();
        let entry = Arc::new(Entry {
            connection,
            running: AtomicI64::new(1),
            // 第一次使用就是本次返回的 lease。
            left_usage: AtomicI64::new(if reuse_times > 0 { reuse_times - 1 } else { -1 }),
            left_requests: AtomicI64::new(if request_times > 0 {
                request_times
            } else {
                i64::MAX
            }),
            unreusable_at: (reusable_secs > 0)
                .then(|| Instant::now() + Duration::from_secs(reusable_secs as u64)),
            retired: AtomicBool::new(false),
        });
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|current| {
            if current.stale(now) {
                current.retire();
                false
            } else {
                true
            }
        });
        entries.push(entry.clone());
        Ok(XmuxLease {
            entry,
            available: Arc::clone(&self.available),
        })
    }
}

fn decrement_if_positive(value: &AtomicI64) {
    let _ = value.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (current > 0).then_some(current - 1)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct FakeConnection {
        closed: AtomicBool,
        close_count: Mutex<u32>,
    }

    impl ManagedConnection for FakeConnection {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Acquire)
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
            *self.close_count.lock() += 1;
        }
    }

    #[tokio::test]
    async fn pending_factory_does_not_hold_entries_lock() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first_started = Arc::new(Notify::new());
        let second_started = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let manager = Arc::new(XmuxManager::new(
            XmuxLimits {
                max_connections: 2,
                ..Default::default()
            },
            {
                let calls = calls.clone();
                let first_started = first_started.clone();
                let second_started = second_started.clone();
                let release_first = release_first.clone();
                move || {
                    let call = calls.fetch_add(1, Ordering::AcqRel);
                    let first_started = first_started.clone();
                    let second_started = second_started.clone();
                    let release_first = release_first.clone();
                    async move {
                        if call == 0 {
                            first_started.notify_one();
                            release_first.notified().await;
                        } else {
                            second_started.notify_one();
                        }
                        Ok(Arc::new(FakeConnection::default()))
                    }
                }
            },
        ));

        let first = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.acquire().await })
        };
        first_started.notified().await;

        let second = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.acquire().await })
        };
        tokio::time::timeout(Duration::from_secs(1), second_started.notified())
            .await
            .expect("second factory was blocked behind the first");
        let second_lease = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second acquire did not complete")
            .expect("second acquire task panicked")
            .expect("second acquire failed");

        release_first.notify_one();
        let first_lease = first.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert!(!Arc::ptr_eq(
            first_lease.connection(),
            second_lease.connection()
        ));
        drop((first_lease, second_lease));
        assert_eq!(manager.creating.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn cancelling_factory_releases_connection_slot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first_started = Arc::new(Notify::new());
        let second_task_started = Arc::new(Notify::new());
        let manager = Arc::new(XmuxManager::new(
            XmuxLimits {
                max_connections: 1,
                ..Default::default()
            },
            {
                let calls = calls.clone();
                let first_started = first_started.clone();
                move || {
                    let call = calls.fetch_add(1, Ordering::AcqRel);
                    let first_started = first_started.clone();
                    async move {
                        if call == 0 {
                            first_started.notify_one();
                            std::future::pending::<()>().await;
                        }
                        Ok(Arc::new(FakeConnection::default()))
                    }
                }
            },
        ));

        let first = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.acquire().await })
        };
        first_started.notified().await;
        let second = {
            let manager = manager.clone();
            let second_task_started = second_task_started.clone();
            tokio::spawn(async move {
                second_task_started.notify_one();
                manager.acquire().await
            })
        };
        second_task_started.notified().await;
        tokio::task::yield_now().await;
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "maxConnections slot was not enforced"
        );

        first.abort();
        let join_error = match first.await {
            Ok(_) => panic!("cancelled acquire unexpectedly completed"),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled());
        let second_lease = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("cancelled factory did not release its slot")
            .expect("second acquire task panicked")
            .expect("second acquire failed");
        assert_eq!(calls.load(Ordering::Acquire), 2);
        drop(second_lease);
        assert_eq!(manager.creating.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn factory_error_releases_connection_slot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let manager = XmuxManager::new(
            XmuxLimits {
                max_connections: 1,
                ..Default::default()
            },
            {
                let calls = calls.clone();
                move || {
                    let call = calls.fetch_add(1, Ordering::AcqRel);
                    async move {
                        if call == 0 {
                            Err(io::Error::other("expected factory failure"))
                        } else {
                            Ok(Arc::new(FakeConnection::default()))
                        }
                    }
                }
            },
        );

        let error = match manager.acquire().await {
            Ok(_) => panic!("factory failure unexpectedly acquired"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "expected factory failure");
        assert_eq!(manager.creating.load(Ordering::Acquire), 0);
        let lease = manager.acquire().await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
        drop(lease);
        assert_eq!(manager.creating.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn max_concurrency_creates_another_connection() {
        let created = Arc::new(AtomicI64::new(0));
        let counter = created.clone();
        let manager = XmuxManager::new(
            XmuxLimits {
                max_concurrency: 1,
                ..Default::default()
            },
            move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::AcqRel);
                    Ok(Arc::new(FakeConnection::default()))
                }
            },
        );
        let first = manager.acquire().await.unwrap();
        let second = manager.acquire().await.unwrap();
        assert_eq!(created.load(Ordering::Acquire), 2);
        assert!(!Arc::ptr_eq(first.connection(), second.connection()));
    }

    #[tokio::test]
    async fn request_limit_retires_connection_after_exact_count() {
        let created = Arc::new(AtomicI64::new(0));
        let counter = created.clone();
        let manager = XmuxManager::new(
            XmuxLimits {
                h_max_request_times: XmuxSampleRange::fixed(2),
                ..Default::default()
            },
            move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::AcqRel);
                    Ok(Arc::new(FakeConnection::default()))
                }
            },
        );
        let first = manager.acquire().await.unwrap();
        assert!(first.consume_request());
        assert!(first.consume_request());
        assert!(!first.consume_request());
        drop(first);
        let _second = manager.acquire().await.unwrap();
        assert_eq!(created.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn reuse_times_and_idle_close_are_enforced() {
        let manager = XmuxManager::new(
            XmuxLimits {
                c_max_reuse_times: XmuxSampleRange::fixed(1),
                ..Default::default()
            },
            || async { Ok(Arc::new(FakeConnection::default())) },
        );
        let first = manager.acquire().await.unwrap();
        let connection = first.connection().clone();
        assert!(first.consume_request());
        drop(first);
        let _replacement = manager.acquire().await.unwrap();
        assert!(connection.is_closed());
        assert_eq!(*connection.close_count.lock(), 1);
    }

    #[tokio::test]
    async fn fixed_lifecycle_ranges_are_sampled_for_each_new_entry() {
        let manager = XmuxManager::new(
            XmuxLimits {
                max_concurrency: 1,
                c_max_reuse_times: XmuxSampleRange::fixed(3),
                h_max_request_times: XmuxSampleRange::fixed(5),
                h_max_reusable_secs: XmuxSampleRange::fixed(30),
                ..Default::default()
            },
            || async { Ok(Arc::new(FakeConnection::default())) },
        );

        let first = manager.acquire().await.unwrap();
        let second = manager.acquire().await.unwrap();
        for lease in [&first, &second] {
            assert_eq!(lease.entry.left_usage.load(Ordering::Acquire), 2);
            assert_eq!(lease.entry.left_requests.load(Ordering::Acquire), 5);
            let remaining = lease
                .entry
                .unreusable_at
                .unwrap()
                .saturating_duration_since(Instant::now());
            assert!(remaining > Duration::from_secs(29));
            assert!(remaining <= Duration::from_secs(30));
        }
    }

    #[tokio::test]
    async fn random_lifecycle_samples_stay_inside_each_configured_range() {
        let manager = XmuxManager::new(
            XmuxLimits {
                max_concurrency: 1,
                c_max_reuse_times: XmuxSampleRange { min: 2, max: 4 },
                h_max_request_times: XmuxSampleRange { min: 5, max: 7 },
                h_max_reusable_secs: XmuxSampleRange { min: 10, max: 12 },
                ..Default::default()
            },
            || async { Ok(Arc::new(FakeConnection::default())) },
        );

        let mut leases = Vec::new();
        for _ in 0..12 {
            let lease = manager.acquire().await.unwrap();
            assert!((1..=2).contains(&lease.entry.left_usage.load(Ordering::Acquire)));
            assert!((5..=6).contains(&lease.entry.left_requests.load(Ordering::Acquire)));
            let remaining = lease
                .entry
                .unreusable_at
                .unwrap()
                .saturating_duration_since(Instant::now());
            assert!(remaining > Duration::from_secs(9));
            assert!(remaining <= Duration::from_secs(11));
            leases.push(lease);
        }
    }
}
