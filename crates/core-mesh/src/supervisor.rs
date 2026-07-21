//! Transactional mesh backend supervision.
//!
//! Backend futures are untrusted external boundaries. Every invocation is
//! cancellation-aware and deadline-bounded, while the global lifecycle mutex
//! is held only for short state transitions.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    sync::{Mutex, MutexGuard, watch},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;

use crate::{
    backend::{BackendError, BackendResult},
    conflict::{ResourceConflict, detect_conflicts},
    model::{
        Attachment, BackendId, BackendKind, BackendOwnership, BackendPhase, BackendStatus,
        ClaimMode, Diagnostic, DiagnosticLevel, EndpointAddress, EndpointPurpose,
        HostResourceClaim, IngressProtocol, MeshSnapshot, MeshSupervisorPhase, OwnedResourceClaim,
        ResourceClaim, ResourceOwner, SocketTransport, SystemResource,
    },
    registry::{BackendRegistry, RegisteredBackend, RegisteredBackendRef},
};

type OperationResult = Result<MeshSnapshot, MeshError>;

const MAX_DIAGNOSTICS_PER_SCOPE: usize = 64;
const MAX_DIAGNOSTIC_CODE_BYTES: usize = 128;
const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 1024;

// Observations cross an untrusted provider boundary before conflict detection.
// These private limits keep that boundary cheap enough for an in-process
// supervisor while still allowing a large real-world mesh inventory. They are
// intentionally private until concrete adapters establish a compatibility
// reason to make them part of the public API.
const MAX_ATTACHMENTS_PER_OBSERVATION: usize = 128;
const MAX_RESOURCE_CLAIMS_PER_OBSERVATION: usize = 128;
const MAX_CAPABILITIES_PER_OBSERVATION: usize = 64;
const MAX_COLLECTION_ITEMS_PER_OBSERVATION: usize = 1024;
const MAX_PROVIDER_STRING_BYTES: usize = 4096;
const MAX_PROVIDER_STRING_BYTES_PER_OBSERVATION: usize = 64 * 1024;
const INVALID_OBSERVATION_MESSAGE: &str = "backend observation exceeded safety limits";

#[derive(Default)]
struct ObservationBudget {
    collection_items: usize,
    string_bytes: usize,
}

impl ObservationBudget {
    fn add_collection(&mut self, items: usize) -> Result<(), &'static str> {
        self.collection_items = self
            .collection_items
            .checked_add(items)
            .ok_or(INVALID_OBSERVATION_MESSAGE)?;
        if self.collection_items > MAX_COLLECTION_ITEMS_PER_OBSERVATION {
            return Err(INVALID_OBSERVATION_MESSAGE);
        }
        Ok(())
    }

    fn add_string(&mut self, value: &str) -> Result<(), &'static str> {
        self.add_string_with_limit(value, MAX_PROVIDER_STRING_BYTES)
    }

    fn add_string_with_limit(
        &mut self,
        value: &str,
        individual_limit: usize,
    ) -> Result<(), &'static str> {
        if value.len() > individual_limit {
            return Err(INVALID_OBSERVATION_MESSAGE);
        }
        self.string_bytes = self
            .string_bytes
            .checked_add(value.len())
            .ok_or(INVALID_OBSERVATION_MESSAGE)?;
        if self.string_bytes > MAX_PROVIDER_STRING_BYTES_PER_OBSERVATION {
            return Err(INVALID_OBSERVATION_MESSAGE);
        }
        Ok(())
    }
}

/// One safe, API-visible backend failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFailure {
    pub backend: BackendId,
    pub operation: &'static str,
    pub code: String,
    pub message: String,
}

impl BackendFailure {
    fn from_backend(backend: BackendId, operation: &'static str, error: &BackendError) -> Self {
        Self {
            backend,
            operation,
            code: error.code().to_owned(),
            message: error.public_message().to_owned(),
        }
    }

    fn safe(
        backend: BackendId,
        operation: &'static str,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let error = BackendError::new(code, message);
        Self::from_backend(backend, operation, &error)
    }

    fn diagnostic(&self) -> Diagnostic {
        Diagnostic::new(
            DiagnosticLevel::Error,
            format!(
                "mesh.backend.{}.{}",
                self.operation,
                self.code.replace(':', ".")
            ),
            format!(
                "backend `{}` {} failed: {}",
                self.backend, self.operation, self.message
            ),
        )
    }
}

/// Transactional supervisor error.
///
/// `Display` and `Debug` are safe renderings. Structured conflict claims are
/// internal data and must be projected through `PublicResourceConflict`
/// before crossing an API boundary.
#[derive(Clone, Error)]
pub enum MeshError {
    #[error("mesh backend probe failed: {failures:?}")]
    Probe { failures: Vec<BackendFailure> },

    #[error("mesh backend status refresh failed: {failures:?}")]
    Status { failures: Vec<BackendFailure> },

    #[error("mesh resource conflicts prevent reconciliation")]
    Conflicts { conflicts: Vec<ResourceConflict> },

    #[error(
        "mesh backend reconciliation failed: {failure:?}; rollback failures: {rollback_failures:?}"
    )]
    Reconcile {
        failure: BackendFailure,
        rollback_failures: Vec<BackendFailure>,
    },

    #[error("mesh shutdown failed: {failures:?}")]
    Stop { failures: Vec<BackendFailure> },

    #[error("mesh still has resources requiring shutdown: {backends:?}")]
    ResidualResources { backends: Vec<BackendId> },

    #[error("mesh lifecycle worker ended before publishing a result")]
    OperationLost,

    #[error(
        "mesh lifecycle worker failed internally: {failure:?}; cleanup failures: {cleanup_failures:?}"
    )]
    Internal {
        failure: BackendFailure,
        cleanup_failures: Vec<BackendFailure>,
    },
}

impl fmt::Debug for MeshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe { failures } => formatter
                .debug_struct("MeshError::Probe")
                .field("failures", failures)
                .finish(),
            Self::Status { failures } => formatter
                .debug_struct("MeshError::Status")
                .field("failures", failures)
                .finish(),
            Self::Conflicts { conflicts } => formatter
                .debug_struct("MeshError::Conflicts")
                .field("count", &conflicts.len())
                .finish(),
            Self::Reconcile {
                failure,
                rollback_failures,
            } => formatter
                .debug_struct("MeshError::Reconcile")
                .field("failure", failure)
                .field("rollback_failures", rollback_failures)
                .finish(),
            Self::Stop { failures } => formatter
                .debug_struct("MeshError::Stop")
                .field("failures", failures)
                .finish(),
            Self::ResidualResources { backends } => formatter
                .debug_struct("MeshError::ResidualResources")
                .field("backends", backends)
                .finish(),
            Self::OperationLost => formatter.write_str("MeshError::OperationLost"),
            Self::Internal {
                failure,
                cleanup_failures,
            } => formatter
                .debug_struct("MeshError::Internal")
                .field("failure", failure)
                .field("cleanup_failures", cleanup_failures)
                .finish(),
        }
    }
}

/// Operation-specific deadlines for untrusted backend adapters.
///
/// Reconciliation commonly includes daemon startup and readiness polling, so
/// it intentionally receives a much larger budget than status observation.
#[derive(Debug, Clone)]
pub struct BackendCallTimeouts {
    pub gate: Duration,
    pub probe: Duration,
    pub reconcile: Duration,
    pub status: Duration,
    pub release: Duration,
}

impl Default for BackendCallTimeouts {
    fn default() -> Self {
        Self {
            gate: Duration::from_secs(2),
            probe: Duration::from_secs(10),
            reconcile: Duration::from_secs(120),
            status: Duration::from_secs(5),
            release: Duration::from_secs(30),
        }
    }
}

impl BackendCallTimeouts {
    fn normalized(mut self) -> Self {
        for timeout in [
            &mut self.gate,
            &mut self.probe,
            &mut self.reconcile,
            &mut self.status,
            &mut self.release,
        ] {
            if timeout.is_zero() {
                *timeout = Duration::from_millis(1);
            }
        }
        self
    }
}

/// Time bounds for untrusted backend calls and dynamic claim monitoring.
#[derive(Debug, Clone)]
pub struct SupervisorOptions {
    pub backend_timeouts: BackendCallTimeouts,
    /// Zero disables background status monitoring.
    pub monitor_interval: Duration,
}

impl Default for SupervisorOptions {
    fn default() -> Self {
        Self {
            backend_timeouts: BackendCallTimeouts::default(),
            monitor_interval: Duration::from_secs(5),
        }
    }
}

impl SupervisorOptions {
    fn normalized(mut self) -> Self {
        self.backend_timeouts = self.backend_timeouts.normalized();
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Start,
    Stop,
}

struct ActiveOperation {
    id: u64,
    kind: OperationKind,
    cancel: CancellationToken,
    completion: watch::Sender<Option<OperationResult>>,
}

struct MonitorTask {
    cancel: CancellationToken,
    join: JoinHandle<()>,
}

#[derive(Default)]
struct LifecycleState {
    running: bool,
    /// Successfully reconciled or not-yet-released backends in registration
    /// order.
    started: Vec<BackendId>,
    /// Reconcile may already have acquired resources before returning.
    in_flight: Option<BackendId>,
    active: Option<ActiveOperation>,
    next_operation_id: u64,
    monitor: Option<MonitorTask>,
    /// Backends automatically isolated by fail-closed monitoring. This state
    /// remains latched until callers acknowledge it with a complete stop,
    /// followed by a fresh start.
    isolated: BTreeSet<BackendId>,
    /// Isolated backends whose detach/terminate operation has not yet
    /// completed successfully. The monitor retries these before trusting any
    /// later healthy status observation.
    pending_release: BTreeSet<BackendId>,
    isolation_conflicts: Vec<ResourceConflict>,
}

struct SupervisorInner {
    registry: BackendRegistry,
    reservations: Vec<OwnedResourceClaim>,
    options: SupervisorOptions,
    lifecycle: Mutex<LifecycleState>,
    maintenance: Mutex<()>,
    snapshots: watch::Sender<MeshSnapshot>,
    shutdown: CancellationToken,
}

/// Coordinates conflict-free startup, monitoring, isolation, and shutdown.
pub struct MeshSupervisor {
    inner: Arc<SupervisorInner>,
}

impl Drop for MeshSupervisor {
    fn drop(&mut self) {
        self.inner.shutdown.cancel();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = Arc::clone(&self.inner);
        // A runtime may begin shutting down between `try_current` and
        // `spawn`. Destructors must never propagate a runtime-state panic.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            runtime.spawn(async move {
                inner.emergency_shutdown().await;
            })
        }));
    }
}

impl MeshSupervisor {
    pub fn new(registry: BackendRegistry, reservations: Vec<HostResourceClaim>) -> Self {
        Self::with_options(registry, reservations, SupervisorOptions::default())
    }

    pub fn with_options(
        registry: BackendRegistry,
        reservations: Vec<HostResourceClaim>,
        options: SupervisorOptions,
    ) -> Self {
        let mut reservations: Vec<_> = reservations
            .into_iter()
            .map(HostResourceClaim::into_owned)
            .collect();
        reservations.sort();
        reservations.dedup();

        let mut snapshot = MeshSnapshot::new(0, MeshSupervisorPhase::Idle, false);
        snapshot.set_reservations(reservations.clone());
        for entry in registry.iter() {
            snapshot.insert_status(Self::empty_status(entry));
        }
        let (snapshots, _) = watch::channel(snapshot);

        Self {
            inner: Arc::new(SupervisorInner {
                registry,
                reservations,
                options: options.normalized(),
                lifecycle: Mutex::new(LifecycleState::default()),
                maintenance: Mutex::new(()),
                snapshots,
                shutdown: CancellationToken::new(),
            }),
        }
    }

    /// Return the latest immutable snapshot without awaiting a lock.
    pub fn snapshot(&self) -> MeshSnapshot {
        self.inner.snapshot()
    }

    pub fn subscribe(&self) -> watch::Receiver<MeshSnapshot> {
        self.inner.snapshots.subscribe()
    }

    /// Start in a detached transaction.
    ///
    /// Aborting the caller does not abort the transaction. A timed out or
    /// cancelled reconcile is followed by bounded reverse release, including
    /// the in-flight backend.
    pub async fn start(&self) -> OperationResult {
        loop {
            let mut launch = None;
            let (receiver, retry_after_wait) = {
                let mut lifecycle = self.inner.lifecycle.lock().await;
                if lifecycle.running {
                    return Ok(self.snapshot());
                }
                if let Some(active) = &lifecycle.active {
                    (
                        active.completion.subscribe(),
                        active.kind != OperationKind::Start,
                    )
                } else {
                    if !lifecycle.started.is_empty()
                        || !lifecycle.isolated.is_empty()
                        || !lifecycle.pending_release.is_empty()
                    {
                        let mut backends = lifecycle.started.clone();
                        backends.extend(lifecycle.isolated.iter().cloned());
                        backends.extend(lifecycle.pending_release.iter().cloned());
                        backends.sort();
                        backends.dedup();
                        return Err(MeshError::ResidualResources { backends });
                    }
                    let (id, cancel, completion, receiver) = self
                        .inner
                        .new_operation(&mut lifecycle, OperationKind::Start);
                    launch = Some((id, cancel, completion));
                    (receiver, false)
                }
            };

            if let Some((id, cancel, completion)) = launch {
                self.inner.spawn_start(id, cancel, completion);
            }
            let result = wait_for_operation(receiver).await;
            if retry_after_wait {
                continue;
            }
            return result;
        }
    }

    /// Stop in a detached transaction.
    ///
    /// If startup is active, stop cancels it without waiting for a global lock;
    /// the startup worker performs rollback, after which stop retries any
    /// release that failed.
    pub async fn stop(&self) -> OperationResult {
        loop {
            let mut launch = None;
            let (receiver, retry_after_wait) = {
                let mut lifecycle = self.inner.lifecycle.lock().await;
                if let Some(active) = &lifecycle.active {
                    if active.kind == OperationKind::Start {
                        active.cancel.cancel();
                    }
                    (
                        active.completion.subscribe(),
                        active.kind == OperationKind::Start,
                    )
                } else if !lifecycle.running
                    && lifecycle.started.is_empty()
                    && lifecycle.isolated.is_empty()
                    && lifecycle.pending_release.is_empty()
                {
                    return Ok(self.snapshot());
                } else {
                    let monitor = lifecycle.monitor.take();
                    if let Some(monitor) = &monitor {
                        monitor.cancel.cancel();
                    }
                    let (id, cancel, completion, receiver) = self
                        .inner
                        .new_operation(&mut lifecycle, OperationKind::Stop);
                    launch = Some((id, cancel, completion, monitor));
                    (receiver, false)
                }
            };

            if let Some((id, cancel, completion, monitor)) = launch {
                self.inner.spawn_stop(id, cancel, completion, monitor);
            }
            let result = wait_for_operation(receiver).await;
            if retry_after_wait {
                continue;
            }
            return result;
        }
    }

    /// Explicit observation-only refresh for internal callers.
    ///
    /// It is deadline-bounded and observation-only. Dynamic isolation is owned
    /// by the supervisor's background monitor, so an HTTP GET never terminates
    /// or detaches a backend.
    pub async fn refresh(&self) -> OperationResult {
        self.inner
            .refresh_once(false, self.inner.shutdown.child_token())
            .await
    }

    fn empty_status(entry: &RegisteredBackendRef) -> BackendStatus {
        let descriptor = entry.descriptor();
        BackendStatus::new(
            descriptor.id().clone(),
            descriptor.kind().clone(),
            descriptor.ownership(),
        )
    }
}

impl SupervisorInner {
    fn snapshot(&self) -> MeshSnapshot {
        self.snapshots.borrow().clone()
    }

    fn new_operation(
        &self,
        lifecycle: &mut LifecycleState,
        kind: OperationKind,
    ) -> (
        u64,
        CancellationToken,
        watch::Sender<Option<OperationResult>>,
        watch::Receiver<Option<OperationResult>>,
    ) {
        lifecycle.next_operation_id = lifecycle.next_operation_id.saturating_add(1);
        let id = lifecycle.next_operation_id;
        let cancel = self.shutdown.child_token();
        let (completion, receiver) = watch::channel(None);
        lifecycle.active = Some(ActiveOperation {
            id,
            kind,
            cancel: cancel.clone(),
            completion: completion.clone(),
        });
        (id, cancel, completion, receiver)
    }

    fn spawn_start(
        self: &Arc<Self>,
        id: u64,
        cancel: CancellationToken,
        completion: watch::Sender<Option<OperationResult>>,
    ) {
        let worker_inner = Arc::clone(self);
        let worker = tokio::spawn(async move { worker_inner.run_start(cancel).await });
        let coordinator = Arc::clone(self);
        tokio::spawn(async move {
            let result = match worker.await {
                Ok(result) => result,
                Err(_) => coordinator.recover_worker_panic(OperationKind::Start).await,
            };
            coordinator.finish_operation(id).await;
            completion.send_replace(Some(result));
        });
    }

    fn spawn_stop(
        self: &Arc<Self>,
        id: u64,
        cancel: CancellationToken,
        completion: watch::Sender<Option<OperationResult>>,
        monitor: Option<MonitorTask>,
    ) {
        let worker_inner = Arc::clone(self);
        let worker = tokio::spawn(async move { worker_inner.run_stop(cancel, monitor).await });
        let coordinator = Arc::clone(self);
        tokio::spawn(async move {
            let result = match worker.await {
                Ok(result) => result,
                Err(_) => coordinator.recover_worker_panic(OperationKind::Stop).await,
            };
            coordinator.finish_operation(id).await;
            completion.send_replace(Some(result));
        });
    }

    async fn finish_operation(&self, id: u64) {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle
            .active
            .as_ref()
            .is_some_and(|active| active.id == id)
        {
            lifecycle.active = None;
        }
    }

    /// Last-owner best-effort cleanup.
    ///
    /// Dropping the public supervisor first cancels an active transaction,
    /// waits for its own bounded rollback, and only then retries residual
    /// resources. This avoids racing a normal `stop` with a duplicate release.
    async fn emergency_shutdown(self: Arc<Self>) {
        self.shutdown.cancel();
        let (receiver, monitor) = {
            let mut lifecycle = self.lifecycle.lock().await;
            let monitor = lifecycle.monitor.take();
            if let Some(monitor) = &monitor {
                monitor.cancel.cancel();
            }
            (
                lifecycle.active.as_ref().map(|active| {
                    active.cancel.cancel();
                    active.completion.subscribe()
                }),
                monitor,
            )
        };
        Self::drain_monitor(monitor).await;
        if let Some(receiver) = receiver {
            let _ =
                time::timeout(self.emergency_drain_timeout(), wait_for_operation(receiver)).await;
        }

        // A cancelled monitor may already be inside a fail-closed release.
        // Waiting on the same maintenance boundary prevents duplicate
        // detach/terminate calls and stale lifecycle commits.
        let _maintenance = self.maintenance.lock().await;
        let targets = {
            let mut lifecycle = self.lifecycle.lock().await;
            let mut targets = lifecycle.started.clone();
            if let Some(in_flight) = lifecycle.in_flight.take()
                && !targets.contains(&in_flight)
            {
                targets.push(in_flight);
            }
            targets
        };
        if targets.is_empty() {
            return;
        }

        let mut working = self.snapshot();
        working.running = false;
        working.supervisor_phase = MeshSupervisorPhase::Stopping;
        for id in &targets {
            if let Some(status) = working.statuses.get_mut(id) {
                status.phase = BackendPhase::Stopping;
            }
        }
        self.publish(working.clone());

        let cleanup = CancellationToken::new();
        let outcome = self
            .release_targets(&targets, &cleanup, &mut working.statuses)
            .await;
        {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.started = retain_failed_order(&targets, &outcome.failed_ids);
            lifecycle.running = false;
            lifecycle.in_flight = None;
            lifecycle
                .pending_release
                .retain(|id| outcome.failed_ids.contains(id));
            if outcome.failures.is_empty() {
                lifecycle.isolated.clear();
                lifecycle.pending_release.clear();
                lifecycle.isolation_conflicts.clear();
            }
        }
        working.running = false;
        if outcome.failures.is_empty() {
            working.supervisor_phase = MeshSupervisorPhase::Stopped;
            working.conflicts.clear();
            working.diagnostics.clear();
            for status in working.statuses.values_mut() {
                status.phase = BackendPhase::Stopped;
                status.diagnostics.clear();
            }
        } else {
            working.supervisor_phase = MeshSupervisorPhase::Failed;
            working
                .diagnostics
                .extend(outcome.failures.iter().map(BackendFailure::diagnostic));
        }
        self.publish(working);
    }

    fn emergency_drain_timeout(&self) -> Duration {
        let backend_count =
            u32::try_from(self.registry.len().saturating_add(1)).unwrap_or(u32::MAX);
        self.options
            .backend_timeouts
            .gate
            .saturating_add(self.options.backend_timeouts.release)
            .saturating_mul(backend_count)
            .saturating_add(Duration::from_secs(1))
    }

    async fn recover_worker_panic(&self, kind: OperationKind) -> OperationResult {
        let operation = match kind {
            OperationKind::Start => "start",
            OperationKind::Stop => "stop",
        };
        let monitor = {
            let mut lifecycle = self.lifecycle.lock().await;
            let monitor = lifecycle.monitor.take();
            if let Some(monitor) = &monitor {
                monitor.cancel.cancel();
            }
            monitor
        };
        Self::drain_monitor(monitor).await;
        let _maintenance = self.maintenance.lock().await;
        let targets = {
            let mut lifecycle = self.lifecycle.lock().await;
            let mut targets = lifecycle.started.clone();
            if let Some(in_flight) = lifecycle.in_flight.take()
                && !targets.contains(&in_flight)
            {
                targets.push(in_flight);
            }
            lifecycle.running = false;
            targets
        };
        let failure = BackendFailure::safe(
            BackendId::new("mesh.supervisor").expect("static id"),
            operation,
            "internal_panic",
            "mesh lifecycle worker panicked",
        );
        let mut working = self.snapshot();
        let cleanup = CancellationToken::new();
        let outcome = self
            .release_targets(&targets, &cleanup, &mut working.statuses)
            .await;
        {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.started = retain_failed_order(&targets, &outcome.failed_ids);
            lifecycle.in_flight = None;
            lifecycle.running = false;
            lifecycle
                .pending_release
                .retain(|id| outcome.failed_ids.contains(id));
        }
        working.running = false;
        working.supervisor_phase = MeshSupervisorPhase::Failed;
        working.diagnostics.push(failure.diagnostic());
        working
            .diagnostics
            .extend(outcome.failures.iter().map(BackendFailure::diagnostic));
        self.publish(working);
        Err(MeshError::Internal {
            failure,
            cleanup_failures: outcome.failures,
        })
    }

    async fn run_start(self: &Arc<Self>, cancel: CancellationToken) -> OperationResult {
        {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.isolated.clear();
            lifecycle.pending_release.clear();
            lifecycle.isolation_conflicts.clear();
        }
        let mut working = self.snapshot();
        working.supervisor_phase = MeshSupervisorPhase::Starting;
        working.running = false;
        working.conflicts.clear();
        working.diagnostics.clear();
        working.set_reservations(self.reservations.clone());
        for entry in self.registry.iter() {
            let status = working
                .statuses
                .entry(entry.id().clone())
                .or_insert_with(|| MeshSupervisor::empty_status(entry));
            status.phase = BackendPhase::Probing;
        }
        self.publish(working.clone());

        let mut observations = Vec::with_capacity(self.registry.len());
        let mut probe_failures = Vec::new();
        for entry in self.registry.iter() {
            match self.call_probe(entry, &cancel).await {
                Ok(observation) => {
                    if let Err(message) = Self::validate_observation(entry, &observation) {
                        let failure = BackendFailure::safe(
                            entry.id().clone(),
                            "probe",
                            "invalid_status",
                            message,
                        );
                        let mut failed = MeshSupervisor::empty_status(entry);
                        failed.phase = BackendPhase::Failed;
                        failed.diagnostics.push(failure.diagnostic());
                        working.insert_status(failed);
                        probe_failures.push(failure);
                    } else {
                        working.insert_status(observation.clone());
                        observations.push((entry.clone(), observation));
                    }
                }
                Err(error) => {
                    let failure = BackendFailure::from_backend(entry.id().clone(), "probe", &error);
                    let mut failed = MeshSupervisor::empty_status(entry);
                    failed.phase = BackendPhase::Failed;
                    failed.diagnostics.push(failure.diagnostic());
                    working.insert_status(failed);
                    probe_failures.push(failure);
                    if cancel.is_cancelled() {
                        break;
                    }
                }
            }
        }

        if !probe_failures.is_empty() {
            {
                let mut lifecycle = self.lifecycle.lock().await;
                lifecycle.running = false;
                lifecycle.in_flight = None;
            }
            working.supervisor_phase = MeshSupervisorPhase::Failed;
            working
                .diagnostics
                .extend(probe_failures.iter().map(BackendFailure::diagnostic));
            self.publish(working);
            return Err(MeshError::Probe {
                failures: probe_failures,
            });
        }

        let conflicts = self.detect_observation_conflicts(&observations);
        if !conflicts.is_empty() {
            Self::mark_conflicts(&mut working, &conflicts, false);
            {
                let mut lifecycle = self.lifecycle.lock().await;
                lifecycle.running = false;
                lifecycle.in_flight = None;
            }
            self.publish(working);
            return Err(MeshError::Conflicts { conflicts });
        }

        for (entry, observation) in observations {
            {
                let mut lifecycle = self.lifecycle.lock().await;
                lifecycle.in_flight = Some(entry.id().clone());
            }
            let result = self
                .call_reconcile(&entry, &observation, &cancel)
                .await
                .and_then(|status| {
                    Self::validate_reconciled_status(&entry, &observation, &status)
                        .map_err(|message| BackendError::new("invalid_status", message))?;
                    Ok(status)
                });

            match result {
                Ok(status) => {
                    let mut lifecycle = self.lifecycle.lock().await;
                    lifecycle.in_flight = None;
                    lifecycle.started.push(entry.id().clone());
                    drop(lifecycle);
                    working.insert_status(status);
                }
                Err(error) => {
                    let failure =
                        BackendFailure::from_backend(entry.id().clone(), "reconcile", &error);
                    let mut failed = observation;
                    failed.phase = BackendPhase::Failed;
                    failed.diagnostics.push(failure.diagnostic());
                    working.insert_status(failed);

                    let rollback_targets = {
                        let mut lifecycle = self.lifecycle.lock().await;
                        let mut targets = lifecycle.started.clone();
                        if !targets.contains(entry.id()) {
                            targets.push(entry.id().clone());
                        }
                        lifecycle.in_flight = None;
                        targets
                    };
                    let cleanup = CancellationToken::new();
                    let outcome = self
                        .release_targets(&rollback_targets, &cleanup, &mut working.statuses)
                        .await;
                    {
                        let mut lifecycle = self.lifecycle.lock().await;
                        lifecycle.started =
                            retain_failed_order(&rollback_targets, &outcome.failed_ids);
                        lifecycle.running = false;
                    }
                    if let Some(status) = working.statuses.get_mut(entry.id()) {
                        status.phase = BackendPhase::Failed;
                    }
                    working.running = false;
                    working.supervisor_phase = MeshSupervisorPhase::Failed;
                    working.diagnostics.push(failure.diagnostic());
                    working
                        .diagnostics
                        .extend(outcome.failures.iter().map(BackendFailure::diagnostic));
                    self.publish(working);
                    return Err(MeshError::Reconcile {
                        failure,
                        rollback_failures: outcome.failures,
                    });
                }
            }
        }

        if cancel.is_cancelled() {
            let targets = {
                let lifecycle = self.lifecycle.lock().await;
                lifecycle.started.clone()
            };
            let failure = BackendFailure::safe(
                BackendId::new("mesh.supervisor").expect("static id"),
                "reconcile",
                "operation_cancelled",
                "startup was cancelled before commit",
            );
            let cleanup = CancellationToken::new();
            let outcome = self
                .release_targets(&targets, &cleanup, &mut working.statuses)
                .await;
            {
                let mut lifecycle = self.lifecycle.lock().await;
                lifecycle.started = retain_failed_order(&targets, &outcome.failed_ids);
                lifecycle.running = false;
            }
            working.running = false;
            working.supervisor_phase = MeshSupervisorPhase::Failed;
            working.diagnostics.push(failure.diagnostic());
            self.publish(working);
            return Err(MeshError::Reconcile {
                failure,
                rollback_failures: outcome.failures,
            });
        }

        let started = {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.running = true;
            lifecycle.in_flight = None;
            lifecycle.started.clone()
        };
        working.running = true;
        working.supervisor_phase = self.aggregate_phase(&started, &working.statuses);
        self.publish(working);
        self.install_monitor().await;
        Ok(self.snapshot())
    }

    async fn run_stop(
        &self,
        cancel: CancellationToken,
        monitor: Option<MonitorTask>,
    ) -> OperationResult {
        Self::drain_monitor(monitor).await;
        // `refresh_once` holds this boundary across observation, isolation,
        // and lifecycle commit. Stop must join that same serial order before
        // re-reading `started`, otherwise it can release a backend twice.
        let _maintenance = self.maintenance.lock().await;
        let targets = {
            let lifecycle = self.lifecycle.lock().await;
            lifecycle.started.clone()
        };
        let mut working = self.snapshot();
        working.supervisor_phase = MeshSupervisorPhase::Stopping;
        working.running = false;
        working.diagnostics.clear();
        for id in &targets {
            if let Some(status) = working.statuses.get_mut(id) {
                status.phase = BackendPhase::Stopping;
            }
        }
        self.publish(working.clone());

        let outcome = self
            .release_targets(&targets, &cancel, &mut working.statuses)
            .await;
        {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.started = retain_failed_order(&targets, &outcome.failed_ids);
            lifecycle.running = false;
            lifecycle.in_flight = None;
            lifecycle
                .pending_release
                .retain(|id| outcome.failed_ids.contains(id));
            if outcome.failures.is_empty() {
                lifecycle.isolated.clear();
                lifecycle.pending_release.clear();
                lifecycle.isolation_conflicts.clear();
            }
        }
        working.running = false;
        if outcome.failures.is_empty() {
            working.conflicts.clear();
            working.diagnostics.clear();
            for status in working.statuses.values_mut() {
                status.phase = BackendPhase::Stopped;
                status.diagnostics.clear();
            }
            working.supervisor_phase = MeshSupervisorPhase::Stopped;
            self.publish(working);
            Ok(self.snapshot())
        } else {
            working.supervisor_phase = MeshSupervisorPhase::Failed;
            working
                .diagnostics
                .extend(outcome.failures.iter().map(BackendFailure::diagnostic));
            self.publish(working);
            Err(MeshError::Stop {
                failures: outcome.failures,
            })
        }
    }

    async fn install_monitor(self: &Arc<Self>) {
        if self.options.monitor_interval.is_zero() {
            return;
        }
        let cancel = self.shutdown.child_token();
        let task_cancel = cancel.clone();
        let weak: Weak<Self> = Arc::downgrade(self);
        let interval_duration = self.options.monitor_interval;
        let join = tokio::spawn(async move {
            let mut interval = time::interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // `interval` ticks immediately; dynamic state cannot have changed
            // before the configured first interval.
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = task_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let Some(inner) = weak.upgrade() else {
                            break;
                        };
                        let _ = inner.refresh_once(true, task_cancel.clone()).await;
                    }
                }
            }
        });
        let previous = {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.monitor.replace(MonitorTask { cancel, join })
        };
        if let Some(previous) = previous {
            previous.cancel.cancel();
            Self::drain_monitor(Some(previous)).await;
        }
    }

    async fn drain_monitor(monitor: Option<MonitorTask>) {
        let Some(monitor) = monitor else {
            return;
        };
        // Do not render JoinError: a panic payload may contain adapter data.
        // The maintenance mutex is acquired after this call and remains the
        // authoritative proof that no monitor side effect is still running.
        let _ = monitor.join.await;
    }

    async fn refresh_once(
        &self,
        isolate_conflicts: bool,
        cancel: CancellationToken,
    ) -> OperationResult {
        let _maintenance = match self.acquire_maintenance(&cancel).await {
            Ok(guard) => guard,
            Err(error) => {
                return Err(MeshError::Status {
                    failures: vec![BackendFailure::from_backend(
                        BackendId::new("mesh.supervisor").expect("static id"),
                        "status",
                        &error,
                    )],
                });
            }
        };

        let (
            mut started,
            was_running,
            operation_active,
            isolated,
            pending_release,
            isolation_conflicts,
        ) = {
            let lifecycle = self.lifecycle.lock().await;
            (
                lifecycle.started.clone(),
                lifecycle.running,
                lifecycle.active.is_some(),
                lifecycle.isolated.clone(),
                lifecycle.pending_release.clone(),
                lifecycle.isolation_conflicts.clone(),
            )
        };
        if operation_active {
            return Ok(self.snapshot());
        }

        let mut working = self.snapshot();
        if isolated.is_empty() {
            working.conflicts.clear();
            working.diagnostics.clear();
        } else {
            working.conflicts = isolation_conflicts.clone();
        }

        // A failed fail-closed release remains a release obligation even if a
        // later status call looks healthy. Retry it before trusting or
        // publishing any new observation. Once release begins it uses a fresh
        // bounded cleanup token: cancelling the monitor asks it to stop after
        // the commit, rather than dropping an externally visible operation
        // half-way through and racing explicit `stop`.
        if isolate_conflicts && !pending_release.is_empty() {
            if cancel.is_cancelled() {
                return Ok(self.snapshot());
            }
            let targets: Vec<_> = started
                .iter()
                .filter(|id| pending_release.contains(*id))
                .cloned()
                .collect();
            let cleanup = CancellationToken::new();
            let outcome = self
                .release_targets(&targets, &cleanup, &mut working.statuses)
                .await;
            let released: BTreeSet<_> = targets
                .iter()
                .filter(|id| !outcome.failed_ids.contains(*id))
                .cloned()
                .collect();
            {
                let mut lifecycle = self.lifecycle.lock().await;
                lifecycle.started.retain(|id| !released.contains(id));
                lifecycle
                    .pending_release
                    .retain(|id| outcome.failed_ids.contains(id));
                lifecycle.running = false;
                started = lifecycle.started.clone();
            }
            for id in &targets {
                if let Some(status) = working.statuses.get_mut(id) {
                    status.phase = if outcome.failed_ids.contains(id) {
                        BackendPhase::Failed
                    } else {
                        BackendPhase::Stopped
                    };
                    push_diagnostic_unique(
                        &mut status.diagnostics,
                        Diagnostic::new(
                            if outcome.failed_ids.contains(id) {
                                DiagnosticLevel::Error
                            } else {
                                DiagnosticLevel::Warning
                            },
                            if outcome.failed_ids.contains(id) {
                                "mesh.fail_closed_release_retry_failed"
                            } else {
                                "mesh.fail_closed_release_retry_succeeded"
                            },
                            if outcome.failed_ids.contains(id) {
                                "fail-closed backend release retry failed"
                            } else {
                                "fail-closed backend release retry succeeded"
                            },
                        ),
                    );
                }
            }
            working.running = false;
            working.supervisor_phase = MeshSupervisorPhase::Degraded;
            working.conflicts = isolation_conflicts.clone();
            for failure in &outcome.failures {
                push_diagnostic_unique(&mut working.diagnostics, failure.diagnostic());
            }
            self.publish(working.clone());
            if !outcome.failures.is_empty() {
                return Err(MeshError::Status {
                    failures: outcome.failures,
                });
            }
            if started.is_empty() || cancel.is_cancelled() {
                return Ok(self.snapshot());
            }
        }

        if started.is_empty() {
            return Ok(self.snapshot());
        }

        let mut failures = Vec::new();
        for id in &started {
            let Some(entry) = self.registry.get(id) else {
                failures.push(BackendFailure::safe(
                    id.clone(),
                    "status",
                    "registry_entry_missing",
                    "registered backend disappeared",
                ));
                continue;
            };
            match self.call_status(entry, &cancel).await {
                Ok(status) => {
                    let expected = working.statuses.get(id);
                    if let Err(message) =
                        Self::validate_running_observation(entry, expected, &status)
                    {
                        failures.push(BackendFailure::safe(
                            id.clone(),
                            "status",
                            "invalid_status",
                            message,
                        ));
                    } else {
                        working.insert_status(status);
                    }
                }
                Err(error) => {
                    failures.push(BackendFailure::from_backend(id.clone(), "status", &error));
                }
            }
            if cancel.is_cancelled() {
                return Ok(self.snapshot());
            }
        }

        if !failures.is_empty() {
            for failure in &failures {
                if let Some(status) = working.statuses.get_mut(&failure.backend) {
                    status.phase = BackendPhase::Degraded;
                    status.diagnostics.push(failure.diagnostic());
                }
            }
            if self.lifecycle.lock().await.active.is_some() {
                return Ok(self.snapshot());
            }

            // A monitor must fail closed when status identity or resource
            // claims cannot be verified. Public refresh remains observation
            // only and therefore never reaches this release path.
            let mut release_failures = Vec::new();
            if isolate_conflicts {
                let failed_ids: BTreeSet<_> = failures
                    .iter()
                    .map(|failure| failure.backend.clone())
                    .collect();
                let targets: Vec<_> = started
                    .iter()
                    .filter(|id| failed_ids.contains(*id))
                    .cloned()
                    .collect();
                if cancel.is_cancelled() {
                    return Ok(self.snapshot());
                }
                let cleanup = CancellationToken::new();
                let outcome = self
                    .release_targets(&targets, &cleanup, &mut working.statuses)
                    .await;
                let released: BTreeSet<_> = targets
                    .iter()
                    .filter(|id| !outcome.failed_ids.contains(*id))
                    .cloned()
                    .collect();
                {
                    let mut lifecycle = self.lifecycle.lock().await;
                    lifecycle.started.retain(|id| !released.contains(id));
                    lifecycle.isolated.extend(targets.iter().cloned());
                    lifecycle
                        .pending_release
                        .extend(outcome.failed_ids.iter().cloned());
                    lifecycle.running = false;
                }
                for id in &targets {
                    if let Some(status) = working.statuses.get_mut(id) {
                        status.phase = BackendPhase::Failed;
                        status.diagnostics.push(Diagnostic::new(
                            if outcome.failed_ids.contains(id) {
                                DiagnosticLevel::Error
                            } else {
                                DiagnosticLevel::Warning
                            },
                            if outcome.failed_ids.contains(id) {
                                "mesh.status_fail_closed_isolation_failed"
                            } else {
                                "mesh.status_fail_closed_isolated"
                            },
                            if outcome.failed_ids.contains(id) {
                                "backend status could not be verified; fail-closed isolation failed"
                            } else {
                                "backend status could not be verified; backend was isolated"
                            },
                        ));
                    }
                }
                release_failures = outcome.failures;
                working.running = false;
            } else {
                working.running = was_running;
            }
            working.supervisor_phase = MeshSupervisorPhase::Degraded;
            working
                .diagnostics
                .extend(failures.iter().map(BackendFailure::diagnostic));
            working
                .diagnostics
                .extend(release_failures.iter().map(BackendFailure::diagnostic));
            self.publish(working);
            failures.extend(release_failures);
            return Err(MeshError::Status { failures });
        }

        let mut claims = self.reservations.clone();
        for id in &started {
            if let Some(status) = working.statuses.get(id) {
                claims.extend(status.owned_resource_claims());
            }
        }
        let conflicts = detect_conflicts(&claims);
        if conflicts.is_empty() {
            if self.lifecycle.lock().await.active.is_some() {
                return Ok(self.snapshot());
            }
            working.running =
                was_running && isolated.is_empty() && started.len() == self.registry.len();
            working.supervisor_phase = if isolated.is_empty() {
                self.aggregate_phase(&started, &working.statuses)
            } else {
                MeshSupervisorPhase::Degraded
            };
            working.conflicts = isolation_conflicts;
            self.publish(working);
            return Ok(self.snapshot());
        }

        Self::mark_conflicts(&mut working, &conflicts, true);
        working.conflicts = merge_conflicts(isolation_conflicts.clone(), conflicts.clone());
        if !isolate_conflicts {
            if self.lifecycle.lock().await.active.is_some() {
                return Ok(self.snapshot());
            }
            working.running = was_running;
            self.publish(working);
            return Err(MeshError::Conflicts { conflicts });
        }

        // Only backend owners can be isolated. Host reservations remain
        // authoritative and never receive lifecycle calls.
        let affected: BTreeSet<BackendId> = conflicts
            .iter()
            .flat_map(|conflict| [&conflict.left.owner, &conflict.right.owner])
            .filter_map(|owner| match owner {
                ResourceOwner::Backend(id) => Some(id.clone()),
                ResourceOwner::HostSubsystem(_) => None,
            })
            .collect();
        let targets: Vec<_> = started
            .iter()
            .filter(|id| affected.contains(*id))
            .cloned()
            .collect();
        if cancel.is_cancelled() {
            return Ok(self.snapshot());
        }
        let cleanup = CancellationToken::new();
        let outcome = self
            .release_targets(&targets, &cleanup, &mut working.statuses)
            .await;

        let released: BTreeSet<_> = targets
            .iter()
            .filter(|id| !outcome.failed_ids.contains(*id))
            .cloned()
            .collect();
        let latched_conflicts = {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.started.retain(|id| !released.contains(id));
            lifecycle.isolated.extend(targets.iter().cloned());
            lifecycle
                .pending_release
                .extend(outcome.failed_ids.iter().cloned());
            lifecycle.isolation_conflicts =
                merge_conflicts(lifecycle.isolation_conflicts.clone(), conflicts.clone());
            lifecycle.running = false;
            lifecycle.isolation_conflicts.clone()
        };
        for id in &targets {
            if let Some(status) = working.statuses.get_mut(id) {
                status.phase = BackendPhase::Conflict;
                status.diagnostics.push(Diagnostic::new(
                    if outcome.failed_ids.contains(id) {
                        DiagnosticLevel::Error
                    } else {
                        DiagnosticLevel::Warning
                    },
                    if outcome.failed_ids.contains(id) {
                        "mesh.dynamic_conflict_isolation_failed"
                    } else {
                        "mesh.dynamic_conflict_isolated"
                    },
                    if outcome.failed_ids.contains(id) {
                        "dynamic resource conflict detected; automatic isolation failed"
                    } else {
                        "dynamic resource conflict detected; backend was isolated"
                    },
                ));
            }
        }
        working.running = false;
        working.supervisor_phase = MeshSupervisorPhase::Degraded;
        working.conflicts = latched_conflicts;
        working
            .diagnostics
            .extend(outcome.failures.iter().map(BackendFailure::diagnostic));
        self.publish(working);
        Err(MeshError::Conflicts { conflicts })
    }

    fn detect_observation_conflicts(
        &self,
        observations: &[(RegisteredBackendRef, BackendStatus)],
    ) -> Vec<ResourceConflict> {
        let mut claims = self.reservations.clone();
        for (_, observation) in observations {
            claims.extend(observation.owned_resource_claims());
        }
        detect_conflicts(&claims)
    }

    fn mark_conflicts(working: &mut MeshSnapshot, conflicts: &[ResourceConflict], dynamic: bool) {
        let affected: BTreeSet<_> = conflicts
            .iter()
            .flat_map(|conflict| [&conflict.left.owner, &conflict.right.owner])
            .filter_map(ResourceOwner::backend_id)
            .cloned()
            .collect();
        for id in affected {
            if let Some(status) = working.statuses.get_mut(&id) {
                status.phase = BackendPhase::Conflict;
                status.diagnostics.push(Diagnostic::new(
                    DiagnosticLevel::Error,
                    "mesh.resource_conflict",
                    if dynamic {
                        format!("backend `{id}` now claims a host resource incompatibly")
                    } else {
                        format!("backend `{id}` claims a host resource incompatibly")
                    },
                ));
            }
        }
        working.running = false;
        working.supervisor_phase = MeshSupervisorPhase::Degraded;
        working.conflicts = conflicts.to_vec();
        working.diagnostics.push(Diagnostic::new(
            DiagnosticLevel::Error,
            if dynamic {
                "mesh.dynamic_resource_conflicts"
            } else {
                "mesh.resource_conflicts"
            },
            format!(
                "{} {}host resource conflict(s) detected",
                conflicts.len(),
                if dynamic { "dynamic " } else { "" }
            ),
        ));
    }

    async fn release_targets(
        &self,
        targets: &[BackendId],
        cancel: &CancellationToken,
        statuses: &mut BTreeMap<BackendId, BackendStatus>,
    ) -> ReleaseOutcome {
        let mut outcome = ReleaseOutcome::default();
        for id in targets.iter().rev() {
            let Some(entry) = self.registry.get(id) else {
                let failure = BackendFailure::safe(
                    id.clone(),
                    "release",
                    "registry_entry_missing",
                    "registered backend disappeared",
                );
                mark_release_failed(statuses, &failure);
                outcome.failed_ids.insert(id.clone());
                outcome.failures.push(failure);
                continue;
            };
            let operation = match entry.descriptor().ownership() {
                crate::model::BackendOwnership::AttachExternal => "detach",
                crate::model::BackendOwnership::ManagedChild
                | crate::model::BackendOwnership::Embedded => "terminate",
            };
            match self.call_release(entry, operation, cancel).await {
                Ok(()) => {
                    if let Some(status) = statuses.get_mut(id) {
                        status.phase = BackendPhase::Stopped;
                    }
                }
                Err(error) => {
                    let failure = BackendFailure::from_backend(id.clone(), operation, &error);
                    mark_release_failed(statuses, &failure);
                    outcome.failed_ids.insert(id.clone());
                    outcome.failures.push(failure);
                }
            }
        }
        outcome
    }

    async fn call_probe(
        &self,
        entry: &RegisteredBackendRef,
        cancel: &CancellationToken,
    ) -> BackendResult<BackendStatus> {
        let _guard = self.acquire_backend(entry, "probe", cancel).await?;
        self.await_backend(
            "probe",
            self.options.backend_timeouts.probe,
            cancel,
            entry.probe(),
        )
        .await
    }

    async fn call_reconcile(
        &self,
        entry: &RegisteredBackendRef,
        observation: &BackendStatus,
        cancel: &CancellationToken,
    ) -> BackendResult<BackendStatus> {
        let _guard = self.acquire_backend(entry, "reconcile", cancel).await?;
        self.await_backend(
            "reconcile",
            self.options.backend_timeouts.reconcile,
            cancel,
            entry.reconcile(observation),
        )
        .await
    }

    async fn call_status(
        &self,
        entry: &RegisteredBackendRef,
        cancel: &CancellationToken,
    ) -> BackendResult<BackendStatus> {
        let _guard = self.acquire_backend(entry, "status", cancel).await?;
        self.await_backend(
            "status",
            self.options.backend_timeouts.status,
            cancel,
            entry.status(),
        )
        .await
    }

    async fn call_release(
        &self,
        entry: &RegisteredBackendRef,
        operation: &'static str,
        cancel: &CancellationToken,
    ) -> BackendResult<()> {
        let _guard = self.acquire_backend(entry, operation, cancel).await?;
        self.await_backend(
            operation,
            self.options.backend_timeouts.release,
            cancel,
            entry.release(),
        )
        .await
    }

    async fn acquire_backend<'a>(
        &self,
        entry: &'a RegisteredBackend,
        operation: &'static str,
        cancel: &CancellationToken,
    ) -> BackendResult<MutexGuard<'a, ()>> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BackendError::cancelled(operation)),
            result = time::timeout(
                self.options.backend_timeouts.gate,
                entry.call_gate().lock(),
            ) => result.map_err(|_| BackendError::timed_out(operation)),
        }
    }

    async fn acquire_maintenance<'a>(
        &'a self,
        cancel: &CancellationToken,
    ) -> BackendResult<MutexGuard<'a, ()>> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BackendError::cancelled("status")),
            result = time::timeout(
                self.options.backend_timeouts.gate,
                self.maintenance.lock(),
            ) => result.map_err(|_| BackendError::timed_out("status")),
        }
    }

    async fn await_backend<T>(
        &self,
        operation: &'static str,
        deadline: Duration,
        cancel: &CancellationToken,
        future: impl Future<Output = BackendResult<T>>,
    ) -> BackendResult<T> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BackendError::cancelled(operation)),
            result = time::timeout(
                deadline,
                CatchUnwindFuture::new(future),
            ) => {
                match result {
                    Err(_) => Err(BackendError::timed_out(operation)),
                    Ok(Err(())) => Err(BackendError::new(
                        "backend_panic",
                        format!("{operation} panicked inside the backend adapter"),
                    )),
                    Ok(Ok(result)) => result,
                }
            }
        }
    }

    fn validate_identity(
        entry: &RegisteredBackendRef,
        status: &BackendStatus,
    ) -> Result<(), String> {
        let descriptor = entry.descriptor();
        if &status.id != descriptor.id() {
            return Err(format!(
                "returned id `{}` does not match frozen id `{}`",
                status.id,
                descriptor.id()
            ));
        }
        if &status.kind != descriptor.kind() {
            return Err("returned backend kind does not match the frozen descriptor".to_owned());
        }
        if status.ownership != descriptor.ownership() {
            return Err(
                "returned backend ownership does not match the frozen descriptor".to_owned(),
            );
        }
        Ok(())
    }

    fn validate_observation(
        entry: &RegisteredBackendRef,
        status: &BackendStatus,
    ) -> Result<(), String> {
        Self::validate_observation_bounds(status).map_err(str::to_owned)?;
        Self::validate_identity(entry, status)
    }

    fn validate_running_observation(
        entry: &RegisteredBackendRef,
        expected: Option<&BackendStatus>,
        status: &BackendStatus,
    ) -> Result<(), String> {
        Self::validate_observation(entry, status)?;
        if entry.descriptor().ownership() == BackendOwnership::AttachExternal {
            let Some(expected) = expected else {
                return Err("external backend has no frozen resource claim envelope".to_owned());
            };
            if normalized_resource_claims(&expected.resource_claims)
                != normalized_resource_claims(&status.resource_claims)
            {
                return Err(
                    "external backend changed its conservative resource claim envelope".to_owned(),
                );
            }
        }
        if !is_running_backend_phase(status.phase) {
            return Err("status returned a non-running phase".to_owned());
        }
        Ok(())
    }

    fn validate_observation_bounds(status: &BackendStatus) -> Result<(), &'static str> {
        if status.attachments.len() > MAX_ATTACHMENTS_PER_OBSERVATION
            || status.resource_claims.len() > MAX_RESOURCE_CLAIMS_PER_OBSERVATION
            || status.diagnostics.len() > MAX_DIAGNOSTICS_PER_SCOPE
            || status.capabilities.len() > MAX_CAPABILITIES_PER_OBSERVATION
        {
            return Err(INVALID_OBSERVATION_MESSAGE);
        }

        let mut budget = ObservationBudget::default();
        budget.add_collection(status.capabilities.len())?;
        budget.add_collection(status.attachments.len())?;
        budget.add_collection(status.resource_claims.len())?;
        budget.add_collection(status.diagnostics.len())?;

        if let BackendKind::Other(name) = &status.kind {
            budget.add_string(name)?;
        }
        if let Some(version) = &status.version {
            budget.add_string(version)?;
        }
        for attachment in &status.attachments {
            validate_attachment_bounds(attachment, &mut budget)?;
        }
        for claim in &status.resource_claims {
            validate_resource_claim_bounds(claim, &mut budget)?;
        }
        for diagnostic in &status.diagnostics {
            budget.add_string_with_limit(&diagnostic.code, MAX_DIAGNOSTIC_CODE_BYTES)?;
            budget.add_string_with_limit(&diagnostic.message, MAX_DIAGNOSTIC_MESSAGE_BYTES)?;
        }
        Ok(())
    }

    fn validate_reconciled_status(
        entry: &RegisteredBackendRef,
        observation: &BackendStatus,
        status: &BackendStatus,
    ) -> Result<(), String> {
        Self::validate_observation(entry, status)?;

        if normalized_resource_claims(&observation.resource_claims)
            != normalized_resource_claims(&status.resource_claims)
        {
            return Err(
                "reconcile returned resource claims that were not covered by preflight".to_owned(),
            );
        }
        if !is_running_backend_phase(status.phase) {
            return Err("reconcile returned a non-running phase".to_owned());
        }
        Ok(())
    }

    fn aggregate_phase(
        &self,
        started: &[BackendId],
        statuses: &BTreeMap<BackendId, BackendStatus>,
    ) -> MeshSupervisorPhase {
        if started.len() == self.registry.len()
            && started.iter().all(|id| {
                statuses
                    .get(id)
                    .is_some_and(|status| status.phase == BackendPhase::Ready)
            })
        {
            MeshSupervisorPhase::Running
        } else {
            MeshSupervisorPhase::Degraded
        }
    }

    fn publish(&self, mut snapshot: MeshSnapshot) {
        let previous = self.snapshots.borrow().generation;
        snapshot.generation = previous.saturating_add(1);
        snapshot.set_reservations(self.reservations.clone());
        normalize_diagnostics(&mut snapshot.diagnostics);
        for status in snapshot.statuses.values_mut() {
            normalize_diagnostics(&mut status.diagnostics);
        }
        self.snapshots.send_replace(snapshot);
    }
}

fn is_running_backend_phase(phase: BackendPhase) -> bool {
    matches!(
        phase,
        BackendPhase::Ready
            | BackendPhase::Degraded
            | BackendPhase::NeedsAuth
            | BackendPhase::Connecting
    )
}

fn normalized_resource_claims(claims: &[ResourceClaim]) -> Vec<ResourceClaim> {
    let mut claims = claims.to_vec();
    claims.sort();
    claims.dedup();
    claims
}

fn validate_attachment_bounds(
    attachment: &Attachment,
    budget: &mut ObservationBudget,
) -> Result<(), &'static str> {
    match attachment {
        Attachment::Interface(interface) => {
            budget.add_string(&interface.name)?;
            budget.add_collection(interface.addresses.len())?;
        }
        Attachment::Route(route) => {
            if let Some(interface) = &route.interface {
                budget.add_string(interface)?;
            }
        }
        Attachment::Endpoint(endpoint) => {
            if let EndpointPurpose::Other(purpose) = &endpoint.purpose {
                budget.add_string(purpose)?;
            }
            validate_endpoint_address_bounds(&endpoint.address, budget)?;
        }
        Attachment::Ingress(ingress) => {
            budget.add_string(&ingress.name)?;
            if let IngressProtocol::Other(protocol) = &ingress.protocol {
                budget.add_string(protocol)?;
            }
            if let Some(source) = &ingress.source {
                budget.add_string(source)?;
            }
            validate_endpoint_address_bounds(&ingress.target, budget)?;
        }
    }
    Ok(())
}

fn validate_endpoint_address_bounds(
    address: &EndpointAddress,
    budget: &mut ObservationBudget,
) -> Result<(), &'static str> {
    match address {
        EndpointAddress::Socket(_) => Ok(()),
        EndpointAddress::UnixSocket(path) => budget.add_string(&path.to_string_lossy()),
        EndpointAddress::NamedPipe(value)
        | EndpointAddress::Url(value)
        | EndpointAddress::Opaque(value) => budget.add_string(value),
    }
}

fn validate_resource_claim_bounds(
    claim: &ResourceClaim,
    budget: &mut ObservationBudget,
) -> Result<(), &'static str> {
    if let ClaimMode::CoordinatedShared { coordination_key } = &claim.mode {
        budget.add_string(coordination_key)?;
    }
    match &claim.resource {
        SystemResource::Interface { name } => budget.add_string(name)?,
        SystemResource::ListenSocket { transport, .. } => {
            if let SocketTransport::Other(transport) = transport {
                budget.add_string(transport)?;
            }
        }
        SystemResource::RouteManager
        | SystemResource::InterfaceManager
        | SystemResource::DefaultRouteV4
        | SystemResource::DefaultRouteV6
        | SystemResource::DnsManager
        | SystemResource::FirewallManager
        | SystemResource::HostsDatabase
        | SystemResource::AddressPrefix { .. }
        | SystemResource::RoutePrefix { .. }
        | SystemResource::RouteTable { .. }
        | SystemResource::FwmarkRange { .. } => {}
    }
    Ok(())
}

/// Convert a panic raised while polling an untrusted backend future into a
/// normal, redacted backend failure. The panic payload is deliberately ignored.
struct CatchUnwindFuture<F> {
    inner: Pin<Box<F>>,
}

impl<F> CatchUnwindFuture<F> {
    fn new(future: F) -> Self {
        Self {
            inner: Box::pin(future),
        }
    }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match catch_unwind(AssertUnwindSafe(|| this.inner.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

#[derive(Default)]
struct ReleaseOutcome {
    failures: Vec<BackendFailure>,
    failed_ids: BTreeSet<BackendId>,
}

fn mark_release_failed(
    statuses: &mut BTreeMap<BackendId, BackendStatus>,
    failure: &BackendFailure,
) {
    if let Some(status) = statuses.get_mut(&failure.backend) {
        status.phase = BackendPhase::Failed;
        push_diagnostic_unique(&mut status.diagnostics, failure.diagnostic());
    }
}

fn push_diagnostic_unique(diagnostics: &mut Vec<Diagnostic>, mut diagnostic: Diagnostic) {
    normalize_diagnostic_fields(&mut diagnostic);
    if let Some(index) = diagnostics
        .iter()
        .position(|existing| existing.level == diagnostic.level && existing.code == diagnostic.code)
    {
        diagnostics.remove(index);
    }
    diagnostics.push(diagnostic);
    normalize_diagnostics(diagnostics);
}

fn normalize_diagnostics(diagnostics: &mut Vec<Diagnostic>) {
    if diagnostics.is_empty() {
        return;
    }

    // Adapter-supplied messages may contain a retry counter or timestamp. Keep
    // only the newest value for each stable (level, code) identity, and retain
    // only the newest bounded set of identities. This keeps long-running
    // monitor snapshots bounded without trusting adapter message stability.
    let mut identities = BTreeSet::new();
    let mut normalized = Vec::with_capacity(diagnostics.len().min(MAX_DIAGNOSTICS_PER_SCOPE));
    for mut diagnostic in diagnostics.drain(..).rev() {
        normalize_diagnostic_fields(&mut diagnostic);
        let identity = (diagnostic.level, diagnostic.code.clone());
        if identities.insert(identity) {
            normalized.push(diagnostic);
            if normalized.len() == MAX_DIAGNOSTICS_PER_SCOPE {
                break;
            }
        }
    }
    normalized.reverse();
    *diagnostics = normalized;
}

fn normalize_diagnostic_fields(diagnostic: &mut Diagnostic) {
    truncate_utf8_bytes(&mut diagnostic.code, MAX_DIAGNOSTIC_CODE_BYTES);
    truncate_utf8_bytes(&mut diagnostic.message, MAX_DIAGNOSTIC_MESSAGE_BYTES);
}

fn truncate_utf8_bytes(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
}

fn retain_failed_order(original: &[BackendId], failed: &BTreeSet<BackendId>) -> Vec<BackendId> {
    original
        .iter()
        .filter(|id| failed.contains(*id))
        .cloned()
        .collect()
}

fn merge_conflicts(
    mut existing: Vec<ResourceConflict>,
    additional: Vec<ResourceConflict>,
) -> Vec<ResourceConflict> {
    existing.extend(additional);
    existing.sort();
    existing.dedup();
    existing
}

async fn wait_for_operation(
    mut receiver: watch::Receiver<Option<OperationResult>>,
) -> OperationResult {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        if receiver.changed().await.is_err() {
            return Err(MeshError::OperationLost);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        io,
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Instant,
    };

    use async_trait::async_trait;
    use tokio::{
        sync::Notify,
        time::{sleep, timeout},
    };

    use super::*;
    use crate::{
        backend::{BackendDescriptor, ExternalNetworkBackend, NetworkBackend, OwnedNetworkBackend},
        model::{
            BackendKind, BackendObservation, BackendOwnership, EndpointAttachment, HostSubsystemId,
            InterfaceAttachment, ResourceClaim, SystemResource,
        },
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(40);
    const TEST_DEADLINE: Duration = Duration::from_secs(2);

    #[test]
    fn diagnostics_keep_latest_message_per_stable_identity() {
        let mut diagnostics = vec![
            Diagnostic::new(DiagnosticLevel::Error, "mesh.retry", "attempt 1"),
            Diagnostic::new(DiagnosticLevel::Warning, "mesh.retry", "warning"),
            Diagnostic::new(DiagnosticLevel::Error, "mesh.retry", "attempt 2"),
        ];

        normalize_diagnostics(&mut diagnostics);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].level, DiagnosticLevel::Warning);
        assert_eq!(diagnostics[0].message, "warning");
        assert_eq!(diagnostics[1].level, DiagnosticLevel::Error);
        assert_eq!(diagnostics[1].message, "attempt 2");
    }

    #[test]
    fn diagnostics_are_bounded_to_the_newest_stable_identities() {
        let mut diagnostics = (0..(MAX_DIAGNOSTICS_PER_SCOPE + 6))
            .map(|index| {
                Diagnostic::new(
                    DiagnosticLevel::Error,
                    format!("mesh.test.{index}"),
                    format!("diagnostic {index}"),
                )
            })
            .collect::<Vec<_>>();

        normalize_diagnostics(&mut diagnostics);

        assert_eq!(diagnostics.len(), MAX_DIAGNOSTICS_PER_SCOPE);
        assert_eq!(diagnostics[0].code, "mesh.test.6");
        assert_eq!(
            diagnostics
                .last()
                .map(|diagnostic| diagnostic.code.as_str()),
            Some("mesh.test.69")
        );
    }

    #[test]
    fn updating_a_full_diagnostic_scope_moves_identity_to_the_newest_position() {
        let mut diagnostics = (0..MAX_DIAGNOSTICS_PER_SCOPE)
            .map(|index| {
                Diagnostic::new(
                    DiagnosticLevel::Error,
                    format!("mesh.test.{index}"),
                    format!("diagnostic {index}"),
                )
            })
            .collect::<Vec<_>>();

        push_diagnostic_unique(
            &mut diagnostics,
            Diagnostic::new(DiagnosticLevel::Error, "mesh.test.0", "newest update"),
        );
        assert_eq!(diagnostics.len(), MAX_DIAGNOSTICS_PER_SCOPE);
        assert_eq!(diagnostics.last().unwrap().code, "mesh.test.0");
        assert_eq!(diagnostics.last().unwrap().message, "newest update");

        push_diagnostic_unique(
            &mut diagnostics,
            Diagnostic::new(DiagnosticLevel::Error, "mesh.test.new", "new identity"),
        );
        assert_eq!(diagnostics.len(), MAX_DIAGNOSTICS_PER_SCOPE);
        assert!(!diagnostics.iter().any(|item| item.code == "mesh.test.1"));
        assert!(diagnostics.iter().any(|item| item.code == "mesh.test.0"));
        assert_eq!(diagnostics.last().unwrap().code, "mesh.test.new");
    }

    #[test]
    fn diagnostic_fields_are_utf8_safely_bounded() {
        let mut diagnostics = Vec::new();
        push_diagnostic_unique(
            &mut diagnostics,
            Diagnostic::new(
                DiagnosticLevel::Error,
                "界".repeat(MAX_DIAGNOSTIC_CODE_BYTES),
                "🙂".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES),
            ),
        );

        let diagnostic = diagnostics.first().expect("normalized diagnostic");
        assert!(diagnostic.code.len() <= MAX_DIAGNOSTIC_CODE_BYTES);
        assert!(diagnostic.message.len() <= MAX_DIAGNOSTIC_MESSAGE_BYTES);
        assert!(diagnostic.code.is_char_boundary(diagnostic.code.len()));
        assert!(
            diagnostic
                .message
                .is_char_boundary(diagnostic.message.len())
        );
        assert!(diagnostic.code.chars().all(|character| character == '界'));
        assert!(
            diagnostic
                .message
                .chars()
                .all(|character| character == '🙂')
        );
    }

    #[test]
    fn observation_bounds_cover_top_level_nested_and_total_budgets() {
        let base = BackendStatus::new(
            backend_id("bounded"),
            BackendKind::Other("test".to_owned()),
            BackendOwnership::ManagedChild,
        );

        let mut too_many_attachments = base.clone();
        too_many_attachments.attachments = vec![
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Control,
                address: EndpointAddress::Opaque("endpoint".to_owned()),
            });
            MAX_ATTACHMENTS_PER_OBSERVATION + 1
        ];

        let mut too_many_claims = base.clone();
        too_many_claims.resource_claims =
            vec![exclusive(SystemResource::DnsManager); MAX_RESOURCE_CLAIMS_PER_OBSERVATION + 1];

        let mut too_many_diagnostics = base.clone();
        too_many_diagnostics.diagnostics =
            vec![
                Diagnostic::new(DiagnosticLevel::Info, "mesh.test", "bounded");
                MAX_DIAGNOSTICS_PER_SCOPE + 1
            ];

        let mut too_many_nested_items = base.clone();
        too_many_nested_items.attachments = vec![Attachment::Interface(InterfaceAttachment {
            name: "mesh0".to_owned(),
            addresses: vec![
                "192.0.2.1/32".parse().expect("valid prefix");
                MAX_COLLECTION_ITEMS_PER_OBSERVATION + 1
            ],
            index: None,
            mtu: None,
        })];

        let mut oversized_string = base.clone();
        oversized_string.version = Some("x".repeat(MAX_PROVIDER_STRING_BYTES + 1));

        let mut excessive_total_string_bytes = base;
        excessive_total_string_bytes.attachments = (0..=(MAX_PROVIDER_STRING_BYTES_PER_OBSERVATION
            / MAX_PROVIDER_STRING_BYTES))
            .map(|_| {
                Attachment::Endpoint(EndpointAttachment {
                    purpose: EndpointPurpose::Control,
                    address: EndpointAddress::Opaque("x".repeat(MAX_PROVIDER_STRING_BYTES)),
                })
            })
            .collect();

        for observation in [
            too_many_attachments,
            too_many_claims,
            too_many_diagnostics,
            too_many_nested_items,
            oversized_string,
            excessive_total_string_bytes,
        ] {
            assert_eq!(
                SupervisorInner::validate_observation_bounds(&observation),
                Err(INVALID_OBSERVATION_MESSAGE)
            );
        }
    }

    #[test]
    fn conflict_error_display_and_debug_do_not_expose_coordination_keys() {
        let secret = "secret-coordination-key";
        let claims = vec![
            OwnedResourceClaim::backend(
                backend_id("left"),
                ResourceClaim::coordinated(SystemResource::DnsManager, secret)
                    .expect("valid coordination key"),
            ),
            OwnedResourceClaim::backend(
                backend_id("right"),
                ResourceClaim::coordinated(SystemResource::DnsManager, "different-key")
                    .expect("valid coordination key"),
            ),
        ];
        let conflicts = detect_conflicts(&claims);
        assert!(!conflicts.is_empty());
        assert!(
            conflicts.iter().any(|conflict| {
                [
                    conflict.left.claim.mode.coordination_key(),
                    conflict.right.claim.mode.coordination_key(),
                ]
                .into_iter()
                .flatten()
                .any(|coordination_key| coordination_key == secret)
            }),
            "test must exercise a conflict that actually contains the secret"
        );

        let error = MeshError::Conflicts { conflicts };
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("different-key"));
        assert!(rendered.contains("mesh resource conflicts prevent reconciliation"));
        assert!(rendered.contains("count"));
    }

    struct FakeBackend {
        label: String,
        descriptor: StdMutex<BackendDescriptor>,
        probe_claims: Vec<ResourceClaim>,
        probe_override: StdMutex<Option<BackendStatus>>,
        status_claims: StdMutex<Option<Vec<ResourceClaim>>>,
        status_override: StdMutex<Option<BackendStatus>>,
        reconcile_claims: StdMutex<Option<Vec<ResourceClaim>>>,
        reconcile_delay: StdMutex<Option<Duration>>,
        status_delay: StdMutex<Option<Duration>>,
        probe_secret: StdMutex<Option<String>>,
        events: Arc<StdMutex<Vec<String>>>,
        reconcile_count: AtomicUsize,
        detach_count: AtomicUsize,
        terminate_count: AtomicUsize,
        attached: AtomicBool,
        process_alive: AtomicBool,
        fail_reconcile: AtomicBool,
        panic_reconcile: AtomicBool,
        fail_detach: AtomicBool,
        fail_terminate: AtomicBool,
        hang_probe: AtomicBool,
        hang_reconcile: AtomicBool,
        hang_status: AtomicBool,
        hang_detach: AtomicBool,
        hang_terminate: AtomicBool,
        block_terminate: AtomicBool,
        reconcile_entered: Notify,
        terminate_entered: Notify,
        continue_terminate: Notify,
    }

    impl FakeBackend {
        fn new(
            id: &str,
            ownership: BackendOwnership,
            probe_claims: Vec<ResourceClaim>,
            events: Arc<StdMutex<Vec<String>>>,
        ) -> Self {
            Self {
                label: id.to_owned(),
                descriptor: StdMutex::new(BackendDescriptor::new(
                    backend_id(id),
                    BackendKind::Other("test".to_owned()),
                    ownership,
                )),
                probe_claims,
                probe_override: StdMutex::new(None),
                status_claims: StdMutex::new(None),
                status_override: StdMutex::new(None),
                reconcile_claims: StdMutex::new(None),
                reconcile_delay: StdMutex::new(None),
                status_delay: StdMutex::new(None),
                probe_secret: StdMutex::new(None),
                events,
                reconcile_count: AtomicUsize::new(0),
                detach_count: AtomicUsize::new(0),
                terminate_count: AtomicUsize::new(0),
                attached: AtomicBool::new(false),
                process_alive: AtomicBool::new(ownership == BackendOwnership::AttachExternal),
                fail_reconcile: AtomicBool::new(false),
                panic_reconcile: AtomicBool::new(false),
                fail_detach: AtomicBool::new(false),
                fail_terminate: AtomicBool::new(false),
                hang_probe: AtomicBool::new(false),
                hang_reconcile: AtomicBool::new(false),
                hang_status: AtomicBool::new(false),
                hang_detach: AtomicBool::new(false),
                hang_terminate: AtomicBool::new(false),
                block_terminate: AtomicBool::new(false),
                reconcile_entered: Notify::new(),
                terminate_entered: Notify::new(),
                continue_terminate: Notify::new(),
            }
        }

        fn status_with(&self, phase: BackendPhase, claims: Vec<ResourceClaim>) -> BackendStatus {
            let descriptor = self.descriptor();
            let mut status = BackendStatus::new(
                descriptor.id().clone(),
                descriptor.kind().clone(),
                descriptor.ownership(),
            );
            status.phase = phase;
            status.resource_claims = claims;
            status
        }

        fn record(&self, operation: &str) {
            self.events
                .lock()
                .expect("event lock")
                .push(format!("{operation}:{}", self.label));
        }

        fn set_dynamic_claims(&self, claims: Vec<ResourceClaim>) {
            *self.status_claims.lock().expect("status claims lock") = Some(claims);
        }

        fn mutate_descriptor_id(&self, id: &str) {
            let mut descriptor = self.descriptor.lock().expect("descriptor lock");
            *descriptor = BackendDescriptor::new(
                backend_id(id),
                descriptor.kind().clone(),
                descriptor.ownership(),
            );
        }
    }

    #[async_trait]
    impl NetworkBackend for FakeBackend {
        fn descriptor(&self) -> BackendDescriptor {
            self.descriptor.lock().expect("descriptor lock").clone()
        }

        async fn probe(&self) -> BackendResult<BackendObservation> {
            self.record("probe");
            if self.hang_probe.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            if let Some(status) = self
                .probe_override
                .lock()
                .expect("probe override lock")
                .clone()
            {
                return Ok(status);
            }
            if let Some(secret) = self.probe_secret.lock().expect("probe secret lock").clone() {
                return Err(BackendError::new("auth_failed", "authentication failed")
                    .with_sensitive_source(io::Error::other(secret)));
            }
            Ok(self.status_with(BackendPhase::Stopped, self.probe_claims.clone()))
        }

        async fn reconcile(
            &self,
            observation: &BackendObservation,
        ) -> BackendResult<BackendStatus> {
            self.record("reconcile");
            self.reconcile_count.fetch_add(1, Ordering::SeqCst);
            self.attached.store(true, Ordering::SeqCst);
            self.process_alive.store(true, Ordering::SeqCst);
            self.reconcile_entered.notify_one();
            let reconcile_delay = *self.reconcile_delay.lock().expect("reconcile delay lock");
            if let Some(delay) = reconcile_delay {
                sleep(delay).await;
            }
            if self.hang_reconcile.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            if self.panic_reconcile.load(Ordering::SeqCst) {
                panic!("raw backend panic payload must stay private");
            }
            if self.fail_reconcile.load(Ordering::SeqCst) {
                return Err(BackendError::new(
                    "reconcile_failed",
                    "synthetic reconcile failure",
                ));
            }
            let claims = self
                .reconcile_claims
                .lock()
                .expect("reconcile claims lock")
                .clone()
                .unwrap_or_else(|| observation.resource_claims.clone());
            Ok(self.status_with(BackendPhase::Ready, claims))
        }

        async fn status(&self) -> BackendResult<BackendStatus> {
            self.record("status");
            let status_delay = *self.status_delay.lock().expect("status delay lock");
            if let Some(delay) = status_delay {
                sleep(delay).await;
            }
            if self.hang_status.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            if let Some(status) = self
                .status_override
                .lock()
                .expect("status override lock")
                .clone()
            {
                return Ok(status);
            }
            let claims = self
                .status_claims
                .lock()
                .expect("status claims lock")
                .clone()
                .unwrap_or_else(|| self.probe_claims.clone());
            let phase = if self.attached.load(Ordering::SeqCst) {
                BackendPhase::Ready
            } else {
                BackendPhase::Stopped
            };
            Ok(self.status_with(phase, claims))
        }
    }

    #[async_trait]
    impl ExternalNetworkBackend for FakeBackend {
        async fn detach(&self) -> BackendResult<()> {
            self.record("detach");
            self.detach_count.fetch_add(1, Ordering::SeqCst);
            if self.hang_detach.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            if self.fail_detach.load(Ordering::SeqCst) {
                return Err(BackendError::new(
                    "detach_failed",
                    "synthetic detach failure",
                ));
            }
            self.attached.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl OwnedNetworkBackend for FakeBackend {
        async fn terminate(&self) -> BackendResult<()> {
            self.record("terminate");
            self.terminate_count.fetch_add(1, Ordering::SeqCst);
            if self.block_terminate.load(Ordering::SeqCst) {
                self.terminate_entered.notify_one();
                self.continue_terminate.notified().await;
            }
            if self.hang_terminate.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            if self.fail_terminate.load(Ordering::SeqCst) {
                return Err(BackendError::new(
                    "terminate_failed",
                    "synthetic terminate failure",
                ));
            }
            self.attached.store(false, Ordering::SeqCst);
            self.process_alive.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    fn backend_id(value: &str) -> BackendId {
        BackendId::new(value).expect("valid backend id")
    }

    fn exclusive(resource: SystemResource) -> ResourceClaim {
        ResourceClaim::exclusive(resource)
    }

    fn registry(backends: &[Arc<FakeBackend>]) -> BackendRegistry {
        let mut registry = BackendRegistry::new();
        for backend in backends {
            match backend.descriptor().ownership() {
                BackendOwnership::AttachExternal => registry
                    .register_external(backend.clone())
                    .expect("external registration"),
                BackendOwnership::ManagedChild => registry
                    .register_managed(backend.clone())
                    .expect("managed registration"),
                BackendOwnership::Embedded => registry
                    .register_embedded(backend.clone())
                    .expect("embedded registration"),
            }
        }
        registry
    }

    fn supervisor(
        backends: &[Arc<FakeBackend>],
        reservations: Vec<HostResourceClaim>,
        monitor_interval: Duration,
    ) -> MeshSupervisor {
        supervisor_with_timeouts(
            backends,
            reservations,
            monitor_interval,
            BackendCallTimeouts {
                gate: TEST_TIMEOUT,
                probe: TEST_TIMEOUT,
                reconcile: TEST_TIMEOUT,
                status: TEST_TIMEOUT,
                release: TEST_TIMEOUT,
            },
        )
    }

    fn supervisor_with_timeouts(
        backends: &[Arc<FakeBackend>],
        reservations: Vec<HostResourceClaim>,
        monitor_interval: Duration,
        backend_timeouts: BackendCallTimeouts,
    ) -> MeshSupervisor {
        MeshSupervisor::with_options(
            registry(backends),
            reservations,
            SupervisorOptions {
                backend_timeouts,
                monitor_interval,
            },
        )
    }

    fn event_log(events: &Arc<StdMutex<Vec<String>>>) -> Vec<String> {
        events.lock().expect("event lock").clone()
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        timeout(TEST_DEADLINE, async {
            loop {
                if predicate() {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition should become true before deadline");
    }

    #[tokio::test]
    async fn host_reservation_and_backend_with_same_name_still_conflict() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let claim = exclusive(SystemResource::DnsManager);
        let backend = Arc::new(FakeBackend::new(
            "capture",
            BackendOwnership::ManagedChild,
            vec![claim.clone()],
            events,
        ));
        let reservation = HostResourceClaim::new(
            HostSubsystemId::new("capture").expect("valid host subsystem id"),
            claim,
        );
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            vec![reservation],
            Duration::ZERO,
        );

        let error = supervisor
            .start()
            .await
            .expect_err("separate namespaces must conflict");
        assert!(matches!(error, MeshError::Conflicts { .. }));
        assert_eq!(backend.reconcile_count.load(Ordering::SeqCst), 0);
        let conflict = &supervisor.snapshot().conflicts[0];
        assert_ne!(conflict.left.owner, conflict.right.owner);
        assert!(
            [&conflict.left.owner, &conflict.right.owner]
                .iter()
                .any(|owner| matches!(owner, ResourceOwner::Backend(_)))
        );
        assert!(
            [&conflict.left.owner, &conflict.right.owner]
                .iter()
                .any(|owner| matches!(owner, ResourceOwner::HostSubsystem(_)))
        );
    }

    #[tokio::test]
    async fn oversized_probe_is_rejected_before_reconcile_with_a_fixed_error() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "oversized-probe",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let secret = "provider-diagnostic-must-not-be-published";
        let mut observation = backend.status_with(BackendPhase::Stopped, Vec::new());
        observation.diagnostics =
            vec![
                Diagnostic::new(DiagnosticLevel::Error, "provider.error", secret);
                MAX_DIAGNOSTICS_PER_SCOPE + 1
            ];
        *backend.probe_override.lock().expect("probe override lock") = Some(observation);
        let supervisor = supervisor(std::slice::from_ref(&backend), Vec::new(), Duration::ZERO);

        let error = supervisor
            .start()
            .await
            .expect_err("oversized probe must fail closed");
        let MeshError::Probe { failures } = &error else {
            panic!("expected probe failure");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].code, "invalid_status");
        assert_eq!(failures[0].message, INVALID_OBSERVATION_MESSAGE);
        assert_eq!(backend.reconcile_count.load(Ordering::SeqCst), 0);
        assert!(!format!("{error:?}").contains(secret));
        assert!(
            !serde_json::to_string(&supervisor.snapshot())
                .unwrap()
                .contains(secret)
        );
    }

    #[tokio::test]
    async fn startup_and_shutdown_are_deterministic_and_reverse_ordered() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let first = Arc::new(FakeBackend::new(
            "first",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let second = Arc::new(FakeBackend::new(
            "second",
            BackendOwnership::Embedded,
            Vec::new(),
            events.clone(),
        ));
        let supervisor = supervisor(&[first.clone(), second.clone()], Vec::new(), Duration::ZERO);

        let started = supervisor.start().await.expect("start succeeds");
        assert!(started.running);
        assert_eq!(started.supervisor_phase, MeshSupervisorPhase::Running);
        supervisor.stop().await.expect("stop succeeds");

        let lifecycle_events: Vec<_> = event_log(&events)
            .into_iter()
            .filter(|event| event.starts_with("reconcile") || event.starts_with("terminate"))
            .collect();
        assert_eq!(
            lifecycle_events,
            [
                "reconcile:first",
                "reconcile:second",
                "terminate:second",
                "terminate:first",
            ]
        );
    }

    #[tokio::test]
    async fn reconcile_failure_releases_in_flight_and_started_backends_in_reverse() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let first = Arc::new(FakeBackend::new(
            "first",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let second = Arc::new(FakeBackend::new(
            "second",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        second.fail_reconcile.store(true, Ordering::SeqCst);
        let supervisor = supervisor(&[first.clone(), second.clone()], Vec::new(), Duration::ZERO);

        assert!(matches!(
            supervisor.start().await,
            Err(MeshError::Reconcile { .. })
        ));
        let release_events: Vec<_> = event_log(&events)
            .into_iter()
            .filter(|event| event.starts_with("terminate"))
            .collect();
        assert_eq!(release_events, ["terminate:second", "terminate:first"]);
        assert!(!first.process_alive.load(Ordering::SeqCst));
        assert!(!second.process_alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stop_aggregates_failures_and_retries_only_residual_backends() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let first = Arc::new(FakeBackend::new(
            "first",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let second = Arc::new(FakeBackend::new(
            "second",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let supervisor = supervisor(&[first.clone(), second.clone()], Vec::new(), Duration::ZERO);
        supervisor.start().await.expect("start succeeds");
        second.fail_terminate.store(true, Ordering::SeqCst);

        let error = supervisor
            .stop()
            .await
            .expect_err("one termination should fail");
        let MeshError::Stop { failures } = error else {
            panic!("expected stop error");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].backend, backend_id("second"));
        assert!(!first.process_alive.load(Ordering::SeqCst));
        assert!(second.process_alive.load(Ordering::SeqCst));

        second.fail_terminate.store(false, Ordering::SeqCst);
        supervisor.stop().await.expect("residual retry succeeds");
        assert_eq!(first.terminate_count.load(Ordering::SeqCst), 1);
        assert_eq!(second.terminate_count.load(Ordering::SeqCst), 2);
        let release_events: Vec<_> = event_log(&events)
            .into_iter()
            .filter(|event| event.starts_with("terminate"))
            .collect();
        assert_eq!(
            release_events,
            ["terminate:second", "terminate:first", "terminate:second"]
        );
    }

    #[tokio::test]
    async fn concurrent_start_and_stop_calls_share_one_transaction() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "shared",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = Arc::new(supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::ZERO,
        ));

        let left = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        let right = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        left.await.unwrap().expect("first start");
        right.await.unwrap().expect("second start");
        assert_eq!(backend.reconcile_count.load(Ordering::SeqCst), 1);

        let left = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.stop().await }
        });
        let right = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.stop().await }
        });
        left.await.unwrap().expect("first stop");
        right.await.unwrap().expect("second stop");
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn snapshots_have_monotonic_generations() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "generation",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(&[backend], Vec::new(), Duration::ZERO);

        let initial = supervisor.snapshot().generation;
        let started = supervisor.start().await.unwrap().generation;
        let refreshed = supervisor.refresh().await.unwrap().generation;
        let stopped = supervisor.stop().await.unwrap().generation;
        assert!(initial < started);
        assert!(started < refreshed);
        assert!(refreshed < stopped);
    }

    #[tokio::test]
    async fn external_backend_is_detached_without_terminating_its_daemon() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "external",
            BackendOwnership::AttachExternal,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(std::slice::from_ref(&backend), Vec::new(), Duration::ZERO);

        supervisor.start().await.unwrap();
        supervisor.stop().await.unwrap();
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 0);
        assert!(!backend.attached.load(Ordering::SeqCst));
        assert!(backend.process_alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn external_backend_cannot_expand_its_frozen_resource_envelope() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "external-envelope",
            BackendOwnership::AttachExternal,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        );

        supervisor.start().await.unwrap();
        backend.set_dynamic_claims(vec![exclusive(SystemResource::DnsManager)]);

        wait_until(|| backend.detach_count.load(Ordering::SeqCst) == 1).await;
        let snapshot = supervisor.snapshot();
        assert!(!snapshot.running);
        assert_eq!(snapshot.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(
            snapshot.statuses[&backend_id("external-envelope")].phase,
            BackendPhase::Failed
        );
        assert!(
            snapshot.statuses[&backend_id("external-envelope")]
                .resource_claims
                .is_empty(),
            "the unreserved claim must never enter the trusted snapshot"
        );
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 0);
        assert!(
            backend.process_alive.load(Ordering::SeqCst),
            "detaching an external adapter must not terminate its daemon"
        );
        assert!(
            snapshot.statuses[&backend_id("external-envelope")]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "mesh.status_fail_closed_isolated")
        );
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn every_hanging_backend_operation_is_deadline_bounded() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let probe = Arc::new(FakeBackend::new(
            "hanging-probe",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        probe.hang_probe.store(true, Ordering::SeqCst);
        let probe_supervisor = supervisor(&[probe], Vec::new(), Duration::ZERO);
        let started_at = Instant::now();
        assert!(matches!(
            probe_supervisor.start().await,
            Err(MeshError::Probe { .. })
        ));
        assert!(started_at.elapsed() < TEST_DEADLINE);

        let backend = Arc::new(FakeBackend::new(
            "hanging-status-release",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(std::slice::from_ref(&backend), Vec::new(), Duration::ZERO);
        supervisor.start().await.unwrap();
        backend.hang_status.store(true, Ordering::SeqCst);
        assert!(matches!(
            timeout(TEST_DEADLINE, supervisor.refresh()).await.unwrap(),
            Err(MeshError::Status { .. })
        ));
        backend.hang_status.store(false, Ordering::SeqCst);
        backend.hang_terminate.store(true, Ordering::SeqCst);
        assert!(matches!(
            timeout(TEST_DEADLINE, supervisor.stop()).await.unwrap(),
            Err(MeshError::Stop { .. })
        ));
        backend.hang_terminate.store(false, Ordering::SeqCst);
        supervisor.stop().await.expect("release retry succeeds");
    }

    #[tokio::test]
    async fn reconcile_has_a_larger_deadline_than_status_observation() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "operation-deadlines",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        *backend
            .reconcile_delay
            .lock()
            .expect("reconcile delay lock") = Some(Duration::from_millis(70));
        *backend.status_delay.lock().expect("status delay lock") = Some(Duration::from_millis(45));
        let supervisor = supervisor_with_timeouts(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::ZERO,
            BackendCallTimeouts {
                gate: Duration::from_millis(20),
                probe: Duration::from_millis(30),
                reconcile: Duration::from_millis(100),
                status: Duration::from_millis(20),
                release: Duration::from_millis(40),
            },
        );

        supervisor
            .start()
            .await
            .expect("longer reconcile budget should allow readiness");
        let error = supervisor
            .refresh()
            .await
            .expect_err("short status budget should fail promptly");
        let MeshError::Status { failures } = error else {
            panic!("expected status timeout");
        };
        assert_eq!(failures[0].code, "operation_timeout");
        *backend.status_delay.lock().expect("status delay lock") = None;
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_last_supervisor_owner_releases_started_backends_once() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "drop-cleanup",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let dropped_supervisor =
            supervisor(std::slice::from_ref(&backend), Vec::new(), Duration::ZERO);
        dropped_supervisor.start().await.unwrap();

        drop(dropped_supervisor);
        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        assert!(!backend.process_alive.load(Ordering::SeqCst));

        let second_events = Arc::new(StdMutex::new(Vec::new()));
        let explicitly_stopped = Arc::new(FakeBackend::new(
            "drop-after-stop",
            BackendOwnership::ManagedChild,
            Vec::new(),
            second_events,
        ));
        let supervisor = supervisor(
            std::slice::from_ref(&explicitly_stopped),
            Vec::new(),
            Duration::ZERO,
        );
        supervisor.start().await.unwrap();
        supervisor.stop().await.unwrap();
        drop(supervisor);
        sleep(Duration::from_millis(30)).await;
        assert_eq!(explicitly_stopped.terminate_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drop_is_non_panicking_when_entered_runtime_is_already_shut_down() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let handle = runtime.handle().clone();
        drop(runtime);

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = handle.enter();
            let supervisor = MeshSupervisor::new(BackendRegistry::new(), Vec::new());
            drop(supervisor);
        }));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn aborted_start_caller_does_not_leak_partially_acquired_resources() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "abort-safe",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.hang_reconcile.store(true, Ordering::SeqCst);
        let supervisor = Arc::new(supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::ZERO,
        ));

        let caller = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        timeout(TEST_DEADLINE, backend.reconcile_entered.notified())
            .await
            .expect("reconcile entered");
        caller.abort();
        assert!(
            caller
                .await
                .expect_err("caller should be aborted")
                .is_cancelled()
        );

        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        assert!(!backend.process_alive.load(Ordering::SeqCst));
        wait_until(|| supervisor.snapshot().supervisor_phase == MeshSupervisorPhase::Failed).await;
        supervisor
            .stop()
            .await
            .expect("no residual resources remain");
    }

    #[tokio::test]
    async fn panicking_backend_completes_waiters_and_rolls_back_safely() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "panic-safe",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.panic_reconcile.store(true, Ordering::SeqCst);
        let supervisor = Arc::new(supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::ZERO,
        ));

        let first = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        let second = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        for waiter in [first, second] {
            let error = timeout(TEST_DEADLINE, waiter)
                .await
                .expect("waiter must complete")
                .expect("waiter task must not panic")
                .expect_err("panicking backend must fail startup");
            let MeshError::Reconcile { failure, .. } = error else {
                panic!("expected redacted reconcile failure");
            };
            assert_eq!(failure.code, "backend_panic");
            assert!(!failure.message.contains("raw backend panic payload"));
        }
        assert_eq!(backend.reconcile_count.load(Ordering::SeqCst), 1);
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        assert!(!backend.process_alive.load(Ordering::SeqCst));
        let json = serde_json::to_string(&supervisor.snapshot()).unwrap();
        assert!(!json.contains("raw backend panic payload"));
    }

    #[tokio::test]
    async fn stop_cancels_hanging_start_without_waiting_for_backend_deadline() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "cancel-safe",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.hang_reconcile.store(true, Ordering::SeqCst);
        let supervisor = Arc::new(supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::ZERO,
        ));
        let caller = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.start().await }
        });
        timeout(TEST_DEADLINE, backend.reconcile_entered.notified())
            .await
            .expect("reconcile entered");

        timeout(TEST_DEADLINE, supervisor.stop())
            .await
            .expect("stop must not deadlock")
            .expect("rollback succeeds");
        assert!(matches!(
            caller.await.unwrap(),
            Err(MeshError::Reconcile { .. })
        ));
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        assert!(!backend.process_alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn background_monitor_isolates_dynamic_conflicts_in_reverse_order() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let first = Arc::new(FakeBackend::new(
            "first",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let second = Arc::new(FakeBackend::new(
            "second",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let third = Arc::new(FakeBackend::new(
            "third",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let supervisor = supervisor(
            &[first.clone(), second.clone(), third.clone()],
            Vec::new(),
            Duration::from_millis(10),
        );
        supervisor.start().await.unwrap();
        let claim = exclusive(SystemResource::DnsManager);
        first.set_dynamic_claims(vec![claim.clone()]);
        second.set_dynamic_claims(vec![claim]);

        wait_until(|| {
            first.terminate_count.load(Ordering::SeqCst) == 1
                && second.terminate_count.load(Ordering::SeqCst) == 1
        })
        .await;
        let snapshot = supervisor.snapshot();
        assert!(!snapshot.running);
        assert_eq!(snapshot.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(
            snapshot.statuses[&backend_id("first")].phase,
            BackendPhase::Conflict
        );
        assert_eq!(
            snapshot.statuses[&backend_id("second")].phase,
            BackendPhase::Conflict
        );
        assert_eq!(
            snapshot.statuses[&backend_id("third")].phase,
            BackendPhase::Ready
        );
        assert_eq!(third.terminate_count.load(Ordering::SeqCst), 0);
        let latched_conflicts = snapshot.conflicts.clone();

        // A later healthy observation of the unaffected backend must not erase
        // the fact that two configured backends were isolated.
        let refreshed = supervisor.refresh().await.unwrap();
        assert!(!refreshed.running);
        assert_eq!(refreshed.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(refreshed.conflicts, latched_conflicts);
        assert!(matches!(
            supervisor.start().await,
            Err(MeshError::ResidualResources { .. })
        ));
        let releases: Vec<_> = event_log(&events)
            .into_iter()
            .filter(|event| event.starts_with("terminate"))
            .collect();
        assert_eq!(releases, ["terminate:second", "terminate:first"]);

        supervisor
            .stop()
            .await
            .expect("explicit stop acknowledges isolation");
        assert_eq!(third.terminate_count.load(Ordering::SeqCst), 1);
        let stopped = supervisor.snapshot();
        assert_eq!(stopped.supervisor_phase, MeshSupervisorPhase::Stopped);
        assert!(stopped.conflicts.is_empty());
    }

    #[tokio::test]
    async fn public_refresh_observes_conflicts_without_lifecycle_side_effects() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let first = Arc::new(FakeBackend::new(
            "first",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events.clone(),
        ));
        let second = Arc::new(FakeBackend::new(
            "second",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(&[first.clone(), second.clone()], Vec::new(), Duration::ZERO);
        supervisor.start().await.unwrap();
        let claim = exclusive(SystemResource::DnsManager);
        first.set_dynamic_claims(vec![claim.clone()]);
        second.set_dynamic_claims(vec![claim]);

        assert!(matches!(
            supervisor.refresh().await,
            Err(MeshError::Conflicts { .. })
        ));
        assert_eq!(first.terminate_count.load(Ordering::SeqCst), 0);
        assert_eq!(second.terminate_count.load(Ordering::SeqCst), 0);
        assert!(supervisor.snapshot().running);
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn monitor_fails_closed_when_dynamic_identity_cannot_be_verified() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "frozen-id",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        );
        supervisor.start().await.unwrap();
        backend.mutate_descriptor_id("untrusted-id");

        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        let snapshot = supervisor.snapshot();
        assert!(!snapshot.running);
        assert_eq!(snapshot.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(
            snapshot.statuses[&backend_id("frozen-id")].phase,
            BackendPhase::Failed
        );
        assert!(!snapshot.statuses.contains_key(&backend_id("untrusted-id")));
        assert!(
            snapshot.statuses[&backend_id("frozen-id")]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "mesh.status_fail_closed_isolated")
        );
        assert!(matches!(
            supervisor.start().await,
            Err(MeshError::ResidualResources { .. })
        ));
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn monitor_fails_closed_when_dynamic_status_exceeds_bounds() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "oversized-status",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        );
        supervisor.start().await.unwrap();

        let secret = "oversized-status-secret";
        let mut status = backend.status_with(BackendPhase::Ready, Vec::new());
        status.attachments = vec![
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Control,
                address: EndpointAddress::Opaque(secret.to_owned()),
            });
            MAX_ATTACHMENTS_PER_OBSERVATION + 1
        ];
        *backend
            .status_override
            .lock()
            .expect("status override lock") = Some(status);

        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        let snapshot = supervisor.snapshot();
        assert!(!snapshot.running);
        assert_eq!(snapshot.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(
            snapshot.statuses[&backend_id("oversized-status")].phase,
            BackendPhase::Failed
        );
        assert!(
            snapshot.statuses[&backend_id("oversized-status")]
                .attachments
                .is_empty()
        );
        assert!(
            snapshot.statuses[&backend_id("oversized-status")]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "mesh.status_fail_closed_isolated")
        );
        assert!(!serde_json::to_string(&snapshot).unwrap().contains(secret));
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn monitor_fails_closed_when_dynamic_phase_is_not_running() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "invalid-dynamic-phase",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        );
        supervisor.start().await.unwrap();

        let status = backend.status_with(BackendPhase::Stopped, Vec::new());
        *backend
            .status_override
            .lock()
            .expect("status override lock") = Some(status);

        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        let snapshot = supervisor.snapshot();
        assert!(!snapshot.running);
        assert_eq!(snapshot.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert_eq!(
            snapshot.statuses[&backend_id("invalid-dynamic-phase")].phase,
            BackendPhase::Failed
        );
        assert!(
            snapshot.statuses[&backend_id("invalid-dynamic-phase")]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "mesh.status_fail_closed_isolated")
        );
        supervisor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn stop_drains_in_flight_monitor_release_without_duplicate_termination() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "monitor-stop-race",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.block_terminate.store(true, Ordering::SeqCst);
        let supervisor = Arc::new(supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        ));
        supervisor.start().await.unwrap();
        backend.mutate_descriptor_id("untrusted-monitor-stop-race");

        timeout(TEST_DEADLINE, backend.terminate_entered.notified())
            .await
            .expect("monitor entered fail-closed termination");
        let stop = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move { supervisor.stop().await }
        });

        sleep(Duration::from_millis(20)).await;
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        backend.block_terminate.store(false, Ordering::SeqCst);
        backend.continue_terminate.notify_one();

        let stopped = timeout(TEST_DEADLINE, stop)
            .await
            .expect("stop must drain monitor")
            .expect("stop task")
            .expect("stop succeeds");
        assert_eq!(stopped.supervisor_phase, MeshSupervisorPhase::Stopped);
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        assert!(!backend.process_alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn monitor_retries_failed_fail_closed_release_before_trusting_status() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "release-retry",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.fail_terminate.store(true, Ordering::SeqCst);
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(40),
        );
        supervisor.start().await.unwrap();
        backend.mutate_descriptor_id("untrusted-release-retry");

        wait_until(|| backend.terminate_count.load(Ordering::SeqCst) == 1).await;
        assert!(backend.process_alive.load(Ordering::SeqCst));
        assert!(
            supervisor.snapshot().statuses[&backend_id("release-retry")]
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "mesh.status_fail_closed_isolation_failed"
                })
        );

        backend.mutate_descriptor_id("release-retry");
        backend.fail_terminate.store(false, Ordering::SeqCst);
        wait_until(|| {
            backend.terminate_count.load(Ordering::SeqCst) == 2
                && !backend.process_alive.load(Ordering::SeqCst)
        })
        .await;
        let retried = supervisor.snapshot();
        assert_eq!(retried.supervisor_phase, MeshSupervisorPhase::Degraded);
        assert!(
            retried.statuses[&backend_id("release-retry")]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "mesh.fail_closed_release_retry_succeeded")
        );

        supervisor
            .stop()
            .await
            .expect("stop only clears the isolation latch");
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn emergency_drop_drains_in_flight_monitor_release_once() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "monitor-drop-race",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        backend.block_terminate.store(true, Ordering::SeqCst);
        let supervisor = supervisor(
            std::slice::from_ref(&backend),
            Vec::new(),
            Duration::from_millis(10),
        );
        supervisor.start().await.unwrap();
        backend.mutate_descriptor_id("untrusted-monitor-drop-race");

        timeout(TEST_DEADLINE, backend.terminate_entered.notified())
            .await
            .expect("monitor entered fail-closed termination");
        drop(supervisor);
        sleep(Duration::from_millis(20)).await;
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        backend.block_terminate.store(false, Ordering::SeqCst);
        backend.continue_terminate.notify_one();

        wait_until(|| !backend.process_alive.load(Ordering::SeqCst)).await;
        sleep(Duration::from_millis(20)).await;
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reconcile_cannot_acquire_claims_missing_from_preflight() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "claim-mutation",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        *backend
            .reconcile_claims
            .lock()
            .expect("reconcile claims lock") = Some(vec![exclusive(SystemResource::DnsManager)]);
        let supervisor = supervisor(std::slice::from_ref(&backend), Vec::new(), Duration::ZERO);

        let error = supervisor.start().await.expect_err("claim drift rejected");
        let MeshError::Reconcile { failure, .. } = error else {
            panic!("expected reconcile error");
        };
        assert_eq!(failure.code, "invalid_status");
        assert_eq!(backend.terminate_count.load(Ordering::SeqCst), 1);
        assert!(!backend.process_alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sensitive_backend_source_never_reaches_errors_or_snapshot_json() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let backend = Arc::new(FakeBackend::new(
            "secret",
            BackendOwnership::ManagedChild,
            Vec::new(),
            events,
        ));
        let secret = "sk-private-raw-stderr";
        *backend.probe_secret.lock().expect("probe secret lock") =
            Some(format!("raw CLI stderr contains {secret}"));
        let supervisor = supervisor(&[backend], Vec::new(), Duration::ZERO);

        let error = supervisor.start().await.expect_err("probe must fail");
        let rendered_error = format!("{error:?}");
        let json = serde_json::to_string(&supervisor.snapshot()).unwrap();
        assert!(!rendered_error.contains(secret));
        assert!(!json.contains(secret));
        assert!(json.contains("auth_failed"));
        assert!(json.contains("authentication failed"));
    }
}
