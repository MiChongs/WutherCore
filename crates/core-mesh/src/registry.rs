//! Deterministic backend registration with frozen descriptors.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    backend::{BackendDescriptor, BackendResult, ExternalNetworkBackend, OwnedNetworkBackend},
    model::{BackendId, BackendObservation, BackendOwnership, BackendStatus},
};

#[derive(Clone)]
enum BackendRef {
    External(Arc<dyn ExternalNetworkBackend>),
    Owned(Arc<dyn OwnedNetworkBackend>),
}

impl BackendRef {
    async fn probe(&self) -> BackendResult<BackendObservation> {
        match self {
            Self::External(backend) => backend.probe().await,
            Self::Owned(backend) => backend.probe().await,
        }
    }

    async fn reconcile(&self, observation: &BackendObservation) -> BackendResult<BackendStatus> {
        match self {
            Self::External(backend) => backend.reconcile(observation).await,
            Self::Owned(backend) => backend.reconcile(observation).await,
        }
    }

    async fn status(&self) -> BackendResult<BackendStatus> {
        match self {
            Self::External(backend) => backend.status().await,
            Self::Owned(backend) => backend.status().await,
        }
    }

    async fn release(&self) -> BackendResult<()> {
        match self {
            Self::External(backend) => backend.detach().await,
            Self::Owned(backend) => backend.terminate().await,
        }
    }
}

/// Frozen registry entry.
///
/// The descriptor is captured once during registration. The backend may return
/// different dynamic metadata later, but lookups, conflict ownership, and
/// release always use this immutable value.
pub struct RegisteredBackend {
    descriptor: BackendDescriptor,
    backend: BackendRef,
    call_gate: Mutex<()>,
}

impl RegisteredBackend {
    pub fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    pub fn id(&self) -> &BackendId {
        self.descriptor.id()
    }

    pub(crate) fn call_gate(&self) -> &Mutex<()> {
        &self.call_gate
    }

    pub(crate) async fn probe(&self) -> BackendResult<BackendObservation> {
        self.backend.probe().await
    }

    pub(crate) async fn reconcile(
        &self,
        observation: &BackendObservation,
    ) -> BackendResult<BackendStatus> {
        self.backend.reconcile(observation).await
    }

    pub(crate) async fn status(&self) -> BackendResult<BackendStatus> {
        self.backend.status().await
    }

    pub(crate) async fn release(&self) -> BackendResult<()> {
        self.backend.release().await
    }
}

pub type RegisteredBackendRef = Arc<RegisteredBackend>;

/// Registration errors are reported before a supervisor can start.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("mesh backend id `{0}` is already registered")]
    DuplicateBackendId(BackendId),

    #[error(
        "backend `{id}` descriptor ownership {actual:?} does not match registration class {expected:?}"
    )]
    OwnershipMismatch {
        id: BackendId,
        expected: BackendOwnership,
        actual: BackendOwnership,
    },
}

/// Ordered registry of configured mesh backends.
///
/// A `Vec` preserves registration order for deterministic reconcile and reverse
/// release. The map is only an index and never controls lifecycle order.
#[derive(Default)]
pub struct BackendRegistry {
    ordered: Vec<RegisteredBackendRef>,
    positions: BTreeMap<BackendId, usize>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_external(
        &mut self,
        backend: Arc<dyn ExternalNetworkBackend>,
    ) -> Result<(), RegistryError> {
        self.insert(
            BackendRef::External(backend),
            BackendOwnership::AttachExternal,
        )
    }

    pub fn register_managed(
        &mut self,
        backend: Arc<dyn OwnedNetworkBackend>,
    ) -> Result<(), RegistryError> {
        self.insert(BackendRef::Owned(backend), BackendOwnership::ManagedChild)
    }

    pub fn register_embedded(
        &mut self,
        backend: Arc<dyn OwnedNetworkBackend>,
    ) -> Result<(), RegistryError> {
        self.insert(BackendRef::Owned(backend), BackendOwnership::Embedded)
    }

    fn insert(
        &mut self,
        backend: BackendRef,
        expected: BackendOwnership,
    ) -> Result<(), RegistryError> {
        let descriptor = match &backend {
            BackendRef::External(backend) => backend.descriptor(),
            BackendRef::Owned(backend) => backend.descriptor(),
        };
        let id = descriptor.id().clone();
        if descriptor.ownership() != expected {
            return Err(RegistryError::OwnershipMismatch {
                id,
                expected,
                actual: descriptor.ownership(),
            });
        }
        if self.positions.contains_key(&id) {
            return Err(RegistryError::DuplicateBackendId(id));
        }

        let position = self.ordered.len();
        self.positions.insert(id, position);
        self.ordered.push(Arc::new(RegisteredBackend {
            descriptor,
            backend,
            call_gate: Mutex::new(()),
        }));
        Ok(())
    }

    pub fn get(&self, id: &BackendId) -> Option<&RegisteredBackendRef> {
        self.positions
            .get(id)
            .and_then(|position| self.ordered.get(*position))
    }

    pub fn ordered(&self) -> &[RegisteredBackendRef] {
        &self.ordered
    }

    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &RegisteredBackendRef> + ExactSizeIterator {
        self.ordered.iter()
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;

    use super::*;
    use crate::{backend::NetworkBackend, model::BackendKind};

    struct StubBackend {
        descriptor: StdMutex<BackendDescriptor>,
    }

    impl StubBackend {
        fn new(id: &str) -> Self {
            Self {
                descriptor: StdMutex::new(BackendDescriptor::new(
                    BackendId::new(id).expect("valid test backend id"),
                    BackendKind::Other("test".to_owned()),
                    BackendOwnership::AttachExternal,
                )),
            }
        }

        fn mutate_id(&self, id: &str) {
            let mut descriptor = self.descriptor.lock().expect("descriptor lock");
            *descriptor = BackendDescriptor::new(
                BackendId::new(id).expect("valid mutated id"),
                descriptor.kind().clone(),
                descriptor.ownership(),
            );
        }

        fn status_value(&self) -> BackendStatus {
            let descriptor = self.descriptor();
            BackendStatus::new(
                descriptor.id().clone(),
                descriptor.kind().clone(),
                descriptor.ownership(),
            )
        }
    }

    #[async_trait]
    impl NetworkBackend for StubBackend {
        fn descriptor(&self) -> BackendDescriptor {
            self.descriptor.lock().expect("descriptor lock").clone()
        }

        async fn probe(&self) -> BackendResult<BackendObservation> {
            Ok(self.status_value())
        }

        async fn reconcile(
            &self,
            _observation: &BackendObservation,
        ) -> BackendResult<BackendStatus> {
            Ok(self.status_value())
        }

        async fn status(&self) -> BackendResult<BackendStatus> {
            Ok(self.status_value())
        }
    }

    #[async_trait]
    impl ExternalNetworkBackend for StubBackend {
        async fn detach(&self) -> BackendResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl OwnedNetworkBackend for StubBackend {
        async fn terminate(&self) -> BackendResult<()> {
            Ok(())
        }
    }

    #[test]
    fn duplicate_backend_id_is_rejected() {
        let mut registry = BackendRegistry::new();
        registry
            .register_external(Arc::new(StubBackend::new("same")))
            .expect("first registration succeeds");

        assert_eq!(
            registry
                .register_external(Arc::new(StubBackend::new("same")))
                .expect_err("duplicate id must fail"),
            RegistryError::DuplicateBackendId(
                BackendId::new("same").expect("valid test backend id")
            )
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registration_order_is_stable_and_not_sorted_by_id() {
        let mut registry = BackendRegistry::new();
        for id in ["z", "a", "m"] {
            registry
                .register_external(Arc::new(StubBackend::new(id)))
                .expect("unique backend");
        }

        let ids: Vec<_> = registry.iter().map(|entry| entry.id().clone()).collect();
        assert_eq!(
            ids,
            ["z", "a", "m"]
                .into_iter()
                .map(|id| BackendId::new(id).expect("valid test backend id"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn descriptor_is_frozen_when_backend_dynamic_id_changes() {
        let backend = Arc::new(StubBackend::new("original"));
        let mut registry = BackendRegistry::new();
        registry
            .register_external(backend.clone())
            .expect("registration succeeds");

        backend.mutate_id("mutated");

        let original = BackendId::new("original").unwrap();
        let mutated = BackendId::new("mutated").unwrap();
        assert_eq!(registry.ordered()[0].id(), &original);
        assert!(registry.get(&original).is_some());
        assert!(registry.get(&mutated).is_none());
    }

    #[test]
    fn registration_class_must_match_frozen_descriptor() {
        let backend = Arc::new(StubBackend::new("external"));
        let mut registry = BackendRegistry::new();
        assert!(matches!(
            registry.register_managed(backend),
            Err(RegistryError::OwnershipMismatch { .. })
        ));
    }
}
