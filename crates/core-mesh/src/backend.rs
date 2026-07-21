//! Backend lifecycle contract.
//!
//! Concrete provider adapters keep provider-specific configuration and process
//! details behind these interfaces. Lifecycle release is deliberately split at
//! the trait level: an external attachment can only be detached, while a
//! managed or embedded backend can only be terminated.

#![forbid(unsafe_code)]

use std::{error::Error as StdError, fmt};

use async_trait::async_trait;

use crate::model::{BackendId, BackendKind, BackendObservation, BackendOwnership, BackendStatus};

/// Immutable identity and lifecycle class captured by the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDescriptor {
    id: BackendId,
    kind: BackendKind,
    ownership: BackendOwnership,
}

impl BackendDescriptor {
    pub fn new(id: BackendId, kind: BackendKind, ownership: BackendOwnership) -> Self {
        Self {
            id,
            kind,
            ownership,
        }
    }

    pub fn id(&self) -> &BackendId {
        &self.id
    }

    pub fn kind(&self) -> &BackendKind {
        &self.kind
    }

    pub fn ownership(&self) -> BackendOwnership {
        self.ownership
    }
}

/// Error returned by one backend lifecycle operation.
///
/// Only `code` and `public_message` may flow into API snapshots. The optional
/// source is sensitive implementation context (for example raw CLI stderr) and
/// is intentionally omitted from `Display`, `Debug`, and `Error::source`.
pub struct BackendError {
    code: String,
    public_message: String,
    sensitive_source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl BackendError {
    pub fn new(code: impl Into<String>, public_message: impl Into<String>) -> Self {
        Self {
            code: sanitize_code(code.into()),
            public_message: sanitize_public_message(public_message.into()),
            sensitive_source: None,
        }
    }

    pub fn with_sensitive_source<E>(mut self, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        self.sensitive_source = Some(Box::new(source));
        self
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn public_message(&self) -> &str {
        &self.public_message
    }

    pub(crate) fn cancelled(operation: &'static str) -> Self {
        Self::new("operation_cancelled", format!("{operation} was cancelled"))
    }

    pub(crate) fn timed_out(operation: &'static str) -> Self {
        Self::new(
            "operation_timeout",
            format!("{operation} exceeded its bounded deadline"),
        )
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.public_message)
    }
}

impl fmt::Debug for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendError")
            .field("code", &self.code)
            .field("public_message", &self.public_message)
            .field(
                "sensitive_source",
                &self.sensitive_source.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl StdError for BackendError {}

pub type BackendResult<T> = Result<T, BackendError>;

/// Provider-neutral observation and reconciliation operations.
///
/// [`Self::probe`] must not acquire a claimed host resource. The registry
/// captures [`Self::descriptor`] exactly once and the supervisor never trusts
/// later descriptor changes for identity, lookup, or release decisions.
#[async_trait]
pub trait NetworkBackend: Send + Sync + 'static {
    fn descriptor(&self) -> BackendDescriptor;

    async fn probe(&self) -> BackendResult<BackendObservation>;

    /// Reconcile using the exact observation that passed conflict preflight.
    ///
    /// Reconcile may be cancelled or timed out. Implementations must therefore
    /// tolerate a subsequent lifecycle release after partial startup.
    async fn reconcile(&self, observation: &BackendObservation) -> BackendResult<BackendStatus>;

    async fn status(&self) -> BackendResult<BackendStatus>;
}

/// Lifecycle capability for a user- or OS-owned external daemon.
///
/// There is no terminate operation on this trait, so a registry entry attached
/// as external cannot accidentally stop, log out, or uninstall the daemon.
/// Because detach cannot undo daemon-owned routes, DNS, or firewall state, an
/// external adapter's resource claims are a conservative envelope for every
/// state that daemon may enter while attached. The supervisor freezes that
/// envelope at preflight and rejects later changes.
#[async_trait]
pub trait ExternalNetworkBackend: NetworkBackend {
    /// Release only attachments owned by this process.
    ///
    /// This operation has at-least-once semantics: a timeout can make the
    /// external result unknowable, so implementations must be idempotent and
    /// safe to retry.
    async fn detach(&self) -> BackendResult<()>;
}

/// Lifecycle capability for a managed child or embedded backend owned by this
/// process.
///
/// There is no detach-only operation on this trait. The registry records
/// whether the frozen descriptor is `ManagedChild` or `Embedded`.
#[async_trait]
pub trait OwnedNetworkBackend: NetworkBackend {
    /// Terminate resources owned by this process.
    ///
    /// This operation has at-least-once semantics: a timeout can make the
    /// external result unknowable, so implementations must be idempotent and
    /// safe to retry.
    async fn terminate(&self) -> BackendResult<()>;
}

fn sanitize_code(code: String) -> String {
    let code = code.trim();
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        "backend_error".to_owned()
    } else {
        code.to_owned()
    }
}

fn sanitize_public_message(message: String) -> String {
    const MAX_CHARS: usize = 512;

    let mut sanitized = String::with_capacity(message.len().min(MAX_CHARS));
    for character in message.chars().take(MAX_CHARS) {
        if character.is_control() {
            sanitized.push(' ');
        } else {
            sanitized.push(character);
        }
    }
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        "backend operation failed".to_owned()
    } else {
        sanitized.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn backend_error_debug_and_display_never_expose_sensitive_source() {
        let secret = "token-super-secret";
        let error = BackendError::new("auth_failed", "authentication failed")
            .with_sensitive_source(io::Error::other(format!("raw stderr: {secret}")));

        let rendered = format!("{error} {error:?}");
        assert!(rendered.contains("auth_failed"));
        assert!(rendered.contains("authentication failed"));
        assert!(!rendered.contains(secret));
        assert!(error.sensitive_source.is_some());
    }

    #[test]
    fn public_error_fields_are_log_safe_and_bounded() {
        let error = BackendError::new("bad\ncode", "first line\nforged line");
        assert_eq!(error.code(), "backend_error");
        assert_eq!(error.public_message(), "first line forged line");
        assert!(error.public_message().len() <= 512);
    }
}
