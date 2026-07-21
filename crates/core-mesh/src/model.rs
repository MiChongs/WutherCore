//! Provider-neutral mesh backend model.
//!
//! These types deliberately separate backend capabilities, observed data-plane
//! attachments, and claimed host resources. A backend can therefore expose only
//! what it actually supports without pretending every mesh product is an L3 VPN.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::Url;

/// Stable, user-visible identity of a configured mesh backend.
///
/// Leading and trailing whitespace is removed at construction time. IDs are
/// limited to 128 bytes and the conservative ASCII set commonly used by
/// adapters (`A-Z`, `a-z`, `0-9`, `/`, `.`, `_`, `:`, and `-`). This keeps IDs
/// safe for structured logs, diagnostics, and serialized map keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BackendId(String);

impl BackendId {
    pub const MAX_BYTES: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, InvalidBackendId> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(InvalidBackendId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for BackendId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for BackendId {
    type Err = InvalidBackendId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for BackendId {
    type Error = InvalidBackendId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BackendId> for String {
    fn from(value: BackendId) -> Self {
        value.into_inner()
    }
}

impl<'de> Deserialize<'de> for BackendId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("backend id must be 1..=128 bytes of ASCII letters, digits, '/', '.', '_', ':', or '-'")]
pub struct InvalidBackendId;

/// Product family implemented by a backend adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Tailscale,
    Headscale,
    CloudflareTunnel,
    CloudflareOneClient,
    CloudflareMesh,
    ZeroTier,
    NetBird,
    Nebula,
    WireGuard,
    Netmaker,
    Innernet,
    Other(String),
}

/// Who owns the backend process and its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOwnership {
    /// Attach to an independently managed daemon or OS service.
    AttachExternal,
    /// Spawn and supervise a child process owned by WutherCore.
    ManagedChild,
    /// Run the backend in-process or through an embedded library.
    Embedded,
}

/// Fine-grained feature advertised by an observed backend instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshCapability {
    L3Interface,
    EmbeddedDialer,
    LocalEndpoint,
    PrivateIngress,
    PublicIngress,
    SubnetRoutes,
    ExitNode,
    PeerInventory,
    IdentityLookup,
    DnsNamespace,
    ManagementApi,
    EventStream,
    HighAvailability,
    PacketForwarding,
    ServiceExposure,
}

/// Lifecycle and health phase common to all backend adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendPhase {
    Disabled,
    Probing,
    Starting,
    NeedsAuth,
    Connecting,
    Ready,
    Degraded,
    Stopping,
    Stopped,
    Conflict,
    Failed,
    Unsupported,
}

/// Dynamic data-plane object exposed by a running backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum Attachment {
    Interface(InterfaceAttachment),
    Route(RouteAttachment),
    Endpoint(EndpointAttachment),
    Ingress(IngressAttachment),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAttachment {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAttachment {
    pub prefix: IpNet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPurpose {
    Control,
    LocalDial,
    Metrics,
    Health,
    Management,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum EndpointAddress {
    Socket(SocketAddr),
    UnixSocket(PathBuf),
    NamedPipe(String),
    Url(String),
    Opaque(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAttachment {
    pub purpose: EndpointPurpose,
    pub address: EndpointAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressProtocol {
    Http,
    Https,
    Tcp,
    Udp,
    Ssh,
    Rdp,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressAttachment {
    pub name: String,
    pub protocol: IngressProtocol,
    /// Provider-side hostname, service name, or network selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub target: EndpointAddress,
}

/// Transport namespace used when claiming a local listening socket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketTransport {
    Tcp,
    Udp,
    Other(String),
}

/// Inclusive host firewall mark range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FwmarkRange {
    start: u32,
    end: u32,
}

impl FwmarkRange {
    pub fn new(start: u32, end: u32) -> Result<Self, InvalidFwmarkRange> {
        if start > end {
            return Err(InvalidFwmarkRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub fn start(self) -> u32 {
        self.start
    }

    pub fn end(self) -> u32 {
        self.end
    }

    pub fn contains(self, value: u32) -> bool {
        self.start <= value && value <= self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

impl<'de> Deserialize<'de> for FwmarkRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRange {
            start: u32,
            end: u32,
        }

        let value = WireRange::deserialize(deserializer)?;
        Self::new(value.start, value.end).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("fwmark range start {start:#x} exceeds end {end:#x}")]
pub struct InvalidFwmarkRange {
    pub start: u32,
    pub end: u32,
}

/// Host resource that can be claimed by one or more coordinated backends.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum SystemResource {
    RouteManager,
    DefaultRouteV4,
    DefaultRouteV6,
    DnsManager,
    FirewallManager,
    HostsDatabase,
    /// Exclusive ownership of an operating-system-assigned interface name.
    ///
    /// This is intentionally broader than [`Self::Interface`]: platforms such
    /// as macOS utun and Android VpnService choose the final interface name
    /// only while activating the device.
    InterfaceManager,
    Interface {
        name: String,
    },
    ListenSocket {
        transport: SocketTransport,
        address: SocketAddr,
    },
    AddressPrefix {
        prefix: IpNet,
    },
    RoutePrefix {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        table: Option<u32>,
        prefix: IpNet,
    },
    RouteTable {
        table: u32,
    },
    FwmarkRange {
        range: FwmarkRange,
    },
}

/// Sharing mode of a host resource claim.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ClaimMode {
    Exclusive,
    CoordinatedShared { coordination_key: String },
}

impl fmt::Debug for ClaimMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exclusive => formatter.write_str("Exclusive"),
            Self::CoordinatedShared { .. } => formatter
                .debug_struct("CoordinatedShared")
                .field("coordination_key", &"[redacted]")
                .finish(),
        }
    }
}

impl ClaimMode {
    /// Construct a coordinated claim while enforcing a non-empty key.
    ///
    /// Conflict detection remains defensive and rejects empty keys that may
    /// arrive from older or manually constructed configurations.
    pub fn coordinated_shared(
        coordination_key: impl Into<String>,
    ) -> Result<Self, InvalidCoordinationKey> {
        let coordination_key = coordination_key.into();
        let coordination_key = coordination_key.trim();
        if coordination_key.is_empty() {
            return Err(InvalidCoordinationKey);
        }
        Ok(Self::CoordinatedShared {
            coordination_key: coordination_key.to_owned(),
        })
    }

    pub fn coordination_key(&self) -> Option<&str> {
        match self {
            Self::Exclusive => None,
            Self::CoordinatedShared { coordination_key } => Some(coordination_key),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("coordination key must not be empty or whitespace")]
pub struct InvalidCoordinationKey;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceClaim {
    pub resource: SystemResource,
    pub mode: ClaimMode,
}

impl ResourceClaim {
    pub fn exclusive(resource: SystemResource) -> Self {
        Self {
            resource,
            mode: ClaimMode::Exclusive,
        }
    }

    pub fn coordinated(
        resource: SystemResource,
        coordination_key: impl Into<String>,
    ) -> Result<Self, InvalidCoordinationKey> {
        Ok(Self {
            resource,
            mode: ClaimMode::coordinated_shared(coordination_key)?,
        })
    }
}

/// Stable identity of a host subsystem that owns a reservation outside the
/// mesh backend registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostSubsystemId(BackendId);

impl HostSubsystemId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidBackendId> {
        BackendId::new(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for HostSubsystemId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A reservation owned by a host subsystem outside the backend registry.
///
/// This dedicated input type prevents a backend owner from being supplied as
/// a host reservation. Conversion to the shared wire model happens only after
/// the supervisor has crossed this typed boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HostResourceClaim {
    pub owner: HostSubsystemId,
    pub claim: ResourceClaim,
}

impl HostResourceClaim {
    pub fn new(owner: HostSubsystemId, claim: ResourceClaim) -> Self {
        Self { owner, claim }
    }

    pub fn into_owned(self) -> OwnedResourceClaim {
        OwnedResourceClaim::host(self.owner, self.claim)
    }
}

/// Collision-proof namespace for resource owners.
///
/// A backend and a host subsystem with the same textual name are intentionally
/// distinct owners, so conflict detection never suppresses a real collision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "namespace", content = "id", rename_all = "snake_case")]
pub enum ResourceOwner {
    Backend(BackendId),
    HostSubsystem(HostSubsystemId),
}

impl ResourceOwner {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Backend(id) => id.as_str(),
            Self::HostSubsystem(id) => id.as_str(),
        }
    }

    pub fn backend_id(&self) -> Option<&BackendId> {
        match self {
            Self::Backend(id) => Some(id),
            Self::HostSubsystem(_) => None,
        }
    }
}

impl fmt::Display for ResourceOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(id) => write!(formatter, "backend:{id}"),
            Self::HostSubsystem(id) => write!(formatter, "host:{id}"),
        }
    }
}

/// A resource claim associated with its collision-proof owner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnedResourceClaim {
    pub owner: ResourceOwner,
    pub claim: ResourceClaim,
}

impl OwnedResourceClaim {
    pub fn backend(owner: BackendId, claim: ResourceClaim) -> Self {
        Self {
            owner: ResourceOwner::Backend(owner),
            claim,
        }
    }

    pub fn host(owner: HostSubsystemId, claim: ResourceClaim) -> Self {
        Self {
            owner: ResourceOwner::HostSubsystem(owner),
            claim,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub code: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(
        level: DiagnosticLevel,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            level,
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Complete, serializable observation of one backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    pub id: BackendId,
    pub kind: BackendKind,
    pub ownership: BackendOwnership,
    pub phase: BackendPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: BTreeSet<MeshCapability>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub resource_claims: Vec<ResourceClaim>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

impl BackendStatus {
    pub fn new(id: BackendId, kind: BackendKind, ownership: BackendOwnership) -> Self {
        Self {
            id,
            kind,
            ownership,
            phase: BackendPhase::Stopped,
            version: None,
            capabilities: BTreeSet::new(),
            attachments: Vec::new(),
            resource_claims: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn owned_resource_claims(&self) -> Vec<OwnedResourceClaim> {
        self.resource_claims
            .iter()
            .cloned()
            .map(|claim| OwnedResourceClaim::backend(self.id.clone(), claim))
            .collect()
    }
}

/// Alias used by probe/reconcile APIs that return an observed snapshot.
pub type BackendObservation = BackendStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSupervisorPhase {
    Idle,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

/// Complete internal supervisor snapshot.
///
/// This model intentionally preserves provider observations for lifecycle and
/// conflict decisions. It must not be serialized directly to an untrusted
/// client; use [`Self::public_view`] for `/v1/mesh/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSnapshot {
    pub generation: u64,
    pub supervisor_phase: MeshSupervisorPhase,
    pub running: bool,
    /// Host-level reservations (for example packet capture or a pre-existing
    /// listener) that participate in conflict checks even when no backend is
    /// currently running.
    #[serde(default, with = "sorted_owned_claims")]
    pub reservations: Vec<OwnedResourceClaim>,
    /// A `BTreeMap` makes backend iteration and serialization deterministic.
    #[serde(default)]
    pub statuses: BTreeMap<BackendId, BackendStatus>,
    #[serde(default)]
    pub conflicts: Vec<crate::conflict::ResourceConflict>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

impl MeshSnapshot {
    pub fn new(generation: u64, supervisor_phase: MeshSupervisorPhase, running: bool) -> Self {
        Self {
            generation,
            supervisor_phase,
            running,
            reservations: Vec::new(),
            statuses: BTreeMap::new(),
            conflicts: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn insert_status(&mut self, status: BackendStatus) -> Option<BackendStatus> {
        self.statuses.insert(status.id.clone(), status)
    }

    /// Replace host reservations and normalize them to deterministic order.
    pub fn set_reservations(&mut self, reservations: impl IntoIterator<Item = OwnedResourceClaim>) {
        self.reservations = reservations.into_iter().collect();
        self.reservations.sort();
        self.reservations.dedup();
    }

    /// Build a separately typed, bounded and redacted API projection.
    #[must_use]
    pub fn public_view(&self) -> PublicMeshSnapshot {
        PublicMeshSnapshot::from(self)
    }
}

const PUBLIC_VERSION_MAX_BYTES: usize = 128;
const PUBLIC_CUSTOM_MAX_BYTES: usize = 256;
const PUBLIC_URL_MAX_BYTES: usize = 2 * 1024;
const PUBLIC_DIAGNOSTIC_CODE_MAX_BYTES: usize = 64;
const PUBLIC_DIAGNOSTIC_MESSAGE: &str = "diagnostic details are available in local process logs";
const PUBLIC_REDACTED_VALUE: &str = "[redacted]";

/// Product family in a public mesh snapshot.
///
/// Provider-defined names are bounded and stripped of control characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicBackendKind {
    Tailscale,
    Headscale,
    CloudflareTunnel,
    CloudflareOneClient,
    CloudflareMesh,
    ZeroTier,
    NetBird,
    Nebula,
    WireGuard,
    Netmaker,
    Innernet,
    Other(String),
}

impl From<&BackendKind> for PublicBackendKind {
    fn from(value: &BackendKind) -> Self {
        match value {
            BackendKind::Tailscale => Self::Tailscale,
            BackendKind::Headscale => Self::Headscale,
            BackendKind::CloudflareTunnel => Self::CloudflareTunnel,
            BackendKind::CloudflareOneClient => Self::CloudflareOneClient,
            BackendKind::CloudflareMesh => Self::CloudflareMesh,
            BackendKind::ZeroTier => Self::ZeroTier,
            BackendKind::NetBird => Self::NetBird,
            BackendKind::Nebula => Self::Nebula,
            BackendKind::WireGuard => Self::WireGuard,
            BackendKind::Netmaker => Self::Netmaker,
            BackendKind::Innernet => Self::Innernet,
            BackendKind::Other(name) => Self::Other(public_custom_string(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum PublicAttachment {
    Interface(PublicInterfaceAttachment),
    Route(PublicRouteAttachment),
    Endpoint(PublicEndpointAttachment),
    Ingress(PublicIngressAttachment),
}

impl From<&Attachment> for PublicAttachment {
    fn from(value: &Attachment) -> Self {
        match value {
            Attachment::Interface(interface) => Self::Interface(interface.into()),
            Attachment::Route(route) => Self::Route(route.into()),
            Attachment::Endpoint(endpoint) => Self::Endpoint(endpoint.into()),
            Attachment::Ingress(ingress) => Self::Ingress(ingress.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicInterfaceAttachment {
    pub name: String,
    pub addresses: Vec<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

impl From<&InterfaceAttachment> for PublicInterfaceAttachment {
    fn from(value: &InterfaceAttachment) -> Self {
        Self {
            name: public_custom_string(&value.name),
            addresses: value.addresses.clone(),
            index: value.index,
            mtu: value.mtu,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicRouteAttachment {
    pub prefix: IpNet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl From<&RouteAttachment> for PublicRouteAttachment {
    fn from(value: &RouteAttachment) -> Self {
        Self {
            prefix: value.prefix,
            table: value.table,
            metric: value.metric,
            interface: value
                .interface
                .as_deref()
                .and_then(|interface| sanitize_optional_text(interface, PUBLIC_CUSTOM_MAX_BYTES)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEndpointPurpose {
    Control,
    LocalDial,
    Metrics,
    Health,
    Management,
    Other(String),
}

impl From<&EndpointPurpose> for PublicEndpointPurpose {
    fn from(value: &EndpointPurpose) -> Self {
        match value {
            EndpointPurpose::Control => Self::Control,
            EndpointPurpose::LocalDial => Self::LocalDial,
            EndpointPurpose::Metrics => Self::Metrics,
            EndpointPurpose::Health => Self::Health,
            EndpointPurpose::Management => Self::Management,
            EndpointPurpose::Other(name) => Self::Other(public_custom_string(name)),
        }
    }
}

/// Endpoint address safe for an unauthenticated serialization boundary.
///
/// URL values retain only scheme, host and port. Filesystem paths, named pipes,
/// opaque values, and malformed URLs are represented by `hidden`, which
/// deliberately has no value field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PublicEndpointAddress {
    Socket(SocketAddr),
    Url(String),
    Hidden,
}

impl From<&EndpointAddress> for PublicEndpointAddress {
    fn from(value: &EndpointAddress) -> Self {
        match value {
            EndpointAddress::Socket(address) => Self::Socket(*address),
            EndpointAddress::UnixSocket(_) | EndpointAddress::NamedPipe(_) => Self::Hidden,
            EndpointAddress::Url(url) => public_url(url).map(Self::Url).unwrap_or(Self::Hidden),
            EndpointAddress::Opaque(_) => Self::Hidden,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicEndpointAttachment {
    pub purpose: PublicEndpointPurpose,
    pub address: PublicEndpointAddress,
}

impl From<&EndpointAttachment> for PublicEndpointAttachment {
    fn from(value: &EndpointAttachment) -> Self {
        Self {
            purpose: (&value.purpose).into(),
            address: (&value.address).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicIngressProtocol {
    Http,
    Https,
    Tcp,
    Udp,
    Ssh,
    Rdp,
    Other(String),
}

impl From<&IngressProtocol> for PublicIngressProtocol {
    fn from(value: &IngressProtocol) -> Self {
        match value {
            IngressProtocol::Http => Self::Http,
            IngressProtocol::Https => Self::Https,
            IngressProtocol::Tcp => Self::Tcp,
            IngressProtocol::Udp => Self::Udp,
            IngressProtocol::Ssh => Self::Ssh,
            IngressProtocol::Rdp => Self::Rdp,
            IngressProtocol::Other(name) => Self::Other(public_custom_string(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicIngressAttachment {
    pub name: String,
    pub protocol: PublicIngressProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub target: PublicEndpointAddress,
}

impl From<&IngressAttachment> for PublicIngressAttachment {
    fn from(value: &IngressAttachment) -> Self {
        Self {
            name: public_custom_string(&value.name),
            protocol: (&value.protocol).into(),
            source: value
                .source
                .as_deref()
                .and_then(|source| sanitize_optional_text(source, PUBLIC_CUSTOM_MAX_BYTES)),
            target: (&value.target).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSocketTransport {
    Tcp,
    Udp,
    Other(String),
}

impl From<&SocketTransport> for PublicSocketTransport {
    fn from(value: &SocketTransport) -> Self {
        match value {
            SocketTransport::Tcp => Self::Tcp,
            SocketTransport::Udp => Self::Udp,
            SocketTransport::Other(name) => Self::Other(public_custom_string(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum PublicSystemResource {
    RouteManager,
    DefaultRouteV4,
    DefaultRouteV6,
    DnsManager,
    FirewallManager,
    HostsDatabase,
    InterfaceManager,
    Interface {
        name: String,
    },
    ListenSocket {
        transport: PublicSocketTransport,
        address: SocketAddr,
    },
    AddressPrefix {
        prefix: IpNet,
    },
    RoutePrefix {
        #[serde(skip_serializing_if = "Option::is_none")]
        table: Option<u32>,
        prefix: IpNet,
    },
    RouteTable {
        table: u32,
    },
    FwmarkRange {
        range: FwmarkRange,
    },
}

impl From<&SystemResource> for PublicSystemResource {
    fn from(value: &SystemResource) -> Self {
        match value {
            SystemResource::RouteManager => Self::RouteManager,
            SystemResource::DefaultRouteV4 => Self::DefaultRouteV4,
            SystemResource::DefaultRouteV6 => Self::DefaultRouteV6,
            SystemResource::DnsManager => Self::DnsManager,
            SystemResource::FirewallManager => Self::FirewallManager,
            SystemResource::HostsDatabase => Self::HostsDatabase,
            SystemResource::InterfaceManager => Self::InterfaceManager,
            SystemResource::Interface { name } => Self::Interface {
                name: public_custom_string(name),
            },
            SystemResource::ListenSocket { transport, address } => Self::ListenSocket {
                transport: transport.into(),
                address: *address,
            },
            SystemResource::AddressPrefix { prefix } => Self::AddressPrefix { prefix: *prefix },
            SystemResource::RoutePrefix { table, prefix } => Self::RoutePrefix {
                table: *table,
                prefix: *prefix,
            },
            SystemResource::RouteTable { table } => Self::RouteTable { table: *table },
            SystemResource::FwmarkRange { range } => Self::FwmarkRange { range: *range },
        }
    }
}

/// Public sharing mode. The coordination key is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PublicClaimMode {
    Exclusive,
    CoordinatedShared,
}

impl From<&ClaimMode> for PublicClaimMode {
    fn from(value: &ClaimMode) -> Self {
        match value {
            ClaimMode::Exclusive => Self::Exclusive,
            ClaimMode::CoordinatedShared { .. } => Self::CoordinatedShared,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicResourceClaim {
    pub resource: PublicSystemResource,
    pub mode: PublicClaimMode,
}

impl From<&ResourceClaim> for PublicResourceClaim {
    fn from(value: &ResourceClaim) -> Self {
        Self {
            resource: (&value.resource).into(),
            mode: (&value.mode).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "namespace", content = "id", rename_all = "snake_case")]
pub enum PublicResourceOwner {
    Backend(BackendId),
    HostSubsystem(HostSubsystemId),
}

impl From<&ResourceOwner> for PublicResourceOwner {
    fn from(value: &ResourceOwner) -> Self {
        match value {
            ResourceOwner::Backend(id) => Self::Backend(id.clone()),
            ResourceOwner::HostSubsystem(id) => Self::HostSubsystem(id.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicOwnedResourceClaim {
    pub owner: PublicResourceOwner,
    pub claim: PublicResourceClaim,
}

impl From<&OwnedResourceClaim> for PublicOwnedResourceClaim {
    fn from(value: &OwnedResourceClaim) -> Self {
        Self {
            owner: (&value.owner).into(),
            claim: (&value.claim).into(),
        }
    }
}

/// Diagnostic safe for the public API.
///
/// Arbitrary provider messages are never copied. The code is retained only
/// when it is a bounded structured identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicDiagnostic {
    pub level: DiagnosticLevel,
    pub code: String,
    pub message: &'static str,
}

impl From<&Diagnostic> for PublicDiagnostic {
    fn from(value: &Diagnostic) -> Self {
        Self {
            level: value.level,
            code: public_diagnostic_code(&value.code),
            message: PUBLIC_DIAGNOSTIC_MESSAGE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicBackendStatus {
    pub id: BackendId,
    pub kind: PublicBackendKind,
    pub ownership: BackendOwnership,
    pub phase: BackendPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub capabilities: BTreeSet<MeshCapability>,
    pub attachments: Vec<PublicAttachment>,
    pub resource_claims: Vec<PublicResourceClaim>,
    pub diagnostics: Vec<PublicDiagnostic>,
}

impl From<&BackendStatus> for PublicBackendStatus {
    fn from(value: &BackendStatus) -> Self {
        Self {
            id: value.id.clone(),
            kind: (&value.kind).into(),
            ownership: value.ownership,
            phase: value.phase,
            version: value
                .version
                .as_deref()
                .and_then(|version| sanitize_optional_text(version, PUBLIC_VERSION_MAX_BYTES)),
            capabilities: value.capabilities.clone(),
            attachments: value
                .attachments
                .iter()
                .map(PublicAttachment::from)
                .collect(),
            resource_claims: value
                .resource_claims
                .iter()
                .map(PublicResourceClaim::from)
                .collect(),
            diagnostics: value
                .diagnostics
                .iter()
                .map(PublicDiagnostic::from)
                .collect(),
        }
    }
}

/// Bounded and redacted projection returned by `/v1/mesh/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicMeshSnapshot {
    pub generation: u64,
    pub supervisor_phase: MeshSupervisorPhase,
    pub running: bool,
    pub reservations: Vec<PublicOwnedResourceClaim>,
    pub statuses: BTreeMap<BackendId, PublicBackendStatus>,
    pub conflicts: Vec<crate::conflict::PublicResourceConflict>,
    pub diagnostics: Vec<PublicDiagnostic>,
}

impl From<&MeshSnapshot> for PublicMeshSnapshot {
    fn from(value: &MeshSnapshot) -> Self {
        Self {
            generation: value.generation,
            supervisor_phase: value.supervisor_phase,
            running: value.running,
            reservations: value
                .reservations
                .iter()
                .map(PublicOwnedResourceClaim::from)
                .collect(),
            statuses: value
                .statuses
                .iter()
                .map(|(id, status)| (id.clone(), status.into()))
                .collect(),
            conflicts: value
                .conflicts
                .iter()
                .map(crate::conflict::PublicResourceConflict::from)
                .collect(),
            diagnostics: value
                .diagnostics
                .iter()
                .map(PublicDiagnostic::from)
                .collect(),
        }
    }
}

pub(crate) fn public_custom_string(value: &str) -> String {
    sanitize_required_text(value, PUBLIC_CUSTOM_MAX_BYTES)
}

fn sanitize_required_text(value: &str, max_bytes: usize) -> String {
    sanitize_optional_text(value, max_bytes).unwrap_or_else(|| PUBLIC_REDACTED_VALUE.to_owned())
}

fn sanitize_optional_text(value: &str, max_bytes: usize) -> Option<String> {
    let mut output = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len().saturating_add(character.len_utf8()) > max_bytes {
            break;
        }
        output.push(character);
    }
    let output = output.trim();
    (!output.is_empty()).then(|| output.to_owned())
}

fn public_diagnostic_code(code: &str) -> String {
    let code = code.trim();
    if code.is_empty()
        || code.len() > PUBLIC_DIAGNOSTIC_CODE_MAX_BYTES
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        "mesh.backend_diagnostic".to_owned()
    } else {
        code.to_owned()
    }
}

fn public_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    // Public mesh endpoints are network locations. This also rejects opaque
    // schemes such as `javascript:` and `data:`.
    url.host_str()?;
    url.set_password(None).ok()?;
    url.set_username("").ok()?;
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);

    let value = url.to_string();
    if value.len() > PUBLIC_URL_MAX_BYTES || value.chars().any(char::is_control) {
        None
    } else {
        Some(value)
    }
}

mod sorted_owned_claims {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::OwnedResourceClaim;

    pub fn serialize<S>(
        reservations: &[OwnedResourceClaim],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut reservations = reservations.to_vec();
        reservations.sort();
        reservations.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<OwnedResourceClaim>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut reservations = Vec::<OwnedResourceClaim>::deserialize(deserializer)?;
        reservations.sort();
        reservations.dedup();
        Ok(reservations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_id_rejects_empty_and_normalizes_outer_whitespace() {
        assert_eq!(BackendId::new("").unwrap_err(), InvalidBackendId);
        assert_eq!(BackendId::new(" \t ").unwrap_err(), InvalidBackendId);
        assert_eq!(
            BackendId::new("  office-mesh  ").unwrap().as_str(),
            "office-mesh"
        );
    }

    #[test]
    fn backend_id_rejects_oversize_and_log_injection_characters() {
        assert!(BackendId::new("a".repeat(BackendId::MAX_BYTES)).is_ok());
        assert!(BackendId::new("a".repeat(BackendId::MAX_BYTES + 1)).is_err());
        for value in [
            "line\nforge",
            "carriage\rforge",
            "tab\tforge",
            "has space",
            "非ascii",
        ] {
            assert!(BackendId::new(value).is_err(), "{value:?} must be rejected");
        }
        assert!(BackendId::new("tailscale/system:prod_1.2").is_ok());
    }

    #[test]
    fn backend_id_deserialization_cannot_inject_serialized_or_logged_lines() {
        let result = serde_json::from_str::<BackendId>(r#""safe\nforged""#);
        assert!(result.is_err());

        let id = BackendId::new("safe/backend:1.2").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#""safe/backend:1.2""#);
        assert!(
            !id.to_string()
                .chars()
                .any(|character| matches!(character, '\r' | '\n' | '\t'))
        );
    }

    #[test]
    fn coordination_key_must_be_non_empty() {
        assert_eq!(
            ClaimMode::coordinated_shared("  ").unwrap_err(),
            InvalidCoordinationKey
        );
        assert_eq!(
            ClaimMode::coordinated_shared(" shared-route ").unwrap(),
            ClaimMode::CoordinatedShared {
                coordination_key: "shared-route".to_owned()
            }
        );
    }

    #[test]
    fn coordination_key_debug_is_redacted() {
        let mode = ClaimMode::coordinated_shared("coordination-key-secret").unwrap();
        let debug = format!("{mode:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("coordination-key-secret"));
    }

    #[test]
    fn fwmark_range_validates_and_detects_boundary_overlap() {
        let left = FwmarkRange::new(0x100, 0x1ff).unwrap();
        let right = FwmarkRange::new(0x1ff, 0x2ff).unwrap();
        assert!(left.overlaps(right));
        assert!(left.contains(0x100));
        assert!(left.contains(0x1ff));
        assert!(FwmarkRange::new(2, 1).is_err());
    }

    #[test]
    fn snapshot_statuses_are_ordered_by_backend_id() {
        let mut snapshot = MeshSnapshot::new(7, MeshSupervisorPhase::Running, true);
        for id in ["z-backend", "a-backend", "m-backend"] {
            snapshot.insert_status(BackendStatus::new(
                BackendId::new(id).unwrap(),
                BackendKind::Other("test".to_owned()),
                BackendOwnership::AttachExternal,
            ));
        }

        let ids: Vec<_> = snapshot.statuses.keys().map(BackendId::as_str).collect();
        assert_eq!(ids, ["a-backend", "m-backend", "z-backend"]);
    }

    #[test]
    fn snapshot_reservations_are_normalized() {
        let mut snapshot = MeshSnapshot::new(8, MeshSupervisorPhase::Idle, false);
        let claim = |owner: &str| {
            OwnedResourceClaim::host(
                HostSubsystemId::new(owner).unwrap(),
                ResourceClaim::exclusive(SystemResource::DnsManager),
            )
        };

        snapshot.set_reservations([claim("z-host"), claim("a-host"), claim("z-host")]);

        let owners: Vec<_> = snapshot
            .reservations
            .iter()
            .map(|claim| claim.owner.as_str())
            .collect();
        assert_eq!(owners, ["a-host", "z-host"]);
    }

    #[test]
    fn public_view_redacts_provider_controlled_values() {
        let id = BackendId::new("public-test").unwrap();
        let mut status = BackendStatus::new(
            id.clone(),
            BackendKind::Other(format!("vendor\n{}", "界".repeat(200))),
            BackendOwnership::AttachExternal,
        );
        status.phase = BackendPhase::Ready;
        status.version = Some(format!("v1\r\n{}", "版".repeat(100)));
        status.attachments = vec![
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Health,
                address: EndpointAddress::Url("https://example.com:8443/health/check".to_owned()),
            }),
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Control,
                address: EndpointAddress::Url(
                    "https://alice:password-secret@example.com:9443/private/path\
                     ?token=query-secret#fragment-secret"
                        .replace(' ', ""),
                ),
            }),
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Other("broken\nurl".to_owned()),
                address: EndpointAddress::Url("not a url invalid-url-secret".to_owned()),
            }),
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Management,
                address: EndpointAddress::Opaque("opaque-secret".to_owned()),
            }),
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Control,
                address: EndpointAddress::UnixSocket(PathBuf::from("/tmp/socket-path-secret")),
            }),
            Attachment::Endpoint(EndpointAttachment {
                purpose: EndpointPurpose::Control,
                address: EndpointAddress::NamedPipe("named-pipe-secret".to_owned()),
            }),
        ];
        status.resource_claims.push(
            ResourceClaim::coordinated(
                SystemResource::Interface {
                    name: "mesh\ninterface".to_owned(),
                },
                "coordination-secret",
            )
            .unwrap(),
        );
        status.diagnostics = vec![
            Diagnostic::new(DiagnosticLevel::Error, "unsafe\ncode", "diagnostic-secret"),
            Diagnostic::new(
                DiagnosticLevel::Warning,
                "mesh.safe_code",
                "another-diagnostic-secret",
            ),
        ];

        let mut snapshot = MeshSnapshot::new(9, MeshSupervisorPhase::Running, true);
        snapshot.insert_status(status);
        let public = snapshot.public_view();
        let public_status = &public.statuses[&id];

        let PublicBackendKind::Other(kind) = &public_status.kind else {
            panic!("custom kind must remain custom");
        };
        assert!(kind.len() <= PUBLIC_CUSTOM_MAX_BYTES);
        assert!(!kind.chars().any(char::is_control));

        let version = public_status.version.as_deref().unwrap();
        assert!(version.len() <= PUBLIC_VERSION_MAX_BYTES);
        assert!(!version.chars().any(char::is_control));

        let addresses: Vec<_> = public_status
            .attachments
            .iter()
            .map(|attachment| match attachment {
                PublicAttachment::Endpoint(endpoint) => &endpoint.address,
                other => panic!("expected endpoint, got {other:?}"),
            })
            .collect();
        assert_eq!(
            addresses[0],
            &PublicEndpointAddress::Url("https://example.com:8443/".to_owned())
        );
        assert_eq!(
            addresses[1],
            &PublicEndpointAddress::Url("https://example.com:9443/".to_owned())
        );
        assert!(
            addresses[2..]
                .iter()
                .all(|address| matches!(address, &&PublicEndpointAddress::Hidden))
        );

        assert_eq!(public_status.diagnostics[0].code, "mesh.backend_diagnostic");
        assert_eq!(public_status.diagnostics[1].code, "mesh.safe_code");
        assert!(
            public_status
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.message == PUBLIC_DIAGNOSTIC_MESSAGE)
        );

        let serialized = serde_json::to_string(&public).unwrap();
        for secret in [
            "alice",
            "password-secret",
            "query-secret",
            "fragment-secret",
            "health/check",
            "private/path",
            "invalid-url-secret",
            "opaque-secret",
            "socket-path-secret",
            "named-pipe-secret",
            "coordination-secret",
            "diagnostic-secret",
            "another-diagnostic-secret",
            "coordination_key",
        ] {
            assert!(
                !serialized.contains(secret),
                "public projection leaked {secret}: {serialized}"
            );
        }
    }
}
