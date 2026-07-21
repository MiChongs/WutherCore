use alloc::collections::BTreeSet;
use alloc::format;
use alloc::vec::Vec;
use core::fmt;

use pki_types::ServerName;

use super::ech::EchGreaseConfig;
use crate::crypto::CryptoProvider;
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, ProtocolVersion, SignatureScheme,
};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::sync::Arc;
use crate::{Error, SupportedProtocolVersion};

/// Builds an optional per-connection ClientHello customization plan.
///
/// This trait is the boundary between profile-specific code and rustls'
/// generic ClientHello shaping primitives. Fingerprint registries should live
/// outside rustls and translate their selected profile into a
/// [`ClientHelloPlan`] for each connection.
///
/// ```
/// use rustls::client::{
///     ClientHelloCipherSuites, ClientHelloContext, ClientHelloCustomizer, ClientHelloGreasePlan,
///     ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension,
///     ClientHelloRawExtensions, ClientHelloSupportedGroups, ClientHelloSupportedVersions,
/// };
/// use rustls::{CipherSuite, Error, NamedGroup, ProtocolVersion};
///
/// #[derive(Debug)]
/// struct RegistryBackedCustomizer;
///
/// impl ClientHelloCustomizer for RegistryBackedCustomizer {
///     fn build_client_hello_plan(
///         &self,
///         context: ClientHelloContext<'_>,
///     ) -> Result<Option<ClientHelloPlan>, Error> {
///         // Profile names and registry lookup live outside rustls. The selected
///         // profile is translated into generic ClientHello controls here.
///         if context.is_quic {
///             return Ok(None);
///         }
///
///         let raw_extensions = ClientHelloRawExtensions::try_from(vec![
///             ClientHelloRawExtension::new(0x1234, vec![1, 2, 3])?,
///         ])?;
///
///         let plan = ClientHelloPlan::new()
///             .with_cipher_suites(ClientHelloCipherSuites::try_from(vec![
///                 CipherSuite::TLS13_AES_128_GCM_SHA256,
///                 CipherSuite::TLS13_AES_256_GCM_SHA384,
///             ])?)
///             .with_supported_versions(ClientHelloSupportedVersions::try_from(vec![
///                 ProtocolVersion::TLSv1_3,
///             ])?)
///             .with_supported_groups(ClientHelloSupportedGroups::try_from(vec![
///                 NamedGroup::X25519,
///             ])?)
///             .with_key_share_plan(ClientHelloKeySharePlan::try_from(vec![
///                 NamedGroup::X25519,
///             ])?)
///             .with_grease(
///                 ClientHelloGreasePlan::new(0x0a0a)?
///                     .with_cipher_suite_position(0)
///                     .with_extension_position(0),
///             )
///             .with_raw_extensions(raw_extensions)
///             .with_padding(ClientHelloPaddingPlan::fixed(8)?);
///
///         Ok(Some(plan))
///     }
/// }
/// ```
pub trait ClientHelloCustomizer: fmt::Debug + Send + Sync {
    /// Return `Ok(None)` to use upstream rustls ClientHello behavior.
    ///
    /// Returning `Ok(Some(ClientHelloPlan::new()))` is also a semantic no-op:
    /// every unset field preserves the normal rustls default for that
    /// connection.
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error>;
}

/// Generic information available while rustls is constructing a ClientHello.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloContext<'a> {
    /// The server name for this connection.
    pub server_name: &'a ServerName<'static>,
    /// ALPN protocols configured for this connection.
    pub alpn_protocols: &'a [Vec<u8>],
    /// Protocol versions enabled for this connection.
    pub versions: &'a [&'static SupportedProtocolVersion],
    /// Crypto provider used for this connection.
    pub crypto_provider: &'a Arc<CryptoProvider>,
    /// Whether this connection is using QUIC.
    pub is_quic: bool,
}

/// Receives the final encoded ClientHello handshake message.
///
/// The captured bytes are the encoded TLS handshake message, including its
/// handshake header and excluding any record-layer header. This is intended for
/// downstream fixture/oracle comparison; it does not change the ClientHello by
/// itself.
pub trait CapturesClientHello: fmt::Debug + Send + Sync {
    /// Captures the encoded ClientHello handshake message after all selected
    /// shaping controls have been applied.
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), Error>;
}

/// Applies a final length-preserving edit to an encoded ClientHello.
///
/// The input bytes are the encoded TLS handshake message, including its
/// handshake header and excluding any record-layer header. The first
/// implementation only permits changing the legacy session id bytes; all other
/// ClientHello bytes must remain unchanged. This mirrors the uTLS/Xray REALITY
/// flow without exposing rustls key exchange internals or allowing arbitrary
/// ClientHello rewrites.
pub trait FinalizesClientHello: fmt::Debug + Send + Sync {
    /// Finalize the encoded ClientHello before it is captured, added to the
    /// transcript, or written to the peer.
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> Result<(), Error>;
}

/// Receives the X25519 key share material used in the ClientHello.
pub trait ObservesX25519KeyShare: fmt::Debug + Send + Sync {
    /// Observes the encoded X25519 public key.
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error>;
}

/// A bounded legacy session id for ClientHello customization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSessionId(Vec<u8>);

impl ClientHelloSessionId {
    /// Return the encoded session id bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for ClientHelloSessionId {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > 32 {
            return Err(Error::General(
                "ClientHello session id cannot exceed 32 bytes".into(),
            ));
        }
        Ok(Self(value))
    }
}

impl AsRef<[u8]> for ClientHelloSessionId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A TLS extension type represented by its IANA u16 value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientHelloExtensionType(pub u16);

/// Explicit order for all non-forced ClientHello extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloExtensionOrder(Vec<ClientHelloExtensionType>);

impl ClientHelloExtensionOrder {
    /// Return the ordered extension types.
    pub fn as_slice(&self) -> &[ClientHelloExtensionType] {
        &self.0
    }
}

impl TryFrom<Vec<u16>> for ClientHelloExtensionOrder {
    type Error = Error;

    fn try_from(value: Vec<u16>) -> Result<Self, Self::Error> {
        let mut seen = BTreeSet::new();
        for extension in &value {
            if !seen.insert(*extension) {
                return Err(Error::General(
                    "ClientHello extension order contains a duplicate extension".into(),
                ));
            }
        }

        Ok(Self(
            value
                .into_iter()
                .map(ClientHelloExtensionType)
                .collect(),
        ))
    }
}

/// Structured ClientHello extension presence controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloExtensionPlan {
    disabled: Vec<ClientHelloExtensionType>,
}

impl ClientHelloExtensionPlan {
    /// Return extension types that should not be emitted.
    pub fn disabled_extensions(&self) -> &[ClientHelloExtensionType] {
        &self.disabled
    }
}

impl TryFrom<Vec<u16>> for ClientHelloExtensionPlan {
    type Error = Error;

    fn try_from(value: Vec<u16>) -> Result<Self, Self::Error> {
        let mut seen = BTreeSet::new();
        for extension in &value {
            if !seen.insert(*extension) {
                return Err(Error::General(
                    "ClientHello extension plan contains a duplicate disabled extension".into(),
                ));
            }
            if matches!(ExtensionType::from(*extension), ExtensionType::Unknown(_)) {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable unknown extensions".into(),
                ));
            }
        }

        Ok(Self {
            disabled: value
                .into_iter()
                .map(ClientHelloExtensionType)
                .collect(),
        })
    }
}

/// Structured ClientHello controls for forcing known extensions to be emitted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientHelloForcedExtensions {
    renegotiation_info_empty: bool,
    session_ticket_request: bool,
    signed_certificate_timestamp_empty: bool,
}

impl ClientHelloForcedExtensions {
    /// Create an empty forced-extension plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit renegotiation_info with an empty renegotiated_connection value.
    pub fn with_renegotiation_info_empty(mut self) -> Self {
        self.renegotiation_info_empty = true;
        self
    }

    /// Emit an empty session_ticket request extension.
    pub fn with_session_ticket_request(mut self) -> Self {
        self.session_ticket_request = true;
        self
    }

    /// Emit an empty signed_certificate_timestamp extension.
    pub fn with_signed_certificate_timestamp_empty(mut self) -> Self {
        self.signed_certificate_timestamp_empty = true;
        self
    }

    pub(crate) fn renegotiation_info_empty(&self) -> bool {
        self.renegotiation_info_empty
    }

    pub(crate) fn session_ticket_request(&self) -> bool {
        self.session_ticket_request
    }

    pub(crate) fn signed_certificate_timestamp_empty(&self) -> bool {
        self.signed_certificate_timestamp_empty
    }
}

/// Explicit ALPN protocol list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloAlpnProtocols(Vec<Vec<u8>>);

impl ClientHelloAlpnProtocols {
    /// Return the ordered ALPN protocol list.
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.0
    }
}

impl TryFrom<Vec<Vec<u8>>> for ClientHelloAlpnProtocols {
    type Error = Error;

    fn try_from(value: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
        let mut seen = BTreeSet::new();
        for protocol in &value {
            if protocol.is_empty() {
                return Err(Error::General(
                    "ClientHello ALPN protocol name cannot be empty".into(),
                ));
            }
            if protocol.len() > usize::from(u8::MAX) {
                return Err(Error::General(
                    "ClientHello ALPN protocol name cannot exceed 255 bytes".into(),
                ));
            }
            if !seen.insert(protocol.clone()) {
                return Err(Error::General(
                    "ClientHello ALPN protocols contain a duplicate value".into(),
                ));
            }
        }

        Ok(Self(value))
    }
}

fn reject_empty_and_duplicate_keys<T, K>(
    values: &[T],
    mut key: impl FnMut(T) -> K,
    what: &str,
) -> Result<(), Error>
where
    T: Copy,
    K: Ord,
{
    if values.is_empty() {
        return Err(Error::General(
            format!("ClientHello {what} cannot be empty").into(),
        ));
    }

    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(key(*value)) {
            return Err(Error::General(
                format!("ClientHello {what} contains a duplicate value").into(),
            ));
        }
    }

    Ok(())
}

fn reject_empty<T>(values: &[T], what: &str) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::General(
            format!("ClientHello {what} cannot be empty").into(),
        ));
    }

    Ok(())
}

/// Explicit cipher suite list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloCipherSuites(Vec<CipherSuite>);

impl ClientHelloCipherSuites {
    /// Return the ordered cipher suite list.
    pub fn as_slice(&self) -> &[CipherSuite] {
        &self.0
    }
}

impl TryFrom<Vec<CipherSuite>> for ClientHelloCipherSuites {
    type Error = Error;

    fn try_from(value: Vec<CipherSuite>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "cipher suites")?;
        if value
            .iter()
            .any(|suite| matches!(suite, CipherSuite::Unknown(_)))
        {
            return Err(Error::General(
                "ClientHello cipher suites cannot contain unknown values".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit advertised cipher suite list and order for the ClientHello.
///
/// Unlike [`ClientHelloCipherSuites`], this list is used only for the
/// serialized ClientHello. It may include known cipher suite identifiers that
/// the configured crypto provider does not implement, so it is intended for
/// fingerprint compatibility only. The negotiated cipher suite must still be
/// implemented by the configured provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloAdvertisedCipherSuites(Vec<CipherSuite>);

impl ClientHelloAdvertisedCipherSuites {
    /// Return the ordered advertised cipher suite list.
    pub fn as_slice(&self) -> &[CipherSuite] {
        &self.0
    }
}

impl TryFrom<Vec<CipherSuite>> for ClientHelloAdvertisedCipherSuites {
    type Error = Error;

    fn try_from(value: Vec<CipherSuite>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "advertised cipher suites")?;
        if value
            .iter()
            .any(|suite| matches!(suite, CipherSuite::Unknown(_)))
        {
            return Err(Error::General(
                "ClientHello advertised cipher suites cannot contain unknown values".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit advertised TLS supported_versions list and order.
///
/// This affects only the serialized ClientHello extension body. It does not
/// enable protocol versions that are not enabled in the rustls config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloAdvertisedSupportedVersions(Vec<ProtocolVersion>);

impl ClientHelloAdvertisedSupportedVersions {
    /// Return the ordered advertised supported versions.
    pub fn as_slice(&self) -> &[ProtocolVersion] {
        &self.0
    }
}

impl TryFrom<Vec<ProtocolVersion>> for ClientHelloAdvertisedSupportedVersions {
    type Error = Error;

    fn try_from(value: Vec<ProtocolVersion>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "advertised supported versions")?;
        if value.len() > usize::from(u8::MAX) / 2 {
            return Err(Error::General(
                "ClientHello advertised supported versions cannot exceed 254 bytes".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit TLS supported_versions list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSupportedVersions(Vec<ProtocolVersion>);

impl ClientHelloSupportedVersions {
    /// Return the ordered supported versions.
    pub fn as_slice(&self) -> &[ProtocolVersion] {
        &self.0
    }
}

impl TryFrom<Vec<ProtocolVersion>> for ClientHelloSupportedVersions {
    type Error = Error;

    fn try_from(value: Vec<ProtocolVersion>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "supported versions")?;
        if value
            .iter()
            .any(|version| !matches!(version, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3))
        {
            return Err(Error::General(
                "ClientHello supported versions can only contain TLS 1.2 and TLS 1.3".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit advertised supported_groups list and order.
///
/// This affects only the serialized ClientHello extension body. It does not add
/// key exchange implementations to the configured crypto provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloAdvertisedSupportedGroups(Vec<NamedGroup>);

impl ClientHelloAdvertisedSupportedGroups {
    /// Return the ordered advertised supported groups.
    pub fn as_slice(&self) -> &[NamedGroup] {
        &self.0
    }
}

impl TryFrom<Vec<NamedGroup>> for ClientHelloAdvertisedSupportedGroups {
    type Error = Error;

    fn try_from(value: Vec<NamedGroup>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "advertised supported groups")?;
        if value.len() > usize::from(u16::MAX) / 2 {
            return Err(Error::General(
                "ClientHello advertised supported groups cannot exceed 65534 bytes".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit supported_groups list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSupportedGroups(Vec<NamedGroup>);

impl ClientHelloSupportedGroups {
    /// Return the ordered supported groups.
    pub fn as_slice(&self) -> &[NamedGroup] {
        &self.0
    }
}

impl TryFrom<Vec<NamedGroup>> for ClientHelloSupportedGroups {
    type Error = Error;

    fn try_from(value: Vec<NamedGroup>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "supported groups")?;

        Ok(Self(value))
    }
}

/// Explicit key_share group list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloKeySharePlan(Vec<NamedGroup>);

impl ClientHelloKeySharePlan {
    /// Return the ordered key_share groups.
    pub fn as_slice(&self) -> &[NamedGroup] {
        &self.0
    }
}

impl TryFrom<Vec<NamedGroup>> for ClientHelloKeySharePlan {
    type Error = Error;

    fn try_from(value: Vec<NamedGroup>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "key share groups")?;

        Ok(Self(value))
    }
}

/// A raw key_share entry added to the serialized ClientHello.
///
/// This affects only the key_share extension bytes. It does not add a key
/// exchange implementation to the configured crypto provider, so peers cannot
/// successfully negotiate a raw-only group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloRawKeyShare {
    group: NamedGroup,
    payload: Vec<u8>,
    position: Option<usize>,
}

impl ClientHelloRawKeyShare {
    /// Create a raw key_share entry appended after rustls-generated shares.
    pub fn new(group: NamedGroup, payload: Vec<u8>) -> Result<Self, Error> {
        Self::new_inner(group, payload, None)
    }

    /// Insert a raw key_share entry at `position` in the key_share list.
    pub fn new_at(position: usize, group: NamedGroup, payload: Vec<u8>) -> Result<Self, Error> {
        Self::new_inner(group, payload, Some(position))
    }

    fn new_inner(
        group: NamedGroup,
        payload: Vec<u8>,
        position: Option<usize>,
    ) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::General(
                "ClientHello raw key share payload cannot be empty".into(),
            ));
        }
        if payload.len() > usize::from(u16::MAX) {
            return Err(Error::General(
                "ClientHello raw key share payload cannot exceed 65535 bytes".into(),
            ));
        }

        Ok(Self {
            group,
            payload,
            position,
        })
    }

    /// Return the advertised key_share group.
    pub fn group(&self) -> NamedGroup {
        self.group
    }

    /// Return the key_share payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Return the insertion position, or `None` when appended.
    pub fn position(&self) -> Option<usize> {
        self.position
    }
}

/// Raw key_share entries added to the serialized ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloRawKeyShares(Vec<ClientHelloRawKeyShare>);

impl ClientHelloRawKeyShares {
    /// Return the raw key_share list.
    pub fn as_slice(&self) -> &[ClientHelloRawKeyShare] {
        &self.0
    }
}

impl TryFrom<Vec<ClientHelloRawKeyShare>> for ClientHelloRawKeyShares {
    type Error = Error;

    fn try_from(value: Vec<ClientHelloRawKeyShare>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::General(
                "ClientHello raw key shares cannot be empty".into(),
            ));
        }

        let mut seen = BTreeSet::new();
        for key_share in &value {
            if !seen.insert(u16::from(key_share.group)) {
                return Err(Error::General(
                    "ClientHello raw key shares contain a duplicate group".into(),
                ));
            }
        }

        Ok(Self(value))
    }
}

/// Explicit signature_algorithms list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloSignatureAlgorithms(Vec<SignatureScheme>);

impl ClientHelloSignatureAlgorithms {
    /// Return the ordered signature algorithms.
    pub fn as_slice(&self) -> &[SignatureScheme] {
        &self.0
    }
}

impl TryFrom<Vec<SignatureScheme>> for ClientHelloSignatureAlgorithms {
    type Error = Error;

    fn try_from(value: Vec<SignatureScheme>) -> Result<Self, Self::Error> {
        reject_empty(&value, "signature algorithms")?;
        if value
            .iter()
            .any(|scheme| matches!(scheme, SignatureScheme::Unknown(_)))
        {
            return Err(Error::General(
                "ClientHello signature algorithms cannot contain unknown values".into(),
            ));
        }

        Ok(Self(value))
    }
}

/// Explicit compress_certificate algorithm list and order for the ClientHello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloCertificateCompressionAlgorithms(Vec<CertificateCompressionAlgorithm>);

impl ClientHelloCertificateCompressionAlgorithms {
    /// Return the ordered certificate compression algorithm list.
    pub fn as_slice(&self) -> &[CertificateCompressionAlgorithm] {
        &self.0
    }
}

impl TryFrom<Vec<CertificateCompressionAlgorithm>> for ClientHelloCertificateCompressionAlgorithms {
    type Error = Error;

    fn try_from(value: Vec<CertificateCompressionAlgorithm>) -> Result<Self, Self::Error> {
        reject_empty_and_duplicate_keys(&value, u16::from, "certificate compression algorithms")?;
        if value
            .iter()
            .any(|algorithm| matches!(algorithm, CertificateCompressionAlgorithm::Unknown(_)))
        {
            return Err(Error::General(
                "ClientHello certificate compression algorithms cannot contain unknown values"
                    .into(),
            ));
        }

        Ok(Self(value))
    }
}

/// A bounded exact known ClientHello extension payload.
///
/// This escape hatch is for byte-level ClientHello shaping of extension types
/// rustls knows about. Unknown extension types should use
/// [`ClientHelloRawExtension`], and GREASE extension slots should use
/// [`ClientHelloGreasePlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloExactExtension {
    extension_type: ClientHelloExtensionType,
    payload: Vec<u8>,
}

impl ClientHelloExactExtension {
    /// Create an exact known ClientHello extension payload.
    pub fn new(extension_type: u16, payload: Vec<u8>) -> Result<Self, Error> {
        if payload.len() > usize::from(u16::MAX) {
            return Err(Error::General(
                "ClientHello exact extension payload cannot exceed 65535 bytes".into(),
            ));
        }
        if is_grease_value(extension_type) {
            return Err(Error::General(
                "ClientHello exact extension type cannot be a GREASE value".into(),
            ));
        }

        match ExtensionType::from(extension_type) {
            ExtensionType::Unknown(_) => {
                return Err(Error::General(
                    "ClientHello exact extension type must be known".into(),
                ));
            }
            ExtensionType::PreSharedKey => {
                return Err(Error::General(
                    "ClientHello exact extension type cannot be pre_shared_key".into(),
                ));
            }
            _ => {}
        }

        Ok(Self {
            extension_type: ClientHelloExtensionType(extension_type),
            payload,
        })
    }

    /// Return the extension type.
    pub fn extension_type(&self) -> ClientHelloExtensionType {
        self.extension_type
    }

    /// Return the exact extension body bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Exact known ClientHello extension payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloExactExtensions(Vec<ClientHelloExactExtension>);

impl ClientHelloExactExtensions {
    /// Return the exact extension list.
    pub fn as_slice(&self) -> &[ClientHelloExactExtension] {
        &self.0
    }
}

impl TryFrom<Vec<ClientHelloExactExtension>> for ClientHelloExactExtensions {
    type Error = Error;

    fn try_from(value: Vec<ClientHelloExactExtension>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::General(
                "ClientHello exact extensions cannot be empty".into(),
            ));
        }

        let mut seen = BTreeSet::new();
        for extension in &value {
            if !seen.insert(extension.extension_type.0) {
                return Err(Error::General(
                    "ClientHello exact extensions contain a duplicate extension".into(),
                ));
            }
        }

        Ok(Self(value))
    }
}

/// A bounded raw unknown ClientHello extension.
///
/// This escape hatch is only for extension types rustls does not know about.
/// Use the structured ClientHello controls for known extensions; GREASE
/// extensions are handled by [`ClientHelloGreasePlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloRawExtension {
    extension_type: ClientHelloExtensionType,
    payload: Vec<u8>,
}

impl ClientHelloRawExtension {
    /// Create a raw unknown ClientHello extension.
    ///
    /// Known extensions and GREASE values are rejected so this escape hatch
    /// cannot silently override structured ClientHello controls.
    pub fn new(extension_type: u16, payload: Vec<u8>) -> Result<Self, Error> {
        if payload.len() > usize::from(u16::MAX) {
            return Err(Error::General(
                "ClientHello raw extension payload cannot exceed 65535 bytes".into(),
            ));
        }
        if !matches!(
            ExtensionType::from(extension_type),
            ExtensionType::Unknown(_)
        ) {
            return Err(Error::General(
                "ClientHello raw extension type must be unknown".into(),
            ));
        }
        if is_grease_value(extension_type) {
            return Err(Error::General(
                "ClientHello raw extension type cannot be a GREASE value".into(),
            ));
        }

        Ok(Self {
            extension_type: ClientHelloExtensionType(extension_type),
            payload,
        })
    }

    /// Return the extension type.
    pub fn extension_type(&self) -> ClientHelloExtensionType {
        self.extension_type
    }

    /// Return the extension body bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Raw unknown ClientHello extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloRawExtensions(Vec<ClientHelloRawExtension>);

impl ClientHelloRawExtensions {
    /// Return the raw extension list.
    pub fn as_slice(&self) -> &[ClientHelloRawExtension] {
        &self.0
    }
}

impl TryFrom<Vec<ClientHelloRawExtension>> for ClientHelloRawExtensions {
    type Error = Error;

    fn try_from(value: Vec<ClientHelloRawExtension>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::General(
                "ClientHello raw extensions cannot be empty".into(),
            ));
        }

        let mut seen = BTreeSet::new();
        for extension in &value {
            if !seen.insert(extension.extension_type.0) {
                return Err(Error::General(
                    "ClientHello raw extensions contain a duplicate extension".into(),
                ));
            }
        }

        Ok(Self(value))
    }
}

/// A GREASE extension entry for ClientHello shaping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloGreaseExtension {
    value: u16,
    position: usize,
    payload: Vec<u8>,
}

impl ClientHelloGreaseExtension {
    /// Create a GREASE extension using one of the RFC 8701 reserved values.
    pub fn new(value: u16, position: usize, payload: Vec<u8>) -> Result<Self, Error> {
        if !is_grease_value(value) {
            return Err(Error::General(
                "ClientHello GREASE extension value must be an RFC 8701 reserved value".into(),
            ));
        }
        if payload.len() > usize::from(u16::MAX) {
            return Err(Error::General(
                "ClientHello GREASE extension payload cannot exceed 65535 bytes".into(),
            ));
        }

        Ok(Self {
            value,
            position,
            payload,
        })
    }

    /// Return the GREASE extension type value.
    pub fn value(&self) -> u16 {
        self.value
    }

    /// Return the insertion position in the non-GREASE non-final extension order.
    ///
    /// Position `0` inserts before the first real extension, and position
    /// `len` inserts after the last real extension.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Return the GREASE extension body bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Explicit GREASE value and insertion positions for ClientHello shaping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloGreasePlan {
    value: u16,
    cipher_suite_position: Option<usize>,
    extensions: Vec<ClientHelloGreaseExtension>,
    supported_version_position: Option<usize>,
    supported_group_position: Option<usize>,
    key_share_position: Option<usize>,
}

impl ClientHelloGreasePlan {
    /// Create a GREASE plan using one of the RFC 8701 reserved values.
    pub fn new(value: u16) -> Result<Self, Error> {
        if !is_grease_value(value) {
            return Err(Error::General(
                "ClientHello GREASE value must be an RFC 8701 reserved value".into(),
            ));
        }

        Ok(Self {
            value,
            cipher_suite_position: None,
            extensions: Vec::new(),
            supported_version_position: None,
            supported_group_position: None,
            key_share_position: None,
        })
    }

    /// Return the GREASE value used by the simple GREASE insertion controls.
    pub fn value(&self) -> u16 {
        self.value
    }

    /// Insert the GREASE value into the cipher suite list at `position`.
    pub fn with_cipher_suite_position(mut self, position: usize) -> Self {
        self.cipher_suite_position = Some(position);
        self
    }

    /// Insert the GREASE extension into the non-GREASE extension list at `position`.
    ///
    /// Position `0` inserts before the first real extension, and position
    /// `len` inserts after the last real extension.
    pub fn with_extension_position(mut self, position: usize) -> Self {
        self.extensions
            .retain(|extension| extension.value() != self.value);
        self.extensions
            .push(ClientHelloGreaseExtension {
                value: self.value,
                position,
                payload: Vec::new(),
            });
        self
    }

    /// Insert a GREASE extension entry into the non-GREASE extension list.
    pub fn with_extension(mut self, extension: ClientHelloGreaseExtension) -> Result<Self, Error> {
        if self
            .extensions
            .iter()
            .any(|existing| existing.value() == extension.value())
        {
            return Err(Error::General(
                "ClientHello GREASE extensions contain a duplicate extension".into(),
            ));
        }

        self.extensions.push(extension);
        Ok(self)
    }

    /// Insert the GREASE value into supported_versions at `position`.
    pub fn with_supported_version_position(mut self, position: usize) -> Self {
        self.supported_version_position = Some(position);
        self
    }

    /// Insert the GREASE value into supported_groups at `position`.
    pub fn with_supported_group_position(mut self, position: usize) -> Self {
        self.supported_group_position = Some(position);
        self
    }

    /// Insert a GREASE key_share entry at `position`.
    pub fn with_key_share_position(mut self, position: usize) -> Self {
        self.key_share_position = Some(position);
        self
    }

    pub(crate) fn cipher_suite_position(&self) -> Option<usize> {
        self.cipher_suite_position
    }

    pub(crate) fn extensions(&self) -> &[ClientHelloGreaseExtension] {
        &self.extensions
    }

    pub(crate) fn supported_version_position(&self) -> Option<usize> {
        self.supported_version_position
    }

    pub(crate) fn supported_group_position(&self) -> Option<usize> {
        self.supported_group_position
    }

    pub(crate) fn key_share_position(&self) -> Option<usize> {
        self.key_share_position
    }
}

fn is_grease_value(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

/// ClientHello padding extension behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientHelloPaddingMode {
    Fixed(u16),
    PadToHandshakeSize(u16),
}

/// Structured control for the ClientHello padding extension.
///
/// Padding bytes are always encoded as zero bytes, as required by RFC 7685.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHelloPaddingPlan {
    mode: ClientHelloPaddingMode,
}

impl ClientHelloPaddingPlan {
    /// Emit a padding extension with exactly `length` zero bytes.
    pub fn fixed(length: usize) -> Result<Self, Error> {
        Ok(Self {
            mode: ClientHelloPaddingMode::Fixed(validate_padding_size(length)?),
        })
    }

    /// Pad the encoded ClientHello handshake message to at least `target_size` bytes.
    ///
    /// `target_size` counts the four-byte TLS handshake header as well as the
    /// ClientHello body. If the ClientHello is already at or above the target
    /// size, an empty padding extension is emitted.
    pub fn pad_to_handshake_size(target_size: usize) -> Result<Self, Error> {
        Ok(Self {
            mode: ClientHelloPaddingMode::PadToHandshakeSize(validate_padding_size(target_size)?),
        })
    }

    pub(crate) fn mode(&self) -> ClientHelloPaddingMode {
        self.mode
    }
}

fn validate_padding_size(size: usize) -> Result<u16, Error> {
    u16::try_from(size)
        .map_err(|_| Error::General("ClientHello padding size cannot exceed 65535 bytes".into()))
}

/// Fixed X25519 key share material.
///
/// Using a fixed key share disables the normal forward secrecy properties
/// provided by generating fresh ephemeral key material for each handshake.
/// This type retains the private key material in memory and is intended only
/// for specialized compatibility and testing scenarios.
#[derive(Clone)]
pub struct FixedX25519KeyShare {
    #[allow(dead_code)]
    private_key: [u8; 32],
    observer: Option<Arc<dyn ObservesX25519KeyShare>>,
}

impl fmt::Debug for FixedX25519KeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedX25519KeyShare")
            .field("private_key", &"<redacted>")
            .field("observer_present", &self.observer.is_some())
            .finish()
    }
}

impl FixedX25519KeyShare {
    /// Create a fixed X25519 key share from private key material.
    ///
    /// This disables the normal forward secrecy properties provided by fresh
    /// ephemeral key shares and retains the private key material in memory.
    /// It is intended only for specialized compatibility and testing
    /// scenarios.
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            private_key,
            observer: None,
        }
    }

    /// Register an observer for the public key derived from this key share.
    pub fn with_observer(mut self, observer: Arc<dyn ObservesX25519KeyShare>) -> Self {
        self.observer = Some(observer);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    #[allow(dead_code)]
    pub(crate) fn observer(&self) -> Option<&Arc<dyn ObservesX25519KeyShare>> {
        self.observer.as_ref()
    }
}

/// Per-connection ClientHello customization plan.
///
/// Each field is independent and optional. Leaving a field unset preserves the
/// rustls default for that aspect of the ClientHello, making an empty plan a
/// no-op that is byte-shape compatible apart from rustls' normal per-connection
/// randomness.
#[derive(Clone, Debug, Default)]
pub struct ClientHelloPlan {
    pub(crate) random: Option<[u8; 32]>,
    pub(crate) session_id: Option<ClientHelloSessionId>,
    pub(crate) capture: Option<Arc<dyn CapturesClientHello>>,
    pub(crate) finalizer: Option<Arc<dyn FinalizesClientHello>>,
    pub(crate) fixed_x25519: Option<FixedX25519KeyShare>,
    pub(crate) extension_order: Option<ClientHelloExtensionOrder>,
    pub(crate) extensions: Option<ClientHelloExtensionPlan>,
    pub(crate) forced_extensions: Option<ClientHelloForcedExtensions>,
    pub(crate) alpn_protocols: Option<ClientHelloAlpnProtocols>,
    pub(crate) cipher_suites: Option<ClientHelloCipherSuites>,
    pub(crate) advertised_cipher_suites: Option<ClientHelloAdvertisedCipherSuites>,
    pub(crate) advertised_supported_versions: Option<ClientHelloAdvertisedSupportedVersions>,
    pub(crate) supported_versions: Option<ClientHelloSupportedVersions>,
    pub(crate) advertised_supported_groups: Option<ClientHelloAdvertisedSupportedGroups>,
    pub(crate) supported_groups: Option<ClientHelloSupportedGroups>,
    pub(crate) key_share_plan: Option<ClientHelloKeySharePlan>,
    pub(crate) raw_key_shares: Option<ClientHelloRawKeyShares>,
    pub(crate) signature_algorithms: Option<ClientHelloSignatureAlgorithms>,
    pub(crate) certificate_compression_algorithms:
        Option<ClientHelloCertificateCompressionAlgorithms>,
    pub(crate) exact_extensions: Option<ClientHelloExactExtensions>,
    pub(crate) raw_extensions: Option<ClientHelloRawExtensions>,
    pub(crate) grease: Option<ClientHelloGreasePlan>,
    pub(crate) grease_ech: Option<EchGreaseConfig>,
    pub(crate) padding: Option<ClientHelloPaddingPlan>,
}

impl ClientHelloPlan {
    /// Create an empty customization plan.
    ///
    /// An empty plan applies no shaping controls.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use fixed ClientHello random bytes.
    pub fn with_random(mut self, random: [u8; 32]) -> Self {
        self.random = Some(random);
        self
    }

    /// Use a fixed legacy session id.
    pub fn with_session_id(mut self, session_id: ClientHelloSessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Capture the final encoded ClientHello.
    pub fn with_capture(mut self, capture: Arc<dyn CapturesClientHello>) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Finalize the encoded ClientHello before capture, transcript, and write.
    ///
    /// This is intended for REALITY-style session id sealing. It is not
    /// supported with active TLS 1.3 PSK binders/resumption.
    pub fn with_finalizer(mut self, finalizer: Arc<dyn FinalizesClientHello>) -> Self {
        self.finalizer = Some(finalizer);
        self
    }

    /// Use fixed X25519 key share material.
    pub fn with_fixed_x25519(mut self, key_share: FixedX25519KeyShare) -> Self {
        self.fixed_x25519 = Some(key_share);
        self
    }

    /// Use an explicit ClientHello extension order.
    pub fn with_extension_order(mut self, order: ClientHelloExtensionOrder) -> Self {
        self.extension_order = Some(order);
        self
    }

    /// Use structured ClientHello extension presence controls.
    pub fn with_extensions(mut self, extensions: ClientHelloExtensionPlan) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Use structured controls for forcing known ClientHello extensions.
    pub fn with_forced_extensions(mut self, extensions: ClientHelloForcedExtensions) -> Self {
        self.forced_extensions = Some(extensions);
        self
    }

    /// Use an explicit ALPN protocol list and order.
    pub fn with_alpn_protocols(mut self, protocols: ClientHelloAlpnProtocols) -> Self {
        self.alpn_protocols = Some(protocols);
        self
    }

    /// Use an explicit cipher suite list and order.
    pub fn with_cipher_suites(mut self, cipher_suites: ClientHelloCipherSuites) -> Self {
        self.cipher_suites = Some(cipher_suites);
        self
    }

    /// Use an explicit advertised cipher suite list and order.
    ///
    /// This affects only the serialized ClientHello. It does not add cipher
    /// suite implementations to the configured crypto provider.
    pub fn with_advertised_cipher_suites(
        mut self,
        cipher_suites: ClientHelloAdvertisedCipherSuites,
    ) -> Self {
        self.advertised_cipher_suites = Some(cipher_suites);
        self
    }

    /// Use an explicit advertised supported_versions list and order.
    ///
    /// This affects only the serialized ClientHello extension. It does not
    /// enable protocol versions that are not enabled in the rustls config.
    pub fn with_advertised_supported_versions(
        mut self,
        versions: ClientHelloAdvertisedSupportedVersions,
    ) -> Self {
        self.advertised_supported_versions = Some(versions);
        self
    }

    /// Use an explicit supported_versions list and order.
    pub fn with_supported_versions(mut self, versions: ClientHelloSupportedVersions) -> Self {
        self.supported_versions = Some(versions);
        self
    }

    /// Use an explicit advertised supported_groups list and order.
    ///
    /// This affects only the serialized ClientHello extension. It does not add
    /// key exchange implementations to the configured crypto provider.
    pub fn with_advertised_supported_groups(
        mut self,
        groups: ClientHelloAdvertisedSupportedGroups,
    ) -> Self {
        self.advertised_supported_groups = Some(groups);
        self
    }

    /// Use an explicit supported_groups list and order.
    pub fn with_supported_groups(mut self, groups: ClientHelloSupportedGroups) -> Self {
        self.supported_groups = Some(groups);
        self
    }

    /// Use an explicit key_share group list and order.
    pub fn with_key_share_plan(mut self, key_share_plan: ClientHelloKeySharePlan) -> Self {
        self.key_share_plan = Some(key_share_plan);
        self
    }

    /// Add raw key_share entries to the serialized ClientHello.
    pub fn with_raw_key_shares(mut self, key_shares: ClientHelloRawKeyShares) -> Self {
        self.raw_key_shares = Some(key_shares);
        self
    }

    /// Use an explicit signature_algorithms list and order.
    pub fn with_signature_algorithms(
        mut self,
        signature_algorithms: ClientHelloSignatureAlgorithms,
    ) -> Self {
        self.signature_algorithms = Some(signature_algorithms);
        self
    }

    /// Use an explicit compress_certificate algorithm list and order.
    pub fn with_certificate_compression_algorithms(
        mut self,
        algorithms: ClientHelloCertificateCompressionAlgorithms,
    ) -> Self {
        self.certificate_compression_algorithms = Some(algorithms);
        self
    }

    /// Add exact known ClientHello extension payloads.
    pub fn with_exact_extensions(mut self, extensions: ClientHelloExactExtensions) -> Self {
        self.exact_extensions = Some(extensions);
        self
    }

    /// Add raw unknown ClientHello extensions.
    pub fn with_raw_extensions(mut self, extensions: ClientHelloRawExtensions) -> Self {
        self.raw_extensions = Some(extensions);
        self
    }

    /// Use explicit GREASE insertion controls.
    pub fn with_grease(mut self, grease: ClientHelloGreasePlan) -> Self {
        self.grease = Some(grease);
        self
    }

    /// Add a GREASE encrypted_client_hello extension.
    ///
    /// This is a per-ClientHello shaping control and does not enable real ECH
    /// for the connection.
    pub fn with_grease_ech(mut self, grease_ech: EchGreaseConfig) -> Self {
        self.grease_ech = Some(grease_ech);
        self
    }

    /// Use explicit ClientHello padding extension controls.
    pub fn with_padding(mut self, padding: ClientHelloPaddingPlan) -> Self {
        self.padding = Some(padding);
        self
    }
}
