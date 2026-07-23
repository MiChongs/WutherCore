use std::{
    fmt,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        CapturesClientHello, ClientHelloAdvertisedCipherSuites,
        ClientHelloAdvertisedSupportedGroups, ClientHelloAdvertisedSupportedVersions,
        ClientHelloAlpnProtocols, ClientHelloCertificateCompressionAlgorithms, ClientHelloContext,
        ClientHelloCustomizer, ClientHelloExactExtension, ClientHelloExactExtensions,
        ClientHelloExtensionOrder, ClientHelloExtensionPlan, ClientHelloForcedExtensions,
        ClientHelloGreaseExtension, ClientHelloGreasePlan, ClientHelloKeySharePlan,
        ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension, ClientHelloRawExtensions,
        ClientHelloRawKeyShare, ClientHelloRawKeyShares, ClientHelloSessionId,
        ClientHelloSupportedGroups, ClientHelloSupportedVersions, FinalizesClientHello,
        FixedX25519KeyShare,
    },
    crypto::{self, CryptoProvider, GetRandomFailed},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateCompressionAlgorithm, CertificateError, CipherSuite, ClientConfig, ClientConnection,
    DigitallySignedStruct, Error as RustlsError, NamedGroup, ProtocolVersion, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use zeroize::Zeroize;

use crate::{
    reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata,
        validate_reality_fingerprint, verify_reality_certificate_der_with_mldsa65, RealityError,
        RealityHandshakeInput, RealityMldsa65CertificateInput, RealityPreparedClientHello,
    },
    reality_connector::{
        RealityClientHelloRequest, RealityTlsSession, RealityTlsSessionOutcome,
        RealityTlsSessionProvider,
    },
    reality_utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile},
    BoxedTransportStream, CapturedTcpStream, PenetratingTlsStream, ServerReadLog, TransportError,
};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_VERIFICATION_UNKNOWN: u8 = 0;
const REALITY_VERIFICATION_VERIFIED: u8 = 1;
const REALITY_VERIFICATION_NOT_REALITY: u8 = 2;
const TLS_CLIENT_HELLO_SESSION_ID_OFFSET: usize = 39;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_CERTIFICATE_COMPRESSION: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const TLS_VERSION_1_3: u16 = 0x0304;
const BROTLI_CERTIFICATE_COMPRESSION: u16 = 0x0002;
const BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE: usize = 512;
const STRUCTURED_OPTIONAL_EXTENSIONS: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_CERTIFICATE_COMPRESSION,
    EXT_SESSION_TICKET,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RENEGOTIATION_INFO,
];

#[derive(Debug, Clone, Default)]
pub struct RustlsRealityTlsSessionProvider;

impl RustlsRealityTlsSessionProvider {
    pub fn new() -> Self {
        Self
    }
}

impl RealityTlsSessionProvider for RustlsRealityTlsSessionProvider {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, RealityError> {
        validate_reality_fingerprint(request.fingerprint)?;

        let plan = RustlsRealityPlan::random().map_err(|_| {
            RealityError::ClientHelloGenerationFailed(
                "failed to fill REALITY handshake entropy".to_owned(),
            )
        })?;
        let prepared = plan.prepare_client_hello(request)?;

        Ok(Box::new(RustlsRealityTlsSession {
            server_name: request.server_name.to_owned(),
            fingerprint: request.fingerprint.to_owned(),
            plan,
            prepared_client_hello: prepared,
        }))
    }
}

#[derive(Clone)]
struct RustlsRealityPlan {
    hello_random: [u8; 32],
    local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RustlsRealityPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityPlan")
            .field("hello_random", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RustlsRealityPlan {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
    }
}

impl RustlsRealityPlan {
    fn random() -> Result<Self, GetRandomFailed> {
        let mut hello_random = [0; 32];
        let mut local_x25519_private_key = [0; 32];
        let secure_random = crypto::ring::default_provider().secure_random;

        secure_random.fill(&mut hello_random)?;
        secure_random.fill(&mut local_x25519_private_key)?;

        let plan = Self {
            hello_random,
            local_x25519_private_key,
        };
        local_x25519_private_key.zeroize();

        Ok(plan)
    }

    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, RealityError> {
        let raw_client_hello = self
            .client_hello_message(
                request.server_name,
                request.fingerprint,
                [0; REALITY_SESSION_ID_LEN],
                [0; 32],
            )
            .map_err(|error| RealityError::ClientHelloGenerationFailed(error.to_string()))?;
        let prepared = RealityPreparedClientHello {
            fingerprint: request.fingerprint.to_owned(),
            raw_client_hello,
            hello_random: self.hello_random,
            session_id_offset: TLS_CLIENT_HELLO_SESSION_ID_OFFSET,
            local_x25519_private_key: self.local_x25519_private_key,
        };
        let validation = validate_reality_client_hello_metadata(&prepared)?;

        debug_assert_eq!(
            validation.session_id_offset,
            TLS_CLIENT_HELLO_SESSION_ID_OFFSET
        );

        Ok(prepared)
    }

    fn client_hello_message(
        &self,
        server_name: &str,
        fingerprint: &str,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        auth_key: [u8; 32],
    ) -> Result<Vec<u8>, TransportError> {
        self.client_hello_message_inner(server_name, fingerprint, session_id, auth_key, None)
    }

    #[cfg(test)]
    fn client_hello_message_with_finalizer(
        &self,
        server_name: &str,
        fingerprint: &str,
        finalizer: Arc<dyn FinalizesClientHello>,
    ) -> Result<Vec<u8>, TransportError> {
        self.client_hello_message_inner(
            server_name,
            fingerprint,
            [0; REALITY_SESSION_ID_LEN],
            [0; 32],
            Some(finalizer),
        )
    }

    fn client_hello_message_inner(
        &self,
        server_name: &str,
        fingerprint: &str,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        auth_key: [u8; 32],
        finalizer: Option<Arc<dyn FinalizesClientHello>>,
    ) -> Result<Vec<u8>, TransportError> {
        let profile = profile_for_fingerprint(fingerprint).ok_or_else(|| {
            TransportError::TlsConfig(format!(
                "unsupported REALITY uTLS fingerprint profile: {fingerprint}"
            ))
        })?;
        let capture = Arc::new(RealityClientHelloCapture::default());
        let customizer = Arc::new(RustlsRealityClientHelloCustomizer::new(
            self,
            profile,
            session_id,
            Some(capture.clone()),
            finalizer,
        ));
        let config = reality_client_config(
            RealityVerificationMaterial::Static {
                auth_key,
                client_hello: None,
            },
            None,
            None,
            Some(customizer),
            profile_uses_structured_certificate_compression(profile),
        )?;
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TransportError::InvalidTlsServerName(server_name.to_owned()))?;
        let mut connection =
            ClientConnection::new(Arc::new(config), server_name).map_err(rustls_config_error)?;
        let mut record = Vec::new();
        connection
            .write_tls(&mut record)
            .map_err(TransportError::Tcp)?;

        capture.take()
    }
}

#[derive(Debug, Default)]
struct RealityClientHelloCapture {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl RealityClientHelloCapture {
    fn take(&self) -> Result<Vec<u8>, TransportError> {
        let mut bytes = self.bytes.lock().map_err(|_| {
            TransportError::TlsConfig("REALITY ClientHello capture lock was poisoned".to_owned())
        })?;
        bytes.take().ok_or_else(|| {
            TransportError::TlsConfig("rustls did not capture a REALITY ClientHello".to_owned())
        })
    }
}

impl CapturesClientHello for RealityClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), RustlsError> {
        let mut captured = self.bytes.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello capture lock was poisoned".to_owned())
        })?;
        *captured = Some(bytes.to_vec());
        Ok(())
    }
}

struct RustlsRealityClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    hello_random: [u8; 32],
    session_id: [u8; REALITY_SESSION_ID_LEN],
    local_x25519_private_key: [u8; 32],
    capture: Option<Arc<RealityClientHelloCapture>>,
    finalizer: Option<Arc<dyn FinalizesClientHello>>,
}

impl RustlsRealityClientHelloCustomizer {
    fn new(
        plan: &RustlsRealityPlan,
        profile: &'static UtlsClientHelloProfile,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        capture: Option<Arc<RealityClientHelloCapture>>,
        finalizer: Option<Arc<dyn FinalizesClientHello>>,
    ) -> Self {
        Self {
            profile,
            hello_random: plan.hello_random,
            session_id,
            local_x25519_private_key: plan.local_x25519_private_key,
            capture,
            finalizer,
        }
    }
}

impl fmt::Debug for RustlsRealityClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityClientHelloCustomizer")
            .field("profile", &self.profile)
            .field("hello_random", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .field("capture", &self.capture.is_some())
            .field("finalizer", &self.finalizer.is_some())
            .finish()
    }
}

impl Drop for RustlsRealityClientHelloCustomizer {
    fn drop(&mut self) {
        self.hello_random.zeroize();
        self.session_id.zeroize();
        self.local_x25519_private_key.zeroize();
    }
}

impl ClientHelloCustomizer for RustlsRealityClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let session_id = ClientHelloSessionId::try_from(self.session_id.to_vec())?;
        let mut plan = ClientHelloPlan::new()
            .with_random(self.hello_random)
            .with_session_id(session_id)
            .with_fixed_x25519(FixedX25519KeyShare::new(self.local_x25519_private_key));

        plan = apply_utls_profile(plan, self.profile)?;

        if let Some(capture) = &self.capture {
            plan = plan.with_capture(capture.clone());
        }
        if let Some(finalizer) = &self.finalizer {
            plan = plan.with_finalizer(finalizer.clone());
        }

        Ok(Some(plan))
    }
}

#[derive(Clone)]
struct RealityFinalizedClientHello {
    auth_key: [u8; 32],
    session_id: [u8; REALITY_SESSION_ID_LEN],
    client_hello: Vec<u8>,
}

impl fmt::Debug for RealityFinalizedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFinalizedClientHello")
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("client_hello_len", &self.client_hello.len())
            .finish()
    }
}

impl Drop for RealityFinalizedClientHello {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.session_id.zeroize();
        self.client_hello.zeroize();
    }
}

#[derive(Default)]
struct RealityFinalizedClientHelloState {
    finalized: Mutex<Option<RealityFinalizedClientHello>>,
}

impl fmt::Debug for RealityFinalizedClientHelloState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFinalizedClientHelloState")
            .finish_non_exhaustive()
    }
}

impl RealityFinalizedClientHelloState {
    fn store(&self, finalized: RealityFinalizedClientHello) -> Result<(), RustlsError> {
        let mut stored = self.finalized.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello finalizer state lock was poisoned".to_owned())
        })?;
        if stored.is_some() {
            return Err(RustlsError::General(
                "REALITY ClientHello finalizer ran more than once".to_owned(),
            ));
        }
        *stored = Some(finalized);
        Ok(())
    }

    fn snapshot(&self) -> Result<RealityFinalizedClientHello, RustlsError> {
        let stored = self.finalized.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello finalizer state lock was poisoned".to_owned())
        })?;
        stored.as_ref().cloned().ok_or_else(|| {
            RustlsError::General("REALITY ClientHello finalizer did not run".to_owned())
        })
    }
}

struct RustlsRealityClientHelloFinalizer {
    fingerprint: String,
    hello_random: [u8; 32],
    local_x25519_private_key: [u8; 32],
    version: [u8; 3],
    unix_time: u32,
    short_id: Vec<u8>,
    server_public_key: [u8; 32],
    finalized_state: Arc<RealityFinalizedClientHelloState>,
}

impl RustlsRealityClientHelloFinalizer {
    fn new(
        plan: &RustlsRealityPlan,
        fingerprint: &str,
        prepared: &crate::reality::RealityPreparedHandshake,
        finalized_state: Arc<RealityFinalizedClientHelloState>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.to_owned(),
            hello_random: plan.hello_random,
            local_x25519_private_key: plan.local_x25519_private_key,
            version: prepared.version,
            unix_time: prepared.unix_time,
            short_id: prepared.short_id.clone(),
            server_public_key: prepared.server_public_key,
            finalized_state,
        }
    }
}

impl fmt::Debug for RustlsRealityClientHelloFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityClientHelloFinalizer")
            .field("fingerprint", &self.fingerprint)
            .field("hello_random", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl Drop for RustlsRealityClientHelloFinalizer {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
        self.short_id.zeroize();
    }
}

impl FinalizesClientHello for RustlsRealityClientHelloFinalizer {
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> Result<(), RustlsError> {
        let prepared = prepare_reality_handshake(RealityHandshakeInput {
            version: self.version,
            unix_time: self.unix_time,
            short_id: self.short_id.clone(),
            server_public_key: self.server_public_key,
            prepared_client_hello: RealityPreparedClientHello {
                fingerprint: self.fingerprint.clone(),
                raw_client_hello: bytes.clone(),
                hello_random: self.hello_random,
                session_id_offset: TLS_CLIENT_HELLO_SESSION_ID_OFFSET,
                local_x25519_private_key: self.local_x25519_private_key,
            },
        })
        .map_err(|error| {
            RustlsError::General(format!("REALITY ClientHello finalization failed: {error}"))
        })?;

        if prepared.patched_client_hello.len() != bytes.len() {
            return Err(RustlsError::General(
                "REALITY ClientHello finalizer changed ClientHello length".to_owned(),
            ));
        }

        let finalized_client_hello = prepared.patched_client_hello.clone();
        bytes.copy_from_slice(&finalized_client_hello);
        self.finalized_state.store(RealityFinalizedClientHello {
            auth_key: prepared.auth_key,
            session_id: prepared.session_id,
            client_hello: finalized_client_hello,
        })
    }
}

fn apply_utls_profile(
    mut plan: ClientHelloPlan,
    profile: &'static UtlsClientHelloProfile,
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan
        .with_advertised_cipher_suites(advertised_cipher_suites(profile)?)
        .with_supported_versions(supported_versions(profile)?);

    if !profile.supported_versions.is_empty() {
        plan = plan.with_advertised_supported_versions(advertised_supported_versions(profile)?);
    }
    if !profile.supported_groups.is_empty() {
        plan = plan.with_supported_groups(supported_groups(profile)?);
        plan = plan.with_advertised_supported_groups(advertised_supported_groups(profile)?);
    }
    if !profile.key_shares.is_empty() {
        plan = plan.with_key_share_plan(key_share_plan(profile)?);
    }
    if let Some(raw_key_shares) = raw_key_shares(profile)? {
        plan = plan.with_raw_key_shares(raw_key_shares);
    }
    if !profile.alpn_protocols.is_empty() {
        plan = plan.with_alpn_protocols(alpn_protocols(profile)?);
    }
    if profile_uses_structured_certificate_compression(profile) {
        plan = plan.with_certificate_compression_algorithms(certificate_compression(profile)?);
    }

    let forced_extensions = forced_extensions(profile);
    let extension_plan = extension_plan(profile)?;
    let (exact_extensions, raw_extensions) = extension_payloads(profile)?;

    plan = plan
        .with_forced_extensions(forced_extensions)
        .with_extensions(extension_plan);
    if !profile.supported_versions.is_empty() {
        plan = plan.with_extension_order(extension_order(profile)?);
    }

    if let Some(exact_extensions) = exact_extensions {
        plan = plan.with_exact_extensions(exact_extensions);
    }
    if let Some(raw_extensions) = raw_extensions {
        plan = plan.with_raw_extensions(raw_extensions);
    }
    if let Some(grease) = grease_plan(profile)? {
        plan = plan.with_grease(grease);
    }
    if profile.padding_length.is_some() {
        plan = plan.with_padding(ClientHelloPaddingPlan::pad_to_handshake_size(
            BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE,
        )?);
    }

    Ok(plan)
}

fn advertised_cipher_suites(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAdvertisedCipherSuites, RustlsError> {
    ClientHelloAdvertisedCipherSuites::try_from(
        profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease_value(*suite))
            .map(CipherSuite::from)
            .collect::<Vec<_>>(),
    )
}

fn supported_versions(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedVersions, RustlsError> {
    let versions = if profile.supported_versions.contains(&TLS_VERSION_1_3) {
        vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
    } else {
        vec![ProtocolVersion::TLSv1_2]
    };
    ClientHelloSupportedVersions::try_from(versions)
}

fn advertised_supported_versions(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAdvertisedSupportedVersions, RustlsError> {
    ClientHelloAdvertisedSupportedVersions::try_from(
        profile
            .supported_versions
            .iter()
            .copied()
            .map(ProtocolVersion::from)
            .collect::<Vec<_>>(),
    )
}

fn supported_groups(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedGroups, RustlsError> {
    let mut groups = Vec::new();
    for group in profile.supported_groups {
        if let Some(group) = real_supported_group(*group) {
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
    }
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloSupportedGroups::try_from(groups)
}

fn advertised_supported_groups(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAdvertisedSupportedGroups, RustlsError> {
    ClientHelloAdvertisedSupportedGroups::try_from(
        profile
            .supported_groups
            .iter()
            .copied()
            .map(NamedGroup::from)
            .collect::<Vec<_>>(),
    )
}

fn key_share_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloKeySharePlan, RustlsError> {
    let mut groups = Vec::new();
    for key_share in profile.key_shares {
        if let Some(group) = real_key_share_group(key_share.group) {
            groups.push(group);
        }
    }
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloKeySharePlan::try_from(groups)
}

fn raw_key_shares(
    profile: &UtlsClientHelloProfile,
) -> Result<Option<ClientHelloRawKeyShares>, RustlsError> {
    let mut raw_key_shares = Vec::new();
    let mut non_grease_position = 0;

    for key_share in profile.key_shares {
        if is_grease_value(key_share.group) {
            continue;
        }

        if real_key_share_group(key_share.group).is_some() {
            non_grease_position += 1;
            continue;
        }

        raw_key_shares.push(ClientHelloRawKeyShare::new_at(
            non_grease_position,
            NamedGroup::from(key_share.group),
            vec![0; key_share.key_exchange_len],
        )?);
        non_grease_position += 1;
    }

    if raw_key_shares.is_empty() {
        Ok(None)
    } else {
        ClientHelloRawKeyShares::try_from(raw_key_shares).map(Some)
    }
}

fn alpn_protocols(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAlpnProtocols, RustlsError> {
    ClientHelloAlpnProtocols::try_from(
        profile
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect::<Vec<_>>(),
    )
}

fn certificate_compression(
    _profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloCertificateCompressionAlgorithms, RustlsError> {
    ClientHelloCertificateCompressionAlgorithms::try_from(vec![
        CertificateCompressionAlgorithm::Brotli,
    ])
}

fn extension_order(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloExtensionOrder, RustlsError> {
    ClientHelloExtensionOrder::try_from(
        profile
            .extensions
            .iter()
            .map(|extension| extension.extension_type)
            .filter(|extension_type| !is_grease_value(*extension_type))
            .collect::<Vec<_>>(),
    )
}

fn extension_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloExtensionPlan, RustlsError> {
    let disabled = STRUCTURED_OPTIONAL_EXTENSIONS
        .iter()
        .copied()
        .filter(|extension_type| !profile_has_extension(profile, *extension_type))
        .filter(|extension_type| {
            *extension_type != EXT_CERTIFICATE_COMPRESSION
                || !profile_uses_structured_certificate_compression(profile)
        })
        .collect::<Vec<_>>();

    ClientHelloExtensionPlan::try_from(disabled)
}

fn forced_extensions(profile: &UtlsClientHelloProfile) -> ClientHelloForcedExtensions {
    let mut forced = ClientHelloForcedExtensions::new();
    if profile_has_extension(profile, EXT_RENEGOTIATION_INFO) {
        forced = forced.with_renegotiation_info_empty();
    }
    if profile_has_extension(profile, EXT_SESSION_TICKET) {
        forced = forced.with_session_ticket_request();
    }
    if profile_has_extension(profile, EXT_SIGNED_CERTIFICATE_TIMESTAMP) {
        forced = forced.with_signed_certificate_timestamp_empty();
    }
    forced
}

fn extension_payloads(
    profile: &UtlsClientHelloProfile,
) -> Result<
    (
        Option<ClientHelloExactExtensions>,
        Option<ClientHelloRawExtensions>,
    ),
    RustlsError,
> {
    let mut exact_extensions = Vec::new();
    let mut raw_extensions = Vec::new();

    if profile_has_extension(profile, EXT_SIGNATURE_ALGORITHMS) {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_SIGNATURE_ALGORITHMS,
            signature_algorithms_payload(profile.signature_algorithms)?,
        )?);
    }
    if profile_has_extension(profile, EXT_DELEGATED_CREDENTIALS) {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            EXT_DELEGATED_CREDENTIALS,
            signature_algorithms_payload(profile.delegated_credentials_algorithms)?,
        )?;
    }
    if !profile_uses_structured_certificate_compression(profile)
        && profile_has_extension(profile, EXT_CERTIFICATE_COMPRESSION)
    {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_CERTIFICATE_COMPRESSION,
            certificate_compression_payload(profile.certificate_compression_algorithms)?,
        )?);
    }
    if let Some(record_size_limit) = profile.record_size_limit {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            EXT_RECORD_SIZE_LIMIT,
            record_size_limit.to_be_bytes().to_vec(),
        )?;
    }
    if let Some(length) = profile.encrypted_client_hello_length {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_ENCRYPTED_CLIENT_HELLO,
            encrypted_client_hello_payload(length)?,
        )?);
    }
    for application_settings in profile.application_settings {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            application_settings.extension_type,
            application_settings_payload(application_settings.protocols)?,
        )?;
    }
    for extension in profile.extensions {
        if is_grease_value(extension.extension_type)
            || is_structured_extension(profile, extension.extension_type)
            || extension.extension_type == EXT_SIGNATURE_ALGORITHMS
            || extension.extension_type == EXT_DELEGATED_CREDENTIALS
            || extension.extension_type == EXT_CERTIFICATE_COMPRESSION
            || extension.extension_type == EXT_RECORD_SIZE_LIMIT
            || extension.extension_type == EXT_ENCRYPTED_CLIENT_HELLO
            || profile
                .application_settings
                .iter()
                .any(|settings| settings.extension_type == extension.extension_type)
        {
            continue;
        }

        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            extension.extension_type,
            vec![0; extension.payload_len],
        )?;
    }

    let exact_extensions = if exact_extensions.is_empty() {
        None
    } else {
        Some(ClientHelloExactExtensions::try_from(exact_extensions)?)
    };
    let raw_extensions = if raw_extensions.is_empty() {
        None
    } else {
        Some(ClientHelloRawExtensions::try_from(raw_extensions)?)
    };

    Ok((exact_extensions, raw_extensions))
}

fn encrypted_client_hello_payload(length: usize) -> Result<Vec<u8>, RustlsError> {
    // The finalizer path reparses ClientHello, so the ECH GREASE placeholder
    // must be syntactically valid even though it remains opaque filler.
    const OUTER_TYPE: u8 = 0;
    const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
    const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
    const CONFIG_ID: u8 = 0;
    const MIN_OUTER_LEN: usize = 11;

    if length < MIN_OUTER_LEN {
        return Err(RustlsError::General(
            "encrypted_client_hello payload is too short".into(),
        ));
    }

    let encrypted_payload_len = length - 10;
    let encrypted_payload_len = u16::try_from(encrypted_payload_len).map_err(|_| {
        RustlsError::General("encrypted_client_hello payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(length);
    payload.push(OUTER_TYPE);
    payload.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    payload.extend_from_slice(&HPKE_AEAD_AES_128_GCM.to_be_bytes());
    payload.push(CONFIG_ID);
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&encrypted_payload_len.to_be_bytes());
    payload.resize(length, 0);
    Ok(payload)
}

fn grease_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<Option<ClientHelloGreasePlan>, RustlsError> {
    let grease_value = profile
        .cipher_suites
        .iter()
        .chain(profile.key_shares.iter().map(|key_share| &key_share.group))
        .chain(
            profile
                .extensions
                .iter()
                .map(|extension| &extension.extension_type),
        )
        .copied()
        .find(|value| is_grease_value(*value));
    let Some(grease_value) = grease_value else {
        return Ok(None);
    };

    let mut grease = ClientHelloGreasePlan::new(grease_value)?;
    if let Some(position) = profile
        .cipher_suites
        .iter()
        .position(|suite| is_grease_value(*suite))
    {
        grease = grease.with_cipher_suite_position(position);
    }
    if let Some(position) = profile
        .key_shares
        .iter()
        .position(|key_share| is_grease_value(key_share.group))
    {
        grease = grease.with_key_share_position(position);
    }
    let mut non_grease_position = 0;
    for extension in profile.extensions {
        if is_grease_value(extension.extension_type) {
            grease = grease.with_extension(ClientHelloGreaseExtension::new(
                extension.extension_type,
                non_grease_position,
                vec![0; extension.payload_len],
            )?)?;
        } else {
            non_grease_position += 1;
        }
    }

    Ok(Some(grease))
}

fn signature_algorithms_payload(algorithms: &[u16]) -> Result<Vec<u8>, RustlsError> {
    let byte_len = algorithms
        .len()
        .checked_mul(2)
        .ok_or_else(|| RustlsError::General("signature_algorithms payload is too large".into()))?;
    let byte_len = u16::try_from(byte_len).map_err(|_| {
        RustlsError::General("signature_algorithms payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(byte_len));
    payload.extend_from_slice(&byte_len.to_be_bytes());
    for algorithm in algorithms {
        payload.extend_from_slice(&algorithm.to_be_bytes());
    }
    Ok(payload)
}

fn certificate_compression_payload(algorithms: &[u16]) -> Result<Vec<u8>, RustlsError> {
    let byte_len = algorithms
        .len()
        .checked_mul(2)
        .ok_or_else(|| RustlsError::General("compress_certificate payload is too large".into()))?;
    let byte_len = u8::try_from(byte_len).map_err(|_| {
        RustlsError::General("compress_certificate payload cannot exceed 255 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(1 + usize::from(byte_len));
    payload.push(byte_len);
    for algorithm in algorithms {
        payload.extend_from_slice(&algorithm.to_be_bytes());
    }
    Ok(payload)
}

fn application_settings_payload(protocols: &[&[u8]]) -> Result<Vec<u8>, RustlsError> {
    let protocols_len = protocols.iter().try_fold(0usize, |total, protocol| {
        if protocol.len() > usize::from(u8::MAX) {
            return Err(RustlsError::General(
                "application_settings protocol name cannot exceed 255 bytes".into(),
            ));
        }
        total
            .checked_add(1 + protocol.len())
            .ok_or_else(|| RustlsError::General("application_settings payload is too large".into()))
    })?;
    let protocols_len = u16::try_from(protocols_len).map_err(|_| {
        RustlsError::General("application_settings payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(protocols_len));
    payload.extend_from_slice(&protocols_len.to_be_bytes());
    for protocol in protocols {
        payload.push(protocol.len() as u8);
        payload.extend_from_slice(protocol);
    }
    Ok(payload)
}

fn push_exact_or_raw_extension(
    exact_extensions: &mut Vec<ClientHelloExactExtension>,
    raw_extensions: &mut Vec<ClientHelloRawExtension>,
    extension_type: u16,
    payload: Vec<u8>,
) -> Result<(), RustlsError> {
    match ClientHelloRawExtension::new(extension_type, payload.clone()) {
        Ok(extension) => {
            raw_extensions.push(extension);
            Ok(())
        }
        Err(_) => {
            exact_extensions.push(ClientHelloExactExtension::new(extension_type, payload)?);
            Ok(())
        }
    }
}

fn is_structured_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    matches!(
        extension_type,
        EXT_SERVER_NAME
            | EXT_STATUS_REQUEST
            | EXT_SUPPORTED_GROUPS
            | EXT_EC_POINT_FORMATS
            | EXT_ALPN
            | EXT_SIGNED_CERTIFICATE_TIMESTAMP
            | EXT_PADDING
            | EXT_EXTENDED_MASTER_SECRET
            | EXT_SESSION_TICKET
            | EXT_SUPPORTED_VERSIONS
            | EXT_PSK_KEY_EXCHANGE_MODES
            | EXT_KEY_SHARE
            | EXT_RENEGOTIATION_INFO
    ) || extension_type == EXT_CERTIFICATE_COMPRESSION
        && profile_uses_structured_certificate_compression(profile)
}

fn profile_has_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    profile
        .extensions
        .iter()
        .any(|extension| extension.extension_type == extension_type)
}

fn profile_uses_structured_certificate_compression(profile: &UtlsClientHelloProfile) -> bool {
    profile.certificate_compression_algorithms == [BROTLI_CERTIFICATE_COMPRESSION]
}

fn real_supported_group(group: u16) -> Option<NamedGroup> {
    match group {
        GROUP_X25519 => Some(NamedGroup::X25519),
        GROUP_X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        GROUP_X25519_MLKEM768_DRAFT => Some(NamedGroup::Unknown(GROUP_X25519_MLKEM768_DRAFT)),
        GROUP_SECP256R1 => Some(NamedGroup::secp256r1),
        GROUP_SECP384R1 => Some(NamedGroup::secp384r1),
        _ => None,
    }
}

fn real_key_share_group(group: u16) -> Option<NamedGroup> {
    match group {
        GROUP_X25519 => Some(NamedGroup::X25519),
        GROUP_X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        GROUP_X25519_MLKEM768_DRAFT => Some(NamedGroup::Unknown(GROUP_X25519_MLKEM768_DRAFT)),
        _ => None,
    }
}

fn is_grease_value(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

struct RustlsRealityTlsSession {
    server_name: String,
    fingerprint: String,
    plan: RustlsRealityPlan,
    prepared_client_hello: RealityPreparedClientHello,
}

impl fmt::Debug for RustlsRealityTlsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityTlsSession")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("plan", &self.plan)
            .finish()
    }
}

#[async_trait]
impl RealityTlsSession for RustlsRealityTlsSession {
    fn prepared_client_hello(&self) -> Result<RealityPreparedClientHello, RealityError> {
        Ok(RealityPreparedClientHello {
            fingerprint: self.prepared_client_hello.fingerprint.clone(),
            raw_client_hello: self.prepared_client_hello.raw_client_hello.clone(),
            hello_random: self.prepared_client_hello.hello_random,
            session_id_offset: self.prepared_client_hello.session_id_offset,
            local_x25519_private_key: self.plan.local_x25519_private_key,
        })
    }

    async fn complete_with_outcome(
        self: Box<Self>,
        tcp_stream: TcpStream,
        prepared: crate::reality::RealityPreparedHandshake,
        mldsa65_verify: Option<Vec<u8>>,
    ) -> Result<RealityTlsSessionOutcome, TransportError> {
        let profile = profile_for_fingerprint(&self.fingerprint).ok_or_else(|| {
            TransportError::TlsConfig(format!(
                "unsupported REALITY uTLS fingerprint profile: {}",
                self.fingerprint
            ))
        })?;
        let finalized_state = Arc::new(RealityFinalizedClientHelloState::default());
        let finalizer = Arc::new(RustlsRealityClientHelloFinalizer::new(
            &self.plan,
            &self.fingerprint,
            &prepared,
            finalized_state.clone(),
        ));

        let server_read_log = mldsa65_verify
            .as_ref()
            .map(|_| Arc::new(Mutex::new(Some(Vec::new()))));
        let mldsa65 = mldsa65_verify.map(|verifying_key| RealityMldsa65VerifierContext {
            verifying_key,
            server_read_log: server_read_log
                .as_ref()
                .expect("ML-DSA verifier has a server read log")
                .clone(),
        });
        let customizer = Arc::new(RustlsRealityClientHelloCustomizer::new(
            &self.plan,
            profile,
            [0; REALITY_SESSION_ID_LEN],
            None,
            Some(finalizer),
        ));
        let verification_outcome = Arc::new(AtomicU8::new(REALITY_VERIFICATION_UNKNOWN));
        let config = Arc::new(reality_client_config(
            RealityVerificationMaterial::Finalized(finalized_state),
            mldsa65,
            Some(verification_outcome.clone()),
            Some(customizer),
            profile_uses_structured_certificate_compression(profile),
        )?);
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(self.server_name.clone()))?;
        let connector = TokioTlsConnector::from(config);
        let tcp_stream = CapturedTcpStream::new(tcp_stream, server_read_log);
        let connect = connector.connect(server_name, tcp_stream);
        let stream = connect.await.map_err(TransportError::Tls)?;
        let stream: BoxedTransportStream = Box::new(PenetratingTlsStream::new(stream));

        match verification_outcome.load(Ordering::Acquire) {
            REALITY_VERIFICATION_VERIFIED => Ok(RealityTlsSessionOutcome::Verified(stream)),
            REALITY_VERIFICATION_NOT_REALITY => Ok(RealityTlsSessionOutcome::NotReality(stream)),
            _ => Err(TransportError::TlsConfig(
                "REALITY certificate verifier did not record an outcome".to_owned(),
            )),
        }
    }
}

fn reality_client_config(
    material: RealityVerificationMaterial,
    mldsa65: Option<RealityMldsa65VerifierContext>,
    verification_outcome: Option<Arc<AtomicU8>>,
    client_hello_customizer: Option<Arc<dyn ClientHelloCustomizer>>,
    certificate_compression: bool,
) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(reality_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let verifier = RealityServerVerifier {
        material,
        mldsa65,
        verification_outcome,
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    if !certificate_compression {
        config.cert_decompressors.clear();
    }
    config.resumption = rustls::client::Resumption::disabled();
    config.client_hello_customizer = client_hello_customizer;

    Ok(config)
}

fn reality_crypto_provider() -> CryptoProvider {
    let mut provider = crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        crypto::aws_lc_rs::kx_group::X25519KYBER768DRAFT00,
        crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        crypto::aws_lc_rs::kx_group::X25519,
        crypto::aws_lc_rs::kx_group::SECP256R1,
        crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    provider
}

fn extract_server_hello(records: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut record_offset = 0;
    while record_offset + TLS_RECORD_HEADER_LEN <= records.len() {
        let record_type = records[record_offset];
        let record_len =
            u16::from_be_bytes([records[record_offset + 3], records[record_offset + 4]]) as usize;
        let record_body_start = record_offset + TLS_RECORD_HEADER_LEN;
        let record_end = record_body_start
            .checked_add(record_len)
            .ok_or_else(|| TransportError::TlsConfig("TLS record length overflow".to_owned()))?;
        if record_end > records.len() {
            return Err(TransportError::TlsConfig(
                "truncated TLS server record".to_owned(),
            ));
        }

        if record_type == TLS_RECORD_HANDSHAKE {
            let mut handshake_offset = record_body_start;
            while handshake_offset + TLS_HANDSHAKE_HEADER_LEN <= record_end {
                let handshake_len = ((records[handshake_offset + 1] as usize) << 16)
                    | ((records[handshake_offset + 2] as usize) << 8)
                    | (records[handshake_offset + 3] as usize);
                let handshake_end = handshake_offset
                    .checked_add(TLS_HANDSHAKE_HEADER_LEN)
                    .and_then(|start| start.checked_add(handshake_len))
                    .ok_or_else(|| {
                        TransportError::TlsConfig("TLS handshake length overflow".to_owned())
                    })?;
                if handshake_end > record_end {
                    return Err(TransportError::TlsConfig(
                        "truncated TLS ServerHello handshake".to_owned(),
                    ));
                }
                if records[handshake_offset] == TLS_HANDSHAKE_SERVER_HELLO {
                    return Ok(records[handshake_offset..handshake_end].to_vec());
                }
                handshake_offset = handshake_end;
            }
        }

        record_offset = record_end;
    }

    Err(TransportError::TlsConfig(
        "TLS ServerHello record was not captured".to_owned(),
    ))
}

fn rustls_config_error(error: RustlsError) -> TransportError {
    TransportError::TlsConfig(error.to_string())
}

struct RealityVerificationSnapshot {
    auth_key: [u8; 32],
    client_hello: Vec<u8>,
}

impl Drop for RealityVerificationSnapshot {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.client_hello.zeroize();
    }
}

enum RealityVerificationMaterial {
    Static {
        auth_key: [u8; 32],
        client_hello: Option<Vec<u8>>,
    },
    Finalized(Arc<RealityFinalizedClientHelloState>),
}

impl fmt::Debug for RealityVerificationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static { client_hello, .. } => formatter
                .debug_struct("RealityVerificationMaterial::Static")
                .field("auth_key", &"<redacted>")
                .field("client_hello_len", &client_hello.as_ref().map(Vec::len))
                .finish(),
            Self::Finalized(_) => formatter
                .debug_struct("RealityVerificationMaterial::Finalized")
                .finish_non_exhaustive(),
        }
    }
}

impl Drop for RealityVerificationMaterial {
    fn drop(&mut self) {
        if let Self::Static {
            auth_key,
            client_hello,
        } = self
        {
            auth_key.zeroize();
            if let Some(client_hello) = client_hello {
                client_hello.zeroize();
            }
        }
    }
}

impl RealityVerificationMaterial {
    fn snapshot(&self) -> Result<RealityVerificationSnapshot, RustlsError> {
        match self {
            Self::Static {
                auth_key,
                client_hello,
            } => Ok(RealityVerificationSnapshot {
                auth_key: *auth_key,
                client_hello: client_hello.clone().unwrap_or_default(),
            }),
            Self::Finalized(finalized_state) => {
                let finalized = finalized_state.snapshot()?;
                Ok(RealityVerificationSnapshot {
                    auth_key: finalized.auth_key,
                    client_hello: finalized.client_hello.clone(),
                })
            }
        }
    }
}

struct RealityMldsa65VerifierContext {
    verifying_key: Vec<u8>,
    server_read_log: ServerReadLog,
}

impl fmt::Debug for RealityMldsa65VerifierContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityMldsa65VerifierContext")
            .field("verifying_key_len", &self.verifying_key.len())
            .finish()
    }
}

struct RealityServerVerifier {
    material: RealityVerificationMaterial,
    mldsa65: Option<RealityMldsa65VerifierContext>,
    verification_outcome: Option<Arc<AtomicU8>>,
}

impl fmt::Debug for RealityServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerVerifier")
            .field("material", &self.material)
            .field("mldsa65", &self.mldsa65)
            .field(
                "verification_outcome",
                &self
                    .verification_outcome
                    .as_ref()
                    .map(|outcome| outcome.load(Ordering::Relaxed)),
            )
            .finish()
    }
}

impl ServerCertVerifier for RealityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let material = self.material.snapshot()?;
        let server_hello;
        let mldsa65 = if let Some(mldsa65) = &self.mldsa65 {
            let captured = {
                let mut captured = mldsa65
                    .server_read_log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                captured.take().ok_or(RustlsError::InvalidCertificate(
                    CertificateError::BadEncoding,
                ))?
            };
            server_hello = extract_server_hello(&captured)
                .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
            Some(RealityMldsa65CertificateInput {
                verifying_key: &mldsa65.verifying_key,
                client_hello: &material.client_hello,
                server_hello: &server_hello,
            })
        } else {
            None
        };

        match verify_reality_certificate_der_with_mldsa65(
            &material.auth_key,
            end_entity.as_ref(),
            mldsa65,
        ) {
            Ok(crate::reality::RealityCertificateVerification::Verified) => {
                if let Some(outcome) = &self.verification_outcome {
                    outcome.store(REALITY_VERIFICATION_VERIFIED, Ordering::Release);
                }
                Ok(ServerCertVerified::assertion())
            }
            Ok(crate::reality::RealityCertificateVerification::NotReality) => {
                if let Some(outcome) = &self.verification_outcome {
                    outcome.store(REALITY_VERIFICATION_NOT_REALITY, Ordering::Release);
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(RustlsError::InvalidCertificate(
                        CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            Err(_) => Err(RustlsError::InvalidCertificate(
                CertificateError::BadEncoding,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let provider = crypto::ring::default_provider();
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    #[test]
    fn reality_client_hello_finalizer_seals_actual_chrome_client_hello() {
        let plan = RustlsRealityPlan::random()
            .expect("REALITY ClientHello plan should get random material");
        let server_secret = X25519StaticSecret::from([7u8; 32]);
        let server_public_key = X25519PublicKey::from(&server_secret).to_bytes();
        let prepared = crate::reality::RealityPreparedHandshake {
            patched_client_hello: Vec::new(),
            auth_key: [0; 32],
            session_id: [0; REALITY_SESSION_ID_LEN],
            version: [0, 0, 1],
            unix_time: 1_700_000_000,
            short_id: vec![0xaa, 0xbb, 0xcc],
            server_public_key,
        };
        let finalized_state = Arc::new(RealityFinalizedClientHelloState::default());
        let finalizer = Arc::new(RustlsRealityClientHelloFinalizer::new(
            &plan,
            "chrome",
            &prepared,
            finalized_state.clone(),
        ));

        let captured = plan
            .client_hello_message_with_finalizer("www.example.com", "chrome", finalizer)
            .expect("finalized ClientHello should be generated");
        let finalized = finalized_state
            .snapshot()
            .expect("finalizer should store verification material");

        assert_eq!(captured, finalized.client_hello);
        assert_eq!(
            &captured[TLS_CLIENT_HELLO_SESSION_ID_OFFSET
                ..TLS_CLIENT_HELLO_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN],
            finalized.session_id
        );
        assert_ne!(finalized.session_id, [0; REALITY_SESSION_ID_LEN]);
        assert_ne!(finalized.auth_key, [0; 32]);
    }
}
