//! Xray 26.7.11 compatible uTLS ClientHello shaping.

use std::{fmt, io, sync::Arc, sync::OnceLock};

use rand::{Rng, seq::SliceRandom};
use rustls::{
    CertificateCompressionAlgorithm, CipherSuite, Error as RustlsError, NamedGroup,
    ProtocolVersion,
    client::{
        ClientHelloAdvertisedCipherSuites, ClientHelloAdvertisedSupportedGroups,
        ClientHelloAdvertisedSupportedVersions, ClientHelloAlpnProtocols,
        ClientHelloCertificateCompressionAlgorithms, ClientHelloContext, ClientHelloCustomizer,
        ClientHelloExactExtension, ClientHelloExactExtensions, ClientHelloExtensionOrder,
        ClientHelloExtensionPlan, ClientHelloForcedExtensions, ClientHelloGreaseExtension,
        ClientHelloGreasePlan, ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan,
        ClientHelloRawExtension, ClientHelloRawExtensions, ClientHelloRawKeyShare,
        ClientHelloRawKeyShares, ClientHelloSupportedGroups, ClientHelloSupportedVersions,
    },
};

use super::utls_profiles::{
    UtlsApplicationSettings, UtlsClientHelloProfile, UtlsExtension, UtlsKeyShare,
    profile_for_fingerprint,
};

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EMS: u16 = 0x0017;
const EXT_CERT_COMPRESSION: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS: u16 = 0x4469;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION: u16 = 0xff01;

const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;
const GROUP_P384: u16 = 0x0018;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_KYBER_DRAFT: u16 = 0x6399;
const TLS13: u16 = 0x0304;
const TLS12: u16 = 0x0303;
const TLS10: u16 = 0x0301;
const BROTLI: u16 = 0x0002;
const BORING_PADDING_TARGET: usize = 512;

const STRUCTURED_OPTIONAL_EXTENSIONS: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    EXT_EMS,
    EXT_CERT_COMPRESSION,
    EXT_SESSION_TICKET,
    EXT_SUPPORTED_VERSIONS,
    EXT_PSK_MODES,
    EXT_RENEGOTIATION,
];

/// Xray `ModernFingerprints` at commit 6e3322d219140a025285ded1114fe17a5edb74d8.
const MODERN_FINGERPRINTS: &[&str] = &[
    "hellofirefox_120",
    "hellofirefox_148",
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
    "hellosafari_26_3",
    "hello360_11_0",
    "helloqq_11_1",
];

static RANDOM_MODERN: OnceLock<&'static str> = OnceLock::new();
static RANDOMIZED: OnceLock<UtlsClientHelloProfile> = OnceLock::new();
static RANDOMIZED_NO_ALPN: OnceLock<UtlsClientHelloProfile> = OnceLock::new();

#[derive(Clone)]
struct XrayClientHelloCustomizer {
    fingerprint: String,
    profile: UtlsClientHelloProfile,
    managed_ech: bool,
}

impl fmt::Debug for XrayClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XrayClientHelloCustomizer")
            .field("fingerprint", &self.fingerprint)
            .field("profile", &self.profile)
            .finish()
    }
}

impl XrayClientHelloCustomizer {
    fn new(fingerprint: &str, alpn: &[String], managed_ech: bool) -> io::Result<Option<Arc<Self>>> {
        validate_xray_fingerprint(fingerprint)?;
        if fingerprint == "unsafe" {
            return Ok(None);
        }
        let fingerprint = if fingerprint.is_empty() {
            "chrome".to_owned()
        } else {
            fingerprint.to_owned()
        };
        let explicit_alpn = alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let require_tls13 = alpn.iter().any(|protocol| protocol == "h3");
        let selected = select_profile(&fingerprint, require_tls13)?;
        if require_tls13 && !selected.supported_versions.contains(&TLS13) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Xray TLS fingerprint {fingerprint:?} cannot be used with ALPN h3 because it does not advertise TLS 1.3"
                ),
            ));
        }
        let profile = override_alpn(selected, &explicit_alpn);
        Ok(Some(Arc::new(Self {
            fingerprint,
            profile,
            managed_ech,
        })))
    }

    fn selected_profile(&self) -> Result<UtlsClientHelloProfile, RustlsError> {
        Ok(self.profile.clone())
    }
}

impl ClientHelloCustomizer for XrayClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        // Xray applies uTLS only to stream transports. Its XHTTP/H3 path gives
        // the ordinary crypto/tls config directly to quic-go; shaping here
        // would also omit QUIC's mandatory transport_parameters extension from
        // the captured TCP extension order.
        if context.is_quic {
            return Ok(None);
        }
        let mut profile = self.selected_profile()?;
        let enabled_versions = context
            .versions
            .iter()
            .map(|version| u16::from(version.version))
            .collect::<Vec<_>>();
        profile.supported_versions.retain(|version| {
            is_grease(*version) || enabled_versions.iter().any(|enabled| enabled == version)
        });
        // A captured uTLS profile can contain an opaque ECH-GREASE payload.
        // When rustls has a real ECHConfig it must build this extension itself:
        // the ciphertext covers ClientHelloInner and cannot be copied from a
        // template. RFC 9849 also makes a managed outer ECH extension final,
        // so it must not participate in the custom non-final order or GREASE
        // positions. rustls appends the freshly encrypted extension itself.
        if self.managed_ech {
            profile.encrypted_client_hello_length = None;
            // The custom padding hook runs after rustls seals ECH. Altering the
            // outer hello at that point would invalidate the HPKE AAD. ECH has
            // its own mandatory inner padding, so leave outer padding managed
            // by the ECH builder instead of applying the captured template.
            profile.padding_length = None;
            profile
                .extensions
                .retain(|extension| !matches!(extension.extension_type, EXT_ECH | EXT_PADDING));
        }
        randomize_grease(&mut profile);
        if self.managed_ech {
            apply_managed_ech_profile(ClientHelloPlan::new(), &profile).map(Some)
        } else {
            apply_profile(ClientHelloPlan::new(), &profile).map(Some)
        }
    }
}

pub(super) struct XrayClientHelloSettings {
    pub(super) customizer: Option<Arc<dyn ClientHelloCustomizer>>,
    pub(super) alpn_protocols: Vec<Vec<u8>>,
    pub(super) tls13: bool,
}

pub(super) fn xray_client_hello_settings(
    fingerprint: &str,
    alpn: &[String],
    managed_ech: bool,
) -> io::Result<XrayClientHelloSettings> {
    let Some(customizer) = XrayClientHelloCustomizer::new(fingerprint, alpn, managed_ech)? else {
        return Ok(XrayClientHelloSettings {
            customizer: None,
            alpn_protocols: alpn.iter().map(|value| value.as_bytes().to_vec()).collect(),
            tls13: true,
        });
    };
    Ok(XrayClientHelloSettings {
        alpn_protocols: customizer.profile.alpn_protocols.clone(),
        tls13: customizer.profile.supported_versions.contains(&TLS13),
        customizer: Some(customizer as Arc<dyn ClientHelloCustomizer>),
    })
}

pub(super) fn fingerprint_is_per_connection_randomized(fingerprint: &str) -> bool {
    matches!(
        fingerprint,
        "hellorandomized" | "hellorandomizedalpn" | "hellorandomizednoalpn"
    )
}

fn select_profile(fingerprint: &str, require_tls13: bool) -> io::Result<UtlsClientHelloProfile> {
    match fingerprint {
        "random" => {
            let name = RANDOM_MODERN.get_or_init(|| {
                let index = rand::rngs::OsRng.gen_range(0..MODERN_FINGERPRINTS.len());
                MODERN_FINGERPRINTS[index]
            });
            profile_for_fingerprint(name).cloned()
        }
        // Xray constructs these preset IDs once per process. `randomized`
        // starts from HelloRandomizedALPN and forces TLS 1.3.
        "randomized" => Ok(RANDOMIZED
            .get_or_init(|| randomized_profile(RandomAlpn::Always, true))
            .clone()),
        "randomizednoalpn" => Ok(RANDOMIZED_NO_ALPN
            .get_or_init(|| randomized_profile(RandomAlpn::Never, true))
            .clone()),
        // Explicit uTLS randomized IDs receive a new seed per connection.
        "hellorandomized" => Ok(randomized_profile(RandomAlpn::Weighted, require_tls13)),
        "hellorandomizedalpn" => Ok(randomized_profile(RandomAlpn::Always, require_tls13)),
        "hellorandomizednoalpn" => Ok(randomized_profile(RandomAlpn::Never, require_tls13)),
        name => profile_for_fingerprint(name).cloned(),
    }
    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// Xray performs a case-sensitive map lookup. Empty means Chrome Auto and
/// `unsafe` deliberately selects ordinary rustls.
pub(crate) fn validate_xray_fingerprint(fingerprint: &str) -> io::Result<()> {
    if fingerprint.is_empty() || fingerprint == "unsafe" {
        return Ok(());
    }
    profile_for_fingerprint(fingerprint)
        .map(|_| ())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown or non-lowercase Xray TLS fingerprint {fingerprint:?}"),
            )
        })
}

fn override_alpn(
    mut profile: UtlsClientHelloProfile,
    explicit_alpn: &[Vec<u8>],
) -> UtlsClientHelloProfile {
    if explicit_alpn.is_empty() {
        return profile;
    }
    profile.alpn_protocols = explicit_alpn.to_vec();
    if !has_extension(&profile, EXT_ALPN) {
        let insert_at = profile
            .extensions
            .iter()
            .position(|ext| ext.extension_type == EXT_PADDING || is_grease(ext.extension_type))
            .unwrap_or(profile.extensions.len());
        profile.extensions.insert(
            insert_at,
            UtlsExtension {
                extension_type: EXT_ALPN,
                payload_len: 2 + explicit_alpn
                    .iter()
                    .map(|protocol| 1 + protocol.len())
                    .sum::<usize>(),
            },
        );
    }

    // h2 ALPS must not survive an explicit h3-only override.
    let removed = profile
        .application_settings
        .iter()
        .filter(|settings| {
            !settings
                .protocols
                .iter()
                .all(|protocol| explicit_alpn.contains(protocol))
        })
        .map(|settings| settings.extension_type)
        .collect::<Vec<_>>();
    profile.application_settings.retain(|settings| {
        settings
            .protocols
            .iter()
            .all(|protocol| explicit_alpn.contains(protocol))
    });
    profile
        .extensions
        .retain(|extension| !removed.contains(&extension.extension_type));
    profile
}

fn apply_profile(
    plan: ClientHelloPlan,
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloPlan, RustlsError> {
    apply_profile_impl(plan, profile, true)
}

fn apply_managed_ech_profile(
    mut plan: ClientHelloPlan,
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan.with_advertised_cipher_suites(ClientHelloAdvertisedCipherSuites::try_from(
        profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .map(CipherSuite::from)
            .collect::<Vec<_>>(),
    )?);
    if !profile.supported_versions.is_empty() {
        plan = plan.with_supported_versions(actual_versions(profile)?);
    }
    if !profile.supported_groups.is_empty() {
        plan = plan.with_supported_groups(actual_groups(profile)?);
    }
    if !profile.key_shares.is_empty() {
        plan = plan.with_key_share_plan(key_share_plan(profile)?);
    }
    if !profile.alpn_protocols.is_empty() {
        plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(
            profile.alpn_protocols.clone(),
        )?);
    }
    Ok(plan)
}

fn apply_profile_impl(
    mut plan: ClientHelloPlan,
    profile: &UtlsClientHelloProfile,
    custom_order: bool,
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan.with_advertised_cipher_suites(ClientHelloAdvertisedCipherSuites::try_from(
        profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .map(CipherSuite::from)
            .collect::<Vec<_>>(),
    )?);
    if !profile.supported_versions.is_empty() {
        plan = plan
            .with_supported_versions(actual_versions(profile)?)
            .with_advertised_supported_versions(ClientHelloAdvertisedSupportedVersions::try_from(
                profile
                    .supported_versions
                    .iter()
                    .copied()
                    .map(ProtocolVersion::from)
                    .collect::<Vec<_>>(),
            )?);
    }
    if !profile.supported_groups.is_empty() {
        plan = plan
            .with_supported_groups(actual_groups(profile)?)
            .with_advertised_supported_groups(ClientHelloAdvertisedSupportedGroups::try_from(
                profile
                    .supported_groups
                    .iter()
                    .copied()
                    .map(NamedGroup::from)
                    .collect::<Vec<_>>(),
            )?);
    }
    if !profile.key_shares.is_empty() {
        plan = plan.with_key_share_plan(key_share_plan(profile)?);
    }
    if let Some(raw) = raw_key_shares(profile)? {
        plan = plan.with_raw_key_shares(raw);
    }
    if !profile.alpn_protocols.is_empty() {
        plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(
            profile.alpn_protocols.clone(),
        )?);
    }
    if uses_structured_brotli(profile) {
        plan = plan.with_certificate_compression_algorithms(
            ClientHelloCertificateCompressionAlgorithms::try_from(vec![
                CertificateCompressionAlgorithm::Brotli,
            ])?,
        );
    }

    let (exact, raw) = extension_payloads(profile)?;
    plan = plan
        .with_forced_extensions(forced_extensions(profile))
        .with_extensions(extension_plan(profile)?);
    if custom_order && !profile.extensions.is_empty() {
        plan = plan.with_extension_order(ClientHelloExtensionOrder::try_from(
            profile
                .extensions
                .iter()
                .map(|ext| ext.extension_type)
                .filter(|extension_type| !is_grease(*extension_type))
                .collect::<Vec<_>>(),
        )?);
    }
    if let Some(exact) = exact {
        plan = plan.with_exact_extensions(exact);
    }
    if let Some(raw) = raw {
        plan = plan.with_raw_extensions(raw);
    }
    if let Some(grease) = grease_plan(profile)? {
        plan = plan.with_grease(grease);
    }
    if profile.padding_length.is_some() {
        plan = plan.with_padding(ClientHelloPaddingPlan::pad_to_handshake_size(
            BORING_PADDING_TARGET,
        )?);
    }
    Ok(plan)
}

fn actual_versions(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedVersions, RustlsError> {
    let mut versions = profile
        .supported_versions
        .iter()
        .filter_map(|version| match *version {
            TLS13 => Some(ProtocolVersion::TLSv1_3),
            TLS12 => Some(ProtocolVersion::TLSv1_2),
            _ => None,
        })
        .collect::<Vec<_>>();
    versions.dedup();
    ClientHelloSupportedVersions::try_from(versions)
}

fn actual_groups(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedGroups, RustlsError> {
    let mut groups = profile
        .supported_groups
        .iter()
        .filter_map(|group| real_group(*group))
        .collect::<Vec<_>>();
    groups.dedup();
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloSupportedGroups::try_from(groups)
}

fn key_share_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloKeySharePlan, RustlsError> {
    let mut groups = profile
        .key_shares
        .iter()
        .filter_map(|share| real_group(share.group))
        .collect::<Vec<_>>();
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloKeySharePlan::try_from(groups)
}

fn raw_key_shares(
    profile: &UtlsClientHelloProfile,
) -> Result<Option<ClientHelloRawKeyShares>, RustlsError> {
    let mut raw = Vec::new();
    let mut position = 0;
    for share in &profile.key_shares {
        if is_grease(share.group) {
            continue;
        }
        if real_group(share.group).is_some() {
            position += 1;
            continue;
        }
        raw.push(ClientHelloRawKeyShare::new_at(
            position,
            NamedGroup::from(share.group),
            vec![0; share.key_exchange_len],
        )?);
        position += 1;
    }
    if raw.is_empty() {
        Ok(None)
    } else {
        ClientHelloRawKeyShares::try_from(raw).map(Some)
    }
}

fn real_group(group: u16) -> Option<NamedGroup> {
    match group {
        GROUP_X25519 => Some(NamedGroup::X25519),
        GROUP_X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        GROUP_X25519_KYBER_DRAFT => Some(NamedGroup::Unknown(group)),
        GROUP_P256 => Some(NamedGroup::secp256r1),
        GROUP_P384 => Some(NamedGroup::secp384r1),
        _ => None,
    }
}

fn extension_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloExtensionPlan, RustlsError> {
    let disabled = STRUCTURED_OPTIONAL_EXTENSIONS
        .iter()
        .copied()
        .filter(|extension_type| !has_extension(profile, *extension_type))
        .filter(|extension_type| {
            *extension_type != EXT_CERT_COMPRESSION || !uses_structured_brotli(profile)
        })
        .collect::<Vec<_>>();
    ClientHelloExtensionPlan::try_from(disabled)
}

fn forced_extensions(profile: &UtlsClientHelloProfile) -> ClientHelloForcedExtensions {
    let mut forced = ClientHelloForcedExtensions::new();
    if has_extension(profile, EXT_RENEGOTIATION) {
        forced = forced.with_renegotiation_info_empty();
    }
    if has_extension(profile, EXT_SESSION_TICKET) {
        forced = forced.with_session_ticket_request();
    }
    if has_extension(profile, EXT_SCT) {
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
    let mut exact = Vec::new();
    let mut raw = Vec::new();

    if has_extension(profile, EXT_SIGNATURE_ALGORITHMS) {
        exact.push(ClientHelloExactExtension::new(
            EXT_SIGNATURE_ALGORITHMS,
            signature_algorithms_payload(&profile.signature_algorithms)?,
        )?);
    }
    if has_extension(profile, EXT_DELEGATED_CREDENTIALS) {
        push_exact_or_raw_extension(
            &mut exact,
            &mut raw,
            EXT_DELEGATED_CREDENTIALS,
            signature_algorithms_payload(&profile.delegated_credentials_algorithms)?,
        )?;
    }
    if !uses_structured_brotli(profile) && has_extension(profile, EXT_CERT_COMPRESSION) {
        exact.push(ClientHelloExactExtension::new(
            EXT_CERT_COMPRESSION,
            certificate_compression_payload(&profile.certificate_compression_algorithms)?,
        )?);
    }
    if let Some(limit) = profile.record_size_limit {
        push_exact_or_raw_extension(
            &mut exact,
            &mut raw,
            EXT_RECORD_SIZE_LIMIT,
            limit.to_be_bytes().to_vec(),
        )?;
    }
    if let Some(length) = profile.encrypted_client_hello_length {
        exact.push(ClientHelloExactExtension::new(
            EXT_ECH,
            encrypted_client_hello_payload(length)?,
        )?);
    }
    for settings in &profile.application_settings {
        push_exact_or_raw_extension(
            &mut exact,
            &mut raw,
            settings.extension_type,
            application_settings_payload(&settings.protocols)?,
        )?;
    }
    for extension in &profile.extensions {
        if is_grease(extension.extension_type)
            || is_structured_extension(profile, extension.extension_type)
            || extension.extension_type == EXT_SIGNATURE_ALGORITHMS
            || extension.extension_type == EXT_DELEGATED_CREDENTIALS
            || extension.extension_type == EXT_CERT_COMPRESSION
            || extension.extension_type == EXT_RECORD_SIZE_LIMIT
            || extension.extension_type == EXT_ECH
            || profile
                .application_settings
                .iter()
                .any(|settings| settings.extension_type == extension.extension_type)
        {
            continue;
        }
        push_exact_or_raw_extension(
            &mut exact,
            &mut raw,
            extension.extension_type,
            vec![0; extension.payload_len],
        )?;
    }

    Ok((
        (!exact.is_empty())
            .then(|| ClientHelloExactExtensions::try_from(exact))
            .transpose()?,
        (!raw.is_empty())
            .then(|| ClientHelloRawExtensions::try_from(raw))
            .transpose()?,
    ))
}

fn encrypted_client_hello_payload(length: usize) -> Result<Vec<u8>, RustlsError> {
    // ECH GREASE remains opaque, but rustls reparses the ClientHello before
    // sending it, so the placeholder must be a syntactically valid outer ECH.
    const MIN_OUTER_LEN: usize = 11;
    if length < MIN_OUTER_LEN {
        return Err(RustlsError::General(
            "encrypted_client_hello payload is too short".into(),
        ));
    }
    let encrypted_len = u16::try_from(length - 10).map_err(|_| {
        RustlsError::General("encrypted_client_hello payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(length);
    payload.push(0); // outer ECH
    payload.extend_from_slice(&1_u16.to_be_bytes()); // HKDF-SHA256
    payload.extend_from_slice(&1_u16.to_be_bytes()); // AES-128-GCM
    payload.push(0); // config id
    payload.extend_from_slice(&0_u16.to_be_bytes()); // empty encapsulated key
    payload.extend_from_slice(&encrypted_len.to_be_bytes());
    payload.resize(length, 0);
    Ok(payload)
}

fn grease_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<Option<ClientHelloGreasePlan>, RustlsError> {
    let grease_value = profile
        .cipher_suites
        .iter()
        .copied()
        .chain(profile.key_shares.iter().map(|share| share.group))
        .chain(
            profile
                .extensions
                .iter()
                .map(|extension| extension.extension_type),
        )
        .find(|value| is_grease(*value));
    let Some(grease_value) = grease_value else {
        return Ok(None);
    };

    let mut grease = ClientHelloGreasePlan::new(grease_value)?;
    if let Some(position) = profile
        .cipher_suites
        .iter()
        .position(|suite| is_grease(*suite))
    {
        grease = grease.with_cipher_suite_position(position);
    }
    if let Some(position) = profile
        .key_shares
        .iter()
        .position(|share| is_grease(share.group))
    {
        grease = grease.with_key_share_position(position);
    }
    let mut non_grease_position = 0;
    for extension in &profile.extensions {
        if is_grease(extension.extension_type) {
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
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| RustlsError::General("signature_algorithms payload is too large".into()))?;
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
        .and_then(|length| u8::try_from(length).ok())
        .ok_or_else(|| RustlsError::General("compress_certificate payload is too large".into()))?;
    let mut payload = Vec::with_capacity(1 + usize::from(byte_len));
    payload.push(byte_len);
    for algorithm in algorithms {
        payload.extend_from_slice(&algorithm.to_be_bytes());
    }
    Ok(payload)
}

fn application_settings_payload(protocols: &[Vec<u8>]) -> Result<Vec<u8>, RustlsError> {
    let protocols_len = protocols.iter().try_fold(0_usize, |total, protocol| {
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
    exact: &mut Vec<ClientHelloExactExtension>,
    raw: &mut Vec<ClientHelloRawExtension>,
    extension_type: u16,
    payload: Vec<u8>,
) -> Result<(), RustlsError> {
    match ClientHelloRawExtension::new(extension_type, payload.clone()) {
        Ok(extension) => raw.push(extension),
        Err(_) => exact.push(ClientHelloExactExtension::new(extension_type, payload)?),
    }
    Ok(())
}

fn is_structured_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    matches!(
        extension_type,
        EXT_SERVER_NAME
            | EXT_STATUS_REQUEST
            | EXT_SUPPORTED_GROUPS
            | EXT_EC_POINT_FORMATS
            | EXT_ALPN
            | EXT_SCT
            | EXT_PADDING
            | EXT_EMS
            | EXT_SESSION_TICKET
            | EXT_SUPPORTED_VERSIONS
            | EXT_PSK_MODES
            | EXT_KEY_SHARE
            | EXT_RENEGOTIATION
    ) || extension_type == EXT_CERT_COMPRESSION && uses_structured_brotli(profile)
}

fn has_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    profile
        .extensions
        .iter()
        .any(|extension| extension.extension_type == extension_type)
}

fn uses_structured_brotli(profile: &UtlsClientHelloProfile) -> bool {
    profile.certificate_compression_algorithms == [BROTLI]
}

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

fn randomize_grease(profile: &mut UtlsClientHelloProfile) {
    const VALUES: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let mut rng = rand::rngs::OsRng;
    let first = VALUES[rng.gen_range(0..VALUES.len())];
    let mut second = VALUES[rng.gen_range(0..VALUES.len())];
    while second == first {
        second = VALUES[rng.gen_range(0..VALUES.len())];
    }

    for suite in &mut profile.cipher_suites {
        if is_grease(*suite) {
            *suite = first;
        }
    }
    for version in &mut profile.supported_versions {
        if is_grease(*version) {
            *version = first;
        }
    }
    for group in &mut profile.supported_groups {
        if is_grease(*group) {
            *group = first;
        }
    }
    for share in &mut profile.key_shares {
        if is_grease(share.group) {
            share.group = first;
        }
    }
    let mut grease_extensions = 0;
    for extension in &mut profile.extensions {
        if is_grease(extension.extension_type) {
            extension.extension_type = if grease_extensions == 0 {
                first
            } else {
                second
            };
            grease_extensions += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum RandomAlpn {
    Always,
    Never,
    Weighted,
}

fn randomized_profile(alpn_mode: RandomAlpn, force_tls13: bool) -> UtlsClientHelloProfile {
    let mut rng = rand::thread_rng();
    let with_alpn = match alpn_mode {
        RandomAlpn::Always => true,
        RandomAlpn::Never => false,
        RandomAlpn::Weighted => rng.gen_bool(0.7),
    };
    let tls13 = force_tls13 || rng.gen_bool(0.4);

    // `cipherSuites` from the exact uTLS revision pinned by Xray. It shuffles
    // TLS-1.2-only suites before obsolete suites, then removes later entries
    // with an increasing probability.
    const TLS12_SUITES: &[(u16, bool)] = &[
        (0xcca8, true),
        (0xcca9, true),
        (0xc02f, true),
        (0xc02b, true),
        (0xc030, true),
        (0xc02c, true),
        (0xc027, true),
        (0xc013, false),
        (0xc023, true),
        (0xc009, false),
        (0xc014, false),
        (0xc00a, false),
        (0x009c, true),
        (0x009d, true),
        (0x003c, true),
        (0x002f, false),
        (0x0035, false),
        (0xc012, false),
        (0x000a, false),
        (0x0005, false),
        (0xc011, false),
        (0xc007, false),
    ];
    let mut modern = TLS12_SUITES
        .iter()
        .filter_map(|(suite, modern)| modern.then_some(*suite))
        .collect::<Vec<_>>();
    let mut obsolete = TLS12_SUITES
        .iter()
        .filter_map(|(suite, modern)| (!modern).then_some(*suite))
        .collect::<Vec<_>>();
    modern.shuffle(&mut rng);
    obsolete.shuffle(&mut rng);
    modern.extend(obsolete);
    if tls13 {
        modern.retain(|suite| !matches!(*suite, 0x0005 | 0xc011 | 0xc007));
        let mut tls13_suites = vec![0x1301, 0x1302, 0x1303];
        tls13_suites.shuffle(&mut rng);
        tls13_suites.extend(modern);
        modern = tls13_suites;
    }
    let original_len = modern.len() as f64;
    let mut index = 1;
    while index < modern.len() {
        if rng.gen_bool((0.4 * index as f64 / original_len).clamp(0.0, 1.0)) {
            modern.remove(index);
        } else {
            index += 1;
        }
    }

    let mut signature_algorithms = vec![0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.gen_bool(0.63) {
        signature_algorithms.push(0x0203);
    }
    if rng.gen_bool(0.59) {
        signature_algorithms.push(0x0603);
    }
    if tls13 || rng.gen_bool(0.51) {
        signature_algorithms.push(0x0804);
        if rng.gen_bool(0.9) {
            signature_algorithms.extend([0x0805, 0x0806]);
        }
    }
    signature_algorithms.shuffle(&mut rng);

    let mut supported_groups = Vec::new();
    if tls13 && rng.gen_bool(0.71) {
        supported_groups.push(GROUP_X25519_MLKEM768);
    }
    if tls13 || rng.gen_bool(0.71) {
        supported_groups.push(GROUP_X25519);
    }
    supported_groups.extend([GROUP_P256, GROUP_P384]);
    if rng.gen_bool(0.46) {
        supported_groups.push(0x0019); // secp521r1
    }

    let mut extensions = vec![
        extension(EXT_SERVER_NAME),
        extension(EXT_SESSION_TICKET),
        extension(EXT_SIGNATURE_ALGORITHMS),
        extension(EXT_EC_POINT_FORMATS),
        extension(EXT_SUPPORTED_GROUPS),
    ];
    let alpn_protocols = if with_alpn {
        extensions.push(extension(EXT_ALPN));
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        Vec::new()
    };
    let with_padding = tls13 || rng.gen_bool(0.62);
    if with_padding {
        extensions.push(extension(EXT_PADDING));
    }
    if rng.gen_bool(0.74) {
        extensions.push(extension(EXT_STATUS_REQUEST));
    }
    if rng.gen_bool(0.46) {
        extensions.push(extension(EXT_SCT));
    }
    if rng.gen_bool(0.75) {
        extensions.push(extension(EXT_RENEGOTIATION));
    }
    if rng.gen_bool(0.77) {
        extensions.push(extension(EXT_EMS));
    }

    let mut key_shares = Vec::new();
    let mut supported_versions = Vec::new();
    let mut application_settings = Vec::new();
    if tls13 {
        key_shares.push(UtlsKeyShare {
            group: GROUP_X25519,
            key_exchange_len: 32,
        });
        if rng.gen_bool(0.5) {
            key_shares.push(UtlsKeyShare {
                group: GROUP_P256,
                key_exchange_len: 65,
            });
        }
        if rng.gen_bool(0.5) {
            key_shares.insert(
                0,
                UtlsKeyShare {
                    group: GROUP_X25519_MLKEM768,
                    key_exchange_len: 1216,
                },
            );
        }
        supported_versions.extend([TLS13, TLS12]);
        if rng.gen_bool(0.5) {
            supported_versions.extend([0x0302, TLS10]);
        }
        extensions.extend([
            extension(EXT_KEY_SHARE),
            extension(EXT_PSK_MODES),
            extension(EXT_SUPPORTED_VERSIONS),
        ]);
        // uTLS deliberately derives this decision from a salted copy of its
        // seed. An independent secure draw has the same lifetime/distribution.
        if with_alpn && rand::rngs::OsRng.gen_bool(0.33) {
            application_settings.push(UtlsApplicationSettings {
                extension_type: EXT_ALPS,
                protocols: vec![b"h2".to_vec()],
            });
            extensions.push(extension(EXT_ALPS));
        }
    }
    extensions.shuffle(&mut rng);

    UtlsClientHelloProfile {
        cipher_suites: modern,
        supported_versions,
        supported_groups,
        key_shares,
        psk_key_exchange_modes: tls13.then_some(vec![1]).unwrap_or_default(),
        signature_algorithms,
        delegated_credentials_algorithms: Vec::new(),
        alpn_protocols,
        certificate_compression_algorithms: Vec::new(),
        record_size_limit: None,
        application_settings,
        extensions,
        padding_length: with_padding.then_some(0),
        encrypted_client_hello_length: None,
    }
}

fn extension(extension_type: u16) -> UtlsExtension {
    UtlsExtension {
        extension_type,
        payload_len: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
    };

    use rustls::{
        ClientConfig, ClientConnection, RootCertStore,
        client::{CapturesClientHello, Resumption},
        pki_types::ServerName,
    };

    use super::*;
    use crate::transport::utls_profiles::profile_names;

    #[derive(Debug, Default)]
    struct Capture(Mutex<Option<Vec<u8>>>);

    impl CapturesClientHello for Capture {
        fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), RustlsError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct CapturingCustomizer {
        profile: UtlsClientHelloProfile,
        capture: Arc<Capture>,
    }

    impl ClientHelloCustomizer for CapturingCustomizer {
        fn build_client_hello_plan(
            &self,
            _context: ClientHelloContext<'_>,
        ) -> Result<Option<ClientHelloPlan>, RustlsError> {
            let mut profile = self.profile.clone();
            randomize_grease(&mut profile);
            Ok(Some(
                apply_profile_impl(ClientHelloPlan::new(), &profile, true)?
                    .with_capture(self.capture.clone()),
            ))
        }
    }

    fn capture_profile(name: &str, profile: UtlsClientHelloProfile) -> Vec<u8> {
        let capture = Arc::new(Capture::default());
        let configured_alpn = profile.alpn_protocols.clone();
        let tls13 = profile.supported_versions.contains(&TLS13);
        let provider = Arc::new(super::super::tls::xray_crypto_provider());
        let tls13_versions = [&rustls::version::TLS13, &rustls::version::TLS12];
        let tls12_versions = [&rustls::version::TLS12];
        let versions = if tls13 {
            tls13_versions.as_slice()
        } else {
            tls12_versions.as_slice()
        };
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.alpn_protocols = configured_alpn;
        config.client_hello_customizer = Some(Arc::new(CapturingCustomizer {
            profile,
            capture: capture.clone(),
        }));
        let server_name = ServerName::try_from("example.com".to_owned()).unwrap();
        let mut connection = ClientConnection::new(Arc::new(config), server_name)
            .unwrap_or_else(|error| panic!("build shaped ClientHello for {name}: {error:?}"));
        let mut records = Vec::new();
        while connection.wants_write() {
            connection.write_tls(&mut records).unwrap();
        }
        let result = capture.0.lock().unwrap().clone().unwrap();
        result
    }

    #[test]
    fn every_static_profile_matches_the_pinned_go_utls_oracle() {
        const RANDOMIZED: &[&str] = &[
            "random",
            "randomized",
            "randomizednoalpn",
            "hellorandomized",
            "hellorandomizedalpn",
            "hellorandomizednoalpn",
        ];
        for name in profile_names()
            .into_iter()
            .filter(|name| !RANDOMIZED.contains(name))
        {
            let expected = profile_for_fingerprint(name).unwrap().clone();
            let actual = parse_client_hello(&capture_profile(name, expected.clone()));
            assert_eq!(actual, expected, "pinned Go uTLS shape mismatch for {name}");
        }
    }

    #[test]
    fn xray_names_are_strict_and_unsafe_is_unshaped() {
        assert!(
            XrayClientHelloCustomizer::new("", &[], false)
                .unwrap()
                .is_some()
        );
        assert!(
            XrayClientHelloCustomizer::new("unsafe", &[], false)
                .unwrap()
                .is_none()
        );
        assert!(validate_xray_fingerprint("hellochrome_133").is_ok());
        assert!(validate_xray_fingerprint("HelloChrome_133").is_err());
        assert!(validate_xray_fingerprint("not-a-fingerprint").is_err());
    }

    #[test]
    fn explicit_h3_alpn_replaces_profile_alpn_and_h2_alps() {
        let customizer = XrayClientHelloCustomizer::new("chrome", &["h3".to_owned()], false)
            .unwrap()
            .unwrap();
        let profile = customizer.selected_profile().unwrap();
        assert_eq!(profile.alpn_protocols, [b"h3".to_vec()]);
        assert!(has_extension(&profile, EXT_ALPN));
        assert!(profile.application_settings.is_empty());
        assert!(!has_extension(&profile, EXT_ALPS));
    }

    #[test]
    fn h3_rejects_static_tls12_only_fingerprints() {
        let result = XrayClientHelloCustomizer::new("360", &["h3".to_owned()], false);
        match result {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(error.to_string().contains("does not advertise TLS 1.3"));
            }
            Ok(_) => assert!(
                false,
                "TLS 1.2-only fingerprint unexpectedly accepted for H3"
            ),
        }
    }

    #[test]
    fn h3_randomized_fingerprints_are_always_tls13_and_keep_per_connection_diversity() {
        for fingerprint in [
            "hellorandomized",
            "hellorandomizedalpn",
            "hellorandomizednoalpn",
        ] {
            let mut shapes = HashSet::new();
            for _ in 0..256 {
                let customizer =
                    match XrayClientHelloCustomizer::new(fingerprint, &["h3".to_owned()], false) {
                        Ok(Some(customizer)) => customizer,
                        Ok(None) => {
                            assert!(false, "randomized H3 fingerprint was not shaped");
                            continue;
                        }
                        Err(error) => {
                            assert!(false, "randomized H3 fingerprint failed: {error}");
                            continue;
                        }
                    };
                let profile = customizer.profile.clone();
                assert_randomized_invariants(&profile);
                assert!(profile.supported_versions.contains(&TLS13));
                assert_eq!(profile.alpn_protocols, [b"h3".to_vec()]);
                assert!(profile.application_settings.is_empty());
                assert!(!has_extension(&profile, EXT_ALPS));
                shapes.insert(format!("{profile:?}"));
            }
            assert!(
                shapes.len() > 128,
                "H3 randomized fingerprint {fingerprint} lacks per-connection diversity"
            );
        }
    }

    #[test]
    fn randomized_presets_follow_xray_lifetimes_and_tls13_override() {
        let randomized = XrayClientHelloCustomizer::new("randomized", &[], false)
            .unwrap()
            .unwrap();
        let first = randomized.selected_profile().unwrap();
        let second = randomized.selected_profile().unwrap();
        assert_eq!(first, second, "Xray seeds this preset once per process");
        assert!(first.supported_versions.contains(&TLS13));
        assert!(!first.alpn_protocols.is_empty());

        let no_alpn = XrayClientHelloCustomizer::new("randomizednoalpn", &[], false)
            .unwrap()
            .unwrap()
            .selected_profile()
            .unwrap();
        assert!(no_alpn.supported_versions.contains(&TLS13));
        assert!(no_alpn.alpn_protocols.is_empty());
        assert!(!has_extension(&no_alpn, EXT_ALPN));
    }

    #[test]
    fn randomized_profiles_hold_utls_invariants_across_many_seeds() {
        let mut weighted_shapes = HashSet::new();
        let mut saw_tls12 = false;
        let mut saw_tls13 = false;
        let mut saw_alpn = false;
        let mut saw_no_alpn = false;

        for _ in 0..256 {
            let weighted = randomized_profile(RandomAlpn::Weighted, false);
            assert_randomized_invariants(&weighted);
            saw_tls13 |= weighted.supported_versions.contains(&TLS13);
            saw_tls12 |= weighted.supported_versions.is_empty();
            saw_alpn |= !weighted.alpn_protocols.is_empty();
            saw_no_alpn |= weighted.alpn_protocols.is_empty();
            weighted_shapes.insert(format!("{weighted:?}"));

            let with_alpn = randomized_profile(RandomAlpn::Always, true);
            assert_randomized_invariants(&with_alpn);
            assert!(with_alpn.supported_versions.contains(&TLS13));
            assert_eq!(
                with_alpn.alpn_protocols,
                [b"h2".to_vec(), b"http/1.1".to_vec()]
            );

            let without_alpn = randomized_profile(RandomAlpn::Never, true);
            assert_randomized_invariants(&without_alpn);
            assert!(without_alpn.supported_versions.contains(&TLS13));
            assert!(without_alpn.alpn_protocols.is_empty());
            assert!(!has_extension(&without_alpn, EXT_ALPN));
        }

        assert!(saw_tls12 && saw_tls13);
        assert!(saw_alpn && saw_no_alpn);
        assert!(
            weighted_shapes.len() > 200,
            "randomized shapes lack diversity"
        );
    }

    fn assert_randomized_invariants(profile: &UtlsClientHelloProfile) {
        assert!(!profile.cipher_suites.is_empty());
        assert_eq!(
            profile.cipher_suites.iter().collect::<HashSet<_>>().len(),
            profile.cipher_suites.len()
        );
        assert_eq!(
            profile
                .signature_algorithms
                .iter()
                .collect::<HashSet<_>>()
                .len(),
            profile.signature_algorithms.len()
        );
        assert_eq!(
            profile
                .extensions
                .iter()
                .map(|extension| extension.extension_type)
                .collect::<HashSet<_>>()
                .len(),
            profile.extensions.len()
        );
        for required in [
            EXT_SERVER_NAME,
            EXT_SESSION_TICKET,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_EC_POINT_FORMATS,
            EXT_SUPPORTED_GROUPS,
        ] {
            assert!(has_extension(profile, required));
        }
        assert!(profile.supported_groups.contains(&GROUP_P256));
        assert!(profile.supported_groups.contains(&GROUP_P384));

        if profile.supported_versions.contains(&TLS13) {
            assert!(has_extension(profile, EXT_SUPPORTED_VERSIONS));
            assert!(has_extension(profile, EXT_KEY_SHARE));
            assert!(has_extension(profile, EXT_PSK_MODES));
            assert_eq!(profile.psk_key_exchange_modes, [1]);
            assert!(!profile.key_shares.is_empty());
            assert!(profile.padding_length.is_some());
        } else {
            assert!(profile.supported_versions.is_empty());
            assert!(!has_extension(profile, EXT_SUPPORTED_VERSIONS));
            assert!(!has_extension(profile, EXT_KEY_SHARE));
            assert!(!has_extension(profile, EXT_PSK_MODES));
            assert!(profile.psk_key_exchange_modes.is_empty());
            assert!(profile.key_shares.is_empty());
        }
    }

    fn parse_client_hello(raw: &[u8]) -> UtlsClientHelloProfile {
        let mut offset = 0;
        assert_eq!(read_u8(raw, &mut offset), 1);
        let handshake_len = read_u24(raw, &mut offset);
        assert_eq!(handshake_len, raw.len() - 4);
        assert_eq!(read_u16(raw, &mut offset), TLS12);
        take(raw, &mut offset, 32);
        let session_id_len = read_u8(raw, &mut offset);
        take(raw, &mut offset, session_id_len);

        let mut cipher_suites = read_u16_list(raw, &mut offset, 2);
        normalize_grease_list(&mut cipher_suites);
        let compression_len = read_u8(raw, &mut offset);
        take(raw, &mut offset, compression_len);
        let extensions_len = read_u16(raw, &mut offset) as usize;
        let extensions_end = offset + extensions_len;
        assert_eq!(extensions_end, raw.len());

        let mut profile = UtlsClientHelloProfile {
            cipher_suites,
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            key_shares: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            signature_algorithms: Vec::new(),
            delegated_credentials_algorithms: Vec::new(),
            alpn_protocols: Vec::new(),
            certificate_compression_algorithms: Vec::new(),
            record_size_limit: None,
            application_settings: Vec::new(),
            extensions: Vec::new(),
            padding_length: None,
            encrypted_client_hello_length: None,
        };
        let mut grease_extension_index = 0_u16;
        while offset < extensions_end {
            let wire_type = read_u16(raw, &mut offset);
            let length = read_u16(raw, &mut offset) as usize;
            let data = take(raw, &mut offset, length);
            let normalized_type = if is_grease(wire_type) {
                let value = 0x0a0a_u16.wrapping_add(grease_extension_index.wrapping_mul(0x1010));
                grease_extension_index = grease_extension_index.wrapping_add(1);
                value
            } else {
                wire_type
            };
            profile.extensions.push(UtlsExtension {
                extension_type: normalized_type,
                payload_len: length,
            });
            parse_extension(wire_type, data, &mut profile);
        }
        assert_eq!(offset, extensions_end);
        profile
    }

    fn parse_extension(extension_type: u16, data: &[u8], profile: &mut UtlsClientHelloProfile) {
        let mut offset = 0;
        match extension_type {
            EXT_SUPPORTED_VERSIONS => {
                profile.supported_versions = read_u16_list(data, &mut offset, 1);
                normalize_grease_list(&mut profile.supported_versions);
            }
            EXT_SUPPORTED_GROUPS => {
                profile.supported_groups = read_u16_list(data, &mut offset, 2);
                normalize_grease_list(&mut profile.supported_groups);
            }
            EXT_SIGNATURE_ALGORITHMS => {
                profile.signature_algorithms = read_u16_list(data, &mut offset, 2);
            }
            EXT_DELEGATED_CREDENTIALS => {
                profile.delegated_credentials_algorithms = read_u16_list(data, &mut offset, 2);
            }
            EXT_ALPN => profile.alpn_protocols = read_protocol_list(data, &mut offset),
            EXT_KEY_SHARE => {
                let list_len = read_u16(data, &mut offset) as usize;
                assert_eq!(offset + list_len, data.len());
                while offset < data.len() {
                    let mut group = read_u16(data, &mut offset);
                    if is_grease(group) {
                        group = 0x0a0a;
                    }
                    let key_exchange_len = read_u16(data, &mut offset) as usize;
                    take(data, &mut offset, key_exchange_len);
                    profile.key_shares.push(UtlsKeyShare {
                        group,
                        key_exchange_len,
                    });
                }
            }
            EXT_PSK_MODES => {
                let length = read_u8(data, &mut offset);
                profile.psk_key_exchange_modes = take(data, &mut offset, length).to_vec();
            }
            EXT_CERT_COMPRESSION => {
                profile.certificate_compression_algorithms = read_u16_list(data, &mut offset, 1);
            }
            EXT_RECORD_SIZE_LIMIT => {
                profile.record_size_limit = Some(read_u16(data, &mut offset));
            }
            EXT_ALPS | 0x44cd => {
                profile.application_settings.push(UtlsApplicationSettings {
                    extension_type,
                    protocols: read_protocol_list(data, &mut offset),
                });
            }
            EXT_PADDING => {
                profile.padding_length = Some(data.len());
                return;
            }
            EXT_ECH => {
                profile.encrypted_client_hello_length = Some(data.len());
                return;
            }
            _ => return,
        }
        assert_eq!(offset, data.len(), "extension {extension_type:#06x}");
    }

    fn read_protocol_list(raw: &[u8], offset: &mut usize) -> Vec<Vec<u8>> {
        let list_len = read_u16(raw, offset) as usize;
        let end = *offset + list_len;
        assert_eq!(end, raw.len());
        let mut protocols = Vec::new();
        while *offset < end {
            let length = read_u8(raw, offset);
            protocols.push(take(raw, offset, length).to_vec());
        }
        protocols
    }

    fn read_u16_list(raw: &[u8], offset: &mut usize, prefix_len: usize) -> Vec<u16> {
        let byte_len = match prefix_len {
            1 => read_u8(raw, offset),
            2 => read_u16(raw, offset) as usize,
            _ => unreachable!(),
        };
        assert_eq!(byte_len % 2, 0);
        let end = *offset + byte_len;
        assert!(end <= raw.len());
        let mut values = Vec::new();
        while *offset < end {
            values.push(read_u16(raw, offset));
        }
        values
    }

    fn normalize_grease_list(values: &mut [u16]) {
        for value in values {
            if is_grease(*value) {
                *value = 0x0a0a;
            }
        }
    }

    fn read_u8(raw: &[u8], offset: &mut usize) -> usize {
        let value = raw[*offset] as usize;
        *offset += 1;
        value
    }

    fn read_u16(raw: &[u8], offset: &mut usize) -> u16 {
        let bytes = take(raw, offset, 2);
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn read_u24(raw: &[u8], offset: &mut usize) -> usize {
        let bytes = take(raw, offset, 3);
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
    }

    fn take<'a>(raw: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
        let end = (*offset).checked_add(length).unwrap();
        assert!(end <= raw.len());
        let result = &raw[*offset..end];
        *offset = end;
        result
    }
}
