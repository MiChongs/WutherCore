use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Deref;

use pki_types::ServerName;

use super::client_hello::ClientHelloPaddingMode;
#[cfg(feature = "tls12")]
use super::tls12;
use super::{ResolvesClientCert, Tls12Resumption};
use crate::SupportedCipherSuite;
#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::inappropriate_handshake_message;
use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::ech::EchState;
use crate::client::{
    ClientConfig, ClientHelloContext, ClientHelloPlan, EchMode, EchStatus, FinalizesClientHello,
    tls13,
};
use crate::common_state::{CommonState, HandshakeKind, Protocol, State};
use crate::conn::ConnectionRandoms;
use crate::crypto::KeyExchangeAlgorithm;
use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, CertificateType, CipherSuite, ContentType,
    HandshakeType, ProtocolVersion,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::{debug, trace};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtensions, ClientExtensionsInput, ClientHelloPayload,
    ClientSessionTicket, EncryptedClientHello, HandshakeMessagePayload, HandshakePayload,
    HelloRetryRequest, KeyShareEntry, ProtocolName, PskKeyExchangeModes, Random, ServerNamePayload,
    SessionId, SupportedEcPointFormats, SupportedProtocolVersions, TransportParameters,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleEarly;
use crate::verify::ServerCertVerifier;
use crate::versions;

pub(super) type NextState<'a> = Box<dyn State<ClientConnectionData> + 'a>;
pub(super) type NextStateOrError<'a> = Result<NextState<'a>, Error>;
pub(super) type ClientContext<'a> = crate::common_state::Context<'a, ClientConnectionData>;

struct ExpectServerHello {
    input: ClientHelloInput,
    transcript_buffer: HandshakeHashBuffer,
    // The key schedule for sending early data.
    //
    // If the server accepts the PSK used for early data then
    // this is used to compute the rest of the key schedule.
    // Otherwise, it is thrown away.
    //
    // If this is `None` then we do not support early data.
    early_data_key_schedule: Option<KeyScheduleEarly>,
    offered_cipher_suites: Vec<CipherSuite>,
    offered_key_share: Option<tls13::OfferedKeyShares>,
    suite: Option<SupportedCipherSuite>,
    ech_state: Option<EchState>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: ClientExtensionsInput<'static>,
}

pub(super) struct ClientHelloInput {
    pub(super) config: Arc<ClientConfig>,
    pub(super) resuming: Option<persist::Retrieved<ClientSessionValue>>,
    pub(super) random: Random,
    pub(super) sent_tls13_fake_ccs: bool,
    pub(super) hello: ClientHelloDetails,
    pub(super) session_id: SessionId,
    pub(super) server_name: ServerName<'static>,
    pub(super) prev_ech_ext: Option<EncryptedClientHello>,
    pub(super) plan: Option<ClientHelloPlan>,
}

impl ClientHelloInput {
    pub(super) fn new(
        server_name: ServerName<'static>,
        extra_exts: &ClientExtensionsInput<'_>,
        cx: &mut ClientContext<'_>,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        let mut resuming = ClientSessionValue::retrieve(&server_name, &config, cx);
        let session_id = match &mut resuming {
            Some(_resuming) => {
                debug!("Resuming session");
                match &mut _resuming.value {
                    #[cfg(feature = "tls12")]
                    ClientSessionValue::Tls12(inner) => {
                        // If we have a ticket, we use the sessionid as a signal that
                        // we're  doing an abbreviated handshake.  See section 3.4 in
                        // RFC5077.
                        if !inner.ticket().0.is_empty() {
                            inner.session_id = SessionId::random(config.provider.secure_random)?;
                        }
                        Some(inner.session_id)
                    }
                    _ => None,
                }
            }
            _ => {
                debug!("Not resuming any session");
                None
            }
        };

        // https://tools.ietf.org/html/rfc8446#appendix-D.4
        // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
        let session_id = match session_id {
            Some(session_id) => session_id,
            None if cx.common.is_quic() => SessionId::empty(),
            None if !config.supports_version(ProtocolVersion::TLSv1_3) => SessionId::empty(),
            None => SessionId::random(config.provider.secure_random)?,
        };

        let hello = ClientHelloDetails::new(
            extra_exts
                .protocols
                .clone()
                .unwrap_or_default(),
            crate::rand::random_u16(config.provider.secure_random)?,
        );

        let plan = match config.client_hello_customizer.as_ref() {
            Some(customizer) => {
                let forbids_tls12 =
                    cx.common.is_quic() || matches!(config.ech_mode, Some(EchMode::Enable(_)));
                let versions: Vec<_> = versions::ALL_VERSIONS
                    .iter()
                    .copied()
                    .filter(|version| match version.version {
                        ProtocolVersion::TLSv1_2 => {
                            !forbids_tls12 && config.supports_version(ProtocolVersion::TLSv1_2)
                        }
                        ProtocolVersion::TLSv1_3 => {
                            config.supports_version(ProtocolVersion::TLSv1_3)
                        }
                        _ => false,
                    })
                    .collect();
                let alpn_protocols: Vec<_> = extra_exts
                    .protocols
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|protocol| protocol.as_ref().to_vec())
                    .collect();

                customizer.build_client_hello_plan(ClientHelloContext {
                    server_name: &server_name,
                    alpn_protocols: &alpn_protocols,
                    versions: &versions,
                    crypto_provider: &config.provider,
                    is_quic: cx.common.is_quic(),
                })?
            }
            None => None,
        };

        let random = plan
            .as_ref()
            .and_then(|plan| plan.random)
            .map(Random::from)
            .unwrap_or(Random::new(config.provider.secure_random)?);

        let session_id = match plan
            .as_ref()
            .and_then(|plan| plan.session_id.as_ref())
        {
            Some(custom_session_id) => SessionId::from_bytes(custom_session_id.as_slice())
                .map_err(|_| Error::General("invalid ClientHello session id".into()))?,
            None => session_id,
        };

        Ok(Self {
            resuming,
            random,
            sent_tls13_fake_ccs: false,
            hello,
            session_id,
            server_name,
            prev_ech_ext: None,
            plan,
            config,
        })
    }

    pub(super) fn start_handshake(
        self,
        extra_exts: ClientExtensionsInput<'static>,
        cx: &mut ClientContext<'_>,
    ) -> NextStateOrError<'static> {
        let mut transcript_buffer = HandshakeHashBuffer::new();
        if self
            .config
            .client_auth_cert_resolver
            .has_certs()
        {
            transcript_buffer.set_client_auth_enabled();
        }

        let needs_key_share = self
            .plan
            .as_ref()
            .and_then(|plan| plan.supported_versions.as_ref())
            .map(|versions| {
                versions
                    .as_slice()
                    .contains(&ProtocolVersion::TLSv1_3)
            })
            .unwrap_or_else(|| self.config.needs_key_share());

        let key_share = if needs_key_share {
            Some(tls13::initial_key_shares(
                &self.config,
                &self.server_name,
                &mut cx.common.kx_state,
                self.plan.as_ref(),
            )?)
        } else {
            None
        };

        let ech_state = match self.config.ech_mode.as_ref() {
            Some(EchMode::Enable(ech_config)) => {
                Some(ech_config.state(self.server_name.clone(), &self.config)?)
            }
            _ => None,
        };

        emit_client_hello_for_retry(
            transcript_buffer,
            None,
            key_share,
            extra_exts,
            None,
            self,
            cx,
            ech_state,
        )
    }
}

fn default_supported_versions(
    config: &ClientConfig,
    forbids_tls12: bool,
) -> SupportedProtocolVersions {
    SupportedProtocolVersions::from_flags(
        config.supports_version(ProtocolVersion::TLSv1_2) && !forbids_tls12,
        config.supports_version(ProtocolVersion::TLSv1_3),
    )
}

fn planned_supported_versions(
    plan: Option<&ClientHelloPlan>,
    config: &ClientConfig,
    forbids_tls12: bool,
) -> Result<SupportedProtocolVersions, Error> {
    let Some(versions) = plan.and_then(|plan| plan.supported_versions.as_ref()) else {
        return Ok(default_supported_versions(config, forbids_tls12));
    };

    for version in versions.as_slice() {
        let supported = match *version {
            ProtocolVersion::TLSv1_2 => {
                !forbids_tls12 && config.supports_version(ProtocolVersion::TLSv1_2)
            }
            ProtocolVersion::TLSv1_3 => config.supports_version(ProtocolVersion::TLSv1_3),
            _ => false,
        };

        if !supported {
            return Err(Error::General(
                "ClientHello supported version is not enabled by this config".into(),
            ));
        }
    }

    Ok(SupportedProtocolVersions::from_slice(versions.as_slice()))
}

fn validate_cipher_suites(
    cipher_suites: &[CipherSuite],
    config: &ClientConfig,
    protocol: Protocol,
    supported_versions: &SupportedProtocolVersions,
) -> Result<(), Error> {
    for suite in cipher_suites {
        if *suite == CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV {
            if supported_versions.tls12 {
                continue;
            }

            return Err(Error::General(
                "ClientHello cipher suite is not usable for the supported versions".into(),
            ));
        }

        let supported = config
            .provider
            .cipher_suites
            .iter()
            .any(|candidate| {
                candidate.suite() == *suite
                    && candidate.usable_for_protocol(protocol)
                    && supported_versions.any(|version| candidate.version().version == version)
            });

        if !supported {
            return Err(Error::General(
                "ClientHello cipher suite is not supported by this config".into(),
            ));
        }
    }

    Ok(())
}

fn validate_supported_groups(
    groups: &[NamedGroup],
    config: &ClientConfig,
    supported_versions: &SupportedProtocolVersions,
) -> Result<(), Error> {
    for group in groups {
        let supported = config
            .provider
            .kx_groups
            .iter()
            .any(|candidate| {
                candidate.name() == *group
                    && supported_versions.any(|version| candidate.usable_for_version(version))
            });

        if !supported {
            return Err(Error::General(
                "ClientHello supported group is not supported by this config".into(),
            ));
        }
    }

    Ok(())
}

fn validate_signature_algorithms(
    signature_algorithms: &[crate::SignatureScheme],
    config: &ClientConfig,
) -> Result<(), Error> {
    let supported = config
        .verifier
        .supported_verify_schemes();

    for algorithm in signature_algorithms {
        if !supported.contains(algorithm) {
            return Err(Error::General(
                "ClientHello signature algorithm is not supported by this config".into(),
            ));
        }
    }

    Ok(())
}

fn validate_certificate_compression_algorithms(
    algorithms: &[CertificateCompressionAlgorithm],
    config: &ClientConfig,
    supported_versions: &SupportedProtocolVersions,
) -> Result<(), Error> {
    if !supported_versions.tls13 {
        return Err(Error::General(
            "ClientHello certificate compression requires TLS 1.3 support".into(),
        ));
    }

    for algorithm in algorithms {
        if !config
            .cert_decompressors
            .iter()
            .any(|decompressor| decompressor.algorithm() == *algorithm)
        {
            return Err(Error::General(
                "ClientHello certificate compression algorithm is not supported by this config"
                    .into(),
            ));
        }
    }

    Ok(())
}

fn apply_alpn_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
    hello: &mut ClientHelloDetails,
) {
    let Some(protocols) = plan.and_then(|plan| plan.alpn_protocols.as_ref()) else {
        return;
    };

    let protocols = match protocols.as_slice().is_empty() {
        true => None,
        false => Some(
            protocols
                .as_slice()
                .iter()
                .cloned()
                .map(ProtocolName::from)
                .collect::<Vec<_>>(),
        ),
    };
    hello.alpn_protocols = protocols.clone().unwrap_or_default();
    exts.protocols = protocols;
}

fn apply_extension_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
    hello: &mut ClientHelloDetails,
    supported_versions: &SupportedProtocolVersions,
    require_ems: bool,
) -> Result<(), Error> {
    let Some(extensions) = plan.and_then(|plan| plan.extensions.as_ref()) else {
        return Ok(());
    };

    for extension in extensions.disabled_extensions() {
        match ExtensionType::from(extension.0) {
            ExtensionType::SupportedVersions if supported_versions.tls13 => {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable supported_versions for TLS 1.3"
                        .into(),
                ));
            }
            ExtensionType::SignatureAlgorithms | ExtensionType::KeyShare => {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable a required extension".into(),
                ));
            }
            ExtensionType::EllipticCurves if supported_versions.tls13 => {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable a required extension".into(),
                ));
            }
            ExtensionType::EncryptedClientHello
            | ExtensionType::EncryptedClientHelloOuterExtensions
            | ExtensionType::TransportParameters
            | ExtensionType::TransportParametersDraft => {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable a managed extension".into(),
                ));
            }
            ExtensionType::ExtendedMasterSecret if require_ems && supported_versions.tls12 => {
                return Err(Error::General(
                    "ClientHello extension plan cannot disable extended_master_secret when it is required".into(),
                ));
            }
            ExtensionType::ServerName => exts.server_name = None,
            ExtensionType::StatusRequest => exts.certificate_status_request = None,
            ExtensionType::EllipticCurves => exts.named_groups = None,
            ExtensionType::ECPointFormats => exts.ec_point_formats = None,
            ExtensionType::SignatureAlgorithmsCert => {}
            ExtensionType::ALProtocolNegotiation => {
                exts.protocols = None;
                hello.alpn_protocols.clear();
            }
            ExtensionType::ClientCertificateType => exts.client_certificate_types = None,
            ExtensionType::ServerCertificateType => exts.server_certificate_types = None,
            ExtensionType::ExtendedMasterSecret => exts.extended_master_secret_request = None,
            ExtensionType::Padding => exts.padding = None,
            ExtensionType::CompressCertificate => {
                exts.certificate_compression_algorithms = None;
                hello.offered_cert_compression = false;
            }
            ExtensionType::SessionTicket => exts.session_ticket = None,
            // TLS 1.2 negotiates through ServerHello.legacy_version, so the
            // RFC 8446 supported_versions extension is optional and may be
            // omitted to reproduce legacy ClientHello fingerprints.
            ExtensionType::SupportedVersions => exts.supported_versions = None,
            ExtensionType::PreSharedKey => {
                if exts.preshared_key_offer.is_some() {
                    return Err(Error::General(
                        "ClientHello extension plan cannot disable an active pre_shared_key extension".into(),
                    ));
                }
            }
            ExtensionType::EarlyData => exts.early_data_request = None,
            ExtensionType::Cookie => exts.cookie = None,
            ExtensionType::PSKKeyExchangeModes => {
                if exts.preshared_key_offer.is_some() {
                    return Err(Error::General(
                        "ClientHello extension plan cannot disable psk_key_exchange_modes when offering PSK".into(),
                    ));
                }
                exts.preshared_key_modes = None;
            }
            ExtensionType::CertificateAuthorities => exts.certificate_authority_names = None,
            ExtensionType::RenegotiationInfo => exts.renegotiation_info = None,
            ExtensionType::SCT
            | ExtensionType::MaxFragmentLength
            | ExtensionType::ClientCertificateUrl
            | ExtensionType::TrustedCAKeys
            | ExtensionType::TruncatedHMAC
            | ExtensionType::UserMapping
            | ExtensionType::ClientAuthz
            | ExtensionType::ServerAuthz
            | ExtensionType::CertificateType
            | ExtensionType::SRP
            | ExtensionType::UseSRTP
            | ExtensionType::Heartbeat
            | ExtensionType::TicketEarlyDataInfo
            | ExtensionType::OIDFilters
            | ExtensionType::PostHandshakeAuth
            | ExtensionType::NextProtocolNegotiation
            | ExtensionType::ChannelId
            | ExtensionType::Unknown(_) => {}
        }
    }

    Ok(())
}

fn zero_padding(length: u16) -> Payload<'static> {
    Payload::new(vec![0; usize::from(length)])
}

fn apply_padding_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
) -> Result<(), Error> {
    let Some(padding) = plan.and_then(|plan| plan.padding.as_ref()) else {
        return Ok(());
    };

    let length = match padding.mode() {
        ClientHelloPaddingMode::Fixed(length) => length,
        ClientHelloPaddingMode::PadToHandshakeSize(_) => 0,
    };
    exts.padding = Some(zero_padding(length));
    Ok(())
}

fn apply_raw_extension_plan(plan: Option<&ClientHelloPlan>, exts: &mut ClientExtensions<'_>) {
    let Some(raw_extensions) = plan.and_then(|plan| plan.raw_extensions.as_ref()) else {
        return;
    };

    exts.raw_extensions = raw_extensions
        .as_slice()
        .iter()
        .map(|extension| {
            (
                ExtensionType::from(extension.extension_type().0),
                Payload::new(extension.payload().to_vec()),
            )
        })
        .collect();
}

fn add_exact_extension_payload(
    exts: &mut ClientExtensions<'_>,
    extension_type: ExtensionType,
    payload: Payload<'static>,
) -> Result<(), Error> {
    if exts.has_exact_extension(extension_type) {
        return Err(Error::General(
            "ClientHello exact extensions contain a duplicate extension".into(),
        ));
    }
    if matches!(extension_type, ExtensionType::PreSharedKey) {
        return Err(Error::General(
            "ClientHello exact extension type cannot be pre_shared_key".into(),
        ));
    }

    exts.exact_extensions
        .push((extension_type, payload));
    Ok(())
}

fn advertised_supported_versions_payload(
    versions: &[ProtocolVersion],
) -> Result<Payload<'static>, Error> {
    let byte_len = versions
        .len()
        .checked_mul(2)
        .ok_or_else(|| {
            Error::General("ClientHello advertised supported versions are too large".into())
        })?;
    let byte_len = u8::try_from(byte_len).map_err(|_| {
        Error::General("ClientHello advertised supported versions cannot exceed 254 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(1 + usize::from(byte_len));
    payload.push(byte_len);
    for version in versions {
        payload.extend_from_slice(&u16::from(*version).to_be_bytes());
    }
    Ok(Payload::new(payload))
}

fn advertised_supported_groups_payload(groups: &[NamedGroup]) -> Result<Payload<'static>, Error> {
    let byte_len = groups
        .len()
        .checked_mul(2)
        .ok_or_else(|| {
            Error::General("ClientHello advertised supported groups are too large".into())
        })?;
    let byte_len = u16::try_from(byte_len).map_err(|_| {
        Error::General("ClientHello advertised supported groups cannot exceed 65534 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(byte_len));
    payload.extend_from_slice(&byte_len.to_be_bytes());
    for group in groups {
        payload.extend_from_slice(&u16::from(*group).to_be_bytes());
    }
    Ok(Payload::new(payload))
}

fn apply_advertised_supported_versions_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
) -> Result<(), Error> {
    let Some(versions) = plan.and_then(|plan| {
        plan.advertised_supported_versions
            .as_ref()
    }) else {
        return Ok(());
    };

    add_exact_extension_payload(
        exts,
        ExtensionType::SupportedVersions,
        advertised_supported_versions_payload(versions.as_slice())?,
    )
}

fn apply_advertised_supported_groups_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
) -> Result<(), Error> {
    let Some(groups) = plan.and_then(|plan| {
        plan.advertised_supported_groups
            .as_ref()
    }) else {
        return Ok(());
    };

    add_exact_extension_payload(
        exts,
        ExtensionType::EllipticCurves,
        advertised_supported_groups_payload(groups.as_slice())?,
    )
}

fn apply_exact_extension_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
) -> Result<(), Error> {
    let Some(exact_extensions) = plan.and_then(|plan| plan.exact_extensions.as_ref()) else {
        return Ok(());
    };

    for extension in exact_extensions.as_slice() {
        let extension_type = ExtensionType::from(extension.extension_type().0);
        if matches!(extension_type, ExtensionType::EncryptedClientHello)
            && exts.encrypted_client_hello.is_some()
        {
            return Err(Error::General(
                "ClientHello exact encrypted_client_hello conflicts with managed ECH".into(),
            ));
        }
        if matches!(
            extension_type,
            ExtensionType::EncryptedClientHelloOuterExtensions
        ) && exts
            .encrypted_client_hello_outer
            .is_some()
        {
            return Err(Error::General(
                "ClientHello exact encrypted_client_hello_outer conflicts with managed ECH".into(),
            ));
        }
        add_exact_extension_payload(
            exts,
            extension_type,
            Payload::new(extension.payload().to_vec()),
        )?;
    }

    Ok(())
}

fn apply_raw_key_share_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
) -> Result<(), Error> {
    let Some(raw_key_shares) = plan.and_then(|plan| plan.raw_key_shares.as_ref()) else {
        return Ok(());
    };
    let Some(key_shares) = exts.key_shares.as_mut() else {
        return Err(Error::General(
            "ClientHello raw key shares require a key_share extension".into(),
        ));
    };

    for raw_key_share in raw_key_shares.as_slice() {
        if key_shares
            .iter()
            .any(|key_share| key_share.group == raw_key_share.group())
        {
            return Err(Error::General(
                "ClientHello raw key shares contain a duplicate group".into(),
            ));
        }

        let entry = KeyShareEntry::new(raw_key_share.group(), raw_key_share.payload().to_vec());
        match raw_key_share.position() {
            Some(position) => {
                if position > key_shares.len() {
                    return Err(Error::General(
                        "ClientHello raw key share position is out of range".into(),
                    ));
                }
                key_shares.insert(position, entry);
            }
            None => key_shares.push(entry),
        }
    }

    Ok(())
}

fn apply_forced_extension_plan(plan: Option<&ClientHelloPlan>, exts: &mut ClientExtensions<'_>) {
    let Some(forced) = plan.and_then(|plan| plan.forced_extensions.as_ref()) else {
        return;
    };

    if forced.renegotiation_info_empty() {
        exts.renegotiation_info = Some(PayloadU8::new(Vec::new()));
    }
    if forced.session_ticket_request() {
        exts.session_ticket = Some(ClientSessionTicket::Request);
    }
    if forced.signed_certificate_timestamp_empty() {
        exts.signed_certificate_timestamp = Some(());
    }
}

fn encoded_client_hello_len(payload: &ClientHelloPayload) -> usize {
    let mut bytes = Vec::new();
    HandshakeMessagePayload(HandshakePayload::ClientHello(payload.clone())).encode(&mut bytes);
    bytes.len()
}

fn finalize_padding_plan(
    plan: Option<&ClientHelloPlan>,
    payload: &mut ClientHelloPayload,
) -> Result<(), Error> {
    let Some(padding) = plan.and_then(|plan| plan.padding.as_ref()) else {
        return Ok(());
    };

    if let ClientHelloPaddingMode::PadToHandshakeSize(target_size) = padding.mode() {
        payload.extensions.padding = Some(Payload::empty());
        let current_size = encoded_client_hello_len(payload);
        let padding_len = usize::from(target_size).saturating_sub(current_size);
        let padding_len = u16::try_from(padding_len).map_err(|_| {
            Error::General("ClientHello padding size cannot exceed 65535 bytes".into())
        })?;
        payload.extensions.padding = Some(zero_padding(padding_len));
    }

    Ok(())
}

fn insert_at<T>(items: &mut Vec<T>, position: usize, value: T, what: &str) -> Result<(), Error> {
    if position > items.len() {
        return Err(Error::General(
            format!("ClientHello GREASE position is out of range for {what}").into(),
        ));
    }

    items.insert(position, value);
    Ok(())
}

fn non_final_extension_count(exts: &ClientExtensions<'_>) -> usize {
    let mut order = exts.collect_used_with_raw();
    order.retain(|ext| {
        !(matches!(ext, ExtensionType::PreSharedKey)
            || matches!(ext, ExtensionType::EncryptedClientHello)
                && exts.encrypted_client_hello.is_some()
                && !exts.has_exact_extension(ExtensionType::EncryptedClientHello)
            || matches!(ext, ExtensionType::EncryptedClientHelloOuterExtensions)
                && exts
                    .encrypted_client_hello_outer
                    .is_some()
                && !exts.has_exact_extension(ExtensionType::EncryptedClientHelloOuterExtensions)
            || exts.contiguous_extensions.contains(ext))
    });
    order.len()
}

fn apply_grease_plan(
    plan: Option<&ClientHelloPlan>,
    exts: &mut ClientExtensions<'_>,
    cipher_suites: &mut Vec<CipherSuite>,
) -> Result<(), Error> {
    let Some(grease) = plan.and_then(|plan| plan.grease.as_ref()) else {
        return Ok(());
    };
    let value = grease.value();

    if let Some(position) = grease.cipher_suite_position() {
        insert_at(
            cipher_suites,
            position,
            CipherSuite::from(value),
            "cipher suites",
        )?;
    }

    if let Some(position) = grease.supported_version_position() {
        let Some(supported_versions) = exts.supported_versions.as_mut() else {
            return Err(Error::General(
                "ClientHello GREASE supported_version requires a supported_versions extension"
                    .into(),
            ));
        };
        if position > supported_versions.as_slice().len() {
            return Err(Error::General(
                "ClientHello GREASE position is out of range for supported versions".into(),
            ));
        }
        supported_versions.set_grease(position, ProtocolVersion::from(value));
    }

    if let Some(position) = grease.supported_group_position() {
        let Some(named_groups) = exts.named_groups.as_mut() else {
            return Err(Error::General(
                "ClientHello GREASE supported_group requires a supported_groups extension".into(),
            ));
        };
        insert_at(
            named_groups,
            position,
            NamedGroup::from(value),
            "supported groups",
        )?;
    }

    if let Some(position) = grease.key_share_position() {
        let Some(key_shares) = exts.key_shares.as_mut() else {
            return Err(Error::General(
                "ClientHello GREASE key_share requires a key_share extension".into(),
            ));
        };
        insert_at(
            key_shares,
            position,
            KeyShareEntry::new(NamedGroup::from(value), vec![0]),
            "key shares",
        )?;
    }

    for extension in grease.extensions() {
        let position = extension.position();
        if position > non_final_extension_count(exts) {
            return Err(Error::General(
                "ClientHello GREASE position is out of range for extensions".into(),
            ));
        }
        exts.grease_extensions.push((
            position,
            ExtensionType::from(extension.value()),
            Payload::new(extension.payload().to_vec()),
        ));
    }

    Ok(())
}

/// Emits the initial ClientHello or a ClientHello in response to
/// a HelloRetryRequest.
///
/// `retryreq` and `suite` are `None` if this is the initial
/// ClientHello.
fn emit_client_hello_for_retry(
    mut transcript_buffer: HandshakeHashBuffer,
    retryreq: Option<&HelloRetryRequest>,
    key_share: Option<tls13::OfferedKeyShares>,
    extra_exts: ClientExtensionsInput<'static>,
    suite: Option<SupportedCipherSuite>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
    mut ech_state: Option<EchState>,
) -> NextStateOrError<'static> {
    let config = &input.config;
    // Defense in depth: the ECH state should be None if ECH is disabled based on config
    // builder semantics.
    let forbids_tls12 = cx.common.is_quic() || ech_state.is_some();

    let supported_versions =
        planned_supported_versions(input.plan.as_ref(), config, forbids_tls12)?;

    // should be unreachable thanks to config builder
    assert!(supported_versions.any(|_| true));

    let mut exts = Box::new(ClientExtensions {
        // offer groups which are usable for any offered version
        named_groups: Some(
            match input
                .plan
                .as_ref()
                .and_then(|plan| plan.supported_groups.as_ref())
            {
                Some(groups) => {
                    validate_supported_groups(groups.as_slice(), config, &supported_versions)?;
                    groups.as_slice().to_vec()
                }
                None => config
                    .provider
                    .kx_groups
                    .iter()
                    .filter(|skxg| supported_versions.any(|v| skxg.usable_for_version(v)))
                    .map(|skxg| skxg.name())
                    .collect(),
            },
        ),
        supported_versions: Some(supported_versions),
        signature_schemes: Some(
            match input
                .plan
                .as_ref()
                .and_then(|plan| plan.signature_algorithms.as_ref())
            {
                Some(signature_algorithms) => {
                    validate_signature_algorithms(signature_algorithms.as_slice(), config)?;
                    signature_algorithms.as_slice().to_vec()
                }
                None => config
                    .verifier
                    .supported_verify_schemes(),
            },
        ),
        extended_master_secret_request: Some(()),
        certificate_status_request: Some(CertificateStatusRequest::build_ocsp()),
        protocols: extra_exts.protocols.clone(),
        ..Default::default()
    });

    match extra_exts.transport_parameters.clone() {
        Some(TransportParameters::Quic(v)) => exts.transport_parameters = Some(v),
        Some(TransportParameters::QuicDraft(v)) => exts.transport_parameters_draft = Some(v),
        None => {}
    };

    if supported_versions.tls13 {
        if let Some(cas_extension) = config.verifier.root_hint_subjects() {
            exts.certificate_authority_names = Some(cas_extension.to_owned());
        }
    }

    // Send the ECPointFormat extension only if we are proposing ECDHE
    if config
        .provider
        .kx_groups
        .iter()
        .any(|skxg| skxg.name().key_exchange_algorithm() == KeyExchangeAlgorithm::ECDHE)
    {
        exts.ec_point_formats = Some(SupportedEcPointFormats::default());
    }

    exts.server_name = match (ech_state.as_ref(), config.enable_sni) {
        // If we have ECH state we have a "cover name" to send in the outer hello
        // as the SNI domain name. This happens unconditionally so we ignore the
        // `enable_sni` value. That will be used later to decide what to do for
        // the protected inner hello's SNI.
        (Some(ech_state), _) => Some(ServerNamePayload::from(&ech_state.outer_name)),

        // If we have no ECH state, and SNI is enabled, try to use the input server_name
        // for the SNI domain name.
        (None, true) => match &input.server_name {
            ServerName::DnsName(dns_name) => Some(ServerNamePayload::from(dns_name)),
            _ => None,
        },

        // If we have no ECH state, and SNI is not enabled, there's nothing to do.
        (None, false) => None,
    };

    if let Some(key_share) = &key_share {
        debug_assert!(supported_versions.tls13);
        exts.key_shares = Some(key_share.key_share_entries()?);
    }

    if let Some(cookie) = retryreq.and_then(|hrr| hrr.cookie.as_ref()) {
        exts.cookie = Some(cookie.clone());
    }

    if supported_versions.tls13 {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        exts.preshared_key_modes = Some(PskKeyExchangeModes {
            psk: false,
            psk_dhe: true,
        });
    }

    input.hello.offered_cert_compression = match input.plan.as_ref().and_then(|plan| {
        plan.certificate_compression_algorithms
            .as_ref()
    }) {
        Some(algorithms) => {
            validate_certificate_compression_algorithms(
                algorithms.as_slice(),
                config,
                &supported_versions,
            )?;
            exts.certificate_compression_algorithms = Some(algorithms.as_slice().to_vec());
            true
        }
        None if supported_versions.tls13 && !config.cert_decompressors.is_empty() => {
            exts.certificate_compression_algorithms = Some(
                config
                    .cert_decompressors
                    .iter()
                    .map(|dec| dec.algorithm())
                    .collect(),
            );
            true
        }
        None => false,
    };

    if config
        .client_auth_cert_resolver
        .only_raw_public_keys()
    {
        exts.client_certificate_types = Some(vec![CertificateType::RawPublicKey]);
    }

    if config
        .verifier
        .requires_raw_public_keys()
    {
        exts.server_certificate_types = Some(vec![CertificateType::RawPublicKey]);
    }

    // If this is a second client hello we're constructing in response to an HRR, and
    // we've rejected ECH or sent GREASE ECH, then we need to carry forward the
    // exact same ECH extension we used in the first hello.
    if matches!(cx.data.ech_status, EchStatus::Rejected | EchStatus::Grease) & retryreq.is_some() {
        if let Some(prev_ech_ext) = input.prev_ech_ext.take() {
            exts.encrypted_client_hello = Some(prev_ech_ext);
        }
    }

    // Do we have a SessionID or ticket cached for this host?
    let tls13_session = prepare_resumption(&input.resuming, &mut exts, suite, cx, config);
    let has_tls13_session = tls13_session.is_some();
    let client_hello_finalizer = input
        .plan
        .as_ref()
        .and_then(|plan| plan.finalizer.as_ref())
        .cloned();
    if client_hello_finalizer.is_some() && has_tls13_session {
        return Err(Error::General(
            "ClientHello finalizer is not supported with TLS 1.3 PSK resumption".into(),
        ));
    }

    // Extensions MAY be randomized
    // but they also need to keep the same order as the previous ClientHello
    exts.order_seed = input.hello.extension_order_seed;

    let custom_cipher_suites = input
        .plan
        .as_ref()
        .and_then(|plan| plan.cipher_suites.as_ref());
    let advertised_cipher_suites = input
        .plan
        .as_ref()
        .and_then(|plan| plan.advertised_cipher_suites.as_ref());
    if custom_cipher_suites.is_some() && advertised_cipher_suites.is_some() {
        return Err(Error::General(
            "ClientHello cannot set both cipher suites and advertised cipher suites".into(),
        ));
    }

    let mut cipher_suites: Vec<_> = match (custom_cipher_suites, advertised_cipher_suites) {
        (Some(cipher_suites), None) => {
            validate_cipher_suites(
                cipher_suites.as_slice(),
                config,
                cx.common.protocol,
                &supported_versions,
            )?;
            cipher_suites.as_slice().to_vec()
        }
        (None, Some(cipher_suites)) => cipher_suites.as_slice().to_vec(),
        (None, None) => config
            .provider
            .cipher_suites
            .iter()
            .filter_map(|cs| match cs.usable_for_protocol(cx.common.protocol) {
                true => Some(cs.suite()),
                false => None,
            })
            .collect(),
        (Some(_), Some(_)) => unreachable!(),
    };

    if custom_cipher_suites.is_none()
        && advertised_cipher_suites.is_none()
        && supported_versions.tls12
    {
        // We don't do renegotiation at all, in fact.
        cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    apply_alpn_plan(input.plan.as_ref(), &mut exts, &mut input.hello);
    #[cfg(feature = "tls12")]
    let require_ems = config.require_ems;
    #[cfg(not(feature = "tls12"))]
    let require_ems = false;

    apply_extension_plan(
        input.plan.as_ref(),
        &mut exts,
        &mut input.hello,
        &supported_versions,
        require_ems,
    )?;
    apply_forced_extension_plan(input.plan.as_ref(), &mut exts);
    apply_raw_extension_plan(input.plan.as_ref(), &mut exts);
    apply_advertised_supported_versions_plan(input.plan.as_ref(), &mut exts)?;
    apply_advertised_supported_groups_plan(input.plan.as_ref(), &mut exts)?;
    apply_exact_extension_plan(input.plan.as_ref(), &mut exts)?;
    apply_raw_key_share_plan(input.plan.as_ref(), &mut exts)?;
    apply_padding_plan(input.plan.as_ref(), &mut exts)?;
    apply_grease_plan(input.plan.as_ref(), &mut exts, &mut cipher_suites)?;

    let mut chp_payload = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: input.random,
        session_id: input.session_id,
        cipher_suites,
        compression_methods: vec![Compression::Null],
        extensions: exts,
    };

    if let Some(order) = input
        .plan
        .as_ref()
        .and_then(|plan| plan.extension_order.as_ref())
    {
        let order = order
            .as_slice()
            .iter()
            .map(|extension| ExtensionType::from(extension.0))
            .collect();
        chp_payload
            .extensions
            .set_custom_order(order)?;
    }

    let ech_grease_config = input
        .plan
        .as_ref()
        .and_then(|plan| plan.grease_ech.as_ref())
        .or_else(|| {
            config
                .ech_mode
                .as_ref()
                .and_then(|mode| match mode {
                    EchMode::Grease(cfg) => Some(cfg),
                    _ => None,
                })
        });
    let ech_grease_ext = ech_grease_config.map(|cfg| {
        cfg.grease_ext(
            config.provider.secure_random,
            input.server_name.clone(),
            &chp_payload,
        )
    });
    let has_exact_ech = chp_payload
        .extensions
        .has_exact_extension(ExtensionType::EncryptedClientHello);
    if has_exact_ech && ech_state.is_some() {
        return Err(Error::General(
            "ClientHello exact encrypted_client_hello conflicts with managed ECH".into(),
        ));
    }
    if has_exact_ech && ech_state.is_none() && cx.data.ech_status == EchStatus::NotOffered {
        cx.data.ech_status = EchStatus::Grease;
    }

    match (cx.data.ech_status, &mut ech_state) {
        // If we haven't offered ECH, or have offered ECH but got a non-rejecting HRR, then
        // we need to replace the client hello payload with an ECH client hello payload.
        (EchStatus::NotOffered | EchStatus::Offered, Some(ech_state)) => {
            // Replace the client hello payload with an ECH client hello payload.
            chp_payload = ech_state.ech_hello(chp_payload, retryreq, &tls13_session)?;
            cx.data.ech_status = EchStatus::Offered;
            // Store the ECH extension in case we need to carry it forward in a subsequent hello.
            input.prev_ech_ext = chp_payload
                .encrypted_client_hello
                .clone();
        }
        // If we haven't offered ECH, and have no ECH state, then consider whether to use GREASE
        // ECH.
        (EchStatus::NotOffered, None) => {
            if !has_exact_ech {
                if let Some(grease_ext) = ech_grease_ext {
                    // Add the GREASE ECH extension.
                    let grease_ext = grease_ext?;
                    chp_payload.encrypted_client_hello = Some(grease_ext.clone());
                    cx.data.ech_status = EchStatus::Grease;
                    // Store the GREASE ECH extension in case we need to carry it forward in a
                    // subsequent hello.
                    input.prev_ech_ext = Some(grease_ext);
                }
            }
        }
        _ => {}
    }

    finalize_padding_plan(input.plan.as_ref(), &mut chp_payload)?;

    // Note what extensions we sent.
    input.hello.sent_extensions = chp_payload
        .extensions
        .collect_used_with_raw();
    let offered_cipher_suites = chp_payload.cipher_suites.clone();

    let mut chp = HandshakeMessagePayload(HandshakePayload::ClientHello(chp_payload));

    let tls13_early_data_key_schedule = match (ech_state.as_mut(), tls13_session) {
        // If we're performing ECH and resuming, then the PSK binder will have been dealt with
        // separately, and we need to take the early_data_key_schedule computed for the inner hello.
        (Some(ech_state), Some(tls13_session)) => ech_state
            .early_data_key_schedule
            .take()
            .map(|schedule| (tls13_session.suite(), schedule)),

        // When we're not doing ECH and resuming, then the PSK binder need to be filled in as
        // normal.
        (_, Some(tls13_session)) => Some((
            tls13_session.suite(),
            tls13::fill_in_psk_binder(&tls13_session, &transcript_buffer, &mut chp),
        )),

        // No early key schedule in other cases.
        _ => None,
    };

    let ch = Message {
        version: match retryreq {
            // <https://datatracker.ietf.org/doc/html/rfc8446#section-5.1>:
            // "This value MUST be set to 0x0303 for all records generated
            //  by a TLS 1.3 implementation ..."
            Some(_) => ProtocolVersion::TLSv1_2,
            // "... other than an initial ClientHello (i.e., one not
            // generated after a HelloRetryRequest), where it MAY also be
            // 0x0301 for compatibility purposes"
            //
            // (retryreq == None means we're in the "initial ClientHello" case)
            None => ProtocolVersion::TLSv1_0,
        },
        payload: MessagePayload::handshake(chp),
    };
    let ch = match client_hello_finalizer.as_deref() {
        Some(finalizer) => {
            let (ch, session_id) = finalize_client_hello(ch, finalizer)?;
            input.session_id = session_id;
            ch
        }
        None => ch,
    };

    if let Some(capture) = input
        .plan
        .as_ref()
        .and_then(|plan| plan.capture.as_ref())
    {
        let mut bytes = Vec::new();
        ch.payload.encode(&mut bytes);
        capture.capture_client_hello(&bytes)?;
    }

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut input.sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {ch:#?}");

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_data_key_schedule =
        tls13_early_data_key_schedule.map(|(resuming_suite, schedule)| {
            if !cx.data.early_data.is_enabled() {
                return schedule;
            }

            let (transcript_buffer, random) = match &ech_state {
                // When using ECH the early data key schedule is derived based on the inner
                // hello transcript and random.
                Some(ech_state) => (
                    &ech_state.inner_hello_transcript,
                    &ech_state.inner_hello_random.0,
                ),
                None => (&transcript_buffer, &input.random.0),
            };

            tls13::derive_early_traffic_secret(
                &*config.key_log,
                cx,
                resuming_suite.common.hash_provider,
                &schedule,
                &mut input.sent_tls13_fake_ccs,
                transcript_buffer,
                random,
            );
            schedule
        });

    let next = ExpectServerHello {
        input,
        transcript_buffer,
        early_data_key_schedule,
        offered_cipher_suites,
        offered_key_share: key_share,
        suite,
        ech_state,
    };

    Ok(if supported_versions.tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest {
            next,
            extra_exts: extra_exts.into_owned(),
        })
    } else {
        Box::new(next)
    })
}

fn finalize_client_hello(
    ch: Message<'static>,
    finalizer: &dyn FinalizesClientHello,
) -> Result<(Message<'static>, SessionId), Error> {
    let Message { version, payload } = ch;
    let MessagePayload::Handshake { encoded, .. } = payload else {
        return Err(Error::General(
            "ClientHello finalizer can only run on handshake messages".into(),
        ));
    };

    let original = encoded.into_vec();
    let session_id_range = client_hello_session_id_range(&original)?;
    let mut finalized = original.clone();
    finalizer.finalize_client_hello(&mut finalized)?;
    let session_id = SessionId::from_bytes(&finalized[session_id_range.clone()])
        .map_err(|_| Error::General("finalized ClientHello session id is invalid".into()))?;
    let parsed = validate_finalized_client_hello(&original, &finalized, session_id_range)?;

    Ok((
        Message {
            version,
            payload: MessagePayload::Handshake {
                parsed,
                encoded: Payload::new(finalized),
            },
        },
        session_id,
    ))
}

fn validate_finalized_client_hello(
    original: &[u8],
    finalized: &[u8],
    session_id_range: core::ops::Range<usize>,
) -> Result<HandshakeMessagePayload<'static>, Error> {
    if finalized.len() != original.len() {
        return Err(Error::General(
            "ClientHello finalizer must preserve ClientHello length".into(),
        ));
    }

    if original[..session_id_range.start] != finalized[..session_id_range.start]
        || original[session_id_range.end..] != finalized[session_id_range.end..]
    {
        return Err(Error::General(
            "ClientHello finalizer may only change legacy session id bytes".into(),
        ));
    }

    let mut reader = Reader::init(finalized);
    let parsed = HandshakeMessagePayload::read(&mut reader)?.into_owned();
    reader.expect_empty("finalized ClientHello")?;
    if !matches!(parsed.0, HandshakePayload::ClientHello(_)) {
        return Err(Error::General(
            "ClientHello finalizer must return a ClientHello handshake message".into(),
        ));
    }

    Ok(parsed)
}

fn client_hello_session_id_range(encoded: &[u8]) -> Result<core::ops::Range<usize>, Error> {
    const HEADER_LEN: usize = 4;
    const LEGACY_VERSION_LEN: usize = 2;
    const RANDOM_LEN: usize = 32;
    let session_id_len_offset = HEADER_LEN + LEGACY_VERSION_LEN + RANDOM_LEN;

    if encoded.len() <= session_id_len_offset {
        return Err(Error::General(
            "encoded ClientHello is too short for legacy session id".into(),
        ));
    }

    if encoded[0] != u8::from(HandshakeType::ClientHello) {
        return Err(Error::General(
            "ClientHello finalizer must receive a ClientHello handshake message".into(),
        ));
    }

    let encoded_len =
        (usize::from(encoded[1]) << 16) | (usize::from(encoded[2]) << 8) | usize::from(encoded[3]);
    if encoded_len + HEADER_LEN != encoded.len() {
        return Err(Error::General(
            "encoded ClientHello length header is inconsistent".into(),
        ));
    }

    let session_id_len = usize::from(encoded[session_id_len_offset]);
    if session_id_len > 32 {
        return Err(Error::General(
            "encoded ClientHello legacy session id is too long".into(),
        ));
    }

    let start = session_id_len_offset + 1;
    let end = start
        .checked_add(session_id_len)
        .ok_or_else(|| Error::General("encoded ClientHello session id is too large".into()))?;
    if end > encoded.len() {
        return Err(Error::General(
            "encoded ClientHello legacy session id is truncated".into(),
        ));
    }

    Ok(start..end)
}

/// Prepares `exts` and `cx` with TLS 1.2 or TLS 1.3 session
/// resumption.
///
/// - `suite` is `None` if this is the initial ClientHello, or
///   `Some` if we're retrying in response to
///   a HelloRetryRequest.
///
/// This function will push onto `exts` to
///
/// (a) request a new ticket if we don't have one,
/// (b) send our TLS 1.2 ticket after retrieving an 1.2 session,
/// (c) send a request for 1.3 early data if allowed and
/// (d) send a 1.3 preshared key if we have one.
///
/// It returns the TLS 1.3 PSKs, if any, for further processing.
fn prepare_resumption<'a>(
    resuming: &'a Option<persist::Retrieved<ClientSessionValue>>,
    exts: &mut ClientExtensions<'_>,
    suite: Option<SupportedCipherSuite>,
    cx: &mut ClientContext<'_>,
    config: &ClientConfig,
) -> Option<persist::Retrieved<&'a persist::Tls13ClientSessionValue>> {
    // Check whether we're resuming with a non-empty ticket.
    let resuming = match resuming {
        Some(resuming) if !resuming.ticket().is_empty() => resuming,
        _ => {
            if config.supports_version(ProtocolVersion::TLSv1_2)
                && config.resumption.tls12_resumption == Tls12Resumption::SessionIdOrTickets
            {
                // If we don't have a ticket, request one.
                exts.session_ticket = Some(ClientSessionTicket::Request);
            }
            return None;
        }
    };

    let Some(tls13) = resuming.map(|csv| csv.tls13()) else {
        // TLS 1.2; send the ticket if we have support this protocol version
        if config.supports_version(ProtocolVersion::TLSv1_2)
            && config.resumption.tls12_resumption == Tls12Resumption::SessionIdOrTickets
        {
            exts.session_ticket = Some(ClientSessionTicket::Offer(Payload::new(resuming.ticket())));
        }
        return None; // TLS 1.2, so nothing to return here
    };

    if !config.supports_version(ProtocolVersion::TLSv1_3) {
        return None;
    }

    // If the server selected TLS 1.2, we can't resume.
    let suite = match suite {
        Some(SupportedCipherSuite::Tls13(suite)) => Some(suite),
        #[cfg(feature = "tls12")]
        Some(SupportedCipherSuite::Tls12(_)) => return None,
        None => None,
    };

    // If the selected cipher suite can't select from the session's, we can't resume.
    if let Some(suite) = suite {
        suite.can_resume_from(tls13.suite())?;
    }

    tls13::prepare_resumption(config, cx, &tls13, exts, suite.is_some());
    Some(tls13)
}

pub(super) fn process_alpn_protocol(
    common: &mut CommonState,
    offered_protocols: &[ProtocolName],
    selected: Option<&ProtocolName>,
    check_selected_offered: bool,
) -> Result<(), Error> {
    common.alpn_protocol = selected.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.alpn_protocol {
        if check_selected_offered && !offered_protocols.contains(alpn_protocol) {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedApplicationProtocol,
            ));
        }
    }

    // RFC 9001 says: "While ALPN only specifies that servers use this alert, QUIC clients MUST
    // use error 0x0178 to terminate a connection when ALPN negotiation fails." We judge that
    // the user intended to use ALPN (rather than some out-of-band protocol negotiation
    // mechanism) if and only if any ALPN protocols were configured. This defends against badly-behaved
    // servers which accept a connection that requires an application-layer protocol they do not
    // understand.
    if common.is_quic() && common.alpn_protocol.is_none() && !offered_protocols.is_empty() {
        return Err(common.send_fatal_alert(
            AlertDescription::NoApplicationProtocol,
            Error::NoApplicationProtocol,
        ));
    }

    debug!(
        "ALPN protocol is {:?}",
        common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(v.as_ref()))
    );
    Ok(())
}

pub(super) fn process_server_cert_type_extension(
    common: &mut CommonState,
    config: &ClientConfig,
    server_cert_extension: Option<&CertificateType>,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    process_cert_type_extension(
        common,
        config
            .verifier
            .requires_raw_public_keys(),
        server_cert_extension.copied(),
        ExtensionType::ServerCertificateType,
    )
}

pub(super) fn process_client_cert_type_extension(
    common: &mut CommonState,
    config: &ClientConfig,
    client_cert_extension: Option<&CertificateType>,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    process_cert_type_extension(
        common,
        config
            .client_auth_cert_resolver
            .only_raw_public_keys(),
        client_cert_extension.copied(),
        ExtensionType::ClientCertificateType,
    )
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> NextStateOrError<'m>
    where
        Self: 'm,
    {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {server_hello:#?}");

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let config = &self.input.config;
        let tls13_supported = config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .selected_version
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if config.supports_version(TLSv1_2) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion.into());
                }

                if server_hello.selected_version.is_some() {
                    return Err({
                        cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::SelectedTls12UsingTls13VersionExtension,
                        )
                    });
                }

                TLSv1_2
            }
            _ => {
                let reason = match server_version {
                    TLSv1_2 | TLSv1_3 => PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                    _ => PeerIncompatible::ServerDoesNotSupportTls12Or13,
                };
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::ProtocolVersion, reason));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedCompression,
                )
            });
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .input
            .hello
            .server_sent_unsolicited_extensions(server_hello, &allowed_unsolicited)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(
                cx.common,
                &self.input.hello.alpn_protocols,
                server_hello
                    .selected_protocol
                    .as_ref()
                    .map(|s| s.as_ref()),
                self.input.config.check_selected_alpn,
            )?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = &server_hello.ec_point_formats {
            if !point_fmts.uncompressed {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints,
                ));
            }
        }

        if !self
            .offered_cipher_suites
            .contains(&server_hello.cipher_suite)
        {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerMisbehaved::SelectedUnofferedCipherSuite,
                )
            });
        }

        let suite = config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerMisbehaved::SelectedUnofferedCipherSuite,
                )
            })?;

        if version != suite.version().version {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnusableCipherSuiteForVersion,
                )
            });
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry,
                    )
                });
            }
            _ => {
                debug!("Using ciphersuite {suite:?}");
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_provider());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.input.random, server_hello.random);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                tls13::handle_server_hello(
                    cx,
                    server_hello,
                    randoms,
                    suite,
                    transcript,
                    self.early_data_key_schedule,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    &m,
                    self.ech_state,
                    self.input,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => tls12::CompleteServerHelloHandling {
                randoms,
                transcript,
                input: self.input,
            }
            .handle_server_hello(cx, suite, server_hello, tls13_supported),
        }
    }

    fn into_owned(self: Box<Self>) -> NextState<'static> {
        self
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState<'static> {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        mut self,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError<'static> {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {hrr:?}");

        cx.common.check_aligned_handshake()?;

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        let config = &self.next.input.config;

        if let (None, Some(req_group)) = (&hrr.cookie, hrr.key_share) {
            if offered_key_share.contains_group(req_group) {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup,
                    )
                });
            }
        }

        // Or has an empty cookie.
        if let Some(cookie) = &hrr.cookie {
            if cookie.0.is_empty() {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithEmptyCookie,
                    )
                });
            }
        }

        // Or asks us to change nothing.
        if hrr.cookie.is_none() && hrr.key_share.is_none() {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges,
                )
            });
        }

        // Or does not echo the session_id from our ClientHello:
        //
        // > the HelloRetryRequest has the same format as a ServerHello message,
        // > and the legacy_version, legacy_session_id_echo, cipher_suite, and
        // > legacy_compression_method fields have the same meaning
        // <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.4>
        //
        // and
        //
        // > A client which receives a legacy_session_id_echo field that does not
        // > match what it sent in the ClientHello MUST abort the handshake with an
        // > "illegal_parameter" alert.
        // <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3>
        if hrr.session_id != self.next.input.session_id {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId,
                )
            });
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.supported_versions {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
                    )
                });
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        if !self
            .next
            .offered_cipher_suites
            .contains(&hrr.cipher_suite)
        {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite,
                )
            });
        }

        let Some(cs) = config.find_cipher_suite(hrr.cipher_suite) else {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite,
                )
            });
        };

        // Or offers ECH related extensions when we didn't offer ECH.
        if cx.data.ech_status == EchStatus::NotOffered && hrr.encrypted_client_hello.is_some() {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch,
                )
            });
        }

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);
        cx.common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);

        // If we offered ECH, we need to confirm that the server accepted it.
        match (self.next.ech_state.as_ref(), cs.tls13()) {
            // If the server did not confirm, then note the new ECH status but
            // continue the handshake. We will abort with an ECH required error
            // at the end.
            (Some(ech_state), Some(tls13_cs))
                if !ech_state.confirm_hrr_acceptance(hrr, tls13_cs, cx.common)? =>
            {
                cx.data.ech_status = EchStatus::Rejected
            }
            (Some(_), None) => {
                unreachable!("ECH state should only be set when TLS 1.3 was negotiated")
            }
            _ => {}
        };

        // This is the draft19 change where the transcript became a tree
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(cs.hash_provider());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // If we offered ECH and the server accepted, we also need to update the separate
        // ECH transcript with the hello retry request message.
        if let Some(ech_state) = self.next.ech_state.as_mut() {
            ech_state.transcript_hrr_update(cs.hash_provider(), &m);
        }

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let key_share = match hrr.key_share {
            Some(group) if !offered_key_share.contains_group(group) => {
                if self
                    .next
                    .input
                    .plan
                    .as_ref()
                    .and_then(|plan| plan.fixed_x25519.as_ref())
                    .is_some()
                {
                    return Err(Error::General(
                        "fixed X25519 key share cannot be retried with a different X25519 group"
                            .into(),
                    ));
                }
                tls13::retry_key_share(config, group, &mut cx.common.kx_state).map_err(|_| {
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                    )
                })?
            }
            _ => offered_key_share,
        };

        emit_client_hello_for_retry(
            transcript_buffer,
            Some(hrr),
            Some(key_share),
            self.extra_exts,
            Some(cs),
            self.next.input,
            cx,
            self.next.ech_state,
        )
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHello(..)),
                ..
            } => self
                .into_expect_server_hello()
                .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(..)),
                ..
            } => self.handle_hello_retry_request(cx, m),
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
            )),
        }
    }

    fn into_owned(self: Box<Self>) -> NextState<'static> {
        self
    }
}

fn process_cert_type_extension(
    common: &mut CommonState,
    client_expects: bool,
    server_negotiated: Option<CertificateType>,
    extension_type: ExtensionType,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    match (client_expects, server_negotiated) {
        (true, Some(CertificateType::RawPublicKey)) => {
            Ok(Some((extension_type, CertificateType::RawPublicKey)))
        }
        (true, _) => Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Error::PeerIncompatible(PeerIncompatible::IncorrectCertificateTypeExtension),
        )),
        (_, Some(CertificateType::RawPublicKey)) => {
            unreachable!("Caught by `PeerMisbehaved::UnsolicitedEncryptedExtension`")
        }
        (_, _) => Ok(None),
    }
}

pub(super) enum ClientSessionValue {
    Tls13(persist::Tls13ClientSessionValue),
    #[cfg(feature = "tls12")]
    Tls12(persist::Tls12ClientSessionValue),
}

impl ClientSessionValue {
    fn retrieve(
        server_name: &ServerName<'static>,
        config: &ClientConfig,
        cx: &mut ClientContext<'_>,
    ) -> Option<persist::Retrieved<Self>> {
        let found = config
            .resumption
            .store
            .take_tls13_ticket(server_name)
            .map(ClientSessionValue::Tls13)
            .or_else(|| {
                #[cfg(feature = "tls12")]
                {
                    config
                        .resumption
                        .store
                        .tls12_session(server_name)
                        .map(ClientSessionValue::Tls12)
                }

                #[cfg(not(feature = "tls12"))]
                None
            })
            .and_then(|resuming| {
                resuming.compatible_config(&config.verifier, &config.client_auth_cert_resolver)
            })
            .and_then(|resuming| {
                let now = config
                    .current_time()
                    .map_err(|_err| debug!("Could not get current time: {_err}"))
                    .ok()?;

                let retrieved = persist::Retrieved::new(resuming, now);
                match retrieved.has_expired() {
                    false => Some(retrieved),
                    true => None,
                }
            })
            .or_else(|| {
                debug!("No cached session for {server_name:?}");
                None
            });

        if let Some(resuming) = &found {
            if cx.common.is_quic() {
                cx.common.quic.params = resuming
                    .tls13()
                    .map(|v| v.quic_params());
            }
        }

        found
    }

    fn common(&self) -> &persist::ClientSessionCommon {
        match self {
            Self::Tls13(inner) => &inner.common,
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => &inner.common,
        }
    }

    fn tls13(&self) -> Option<&persist::Tls13ClientSessionValue> {
        match self {
            Self::Tls13(v) => Some(v),
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => None,
        }
    }

    fn compatible_config(
        self,
        server_cert_verifier: &Arc<dyn ServerCertVerifier>,
        client_creds: &Arc<dyn ResolvesClientCert>,
    ) -> Option<Self> {
        match &self {
            Self::Tls13(v) => v
                .compatible_config(server_cert_verifier, client_creds)
                .then_some(self),
            #[cfg(feature = "tls12")]
            Self::Tls12(v) => v
                .compatible_config(server_cert_verifier, client_creds)
                .then_some(self),
        }
    }
}

impl Deref for ClientSessionValue {
    type Target = persist::ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        self.common()
    }
}
