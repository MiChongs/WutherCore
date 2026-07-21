#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc as StdArc, Mutex};

use pki_types::{CertificateDer, ServerName};

use crate::client::{
    ClientConfig, ClientConnection, ClientHelloAdvertisedCipherSuites,
    ClientHelloAdvertisedSupportedGroups, ClientHelloAdvertisedSupportedVersions,
    ClientHelloAlpnProtocols, ClientHelloCertificateCompressionAlgorithms, ClientHelloCipherSuites,
    ClientHelloContext, ClientHelloCustomizer, ClientHelloExactExtension,
    ClientHelloExactExtensions, ClientHelloExtensionOrder, ClientHelloExtensionPlan,
    ClientHelloForcedExtensions, ClientHelloGreaseExtension, ClientHelloGreasePlan,
    ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension,
    ClientHelloRawExtensions, ClientHelloRawKeyShare, ClientHelloRawKeyShares,
    ClientHelloSessionId, ClientHelloSignatureAlgorithms, ClientHelloSupportedGroups,
    ClientHelloSupportedVersions, EchStatus, FinalizesClientHello, Resumption, Tls12Resumption,
};
use crate::crypto::CryptoProvider;
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, ContentType, ProtocolVersion, SignatureScheme,
};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, EncryptedClientHello, HandshakeMessagePayload,
    HandshakePayload, HelloRetryRequest, Random, ServerHelloPayload, SessionId,
    SupportedEcPointFormats,
};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::sync::Arc;
use crate::{Error, PeerIncompatible, PeerMisbehaved, RootCertStore};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::sync::OnceLock;

    use super::super::*;
    use crate::client::AlwaysResolvesClientRawPublicKeys;
    use crate::crypto::cipher::MessageEncrypter;
    use crate::crypto::tls13::OkmBlock;
    use crate::enums::CertificateType;
    use crate::msgs::base::PayloadU8;
    use crate::msgs::enums::ECCurveType;
    use crate::msgs::handshake::{
        CertificateChain, EcParameters, HelloRetryRequestExtensions, KeyShareEntry,
        ServerEcdhParams, ServerExtensions, ServerKeyExchange, ServerKeyExchangeParams,
        ServerKeyExchangePayload,
    };
    use crate::msgs::message::PlainMessage;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{PrivateKeyDer, UnixTime};
    #[cfg(feature = "aws_lc_rs")]
    use crate::server::{ServerConfig, ServerConnection};
    use crate::sign::CertifiedKey;
    use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key};
    use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::{DigitallySignedStruct, DistinguishedName, KeyLog, version};

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.extensions.session_ticket.is_none());
    }

    #[test]
    fn test_no_renegotiation_scsv_on_tls_1_3() {
        let ch = client_hello_sent_for_config(
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap();
        assert!(
            !ch.cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        );
    }

    #[test]
    fn test_client_does_not_offer_sha1() {
        for version in crate::ALL_VERSIONS {
            let config =
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots())
                    .with_no_client_auth();
            let ch = client_hello_sent_for_config(config).unwrap();
            assert!(
                !ch.extensions
                    .signature_schemes
                    .as_ref()
                    .unwrap()
                    .contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }

    #[test]
    fn client_hello_customizer_can_fix_random() {
        let fixed_random = [0x42u8; 32];
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_random(fixed_random))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.random, Random::from(fixed_random));
    }

    #[test]
    fn client_hello_customizer_can_fix_session_id() {
        let session_id = vec![0x11, 0x22, 0x33, 0x44];
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_session_id(
                ClientHelloSessionId::try_from(session_id.clone()).unwrap(),
            ))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(ch.session_id.as_ref(), session_id.as_slice());
    }

    #[test]
    fn client_hello_customizer_captures_raw_client_hello() {
        let captured = StdArc::new(Mutex::new(Vec::new()));
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_capture(StdArc::new(
                RecordingClientHelloCapture {
                    bytes: captured.clone(),
                },
            )))),
        }));

        let emitted = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(*captured.lock().unwrap(), emitted);
    }

    #[test]
    fn client_hello_finalizer_patches_captured_and_emitted_session_id() {
        let captured = StdArc::new(Mutex::new(Vec::new()));
        let finalizer_called = StdArc::new(AtomicBool::new(false));
        let replacement_session_id = [0x5au8; 32];
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(vec![0; 32]).unwrap())
                    .with_finalizer(StdArc::new(PatchingClientHelloFinalizer {
                        replacement_session_id,
                        called: finalizer_called.clone(),
                    }))
                    .with_capture(StdArc::new(RecordingClientHelloCapture {
                        bytes: captured.clone(),
                    })),
            )),
        }));

        let emitted = client_hello_encoded_bytes_for_config(config).unwrap();
        let ch = client_hello_from_encoded(&emitted);

        assert!(finalizer_called.load(Ordering::SeqCst));
        assert_eq!(ch.session_id.as_ref(), replacement_session_id);
        assert_eq!(*captured.lock().unwrap(), emitted);
    }

    #[test]
    fn client_hello_finalizer_error_fails_before_emitting_client_hello() {
        let finalizer_called = StdArc::new(AtomicBool::new(false));
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(vec![0; 32]).unwrap())
                    .with_finalizer(StdArc::new(FailingClientHelloFinalizer {
                        called: finalizer_called.clone(),
                    })),
            )),
        }));

        let err = ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
            .unwrap_err();

        assert!(finalizer_called.load(Ordering::SeqCst));
        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("test finalizer failure"));
    }

    #[test]
    fn client_hello_finalizer_rejects_non_session_id_changes() {
        let finalizer_called = StdArc::new(AtomicBool::new(false));
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(vec![0; 32]).unwrap())
                    .with_finalizer(StdArc::new(MutatingClientHelloFinalizer {
                        mutation: ClientHelloFinalizerMutation::NonSessionByte,
                        called: finalizer_called.clone(),
                    })),
            )),
        }));

        let err = ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
            .unwrap_err();

        assert!(finalizer_called.load(Ordering::SeqCst));
        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("may only change legacy session id bytes"));
    }

    #[test]
    fn client_hello_finalizer_rejects_length_changes() {
        let finalizer_called = StdArc::new(AtomicBool::new(false));
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(vec![0; 32]).unwrap())
                    .with_finalizer(StdArc::new(MutatingClientHelloFinalizer {
                        mutation: ClientHelloFinalizerMutation::Length,
                        called: finalizer_called.clone(),
                    })),
            )),
        }));

        let err = ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
            .unwrap_err();

        assert!(finalizer_called.load(Ordering::SeqCst));
        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("must preserve ClientHello length"));
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_finalizer_session_id_completes_tls13_handshake() {
        let finalizer_called = StdArc::new(AtomicBool::new(false));
        let replacement_session_id = [0x5au8; 32];
        let provider = super::provider::default_provider();
        let mut client_config = ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        client_config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_session_id(ClientHelloSessionId::try_from(vec![0; 32]).unwrap())
                    .with_finalizer(StdArc::new(PatchingClientHelloFinalizer {
                        replacement_session_id,
                        called: finalizer_called.clone(),
                    })),
            )),
        }));
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        let mut client = ClientConnection::new(
            client_config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config.into()).unwrap();

        do_handshake(&mut client, &mut server);

        assert!(finalizer_called.load(Ordering::SeqCst));
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn client_hello_noop_customizer_preserves_normalized_shape() {
        let baseline = client_hello_shape_for_config(tls13_x25519_config_with_alpn())
            .unwrap()
            .with_sorted_extensions();
        assert!(!baseline.extensions.is_empty());

        let mut config = tls13_x25519_config_with_alpn();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(None),
        }));

        let customized = client_hello_shape_for_config(config)
            .unwrap()
            .with_sorted_extensions();

        assert_eq!(customized, baseline);
    }

    #[test]
    fn client_hello_empty_plan_preserves_normalized_shape() {
        let baseline = client_hello_shape_for_config(tls13_x25519_config_with_alpn())
            .unwrap()
            .with_sorted_extensions();
        assert!(!baseline.extensions.is_empty());

        let mut config = tls13_x25519_config_with_alpn();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new())),
        }));

        let customized = client_hello_shape_for_config(config)
            .unwrap()
            .with_sorted_extensions();

        assert_eq!(customized, baseline);
    }

    #[test]
    fn client_hello_customizer_can_fix_extension_order() {
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_extension_order(order))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions
                .used_extensions_in_encoding_order(),
            vec![
                ExtensionType::SupportedVersions,
                ExtensionType::ServerName,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::EllipticCurves,
                ExtensionType::ECPointFormats,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::StatusRequest,
                ExtensionType::KeyShare,
                ExtensionType::PSKKeyExchangeModes,
            ]
        );
    }

    #[test]
    fn client_hello_customizer_can_set_cipher_suites() {
        let cipher_suites = ClientHelloCipherSuites::try_from(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_cipher_suites(cipher_suites),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.cipher_suites,
            vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
            ]
        );
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_cipher_suite() {
        let cipher_suites =
            ClientHelloCipherSuites::try_from(vec![CipherSuite::TLS13_AES_128_CCM_8_SHA256])
                .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_cipher_suites(cipher_suites),
            )),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("cipher suite"));
    }

    #[test]
    fn client_hello_customizer_can_advertise_unsupported_cipher_suites() {
        let cipher_suites = ClientHelloAdvertisedCipherSuites::try_from(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_advertised_cipher_suites(cipher_suites),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.cipher_suites,
            vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ]
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn client_rejects_advertise_only_unsupported_cipher_suite_selection() {
        let cipher_suites = ClientHelloAdvertisedCipherSuites::try_from(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_advertised_cipher_suites(cipher_suites),
            )),
        }));

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::SelectedUnofferedCipherSuite.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn client_rejects_advertise_only_unadvertised_cipher_suite_selection() {
        let cipher_suites = ClientHelloAdvertisedCipherSuites::try_from(vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_advertised_cipher_suites(cipher_suites),
            )),
        }));

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::SelectedUnofferedCipherSuite.into()
        );
    }

    #[test]
    fn client_hello_customizer_can_set_supported_versions() {
        let versions = ClientHelloSupportedVersions::try_from(vec![
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_3,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_supported_versions(versions),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();
        let versions = ch
            .extensions
            .supported_versions
            .unwrap();

        assert_eq!(
            versions.as_slice(),
            &[ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3]
        );
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_supported_version() {
        let versions =
            ClientHelloSupportedVersions::try_from(vec![ProtocolVersion::TLSv1_2]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_supported_versions(versions),
            )),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("supported version"));
    }

    #[test]
    fn client_hello_customizer_can_set_supported_groups() {
        let groups =
            ClientHelloSupportedGroups::try_from(vec![NamedGroup::secp256r1, NamedGroup::X25519])
                .unwrap();
        let provider = CryptoProvider {
            kx_groups: vec![
                super::provider::kx_group::X25519,
                super::provider::kx_group::SECP256R1,
            ],
            ..super::provider::default_provider()
        };
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_supported_groups(groups))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions.named_groups.unwrap(),
            vec![NamedGroup::secp256r1, NamedGroup::X25519]
        );
        assert_eq!(
            ch.extensions.key_shares.unwrap()[0].group,
            NamedGroup::secp256r1
        );
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_supported_group() {
        let groups = ClientHelloSupportedGroups::try_from(vec![NamedGroup::secp256r1]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_supported_groups(groups))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("supported group"));
    }

    #[test]
    fn client_hello_customizer_can_advertise_legacy_versions_and_unknown_groups() {
        let versions = ClientHelloAdvertisedSupportedVersions::try_from(vec![
            ProtocolVersion::from(0x0a0a),
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_0,
        ])
        .unwrap();
        let groups = ClientHelloAdvertisedSupportedGroups::try_from(vec![
            NamedGroup::from(0x0a0a),
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::from(0x6399),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_advertised_supported_versions(versions)
                    .with_advertised_supported_groups(groups),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::SupportedVersions),
            )
            .unwrap(),
            vec![
                10, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01,
            ],
        );
        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::EllipticCurves)
            )
            .unwrap(),
            vec![0, 8, 0x0a, 0x0a, 0x11, 0xec, 0x00, 0x1d, 0x63, 0x99],
        );
    }

    #[test]
    fn client_hello_customizer_can_set_signature_algorithms() {
        let signature_algorithms = ClientHelloSignatureAlgorithms::try_from(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_signature_algorithms(signature_algorithms),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions.signature_schemes.unwrap(),
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        );
    }

    #[test]
    fn client_hello_customizer_can_set_duplicate_signature_algorithms() {
        let signature_algorithms = ClientHelloSignatureAlgorithms::try_from(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_signature_algorithms(signature_algorithms),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::SignatureAlgorithms),
            )
            .unwrap(),
            vec![0, 4, 0x04, 0x03, 0x04, 0x03],
        );
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_signature_algorithm() {
        let signature_algorithms =
            ClientHelloSignatureAlgorithms::try_from(vec![SignatureScheme::RSA_PKCS1_SHA1])
                .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_signature_algorithms(signature_algorithms),
            )),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("signature algorithm"));
    }

    #[test]
    fn client_hello_customizer_can_set_certificate_compression_algorithms() {
        static ZLIB_DECOMPRESSOR: TestCertDecompressor =
            TestCertDecompressor(CertificateCompressionAlgorithm::Zlib);
        static BROTLI_DECOMPRESSOR: TestCertDecompressor =
            TestCertDecompressor(CertificateCompressionAlgorithm::Brotli);

        let algorithms = ClientHelloCertificateCompressionAlgorithms::try_from(vec![
            CertificateCompressionAlgorithm::Brotli,
            CertificateCompressionAlgorithm::Zlib,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.cert_decompressors = vec![&ZLIB_DECOMPRESSOR, &BROTLI_DECOMPRESSOR];
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_certificate_compression_algorithms(algorithms),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        assert_eq!(
            ch.extensions
                .certificate_compression_algorithms
                .unwrap(),
            vec![
                CertificateCompressionAlgorithm::Brotli,
                CertificateCompressionAlgorithm::Zlib,
            ]
        );
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_certificate_compression_algorithm() {
        let algorithms = ClientHelloCertificateCompressionAlgorithms::try_from(vec![
            CertificateCompressionAlgorithm::Zlib,
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.cert_decompressors.clear();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_certificate_compression_algorithms(algorithms),
            )),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("certificate compression"));
    }

    #[test]
    fn client_hello_customizer_can_set_alpn_protocols() {
        let alpn =
            ClientHelloAlpnProtocols::try_from(vec![b"http/1.1".to_vec(), b"h2".to_vec()]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_alpn_protocols(alpn))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();
        let protocols = ch.extensions.protocols.unwrap();

        assert_eq!(protocols[0].as_ref(), b"http/1.1");
        assert_eq!(protocols[1].as_ref(), b"h2");
    }

    #[test]
    fn client_hello_alpn_protocols_rejects_empty_protocol_name() {
        assert!(ClientHelloAlpnProtocols::try_from(vec![Vec::new()]).is_err());
    }

    #[test]
    fn client_hello_customizer_can_disable_optional_extensions() {
        let disabled = vec![
            ExtensionType::ServerName,
            ExtensionType::StatusRequest,
            ExtensionType::ALProtocolNegotiation,
            ExtensionType::ExtendedMasterSecret,
            ExtensionType::ECPointFormats,
            ExtensionType::PSKKeyExchangeModes,
            ExtensionType::CompressCertificate,
        ];
        let extensions = ClientHelloExtensionPlan::try_from(
            disabled
                .iter()
                .map(|ext| u16::from(*ext))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_extensions(extensions))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();
        let used_extensions = ch
            .extensions
            .used_extensions_in_encoding_order();

        for extension in disabled {
            assert!(
                !used_extensions.contains(&extension),
                "{extension:?} was still emitted"
            );
        }
        assert!(ch.extensions.server_name.is_none());
        assert!(
            ch.extensions
                .certificate_status_request
                .is_none()
        );
        assert!(ch.extensions.protocols.is_none());
        assert!(
            ch.extensions
                .extended_master_secret_request
                .is_none()
        );
        assert!(ch.extensions.ec_point_formats.is_none());
        assert!(
            ch.extensions
                .preshared_key_modes
                .is_none()
        );
        assert!(
            ch.extensions
                .certificate_compression_algorithms
                .is_none()
        );
    }

    #[test]
    fn client_hello_customizer_rejects_disabling_required_extension() {
        let extensions =
            ClientHelloExtensionPlan::try_from(vec![u16::from(ExtensionType::SupportedVersions)])
                .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_extensions(extensions))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("required extension"));
    }

    #[test]
    fn client_hello_extension_plan_rejects_duplicate_disabled_extension() {
        assert!(
            ClientHelloExtensionPlan::try_from(vec![
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::ServerName),
            ])
            .is_err()
        );
    }

    #[test]
    fn client_hello_customizer_can_force_known_extensions() {
        let forced = ClientHelloForcedExtensions::new()
            .with_renegotiation_info_empty()
            .with_session_ticket_request()
            .with_signed_certificate_timestamp_empty();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::RenegotiationInfo),
            u16::from(ExtensionType::SessionTicket),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::SCT),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_forced_extensions(forced)
                    .with_extension_order(order),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_order(vec![
                u16::from(ExtensionType::SupportedVersions),
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::EllipticCurves),
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::RenegotiationInfo),
                u16::from(ExtensionType::SessionTicket),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::SCT),
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
            ])
            .expect_extension_body(
                u16::from(ExtensionType::RenegotiationInfo),
                ExpectedExtensionBody::Exact(vec![0]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::SessionTicket),
                ExpectedExtensionBody::Exact(vec![]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::SCT),
                ExpectedExtensionBody::Exact(vec![]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_customizer_can_insert_grease_values() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_cipher_suite_position(0)
            .with_supported_group_position(0)
            .with_key_share_position(0)
            .with_extension_position(0);
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_grease(grease))),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();
        let ch = client_hello_from_encoded(&encoded);

        assert_eq!(ch.cipher_suites[0], CipherSuite::from(0x0a0a));
        assert_eq!(
            ch.extensions
                .named_groups
                .as_ref()
                .unwrap()[0],
            NamedGroup::from(0x0a0a)
        );
        assert_eq!(
            ch.extensions
                .key_shares
                .as_ref()
                .unwrap()[0]
                .group,
            NamedGroup::from(0x0a0a)
        );
        assert_eq!(
            client_hello_extension_types_from_encoded(&encoded)[0],
            0x0a0a
        );
    }

    #[test]
    fn client_hello_customizer_can_insert_multiple_grease_extensions_with_payloads() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x0a0a, 0, vec![]).unwrap())
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x1a1a, 4, vec![0]).unwrap())
            .unwrap();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_extension_order(order)
                    .with_grease(grease),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_order(vec![
                0x0a0a,
                u16::from(ExtensionType::SupportedVersions),
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::EllipticCurves),
                0x1a1a,
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
            ])
            .expect_extension_body(0x0a0a, ExpectedExtensionBody::Exact(vec![]))
            .expect_extension_body(0x1a1a, ExpectedExtensionBody::Exact(vec![0]))
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_customizer_can_place_second_grease_extension_after_last_real_extension() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x0a0a, 0, vec![]).unwrap())
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x1a1a, 9, vec![0]).unwrap())
            .unwrap();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_extension_order(order)
                    .with_grease(grease),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_order(vec![
                0x0a0a,
                u16::from(ExtensionType::SupportedVersions),
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::EllipticCurves),
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
                0x1a1a,
            ])
            .expect_extension_body(0x0a0a, ExpectedExtensionBody::Exact(vec![]))
            .expect_extension_body(0x1a1a, ExpectedExtensionBody::Exact(vec![0]))
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_customizer_can_insert_supported_versions_grease() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_supported_version_position(0);
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_grease(grease))),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::SupportedVersions),
            )
            .unwrap(),
            vec![4, 0x0a, 0x0a, 0x03, 0x04]
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_plan_grease_ech_keeps_tls12_supported_versions() {
        let grease_ech = crate::client::EchGreaseConfig::new(
            crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
            crate::crypto::hpke::HpkePublicKey(vec![7; 32]),
        );
        let versions = ClientHelloSupportedVersions::try_from(vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ])
        .unwrap();
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_supported_versions(versions)
                    .with_grease_ech(grease_ech),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::SupportedVersions),
            )
            .unwrap(),
            vec![4, 0x03, 0x04, 0x03, 0x03]
        );
        assert!(
            client_hello_extension_types_from_encoded(&encoded)
                .contains(&u16::from(ExtensionType::EncryptedClientHello))
        );
    }

    #[test]
    fn client_hello_plan_exact_ech_marks_grease_ech_status() {
        let exact_ech = ClientHelloExactExtension::new(
            u16::from(ExtensionType::EncryptedClientHello),
            vec![0, 0, 1, 0, 1, 0, 0, 0, 1, 0],
        )
        .unwrap();
        let exact_extensions = ClientHelloExactExtensions::try_from(vec![exact_ech]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_exact_extensions(exact_extensions),
            )),
        }));
        let mut client =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();

        client
            .write_tls(&mut Vec::new())
            .unwrap();

        assert_eq!(client.ech_status(), EchStatus::Grease);
    }

    #[test]
    fn client_hello_oracle_places_raw_alps_with_alpn_compression_and_padding() {
        static BROTLI_DECOMPRESSOR: TestCertDecompressor =
            TestCertDecompressor(CertificateCompressionAlgorithm::Brotli);

        let alps = ClientHelloRawExtension::new(0x4469, vec![0, 3, b'h', b'2', 0]).unwrap();
        let raw_extensions = ClientHelloRawExtensions::try_from(vec![alps]).unwrap();
        let alpn =
            ClientHelloAlpnProtocols::try_from(vec![b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap();
        let compression = ClientHelloCertificateCompressionAlgorithms::try_from(vec![
            CertificateCompressionAlgorithm::Brotli,
        ])
        .unwrap();
        let padding = ClientHelloPaddingPlan::fixed(8).unwrap();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::ALProtocolNegotiation),
            u16::from(ExtensionType::CompressCertificate),
            0x4469,
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
            u16::from(ExtensionType::Padding),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.cert_decompressors = vec![&BROTLI_DECOMPRESSOR];
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_alpn_protocols(alpn)
                    .with_certificate_compression_algorithms(compression)
                    .with_raw_extensions(raw_extensions)
                    .with_extension_order(order)
                    .with_padding(padding),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_order(vec![
                u16::from(ExtensionType::SupportedVersions),
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::EllipticCurves),
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::ALProtocolNegotiation),
                u16::from(ExtensionType::CompressCertificate),
                0x4469,
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
                u16::from(ExtensionType::Padding),
            ])
            .expect_extension_body(
                0x4469,
                ExpectedExtensionBody::Exact(vec![0, 3, b'h', b'2', 0]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::Padding),
                ExpectedExtensionBody::Exact(vec![0; 8]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_oracle_can_place_forced_and_grease_extensions_before_padding() {
        static BROTLI_DECOMPRESSOR: TestCertDecompressor =
            TestCertDecompressor(CertificateCompressionAlgorithm::Brotli);

        let advertised_cipher_suites = ClientHelloAdvertisedCipherSuites::try_from(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ])
        .unwrap();
        let supported_versions = ClientHelloSupportedVersions::try_from(vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ])
        .unwrap();
        let supported_groups = ClientHelloSupportedGroups::try_from(vec![
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ])
        .unwrap();
        let key_shares = ClientHelloKeySharePlan::try_from(vec![NamedGroup::X25519]).unwrap();
        let signature_algorithms = ClientHelloSignatureAlgorithms::try_from(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
        ])
        .unwrap();
        let alpn =
            ClientHelloAlpnProtocols::try_from(vec![b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap();
        let compression = ClientHelloCertificateCompressionAlgorithms::try_from(vec![
            CertificateCompressionAlgorithm::Brotli,
        ])
        .unwrap();
        let raw_extensions = ClientHelloRawExtensions::try_from(vec![
            ClientHelloRawExtension::new(0x4469, vec![0, 3, b'h', b'2', 0]).unwrap(),
        ])
        .unwrap();
        let forced = ClientHelloForcedExtensions::new()
            .with_renegotiation_info_empty()
            .with_session_ticket_request()
            .with_signed_certificate_timestamp_empty();
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_cipher_suite_position(0)
            .with_supported_version_position(0)
            .with_supported_group_position(0)
            .with_key_share_position(0)
            .with_extension(ClientHelloGreaseExtension::new(0x0a0a, 0, vec![]).unwrap())
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x1a1a, 15, vec![0]).unwrap())
            .unwrap();
        let extension_order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::RenegotiationInfo),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::SessionTicket),
            u16::from(ExtensionType::ALProtocolNegotiation),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::SCT),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::CompressCertificate),
            0x4469,
            u16::from(ExtensionType::Padding),
        ])
        .unwrap();
        let padding = ClientHelloPaddingPlan::pad_to_handshake_size(512).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13, &version::TLS12])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.cert_decompressors = vec![&BROTLI_DECOMPRESSOR];
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_advertised_cipher_suites(advertised_cipher_suites)
                    .with_supported_versions(supported_versions)
                    .with_supported_groups(supported_groups)
                    .with_key_share_plan(key_shares)
                    .with_signature_algorithms(signature_algorithms)
                    .with_alpn_protocols(alpn)
                    .with_certificate_compression_algorithms(compression)
                    .with_raw_extensions(raw_extensions)
                    .with_forced_extensions(forced)
                    .with_grease(grease)
                    .with_extension_order(extension_order)
                    .with_padding(padding),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(encoded.len(), 512);
        let padding_body =
            client_hello_extension_body_from_encoded(&encoded, u16::from(ExtensionType::Padding))
                .unwrap();
        assert_eq!(padding_body.len(), 206);
        assert!(
            padding_body
                .iter()
                .all(|byte| *byte == 0)
        );
        ClientHelloOracle::new()
            .expect_extension_order(vec![
                0x0a0a,
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::RenegotiationInfo),
                u16::from(ExtensionType::EllipticCurves),
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::SessionTicket),
                u16::from(ExtensionType::ALProtocolNegotiation),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::SCT),
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
                u16::from(ExtensionType::SupportedVersions),
                u16::from(ExtensionType::CompressCertificate),
                0x4469,
                0x1a1a,
                u16::from(ExtensionType::Padding),
            ])
            .expect_extension_body(0x0a0a, ExpectedExtensionBody::Exact(vec![]))
            .expect_extension_body(
                u16::from(ExtensionType::RenegotiationInfo),
                ExpectedExtensionBody::Exact(vec![0]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::SessionTicket),
                ExpectedExtensionBody::Exact(vec![]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::SCT),
                ExpectedExtensionBody::Exact(vec![]),
            )
            .expect_extension_body(
                0x4469,
                ExpectedExtensionBody::Exact(vec![0, 3, b'h', b'2', 0]),
            )
            .expect_extension_body(0x1a1a, ExpectedExtensionBody::Exact(vec![0]))
            .expect_extension_body(
                u16::from(ExtensionType::Padding),
                ExpectedExtensionBody::Exact(vec![0; 206]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_oracle_matches_complex_shaped_fingerprint_surface() {
        let raw_extension = ClientHelloRawExtension::new(0x1234, vec![1, 2, 3]).unwrap();
        let raw_extensions = ClientHelloRawExtensions::try_from(vec![raw_extension]).unwrap();
        let extension_order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            0x1234,
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
            u16::from(ExtensionType::Padding),
        ])
        .unwrap();
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_cipher_suite_position(0)
            .with_supported_version_position(0)
            .with_supported_group_position(0)
            .with_key_share_position(0)
            .with_extension_position(0);
        let cipher_suites = ClientHelloCipherSuites::try_from(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ])
        .unwrap();
        let padding = ClientHelloPaddingPlan::fixed(4).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_cipher_suites(cipher_suites)
                    .with_raw_extensions(raw_extensions)
                    .with_extension_order(extension_order)
                    .with_grease(grease)
                    .with_padding(padding),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_client_version(ProtocolVersion::TLSv1_2)
            .expect_session_id_len(32)
            .expect_cipher_suites(vec![
                CipherSuite::from(0x0a0a),
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
            ])
            .expect_compression_methods(vec![Compression::Null])
            .expect_extension_order(vec![
                0x0a0a,
                u16::from(ExtensionType::SupportedVersions),
                0x1234,
                u16::from(ExtensionType::ServerName),
                u16::from(ExtensionType::SignatureAlgorithms),
                u16::from(ExtensionType::EllipticCurves),
                u16::from(ExtensionType::ECPointFormats),
                u16::from(ExtensionType::ExtendedMasterSecret),
                u16::from(ExtensionType::StatusRequest),
                u16::from(ExtensionType::KeyShare),
                u16::from(ExtensionType::PSKKeyExchangeModes),
                u16::from(ExtensionType::Padding),
            ])
            .expect_extension_body(
                u16::from(ExtensionType::SupportedVersions),
                ExpectedExtensionBody::Exact(vec![4, 0x0a, 0x0a, 0x03, 0x04]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::EllipticCurves),
                ExpectedExtensionBody::Exact(vec![0, 4, 0x0a, 0x0a, 0x00, 0x1d]),
            )
            .expect_extension_body(
                u16::from(ExtensionType::KeyShare),
                ExpectedExtensionBody::KeyShare(vec![(0x0a0a, 1), (0x001d, 32)]),
            )
            .expect_extension_body(0x1234, ExpectedExtensionBody::Exact(vec![1, 2, 3]))
            .expect_extension_body(
                u16::from(ExtensionType::Padding),
                ExpectedExtensionBody::Exact(vec![0, 0, 0, 0]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_grease_plan_rejects_non_grease_values() {
        assert!(ClientHelloGreasePlan::new(0x1234).is_err());
    }

    #[test]
    fn client_hello_grease_extension_rejects_non_grease_values() {
        assert!(ClientHelloGreaseExtension::new(0x1234, 0, vec![]).is_err());
    }

    #[test]
    fn client_hello_grease_plan_rejects_duplicate_extension_values() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x1a1a, 0, vec![]).unwrap())
            .unwrap();

        assert!(
            grease
                .with_extension(ClientHelloGreaseExtension::new(0x1a1a, 1, vec![0]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn client_hello_customizer_rejects_out_of_range_grease_position() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_supported_group_position(99);
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_grease(grease))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("GREASE position"));
    }

    #[test]
    fn client_hello_customizer_rejects_out_of_range_grease_extension_position() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_extension(ClientHelloGreaseExtension::new(0x0a0a, 99, vec![]).unwrap())
            .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_grease(grease))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("GREASE position"));
    }

    #[test]
    fn client_hello_customizer_rejects_out_of_range_supported_versions_grease_position() {
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_supported_version_position(99);
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_grease(grease))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("GREASE position"));
    }

    #[cfg(all(
        feature = "aws-lc-rs",
        feature = "prefer-post-quantum",
        not(feature = "fips")
    ))]
    #[test]
    fn client_hello_customizer_can_set_key_share_groups() {
        let key_shares =
            ClientHelloKeySharePlan::try_from(vec![NamedGroup::X25519, NamedGroup::X25519MLKEM768])
                .unwrap();
        let mut config = ClientConfig::builder_with_provider(
            crate::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_key_share_plan(key_shares))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();
        let key_shares = ch.extensions.key_shares.unwrap();

        assert_eq!(key_shares.len(), 2);
        assert_eq!(key_shares[0].group, NamedGroup::X25519);
        assert_eq!(key_shares[1].group, NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn client_hello_customizer_rejects_unsupported_key_share_group() {
        let key_shares = ClientHelloKeySharePlan::try_from(vec![NamedGroup::secp256r1]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_key_share_plan(key_shares))),
        }));

        let err = client_hello_sent_for_config(config).unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("key share"));
    }

    #[test]
    fn client_hello_customizer_can_add_raw_key_shares() {
        let raw_key_share =
            ClientHelloRawKeyShare::new(NamedGroup::from(0x6399), vec![0x42; 1216]).unwrap();
        let raw_key_shares = ClientHelloRawKeyShares::try_from(vec![raw_key_share]).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new().with_raw_key_shares(raw_key_shares),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_body(
                u16::from(ExtensionType::KeyShare),
                ExpectedExtensionBody::KeyShare(vec![(0x001d, 32), (0x6399, 1216)]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_customizer_can_position_raw_key_shares() {
        let raw_key_share =
            ClientHelloRawKeyShare::new_at(0, NamedGroup::X25519MLKEM768, vec![0x42; 1216])
                .unwrap();
        let raw_key_shares = ClientHelloRawKeyShares::try_from(vec![raw_key_share]).unwrap();
        let grease = ClientHelloGreasePlan::new(0x0a0a)
            .unwrap()
            .with_key_share_position(0);
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_raw_key_shares(raw_key_shares)
                    .with_grease(grease),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        ClientHelloOracle::new()
            .expect_extension_body(
                u16::from(ExtensionType::KeyShare),
                ExpectedExtensionBody::KeyShare(vec![(0x0a0a, 1), (0x11ec, 1216), (0x001d, 32)]),
            )
            .assert_matches_encoded(&encoded);
    }

    #[test]
    fn client_hello_raw_key_share_rejects_empty_payloads() {
        assert!(ClientHelloRawKeyShare::new(NamedGroup::from(0x6399), Vec::new()).is_err());
    }

    #[test]
    fn client_hello_key_share_plan_rejects_duplicate_groups() {
        assert!(
            ClientHelloKeySharePlan::try_from(vec![NamedGroup::X25519, NamedGroup::X25519])
                .is_err()
        );
    }

    #[test]
    fn client_hello_customizer_can_add_fixed_padding() {
        let padding = ClientHelloPaddingPlan::fixed(16).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_padding(padding))),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();
        let ch = client_hello_from_encoded(&encoded);

        assert_eq!(
            client_hello_extension_body_from_encoded(&encoded, u16::from(ExtensionType::Padding))
                .unwrap(),
            vec![0u8; 16]
        );
        assert!(
            ch.extensions
                .used_extensions_in_encoding_order()
                .contains(&ExtensionType::Padding)
        );
    }

    #[test]
    fn client_hello_customizer_can_pad_to_handshake_size() {
        let base_len = client_hello_encoded_bytes_for_config(
            ClientConfig::builder_with_provider(x25519_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap()
        .len();
        let target_len = base_len + 32;
        let padding = ClientHelloPaddingPlan::pad_to_handshake_size(target_len).unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_padding(padding))),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();
        let padding =
            client_hello_extension_body_from_encoded(&encoded, u16::from(ExtensionType::Padding))
                .unwrap();

        assert_eq!(encoded.len(), target_len);
        assert!(padding.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn client_hello_customizer_padding_rejects_oversized_fixed_length() {
        assert!(ClientHelloPaddingPlan::fixed(u16::MAX as usize + 1).is_err());
    }

    #[test]
    fn client_hello_customizer_can_add_raw_unknown_extension() {
        let raw_extension = ClientHelloRawExtension::new(0x1234, vec![1, 2, 3]).unwrap();
        let raw_extensions = ClientHelloRawExtensions::try_from(vec![raw_extension]).unwrap();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            0x1234,
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_raw_extensions(raw_extensions)
                    .with_extension_order(order),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_types_from_encoded(&encoded)[1],
            0x1234
        );
        assert_eq!(
            client_hello_extension_body_from_encoded(&encoded, 0x1234).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn client_hello_raw_extension_rejects_known_and_grease_types() {
        assert!(
            ClientHelloRawExtension::new(u16::from(ExtensionType::ServerName), Vec::new()).is_err()
        );
        assert!(ClientHelloRawExtension::new(0x0a0a, Vec::new()).is_err());
    }

    #[test]
    fn client_hello_customizer_can_insert_exact_known_extension() {
        let exact_ech = ClientHelloExactExtension::new(
            u16::from(ExtensionType::EncryptedClientHello),
            vec![0x42; 186],
        )
        .unwrap();
        let exact_extensions = ClientHelloExactExtensions::try_from(vec![exact_ech]).unwrap();
        let order = ClientHelloExtensionOrder::try_from(vec![
            u16::from(ExtensionType::SupportedVersions),
            u16::from(ExtensionType::EncryptedClientHello),
            u16::from(ExtensionType::ServerName),
            u16::from(ExtensionType::SignatureAlgorithms),
            u16::from(ExtensionType::EllipticCurves),
            u16::from(ExtensionType::ECPointFormats),
            u16::from(ExtensionType::ExtendedMasterSecret),
            u16::from(ExtensionType::StatusRequest),
            u16::from(ExtensionType::KeyShare),
            u16::from(ExtensionType::PSKKeyExchangeModes),
        ])
        .unwrap();
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_exact_extensions(exact_extensions)
                    .with_extension_order(order),
            )),
        }));

        let encoded = client_hello_encoded_bytes_for_config(config).unwrap();

        assert_eq!(
            client_hello_extension_types_from_encoded(&encoded)[1],
            u16::from(ExtensionType::EncryptedClientHello)
        );
        assert_eq!(
            client_hello_extension_body_from_encoded(
                &encoded,
                u16::from(ExtensionType::EncryptedClientHello),
            )
            .unwrap(),
            vec![0x42; 186],
        );
    }

    #[test]
    fn client_hello_exact_extension_rejects_unknown_grease_and_psk_types() {
        assert!(ClientHelloExactExtension::new(0x1234, Vec::new()).is_err());
        assert!(ClientHelloExactExtension::new(0x0a0a, Vec::new()).is_err());
        assert!(
            ClientHelloExactExtension::new(u16::from(ExtensionType::PreSharedKey), Vec::new())
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_missing_emitted_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.ec_point_formats = Some(SupportedEcPointFormats::default());

        assert!(
            extensions
                .set_custom_order(vec![ExtensionType::ExtendedMasterSecret])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_extra_non_emitted_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ECPointFormats,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_duplicate_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ExtendedMasterSecret,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_forced_final_extension() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.encrypted_client_hello = Some(EncryptedClientHello::Inner);

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::EncryptedClientHello,
                ])
                .is_err()
        );
    }

    #[test]
    fn client_extensions_custom_order_rejects_contiguous_extension_and_appends_it_once() {
        let mut extensions = ClientExtensions::default();
        extensions.extended_master_secret_request = Some(());
        extensions.ec_point_formats = Some(SupportedEcPointFormats::default());
        extensions
            .contiguous_extensions
            .push(ExtensionType::ECPointFormats);

        assert!(
            extensions
                .set_custom_order(vec![
                    ExtensionType::ExtendedMasterSecret,
                    ExtensionType::ECPointFormats,
                ])
                .is_err()
        );
        extensions
            .set_custom_order(vec![ExtensionType::ExtendedMasterSecret])
            .unwrap();

        assert_eq!(
            extensions.used_extensions_in_encoding_order(),
            vec![
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::ECPointFormats,
            ]
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_customizer_can_set_fixed_x25519_key_share() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let mut config = ClientConfig::builder_with_provider(aws_lc_x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_fixed_x25519(
                crate::client::FixedX25519KeyShare::new(private_key).with_observer(StdArc::new(
                    RecordingX25519KeyShare {
                        public_key: observed_public.clone(),
                    },
                )),
            ))),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        let key_share = ch
            .extensions
            .key_shares
            .as_ref()
            .unwrap()
            .iter()
            .find(|share| share.group == NamedGroup::X25519)
            .unwrap();
        assert_eq!(key_share.payload.0.as_slice(), expected_public.as_slice());
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_customizer_can_set_fixed_x25519_inside_hybrid_key_share() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let key_shares =
            ClientHelloKeySharePlan::try_from(vec![NamedGroup::X25519MLKEM768]).unwrap();
        let provider = CryptoProvider {
            kx_groups: vec![crate::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
            ..crate::crypto::aws_lc_rs::default_provider()
        };
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_key_share_plan(key_shares)
                    .with_fixed_x25519(
                        crate::client::FixedX25519KeyShare::new(private_key).with_observer(
                            StdArc::new(RecordingX25519KeyShare {
                                public_key: observed_public.clone(),
                            }),
                        ),
                    ),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        let key_share = ch
            .extensions
            .key_shares
            .as_ref()
            .unwrap()
            .iter()
            .find(|share| share.group == NamedGroup::X25519MLKEM768)
            .unwrap();
        assert_eq!(
            &key_share.payload.0[key_share.payload.0.len() - 32..],
            expected_public.as_slice()
        );
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn client_hello_customizer_can_set_fixed_x25519_inside_draft_kyber_key_share() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let draft_group = NamedGroup::Unknown(0x6399);
        let key_shares = ClientHelloKeySharePlan::try_from(vec![draft_group]).unwrap();
        let provider = CryptoProvider {
            kx_groups: vec![crate::crypto::aws_lc_rs::kx_group::X25519KYBER768DRAFT00],
            ..crate::crypto::aws_lc_rs::default_provider()
        };
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_key_share_plan(key_shares)
                    .with_fixed_x25519(
                        crate::client::FixedX25519KeyShare::new(private_key).with_observer(
                            StdArc::new(RecordingX25519KeyShare {
                                public_key: observed_public.clone(),
                            }),
                        ),
                    ),
            )),
        }));

        let ch = client_hello_sent_for_config(config).unwrap();

        let key_share = ch
            .extensions
            .key_shares
            .as_ref()
            .unwrap()
            .first()
            .unwrap();
        assert_eq!(key_share.group, draft_group);
        assert_eq!(&key_share.payload.0[..32], expected_public.as_slice());
        assert_eq!(key_share.payload.0.len(), 1216);
        assert!(
            key_share.payload.0[32..]
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn fixed_x25519_key_share_completes_tls13_handshake() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let provider = aws_lc_x25519_provider();
        let mut client_config = ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        client_config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(ClientHelloPlan::new().with_fixed_x25519(
                crate::client::FixedX25519KeyShare::new(private_key).with_observer(StdArc::new(
                    RecordingX25519KeyShare {
                        public_key: observed_public.clone(),
                    },
                )),
            ))),
        }));
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        let mut client = ClientConnection::new(
            client_config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config.into()).unwrap();

        do_handshake(&mut client, &mut server);

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn fixed_x25519_draft_kyber_key_share_completes_tls13_handshake() {
        let private_key =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let observed_public = StdArc::new(Mutex::new(None));
        let draft_group = NamedGroup::Unknown(0x6399);
        let key_shares = ClientHelloKeySharePlan::try_from(vec![draft_group]).unwrap();
        let provider = CryptoProvider {
            kx_groups: vec![crate::crypto::aws_lc_rs::kx_group::X25519KYBER768DRAFT00],
            ..crate::crypto::aws_lc_rs::default_provider()
        };
        let mut client_config = ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        client_config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_key_share_plan(key_shares)
                    .with_fixed_x25519(
                        crate::client::FixedX25519KeyShare::new(private_key).with_observer(
                            StdArc::new(RecordingX25519KeyShare {
                                public_key: observed_public.clone(),
                            }),
                        ),
                    ),
            )),
        }));
        let server_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        let mut client = ClientConnection::new(
            client_config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config.into()).unwrap();

        do_handshake(&mut client, &mut server);

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(
            observed_public
                .lock()
                .unwrap()
                .unwrap()
                .as_slice(),
            expected_public.as_slice()
        );
    }

    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    #[test]
    fn fixed_x25519_without_aws_lc_fails_loudly() {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.client_hello_customizer = Some(StdArc::new(StaticClientHelloCustomizer {
            plan: Mutex::new(Some(
                ClientHelloPlan::new()
                    .with_fixed_x25519(crate::client::FixedX25519KeyShare::new([1u8; 32])),
            )),
        }));

        let err = ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
            .unwrap_err();

        let Error::General(message) = err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(message.contains("X25519"));
        assert!(message.contains("aws_lc_rs") || message.contains("aws-lc"));
    }

    #[test]
    fn client_hello_customizer_session_id_rejects_long_values() {
        let too_long = vec![0xaau8; 33];

        assert!(ClientHelloSessionId::try_from(too_long).is_err());
    }

    #[test]
    fn test_client_rejects_hrr_with_varied_session_id() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // server replies with HRR, but does not echo `session_id` as required.
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };

        conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }

        let config = Arc::new(config);
        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
        );
    }

    #[test]
    fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
        let cas_sending_server_verifier =
            ServerVerifierWithAuthorityNames(vec![DistinguishedName::from(b"hello".to_vec())]);

        for (protocol_version, cas_extension_expected) in
            [(&version::TLS12, false), (&version::TLS13, true)]
        {
            let client_hello = client_hello_sent_for_config(
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[protocol_version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                    .with_no_client_auth(),
            )
            .unwrap();
            assert_eq!(
                client_hello
                    .extensions
                    .certificate_authority_names
                    .is_some(),
                cas_extension_expected
            );
        }
    }

    /// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
        let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
        let config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let cert = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                    &b"does not matter"[..],
                )])),
            )),
        };
        conn.read_tls(&mut cert.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_kx = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                    ServerKeyExchange {
                        dss: DigitallySignedStruct::new(
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            b"also does not matter".to_vec(),
                        ),
                        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                            curve_params: EcParameters {
                                curve_type: ECCurveType::NamedCurve,
                                named_group: NamedGroup::X25519,
                            },
                            public: PayloadU8::new(vec![0xab; 32]),
                        }),
                    },
                )),
            )),
        };
        conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_done = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHelloDone,
            )),
        };
        conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        assert!(
            verifier
                .seen_sha1_signature
                .load(Ordering::SeqCst)
        );
    }

    #[derive(Debug, Default)]
    struct ExpectSha1EcdsaVerifier {
        seen_sha1_signature: AtomicBool,
    }

    impl ServerCertVerifier for ExpectSha1EcdsaVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
            self.seen_sha1_signature
                .store(true, Ordering::SeqCst);
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_SHA1_Legacy]
        }
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions::default()),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::X509),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::X509),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_accepts_rpk_server() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::RawPublicKey),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Ok(())
        );
    }

    fn client_requiring_rpk_receives_server_ee(
        encrypted_extensions: ServerExtensions<'_>,
    ) -> Result<(), Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut conn = ClientConnection::new(
            client_config_for_rpk(fake_server_crypto.clone()).into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
            )),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets().map(|_| ())
    }

    fn client_config_for_rpk(key_log: Arc<dyn KeyLog>) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
                client_certified_key(),
            ))));
        config.key_log = key_log;
        config
    }

    fn client_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(client_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn client_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
        )
        .unwrap()
    }

    fn x25519_provider() -> CryptoProvider {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
        // creation of fake server messages.
        CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        }
    }

    fn tls13_x25519_config_with_alpn() -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }

    #[cfg(feature = "aws_lc_rs")]
    fn aws_lc_x25519_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![crate::crypto::aws_lc_rs::kx_group::X25519],
            ..crate::crypto::aws_lc_rs::default_provider()
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
        )
        .unwrap()
    }

    #[cfg(feature = "aws_lc_rs")]
    fn server_cert() -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/inter.der")[..]),
        ]
    }

    #[cfg(feature = "aws_lc_rs")]
    fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
        while client.is_handshaking() || server.is_handshaking() {
            transfer_client_to_server(client, server);
            server.process_new_packets().unwrap();
            transfer_server_to_client(server, client);
            client.process_new_packets().unwrap();
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn transfer_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
        let mut buf = [0u8; 262144];

        while client.wants_write() {
            let sz = client
                .write_tls(&mut &mut buf[..])
                .unwrap();
            if sz == 0 {
                return;
            }

            let mut offs = 0;
            while offs < sz {
                offs += server
                    .read_tls(&mut &buf[offs..sz])
                    .unwrap();
            }
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn transfer_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
        let mut buf = [0u8; 262144];

        while server.wants_write() {
            let sz = server
                .write_tls(&mut &mut buf[..])
                .unwrap();
            if sz == 0 {
                return;
            }

            let mut offs = 0;
            while offs < sz {
                offs += client
                    .read_tls(&mut &buf[offs..sz])
                    .unwrap();
            }
        }
    }

    #[derive(Clone, Debug)]
    struct ServerVerifierWithAuthorityNames(Vec<DistinguishedName>);

    impl ServerCertVerifier for ServerVerifierWithAuthorityNames {
        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            Some(self.0.as_slice())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }
    }

    #[derive(Debug)]
    struct ServerVerifierRequiringRpk;

    impl ServerCertVerifier for ServerVerifierRequiringRpk {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct FakeServerCrypto {
        server_handshake_secret: OnceLock<Vec<u8>>,
    }

    impl FakeServerCrypto {
        fn new() -> Self {
            Self {
                server_handshake_secret: OnceLock::new(),
            }
        }

        fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self
                .server_handshake_secret
                .get()
                .unwrap();

            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));

            // Derive Encrypter
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.encrypter(key, iv)
        }
    }

    impl KeyLog for FakeServerCrypto {
        fn will_log(&self, _label: &str) -> bool {
            true
        }

        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                self.server_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            }
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[cfg(all(
    feature = "aws-lc-rs",
    feature = "prefer-post-quantum",
    not(feature = "fips")
))]
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
    assert_eq!(key_shares[1].group, NamedGroup::X25519);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    use crate::crypto::aws_lc_rs;
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
}

#[derive(Debug)]
struct StaticClientHelloCustomizer {
    plan: Mutex<Option<ClientHelloPlan>>,
}

impl ClientHelloCustomizer for StaticClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error> {
        Ok(self.plan.lock().unwrap().take())
    }
}

#[derive(Debug)]
struct RecordingClientHelloCapture {
    bytes: StdArc<Mutex<Vec<u8>>>,
}

impl crate::client::CapturesClientHello for RecordingClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), Error> {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

#[derive(Debug)]
struct PatchingClientHelloFinalizer {
    replacement_session_id: [u8; 32],
    called: StdArc<AtomicBool>,
}

impl FinalizesClientHello for PatchingClientHelloFinalizer {
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        self.called
            .store(true, Ordering::SeqCst);
        assert_eq!(bytes[38], 32);
        assert_eq!(&bytes[39..71], &[0; 32]);
        bytes[39..71].copy_from_slice(&self.replacement_session_id);
        Ok(())
    }
}

#[derive(Debug)]
struct FailingClientHelloFinalizer {
    called: StdArc<AtomicBool>,
}

impl FinalizesClientHello for FailingClientHelloFinalizer {
    fn finalize_client_hello(&self, _bytes: &mut Vec<u8>) -> Result<(), Error> {
        self.called
            .store(true, Ordering::SeqCst);
        Err(Error::General("test finalizer failure".into()))
    }
}

#[derive(Debug)]
struct MutatingClientHelloFinalizer {
    mutation: ClientHelloFinalizerMutation,
    called: StdArc<AtomicBool>,
}

#[derive(Debug)]
enum ClientHelloFinalizerMutation {
    NonSessionByte,
    Length,
}

impl FinalizesClientHello for MutatingClientHelloFinalizer {
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        self.called
            .store(true, Ordering::SeqCst);
        match self.mutation {
            ClientHelloFinalizerMutation::NonSessionByte => bytes[10] ^= 0xff,
            ClientHelloFinalizerMutation::Length => bytes.push(0),
        }
        Ok(())
    }
}

#[cfg(feature = "aws_lc_rs")]
#[derive(Debug)]
struct RecordingX25519KeyShare {
    public_key: StdArc<Mutex<Option<[u8; 32]>>>,
}

#[cfg(feature = "aws_lc_rs")]
impl crate::client::ObservesX25519KeyShare for RecordingX25519KeyShare {
    fn observe_x25519_key_share(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        *self.public_key.lock().unwrap() = Some(*public_key);
        Ok(())
    }
}

#[derive(Debug)]
struct TestCertDecompressor(CertificateCompressionAlgorithm);

impl crate::compress::CertDecompressor for TestCertDecompressor {
    fn decompress(
        &self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(), crate::compress::DecompressionFailed> {
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientHelloShape {
    client_version: ProtocolVersion,
    session_id_len: usize,
    cipher_suites: Vec<CipherSuite>,
    compression_methods: Vec<Compression>,
    extensions: Vec<ClientHelloExtensionShape>,
}

impl ClientHelloShape {
    fn with_sorted_extensions(mut self) -> Self {
        self.extensions
            .sort_by_key(|extension| extension.extension_type);
        self
    }
}

#[derive(Default)]
struct ClientHelloOracle {
    client_version: Option<ProtocolVersion>,
    session_id_len: Option<usize>,
    cipher_suites: Option<Vec<CipherSuite>>,
    compression_methods: Option<Vec<Compression>>,
    extension_order: Option<Vec<u16>>,
    extension_bodies: Vec<(u16, ExpectedExtensionBody)>,
}

impl ClientHelloOracle {
    fn new() -> Self {
        Self::default()
    }

    fn expect_client_version(mut self, version: ProtocolVersion) -> Self {
        self.client_version = Some(version);
        self
    }

    fn expect_session_id_len(mut self, len: usize) -> Self {
        self.session_id_len = Some(len);
        self
    }

    fn expect_cipher_suites(mut self, cipher_suites: Vec<CipherSuite>) -> Self {
        self.cipher_suites = Some(cipher_suites);
        self
    }

    fn expect_compression_methods(mut self, methods: Vec<Compression>) -> Self {
        self.compression_methods = Some(methods);
        self
    }

    fn expect_extension_order(mut self, order: Vec<u16>) -> Self {
        self.extension_order = Some(order);
        self
    }

    fn expect_extension_body(mut self, extension_type: u16, body: ExpectedExtensionBody) -> Self {
        self.extension_bodies
            .push((extension_type, body));
        self
    }

    fn assert_matches_encoded(self, encoded: &[u8]) {
        let shape = client_hello_shape_from_encoded(encoded);

        if let Some(expected) = self.client_version {
            assert_eq!(shape.client_version, expected, "ClientHello legacy_version");
        }
        if let Some(expected) = self.session_id_len {
            assert_eq!(shape.session_id_len, expected, "ClientHello session_id len");
        }
        if let Some(expected) = self.cipher_suites {
            assert_eq!(shape.cipher_suites, expected, "ClientHello cipher_suites");
        }
        if let Some(expected) = self.compression_methods {
            assert_eq!(
                shape.compression_methods, expected,
                "ClientHello compression_methods"
            );
        }
        if let Some(expected) = self.extension_order {
            let actual = shape
                .extensions
                .iter()
                .map(|extension| extension.extension_type)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "ClientHello extension order");
        }

        for (expected_type, expected_body) in self.extension_bodies {
            let actual = shape
                .extensions
                .iter()
                .find(|extension| extension.extension_type == expected_type)
                .unwrap_or_else(|| {
                    panic!("ClientHello extension 0x{expected_type:04x} was not emitted")
                });
            assert_eq!(
                actual.body,
                expected_body.into_shape(),
                "ClientHello extension 0x{expected_type:04x} body"
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientHelloExtensionShape {
    extension_type: u16,
    body: ClientHelloExtensionBodyShape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExpectedExtensionBody {
    Exact(Vec<u8>),
    KeyShare(Vec<(u16, usize)>),
}

impl ExpectedExtensionBody {
    fn into_shape(self) -> ClientHelloExtensionBodyShape {
        match self {
            Self::Exact(body) => ClientHelloExtensionBodyShape::Exact(body),
            Self::KeyShare(entries) => ClientHelloExtensionBodyShape::KeyShare(entries),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClientHelloExtensionBodyShape {
    Exact(Vec<u8>),
    KeyShare(Vec<(u16, usize)>),
}

fn client_hello_shape_for_config(config: ClientConfig) -> Result<ClientHelloShape, Error> {
    let encoded = client_hello_encoded_bytes_for_config(config)?;
    Ok(client_hello_shape_from_encoded(&encoded))
}

fn client_hello_shape_from_encoded(encoded: &[u8]) -> ClientHelloShape {
    let ch = client_hello_from_encoded(encoded);
    let extensions = client_hello_extensions_from_encoded(encoded)
        .into_iter()
        .map(|(extension_type, body)| ClientHelloExtensionShape {
            extension_type,
            body: client_hello_extension_body_shape(extension_type, body),
        })
        .collect();

    ClientHelloShape {
        client_version: ch.client_version,
        session_id_len: ch.session_id.as_ref().len(),
        cipher_suites: ch.cipher_suites,
        compression_methods: ch.compression_methods,
        extensions,
    }
}

fn client_hello_extension_body_shape(
    extension_type: u16,
    body: Vec<u8>,
) -> ClientHelloExtensionBodyShape {
    match ExtensionType::from(extension_type) {
        ExtensionType::KeyShare => ClientHelloExtensionBodyShape::KeyShare(key_share_shape(&body)),
        _ => ClientHelloExtensionBodyShape::Exact(body),
    }
}

fn key_share_shape(body: &[u8]) -> Vec<(u16, usize)> {
    let mut offset = 0;
    assert!(body.len() >= 2);
    let key_shares_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    assert_eq!(key_shares_len, body.len() - offset);

    let mut entries = Vec::new();
    while offset < body.len() {
        assert!(body.len() >= offset + 4);
        let group = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let payload_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        assert!(body.len() >= offset + payload_len);
        entries.push((group, payload_len));
        offset += payload_len;
    }

    entries
}

fn client_hello_encoded_bytes_for_config(config: ClientConfig) -> Result<Vec<u8>, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    assert_eq!(message.typ, ContentType::Handshake);
    Ok(message.payload.into_vec())
}

fn client_hello_from_encoded(encoded: &[u8]) -> ClientHelloPayload {
    let message = HandshakeMessagePayload::read(&mut Reader::init(encoded)).unwrap();

    match message.0 {
        HandshakePayload::ClientHello(ch) => ch,
        other => panic!("unexpected handshake payload {other:?}"),
    }
}

fn client_hello_extension_types_from_encoded(encoded: &[u8]) -> Vec<u16> {
    client_hello_extensions_from_encoded(encoded)
        .into_iter()
        .map(|(extension_type, _)| extension_type)
        .collect()
}

fn client_hello_extension_body_from_encoded(
    encoded: &[u8],
    extension_type: u16,
) -> Option<Vec<u8>> {
    client_hello_extensions_from_encoded(encoded)
        .into_iter()
        .find_map(|(typ, body)| (typ == extension_type).then_some(body))
}

fn client_hello_extensions_from_encoded(encoded: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let body = &encoded[4..];
    let mut offset = 2 + 32;
    let session_id_len = body[offset] as usize;
    offset += 1 + session_id_len;
    let cipher_suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    let compression_methods_len = body[offset] as usize;
    offset += 1 + compression_methods_len;
    let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    let mut extensions = Vec::new();
    while offset < extensions_end {
        let extension_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let extension_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        extensions.push((
            extension_type,
            body[offset..offset + extension_len].to_vec(),
        ));
        offset += extension_len;
    }

    extensions
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
