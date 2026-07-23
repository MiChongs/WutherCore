use std::fmt;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};
use sha2::{Sha256, Sha512};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use x509_parser::{
    oid_registry::OID_SIG_ED25519,
    prelude::{FromDer, X509Certificate},
};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_MAX_SHORT_ID_LEN: usize = 8;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
const TLS_GROUP_X25519: u16 = 0x001d;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const TLS_GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const TLS_GROUP_X25519_MLKEM768_KEY_EXCHANGE_LEN: usize = 1216;

pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloPatch {
    pub session_id_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloKeyShare {
    pub group: RealityClientHelloKeyShareGroup,
    pub offset: usize,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityClientHelloKeyShareGroup {
    X25519,
    X25519MlKem768,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloValidation {
    pub session_id_offset: usize,
    pub key_share: RealityClientHelloKeyShare,
}

pub struct RealityPreparedClientHello {
    pub fingerprint: String,
    pub raw_client_hello: Vec<u8>,
    pub hello_random: [u8; 32],
    pub session_id_offset: usize,
    pub local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RealityPreparedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedClientHello")
            .field("fingerprint", &self.fingerprint)
            .field("raw_client_hello_len", &self.raw_client_hello.len())
            .field("hello_random", &"<redacted>")
            .field("session_id_offset", &self.session_id_offset)
            .field("local_x25519_private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RealityPreparedClientHello {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
    }
}

pub struct RealityHandshakeInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub server_public_key: [u8; 32],
    pub prepared_client_hello: RealityPreparedClientHello,
}

impl fmt::Debug for RealityHandshakeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityHandshakeInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .field("prepared_client_hello", &self.prepared_client_hello)
            .finish()
    }
}

impl Drop for RealityHandshakeInput {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
}

pub struct RealityPreparedHandshake {
    pub patched_client_hello: Vec<u8>,
    pub auth_key: [u8; 32],
    pub session_id: [u8; 32],
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub server_public_key: [u8; 32],
}

impl fmt::Debug for RealityPreparedHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedHandshake")
            .field("patched_client_hello_len", &self.patched_client_hello.len())
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl Drop for RealityPreparedHandshake {
    fn drop(&mut self) {
        self.patched_client_hello.zeroize();
        self.auth_key.zeroize();
        self.session_id.zeroize();
        self.short_id.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RealityCertificateInput<'a> {
    pub auth_key: &'a [u8; 32],
    pub ed25519_public_key: &'a [u8; 32],
    pub certificate_signature: &'a [u8],
}

impl fmt::Debug for RealityCertificateInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityCertificateInput")
            .field("auth_key", &"<redacted>")
            .field("ed25519_public_key", &"<redacted>")
            .field("certificate_signature", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RealityMldsa65CertificateInput<'a> {
    pub verifying_key: &'a [u8],
    pub client_hello: &'a [u8],
    pub server_hello: &'a [u8],
}

impl fmt::Debug for RealityMldsa65CertificateInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityMldsa65CertificateInput")
            .field("verifying_key_len", &self.verifying_key.len())
            .field("client_hello_len", &self.client_hello.len())
            .field("server_hello_len", &self.server_hello.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityCertificateVerification {
    Verified,
    NotReality,
}

impl fmt::Debug for RealitySessionIdInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealitySessionIdInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("shared_secret", &"<redacted>")
            .field("hello_random", &"<redacted>")
            .finish()
    }
}

impl Drop for RealitySessionIdInput {
    fn drop(&mut self) {
        self.short_id.zeroize();
        self.shared_secret.zeroize();
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("reality short id cannot exceed 8 bytes")]
    ShortIdTooLong,
    #[error("client hello session id range {offset}..{end} is out of bounds for {len} bytes")]
    InvalidSessionIdRange {
        offset: usize,
        end: usize,
        len: usize,
    },
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
    #[error(
        "REALITY fingerprint {0} does not support REALITY because it has no X25519-compatible key share"
    )]
    RealityFingerprintNotRealityCapable(String),
    #[error("failed to generate REALITY ClientHello: {0}")]
    ClientHelloGenerationFailed(String),
    #[error("invalid ClientHello: {reason}")]
    InvalidClientHello { reason: &'static str },
    #[error("ClientHello random does not match prepared metadata")]
    ClientHelloRandomMismatch,
    #[error("ClientHello does not contain a 32-byte session id")]
    MissingClientHelloSessionId,
    #[error(
        "prepared ClientHello session-id offset {actual} does not match parsed offset {expected}"
    )]
    ClientHelloSessionIdOffsetMismatch { expected: usize, actual: usize },
    #[error("ClientHello does not contain an X25519-compatible key share")]
    MissingClientHelloX25519KeyShare,
    #[error("ClientHello key-share public key does not match local private key")]
    ClientHelloKeyShareMismatch,
    #[error("reality X25519 shared secret was all zero")]
    AllZeroSharedSecret,
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
    #[error("invalid reality certificate DER")]
    InvalidRealityCertificateDer,
    #[error("invalid reality certificate bit string")]
    InvalidRealityCertificateBitString,
    #[error("invalid reality Ed25519 public key length {len}")]
    InvalidRealityCertificatePublicKey { len: usize },
    #[error("invalid reality ML-DSA-65 verify key length {len}")]
    InvalidRealityMldsa65VerifyKey { len: usize },
}

pub fn validate_reality_fingerprint(fingerprint: &str) -> Result<&'static str, RealityError> {
    let Some(fingerprint) = xray_utls::normalize_reality_fingerprint(fingerprint) else {
        return Err(RealityError::UnsupportedRealityFingerprint(
            fingerprint.to_owned(),
        ));
    };

    if xray_utls::normalize_reality_supported_fingerprint(fingerprint).is_none() {
        return Err(RealityError::RealityFingerprintNotRealityCapable(
            fingerprint.to_owned(),
        ));
    }

    Ok(fingerprint)
}

struct ParsedClientHello {
    random: [u8; 32],
    session_id_offset: usize,
    key_share: Option<RealityClientHelloKeyShare>,
}

struct ClientHelloCursor<'a> {
    raw: &'a [u8],
    offset: usize,
    base: usize,
}

impl<'a> ClientHelloCursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            offset: 0,
            base: 0,
        }
    }

    fn with_base(raw: &'a [u8], base: usize) -> Self {
        Self {
            raw,
            offset: 0,
            base,
        }
    }

    fn absolute_offset(&self) -> usize {
        self.base + self.offset
    }

    fn checked_end(&self, len: usize, reason: &'static str) -> Result<usize, RealityError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealityError::InvalidClientHello { reason })?;
        if end > self.raw.len() {
            return Err(RealityError::InvalidClientHello { reason });
        }

        Ok(end)
    }

    fn take(&mut self, len: usize, reason: &'static str) -> Result<&'a [u8], RealityError> {
        let end = self.checked_end(len, reason)?;
        let value = &self.raw[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self, reason: &'static str) -> Result<u8, RealityError> {
        Ok(self.take(1, reason)?[0])
    }

    fn read_u16(&mut self, reason: &'static str) -> Result<u16, RealityError> {
        let bytes = self.take(2, reason)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self, reason: &'static str) -> Result<usize, RealityError> {
        let bytes = self.take(3, reason)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }
}

impl ParsedClientHello {
    fn parse(raw: &[u8]) -> Result<Self, RealityError> {
        let mut cursor = ClientHelloCursor::new(raw);

        let handshake_type = cursor.read_u8("missing handshake type")?;
        if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
            return Err(RealityError::InvalidClientHello {
                reason: "unexpected handshake type",
            });
        }

        let handshake_len = cursor.read_u24("missing handshake length")?;
        let expected_handshake_len =
            raw.len()
                .checked_sub(4)
                .ok_or(RealityError::InvalidClientHello {
                    reason: "missing handshake header",
                })?;
        if handshake_len != expected_handshake_len {
            return Err(RealityError::InvalidClientHello {
                reason: "handshake length mismatch",
            });
        }

        cursor.take(2, "missing legacy version")?;
        let mut random = [0u8; 32];
        random.copy_from_slice(cursor.take(32, "missing random")?);

        let session_id_len = usize::from(cursor.read_u8("missing session id length")?);
        if session_id_len != REALITY_SESSION_ID_LEN {
            return Err(RealityError::MissingClientHelloSessionId);
        }
        let session_id_offset = cursor.absolute_offset();
        cursor.take(REALITY_SESSION_ID_LEN, "truncated session id")?;

        let cipher_suites_len = usize::from(cursor.read_u16("missing cipher suites length")?);
        if cipher_suites_len % 2 != 0 {
            return Err(RealityError::InvalidClientHello {
                reason: "cipher suites length is not even",
            });
        }
        cursor.take(cipher_suites_len, "truncated cipher suites")?;

        let compression_methods_len =
            usize::from(cursor.read_u8("missing compression methods length")?);
        cursor.take(compression_methods_len, "truncated compression methods")?;

        let extensions_len = usize::from(cursor.read_u16("missing extensions length")?);
        let extensions_start = cursor.absolute_offset();
        if cursor.checked_end(extensions_len, "truncated extensions")? != raw.len() {
            return Err(RealityError::InvalidClientHello {
                reason: "extensions length mismatch",
            });
        }
        let extensions = cursor.take(extensions_len, "truncated extensions")?;

        let mut extensions_cursor = ClientHelloCursor::with_base(extensions, extensions_start);
        let mut key_share = None;
        while extensions_cursor.offset < extensions.len() {
            let extension_type = extensions_cursor.read_u16("missing extension type")?;
            let extension_len =
                usize::from(extensions_cursor.read_u16("missing extension length")?);
            let extension_offset = extensions_cursor.absolute_offset();
            let extension_data =
                extensions_cursor.take(extension_len, "truncated extension data")?;
            if extension_type == TLS_EXTENSION_KEY_SHARE {
                key_share = parse_key_share_extension(extension_data, extension_offset)?;
                if key_share.is_some() {
                    break;
                }
            }
        }

        Ok(Self {
            random,
            session_id_offset,
            key_share,
        })
    }
}

fn parse_key_share_extension(
    extension_data: &[u8],
    extension_offset: usize,
) -> Result<Option<RealityClientHelloKeyShare>, RealityError> {
    let mut cursor = ClientHelloCursor::with_base(extension_data, extension_offset);
    let client_shares_len = usize::from(cursor.read_u16("missing key-share vector length")?);
    if cursor.checked_end(client_shares_len, "truncated key-share vector")? != extension_data.len()
    {
        return Err(RealityError::InvalidClientHello {
            reason: "key-share vector length mismatch",
        });
    }

    let mut hybrid_key_share = None;

    while cursor.offset < extension_data.len() {
        let group = cursor.read_u16("missing key-share group")?;
        let key_exchange_len = usize::from(cursor.read_u16("missing key-share length")?);
        let key_exchange_offset = cursor.absolute_offset();
        let key_exchange = cursor.take(key_exchange_len, "truncated key-share bytes")?;

        if is_tls_grease_value(group) {
            continue;
        }

        match group {
            TLS_GROUP_X25519 => {
                if key_exchange.len() != 32 {
                    return Err(RealityError::InvalidClientHello {
                        reason: "invalid X25519 key-share length",
                    });
                }

                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(key_exchange);
                return Ok(Some(RealityClientHelloKeyShare {
                    group: RealityClientHelloKeyShareGroup::X25519,
                    offset: key_exchange_offset,
                    public_key,
                }));
            }
            TLS_GROUP_X25519_MLKEM768 | TLS_GROUP_X25519_MLKEM768_DRAFT => {
                if key_exchange.len() != TLS_GROUP_X25519_MLKEM768_KEY_EXCHANGE_LEN {
                    return Err(RealityError::InvalidClientHello {
                        reason: "invalid X25519MLKEM768 key-share length",
                    });
                }

                let public_key_offset = if group == TLS_GROUP_X25519_MLKEM768_DRAFT {
                    key_exchange_offset
                } else {
                    key_exchange_offset + key_exchange.len() - 32
                };
                let mut public_key = [0u8; 32];
                if group == TLS_GROUP_X25519_MLKEM768_DRAFT {
                    public_key.copy_from_slice(&key_exchange[..32]);
                } else {
                    public_key.copy_from_slice(&key_exchange[key_exchange.len() - 32..]);
                }
                hybrid_key_share.get_or_insert(RealityClientHelloKeyShare {
                    group: RealityClientHelloKeyShareGroup::X25519MlKem768,
                    offset: public_key_offset,
                    public_key,
                });
            }
            _ => {}
        }
    }

    Ok(hybrid_key_share)
}

fn is_tls_grease_value(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

/// Validates uTLS `hello.Raw` ClientHello metadata for REALITY preparation.
///
/// The input must be TLS handshake ClientHello bytes, not a TLS record. This
/// boundary is intentionally separate from `prepare_reality_handshake` so the
/// current synthetic preparation tests can remain narrow while the future live
/// provider can validate real Chrome/uTLS output before sealing.
pub fn validate_reality_client_hello_metadata(
    prepared: &RealityPreparedClientHello,
) -> Result<RealityClientHelloValidation, RealityError> {
    validate_reality_fingerprint(&prepared.fingerprint)?;

    let parsed = ParsedClientHello::parse(&prepared.raw_client_hello)?;
    if parsed.random != prepared.hello_random {
        return Err(RealityError::ClientHelloRandomMismatch);
    }
    if parsed.session_id_offset != prepared.session_id_offset {
        return Err(RealityError::ClientHelloSessionIdOffsetMismatch {
            expected: parsed.session_id_offset,
            actual: prepared.session_id_offset,
        });
    }

    let key_share = parsed
        .key_share
        .ok_or(RealityError::MissingClientHelloX25519KeyShare)?;
    let local_x25519_private_key = Zeroizing::new(prepared.local_x25519_private_key);
    let local_secret = StaticSecret::from(*local_x25519_private_key);
    let local_public_key = PublicKey::from(&local_secret).to_bytes();
    if local_public_key != key_share.public_key {
        return Err(RealityError::ClientHelloKeyShareMismatch);
    }

    Ok(RealityClientHelloValidation {
        session_id_offset: parsed.session_id_offset,
        key_share,
    })
}

/// Derives Xray-core's REALITY auth key from the X25519 shared secret.
///
/// Xray-core uses HKDF-SHA256 with `hello.Random[..20]` as salt and
/// `REALITY` as info. The resulting key is used both for ClientHello
/// session-id sealing and REALITY certificate binding.
pub fn derive_reality_auth_key(
    shared_secret: &[u8; 32],
    hello_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key[..])
        .map_err(|_| RealityError::Hkdf)?;
    Ok(auth_key)
}

/// Prepares a REALITY ClientHello for the future live connector.
///
/// This function does not perform network I/O. The caller supplies raw
/// ClientHello metadata produced by a Chrome/uTLS-compatible provider.
pub fn prepare_reality_handshake(
    mut input: RealityHandshakeInput,
) -> Result<RealityPreparedHandshake, RealityError> {
    validate_reality_fingerprint(&input.prepared_client_hello.fingerprint)?;
    let mut output_short_id = Zeroizing::new(input.short_id.clone());
    let output_server_public_key = input.server_public_key;

    let local_x25519_private_key =
        Zeroizing::new(input.prepared_client_hello.local_x25519_private_key);
    input
        .prepared_client_hello
        .local_x25519_private_key
        .zeroize();

    let local_secret = StaticSecret::from(*local_x25519_private_key);
    let server_public_key = PublicKey::from(input.server_public_key);
    let shared_secret = local_secret.diffie_hellman(&server_public_key);
    if !shared_secret.was_contributory() {
        return Err(RealityError::AllZeroSharedSecret);
    }

    let shared_secret = Zeroizing::new(shared_secret.to_bytes());
    let auth_key = Zeroizing::new(derive_reality_auth_key(
        &shared_secret,
        &input.prepared_client_hello.hello_random,
    )?);

    let session_input = RealitySessionIdInput {
        version: input.version,
        unix_time: input.unix_time,
        short_id: std::mem::take(&mut input.short_id),
        shared_secret: *shared_secret,
        hello_random: input.prepared_client_hello.hello_random,
    };
    let mut raw_client_hello = std::mem::take(&mut input.prepared_client_hello.raw_client_hello);
    let session_id = seal_reality_client_hello(
        &session_input,
        RealityClientHelloPatch {
            session_id_offset: input.prepared_client_hello.session_id_offset,
        },
        &mut raw_client_hello,
    )?;

    Ok(RealityPreparedHandshake {
        patched_client_hello: raw_client_hello,
        auth_key: *auth_key,
        session_id,
        version: input.version,
        unix_time: input.unix_time,
        short_id: std::mem::take(&mut *output_short_id),
        server_public_key: output_server_public_key,
    })
}

/// Builds the sealed 32-byte REALITY session id.
///
/// `raw_client_hello_before_seal` must be the pre-seal raw ClientHello bytes
/// with the target session-id range already zeroed. Xray-core uses those bytes
/// as AEAD associated data before copying the sealed session id back.
pub fn build_reality_session_id(
    input: &RealitySessionIdInput,
    raw_client_hello_before_seal: &[u8],
) -> Result<[u8; 32], RealityError> {
    validate_reality_short_id(input)?;

    let mut session_id_prefix = Zeroizing::new([0u8; 16]);
    session_id_prefix[..3].copy_from_slice(&input.version);
    session_id_prefix[4..8].copy_from_slice(&input.unix_time.to_be_bytes());
    session_id_prefix[8..8 + input.short_id.len()].copy_from_slice(&input.short_id);

    let auth_key = Zeroizing::new(derive_reality_auth_key(
        &input.shared_secret,
        &input.hello_random,
    )?);

    let cipher = Aes256Gcm::new_from_slice(&auth_key[..]).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random[20..]);
    let tag = cipher
        .encrypt_in_place_detached(
            nonce,
            raw_client_hello_before_seal,
            session_id_prefix.as_mut(),
        )
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(session_id_prefix.as_ref());
    session_id[16..].copy_from_slice(&tag);
    Ok(session_id)
}

/// Verifies Xray-core's non-ML-DSA REALITY certificate binding.
///
/// Xray-core recognizes a REALITY peer certificate when
/// `HMAC-SHA512(auth_key, ed25519_public_key)` equals the leaf certificate
/// signature bytes. The auth key is the derived REALITY auth key, not the raw
/// X25519 shared secret.
pub fn verify_reality_certificate_binding(
    input: RealityCertificateInput<'_>,
) -> RealityCertificateVerification {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(input.auth_key)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(input.ed25519_public_key);

    if mac.verify_slice(input.certificate_signature).is_ok() {
        RealityCertificateVerification::Verified
    } else {
        RealityCertificateVerification::NotReality
    }
}

/// Parses a leaf certificate DER and verifies Xray-core's REALITY HMAC binding.
///
/// This is only the REALITY recognition step. Normal x509 fallback validation
/// stays outside this primitive.
pub fn verify_reality_certificate_der(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
) -> Result<RealityCertificateVerification, RealityError> {
    verify_reality_certificate_der_with_mldsa65(auth_key, leaf_der, None)
}

pub fn verify_reality_certificate_der_with_mldsa65(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
    mldsa65: Option<RealityMldsa65CertificateInput<'_>>,
) -> Result<RealityCertificateVerification, RealityError> {
    let (remaining, certificate) = X509Certificate::from_der(leaf_der)
        .map_err(|_| RealityError::InvalidRealityCertificateDer)?;
    if !remaining.is_empty() {
        return Err(RealityError::InvalidRealityCertificateDer);
    }

    let public_key_info = certificate.public_key();
    if public_key_info.algorithm.algorithm != OID_SIG_ED25519 {
        return Ok(RealityCertificateVerification::NotReality);
    }
    if public_key_info.algorithm.parameters.is_some()
        || (certificate.signature_algorithm.algorithm == OID_SIG_ED25519
            && certificate.signature_algorithm.parameters.is_some())
    {
        return Err(RealityError::InvalidRealityCertificateDer);
    }
    if public_key_info.subject_public_key.unused_bits != 0
        || certificate.signature_value.unused_bits != 0
    {
        return Err(RealityError::InvalidRealityCertificateBitString);
    }

    let public_key = public_key_info.subject_public_key.data.as_ref();
    let public_key: &[u8; 32] =
        public_key
            .try_into()
            .map_err(|_| RealityError::InvalidRealityCertificatePublicKey {
                len: public_key.len(),
            })?;

    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(auth_key).expect("HMAC-SHA512 accepts any key length");
    mac.update(public_key);

    if mac
        .clone()
        .verify_slice(certificate.signature_value.data.as_ref())
        .is_err()
    {
        return Ok(RealityCertificateVerification::NotReality);
    }

    let Some(mldsa65) = mldsa65 else {
        return Ok(RealityCertificateVerification::Verified);
    };

    let Some(extension) = certificate.extensions().first() else {
        return Ok(RealityCertificateVerification::NotReality);
    };
    let verifying_key_bytes: EncodedVerifyingKey<MlDsa65> = mldsa65
        .verifying_key
        .try_into()
        .map_err(|_| RealityError::InvalidRealityMldsa65VerifyKey {
            len: mldsa65.verifying_key.len(),
        })?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&verifying_key_bytes);
    let Ok(signature) = Signature::<MlDsa65>::try_from(extension.value) else {
        return Ok(RealityCertificateVerification::NotReality);
    };
    mac.update(mldsa65.client_hello);
    mac.update(mldsa65.server_hello);
    let message = mac.finalize().into_bytes();

    if verifying_key.verify(message.as_slice(), &signature).is_ok() {
        Ok(RealityCertificateVerification::Verified)
    } else {
        Ok(RealityCertificateVerification::NotReality)
    }
}

/// Seals and patches the REALITY session id bytes into a raw ClientHello.
///
/// Invalid session-id ranges and overlong `short_id` values return before mutating
/// `raw_client_hello`. On success, the configured session-id range is first zeroed
/// for associated-data construction and then rewritten with the sealed bytes.
pub fn seal_reality_client_hello(
    input: &RealitySessionIdInput,
    patch: RealityClientHelloPatch,
    raw_client_hello: &mut [u8],
) -> Result<[u8; REALITY_SESSION_ID_LEN], RealityError> {
    validate_reality_short_id(input)?;

    let offset = patch.session_id_offset;
    let len = raw_client_hello.len();
    let end =
        offset
            .checked_add(REALITY_SESSION_ID_LEN)
            .ok_or(RealityError::InvalidSessionIdRange {
                offset,
                end: usize::MAX,
                len,
            })?;

    if end > len {
        return Err(RealityError::InvalidSessionIdRange { offset, end, len });
    }

    raw_client_hello[offset..end].fill(0);
    let session_id = build_reality_session_id(input, raw_client_hello)?;
    raw_client_hello[offset..end].copy_from_slice(&session_id);

    Ok(session_id)
}

fn validate_reality_short_id(input: &RealitySessionIdInput) -> Result<(), RealityError> {
    if input.short_id.len() > REALITY_MAX_SHORT_ID_LEN {
        return Err(RealityError::ShortIdTooLong);
    }

    Ok(())
}
