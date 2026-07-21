//! ClientHello 形状数据库。
//!
//! 数据由 Xray 26.7.11 固定的 uTLS 版本
//! `v1.8.3-0.20260301010127-aa6edf4b11af` 实际生成并解析得到。数据库只保存
//! 线上的结构字段，不保存 ClientHello random、session id 或临时密钥。

use std::{collections::HashMap, io::Read, sync::OnceLock};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::GzDecoder;
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct UtlsClientHelloProfile {
    pub cipher_suites: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_shares: Vec<UtlsKeyShare>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub delegated_credentials_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub certificate_compression_algorithms: Vec<u16>,
    pub record_size_limit: Option<u16>,
    pub application_settings: Vec<UtlsApplicationSettings>,
    pub extensions: Vec<UtlsExtension>,
    pub padding_length: Option<usize>,
    pub encrypted_client_hello_length: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UtlsKeyShare {
    pub group: u16,
    pub key_exchange_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct UtlsApplicationSettings {
    pub extension_type: u16,
    pub protocols: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UtlsExtension {
    pub extension_type: u16,
    pub payload_len: usize,
}

#[derive(Debug, Deserialize)]
struct OracleProfile {
    fingerprint: String,
    #[serde(default)]
    cipher_suites: Vec<String>,
    #[serde(default)]
    supported_versions: Vec<String>,
    #[serde(default)]
    supported_groups: Vec<String>,
    #[serde(default)]
    key_shares: Vec<OracleKeyShare>,
    #[serde(default)]
    psk_key_exchange_modes: Vec<String>,
    #[serde(default)]
    signature_algorithms: Vec<String>,
    #[serde(default)]
    delegated_credentials_algorithms: Vec<String>,
    #[serde(default)]
    alpn_protocols: Vec<String>,
    #[serde(default)]
    certificate_compression_algorithms: Vec<String>,
    record_size_limit: Option<String>,
    #[serde(default)]
    application_settings: Vec<OracleApplicationSettings>,
    #[serde(default)]
    extensions: Vec<OracleExtension>,
    padding_length: Option<usize>,
    encrypted_client_hello_length: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OracleKeyShare {
    group: String,
    key_exchange_length: usize,
}

#[derive(Debug, Deserialize)]
struct OracleApplicationSettings {
    #[serde(rename = "type")]
    extension_type: String,
    protocols: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OracleExtension {
    #[serde(rename = "type")]
    extension_type: String,
    length: usize,
}

static PROFILES: OnceLock<Result<HashMap<String, UtlsClientHelloProfile>, String>> =
    OnceLock::new();

pub(super) fn profile_for_fingerprint(
    fingerprint: &str,
) -> Result<&'static UtlsClientHelloProfile, String> {
    let profiles = PROFILES
        .get_or_init(load_profiles)
        .as_ref()
        .map_err(Clone::clone)?;
    profiles
        .get(fingerprint)
        .ok_or_else(|| format!("uTLS profile database has no entry for {fingerprint:?}"))
}

#[cfg(test)]
pub(super) fn profile_names() -> Vec<&'static str> {
    let profiles = PROFILES.get_or_init(load_profiles).as_ref().unwrap();
    let mut names = profiles.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    names
}

fn load_profiles() -> Result<HashMap<String, UtlsClientHelloProfile>, String> {
    let compressed = STANDARD
        .decode(PROFILE_DB_GZIP_BASE64)
        .map_err(|error| format!("decode embedded uTLS profile database: {error}"))?;
    let mut json = String::new();
    GzDecoder::new(compressed.as_slice())
        .read_to_string(&mut json)
        .map_err(|error| format!("decompress embedded uTLS profile database: {error}"))?;
    let oracle_profiles: Vec<OracleProfile> = serde_json::from_str(&json)
        .map_err(|error| format!("parse embedded uTLS profile database: {error}"))?;

    let mut profiles = HashMap::with_capacity(oracle_profiles.len());
    for oracle in oracle_profiles {
        let fingerprint = oracle.fingerprint.clone();
        let profile = convert_profile(oracle)
            .map_err(|error| format!("invalid embedded uTLS profile {fingerprint:?}: {error}"))?;
        if profiles.insert(fingerprint.clone(), profile).is_some() {
            return Err(format!(
                "duplicate embedded uTLS fingerprint {fingerprint:?}"
            ));
        }
    }
    Ok(profiles)
}

fn convert_profile(oracle: OracleProfile) -> Result<UtlsClientHelloProfile, String> {
    let mut grease_extension_index = 0_u16;
    let extensions = oracle
        .extensions
        .into_iter()
        .map(|extension| {
            let extension_type = if extension.extension_type == "GREASE" {
                let value = 0x0a0a_u16.wrapping_add(grease_extension_index.wrapping_mul(0x1010));
                grease_extension_index = grease_extension_index.wrapping_add(1);
                value
            } else {
                parse_wire_u16(&extension.extension_type)?
            };
            Ok(UtlsExtension {
                extension_type,
                payload_len: extension.length,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(UtlsClientHelloProfile {
        cipher_suites: parse_wire_list(&oracle.cipher_suites)?,
        supported_versions: parse_wire_list(&oracle.supported_versions)?,
        supported_groups: parse_wire_list(&oracle.supported_groups)?,
        key_shares: oracle
            .key_shares
            .into_iter()
            .map(|share| {
                Ok(UtlsKeyShare {
                    group: parse_wire_u16(&share.group)?,
                    key_exchange_len: share.key_exchange_length,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        psk_key_exchange_modes: parse_wire_u8_list(&oracle.psk_key_exchange_modes)?,
        signature_algorithms: parse_wire_list(&oracle.signature_algorithms)?,
        delegated_credentials_algorithms: parse_wire_list(
            &oracle.delegated_credentials_algorithms,
        )?,
        alpn_protocols: oracle
            .alpn_protocols
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        certificate_compression_algorithms: parse_wire_list(
            &oracle.certificate_compression_algorithms,
        )?,
        record_size_limit: oracle
            .record_size_limit
            .as_deref()
            .map(parse_wire_u16)
            .transpose()?,
        application_settings: oracle
            .application_settings
            .into_iter()
            .map(|settings| {
                Ok(UtlsApplicationSettings {
                    extension_type: parse_wire_u16(&settings.extension_type)?,
                    protocols: settings
                        .protocols
                        .into_iter()
                        .map(String::into_bytes)
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        extensions,
        padding_length: oracle.padding_length,
        encrypted_client_hello_length: oracle.encrypted_client_hello_length,
    })
}

fn parse_wire_list(values: &[String]) -> Result<Vec<u16>, String> {
    values.iter().map(|value| parse_wire_u16(value)).collect()
}

fn parse_wire_u8_list(values: &[String]) -> Result<Vec<u8>, String> {
    values
        .iter()
        .map(|value| {
            let value = value
                .strip_prefix("0x")
                .ok_or_else(|| format!("wire value is not hexadecimal: {value:?}"))?;
            u8::from_str_radix(value, 16)
                .map_err(|error| format!("invalid byte wire value {value:?}: {error}"))
        })
        .collect()
}

fn parse_wire_u16(value: &str) -> Result<u16, String> {
    if value == "GREASE" {
        return Ok(0x0a0a);
    }
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("wire value is not hexadecimal: {value:?}"))?;
    u16::from_str_radix(value, 16).map_err(|error| format!("invalid wire value {value:?}: {error}"))
}

// gzip(marshal(normalized ClientHello shapes)); generated from the pinned Go
// oracle named at the top of this file. SHA-256 of the decompressed JSON:
// 2f6d1f4546c25e9c968713585843e6892780957d28a4c35fc70e2c8f500ca3a7.
const PROFILE_DB_GZIP_BASE64: &str = "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";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_database_contains_pinned_xray_profiles() {
        let profiles = PROFILES.get_or_init(load_profiles).as_ref().unwrap();
        assert_eq!(profiles.len(), 62);
        assert_eq!(
            profiles["chrome"].cipher_suites,
            [
                0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        assert_eq!(
            profiles["hellogolang"].supported_groups,
            [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
        );
        assert_eq!(
            profiles["hellochrome_133"], profiles["hellochrome_auto"],
            "Xray 26.7.11 Chrome Auto is Chrome 133"
        );
    }

    #[test]
    fn embedded_database_matches_pinned_oracle_digest() {
        let compressed = STANDARD.decode(PROFILE_DB_GZIP_BASE64).unwrap();
        let mut json = Vec::new();
        GzDecoder::new(compressed.as_slice())
            .read_to_end(&mut json)
            .unwrap();
        assert_eq!(json.len(), 87_017);
        assert_eq!(
            format!("{:x}", Sha256::digest(&json)),
            "2f6d1f4546c25e9c968713585843e6892780957d28a4c35fc70e2c8f500ca3a7"
        );
    }
}
