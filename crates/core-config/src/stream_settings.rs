//! Xray-compatible stream socket policy and final-mask configuration.
//!
//! Field names and defaults in this module are pinned to Xray-core 26.7.11
//! (`6e3322d219140a025285ded1114fe17a5edb74d8`). Keeping the wire-facing
//! configuration typed here prevents an accepted setting from being silently
//! discarded by the outbound runtime.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::model::XhttpDownloadTlsSettings;

/// `streamSettings` on an outbound node.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NodeStreamSettings {
    /// Xray names raw TCP `tcp`; `raw` is accepted by the higher-level model.
    pub network: Option<String>,
    pub sockopt: Option<OutboundSocketConfig>,
    pub finalmask: Option<FinalMaskConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct OutboundSocketConfig {
    pub mark: i32,
    pub tcp_fast_open: Option<BoolOrI32>,
    /// Inbound-only in Xray. Registered so an imported Xray object is not
    /// rejected; it is deliberately ignored for outbound sockets.
    pub tproxy: Option<String>,
    /// Inbound-only in Xray.
    pub accept_proxy_protocol: bool,
    pub domain_strategy: DomainStrategy,
    pub dialer_proxy: String,
    pub tcp_keep_alive_interval: i32,
    pub tcp_keep_alive_idle: i32,
    pub tcp_congestion: String,
    pub interface: String,
    /// Inbound listener-only in Xray.
    pub v6only: bool,
    pub tcp_window_clamp: i32,
    pub tcp_user_timeout: i32,
    pub tcp_max_seg: i32,
    /// Freedom/inbound metadata option, not a socket dial option.
    pub penetrate: bool,
    pub tcp_mptcp: bool,
    #[serde(rename = "customSockopt")]
    pub custom_sockopt: Vec<CustomSockoptConfig>,
    pub address_port_strategy: AddressPortStrategy,
    pub happy_eyeballs: HappyEyeballsConfig,
    /// HTTP/gRPC inbound-only in Xray.
    pub trusted_x_forwarded_for: Vec<String>,
}

impl OutboundSocketConfig {
    /// Xray's protobuf TFO value: omitted/0 means do not call setsockopt,
    /// `false` means explicitly disable (-1), `true` means queue 256.
    pub fn tfo_value(&self) -> i32 {
        match self.tcp_fast_open {
            None | Some(BoolOrI32::Int(0)) => 0,
            Some(BoolOrI32::Bool(true)) => 256,
            Some(BoolOrI32::Bool(false)) => -1,
            Some(BoolOrI32::Int(v)) => v,
        }
    }

    pub fn is_effectively_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BoolOrI32 {
    Bool(bool),
    Int(i32),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct CustomSockoptConfig {
    /// Xray 26.7.11 accidentally spells this field `Syetem` internally but the
    /// JSON spelling remains `system`.
    pub system: String,
    pub network: String,
    pub level: String,
    pub opt: String,
    pub value: String,
    #[serde(rename = "type")]
    pub value_type: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub enum DomainStrategy {
    #[default]
    #[serde(rename = "AsIs", alias = "asis", alias = "")]
    AsIs,
    #[serde(rename = "UseIP", alias = "useip")]
    UseIp,
    #[serde(rename = "UseIPv4", alias = "useipv4")]
    UseIpv4,
    #[serde(rename = "UseIPv6", alias = "useipv6")]
    UseIpv6,
    #[serde(rename = "UseIPv4v6", alias = "useipv4v6")]
    UseIpv4v6,
    #[serde(rename = "UseIPv6v4", alias = "useipv6v4")]
    UseIpv6v4,
    #[serde(rename = "ForceIP", alias = "forceip")]
    ForceIp,
    #[serde(rename = "ForceIPv4", alias = "forceipv4")]
    ForceIpv4,
    #[serde(rename = "ForceIPv6", alias = "forceipv6")]
    ForceIpv6,
    #[serde(rename = "ForceIPv4v6", alias = "forceipv4v6")]
    ForceIpv4v6,
    #[serde(rename = "ForceIPv6v4", alias = "forceipv6v4")]
    ForceIpv6v4,
}

impl<'de> Deserialize<'de> for DomainStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_lowercase().as_str() {
            "" | "asis" => Ok(Self::AsIs),
            "useip" => Ok(Self::UseIp),
            "useipv4" => Ok(Self::UseIpv4),
            "useipv6" => Ok(Self::UseIpv6),
            "useipv4v6" => Ok(Self::UseIpv4v6),
            "useipv6v4" => Ok(Self::UseIpv6v4),
            "forceip" => Ok(Self::ForceIp),
            "forceipv4" => Ok(Self::ForceIpv4),
            "forceipv6" => Ok(Self::ForceIpv6),
            "forceipv4v6" => Ok(Self::ForceIpv4v6),
            "forceipv6v4" => Ok(Self::ForceIpv6v4),
            _ => Err(de::Error::custom(format!(
                "unsupported domain strategy `{value}`"
            ))),
        }
    }
}

impl DomainStrategy {
    pub fn force(self) -> bool {
        matches!(
            self,
            Self::ForceIp
                | Self::ForceIpv4
                | Self::ForceIpv6
                | Self::ForceIpv4v6
                | Self::ForceIpv6v4
        )
    }

    pub fn use_ip(self) -> bool {
        !matches!(self, Self::AsIs)
    }

    pub fn prefer_ipv6(self) -> bool {
        matches!(
            self,
            Self::UseIpv6 | Self::UseIpv6v4 | Self::ForceIpv6 | Self::ForceIpv6v4
        )
    }

    pub fn allow_ipv4(self) -> bool {
        !matches!(self, Self::UseIpv6 | Self::ForceIpv6)
    }

    pub fn allow_ipv6(self) -> bool {
        !matches!(self, Self::UseIpv4 | Self::ForceIpv4)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub enum AddressPortStrategy {
    #[default]
    #[serde(rename = "none", alias = "None", alias = "")]
    None,
    #[serde(rename = "srvPortOnly", alias = "SrvPortOnly", alias = "srvportonly")]
    SrvPortOnly,
    #[serde(
        rename = "srvAddressOnly",
        alias = "SrvAddressOnly",
        alias = "srvaddressonly"
    )]
    SrvAddressOnly,
    #[serde(
        rename = "srvPortAndAddress",
        alias = "SrvPortAndAddress",
        alias = "srvportandaddress"
    )]
    SrvPortAndAddress,
    #[serde(rename = "txtPortOnly", alias = "TxtPortOnly", alias = "txtportonly")]
    TxtPortOnly,
    #[serde(
        rename = "txtAddressOnly",
        alias = "TxtAddressOnly",
        alias = "txtaddressonly"
    )]
    TxtAddressOnly,
    #[serde(
        rename = "txtPortAndAddress",
        alias = "TxtPortAndAddress",
        alias = "txtportandaddress"
    )]
    TxtPortAndAddress,
}

impl<'de> Deserialize<'de> for AddressPortStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "srvportonly" => Ok(Self::SrvPortOnly),
            "srvaddressonly" => Ok(Self::SrvAddressOnly),
            "srvportandaddress" => Ok(Self::SrvPortAndAddress),
            "txtportonly" => Ok(Self::TxtPortOnly),
            "txtaddressonly" => Ok(Self::TxtAddressOnly),
            "txtportandaddress" => Ok(Self::TxtPortAndAddress),
            _ => Err(de::Error::custom(format!(
                "unsupported address and port strategy `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HappyEyeballsConfig {
    #[serde(rename = "prioritizeIPv6")]
    pub prioritize_ipv6: bool,
    pub interleave: u32,
    pub try_delay_ms: u64,
    pub max_concurrent_try: u32,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 0,
            max_concurrent_try: 4,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FinalMaskConfig {
    pub tcp: Vec<TcpMaskConfig>,
    pub udp: Vec<UdpMaskConfig>,
    pub quic_params: Option<QuicParamsConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", content = "settings")]
pub enum TcpMaskConfig {
    #[serde(rename = "header-custom")]
    HeaderCustom(HeaderCustomTcpConfig),
    #[serde(rename = "fragment")]
    Fragment(FragmentMaskConfig),
    #[serde(rename = "sudoku")]
    Sudoku(SudokuMaskConfig),
    #[serde(rename = "xmc")]
    Xmc(XmcMaskConfig),
}

impl<'de> Deserialize<'de> for TcpMaskConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = MaskEnvelope::deserialize(deserializer)?;
        let settings = raw.settings.unwrap_or_else(empty_settings);
        match raw.kind.as_str() {
            "header-custom" => decode_mask(settings).map(Self::HeaderCustom),
            "fragment" => decode_mask(settings).map(Self::Fragment),
            "sudoku" => decode_mask(settings).map(Self::Sudoku),
            "xmc" => decode_mask(settings).map(Self::Xmc),
            kind => Err(de::Error::custom(format!(
                "unknown TCP finalmask type `{kind}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", content = "settings")]
pub enum UdpMaskConfig {
    #[serde(rename = "header-custom")]
    HeaderCustom(HeaderCustomUdpConfig),
    #[serde(rename = "mkcp-legacy")]
    MkcpLegacy(MkcpLegacyMaskConfig),
    #[serde(rename = "noise")]
    Noise(NoiseMaskConfig),
    #[serde(rename = "salamander")]
    Salamander(SalamanderMaskConfig),
    #[serde(rename = "sudoku")]
    Sudoku(SudokuMaskConfig),
    #[serde(rename = "xdns")]
    Xdns(XdnsMaskConfig),
    #[serde(rename = "xicmp")]
    Xicmp(XicmpMaskConfig),
    #[serde(rename = "realm")]
    Realm(RealmMaskConfig),
}

impl<'de> Deserialize<'de> for UdpMaskConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = MaskEnvelope::deserialize(deserializer)?;
        let settings = raw.settings.unwrap_or_else(empty_settings);
        match raw.kind.as_str() {
            "header-custom" => decode_mask(settings).map(Self::HeaderCustom),
            "mkcp-legacy" => decode_mask(settings).map(Self::MkcpLegacy),
            "noise" => decode_mask(settings).map(Self::Noise),
            "salamander" => decode_mask(settings).map(Self::Salamander),
            "sudoku" => decode_mask(settings).map(Self::Sudoku),
            "xdns" => decode_mask(settings).map(Self::Xdns),
            "xicmp" => decode_mask(settings).map(Self::Xicmp),
            "realm" => decode_mask(settings).map(Self::Realm),
            kind => Err(de::Error::custom(format!(
                "unknown UDP finalmask type `{kind}`"
            ))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaskEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    settings: Option<serde_json::Value>,
}

fn empty_settings() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn decode_mask<E, T>(settings: serde_json::Value) -> Result<T, E>
where
    E: de::Error,
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(settings).map_err(E::custom)
}

/// Xray integer range: either `7` or a string such as `"3-9"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct I32Range {
    pub left: i32,
    pub right: i32,
    pub from: i32,
    pub to: i32,
}

impl I32Range {
    pub const fn fixed(value: i32) -> Self {
        Self {
            left: value,
            right: value,
            from: value,
            to: value,
        }
    }

    pub fn new(left: i32, right: i32) -> Self {
        Self {
            left,
            right,
            from: left.min(right),
            to: left.max(right),
        }
    }
}

impl Serialize for I32Range {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.left == self.right {
            serializer.serialize_i32(self.left)
        } else {
            serializer.serialize_str(&format!("{}-{}", self.left, self.right))
        }
    }
}

impl<'de> Deserialize<'de> for I32Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = I32Range;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer or an integer range like 1-5")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = i32::try_from(value).map_err(E::custom)?;
                Ok(I32Range::fixed(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = i32::try_from(value).map_err(E::custom)?;
                Ok(I32Range::fixed(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_i32_range(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse_i32_range(value: &str) -> Result<I32Range, String> {
    let value = value.trim();
    if let Ok(single) = i32::from_str(value) {
        return Ok(I32Range::fixed(single));
    }
    // A range separator is the first '-' after the optional sign of `left`.
    let start = usize::from(value.starts_with('-'));
    let separator = value[start..]
        .find('-')
        .map(|offset| start + offset)
        .ok_or_else(|| format!("invalid integer range `{value}`"))?;
    let left = value[..separator]
        .parse::<i32>()
        .map_err(|_| format!("invalid range start `{value}`"))?;
    let right = value[separator + 1..]
        .parse::<i32>()
        .map_err(|_| format!("invalid range end `{value}`"))?;
    Ok(I32Range::new(left, right))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FragmentMaskConfig {
    pub packets: String,
    pub length: I32Range,
    pub delay: I32Range,
    pub lengths: Vec<I32Range>,
    pub delays: Vec<I32Range>,
    pub max_split: I32Range,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HeaderCustomTcpConfig {
    pub clients: Vec<Vec<HeaderCustomTcpItem>>,
    pub servers: Vec<Vec<HeaderCustomTcpItem>>,
    pub errors: Vec<Vec<HeaderCustomTcpItem>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HeaderCustomTcpItem {
    pub delay: I32Range,
    pub rand: i32,
    pub rand_range: Option<I32Range>,
    pub capture: String,
    #[serde(rename = "type")]
    pub packet_type: String,
    pub reuse: String,
    pub transform: Option<CustomTransform>,
    pub packet: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HeaderCustomUdpConfig {
    pub mode: String,
    pub client: Vec<HeaderCustomUdpItem>,
    pub server: Vec<HeaderCustomUdpItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HeaderCustomUdpItem {
    pub rand: i32,
    pub rand_range: Option<I32Range>,
    pub capture: String,
    #[serde(rename = "type")]
    pub packet_type: String,
    pub reuse: String,
    pub transform: Option<CustomTransform>,
    pub packet: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CustomTransform {
    pub op: String,
    pub args: Vec<CustomTransformArg>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct CustomTransformArg {
    #[serde(rename = "type")]
    pub bytes_type: String,
    pub bytes: Option<serde_json::Value>,
    pub u64: Option<u64>,
    pub reuse: String,
    pub metadata: String,
    pub transform: Option<Box<CustomTransform>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SudokuMaskConfig {
    pub password: String,
    pub ascii: String,
    pub custom_table: String,
    #[serde(rename = "custom_table")]
    pub legacy_custom_table: String,
    pub custom_tables: Vec<String>,
    #[serde(rename = "custom_tables")]
    pub legacy_custom_sets: Vec<String>,
    pub padding_min: u32,
    #[serde(rename = "padding_min")]
    pub legacy_padding_min: u32,
    pub padding_max: u32,
    #[serde(rename = "padding_max")]
    pub legacy_padding_max: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct XmcMaskConfig {
    pub hostname: String,
    pub usernames: Vec<String>,
    pub password: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NoiseMaskConfig {
    pub reset: I32Range,
    pub noise: Vec<NoiseItemConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NoiseItemConfig {
    pub rand: I32Range,
    pub rand_range: Option<I32Range>,
    #[serde(rename = "type")]
    pub packet_type: String,
    pub packet: Option<serde_json::Value>,
    pub delay: I32Range,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct MkcpLegacyMaskConfig {
    pub header: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SalamanderMaskConfig {
    pub password: String,
    pub packet_size: I32Range,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct XdnsMaskConfig {
    /// Removed by Xray 26.7.11. Kept only so validation can emit the precise
    /// migration error instead of treating it as an unknown field.
    pub domain: Option<serde_json::Value>,
    pub domains: Vec<String>,
    pub resolvers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct XicmpMaskConfig {
    #[serde(rename = "dgram")]
    pub dgram: bool,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct RealmMaskConfig {
    pub url: String,
    pub stun_servers: Vec<String>,
    /// Complete Xray TLS object shared with XHTTP/downloadSettings. Realm uses
    /// the same validated executor, so advanced fields (certificates, pins,
    /// versions, curves, uTLS fingerprints and ECH) cannot diverge or be lost.
    pub tls_config: Option<XhttpDownloadTlsSettings>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct QuicParamsConfig {
    pub congestion: String,
    pub debug: bool,
    pub bbr_profile: String,
    pub brutal_up: BandwidthValue,
    pub brutal_down: BandwidthValue,
    pub udp_hop: UdpHopConfig,
    pub init_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub init_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: i64,
    pub keep_alive_period: i64,
    #[serde(rename = "disablePathMTUDiscovery")]
    pub disable_path_mtu_discovery: bool,
    pub max_incoming_streams: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct UdpHopConfig {
    pub ports: PortListValue,
    pub interval: I32Range,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortListValue {
    #[default]
    Empty,
    Number(u32),
    Text(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum BandwidthValue {
    #[default]
    Empty,
    Number(u64),
    Text(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_range_accepts_signed_and_reversed_values() {
        let a: I32Range = serde_json::from_str("\"-1919--810\"").unwrap();
        assert_eq!((a.left, a.right, a.from, a.to), (-1919, -810, -1919, -810));
        let b: I32Range = serde_json::from_str("\"9-3\"").unwrap();
        assert_eq!((b.left, b.right, b.from, b.to), (9, 3, 3, 9));
        let c: I32Range = serde_json::from_str("-7").unwrap();
        assert_eq!(c, I32Range::fixed(-7));
    }

    #[test]
    fn sockopt_defaults_match_xray_26_7_11() {
        let cfg: OutboundSocketConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.domain_strategy, DomainStrategy::AsIs);
        assert_eq!(cfg.tfo_value(), 0);
        assert_eq!(cfg.happy_eyeballs.interleave, 1);
        assert_eq!(cfg.happy_eyeballs.try_delay_ms, 0);
        assert_eq!(cfg.happy_eyeballs.max_concurrent_try, 4);
    }

    #[test]
    fn tfo_bool_and_integer_match_xray_mapping() {
        let yes: OutboundSocketConfig = serde_json::from_str(r#"{"tcpFastOpen":true}"#).unwrap();
        let no: OutboundSocketConfig = serde_json::from_str(r#"{"tcpFastOpen":false}"#).unwrap();
        let zero: OutboundSocketConfig = serde_json::from_str(r#"{"tcpFastOpen":0}"#).unwrap();
        assert_eq!(yes.tfo_value(), 256);
        assert_eq!(no.tfo_value(), -1);
        assert_eq!(zero.tfo_value(), 0);
    }

    #[test]
    fn xray_strings_are_case_insensitive() {
        let cfg: OutboundSocketConfig = serde_json::from_str(
            r#"{"domainStrategy":"FORCEIPv6V4","addressPortStrategy":"TXTPORTANDADDRESS"}"#,
        )
        .unwrap();
        assert_eq!(cfg.domain_strategy, DomainStrategy::ForceIpv6v4);
        assert_eq!(
            cfg.address_port_strategy,
            AddressPortStrategy::TxtPortAndAddress
        );
    }

    #[test]
    fn mask_settings_may_be_omitted_like_xray_loader() {
        let tcp: TcpMaskConfig = serde_json::from_str(r#"{"type":"fragment"}"#).unwrap();
        assert!(matches!(tcp, TcpMaskConfig::Fragment(_)));
        let udp: UdpMaskConfig = serde_json::from_str(r#"{"type":"mkcp-legacy"}"#).unwrap();
        assert!(matches!(udp, UdpMaskConfig::MkcpLegacy(_)));
    }

    #[test]
    fn legacy_sudoku_keys_keep_their_official_json_spelling() {
        let config: SudokuMaskConfig = serde_json::from_str(
            r#"{"password":"p","custom_table":"xxppvvvv","custom_tables":["ppxxvvvv"],"padding_min":1,"padding_max":2}"#,
        )
        .unwrap();
        assert_eq!(config.legacy_custom_table, "xxppvvvv");
        assert_eq!(config.legacy_custom_sets, ["ppxxvvvv"]);
        assert_eq!(config.legacy_padding_min, 1);
        let encoded = serde_json::to_value(config).unwrap();
        assert_eq!(encoded["custom_table"], "xxppvvvv");
        assert!(encoded.get("legacyCustomTable").is_none());
    }

    #[test]
    fn complete_stream_shape_registers_socket_tcp_udp_and_quic_fields() {
        let stream: NodeStreamSettings = serde_json::from_str(
            r#"{
                "network":"raw",
                "sockopt":{
                    "mark":7,"tcpFastOpen":128,"domainStrategy":"UseIPv6v4",
                    "dialerProxy":"DIRECT","tcpKeepAliveInterval":20,
                    "tcpKeepAliveIdle":30,"tcpCongestion":"bbr",
                    "interface":"Ethernet","tcpWindowClamp":65535,
                    "tcpUserTimeout":1200,"tcpMaxSeg":1400,"tcpMptcp":true,
                    "customSockopt":[{"system":"windows","network":"tcp","level":"6","opt":"1","value":"1","type":"int"}],
                    "addressPortStrategy":"txtPortAndAddress",
                    "happyEyeballs":{"prioritizeIPv6":true,"interleave":2,"tryDelayMs":250,"maxConcurrentTry":3}
                },
                "finalmask":{
                    "tcp":[
                        {"type":"header-custom","settings":{"clients":[],"servers":[],"errors":[]}},
                        {"type":"fragment","settings":{"packets":"tlshello","length":"2-5","delay":"0-1","maxSplit":3}},
                        {"type":"sudoku","settings":{"password":"p"}},
                        {"type":"xmc","settings":{"hostname":"mc.example","usernames":["Dream"],"password":"p"}}
                    ],
                    "udp":[
                        {"type":"header-custom","settings":{"mode":"prefix"}},
                        {"type":"mkcp-legacy"},{"type":"noise"},
                        {"type":"salamander","settings":{"password":"p","packetSize":"1200-1400"}},
                        {"type":"sudoku","settings":{"password":"p"}},
                        {"type":"xdns","settings":{"resolvers":["8.8.8.8+udp://example.com:53"]}},
                        {"type":"xicmp","settings":{"dgram":true,"ips":["192.0.2.1"]}},
                        {"type":"realm","settings":{"url":"realm://token@example.com/id","stunServers":["stun.example:3478"]}}
                    ],
                    "quicParams":{"congestion":"bbr","bbrProfile":"standard","brutalUp":"10 mbps","udpHop":{"ports":"2000-3000","interval":"5-10"},"maxIdleTimeout":30,"keepAlivePeriod":10,"disablePathMTUDiscovery":true,"maxIncomingStreams":16}
                }
            }"#,
        )
        .unwrap();
        let socket = stream.sockopt.unwrap();
        assert_eq!(socket.tfo_value(), 128);
        assert_eq!(socket.happy_eyeballs.max_concurrent_try, 3);
        let finalmask = stream.finalmask.unwrap();
        assert_eq!(finalmask.tcp.len(), 4);
        assert_eq!(finalmask.udp.len(), 8);
        assert_eq!(
            finalmask.quic_params.unwrap().udp_hop.ports,
            PortListValue::Text("2000-3000".into())
        );
    }

    #[test]
    fn listener_stream_settings_are_compiled_into_runtime_plan() {
        let plan = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
name: inbound-finalmask
listen:
  local:
    host: 127.0.0.1
    port: 7890
    streamSettings:
      network: raw
      sockopt:
        acceptProxyProtocol: true
        trustedXForwardedFor: [X-Trusted-CDN]
      finalmask:
        tcp:
          - type: sudoku
            settings: { password: inbound-secret }
route:
  preset: direct
"#,
        )
        .unwrap();
        let settings = plan
            .listen
            .mixed
            .unwrap()
            .stream_settings
            .expect("listener streamSettings");
        assert!(settings.sockopt.unwrap().accept_proxy_protocol);
        assert!(matches!(
            &settings.finalmask.unwrap().tcp[..],
            [TcpMaskConfig::Sudoku(_)]
        ));
    }

    #[test]
    fn unknown_nested_stream_field_is_rejected() {
        let error = serde_json::from_str::<NodeStreamSettings>(
            r#"{"sockopt":{"domainStrategy":"AsIs","silentlyIgnored":true}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("silentlyIgnored"));
    }

    #[test]
    fn realm_tls_object_is_complete_strongly_typed_and_strict() {
        let mask: UdpMaskConfig = serde_json::from_str(
            r#"{
                "type":"realm",
                "settings":{
                    "url":"realm://token@example.com/id",
                    "stunServers":["stun.example:3478"],
                    "tlsConfig":{
                        "serverName":"control.example",
                        "alpn":"h2,http/1.1",
                        "enableSessionResumption":true,
                        "minVersion":"1.2",
                        "maxVersion":"1.3",
                        "cipherSuites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "curvePreferences":["x25519","curveP256"],
                        "pinnedPeerCertSha256":"00:11",
                        "verifyPeerCertByName":"control.example",
                        "echConfigList":"https://ech.example/config",
                        "echSockopt":{"mark":7},
                        "certificates":[{"certificate":["pem"],"usage":"verify"}]
                    }
                }
            }"#,
        )
        .unwrap();
        let UdpMaskConfig::Realm(realm) = mask else {
            panic!("realm mask");
        };
        let tls = realm.tls_config.unwrap();
        assert_eq!(tls.alpn.unwrap(), ["h2", "http/1.1"]);
        assert_eq!(tls.curve_preferences.unwrap(), ["x25519", "curveP256"]);
        assert_eq!(
            tls.certificates[0].usage,
            Some(crate::model::XhttpTlsCertificateUsage::Verify)
        );
        assert_eq!(tls.ech_socket_settings.unwrap().mark, Some(7));

        let error = serde_json::from_str::<XhttpDownloadTlsSettings>(r#"{"serverNmae":"typo"}"#)
            .unwrap_err();
        assert!(error.to_string().contains("serverNmae"));
    }
}
