//! 通用传输层：TCP / TLS / WebSocket。
//!
//! 上层协议（Shadowsocks / Trojan / VLESS / VMess）不关心底层走的是
//! 裸 TCP、TLS、还是 WS-over-TLS。它们通过 [`Transport::connect`] 拿到一个
//! `BoxedStream` 之后，就可以把"目标地址 + 数据"按各自协议的格式写进去。
//!
//! 三种实现：
//! * [`tcp::TcpTransport`]      —— 纯 TCP
//! * [`tls::TlsTransport`]      —— TLS over TCP（rustls + ring + webpki-roots）
//! * [`ws::WsTransport`]        —— WebSocket，可选叠加 TLS（即 wss）

use std::io;

use async_trait::async_trait;
use core_config::model::XhttpDownloadTlsSettings;

use crate::adapter::BoxedStream;

pub(crate) mod boring_tls;
pub(crate) mod ech;
pub mod finalmask;
pub mod grpc_transport;
pub mod h2_transport;
pub mod http_transport;
pub mod reality;
#[allow(unsafe_code)]
pub mod tcp;
pub mod tls;
mod utls;
mod utls_profiles;
pub mod ws;
pub mod xhttp_transport;

pub use grpc_transport::{GrpcOptions, GrpcTransport};
pub use h2_transport::{H2Options, H2Transport};
pub use http_transport::{HttpOptions, HttpTransport};
pub use reality::{RealityOptions, RealityTransport};
pub use xhttp_transport::{XhttpOptions, XhttpTransport};

#[async_trait]
pub trait Transport: Send + Sync {
    /// 与远端建立一条字节流。
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream>;
}

/// 公共 TLS 选项。
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub enabled: bool,
    pub sni: Option<String>,
    /// 默认 false（验证证书）；设置为 true 关闭证书校验（仅 debug）。
    pub insecure: bool,
    /// ALPN 提示（如 ["h2", "http/1.1"]）。
    pub alpn: Vec<String>,
    /// 是否启用 TLS 会话恢复。默认关闭，与 Xray TLS 配置一致。
    pub enable_session_resumption: bool,
    /// Xray/uTLS ClientHello 指纹。空串等价 `HelloChrome_Auto`；`unsafe`
    /// 显式保留普通 rustls ClientHello，其余值必须与 Xray 名称完全匹配。
    pub fingerprint: String,
    /// Xray `pinnedPeerCertSha256`：允许匹配叶证书，或把匹配的中间 CA
    /// 作为本次握手的唯一信任锚。
    pub pinned_peer_cert_sha256: Vec<[u8; 32]>,
    /// Xray `verifyPeerCertByName`：非空时不使用拨号 SNI 做名称验证，而是
    /// 依次尝试这里的 DNS/IP 名称。
    pub verify_peer_cert_by_name: Vec<String>,
    /// 完整 Xray TLS 配置。仅 XHTTP 使用此对象；保留完整值可保证 TCP 与
    /// QUIC 后端在能力选择时不会丢字段或静默忽略高级配置。
    pub xray_settings: Option<XhttpDownloadTlsSettings>,
    /// `echConfigList` 为 DNS URL 时由异步解析器写入；不参与用户配置序列化。
    pub(crate) resolved_ech_config_list: Option<Vec<u8>>,
}

impl TlsOptions {
    /// Compile one complete, strongly typed Xray TLS object into executable
    /// transport options. Callers only pass the source settings; certificates,
    /// pins, name overrides, ALPN, resumption, fingerprint and ECH stay on one
    /// validation/parsing path shared by XHTTP, Realm and stacked transports.
    pub fn from_xray_settings(settings: XhttpDownloadTlsSettings) -> io::Result<Self> {
        settings
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let pinned_peer_cert_sha256 =
            parse_pinned_peer_cert_sha256(settings.pinned_peer_cert_sha256.as_deref())?;
        let verify_peer_cert_by_name =
            parse_verify_peer_cert_by_name(settings.verify_peer_cert_by_name.as_deref());
        Ok(Self {
            enabled: true,
            sni: settings
                .server_name
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            insecure: false,
            alpn: settings.alpn.clone().unwrap_or_default(),
            enable_session_resumption: settings.enable_session_resumption.unwrap_or(false),
            fingerprint: settings.fingerprint.clone().unwrap_or_default(),
            pinned_peer_cert_sha256,
            verify_peer_cert_by_name,
            xray_settings: Some(settings),
            resolved_ech_config_list: None,
        })
    }
}

pub(crate) fn parse_pinned_peer_cert_sha256(value: Option<&str>) -> io::Result<Vec<[u8; 32]>> {
    let mut pins = Vec::new();
    for encoded in value.unwrap_or_default().split(',') {
        let encoded = encoded.trim();
        if encoded.is_empty() {
            continue;
        }
        let compact = encoded.replace(':', "");
        let decoded = hex::decode(&compact).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid pinnedPeerCertSha256 value {encoded:?}: {error}"),
            )
        })?;
        let pin: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "incorrect pinnedPeerCertSha256 length for {encoded:?}: got {} bytes, expected 32",
                    decoded.len()
                ),
            )
        })?;
        pins.push(pin);
    }
    Ok(pins)
}

pub(crate) fn parse_verify_peer_cert_by_name(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WsOptions {
    pub enabled: bool,
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_tls_settings_compile_through_one_public_entrypoint() {
        let settings = XhttpDownloadTlsSettings {
            server_name: Some("inner.example".into()),
            alpn: Some(vec!["h2".into()]),
            enable_session_resumption: Some(true),
            fingerprint: Some("chrome".into()),
            pinned_peer_cert_sha256: Some(format!("{}:{}", "11".repeat(16), "22".repeat(16))),
            verify_peer_cert_by_name: Some("one.example, two.example".into()),
            min_version: Some("1.2".into()),
            max_version: Some("1.3".into()),
            ..Default::default()
        };
        let options = TlsOptions::from_xray_settings(settings.clone()).unwrap();
        assert!(options.enabled);
        assert_eq!(options.sni.as_deref(), Some("inner.example"));
        assert_eq!(options.alpn, ["h2"]);
        assert!(options.enable_session_resumption);
        assert_eq!(options.fingerprint, "chrome");
        assert_eq!(options.pinned_peer_cert_sha256.len(), 1);
        assert_eq!(
            options.verify_peer_cert_by_name,
            ["one.example", "two.example"]
        );
        assert_eq!(options.xray_settings, Some(settings));
    }

    #[test]
    fn xray_tls_entrypoint_fails_closed_before_transport_creation() {
        let invalid_pin = XhttpDownloadTlsSettings {
            pinned_peer_cert_sha256: Some("abcd".into()),
            ..Default::default()
        };
        assert!(TlsOptions::from_xray_settings(invalid_pin).is_err());

        let invalid_version = XhttpDownloadTlsSettings {
            min_version: Some("1.3".into()),
            max_version: Some("1.2".into()),
            ..Default::default()
        };
        assert!(TlsOptions::from_xray_settings(invalid_version).is_err());
    }
}
