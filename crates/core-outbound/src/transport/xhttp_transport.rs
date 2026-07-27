//! XHTTP Transport —— 把 [`crate::proto::xhttp::XhttpClient`] 包装成 [`Transport`]
//! 接口，使 VLESS / VMess / Trojan 可以把 transport=xhttp 节点的 dial 委托过来。
//!
//! 与 mihomo 行为对齐：上层协议拿到 BoxedStream 后，按自己的协议头部写到 stream 上，
//! XHTTP transport 内部把这些字节封装在 HTTP/2 请求体里送出。

use std::sync::Arc;

use async_trait::async_trait;
use core_config::model::{XhttpDownloadRealitySettings, XhttpDownloadTlsSettings};

use crate::{
    adapter::BoxedStream,
    proto::xhttp::{Config as XhttpConfig, XhttpClient},
    transport::Transport,
};

#[derive(Debug, Clone)]
pub struct XhttpOptions {
    pub enabled: bool,
    pub config: XhttpConfig,
    /// 是否在 TCP HTTP 连接上启用 TLS。明文严格选择 HTTP/1.1；
    /// TLS 再按 ALPN 决定 H1/H2/H3。
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub enable_session_resumption: bool,
    pub fingerprint: Option<String>,
    pub pinned_peer_cert_sha256: Vec<[u8; 32]>,
    pub verify_peer_cert_by_name: Vec<String>,
    /// Preserve the complete typed object so capabilities added to the shared
    /// TLS builder cannot be lost at the registry boundary.
    pub tls_settings: Option<XhttpDownloadTlsSettings>,
    pub reality_settings: Option<XhttpDownloadRealitySettings>,
    pub has_reality: bool,
}

impl Default for XhttpOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            config: XhttpConfig::default(),
            tls: true,
            sni: None,
            insecure: false,
            alpn: Vec::new(),
            enable_session_resumption: false,
            fingerprint: None,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            tls_settings: None,
            reality_settings: None,
            has_reality: false,
        }
    }
}

pub struct XhttpTransport {
    client: Arc<XhttpClient>,
    has_reality: bool,
}

impl XhttpTransport {
    pub fn new(host: impl Into<String>, port: u16, opts: XhttpOptions) -> Self {
        let mut client = XhttpClient::new(opts.config, host, port);
        client.tls = opts.tls;
        client.sni = opts.sni;
        client.insecure = opts.insecure;
        client.enable_session_resumption = opts.enable_session_resumption;
        client.fingerprint = opts.fingerprint;
        client.pinned_peer_cert_sha256 = opts.pinned_peer_cert_sha256;
        client.verify_peer_cert_by_name = opts.verify_peer_cert_by_name;
        client.tls_settings = opts.tls_settings;
        client.reality_settings = opts.reality_settings;
        if !opts.alpn.is_empty() {
            client.alpn = opts.alpn;
        }
        Self {
            client: Arc::new(client),
            has_reality: opts.has_reality,
        }
    }
}

#[async_trait]
impl Transport for XhttpTransport {
    async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<BoxedStream> {
        // host/port 已绑定到 self.client 上（XHTTP 是站点级 transport，不针对每次 dial 改变远端）
        self.client.dial(self.has_reality).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default() {
        let opts = XhttpOptions::default();
        assert!(!opts.enabled);
        assert!(opts.tls);
        assert!(!opts.has_reality);
    }

    #[test]
    fn transport_construct() {
        let opts = XhttpOptions {
            enabled: true,
            config: XhttpConfig {
                path: "/api".into(),
                mode: "packet-up".into(),
                ..Default::default()
            },
            tls: true,
            sni: Some("example.com".into()),
            insecure: false,
            alpn: vec!["h2".into()],
            enable_session_resumption: false,
            fingerprint: Some("chrome".into()),
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            tls_settings: None,
            reality_settings: None,
            has_reality: false,
        };
        let _t = XhttpTransport::new("example.com", 443, opts);
    }
}
