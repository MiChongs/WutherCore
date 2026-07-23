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

use async_trait::async_trait;

use crate::adapter::BoxedStream;

pub mod grpc_transport;
pub mod h2_transport;
pub mod http_transport;
pub mod reality;
pub mod tcp;
pub mod tls;
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
}

#[derive(Debug, Clone, Default)]
pub struct WsOptions {
    pub enabled: bool,
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}
