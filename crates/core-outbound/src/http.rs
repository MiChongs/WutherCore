//! HTTP CONNECT 出站。
//!
//! 仅支持 TCP；`HTTPS over CONNECT`，自动注入 Basic auth。

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    adapter::{BoxedStream, DialContext, OutboundAdapter},
    transport::Transport,
};

#[derive(Debug, Clone)]
pub struct HttpOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl HttpOutbound {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            auth: None,
        }
    }

    pub fn with_auth(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.auth = Some((user.into(), pass.into()));
        self
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[async_trait]
impl OutboundAdapter for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "http"
    }
    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // 走 TcpTransport：自带 WutherCore resolver + SO_MARK 绕 TUN。
        let mut s = crate::transport::tcp::TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;
        let target = format!("{}:{}", ctx.host, ctx.port);
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some((u, p)) = &self.auth {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).await?;
        let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("HTTP CONNECT 失败: {}", resp.lines().next().unwrap_or("")),
            ));
        }
        Ok(Box::pin(s))
    }
}
