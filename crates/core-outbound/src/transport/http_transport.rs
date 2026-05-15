//! HTTP/1.1 obfuscation 传输层 —— 与 mihomo `transport/vmess/http.go` (StreamHTTPConn) 等价。
//!
//! 在 TLS 上叠加 HTTP/1.1 伪装：
//! 1. TLS 握手（必须）
//! 2. 客户端写出一段伪装的 HTTP/1.1 请求 header（method/path/host/headers）
//! 3. 此后是双向裸字节流（不再封装 HTTP 协议帧）
//!
//! 服务器端会读取并丢弃 HTTP 头部，然后开始裸字节通信。这是最简单的
//! HTTP obfs 模式（mihomo 中称为 `Network: "http"`，与 xhttp/h2/grpc 不同）。

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use rand::seq::SliceRandom;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    adapter::BoxedStream,
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

#[derive(Debug, Clone, Default)]
pub struct HttpOptions {
    pub enabled: bool,
    pub method: String,                 // 默认 GET
    pub path: Vec<String>,              // 候选 path 列表，随机选一个
    pub host: Vec<String>,              // 候选 Host 头列表
    pub headers: Vec<(String, String)>, // 额外头部
}

pub struct HttpTransport {
    opts: HttpOptions,
    tls: TlsOptions,
}

impl HttpTransport {
    pub fn new(opts: HttpOptions, tls: TlsOptions) -> Self {
        Self { opts, tls }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let mut tls = self.tls.clone();
        tls.enabled = true;
        // 选 path / host 在 await 前完成（避免 ThreadRng 跨 await）
        let (path, host_header) = {
            let mut rng = rand::thread_rng();
            let p = if !self.opts.path.is_empty() {
                self.opts
                    .path
                    .choose(&mut rng)
                    .cloned()
                    .unwrap_or_else(|| "/".into())
            } else {
                "/".into()
            };
            let h = if !self.opts.host.is_empty() {
                self.opts
                    .host
                    .choose(&mut rng)
                    .cloned()
                    .unwrap_or_else(|| host.to_string())
            } else {
                host.to_string()
            };
            (p, h)
        };
        let mut stream = TlsTransport::new(tls).connect(host, port).await?;
        let method = if self.opts.method.is_empty() {
            "GET"
        } else {
            &self.opts.method
        };

        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(method.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        buf.extend_from_slice(host_header.as_bytes());
        buf.extend_from_slice(b"\r\n");
        for (k, v) in &self.opts.headers {
            buf.extend_from_slice(k.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(v.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        if !self
            .opts
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        {
            buf.extend_from_slice(
                b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n",
            );
        }
        buf.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
        stream.write_all(&buf).await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default() {
        let o = HttpOptions::default();
        assert!(!o.enabled);
        assert_eq!(o.method, "");
    }

    #[test]
    fn http_transport_construct() {
        let opts = HttpOptions {
            enabled: true,
            method: "GET".into(),
            path: vec!["/index.html".into()],
            host: vec!["example.com".into()],
            headers: vec![("X-Token".into(), "abc".into())],
        };
        let _t = HttpTransport::new(opts, TlsOptions::default());
    }
}
