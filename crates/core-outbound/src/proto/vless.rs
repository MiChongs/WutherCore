//! VLESS 出站（无加密版本）—— 与 mihomo / xray 互通。
//!
//! 协议头部（[reference](https://xtls.github.io/development/protocols/vless.html)）：
//! `Version(1) || UUID(16) || AddonsLen(1) || Addons || Cmd(1) || Port(2 BE) || ATYP(1) || ADDR`
//! * Version = 0x00（VLESS 当前版本）。
//! * Cmd     = 0x01 (TCP) / 0x02 (UDP) / 0x03 (Mux)。
//! * ATYP/ADDR 与 VMess 一致：0x01 IPv4 / 0x02 Domain (1B len + N) / 0x03 IPv6。
//!
//! 服务器响应：`Version(1) || AddonsLen(1) || Addons`，之后双向裸 payload。
//!
//! ## Network 类型分发（与 mihomo `Network` 字段对齐）
//!
//! | Network | 传输实现 |
//! |---|---|
//! | `tcp` (默认) | 裸 TCP / TLS |
//! | `ws` | WebSocket（可选 TLS） |
//! | `http` | HTTP/1.1 obfuscation over TLS |
//! | `h2` | HTTP/2 over TLS（PUT/POST + custom Host/Path） |
//! | `grpc` | gRPC over TLS（gun protocol） |
//! | `xhttp` | XHTTP transport（H2 三种模式：stream-one/stream-up/packet-up） |

use async_trait::async_trait;
use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter},
    transport::{
        GrpcOptions, H2Options, HttpOptions, TlsOptions, Transport, WsOptions, XhttpOptions,
        grpc_transport::GrpcTransport, h2_transport::H2Transport, http_transport::HttpTransport,
        tcp::TcpTransport, tls::TlsTransport, ws::WsTransport, xhttp_transport::XhttpTransport,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessNetwork {
    Tcp,
    Ws,
    Http,
    H2,
    Grpc,
    Xhttp,
}

impl VlessNetwork {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "ws" | "websocket" => Self::Ws,
            "http" => Self::Http,
            "h2" | "http2" | "http/2" => Self::H2,
            "grpc" | "gun" => Self::Grpc,
            "xhttp" | "splithttp" => Self::Xhttp,
            _ => Self::Tcp,
        }
    }
}

impl Default for VlessNetwork {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone, Default)]
pub struct VlessOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub uuid: Uuid,
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub network: VlessNetwork,
    pub ws: Option<WsOptions>,
    pub http: Option<HttpOptions>,
    pub h2: Option<H2Options>,
    pub grpc: Option<GrpcOptions>,
    pub xhttp: Option<XhttpOptions>,
}

impl VlessOutbound {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16, uuid: Uuid) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            uuid,
            ..Default::default()
        }
    }

    fn tls_opts(&self) -> TlsOptions {
        TlsOptions {
            enabled: self.tls,
            sni: self.sni.clone(),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        }
    }

    /// 按 network 类型派发到对应 transport
    async fn dial_transport(&self) -> std::io::Result<BoxedStream> {
        match self.network {
            VlessNetwork::Tcp => {
                if self.tls {
                    TlsTransport::new(self.tls_opts())
                        .connect(&self.host, self.port)
                        .await
                } else {
                    TcpTransport::default().connect(&self.host, self.port).await
                }
            }
            VlessNetwork::Ws => {
                let ws = self.ws.clone().unwrap_or_else(|| WsOptions {
                    enabled: true,
                    path: "/".into(),
                    host: None,
                    headers: vec![],
                });
                WsTransport::new(ws, self.tls)
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::Http => {
                let opts = self.http.clone().unwrap_or_default();
                HttpTransport::new(opts, self.tls_opts())
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::H2 => {
                let opts = self.h2.clone().unwrap_or_default();
                H2Transport::new(opts, self.tls_opts())
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::Grpc => {
                let opts = self.grpc.clone().unwrap_or_default();
                GrpcTransport::new(opts, self.tls_opts())
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::Xhttp => {
                let opts = self.xhttp.clone().unwrap_or_default();
                XhttpTransport::new(self.host.clone(), self.port, opts)
                    .connect(&self.host, self.port)
                    .await
            }
        }
    }
}

#[async_trait]
impl OutboundAdapter for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "vless"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = self.dial_transport().await?;
        let mut buf = Vec::with_capacity(64);
        buf.put_u8(0x00); // version
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.put_u8(0x00); // addons length = 0
        buf.put_u8(0x01); // CONNECT (TCP)
        buf.put_u16(ctx.port);
        // ATYP + ADDR：1=IPv4 2=Domain 3=IPv6
        if let Ok(ip) = ctx.host.parse::<std::net::Ipv4Addr>() {
            buf.put_u8(0x01);
            buf.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = ctx.host.parse::<std::net::Ipv6Addr>() {
            buf.put_u8(0x03);
            buf.extend_from_slice(&ip.octets());
        } else {
            buf.put_u8(0x02);
            buf.put_u8(ctx.host.len().min(255) as u8);
            buf.extend_from_slice(ctx.host.as_bytes());
        }
        stream.write_all(&buf).await?;

        // 读取 server 响应：Version(1) + AddonsLen(1) + Addons
        let mut resp_head = [0u8; 2];
        stream.read_exact(&mut resp_head).await?;
        if resp_head[1] > 0 {
            let mut addons = vec![0u8; resp_head[1] as usize];
            stream.read_exact(&mut addons).await?;
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_parse() {
        assert_eq!(VlessNetwork::parse("tcp"), VlessNetwork::Tcp);
        assert_eq!(VlessNetwork::parse("ws"), VlessNetwork::Ws);
        assert_eq!(VlessNetwork::parse("WS"), VlessNetwork::Ws);
        assert_eq!(VlessNetwork::parse("http"), VlessNetwork::Http);
        assert_eq!(VlessNetwork::parse("h2"), VlessNetwork::H2);
        assert_eq!(VlessNetwork::parse("grpc"), VlessNetwork::Grpc);
        assert_eq!(VlessNetwork::parse("gun"), VlessNetwork::Grpc);
        assert_eq!(VlessNetwork::parse("xhttp"), VlessNetwork::Xhttp);
        assert_eq!(VlessNetwork::parse("splithttp"), VlessNetwork::Xhttp);
        assert_eq!(VlessNetwork::parse(""), VlessNetwork::Tcp);
    }

    #[test]
    fn vless_construct_default_network_tcp() {
        let u = Uuid::nil();
        let ob = VlessOutbound::new("v", "1.2.3.4", 443, u);
        assert_eq!(ob.network, VlessNetwork::Tcp);
        assert_eq!(ob.protocol(), "vless");
    }
}
