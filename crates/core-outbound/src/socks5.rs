//! SOCKS5 出站 —— 仅 TCP CONNECT，支持 user/pass 认证。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::{BoxedStream, DialContext, OutboundAdapter};
use crate::transport::Transport;

#[derive(Debug, Clone)]
pub struct Socks5Outbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl Socks5Outbound {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            auth: None,
        }
    }
    pub fn with_auth(mut self, u: impl Into<String>, p: impl Into<String>) -> Self {
        self.auth = Some((u.into(), p.into()));
        self
    }
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[async_trait]
impl OutboundAdapter for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "socks5"
    }
    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // 走 TcpTransport：自带 RPKernel resolver + SO_MARK 绕 TUN。
        let mut s = crate::transport::tcp::TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // greeting
        if self.auth.is_some() {
            s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?; // 支持 NO_AUTH 与 USER_PASS
        } else {
            s.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            return Err(io_err("socks5 版本错误"));
        }
        match resp[1] {
            0x00 => {}
            0x02 => {
                let (u, p) = self
                    .auth
                    .as_ref()
                    .ok_or_else(|| io_err("服务器要求 USER_PASS 但未配置"))?;
                let mut buf = vec![0x01, u.len() as u8];
                buf.extend_from_slice(u.as_bytes());
                buf.push(p.len() as u8);
                buf.extend_from_slice(p.as_bytes());
                s.write_all(&buf).await?;
                let mut ar = [0u8; 2];
                s.read_exact(&mut ar).await?;
                if ar[1] != 0x00 {
                    return Err(io_err("socks5 user/pass 鉴权失败"));
                }
            }
            other => return Err(io_err(&format!("socks5 不支持的方法: {other}"))),
        }

        // CONNECT
        let mut req = vec![0x05, 0x01, 0x00];
        if let Ok(ip) = ctx.host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = ctx.host.parse::<std::net::Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        } else {
            req.push(0x03);
            req.push(ctx.host.len() as u8);
            req.extend_from_slice(ctx.host.as_bytes());
        }
        req.extend_from_slice(&ctx.port.to_be_bytes());
        s.write_all(&req).await?;

        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            return Err(io_err(&format!("socks5 CONNECT 失败: rep={}", head[1])));
        }
        // 跳过 BND.ADDR + BND.PORT
        match head[3] {
            0x01 => {
                let mut buf = [0u8; 6];
                s.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 18];
                s.read_exact(&mut buf).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await?;
                let mut rest = vec![0u8; len[0] as usize + 2];
                s.read_exact(&mut rest).await?;
            }
            _ => return Err(io_err("socks5 BND.ADDR 类型错误")),
        }
        Ok(Box::pin(s))
    }
}

fn io_err(s: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.to_string())
}
