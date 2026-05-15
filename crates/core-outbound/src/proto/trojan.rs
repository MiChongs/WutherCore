//! Trojan 出站 —— 与 mihomo / trojan-go 互通。
//!
//! 协议（[reference](https://trojan-gfw.github.io/trojan/protocol)）：
//! 1. 通过 TLS 连到服务器（必须启用 TLS）；
//! 2. 客户端发送：
//!    `hex(SHA-224(password)) [56B] || CRLF || CMD(1) || ATYP || ADDR || PORT || CRLF || payload`
//!    其中 CMD = 0x01 (CONNECT) / 0x03 (UDP ASSOCIATE)；ATYP/ADDR/PORT 与 SOCKS5 相同。
//! 3. 之后双向就是裸 payload。

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::Mutex as AsyncMutex,
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    proto::addr::encode_socks_addr,
    transport::{TlsOptions, Transport, tls::TlsTransport},
};

const TROJAN_CMD_TCP: u8 = 0x01;
const TROJAN_CMD_UDP: u8 = 0x03;
const TROJAN_UDP_MAX_PACKET: usize = 8192;

#[derive(Debug, Clone)]
pub struct TrojanOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub udp: bool,
}

impl TrojanOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec![],
            udp: true,
        }
    }

    async fn connect_tls(&self) -> std::io::Result<BoxedStream> {
        let tls = TlsTransport::new(TlsOptions {
            enabled: true,
            sni: self.sni.clone(),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        });
        tls.connect(&self.host, self.port).await
    }

    async fn write_header(
        &self,
        stream: &mut BoxedStream,
        command: u8,
        host: &str,
        port: u16,
    ) -> std::io::Result<()> {
        let mut h = Sha224::new();
        h.update(self.password.as_bytes());
        let hash = h.finalize();
        let hex_hash = hex_encode(&hash);

        let target = encode_socks_addr(host, port);
        let mut header = Vec::with_capacity(56 + 2 + 1 + target.len() + 2);
        header.extend_from_slice(hex_hash.as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(command);
        header.extend_from_slice(&target);
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).await
    }
}

#[async_trait]
impl OutboundAdapter for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "trojan"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = self.connect_tls().await?;
        self.write_header(&mut stream, TROJAN_CMD_TCP, &ctx.host, ctx.port)
            .await?;
        tracing::info!(
            target: "dial::trojan",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %format!("{}:{}", self.host, self.port),
            target = %format!("{}:{}", ctx.host, ctx.port),
            "tcp connect header sent",
        );
        Ok(stream)
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        if !self.udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("outbound `{}`/trojan udp disabled by config", self.name),
            ));
        }
        let mut stream = self.connect_tls().await?;
        self.write_header(&mut stream, TROJAN_CMD_UDP, &ctx.host, ctx.port)
            .await?;
        let (read, write) = tokio::io::split(stream);
        tracing::info!(
            target: "dial::trojan",
            id = ctx.dial_id,
            proxy = %self.name,
            target = %format!("{}:{}", ctx.host, ctx.port),
            "udp associate ok",
        );
        Ok(Box::new(TrojanUdp {
            read: AsyncMutex::new(read),
            write: AsyncMutex::new(write),
        }))
    }
}

struct TrojanUdp {
    read: AsyncMutex<ReadHalf<BoxedStream>>,
    write: AsyncMutex<WriteHalf<BoxedStream>>,
}

#[async_trait]
impl UdpSocketLike for TrojanUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        let addr = encode_socks_addr(target, port);
        let mut write = self.write.lock().await;
        for chunk in buf.chunks(TROJAN_UDP_MAX_PACKET) {
            write_trojan_udp_packet(&mut *write, &addr, chunk).await?;
        }
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read = self.read.lock().await;
        let _ = read_socks_addr_async(&mut *read).await?;
        let mut len = [0u8; 2];
        read.read_exact(&mut len).await?;
        let total = u16::from_be_bytes(len) as usize;
        let mut crlf = [0u8; 2];
        read.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(io_err("trojan udp packet missing crlf"));
        }
        let mut payload = vec![0u8; total];
        if total > 0 {
            read.read_exact(&mut payload).await?;
        }
        let copy_len = total.min(buf.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
        Ok(copy_len)
    }

    async fn close(&self) -> std::io::Result<()> {
        let mut write = self.write.lock().await;
        let _ = write.shutdown().await;
        Ok(())
    }
}

async fn write_trojan_udp_packet<W>(
    write: &mut W,
    addr: &[u8],
    payload: &[u8],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut packet = Vec::with_capacity(addr.len() + 2 + 2 + payload.len());
    packet.extend_from_slice(addr);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    write.write_all(&packet).await
}

async fn read_socks_addr_async<R>(read: &mut R) -> std::io::Result<(String, u16)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut atyp = [0u8; 1];
    read.read_exact(&mut atyp).await?;
    match atyp[0] {
        0x01 => {
            let mut buf = [0u8; 6];
            read.read_exact(&mut buf).await?;
            let host = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).to_string();
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((host, port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            read.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            read.read_exact(&mut buf).await?;
            let host = std::str::from_utf8(&buf[..len[0] as usize])
                .map_err(|_| io_err("trojan udp domain invalid"))?
                .to_string();
            let port = u16::from_be_bytes([buf[len[0] as usize], buf[len[0] as usize + 1]]);
            Ok((host, port))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            read.read_exact(&mut buf).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let host = std::net::Ipv6Addr::from(ip).to_string();
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((host, port))
        }
        _ => Err(io_err("trojan udp address type invalid")),
    }
}

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(TABLE[(*b >> 4) as usize] as char);
        s.push(TABLE[(*b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_hex_is_56_chars() {
        let mut h = Sha224::new();
        h.update(b"hello");
        let s = hex_encode(&h.finalize());
        assert_eq!(s.len(), 56);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn udp_capability_is_declared_when_enabled() {
        let ob = TrojanOutbound::new("trojan", "example.com", 443, "password");
        assert!(ob.capabilities().udp);
    }
}
