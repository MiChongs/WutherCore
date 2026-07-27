//! Trojan 出站 —— 与 mihomo / trojan-go 互通。
//!
//! 协议（[reference](https://trojan-gfw.github.io/trojan/protocol)）：
//! 1. 通过 TLS 直连，或通过承载 TLS 的 XHTTP 传输连到服务器；
//! 2. 客户端发送：
//!    `hex(SHA-224(password)) [56B] || CRLF || CMD(1) || ATYP || ADDR || PORT || CRLF || payload`
//!    其中 CMD = 0x01 (CONNECT) / 0x03 (UDP ASSOCIATE)；ATYP/ADDR/PORT 与 SOCKS5 相同。
//! 3. 之后双向就是裸 payload。

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::Mutex as AsyncMutex,
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    proto::addr::encode_socks_addr,
    transport::{
        GrpcOptions, GrpcTransport, TlsOptions, Transport, XhttpOptions, tcp::TcpTransport,
        tls::TlsTransport, xhttp_transport::XhttpTransport,
    },
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
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub tls_options: Option<TlsOptions>,
    pub udp: bool,
    pub xhttp: Option<XhttpOptions>,
    pub grpc: Option<GrpcOptions>,
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
            tls: true,
            sni: None,
            insecure: false,
            alpn: vec![],
            tls_options: None,
            udp: true,
            xhttp: None,
            grpc: None,
        }
    }

    async fn connect_transport(&self) -> std::io::Result<BoxedStream> {
        let tls = self.tls_options.clone().unwrap_or_else(|| TlsOptions {
            enabled: self.tls,
            sni: self.sni.clone(),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
            fingerprint: String::new(),
            enable_session_resumption: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            xray_settings: None,
            resolved_ech_config_list: None,
        });
        if let Some(grpc) = self.grpc.as_ref() {
            GrpcTransport::new(grpc.clone(), tls)
                .connect(&self.host, self.port)
                .await
        } else if self.tls {
            TlsTransport::new(tls).connect(&self.host, self.port).await
        } else {
            TcpTransport::default().connect(&self.host, self.port).await
        }
    }

    async fn dial_transport(&self) -> std::io::Result<BoxedStream> {
        if let Some(options) = self.xhttp.clone() {
            XhttpTransport::new(self.host.clone(), self.port, options)
                .connect(&self.host, self.port)
                .await
        } else {
            self.connect_transport().await
        }
    }

    fn build_header(&self, command: u8, host: &str, port: u16) -> Vec<u8> {
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
        header
    }

    async fn connect_with_header(
        &self,
        command: u8,
        host: &str,
        port: u16,
    ) -> std::io::Result<BoxedStream> {
        let mut stream = self.dial_transport().await?;
        let header = self.build_header(command, host, port);
        if self.xhttp.is_some() {
            Ok(Box::pin(PrefixedWriteStream::new(stream, header)))
        } else {
            stream.write_all(&header).await?;
            Ok(stream)
        }
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
        let stream = self
            .connect_with_header(TROJAN_CMD_TCP, &ctx.host, ctx.port)
            .await?;
        tracing::info!(
            target: "dial::trojan",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %format!("{}:{}", self.host, self.port),
            target = %format!("{}:{}", ctx.host, ctx.port),
            "tcp connect prepared",
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
        let stream = self
            .connect_with_header(TROJAN_CMD_UDP, &ctx.host, ctx.port)
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

/// Keeps the Trojan request header adjacent to the first application payload
/// on XHTTP. This mirrors Xray's first-payload buffering and avoids needlessly
/// splitting the logical Trojan request across multiple XHTTP body fragments.
///
/// A write combines both byte sequences in one inner `poll_write`. A read,
/// flush, or shutdown before any payload still sends the header so banner-first
/// protocols and empty TCP sessions remain usable.
struct PrefixedWriteStream {
    inner: BoxedStream,
    prefix: Option<Vec<u8>>,
}

impl PrefixedWriteStream {
    fn new(inner: BoxedStream, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix: Some(prefix),
        }
    }

    fn poll_prefix(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            let Some(prefix) = self.prefix.take() else {
                return Poll::Ready(Ok(()));
            };
            if prefix.is_empty() {
                continue;
            }
            match self.inner.as_mut().poll_write(cx, &prefix) {
                Poll::Pending => {
                    self.prefix = Some(prefix);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    if written < prefix.len() {
                        self.prefix = Some(prefix[written..].to_vec());
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncRead for PrefixedWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_prefix(cx) {
            Poll::Ready(Ok(())) => this.inner.as_mut().poll_read(cx, buffer),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PrefixedWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let Some(prefix) = this.prefix.take() else {
            return this.inner.as_mut().poll_write(cx, data);
        };
        if data.is_empty() {
            this.prefix = Some(prefix);
            return match this.poll_prefix(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }

        let prefix_len = prefix.len();
        let mut combined = Vec::with_capacity(prefix_len + data.len());
        combined.extend_from_slice(&prefix);
        combined.extend_from_slice(data);
        let mut written = 0;
        loop {
            match this.inner.as_mut().poll_write(cx, &combined[written..]) {
                Poll::Pending => {
                    if written < prefix_len {
                        this.prefix = Some(prefix[written..].to_vec());
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(count)) => {
                    written += count;
                    if written > prefix_len {
                        return Poll::Ready(Ok((written - prefix_len).min(data.len())));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_prefix(cx) {
            Poll::Ready(Ok(())) => this.inner.as_mut().poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_prefix(cx) {
            Poll::Ready(Ok(())) => this.inner.as_mut().poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
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
        self.recv_from_endpoint(buf).await.map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Option<std::net::SocketAddr>)> {
        let mut read = self.read.lock().await;
        let (host, port) = read_socks_addr_async(&mut *read).await?;
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
        let endpoint = host
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|address| std::net::SocketAddr::new(address, port));
        Ok((copy_len, endpoint))
    }

    async fn close(&self) -> std::io::Result<()> {
        let mut write = self.write.lock().await;
        let _ = write.shutdown().await;
        Ok(())
    }

    fn supports_multi_target(&self) -> bool {
        true
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
    use std::sync::{Arc, Mutex};

    use super::*;

    struct RecordingStream {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        max_write: usize,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let count = data.len().min(self.max_write);
            self.writes.lock().unwrap().push(data[..count].to_vec());
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn first_application_write_is_coalesced_with_trojan_header() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let inner: BoxedStream = Box::pin(RecordingStream {
            writes: writes.clone(),
            max_write: usize::MAX,
        });
        let mut stream = PrefixedWriteStream::new(inner, b"header".to_vec());
        stream.write_all(b"payload").await.unwrap();

        assert_eq!(&*writes.lock().unwrap(), &[b"headerpayload".to_vec()]);
    }

    #[tokio::test]
    async fn partial_inner_writes_preserve_prefix_and_payload_exactly_once() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let inner: BoxedStream = Box::pin(RecordingStream {
            writes: writes.clone(),
            max_write: 3,
        });
        let mut stream = PrefixedWriteStream::new(inner, b"header".to_vec());
        stream.write_all(b"payload").await.unwrap();

        let observed = writes
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(observed, b"headerpayload");
    }

    #[tokio::test]
    async fn flush_without_payload_still_sends_trojan_header() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let inner: BoxedStream = Box::pin(RecordingStream {
            writes: writes.clone(),
            max_write: usize::MAX,
        });
        let mut stream = PrefixedWriteStream::new(inner, b"header".to_vec());
        stream.flush().await.unwrap();

        assert_eq!(&*writes.lock().unwrap(), &[b"header".to_vec()]);
    }

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
