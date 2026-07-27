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
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::{
    io::{AsyncReadExt, ReadHalf, WriteHalf},
    sync::Mutex as AsyncMutex,
};
use uuid::Uuid;

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    transport::{
        GrpcOptions, H2Options, HttpOptions, RealityOptions, RealityTransport, TlsOptions,
        Transport, WsOptions, XhttpOptions, grpc_transport::GrpcTransport,
        h2_transport::H2Transport, http_transport::HttpTransport, tcp::TcpTransport,
        tls::TlsTransport, ws::WsTransport, xhttp_transport::XhttpTransport,
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
    /// 完整 TLS/ECH 客户端配置；由注册层一次性严格编译。
    pub tls_options: Option<TlsOptions>,
    pub reality: Option<RealityOptions>,
    pub network: VlessNetwork,
    pub ws: Option<WsOptions>,
    pub http: Option<HttpOptions>,
    pub h2: Option<H2Options>,
    pub grpc: Option<GrpcOptions>,
    pub xhttp: Option<XhttpOptions>,
}

/// A VLESS stream whose response header is consumed on the first application
/// read instead of while dialing.
///
/// Xray writes the response header from its downlink copy task. Waiting for
/// that header in [`OutboundAdapter::dial_tcp`] deadlocks protocols whose
/// upstream does not produce data until the client sends its first request.
/// Writes must therefore remain usable immediately after the request header
/// has been sent.
struct VlessResponseStream {
    inner: BoxedStream,
    state: VlessResponseState,
}

#[derive(Debug, Clone, Copy)]
enum VlessResponseState {
    Version,
    AddonsLength,
    Addons(usize),
    Ready,
    Failed,
}

impl VlessResponseStream {
    fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            state: VlessResponseState::Version,
        }
    }

    fn poll_control_byte(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u8>> {
        let mut byte = [0_u8; 1];
        let mut read_buf = ReadBuf::new(&mut byte);
        match self.inner.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated VLESS response header",
                )))
            }
            Poll::Ready(Ok(())) => Poll::Ready(Ok(byte[0])),
        }
    }

    fn fail(&mut self, error: io::Error) -> Poll<io::Result<()>> {
        self.state = VlessResponseState::Failed;
        Poll::Ready(Err(error))
    }
}

impl AsyncRead for VlessResponseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        loop {
            match this.state {
                VlessResponseState::Version => match this.poll_control_byte(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return this.fail(error),
                    Poll::Ready(Ok(0)) => this.state = VlessResponseState::AddonsLength,
                    Poll::Ready(Ok(version)) => {
                        return this.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "unexpected VLESS response version: expected 0, received {version}"
                            ),
                        ));
                    }
                },
                VlessResponseState::AddonsLength => match this.poll_control_byte(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return this.fail(error),
                    Poll::Ready(Ok(0)) => this.state = VlessResponseState::Ready,
                    Poll::Ready(Ok(length)) => {
                        this.state = VlessResponseState::Addons(usize::from(length));
                    }
                },
                VlessResponseState::Addons(remaining) => {
                    let mut discard = [0_u8; u8::MAX as usize];
                    let take = remaining.min(discard.len());
                    let mut read_buf = ReadBuf::new(&mut discard[..take]);
                    match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return this.fail(error),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return this.fail(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated VLESS response addons",
                            ));
                        }
                        Poll::Ready(Ok(())) => {
                            let remaining = remaining - read_buf.filled().len();
                            this.state = if remaining == 0 {
                                VlessResponseState::Ready
                            } else {
                                VlessResponseState::Addons(remaining)
                            };
                        }
                    }
                }
                VlessResponseState::Ready => {
                    return this.inner.as_mut().poll_read(cx, buf);
                }
                VlessResponseState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "VLESS response header validation previously failed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for VlessResponseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_shutdown(cx)
    }
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
        self.tls_options.clone().unwrap_or_else(|| TlsOptions {
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
        })
    }

    /// 按 network 类型派发到对应 transport
    async fn dial_transport(&self) -> std::io::Result<BoxedStream> {
        match self.network {
            VlessNetwork::Tcp => {
                if let Some(reality) = &self.reality {
                    RealityTransport::new(reality.clone())?
                        .connect(&self.host, self.port)
                        .await
                } else if self.tls {
                    TlsTransport::new(self.tls_opts())
                        .connect(&self.host, self.port)
                        .await
                } else {
                    TcpTransport::default().connect(&self.host, self.port).await
                }
            }
            VlessNetwork::Ws => {
                if self.reality.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "VLESS REALITY over WebSocket requires a carrier-aware WebSocket transport and is not enabled",
                    ));
                }
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
                if self.reality.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "VLESS REALITY over HTTP obfuscation is not enabled",
                    ));
                }
                let opts = self.http.clone().unwrap_or_default();
                HttpTransport::new(opts, self.tls_opts())
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::H2 => {
                if self.reality.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "VLESS REALITY over H2 requires a carrier-aware H2 transport and is not enabled",
                    ));
                }
                let opts = self.h2.clone().unwrap_or_default();
                H2Transport::new(opts, self.tls_opts())
                    .connect(&self.host, self.port)
                    .await
            }
            VlessNetwork::Grpc => {
                let opts = self.grpc.clone().unwrap_or_default();
                if let Some(reality) = &self.reality {
                    let authority_tls = TlsOptions {
                        sni: Some(reality.config.server_name.clone()),
                        alpn: vec!["h2".into()],
                        ..Default::default()
                    };
                    let grpc = GrpcTransport::new(opts, authority_tls);
                    let carrier = RealityTransport::new(reality.clone())?
                        .connect(&self.host, self.port)
                        .await?;
                    grpc.connect_over(carrier, &self.host, self.port).await
                } else {
                    GrpcTransport::new(opts, self.tls_opts())
                        .connect(&self.host, self.port)
                        .await
                }
            }
            VlessNetwork::Xhttp => {
                if self.reality.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "VLESS REALITY over XHTTP is composed by the full XHTTP branch and is not enabled in this isolated REALITY branch",
                    ));
                }
                let opts = self.xhttp.clone().unwrap_or_default();
                XhttpTransport::new(self.host.clone(), self.port, opts)
                    .connect(&self.host, self.port)
                    .await
            }
        }
    }

    async fn write_request_header(
        &self,
        stream: &mut BoxedStream,
        command: u8,
        ctx: &DialContext,
    ) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(64);
        buffer.put_u8(0x00);
        buffer.extend_from_slice(self.uuid.as_bytes());
        buffer.put_u8(0x00);
        buffer.put_u8(command);
        buffer.put_u16(ctx.port);
        encode_vless_address(&mut buffer, &ctx.host)?;
        stream.write_all(&buffer).await
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
            udp: true,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = self.dial_transport().await?;
        self.write_request_header(&mut stream, 0x01, &ctx).await?;
        Ok(Box::pin(VlessResponseStream::new(stream)))
    }

    async fn dial_udp(&self, ctx: DialContext) -> io::Result<BoxedUdp> {
        let mut stream = self.dial_transport().await?;
        self.write_request_header(&mut stream, 0x02, &ctx).await?;
        let (read, write) = tokio::io::split(VlessResponseStream::new(stream));
        Ok(Box::new(VlessUdp {
            target: ctx.host,
            port: ctx.port,
            read: AsyncMutex::new(read),
            write: AsyncMutex::new(write),
        }))
    }
}

fn encode_vless_address(buffer: &mut Vec<u8>, host: &str) -> io::Result<()> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        buffer.put_u8(0x01);
        buffer.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        buffer.put_u8(0x03);
        buffer.extend_from_slice(&ip.octets());
    } else {
        if host.is_empty() || host.len() > usize::from(u8::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS destination domain must contain 1..=255 bytes",
            ));
        }
        buffer.put_u8(0x02);
        buffer.put_u8(host.len() as u8);
        buffer.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

struct VlessUdp {
    target: String,
    port: u16,
    read: AsyncMutex<ReadHalf<VlessResponseStream>>,
    write: AsyncMutex<WriteHalf<VlessResponseStream>>,
}

#[async_trait]
impl UdpSocketLike for VlessUdp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if port != self.port || !same_udp_target(target, &self.target) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "VLESS UDP command is bound to {}:{}, cannot send to {target}:{port}",
                    self.target, self.port
                ),
            ));
        }
        let length = u16::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP datagram exceeds 65535 bytes",
            )
        })?;
        let mut write = self.write.lock().await;
        write.write_all(&length.to_be_bytes()).await?;
        write.write_all(payload).await?;
        write.flush().await?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let mut read = self.read.lock().await;
        let length = read.read_u16().await? as usize;
        let mut payload = vec![0_u8; length];
        read.read_exact(&mut payload).await?;
        let copied = output.len().min(length);
        output[..copied].copy_from_slice(&payload[..copied]);
        Ok(copied)
    }

    async fn close(&self) -> io::Result<()> {
        self.write.lock().await.shutdown().await
    }
}

fn same_udp_target(left: &str, right: &str) -> bool {
    match (
        left.parse::<std::net::IpAddr>(),
        right.parse::<std::net::IpAddr>(),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.eq_ignore_ascii_case(right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn response_header_is_consumed_lazily_without_blocking_writes() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = VlessResponseStream::new(Box::pin(client));

        stream.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        server
            .write_all(&[0, 2, 0xaa, 0xbb, b'o', b'k'])
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
    }

    #[tokio::test]
    async fn response_header_rejects_unexpected_version() {
        let (client, mut server) = tokio::io::duplex(8);
        let mut stream = VlessResponseStream::new(Box::pin(client));
        server.write_all(&[1, 0]).await.unwrap();

        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("received 1"));
    }

    #[tokio::test]
    async fn response_header_rejects_truncated_addons() {
        let (client, mut server) = tokio::io::duplex(8);
        let mut stream = VlessResponseStream::new(Box::pin(client));
        server.write_all(&[0, 2, 0xaa]).await.unwrap();
        server.shutdown().await.unwrap();

        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn udp_datagrams_are_length_framed_and_response_header_is_lazy() {
        let (client, mut server) = tokio::io::duplex(256);
        let (read, write) =
            tokio::io::split(VlessResponseStream::new(Box::pin(client) as BoxedStream));
        let udp = VlessUdp {
            target: "127.0.0.1".into(),
            port: 53,
            read: AsyncMutex::new(read),
            write: AsyncMutex::new(write),
        };

        let server_task = tokio::spawn(async move {
            server.write_all(&[0, 0]).await.unwrap();
            let length = server.read_u16().await.unwrap() as usize;
            let mut payload = vec![0; length];
            server.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"dns-query");
            server.write_u16(payload.len() as u16).await.unwrap();
            server.write_all(&payload).await.unwrap();
        });

        assert_eq!(udp.send_to(b"dns-query", "127.0.0.1", 53).await.unwrap(), 9);
        let mut response = [0_u8; 32];
        let received = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..received], b"dns-query");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_fixed_destination_rejects_cross_target_and_oversize_datagram() {
        let (client, _server) = tokio::io::duplex(32);
        let (read, write) =
            tokio::io::split(VlessResponseStream::new(Box::pin(client) as BoxedStream));
        let udp = VlessUdp {
            target: "dns.example".into(),
            port: 53,
            read: AsyncMutex::new(read),
            write: AsyncMutex::new(write),
        };
        assert_eq!(
            udp.send_to(b"x", "other.example", 53)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            udp.send_to(&vec![0; usize::from(u16::MAX) + 1], "DNS.EXAMPLE", 53)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
