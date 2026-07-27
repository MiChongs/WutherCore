//! Snell v1-v5 client protocol.
//!
//! The authenticated record layer lives in [`super::snell_codec`]. This module
//! implements the official command header, TCP tunnel acknowledgement, and
//! Snell's non-SOCKS UDP address format used by Mihomo and Surge.

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    proto::snell_codec::{
        MAX_FRAME_LENGTH, SnellReadHalf, SnellReadStatus, SnellStream, SnellVersion, SnellWriteHalf,
    },
    transport::{
        Transport,
        simple_obfs::{SimpleObfsMode, SimpleObfsStream},
        tcp::TcpTransport,
    },
};

const PROTOCOL_VERSION: u8 = 1;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_CONNECT_V2: u8 = 5;
const COMMAND_UDP: u8 = 6;
const COMMAND_UDP_FORWARD: u8 = 1;
const REPLY_TUNNEL: u8 = 0;
const REPLY_PONG: u8 = 1;
const REPLY_ERROR: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnellObfs {
    None,
    Http { host: String },
    Tls { host: String },
}

const REUSE_POOL_SIZE: usize = 10;
const REUSE_POOL_IDLE: Duration = Duration::from_secs(15);

struct PooledSnell {
    stream: SnellStream,
    idle_since: Instant,
}

struct SnellPool {
    streams: Mutex<Vec<PooledSnell>>,
}

impl SnellPool {
    fn new() -> Self {
        Self {
            streams: Mutex::new(Vec::new()),
        }
    }

    async fn take(&self) -> Option<SnellStream> {
        let now = Instant::now();
        let mut streams = self.streams.lock().await;
        streams.retain(|entry| now.duration_since(entry.idle_since) <= REUSE_POOL_IDLE);
        streams.pop().map(|entry| entry.stream)
    }

    fn put(self: &Arc<Self>, stream: SnellStream) {
        let entry = PooledSnell {
            stream,
            idle_since: Instant::now(),
        };
        if let Ok(mut streams) = self.streams.try_lock() {
            if streams.len() < REUSE_POOL_SIZE {
                streams.push(entry);
            }
            return;
        }
        let pool = Arc::clone(self);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut streams = pool.streams.lock().await;
                if streams.len() < REUSE_POOL_SIZE {
                    streams.push(entry);
                }
            });
        }
    }
}

impl fmt::Debug for SnellPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnellPool")
    }
}

#[derive(Debug, Clone)]
pub struct SnellOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: Arc<[u8]>,
    pub version: SnellVersion,
    pub udp: bool,
    pub reuse: bool,
    pub obfs: SnellObfs,
    pool: Arc<SnellPool>,
}

impl SnellOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: &str,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: Arc::from(password.as_bytes()),
            version: SnellVersion::V1,
            udp: false,
            reuse: false,
            obfs: SnellObfs::None,
            pool: Arc::new(SnellPool::new()),
        }
    }

    pub fn with_version(mut self, version: u8) -> Result<Self, String> {
        self.version = SnellVersion::parse(version)?;
        Ok(self)
    }

    pub fn with_udp(mut self, enabled: bool) -> Result<Self, String> {
        if enabled && !self.version.supports_udp() {
            return Err(format!(
                "Snell v{} does not support UDP; use version 3, 4 or 5",
                self.version.number()
            ));
        }
        self.udp = enabled;
        Ok(self)
    }

    pub fn with_reuse(mut self, enabled: bool) -> Result<Self, String> {
        if enabled && !self.version.supports_reuse() {
            return Err(format!(
                "Snell reuse requires version 4 or 5, got v{}",
                self.version.number()
            ));
        }
        self.reuse = enabled;
        Ok(self)
    }

    pub fn with_obfs_http(mut self, host: impl Into<String>) -> Result<Self, String> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err("Snell HTTP obfs host must not be empty".into());
        }
        self.obfs = SnellObfs::Http { host };
        Ok(self)
    }

    pub fn with_obfs_tls(mut self, host: impl Into<String>) -> Result<Self, String> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err("Snell TLS obfs host must not be empty".into());
        }
        self.obfs = SnellObfs::Tls { host };
        Ok(self)
    }

    async fn connect_stream(&self, expect_reply: bool) -> io::Result<SnellStream> {
        let stream = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;
        let stream: BoxedStream = match &self.obfs {
            SnellObfs::None => stream,
            SnellObfs::Http { host } => Box::pin(SimpleObfsStream::client(
                stream,
                SimpleObfsMode::Http {
                    host: host.clone(),
                    port: self.port,
                },
            )),
            SnellObfs::Tls { host } => Box::pin(SimpleObfsStream::client(
                stream,
                SimpleObfsMode::Tls { host: host.clone() },
            )),
        };
        SnellStream::new(stream, self.password.clone(), self.version, expect_reply)
    }

    fn reuse_enabled(&self) -> bool {
        self.version == SnellVersion::V2 || self.reuse
    }

    async fn reusable_stream(&self) -> io::Result<SnellStream> {
        if let Some(stream) = self.pool.take().await {
            Ok(stream)
        } else {
            self.connect_stream(true).await
        }
    }
}

struct ReusableSnellStream {
    stream: Option<SnellStream>,
    pool: Arc<SnellPool>,
    read_ended: bool,
    write_ended: bool,
    reusable: bool,
}

impl ReusableSnellStream {
    fn new(stream: SnellStream, pool: Arc<SnellPool>) -> Self {
        Self {
            stream: Some(stream),
            pool,
            read_ended: false,
            write_ended: false,
            reusable: true,
        }
    }

    fn finish_if_ready(&mut self) {
        if self.reusable && self.read_ended && self.write_ended {
            if let Some(stream) = self.stream.take() {
                self.pool.put(stream);
            }
        }
    }
}

impl Drop for ReusableSnellStream {
    fn drop(&mut self) {
        self.finish_if_ready();
    }
}

impl AsyncRead for ReusableSnellStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_ended {
            return Poll::Ready(Ok(()));
        }
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match stream.poll_session_read(cx, output) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.reusable = false;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(SnellReadStatus::Data)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(SnellReadStatus::End)) => {
                self.read_ended = true;
                self.finish_if_ready();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(SnellReadStatus::TransportEof)) => {
                self.read_ended = true;
                self.reusable = false;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for ReusableSnellStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_ended {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Snell logical stream is half-closed",
            )));
        }
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        Pin::new(stream).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_ended {
            return Poll::Ready(Ok(()));
        }
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match stream.poll_write_end(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.reusable = false;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                self.write_ended = true;
                self.finish_if_ready();
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[async_trait]
impl OutboundAdapter for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "snell"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: self.reuse_enabled(),
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> io::Result<BoxedStream> {
        let reusable = self.reuse_enabled();
        let mut stream = if reusable {
            self.reusable_stream().await?
        } else {
            self.connect_stream(true).await?
        };
        let command = if self.version == SnellVersion::V2 || reusable {
            COMMAND_CONNECT_V2
        } else {
            COMMAND_CONNECT
        };
        let header = encode_tcp_request(command, &ctx.host, ctx.port)?;
        stream.write_frame(&header).await?;
        tracing::info!(
            target: "dial::snell",
            id = ctx.dial_id,
            proxy = %self.name,
            version = self.version.number(),
            reuse = self.reuse,
            server = %format!("{}:{}", self.host, self.port),
            destination = %format!("{}:{}", ctx.host, ctx.port),
            "Snell TCP command sent",
        );
        if reusable {
            Ok(Box::pin(ReusableSnellStream::new(
                stream,
                Arc::clone(&self.pool),
            )))
        } else {
            Ok(Box::pin(stream))
        }
    }

    async fn dial_udp(&self, ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound `{}`/snell UDP disabled by config", self.name),
            ));
        }
        if !self.version.supports_udp() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Snell v{} does not support UDP", self.version.number()),
            ));
        }
        let mut stream = self.connect_stream(self.version.uses_v4_records()).await?;
        stream
            .write_frame(&[PROTOCOL_VERSION, COMMAND_UDP, 0])
            .await?;
        let (read, write) = stream.into_split();
        Ok(Box::new(SnellUdp {
            read: Mutex::new(read),
            write: Mutex::new(write),
            target_host: ctx.host,
            target_port: ctx.port,
        }))
    }
}

fn encode_tcp_request(command: u8, host: &str, port: u16) -> io::Result<Vec<u8>> {
    let host = host.as_bytes();
    let host_length = u8::try_from(host.len())
        .map_err(|_| invalid_input("Snell destination hostname exceeds 255 bytes"))?;
    let mut header = Vec::with_capacity(6 + host.len());
    header.extend_from_slice(&[PROTOCOL_VERSION, command, 0, host_length]);
    header.extend_from_slice(host);
    header.extend_from_slice(&port.to_be_bytes());
    Ok(header)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnellRequest {
    Ping,
    Tcp {
        host: String,
        port: u16,
        reuse: bool,
    },
    Udp,
}

pub fn parse_request_header(frame: &[u8]) -> io::Result<SnellRequest> {
    if frame.len() < 3 || frame[0] != PROTOCOL_VERSION {
        return Err(invalid_data("invalid Snell command header"));
    }
    let command = frame[1];
    let client_id_length = frame[2] as usize;
    let mut offset = 3usize
        .checked_add(client_id_length)
        .ok_or_else(|| invalid_data("Snell client ID length overflow"))?;
    if frame.len() < offset {
        return Err(invalid_data("truncated Snell client ID"));
    }
    match command {
        0 => Ok(SnellRequest::Ping),
        COMMAND_UDP => {
            if frame.len() != offset {
                return Err(invalid_data("Snell UDP header contains trailing bytes"));
            }
            Ok(SnellRequest::Udp)
        }
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let host_length = *frame
                .get(offset)
                .ok_or_else(|| invalid_data("Snell TCP header has no hostname length"))?
                as usize;
            offset += 1;
            if frame.len() != offset + host_length + 2 {
                return Err(invalid_data("truncated or extended Snell TCP header"));
            }
            let host = std::str::from_utf8(&frame[offset..offset + host_length])
                .map_err(|_| invalid_data("Snell destination hostname is not UTF-8"))?
                .to_owned();
            if host.is_empty() {
                return Err(invalid_data("Snell destination hostname is empty"));
            }
            offset += host_length;
            let port = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            if port == 0 {
                return Err(invalid_data("Snell destination port is zero"));
            }
            Ok(SnellRequest::Tcp {
                host,
                port,
                reuse: command == COMMAND_CONNECT_V2,
            })
        }
        command => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported Snell command {command}"),
        )),
    }
}

pub fn tunnel_reply() -> [u8; 1] {
    [REPLY_TUNNEL]
}

pub fn pong_reply() -> [u8; 1] {
    [REPLY_PONG]
}

pub fn error_reply(code: u8, message: &str) -> Vec<u8> {
    let message = message.as_bytes();
    let length = message.len().min(u8::MAX as usize);
    let mut reply = Vec::with_capacity(3 + length);
    reply.extend_from_slice(&[REPLY_ERROR, code, length as u8]);
    reply.extend_from_slice(&message[..length]);
    reply
}

struct SnellUdp {
    read: Mutex<SnellReadHalf>,
    write: Mutex<SnellWriteHalf>,
    target_host: String,
    target_port: u16,
}

#[async_trait]
impl UdpSocketLike for SnellUdp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if target != self.target_host || port != self.target_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Snell UDP association is pinned to {}:{}, got {target}:{port}",
                    self.target_host, self.target_port
                ),
            ));
        }
        let packet = encode_udp_request(target, port, payload)?;
        self.write.lock().await.write_frame(&packet).await?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let frame = self.read.lock().await.read_frame().await?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "Snell UDP stream ended")
        })?;
        let (_, _, payload) = parse_udp_response(&frame)?;
        if payload.len() > output.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Snell UDP response is {} bytes but caller buffer is {} bytes",
                    payload.len(),
                    output.len()
                ),
            ));
        }
        output[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    async fn close(&self) -> io::Result<()> {
        let mut writer = self.write.lock().await;
        writer.write_end().await?;
        writer.shutdown().await
    }
}

pub fn encode_udp_request(host: &str, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(24 + payload.len());
    output.push(COMMAND_UDP_FORWARD);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            output.extend_from_slice(&[0, 4]);
            output.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            output.extend_from_slice(&[0, 6]);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let host = host.as_bytes();
            let length = u8::try_from(host.len())
                .map_err(|_| invalid_input("Snell UDP hostname exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid_input("Snell UDP hostname is empty"));
            }
            output.push(length);
            output.extend_from_slice(host);
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    if output.len() + payload.len() > MAX_FRAME_LENGTH {
        return Err(invalid_input("Snell UDP request exceeds 0x3fff bytes"));
    }
    output.extend_from_slice(payload);
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnellUdpRequest<'a> {
    pub host: String,
    pub port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp_request(packet: &[u8]) -> io::Result<SnellUdpRequest<'_>> {
    if packet.len() < 4 || packet[0] != COMMAND_UDP_FORWARD {
        return Err(invalid_data("invalid Snell UDP request"));
    }
    let address_length = packet[1] as usize;
    if address_length != 0 {
        let address_end = 2 + address_length;
        if packet.len() <= address_end + 2 {
            return Err(invalid_data("truncated Snell UDP domain request"));
        }
        let host = std::str::from_utf8(&packet[2..address_end])
            .map_err(|_| invalid_data("Snell UDP hostname is not UTF-8"))?
            .to_owned();
        let port = u16::from_be_bytes([packet[address_end], packet[address_end + 1]]);
        return Ok(SnellUdpRequest {
            host,
            port,
            payload: &packet[address_end + 2..],
        });
    }
    let family = *packet
        .get(2)
        .ok_or_else(|| invalid_data("Snell UDP IP family is missing"))?;
    let (host, offset) = match family {
        4 if packet.len() >= 9 => (
            Ipv4Addr::new(packet[3], packet[4], packet[5], packet[6]).to_string(),
            7,
        ),
        6 if packet.len() >= 21 => {
            let octets: [u8; 16] = packet[3..19].try_into().expect("checked IPv6 length");
            (Ipv6Addr::from(octets).to_string(), 19)
        }
        4 | 6 => return Err(invalid_data("truncated Snell UDP IP request")),
        _ => return Err(invalid_data("invalid Snell UDP IP family")),
    };
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    Ok(SnellUdpRequest {
        host,
        port,
        payload: &packet[offset + 2..],
    })
}

pub fn encode_udp_response(source: IpAddr, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(19 + payload.len());
    match source {
        IpAddr::V4(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.push(6);
            output.extend_from_slice(&address.octets());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    if output.len() + payload.len() > MAX_FRAME_LENGTH {
        return Err(invalid_input("Snell UDP response exceeds 0x3fff bytes"));
    }
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn parse_udp_response(packet: &[u8]) -> io::Result<(IpAddr, u16, &[u8])> {
    let family = *packet
        .first()
        .ok_or_else(|| invalid_data("empty Snell UDP response"))?;
    match family {
        4 if packet.len() >= 7 => Ok((
            IpAddr::V4(Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4])),
            u16::from_be_bytes([packet[5], packet[6]]),
            &packet[7..],
        )),
        6 if packet.len() >= 19 => {
            let octets: [u8; 16] = packet[1..17].try_into().expect("checked IPv6 length");
            Ok((
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([packet[17], packet[18]]),
                &packet[19..],
            ))
        }
        4 | 6 => Err(invalid_data("truncated Snell UDP response")),
        _ => Err(invalid_data("invalid Snell UDP response IP family")),
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn official_tcp_headers_are_version_one_for_every_generation() {
        assert_eq!(
            encode_tcp_request(COMMAND_CONNECT, "example.com", 443).unwrap(),
            b"\x01\x01\x00\x0bexample.com\x01\xbb"
        );
        assert_eq!(
            encode_tcp_request(COMMAND_CONNECT_V2, "a", 80).unwrap(),
            b"\x01\x05\x00\x01a\x00\x50"
        );
    }

    #[test]
    fn request_parser_accepts_tcp_udp_and_reuse() {
        assert_eq!(
            parse_request_header(b"\x01\x01\x00\x03dns\x00\x35").unwrap(),
            SnellRequest::Tcp {
                host: "dns".into(),
                port: 53,
                reuse: false,
            }
        );
        assert_eq!(
            parse_request_header(b"\x01\x05\x00\x01a\x00\x50").unwrap(),
            SnellRequest::Tcp {
                host: "a".into(),
                port: 80,
                reuse: true,
            }
        );
        assert_eq!(
            parse_request_header(b"\x01\x06\x00").unwrap(),
            SnellRequest::Udp
        );
    }

    #[test]
    fn udp_request_round_trips_domain_ipv4_and_ipv6() {
        for host in ["example.com", "192.0.2.1", "2001:db8::1"] {
            let encoded = encode_udp_request(host, 5353, b"dns").unwrap();
            let decoded = parse_udp_request(&encoded).unwrap();
            assert_eq!(decoded.host, host);
            assert_eq!(decoded.port, 5353);
            assert_eq!(decoded.payload, b"dns");
        }
    }

    #[test]
    fn udp_response_round_trips_both_families() {
        for address in [
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap(),
        ] {
            let encoded = encode_udp_response(address, 53, b"answer").unwrap();
            let (decoded, port, payload) = parse_udp_response(&encoded).unwrap();
            assert_eq!(decoded, address);
            assert_eq!(port, 53);
            assert_eq!(payload, b"answer");
        }
    }

    #[test]
    fn version_capabilities_are_strict() {
        assert!(!SnellVersion::V2.supports_udp());
        assert!(SnellVersion::V3.supports_udp());
        assert!(!SnellVersion::V3.supports_reuse());
        assert!(SnellVersion::V2.supports_reuse());
        assert!(SnellVersion::V4.supports_reuse());
        assert!(SnellVersion::V5.supports_reuse());
    }

    #[tokio::test]
    async fn v2_and_v4_clients_reuse_one_authenticated_transport() {
        for version in [2u8, 4u8] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let accepted_server = Arc::clone(&accepted);
            let server = tokio::spawn(async move {
                let (transport, _) = listener.accept().await.unwrap();
                accepted_server.fetch_add(1, Ordering::SeqCst);
                let version = SnellVersion::parse(version).unwrap();
                let mut stream = SnellStream::new(
                    Box::pin(transport),
                    Arc::from(&b"pool-password"[..]),
                    version,
                    false,
                )
                .unwrap();
                for _ in 0..2 {
                    let header = stream.read_frame().await.unwrap().unwrap();
                    assert!(matches!(
                        parse_request_header(&header).unwrap(),
                        SnellRequest::Tcp { reuse: true, .. }
                    ));
                    stream.write_frame(&tunnel_reply()).await.unwrap();
                    loop {
                        match stream.read_event().await.unwrap() {
                            crate::proto::snell_codec::SnellFrameEvent::Data(frame) => {
                                stream.write_frame(&frame).await.unwrap();
                            }
                            crate::proto::snell_codec::SnellFrameEvent::End => {
                                stream.write_end().await.unwrap();
                                break;
                            }
                            crate::proto::snell_codec::SnellFrameEvent::TransportEof => {
                                panic!("pooled transport closed between logical sessions");
                            }
                        }
                    }
                }
            });

            let outbound = SnellOutbound::new(
                format!("snell-v{version}"),
                address.ip().to_string(),
                address.port(),
                "pool-password",
            )
            .with_version(version)
            .unwrap()
            .with_reuse(version == 4)
            .unwrap();
            for payload in [b"first".as_slice(), b"second".as_slice()] {
                let mut stream = outbound
                    .dial_tcp(DialContext::tcp("target.invalid", 443))
                    .await
                    .unwrap();
                stream.write_all(payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut echoed = vec![0u8; payload.len()];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
                stream.shutdown().await.unwrap();
                let mut eof = [0u8; 1];
                assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
                drop(stream);
            }
            server.await.unwrap();
            assert_eq!(accepted.load(Ordering::SeqCst), 1);
        }
    }
}
