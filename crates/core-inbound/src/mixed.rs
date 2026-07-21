//! Mixed 入站 —— 通过首字节判定 HTTP 还是 SOCKS5。
//!
//! * 首字节 0x05：进入 SOCKS5 协议握手；
//! * 否则按 HTTP 解析；支持 CONNECT 与普通代理（GET/POST 等）。
//!
//! 每个连接：
//! 1. 解析目标 host/port；
//! 2. 交给 [`core_runtime::ListenerHandler`] 做规则路由、出站拨号与连接管理；
//! 3. 双向 splice 转发字节。

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine;
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, Sleep, timeout},
};
use tracing::{debug, info, warn};

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REP_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS_REP_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS_REP_TTL_EXPIRED: u8 = 0x06;
const SOCKS_REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

const SOCKS_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_UDP_ASSOCIATION_IDLE: Duration = Duration::from_secs(5 * 60);
const SOCKS_UDP_SESSION_IDLE: Duration = Duration::from_secs(2 * 60);
const SOCKS_UDP_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const SOCKS_UDP_CLIENT_HINT_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKS_UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const MIXED_MAX_CONNECTIONS: usize = 1024;
const MIXED_MAX_UDP_TARGET_SESSIONS: usize = 4096;
const SOCKS_UDP_MAX_SESSIONS: usize = 256;
const SOCKS_UDP_SESSION_QUEUE: usize = 64;
const SOCKS_UDP_MAX_DATAGRAM: usize = 65_507;
const SOCKS_UDP_MAX_ASSOCIATION_PACKETS: u64 = 1_000_000;
const MIXED_PROTOCOL_DETECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_MAX_HEADER_BYTES: usize = 16 * 1024;
const HTTP_MAX_HEADERS: usize = 128;
const HTTP_READ_CHUNK_BYTES: usize = 2048;

#[derive(Debug, Clone)]
pub struct MixedListener {
    pub listen: SocketAddr,
    pub auth: Option<Vec<core_config::runtime_plan::UserPass>>,
    /// Whether RFC 1928 UDP ASSOCIATE is accepted on the mixed listener.
    pub udp: bool,
}

async fn bind_mixed_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(listen).await
}

pub async fn run_mixed(listener: MixedListener, runtime: Arc<Runtime>) -> io::Result<()> {
    // Host-resource arbitration reserves this exact address. Falling back to a
    // different port would make the reservation and the live socket diverge.
    let l = bind_mixed_listener(listener.listen).await?;
    let bound = l.local_addr()?;
    info!(addr = %bound, "mixed inbound listening");
    serve_mixed(l, listener, runtime).await
}

async fn serve_mixed(
    listener_socket: TcpListener,
    listener: MixedListener,
    runtime: Arc<Runtime>,
) -> io::Result<()> {
    let auth = listener.auth.map(Arc::new);
    let connection_permits = Arc::new(Semaphore::new(MIXED_MAX_CONNECTIONS));
    let udp_session_permits = Arc::new(Semaphore::new(MIXED_MAX_UDP_TARGET_SESSIONS));
    // JoinSet aborts every in-flight connection when this listener future is
    // cancelled or returns. Detached tasks would otherwise keep sockets and
    // runtime state alive after the listener has shut down.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener_socket.accept() => {
                let (sock, peer) = accepted?;
                let _ = sock.set_nodelay(true);
                let permit = match connection_permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(peer = %peer, limit = MIXED_MAX_CONNECTIONS, "mixed inbound connection limit reached");
                        continue;
                    }
                };
                let runtime = runtime.clone();
                let auth = auth.clone();
                let udp = listener.udp;
                let udp_session_permits = udp_session_permits.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle(sock, peer, runtime, auth, udp, udp_session_permits).await {
                        debug!(error = %e, peer = %peer, "mixed handle error");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "mixed connection task failed");
                }
            }
        }
    }
}

async fn handle(
    sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<Arc<Vec<core_config::runtime_plan::UserPass>>>,
    udp_enabled: bool,
    udp_session_permits: Arc<Semaphore>,
) -> io::Result<()> {
    let mut peek = [0u8; 1];
    let n = timeout(MIXED_PROTOCOL_DETECT_TIMEOUT, sock.peek(&mut peek))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "mixed protocol detection timed out",
            )
        })??;
    if n == 0 {
        return Ok(());
    }
    if peek[0] == 0x05 {
        handle_socks5(
            sock,
            peer,
            runtime,
            auth.as_deref().map(|v| v.as_slice()),
            udp_enabled,
            udp_session_permits,
        )
        .await
    } else {
        handle_http(sock, peer, runtime, auth.as_deref().map(|v| v.as_slice())).await
    }
}

/* ---------------- SOCKS5 ---------------- */

async fn handle_socks5(
    mut sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
    udp_enabled: bool,
    udp_session_permits: Arc<Semaphore>,
) -> io::Result<()> {
    negotiate_socks5_auth(&mut sock, auth).await?;

    let request = match read_socks5_request(&mut sock).await {
        Ok(request) => request,
        Err(e) => {
            let _ = send_socks5_reply(&mut sock, e.reply, unspecified_for(peer)).await;
            return Err(e.source);
        }
    };

    match request.command {
        SOCKS_CMD_CONNECT => {
            if request.port == 0 {
                send_socks5_reply(&mut sock, SOCKS_REP_GENERAL_FAILURE, unspecified_for(peer))
                    .await?;
                return Err(invalid_data("SOCKS5 CONNECT target port must not be zero"));
            }
            handle_socks5_connect(sock, peer, runtime, request.address, request.port).await
        }
        SOCKS_CMD_UDP_ASSOCIATE if udp_enabled => {
            handle_socks5_udp_associate(
                sock,
                peer,
                runtime,
                request.address,
                request.port,
                UdpRelayLimits::default(),
                udp_session_permits,
            )
            .await
        }
        SOCKS_CMD_UDP_ASSOCIATE => {
            send_socks5_reply(
                &mut sock,
                SOCKS_REP_COMMAND_NOT_SUPPORTED,
                unspecified_for(peer),
            )
            .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 UDP ASSOCIATE is disabled by listen.local.udp=false",
            ))
        }
        _ => {
            send_socks5_reply(
                &mut sock,
                SOCKS_REP_COMMAND_NOT_SUPPORTED,
                unspecified_for(peer),
            )
            .await?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported SOCKS5 command: 0x{:02x}", request.command),
            ))
        }
    }
}

async fn negotiate_socks5_auth(
    sock: &mut TcpStream,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
) -> io::Result<()> {
    // VER + NMETHODS
    let mut head = [0u8; 2];
    read_control(sock, &mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(invalid_data("invalid SOCKS5 greeting version"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    read_control(sock, &mut methods).await?;

    let need_auth = auth.map(|v| !v.is_empty()).unwrap_or(false);
    let chosen = if need_auth {
        if methods.contains(&0x02) {
            0x02
        } else {
            write_control(sock, &[SOCKS_VERSION, 0xff]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client does not offer username/password authentication",
            ));
        }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        write_control(sock, &[SOCKS_VERSION, 0xff]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 client does not offer no-authentication",
        ));
    };
    write_control(sock, &[SOCKS_VERSION, chosen]).await?;

    if chosen == 0x02 {
        // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
        let mut auth_head = [0u8; 2];
        read_control(sock, &mut auth_head).await?;
        if auth_head[0] != 0x01 || auth_head[1] == 0 {
            write_control(sock, &[0x01, 0x01]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid SOCKS5 username/password sub-negotiation",
            ));
        }
        let mut user = vec![0u8; auth_head[1] as usize];
        read_control(sock, &mut user).await?;
        let mut plen = [0u8; 1];
        read_control(sock, &mut plen).await?;
        if plen[0] == 0 {
            write_control(sock, &[0x01, 0x01]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 password must not be empty",
            ));
        }
        let mut pwd = vec![0u8; plen[0] as usize];
        read_control(sock, &mut pwd).await?;
        let ok = auth
            .map(|v| {
                v.iter()
                    .any(|entry| entry.user.as_bytes() == user && entry.pass.as_bytes() == pwd)
            })
            .unwrap_or(false);
        if !ok {
            write_control(sock, &[0x01, 0x01]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ));
        }
        write_control(sock, &[0x01, 0x00]).await?;
    }
    Ok(())
}

async fn read_socks5_request(sock: &mut TcpStream) -> Result<SocksRequest, SocksRequestError> {
    let mut h = [0u8; 4];
    read_control(sock, &mut h)
        .await
        .map_err(SocksRequestError::general)?;
    if h[0] != SOCKS_VERSION || h[2] != 0 {
        return Err(SocksRequestError::general(invalid_data(
            "invalid SOCKS5 request version or reserved byte",
        )));
    }

    let address = match h[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            read_control(sock, &mut buf)
                .await
                .map_err(SocksRequestError::general)?;
            SocksAddress::Ip(IpAddr::V4(Ipv4Addr::from(buf)))
        }
        0x04 => {
            let mut buf = [0u8; 16];
            read_control(sock, &mut buf)
                .await
                .map_err(SocksRequestError::general)?;
            SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(buf)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_control(sock, &mut len)
                .await
                .map_err(SocksRequestError::general)?;
            if len[0] == 0 {
                return Err(SocksRequestError::address(invalid_data(
                    "SOCKS5 domain must not be empty",
                )));
            }
            let mut buf = vec![0u8; len[0] as usize];
            read_control(sock, &mut buf)
                .await
                .map_err(SocksRequestError::general)?;
            let domain = String::from_utf8(buf).map_err(|_| {
                SocksRequestError::address(invalid_data("SOCKS5 domain is not UTF-8"))
            })?;
            SocksAddress::Domain(normalize_domain(&domain).map_err(SocksRequestError::address)?)
        }
        _ => {
            return Err(SocksRequestError::address(invalid_data(format!(
                "unsupported SOCKS5 address type: 0x{:02x}",
                h[3]
            ))));
        }
    };
    let mut port_buf = [0u8; 2];
    read_control(sock, &mut port_buf)
        .await
        .map_err(SocksRequestError::general)?;
    Ok(SocksRequest {
        command: h[1],
        address,
        port: u16::from_be_bytes(port_buf),
    })
}

async fn handle_socks5_connect(
    mut sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    address: SocksAddress,
    port: u16,
) -> io::Result<()> {
    let handler = ListenerHandler::new(runtime);
    let inbound_addr = sock.local_addr()?;
    let metadata =
        InboundMetadata::tcp("socks5", "Socks5", peer, inbound_addr, address.host(), port);
    match handler.prepare_tcp(metadata).await {
        Ok(prepared) => {
            // The stream abstraction does not expose the outbound socket's local
            // endpoint. Report an address-family-correct unspecified BND rather
            // than falsely identifying the inbound control endpoint as that bind.
            send_socks5_reply(&mut sock, SOCKS_REP_SUCCEEDED, unspecified_for(peer)).await?;
            handler.relay_prepared_tcp(sock, prepared).await
        }
        Err(e) => {
            let reply = socks_reply_for_io_error(&e);
            send_socks5_reply(&mut sock, reply, unspecified_for(peer)).await?;
            Err(e)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SocksAddress {
    Ip(IpAddr),
    Domain(String),
}

impl SocksAddress {
    fn host(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Domain(domain) => domain.clone(),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(IpAddr::V4(ip)) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Self::Ip(IpAddr::V6(ip)) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
            Self::Domain(domain) => {
                let bytes = domain.as_bytes();
                let len = u8::try_from(bytes.len())
                    .map_err(|_| invalid_data("SOCKS5 domain exceeds 255 bytes"))?;
                if len == 0 {
                    return Err(invalid_data("SOCKS5 domain must not be empty"));
                }
                out.push(0x03);
                out.push(len);
                out.extend_from_slice(bytes);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SocksRequest {
    command: u8,
    address: SocksAddress,
    port: u16,
}

#[derive(Debug)]
struct SocksRequestError {
    reply: u8,
    source: io::Error,
}

impl SocksRequestError {
    fn general(source: io::Error) -> Self {
        Self {
            reply: SOCKS_REP_GENERAL_FAILURE,
            source,
        }
    }

    fn address(source: io::Error) -> Self {
        Self {
            reply: SOCKS_REP_ADDRESS_NOT_SUPPORTED,
            source,
        }
    }
}

async fn read_control(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    timeout(SOCKS_CONTROL_IO_TIMEOUT, sock.read_exact(buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 control read timed out"))??;
    Ok(())
}

async fn write_control(sock: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
    timeout(SOCKS_CONTROL_IO_TIMEOUT, sock.write_all(buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 control write timed out"))??;
    Ok(())
}

async fn send_socks5_reply(sock: &mut TcpStream, reply: u8, bound: SocketAddr) -> io::Result<()> {
    let mut frame = Vec::with_capacity(22);
    frame.extend_from_slice(&[SOCKS_VERSION, reply, 0x00]);
    SocksAddress::Ip(bound.ip()).encode(&mut frame)?;
    frame.extend_from_slice(&bound.port().to_be_bytes());
    write_control(sock, &frame).await
}

fn socks_reply_for_io_error(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => SOCKS_REP_NOT_ALLOWED,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotFound => SOCKS_REP_HOST_UNREACHABLE,
        io::ErrorKind::ConnectionRefused => SOCKS_REP_CONNECTION_REFUSED,
        io::ErrorKind::TimedOut => SOCKS_REP_TTL_EXPIRED,
        _ => SOCKS_REP_GENERAL_FAILURE,
    }
}

fn unspecified_for(peer: SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn normalize_domain(domain: &str) -> io::Result<String> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > u8::MAX as usize {
        return Err(invalid_data("invalid SOCKS5 domain length"));
    }
    Ok(normalized)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug, Clone, Copy)]
struct UdpRelayLimits {
    association_idle: Duration,
    session_idle: Duration,
    shutdown_grace: Duration,
    max_sessions: usize,
    session_queue: usize,
    max_datagram: usize,
    max_packets: u64,
}

impl Default for UdpRelayLimits {
    fn default() -> Self {
        Self {
            association_idle: SOCKS_UDP_ASSOCIATION_IDLE,
            session_idle: SOCKS_UDP_SESSION_IDLE,
            shutdown_grace: SOCKS_UDP_SHUTDOWN_GRACE,
            max_sessions: SOCKS_UDP_MAX_SESSIONS,
            session_queue: SOCKS_UDP_SESSION_QUEUE,
            max_datagram: SOCKS_UDP_MAX_DATAGRAM,
            max_packets: SOCKS_UDP_MAX_ASSOCIATION_PACKETS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpTarget {
    address: SocksAddress,
    port: u16,
}

impl UdpTarget {
    fn host(&self) -> String {
        self.address.host()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpHeaderError {
    TooShort,
    ReservedNonZero,
    FragmentationUnsupported(u8),
    AddressTypeUnsupported(u8),
    EmptyDomain,
    InvalidDomain,
    ZeroPort,
    DatagramTooLarge,
}

impl fmt::Display for UdpHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("truncated SOCKS5 UDP datagram"),
            Self::ReservedNonZero => f.write_str("SOCKS5 UDP RSV must be zero"),
            Self::FragmentationUnsupported(fragment) => {
                write!(
                    f,
                    "SOCKS5 UDP fragmentation is unsupported (FRAG={fragment})"
                )
            }
            Self::AddressTypeUnsupported(atyp) => {
                write!(f, "unsupported SOCKS5 UDP ATYP 0x{atyp:02x}")
            }
            Self::EmptyDomain => f.write_str("SOCKS5 UDP domain must not be empty"),
            Self::InvalidDomain => f.write_str("SOCKS5 UDP domain is not valid UTF-8"),
            Self::ZeroPort => f.write_str("SOCKS5 UDP target port must not be zero"),
            Self::DatagramTooLarge => f.write_str("SOCKS5 UDP datagram exceeds relay limit"),
        }
    }
}

#[derive(Debug)]
struct ParsedUdpDatagram<'a> {
    target: UdpTarget,
    payload: &'a [u8],
}

fn parse_socks5_udp_datagram(packet: &[u8]) -> Result<ParsedUdpDatagram<'_>, UdpHeaderError> {
    if packet.len() < 4 {
        return Err(UdpHeaderError::TooShort);
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(UdpHeaderError::ReservedNonZero);
    }
    if packet[2] != 0 {
        return Err(UdpHeaderError::FragmentationUnsupported(packet[2]));
    }

    let mut cursor = 4usize;
    let address = match packet[3] {
        0x01 => {
            let end = cursor
                .checked_add(4)
                .filter(|end| *end <= packet.len())
                .ok_or(UdpHeaderError::TooShort)?;
            let octets: [u8; 4] = packet[cursor..end]
                .try_into()
                .map_err(|_| UdpHeaderError::TooShort)?;
            cursor = end;
            SocksAddress::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        0x04 => {
            let end = cursor
                .checked_add(16)
                .filter(|end| *end <= packet.len())
                .ok_or(UdpHeaderError::TooShort)?;
            let octets: [u8; 16] = packet[cursor..end]
                .try_into()
                .map_err(|_| UdpHeaderError::TooShort)?;
            cursor = end;
            SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        0x03 => {
            let len = *packet.get(cursor).ok_or(UdpHeaderError::TooShort)? as usize;
            cursor += 1;
            if len == 0 {
                return Err(UdpHeaderError::EmptyDomain);
            }
            let end = cursor
                .checked_add(len)
                .filter(|end| *end <= packet.len())
                .ok_or(UdpHeaderError::TooShort)?;
            let domain = std::str::from_utf8(&packet[cursor..end])
                .map_err(|_| UdpHeaderError::InvalidDomain)?;
            let domain = normalize_domain(domain).map_err(|_| UdpHeaderError::EmptyDomain)?;
            cursor = end;
            SocksAddress::Domain(domain)
        }
        atyp => return Err(UdpHeaderError::AddressTypeUnsupported(atyp)),
    };

    let port_end = cursor
        .checked_add(2)
        .filter(|end| *end <= packet.len())
        .ok_or(UdpHeaderError::TooShort)?;
    let port = u16::from_be_bytes(
        packet[cursor..port_end]
            .try_into()
            .map_err(|_| UdpHeaderError::TooShort)?,
    );
    if port == 0 {
        return Err(UdpHeaderError::ZeroPort);
    }

    Ok(ParsedUdpDatagram {
        target: UdpTarget { address, port },
        payload: &packet[port_end..],
    })
}

fn encode_socks5_udp_datagram(
    target: &UdpTarget,
    payload: &[u8],
    max_datagram: usize,
) -> Result<Vec<u8>, UdpHeaderError> {
    let mut packet = Vec::with_capacity(22usize.saturating_add(payload.len()));
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    target
        .address
        .encode(&mut packet)
        .map_err(|_| UdpHeaderError::InvalidDomain)?;
    packet.extend_from_slice(&target.port.to_be_bytes());
    if packet.len().saturating_add(payload.len()) > max_datagram {
        return Err(UdpHeaderError::DatagramTooLarge);
    }
    packet.extend_from_slice(payload);
    Ok(packet)
}

#[derive(Debug)]
struct UdpClientPin {
    ip: IpAddr,
    requested_port: Option<u16>,
    endpoint: Option<SocketAddr>,
}

impl UdpClientPin {
    fn accept(&mut self, source: SocketAddr) -> bool {
        if let Some(endpoint) = self.endpoint {
            return endpoint == source;
        }
        if !same_ip(self.ip, source.ip()) {
            return false;
        }
        if self
            .requested_port
            .is_some_and(|port| port != source.port())
        {
            return false;
        }
        // Preserve IPv6 flow/scope information from the actual UDP datagram.
        self.endpoint = Some(source);
        true
    }

    fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }
}

async fn client_pin_from_request(
    address: &SocksAddress,
    port: u16,
    peer: SocketAddr,
) -> io::Result<UdpClientPin> {
    let address_matches = match address {
        SocksAddress::Ip(ip) if ip.is_unspecified() => true,
        SocksAddress::Ip(ip) => same_ip(*ip, peer.ip()),
        SocksAddress::Domain(domain) => {
            let lookup = timeout(
                SOCKS_UDP_CLIENT_HINT_TIMEOUT,
                tokio::net::lookup_host((domain.as_str(), port.max(1))),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS5 UDP client-address lookup timed out",
                )
            })??;
            lookup.into_iter().any(|addr| same_ip(addr.ip(), peer.ip()))
        }
    };
    if !address_matches {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "SOCKS5 UDP client address {} does not match TCP peer {}",
                address.host(),
                peer.ip()
            ),
        ));
    }
    Ok(UdpClientPin {
        ip: peer.ip(),
        requested_port: (port != 0).then_some(port),
        endpoint: None,
    })
}

fn same_ip(left: IpAddr, right: IpAddr) -> bool {
    fn canonical(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        }
    }
    canonical(left) == canonical(right)
}

fn udp_bind_addr(peer: SocketAddr, control_local: SocketAddr) -> SocketAddr {
    let mut address = match (peer.ip(), control_local.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => control_local,
        (IpAddr::V4(_), _) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (IpAddr::V6(_), _) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    address.set_port(0);
    address
}

fn advertised_udp_addr(
    relay_local: SocketAddr,
    control_local: SocketAddr,
    peer: SocketAddr,
) -> SocketAddr {
    if !relay_local.ip().is_unspecified() {
        return relay_local;
    }
    let control_matches_family = peer.is_ipv4() == control_local.is_ipv4();
    if control_matches_family && !control_local.ip().is_unspecified() {
        let mut advertised = control_local;
        advertised.set_port(relay_local.port());
        advertised
    } else {
        relay_local
    }
}

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    client_address: SocksAddress,
    client_port: u16,
    limits: UdpRelayLimits,
    udp_session_permits: Arc<Semaphore>,
) -> io::Result<()> {
    let control_local = control.local_addr()?;
    let mut client_pin = match client_pin_from_request(&client_address, client_port, peer).await {
        Ok(pin) => pin,
        Err(error) => {
            send_socks5_reply(&mut control, SOCKS_REP_NOT_ALLOWED, unspecified_for(peer)).await?;
            return Err(error);
        }
    };

    let relay = match UdpSocket::bind(udp_bind_addr(peer, control_local)).await {
        Ok(relay) => Arc::new(relay),
        Err(error) => {
            send_socks5_reply(
                &mut control,
                socks_reply_for_io_error(&error),
                unspecified_for(peer),
            )
            .await?;
            return Err(error);
        }
    };
    let relay_local = relay.local_addr()?;
    let advertised = advertised_udp_addr(relay_local, control_local, peer);
    send_socks5_reply(&mut control, SOCKS_REP_SUCCEEDED, advertised).await?;

    debug!(
        peer = %peer,
        relay = %advertised,
        client_port,
        "SOCKS5 UDP association established"
    );

    let handler = ListenerHandler::new(runtime);
    let (shutdown_tx, _) = watch::channel(false);
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let mut sessions = HashMap::<UdpTarget, UdpTargetSession>::new();
    let mut next_session_id = 1u64;
    let mut accepted_packets = 0u64;
    let mut recv_buf = vec![0u8; limits.max_datagram.saturating_add(1)];
    let mut control_buf = [0u8; 1024];
    let mut association_idle = Box::pin(tokio::time::sleep(limits.association_idle));
    let mut terminal_error = None;

    loop {
        tokio::select! {
            control_result = control.read(&mut control_buf) => {
                match control_result {
                    Ok(0) => break,
                    Ok(_) => {
                        // RFC 1928 keeps this TCP connection solely as association
                        // lifetime. Extra control bytes carry no protocol meaning.
                    }
                    Err(error) => {
                        terminal_error = Some(error);
                        break;
                    }
                }
            }
            datagram = relay.recv_from(&mut recv_buf) => {
                let (size, source) = match datagram {
                    Ok(value) => value,
                    Err(error) => {
                        terminal_error = Some(error);
                        break;
                    }
                };
                if size > limits.max_datagram {
                    debug!(peer = %source, size, "drop oversized SOCKS5 UDP datagram");
                    continue;
                }
                let parsed = match parse_socks5_udp_datagram(&recv_buf[..size]) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        debug!(peer = %source, error = %error, "drop malformed SOCKS5 UDP datagram");
                        continue;
                    }
                };
                if !client_pin.accept(source) {
                    debug!(peer = %source, tcp_peer = %peer, "drop SOCKS5 UDP datagram from non-associated client");
                    continue;
                }
                let Some(client_endpoint) = client_pin.endpoint() else {
                    continue;
                };
                accepted_packets = accepted_packets.saturating_add(1);
                if accepted_packets > limits.max_packets {
                    terminal_error = Some(io::Error::new(
                        io::ErrorKind::QuotaExceeded,
                        "SOCKS5 UDP association packet limit exceeded",
                    ));
                    break;
                }
                association_idle
                    .as_mut()
                    .reset(Instant::now() + limits.association_idle);

                let target = parsed.target;
                let payload = parsed.payload.to_vec();
                let existing = sessions
                    .get(&target)
                    .map(|entry| (entry.id, entry.tx.clone()));
                if let Some((id, tx)) = existing {
                    match tx.try_send(payload) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            debug!(target = %target.address.host(), port = target.port, "drop SOCKS5 UDP packet: target queue full");
                        }
                        Err(mpsc::error::TrySendError::Closed(payload)) => {
                            if sessions.get(&target).is_some_and(|entry| entry.id == id) {
                                sessions.remove(&target);
                            }
                            if sessions.len() < limits.max_sessions {
                                let entry = spawn_udp_target_session(
                                    next_session_id,
                                    target.clone(),
                                    payload,
                                    client_endpoint,
                                    relay.clone(),
                                    relay_local,
                                    handler.clone(),
                                    shutdown_tx.subscribe(),
                                    done_tx.clone(),
                                    limits,
                                    udp_session_permits.clone(),
                                );
                                if let Some(entry) = entry {
                                    sessions.insert(target, entry);
                                    next_session_id = next_session_id.wrapping_add(1).max(1);
                                }
                            }
                        }
                    }
                } else if sessions.len() >= limits.max_sessions {
                    debug!(target = %target.address.host(), port = target.port, "drop SOCKS5 UDP packet: session limit reached");
                } else {
                    let entry = spawn_udp_target_session(
                        next_session_id,
                        target.clone(),
                        payload,
                        client_endpoint,
                        relay.clone(),
                        relay_local,
                        handler.clone(),
                        shutdown_tx.subscribe(),
                        done_tx.clone(),
                        limits,
                        udp_session_permits.clone(),
                    );
                    if let Some(entry) = entry {
                        sessions.insert(target, entry);
                        next_session_id = next_session_id.wrapping_add(1).max(1);
                    }
                }
            }
            Some(done) = done_rx.recv() => {
                if sessions
                    .get(&done.target)
                    .is_some_and(|entry| entry.id == done.id)
                {
                    sessions.remove(&done.target);
                }
            }
            _ = &mut association_idle => {
                debug!(peer = %peer, "SOCKS5 UDP association idle timeout");
                break;
            }
        }
    }

    shutdown_udp_sessions(sessions, shutdown_tx, limits.shutdown_grace).await;
    debug!(peer = %peer, "SOCKS5 UDP association closed");
    terminal_error.map_or(Ok(()), Err)
}

struct UdpTargetSession {
    id: u64,
    tx: mpsc::Sender<Vec<u8>>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
struct UdpTargetDone {
    id: u64,
    target: UdpTarget,
}

struct UdpTargetDoneGuard {
    id: u64,
    target: UdpTarget,
    sender: mpsc::UnboundedSender<UdpTargetDone>,
}

impl Drop for UdpTargetDoneGuard {
    fn drop(&mut self) {
        let _ = self.sender.send(UdpTargetDone {
            id: self.id,
            target: self.target.clone(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_udp_target_session(
    id: u64,
    target: UdpTarget,
    first_payload: Vec<u8>,
    client_endpoint: SocketAddr,
    relay: Arc<UdpSocket>,
    relay_local: SocketAddr,
    handler: ListenerHandler,
    shutdown: watch::Receiver<bool>,
    done: mpsc::UnboundedSender<UdpTargetDone>,
    limits: UdpRelayLimits,
    session_permits: Arc<Semaphore>,
) -> Option<UdpTargetSession> {
    let permit = match session_permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            debug!(
                limit = MIXED_MAX_UDP_TARGET_SESSIONS,
                "drop SOCKS5 UDP packet: global target-session limit reached"
            );
            return None;
        }
    };
    let (tx, rx) = mpsc::channel(limits.session_queue);
    // A newly-created bounded channel always has room for its first packet.
    let _ = tx.try_send(first_payload);
    let worker_target = target.clone();
    let handle = tokio::spawn(async move {
        let _permit = permit;
        run_udp_target_session(
            id,
            worker_target,
            client_endpoint,
            relay,
            relay_local,
            handler,
            rx,
            shutdown,
            done,
            limits,
        )
        .await;
    });
    Some(UdpTargetSession { id, tx, handle })
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_target_session(
    id: u64,
    target: UdpTarget,
    client_endpoint: SocketAddr,
    relay: Arc<UdpSocket>,
    relay_local: SocketAddr,
    handler: ListenerHandler,
    mut packets: mpsc::Receiver<Vec<u8>>,
    mut shutdown: watch::Receiver<bool>,
    done: mpsc::UnboundedSender<UdpTargetDone>,
    limits: UdpRelayLimits,
) {
    let _done = UdpTargetDoneGuard {
        id,
        target: target.clone(),
        sender: done,
    };
    if *shutdown.borrow() {
        return;
    }

    let metadata = InboundMetadata::udp(
        "socks5",
        "Socks5",
        client_endpoint,
        Some(relay_local),
        target.host(),
        target.port,
    );
    let prepared = tokio::select! {
        _ = shutdown.changed() => return,
        result = timeout(SOCKS_UDP_DIAL_TIMEOUT, handler.new_packet(metadata)) => {
            match result {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(error)) => {
                    debug!(target = %target.address.host(), port = target.port, error = %error, "SOCKS5 UDP target dial failed");
                    return;
                }
                Err(_) => {
                    debug!(target = %target.address.host(), port = target.port, "SOCKS5 UDP target dial timed out");
                    return;
                }
            }
        }
    };

    let mut recv_buf = vec![0u8; limits.max_datagram.saturating_add(1)];
    let mut idle: std::pin::Pin<Box<Sleep>> = Box::pin(tokio::time::sleep(limits.session_idle));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                match prepared
                    .socket
                    .send_to(&packet, &prepared.target_host, prepared.target_port)
                    .await
                {
                    Ok(size) => {
                        handler.record_upload(&prepared.guard, size as u64);
                        idle.as_mut().reset(Instant::now() + limits.session_idle);
                    }
                    Err(error) => {
                        debug!(target = %target.address.host(), port = target.port, error = %error, "SOCKS5 UDP target send failed");
                        break;
                    }
                }
            }
            result = prepared.socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok(size) if size <= limits.max_datagram => {
                        let response = match encode_socks5_udp_datagram(
                            &target,
                            &recv_buf[..size],
                            limits.max_datagram,
                        ) {
                            Ok(response) => response,
                            Err(error) => {
                                debug!(target = %target.address.host(), port = target.port, error = %error, "drop oversized SOCKS5 UDP response");
                                continue;
                            }
                        };
                        match relay.send_to(&response, client_endpoint).await {
                            Ok(_) => {
                                handler.record_download(&prepared.guard, size as u64);
                                idle.as_mut().reset(Instant::now() + limits.session_idle);
                            }
                            Err(error) => {
                                debug!(peer = %client_endpoint, error = %error, "SOCKS5 UDP client send failed");
                                break;
                            }
                        }
                    }
                    Ok(size) => {
                        debug!(target = %target.address.host(), port = target.port, size, "drop oversized outbound UDP response");
                    }
                    Err(error) => {
                        debug!(target = %target.address.host(), port = target.port, error = %error, "SOCKS5 UDP target receive failed");
                        break;
                    }
                }
            }
            _ = &mut idle => break,
        }
    }

    if timeout(limits.shutdown_grace, prepared.socket.close())
        .await
        .is_err()
    {
        warn!(
            target = %target.address.host(),
            port = target.port,
            "SOCKS5 UDP target close timed out"
        );
    }
}

async fn shutdown_udp_sessions(
    mut sessions: HashMap<UdpTarget, UdpTargetSession>,
    shutdown: watch::Sender<bool>,
    grace: Duration,
) {
    let _ = shutdown.send(true);
    let deadline = Instant::now() + grace;
    for (_, mut entry) in sessions.drain() {
        if tokio::time::timeout_at(deadline, &mut entry.handle)
            .await
            .is_err()
        {
            entry.handle.abort();
            let _ = entry.handle.await;
        }
    }
}

/* ---------------- HTTP ---------------- */

async fn handle_http(
    mut sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
) -> io::Result<()> {
    let (head, prefetched) = match read_http_head(&mut sock, HTTP_HEADER_TIMEOUT).await {
        Ok(value) => value,
        Err(error) => {
            let response = if error.kind() == io::ErrorKind::TimedOut {
                b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    .as_slice()
            } else if error.kind() == io::ErrorKind::InvalidData {
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    .as_slice()
            } else {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    .as_slice()
            };
            let _ = write_http_control(&mut sock, response).await;
            return Err(error);
        }
    };
    let request = match parse_http_request_head(&head) {
        Ok(request) => request,
        Err(error) => {
            let _ = write_http_control(
                &mut sock,
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return Err(error);
        }
    };
    if !http_proxy_authenticated(&request, auth) {
        let _ = write_http_control(
            &mut sock,
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"RPKernel\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP proxy authentication failed",
        ));
    }
    let route = match parse_http_route(&request) {
        Ok(route) => route,
        Err(error) => {
            let _ = write_http_control(
                &mut sock,
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return Err(error);
        }
    };

    let handler = ListenerHandler::new(runtime);
    let inbound_addr = sock.local_addr()?;
    match route {
        HttpRoute::Connect(authority) => {
            let metadata = InboundMetadata::tcp(
                "http-connect",
                "HTTP",
                peer,
                inbound_addr,
                authority.host,
                authority.port,
            );
            match handler.prepare_tcp(metadata).await {
                Ok(mut prepared) => {
                    write_http_control(&mut sock, b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    if !prefetched.is_empty() {
                        prepared.result.stream.write_all(&prefetched).await?;
                        handler.record_upload(&prepared.guard, prefetched.len() as u64);
                    }
                    handler.relay_prepared_tcp(sock, prepared).await
                }
                Err(error) => {
                    let _ = write_http_control(
                        &mut sock,
                        b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
                    Err(error)
                }
            }
        }
        HttpRoute::Forward(target) => {
            let body_framing = match request.forward_body_framing() {
                Ok(framing) => framing,
                Err(error) => {
                    let response = if error.kind() == io::ErrorKind::Unsupported {
                        b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                            .as_slice()
                    } else {
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                            .as_slice()
                    };
                    let _ = write_http_control(&mut sock, response).await;
                    return Err(error);
                }
            };
            if let Err(error) = body_framing.validate_prefetched(&prefetched) {
                let _ = write_http_control(
                    &mut sock,
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
                return Err(error);
            }
            let forwarded_head = build_forward_head(&request, &target);
            let metadata = InboundMetadata::tcp(
                "http",
                "HTTP",
                peer,
                inbound_addr,
                target.authority.host.clone(),
                target.authority.port,
            );
            match handler.prepare_tcp(metadata).await {
                Ok(mut prepared) => {
                    if let Err(error) = prepared.result.stream.write_all(&forwarded_head).await {
                        let _ = write_http_control(
                            &mut sock,
                            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                        return Err(error);
                    }
                    handler.record_upload(&prepared.guard, forwarded_head.len() as u64);
                    let request_stream = HttpSingleRequestStream::new(
                        sock,
                        prefetched,
                        body_framing,
                        HTTP_BODY_IDLE_TIMEOUT,
                    )?;
                    handler.relay_prepared_tcp(request_stream, prepared).await
                }
                Err(error) => {
                    let _ = write_http_control(
                        &mut sock,
                        b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
                    Err(error)
                }
            }
        }
    }
}

#[derive(Debug)]
struct HttpRequestHead {
    method: String,
    target: String,
    version: String,
    headers: Vec<HttpHeader>,
}

#[derive(Debug)]
struct HttpHeader {
    name: String,
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthority {
    host: String,
    port: u16,
    host_header: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ForwardTarget {
    authority: ParsedAuthority,
    origin_form: String,
}

#[derive(Debug, PartialEq, Eq)]
enum HttpRoute {
    Connect(ParsedAuthority),
    Forward(ForwardTarget),
}

async fn read_http_head<R>(sock: &mut R, header_timeout: Duration) -> io::Result<(Vec<u8>, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    timeout(header_timeout, read_http_head_inner(sock))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request header timed out"))?
}

async fn read_http_head_inner<R>(sock: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut received = Vec::with_capacity(HTTP_READ_CHUNK_BYTES);
    let mut chunk = [0u8; HTTP_READ_CHUNK_BYTES];
    loop {
        let size = sock.read(&mut chunk).await?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP request header completed",
            ));
        }
        received.extend_from_slice(&chunk[..size]);
        if let Some(start) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = start + 4;
            if end > HTTP_MAX_HEADER_BYTES {
                return Err(invalid_data("HTTP request header exceeds 16 KiB"));
            }
            let prefetched = received.split_off(end);
            return Ok((received, prefetched));
        }
        if received.len() >= HTTP_MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP request header exceeds 16 KiB"));
        }
    }
}

fn parse_http_request_head(head: &[u8]) -> io::Result<HttpRequestHead> {
    if !head.ends_with(b"\r\n\r\n") {
        return Err(invalid_data("incomplete HTTP request header"));
    }
    let block = &head[..head.len() - 4];
    let mut raw_lines = block.split(|byte| *byte == b'\n').peekable();
    let request_line = raw_lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let request_line = strip_line_cr(request_line, raw_lines.peek().is_some())?;
    let request_line = std::str::from_utf8(request_line)
        .map_err(|_| invalid_data("HTTP request line is not UTF-8"))?;
    if !request_line.is_ascii() {
        return Err(invalid_data("HTTP request line must be ASCII"));
    }
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let target = parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;
    if parts.next().is_some()
        || method.is_empty()
        || !method.as_bytes().iter().copied().all(is_http_token_byte)
        || target.is_empty()
        || target.as_bytes().iter().any(u8::is_ascii_control)
    {
        return Err(invalid_data("malformed HTTP request line"));
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data("unsupported HTTP version"));
    }

    let mut headers = Vec::new();
    let mut host_seen = false;
    let mut proxy_authorization_seen = false;
    let mut content_length_seen = false;
    let mut transfer_encoding_seen = false;
    while let Some(raw_line) = raw_lines.next() {
        if headers.len() >= HTTP_MAX_HEADERS {
            return Err(invalid_data("too many HTTP request headers"));
        }
        let line = strip_line_cr(raw_line, raw_lines.peek().is_some())?;
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(invalid_data("empty or folded HTTP header field"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid_data("HTTP header field is missing ':'"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_http_token_byte) {
            return Err(invalid_data("invalid HTTP header field name"));
        }
        let value = trim_http_ows(&line[colon + 1..]);
        if value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(invalid_data("invalid control byte in HTTP header value"));
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| invalid_data("HTTP header field name must be ASCII"))?
            .to_string();

        if name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err(invalid_data("duplicate Host header"));
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case("proxy-authorization") {
            if proxy_authorization_seen {
                return Err(invalid_data("duplicate Proxy-Authorization header"));
            }
            proxy_authorization_seen = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length_seen || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(invalid_data("invalid or duplicate Content-Length header"));
            }
            content_length_seen = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding_seen || value.is_empty() {
                return Err(invalid_data(
                    "invalid or duplicate Transfer-Encoding header",
                ));
            }
            transfer_encoding_seen = true;
        } else if name.eq_ignore_ascii_case("connection")
            && (value.is_empty()
                || value.split(|byte| *byte == b',').any(|option| {
                    let option = trim_http_ows(option);
                    option.is_empty() || !option.iter().copied().all(is_http_token_byte)
                }))
        {
            return Err(invalid_data("invalid Connection header options"));
        }
        headers.push(HttpHeader {
            name,
            value: value.to_vec(),
        });
    }
    if content_length_seen && transfer_encoding_seen {
        return Err(invalid_data(
            "request must not contain both Transfer-Encoding and Content-Length",
        ));
    }

    Ok(HttpRequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
    })
}

fn strip_line_cr(line: &[u8], followed_by_lf: bool) -> io::Result<&[u8]> {
    match (line.strip_suffix(b"\r"), followed_by_lf) {
        (Some(line), true) if !line.contains(&b'\r') => Ok(line),
        (None, true) => Err(invalid_data("HTTP header uses a bare line feed")),
        (_, true) => Err(invalid_data("invalid carriage return in HTTP line")),
        (_, false) if line.contains(&b'\r') => {
            Err(invalid_data("invalid carriage return in HTTP line"))
        }
        (_, false) => Ok(line),
    }
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_http_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_http_route(request: &HttpRequestHead) -> io::Result<HttpRoute> {
    let host_header = request.header("host");
    if request.version == "HTTP/1.1" && host_header.is_none() {
        return Err(invalid_data("HTTP/1.1 request is missing Host header"));
    }
    if let Some(value) = host_header {
        let value =
            std::str::from_utf8(value).map_err(|_| invalid_data("Host header must be ASCII"))?;
        // Validate even when absolute-form supplies the routing authority. This
        // prevents malformed or ambiguous Host values from crossing the proxy.
        parse_authority(value, Some(80), false)?;
    }

    if request.method == "CONNECT" {
        return Ok(HttpRoute::Connect(parse_authority(
            &request.target,
            None,
            true,
        )?));
    }
    if request.target.contains('#') {
        return Err(invalid_data(
            "HTTP request target must not contain a fragment",
        ));
    }
    if request.target.starts_with('/') || request.target == "*" {
        if request.target == "*" && request.method != "OPTIONS" {
            return Err(invalid_data(
                "asterisk-form request target is only valid for OPTIONS",
            ));
        }
        let host = host_header.ok_or_else(|| {
            invalid_data("origin-form HTTP request requires a Host header for routing")
        })?;
        let host =
            std::str::from_utf8(host).map_err(|_| invalid_data("Host header must be ASCII"))?;
        return Ok(HttpRoute::Forward(ForwardTarget {
            authority: parse_authority(host, Some(80), false)?,
            origin_form: request.target.clone(),
        }));
    }
    Ok(HttpRoute::Forward(parse_absolute_target(&request.target)?))
}

impl HttpRequestHead {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_slice())
    }

    fn forward_body_framing(&self) -> io::Result<HttpBodyFraming> {
        for framing_field in ["host", "content-length", "transfer-encoding", "trailer"] {
            if self.connection_option(framing_field) {
                return Err(invalid_data(
                    "Connection header must not nominate routing or framing fields",
                ));
            }
        }
        if self.header("upgrade").is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTP Upgrade is only supported through CONNECT tunnelling",
            ));
        }
        if let Some(value) = self.header("transfer-encoding") {
            if self.version != "HTTP/1.1" {
                return Err(invalid_data(
                    "Transfer-Encoding is not valid on an HTTP/1.0 request",
                ));
            }
            let value = std::str::from_utf8(value)
                .map_err(|_| invalid_data("Transfer-Encoding must be ASCII"))?;
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "only a single chunked transfer coding is supported",
                ));
            }
            for trailer in self
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("trailer"))
            {
                validate_http_trailer_declaration(&trailer.value)?;
            }
            return Ok(HttpBodyFraming::chunked());
        }
        if self.header("trailer").is_some() {
            return Err(invalid_data(
                "Trailer header requires chunked Transfer-Encoding",
            ));
        }
        let Some(value) = self.header("content-length") else {
            return Ok(HttpBodyFraming::fixed(0));
        };
        let value =
            std::str::from_utf8(value).map_err(|_| invalid_data("Content-Length must be ASCII"))?;
        let length = value
            .parse::<u64>()
            .map_err(|_| invalid_data("Content-Length exceeds the supported range"))?;
        Ok(HttpBodyFraming::fixed(length))
    }

    fn connection_option(&self, name: &str) -> bool {
        self.headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("connection"))
            .flat_map(|header| header.value.split(|byte| *byte == b','))
            .map(trim_http_ows)
            .any(|option| option.eq_ignore_ascii_case(name.as_bytes()))
    }
}

fn parse_absolute_target(target: &str) -> io::Result<ForwardTarget> {
    let scheme_end = target.find("://").ok_or_else(|| {
        invalid_data("non-CONNECT proxy request requires absolute- or origin-form")
    })?;
    let scheme = &target[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only http:// absolute-form requests are supported; HTTPS must use CONNECT",
        ));
    }
    let remainder = &target[scheme_end + 3..];
    let authority_end = remainder
        .char_indices()
        .find_map(|(index, ch)| matches!(ch, '/' | '?' | '#').then_some(index))
        .unwrap_or(remainder.len());
    let authority = parse_authority(&remainder[..authority_end], Some(80), false)?;
    let suffix = &remainder[authority_end..];
    if suffix.contains('#') {
        return Err(invalid_data(
            "absolute-form URI must not contain a fragment",
        ));
    }
    let origin_form = if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else if suffix.starts_with('/') {
        suffix.to_string()
    } else {
        return Err(invalid_data("malformed absolute-form request target"));
    };
    Ok(ForwardTarget {
        authority,
        origin_form,
    })
}

fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
    require_port: bool,
) -> io::Result<ParsedAuthority> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || authority.contains(['@', '/', '?', '#'])
    {
        return Err(invalid_data("invalid HTTP authority"));
    }

    let (raw_host, raw_port, ipv6) = if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest
            .find(']')
            .ok_or_else(|| invalid_data("unterminated IPv6 address in HTTP authority"))?;
        let raw_host = &rest[..closing];
        let after = &rest[closing + 1..];
        let raw_port = if after.is_empty() {
            None
        } else {
            Some(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| invalid_data("invalid text after IPv6 address"))?,
            )
        };
        if raw_host.parse::<Ipv6Addr>().is_err() {
            return Err(invalid_data("invalid IPv6 address in HTTP authority"));
        }
        (raw_host, raw_port, true)
    } else {
        if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
            return Err(invalid_data("IPv6 HTTP authority must use square brackets"));
        }
        let (raw_host, raw_port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        (raw_host, raw_port, false)
    };
    if raw_host.is_empty() {
        return Err(invalid_data("HTTP authority host is empty"));
    }

    let explicit_port = raw_port.is_some();
    let port = match raw_port {
        Some(raw_port) if !raw_port.is_empty() => raw_port
            .parse::<u16>()
            .map_err(|_| invalid_data("invalid HTTP authority port"))?,
        Some(_) => return Err(invalid_data("HTTP authority port is empty")),
        None if require_port => {
            return Err(invalid_data("CONNECT authority must include a port"));
        }
        None => default_port.ok_or_else(|| invalid_data("HTTP authority is missing a port"))?,
    };
    if port == 0 {
        return Err(invalid_data("HTTP authority port must not be zero"));
    }

    let host = if ipv6 {
        raw_host
            .parse::<Ipv6Addr>()
            .expect("IPv6 address was validated")
            .to_string()
    } else if let Ok(ip) = raw_host.parse::<Ipv4Addr>() {
        ip.to_string()
    } else {
        normalize_http_domain(raw_host)?
    };
    let host_literal = if ipv6 {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let host_header = if explicit_port {
        format!("{host_literal}:{port}")
    } else {
        host_literal
    };
    Ok(ParsedAuthority {
        host,
        port,
        host_header,
    })
}

fn normalize_http_domain(host: &str) -> io::Result<String> {
    if !host.is_ascii()
        || host.len() > 253
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')))
    {
        return Err(invalid_data("invalid HTTP authority host"));
    }
    let without_root_dot = host.strip_suffix('.').unwrap_or(host);
    if without_root_dot.is_empty()
        || without_root_dot
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        || (without_root_dot
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
            && without_root_dot.parse::<Ipv4Addr>().is_err())
    {
        return Err(invalid_data("invalid HTTP authority host"));
    }
    Ok(host.to_ascii_lowercase())
}

fn http_proxy_authenticated(
    request: &HttpRequestHead,
    auth: Option<&[core_config::runtime_plan::UserPass]>,
) -> bool {
    let Some(auth) = auth.filter(|entries| !entries.is_empty()) else {
        return true;
    };
    let Some(value) = request.header("proxy-authorization") else {
        return false;
    };
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let mut parts = value.split_ascii_whitespace();
    let (Some(scheme), Some(credentials), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) else {
        return false;
    };
    let Some(colon) = decoded.iter().position(|byte| *byte == b':') else {
        return false;
    };
    auth.iter().any(|entry| {
        entry.user.as_bytes() == &decoded[..colon] && entry.pass.as_bytes() == &decoded[colon + 1..]
    })
}

fn build_forward_head(request: &HttpRequestHead, target: &ForwardTarget) -> Vec<u8> {
    let connection_options = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(|byte| *byte == b','))
        .filter_map(|option| std::str::from_utf8(trim_http_ows(option)).ok())
        .collect::<Vec<_>>();
    let mut head = Vec::with_capacity(HTTP_MAX_HEADER_BYTES);
    head.extend_from_slice(request.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(target.origin_form.as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.version.as_bytes());
    head.extend_from_slice(b"\r\nHost: ");
    head.extend_from_slice(target.authority.host_header.as_bytes());
    head.extend_from_slice(b"\r\nConnection: close\r\nVia: 1.1 RPKernel\r\n");
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("host")
            || header.name.eq_ignore_ascii_case("proxy-authorization")
            || header.name.eq_ignore_ascii_case("proxy-connection")
            || header.name.eq_ignore_ascii_case("proxy-authenticate")
            || header.name.eq_ignore_ascii_case("connection")
            || header.name.eq_ignore_ascii_case("keep-alive")
            || header.name.eq_ignore_ascii_case("te")
            || header.name.eq_ignore_ascii_case("upgrade")
            || connection_options
                .iter()
                .any(|option| header.name.eq_ignore_ascii_case(option))
        {
            continue;
        }
        head.extend_from_slice(header.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(&header.value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// Presents exactly one HTTP request body to the relay and then returns EOF.
///
/// The write side remains the original client socket, so the origin response
/// still streams normally. Returning EOF after the declared body makes the
/// relay half-close the upstream connection and prevents a second proxy
/// request (possibly for another target) from bypassing HTTP parsing.
struct HttpSingleRequestStream<S> {
    inner: S,
    prefetched: Vec<u8>,
    prefetched_position: usize,
    body: HttpBodyFraming,
    idle_timeout: Duration,
    idle_sleep: Pin<Box<Sleep>>,
}

impl<S> HttpSingleRequestStream<S> {
    fn new(
        inner: S,
        prefetched: Vec<u8>,
        body: HttpBodyFraming,
        idle_timeout: Duration,
    ) -> io::Result<Self> {
        body.validate_prefetched(&prefetched)?;
        Ok(Self {
            inner,
            prefetched,
            prefetched_position: 0,
            body,
            idle_timeout,
            idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
        })
    }

    #[cfg(test)]
    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for HttpSingleRequestStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.body.is_complete() || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.prefetched_position < this.prefetched.len() {
            let size = this.body.read_limit(output.remaining()).min(
                this.prefetched
                    .len()
                    .saturating_sub(this.prefetched_position),
            );
            let end = this.prefetched_position + size;
            this.body
                .consume(&this.prefetched[this.prefetched_position..end])?;
            output.put_slice(&this.prefetched[this.prefetched_position..end]);
            this.prefetched_position += size;
            this.idle_sleep
                .as_mut()
                .reset(Instant::now() + this.idle_timeout);
            return Poll::Ready(Ok(()));
        }

        let maximum = this.body.read_limit(output.remaining());
        let read = {
            let destination = output.initialize_unfilled_to(maximum);
            let mut limited = ReadBuf::new(destination);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => Ok(limited.filled().len()),
                Poll::Ready(Err(error)) => Err(error),
                Poll::Pending => {
                    if this.idle_sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP request body idle timeout",
                        )));
                    }
                    return Poll::Pending;
                }
            }
        };
        match read {
            Ok(0) => Poll::Ready(Err(invalid_data(
                "client closed before the declared HTTP request body completed",
            ))),
            Ok(size) => {
                let bytes = &output.initialize_unfilled_to(size)[..size];
                this.body.consume(bytes)?;
                output.advance(size);
                this.idle_sleep
                    .as_mut()
                    .reset(Instant::now() + this.idle_timeout);
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S> AsyncWrite for HttpSingleRequestStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
enum HttpBodyFraming {
    Fixed { remaining: u64 },
    Chunked(ChunkedBodyState),
}

impl HttpBodyFraming {
    fn fixed(remaining: u64) -> Self {
        Self::Fixed { remaining }
    }

    fn chunked() -> Self {
        Self::Chunked(ChunkedBodyState::SizeLine { line: Vec::new() })
    }

    fn is_complete(&self) -> bool {
        matches!(
            self,
            Self::Fixed { remaining: 0 } | Self::Chunked(ChunkedBodyState::Complete)
        )
    }

    fn read_limit(&self, output_remaining: usize) -> usize {
        match self {
            Self::Fixed { remaining } => {
                output_remaining.min((*remaining).min(usize::MAX as u64) as usize)
            }
            Self::Chunked(ChunkedBodyState::Data { remaining }) => {
                output_remaining.min((*remaining).min(usize::MAX as u64) as usize)
            }
            Self::Chunked(ChunkedBodyState::Complete) => 0,
            Self::Chunked(_) => output_remaining.min(1),
        }
    }

    fn consume(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self {
            Self::Fixed { remaining } => {
                if data.len() as u64 > *remaining {
                    return Err(invalid_data(
                        "HTTP request contains bytes beyond its declared body",
                    ));
                }
                *remaining -= data.len() as u64;
                Ok(())
            }
            Self::Chunked(state) => state.consume(data),
        }
    }

    fn validate_prefetched(&self, data: &[u8]) -> io::Result<()> {
        let mut framing = self.clone();
        for byte in data {
            if framing.is_complete() {
                return Err(invalid_data(
                    "HTTP request contains bytes beyond its declared body",
                ));
            }
            framing.consume(std::slice::from_ref(byte))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum ChunkedBodyState {
    SizeLine {
        line: Vec<u8>,
    },
    Data {
        remaining: u64,
    },
    DataCrlf {
        position: u8,
    },
    Trailers {
        line: Vec<u8>,
        bytes: usize,
        fields: usize,
    },
    Complete,
}

impl ChunkedBodyState {
    fn consume(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::SizeLine { line } => {
                if data.len() != 1 {
                    return Err(invalid_data("invalid chunk-size parser input"));
                }
                line.push(data[0]);
                if line.len() > 1024 {
                    return Err(invalid_data("HTTP chunk-size line exceeds 1024 bytes"));
                }
                if data[0] == b'\n' {
                    let size = parse_http_chunk_size(line)?;
                    *self = if size == 0 {
                        Self::Trailers {
                            line: Vec::new(),
                            bytes: 0,
                            fields: 0,
                        }
                    } else {
                        Self::Data { remaining: size }
                    };
                }
                Ok(())
            }
            Self::Data { remaining } => {
                if data.len() as u64 > *remaining {
                    return Err(invalid_data("HTTP chunk data exceeds its declared size"));
                }
                *remaining -= data.len() as u64;
                if *remaining == 0 {
                    *self = Self::DataCrlf { position: 0 };
                }
                Ok(())
            }
            Self::DataCrlf { position } => {
                if data.len() != 1 {
                    return Err(invalid_data("invalid HTTP chunk delimiter input"));
                }
                match (*position, data[0]) {
                    (0, b'\r') => *position = 1,
                    (1, b'\n') => *self = Self::SizeLine { line: Vec::new() },
                    _ => {
                        return Err(invalid_data(
                            "HTTP chunk data is missing its CRLF delimiter",
                        ));
                    }
                }
                Ok(())
            }
            Self::Trailers {
                line,
                bytes,
                fields,
            } => {
                if data.len() != 1 {
                    return Err(invalid_data("invalid HTTP trailer parser input"));
                }
                line.push(data[0]);
                *bytes = bytes
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("HTTP trailer size overflow"))?;
                if *bytes > HTTP_MAX_HEADER_BYTES {
                    return Err(invalid_data("HTTP chunk trailers exceed 16 KiB"));
                }
                if data[0] == b'\n' {
                    let trailer = parse_http_chunk_trailer(line)?;
                    if trailer {
                        *fields += 1;
                        if *fields > HTTP_MAX_HEADERS {
                            return Err(invalid_data("too many HTTP chunk trailer fields"));
                        }
                        line.clear();
                    } else {
                        *self = Self::Complete;
                    }
                }
                Ok(())
            }
            Self::Complete => Err(invalid_data(
                "HTTP request contains bytes beyond its chunked body",
            )),
        }
    }
}

fn parse_http_chunk_size(line: &[u8]) -> io::Result<u64> {
    let content = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| invalid_data("HTTP chunk-size line must end in CRLF"))?;
    if content.iter().any(|byte| *byte < 0x20 || *byte > 0x7e) {
        return Err(invalid_data("invalid byte in HTTP chunk-size line"));
    }
    let size = content
        .split(|byte| *byte == b';')
        .next()
        .ok_or_else(|| invalid_data("HTTP chunk size is missing"))?;
    if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_data("invalid HTTP chunk size"));
    }
    let size =
        std::str::from_utf8(size).map_err(|_| invalid_data("HTTP chunk size must be ASCII"))?;
    u64::from_str_radix(size, 16).map_err(|_| invalid_data("HTTP chunk size overflow"))
}

/// Returns `true` for a non-empty trailer field and `false` for the terminal
/// empty line.
fn parse_http_chunk_trailer(line: &[u8]) -> io::Result<bool> {
    let content = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| invalid_data("HTTP chunk trailer line must end in CRLF"))?;
    if content.is_empty() {
        return Ok(false);
    }
    if matches!(content.first(), Some(b' ' | b'\t')) {
        return Err(invalid_data("folded HTTP chunk trailers are not allowed"));
    }
    let colon = content
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| invalid_data("HTTP chunk trailer is missing ':'"))?;
    let name = &content[..colon];
    let value = trim_http_ows(&content[colon + 1..]);
    if name.is_empty()
        || !name.iter().copied().all(is_http_token_byte)
        || value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(invalid_data("invalid HTTP chunk trailer field"));
    }
    validate_http_trailer_name(name)?;
    Ok(true)
}

fn validate_http_trailer_declaration(value: &[u8]) -> io::Result<()> {
    let mut fields = value.split(|byte| *byte == b',').peekable();
    if fields.peek().is_none() {
        return Err(invalid_data("Trailer header field list is empty"));
    }
    for field in fields {
        let field = trim_http_ows(field);
        if field.is_empty() || !field.iter().copied().all(is_http_token_byte) {
            return Err(invalid_data("invalid field name in Trailer header"));
        }
        validate_http_trailer_name(field)?;
    }
    Ok(())
}

fn validate_http_trailer_name(name: &[u8]) -> io::Result<()> {
    // RFC 9110 section 6.5.1 prohibits fields whose semantics must be known
    // before the content: framing, routing, authentication, request controls,
    // response controls, and content format. Unknown extension fields remain
    // available because their own specifications can explicitly permit
    // trailers (integrity/signature metadata is a common example).
    const FORBIDDEN: &[&str] = &[
        "accept",
        "accept-charset",
        "accept-encoding",
        "accept-language",
        "accept-ranges",
        "access-control-request-headers",
        "access-control-request-method",
        "age",
        "allow",
        "authentication-info",
        "authorization",
        "cache-control",
        "connection",
        "content-disposition",
        "content-encoding",
        "content-language",
        "content-length",
        "content-location",
        "content-range",
        "content-type",
        "cookie",
        "early-data",
        "expect",
        "expires",
        "forwarded",
        "from",
        "host",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-range",
        "if-unmodified-since",
        "keep-alive",
        "location",
        "max-forwards",
        "origin",
        "pragma",
        "prefer",
        "priority",
        "proxy-authenticate",
        "proxy-authentication-info",
        "proxy-authorization",
        "proxy-connection",
        "range",
        "referer",
        "retry-after",
        "server",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "upgrade-insecure-requests",
        "user-agent",
        "vary",
        "via",
        "warning",
        "www-authenticate",
    ];
    if FORBIDDEN
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden.as_bytes()))
    {
        return Err(invalid_data("forbidden HTTP chunk trailer field"));
    }
    Ok(())
}

async fn write_http_control(sock: &mut TcpStream, response: &[u8]) -> io::Result<()> {
    timeout(HTTP_CONTROL_IO_TIMEOUT, sock.write_all(response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP response write timed out"))?
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use tokio::sync::Mutex;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn network_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn mixed_bind_is_exact_and_fails_when_requested_port_is_occupied() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();

        let error = bind_mixed_listener(address)
            .await
            .expect_err("must not fall back to an undeclared port");

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    fn test_runtime() -> Arc<Runtime> {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
name: mixed-udp-test
route:
  preset: direct
"#,
        )
        .unwrap();
        Arc::new(Runtime::build(plan))
    }

    struct TestMixedServer {
        addr: SocketAddr,
        task: JoinHandle<()>,
    }

    impl Drop for TestMixedServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_test_mixed(
        ip: IpAddr,
        udp: bool,
        auth: Option<Vec<core_config::runtime_plan::UserPass>>,
    ) -> TestMixedServer {
        let socket = TcpListener::bind(SocketAddr::new(ip, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = MixedListener {
            listen: addr,
            auth,
            udp,
        };
        let runtime = test_runtime();
        let task = tokio::spawn(async move {
            let _ = serve_mixed(socket, listener, runtime).await;
        });
        TestMixedServer { addr, task }
    }

    struct TestUdpEcho {
        addr: SocketAddr,
        received: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
        task: JoinHandle<()>,
    }

    impl Drop for TestUdpEcho {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_udp_echo(ip: IpAddr) -> TestUdpEcho {
        let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (tx, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((size, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let payload = buf[..size].to_vec();
                let _ = tx.send((payload.clone(), peer));
                let _ = socket.send_to(&payload, peer).await;
            }
        });
        TestUdpEcho {
            addr,
            received,
            task,
        }
    }

    async fn read_socks_reply(stream: &mut TcpStream) -> (u8, SocketAddr) {
        let mut head = [0u8; 4];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut head))
            .await
            .expect("SOCKS5 reply header timeout")
            .unwrap();
        assert_eq!(head[0], SOCKS_VERSION);
        assert_eq!(head[2], 0);
        let ip = match head[3] {
            0x01 => {
                let mut octets = [0u8; 4];
                timeout(TEST_TIMEOUT, stream.read_exact(&mut octets))
                    .await
                    .expect("SOCKS5 IPv4 reply timeout")
                    .unwrap();
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            0x04 => {
                let mut octets = [0u8; 16];
                timeout(TEST_TIMEOUT, stream.read_exact(&mut octets))
                    .await
                    .expect("SOCKS5 IPv6 reply timeout")
                    .unwrap();
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            atyp => panic!("unexpected reply ATYP {atyp:#x}"),
        };
        let mut port = [0u8; 2];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut port))
            .await
            .expect("SOCKS5 reply port timeout")
            .unwrap();
        (head[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
    }

    async fn connect_no_auth(server: SocketAddr) -> TcpStream {
        let mut control = timeout(TEST_TIMEOUT, TcpStream::connect(server))
            .await
            .expect("mixed connect timeout")
            .unwrap();
        control.write_all(&[SOCKS_VERSION, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        timeout(TEST_TIMEOUT, control.read_exact(&mut method))
            .await
            .expect("SOCKS5 greeting timeout")
            .unwrap();
        assert_eq!(method, [SOCKS_VERSION, 0]);
        control
    }

    async fn open_udp_association(
        server: SocketAddr,
        client: SocketAddr,
    ) -> (TcpStream, u8, SocketAddr) {
        let mut control = connect_no_auth(server).await;
        let mut request = vec![SOCKS_VERSION, SOCKS_CMD_UDP_ASSOCIATE, 0];
        SocksAddress::Ip(client.ip()).encode(&mut request).unwrap();
        request.extend_from_slice(&client.port().to_be_bytes());
        control.write_all(&request).await.unwrap();
        let (reply, relay) = read_socks_reply(&mut control).await;
        (control, reply, relay)
    }

    async fn send_udp_request(
        client: &UdpSocket,
        relay: SocketAddr,
        target: UdpTarget,
        payload: &[u8],
    ) {
        let packet = encode_socks5_udp_datagram(&target, payload, SOCKS_UDP_MAX_DATAGRAM).unwrap();
        timeout(TEST_TIMEOUT, client.send_to(&packet, relay))
            .await
            .expect("SOCKS5 UDP send timeout")
            .unwrap();
    }

    async fn recv_udp_response(client: &UdpSocket) -> (UdpTarget, Vec<u8>) {
        let mut buf = vec![0u8; 65_536];
        let (size, _) = timeout(TEST_TIMEOUT, client.recv_from(&mut buf))
            .await
            .expect("SOCKS5 UDP response timeout")
            .unwrap();
        let parsed = parse_socks5_udp_datagram(&buf[..size]).unwrap();
        (parsed.target, parsed.payload.to_vec())
    }

    fn target(addr: SocketAddr) -> UdpTarget {
        UdpTarget {
            address: SocksAddress::Ip(addr.ip()),
            port: addr.port(),
        }
    }

    #[test]
    fn http_absolute_and_origin_forms_route_and_rewrite_strictly() {
        let request = parse_http_request_head(
            b"POST http://[2001:db8::1]:8080/upload?x=1 HTTP/1.1\r\n\
              Host: wrong.example\r\n\
              Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
              Proxy-Connection: keep-alive\r\n\
              Connection: X-Hop, keep-alive\r\n\
              X-Hop: secret\r\n\
              Content-Length: 4\r\n\r\n",
        )
        .unwrap();
        let route = parse_http_route(&request).unwrap();
        let HttpRoute::Forward(target) = route else {
            panic!("absolute-form request did not produce a forward route");
        };
        assert_eq!(target.authority.host, "2001:db8::1");
        assert_eq!(target.authority.port, 8080);
        assert_eq!(target.authority.host_header, "[2001:db8::1]:8080");
        assert_eq!(target.origin_form, "/upload?x=1");
        let rewritten = build_forward_head(&request, &target);
        let rewritten = std::str::from_utf8(&rewritten).unwrap();
        assert!(rewritten.starts_with("POST /upload?x=1 HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n"));
        assert!(rewritten.contains("\r\nConnection: close\r\n"));
        assert!(rewritten.contains("\r\nVia: 1.1 RPKernel\r\n"));
        assert!(!rewritten.contains("wrong.example"));
        assert!(!rewritten.contains("X-Hop"));
        assert!(!rewritten.to_ascii_lowercase().contains("proxy-"));

        let request =
            parse_http_request_head(b"GET /status HTTP/1.1\r\nHost: Example.COM:8081\r\n\r\n")
                .unwrap();
        assert_eq!(
            parse_http_route(&request).unwrap(),
            HttpRoute::Forward(ForwardTarget {
                authority: ParsedAuthority {
                    host: "example.com".into(),
                    port: 8081,
                    host_header: "example.com:8081".into(),
                },
                origin_form: "/status".into(),
            })
        );
    }

    #[test]
    fn http_connect_and_basic_auth_support_ipv6_and_case_insensitive_scheme() {
        let request = parse_http_request_head(
            b"CONNECT [2001:db8::5]:443 HTTP/1.1\r\n\
              Host: [2001:db8::5]:443\r\n\
              Proxy-Authorization: bAsIc dXNlcjpwYXNz\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            parse_http_route(&request).unwrap(),
            HttpRoute::Connect(ParsedAuthority {
                host: "2001:db8::5".into(),
                port: 443,
                host_header: "[2001:db8::5]:443".into(),
            })
        );
        let auth = [core_config::runtime_plan::UserPass {
            user: "user".into(),
            pass: "pass".into(),
        }];
        assert!(http_proxy_authenticated(&request, Some(&auth)));
        assert!(!http_proxy_authenticated(
            &parse_http_request_head(
                b"CONNECT example.com:443 HTTP/1.1\r\n\
                  Host: example.com:443\r\n\
                  Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n",
            )
            .unwrap(),
            Some(&auth),
        ));
    }

    #[test]
    fn http_parser_rejects_ambiguous_headers_and_targets() {
        for malformed in [
            b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive,,X-Hop\r\n\r\n"
                .as_slice(),
            b"GET / HTTP/1.1\nHost: example.com\r\n\r\n".as_slice(),
            b"GET /\0 HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        ] {
            assert!(parse_http_request_head(malformed).is_err(), "{malformed:?}");
        }

        for malformed_target in [
            b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n".as_slice(),
            b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"GET example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"GET http://user@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
            b"GET http://127.000.0.1/ HTTP/1.1\r\nHost: 127.000.0.1\r\n\r\n".as_slice(),
            b"CONNECT 2001:db8::1:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n".as_slice(),
            b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice(),
        ] {
            let request = parse_http_request_head(malformed_target).unwrap();
            assert!(parse_http_route(&request).is_err(), "{malformed_target:?}");
        }
    }

    #[test]
    fn http_forward_body_framing_accepts_bounded_standard_forms() {
        let content_length = parse_http_request_head(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
        )
        .unwrap();
        assert!(matches!(
            content_length.forward_body_framing().unwrap(),
            HttpBodyFraming::Fixed { remaining: 4 }
        ));

        let chunked = parse_http_request_head(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert!(matches!(
            chunked.forward_body_framing().unwrap(),
            HttpBodyFraming::Chunked(_)
        ));

        let unsupported = parse_http_request_head(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            unsupported.forward_body_framing().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let overflow = parse_http_request_head(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999999999999999999999999\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            overflow.forward_body_framing().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        for ambiguous in [
            b"POST / HTTP/1.1\r\nHost: example.com\r\nConnection: Content-Length\r\nContent-Length: 4\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nConnection: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.0\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTrailer: Digest\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Digest, Content-Type\r\n\r\n"
                .as_slice(),
        ] {
            let request = parse_http_request_head(ambiguous).unwrap();
            assert_eq!(
                request.forward_body_framing().unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{ambiguous:?}"
            );
        }
    }

    #[tokio::test]
    async fn http_single_request_stream_stops_at_declared_body_boundary() {
        let (mut client, proxy) = tokio::io::duplex(1024);
        client.write_all(b"dySECOND").await.unwrap();
        let mut request = HttpSingleRequestStream::new(
            proxy,
            b"bo".to_vec(),
            HttpBodyFraming::fixed(4),
            Duration::from_secs(1),
        )
        .unwrap();

        let mut body = Vec::new();
        request.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"body");

        let mut proxy = request.into_inner();
        let mut second = [0u8; 6];
        proxy.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"SECOND");
    }

    #[tokio::test]
    async fn http_single_request_stream_rejects_overread_and_slow_body() {
        let (_, proxy) = tokio::io::duplex(1024);
        assert!(
            HttpSingleRequestStream::new(
                proxy,
                b"body plus pipeline".to_vec(),
                HttpBodyFraming::fixed(4),
                Duration::from_secs(1),
            )
            .is_err()
        );

        let (_client, proxy) = tokio::io::duplex(1024);
        let mut request = HttpSingleRequestStream::new(
            proxy,
            Vec::new(),
            HttpBodyFraming::fixed(1),
            Duration::from_millis(25),
        )
        .unwrap();
        let mut byte = [0u8; 1];
        let error = request.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn http_chunked_stream_preserves_trailers_and_stops_before_pipeline() {
        let (mut client, proxy) = tokio::io::duplex(1024);
        client
            .write_all(b"dy\r\n0\r\nX-Checksum: yes\r\n\r\nSECOND")
            .await
            .unwrap();
        let mut request = HttpSingleRequestStream::new(
            proxy,
            b"4\r\nbo".to_vec(),
            HttpBodyFraming::chunked(),
            Duration::from_secs(1),
        )
        .unwrap();

        let mut body = Vec::new();
        request.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"4\r\nbody\r\n0\r\nX-Checksum: yes\r\n\r\n");

        let mut proxy = request.into_inner();
        let mut second = [0u8; 6];
        proxy.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"SECOND");
    }

    #[test]
    fn http_chunked_framing_rejects_malformed_or_forbidden_trailers() {
        for body in [
            b"z\r\n".as_slice(),
            b"1\r\naX".as_slice(),
            b"0\r\nContent-Length: 4\r\n\r\n".as_slice(),
            b"0\r\nProxy-Connection: keep-alive\r\n\r\n".as_slice(),
            b"0\r\nCookie: session=secret\r\n\r\n".as_slice(),
            b"0\r\nExpect: 100-continue\r\n\r\n".as_slice(),
            b"0\r\nContent-Encoding: gzip\r\n\r\n".as_slice(),
            b"0\r\nContent-Type: application/json\r\n\r\n".as_slice(),
            b"0\r\nContent-Range: bytes 0-3/4\r\n\r\n".as_slice(),
            b"0\r\nRange: bytes=0-3\r\n\r\n".as_slice(),
            b"0\r\nIf-None-Match: \"tag\"\r\n\r\n".as_slice(),
            b"0\n\n".as_slice(),
        ] {
            assert!(
                HttpBodyFraming::chunked()
                    .validate_prefetched(body)
                    .is_err(),
                "{body:?}"
            );
        }
    }

    #[tokio::test]
    async fn http_header_reader_preserves_tail_and_enforces_limits() {
        let payload = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody";
        let (mut writer, mut reader) = tokio::io::duplex(32 * 1024);
        writer.write_all(payload).await.unwrap();
        let (head, tail) = read_http_head(&mut reader, TEST_TIMEOUT).await.unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(tail, b"body");

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        writer
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
            .await
            .unwrap();
        let error = read_http_head(&mut reader, Duration::from_millis(25))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let (mut writer, mut reader) = tokio::io::duplex(HTTP_MAX_HEADER_BYTES + 1);
        writer
            .write_all(&vec![b'a'; HTTP_MAX_HEADER_BYTES])
            .await
            .unwrap();
        let error = read_http_head(&mut reader, TEST_TIMEOUT).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn mixed_listener_shutdown_aborts_open_http_connections() {
        let _guard = network_test_lock().lock().await;
        let mut server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, None).await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        server.task.abort();
        let _ = timeout(TEST_TIMEOUT, &mut server.task).await;
        let mut byte = [0u8; 1];
        let closed = timeout(Duration::from_secs(1), client.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "connection task survived listener shutdown: {closed:?}"
        );
    }

    #[tokio::test]
    async fn http_auth_challenge_precedes_target_routing() {
        let _guard = network_test_lock().lock().await;
        let auth = vec![core_config::runtime_plan::UserPass {
            user: "user".into(),
            pass: "pass".into(),
        }];
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, Some(auth)).await;
        let mut client = TcpStream::connect(server.addr).await.unwrap();
        client
            .write_all(b"GET invalid-authority HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let (response, tail) = read_http_head(&mut client, TEST_TIMEOUT).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(tail.is_empty());
    }

    #[test]
    fn udp_header_round_trips_ipv4_ipv6_and_domain() {
        let targets = [
            UdpTarget {
                address: SocksAddress::Ip("192.0.2.7".parse().unwrap()),
                port: 53,
            },
            UdpTarget {
                address: SocksAddress::Ip("2001:db8::7".parse().unwrap()),
                port: 5353,
            },
            UdpTarget {
                address: SocksAddress::Domain("example.com".into()),
                port: 443,
            },
        ];
        for target in targets {
            let encoded =
                encode_socks5_udp_datagram(&target, b"payload", SOCKS_UDP_MAX_DATAGRAM).unwrap();
            let parsed = parse_socks5_udp_datagram(&encoded).unwrap();
            assert_eq!(parsed.target, target);
            assert_eq!(parsed.payload, b"payload");
        }
    }

    #[test]
    fn udp_header_rejects_reserved_and_fragment_fields() {
        let target = UdpTarget {
            address: SocksAddress::Ip("127.0.0.1".parse().unwrap()),
            port: 53,
        };
        let mut packet =
            encode_socks5_udp_datagram(&target, b"dns", SOCKS_UDP_MAX_DATAGRAM).unwrap();
        packet[0] = 1;
        assert_eq!(
            parse_socks5_udp_datagram(&packet).unwrap_err(),
            UdpHeaderError::ReservedNonZero
        );
        packet[0] = 0;
        packet[2] = 1;
        assert_eq!(
            parse_socks5_udp_datagram(&packet).unwrap_err(),
            UdpHeaderError::FragmentationUnsupported(1)
        );
    }

    #[test]
    fn runtime_plan_preserves_mixed_udp_switch() {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
name: mixed-udp-off
listen:
  local:
    host: 127.0.0.1
    port: 1080
    udp: false
route:
  preset: direct
"#,
        )
        .unwrap();
        assert!(!plan.listen.mixed.unwrap().udp);
    }

    #[tokio::test]
    async fn disabled_udp_associate_returns_command_not_supported() {
        let _guard = network_test_lock().lock().await;
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), false, None).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_control, reply, relay) =
            open_udp_association(server.addr, client.local_addr().unwrap()).await;
        assert_eq!(reply, SOCKS_REP_COMMAND_NOT_SUPPORTED);
        assert_eq!(relay.port(), 0);
    }

    #[tokio::test]
    async fn udp_associate_pins_client_endpoint() {
        let _guard = network_test_lock().lock().await;
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, None).await;
        let intended = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut echo = spawn_udp_echo(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let (_control, reply, relay) =
            open_udp_association(server.addr, intended.local_addr().unwrap()).await;
        assert_eq!(reply, SOCKS_REP_SUCCEEDED);
        assert_eq!(relay.ip(), server.addr.ip());
        assert_ne!(relay.port(), 0);

        send_udp_request(&attacker, relay, target(echo.addr), b"attacker").await;
        assert!(
            timeout(Duration::from_millis(300), echo.received.recv())
                .await
                .is_err(),
            "non-associated client packet reached the target"
        );

        send_udp_request(&intended, relay, target(echo.addr), b"intended").await;
        let (response_target, response) = recv_udp_response(&intended).await;
        assert_eq!(response_target, target(echo.addr));
        assert_eq!(response, b"intended");
    }

    #[tokio::test]
    async fn udp_associate_keeps_multiple_targets_isolated() {
        let _guard = network_test_lock().lock().await;
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, None).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_a = spawn_udp_echo(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let echo_b = spawn_udp_echo(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let (_control, reply, relay) =
            open_udp_association(server.addr, client.local_addr().unwrap()).await;
        assert_eq!(reply, SOCKS_REP_SUCCEEDED);

        send_udp_request(&client, relay, target(echo_a.addr), b"from-a").await;
        send_udp_request(&client, relay, target(echo_b.addr), b"from-b").await;
        let first = recv_udp_response(&client).await;
        let second = recv_udp_response(&client).await;
        let responses = HashMap::from([first, second]);
        assert_eq!(responses.get(&target(echo_a.addr)).unwrap(), b"from-a");
        assert_eq!(responses.get(&target(echo_b.addr)).unwrap(), b"from-b");
    }

    #[tokio::test]
    async fn udp_associate_closes_with_control_connection() {
        let _guard = network_test_lock().lock().await;
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, None).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut echo = spawn_udp_echo(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let (control, reply, relay) =
            open_udp_association(server.addr, client.local_addr().unwrap()).await;
        assert_eq!(reply, SOCKS_REP_SUCCEEDED);

        send_udp_request(&client, relay, target(echo.addr), b"before-close").await;
        assert_eq!(recv_udp_response(&client).await.1, b"before-close");
        let _ = timeout(TEST_TIMEOUT, echo.received.recv())
            .await
            .expect("echo receive timeout");

        drop(control);
        tokio::time::sleep(Duration::from_millis(300)).await;
        send_udp_request(&client, relay, target(echo.addr), b"after-close").await;
        assert!(
            timeout(Duration::from_millis(500), echo.received.recv())
                .await
                .is_err(),
            "UDP relay accepted a packet after its control connection closed"
        );
    }

    #[tokio::test]
    async fn socks5_auth_and_unsupported_command_replies_are_rfc_compliant() {
        let _guard = network_test_lock().lock().await;
        let auth = vec![core_config::runtime_plan::UserPass {
            user: "user".into(),
            pass: "pass".into(),
        }];
        let server = spawn_test_mixed(IpAddr::V4(Ipv4Addr::LOCALHOST), true, Some(auth)).await;

        let mut no_auth = TcpStream::connect(server.addr).await.unwrap();
        no_auth.write_all(&[SOCKS_VERSION, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        no_auth.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, 0xff]);

        let mut control = TcpStream::connect(server.addr).await.unwrap();
        control.write_all(&[SOCKS_VERSION, 1, 0x02]).await.unwrap();
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, 0x02]);
        control
            .write_all(&[
                0x01, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's',
            ])
            .await
            .unwrap();
        let mut auth_reply = [0u8; 2];
        control.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x00]);
        control
            .write_all(&[SOCKS_VERSION, 0x02, 0, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (reply, _) = read_socks_reply(&mut control).await;
        assert_eq!(reply, SOCKS_REP_COMMAND_NOT_SUPPORTED);
    }

    async fn ipv6_udp_data_plane_available() -> bool {
        let server = match UdpSocket::bind("[::1]:0").await {
            Ok(socket) => socket,
            Err(_) => return false,
        };
        let client = match UdpSocket::bind("[::1]:0").await {
            Ok(socket) => socket,
            Err(_) => return false,
        };
        let server_addr = match server.local_addr() {
            Ok(addr) => addr,
            Err(_) => return false,
        };
        if timeout(
            Duration::from_millis(500),
            client.send_to(b"probe", server_addr),
        )
        .await
        .is_err()
        {
            return false;
        }
        let mut buf = [0u8; 16];
        let (size, peer) =
            match timeout(Duration::from_millis(500), server.recv_from(&mut buf)).await {
                Ok(Ok(value)) => value,
                _ => return false,
            };
        if !matches!(
            timeout(
                Duration::from_millis(500),
                server.send_to(&buf[..size], peer)
            )
            .await,
            Ok(Ok(_))
        ) {
            return false;
        }
        matches!(
            timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await,
            Ok(Ok((5, _))) if &buf[..5] == b"probe"
        )
    }

    #[tokio::test]
    async fn udp_associate_ipv6_round_trip_when_host_data_plane_is_available() {
        let _guard = network_test_lock().lock().await;
        if !ipv6_udp_data_plane_available().await {
            eprintln!("skipping live IPv6 SOCKS5 UDP test: host IPv6 data plane unavailable");
            return;
        }
        let server = spawn_test_mixed(IpAddr::V6(Ipv6Addr::LOCALHOST), true, None).await;
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        let echo = spawn_udp_echo(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
        let (_control, reply, relay) =
            open_udp_association(server.addr, client.local_addr().unwrap()).await;
        assert_eq!(reply, SOCKS_REP_SUCCEEDED);
        assert!(relay.is_ipv6());
        assert_ne!(relay.port(), 0);

        send_udp_request(&client, relay, target(echo.addr), b"ipv6").await;
        let (response_target, response) = recv_udp_response(&client).await;
        assert_eq!(response_target, target(echo.addr));
        assert_eq!(response, b"ipv6");
    }
}
