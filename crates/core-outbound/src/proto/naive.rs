//! NaiveProxy outbound backed by the SagerNet Cronet native stack.
//!
//! Cronet exposes a blocking bidirectional stream. Each tunnel is bridged to a
//! Tokio stream through a loopback socket pair; the native read and write
//! directions run concurrently on scoped OS threads. This keeps blocking
//! Cronet callbacks away from Tokio workers and preserves backpressure.

use std::{
    io::{self, Read, Write},
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
        UdpSocket,
    },
    sync::{Arc, OnceLock, mpsc},
};

use async_trait::async_trait;
use cronet::{BidirectionalConnection, Header, NaiveClient, NaiveClientOptions, NetworkHooks};
use hickory_proto::{
    op::Message,
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use rand::{RngCore, rngs::OsRng};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream as TokioTcpStream,
    sync::{Mutex as AsyncMutex, oneshot},
};

use crate::adapter::{
    BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
    apply_outbound_mark_for_addr, bind_outbound_socket, protect_socket,
};

const NAIVE_PADDING_CHUNKS: usize = 8;
const NAIVE_MAX_CHUNK: usize = u16::MAX as usize;
const UOT_V2_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

#[derive(Clone, Debug)]
pub struct NaiveOutboundConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub server_name: Option<String>,
    pub insecure_concurrency: usize,
    pub extra_headers: Vec<Header>,
    pub udp_over_tcp: bool,
    pub quic: bool,
    pub quic_congestion_control: String,
    pub receive_window: u64,
    pub quic_session_receive_window: u64,
    pub trusted_root_certificates: Option<String>,
    pub ech_enabled: bool,
    pub ech_config_list: Vec<u8>,
    pub ech_query_server_name: Option<String>,
}

impl NaiveOutboundConfig {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            username: None,
            password: None,
            server_name: None,
            insecure_concurrency: 1,
            extra_headers: Vec::new(),
            udp_over_tcp: false,
            quic: false,
            quic_congestion_control: String::new(),
            receive_window: 0,
            quic_session_receive_window: 0,
            trusted_root_certificates: None,
            ech_enabled: false,
            ech_config_list: Vec::new(),
            ech_query_server_name: None,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.host.trim().is_empty() {
            return Err(invalid_input("Naive server must not be empty"));
        }
        if self.port == 0 {
            return Err(invalid_input("Naive server port must not be zero"));
        }
        if self.quic && self.insecure_concurrency.max(1) > 1 {
            return Err(invalid_input(
                "Naive insecure_concurrency is incompatible with QUIC",
            ));
        }
        if !matches!(
            self.quic_congestion_control.as_str(),
            "" | "TBBR" | "B2ON" | "QBIC" | "RENO"
        ) {
            return Err(invalid_input(format!(
                "unknown Naive QUIC congestion control `{}`",
                self.quic_congestion_control
            )));
        }
        for header in &self.extra_headers {
            if header.name.is_empty()
                || header.name.starts_with(':')
                || header.name.starts_with('-')
                || header.name.eq_ignore_ascii_case("proxy-authorization")
                || header.name.eq_ignore_ascii_case("padding")
            {
                return Err(invalid_input(format!(
                    "Naive extra header `{}` is reserved or invalid",
                    header.name
                )));
            }
            if header.name.contains(['\r', '\n']) || header.value.contains(['\r', '\n']) {
                return Err(invalid_input("Naive extra headers must not contain CR/LF"));
            }
        }
        Ok(())
    }

    fn client_options(&self) -> NaiveClientOptions {
        let authority = format_authority(&self.host, self.port);
        let mut options = NaiveClientOptions::new(format!("https://{authority}"));
        options.username = self.username.clone();
        options.password = self.password.clone();
        options.insecure_concurrency = self.insecure_concurrency.max(1);
        options.extra_headers = self.extra_headers.clone();
        options.quic = self.quic;
        options.server_name = self.server_name.clone();
        options.server_address = Some(self.host.clone());
        options.ech_enabled = self.ech_enabled;
        options.ech_config_list = self.ech_config_list.clone();
        options.ech_query_server_name = self.ech_query_server_name.clone();
        options.quic_congestion_control = self.quic_congestion_control.clone();
        options.receive_window = self.receive_window;
        options.quic_session_receive_window = self.quic_session_receive_window;
        options
    }
}

pub struct NaiveOutbound {
    name: String,
    config: NaiveOutboundConfig,
    client: Arc<OnceLock<Result<Arc<NaiveClient>, String>>>,
}

impl NaiveOutbound {
    pub fn new(name: impl Into<String>, config: NaiveOutboundConfig) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            name: name.into(),
            config,
            client: Arc::new(OnceLock::new()),
        })
    }

    fn initialize_client(
        config: &NaiveOutboundConfig,
        cell: &OnceLock<Result<Arc<NaiveClient>, String>>,
    ) -> io::Result<Arc<NaiveClient>> {
        cell.get_or_init(|| {
            let mut hooks = NetworkHooks::new()
                .tcp_connector(connect_tcp)
                .udp_connector(connect_udp)
                .dns_resolver(system_dns);
            if let Some(certificates) = config.trusted_root_certificates.clone() {
                hooks = hooks.trusted_root_certificates(certificates);
            }
            NaiveClient::start(config.client_options(), hooks)
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|error| io::Error::other(format!("start Naive Cronet client: {error}")))
    }

    async fn dial_tunnel(&self, destination: String) -> io::Result<BoxedStream> {
        let (application, bridge) = tcp_pair()?;
        application.set_nonblocking(true)?;
        let stream = TokioTcpStream::from_std(application)?;
        let config = self.config.clone();
        let client_cell = Arc::clone(&self.client);
        let (ready_tx, ready_rx) = oneshot::channel();
        let thread_name = format!("naive-{}", sanitize_thread_name(&self.name));

        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let client = match Self::initialize_client(&config, &client_cell) {
                    Ok(client) => client,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let connection = match client.dial(destination) {
                    Ok(connection) => connection,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    connection.cancel();
                    return;
                }
                bridge_connection(connection.inner(), bridge);
            })
            .map_err(|error| io::Error::other(format!("spawn Naive bridge: {error}")))?;

        ready_rx
            .await
            .map_err(|_| io::Error::other("Naive bridge exited before handshake"))??;
        Ok(Box::pin(stream))
    }
}

#[async_trait]
impl OutboundAdapter for NaiveOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        "naive"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.config.udp_over_tcp,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> io::Result<BoxedStream> {
        self.dial_tunnel(format_authority(&ctx.host, ctx.port))
            .await
    }

    async fn dial_udp(&self, ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.config.udp_over_tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Naive UDP requires udp_over_tcp",
            ));
        }
        let mut stream = self.dial_tunnel(format!("{UOT_V2_MAGIC}:0")).await?;
        let request = encode_uot_request(&ctx.host, ctx.port)?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Box::new(NaiveUdp {
            target: normalize_host(&ctx.host),
            port: ctx.port,
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
        }))
    }
}

struct NaiveUdp {
    target: String,
    port: u16,
    reader: AsyncMutex<ReadHalf<BoxedStream>>,
    writer: AsyncMutex<WriteHalf<BoxedStream>>,
}

#[async_trait]
impl UdpSocketLike for NaiveUdp {
    async fn send_to(&self, packet: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if normalize_host(target) != self.target || port != self.port {
            return Err(invalid_input(
                "Naive UoT association cannot send to a different target",
            ));
        }
        let length = u16::try_from(packet.len())
            .map_err(|_| invalid_input("Naive UoT packet exceeds 65535 bytes"))?;
        let mut writer = self.writer.lock().await;
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(packet).await?;
        writer.flush().await?;
        Ok(packet.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.lock().await;
        let length = usize::from(reader.read_u16().await?);
        if length > output.len() {
            let mut remaining = length;
            let mut discard = [0_u8; 2048];
            while remaining != 0 {
                let count = remaining.min(discard.len());
                reader.read_exact(&mut discard[..count]).await?;
                remaining -= count;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Naive UoT receive buffer is too small: {} < {length}",
                    output.len()
                ),
            ));
        }
        reader.read_exact(&mut output[..length]).await?;
        Ok(length)
    }

    async fn close(&self) -> io::Result<()> {
        self.writer.lock().await.shutdown().await
    }
}

#[derive(Clone, Copy)]
enum BridgeDirection {
    Inbound,
    Outbound,
}

fn bridge_connection(connection: &BidirectionalConnection<'_>, socket: TcpStream) {
    let inbound_socket = match socket.try_clone() {
        Ok(socket) => socket,
        Err(_) => {
            connection.cancel();
            return;
        }
    };
    let shutdown_socket = socket.try_clone().ok();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let inbound_done = done_tx.clone();
        scope.spawn(move || {
            let result = copy_from_cronet(connection, inbound_socket);
            let _ = inbound_done.send((BridgeDirection::Inbound, result));
        });
        scope.spawn(move || {
            let result = copy_to_cronet(socket, connection);
            let _ = done_tx.send((BridgeDirection::Outbound, result));
        });

        let first = done_rx.recv();
        match first {
            Ok((BridgeDirection::Outbound, Ok(()))) => {
                let _ = done_rx.recv();
            }
            _ => {
                connection.cancel();
                if let Some(socket) = &shutdown_socket {
                    let _ = socket.shutdown(Shutdown::Both);
                }
                let _ = done_rx.recv();
            }
        }
        connection.cancel();
        if let Some(socket) = &shutdown_socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    });
}

fn copy_from_cronet(
    connection: &BidirectionalConnection<'_>,
    mut socket: TcpStream,
) -> io::Result<()> {
    let mut payload = vec![0_u8; 32 * 1024];
    for _ in 0..NAIVE_PADDING_CHUNKS {
        let mut header = [0_u8; 3];
        read_cronet_exact(connection, &mut header)?;
        let payload_len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let padding_len = usize::from(header[2]);
        let mut remaining = payload_len;
        while remaining != 0 {
            let count = remaining.min(payload.len());
            read_cronet_exact(connection, &mut payload[..count])?;
            socket.write_all(&payload[..count])?;
            remaining -= count;
        }
        skip_cronet(connection, padding_len)?;
    }
    loop {
        let count = connection.read_shared(&mut payload)?;
        if count == 0 {
            socket.shutdown(Shutdown::Write)?;
            return Ok(());
        }
        socket.write_all(&payload[..count])?;
    }
}

fn copy_to_cronet(
    mut socket: TcpStream,
    connection: &BidirectionalConnection<'_>,
) -> io::Result<()> {
    let mut payload = vec![0_u8; 32 * 1024];
    let mut padded = 0usize;
    loop {
        let count = socket.read(&mut payload)?;
        if count == 0 {
            connection.write_shared(&[], true)?;
            return Ok(());
        }
        if padded < NAIVE_PADDING_CHUNKS {
            let payload_len = count.min(NAIVE_MAX_CHUNK);
            let padding_len = (OsRng.next_u32() & 0xff) as usize;
            let mut frame = Vec::with_capacity(3 + payload_len + padding_len);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
            frame.push(padding_len as u8);
            frame.extend_from_slice(&payload[..payload_len]);
            frame.resize(frame.len() + padding_len, 0);
            connection.write_shared(&frame, false)?;
            padded += 1;
        } else {
            connection.write_shared(&payload[..count], false)?;
        }
    }
}

fn read_cronet_exact(
    connection: &BidirectionalConnection<'_>,
    mut output: &mut [u8],
) -> io::Result<()> {
    while !output.is_empty() {
        let count = connection.read_shared(output)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        output = &mut output[count..];
    }
    Ok(())
}

fn skip_cronet(connection: &BidirectionalConnection<'_>, mut length: usize) -> io::Result<()> {
    let mut discard = [0_u8; 512];
    while length != 0 {
        let count = length.min(discard.len());
        read_cronet_exact(connection, &mut discard[..count])?;
        length -= count;
    }
    Ok(())
}

fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last_error = None;
    for peer in (host, port).to_socket_addrs()? {
        let domain = if peer.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if let Err(error) = prepare_socket(&socket, peer) {
            last_error = Some(error);
            continue;
        }
        match socket.connect(&SockAddr::from(peer)) {
            Ok(()) => return Ok(socket.into()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Naive TCP server has no addresses")
    }))
}

fn connect_udp(host: &str, port: u16) -> io::Result<UdpSocket> {
    let mut last_error = None;
    for peer in (host, port).to_socket_addrs()? {
        let domain = if peer.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if let Err(error) = prepare_socket(&socket, peer) {
            last_error = Some(error);
            continue;
        }
        let local = if peer.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        if let Err(error) = socket.bind(&SockAddr::from(local)) {
            last_error = Some(error);
            continue;
        }
        match socket.connect(&SockAddr::from(peer)) {
            Ok(()) => return Ok(socket.into()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Naive UDP server has no addresses")
    }))
}

fn prepare_socket(socket: &Socket, peer: SocketAddr) -> io::Result<()> {
    protect_socket(socket)?;
    apply_outbound_mark_for_addr(socket, peer)?;
    bind_outbound_socket(socket, peer)
}

fn system_dns(query: &[u8]) -> io::Result<Vec<u8>> {
    let request = Message::from_vec(query).map_err(io::Error::other)?;
    let mut response = request.clone().into_response();
    response.answers.clear();
    response.authorities.clear();
    response.additionals.clear();
    let Some(question) = request.queries.first() else {
        return response.to_vec().map_err(io::Error::other);
    };
    let host = question.name().to_utf8().trim_end_matches('.').to_owned();
    for address in (host.as_str(), 0).to_socket_addrs()? {
        let data = match (question.query_type(), address.ip()) {
            (RecordType::A, IpAddr::V4(address)) => Some(RData::A(A(address))),
            (RecordType::AAAA, IpAddr::V6(address)) => Some(RData::AAAA(AAAA(address))),
            _ => None,
        };
        if let Some(data) = data {
            response.add_answer(Record::from_rdata(question.name().clone(), 60, data));
        }
    }
    response.to_vec().map_err(io::Error::other)
}

fn encode_uot_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut request = vec![1_u8]; // isConnect=true
    encode_socks_address(&mut request, host, port, [0x01, 0x04, 0x03])?;
    Ok(request)
}

fn encode_socks_address(
    output: &mut Vec<u8>,
    host: &str,
    port: u16,
    families: [u8; 3],
) -> io::Result<()> {
    let host = normalize_host(host);
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        output.push(families[0]);
        output.extend_from_slice(&address.octets());
    } else if let Ok(address) = host.parse::<Ipv6Addr>() {
        output.push(families[1]);
        output.extend_from_slice(&address.octets());
    } else {
        let length = u8::try_from(host.len())
            .map_err(|_| invalid_input("Naive UoT domain exceeds 255 bytes"))?;
        if length == 0 {
            return Err(invalid_input("Naive UoT domain must not be empty"));
        }
        output.push(families[2]);
        output.push(length);
        output.extend_from_slice(host.as_bytes());
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn format_authority(host: &str, port: u16) -> String {
    let host = normalize_host(host);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase()
}

fn sanitize_thread_name(name: &str) -> String {
    let name = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(24)
        .collect::<String>();
    if name.is_empty() {
        "bridge".into()
    } else {
        name
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, sync::Arc, time::Duration};

    use bytes::Bytes;
    use h2::server::SendResponse;
    use http::{Request, Response};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use time::{Duration as TimeDuration, OffsetDateTime};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn encodes_uot_v2_connect_request() {
        assert_eq!(
            encode_uot_request("dns.example", 53).unwrap(),
            [
                1, 3, 11, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 53,
            ]
        );
        assert_eq!(
            encode_uot_request("192.0.2.1", 5353).unwrap(),
            [1, 1, 192, 0, 2, 1, 0x14, 0xe9]
        );
    }

    #[test]
    fn validates_quic_pool_and_reserved_headers() {
        let mut config = NaiveOutboundConfig::new("proxy.example", 443);
        config.quic = true;
        config.insecure_concurrency = 2;
        assert!(config.validate().is_err());

        config.insecure_concurrency = 1;
        config.extra_headers.push(Header {
            name: "Proxy-Authorization".into(),
            value: "secret".into(),
        });
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn uot_rejects_cross_target_and_discards_oversized_packet() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(Box::pin(client) as BoxedStream);
        let udp = NaiveUdp {
            target: "dns.example".into(),
            port: 53,
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(writer),
        };
        assert!(udp.send_to(b"x", "other.example", 53).await.is_err());

        server.write_all(&4_u16.to_be_bytes()).await.unwrap();
        server.write_all(b"data").await.unwrap();
        server.write_all(&2_u16.to_be_bytes()).await.unwrap();
        server.write_all(b"ok").await.unwrap();
        let mut small = [0_u8; 2];
        assert!(udp.recv_from(&mut small).await.is_err());
        assert_eq!(udp.recv_from(&mut small).await.unwrap(), 2);
        assert_eq!(&small, b"ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_h2_tunnel_round_trip() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::time::timeout(Duration::from_secs(20), async {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params =
                CertificateParams::new(vec!["RPKernel Naive test CA".into()]).unwrap();
            let now = OffsetDateTime::now_utc();
            ca_params.not_before = now - TimeDuration::days(1);
            ca_params.not_after = now + TimeDuration::days(30);
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
            server_params.not_before = now - TimeDuration::days(1);
            server_params.not_after = now + TimeDuration::days(30);
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_certificate = server_params.signed_by(&server_key, &ca).unwrap();
            let root_pem = ca.pem();
            let certificate: CertificateDer<'static> = server_certificate.der().clone();
            let private_key =
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
            let mut tls = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .unwrap();
            tls.alpn_protocols = vec![b"h2".to_vec()];

            let listener = TokioTcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(serve_naive_echo(listener, TlsAcceptor::from(Arc::new(tls))));

            let mut config = NaiveOutboundConfig::new("localhost", port);
            config.trusted_root_certificates = Some(root_pem);
            let outbound = NaiveOutbound::new("native-test", config).unwrap();
            let mut stream = outbound
                .dial_tcp(DialContext::tcp("echo.invalid", 443))
                .await
                .unwrap();
            let payloads = [
                b"one".as_slice(),
                b"two-two".as_slice(),
                b"three-three-three".as_slice(),
                b"4".as_slice(),
                b"five".as_slice(),
                b"six".as_slice(),
                b"seven".as_slice(),
                b"eight".as_slice(),
                b"ninth chunk is deliberately unpadded".as_slice(),
            ];
            for payload in payloads {
                stream.write_all(payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut echoed = vec![0; payload.len()];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            }
            stream.shutdown().await.unwrap();
            server.abort();
            let _ = server.await;
        })
        .await
        .expect("native Naive H2 test timed out");
    }

    async fn serve_naive_echo(listener: TokioTcpListener, acceptor: TlsAcceptor) -> io::Result<()> {
        let (socket, _) = listener.accept().await?;
        let socket = acceptor.accept(socket).await.map_err(io::Error::other)?;
        let mut connection = h2::server::handshake(socket)
            .await
            .map_err(io::Error::other)?;
        while let Some(request) = connection.accept().await {
            let (request, respond) = request.map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = echo_connect(request, respond).await;
            });
        }
        Ok(())
    }

    async fn echo_connect(
        request: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
    ) -> io::Result<()> {
        if request.method() != http::Method::CONNECT {
            respond
                .send_response(
                    Response::builder()
                        .status(405)
                        .body(())
                        .map_err(io::Error::other)?,
                    true,
                )
                .map_err(io::Error::other)?;
            return Ok(());
        }
        let mut request_body = request.into_body();
        let mut response_body = respond
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .map_err(io::Error::other)?,
                false,
            )
            .map_err(io::Error::other)?;
        while let Some(packet) = request_body.data().await {
            let packet = packet.map_err(io::Error::other)?;
            request_body
                .flow_control()
                .release_capacity(packet.len())
                .map_err(io::Error::other)?;
            response_body.reserve_capacity(packet.len());
            while response_body.capacity() < packet.len() {
                match poll_fn(|context| response_body.poll_capacity(context)).await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(io::Error::other(error)),
                    None => return Ok(()),
                }
            }
            response_body
                .send_data(packet, false)
                .map_err(io::Error::other)?;
        }
        response_body
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)
    }
}
