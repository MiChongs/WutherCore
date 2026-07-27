//! Xray 26.7.11 xicmp carrier for ICMPv4/v6 echo packets.
//!
//! Source of truth: `transport/internet/finalmask/xicmp` at
//! `6e3322d219140a025285ded1114fe17a5edb74d8`. Client requests carry
//! `clientID[8] || QUIC packet`; replies carry only the QUIC packet. Both
//! privileged RAW sockets and unprivileged ping DGRAM sockets are supported.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use core_config::XicmpMaskConfig;
use rand::{RngCore, seq::SliceRandom};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::adapter::{BoxedUdp, UdpSocketLike};

const MAX_PACKET: usize = 4096;
const ICMP_HEADER: usize = 8;
const CLIENT_ID: usize = 8;
const SEQUENCE_WINDOW: u16 = 1000;

pub(super) fn wrap_client(
    inner: BoxedUdp,
    config: &XicmpMaskConfig,
    remote: Option<SocketAddr>,
) -> io::Result<BoxedUdp> {
    let ips = config
        .ips
        .iter()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .map_err(|_| invalid(format!("invalid xicmp IP `{ip}`")))
        })
        .collect::<io::Result<Vec<_>>>()?;
    if ips.is_empty() && remote.is_none() {
        return Err(invalid(
            "xicmp needs a resolved remote address when settings.ips is empty",
        ));
    }
    let (ipv4, ipv4_guard) = open_icmp_socket(false, config.dgram, false)?;
    let (ipv6, ipv6_guard) = open_icmp_socket(true, config.dgram, false)?;
    let mut client_id = [0; CLIENT_ID];
    rand::rngs::OsRng.fill_bytes(&mut client_id);
    let id = rand::random::<u16>();
    let sequence = Arc::new(AtomicU16::new(1));
    let closed = Arc::new(AtomicBool::new(false));
    let (output_tx, output_rx) = tokio::sync::mpsc::channel(256);
    let mut tasks = Vec::with_capacity(2);
    tasks.push(spawn_receiver(
        ipv4.clone(),
        IpFamily::V4,
        config.dgram,
        id,
        client_id,
        sequence.clone(),
        closed.clone(),
        output_tx.clone(),
    ));
    tasks.push(spawn_receiver(
        ipv6.clone(),
        IpFamily::V6,
        config.dgram,
        id,
        client_id,
        sequence.clone(),
        closed.clone(),
        output_tx,
    ));
    Ok(Box::new(XicmpClient {
        inner,
        ipv4,
        ipv6,
        _ipv4_guard: ipv4_guard,
        _ipv6_guard: ipv6_guard,
        ips,
        remote,
        client_id,
        id,
        sequence,
        output: Mutex::new(output_rx),
        closed,
        tasks: Mutex::new(tasks),
    }))
}

pub(super) fn wrap_server(inner: BoxedUdp, config: &XicmpMaskConfig) -> io::Result<BoxedUdp> {
    let allowed_ips = config
        .ips
        .iter()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .map_err(|_| invalid(format!("invalid xicmp IP `{ip}`")))
        })
        .collect::<io::Result<HashSet<_>>>()?;
    // Xray servers always need raw ICMP sockets; DGRAM ping sockets cannot
    // receive arbitrary clients' echo requests.
    let (ipv4, ipv4_guard) = open_icmp_socket(false, false, true)?;
    let (ipv6, ipv6_guard) = open_icmp_socket(true, false, true)?;
    let records = Arc::new(Mutex::new(HashMap::new()));
    let closed = Arc::new(AtomicBool::new(false));
    let (output_tx, output_rx) = tokio::sync::mpsc::channel(256);
    let tasks = vec![
        spawn_server_receiver(
            ipv4.clone(),
            IpFamily::V4,
            allowed_ips.clone(),
            records.clone(),
            output_tx.clone(),
            closed.clone(),
        ),
        spawn_server_receiver(
            ipv6.clone(),
            IpFamily::V6,
            allowed_ips,
            records.clone(),
            output_tx,
            closed.clone(),
        ),
    ];
    Ok(Box::new(XicmpServer {
        inner,
        ipv4,
        ipv6,
        _ipv4_guard: ipv4_guard,
        _ipv6_guard: ipv6_guard,
        records,
        output: Mutex::new(output_rx),
        closed,
        tasks: Mutex::new(tasks),
    }))
}

#[derive(Clone)]
struct ServerRecord {
    source: SocketAddr,
    destination: Option<IpAddr>,
    family: IpFamily,
    id: u16,
    sequence: u16,
    last: Instant,
}

struct XicmpServer {
    inner: BoxedUdp,
    ipv4: Arc<tokio::net::UdpSocket>,
    ipv6: Arc<tokio::net::UdpSocket>,
    _ipv4_guard: crate::loopback::LoopbackUdpGuard,
    _ipv6_guard: crate::loopback::LoopbackUdpGuard,
    records: Arc<Mutex<HashMap<SocketAddr, ServerRecord>>>,
    output: Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

#[async_trait]
impl UdpSocketLike for XicmpServer {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if payload.len() + ICMP_HEADER > MAX_PACKET {
            return Err(invalid("xicmp server reply exceeds packet limit"));
        }
        let synthetic = parse_synthetic_address(target, port)?;
        let record = {
            let mut records = self.records.lock().await;
            records.retain(|_, record| record.last.elapsed() < Duration::from_secs(60));
            let record = records
                .get_mut(&synthetic)
                .ok_or_else(|| invalid(format!("unknown xicmp client `{synthetic}`")))?;
            record.last = Instant::now();
            record.clone()
        };
        let wire = encode_echo(
            record.family.reply_type(),
            record.id,
            record.sequence,
            payload,
        );
        send_server_reply(
            match record.family {
                IpFamily::V4 => &self.ipv4,
                IpFamily::V6 => &self.ipv6,
            },
            &wire,
            record.source,
            record.destination,
        )
        .await?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<SocketAddr>)> {
        let (packet, source) = self
            .output
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if packet.len() > output.len() {
            return Err(invalid(format!(
                "xicmp decoded packet is {} bytes, buffer is {}",
                packet.len(),
                output.len()
            )));
        }
        output[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), Some(source)))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    async fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            for task in self.tasks.lock().await.drain(..) {
                task.abort();
            }
        }
        self.inner.close().await
    }
}

fn spawn_server_receiver(
    socket: Arc<tokio::net::UdpSocket>,
    family: IpFamily,
    allowed_ips: HashSet<IpAddr>,
    records: Arc<Mutex<HashMap<SocketAddr, ServerRecord>>>,
    output: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    closed: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0; MAX_PACKET + 64];
        while !closed.load(Ordering::Acquire) {
            let (length, source, destination) =
                match recv_server_request(&socket, &mut buffer, family).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(%error, ?family, "xicmp server receive failed");
                        return;
                    }
                };
            if !allowed_ips.is_empty() && !allowed_ips.contains(&source.ip()) {
                continue;
            }
            let request = match decode_server_request(&buffer[..length], family == IpFamily::V6) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let synthetic = client_id_to_address(request.client_id);
            {
                let mut records = records.lock().await;
                records.retain(|_, record| record.last.elapsed() < Duration::from_secs(60));
                if records.len() >= 4096 && !records.contains_key(&synthetic) {
                    continue;
                }
                records.insert(
                    synthetic,
                    ServerRecord {
                        source,
                        destination,
                        family,
                        id: request.id,
                        sequence: request.sequence,
                        last: Instant::now(),
                    },
                );
            }
            if output.try_send((request.payload, synthetic)).is_err() {
                continue;
            }
        }
    })
}

fn client_id_to_address(client_id: [u8; CLIENT_ID]) -> SocketAddr {
    let mut octets = [0; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[8..].copy_from_slice(&client_id);
    SocketAddr::new(Ipv6Addr::from(octets).into(), 0)
}

fn parse_synthetic_address(target: &str, port: u16) -> io::Result<SocketAddr> {
    let ip = normalize_host(target)
        .parse::<IpAddr>()
        .map_err(|_| invalid(format!("invalid xicmp client address `{target}`")))?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(not(target_os = "linux"))]
async fn recv_server_request(
    socket: &tokio::net::UdpSocket,
    output: &mut [u8],
    _family: IpFamily,
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let (length, source) = socket.recv_from(output).await?;
    Ok((length, source, None))
}

#[cfg(not(target_os = "linux"))]
async fn send_server_reply(
    socket: &tokio::net::UdpSocket,
    packet: &[u8],
    target: SocketAddr,
    _source: Option<IpAddr>,
) -> io::Result<usize> {
    socket.send_to(packet, target).await
}

#[cfg(target_os = "linux")]
fn enable_destination_control(socket: &Socket, ipv6: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let value: libc::c_int = 1;
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
async fn recv_server_request(
    socket: &tokio::net::UdpSocket,
    output: &mut [u8],
    family: IpFamily,
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    use std::os::fd::AsRawFd;

    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_with_destination(socket.as_raw_fd(), output, family)
        }) {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn recvmsg_with_destination(
    fd: std::os::fd::RawFd,
    output: &mut [u8],
    family: IpFamily,
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut control = [0u8; 128];
    let mut iovec = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_name = address.as_mut_ptr().cast();
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let length = unsafe { libc::recvmsg(fd, &mut message, 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = unsafe { address.assume_init() };
    let source = sockaddr_to_socket_addr(&address)?;
    let mut destination = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let control_header = unsafe { &*header };
        if family == IpFamily::V4
            && control_header.cmsg_level == libc::IPPROTO_IP
            && control_header.cmsg_type == libc::IP_PKTINFO
            && control_header.cmsg_len
                >= unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as _) } as usize
        {
            let info = unsafe { &*(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>()) };
            destination = Some(IpAddr::V4(Ipv4Addr::from(
                info.ipi_addr.s_addr.to_ne_bytes(),
            )));
        } else if family == IpFamily::V6
            && control_header.cmsg_level == libc::IPPROTO_IPV6
            && control_header.cmsg_type == libc::IPV6_PKTINFO
            && control_header.cmsg_len
                >= unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) } as usize
        {
            let info = unsafe { &*(libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>()) };
            destination = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    Ok((length as usize, source, destination))
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socket_addr(address: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match i32::from(address.ss_family) {
        libc::AF_INET => {
            let address = unsafe { &*(address as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            ))
        }
        family => Err(invalid(format!(
            "xicmp recvmsg returned unsupported address family {family}"
        ))),
    }
}

#[cfg(target_os = "linux")]
async fn send_server_reply(
    socket: &tokio::net::UdpSocket,
    packet: &[u8],
    target: SocketAddr,
    source: Option<IpAddr>,
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let Some(source) = source else {
        return socket.send_to(packet, target).await;
    };
    loop {
        socket.writable().await?;
        match socket.try_io(tokio::io::Interest::WRITABLE, || {
            sendmsg_from_source(socket.as_raw_fd(), packet, target, source)
        }) {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn sendmsg_from_source(
    fd: std::os::fd::RawFd,
    packet: &[u8],
    target: SocketAddr,
    source: IpAddr,
) -> io::Result<usize> {
    if target.is_ipv4() != source.is_ipv4() {
        return Err(invalid("xicmp reply source/target address family mismatch"));
    }
    let target = SockAddr::from(target);
    let control_size = if source.is_ipv4() {
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as _) as usize }
    } else {
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as _) as usize }
    };
    let mut control = vec![0u8; control_size];
    let mut iovec = libc::iovec {
        iov_base: packet.as_ptr().cast_mut().cast(),
        iov_len: packet.len(),
    };
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_name = target.as_ptr().cast_mut().cast();
    message.msg_namelen = target.len();
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(io::Error::other("failed to allocate xicmp control message"));
    }
    match source {
        IpAddr::V4(source) => unsafe {
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = libc::IP_PKTINFO;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as _) as usize;
            let info = libc::CMSG_DATA(header).cast::<libc::in_pktinfo>();
            *info = std::mem::zeroed();
            (*info).ipi_spec_dst.s_addr = u32::from_ne_bytes(source.octets());
        },
        IpAddr::V6(source) => unsafe {
            (*header).cmsg_level = libc::IPPROTO_IPV6;
            (*header).cmsg_type = libc::IPV6_PKTINFO;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) as usize;
            let info = libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>();
            *info = std::mem::zeroed();
            (*info).ipi6_addr.s6_addr = source.octets();
        },
    }
    let length = unsafe { libc::sendmsg(fd, &message, 0) };
    if length < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(length as usize)
    }
}

fn open_icmp_socket(
    ipv6: bool,
    dgram: bool,
    receive_destination: bool,
) -> io::Result<(
    Arc<tokio::net::UdpSocket>,
    crate::loopback::LoopbackUdpGuard,
)> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let kind = if dgram { Type::DGRAM } else { Type::RAW };
    let protocol = if ipv6 {
        Protocol::ICMPV6
    } else {
        Protocol::ICMPV4
    };
    let socket = Socket::new(domain, kind, Some(protocol))?;
    if ipv6 {
        socket.set_only_v6(true)?;
    }
    #[cfg(target_os = "linux")]
    if receive_destination {
        enable_destination_control(&socket, ipv6)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = receive_destination;
    socket.bind(&SockAddr::from(if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }))?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    // ICMP is still an outbound IP socket and must traverse the same protector,
    // mark and interface binding chain as UDP carriers.
    let guard = crate::adapter::prepare_outbound_udp_socket(&socket)?;
    Ok((Arc::new(tokio::net::UdpSocket::from_std(socket)?), guard))
}

struct XicmpClient {
    inner: BoxedUdp,
    ipv4: Arc<tokio::net::UdpSocket>,
    ipv6: Arc<tokio::net::UdpSocket>,
    // Registration is scoped to the lifetime of the ICMP carrier. Dropping it
    // when the socket was created would make TUN self-capture detection blind.
    _ipv4_guard: crate::loopback::LoopbackUdpGuard,
    _ipv6_guard: crate::loopback::LoopbackUdpGuard,
    ips: Vec<IpAddr>,
    remote: Option<SocketAddr>,
    client_id: [u8; CLIENT_ID],
    id: u16,
    sequence: Arc<AtomicU16>,
    output: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

#[async_trait]
impl UdpSocketLike for XicmpClient {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> io::Result<usize> {
        if payload.len() + ICMP_HEADER + CLIENT_ID > MAX_PACKET {
            return Err(invalid(format!(
                "xicmp packet is {} bytes; maximum payload is {}",
                payload.len(),
                MAX_PACKET - ICMP_HEADER - CLIENT_ID
            )));
        }
        let ip = if let Some(ip) = self.ips.choose(&mut rand::thread_rng()) {
            *ip
        } else if let Some(remote) = self.remote {
            remote.ip()
        } else {
            normalize_host(target)
                .parse::<IpAddr>()
                .map_err(|_| invalid(format!("xicmp target `{target}:{port}` is unresolved")))?
        };
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);
        let mut data = Vec::with_capacity(CLIENT_ID + payload.len());
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(payload);
        let family = if ip.is_ipv4() {
            IpFamily::V4
        } else {
            IpFamily::V6
        };
        let wire = encode_echo(family.request_type(), self.id, sequence, &data);
        let address = SocketAddr::new(ip, 0);
        match family {
            IpFamily::V4 => self.ipv4.send_to(&wire, address).await?,
            IpFamily::V6 => self.ipv6.send_to(&wire, address).await?,
        };
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .output
            .lock()
            .await
            .recv()
            .await
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        if packet.len() > output.len() {
            return Err(invalid(format!(
                "xicmp decoded packet is {} bytes, buffer is {}",
                packet.len(),
                output.len()
            )));
        }
        output[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    async fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            for task in self.tasks.lock().await.drain(..) {
                task.abort();
            }
        }
        self.inner.close().await
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_receiver(
    socket: Arc<tokio::net::UdpSocket>,
    family: IpFamily,
    dgram: bool,
    id: u16,
    client_id: [u8; CLIENT_ID],
    sequence: Arc<AtomicU16>,
    closed: Arc<AtomicBool>,
    output: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0; MAX_PACKET + 64];
        while !closed.load(Ordering::Acquire) {
            let (length, _) = match socket.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(error) => {
                    tracing::debug!(%error, ?family, "xicmp receive failed");
                    return;
                }
            };
            let echo = match decode_echo(&buffer[..length], family) {
                Ok(echo) if echo.kind == family.reply_type() => echo,
                _ => continue,
            };
            if !dgram && echo.id != id {
                continue;
            }
            if sequence_distance(echo.sequence, sequence.load(Ordering::Acquire)) > SEQUENCE_WINDOW
            {
                continue;
            }
            if echo.data.len() > CLIENT_ID && echo.data[..CLIENT_ID] == client_id {
                // Raw sockets can observe our own echo request.
                continue;
            }
            if output.send(echo.data.to_vec()).await.is_err() {
                return;
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    const fn request_type(self) -> u8 {
        match self {
            Self::V4 => 8,
            Self::V6 => 128,
        }
    }

    const fn reply_type(self) -> u8 {
        match self {
            Self::V4 => 0,
            Self::V6 => 129,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct EchoPacket<'a> {
    kind: u8,
    id: u16,
    sequence: u16,
    data: &'a [u8],
}

fn encode_echo(kind: u8, id: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut output = vec![0; ICMP_HEADER + data.len()];
    output[0] = kind;
    output[4..6].copy_from_slice(&id.to_be_bytes());
    output[6..8].copy_from_slice(&sequence.to_be_bytes());
    output[8..].copy_from_slice(data);
    if matches!(kind, 0 | 8) {
        let checksum = internet_checksum(&output);
        output[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    output
}

fn decode_echo(mut wire: &[u8], family: IpFamily) -> io::Result<EchoPacket<'_>> {
    // Linux IPv4 SOCK_RAW may include the IPv4 header, whereas ping sockets and
    // IPv6 raw sockets expose the ICMP message directly.
    if family == IpFamily::V4 && wire.first().is_some_and(|byte| byte >> 4 == 4) {
        let header = usize::from(wire[0] & 0x0f) * 4;
        if header < 20 || wire.len() < header {
            return Err(invalid("xicmp IPv4 header is truncated"));
        }
        wire = &wire[header..];
    }
    if wire.len() < ICMP_HEADER {
        return Err(invalid("xicmp echo header is truncated"));
    }
    Ok(EchoPacket {
        kind: wire[0],
        id: u16::from_be_bytes([wire[4], wire[5]]),
        sequence: u16::from_be_bytes([wire[6], wire[7]]),
        data: &wire[8..],
    })
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn sequence_distance(left: u16, right: u16) -> u16 {
    left.wrapping_sub(right).min(right.wrapping_sub(left))
}

fn normalize_host(host: &str) -> &str {
    host.trim()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| host.trim())
}

/// Server-side request state. The inbound raw socket records this by synthetic
/// client ID and reuses the exact echo id/sequence for its reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerRequest {
    pub(crate) client_id: [u8; CLIENT_ID],
    pub(crate) id: u16,
    pub(crate) sequence: u16,
    pub(crate) payload: Vec<u8>,
    family: IpFamily,
}

pub(crate) fn decode_server_request(wire: &[u8], family_v6: bool) -> io::Result<ServerRequest> {
    let family = if family_v6 {
        IpFamily::V6
    } else {
        IpFamily::V4
    };
    let echo = decode_echo(wire, family)?;
    if echo.kind != family.request_type() || echo.data.len() <= CLIENT_ID {
        return Err(invalid("xicmp server request is not a client echo"));
    }
    let mut client_id = [0; CLIENT_ID];
    client_id.copy_from_slice(&echo.data[..CLIENT_ID]);
    Ok(ServerRequest {
        client_id,
        id: echo.id,
        sequence: echo.sequence,
        payload: echo.data[CLIENT_ID..].to_vec(),
        family,
    })
}

pub(crate) fn encode_server_reply(request: &ServerRequest, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() + ICMP_HEADER > MAX_PACKET {
        return Err(invalid("xicmp server reply exceeds packet limit"));
    }
    Ok(encode_echo(
        request.family.reply_type(),
        request.id,
        request.sequence,
        payload,
    ))
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_client_server_wire_roundtrip_and_checksum() {
        let id = *b"abcdefgh";
        let mut data = id.to_vec();
        data.extend_from_slice(b"quic packet");
        let request = encode_echo(8, 0xabcd, 7, &data);
        assert_eq!(internet_checksum(&request), 0);
        let server = decode_server_request(&request, false).unwrap();
        assert_eq!(server.client_id, id);
        assert_eq!(server.payload, b"quic packet");
        let reply = encode_server_reply(&server, b"response").unwrap();
        assert_eq!(internet_checksum(&reply), 0);
        assert_eq!(decode_echo(&reply, IpFamily::V4).unwrap().data, b"response");
    }

    #[test]
    fn ipv6_client_server_wire_roundtrip() {
        let mut data = b"12345678".to_vec();
        data.extend_from_slice(b"payload");
        let request = encode_echo(128, 42, 65535, &data);
        let server = decode_server_request(&request, true).unwrap();
        assert_eq!(server.payload, b"payload");
        let reply = encode_server_reply(&server, b"answer").unwrap();
        let echo = decode_echo(&reply, IpFamily::V6).unwrap();
        assert_eq!((echo.kind, echo.id, echo.sequence), (129, 42, 65535));
        assert_eq!(echo.data, b"answer");
    }

    #[test]
    fn sequence_window_handles_u16_wrap_and_malformed_packets() {
        assert_eq!(sequence_distance(2, 65534), 4);
        assert!(sequence_distance(2000, 0) > SEQUENCE_WINDOW);
        assert!(decode_server_request(&[8, 0], false).is_err());
        assert!(decode_server_request(&encode_echo(8, 1, 1, b"12345678"), false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_pktinfo_receives_destination_and_selects_reply_source() {
        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        enable_destination_control(&raw, false).unwrap();
        raw.bind(&SockAddr::from(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
        raw.set_nonblocking(true).unwrap();
        let server_addr = raw.local_addr().unwrap().as_socket().unwrap();
        let raw: std::net::UdpSocket = raw.into();
        let server = tokio::net::UdpSocket::from_std(raw).unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"request", server_addr).await.unwrap();

        let mut request = [0u8; 32];
        let (length, source, destination) =
            recv_server_request(&server, &mut request, IpFamily::V4)
                .await
                .unwrap();
        assert_eq!(&request[..length], b"request");
        assert_eq!(destination, Some("127.0.0.1".parse().unwrap()));
        send_server_reply(&server, b"reply", source, destination)
            .await
            .unwrap();
        let mut reply = [0u8; 32];
        let (length, reply_source) = client.recv_from(&mut reply).await.unwrap();
        assert_eq!(&reply[..length], b"reply");
        assert_eq!(reply_source, server_addr);
    }
}
