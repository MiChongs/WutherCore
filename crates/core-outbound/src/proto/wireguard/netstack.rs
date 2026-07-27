use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};

use futures::future::poll_fn;
use parking_lot::Mutex;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    storage::PacketMetadata,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

use super::{config::WireGuardConfig, io_err};

const FIRST_EPHEMERAL_PORT: u16 = 1_024;
const LAST_EPHEMERAL_PORT: u16 = u16::MAX;
const MAX_IP_PACKET: usize = 65_535;
const IPV6_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct VirtualDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
    queue_limit: usize,
}

impl VirtualDevice {
    fn new(mtu: usize, queue_limit: usize) -> Self {
        // smoltcp 0.11 advances IPv4 fragment offsets in octets but rounds the
        // encoded offset down to 8-byte units. Reporting an IP MTU whose
        // (mtu - 20) is aligned prevents overlapping fragments for arbitrary
        // configured WireGuard MTUs; the public MTU remains unchanged.
        let mtu = mtu - ((mtu - 4) % 8);
        Self {
            rx: VecDeque::with_capacity(queue_limit.min(1_024)),
            tx: VecDeque::with_capacity(queue_limit.min(1_024)),
            mtu,
            queue_limit,
        }
    }

    fn inject(&mut self, packet: Vec<u8>) -> std::io::Result<()> {
        if packet.len() > MAX_IP_PACKET {
            return Err(io_err("wireguard plaintext IP packet exceeds 65535 bytes"));
        }
        if self.rx.len() >= self.queue_limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "wireguard plaintext receive queue is full",
            ));
        }
        self.rx.push_back(packet);
        Ok(())
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Ipv6FragmentKey {
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
    next_header: u8,
}

struct Ipv6Assembly {
    prefix: Vec<u8>,
    next_header_field: usize,
    next_header: u8,
    data: Vec<u8>,
    received: Vec<bool>,
    total: Option<usize>,
    received_bytes: usize,
    updated: StdInstant,
}

struct Ipv6Reassembler {
    entries: HashMap<Ipv6FragmentKey, Ipv6Assembly>,
    max_entries: usize,
}

impl Ipv6Reassembler {
    fn new(packet_queue: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: (packet_queue / 16).clamp(4, 64),
        }
    }

    fn process(&mut self, packet: Vec<u8>) -> std::io::Result<Option<Vec<u8>>> {
        let Some(fragment) = parse_ipv6_fragment(&packet)? else {
            return Ok(Some(packet));
        };
        if fragment.offset == 0 && !fragment.more {
            return reassemble_atomic_ipv6(&packet, fragment).map(Some);
        }
        if fragment.more && (fragment.data.len() % 8 != 0 || fragment.data.is_empty()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wireguard IPv6 non-final fragment payload is not 8-byte aligned",
            ));
        }
        let end = fragment
            .offset
            .checked_add(fragment.data.len())
            .filter(|end| fragment.prefix_len + *end <= MAX_IP_PACKET)
            .ok_or_else(|| io_err("wireguard IPv6 fragment exceeds packet size limit"))?;
        self.entries
            .retain(|_, entry| entry.updated.elapsed() < IPV6_REASSEMBLY_TIMEOUT);
        if !self.entries.contains_key(&fragment.key) {
            if self.entries.len() >= self.max_entries
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.updated)
                    .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
            let mut prefix = packet[..fragment.prefix_len].to_vec();
            prefix[4..6].fill(0);
            self.entries.insert(
                fragment.key.clone(),
                Ipv6Assembly {
                    prefix,
                    next_header_field: fragment.next_header_field,
                    next_header: fragment.key.next_header,
                    data: Vec::new(),
                    received: Vec::new(),
                    total: None,
                    received_bytes: 0,
                    updated: StdInstant::now(),
                },
            );
        }
        let mut invalid = None;
        let complete = {
            let entry = self
                .entries
                .get_mut(&fragment.key)
                .expect("IPv6 assembly inserted above");
            let mut prefix = packet[..fragment.prefix_len].to_vec();
            prefix[4..6].fill(0);
            if entry.prefix != prefix
                || entry.next_header_field != fragment.next_header_field
                || entry.next_header != fragment.key.next_header
            {
                invalid = Some("wireguard IPv6 fragments disagree on unfragmentable headers");
                false
            } else if fragment.offset < entry.received.len().min(end)
                && entry.received[fragment.offset..entry.received.len().min(end)]
                    .iter()
                    .any(|received| *received)
            {
                invalid = Some("wireguard IPv6 fragment overlap rejected");
                false
            } else if entry.total.is_some_and(|total| end > total) {
                invalid = Some("wireguard IPv6 fragment extends beyond final fragment");
                false
            } else {
                entry.data.resize(entry.data.len().max(end), 0);
                entry.received.resize(entry.received.len().max(end), false);
                entry.data[fragment.offset..end].copy_from_slice(fragment.data);
                entry.received[fragment.offset..end].fill(true);
                entry.received_bytes += fragment.data.len();
                entry.updated = StdInstant::now();
                if !fragment.more {
                    if entry.total.is_some_and(|total| total != end)
                        || entry.received[end..].iter().any(|received| *received)
                    {
                        invalid = Some("wireguard IPv6 fragments contain conflicting final sizes");
                    } else {
                        entry.total = Some(end);
                    }
                }
                entry
                    .total
                    .is_some_and(|total| entry.received_bytes == total)
            }
        };
        if let Some(message) = invalid {
            self.entries.remove(&fragment.key);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            ));
        }
        if !complete {
            return Ok(None);
        }
        let entry = self
            .entries
            .remove(&fragment.key)
            .expect("complete IPv6 assembly exists");
        let total = entry.total.expect("complete assembly has final size");
        let mut packet = entry.prefix;
        packet[entry.next_header_field] = entry.next_header;
        packet.extend_from_slice(&entry.data[..total]);
        let payload_len = packet.len() - 40;
        packet[4..6].copy_from_slice(
            &u16::try_from(payload_len)
                .map_err(|_| io_err("wireguard reassembled IPv6 payload length overflow"))?
                .to_be_bytes(),
        );
        Ok(Some(packet))
    }
}

struct ParsedIpv6Fragment<'a> {
    key: Ipv6FragmentKey,
    prefix_len: usize,
    next_header_field: usize,
    offset: usize,
    more: bool,
    data: &'a [u8],
}

fn parse_ipv6_fragment(packet: &[u8]) -> std::io::Result<Option<ParsedIpv6Fragment<'_>>> {
    if packet.first().map(|byte| byte >> 4) != Some(6) {
        return Ok(None);
    }
    if packet.len() < 40 {
        return Err(io_err(
            "wireguard IPv6 packet is shorter than its base header",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len == 0 || payload_len + 40 != packet.len() {
        return Err(io_err(
            "wireguard IPv6 packet has an invalid payload length",
        ));
    }
    let mut next_header = packet[6];
    let mut next_header_field = 6usize;
    let mut cursor = 40usize;
    loop {
        if next_header == 44 {
            if cursor + 8 > packet.len() {
                return Err(io_err("wireguard IPv6 fragment header is truncated"));
            }
            if packet[cursor + 1] != 0 {
                return Err(io_err("wireguard IPv6 fragment reserved byte is non-zero"));
            }
            let offset_flags = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
            if offset_flags & 0x0006 != 0 {
                return Err(io_err("wireguard IPv6 fragment reserved bits are non-zero"));
            }
            return Ok(Some(ParsedIpv6Fragment {
                key: Ipv6FragmentKey {
                    source: packet[8..24]
                        .try_into()
                        .expect("IPv6 source length checked"),
                    destination: packet[24..40]
                        .try_into()
                        .expect("IPv6 destination length checked"),
                    identification: u32::from_be_bytes(
                        packet[cursor + 4..cursor + 8]
                            .try_into()
                            .expect("fragment id length checked"),
                    ),
                    next_header: packet[cursor],
                },
                prefix_len: cursor,
                next_header_field,
                offset: usize::from(offset_flags & 0xfff8),
                more: offset_flags & 1 != 0,
                data: &packet[cursor + 8..],
            }));
        }
        if !matches!(next_header, 0 | 43 | 60) {
            return Ok(None);
        }
        if cursor + 2 > packet.len() {
            return Err(io_err("wireguard IPv6 extension header is truncated"));
        }
        let length = (usize::from(packet[cursor + 1]) + 1) * 8;
        if cursor + length > packet.len() {
            return Err(io_err("wireguard IPv6 extension header length is invalid"));
        }
        next_header_field = cursor;
        next_header = packet[cursor];
        cursor += length;
    }
}

fn reassemble_atomic_ipv6(
    packet: &[u8],
    fragment: ParsedIpv6Fragment<'_>,
) -> std::io::Result<Vec<u8>> {
    let mut reassembled = packet[..fragment.prefix_len].to_vec();
    reassembled[fragment.next_header_field] = fragment.key.next_header;
    reassembled.extend_from_slice(fragment.data);
    let payload_len = reassembled.len() - 40;
    reassembled[4..6].copy_from_slice(
        &u16::try_from(payload_len)
            .map_err(|_| io_err("wireguard atomic IPv6 payload length overflow"))?
            .to_be_bytes(),
    );
    Ok(reassembled)
}

struct VirtualRxToken {
    packet: Vec<u8>,
}

struct VirtualTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.packet)
    }
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.tx.push_back(packet);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx.len() >= self.queue_limit {
            return None;
        }
        let packet = self.rx.pop_front()?;
        Some((
            VirtualRxToken { packet },
            VirtualTxToken { tx: &mut self.tx },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.tx.len() < self.queue_limit).then_some(VirtualTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

struct StackState {
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    handles: HashSet<SocketHandle>,
    ports: HashSet<u16>,
    next_port: u16,
    tcp_count: usize,
    udp_count: usize,
    max_tcp_sessions: usize,
    max_udp_sessions: usize,
    tcp_buffer_size: usize,
    udp_buffer_size: usize,
    local_v4: Option<IpAddr>,
    local_v6: Option<IpAddr>,
    ipv6_reassembly: Ipv6Reassembler,
}

impl StackState {
    fn new(config: &WireGuardConfig) -> std::io::Result<Self> {
        let mut device = VirtualDevice::new(config.mtu, config.packet_queue);
        let interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        let mut interface = Interface::new(interface_config, &mut device, smol_now());
        let mut local_v4 = None;
        let mut local_v6 = None;
        interface.update_ip_addrs(|addresses| {
            for address in &config.local_addresses {
                let ip = address.addr();
                let cidr = IpCidr::new(to_smol_ip(ip), address.prefix_len());
                addresses
                    .push(cidr)
                    .expect("wireguard local address count validated against smoltcp capacity");
                match ip {
                    IpAddr::V4(_) if local_v4.is_none() => local_v4 = Some(ip),
                    IpAddr::V6(_) if local_v6.is_none() => local_v6 = Some(ip),
                    _ => {}
                }
            }
        });
        if let Some(IpAddr::V4(ip)) = local_v4 {
            interface
                .routes_mut()
                .add_default_ipv4_route(ip.into())
                .map_err(|_| io_err("wireguard smoltcp IPv4 route table is full"))?;
        }
        if let Some(IpAddr::V6(ip)) = local_v6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(ip.into())
                .map_err(|_| io_err("wireguard smoltcp IPv6 route table is full"))?;
        }

        Ok(Self {
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            handles: HashSet::new(),
            ports: HashSet::new(),
            next_port: FIRST_EPHEMERAL_PORT,
            tcp_count: 0,
            udp_count: 0,
            max_tcp_sessions: config.max_tcp_sessions,
            max_udp_sessions: config.max_udp_sessions,
            tcp_buffer_size: config.tcp_buffer_size,
            udp_buffer_size: config.udp_buffer_size,
            local_v4,
            local_v6,
            ipv6_reassembly: Ipv6Reassembler::new(config.packet_queue),
        })
    }

    fn allocate_port(&mut self) -> std::io::Result<u16> {
        let attempts = usize::from(LAST_EPHEMERAL_PORT - FIRST_EPHEMERAL_PORT) + 1;
        for _ in 0..attempts {
            let port = self.next_port;
            self.next_port = if port == LAST_EPHEMERAL_PORT {
                FIRST_EPHEMERAL_PORT
            } else {
                port + 1
            };
            if self.ports.insert(port) {
                return Ok(port);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "wireguard virtual ephemeral port range is exhausted",
        ))
    }

    fn source_for(&self, target: IpAddr) -> std::io::Result<IpAddr> {
        match target {
            IpAddr::V4(_) => self.local_v4,
            IpAddr::V6(_) => self.local_v6,
        }
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("wireguard has no local address for target family {target}"),
            )
        })
    }

    fn open_tcp(
        &mut self,
        target: SocketAddr,
        notify: Arc<Notify>,
        shared: Arc<StackShared>,
    ) -> std::io::Result<WireGuardTcpStream> {
        if self.tcp_count >= self.max_tcp_sessions {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "wireguard maximum TCP session count reached",
            ));
        }
        let source = self.source_for(target.ip())?;
        let port = self.allocate_port()?;
        let rx = tcp::SocketBuffer::new(vec![0; self.tcp_buffer_size]);
        let tx = tcp::SocketBuffer::new(vec![0; self.tcp_buffer_size]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_nagle_enabled(false);
        if let Err(error) = socket.connect(
            self.interface.context(),
            IpEndpoint::new(to_smol_ip(target.ip()), target.port()),
            IpEndpoint::new(to_smol_ip(source), port),
        ) {
            self.ports.remove(&port);
            return Err(io_err(format!(
                "wireguard TCP connect setup failed: {error:?}"
            )));
        }
        let handle = self.sockets.add(socket);
        self.handles.insert(handle);
        self.tcp_count += 1;
        Ok(WireGuardTcpStream {
            lease: Arc::new(SocketLease::new(
                shared,
                handle,
                port,
                SocketKind::Tcp,
                Duration::MAX,
            )),
            notify,
            shutdown_epoch: None,
        })
    }

    fn open_udp(
        &mut self,
        target: SocketAddr,
        original_host: String,
        idle_timeout: Duration,
        notify: Arc<Notify>,
        shared: Arc<StackShared>,
    ) -> std::io::Result<WireGuardUdpSocket> {
        if self.udp_count >= self.max_udp_sessions {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "wireguard maximum UDP session count reached",
            ));
        }
        let source = self.source_for(target.ip())?;
        let port = self.allocate_port()?;
        let metadata_capacity = (self.udp_buffer_size / 512).clamp(16, 4_096);
        let rx = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; self.udp_buffer_size],
        );
        let tx = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; self.udp_buffer_size],
        );
        let mut socket = udp::Socket::new(rx, tx);
        if let Err(error) = socket.bind(IpListenEndpoint {
            addr: Some(to_smol_ip(source)),
            port,
        }) {
            self.ports.remove(&port);
            return Err(io_err(format!("wireguard UDP bind failed: {error:?}")));
        }
        let handle = self.sockets.add(socket);
        self.handles.insert(handle);
        self.udp_count += 1;
        let lease = Arc::new(SocketLease::new(
            shared,
            handle,
            port,
            SocketKind::Udp,
            idle_timeout,
        ));
        spawn_idle_reaper(Arc::downgrade(&lease), notify.clone());
        Ok(WireGuardUdpSocket {
            lease,
            notify,
            target,
            original_host,
        })
    }

    fn remove(&mut self, handle: SocketHandle, port: u16, kind: SocketKind) {
        if !self.handles.remove(&handle) {
            return;
        }
        let _ = self.sockets.remove(handle);
        self.ports.remove(&port);
        match kind {
            SocketKind::Tcp => self.tcp_count = self.tcp_count.saturating_sub(1),
            SocketKind::Udp => self.udp_count = self.udp_count.saturating_sub(1),
        }
    }

    fn poll(&mut self) {
        let _ = self
            .interface
            .poll(smol_now(), &mut self.device, &mut self.sockets);
    }
}

pub(super) struct StackShared {
    state: Mutex<StackState>,
    notify: Arc<Notify>,
    epoch: AtomicU64,
}

impl StackShared {
    pub(super) fn new(config: &WireGuardConfig) -> std::io::Result<Arc<Self>> {
        let notify = Arc::new(Notify::new());
        let state = StackState::new(config)?;
        Ok(Arc::new(Self {
            state: Mutex::new(state),
            notify,
            epoch: AtomicU64::new(0),
        }))
    }

    pub(super) fn notify(&self) {
        self.notify.notify_one();
    }

    pub(super) async fn notified(&self) {
        self.notify.notified().await;
    }

    pub(super) fn inject(&self, packet: Vec<u8>) -> std::io::Result<()> {
        let mut state = self.state.lock();
        let result = match state.ipv6_reassembly.process(packet)? {
            Some(packet) => state.device.inject(packet),
            None => Ok(()),
        };
        drop(state);
        self.notify();
        result
    }

    pub(super) fn poll_and_drain(&self) -> Vec<Vec<u8>> {
        let mut state = self.state.lock();
        state.poll();
        let packets = state.device.drain_tx();
        self.epoch.fetch_add(1, Ordering::Release);
        packets
    }

    pub(super) fn open_tcp(
        self: &Arc<Self>,
        target: SocketAddr,
    ) -> std::io::Result<WireGuardTcpStream> {
        self.state
            .lock()
            .open_tcp(target, self.notify.clone(), self.clone())
    }

    pub(super) fn open_udp(
        self: &Arc<Self>,
        target: SocketAddr,
        original_host: String,
        idle_timeout: Duration,
    ) -> std::io::Result<WireGuardUdpSocket> {
        self.state.lock().open_udp(
            target,
            original_host,
            idle_timeout,
            self.notify.clone(),
            self.clone(),
        )
    }

    #[cfg(test)]
    pub(super) fn open_echo_services(
        &self,
        tcp_port: u16,
        udp_port: u16,
    ) -> std::io::Result<EchoServices> {
        let mut state = self.state.lock();
        let tcp_rx = tcp::SocketBuffer::new(vec![0; state.tcp_buffer_size]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; state.tcp_buffer_size]);
        let mut tcp_socket = tcp::Socket::new(tcp_rx, tcp_tx);
        tcp_socket
            .listen(tcp_port)
            .map_err(|error| io_err(format!("wireguard test TCP listen failed: {error:?}")))?;
        let tcp = state.sockets.add(tcp_socket);

        let metadata_capacity = (state.udp_buffer_size / 512).clamp(16, 4_096);
        let udp_rx = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; state.udp_buffer_size],
        );
        let udp_tx = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY; metadata_capacity],
            vec![0; state.udp_buffer_size],
        );
        let mut udp_socket = udp::Socket::new(udp_rx, udp_tx);
        udp_socket
            .bind(udp_port)
            .map_err(|error| io_err(format!("wireguard test UDP listen failed: {error:?}")))?;
        let udp = state.sockets.add(udp_socket);

        let dns_rx = udp::PacketBuffer::new(vec![PacketMetadata::EMPTY; 32], vec![0; 64 * 1024]);
        let dns_tx = udp::PacketBuffer::new(vec![PacketMetadata::EMPTY; 32], vec![0; 64 * 1024]);
        let mut dns_socket = udp::Socket::new(dns_rx, dns_tx);
        dns_socket
            .bind(53)
            .map_err(|error| io_err(format!("wireguard test DNS listen failed: {error:?}")))?;
        let dns = state.sockets.add(dns_socket);
        Ok(EchoServices { tcp, udp, dns })
    }

    #[cfg(test)]
    pub(super) fn poll_echo_and_drain(&self, services: EchoServices) -> Vec<Vec<u8>> {
        let mut state = self.state.lock();
        state.poll();
        {
            let socket = state.sockets.get_mut::<tcp::Socket>(services.tcp);
            if socket.can_recv() && socket.can_send() {
                let available = socket.recv_queue().min(64 * 1024);
                let mut buffer = vec![0; available];
                if let Ok(received) = socket.recv_slice(&mut buffer) {
                    buffer.truncate(received);
                    if !buffer.is_empty() {
                        let _ = socket.send_slice(&buffer);
                    }
                }
            }
            if socket.state() == tcp::State::CloseWait && socket.send_queue() == 0 {
                socket.close();
            }
        }
        {
            let socket = state.sockets.get_mut::<udp::Socket>(services.udp);
            while socket.can_recv() && socket.can_send() {
                let mut buffer = vec![0; 65_535];
                let Ok((received, metadata)) = socket.recv_slice(&mut buffer) else {
                    break;
                };
                buffer.truncate(received);
                if socket.send_slice(&buffer, metadata.endpoint).is_err() {
                    break;
                }
            }
        }
        {
            let socket = state.sockets.get_mut::<udp::Socket>(services.dns);
            while socket.can_recv() && socket.can_send() {
                let mut buffer = vec![0; 65_535];
                let Ok((received, metadata)) = socket.recv_slice(&mut buffer) else {
                    break;
                };
                buffer.truncate(received);
                let Ok(response) = test_dns_response(&buffer) else {
                    continue;
                };
                if socket.send_slice(&response, metadata.endpoint).is_err() {
                    break;
                }
            }
        }
        state.poll();
        let packets = state.device.drain_tx();
        self.epoch.fetch_add(1, Ordering::Release);
        packets
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct EchoServices {
    tcp: SocketHandle,
    udp: SocketHandle,
    dns: SocketHandle,
}

#[cfg(test)]
fn test_dns_response(request: &[u8]) -> std::io::Result<Vec<u8>> {
    use hickory_proto::{
        op::{Message, MessageType, ResponseCode},
        rr::{
            RData, Record, RecordType,
            rdata::{A, AAAA},
        },
        serialize::binary::{BinDecodable, BinEncodable},
    };
    let request = Message::from_bytes(request)
        .map_err(|error| io_err(format!("test DNS request decode failed: {error}")))?;
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    for query in &request.queries {
        response.add_query(query.clone());
        let data = match query.query_type() {
            RecordType::A => Some(RData::A(A::new(10, 99, 0, 1))),
            RecordType::AAAA => Some(RData::AAAA(AAAA::new(0xfd99, 0, 0, 0, 0, 0, 0, 1))),
            _ => None,
        };
        if let Some(data) = data {
            response.add_answer(Record::from_rdata(query.name().clone(), 30, data));
        }
    }
    response
        .to_bytes()
        .map_err(|error| io_err(format!("test DNS response encode failed: {error}")))
}

struct SocketLease {
    shared: Arc<StackShared>,
    handle: SocketHandle,
    port: u16,
    kind: SocketKind,
    removed: AtomicBool,
    last_activity: Mutex<StdInstant>,
    idle_timeout: Duration,
}

impl SocketLease {
    fn new(
        shared: Arc<StackShared>,
        handle: SocketHandle,
        port: u16,
        kind: SocketKind,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            shared,
            handle,
            port,
            kind,
            removed: AtomicBool::new(false),
            last_activity: Mutex::new(StdInstant::now()),
            idle_timeout,
        }
    }

    fn touch(&self) {
        *self.last_activity.lock() = StdInstant::now();
    }

    fn remove(&self) {
        if self.removed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared
            .state
            .lock()
            .remove(self.handle, self.port, self.kind);
        self.shared.notify();
    }

    fn ensure_active(&self) -> std::io::Result<()> {
        if self.removed.load(Ordering::Acquire) {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wireguard virtual socket is closed",
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for SocketLease {
    fn drop(&mut self) {
        self.remove();
    }
}

fn spawn_idle_reaper(weak_lease: std::sync::Weak<SocketLease>, notify: Arc<Notify>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        loop {
            let Some(lease) = weak_lease.upgrade() else {
                break;
            };
            let interval = (lease.idle_timeout / 2).max(Duration::from_secs(1));
            drop(lease);
            tokio::time::sleep(interval).await;
            let Some(lease) = weak_lease.upgrade() else {
                break;
            };
            if lease.last_activity.lock().elapsed() >= lease.idle_timeout {
                lease.remove();
                notify.notify_one();
                break;
            }
        }
    });
}

pub struct WireGuardTcpStream {
    lease: Arc<SocketLease>,
    notify: Arc<Notify>,
    shutdown_epoch: Option<u64>,
}

impl WireGuardTcpStream {
    pub(super) async fn wait_connected(&mut self, timeout: Duration) -> std::io::Result<()> {
        let lease = self.lease.clone();
        let result = tokio::time::timeout(
            timeout,
            poll_fn(move |cx| {
                lease.ensure_active()?;
                let mut state = lease.shared.state.lock();
                let socket = state.sockets.get_mut::<tcp::Socket>(lease.handle);
                match socket.state() {
                    tcp::State::Established => Poll::Ready(Ok(())),
                    tcp::State::Closed | tcp::State::Closing | tcp::State::TimeWait => {
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "wireguard virtual TCP connection was refused",
                        )))
                    }
                    _ => {
                        socket.register_recv_waker(cx.waker());
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                }
            }),
        )
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.lease.remove();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "wireguard virtual TCP connect timed out",
                ))
            }
        }
    }
}

impl AsyncRead for WireGuardTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.lease.ensure_active()?;
        let mut state = self.lease.shared.state.lock();
        let socket = state.sockets.get_mut::<tcp::Socket>(self.lease.handle);
        if socket.can_recv() {
            let destination = buffer.initialize_unfilled();
            let received = socket
                .recv_slice(destination)
                .map_err(|error| io_err(format!("wireguard TCP receive failed: {error:?}")))?;
            buffer.advance(received);
            self.lease.touch();
            self.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WireGuardTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.lease.ensure_active()?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.lease.shared.state.lock();
        let socket = state.sockets.get_mut::<tcp::Socket>(self.lease.handle);
        if socket.can_send() {
            let sent = socket
                .send_slice(buffer)
                .map_err(|error| io_err(format!("wireguard TCP send failed: {error:?}")))?;
            self.lease.touch();
            self.notify.notify_one();
            return Poll::Ready(Ok(sent));
        }
        if !socket.may_send() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wireguard virtual TCP write half is closed",
            )));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.lease.ensure_active()?;
        let mut state = self.lease.shared.state.lock();
        let socket = state.sockets.get_mut::<tcp::Socket>(self.lease.handle);
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !socket.may_send() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wireguard virtual TCP connection closed before pending data was flushed",
            )));
        }
        socket.register_send_waker(cx.waker());
        self.notify.notify_one();
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.lease.ensure_active()?;
        let current_epoch = self.lease.shared.epoch.load(Ordering::Acquire);
        let initiate_shutdown = self.shutdown_epoch.is_none();
        if initiate_shutdown {
            self.shutdown_epoch = Some(current_epoch);
        }
        let (send_queue_empty, connection_closed) = {
            let mut state = self.lease.shared.state.lock();
            let socket = state.sockets.get_mut::<tcp::Socket>(self.lease.handle);
            if initiate_shutdown {
                socket.close();
            }
            socket.register_send_waker(cx.waker());
            (
                socket.send_queue() == 0,
                matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait),
            )
        };
        if connection_closed {
            return Poll::Ready(Ok(()));
        }
        if !send_queue_empty {
            // Do not report shutdown while application data is still buffered.
            // Remember the latest poll epoch with pending data so at least one
            // subsequent stack poll can emit the final data and FIN.
            self.shutdown_epoch = Some(current_epoch);
        } else if self.shutdown_epoch != Some(current_epoch) {
            return Poll::Ready(Ok(()));
        }
        self.notify.notify_one();
        Poll::Pending
    }
}

pub struct WireGuardUdpSocket {
    lease: Arc<SocketLease>,
    notify: Arc<Notify>,
    target: SocketAddr,
    original_host: String,
}

impl WireGuardUdpSocket {
    fn validate_target(&self, host: &str, port: u16) -> std::io::Result<()> {
        let same_host = host.eq_ignore_ascii_case(&self.original_host)
            || host.parse::<IpAddr>().ok() == Some(self.target.ip());
        if port != self.target.port() || !same_host {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "wireguard UDP association is fixed to {}:{}",
                    self.original_host,
                    self.target.port()
                ),
            ));
        }
        Ok(())
    }

    pub(super) async fn send_to(
        &self,
        buffer: &[u8],
        host: &str,
        port: u16,
    ) -> std::io::Result<usize> {
        self.validate_target(host, port)?;
        let max_payload = if self.target.is_ipv4() {
            65_507
        } else {
            65_487
        };
        if buffer.len() > max_payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wireguard UDP payload exceeds the IP protocol maximum",
            ));
        }
        let lease = self.lease.clone();
        let target = self.target;
        poll_fn(move |cx| {
            lease.ensure_active()?;
            let mut state = lease.shared.state.lock();
            let socket = state.sockets.get_mut::<udp::Socket>(lease.handle);
            match socket.send_slice(
                buffer,
                IpEndpoint::new(to_smol_ip(target.ip()), target.port()),
            ) {
                Ok(()) => {
                    lease.touch();
                    Poll::Ready(Ok(buffer.len()))
                }
                Err(udp::SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(error) => {
                    Poll::Ready(Err(io_err(format!("wireguard UDP send failed: {error:?}"))))
                }
            }
        })
        .await
        .inspect(|_| self.notify.notify_one())
    }

    pub(super) async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let lease = self.lease.clone();
        let target = self.target;
        poll_fn(move |cx| {
            loop {
                lease.ensure_active()?;
                let mut state = lease.shared.state.lock();
                let socket = state.sockets.get_mut::<udp::Socket>(lease.handle);
                match socket.recv_slice(buffer) {
                    Ok((received, metadata)) => {
                        let source = from_smol_endpoint(metadata.endpoint);
                        if source != target {
                            continue;
                        }
                        lease.touch();
                        return Poll::Ready(Ok(received));
                    }
                    Err(udp::RecvError::Exhausted) => {
                        socket.register_recv_waker(cx.waker());
                        return Poll::Pending;
                    }
                    Err(udp::RecvError::Truncated) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "wireguard UDP receive buffer is smaller than the datagram",
                        )));
                    }
                }
            }
        })
        .await
    }

    pub(super) fn close(&self) {
        self.lease.remove();
    }
}

fn to_smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(ip) => IpAddress::Ipv4(ip.into()),
        IpAddr::V6(ip) => IpAddress::Ipv6(ip.into()),
    }
}

fn from_smol_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip.into()),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip.into()),
    };
    SocketAddr::new(ip, endpoint.port)
}

fn smol_now() -> Instant {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    Instant::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wireguard::{config::WireGuardPeerConfig, fragment::fragment_ip_packet};

    fn config() -> WireGuardConfig {
        let mut config = WireGuardConfig::new(
            [1; 32],
            WireGuardPeerConfig::new("127.0.0.1", 51_820, [2; 32]),
        );
        config.local_addresses = vec![
            "10.0.0.2/32".parse().unwrap(),
            "fd00::2/128".parse().unwrap(),
        ];
        config
    }

    fn large_ipv6_packet() -> Vec<u8> {
        let payload = (0..3_000).map(|index| index as u8).collect::<Vec<_>>();
        let mut packet = vec![0_u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = 59;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[1; 16]);
        packet[24..40].copy_from_slice(&[2; 16]);
        packet[40..].copy_from_slice(&payload);
        packet
    }

    #[test]
    fn virtual_device_applies_bounded_backpressure() {
        let mut device = VirtualDevice::new(1_420, 2);
        device.inject(vec![0x45; 40]).unwrap();
        device.inject(vec![0x45; 40]).unwrap();
        assert_eq!(
            device.inject(vec![0x45; 40]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn ipv6_reassembly_accepts_out_of_order_fragments() {
        let packet = large_ipv6_packet();
        let fragments = fragment_ip_packet(&packet, 1_280).unwrap();
        assert!(fragments.len() > 1);
        let mut reassembler = Ipv6Reassembler::new(128);
        let mut reassembled = None;
        for fragment in fragments.into_iter().rev() {
            if let Some(complete) = reassembler.process(fragment).unwrap() {
                reassembled = Some(complete);
            }
        }
        assert_eq!(reassembled.as_deref(), Some(packet.as_slice()));
        assert!(reassembler.entries.is_empty());
    }

    #[test]
    fn ipv6_reassembly_rejects_overlapping_fragments() {
        let packet = large_ipv6_packet();
        let first = fragment_ip_packet(&packet, 1_280).unwrap().remove(0);
        let mut reassembler = Ipv6Reassembler::new(128);
        assert!(reassembler.process(first.clone()).unwrap().is_none());
        let error = reassembler.process(first).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("overlap"));
        assert!(reassembler.entries.is_empty());
    }

    #[tokio::test]
    async fn stack_opens_real_tcp_and_udp_socket_handles() {
        let config = config();
        let shared = StackShared::new(&config).unwrap();
        let tcp = shared.open_tcp("10.0.0.1:80".parse().unwrap()).unwrap();
        let udp = shared
            .open_udp(
                "10.0.0.1:53".parse().unwrap(),
                "10.0.0.1".into(),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_ne!(tcp.lease.handle, udp.lease.handle);
        drop(tcp);
        udp.close();
        let state = shared.state.lock();
        assert_eq!(state.tcp_count, 0);
        assert_eq!(state.udp_count, 0);
    }

    #[tokio::test]
    async fn stack_emits_ipv6_udp_packets() {
        let config = config();
        let shared = StackShared::new(&config).unwrap();
        let udp = shared
            .open_udp(
                "[fd00::1]:53".parse().unwrap(),
                "fd00::1".into(),
                Duration::from_secs(60),
            )
            .unwrap();
        udp.send_to(&[1, 2, 3], "fd00::1", 53).await.unwrap();
        let packets = shared.poll_and_drain();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][0] >> 4, 6);
    }
}
