use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine;
use core_config::{I32Range, NoiseItemConfig, NoiseMaskConfig, UdpMaskConfig};
use rand::{Rng, RngCore};
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedUdp, UdpSocketLike};

use super::{
    header_custom::{StandaloneServerAction, UdpCustomCodec, UdpRole},
    mkcp::MkcpCodec,
    salamander::SalamanderCodec,
    sudoku,
};

const MAX_WIRE_DATAGRAM: usize = u16::MAX as usize;
const MAX_EXPANDED_PACKETS: usize = 64;
const MAX_EXPANDED_BYTES: usize = 256 * 1024;
const MAX_QUEUED_PACKETS: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_PEER_CAPACITY: usize = 4096;
const SERVER_PEER_TTL: Duration = Duration::from_secs(60);
const SERVER_PEER_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

pub(super) fn wrap_client(
    inner: BoxedUdp,
    masks: &[UdpMaskConfig],
    _target: String,
    _port: u16,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedUdp> {
    wrap(inner, masks, UdpRole::Client, local, remote)
}

pub(super) fn wrap_server(
    inner: BoxedUdp,
    masks: &[UdpMaskConfig],
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedUdp> {
    wrap(inner, masks, UdpRole::Server, local, remote)
}

fn wrap(
    inner: BoxedUdp,
    masks: &[UdpMaskConfig],
    role: UdpRole,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedUdp> {
    let (stack, server_stacks) = match role {
        UdpRole::Client => (
            Some(AsyncMutex::new(MaskStack::new(masks, role, local, remote)?)),
            None,
        ),
        UdpRole::Server => (
            None,
            Some(AsyncMutex::new(ServerMaskStacks::new(masks, local)?)),
        ),
    };
    Ok(Box::new(MaskedUdp {
        inner,
        role,
        stack,
        server_stacks,
        receive_gate: AsyncMutex::new(()),
        queued: AsyncMutex::new(VecDeque::new()),
    }))
}

struct MaskedUdp {
    inner: BoxedUdp,
    role: UdpRole,
    stack: Option<AsyncMutex<MaskStack>>,
    server_stacks: Option<AsyncMutex<ServerMaskStacks>>,
    receive_gate: AsyncMutex<()>,
    queued: AsyncMutex<VecDeque<ReceivedWire>>,
}

struct ReceivedWire {
    data: Vec<u8>,
    source: Option<SocketAddr>,
}

struct ServerMaskStacks {
    masks: Vec<UdpMaskConfig>,
    local: Option<SocketAddr>,
    peers: HashMap<SocketAddr, ServerPeerStack>,
    last_cleanup: Instant,
}

struct ServerPeerStack {
    stack: MaskStack,
    last_seen: Instant,
}

impl ServerMaskStacks {
    fn new(masks: &[UdpMaskConfig], local: Option<SocketAddr>) -> std::io::Result<Self> {
        // Compile once during listener startup so malformed masks fail before
        // the first untrusted datagram creates per-peer state.
        let _ = MaskStack::new(masks, UdpRole::Server, local, None)?;
        Ok(Self {
            masks: masks.to_vec(),
            local,
            peers: HashMap::new(),
            last_cleanup: Instant::now(),
        })
    }

    fn stack(&mut self, peer: SocketAddr) -> std::io::Result<&mut MaskStack> {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= SERVER_PEER_CLEANUP_INTERVAL {
            self.peers
                .retain(|_, state| now.duration_since(state.last_seen) < SERVER_PEER_TTL);
            self.last_cleanup = now;
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= SERVER_PEER_CAPACITY {
            let oldest = self
                .peers
                .iter()
                .min_by_key(|(_, state)| state.last_seen)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                self.peers.remove(&oldest);
            }
        }
        if !self.peers.contains_key(&peer) {
            let stack = MaskStack::new(&self.masks, UdpRole::Server, self.local, Some(peer))?;
            self.peers.insert(
                peer,
                ServerPeerStack {
                    stack,
                    last_seen: now,
                },
            );
        }
        let state = self.peers.get_mut(&peer).expect("peer inserted above");
        state.last_seen = now;
        Ok(&mut state.stack)
    }
}

enum ServerReceiveAction {
    Drop,
    Reply(Vec<u8>),
    Payload(Vec<u8>),
}

#[async_trait]
impl UdpSocketLike for MaskedUdp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        if self.role == UdpRole::Server {
            let peer = parse_server_peer(target, port)?;
            let packets = self
                .server_stacks
                .as_ref()
                .expect("server mask table")
                .lock()
                .await
                .stack(peer)?
                .encode_range(vec![EncodedPacket::new(payload.to_vec())], 0)?;
            self.send_packets(packets, target, port).await?;
            return Ok(payload.len());
        }
        self.ensure_standalone_handshakes(target, port).await?;
        let packets = self
            .stack
            .as_ref()
            .expect("client mask stack")
            .lock()
            .await
            .encode_range(vec![EncodedPacket::new(payload.to_vec())], 0)?;
        self.send_packets(packets, target, port).await?;
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> std::io::Result<usize> {
        self.recv_from_endpoint(output)
            .await
            .map(|(length, _)| length)
    }

    async fn recv_from_endpoint(
        &self,
        output: &mut [u8],
    ) -> std::io::Result<(usize, Option<SocketAddr>)> {
        if let Some(packet) = self.queued.lock().await.pop_front() {
            return copy_received(output, packet);
        }
        let _gate = self.receive_gate.lock().await;
        loop {
            let packet = self.receive_wire().await?;
            if self.role == UdpRole::Server {
                let source = packet.source.ok_or_else(|| {
                    invalid("finalmask UDP server requires a source-aware carrier")
                })?;
                let action = {
                    let mut stacks = self
                        .server_stacks
                        .as_ref()
                        .expect("server mask table")
                        .lock()
                        .await;
                    let stack = stacks.stack(source)?;
                    match stack.standalone_server_action(&packet.data)? {
                        Some(StandaloneServerAction::Drop) => ServerReceiveAction::Drop,
                        Some(StandaloneServerAction::Reply(reply)) => {
                            ServerReceiveAction::Reply(reply)
                        }
                        Some(StandaloneServerAction::Payload(payload)) => {
                            ServerReceiveAction::Payload(payload)
                        }
                        None => match stack.decode_range(packet.data, 0)? {
                            Some(payload) => ServerReceiveAction::Payload(payload),
                            None => ServerReceiveAction::Drop,
                        },
                    }
                };
                match action {
                    ServerReceiveAction::Drop => continue,
                    ServerReceiveAction::Reply(reply) => {
                        self.inner
                            .send_to(&reply, &source.ip().to_string(), source.port())
                            .await?;
                        continue;
                    }
                    ServerReceiveAction::Payload(payload) => {
                        return copy_received(
                            output,
                            ReceivedWire {
                                data: payload,
                                source: Some(source),
                            },
                        );
                    }
                }
            }
            let decoded = self
                .stack
                .as_ref()
                .expect("client mask stack")
                .lock()
                .await
                .decode_range(packet.data, 0)?;
            if let Some(decoded) = decoded {
                return copy_received(
                    output,
                    ReceivedWire {
                        data: decoded,
                        source: packet.source,
                    },
                );
            }
        }
    }

    async fn close(&self) -> std::io::Result<()> {
        self.inner.close().await
    }

    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

impl MaskedUdp {
    async fn ensure_standalone_handshakes(&self, target: &str, port: u16) -> std::io::Result<()> {
        let stack = self.stack.as_ref().expect("client mask stack");
        let indexes = stack.lock().await.standalone_indexes();
        // A generated handshake from an outer mask traverses every inner mask,
        // so authenticate inner standalone masks first.
        for index in indexes.into_iter().rev() {
            let already_established = stack.lock().await.custom_established(index)?;
            if already_established {
                continue;
            }
            let _gate = self.receive_gate.lock().await;
            let request = stack.lock().await.custom_request(index)?;
            let packets = self
                .stack
                .as_ref()
                .expect("client mask stack")
                .lock()
                .await
                .encode_range(vec![EncodedPacket::new(request)], index + 1)?;
            self.send_packets(packets, target, port).await?;
            let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
            loop {
                let wire = tokio::time::timeout_at(deadline, self.receive_wire())
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "header-custom UDP standalone handshake timed out",
                        )
                    })??;
                let ReceivedWire { data, source } = wire;
                let Some(packet) = stack.lock().await.decode_range(data, index + 1)? else {
                    continue;
                };
                if self
                    .stack
                    .as_ref()
                    .expect("client mask stack")
                    .lock()
                    .await
                    .custom_accept_response(index, &packet)?
                {
                    break;
                }
                let mut queued = self.queued.lock().await;
                if queued.len() >= MAX_QUEUED_PACKETS {
                    queued.pop_front();
                }
                queued.push_back(ReceivedWire {
                    data: packet,
                    source,
                });
            }
        }
        Ok(())
    }

    async fn send_packets(
        &self,
        packets: Vec<EncodedPacket>,
        target: &str,
        port: u16,
    ) -> std::io::Result<()> {
        for packet in packets {
            self.inner.send_to(&packet.data, target, port).await?;
            if !packet.delay_after.is_zero() {
                tokio::time::sleep(packet.delay_after).await;
            }
        }
        Ok(())
    }

    async fn receive_wire(&self) -> std::io::Result<ReceivedWire> {
        let mut buffer = vec![0; MAX_WIRE_DATAGRAM];
        let (length, source) = self.inner.recv_from_endpoint(&mut buffer).await?;
        if length > buffer.len() {
            return Err(invalid("underlying UDP socket returned an invalid length"));
        }
        buffer.truncate(length);
        Ok(ReceivedWire {
            data: buffer,
            source,
        })
    }
}

struct MaskStack {
    masks: Vec<MaskCodec>,
}

enum MaskCodec {
    HeaderCustom(UdpCustomCodec),
    Mkcp(MkcpCodec),
    Noise(NoiseCodec),
    Salamander(SalamanderCodec),
    Sudoku(sudoku::UdpCodec),
}

impl MaskStack {
    fn new(
        masks: &[UdpMaskConfig],
        role: UdpRole,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        if masks.len() > MAX_EXPANDED_PACKETS {
            return Err(invalid("too many finalmask UDP stages"));
        }
        let mut compiled = Vec::with_capacity(masks.len());
        for mask in masks {
            compiled.push(match mask {
                UdpMaskConfig::HeaderCustom(config) => MaskCodec::HeaderCustom(
                    UdpCustomCodec::new(config, role, local, remote)?,
                ),
                UdpMaskConfig::MkcpLegacy(config) => MaskCodec::Mkcp(MkcpCodec::new(config)?),
                UdpMaskConfig::Noise(config) => MaskCodec::Noise(NoiseCodec::new(config)?),
                UdpMaskConfig::Salamander(config) => {
                    MaskCodec::Salamander(SalamanderCodec::new(config)?)
                }
                UdpMaskConfig::Sudoku(config) => {
                    MaskCodec::Sudoku(sudoku::UdpCodec::new(config)?)
                }
                UdpMaskConfig::Xdns(_) => {
                    return Err(unsupported(
                        "xdns requires the raw carrier endpoint and cannot wrap a protocol-level UDP association",
                    ));
                }
                UdpMaskConfig::Xicmp(_) => {
                    return Err(unsupported(
                        "xicmp requires a raw ICMP carrier and cannot wrap a protocol-level UDP association",
                    ));
                }
                UdpMaskConfig::Realm(_) => {
                    return Err(unsupported(
                        "realm requires NAT traversal before carrier creation and cannot wrap a protocol-level UDP association",
                    ));
                }
            });
        }
        Ok(Self { masks: compiled })
    }

    fn standalone_indexes(&self) -> Vec<usize> {
        self.masks
            .iter()
            .enumerate()
            .filter_map(|(index, mask)| match mask {
                MaskCodec::HeaderCustom(codec) if codec.is_standalone() => Some(index),
                _ => None,
            })
            .collect()
    }

    fn custom_established(&mut self, index: usize) -> std::io::Result<bool> {
        match self.masks.get_mut(index) {
            Some(MaskCodec::HeaderCustom(codec)) if codec.is_standalone() => {
                Ok(codec.established())
            }
            _ => Err(invalid("standalone mask index is invalid")),
        }
    }

    fn custom_request(&mut self, index: usize) -> std::io::Result<Vec<u8>> {
        match self.masks.get_mut(index) {
            Some(MaskCodec::HeaderCustom(codec)) => codec.standalone_request(),
            _ => Err(invalid("standalone mask index is invalid")),
        }
    }

    fn custom_accept_response(&mut self, index: usize, packet: &[u8]) -> std::io::Result<bool> {
        match self.masks.get_mut(index) {
            Some(MaskCodec::HeaderCustom(codec)) => codec.accept_standalone_response(packet),
            _ => Err(invalid("standalone mask index is invalid")),
        }
    }

    fn standalone_server_action(
        &mut self,
        packet: &[u8],
    ) -> std::io::Result<Option<StandaloneServerAction>> {
        match self.masks.as_mut_slice() {
            [MaskCodec::HeaderCustom(codec)] if codec.is_standalone() => {
                codec.handle_standalone_server_packet(packet).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn encode_range(
        &mut self,
        mut packets: Vec<EncodedPacket>,
        start: usize,
    ) -> std::io::Result<Vec<EncodedPacket>> {
        for mask in &mut self.masks[start..] {
            let mut next = Vec::new();
            for packet in packets {
                let transformed = mask.encode(packet.data)?;
                if transformed.is_empty() {
                    continue;
                }
                let last = transformed.len() - 1;
                for (index, mut transformed) in transformed.into_iter().enumerate() {
                    if index == last {
                        transformed.delay_after += packet.delay_after;
                    }
                    next.push(transformed);
                }
            }
            validate_expansion(&next)?;
            packets = next;
        }
        Ok(packets)
    }

    fn decode_range(
        &mut self,
        mut packet: Vec<u8>,
        start: usize,
    ) -> std::io::Result<Option<Vec<u8>>> {
        for mask in self.masks[start..].iter_mut().rev() {
            let Some(decoded) = mask.decode(&packet)? else {
                return Ok(None);
            };
            packet = decoded;
            if packet.len() > MAX_WIRE_DATAGRAM {
                return Err(invalid(
                    "decoded finalmask UDP datagram exceeds 65535 bytes",
                ));
            }
        }
        Ok(Some(packet))
    }
}

impl MaskCodec {
    fn encode(&mut self, packet: Vec<u8>) -> std::io::Result<Vec<EncodedPacket>> {
        let packets = match self {
            Self::HeaderCustom(codec) => vec![codec.encode_prefix(&packet)?],
            Self::Mkcp(codec) => vec![codec.encode(&packet)?],
            Self::Noise(codec) => return codec.encode(packet),
            Self::Salamander(codec) => codec.encode(&packet)?,
            Self::Sudoku(codec) => vec![codec.encode(&packet)?],
        };
        Ok(packets.into_iter().map(EncodedPacket::new).collect())
    }

    fn decode(&mut self, packet: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        match self {
            Self::HeaderCustom(codec) => codec.decode_prefix(packet).map(Some),
            Self::Mkcp(codec) => codec.decode(packet).map(Some),
            Self::Noise(_) => Ok(Some(packet.to_vec())),
            Self::Salamander(codec) => codec.decode(packet),
            Self::Sudoku(codec) => codec.decode(packet).map(Some),
        }
    }
}

struct EncodedPacket {
    data: Vec<u8>,
    delay_after: Duration,
}

impl EncodedPacket {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            delay_after: Duration::ZERO,
        }
    }
}

struct NoiseCodec {
    reset: I32Range,
    items: Vec<NoiseItem>,
    next_reset: Option<Instant>,
}

struct NoiseItem {
    source: NoiseSource,
    delay: I32Range,
}

enum NoiseSource {
    Random { length: I32Range, bytes: I32Range },
    Packet(Vec<u8>),
}

impl NoiseCodec {
    fn new(config: &NoiseMaskConfig) -> std::io::Result<Self> {
        if config.noise.len() > MAX_EXPANDED_PACKETS - 1 {
            return Err(invalid("noise mask has too many packets"));
        }
        let mut items = Vec::with_capacity(config.noise.len());
        for item in &config.noise {
            items.push(NoiseItem::new(item)?);
        }
        Ok(Self {
            reset: config.reset,
            items,
            next_reset: None,
        })
    }

    fn encode(&mut self, payload: Vec<u8>) -> std::io::Result<Vec<EncodedPacket>> {
        let now = Instant::now();
        let due = self
            .next_reset
            .is_none_or(|deadline| self.reset.to > 0 && deadline <= now);
        let mut output = Vec::new();
        if due {
            for item in &self.items {
                output.push(item.generate()?);
            }
        }
        self.next_reset = Some(
            now + Duration::from_secs(u64::try_from(random_between(self.reset).max(0)).unwrap()),
        );
        output.push(EncodedPacket::new(payload));
        Ok(output)
    }
}

impl NoiseItem {
    fn new(config: &NoiseItemConfig) -> std::io::Result<Self> {
        let has_random = config.rand.to > 0;
        if has_random && config.packet.is_some() {
            return Err(invalid("noise item cannot configure both rand and packet"));
        }
        let source = if has_random {
            if config.rand.from < 0 {
                return Err(invalid("noise random length cannot be negative"));
            }
            let bytes = config.rand_range.unwrap_or_else(|| I32Range::new(0, 255));
            if bytes.from < 0 || bytes.to > 255 {
                return Err(invalid("noise randRange must be within 0..=255"));
            }
            NoiseSource::Random {
                length: config.rand,
                bytes,
            }
        } else {
            NoiseSource::Packet(parse_bytes(config.packet.as_ref(), &config.packet_type)?)
        };
        if config.delay.from < 0 {
            return Err(invalid("noise delay cannot be negative"));
        }
        Ok(Self {
            source,
            delay: config.delay,
        })
    }

    fn generate(&self) -> std::io::Result<EncodedPacket> {
        let data = match &self.source {
            NoiseSource::Packet(packet) => packet.clone(),
            NoiseSource::Random { length, bytes } => {
                let length = usize::try_from(random_between(*length)).map_err(invalid)?;
                if length > MAX_WIRE_DATAGRAM {
                    return Err(invalid("noise packet exceeds 65535 bytes"));
                }
                let mut output = vec![0; length];
                rand::thread_rng().fill_bytes(&mut output);
                if bytes.from != 0 || bytes.to != 255 {
                    let width = (bytes.to - bytes.from + 1) as u8;
                    for byte in &mut output {
                        *byte = bytes.from as u8 + *byte % width;
                    }
                }
                output
            }
        };
        Ok(EncodedPacket {
            data,
            delay_after: Duration::from_millis(
                u64::try_from(random_between(self.delay).max(0)).unwrap(),
            ),
        })
    }
}

fn random_between(range: I32Range) -> i32 {
    if range.from == range.to {
        range.from
    } else {
        rand::thread_rng().gen_range(range.from..range.to)
    }
}

fn parse_bytes(value: Option<&serde_json::Value>, kind: &str) -> std::io::Result<Vec<u8>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match kind.to_ascii_lowercase().as_str() {
        "" | "array" => serde_json::from_value(value.clone()).map_err(invalid),
        "str" => value
            .as_str()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| invalid("noise str packet must be a string")),
        "hex" => value
            .as_str()
            .ok_or_else(|| invalid("noise hex packet must be a string"))
            .and_then(|value| hex::decode(value).map_err(invalid)),
        "base64" => value
            .as_str()
            .ok_or_else(|| invalid("noise base64 packet must be a string"))
            .and_then(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(invalid)
            }),
        other => Err(invalid(format!("unknown noise byte type `{other}`"))),
    }
}

fn validate_expansion(packets: &[EncodedPacket]) -> std::io::Result<()> {
    if packets.len() > MAX_EXPANDED_PACKETS {
        return Err(invalid("finalmask UDP expansion exceeds packet limit"));
    }
    let total = packets.iter().try_fold(0usize, |total, packet| {
        if packet.data.len() > MAX_WIRE_DATAGRAM {
            return Err(invalid("finalmask wire datagram exceeds 65535 bytes"));
        }
        total
            .checked_add(packet.data.len())
            .ok_or_else(|| invalid("finalmask UDP expansion length overflow"))
    })?;
    if total > MAX_EXPANDED_BYTES {
        return Err(invalid("finalmask UDP expansion exceeds byte limit"));
    }
    Ok(())
}

fn copy_datagram(output: &mut [u8], packet: &[u8]) -> std::io::Result<usize> {
    if output.len() < packet.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "UDP receive buffer is {} bytes, decoded datagram is {} bytes",
                output.len(),
                packet.len()
            ),
        ));
    }
    output[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}

fn copy_received(
    output: &mut [u8],
    packet: ReceivedWire,
) -> std::io::Result<(usize, Option<SocketAddr>)> {
    let length = copy_datagram(output, &packet.data)?;
    Ok((length, packet.source))
}

fn parse_server_peer(target: &str, port: u16) -> std::io::Result<SocketAddr> {
    let target = target
        .trim()
        .strip_prefix('[')
        .and_then(|target| target.strip_suffix(']'))
        .unwrap_or_else(|| target.trim());
    let ip = target.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("finalmask UDP server reply requires an IP destination, got `{target}`"),
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn unsupported(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Unsupported, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, sync::Arc};

    use core_config::{
        HeaderCustomUdpConfig, HeaderCustomUdpItem, MkcpLegacyMaskConfig, SalamanderMaskConfig,
        SudokuMaskConfig,
    };
    use parking_lot::Mutex;
    use tokio::sync::{Mutex as AsyncMutex, mpsc};

    use super::*;

    #[derive(Default)]
    struct LoopUdp {
        packets: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    #[async_trait]
    impl UdpSocketLike for LoopUdp {
        async fn send_to(&self, buf: &[u8], _target: &str, _port: u16) -> std::io::Result<usize> {
            self.packets.lock().push_back(buf.to_vec());
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let packet = self
                .packets
                .lock()
                .pop_front()
                .ok_or_else(|| invalid("loop queue is empty"))?;
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    struct LinkUdp {
        local: SocketAddr,
        incoming: AsyncMutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
        outgoing: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    }

    fn linked_udp_pair(left: SocketAddr, right: SocketAddr) -> (LinkUdp, LinkUdp) {
        let (left_to_right_tx, left_to_right_rx) = mpsc::channel(16);
        let (right_to_left_tx, right_to_left_rx) = mpsc::channel(16);
        (
            LinkUdp {
                local: left,
                incoming: AsyncMutex::new(right_to_left_rx),
                outgoing: left_to_right_tx,
            },
            LinkUdp {
                local: right,
                incoming: AsyncMutex::new(left_to_right_rx),
                outgoing: right_to_left_tx,
            },
        )
    }

    #[async_trait]
    impl UdpSocketLike for LinkUdp {
        async fn send_to(&self, buf: &[u8], _target: &str, _port: u16) -> io::Result<usize> {
            self.outgoing
                .send((buf.to_vec(), self.local))
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.recv_from_endpoint(buf).await.map(|(length, _)| length)
        }

        async fn recv_from_endpoint(
            &self,
            buf: &mut [u8],
        ) -> io::Result<(usize, Option<SocketAddr>)> {
            let (packet, source) = self
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::BrokenPipe)?;
            if packet.len() > buf.len() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), Some(source)))
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(Some(self.local))
        }
    }

    #[tokio::test]
    async fn composed_packet_masks_roundtrip_in_xray_order() {
        let masks = vec![
            UdpMaskConfig::HeaderCustom(HeaderCustomUdpConfig {
                mode: "prefix".into(),
                client: vec![HeaderCustomUdpItem {
                    packet_type: "hex".into(),
                    packet: Some(serde_json::Value::String("aabb".into())),
                    ..Default::default()
                }],
                server: vec![HeaderCustomUdpItem {
                    packet_type: "hex".into(),
                    packet: Some(serde_json::Value::String("aabb".into())),
                    ..Default::default()
                }],
            }),
            UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default()),
            UdpMaskConfig::Salamander(SalamanderMaskConfig {
                password: "password".into(),
                ..Default::default()
            }),
            UdpMaskConfig::Sudoku(SudokuMaskConfig {
                password: "sudoku".into(),
                ..Default::default()
            }),
        ];
        let socket = wrap_client(
            Box::new(LoopUdp::default()),
            &masks,
            "example.com".into(),
            443,
            None,
            None,
        )
        .unwrap();
        socket
            .send_to(b"payload", "example.com", 443)
            .await
            .unwrap();
        let mut output = [0; 64];
        let length = socket.recv_from(&mut output).await.unwrap();
        assert_eq!(&output[..length], b"payload");
    }

    #[tokio::test]
    async fn composed_client_and_server_wrappers_exchange_datagrams() {
        let client_addr: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let server_addr: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let (client_link, server_link) = linked_udp_pair(client_addr, server_addr);
        let masks = vec![
            UdpMaskConfig::Sudoku(SudokuMaskConfig {
                password: "sudoku".into(),
                ..Default::default()
            }),
            UdpMaskConfig::HeaderCustom(HeaderCustomUdpConfig {
                mode: "prefix".into(),
                client: vec![HeaderCustomUdpItem {
                    packet_type: "hex".into(),
                    packet: Some(serde_json::Value::String("aabb".into())),
                    ..Default::default()
                }],
                server: vec![HeaderCustomUdpItem {
                    packet_type: "hex".into(),
                    packet: Some(serde_json::Value::String("ccdd".into())),
                    ..Default::default()
                }],
            }),
            UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default()),
            UdpMaskConfig::Salamander(SalamanderMaskConfig {
                password: "password".into(),
                ..Default::default()
            }),
        ];
        let client = wrap_client(
            Box::new(client_link),
            &masks,
            "198.51.100.20".into(),
            443,
            Some(client_addr),
            Some(server_addr),
        )
        .unwrap();
        let server = wrap_server(Box::new(server_link), &masks, Some(server_addr), None).unwrap();

        client
            .send_to(b"request", "198.51.100.20", 443)
            .await
            .unwrap();
        let mut buffer = [0; 256];
        let (length, source) = server.recv_from_endpoint(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"request");
        assert_eq!(source, Some(client_addr));

        server
            .send_to(b"response", "192.0.2.10", 40000)
            .await
            .unwrap();
        let (length, source) = client.recv_from_endpoint(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"response");
        assert_eq!(source, Some(server_addr));
    }

    #[test]
    fn server_header_capture_state_is_isolated_per_peer() {
        let masks = vec![UdpMaskConfig::HeaderCustom(HeaderCustomUdpConfig {
            mode: "prefix".into(),
            client: vec![HeaderCustomUdpItem {
                rand: 1,
                capture: "nonce".into(),
                ..Default::default()
            }],
            server: vec![HeaderCustomUdpItem {
                reuse: "nonce".into(),
                ..Default::default()
            }],
        })];
        let local: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let first: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:40001".parse().unwrap();
        let mut stacks = ServerMaskStacks::new(&masks, Some(local)).unwrap();
        assert_eq!(
            stacks
                .stack(first)
                .unwrap()
                .decode_range(vec![0x11, b'a'], 0)
                .unwrap(),
            Some(vec![b'a'])
        );
        assert_eq!(
            stacks
                .stack(second)
                .unwrap()
                .decode_range(vec![0x22, b'b'], 0)
                .unwrap(),
            Some(vec![b'b'])
        );

        let first_reply = stacks
            .stack(first)
            .unwrap()
            .encode_range(vec![EncodedPacket::new(vec![b'1'])], 0)
            .unwrap();
        let second_reply = stacks
            .stack(second)
            .unwrap()
            .encode_range(vec![EncodedPacket::new(vec![b'2'])], 0)
            .unwrap();
        assert_eq!(first_reply[0].data, [0x11, b'1']);
        assert_eq!(second_reply[0].data, [0x22, b'2']);
    }

    #[test]
    fn expansion_limit_rejects_resource_abuse() {
        let packets = (0..=MAX_EXPANDED_PACKETS)
            .map(|_| EncodedPacket::new(Vec::new()))
            .collect::<Vec<_>>();
        assert!(validate_expansion(&packets).is_err());
    }
}
