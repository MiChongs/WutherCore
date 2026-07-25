use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const VERSION: u8 = 1;
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 120;
pub const MAX_PADDING_BYTES: usize = 4096;
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;
const MAX_UDP_FRAGMENTS: usize = 256;
const AUTH_TOKEN_BYTES: usize = 1 + 8 + 8 + 16 + 4 + 32;
const FLOW_TAG_BYTES: usize = 16;
const FLOW_RESPONSE_BYTES: usize = 2 + 1 + 1 + 8 + FLOW_TAG_BYTES;
const UDP_HEADER_BYTES: usize = 2 + 1 + 1 + 8 + 4 + 2 + 2 + 2;
const UDP_TAG_BYTES: usize = 16;

#[derive(Clone)]
pub struct YoungKey(Arc<Zeroizing<[u8; 32]>>);

impl YoungKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }

    pub fn parse_base64url(value: &str) -> io::Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|error| invalid_input(format!("Young 密钥不是合法 base64url：{error}")))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid_input("Young 密钥解码后必须正好为 32 字节"))?;
        Ok(Self::from_bytes(bytes))
    }

    #[must_use]
    pub fn id(&self) -> [u8; 8] {
        let digest = Sha256::digest(self.as_bytes());
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix has fixed size")
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl fmt::Debug for YoungKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YoungKey")
            .field("id", &hex_id(self.id()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct SessionKey(Arc<Zeroizing<[u8; 32]>>);

impl SessionKey {
    fn new(bytes: [u8; 32]) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionKey")
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct KeyRing {
    keys: Vec<YoungKey>,
}

impl KeyRing {
    pub fn new(keys: Vec<YoungKey>) -> io::Result<Self> {
        if keys.is_empty() {
            return Err(invalid_input("Young key ring 不能为空"));
        }
        let mut ids = HashSet::new();
        for key in &keys {
            if !ids.insert(key.id()) {
                return Err(invalid_input("Young key ring 包含重复 key id"));
            }
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn find(&self, id: [u8; 8]) -> Option<YoungKey> {
        self.keys.iter().find(|key| key.id() == id).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Debug)]
pub struct ReplayCache {
    entries: Mutex<HashMap<[u8; 24], u64>>,
    max_entries: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: 65_536,
        }
    }
}

impl ReplayCache {
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    pub fn check_and_insert(
        &self,
        key_id: [u8; 8],
        nonce: [u8; 16],
        timestamp: u64,
        now: u64,
        window_secs: u64,
    ) -> io::Result<()> {
        let mut replay_key = [0; 24];
        replay_key[..8].copy_from_slice(&key_id);
        replay_key[8..].copy_from_slice(&nonce);
        let cutoff = now.saturating_sub(window_secs.saturating_mul(2));
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("Young replay cache lock poisoned"))?;
        entries.retain(|_, seen_at| *seen_at >= cutoff);
        if entries.contains_key(&replay_key) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Young 会话认证重放被拒绝",
            ));
        }
        if entries.len() >= self.max_entries {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, seen_at)| **seen_at)
                .map(|(key, _)| *key)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(replay_key, timestamp);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> io::Result<Self> {
        let host = host.into();
        if port == 0 {
            return Err(invalid_input("Young 目标端口不能为 0"));
        }
        if host.is_empty() || host.len() > 253 || host.as_bytes().contains(&0) {
            return Err(invalid_input("Young 目标主机长度必须为 1..=253 字节"));
        }
        Ok(Self { host, port })
    }

    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') && self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowKind {
    Tcp = 1,
    Udp = 2,
}

impl TryFrom<u8> for FlowKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(unsupported(format!("不支持的 Young flow kind：{value}"))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowOpen {
    pub kind: FlowKind,
    pub flow_id: u64,
    pub target: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    BadRequest = 1,
    Unauthorized = 2,
    ConnectFailed = 3,
    Unsupported = 4,
    ResourceLimit = 5,
}

impl TryFrom<u8> for Status {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::BadRequest),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::ConnectFailed),
            4 => Ok(Self::Unsupported),
            5 => Ok(Self::ResourceLimit),
            _ => Err(invalid_data(format!("未知 Young 状态码：{value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowResponse {
    pub status: Status,
    pub flow_id: u64,
}

pub fn unix_time_secs() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| io::Error::other(format!("系统时钟早于 UNIX epoch：{error}")))
}

#[must_use]
pub fn derive_rotating_path(key: &YoungKey, base_path: &str, unix_seconds: u64) -> String {
    let day = unix_seconds / 86_400;
    let suffix = hmac_tag(key.as_bytes(), &[b"young/path/v1", &day.to_be_bytes()]);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&suffix[..9]);
    let base = if base_path.starts_with('/') {
        base_path.trim_end_matches('/').to_owned()
    } else {
        format!("/{}", base_path.trim_end_matches('/'))
    };
    format!("{base}/{token}")
}

pub fn create_authorization(
    key: &YoungKey,
    authority: &str,
    path: &str,
    capabilities: u32,
) -> io::Result<(String, [u8; 16])> {
    let timestamp = unix_time_secs()?;
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    Ok((
        create_authorization_at(key, authority, path, capabilities, timestamp, nonce),
        nonce,
    ))
}

#[must_use]
pub fn create_authorization_at(
    key: &YoungKey,
    authority: &str,
    path: &str,
    capabilities: u32,
    timestamp: u64,
    nonce: [u8; 16],
) -> String {
    let mut token = Vec::with_capacity(AUTH_TOKEN_BYTES);
    token.push(VERSION);
    token.extend_from_slice(&key.id());
    token.extend_from_slice(&timestamp.to_be_bytes());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&capabilities.to_be_bytes());
    let tag = hmac_tag(
        key.as_bytes(),
        &[
            b"young/session/v1",
            authority.as_bytes(),
            path.as_bytes(),
            &token,
        ],
    );
    token.extend_from_slice(&tag);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
}

pub fn verify_authorization(
    encoded: &str,
    authority: &str,
    path: &str,
    keys: &KeyRing,
    replay: &ReplayCache,
    now: u64,
    clock_skew_secs: u64,
) -> io::Result<(YoungKey, [u8; 16], u32)> {
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| permission_denied("Young authorization 编码无效"))?;
    if token.len() != AUTH_TOKEN_BYTES || token[0] != VERSION {
        return Err(permission_denied("Young authorization 版本或长度无效"));
    }
    let key_id: [u8; 8] = token[1..9].try_into().expect("checked length");
    let timestamp = u64::from_be_bytes(token[9..17].try_into().expect("checked length"));
    let nonce: [u8; 16] = token[17..33].try_into().expect("checked length");
    let capabilities = u32::from_be_bytes(token[33..37].try_into().expect("checked length"));
    if now.abs_diff(timestamp) > clock_skew_secs {
        return Err(permission_denied("Young authorization 超出允许时间窗"));
    }
    let key = keys
        .find(key_id)
        .ok_or_else(|| permission_denied("Young key id 未授权"))?;
    verify_hmac(
        key.as_bytes(),
        &[
            b"young/session/v1",
            authority.as_bytes(),
            path.as_bytes(),
            &token[..37],
        ],
        &token[37..],
    )?;
    replay.check_and_insert(key_id, nonce, timestamp, now, clock_skew_secs)?;
    Ok((key, nonce, capabilities))
}

#[must_use]
pub fn server_accept_proof(key: &YoungKey, client_nonce: [u8; 16]) -> String {
    let tag = hmac_tag(key.as_bytes(), &[b"young/server-accept/v1", &client_nonce]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag)
}

pub fn verify_server_accept_proof(
    key: &YoungKey,
    client_nonce: [u8; 16],
    encoded: &str,
) -> io::Result<()> {
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| permission_denied("Young server proof 编码无效"))?;
    verify_hmac(
        key.as_bytes(),
        &[b"young/server-accept/v1", &client_nonce],
        &proof,
    )
}

#[must_use]
pub fn derive_session_key(key: &YoungKey, exporter: &[u8], client_nonce: [u8; 16]) -> SessionKey {
    SessionKey::new(hmac_tag(
        key.as_bytes(),
        &[b"young/exporter/v1", exporter, &client_nonce],
    ))
}

pub fn encode_flow_open(
    session_key: &SessionKey,
    open: &FlowOpen,
    padding_len: usize,
) -> io::Result<Vec<u8>> {
    if padding_len > MAX_PADDING_BYTES {
        return Err(invalid_input("Young flow padding 超过上限"));
    }
    let mut frame = Vec::with_capacity(64 + padding_len);
    frame.extend_from_slice(b"YF");
    frame.push(VERSION);
    frame.push(open.kind as u8);
    frame.extend_from_slice(&open.flow_id.to_be_bytes());
    encode_target(&mut frame, &open.target)?;
    frame.extend_from_slice(
        &u16::try_from(padding_len)
            .map_err(|_| invalid_input("Young flow padding 过大"))?
            .to_be_bytes(),
    );
    let padding_start = frame.len();
    frame.resize(padding_start + padding_len, 0);
    OsRng.fill_bytes(&mut frame[padding_start..]);
    let tag = hmac_tag(session_key.as_bytes(), &[b"young/flow-open/v1", &frame]);
    frame.extend_from_slice(&tag[..FLOW_TAG_BYTES]);
    Ok(frame)
}

pub fn decode_flow_open(
    session_key: &SessionKey,
    input: &[u8],
) -> io::Result<Option<(FlowOpen, usize)>> {
    const FIXED: usize = 2 + 1 + 1 + 8;
    if input.len() < FIXED {
        return Ok(None);
    }
    if &input[..2] != b"YF" || input[2] != VERSION {
        return Err(invalid_data("Young flow open magic/version 无效"));
    }
    let kind = FlowKind::try_from(input[3])?;
    let flow_id = u64::from_be_bytes(input[4..12].try_into().expect("checked fixed header"));
    let Some((target, target_bytes)) = decode_target(&input[12..])? else {
        return Ok(None);
    };
    let padding_offset = 12 + target_bytes;
    if input.len() < padding_offset + 2 {
        return Ok(None);
    }
    let padding_len = usize::from(u16::from_be_bytes(
        input[padding_offset..padding_offset + 2]
            .try_into()
            .expect("checked"),
    ));
    if padding_len > MAX_PADDING_BYTES {
        return Err(invalid_data("Young flow padding 超过上限"));
    }
    let authenticated_len = padding_offset + 2 + padding_len;
    let total = authenticated_len + FLOW_TAG_BYTES;
    if input.len() < total {
        return Ok(None);
    }
    verify_hmac_truncated(
        session_key.as_bytes(),
        &[b"young/flow-open/v1", &input[..authenticated_len]],
        &input[authenticated_len..total],
    )?;
    Ok(Some((
        FlowOpen {
            kind,
            flow_id,
            target,
        },
        total,
    )))
}

#[must_use]
pub fn encode_flow_response(
    session_key: &SessionKey,
    response: FlowResponse,
) -> [u8; FLOW_RESPONSE_BYTES] {
    let mut output = [0; FLOW_RESPONSE_BYTES];
    output[..2].copy_from_slice(b"YR");
    output[2] = VERSION;
    output[3] = response.status as u8;
    output[4..12].copy_from_slice(&response.flow_id.to_be_bytes());
    let tag = hmac_tag(
        session_key.as_bytes(),
        &[b"young/flow-response/v1", &output[..12]],
    );
    output[12..].copy_from_slice(&tag[..FLOW_TAG_BYTES]);
    output
}

pub fn decode_flow_response(
    session_key: &SessionKey,
    input: &[u8],
) -> io::Result<Option<(FlowResponse, usize)>> {
    if input.len() < FLOW_RESPONSE_BYTES {
        return Ok(None);
    }
    if &input[..2] != b"YR" || input[2] != VERSION {
        return Err(invalid_data("Young flow response magic/version 无效"));
    }
    verify_hmac_truncated(
        session_key.as_bytes(),
        &[b"young/flow-response/v1", &input[..12]],
        &input[12..FLOW_RESPONSE_BYTES],
    )?;
    Ok(Some((
        FlowResponse {
            status: Status::try_from(input[3])?,
            flow_id: u64::from_be_bytes(input[4..12].try_into().expect("checked")),
        },
        FLOW_RESPONSE_BYTES,
    )))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFragment {
    pub association_id: u64,
    pub packet_id: u32,
    pub index: u16,
    pub count: u16,
    pub total_len: u16,
    pub payload: Vec<u8>,
}

pub fn encode_udp_fragments(
    session_key: &SessionKey,
    association_id: u64,
    packet_id: u32,
    payload: &[u8],
    max_datagram_size: usize,
) -> io::Result<Vec<Vec<u8>>> {
    if payload.is_empty() || payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(invalid_input("Young UDP payload 长度必须为 1..=65507"));
    }
    let overhead = UDP_HEADER_BYTES + UDP_TAG_BYTES;
    if max_datagram_size <= overhead {
        return Err(invalid_input(
            "WebTransport datagram 上限不足以承载 Young header",
        ));
    }
    let chunk_size = max_datagram_size - overhead;
    let count = payload.len().div_ceil(chunk_size);
    if count > MAX_UDP_FRAGMENTS {
        return Err(invalid_input("Young UDP fragment 数量超过上限"));
    }
    let count_u16 =
        u16::try_from(count).map_err(|_| invalid_input("Young UDP fragment 数量过多"))?;
    let total_len =
        u16::try_from(payload.len()).map_err(|_| invalid_input("Young UDP payload 超过 u16"))?;
    payload
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let mut frame = Vec::with_capacity(overhead + chunk.len());
            frame.extend_from_slice(b"YD");
            frame.push(VERSION);
            frame.push(0);
            frame.extend_from_slice(&association_id.to_be_bytes());
            frame.extend_from_slice(&packet_id.to_be_bytes());
            frame.extend_from_slice(
                &u16::try_from(index)
                    .map_err(|_| invalid_input("Young UDP fragment index 过大"))?
                    .to_be_bytes(),
            );
            frame.extend_from_slice(&count_u16.to_be_bytes());
            frame.extend_from_slice(&total_len.to_be_bytes());
            frame.extend_from_slice(chunk);
            let tag = hmac_tag(session_key.as_bytes(), &[b"young/udp-fragment/v1", &frame]);
            frame.extend_from_slice(&tag[..UDP_TAG_BYTES]);
            Ok(frame)
        })
        .collect()
}

pub fn decode_udp_fragment(session_key: &SessionKey, input: &[u8]) -> io::Result<UdpFragment> {
    if input.len() < UDP_HEADER_BYTES + UDP_TAG_BYTES
        || &input[..2] != b"YD"
        || input[2] != VERSION
        || input[3] != 0
    {
        return Err(invalid_data("Young UDP fragment header 无效"));
    }
    let authenticated_len = input.len() - UDP_TAG_BYTES;
    verify_hmac_truncated(
        session_key.as_bytes(),
        &[b"young/udp-fragment/v1", &input[..authenticated_len]],
        &input[authenticated_len..],
    )?;
    let association_id = u64::from_be_bytes(input[4..12].try_into().expect("checked"));
    let packet_id = u32::from_be_bytes(input[12..16].try_into().expect("checked"));
    let index = u16::from_be_bytes(input[16..18].try_into().expect("checked"));
    let count = u16::from_be_bytes(input[18..20].try_into().expect("checked"));
    let total_len = u16::from_be_bytes(input[20..22].try_into().expect("checked"));
    let payload_len = authenticated_len - UDP_HEADER_BYTES;
    if count == 0
        || usize::from(count) > MAX_UDP_FRAGMENTS
        || count > total_len
        || index >= count
        || total_len == 0
        || usize::from(total_len) > MAX_UDP_PAYLOAD_BYTES
        || payload_len == 0
        || payload_len > usize::from(total_len)
    {
        return Err(invalid_data("Young UDP fragment metadata 无效"));
    }
    Ok(UdpFragment {
        association_id,
        packet_id,
        index,
        count,
        total_len,
        payload: input[UDP_HEADER_BYTES..authenticated_len].to_vec(),
    })
}

#[derive(Debug)]
struct PartialPacket {
    created: Instant,
    total_len: usize,
    fragments: Vec<Option<Vec<u8>>>,
    received_len: usize,
}

#[derive(Debug)]
pub struct UdpReassembler {
    entries: HashMap<(u64, u32), PartialPacket>,
    max_packets: usize,
    timeout: Duration,
}

impl Default for UdpReassembler {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            max_packets: 256,
            timeout: Duration::from_secs(10),
        }
    }
}

impl UdpReassembler {
    pub fn push(&mut self, fragment: UdpFragment, now: Instant) -> io::Result<Option<Vec<u8>>> {
        self.entries
            .retain(|_, packet| now.duration_since(packet.created) <= self.timeout);
        if self.entries.len() >= self.max_packets
            && !self
                .entries
                .contains_key(&(fragment.association_id, fragment.packet_id))
        {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, packet)| packet.created)
                .map(|(key, _)| *key)
            {
                self.entries.remove(&oldest);
            }
        }
        let key = (fragment.association_id, fragment.packet_id);
        let packet = self.entries.entry(key).or_insert_with(|| PartialPacket {
            created: now,
            total_len: usize::from(fragment.total_len),
            fragments: vec![None; usize::from(fragment.count)],
            received_len: 0,
        });
        if packet.total_len != usize::from(fragment.total_len)
            || packet.fragments.len() != usize::from(fragment.count)
        {
            self.entries.remove(&key);
            return Err(invalid_data(
                "Young UDP fragment 元数据在同一 packet 内不一致",
            ));
        }
        let slot = &mut packet.fragments[usize::from(fragment.index)];
        if slot.is_none() {
            packet.received_len = packet.received_len.saturating_add(fragment.payload.len());
            *slot = Some(fragment.payload);
        }
        if packet.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        let packet = self.entries.remove(&key).expect("entry exists");
        if packet.received_len != packet.total_len {
            return Err(invalid_data("Young UDP fragment 重组长度不符"));
        }
        let mut output = Vec::with_capacity(packet.total_len);
        for fragment in packet.fragments {
            output.extend_from_slice(fragment.as_deref().expect("all present"));
        }
        Ok(Some(output))
    }
}

fn encode_target(output: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    output.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<Ipv4Addr>() {
        output.push(1);
        output.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target.host.parse::<Ipv6Addr>() {
        output.push(3);
        output.extend_from_slice(&ip.octets());
    } else {
        let host = target.host.as_bytes();
        output.push(2);
        output.push(
            u8::try_from(host.len()).map_err(|_| invalid_input("Young 目标域名超过 255 字节"))?,
        );
        output.extend_from_slice(host);
    }
    Ok(())
}

fn decode_target(input: &[u8]) -> io::Result<Option<(Target, usize)>> {
    if input.len() < 3 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    let (host, consumed) = match input[2] {
        1 => {
            if input.len() < 7 {
                return Ok(None);
            }
            (
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&input[3..7]).expect("checked"),
                ))
                .to_string(),
                7,
            )
        }
        2 => {
            if input.len() < 4 {
                return Ok(None);
            }
            let length = usize::from(input[3]);
            if length == 0 {
                return Err(invalid_data("Young 目标域名为空"));
            }
            if input.len() < 4 + length {
                return Ok(None);
            }
            (
                String::from_utf8(input[4..4 + length].to_vec())
                    .map_err(|_| invalid_data("Young 目标域名不是 UTF-8"))?,
                4 + length,
            )
        }
        3 => {
            if input.len() < 19 {
                return Ok(None);
            }
            (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&input[3..19]).expect("checked"),
                ))
                .to_string(),
                19,
            )
        }
        value => return Err(invalid_data(format!("未知 Young 地址类型：{value}"))),
    };
    Ok(Some((Target::new(host, port)?, consumed)))
}

fn hmac_tag(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn verify_hmac(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> io::Result<()> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(tag)
        .map_err(|_| permission_denied("Young authentication tag 不匹配"))
}

fn verify_hmac_truncated(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> io::Result<()> {
    if tag.len() != FLOW_TAG_BYTES {
        return Err(permission_denied("Young truncated tag 长度无效"));
    }
    let expected = hmac_tag(key, parts);
    use subtle::ConstantTimeEq as _;
    if bool::from(expected[..tag.len()].ct_eq(tag)) {
        Ok(())
    } else {
        Err(permission_denied("Young authentication tag 不匹配"))
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn permission_denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

fn hex_id(id: [u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(16);
    for byte in id {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> YoungKey {
        YoungKey::from_bytes([byte; 32])
    }

    #[test]
    fn authorization_is_bound_to_path_and_replay_safe() {
        let key = key(7);
        let keys = KeyRing::new(vec![key.clone()]).unwrap();
        let replay = ReplayCache::default();
        let path = derive_rotating_path(&key, "/assets", 1_700_000_000);
        let token = create_authorization_at(&key, "example.com", &path, 3, 1_700_000_000, [9; 16]);
        let verified = verify_authorization(
            &token,
            "example.com",
            &path,
            &keys,
            &replay,
            1_700_000_001,
            120,
        )
        .unwrap();
        assert_eq!(verified.0.id(), key.id());
        assert_eq!(verified.2, 3);
        assert!(
            verify_authorization(
                &token,
                "example.com",
                &path,
                &keys,
                &replay,
                1_700_000_001,
                120,
            )
            .is_err()
        );
    }

    #[test]
    fn flow_open_is_incremental_and_authenticated() {
        let session = SessionKey::new([5; 32]);
        let open = FlowOpen {
            kind: FlowKind::Tcp,
            flow_id: 42,
            target: Target::new("example.com", 443).unwrap(),
        };
        let encoded = encode_flow_open(&session, &open, 127).unwrap();
        assert!(
            decode_flow_open(&session, &encoded[..20])
                .unwrap()
                .is_none()
        );
        let (decoded, consumed) = decode_flow_open(&session, &encoded).unwrap().unwrap();
        assert_eq!(decoded, open);
        assert_eq!(consumed, encoded.len());
        let mut tampered = encoded;
        tampered[15] ^= 1;
        assert!(decode_flow_open(&session, &tampered).is_err());
    }

    #[test]
    fn udp_fragments_reassemble_out_of_order() {
        let session = SessionKey::new([3; 32]);
        let payload = vec![0x5a; 5000];
        assert!(
            encode_udp_fragments(
                &session,
                99,
                6,
                &payload,
                UDP_HEADER_BYTES + UDP_TAG_BYTES + 1,
            )
            .is_err()
        );
        let mut fragments = encode_udp_fragments(&session, 99, 7, &payload, 900).unwrap();
        fragments.reverse();
        let mut reassembler = UdpReassembler::default();
        let mut output = None;
        for encoded in fragments {
            output = reassembler
                .push(
                    decode_udp_fragment(&session, &encoded).unwrap(),
                    Instant::now(),
                )
                .unwrap()
                .or(output);
        }
        assert_eq!(output.unwrap(), payload);
    }
}
