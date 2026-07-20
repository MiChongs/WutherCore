//! Shadowsocks 2022 (SIP022) —— 完整实现，与 mihomo / sing-box / shadowsocks-rust 互通。
//!
//! 协议参考：
//! * [SIP022](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md)
//! * [SIP022 EIH](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md)
//! * mihomo `transport/shadowsocks/shadowstream` + `core/v2ray/proxy/shadowsocks_2022`
//!
//! ## 实现的 cipher
//! * `2022-blake3-aes-128-gcm`         —— PSK 16B
//! * `2022-blake3-aes-256-gcm`         —— PSK 32B
//! * `2022-blake3-chacha20-poly1305`   —— PSK 32B
//!
//! ## 完整功能
//! * **TCP request**：salt + AEAD(fixed_header) + AEAD(variable_header + padding + initial_payload)
//! * **TCP response**：salt + AEAD(fixed_header_with_request_salt_echo) + AEAD(variable_header)
//! * **UDP**：AES 方法使用独立头 + AES-GCM，ChaCha 方法使用 XChaCha20-Poly1305
//! * **EIH (Extensible Identity Headers)**：多用户场景下，client 发送 N 层 16B 加密 user hash，server 按 hash 找到对应 user PSK
//! * **Timestamp 校验**：服务器需校验请求 timestamp 与本地时差 ≤ 30 秒，否则丢弃（防重放）
//! * **Padding**：variable_header 后可附加随机字节防流量指纹识别
//!
//! ## 帧布局
//!
//! ### TCP Request
//! ```text
//! [salt: PSK_LEN]
//! [EIH identity headers: N * 16B]
//! [AEAD(fixed_header)] := AEAD( type=0x00 (1B) || timestamp_be (8B) || initial_payload_length_be (2B) ) -> 11+16
//! [AEAD(variable_header + initial_payload)] :=
//!   AEAD( addr (SOCKS5) || padding_len_be (2B) || padding (padding_len B) || initial_payload )
//! [AEAD(length(2B BE))]   |
//! [AEAD(payload(N))]      | 后续 chunk
//! ```
//!
//! ### TCP Response
//! ```text
//! [salt: PSK_LEN]
//! [AEAD(fixed_header)] := AEAD( type=0x01 (1B) || timestamp_be (8B) || request_salt (PSK_LEN B) || initial_payload_length_be (2B) )
//! [AEAD(initial_payload)]
//! [AEAD(length)] [AEAD(payload)] ...
//! ```

use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, aead::Aead};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use rand::RngCore;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};

use crate::{
    adapter::{BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike},
    proto::addr::{decode_socks_addr, encode_socks_addr},
    transport::{Transport, tcp::TcpTransport},
};

const PAYLOAD_MAX: usize = 0xffff;
/// timestamp 漂移容差（秒）—— 与 mihomo 保持一致
pub const TIMESTAMP_TOLERANCE: i64 = 30;
/// 最大 padding 长度（字节）
pub const MAX_PADDING_LEN: u16 = 900;
const UDP_TAG_LEN: usize = 16;
const UDP_AES_SEPARATE_HEADER_LEN: usize = 16;
const UDP_XCHACHA_NONCE_LEN: usize = 24;
const UDP_REPLAY_WINDOW_BITS: u64 = 128;
const UDP_SERVER_SESSION_TTL: Duration = Duration::from_secs(300);
const UDP_MAX_SERVER_SESSIONS: usize = 64;
const UDP_MAX_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ss22Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Ss22Cipher {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha20-ietf-poly1305" => {
                Some(Self::Chacha20Poly1305)
            }
            _ => None,
        }
    }
}

/// 多用户 PSK 列表（EIH）。第 0 项是本节点 PSK，后续是上游 server 的 user PSK 列表。
#[derive(Debug, Clone, Default)]
pub struct Ss22UserPsks {
    pub layers: Vec<Vec<u8>>, // 每层 PSK，长度必须等于 cipher.key_len()
}

#[derive(Debug, Clone)]
pub struct Ss2022Outbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub cipher: Ss22Cipher,
    pub psk: Arc<[u8]>,
    /// EIH 多层 PSK（从客户端到目标 server 的链路）。空表示无 EIH。
    pub eih_layers: Arc<Vec<Vec<u8>>>,
    pub udp: bool,
}

impl Ss2022Outbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        cipher: Ss22Cipher,
        psk_chain: &str,
    ) -> std::io::Result<Self> {
        let (psk, eih_layers) = parse_psk_chain(cipher, psk_chain)?;
        Ok(Self {
            name: name.into(),
            host: host.into(),
            port,
            cipher,
            psk: Arc::from(psk.into_boxed_slice()),
            eih_layers: Arc::new(eih_layers),
            udp: true,
        })
    }

    /// 加入 EIH 身份 PSK。每层都是一个 b64 字符串，按客户端到最终服务端的顺序排列。
    /// 最终用户 PSK 仍由构造函数的 `psk_chain` 提供。
    pub fn with_eih_layers(mut self, layers_b64: &[&str]) -> std::io::Result<Self> {
        if self.cipher == Ss22Cipher::Chacha20Poly1305 && !layers_b64.is_empty() {
            return Err(invalid_data("ss2022 chacha20 does not support EIH"));
        }
        use base64::{
            Engine, alphabet,
            engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
        };
        let decoder = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        let mut layers = Vec::with_capacity(layers_b64.len());
        for s in layers_b64 {
            let v = decoder
                .decode(s.trim())
                .map_err(|_| invalid_data("ss2022 eih layer base64 decode"))?;
            if v.len() != self.cipher.key_len() {
                return Err(invalid_data("ss2022 eih layer length mismatch"));
            }
            layers.push(v);
        }
        self.eih_layers = Arc::new(layers);
        Ok(self)
    }
}

fn parse_psk_chain(
    cipher: Ss22Cipher,
    psk_chain: &str,
) -> std::io::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    use base64::{
        Engine, alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    };

    let parts: Vec<&str> = psk_chain.split(':').map(str::trim).collect();
    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid_data("ss2022 PSK chain contains an empty key"));
    }
    if cipher == Ss22Cipher::Chacha20Poly1305 && parts.len() != 1 {
        return Err(invalid_data("ss2022 chacha20 does not support EIH"));
    }

    let mut decoded = Vec::with_capacity(parts.len());
    let decoder = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    for part in parts {
        let key = decoder
            .decode(part)
            .map_err(|_| invalid_data("ss2022 PSK base64 decode failed"))?;
        if key.len() != cipher.key_len() {
            return Err(invalid_data("ss2022 PSK length mismatch with cipher"));
        }
        decoded.push(key);
    }

    let user_psk = decoded
        .pop()
        .ok_or_else(|| invalid_data("ss2022 user PSK is missing"))?;
    Ok((user_psk, decoded))
}

#[async_trait]
impl OutboundAdapter for Ss2022Outbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "ss2022"
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
        let mut stream = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // 1) 随机 salt 与 PSK 等长
        let salt_len = self.cipher.key_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // 2) 派生 session subkey
        let subkey = derive_subkey(&self.psk, &salt, salt_len);

        // 3) 计算 EIH 头部（多用户场景）
        let eih_headers = build_tcp_eih_layers(self.cipher, &self.eih_layers, &self.psk, &salt)?;

        // 4) 构造 variable_header: addr || padding_len(2B) || padding || initial_payload(无)
        let target = encode_socks_addr(&ctx.host, ctx.port);
        let mut var_hdr = Vec::with_capacity(target.len() + 2 + MAX_PADDING_LEN as usize);
        var_hdr.extend_from_slice(&target);

        // 随机 padding（防指纹识别）
        let padding_len = {
            let mut b = [0u8; 2];
            rand::rngs::OsRng.fill_bytes(&mut b);
            (u16::from_be_bytes(b) % MAX_PADDING_LEN + 1) as usize
        };
        var_hdr.put_u16(padding_len as u16);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            rand::rngs::OsRng.fill_bytes(&mut padding);
            var_hdr.extend_from_slice(&padding);
        }

        // 5) fixed_header: type=0x00 || timestamp_be8 || initial_payload_len_be2
        let initial_len = var_hdr.len() as u16;
        let now = chrono::Utc::now().timestamp() as u64;
        let mut fixed = Vec::with_capacity(11);
        fixed.put_u8(0x00);
        fixed.put_u64(now);
        fixed.put_u16(initial_len);

        // 6) AEAD seal
        let mut send = Ss22Cryptor::new(self.cipher, &subkey);
        let fixed_sealed = send.seal(&fixed)?;
        let var_sealed = send.seal(&var_hdr)?;

        // 7) EIH 位于 salt 与 AEAD chunks 之间，不能放进 variable header 密文。
        let mut wire = Vec::with_capacity(
            salt.len() + eih_headers.len() + fixed_sealed.len() + var_sealed.len(),
        );
        wire.extend_from_slice(&salt);
        wire.extend_from_slice(&eih_headers);
        wire.extend_from_slice(&fixed_sealed);
        wire.extend_from_slice(&var_sealed);
        stream.write_all(&wire).await?;

        // 8) 包装为流
        Ok(Box::pin(Ss22Stream {
            inner: stream,
            send,
            recv_state: RecvState::WaitSalt,
            psk: self.psk.clone(),
            cipher: self.cipher,
            request_salt: Arc::from(salt.into_boxed_slice()),
            cipher_buf: BytesMut::with_capacity(32 * 1024),
            plain_buf: BytesMut::with_capacity(32 * 1024),
            write_buf: BytesMut::with_capacity(64 * 1024),
        }))
    }

    async fn dial_udp(&self, ctx: DialContext) -> std::io::Result<BoxedUdp> {
        if !self.udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("outbound `{}`/ss2022 udp disabled by config", self.name),
            ));
        }

        let server = resolve_first(&self.host, self.port).await?;
        let (std_sock, loopback_guard) = crate::create_outbound_udp_socket(server)?;
        let sock = UdpSocket::from_std(std_sock)?;
        let client_session_id = random_nonzero_u64();
        tracing::info!(
            target: "dial::ss2022",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %server,
            client_session_id,
            "udp associate ok",
        );

        Ok(Box::new(Ss2022Udp {
            sock: Arc::new(sock),
            cipher: self.cipher,
            psk: self.psk.clone(),
            eih_layers: self.eih_layers.clone(),
            client_session_id,
            next_packet_id: AtomicU64::new(0),
            replay: Mutex::new(ServerReplayTable::default()),
            loopback_guard,
        }))
    }
}

/// 派生 session subkey：BLAKE3-DeriveKey
fn derive_subkey(psk: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(psk.len() + salt.len());
    input.extend_from_slice(psk);
    input.extend_from_slice(salt);
    let mut out = vec![0u8; len];
    blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey")
        .update(&input)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// SIP022 EIH TCP identity headers:
/// `AES(identity_subkey(iPSK, salt), BLAKE3(next_PSK)[..16])`.
fn build_tcp_eih_layers(
    cipher: Ss22Cipher,
    identity_psks: &[Vec<u8>],
    user_psk: &[u8],
    salt: &[u8],
) -> std::io::Result<Vec<u8>> {
    if identity_psks.is_empty() {
        return Ok(Vec::new());
    }
    if cipher == Ss22Cipher::Chacha20Poly1305 {
        return Err(invalid_data("ss2022 chacha20 does not support EIH"));
    }

    let mut out = Vec::with_capacity(identity_psks.len() * 16);
    for (index, identity_psk) in identity_psks.iter().enumerate() {
        let next_psk = if index + 1 < identity_psks.len() {
            identity_psks[index + 1].as_slice()
        } else {
            user_psk
        };
        let mut block = aes::Block::clone_from_slice(&blake3::hash(next_psk).as_bytes()[..16]);
        let identity_subkey = derive_identity_subkey(identity_psk, salt, cipher.key_len());
        aes_encrypt_block(cipher, &identity_subkey, &mut block)?;
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn derive_identity_subkey(identity_psk: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(identity_psk.len() + salt.len());
    input.extend_from_slice(identity_psk);
    input.extend_from_slice(salt);
    let mut out = vec![0u8; len];
    blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey")
        .update(&input)
        .finalize_xof()
        .fill(&mut out);
    out
}

fn aes_encrypt_block(
    cipher: Ss22Cipher,
    key: &[u8],
    block: &mut aes::Block,
) -> std::io::Result<()> {
    match cipher {
        Ss22Cipher::Aes128Gcm => {
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|_| invalid_data("ss2022 AES-128 key length"))?;
            cipher.encrypt_block(block);
        }
        Ss22Cipher::Aes256Gcm => {
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|_| invalid_data("ss2022 AES-256 key length"))?;
            cipher.encrypt_block(block);
        }
        Ss22Cipher::Chacha20Poly1305 => {
            return Err(invalid_data("ss2022 chacha20 has no AES block header"));
        }
    }
    Ok(())
}

fn aes_decrypt_block(
    cipher: Ss22Cipher,
    key: &[u8],
    block: &mut aes::Block,
) -> std::io::Result<()> {
    match cipher {
        Ss22Cipher::Aes128Gcm => {
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|_| invalid_data("ss2022 AES-128 key length"))?;
            cipher.decrypt_block(block);
        }
        Ss22Cipher::Aes256Gcm => {
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|_| invalid_data("ss2022 AES-256 key length"))?;
            cipher.decrypt_block(block);
        }
        Ss22Cipher::Chacha20Poly1305 => {
            return Err(invalid_data("ss2022 chacha20 has no AES block header"));
        }
    }
    Ok(())
}

enum Ss22Aead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl Ss22Aead {
    fn new(cipher: Ss22Cipher, key: &[u8]) -> std::io::Result<Self> {
        match cipher {
            Ss22Cipher::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map(Box::new)
                .map(Self::Aes128)
                .map_err(|_| invalid_data("ss2022 AES-128-GCM key length")),
            Ss22Cipher::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map(Box::new)
                .map(Self::Aes256)
                .map_err(|_| invalid_data("ss2022 AES-256-GCM key length")),
            Ss22Cipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map(Box::new)
                .map(Self::Chacha)
                .map_err(|_| invalid_data("ss2022 ChaCha20-Poly1305 key length")),
        }
    }

    fn seal(&self, nonce: &[u8; 12], msg: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), msg)
                .map_err(|_| invalid_data("ss2022 AES-128-GCM seal failed")),
            Self::Aes256(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), msg)
                .map_err(|_| invalid_data("ss2022 AES-256-GCM seal failed")),
            Self::Chacha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), msg)
                .map_err(|_| invalid_data("ss2022 ChaCha20-Poly1305 seal failed")),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid_data("ss2022 AES-128-GCM open failed")),
            Self::Aes256(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid_data("ss2022 AES-256-GCM open failed")),
            Self::Chacha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid_data("ss2022 ChaCha20-Poly1305 open failed")),
        }
    }
}

struct Ss22Cryptor {
    aead: Ss22Aead,
    nonce: u128,
}

impl Ss22Cryptor {
    fn new(cipher: Ss22Cipher, key: &[u8]) -> Self {
        let aead = Ss22Aead::new(cipher, key).expect("validated ss2022 key length");
        Self { aead, nonce: 0 }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let n = self.nonce;
        self.nonce = self.nonce.wrapping_add(1);
        let bytes = n.to_le_bytes();
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes[..12]);
        out
    }

    fn seal(&mut self, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        self.aead.seal(&n, msg)
    }

    fn open(&mut self, ct: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        self.aead.open(&n, ct)
    }
}

enum RecvState {
    WaitSalt,
    WaitFixedHeader {
        recv: Ss22Cryptor,
    },
    Body {
        recv: Ss22Cryptor,
        expecting_len: Option<usize>,
    },
}

pin_project! {
    struct Ss22Stream {
        #[pin]
        inner: BoxedStream,
        send: Ss22Cryptor,
        recv_state: RecvState,
        psk: Arc<[u8]>,
        cipher: Ss22Cipher,
        // 客户端发送出去的 salt，用于校验 server 响应中的 echo
        request_salt: Arc<[u8]>,
        cipher_buf: BytesMut,
        plain_buf: BytesMut,
        write_buf: BytesMut,
    }
}

impl AsyncRead for Ss22Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.plain_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.plain_buf.len());
                buf.put_slice(&this.plain_buf[..n]);
                this.plain_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            let progress = match this.recv_state {
                RecvState::WaitSalt => {
                    let salt_len = this.cipher.key_len();
                    if this.cipher_buf.len() < salt_len {
                        Ok(false)
                    } else {
                        let salt = this.cipher_buf.split_to(salt_len).to_vec();
                        let subkey = derive_subkey(this.psk, &salt, salt_len);
                        let recv = Ss22Cryptor::new(*this.cipher, &subkey);
                        *this.recv_state = RecvState::WaitFixedHeader { recv };
                        Ok(true)
                    }
                }
                RecvState::WaitFixedHeader { recv } => {
                    // server 响应 fixed_header 长度 = 1 + 8 + salt_len + 2 + 16
                    let salt_len = this.cipher.key_len();
                    let need = 1 + 8 + salt_len + 2 + 16;
                    if this.cipher_buf.len() < need {
                        Ok(false)
                    } else {
                        let cipher_chunk = this.cipher_buf.split_to(need).to_vec();
                        match recv.open(&cipher_chunk) {
                            Ok(plain) => {
                                if plain.len() != 1 + 8 + salt_len + 2 {
                                    Err(io_err("ss22 fixed header size"))
                                } else if plain[0] != 0x01 {
                                    Err(io_err("ss22 fixed header type (expect 0x01)"))
                                } else {
                                    // timestamp 校验：±30s
                                    let timestamp = u64::from_be_bytes([
                                        plain[1], plain[2], plain[3], plain[4], plain[5], plain[6],
                                        plain[7], plain[8],
                                    ]);
                                    if !timestamp_within_tolerance(timestamp, unix_timestamp()) {
                                        return Poll::Ready(Err(invalid_data(
                                            "ss22 timestamp out of tolerance",
                                        )));
                                    }
                                    // 校验 request_salt echo
                                    let echoed = &plain[9..9 + salt_len];
                                    if echoed != &this.request_salt[..] {
                                        return Poll::Ready(Err(io_err(
                                            "ss22 request_salt mismatch",
                                        )));
                                    }
                                    let initial_len = u16::from_be_bytes([
                                        plain[9 + salt_len],
                                        plain[10 + salt_len],
                                    ])
                                        as usize;
                                    let dummy = Ss22Cryptor::new(
                                        *this.cipher,
                                        &[0u8; 32][..this.cipher.key_len()],
                                    );
                                    let recv_taken = std::mem::replace(recv, dummy);
                                    *this.recv_state = RecvState::Body {
                                        recv: recv_taken,
                                        expecting_len: Some(initial_len),
                                    };
                                    Ok(true)
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
                RecvState::Body {
                    recv,
                    expecting_len,
                    ..
                } => {
                    let tag = 16;
                    if expecting_len.is_none() {
                        if this.cipher_buf.len() < 2 + tag {
                            Ok(false)
                        } else {
                            let cipher_chunk = this.cipher_buf.split_to(2 + tag).to_vec();
                            match recv.open(&cipher_chunk) {
                                Ok(plain) => {
                                    let length = u16::from_be_bytes([plain[0], plain[1]]) as usize;
                                    *expecting_len = Some(length);
                                    Ok(true)
                                }
                                Err(e) => Err(e),
                            }
                        }
                    } else {
                        let length = expecting_len.unwrap();
                        if this.cipher_buf.len() < length + tag {
                            Ok(false)
                        } else {
                            let cipher_chunk = this.cipher_buf.split_to(length + tag).to_vec();
                            match recv.open(&cipher_chunk) {
                                Ok(plain) => {
                                    this.plain_buf.extend_from_slice(&plain);
                                    *expecting_len = None;
                                    Ok(true)
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                }
            };

            match progress {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match this.inner.as_mut().poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        let clean_eof = match this.recv_state {
                            RecvState::Body { expecting_len, .. } => {
                                expecting_len.is_none() && this.cipher_buf.is_empty()
                            }
                            _ => false,
                        };
                        return if clean_eof {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "truncated ss2022 response",
                            )))
                        };
                    }
                    this.cipher_buf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl AsyncWrite for Ss22Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match poll_drain_write_buf(this.inner.as_mut(), this.write_buf, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk = &data[..data.len().min(PAYLOAD_MAX)];
        let len_be = (chunk.len() as u16).to_be_bytes();
        let len_sealed = match this.send.seal(&len_be) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let payload_sealed = match this.send.seal(chunk) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut packet = Vec::with_capacity(len_sealed.len() + payload_sealed.len());
        packet.extend_from_slice(&len_sealed);
        packet.extend_from_slice(&payload_sealed);
        this.write_buf.extend_from_slice(&packet);

        match poll_drain_write_buf(this.inner.as_mut(), this.write_buf, cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk.len())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        match poll_drain_write_buf(this.inner.as_mut(), this.write_buf, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => this.inner.poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        match poll_drain_write_buf(this.inner.as_mut(), this.write_buf, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => this.inner.poll_shutdown(cx),
        }
    }
}

fn poll_drain_write_buf(
    mut inner: Pin<&mut BoxedStream>,
    write_buf: &mut BytesMut,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<()>> {
    while !write_buf.is_empty() {
        match inner.as_mut().poll_write(cx, write_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            Poll::Ready(Ok(written)) => {
                write_buf.advance(written);
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
    }
    Poll::Ready(Ok(()))
}

/* ---------------- UDP 包加解密 ---------------- */

struct Ss2022Udp {
    sock: Arc<UdpSocket>,
    cipher: Ss22Cipher,
    psk: Arc<[u8]>,
    eih_layers: Arc<Vec<Vec<u8>>>,
    client_session_id: u64,
    next_packet_id: AtomicU64,
    replay: Mutex<ServerReplayTable>,
    loopback_guard: crate::loopback::LoopbackUdpGuard,
}

#[async_trait]
impl UdpSocketLike for Ss2022Udp {
    async fn send_to(&self, payload: &[u8], target: &str, port: u16) -> std::io::Result<usize> {
        let packet_id = self
            .next_packet_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| std::io::Error::other("ss2022 UDP packet counter exhausted"))?;
        let address = encode_socks_addr(target, port);
        let packet = seal_udp_packet(
            self.cipher,
            &self.psk,
            &self.eih_layers,
            UdpPacketDirection::Client,
            self.client_session_id,
            packet_id,
            None,
            &address,
            payload,
            unix_timestamp(),
        )?;
        if packet.len() > UDP_MAX_PACKET_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ss2022 UDP packet exceeds the maximum datagram size",
            ));
        }
        let sent = self.sock.send(&packet).await?;
        if sent != packet.len() {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        Ok(payload.len())
    }

    async fn recv_from(&self, output: &mut [u8]) -> std::io::Result<usize> {
        let mut packet = vec![0u8; UDP_MAX_PACKET_SIZE];
        loop {
            packet.resize(UDP_MAX_PACKET_SIZE, 0);
            let received = self.sock.recv(&mut packet).await?;
            packet.truncate(received);
            let decoded = match open_udp_packet(
                self.cipher,
                &self.psk,
                &[],
                UdpPacketDirection::Server,
                &packet,
                unix_timestamp(),
            ) {
                Ok(decoded) => decoded,
                Err(error) => {
                    tracing::debug!(
                        target: "dial::ss2022",
                        client_session_id = self.client_session_id,
                        %error,
                        "discarding invalid UDP response"
                    );
                    continue;
                }
            };
            if decoded.client_session_id != Some(self.client_session_id) {
                tracing::debug!(
                    target: "dial::ss2022",
                    expected = self.client_session_id,
                    actual = ?decoded.client_session_id,
                    "discarding UDP response for another client session"
                );
                continue;
            }
            if let Err(error) = self.replay.lock().check_and_mark(
                decoded.session_id,
                decoded.packet_id,
                Instant::now(),
            ) {
                tracing::debug!(
                    target: "dial::ss2022",
                    server_session_id = decoded.session_id,
                    packet_id = decoded.packet_id,
                    %error,
                    "discarding replayed or stale UDP response"
                );
                continue;
            }

            let copy_len = decoded.payload.len().min(output.len());
            output[..copy_len].copy_from_slice(&decoded.payload[..copy_len]);
            return Ok(copy_len);
        }
    }

    async fn close(&self) -> std::io::Result<()> {
        let _ = &self.loopback_guard;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpPacketDirection {
    Client,
    Server,
}

impl UdpPacketDirection {
    fn header_type(self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DecodedUdpPacket {
    session_id: u64,
    packet_id: u64,
    client_session_id: Option<u64>,
    target: String,
    port: u16,
    payload: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn seal_udp_packet(
    cipher: Ss22Cipher,
    user_psk: &[u8],
    identity_psks: &[Vec<u8>],
    direction: UdpPacketDirection,
    session_id: u64,
    packet_id: u64,
    client_session_id: Option<u64>,
    address: &[u8],
    payload: &[u8],
    timestamp: u64,
) -> std::io::Result<Vec<u8>> {
    if session_id == 0 {
        return Err(invalid_data("ss2022 UDP session ID must be non-zero"));
    }
    if direction == UdpPacketDirection::Server && client_session_id.is_none() {
        return Err(invalid_data(
            "ss2022 UDP server packet is missing the client session ID",
        ));
    }
    if direction == UdpPacketDirection::Server && !identity_psks.is_empty() {
        return Err(invalid_data(
            "ss2022 UDP response packets cannot contain EIH",
        ));
    }

    let mut separate_header = [0u8; UDP_AES_SEPARATE_HEADER_LEN];
    separate_header[..8].copy_from_slice(&session_id.to_be_bytes());
    separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut body = Vec::with_capacity(
        1 + 8 + client_session_id.map_or(0, |_| 8) + 2 + address.len() + payload.len(),
    );
    body.put_u8(direction.header_type());
    body.put_u64(timestamp);
    if let Some(client_session_id) = client_session_id {
        body.put_u64(client_session_id);
    }
    body.put_u16(0);
    body.extend_from_slice(address);
    body.extend_from_slice(payload);

    match cipher {
        Ss22Cipher::Aes128Gcm | Ss22Cipher::Aes256Gcm => {
            let identity_headers = if direction == UdpPacketDirection::Client {
                build_udp_eih_layers(cipher, identity_psks, user_psk, &separate_header)?
            } else {
                Vec::new()
            };
            let subkey = derive_subkey(user_psk, &separate_header[..8], cipher.key_len());
            let nonce: [u8; 12] = separate_header[4..16]
                .try_into()
                .expect("12-byte ss2022 UDP nonce");
            let encrypted_body = Ss22Aead::new(cipher, &subkey)?.seal(&nonce, &body)?;

            let separate_key = identity_psks.first().map_or(user_psk, Vec::as_slice);
            let mut encrypted_header = aes::Block::clone_from_slice(&separate_header);
            aes_encrypt_block(cipher, separate_key, &mut encrypted_header)?;

            let mut packet = Vec::with_capacity(
                encrypted_header.len() + identity_headers.len() + encrypted_body.len(),
            );
            packet.extend_from_slice(&encrypted_header);
            packet.extend_from_slice(&identity_headers);
            packet.extend_from_slice(&encrypted_body);
            Ok(packet)
        }
        Ss22Cipher::Chacha20Poly1305 => {
            if !identity_psks.is_empty() {
                return Err(invalid_data("ss2022 chacha20 does not support EIH"));
            }
            let cipher = XChaCha20Poly1305::new_from_slice(user_psk)
                .map_err(|_| invalid_data("ss2022 XChaCha20 key length"))?;
            let mut nonce = [0u8; UDP_XCHACHA_NONCE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let mut plaintext = Vec::with_capacity(separate_header.len() + body.len());
            plaintext.extend_from_slice(&separate_header);
            plaintext.extend_from_slice(&body);
            let encrypted = cipher
                .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
                .map_err(|_| invalid_data("ss2022 XChaCha20 UDP seal failed"))?;

            let mut packet = Vec::with_capacity(nonce.len() + encrypted.len());
            packet.extend_from_slice(&nonce);
            packet.extend_from_slice(&encrypted);
            Ok(packet)
        }
    }
}

fn open_udp_packet(
    cipher: Ss22Cipher,
    user_psk: &[u8],
    identity_psks: &[Vec<u8>],
    direction: UdpPacketDirection,
    packet: &[u8],
    now: u64,
) -> std::io::Result<DecodedUdpPacket> {
    let (separate_header, body) = match cipher {
        Ss22Cipher::Aes128Gcm | Ss22Cipher::Aes256Gcm => {
            let identity_len = if direction == UdpPacketDirection::Client {
                identity_psks
                    .len()
                    .checked_mul(16)
                    .ok_or_else(|| invalid_data("ss2022 UDP EIH length overflow"))?
            } else {
                0
            };
            let body_offset = UDP_AES_SEPARATE_HEADER_LEN
                .checked_add(identity_len)
                .ok_or_else(|| invalid_data("ss2022 UDP header length overflow"))?;
            if packet.len() < body_offset + UDP_TAG_LEN {
                return Err(invalid_data("ss2022 UDP AES packet is truncated"));
            }

            let separate_key = identity_psks.first().map_or(user_psk, Vec::as_slice);
            let mut header = aes::Block::clone_from_slice(&packet[..UDP_AES_SEPARATE_HEADER_LEN]);
            aes_decrypt_block(cipher, separate_key, &mut header)?;
            let separate_header: [u8; UDP_AES_SEPARATE_HEADER_LEN] = header.into();

            if identity_len > 0 {
                let expected =
                    build_udp_eih_layers(cipher, identity_psks, user_psk, &separate_header)?;
                if packet[UDP_AES_SEPARATE_HEADER_LEN..body_offset] != expected {
                    return Err(invalid_data("ss2022 UDP EIH validation failed"));
                }
            }

            let subkey = derive_subkey(user_psk, &separate_header[..8], cipher.key_len());
            let nonce: [u8; 12] = separate_header[4..16]
                .try_into()
                .expect("12-byte ss2022 UDP nonce");
            let body = Ss22Aead::new(cipher, &subkey)?.open(&nonce, &packet[body_offset..])?;
            (separate_header, body)
        }
        Ss22Cipher::Chacha20Poly1305 => {
            if !identity_psks.is_empty() {
                return Err(invalid_data("ss2022 chacha20 does not support EIH"));
            }
            if packet.len() < UDP_XCHACHA_NONCE_LEN + UDP_TAG_LEN + UDP_AES_SEPARATE_HEADER_LEN {
                return Err(invalid_data("ss2022 UDP XChaCha20 packet is truncated"));
            }
            let cipher = XChaCha20Poly1305::new_from_slice(user_psk)
                .map_err(|_| invalid_data("ss2022 XChaCha20 key length"))?;
            let plaintext = cipher
                .decrypt(
                    XNonce::from_slice(&packet[..UDP_XCHACHA_NONCE_LEN]),
                    &packet[UDP_XCHACHA_NONCE_LEN..],
                )
                .map_err(|_| invalid_data("ss2022 XChaCha20 UDP open failed"))?;
            if plaintext.len() < UDP_AES_SEPARATE_HEADER_LEN {
                return Err(invalid_data("ss2022 UDP XChaCha20 plaintext is truncated"));
            }
            let separate_header = plaintext[..UDP_AES_SEPARATE_HEADER_LEN]
                .try_into()
                .expect("16-byte ss2022 UDP separate header");
            (
                separate_header,
                plaintext[UDP_AES_SEPARATE_HEADER_LEN..].to_vec(),
            )
        }
    };

    let session_id = u64::from_be_bytes(
        separate_header[..8]
            .try_into()
            .expect("8-byte ss2022 UDP session ID"),
    );
    if session_id == 0 {
        return Err(invalid_data("ss2022 UDP session ID must be non-zero"));
    }
    let packet_id = u64::from_be_bytes(
        separate_header[8..]
            .try_into()
            .expect("8-byte ss2022 UDP packet ID"),
    );
    parse_udp_body(direction, session_id, packet_id, &body, now)
}

fn parse_udp_body(
    direction: UdpPacketDirection,
    session_id: u64,
    packet_id: u64,
    body: &[u8],
    now: u64,
) -> std::io::Result<DecodedUdpPacket> {
    let fixed_len = 1
        + 8
        + if direction == UdpPacketDirection::Server {
            8
        } else {
            0
        }
        + 2;
    if body.len() < fixed_len {
        return Err(invalid_data("ss2022 UDP body is truncated"));
    }

    let mut cursor = body;
    let packet_type = cursor.get_u8();
    if packet_type != direction.header_type() {
        return Err(invalid_data("ss2022 UDP packet direction is invalid"));
    }
    let timestamp = cursor.get_u64();
    if !timestamp_within_tolerance(timestamp, now) {
        return Err(invalid_data("ss2022 UDP timestamp is out of tolerance"));
    }
    let client_session_id = if direction == UdpPacketDirection::Server {
        let id = cursor.get_u64();
        if id == 0 {
            return Err(invalid_data(
                "ss2022 UDP response has a zero client session ID",
            ));
        }
        Some(id)
    } else {
        None
    };
    let padding_len = cursor.get_u16() as usize;
    if cursor.len() < padding_len {
        return Err(invalid_data("ss2022 UDP padding is truncated"));
    }
    cursor.advance(padding_len);

    let (target, port, address_len) = decode_socks_addr(cursor)?;
    if cursor.len() < address_len {
        return Err(invalid_data("ss2022 UDP address is truncated"));
    }
    let payload = cursor[address_len..].to_vec();
    Ok(DecodedUdpPacket {
        session_id,
        packet_id,
        client_session_id,
        target,
        port,
        payload,
    })
}

fn build_udp_eih_layers(
    cipher: Ss22Cipher,
    identity_psks: &[Vec<u8>],
    user_psk: &[u8],
    separate_header: &[u8; UDP_AES_SEPARATE_HEADER_LEN],
) -> std::io::Result<Vec<u8>> {
    if identity_psks.is_empty() {
        return Ok(Vec::new());
    }
    if cipher == Ss22Cipher::Chacha20Poly1305 {
        return Err(invalid_data("ss2022 chacha20 does not support EIH"));
    }

    let mut headers = Vec::with_capacity(identity_psks.len() * 16);
    for (index, identity_psk) in identity_psks.iter().enumerate() {
        let next_psk = if index + 1 < identity_psks.len() {
            identity_psks[index + 1].as_slice()
        } else {
            user_psk
        };
        let mut plaintext = [0u8; 16];
        plaintext.copy_from_slice(&blake3::hash(next_psk).as_bytes()[..16]);
        for (byte, header_byte) in plaintext.iter_mut().zip(separate_header) {
            *byte ^= header_byte;
        }
        let mut block = aes::Block::clone_from_slice(&plaintext);
        aes_encrypt_block(cipher, identity_psk, &mut block)?;
        headers.extend_from_slice(&block);
    }
    Ok(headers)
}

#[derive(Debug, Default)]
struct ServerReplayTable {
    sessions: HashMap<u64, ServerReplaySession>,
}

impl ServerReplayTable {
    fn check_and_mark(
        &mut self,
        session_id: u64,
        packet_id: u64,
        now: Instant,
    ) -> std::io::Result<()> {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.last_seen) <= UDP_SERVER_SESSION_TTL
        });
        if !self.sessions.contains_key(&session_id)
            && self.sessions.len() >= UDP_MAX_SERVER_SESSIONS
        {
            return Err(invalid_data("ss2022 UDP server session limit exceeded"));
        }

        let session = self
            .sessions
            .entry(session_id)
            .or_insert_with(|| ServerReplaySession {
                last_seen: now,
                window: ReplayWindow::default(),
            });
        if !session.window.check_and_mark(packet_id) {
            return Err(invalid_data(
                "ss2022 UDP packet is duplicate or outside the replay window",
            ));
        }
        session.last_seen = now;
        Ok(())
    }
}

#[derive(Debug)]
struct ServerReplaySession {
    last_seen: Instant,
    window: ReplayWindow,
}

#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn check_and_mark(&mut self, packet_id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(packet_id);
            self.bitmap = 1;
            return true;
        };

        if packet_id > highest {
            let shift = packet_id - highest;
            self.bitmap = if shift >= UDP_REPLAY_WINDOW_BITS {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = Some(packet_id);
            return true;
        }

        let distance = highest - packet_id;
        if distance >= UDP_REPLAY_WINDOW_BITS {
            return false;
        }
        let mask = 1u128 << distance;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

fn random_nonzero_u64() -> u64 {
    loop {
        let value = rand::rngs::OsRng.next_u64();
        if value != 0 {
            return value;
        }
    }
}

fn unix_timestamp() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn timestamp_within_tolerance(timestamp: u64, now: u64) -> bool {
    now.abs_diff(timestamp) <= TIMESTAMP_TOLERANCE as u64
}

async fn resolve_first(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    crate::resolve_host(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| invalid_data("ss2022 server resolved to no addresses"))
}

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::other(s)
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn cipher_parse() {
        assert_eq!(
            Ss22Cipher::parse("2022-blake3-aes-128-gcm"),
            Some(Ss22Cipher::Aes128Gcm)
        );
        assert_eq!(
            Ss22Cipher::parse("2022-blake3-aes-256-gcm"),
            Some(Ss22Cipher::Aes256Gcm)
        );
        assert_eq!(
            Ss22Cipher::parse("2022-blake3-chacha20-poly1305"),
            Some(Ss22Cipher::Chacha20Poly1305)
        );
        assert_eq!(Ss22Cipher::parse("aes-128-gcm"), None);
    }

    #[test]
    fn subkey_deterministic() {
        let psk = vec![0x12u8; 16];
        let salt = vec![0x34u8; 16];
        let a = derive_subkey(&psk, &salt, 16);
        let b = derive_subkey(&psk, &salt, 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn round_trip_chunk() {
        let key = vec![0x99u8; 16];
        let mut send = Ss22Cryptor::new(Ss22Cipher::Aes128Gcm, &key);
        let mut recv = Ss22Cryptor::new(Ss22Cipher::Aes128Gcm, &key);
        let pt = b"hello ss2022";
        let ct = send.seal(pt).unwrap();
        let pt2 = recv.open(&ct).unwrap();
        assert_eq!(pt, &pt2[..]);
    }

    #[test]
    fn outbound_psk_len_check() {
        let psk16 = b64(&[0u8; 16]);
        let ok = Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes128Gcm, &psk16);
        assert!(ok.is_ok());
        let err = Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes256Gcm, &psk16);
        assert!(err.is_err());
    }

    #[test]
    fn psk_chain_uses_last_key_as_user_psk() {
        let i0 = [0x10; 16];
        let i1 = [0x20; 16];
        let user = [0x30; 16];
        let chain = format!("{}:{}:{}", b64(&i0), b64(&i1), b64(&user));
        let outbound =
            Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes128Gcm, &chain).unwrap();
        assert_eq!(&*outbound.psk, &user);
        assert_eq!(&*outbound.eih_layers, &[i0.to_vec(), i1.to_vec()]);

        let unpadded = b64(&user).trim_end_matches('=').to_owned();
        let outbound =
            Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes128Gcm, &unpadded).unwrap();
        assert_eq!(&*outbound.psk, &user);
    }

    #[test]
    fn psk_chain_rejects_empty_and_chacha_eih() {
        let key = b64(&[0x11; 32]);
        assert!(
            Ss2022Outbound::new(
                "t",
                "127.0.0.1",
                0,
                Ss22Cipher::Aes256Gcm,
                &format!("{key}:"),
            )
            .is_err()
        );
        assert!(
            Ss2022Outbound::new(
                "t",
                "127.0.0.1",
                0,
                Ss22Cipher::Chacha20Poly1305,
                &format!("{key}:{key}"),
            )
            .is_err()
        );
    }

    #[test]
    fn tcp_eih_layers_use_next_psk_and_identity_subkey() {
        let cipher = Ss22Cipher::Aes128Gcm;
        let layers = vec![vec![0u8; 16], vec![1u8; 16]];
        let user = vec![2u8; 16];
        let salt = vec![0x42u8; 16];
        let out = build_tcp_eih_layers(cipher, &layers, &user, &salt).unwrap();
        assert_eq!(out.len(), 32);

        for (index, encrypted) in out.chunks_exact(16).enumerate() {
            let identity_subkey = derive_identity_subkey(&layers[index], &salt, cipher.key_len());
            let mut block = aes::Block::clone_from_slice(encrypted);
            aes_decrypt_block(cipher, &identity_subkey, &mut block).unwrap();
            let next = if index + 1 < layers.len() {
                layers[index + 1].as_slice()
            } else {
                user.as_slice()
            };
            assert_eq!(&block[..], &blake3::hash(next).as_bytes()[..16]);
        }
    }

    #[test]
    fn tcp_eih_layers_empty() {
        let cipher = Ss22Cipher::Aes256Gcm;
        let salt = vec![0x42u8; 32];
        let out = build_tcp_eih_layers(cipher, &[], &[1u8; 32], &salt).unwrap();
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn udp_aes_eih_packet_round_trip() {
        let psk = vec![0xaau8; 16];
        let identities = vec![vec![0xbbu8; 16], vec![0xccu8; 16]];
        let addr = encode_socks_addr("1.2.3.4", 80);
        let payload = b"hello";
        let timestamp = 1_700_000_000;
        let packet = seal_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &psk,
            &identities,
            UdpPacketDirection::Client,
            0x0102_0304_0506_0708,
            7,
            None,
            &addr,
            payload,
            timestamp,
        )
        .unwrap();
        let expected_len =
            16 + identities.len() * 16 + (1 + 8 + 2 + addr.len() + payload.len()) + UDP_TAG_LEN;
        assert_eq!(packet.len(), expected_len);

        let decoded = open_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &psk,
            &identities,
            UdpPacketDirection::Client,
            &packet,
            timestamp,
        )
        .unwrap();
        assert_eq!(
            decoded,
            DecodedUdpPacket {
                session_id: 0x0102_0304_0506_0708,
                packet_id: 7,
                client_session_id: None,
                target: "1.2.3.4".into(),
                port: 80,
                payload: payload.to_vec(),
            }
        );

        let mut tampered = packet;
        tampered[16] ^= 1;
        assert!(
            open_udp_packet(
                Ss22Cipher::Aes128Gcm,
                &psk,
                &identities,
                UdpPacketDirection::Client,
                &tampered,
                timestamp,
            )
            .is_err()
        );
    }

    #[test]
    fn udp_aes_server_packet_round_trip() {
        let psk = vec![0x44u8; 32];
        let addr = encode_socks_addr("2001:db8::1", 5353);
        let timestamp = 1_700_000_001;
        let packet = seal_udp_packet(
            Ss22Cipher::Aes256Gcm,
            &psk,
            &[],
            UdpPacketDirection::Server,
            99,
            3,
            Some(42),
            &addr,
            b"answer",
            timestamp,
        )
        .unwrap();
        let decoded = open_udp_packet(
            Ss22Cipher::Aes256Gcm,
            &psk,
            &[],
            UdpPacketDirection::Server,
            &packet,
            timestamp,
        )
        .unwrap();
        assert_eq!(decoded.session_id, 99);
        assert_eq!(decoded.packet_id, 3);
        assert_eq!(decoded.client_session_id, Some(42));
        assert_eq!(decoded.target, "2001:db8::1");
        assert_eq!(decoded.port, 5353);
        assert_eq!(decoded.payload, b"answer");
    }

    #[test]
    fn udp_chacha_packet_round_trip() {
        let psk = vec![0x55u8; 32];
        let addr = encode_socks_addr("dns.example", 53);
        let timestamp = 1_700_000_002;
        let packet = seal_udp_packet(
            Ss22Cipher::Chacha20Poly1305,
            &psk,
            &[],
            UdpPacketDirection::Client,
            0x1234,
            0,
            None,
            &addr,
            b"query",
            timestamp,
        )
        .unwrap();
        assert_eq!(
            packet.len(),
            UDP_XCHACHA_NONCE_LEN
                + UDP_AES_SEPARATE_HEADER_LEN
                + 1
                + 8
                + 2
                + addr.len()
                + 5
                + UDP_TAG_LEN
        );
        let decoded = open_udp_packet(
            Ss22Cipher::Chacha20Poly1305,
            &psk,
            &[],
            UdpPacketDirection::Client,
            &packet,
            timestamp,
        )
        .unwrap();
        assert_eq!(decoded.target, "dns.example");
        assert_eq!(decoded.port, 53);
        assert_eq!(decoded.payload, b"query");
    }

    #[test]
    fn udp_rejects_wrong_direction_timestamp_and_client_session() {
        let psk = vec![0x66u8; 16];
        let addr = encode_socks_addr("127.0.0.1", 9);
        let packet = seal_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &psk,
            &[],
            UdpPacketDirection::Server,
            10,
            1,
            Some(20),
            &addr,
            b"x",
            100,
        )
        .unwrap();
        assert!(
            open_udp_packet(
                Ss22Cipher::Aes128Gcm,
                &psk,
                &[],
                UdpPacketDirection::Client,
                &packet,
                100,
            )
            .is_err()
        );
        assert!(
            open_udp_packet(
                Ss22Cipher::Aes128Gcm,
                &psk,
                &[],
                UdpPacketDirection::Server,
                &packet,
                131,
            )
            .is_err()
        );
    }

    #[test]
    fn replay_window_accepts_reordering_and_rejects_duplicates() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_mark(100));
        assert!(window.check_and_mark(102));
        assert!(window.check_and_mark(101));
        assert!(!window.check_and_mark(101));
        assert!(window.check_and_mark(0));
        assert!(!window.check_and_mark(0));
        assert!(window.check_and_mark(300));
        assert!(!window.check_and_mark(100));
    }

    #[test]
    fn server_replay_table_is_scoped_by_session() {
        let now = Instant::now();
        let mut table = ServerReplayTable::default();
        assert!(table.check_and_mark(1, 0, now).is_ok());
        assert!(table.check_and_mark(2, 0, now).is_ok());
        assert!(table.check_and_mark(1, 0, now).is_err());
    }

    #[tokio::test]
    async fn udp_socket_discards_invalid_responses_without_ending_association() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let identity = vec![0x71; 16];
        let user = vec![0x72; 16];
        let chain = format!("{}:{}", b64(&identity), b64(&user));
        let outbound = Ss2022Outbound::new(
            "ss22-test",
            server_addr.ip().to_string(),
            server_addr.port(),
            Ss22Cipher::Aes128Gcm,
            &chain,
        )
        .unwrap();
        let udp = outbound
            .dial_udp(DialContext::udp("unused.example", 53))
            .await
            .unwrap();
        udp.send_to(b"request", "dns.example", 53).await.unwrap();

        let mut wire = vec![0u8; UDP_MAX_PACKET_SIZE];
        let (received, peer) = server.recv_from(&mut wire).await.unwrap();
        let request = open_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &user,
            std::slice::from_ref(&identity),
            UdpPacketDirection::Client,
            &wire[..received],
            unix_timestamp(),
        )
        .unwrap();
        assert_eq!(request.target, "dns.example");
        assert_eq!(request.port, 53);
        assert_eq!(request.payload, b"request");

        let response = seal_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &user,
            &[],
            UdpPacketDirection::Server,
            0x9876,
            0,
            Some(request.session_id),
            &encode_socks_addr("203.0.113.7", 53),
            b"response",
            unix_timestamp(),
        )
        .unwrap();
        server.send_to(&response, peer).await.unwrap();
        let mut output = [0u8; 64];
        let len = udp.recv_from(&mut output).await.unwrap();
        assert_eq!(&output[..len], b"response");

        // A duplicate, a malformed datagram, and a response for another
        // association must be discarded without terminating this association.
        server.send_to(&response, peer).await.unwrap();
        server.send_to(&[0u8; 4], peer).await.unwrap();
        let wrong_session = seal_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &user,
            &[],
            UdpPacketDirection::Server,
            0x9876,
            1,
            Some(request.session_id.wrapping_add(1)),
            &encode_socks_addr("203.0.113.7", 53),
            b"wrong association",
            unix_timestamp(),
        )
        .unwrap();
        server.send_to(&wrong_session, peer).await.unwrap();
        let next_response = seal_udp_packet(
            Ss22Cipher::Aes128Gcm,
            &user,
            &[],
            UdpPacketDirection::Server,
            0x9876,
            1,
            Some(request.session_id),
            &encode_socks_addr("203.0.113.7", 53),
            b"next response",
            unix_timestamp(),
        )
        .unwrap();
        server.send_to(&next_response, peer).await.unwrap();

        let len = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut output))
            .await
            .expect("invalid responses must not stall the association")
            .unwrap();
        assert_eq!(&output[..len], b"next response");
    }

    #[test]
    fn timestamp_validation_handles_full_u64_range_without_overflow() {
        assert!(timestamp_within_tolerance(1_000, 1_030));
        assert!(!timestamp_within_tolerance(1_000, 1_031));
        assert!(!timestamp_within_tolerance(u64::MAX, 1_000));
    }

    #[tokio::test]
    async fn tcp_eih_is_between_salt_and_aead_chunks() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let identity = vec![0x81; 16];
        let user = vec![0x82; 16];
        let identity_for_server = identity.clone();
        let user_for_server = user.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let prefix_len = 16 + 16 + (11 + UDP_TAG_LEN);
            let mut prefix = vec![0u8; prefix_len];
            stream.read_exact(&mut prefix).await.unwrap();
            let salt = &prefix[..16];
            let identity_header = &prefix[16..32];
            let expected_eih = build_tcp_eih_layers(
                Ss22Cipher::Aes128Gcm,
                std::slice::from_ref(&identity_for_server),
                &user_for_server,
                salt,
            )
            .unwrap();
            assert_eq!(identity_header, expected_eih);

            let subkey = derive_subkey(&user_for_server, salt, 16);
            let mut decryptor = Ss22Cryptor::new(Ss22Cipher::Aes128Gcm, &subkey);
            let fixed = decryptor.open(&prefix[32..]).unwrap();
            assert_eq!(fixed[0], 0);
            let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
            let mut encrypted_variable = vec![0u8; variable_len + UDP_TAG_LEN];
            stream.read_exact(&mut encrypted_variable).await.unwrap();
            let variable = decryptor.open(&encrypted_variable).unwrap();
            let (target, port, address_len) = decode_socks_addr(&variable).unwrap();
            assert_eq!(target, "target.example");
            assert_eq!(port, 443);
            let padding_len =
                u16::from_be_bytes([variable[address_len], variable[address_len + 1]]) as usize;
            assert!((1..=MAX_PADDING_LEN as usize).contains(&padding_len));
            assert_eq!(variable.len(), address_len + 2 + padding_len);
        });

        let chain = format!("{}:{}", b64(&identity), b64(&user));
        let outbound = Ss2022Outbound::new(
            "ss22-tcp-test",
            server_addr.ip().to_string(),
            server_addr.port(),
            Ss22Cipher::Aes128Gcm,
            &chain,
        )
        .unwrap();
        let stream = outbound
            .dial_tcp(DialContext::tcp("target.example", 443))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn stream_write_survives_partial_pending_inner_writes() {
        let (client, mut server) = tokio::io::duplex(7);
        let key = vec![0x88; 16];
        let first = b"first payload".to_vec();
        let second = b"second payload".to_vec();
        let expected_wire_len = (2 + UDP_TAG_LEN + first.len() + UDP_TAG_LEN)
            + (2 + UDP_TAG_LEN + second.len() + UDP_TAG_LEN);
        let reader = tokio::spawn(async move {
            let mut wire = vec![0u8; expected_wire_len];
            server.read_exact(&mut wire).await.unwrap();
            wire
        });

        let mut stream = Ss22Stream {
            inner: Box::pin(client),
            send: Ss22Cryptor::new(Ss22Cipher::Aes128Gcm, &key),
            recv_state: RecvState::WaitSalt,
            psk: Arc::from(key.clone().into_boxed_slice()),
            cipher: Ss22Cipher::Aes128Gcm,
            request_salt: Arc::from(vec![0u8; 16].into_boxed_slice()),
            cipher_buf: BytesMut::new(),
            plain_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
        };
        stream.write_all(&first).await.unwrap();
        stream.write_all(&second).await.unwrap();
        stream.flush().await.unwrap();
        let wire = reader.await.unwrap();

        let mut decryptor = Ss22Cryptor::new(Ss22Cipher::Aes128Gcm, &key);
        let mut offset = 0;
        for expected in [&first[..], &second[..]] {
            let length = decryptor
                .open(&wire[offset..offset + 2 + UDP_TAG_LEN])
                .unwrap();
            offset += 2 + UDP_TAG_LEN;
            assert_eq!(
                u16::from_be_bytes(length.try_into().unwrap()) as usize,
                expected.len()
            );
            let payload = decryptor
                .open(&wire[offset..offset + expected.len() + UDP_TAG_LEN])
                .unwrap();
            offset += expected.len() + UDP_TAG_LEN;
            assert_eq!(payload, expected);
        }
        assert_eq!(offset, wire.len());
    }
}
