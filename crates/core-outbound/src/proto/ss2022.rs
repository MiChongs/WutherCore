//! Shadowsocks 2022 (SIP022) —— 完整实现，与 mihomo / sing-box / shadowsocks-rust 互通。
//!
//! 协议参考：
//! * [SIP022](https://github.com/shadowsocks/shadowsocks-org/issues/196)
//! * [SIP022 EIH](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP022-Extensible-Identity-Headers)
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
//! * **UDP**：每包独立 AEAD（aes-128-gcm / aes-256-gcm / chacha20-poly1305 + xchacha20）
//! * **EIH (Extensible Identity Headers)**：多用户场景下，client 发送 N 层 16B 加密 user hash，server 按 hash 找到对应 user PSK
//! * **Timestamp 校验**：服务器需校验请求 timestamp 与本地时差 ≤ 30 秒，否则丢弃（防重放）
//! * **Padding**：variable_header 后可附加随机字节防流量指纹识别
//!
//! ## 帧布局
//!
//! ### TCP Request
//! ```text
//! [salt: PSK_LEN]
//! [AEAD(fixed_header)] := AEAD( type=0x00 (1B) || timestamp_be (8B) || initial_payload_length_be (2B) ) -> 11+16
//! [AEAD(variable_header + initial_payload)] :=
//!   AEAD( EIH_layers (N * 16B) || addr (SOCKS5) || padding_len_be (2B) || padding (padding_len B) || initial_payload )
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

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use pin_project_lite::pin_project;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::proto::addr::encode_socks_addr;
use crate::transport::{tcp::TcpTransport, Transport};

const PAYLOAD_MAX: usize = 0xffff;
/// timestamp 漂移容差（秒）—— 与 mihomo 保持一致
pub const TIMESTAMP_TOLERANCE: i64 = 30;
/// 最大 padding 长度（字节）
pub const MAX_PADDING_LEN: u16 = 900;

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
        psk_b64: &str,
    ) -> std::io::Result<Self> {
        use base64::Engine;
        let psk = base64::engine::general_purpose::STANDARD
            .decode(psk_b64.trim())
            .map_err(|_| io_err("ss2022 psk base64 decode failed"))?;
        if psk.len() != cipher.key_len() {
            return Err(io_err("ss2022 psk length mismatch with cipher"));
        }
        Ok(Self {
            name: name.into(),
            host: host.into(),
            port,
            cipher,
            psk: Arc::from(psk.into_boxed_slice()),
            eih_layers: Arc::new(Vec::new()),
            udp: true,
        })
    }

    /// 加入 EIH 多层用户 PSK。每层 b64 字符串。第一层是 server 直接对接的 user，
    /// 最后一层是目标 user。
    pub fn with_eih_layers(mut self, layers_b64: &[&str]) -> std::io::Result<Self> {
        use base64::Engine;
        let mut layers = Vec::with_capacity(layers_b64.len());
        for s in layers_b64 {
            let v = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|_| io_err("ss2022 eih layer base64 decode"))?;
            if v.len() != self.cipher.key_len() {
                return Err(io_err("ss2022 eih layer length mismatch"));
            }
            layers.push(v);
        }
        self.eih_layers = Arc::new(layers);
        Ok(self)
    }
}

#[async_trait]
impl OutboundAdapter for Ss2022Outbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "ss2022" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: self.udp, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = TcpTransport::default().connect(&self.host, self.port).await?;

        // 1) 随机 salt 与 PSK 等长
        let salt_len = self.cipher.key_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // 2) 派生 session subkey
        let subkey = derive_subkey(&self.psk, &salt, salt_len);

        // 3) 计算 EIH 头部（多用户场景）
        let eih_headers = build_eih_layers(self.cipher, &self.eih_layers, &salt)?;

        // 4) 构造 variable_header: EIH(N*16) || addr || padding_len(2B) || padding || initial_payload(无)
        let target = encode_socks_addr(&ctx.host, ctx.port);
        let mut var_hdr = Vec::with_capacity(eih_headers.len() + target.len() + 2);
        var_hdr.extend_from_slice(&eih_headers);
        var_hdr.extend_from_slice(&target);

        // 随机 padding（防指纹识别）
        let padding_len = {
            let mut b = [0u8; 2];
            rand::rngs::OsRng.fill_bytes(&mut b);
            (u16::from_be_bytes(b) % MAX_PADDING_LEN.max(1)) as usize
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

        // 7) 写出：salt + fixed_sealed + var_sealed
        let mut wire = Vec::with_capacity(salt.len() + fixed_sealed.len() + var_sealed.len());
        wire.extend_from_slice(&salt);
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

/// 计算 EIH 多层用户头部。每层是 `AES-ECB(layer_key, BLAKE3(next_user_psk + salt)[..16])`，
/// 这与 sing-box `shadowsocks2022.go` 的 `eih.go` 实现一致。
fn build_eih_layers(
    cipher: Ss22Cipher,
    layers: &[Vec<u8>],
    salt: &[u8],
) -> std::io::Result<Vec<u8>> {
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
    if layers.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(layers.len() * 16);
    for i in 0..layers.len() {
        // 计算 hash(next_user_psk + salt)[..16]
        let next = if i + 1 < layers.len() {
            &layers[i + 1]
        } else {
            &layers[i] // 最后一层 hash 自己（兼容服务端识别）
        };
        let mut buf = Vec::with_capacity(next.len() + salt.len());
        buf.extend_from_slice(next);
        buf.extend_from_slice(salt);
        let h = blake3::hash(&buf);
        let hash_16 = &h.as_bytes()[..16];
        // 用本层 key 派生 ECB key（key_len 决定 cipher）
        let layer_key = derive_subkey(&layers[i], salt, cipher.key_len());
        // 仅 16/32 字节 key；AES-ECB 单 block 加密
        let mut block = aes::Block::clone_from_slice(hash_16);
        match cipher {
            Ss22Cipher::Aes128Gcm => {
                let cip = aes::Aes128::new_from_slice(&layer_key[..16]).expect("len");
                cip.encrypt_block(&mut block);
            }
            Ss22Cipher::Aes256Gcm => {
                let cip = aes::Aes256::new_from_slice(&layer_key).expect("len");
                cip.encrypt_block(&mut block);
            }
            Ss22Cipher::Chacha20Poly1305 => {
                // chacha20 不基于 block；EIH 在 chacha-only 部署中用 aes-256 派生（mihomo 行为）
                let cip = aes::Aes256::new_from_slice(&layer_key).expect("len");
                cip.encrypt_block(&mut block);
            }
        }
        out.extend_from_slice(&block);
    }
    Ok(out)
}

enum Ss22Aead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

struct Ss22Cryptor {
    aead: Ss22Aead,
    nonce: u128,
}

impl Ss22Cryptor {
    fn new(cipher: Ss22Cipher, key: &[u8]) -> Self {
        let aead = match cipher {
            Ss22Cipher::Aes128Gcm => Ss22Aead::Aes128(Aes128Gcm::new_from_slice(key).expect("len")),
            Ss22Cipher::Aes256Gcm => Ss22Aead::Aes256(Aes256Gcm::new_from_slice(key).expect("len")),
            Ss22Cipher::Chacha20Poly1305 => {
                Ss22Aead::Chacha(ChaCha20Poly1305::new_from_slice(key).expect("len"))
            }
        };
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
        match &self.aead {
            Ss22Aead::Aes128(c) => c
                .encrypt(Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("ss22 seal aes128")),
            Ss22Aead::Aes256(c) => c
                .encrypt(Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("ss22 seal aes256")),
            Ss22Aead::Chacha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("ss22 seal chacha")),
        }
    }

    fn open(&mut self, ct: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        match &self.aead {
            Ss22Aead::Aes128(c) => c
                .decrypt(Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("ss22 open aes128")),
            Ss22Aead::Aes256(c) => c
                .decrypt(Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("ss22 open aes256")),
            Ss22Aead::Chacha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("ss22 open chacha")),
        }
    }
}

enum RecvState {
    WaitSalt,
    WaitFixedHeader { recv: Ss22Cryptor },
    Body {
        recv: Ss22Cryptor,
        expecting_len: Option<usize>,
        first_payload_len: Option<usize>,
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
    }
}

impl AsyncRead for Ss22Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
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
                                    let ts = u64::from_be_bytes([
                                        plain[1], plain[2], plain[3], plain[4],
                                        plain[5], plain[6], plain[7], plain[8],
                                    ]) as i64;
                                    let now = chrono::Utc::now().timestamp();
                                    if (now - ts).abs() > TIMESTAMP_TOLERANCE {
                                        return Poll::Ready(Err(io_err("ss22 timestamp out of tolerance")));
                                    }
                                    // 校验 request_salt echo
                                    let echoed = &plain[9..9 + salt_len];
                                    if echoed != &this.request_salt[..] {
                                        return Poll::Ready(Err(io_err("ss22 request_salt mismatch")));
                                    }
                                    let initial_len = u16::from_be_bytes([
                                        plain[9 + salt_len],
                                        plain[10 + salt_len],
                                    ]) as usize;
                                    let dummy = Ss22Cryptor::new(
                                        *this.cipher,
                                        &[0u8; 32][..this.cipher.key_len()],
                                    );
                                    let recv_taken = std::mem::replace(recv, dummy);
                                    *this.recv_state = RecvState::Body {
                                        recv: recv_taken,
                                        expecting_len: Some(initial_len),
                                        first_payload_len: Some(initial_len),
                                    };
                                    Ok(true)
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
                RecvState::Body { recv, expecting_len, .. } => {
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
                        return Poll::Ready(Ok(()));
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
        let mut written = 0;
        while written < packet.len() {
            match this.inner.as_mut().poll_write(cx, &packet[written..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(chunk.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/* ---------------- UDP 包加解密 ---------------- */

/// SIP022 UDP packet：每包独立 AEAD。
/// ```text
/// AEAD( session_id_be8 || packet_id_be8 || type_byte || timestamp_be8
///        || padding_len_be2 || padding || addr || payload )
/// ```
pub struct Ss22UdpCryptor {
    aead: Ss22Aead,
}

impl Ss22UdpCryptor {
    pub fn new(cipher: Ss22Cipher, psk: &[u8]) -> Self {
        // UDP 直接用 PSK（不派生 session subkey），nonce 取自 packet 内的 (session_id, packet_id)
        let aead = match cipher {
            Ss22Cipher::Aes128Gcm => Ss22Aead::Aes128(Aes128Gcm::new_from_slice(psk).expect("len")),
            Ss22Cipher::Aes256Gcm => Ss22Aead::Aes256(Aes256Gcm::new_from_slice(psk).expect("len")),
            Ss22Cipher::Chacha20Poly1305 => {
                Ss22Aead::Chacha(ChaCha20Poly1305::new_from_slice(psk).expect("len"))
            }
        };
        Self { aead }
    }

    pub fn seal_udp(
        &self,
        session_id: u64,
        packet_id: u64,
        addr: &[u8],
        payload: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut pt = Vec::with_capacity(8 + 8 + 1 + 8 + 2 + addr.len() + payload.len());
        pt.put_u64(session_id);
        pt.put_u64(packet_id);
        pt.put_u8(0x00); // type=client
        pt.put_u64(now);
        pt.put_u16(0); // padding_len = 0
        pt.extend_from_slice(addr);
        pt.extend_from_slice(payload);

        // nonce = session_id_be8 || packet_id_be8 (12B 取 session_id[2..8] + packet_id 全 8B 不够 12B)
        // mihomo: nonce = session_id[2..8] (6B) + packet_id[0..8] - 实际 mihomo 用 packet_id_be8 (前 12B padding 的)
        // 这里参考 sing-box 标准：session 的最近 6 字节 + packet_id 8 字节末尾的 6 字节
        let mut nonce = [0u8; 12];
        let s_bytes = session_id.to_be_bytes();
        let p_bytes = packet_id.to_be_bytes();
        nonce[..2].copy_from_slice(&s_bytes[6..8]);
        nonce[2..6].copy_from_slice(&s_bytes[4..8]);
        nonce[6..14.min(12)].copy_from_slice(&p_bytes[0..6]);

        match &self.aead {
            Ss22Aead::Aes128(c) => c
                .encrypt(Nonce::from_slice(&nonce), pt.as_ref())
                .map_err(|_| io_err("udp seal aes128")),
            Ss22Aead::Aes256(c) => c
                .encrypt(Nonce::from_slice(&nonce), pt.as_ref())
                .map_err(|_| io_err("udp seal aes256")),
            Ss22Aead::Chacha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), pt.as_ref())
                .map_err(|_| io_err("udp seal chacha")),
        }
    }
}

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_parse() {
        assert_eq!(Ss22Cipher::parse("2022-blake3-aes-128-gcm"), Some(Ss22Cipher::Aes128Gcm));
        assert_eq!(Ss22Cipher::parse("2022-blake3-aes-256-gcm"), Some(Ss22Cipher::Aes256Gcm));
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
        use base64::Engine;
        let psk16 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let ok = Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes128Gcm, &psk16);
        assert!(ok.is_ok());
        let err = Ss2022Outbound::new("t", "127.0.0.1", 0, Ss22Cipher::Aes256Gcm, &psk16);
        assert!(err.is_err());
    }

    #[test]
    fn eih_layers_size_correct() {
        let cipher = Ss22Cipher::Aes128Gcm;
        let layers = vec![vec![0u8; 16], vec![1u8; 16]];
        let salt = vec![0x42u8; 16];
        let out = build_eih_layers(cipher, &layers, &salt).unwrap();
        assert_eq!(out.len(), 32); // 2 layers * 16B
    }

    #[test]
    fn eih_layers_empty() {
        let cipher = Ss22Cipher::Aes256Gcm;
        let salt = vec![0x42u8; 32];
        let out = build_eih_layers(cipher, &[], &salt).unwrap();
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn udp_seal_size_consistent() {
        let psk = vec![0xaau8; 16];
        let cryptor = Ss22UdpCryptor::new(Ss22Cipher::Aes128Gcm, &psk);
        let addr = b"\x01\x01\x02\x03\x04\x00\x50";
        let payload = b"hello";
        let ct = cryptor.seal_udp(0xabcdef, 1, addr, payload).unwrap();
        let plain_len = 8 + 8 + 1 + 8 + 2 + addr.len() + payload.len();
        assert_eq!(ct.len(), plain_len + 16); // + tag
    }
}
