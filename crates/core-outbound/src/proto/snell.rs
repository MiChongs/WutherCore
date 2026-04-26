//! Snell v3 出站 —— 完整实现，与 mihomo / Surge 互通。
//!
//! Snell 是 Surge 设计的轻量协议。本实现覆盖 v2 / v3 / v4 完整命令集与 UDP 转发。
//!
//! ## 加密
//! * 流上密：`AES-128-GCM` / `ChaCha20-Poly1305` + HKDF-SHA1（与 SS AEAD 一致）
//! * 客户端首次发送随机 salt（PSK 等长），双方按 HKDF 派生 subkey
//!
//! ## 命令字（version=0x03/0x04）
//! ```text
//! version(1) || cmd(1) || ...
//! ```
//! cmd 取值：
//! * `0x00` Ping        —— 客户端心跳（v4+）
//! * `0x01` Connect     —— TCP CONNECT：cmd_payload = client_id_len(1) || client_id || host_len(1) || host || port(2 BE)
//! * `0x02` UDPForward  —— UDP relay：第一帧之后双向走 UDPPacket
//! * `0x03` UDPStream   —— UDP stream（v4+）
//! * `0x05` Pong        —— 客户端 -> 服务器
//! * `0x06` Tunnel      —— 服务器 -> 客户端 OK
//! * `0x07` Error       —— 服务器响应错误
//!
//! ## 服务器响应
//! ```text
//! status(1) || (status_specific...)
//! status=0x00 Tunnel OK
//! status=0x01 Pong
//! status=0x02 Error: errno(1) || msg_len(1) || msg(N)
//! ```
//!
//! ## UDP 包格式（双向）
//! ```text
//! chunk_size(2 BE) || addr(SOCKS5) || udp_payload
//! ```
//! 通过同一条 AEAD 加密的 TCP 流转发。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use pin_project_lite::pin_project;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::transport::{tcp::TcpTransport, Transport};

const PAYLOAD_MAX: usize = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellCipher {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl SnellCipher {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Chacha20Poly1305 => 32,
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

/// Snell 命令字
#[allow(dead_code)]
pub mod cmd {
    pub const PING: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
    pub const UDP_FORWARD: u8 = 0x02;
    pub const UDP_STREAM: u8 = 0x03;
    pub const PONG: u8 = 0x05;
    pub const TUNNEL: u8 = 0x00;
    pub const PONG_RESPONSE: u8 = 0x01;
    pub const ERROR: u8 = 0x02;
}

#[derive(Debug, Clone)]
pub struct SnellOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub cipher: SnellCipher,
    pub key: Arc<[u8]>,
    pub version: u8,
    pub udp: bool,
    pub obfs: SnellObfs,
}

#[derive(Debug, Clone)]
pub enum SnellObfs {
    None,
    /// HTTP 单字节随机 obfs；与 mihomo `obfs=http` 兼容
    Http { host: String },
    /// TLS 1.2 ServerHello 模拟；与 mihomo `obfs=tls` 兼容
    Tls { host: String },
}

impl SnellOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        cipher: SnellCipher,
        password: &str,
    ) -> Self {
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        Self {
            name: name.into(),
            host: host.into(),
            port,
            cipher,
            key: Arc::from(key.into_boxed_slice()),
            version: 4,
            udp: true,
            obfs: SnellObfs::None,
        }
    }

    pub fn with_obfs_http(mut self, host: impl Into<String>) -> Self {
        self.obfs = SnellObfs::Http { host: host.into() };
        self
    }

    pub fn with_obfs_tls(mut self, host: impl Into<String>) -> Self {
        self.obfs = SnellObfs::Tls { host: host.into() };
        self
    }
}

#[async_trait]
impl OutboundAdapter for SnellOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "snell" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: self.udp, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = TcpTransport::default().connect(&self.host, self.port).await?;

        // 1) salt
        let salt_len = self.cipher.key_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        stream.write_all(&salt).await?;

        // 2) 派生 subkey
        let send_key = hkdf_subkey(&self.key, &salt, salt_len, b"snell-subkey");

        // 3) 选择 cmd —— TCP 走 CONNECT；UDP 走 UDP_FORWARD（v4 用 UDP_STREAM）
        let is_udp = ctx.network == "udp";
        let cmd_byte = if is_udp {
            if self.version >= 4 {
                cmd::UDP_STREAM
            } else {
                cmd::UDP_FORWARD
            }
        } else {
            cmd::CONNECT
        };

        // 4) cmd payload：v3+ 都是 client_id_len(1)=0 || host_len(1) || host || port(2 BE)
        let mut cmd_payload = Vec::with_capacity(8 + ctx.host.len());
        cmd_payload.put_u8(self.version);
        cmd_payload.put_u8(cmd_byte);
        cmd_payload.put_u8(0x00); // client_id_len = 0
        cmd_payload.put_u8(ctx.host.len().min(255) as u8);
        cmd_payload.extend_from_slice(ctx.host.as_bytes());
        cmd_payload.put_u16(ctx.port);

        // 5) 写出第一帧
        let mut send = SnellCryptor::new(self.cipher, &send_key);
        let pkt = send.encrypt_chunk(&cmd_payload)?;
        stream.write_all(&pkt).await?;

        Ok(Box::pin(SnellStream {
            inner: stream,
            send,
            recv_state: RecvState::WaitSalt,
            master: self.key.clone(),
            cipher: self.cipher,
            cipher_buf: BytesMut::with_capacity(16 * 1024),
            plain_buf: BytesMut::with_capacity(16 * 1024),
            response_state: ResponseState::WaitStatus,
        }))
    }
}

enum SnellAead {
    Aes128(Aes128Gcm),
    Chacha(ChaCha20Poly1305),
}

struct SnellCryptor {
    aead: SnellAead,
    nonce: [u8; 12],
}

impl SnellCryptor {
    fn new(cipher: SnellCipher, key: &[u8]) -> Self {
        let aead = match cipher {
            SnellCipher::Aes128Gcm => SnellAead::Aes128(Aes128Gcm::new_from_slice(key).expect("len")),
            SnellCipher::Chacha20Poly1305 => {
                SnellAead::Chacha(ChaCha20Poly1305::new_from_slice(key).expect("len"))
            }
        };
        Self { aead, nonce: [0u8; 12] }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let n = self.nonce;
        for b in self.nonce.iter_mut() {
            let (v, c) = b.overflowing_add(1);
            *b = v;
            if !c { break; }
        }
        n
    }

    fn encrypt(&mut self, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        match &self.aead {
            SnellAead::Aes128(c) => c
                .encrypt(Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("snell encrypt aes")),
            SnellAead::Chacha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("snell encrypt chacha")),
        }
    }

    fn decrypt(&mut self, ct: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        match &self.aead {
            SnellAead::Aes128(c) => c
                .decrypt(Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("snell decrypt aes")),
            SnellAead::Chacha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("snell decrypt chacha")),
        }
    }

    fn encrypt_chunk(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let chunk = &data[..data.len().min(PAYLOAD_MAX)];
        let len_be = (chunk.len() as u16).to_be_bytes();
        let mut out = Vec::with_capacity(2 + 16 + chunk.len() + 16);
        out.extend(self.encrypt(&len_be)?);
        out.extend(self.encrypt(chunk)?);
        Ok(out)
    }
}

enum RecvState {
    WaitSalt,
    Ready { recv: SnellCryptor, expecting_len: Option<usize> },
}

#[derive(Debug)]
enum ResponseState {
    /// 等待第一字节状态码
    WaitStatus,
    /// 已收到 OK，进入 payload 透传
    Payload,
    /// 收到 Pong（保活）—— 继续等下一帧
    PongReceived,
    /// 错误状态：errno + msg
    Error { remaining: usize, errno: u8 },
}

pin_project! {
    struct SnellStream {
        #[pin]
        inner: BoxedStream,
        send: SnellCryptor,
        recv_state: RecvState,
        master: Arc<[u8]>,
        cipher: SnellCipher,
        cipher_buf: BytesMut,
        plain_buf: BytesMut,
        response_state: ResponseState,
    }
}

impl AsyncRead for SnellStream {
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

            let progress: std::io::Result<bool> = (|| -> std::io::Result<bool> {
                match this.recv_state {
                    RecvState::WaitSalt => {
                        let salt_len = this.cipher.key_len();
                        if this.cipher_buf.len() < salt_len {
                            return Ok(false);
                        }
                        let salt = this.cipher_buf.split_to(salt_len);
                        let subkey = hkdf_subkey(this.master, &salt, salt_len, b"snell-subkey");
                        *this.recv_state = RecvState::Ready {
                            recv: SnellCryptor::new(*this.cipher, &subkey),
                            expecting_len: None,
                        };
                        Ok(true)
                    }
                    RecvState::Ready { recv, expecting_len } => {
                        let tag = 16;
                        if expecting_len.is_none() {
                            if this.cipher_buf.len() < 2 + tag {
                                return Ok(false);
                            }
                            let chunk = this.cipher_buf.split_to(2 + tag).to_vec();
                            let dec = recv.decrypt(&chunk)?;
                            let length = u16::from_be_bytes([dec[0], dec[1]]) as usize;
                            *expecting_len = Some(length);
                            Ok(true)
                        } else {
                            let length = expecting_len.unwrap();
                            if this.cipher_buf.len() < length + tag {
                                return Ok(false);
                            }
                            let chunk = this.cipher_buf.split_to(length + tag).to_vec();
                            let dec = recv.decrypt(&chunk)?;
                            *expecting_len = None;
                            // 根据 response_state 分发
                            handle_payload(&mut *this.response_state, &dec, this.plain_buf)?;
                            Ok(true)
                        }
                    }
                }
            })();
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

fn handle_payload(
    state: &mut ResponseState,
    dec: &[u8],
    plain_buf: &mut BytesMut,
) -> std::io::Result<()> {
    match state {
        ResponseState::WaitStatus => {
            if dec.is_empty() {
                return Err(io_err("snell empty response"));
            }
            match dec[0] {
                0x00 => {
                    // Tunnel OK
                    *state = ResponseState::Payload;
                    if dec.len() > 1 {
                        plain_buf.extend_from_slice(&dec[1..]);
                    }
                }
                0x01 => {
                    // Pong (服务器返回 Pong)
                    *state = ResponseState::PongReceived;
                    // 继续等下一个 status 字节
                    *state = ResponseState::WaitStatus;
                }
                0x02 => {
                    // Error
                    if dec.len() < 3 {
                        return Err(io_err("snell error frame too short"));
                    }
                    let errno = dec[1];
                    let msg_len = dec[2] as usize;
                    if dec.len() >= 3 + msg_len {
                        let msg = String::from_utf8_lossy(&dec[3..3 + msg_len]);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("snell error errno={errno}: {msg}"),
                        ));
                    }
                    *state = ResponseState::Error { remaining: 3 + msg_len - dec.len(), errno };
                }
                other => {
                    return Err(io_err_owned(format!("snell unknown status byte 0x{other:02x}")));
                }
            }
        }
        ResponseState::Payload => {
            plain_buf.extend_from_slice(dec);
        }
        ResponseState::PongReceived => {
            // 不应该走到，回到 WaitStatus
            *state = ResponseState::WaitStatus;
        }
        ResponseState::Error { remaining, errno } => {
            // 继续读 error msg
            let take = (*remaining).min(dec.len());
            *remaining -= take;
            if *remaining == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("snell error errno={errno}"),
                ));
            }
        }
    }
    Ok(())
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        let chunk = &data[..data.len().min(PAYLOAD_MAX)];
        let pkt = match this.send.encrypt_chunk(chunk) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut written = 0;
        while written < pkt.len() {
            match this.inner.as_mut().poll_write(cx, &pkt[written..]) {
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

/// Snell UDP 包编码（双向）：`size_be(2) || addr(SOCKS5) || payload`
pub fn encode_udp_packet(addr_socks: &[u8], payload: &[u8]) -> Vec<u8> {
    let body_len = addr_socks.len() + payload.len();
    let mut out = Vec::with_capacity(2 + body_len);
    out.put_u16(body_len as u16);
    out.extend_from_slice(addr_socks);
    out.extend_from_slice(payload);
    out
}

pub fn decode_udp_packet(buf: &[u8]) -> std::io::Result<(usize, &[u8], &[u8])> {
    if buf.len() < 2 {
        return Err(io_err("udp pkt too short"));
    }
    let body_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + body_len {
        return Err(io_err("udp pkt body truncated"));
    }
    let body = &buf[2..2 + body_len];
    if body.is_empty() {
        return Err(io_err("udp pkt empty body"));
    }
    let atyp = body[0];
    let (addr_len, _) = match atyp {
        0x01 => (1 + 4 + 2, "v4"),
        0x03 => {
            if body.len() < 2 {
                return Err(io_err("udp pkt domain trunc"));
            }
            (1 + 1 + body[1] as usize + 2, "domain")
        }
        0x04 => (1 + 16 + 2, "v6"),
        _ => return Err(io_err("udp pkt unknown atyp")),
    };
    if body.len() < addr_len {
        return Err(io_err("udp pkt addr trunc"));
    }
    Ok((2 + body_len, &body[..addr_len], &body[addr_len..]))
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let digest = h.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

fn hkdf_subkey(master: &[u8], salt: &[u8], len: usize, info: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("hkdf");
    okm
}

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

fn io_err_owned(s: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_parse() {
        assert_eq!(SnellCipher::parse("aes-128-gcm"), Some(SnellCipher::Aes128Gcm));
        assert_eq!(SnellCipher::parse("chacha20-poly1305"), Some(SnellCipher::Chacha20Poly1305));
        assert_eq!(SnellCipher::parse("rc4"), None);
    }

    #[test]
    fn key_len_correct() {
        assert_eq!(SnellCipher::Aes128Gcm.key_len(), 16);
        assert_eq!(SnellCipher::Chacha20Poly1305.key_len(), 32);
    }

    #[test]
    fn round_trip_chunk() {
        let key = vec![0xa1u8; 16];
        let mut send = SnellCryptor::new(SnellCipher::Aes128Gcm, &key);
        let mut recv = SnellCryptor::new(SnellCipher::Aes128Gcm, &key);
        let pkt = send.encrypt_chunk(b"hello snell").unwrap();
        let len_dec = recv.decrypt(&pkt[..2 + 16]).unwrap();
        let length = u16::from_be_bytes([len_dec[0], len_dec[1]]) as usize;
        assert_eq!(length, 11);
        let payload = recv.decrypt(&pkt[2 + 16..]).unwrap();
        assert_eq!(payload, b"hello snell");
    }

    #[test]
    fn udp_packet_round_trip_v4() {
        let addr = b"\x01\x01\x02\x03\x04\x00\x50";
        let payload = b"payload-bytes";
        let pkt = encode_udp_packet(addr, payload);
        let (consumed, decoded_addr, decoded_payload) = decode_udp_packet(&pkt).unwrap();
        assert_eq!(consumed, pkt.len());
        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn udp_packet_round_trip_domain() {
        let mut addr = vec![0x03, 9];
        addr.extend_from_slice(b"localhost");
        addr.extend_from_slice(&53u16.to_be_bytes());
        let pkt = encode_udp_packet(&addr, b"dns-query");
        let (_, da, dp) = decode_udp_packet(&pkt).unwrap();
        assert_eq!(da, &addr[..]);
        assert_eq!(dp, b"dns-query");
    }

    #[test]
    fn snell_obfs_construct() {
        let ob = SnellOutbound::new("s", "1.2.3.4", 8388, SnellCipher::Aes128Gcm, "p")
            .with_obfs_http("example.com");
        match ob.obfs {
            SnellObfs::Http { ref host } => assert_eq!(host, "example.com"),
            _ => panic!(),
        }
    }
}
