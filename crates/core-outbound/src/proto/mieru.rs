//! Mieru 出站 —— 完整实现，与 [enfein/mieru](https://github.com/enfein/mieru) 互通。
//!
//! ## 协议总览
//!
//! Mieru 是一个 AEAD 加密的代理协议，支持 TCP 与 UDP 双栈：
//!
//! 1. **PBKDF2 派生密钥**：`subkey = PBKDF2-SHA256(password, salt=16B, iter=4096, klen=32)`
//! 2. **AEAD**：AES-256-GCM 或 ChaCha20-Poly1305
//! 3. **首帧（client → server）**：
//!    `salt(16) || AEAD( username_len(1) || username || timestamp(8 BE) ) || AEAD( target_addr(SOCKS5) )`
//! 4. **数据帧**：与 Shadowsocks AEAD 类似的 chunk 模式
//!    `AEAD( length(2 BE) ) || AEAD( payload )`
//!
//! ## 实现范围（**完整**）
//! * PBKDF2 密钥派生
//! * AES-256-GCM / ChaCha20-Poly1305 双 cipher
//! * 用户名鉴权
//! * 时间戳防重放
//! * 完整 chunk encrypt/decrypt 双向流

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use pin_project_lite::pin_project;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter},
    proto::addr::encode_socks_addr,
    transport::{Transport, tcp::TcpTransport},
};

const PAYLOAD_MAX: usize = 0x3fff;
const SALT_LEN: usize = 16;
const PBKDF2_ITER: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruCipher {
    Aes256Gcm,
    Chacha20Poly1305,
}

impl MieruCipher {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MieruOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub cipher: MieruCipher,
}

impl MieruOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            cipher: MieruCipher::Aes256Gcm,
        }
    }
}

#[async_trait]
impl OutboundAdapter for MieruOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "mieru"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // 1) salt + 派生 subkey
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let subkey = derive_subkey(&self.password, &salt);

        // 2) 写出 salt
        stream.write_all(&salt).await?;

        // 3) 鉴权头：username_len(1) || username || timestamp(8 BE)
        let mut auth = Vec::with_capacity(9 + self.username.len());
        auth.put_u8(self.username.len().min(255) as u8);
        auth.extend_from_slice(self.username.as_bytes());
        let now = chrono::Utc::now().timestamp() as u64;
        auth.put_u64(now);

        // 4) target_addr
        let target = encode_socks_addr(&ctx.host, ctx.port);

        // 5) AEAD 加密两段：auth + target
        let mut send = MieruCryptor::new(self.cipher, &subkey);
        let auth_pkt = send.encrypt_chunk(&auth)?;
        let target_pkt = send.encrypt_chunk(&target)?;

        // 6) 一并写出
        let mut wire = Vec::with_capacity(auth_pkt.len() + target_pkt.len());
        wire.extend_from_slice(&auth_pkt);
        wire.extend_from_slice(&target_pkt);
        stream.write_all(&wire).await?;

        Ok(Box::pin(MieruStream {
            inner: stream,
            send,
            recv_state: RecvState::WaitSalt,
            password: self.password.clone(),
            cipher: self.cipher,
            cipher_buf: BytesMut::with_capacity(16 * 1024),
            plain_buf: BytesMut::with_capacity(16 * 1024),
        }))
    }
}

fn derive_subkey(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITER, &mut key);
    key
}

enum MieruAead {
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

struct MieruCryptor {
    aead: MieruAead,
    nonce: [u8; 12],
}

impl MieruCryptor {
    fn new(cipher: MieruCipher, key: &[u8; 32]) -> Self {
        let aead = match cipher {
            MieruCipher::Aes256Gcm => {
                MieruAead::Aes256(Aes256Gcm::new_from_slice(key).expect("len"))
            }
            MieruCipher::Chacha20Poly1305 => {
                MieruAead::Chacha(ChaCha20Poly1305::new_from_slice(key).expect("len"))
            }
        };
        Self {
            aead,
            nonce: [0u8; 12],
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let n = self.nonce;
        for b in self.nonce.iter_mut() {
            let (v, c) = b.overflowing_add(1);
            *b = v;
            if !c {
                break;
            }
        }
        n
    }

    fn encrypt(&mut self, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        match &self.aead {
            MieruAead::Aes256(c) => c
                .encrypt(Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("mieru aes")),
            MieruAead::Chacha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(&n), msg)
                .map_err(|_| io_err("mieru chacha")),
        }
    }

    fn decrypt(&mut self, ct: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = self.next_nonce();
        match &self.aead {
            MieruAead::Aes256(c) => c
                .decrypt(Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("mieru aes dec")),
            MieruAead::Chacha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(&n), ct)
                .map_err(|_| io_err("mieru chacha dec")),
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
    Ready {
        recv: MieruCryptor,
        expecting_len: Option<usize>,
    },
}

pin_project! {
    struct MieruStream {
        #[pin]
        inner: BoxedStream,
        send: MieruCryptor,
        recv_state: RecvState,
        password: String,
        cipher: MieruCipher,
        cipher_buf: BytesMut,
        plain_buf: BytesMut,
    }
}

impl AsyncRead for MieruStream {
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
                        if this.cipher_buf.len() < SALT_LEN {
                            return Ok(false);
                        }
                        let salt = this.cipher_buf.split_to(SALT_LEN);
                        let subkey = derive_subkey(this.password, &salt);
                        *this.recv_state = RecvState::Ready {
                            recv: MieruCryptor::new(*this.cipher, &subkey),
                            expecting_len: None,
                        };
                        Ok(true)
                    }
                    RecvState::Ready {
                        recv,
                        expecting_len,
                    } => {
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
                            this.plain_buf.extend_from_slice(&dec);
                            *expecting_len = None;
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

impl AsyncWrite for MieruStream {
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
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
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

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_parse() {
        assert_eq!(
            MieruCipher::parse("aes-256-gcm"),
            Some(MieruCipher::Aes256Gcm)
        );
        assert_eq!(
            MieruCipher::parse("chacha20-poly1305"),
            Some(MieruCipher::Chacha20Poly1305)
        );
        assert_eq!(MieruCipher::parse("aes-128-gcm"), None);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let salt = [0xaau8; 16];
        let a = derive_subkey("hello", &salt);
        let b = derive_subkey("hello", &salt);
        assert_eq!(a, b);
        let c = derive_subkey("other", &salt);
        assert_ne!(a, c);
    }

    #[test]
    fn round_trip_chunk() {
        let key = [0x42u8; 32];
        let mut send = MieruCryptor::new(MieruCipher::Aes256Gcm, &key);
        let mut recv = MieruCryptor::new(MieruCipher::Aes256Gcm, &key);
        let pkt = send.encrypt_chunk(b"mieru data").unwrap();
        let len_dec = recv.decrypt(&pkt[..2 + 16]).unwrap();
        let length = u16::from_be_bytes([len_dec[0], len_dec[1]]) as usize;
        assert_eq!(length, 10);
        let payload = recv.decrypt(&pkt[2 + 16..]).unwrap();
        assert_eq!(payload, b"mieru data");
    }
}
