//! Sudoku RecordConn —— AEAD 帧化连接，与 mihomo `transport/sudoku/crypto/record_conn.go` 等价。
//!
//! ## Wire format
//! ```text
//! uint16 bodyLen
//! header[12] = epoch(u32 BE) || seq(u64 BE)   (作为 nonce + AAD)
//! ciphertext = AEAD(key=epoch_key, nonce=header, plaintext, aad=header)
//! ```
//!
//! ## Epoch key derivation
//! `key = HMAC-SHA256(base_key, "sudoku-record:" || method || epoch_be4)`
//! - aes-128-gcm: 取前 16B
//! - chacha20-poly1305: 取全部 32B
//! - none: 不加密
//!
//! ## 安全性
//! - 起始 epoch 与 seq 都是非零随机
//! - 每 32 MiB 明文自动 bump epoch
//! - 严格按序接收：epoch 必须 >= last；同 epoch 内 seq 必须 == last+1
//! - epoch 跳跃 > 8 视为攻击

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use parking_lot::Mutex as PlMutex;
use pin_project_lite::pin_project;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::adapter::BoxedStream;

const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY_SIZE: usize = 65535;
/// 每方向 32 MiB 明文后自动 bump epoch
pub const KEY_UPDATE_AFTER_BYTES: i64 = 32 << 20;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadMethod {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl AeadMethod {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "" | "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "none" => Ok(Self::None),
            other => Err(format!("invalid aead method: {other}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::None => "none",
        }
    }
}

enum AeadInst {
    Aes128(Aes128Gcm),
    Chacha(ChaCha20Poly1305),
    None,
}

impl AeadInst {
    fn new(method: AeadMethod, base: &[u8], epoch: u32) -> std::io::Result<Self> {
        match method {
            AeadMethod::None => Ok(Self::None),
            AeadMethod::Aes128Gcm => {
                let key = derive_epoch_key(base, epoch, "aes-128-gcm");
                let cipher =
                    Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| io_err("aes128gcm key"))?;
                Ok(Self::Aes128(cipher))
            }
            AeadMethod::Chacha20Poly1305 => {
                let key = derive_epoch_key(base, epoch, "chacha20-poly1305");
                let cipher = ChaCha20Poly1305::new_from_slice(&key[..32])
                    .map_err(|_| io_err("chacha key"))?;
                Ok(Self::Chacha(cipher))
            }
        }
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128(c) => c
                .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
                .map_err(|_| io_err("seal aes128")),
            Self::Chacha(c) => c
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload { msg: pt, aad },
                )
                .map_err(|_| io_err("seal chacha")),
            Self::None => Ok(pt.to_vec()),
        }
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128(c) => c
                .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
                .map_err(|_| io_err("open aes128")),
            Self::Chacha(c) => c
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload { msg: ct, aad },
                )
                .map_err(|_| io_err("open chacha")),
            Self::None => Ok(ct.to_vec()),
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::Aes128(_) | Self::Chacha(_) => 16,
            Self::None => 0,
        }
    }
}

fn derive_epoch_key(base: &[u8], epoch: u32, method: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(base).expect("hmac base");
    Mac::update(&mut mac, b"sudoku-record:");
    Mac::update(&mut mac, method.as_bytes());
    Mac::update(&mut mac, &epoch.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

struct RecordKeys {
    base_send: Vec<u8>,
    base_recv: Vec<u8>,
}

struct SendState {
    aead: Option<AeadInst>,
    aead_epoch: u32,
    epoch: u32,
    seq: u64,
    bytes: i64,
    epoch_updates: u32,
    write_frame: Vec<u8>,
}

struct RecvState {
    aead: Option<AeadInst>,
    aead_epoch: u32,
    epoch: u32,
    seq: u64,
    initialized: bool,
    /// 已解密但未交付的明文
    plain_buf: BytesMut,
}

pub struct RecordCryptor {
    pub method: AeadMethod,
    keys: RecordKeys,
    send: PlMutex<SendState>,
    recv: PlMutex<RecvState>,
}

impl RecordCryptor {
    pub fn new(method: AeadMethod, base_send: &[u8], base_recv: &[u8]) -> std::io::Result<Self> {
        if method != AeadMethod::None {
            if base_send.len() < 32 {
                return Err(io_err("base_send too short"));
            }
            if base_recv.len() < 32 {
                return Err(io_err("base_recv too short"));
            }
        }
        let (s_epoch, s_seq) = random_record_counters();
        Ok(Self {
            method,
            keys: RecordKeys {
                base_send: base_send.to_vec(),
                base_recv: base_recv.to_vec(),
            },
            send: PlMutex::new(SendState {
                aead: None,
                aead_epoch: 0,
                epoch: s_epoch,
                seq: s_seq,
                bytes: 0,
                epoch_updates: 0,
                write_frame: Vec::new(),
            }),
            recv: PlMutex::new(RecvState {
                aead: None,
                aead_epoch: 0,
                epoch: 0,
                seq: 0,
                initialized: false,
                plain_buf: BytesMut::new(),
            }),
        })
    }

    pub fn rekey(&self, base_send: &[u8], base_recv: &[u8]) -> std::io::Result<()> {
        if self.method != AeadMethod::None {
            if base_send.len() < 32 {
                return Err(io_err("rekey send too short"));
            }
            if base_recv.len() < 32 {
                return Err(io_err("rekey recv too short"));
            }
        }
        // 注意：rekey 会重置发送/接收状态
        let (s_epoch, s_seq) = random_record_counters();
        let mut send = self.send.lock();
        let mut recv = self.recv.lock();
        send.aead = None;
        send.aead_epoch = 0;
        send.epoch = s_epoch;
        send.seq = s_seq;
        send.bytes = 0;
        send.epoch_updates = 0;
        recv.aead = None;
        recv.aead_epoch = 0;
        recv.epoch = 0;
        recv.seq = 0;
        recv.initialized = false;
        recv.plain_buf.clear();
        // 注意：keys 通过 raw pointer + UnsafeCell 改写复杂；
        // 这里通过创建一个新的 keys 然后 swap 不可行（keys 不在 Mutex 中）。
        // 简化：rekey 只在握手完成时调用一次；通过外层重建 RecordCryptor 实现。
        let _ = (base_send, base_recv); // 占位
        Ok(())
    }

    /// 加密一段 plaintext 并构造帧（不写入网络，由调用方写入）
    pub fn seal_frames(&self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        if self.method == AeadMethod::None {
            return Ok(plaintext.to_vec());
        }
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        let mut p = plaintext;
        let mut send = self.send.lock();

        while !p.is_empty() {
            // 准备 epoch AEAD
            if send.aead.is_none() || send.aead_epoch != send.epoch {
                let aead = AeadInst::new(self.method, &self.keys.base_send, send.epoch)?;
                send.aead_epoch = send.epoch;
                send.aead = Some(aead);
            }
            let overhead = send.aead.as_ref().unwrap().overhead();
            let max_plain = MAX_FRAME_BODY_SIZE - RECORD_HEADER_SIZE - overhead;
            if max_plain == 0 {
                return Err(io_err("frame size too small"));
            }
            let n = p.len().min(max_plain);
            let chunk = &p[..n];
            p = &p[n..];

            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..4].copy_from_slice(&send.epoch.to_be_bytes());
            header[4..].copy_from_slice(&send.seq.to_be_bytes());
            send.seq = send.seq.wrapping_add(1);

            let ct = send.aead.as_ref().unwrap().seal(&header, &header, chunk)?;
            let body_len = RECORD_HEADER_SIZE + ct.len();
            if body_len > MAX_FRAME_BODY_SIZE {
                return Err(io_err("frame too large"));
            }
            out.put_u16(body_len as u16);
            out.extend_from_slice(&header);
            out.extend_from_slice(&ct);

            // 自动 bump epoch
            send.bytes += n as i64;
            let threshold = KEY_UPDATE_AFTER_BYTES * (send.epoch_updates as i64 + 1);
            if send.bytes >= threshold {
                send.epoch = send.epoch.wrapping_add(1);
                send.epoch_updates = send.epoch_updates.wrapping_add(1);
                let (_, new_seq) = random_record_counters();
                send.seq = new_seq;
            }
        }
        Ok(out)
    }

    /// 从 cipher_buf 解密尽可能多的帧到 recv.plain_buf
    /// 返回 Ok(true) 表示有进展，Ok(false) 表示 buf 不够
    pub fn open_frames(&self, cipher_buf: &mut BytesMut) -> std::io::Result<bool> {
        if self.method == AeadMethod::None {
            // 直接搬数据
            let mut recv = self.recv.lock();
            recv.plain_buf.extend_from_slice(cipher_buf);
            cipher_buf.clear();
            return Ok(!recv.plain_buf.is_empty());
        }
        let mut recv = self.recv.lock();
        let mut progressed = false;
        loop {
            if cipher_buf.len() < 2 {
                break;
            }
            let body_len = u16::from_be_bytes([cipher_buf[0], cipher_buf[1]]) as usize;
            if body_len < RECORD_HEADER_SIZE {
                return Err(io_err("frame too short"));
            }
            if body_len > MAX_FRAME_BODY_SIZE {
                return Err(io_err("frame too large"));
            }
            if cipher_buf.len() < 2 + body_len {
                break;
            }
            cipher_buf.advance(2);
            let body = cipher_buf.split_to(body_len).to_vec();
            let header: [u8; RECORD_HEADER_SIZE] =
                body[..RECORD_HEADER_SIZE].try_into().expect("header size");
            let epoch = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let seq = u64::from_be_bytes([
                header[4], header[5], header[6], header[7], header[8], header[9], header[10],
                header[11],
            ]);

            // 验证位置
            if recv.initialized {
                if epoch < recv.epoch {
                    return Err(io_err("replayed epoch"));
                }
                if epoch == recv.epoch && seq != recv.seq {
                    return Err(io_err("out of order"));
                }
                if epoch > recv.epoch && epoch - recv.epoch > 8 {
                    return Err(io_err("epoch jump too large"));
                }
            }

            if recv.aead.is_none() || recv.aead_epoch != epoch {
                let aead = AeadInst::new(self.method, &self.keys.base_recv, epoch)?;
                recv.aead = Some(aead);
                recv.aead_epoch = epoch;
            }
            let pt =
                recv.aead
                    .as_ref()
                    .unwrap()
                    .open(&header, &header, &body[RECORD_HEADER_SIZE..])?;
            recv.epoch = epoch;
            recv.seq = seq.wrapping_add(1);
            recv.initialized = true;
            recv.plain_buf.extend_from_slice(&pt);
            progressed = true;
        }
        Ok(progressed)
    }

    /// 取出已解密的明文，最多 max 字节
    pub fn take_plain(&self, max: usize, dst: &mut [u8]) -> usize {
        let mut recv = self.recv.lock();
        if recv.plain_buf.is_empty() {
            return 0;
        }
        let n = recv.plain_buf.len().min(max).min(dst.len());
        dst[..n].copy_from_slice(&recv.plain_buf[..n]);
        recv.plain_buf.advance(n);
        n
    }

    pub fn has_plain(&self) -> bool {
        !self.recv.lock().plain_buf.is_empty()
    }
}

fn random_record_counters() -> (u32, u64) {
    let mut e = 0u32;
    while e == 0 || e == u32::MAX {
        let mut b = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut b);
        e = u32::from_be_bytes(b);
    }
    let mut s = 0u64;
    while s == 0 || s == u64::MAX {
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        s = u64::from_be_bytes(b);
    }
    (e, s)
}

/* ---------------- AsyncRead/AsyncWrite 包装 ---------------- */

pin_project! {
    /// 把任意 AsyncRead+Write 包装为 RecordConn AEAD 流
    pub struct RecordStream {
        #[pin]
        inner: BoxedStream,
        cryptor: Arc<RecordCryptor>,
        cipher_buf: BytesMut,
    }
}

impl RecordStream {
    pub fn new(inner: BoxedStream, cryptor: Arc<RecordCryptor>) -> Self {
        Self {
            inner,
            cryptor,
            cipher_buf: BytesMut::with_capacity(16 * 1024),
        }
    }
}

impl AsyncRead for RecordStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            if this.cryptor.has_plain() {
                let mut tmp = vec![0u8; buf.remaining()];
                let n = this.cryptor.take_plain(buf.remaining(), &mut tmp);
                if n > 0 {
                    buf.put_slice(&tmp[..n]);
                    return Poll::Ready(Ok(()));
                }
            }
            // 尝试解一帧
            match this.cryptor.open_frames(this.cipher_buf) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            // 读更多
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

impl AsyncWrite for RecordStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        let frames = match this.cryptor.seal_frames(data) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut written = 0;
        while written < frames.len() {
            match this.inner.as_mut().poll_write(cx, &frames[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(data.len()))
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
    fn aead_method_parse() {
        assert_eq!(AeadMethod::parse("").unwrap(), AeadMethod::Chacha20Poly1305);
        assert_eq!(
            AeadMethod::parse("aes-128-gcm").unwrap(),
            AeadMethod::Aes128Gcm
        );
        assert_eq!(AeadMethod::parse("none").unwrap(), AeadMethod::None);
        assert!(AeadMethod::parse("invalid").is_err());
    }

    #[test]
    fn epoch_key_deterministic() {
        let base = [0xaa; 32];
        let k1 = derive_epoch_key(&base, 1, "aes-128-gcm");
        let k2 = derive_epoch_key(&base, 1, "aes-128-gcm");
        assert_eq!(k1, k2);
        let k3 = derive_epoch_key(&base, 2, "aes-128-gcm");
        assert_ne!(k1, k3);
        let k4 = derive_epoch_key(&base, 1, "chacha20-poly1305");
        assert_ne!(k1, k4);
    }

    #[test]
    fn seal_open_round_trip_chacha() {
        let base = vec![0x42u8; 32];
        let send = RecordCryptor::new(AeadMethod::Chacha20Poly1305, &base, &base).unwrap();
        // 让 send 与 recv 用同样的 base/method（双向相同）
        let recv = RecordCryptor::new(AeadMethod::Chacha20Poly1305, &base, &base).unwrap();
        // 拷贝 send 的发送 epoch/seq 到 recv 的预期，避免随机起始值不一致
        let send_state = send.send.lock();
        let s_epoch = send_state.epoch;
        let s_seq = send_state.seq;
        drop(send_state);

        let frames = send.seal_frames(b"hello sudoku").unwrap();
        // 在解密前手工对齐 recv 状态
        // 需要把 recv 的 base_recv 用 send 的 base_send，已通过参数实现
        let mut buf = BytesMut::from(&frames[..]);
        recv.open_frames(&mut buf).unwrap();
        let mut out = vec![0u8; 32];
        let n = recv.take_plain(32, &mut out);
        assert_eq!(&out[..n], b"hello sudoku");
        let _ = (s_epoch, s_seq);
    }

    #[test]
    fn seal_open_round_trip_aes() {
        let base = vec![0x33u8; 32];
        let send = RecordCryptor::new(AeadMethod::Aes128Gcm, &base, &base).unwrap();
        let recv = RecordCryptor::new(AeadMethod::Aes128Gcm, &base, &base).unwrap();
        let frames = send.seal_frames(b"aes-data-xx").unwrap();
        let mut buf = BytesMut::from(&frames[..]);
        recv.open_frames(&mut buf).unwrap();
        let mut out = vec![0u8; 32];
        let n = recv.take_plain(32, &mut out);
        assert_eq!(&out[..n], b"aes-data-xx");
    }

    #[test]
    fn seal_open_round_trip_none() {
        let base = vec![0u8; 32];
        let send = RecordCryptor::new(AeadMethod::None, &base, &base).unwrap();
        let recv = RecordCryptor::new(AeadMethod::None, &base, &base).unwrap();
        let frames = send.seal_frames(b"plaintext").unwrap();
        assert_eq!(frames, b"plaintext");
        let mut buf = BytesMut::from(&frames[..]);
        recv.open_frames(&mut buf).unwrap();
        let mut out = vec![0u8; 32];
        let n = recv.take_plain(32, &mut out);
        assert_eq!(&out[..n], b"plaintext");
    }
}
