//! Snell v1-v5 authenticated record layer.
//!
//! The wire format follows Mihomo v1.19.29 `transport/snell`: v1 uses
//! ChaCha20-Poly1305, v2/v3 use AES-128-GCM, and v4/v5 use the padded v4
//! AES-128-GCM record format. Every generation derives per-direction keys with
//! Argon2id (memory=8 KiB, iterations=3, lanes=1).

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use bytes::{Buf, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

use crate::adapter::BoxedStream;

pub const MAX_FRAME_LENGTH: usize = 0x3fff;
const SALT_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const V4_HEADER_PLAIN_LENGTH: usize = 7;
const V4_HEADER_CIPHER_LENGTH: usize = V4_HEADER_PLAIN_LENGTH + TAG_LENGTH;
const V4_FRAME_SIZE: usize = 1460;
const V4_INITIAL_PADDING_MIN: usize = 0x100;
const V4_INITIAL_PADDING_SPAN: usize = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
}

impl SnellVersion {
    pub fn parse(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(format!("Snell version must be in 1..=5, got {value}")),
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }

    pub fn supports_udp(self) -> bool {
        self.number() >= 3
    }

    pub fn supports_reuse(self) -> bool {
        matches!(self, Self::V2 | Self::V4 | Self::V5)
    }

    fn is_v4_records(self) -> bool {
        self.number() >= 4
    }

    pub fn uses_v4_records(self) -> bool {
        self.is_v4_records()
    }
}

enum Cipher {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl Cipher {
    fn new(version: SnellVersion, password: &[u8], salt: &[u8]) -> io::Result<Self> {
        let key = snell_kdf(password, salt)?;
        if version == SnellVersion::V1 {
            Ok(Self::ChaCha(
                ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| invalid_data("invalid Snell ChaCha20 key"))?,
            ))
        } else {
            Ok(Self::Aes(
                Aes128Gcm::new_from_slice(&key[..16])
                    .map_err(|_| invalid_data("invalid Snell AES key"))?,
            ))
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| invalid_data("Snell AES-GCM encryption failed")),
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| invalid_data("Snell ChaCha20-Poly1305 encryption failed")),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid_data("Snell AES-GCM authentication failed")),
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid_data("Snell ChaCha20-Poly1305 authentication failed")),
        }
    }
}

fn snell_kdf(password: &[u8], salt: &[u8]) -> io::Result<[u8; 32]> {
    let params = Params::new(8, 3, 1, Some(32))
        .map_err(|error| invalid_data(format!("invalid Snell Argon2 parameters: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|error| invalid_data(format!("Snell Argon2 derivation failed: {error}")))?;
    Ok(output)
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

enum DecodeState {
    Salt,
    LegacyLength {
        cipher: Cipher,
        nonce: [u8; 12],
    },
    LegacyPayload {
        cipher: Cipher,
        nonce: [u8; 12],
        length: usize,
    },
    V4Header {
        cipher: Cipher,
        nonce: [u8; 12],
    },
    V4Payload {
        cipher: Cipher,
        nonce: [u8; 12],
        padding: usize,
        length: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyState {
    None,
    Waiting,
    Accepted,
}

/// One authenticated Snell record-layer event.
///
/// `End` is the protocol's zero-length chunk and is intentionally distinct
/// from `TransportEof`: v4/v5 connection reuse starts the next logical request
/// on the same encrypted transport after an `End` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnellFrameEvent {
    Data(Vec<u8>),
    End,
    TransportEof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnellReadStatus {
    Data,
    End,
    TransportEof,
}

pub struct SnellReadHalf {
    inner: ReadHalf<BoxedStream>,
    password: Arc<[u8]>,
    version: SnellVersion,
    state: DecodeState,
    wire: BytesMut,
    plain: BytesMut,
    reply: ReplyState,
    transport_eof: bool,
}

impl SnellReadHalf {
    fn new(
        inner: ReadHalf<BoxedStream>,
        password: Arc<[u8]>,
        version: SnellVersion,
        expect_reply: bool,
    ) -> Self {
        Self {
            inner,
            password,
            version,
            state: DecodeState::Salt,
            wire: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::with_capacity(16 * 1024),
            reply: if expect_reply {
                ReplyState::Waiting
            } else {
                ReplyState::None
            },
            transport_eof: false,
        }
    }

    fn try_decode_frame(&mut self) -> io::Result<Option<SnellFrameEvent>> {
        loop {
            match std::mem::replace(&mut self.state, DecodeState::Salt) {
                DecodeState::Salt => {
                    if self.wire.len() < SALT_LENGTH {
                        self.state = DecodeState::Salt;
                        return Ok(None);
                    }
                    let salt = self.wire.split_to(SALT_LENGTH);
                    let cipher = Cipher::new(self.version, &self.password, &salt)?;
                    self.state = if self.version.is_v4_records() {
                        DecodeState::V4Header {
                            cipher,
                            nonce: [0; 12],
                        }
                    } else {
                        DecodeState::LegacyLength {
                            cipher,
                            nonce: [0; 12],
                        }
                    };
                }
                DecodeState::LegacyLength { cipher, mut nonce } => {
                    if self.wire.len() < 2 + TAG_LENGTH {
                        self.state = DecodeState::LegacyLength { cipher, nonce };
                        return Ok(None);
                    }
                    let ciphertext = self.wire.split_to(2 + TAG_LENGTH);
                    let decoded = cipher.open(&nonce, &ciphertext)?;
                    increment_nonce(&mut nonce);
                    if decoded.len() != 2 {
                        return Err(invalid_data("Snell legacy length has invalid size"));
                    }
                    let length = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
                    if length > MAX_FRAME_LENGTH {
                        return Err(invalid_data("Snell legacy frame exceeds 0x3fff bytes"));
                    }
                    self.state = DecodeState::LegacyPayload {
                        cipher,
                        nonce,
                        length,
                    };
                }
                DecodeState::LegacyPayload {
                    cipher,
                    mut nonce,
                    length,
                } => {
                    let needed = length + TAG_LENGTH;
                    if self.wire.len() < needed {
                        self.state = DecodeState::LegacyPayload {
                            cipher,
                            nonce,
                            length,
                        };
                        return Ok(None);
                    }
                    let ciphertext = self.wire.split_to(needed);
                    let decoded = cipher.open(&nonce, &ciphertext)?;
                    increment_nonce(&mut nonce);
                    let end = decoded.is_empty();
                    self.state = DecodeState::LegacyLength { cipher, nonce };
                    return Ok(Some(if end {
                        SnellFrameEvent::End
                    } else {
                        SnellFrameEvent::Data(decoded)
                    }));
                }
                DecodeState::V4Header { cipher, mut nonce } => {
                    if self.wire.len() < V4_HEADER_CIPHER_LENGTH {
                        self.state = DecodeState::V4Header { cipher, nonce };
                        return Ok(None);
                    }
                    let ciphertext = self.wire.split_to(V4_HEADER_CIPHER_LENGTH);
                    let header = cipher.open(&nonce, &ciphertext)?;
                    increment_nonce(&mut nonce);
                    if header.len() != V4_HEADER_PLAIN_LENGTH || header[0] != 4 {
                        return Err(invalid_data("invalid Snell v4 record header"));
                    }
                    let padding = u16::from_be_bytes([header[3], header[4]]) as usize;
                    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
                    if length > MAX_FRAME_LENGTH || padding > MAX_FRAME_LENGTH {
                        return Err(invalid_data("Snell v4 record exceeds 0x3fff bytes"));
                    }
                    if length == 0 && padding != 0 {
                        return Err(invalid_data("Snell v4 zero chunk contains padding"));
                    }
                    self.state = DecodeState::V4Payload {
                        cipher,
                        nonce,
                        padding,
                        length,
                    };
                }
                DecodeState::V4Payload {
                    cipher,
                    mut nonce,
                    padding,
                    length,
                } => {
                    if length == 0 {
                        self.state = DecodeState::V4Header { cipher, nonce };
                        return Ok(Some(SnellFrameEvent::End));
                    }
                    let needed = padding + length + TAG_LENGTH;
                    if self.wire.len() < needed {
                        self.state = DecodeState::V4Payload {
                            cipher,
                            nonce,
                            padding,
                            length,
                        };
                        return Ok(None);
                    }
                    let mut frame = self.wire.split_to(needed).to_vec();
                    let (padding_bytes, payload_cipher) = frame.split_at_mut(padding);
                    swap_padding(padding_bytes, payload_cipher);
                    let decoded = cipher.open(&nonce, payload_cipher)?;
                    increment_nonce(&mut nonce);
                    self.state = DecodeState::V4Header { cipher, nonce };
                    return Ok(Some(SnellFrameEvent::Data(decoded)));
                }
            }
        }
    }

    fn process_reply(&mut self, frame: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if self.reply != ReplyState::Waiting {
            return Ok(Some(frame));
        }
        let status = *frame
            .first()
            .ok_or_else(|| invalid_data("empty Snell server reply"))?;
        match status {
            0 => {
                self.reply = ReplyState::Accepted;
                Ok((frame.len() > 1).then(|| frame[1..].to_vec()))
            }
            1 => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Snell server returned pong instead of tunnel",
            )),
            2 => {
                if frame.len() < 3 {
                    return Err(invalid_data("truncated Snell error reply"));
                }
                let message_length = frame[2] as usize;
                if frame.len() < 3 + message_length {
                    return Err(invalid_data("truncated Snell error message"));
                }
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!(
                        "Snell server error {}: {}",
                        frame[1],
                        String::from_utf8_lossy(&frame[3..3 + message_length])
                    ),
                ))
            }
            status => Err(invalid_data(format!(
                "unsupported Snell server reply {status}"
            ))),
        }
    }

    fn poll_next_event(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<SnellFrameEvent>> {
        loop {
            match self.try_decode_frame() {
                Ok(Some(SnellFrameEvent::Data(frame))) => match self.process_reply(frame) {
                    Ok(Some(frame)) => {
                        return Poll::Ready(Ok(SnellFrameEvent::Data(frame)));
                    }
                    Ok(None) => continue,
                    Err(error) => return Poll::Ready(Err(error)),
                },
                Ok(Some(SnellFrameEvent::End)) => {
                    if self.reply == ReplyState::Accepted {
                        self.reply = ReplyState::Waiting;
                    }
                    return Poll::Ready(Ok(SnellFrameEvent::End));
                }
                Ok(Some(SnellFrameEvent::TransportEof)) => unreachable!("decoder event"),
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }

            if self.transport_eof {
                return Poll::Ready(if self.wire.is_empty() {
                    Ok(SnellFrameEvent::TransportEof)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated Snell encrypted record",
                    ))
                });
            }

            let mut temporary = [0u8; 16 * 1024];
            let mut buffer = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    self.transport_eof = true;
                }
                Poll::Ready(Ok(())) => self.wire.extend_from_slice(buffer.filled()),
            }
        }
    }

    pub async fn read_event(&mut self) -> io::Result<SnellFrameEvent> {
        std::future::poll_fn(|cx| self.poll_next_event(cx)).await
    }

    pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.read_event().await? {
            SnellFrameEvent::Data(frame) => Ok(Some(frame)),
            SnellFrameEvent::End | SnellFrameEvent::TransportEof => Ok(None),
        }
    }

    fn poll_session_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SnellReadStatus>> {
        loop {
            if !self.plain.is_empty() {
                let length = output.remaining().min(self.plain.len());
                output.put_slice(&self.plain[..length]);
                self.plain.advance(length);
                return Poll::Ready(Ok(SnellReadStatus::Data));
            }
            match self.poll_next_event(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(SnellFrameEvent::End)) => {
                    return Poll::Ready(Ok(SnellReadStatus::End));
                }
                Poll::Ready(Ok(SnellFrameEvent::TransportEof)) => {
                    return Poll::Ready(Ok(SnellReadStatus::TransportEof));
                }
                Poll::Ready(Ok(SnellFrameEvent::Data(frame))) => {
                    self.plain.extend_from_slice(&frame);
                }
            }
        }
    }
}

impl AsyncRead for SnellReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_session_read(cx, output) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }
}

struct Encoder {
    version: SnellVersion,
    cipher: Option<Cipher>,
    nonce: [u8; 12],
    salt: [u8; SALT_LENGTH],
    salt_sent: bool,
    initial_padding: usize,
    payload_limit: usize,
    last_write: Option<Instant>,
}

impl Encoder {
    fn new(password: Arc<[u8]>, version: SnellVersion) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let cipher = Cipher::new(version, &password, &salt)?;
        let initial_padding = V4_INITIAL_PADDING_MIN + random_below(V4_INITIAL_PADDING_SPAN)?;
        Ok(Self {
            version,
            cipher: Some(cipher),
            nonce: [0; 12],
            salt,
            salt_sent: false,
            initial_padding,
            payload_limit: 0,
            last_write: None,
        })
    }

    fn next_payload_limit(&mut self) -> usize {
        if !self.version.is_v4_records() {
            return MAX_FRAME_LENGTH;
        }
        let now = Instant::now();
        let limit = match self.last_write {
            None => V4_FRAME_SIZE - 55 - self.initial_padding,
            Some(previous) if now.duration_since(previous) > Duration::from_secs(30) => {
                V4_FRAME_SIZE - 39
            }
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);
        self.payload_limit = (limit + V4_FRAME_SIZE - 39).min(MAX_FRAME_LENGTH);
        if limit == 0 || limit > MAX_FRAME_LENGTH {
            MAX_FRAME_LENGTH
        } else {
            limit
        }
    }

    fn encode(&mut self, payload: &[u8], packet: bool) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_FRAME_LENGTH {
            return Err(invalid_input("Snell frame exceeds 0x3fff bytes"));
        }
        if self.version.is_v4_records() {
            self.encode_v4(payload, packet)
        } else {
            self.encode_legacy(payload)
        }
    }

    fn prefix_salt(&mut self, output: &mut Vec<u8>) {
        if !self.salt_sent {
            output.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
    }

    fn encode_legacy(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(
            (!self.salt_sent as usize) * SALT_LENGTH + 2 + TAG_LENGTH + payload.len() + TAG_LENGTH,
        );
        self.prefix_salt(&mut output);
        let cipher = self.cipher.as_ref().expect("encoder cipher");
        output.extend(cipher.seal(&self.nonce, &(payload.len() as u16).to_be_bytes())?);
        increment_nonce(&mut self.nonce);
        output.extend(cipher.seal(&self.nonce, payload)?);
        increment_nonce(&mut self.nonce);
        Ok(output)
    }

    fn encode_v4(&mut self, payload: &[u8], packet: bool) -> io::Result<Vec<u8>> {
        let padding_length = if !self.salt_sent && !payload.is_empty() {
            self.initial_padding
        } else {
            0
        };
        if payload.is_empty() && padding_length != 0 {
            return Err(invalid_input("Snell v4 zero chunk cannot contain padding"));
        }
        let mut header = [0u8; V4_HEADER_PLAIN_LENGTH];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let cipher = self.cipher.as_ref().expect("encoder cipher");
        let header_cipher = cipher.seal(&self.nonce, &header)?;
        increment_nonce(&mut self.nonce);
        let mut payload_cipher = if payload.is_empty() {
            Vec::new()
        } else {
            let sealed = cipher.seal(&self.nonce, payload)?;
            increment_nonce(&mut self.nonce);
            sealed
        };
        let mut output = Vec::with_capacity(
            (!self.salt_sent as usize) * SALT_LENGTH
                + header_cipher.len()
                + padding_length
                + payload_cipher.len(),
        );
        self.prefix_salt(&mut output);
        output.extend_from_slice(&header_cipher);
        if padding_length > 0 {
            let mut padding = make_v4_padding(&payload_cipher, padding_length)?;
            swap_padding(&mut padding, &mut payload_cipher);
            output.extend_from_slice(&padding);
        }
        output.extend_from_slice(&payload_cipher);
        if packet {
            self.last_write = Some(Instant::now());
        }
        Ok(output)
    }
}

pub struct SnellWriteHalf {
    inner: WriteHalf<BoxedStream>,
    encoder: Encoder,
    pending: Vec<u8>,
    pending_offset: usize,
    pending_plain_length: usize,
    end_queued: bool,
}

impl SnellWriteHalf {
    fn new(
        inner: WriteHalf<BoxedStream>,
        password: Arc<[u8]>,
        version: SnellVersion,
    ) -> io::Result<Self> {
        Ok(Self {
            inner,
            encoder: Encoder::new(password, version)?,
            pending: Vec::new(),
            pending_offset: 0,
            pending_plain_length: 0,
            end_queued: false,
        })
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pending_offset < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => self.pending_offset += written,
            }
        }
        let plain_length = self.pending_plain_length;
        self.pending.clear();
        self.pending_offset = 0;
        self.pending_plain_length = 0;
        Poll::Ready(Ok(plain_length))
    }

    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        self.flush().await?;
        let frame = self.encoder.encode(payload, true)?;
        self.inner.write_all(&frame).await
    }

    pub async fn write_end(&mut self) -> io::Result<()> {
        self.write_frame(&[]).await?;
        self.inner.flush().await
    }

    fn poll_write_end(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.end_queued {
            if !self.pending.is_empty() {
                match self.poll_pending(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(_)) => {}
                }
            }
            match self.encoder.encode(&[], true) {
                Ok(frame) => {
                    self.pending = frame;
                    self.pending_plain_length = 0;
                    self.end_queued = true;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        if !self.pending.is_empty() {
            match self.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.end_queued = false;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for SnellWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending.is_empty() {
            return self.poll_pending(cx);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let limit = self.encoder.next_payload_limit().min(input.len());
        match self.encoder.encode(&input[..limit], false) {
            Ok(frame) => {
                self.pending = frame;
                self.pending_plain_length = limit;
                self.poll_pending(cx)
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pending.is_empty() {
            match self.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct SnellStream {
    read: SnellReadHalf,
    write: SnellWriteHalf,
}

impl SnellStream {
    pub fn new(
        stream: BoxedStream,
        password: Arc<[u8]>,
        version: SnellVersion,
        expect_reply: bool,
    ) -> io::Result<Self> {
        let (read, write) = tokio::io::split(stream);
        Ok(Self {
            read: SnellReadHalf::new(read, password.clone(), version, expect_reply),
            write: SnellWriteHalf::new(write, password, version)?,
        })
    }

    pub fn into_split(self) -> (SnellReadHalf, SnellWriteHalf) {
        (self.read, self.write)
    }

    pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.read.read_frame().await
    }

    pub async fn read_event(&mut self) -> io::Result<SnellFrameEvent> {
        self.read.read_event().await
    }

    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write.write_frame(payload).await
    }

    pub async fn write_end(&mut self) -> io::Result<()> {
        self.write.write_end().await
    }

    pub(crate) fn poll_session_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SnellReadStatus>> {
        self.read.poll_session_read(cx, output)
    }

    pub(crate) fn poll_write_end(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.poll_write_end(cx)
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, output)
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
    }
}

fn make_v4_padding(payload_cipher: &[u8], length: usize) -> io::Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let considered = payload_cipher.len() & !3;
    let ones: usize = payload_cipher[..considered]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    let zeros = 8 * payload_cipher.len() - ones;
    if zeros == 0 {
        return random_bytes(length);
    }
    let ratio = ones as f64 / zeros as f64;
    if !(0.5..1.6).contains(&ratio) {
        return random_bytes(length);
    }
    let base = if zeros < ones { 0.4 } else { 1.6 };
    let target_ratio = base + random_unit()? / 10.0;
    let total_bits = 8 * (length + payload_cipher.len());
    let target_ones =
        (total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - ones as f64) as isize;
    if target_ones < 0 || target_ones as usize > 8 * length {
        return random_bytes(length);
    }
    bit_count_padding(length, target_ones as usize)
}

fn bit_count_padding(length: usize, ones: usize) -> io::Result<Vec<u8>> {
    let total_bits = length * 8;
    if ones > total_bits {
        return Err(invalid_input("invalid Snell v4 padding bit count"));
    }
    let mut bits = vec![false; total_bits];
    bits[..ones].fill(true);
    for index in (1..total_bits).rev() {
        let other = random_below(index + 1)?;
        bits.swap(index, other);
    }
    let mut output = vec![0u8; length];
    for (index, bit) in bits.into_iter().enumerate() {
        if bit {
            output[index / 8] |= 1 << (index % 8);
        }
    }
    Ok(output)
}

fn random_bytes(length: usize) -> io::Result<Vec<u8>> {
    let mut output = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut output);
    Ok(output)
}

fn random_below(maximum: usize) -> io::Result<usize> {
    if maximum == 0 {
        return Err(invalid_input("random upper bound must be positive"));
    }
    let zone = usize::MAX - usize::MAX % maximum;
    loop {
        let value = rand::rngs::OsRng.next_u64() as usize;
        if value < zone {
            return Ok(value % maximum);
        }
    }
}

fn random_unit() -> io::Result<f64> {
    let value = rand::rngs::OsRng.next_u64() >> 11;
    Ok(value as f64 / (1u64 << 53) as f64)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn boxed(stream: tokio::io::DuplexStream) -> BoxedStream {
        Box::pin(stream)
    }

    #[tokio::test]
    async fn every_version_round_trips_fragmented_bidirectional_records() {
        for version in [
            SnellVersion::V1,
            SnellVersion::V2,
            SnellVersion::V3,
            SnellVersion::V4,
            SnellVersion::V5,
        ] {
            let (left, right) = tokio::io::duplex(97);
            let password: Arc<[u8]> = Arc::from(&b"correct horse battery staple"[..]);
            let mut client =
                SnellStream::new(boxed(left), password.clone(), version, false).unwrap();
            let mut server = SnellStream::new(boxed(right), password, version, false).unwrap();
            let payload = vec![version.number(); 32 * 1024];
            let expected = payload.clone();
            let send = tokio::spawn(async move {
                client.write_all(&payload).await.unwrap();
                client.flush().await.unwrap();
            });
            let mut received = vec![0u8; expected.len()];
            server.read_exact(&mut received).await.unwrap();
            send.await.unwrap();
            assert_eq!(received, expected);
        }
    }

    #[tokio::test]
    async fn packet_frames_preserve_datagram_boundaries() {
        let (left, right) = tokio::io::duplex(64);
        let password: Arc<[u8]> = Arc::from(&b"psk"[..]);
        let mut client =
            SnellStream::new(boxed(left), password.clone(), SnellVersion::V4, false).unwrap();
        let mut server = SnellStream::new(boxed(right), password, SnellVersion::V4, false).unwrap();
        let send = tokio::spawn(async move {
            client.write_frame(b"first").await.unwrap();
            client.write_frame(b"second").await.unwrap();
        });
        assert_eq!(server.read_frame().await.unwrap().unwrap(), b"first");
        assert_eq!(server.read_frame().await.unwrap().unwrap(), b"second");
        send.await.unwrap();
    }

    #[tokio::test]
    async fn every_version_rejects_an_incorrect_psk() {
        for version in [
            SnellVersion::V1,
            SnellVersion::V2,
            SnellVersion::V3,
            SnellVersion::V4,
            SnellVersion::V5,
        ] {
            let (left, right) = tokio::io::duplex(16 * 1024);
            let mut client =
                SnellStream::new(boxed(left), Arc::from(&b"client-psk"[..]), version, false)
                    .unwrap();
            let mut server =
                SnellStream::new(boxed(right), Arc::from(&b"server-psk"[..]), version, false)
                    .unwrap();

            client.write_frame(b"authenticated payload").await.unwrap();
            let error = server.read_event().await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "version {version:?}"
            );
        }
    }

    #[tokio::test]
    async fn truncated_authenticated_frame_is_never_accepted_as_eof() {
        for version in [SnellVersion::V1, SnellVersion::V4] {
            let (left, right) = tokio::io::duplex(16 * 1024);
            let password: Arc<[u8]> = Arc::from(&b"shared-psk"[..]);
            let mut encoder = Encoder::new(password.clone(), version).unwrap();
            let mut frame = encoder
                .encode(b"must authenticate completely", false)
                .unwrap();
            frame.truncate(frame.len() - 1);

            let send = tokio::spawn(async move {
                let mut left = left;
                left.write_all(&frame).await.unwrap();
                left.shutdown().await.unwrap();
            });
            let mut server = SnellStream::new(boxed(right), password, version, false).unwrap();
            let error = server.read_event().await.unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "version {version:?}"
            );
            send.await.unwrap();
        }
    }

    #[test]
    fn argon2id_matches_mihomo_parameters() {
        assert_eq!(
            hex::encode(snell_kdf(b"password", &[7u8; 16]).unwrap()),
            "8dfb1b2d65df89c27e48e7df6227434c90694924c3eb48383fe6df0cb25712ca"
        );
    }
}
