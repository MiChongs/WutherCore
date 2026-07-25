//! SIP003 simple-obfs HTTP and TLS stream camouflage.
//!
//! Both client and server directions are implemented so protocol inbounds can
//! use exactly the same parser as outbounds. Parsing is incremental and
//! bounded; fragmented headers never cause data loss.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use bytes::{Buf, BytesMut};
use chrono::{DateTime, Utc};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::adapter::BoxedStream;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const TLS_CHUNK_BYTES: usize = 1 << 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleObfsMode {
    Http { host: String, port: u16 },
    Tls { host: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

pub struct SimpleObfsStream {
    read: ObfsRead,
    write: ObfsWrite,
}

impl SimpleObfsStream {
    pub fn client(stream: BoxedStream, mode: SimpleObfsMode) -> Self {
        Self::new(stream, mode, Role::Client)
    }

    pub fn server(stream: BoxedStream, mode: SimpleObfsMode) -> Self {
        Self::new(stream, mode, Role::Server)
    }

    fn new(stream: BoxedStream, mode: SimpleObfsMode, role: Role) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: ObfsRead::new(read, mode.clone(), role),
            write: ObfsWrite::new(write, mode, role),
        }
    }
}

impl AsyncRead for SimpleObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, output)
    }
}

impl AsyncWrite for SimpleObfsStream {
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

struct ObfsRead {
    inner: ReadHalf<BoxedStream>,
    mode: SimpleObfsMode,
    role: Role,
    wire: BytesMut,
    plain: BytesMut,
    first: bool,
    eof: bool,
}

impl ObfsRead {
    fn new(inner: ReadHalf<BoxedStream>, mode: SimpleObfsMode, role: Role) -> Self {
        Self {
            inner,
            mode,
            role,
            wire: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::with_capacity(16 * 1024),
            first: true,
            eof: false,
        }
    }

    fn try_decode(&mut self) -> io::Result<bool> {
        match self.mode {
            SimpleObfsMode::Http { .. } => self.try_decode_http(),
            SimpleObfsMode::Tls { .. } => self.try_decode_tls(),
        }
    }

    fn try_decode_http(&mut self) -> io::Result<bool> {
        if !self.first {
            if self.wire.is_empty() {
                return Ok(false);
            }
            self.plain.extend_from_slice(&self.wire.split());
            return Ok(true);
        }
        let Some(header_end) = find_subslice(&self.wire, b"\r\n\r\n") else {
            if self.wire.len() > MAX_HEADER_BYTES {
                return Err(invalid_data("simple-obfs HTTP header exceeds 64 KiB"));
            }
            return Ok(false);
        };
        let header_length = header_end + 4;
        let header = std::str::from_utf8(&self.wire[..header_length])
            .map_err(|_| invalid_data("simple-obfs HTTP header is not UTF-8"))?;
        let mut lines = header.split("\r\n");
        let start = lines
            .next()
            .ok_or_else(|| invalid_data("simple-obfs HTTP start line is missing"))?;
        let content_length = header_value(header, "content-length")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| invalid_data("invalid simple-obfs Content-Length"))
            })
            .transpose()?
            .unwrap_or(0);
        match self.role {
            Role::Client => {
                let status = start
                    .split_whitespace()
                    .nth(1)
                    .ok_or_else(|| invalid_data("simple-obfs HTTP status is missing"))?;
                if status != "101" {
                    return Err(invalid_data(format!(
                        "simple-obfs HTTP server returned status {status}"
                    )));
                }
            }
            Role::Server => {
                if !start.starts_with("GET ") {
                    return Err(invalid_data("simple-obfs HTTP request is not GET"));
                }
                let connection = header_value(header, "connection").unwrap_or_default();
                let upgrade = header_value(header, "upgrade").unwrap_or_default();
                if !connection
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                    || !upgrade.eq_ignore_ascii_case("websocket")
                {
                    return Err(invalid_data(
                        "simple-obfs HTTP request is not a WebSocket upgrade",
                    ));
                }
            }
        }
        if self.wire.len() < header_length + content_length {
            return Ok(false);
        }
        self.wire.advance(header_length);
        if content_length > 0 {
            self.plain
                .extend_from_slice(&self.wire.split_to(content_length));
        }
        if !self.wire.is_empty() {
            self.plain.extend_from_slice(&self.wire.split());
        }
        self.first = false;
        Ok(true)
    }

    fn try_decode_tls(&mut self) -> io::Result<bool> {
        if self.first {
            let decoded = match self.role {
                Role::Server => decode_client_hello_ticket(&self.wire)?,
                Role::Client => decode_server_hello_payload(&self.wire)?,
            };
            let Some((consumed, payload)) = decoded else {
                if self.wire.len() > MAX_HEADER_BYTES {
                    return Err(invalid_data("simple-obfs TLS handshake exceeds 64 KiB"));
                }
                return Ok(false);
            };
            self.wire.advance(consumed);
            self.plain.extend_from_slice(&payload);
            self.first = false;
            return Ok(true);
        }
        let Some((consumed, payload)) = decode_tls_record(&self.wire, 0x17)? else {
            return Ok(false);
        };
        let payload = payload.to_vec();
        self.wire.advance(consumed);
        self.plain.extend_from_slice(&payload);
        Ok(true)
    }
}

impl AsyncRead for ObfsRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain.is_empty() {
                let length = output.remaining().min(self.plain.len());
                output.put_slice(&self.plain[..length]);
                self.plain.advance(length);
                return Poll::Ready(Ok(()));
            }
            match self.try_decode() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            if self.eof {
                return Poll::Ready(if self.wire.is_empty() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated simple-obfs frame",
                    ))
                });
            }
            let mut temporary = [0u8; 16 * 1024];
            let mut buffer = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => self.eof = true,
                Poll::Ready(Ok(())) => self.wire.extend_from_slice(buffer.filled()),
            }
        }
    }
}

struct ObfsWrite {
    inner: WriteHalf<BoxedStream>,
    mode: SimpleObfsMode,
    role: Role,
    first: bool,
    pending: Vec<u8>,
    offset: usize,
    plain_length: usize,
}

impl ObfsWrite {
    fn new(inner: WriteHalf<BoxedStream>, mode: SimpleObfsMode, role: Role) -> Self {
        Self {
            inner,
            mode,
            role,
            first: true,
            pending: Vec::new(),
            offset: 0,
            plain_length: 0,
        }
    }

    fn encode(&mut self, input: &[u8]) -> io::Result<(Vec<u8>, usize)> {
        let length = input.len().min(TLS_CHUNK_BYTES);
        let payload = &input[..length];
        let encoded = match (&self.mode, self.role, self.first) {
            (SimpleObfsMode::Http { host, port }, Role::Client, true) => {
                http_request(host, *port, payload)
            }
            (SimpleObfsMode::Http { .. }, Role::Server, true) => http_response(payload),
            (SimpleObfsMode::Http { .. }, _, false) => payload.to_vec(),
            (SimpleObfsMode::Tls { host }, Role::Client, true) => tls_client_hello(host, payload)?,
            (SimpleObfsMode::Tls { .. }, Role::Server, true) => tls_server_hello(payload)?,
            (SimpleObfsMode::Tls { .. }, _, false) => tls_application_record(payload),
        };
        self.first = false;
        Ok((encoded, length))
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.offset < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => self.offset += written,
            }
        }
        let length = self.plain_length;
        self.pending.clear();
        self.offset = 0;
        self.plain_length = 0;
        Poll::Ready(Ok(length))
    }
}

impl AsyncWrite for ObfsWrite {
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
        match self.encode(input) {
            Ok((encoded, length)) => {
                self.pending = encoded;
                self.plain_length = length;
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

fn http_request(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let authority = if port == 80 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let minor = rand::rngs::OsRng.next_u32() % 54;
    let patch = rand::rngs::OsRng.next_u32() % 2;
    let header = format!(
        "GET / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: curl/7.{minor}.{patch}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\n\
         Content-Length: {}\r\n\r\n",
        URL_SAFE.encode(random),
        payload.len()
    );
    [header.as_bytes(), payload].concat()
}

fn http_response(payload: &[u8]) -> Vec<u8> {
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let now: DateTime<Utc> = SystemTime::now().into();
    let header = format!(
        "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.8.1\r\nDate: {}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\
         Content-Length: {}\r\n\r\n",
        now.format("%a, %d %b %Y %H:%M:%S GMT"),
        URL_SAFE.encode(random),
        payload.len()
    );
    [header.as_bytes(), payload].concat()
}

fn header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split("\r\n").skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field
            .trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn tls_client_hello(host: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let host = host.as_bytes();
    let host_length = u16::try_from(host.len())
        .map_err(|_| invalid_input("simple-obfs TLS hostname is too long"))?;
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let mut body = Vec::with_capacity(256 + host.len() + payload.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(
        &(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32)
            .to_be_bytes(),
    );
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    const CIPHERS: &[u8] = &[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ];
    body.extend_from_slice(&(CIPHERS.len() as u16).to_be_bytes());
    body.extend_from_slice(CIPHERS);
    body.extend_from_slice(&[1, 0]);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0, 0x23]);
    extensions.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extensions.extend_from_slice(payload);
    extensions.extend_from_slice(&[0, 0]);
    extensions.extend_from_slice(&(host_length + 5).to_be_bytes());
    extensions.extend_from_slice(&(host_length + 3).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&host_length.to_be_bytes());
    extensions.extend_from_slice(host);
    extensions.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00,
        0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01,
        0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04,
        0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
    ]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(1);
    put_u24(&mut handshake, body.len())?;
    handshake.extend_from_slice(&body);
    tls_record(0x16, 0x0301, &handshake)
}

fn tls_server_hello(payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let mut body = Vec::with_capacity(87);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(
        &(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32)
            .to_be_bytes(),
    );
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&[0xcc, 0xa8, 0]);
    body.extend_from_slice(&[
        0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02,
        0x01, 0x00,
    ]);
    let mut handshake = Vec::new();
    handshake.push(2);
    put_u24(&mut handshake, body.len())?;
    handshake.extend_from_slice(&body);
    let mut output = tls_record(0x16, 0x0301, &handshake)?;
    output.extend_from_slice(&tls_record(0x14, 0x0303, &[1])?);
    output.extend_from_slice(&tls_record(0x16, 0x0303, payload)?);
    Ok(output)
}

fn tls_application_record(payload: &[u8]) -> Vec<u8> {
    tls_record(0x17, 0x0303, payload).expect("TLS chunk is bounded to u16")
}

fn tls_record(kind: u8, version: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len())
        .map_err(|_| invalid_input("simple-obfs TLS record exceeds u16"))?;
    let mut output = Vec::with_capacity(5 + payload.len());
    output.push(kind);
    output.extend_from_slice(&version.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn decode_tls_record(input: &[u8], expected_kind: u8) -> io::Result<Option<(usize, &[u8])>> {
    if input.len() < 5 {
        return Ok(None);
    }
    if input[0] != expected_kind || !matches!(&input[1..3], [0x03, 0x01] | [0x03, 0x03]) {
        return Err(invalid_data("invalid simple-obfs TLS record header"));
    }
    let length = u16::from_be_bytes([input[3], input[4]]) as usize;
    if input.len() < 5 + length {
        return Ok(None);
    }
    Ok(Some((5 + length, &input[5..5 + length])))
}

fn decode_client_hello_ticket(input: &[u8]) -> io::Result<Option<(usize, Vec<u8>)>> {
    let Some((consumed, handshake)) = decode_tls_record(input, 0x16)? else {
        return Ok(None);
    };
    if handshake.len() < 4 || handshake[0] != 1 {
        return Err(invalid_data("simple-obfs TLS message is not ClientHello"));
    }
    let declared = read_u24(&handshake[1..4]);
    if handshake.len() != 4 + declared {
        return Err(invalid_data("invalid simple-obfs ClientHello length"));
    }
    let body = &handshake[4..];
    let mut offset = 34;
    let session_length = read_u8(body, &mut offset)? as usize;
    take(body, &mut offset, session_length)?;
    let cipher_length = read_u16(body, &mut offset)? as usize;
    take(body, &mut offset, cipher_length)?;
    let compression_length = read_u8(body, &mut offset)? as usize;
    take(body, &mut offset, compression_length)?;
    let extensions_length = read_u16(body, &mut offset)? as usize;
    let extensions = take(body, &mut offset, extensions_length)?;
    if offset != body.len() {
        return Err(invalid_data(
            "simple-obfs ClientHello contains trailing bytes",
        ));
    }
    let mut cursor = 0;
    while cursor < extensions.len() {
        let kind = read_u16(extensions, &mut cursor)?;
        let length = read_u16(extensions, &mut cursor)? as usize;
        let value = take(extensions, &mut cursor, length)?;
        if kind == 0x23 {
            return Ok(Some((consumed, value.to_vec())));
        }
    }
    Err(invalid_data(
        "simple-obfs ClientHello has no session-ticket payload",
    ))
}

fn decode_server_hello_payload(input: &[u8]) -> io::Result<Option<(usize, Vec<u8>)>> {
    let Some((first, server_hello)) = decode_tls_record(input, 0x16)? else {
        return Ok(None);
    };
    if server_hello.first() != Some(&2) {
        return Err(invalid_data("simple-obfs TLS message is not ServerHello"));
    }
    let Some((second, change_cipher)) = decode_tls_record(&input[first..], 0x14)? else {
        return Ok(None);
    };
    if change_cipher != [1] {
        return Err(invalid_data("invalid simple-obfs ChangeCipherSpec"));
    }
    let Some((third, payload)) = decode_tls_record(&input[first + second..], 0x16)? else {
        return Ok(None);
    };
    Ok(Some((first + second + third, payload.to_vec())))
}

fn read_u8(input: &[u8], offset: &mut usize) -> io::Result<u8> {
    let value = *input
        .get(*offset)
        .ok_or_else(|| invalid_data("truncated simple-obfs TLS structure"))?;
    *offset += 1;
    Ok(value)
}

fn read_u16(input: &[u8], offset: &mut usize) -> io::Result<u16> {
    let value = take(input, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid_data("simple-obfs TLS offset overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or_else(|| invalid_data("truncated simple-obfs TLS structure"))?;
    *offset = end;
    Ok(value)
}

fn put_u24(output: &mut Vec<u8>, value: usize) -> io::Result<()> {
    if value > 0x00ff_ffff {
        return Err(invalid_input("simple-obfs handshake exceeds u24"));
    }
    output.extend_from_slice(&[
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]);
    Ok(())
}

fn read_u24(input: &[u8]) -> usize {
    (input[0] as usize) << 16 | (input[1] as usize) << 8 | input[2] as usize
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn boxed(stream: tokio::io::DuplexStream) -> BoxedStream {
        Box::pin(stream)
    }

    async fn round_trip(mode: SimpleObfsMode) {
        let (left, right) = tokio::io::duplex(31);
        let mut client = SimpleObfsStream::client(boxed(left), mode.clone());
        let mut server = SimpleObfsStream::server(boxed(right), mode);
        let request = b"client encrypted bytes".repeat(100);
        let expected_request = request.clone();
        let client_send = tokio::spawn(async move {
            client.write_all(&request).await.unwrap();
            client.flush().await.unwrap();
            let mut response = vec![0u8; 2100];
            client.read_exact(&mut response).await.unwrap();
            response
        });
        let mut decoded_request = vec![0u8; expected_request.len()];
        server.read_exact(&mut decoded_request).await.unwrap();
        assert_eq!(decoded_request, expected_request);
        server.write_all(&vec![9u8; 2100]).await.unwrap();
        server.flush().await.unwrap();
        assert_eq!(client_send.await.unwrap(), vec![9u8; 2100]);
    }

    #[tokio::test]
    async fn http_client_and_server_round_trip_fragmented_io() {
        round_trip(SimpleObfsMode::Http {
            host: "example.com".into(),
            port: 443,
        })
        .await;
    }

    #[tokio::test]
    async fn tls_client_and_server_round_trip_fragmented_io() {
        round_trip(SimpleObfsMode::Tls {
            host: "example.com".into(),
        })
        .await;
    }

    #[test]
    fn client_hello_ticket_parser_extracts_payload_and_sni_structure() {
        let hello = tls_client_hello("example.com", b"ciphertext").unwrap();
        let (consumed, payload) = decode_client_hello_ticket(&hello).unwrap().unwrap();
        assert_eq!(consumed, hello.len());
        assert_eq!(payload, b"ciphertext");
    }
}
