use std::collections::HashSet;
use std::io;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::buffer::SliceReader;

const TLS_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const TLS_1_3: u16 = 0x0304;
const RFC8446_MAX_CIPHERTEXT: usize = 16_640;

/// Resource bounds applied before authentication.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloLimits {
    pub max_record_payload: usize,
    pub max_handshake_bytes: usize,
    pub max_wire_bytes: usize,
    pub max_records: usize,
}

impl Default for ClientHelloLimits {
    fn default() -> Self {
        Self {
            max_record_payload: RFC8446_MAX_CIPHERTEXT,
            max_handshake_bytes: u16::MAX as usize,
            max_wire_bytes: 96 * 1024,
            max_records: 16,
        }
    }
}

/// A complete, possibly TLS-record-fragmented ClientHello.
#[derive(Clone, Debug)]
pub struct ClientHello {
    wire: Bytes,
    handshake: Bytes,
    server_name: String,
    supports_tls13: bool,
    alpn_protocols: Vec<Vec<u8>>,
    key_shares: Vec<(u16, Bytes)>,
}

impl ClientHello {
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }
    pub fn handshake_bytes(&self) -> &[u8] {
        &self.handshake
    }
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    pub fn supports_tls13(&self) -> bool {
        self.supports_tls13
    }
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }
    pub fn key_share(&self, group: u16) -> Option<&[u8]> {
        self.key_shares
            .iter()
            .find_map(|(candidate, data)| (*candidate == group).then_some(data.as_ref()))
    }

    pub(crate) fn canonical_record(&self) -> io::Result<Vec<u8>> {
        let len = u16::try_from(self.handshake.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello exceeds one canonical TLS record",
            )
        })?;
        let mut out = Vec::with_capacity(TLS_HEADER_LEN + self.handshake.len());
        out.extend_from_slice(&[TLS_HANDSHAKE, 0x03, 0x01]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.handshake);
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) async fn read_client_hello<R>(
    stream: &mut R,
    limits: ClientHelloLimits,
) -> io::Result<ClientHello>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut sink = tokio::io::sink();
    let mut forwarded = 0;
    read_client_hello_forwarded(stream, &mut sink, limits, &mut forwarded).await
}

/// Read and parse a ClientHello while relaying every complete TLS record chunk
/// to the camouflage target. `forwarded` allows the caller to relay only the
/// not-yet-forwarded suffix if a timeout interrupts a partial read.
pub(crate) async fn read_client_hello_forwarded<R, W>(
    stream: &mut R,
    target: &mut W,
    limits: ClientHelloLimits,
    forwarded: &mut usize,
) -> io::Result<ClientHello>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    if limits.max_records == 0
        || limits.max_record_payload == 0
        || limits.max_handshake_bytes < 4
        || limits.max_wire_bytes < TLS_HEADER_LEN
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ClientHello limits",
        ));
    }

    let mut wire = BytesMut::new();
    let mut handshake = BytesMut::new();
    let mut expected_handshake_len = None;

    for _ in 0..limits.max_records {
        let mut header = [0u8; TLS_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        write_forwarded(target, &header, forwarded).await?;
        if header[0] != TLS_HANDSHAKE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-handshake TLS record before complete ClientHello",
            ));
        }
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if payload_len == 0
            || payload_len > limits.max_record_payload
            || payload_len > RFC8446_MAX_CIPHERTEXT
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TLS record length",
            ));
        }
        if wire.len().saturating_add(TLS_HEADER_LEN + payload_len) > limits.max_wire_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello wire limit exceeded",
            ));
        }

        let mut payload = vec![0; payload_len];
        stream.read_exact(&mut payload).await?;
        write_forwarded(target, &payload, forwarded).await?;

        wire.extend_from_slice(&header);
        wire.extend_from_slice(&payload);
        handshake.extend_from_slice(&payload);

        if handshake.len() >= 4 && expected_handshake_len.is_none() {
            if handshake[0] != CLIENT_HELLO {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "first handshake message is not ClientHello",
                ));
            }
            let body_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            let total = body_len.checked_add(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "ClientHello length overflow")
            })?;
            if total > limits.max_handshake_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ClientHello handshake limit exceeded",
                ));
            }
            expected_handshake_len = Some(total);
        }

        if let Some(total) = expected_handshake_len {
            if handshake.len() >= total {
                handshake.truncate(total);
                return parse_client_hello(wire.freeze(), handshake.freeze());
            }
        } else if handshake.len() > limits.max_handshake_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello header limit exceeded",
            ));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "ClientHello record-count limit exceeded",
    ))
}

async fn write_forwarded<W>(
    target: &mut W,
    mut bytes: &[u8],
    forwarded: &mut usize,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    while !bytes.is_empty() {
        // A single Tokio `write` is cancellation-safe. Accounting after each
        // partial write prevents a timeout from duplicating a relayed prefix.
        let written = target.write(bytes).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "camouflage target stopped accepting ClientHello bytes",
            ));
        }
        *forwarded = forwarded.saturating_add(written);
        bytes = &bytes[written..];
    }
    Ok(())
}

fn parse_client_hello(wire: Bytes, handshake: Bytes) -> io::Result<ClientHello> {
    let mut reader = SliceReader::new(&handshake);
    if reader.read_u8()? != CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a ClientHello",
        ));
    }
    let declared = reader.read_u24_be()?;
    if declared != reader.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ClientHello length mismatch",
        ));
    }
    if reader.read_u16_be()? != 0x0303 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ClientHello legacy version",
        ));
    }
    reader.skip(32)?;
    let session_len = reader.read_u8()? as usize;
    if session_len > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid legacy session id",
        ));
    }
    reader.skip(session_len)?;
    let suites_len = reader.read_u16_be()? as usize;
    if suites_len < 2 || suites_len % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid cipher suites",
        ));
    }
    reader.skip(suites_len)?;
    let compression_len = reader.read_u8()? as usize;
    if compression_len != 1 || reader.read_u8()? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS 1.3 legacy compression methods",
        ));
    }
    let extensions_len = reader.read_u16_be()? as usize;
    if extensions_len != reader.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ClientHello extensions length mismatch",
        ));
    }

    let extensions = reader.read_slice(extensions_len)?;
    let mut extensions = SliceReader::new(extensions);
    let mut server_name = None;
    let mut supports_tls13 = false;
    let mut alpn_protocols = Vec::new();
    let mut key_shares = Vec::new();
    let mut seen_extensions = HashSet::new();

    while extensions.remaining() != 0 {
        if extensions.remaining() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated extension",
            ));
        }
        let kind = extensions.read_u16_be()?;
        let len = extensions.read_u16_be()? as usize;
        let value = extensions.read_slice(len)?;
        if !seen_extensions.insert(kind) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate ClientHello extension",
            ));
        }
        match kind {
            0 => server_name = Some(parse_server_name(value)?),
            16 => alpn_protocols = parse_alpn(value)?,
            43 => supports_tls13 = parse_supported_versions(value)?.contains(&TLS_1_3),
            51 => key_shares = parse_key_shares(value)?,
            _ => {}
        }
    }

    let server_name = server_name
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ClientHello has no SNI"))?;
    if server_name.len() > 253 || server_name.bytes().any(|b| b == 0 || !b.is_ascii()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SNI"));
    }

    Ok(ClientHello {
        wire,
        handshake,
        server_name,
        supports_tls13,
        alpn_protocols,
        key_shares,
    })
}

fn parse_server_name(data: &[u8]) -> io::Result<String> {
    let mut r = SliceReader::new(data);
    let list_len = r.read_u16_be()? as usize;
    if list_len != r.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SNI list",
        ));
    }
    let mut host_name = None;
    while r.remaining() != 0 {
        let kind = r.read_u8()?;
        let len = r.read_u16_be()? as usize;
        let name = r.read_slice(len)?;
        if kind == 0 {
            if host_name.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate SNI host_name",
                ));
            }
            host_name = Some(
                std::str::from_utf8(name)
                    .map(str::to_owned)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 SNI"))?,
            );
        }
    }
    host_name.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SNI host_name missing"))
}

fn parse_supported_versions(data: &[u8]) -> io::Result<Vec<u16>> {
    let mut r = SliceReader::new(data);
    let len = r.read_u8()? as usize;
    if len != r.remaining() || len % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid supported_versions",
        ));
    }
    let mut out = Vec::with_capacity(len / 2);
    while r.remaining() != 0 {
        out.push(r.read_u16_be()?);
    }
    Ok(out)
}

fn parse_alpn(data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut r = SliceReader::new(data);
    let len = r.read_u16_be()? as usize;
    if len != r.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ALPN list",
        ));
    }
    let mut out = Vec::new();
    while r.remaining() != 0 {
        let item_len = r.read_u8()? as usize;
        if item_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty ALPN protocol",
            ));
        }
        out.push(r.read_slice(item_len)?.to_vec());
    }
    Ok(out)
}

fn parse_key_shares(data: &[u8]) -> io::Result<Vec<(u16, Bytes)>> {
    let mut r = SliceReader::new(data);
    let len = r.read_u16_be()? as usize;
    if len != r.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid key_share list",
        ));
    }
    let mut out = Vec::new();
    let mut groups = HashSet::new();
    while r.remaining() != 0 {
        let group = r.read_u16_be()?;
        let key_len = r.read_u16_be()? as usize;
        if key_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty key share",
            ));
        }
        if !groups.insert(group) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate key-share group",
            ));
        }
        out.push((group, Bytes::copy_from_slice(r.read_slice(key_len)?)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn client_hello_handshake() -> Vec<u8> {
        let mut extensions = Vec::new();
        let host = b"example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        extensions.extend_from_slice(&43u16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[2, 3, 4]);
        let mut shares = Vec::new();
        shares.extend_from_slice(&36u16.to_be_bytes());
        shares.extend_from_slice(&29u16.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(&[7; 32]);
        extensions.extend_from_slice(&51u16.to_be_bytes());
        extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&shares);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[3; 32]);
        body.push(32);
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut msg = vec![
            1,
            ((body.len() >> 16) & 255) as u8,
            ((body.len() >> 8) & 255) as u8,
            (body.len() & 255) as u8,
        ];
        msg.extend_from_slice(&body);
        msg
    }

    fn record(fragment: &[u8]) -> Vec<u8> {
        let mut out = vec![22, 3, 1];
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    #[tokio::test]
    async fn reads_fragmented_client_hello_without_losing_wire_bytes() {
        let hello = client_hello_handshake();
        let split = 31;
        let mut wire = record(&hello[..split]);
        wire.extend_from_slice(&record(&hello[split..]));
        let (mut tx, mut rx) = tokio::io::duplex(wire.len());
        tx.write_all(&wire).await.unwrap();
        drop(tx);
        let parsed = read_client_hello(&mut rx, ClientHelloLimits::default())
            .await
            .unwrap();
        assert_eq!(parsed.wire_bytes(), wire);
        assert_eq!(parsed.handshake_bytes(), hello);
        assert_eq!(parsed.server_name(), "example.com");
        assert!(parsed.supports_tls13());
        assert_eq!(parsed.key_share(29), Some(&[7; 32][..]));
    }

    #[tokio::test]
    async fn rejects_record_over_bound_before_allocating_payload() {
        let header = [22, 3, 1, 0x40, 0x01];
        let (mut tx, mut rx) = tokio::io::duplex(header.len());
        tx.write_all(&header).await.unwrap();
        drop(tx);
        let err = read_client_hello(
            &mut rx,
            ClientHelloLimits {
                max_record_payload: 1024,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
