//! Xray Salamander and Gecko UDP packet masking.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use core_config::SalamanderMaskConfig;
use rand::{Rng, RngCore, rngs::OsRng};

const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const PSK_MIN_LEN: usize = 4;

const GECKO_FLAG_FRAGMENT: u8 = 0x80;
const GECKO_HEADER_SIZE: usize = 5;
const GECKO_MIN_FRAGMENT_CHUNKS: usize = 2;
const GECKO_MAX_FRAGMENT_CHUNKS: usize = 8;
const GECKO_DEFAULT_MIN_PACKET: usize = 512;
const GECKO_DEFAULT_MAX_PACKET: usize = 1200;
const GECKO_BUFFER_SIZE: usize = 2048;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 8;

pub(super) struct SalamanderCodec {
    password: Vec<u8>,
    gecko: Option<GeckoState>,
}

struct GeckoState {
    min_packet: usize,
    max_packet: usize,
    next_message_id: u8,
    entries: HashMap<u8, ReassemblyEntry>,
}

struct ReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    deadline: Instant,
}

impl SalamanderCodec {
    pub(super) fn new(config: &SalamanderMaskConfig) -> std::io::Result<Self> {
        if config.password.as_bytes().len() < PSK_MIN_LEN {
            return Err(invalid(format!(
                "Salamander PSK must be at least {PSK_MIN_LEN} bytes"
            )));
        }
        let gecko = if config.packet_size.to > 0 {
            let min_packet = if config.packet_size.from == 0 {
                GECKO_DEFAULT_MIN_PACKET
            } else {
                usize::try_from(config.packet_size.from)
                    .map_err(|_| invalid("gecko minimum packet size is negative"))?
            };
            let max_packet = if config.packet_size.to == 0 {
                GECKO_DEFAULT_MAX_PACKET
            } else {
                usize::try_from(config.packet_size.to)
                    .map_err(|_| invalid("gecko maximum packet size is negative"))?
            };
            if min_packet == 0 || min_packet > max_packet || max_packet > GECKO_BUFFER_SIZE {
                return Err(invalid("gecko: invalid min/max packet size"));
            }
            Some(GeckoState {
                min_packet,
                max_packet,
                next_message_id: 0,
                entries: HashMap::new(),
            })
        } else {
            None
        };
        Ok(Self {
            password: config.password.as_bytes().to_vec(),
            gecko,
        })
    }

    pub(super) fn encode(&mut self, payload: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
        let Some(gecko) = self.gecko.as_mut() else {
            return Ok(vec![obfuscate(&self.password, payload)?]);
        };
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        if payload[0] & GECKO_FLAG_FRAGMENT == 0 {
            return Ok(vec![obfuscate(&self.password, payload)?]);
        }

        let chunk_count =
            rand::thread_rng().gen_range(GECKO_MIN_FRAGMENT_CHUNKS..=GECKO_MAX_FRAGMENT_CHUNKS);
        let chunk_size = payload.len() / chunk_count;
        gecko.next_message_id = gecko.next_message_id.wrapping_add(1);
        let message_id = gecko.next_message_id;
        let mut packets = Vec::with_capacity(chunk_count);
        for index in 0..chunk_count {
            let start = index * chunk_size;
            let end = if index + 1 == chunk_count {
                payload.len()
            } else {
                start + chunk_size
            };
            let chunk = &payload[start..end];
            let base = SALT_LEN + GECKO_HEADER_SIZE + chunk.len();
            let low = gecko.min_packet.max(base);
            let pad_len = if low > gecko.max_packet {
                0
            } else {
                low - base + rand::thread_rng().gen_range(0..=gecko.max_packet - low)
            };
            let pad_len = u16::try_from(pad_len).expect("gecko packet size is bounded");
            let mut frame = vec![0; GECKO_HEADER_SIZE + usize::from(pad_len) + chunk.len()];
            frame[0] = GECKO_FLAG_FRAGMENT;
            frame[1] = message_id;
            frame[2] = ((index as u8) << 4) | chunk_count as u8;
            frame[3..5].copy_from_slice(&pad_len.to_be_bytes());
            OsRng.fill_bytes(
                &mut frame[GECKO_HEADER_SIZE..GECKO_HEADER_SIZE + usize::from(pad_len)],
            );
            frame[GECKO_HEADER_SIZE + usize::from(pad_len)..].copy_from_slice(chunk);
            packets.push(obfuscate(&self.password, &frame)?);
        }
        Ok(packets)
    }

    pub(super) fn decode(&mut self, packet: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        let decoded = deobfuscate(&self.password, packet)?;
        let Some(gecko) = self.gecko.as_mut() else {
            return Ok(Some(decoded));
        };
        if decoded.is_empty() {
            return Ok(None);
        }
        if decoded[0] & GECKO_FLAG_FRAGMENT == 0 {
            return Ok(Some(decoded));
        }
        let (header, payload) = decode_frame(&decoded)?;
        let now = Instant::now();
        gecko.entries.retain(|_, entry| entry.deadline > now);
        if !gecko.entries.contains_key(&header.message_id)
            && gecko.entries.len() >= GECKO_MAX_REASSEMBLY
            && let Some(oldest) = gecko
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.deadline)
                .map(|(&key, _)| key)
        {
            gecko.entries.remove(&oldest);
        }
        let entry = gecko
            .entries
            .entry(header.message_id)
            .or_insert_with(|| ReassemblyEntry {
                chunks: vec![None; header.total_chunks as usize],
                received: 0,
                deadline: now + GECKO_REASSEMBLY_TTL,
            });
        if entry.chunks.len() != header.total_chunks as usize {
            return Ok(None);
        }
        let slot = &mut entry.chunks[header.chunk_index as usize];
        if slot.is_some() {
            return Ok(None);
        }
        *slot = Some(payload.to_vec());
        entry.received += 1;
        if entry.received != entry.chunks.len() {
            return Ok(None);
        }
        let entry = gecko
            .entries
            .remove(&header.message_id)
            .expect("complete entry exists");
        let total = entry
            .chunks
            .iter()
            .map(|chunk| chunk.as_ref().map_or(0, Vec::len))
            .sum();
        if total > u16::MAX as usize {
            return Err(invalid("gecko reassembled datagram exceeds 65535 bytes"));
        }
        let mut output = Vec::with_capacity(total);
        for chunk in entry.chunks {
            output.extend_from_slice(chunk.as_deref().expect("complete entry"));
        }
        Ok(Some(output))
    }
}

struct FrameHeader {
    message_id: u8,
    chunk_index: u8,
    total_chunks: u8,
}

fn decode_frame(frame: &[u8]) -> std::io::Result<(FrameHeader, &[u8])> {
    if frame.len() < GECKO_HEADER_SIZE {
        return Err(invalid("gecko frame is truncated"));
    }
    let chunk_index = frame[2] >> 4;
    let total_chunks = frame[2] & 0x0f;
    if !(GECKO_MIN_FRAGMENT_CHUNKS as u8..=GECKO_MAX_FRAGMENT_CHUNKS as u8).contains(&total_chunks)
        || chunk_index >= total_chunks
    {
        return Err(invalid("gecko frame header is invalid"));
    }
    let padding = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    let payload_offset = GECKO_HEADER_SIZE
        .checked_add(padding)
        .ok_or_else(|| invalid("gecko padding length overflow"))?;
    let payload = frame
        .get(payload_offset..)
        .ok_or_else(|| invalid("gecko frame padding is truncated"))?;
    Ok((
        FrameHeader {
            message_id: frame[1],
            chunk_index,
            total_chunks,
        },
        payload,
    ))
}

fn obfuscate(password: &[u8], payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = salamander_key(password, &salt)?;
    let mut output = Vec::with_capacity(SALT_LEN + payload.len());
    output.extend_from_slice(&salt);
    output.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
    );
    Ok(output)
}

fn deobfuscate(password: &[u8], packet: &[u8]) -> std::io::Result<Vec<u8>> {
    if packet.len() <= SALT_LEN {
        return Err(invalid("Salamander packet is truncated"));
    }
    let key = salamander_key(password, &packet[..SALT_LEN])?;
    Ok(packet[SALT_LEN..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % KEY_LEN])
        .collect())
}

fn salamander_key(password: &[u8], salt: &[u8]) -> std::io::Result<[u8; KEY_LEN]> {
    let mut hasher = Blake2bVar::new(KEY_LEN).map_err(invalid)?;
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0u8; KEY_LEN];
    hasher.finalize_variable(&mut key).map_err(invalid)?;
    Ok(key)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use core_config::I32Range;

    use super::*;

    #[test]
    fn simple_roundtrip_and_short_packet_rejected() {
        let mut codec = SalamanderCodec::new(&SalamanderMaskConfig {
            password: "password".into(),
            ..Default::default()
        })
        .unwrap();
        let encoded = codec.encode(b"payload").unwrap().pop().unwrap();
        assert_eq!(codec.decode(&encoded).unwrap().unwrap(), b"payload");
        assert!(codec.decode(&[0; 8]).is_err());
    }

    #[test]
    fn gecko_reassembles_out_of_order_and_drops_duplicate() {
        let config = SalamanderMaskConfig {
            password: "password".into(),
            packet_size: I32Range::new(80, 120),
        };
        let mut sender = SalamanderCodec::new(&config).unwrap();
        let mut receiver = SalamanderCodec::new(&config).unwrap();
        let mut payload = vec![0x80];
        payload.extend(0u8..=250);
        let mut packets = sender.encode(&payload).unwrap();
        let duplicate = packets[0].clone();
        packets.reverse();
        assert!(receiver.decode(&duplicate).unwrap().is_none());
        let mut output = None;
        for packet in packets {
            if let Some(decoded) = receiver.decode(&packet).unwrap() {
                output = Some(decoded);
            }
        }
        assert_eq!(output.unwrap(), payload);
    }

    #[test]
    fn gecko_resource_table_is_bounded() {
        let config = SalamanderMaskConfig {
            password: "password".into(),
            packet_size: I32Range::new(80, 120),
        };
        let mut sender = SalamanderCodec::new(&config).unwrap();
        let mut receiver = SalamanderCodec::new(&config).unwrap();
        for marker in 0..32u8 {
            let mut payload = vec![0x80, marker];
            payload.extend(vec![marker; 200]);
            let packet = sender.encode(&payload).unwrap().remove(0);
            let _ = receiver.decode(&packet);
        }
        assert!(receiver.gecko.as_ref().unwrap().entries.len() <= GECKO_MAX_REASSEMBLY);
    }
}
