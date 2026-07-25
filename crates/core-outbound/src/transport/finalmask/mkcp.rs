//! Xray 26.7.11 `mkcp-legacy` UDP masks.
//!
//! This is a byte-for-byte port of the implementations under
//! `transport/internet/finalmask/mkcp` at commit
//! `6e3322d219140a025285ded1114fe17a5edb74d8`.

use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use core_config::MkcpLegacyMaskConfig;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

const AES_NONCE_SIZE: usize = 12;

pub(super) struct MkcpCodec {
    mode: Mode,
}

enum Mode {
    Original,
    Aes128Gcm(Aes128Gcm),
    Header(Header),
}

enum Header {
    Dns(Vec<u8>),
    Dtls {
        epoch: u16,
        length: u16,
        sequence: u32,
    },
    Srtp {
        header: u16,
        number: u16,
    },
    Utp {
        header: u8,
        extension: u8,
        connection_id: u16,
    },
    Wechat {
        sequence: u32,
    },
    Wireguard,
}

impl MkcpCodec {
    pub(super) fn new(config: &MkcpLegacyMaskConfig) -> std::io::Result<Self> {
        let mode = if config.header.is_empty() {
            if config.value.is_empty() {
                Mode::Original
            } else {
                let hash = Sha256::digest(config.value.as_bytes());
                Mode::Aes128Gcm(Aes128Gcm::new_from_slice(&hash[..16]).map_err(invalid)?)
            }
        } else {
            let header = match config.header.to_ascii_lowercase().as_str() {
                "dns" => Header::Dns(dns_header(if config.value.is_empty() {
                    "www.baidu.com"
                } else {
                    &config.value
                })?),
                "dtls" => Header::Dtls {
                    epoch: 0,
                    length: 0,
                    sequence: 0,
                },
                "srtp" => Header::Srtp {
                    header: 0,
                    number: 0,
                },
                "utp" => Header::Utp {
                    header: 0,
                    extension: 0,
                    connection_id: 0,
                },
                "wechat" => Header::Wechat { sequence: 0 },
                "wireguard" => Header::Wireguard,
                other => {
                    return Err(invalid(format!("invalid mkcp-legacy header `{other}`")));
                }
            };
            Mode::Header(header)
        };
        Ok(Self { mode })
    }

    pub(super) fn encode(&mut self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        match &mut self.mode {
            Mode::Original => encode_original(payload),
            Mode::Aes128Gcm(cipher) => {
                let mut nonce = [0u8; AES_NONCE_SIZE];
                OsRng.fill_bytes(&mut nonce);
                let encrypted = cipher
                    .encrypt(Nonce::from_slice(&nonce), payload)
                    .map_err(other)?;
                let mut output = Vec::with_capacity(nonce.len() + encrypted.len());
                output.extend_from_slice(&nonce);
                output.extend_from_slice(&encrypted);
                Ok(output)
            }
            Mode::Header(header) => {
                let mut output = vec![0; header.size()];
                header.serialize(&mut output);
                output.extend_from_slice(payload);
                Ok(output)
            }
        }
    }

    pub(super) fn decode(&mut self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        match &mut self.mode {
            Mode::Original => decode_original(packet),
            Mode::Aes128Gcm(cipher) => {
                if packet.len() < AES_NONCE_SIZE + 16 {
                    return Err(invalid("mkcp-legacy aes128gcm packet is truncated"));
                }
                cipher
                    .decrypt(
                        Nonce::from_slice(&packet[..AES_NONCE_SIZE]),
                        &packet[AES_NONCE_SIZE..],
                    )
                    .map_err(|_| invalid("mkcp-legacy aes128gcm authentication failed"))
            }
            Mode::Header(header) => packet
                .get(header.size()..)
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("mkcp-legacy header packet is truncated")),
        }
    }
}

impl Header {
    fn size(&self) -> usize {
        match self {
            Self::Dns(header) => header.len(),
            Self::Dtls { .. } | Self::Wechat { .. } => 13,
            Self::Srtp { .. } | Self::Utp { .. } | Self::Wireguard => 4,
        }
    }

    fn serialize(&mut self, output: &mut [u8]) {
        match self {
            Self::Dns(header) => {
                output.copy_from_slice(header);
                let txid = rand::random::<u16>().to_be_bytes();
                output[..2].copy_from_slice(&txid);
            }
            Self::Dtls {
                epoch,
                length,
                sequence,
            } => {
                output[0] = 23;
                output[1] = 254;
                output[2] = 253;
                output[3..5].copy_from_slice(&epoch.to_be_bytes());
                output[5] = 0;
                output[6] = 0;
                output[7..11].copy_from_slice(&sequence.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                output[11..13].copy_from_slice(&length.to_be_bytes());
                *length = length.wrapping_add(17);
                if *length > 100 {
                    *length -= 50;
                }
            }
            Self::Srtp { header, number } => {
                *number = number.wrapping_add(1);
                output[..2].copy_from_slice(&header.to_be_bytes());
                output[2..4].copy_from_slice(&number.to_be_bytes());
            }
            Self::Utp {
                header,
                extension,
                connection_id,
            } => {
                output[..2].copy_from_slice(&connection_id.to_be_bytes());
                output[2] = *header;
                output[3] = *extension;
            }
            Self::Wechat { sequence } => {
                *sequence = sequence.wrapping_add(1);
                output[0] = 0xa1;
                output[1] = 0x08;
                output[2..6].copy_from_slice(&sequence.to_be_bytes());
                output[6..13].copy_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            Self::Wireguard => output.copy_from_slice(&[0x04, 0x00, 0x00, 0x00]),
        }
    }
}

fn encode_original(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len())
        .map_err(|_| invalid("mkcp-legacy original payload exceeds 65535 bytes"))?;
    let mut output = Vec::with_capacity(payload.len() + 9);
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    let hash = fnv1a32(&output[4..]).to_be_bytes();
    output[..4].copy_from_slice(&hash);
    xor_forward_padded(&mut output);
    Ok(output)
}

fn decode_original(packet: &[u8]) -> std::io::Result<Vec<u8>> {
    if packet.len() < 6 {
        return Err(invalid("mkcp-legacy original packet is truncated"));
    }
    let mut decoded = packet.to_vec();
    xor_backward_padded(&mut decoded);
    let expected = u32::from_be_bytes(decoded[..4].try_into().expect("four bytes"));
    if fnv1a32(&decoded[4..]) != expected {
        return Err(invalid("mkcp-legacy original authentication failed"));
    }
    let length = u16::from_be_bytes(decoded[4..6].try_into().expect("two bytes")) as usize;
    if decoded.len() - 6 != length {
        return Err(invalid("mkcp-legacy original length mismatch"));
    }
    Ok(decoded.split_off(6))
}

fn xor_forward_padded(bytes: &mut Vec<u8>) {
    let original = bytes.len();
    let padding = (4 - original % 4) % 4;
    bytes.resize(original + padding, 0);
    for index in 4..bytes.len() {
        bytes[index] ^= bytes[index - 4];
    }
    bytes.truncate(original);
}

fn xor_backward_padded(bytes: &mut Vec<u8>) {
    let original = bytes.len();
    let padding = (4 - original % 4) % 4;
    bytes.resize(original + padding, 0);
    for index in (4..bytes.len()).rev() {
        bytes[index] ^= bytes[index - 4];
    }
    bytes.truncate(original);
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn dns_header(domain: &str) -> std::io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(272);
    header.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x01]);
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&pack_domain_name(&format!("{domain}."))?);
    header.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    Ok(header)
}

fn pack_domain_name(domain: &str) -> std::io::Result<Vec<u8>> {
    let mut labels = Vec::<Vec<u8>>::new();
    let mut current = Vec::new();
    let mut escaped = false;
    for byte in domain.bytes() {
        if escaped {
            current.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'.' {
            if current.len() >= 64 {
                return Err(invalid("mkcp-legacy DNS label is too long"));
            }
            labels.push(std::mem::take(&mut current));
        } else {
            current.push(byte);
        }
    }
    if escaped {
        return Err(invalid("mkcp-legacy DNS name ends in an escape"));
    }
    if !current.is_empty() {
        labels.push(current);
    }
    let mut output = Vec::new();
    for label in labels {
        output.push(label.len() as u8);
        output.extend_from_slice(&label);
    }
    if output.last().copied() != Some(0) {
        output.push(0);
    }
    if output.len() > 255 {
        return Err(invalid("mkcp-legacy DNS name exceeds 255 bytes"));
    }
    Ok(output)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_roundtrip_and_tamper_rejection() {
        let mut codec = MkcpCodec::new(&MkcpLegacyMaskConfig::default()).unwrap();
        let encoded = codec.encode(b"hello mkcp").unwrap();
        assert_eq!(codec.decode(&encoded).unwrap(), b"hello mkcp");
        let mut tampered = encoded;
        tampered[5] ^= 1;
        assert!(codec.decode(&tampered).is_err());
    }

    #[test]
    fn aes128gcm_roundtrip_and_tamper_rejection() {
        let config = MkcpLegacyMaskConfig {
            value: "password".into(),
            ..Default::default()
        };
        let mut codec = MkcpCodec::new(&config).unwrap();
        let encoded = codec.encode(b"hello aes").unwrap();
        assert_eq!(codec.decode(&encoded).unwrap(), b"hello aes");
        let mut tampered = encoded;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(codec.decode(&tampered).is_err());
    }

    #[test]
    fn named_headers_match_pinned_wire_shapes() {
        for (name, prefix) in [
            ("wireguard", vec![4, 0, 0, 0]),
            (
                "wechat",
                vec![
                    0xa1, 0x08, 0, 0, 0, 1, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30,
                ],
            ),
            ("dtls", vec![23, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            let mut codec = MkcpCodec::new(&MkcpLegacyMaskConfig {
                header: name.into(),
                ..Default::default()
            })
            .unwrap();
            let packet = codec.encode(b"p").unwrap();
            assert_eq!(&packet[..prefix.len()], prefix, "header={name}");
            assert_eq!(codec.decode(&packet).unwrap(), b"p");
        }
    }
}
