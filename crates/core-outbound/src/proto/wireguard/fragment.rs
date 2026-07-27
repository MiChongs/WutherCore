use std::sync::atomic::{AtomicU32, Ordering};

use super::io_err;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const IPV6_FRAGMENT_HEADER: usize = 8;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_DESTINATION_OPTIONS: u8 = 60;

static IPV6_FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);

pub(super) fn fragment_ip_packet(packet: &[u8], mtu: usize) -> std::io::Result<Vec<Vec<u8>>> {
    if packet.len() <= mtu {
        return Ok(vec![packet.to_vec()]);
    }
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => fragment_ipv4(packet, mtu),
        Some(6) => fragment_ipv6(packet, mtu),
        _ => Err(io_err(
            "wireguard plaintext is not a valid IPv4/IPv6 packet",
        )),
    }
}

fn fragment_ipv4(packet: &[u8], mtu: usize) -> std::io::Result<Vec<Vec<u8>>> {
    if packet.len() < IPV4_MIN_HEADER {
        return Err(io_err(
            "wireguard IPv4 packet is shorter than its base header",
        ));
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_MIN_HEADER || header_len > packet.len() || total_len != packet.len() {
        return Err(io_err(
            "wireguard IPv4 packet has an invalid header/total length",
        ));
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_offset & 0x3fff != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wireguard cannot re-fragment an existing IPv4 fragment",
        ));
    }
    if flags_offset & 0x4000 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wireguard IPv4 packet exceeds mtu while Don't Fragment is set",
        ));
    }
    let copied_options = copied_ipv4_options(&packet[IPV4_MIN_HEADER..header_len])?;
    let payload = &packet[header_len..];
    let mut offset = 0usize;
    let mut fragments = Vec::new();
    while offset < payload.len() {
        let options = if offset == 0 {
            &packet[IPV4_MIN_HEADER..header_len]
        } else {
            copied_options.as_slice()
        };
        let fragment_header_len = IPV4_MIN_HEADER + options.len();
        let capacity = mtu
            .checked_sub(fragment_header_len)
            .ok_or_else(|| io_err("wireguard mtu is too small for the IPv4 header and options"))?;
        let remaining = payload.len() - offset;
        let take = if remaining > capacity {
            capacity & !7
        } else {
            remaining
        };
        if take == 0 {
            return Err(io_err(
                "wireguard mtu leaves no aligned IPv4 fragment payload",
            ));
        }
        let more = offset + take < payload.len();
        let mut fragment = vec![0; fragment_header_len + take];
        fragment[..IPV4_MIN_HEADER].copy_from_slice(&packet[..IPV4_MIN_HEADER]);
        fragment[IPV4_MIN_HEADER..fragment_header_len].copy_from_slice(options);
        fragment[0] = 0x40
            | u8::try_from(fragment_header_len / 4)
                .map_err(|_| io_err("wireguard IPv4 header is too long"))?;
        let fragment_len = u16::try_from(fragment.len())
            .map_err(|_| io_err("wireguard IPv4 fragment length overflow"))?;
        fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
        let fragment_offset = u16::try_from(offset / 8)
            .map_err(|_| io_err("wireguard IPv4 fragment offset overflow"))?;
        let fragment_flags =
            (flags_offset & 0x8000) | if more { 0x2000 } else { 0 } | fragment_offset;
        fragment[6..8].copy_from_slice(&fragment_flags.to_be_bytes());
        fragment[10..12].fill(0);
        fragment[fragment_header_len..].copy_from_slice(&payload[offset..offset + take]);
        let checksum = ipv4_checksum(&fragment[..fragment_header_len]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragments.push(fragment);
        offset += take;
    }
    Ok(fragments)
}

fn copied_ipv4_options(options: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut copied = Vec::new();
    let mut cursor = 0usize;
    while cursor < options.len() {
        let kind = options[cursor];
        match kind {
            0 => break,
            1 => cursor += 1,
            _ => {
                let length = options
                    .get(cursor + 1)
                    .copied()
                    .map(usize::from)
                    .ok_or_else(|| io_err("wireguard IPv4 option is missing its length"))?;
                if length < 2 || cursor + length > options.len() {
                    return Err(io_err("wireguard IPv4 option has an invalid length"));
                }
                if kind & 0x80 != 0 {
                    copied.extend_from_slice(&options[cursor..cursor + length]);
                }
                cursor += length;
            }
        }
    }
    while copied.len() % 4 != 0 {
        copied.push(0);
    }
    Ok(copied)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        let value = if word.len() == 2 {
            u16::from_be_bytes([word[0], word[1]])
        } else {
            u16::from(word[0]) << 8
        };
        sum += u32::from(value);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

fn fragment_ipv6(packet: &[u8], mtu: usize) -> std::io::Result<Vec<Vec<u8>>> {
    if packet.len() < IPV6_HEADER {
        return Err(io_err(
            "wireguard IPv6 packet is shorter than its base header",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len == 0 || payload_len + IPV6_HEADER != packet.len() {
        return Err(io_err(
            "wireguard IPv6 packet has an invalid payload length or unsupported jumbogram",
        ));
    }
    let (unfragmentable_end, next_header_field, fragment_next) =
        ipv6_fragment_insertion_point(packet)?;
    let fragmentable = &packet[unfragmentable_end..];
    let capacity = mtu
        .checked_sub(unfragmentable_end + IPV6_FRAGMENT_HEADER)
        .ok_or_else(|| io_err("wireguard mtu is too small for IPv6 fragmentation headers"))?;
    let aligned_capacity = capacity & !7;
    if aligned_capacity == 0 {
        return Err(io_err(
            "wireguard mtu leaves no aligned IPv6 fragment payload",
        ));
    }
    let identification = IPV6_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
    let mut offset = 0usize;
    let mut fragments = Vec::new();
    while offset < fragmentable.len() {
        let remaining = fragmentable.len() - offset;
        let take = if remaining > capacity {
            aligned_capacity
        } else {
            remaining
        };
        let more = offset + take < fragmentable.len();
        let mut fragment = Vec::with_capacity(unfragmentable_end + IPV6_FRAGMENT_HEADER + take);
        fragment.extend_from_slice(&packet[..unfragmentable_end]);
        fragment[next_header_field] = IPV6_FRAGMENT;
        fragment.push(fragment_next);
        fragment.push(0);
        let mut offset_flags = u16::try_from(offset)
            .map_err(|_| io_err("wireguard IPv6 fragment offset overflow"))?
            & 0xfff8;
        if more {
            offset_flags |= 1;
        }
        fragment.extend_from_slice(&offset_flags.to_be_bytes());
        fragment.extend_from_slice(&identification.to_be_bytes());
        fragment.extend_from_slice(&fragmentable[offset..offset + take]);
        let new_payload_len = fragment.len() - IPV6_HEADER;
        fragment[4..6].copy_from_slice(
            &u16::try_from(new_payload_len)
                .map_err(|_| io_err("wireguard IPv6 fragment length overflow"))?
                .to_be_bytes(),
        );
        fragments.push(fragment);
        offset += take;
    }
    Ok(fragments)
}

fn ipv6_fragment_insertion_point(packet: &[u8]) -> std::io::Result<(usize, usize, u8)> {
    #[derive(Clone, Copy)]
    struct Extension {
        kind: u8,
        start: usize,
        end: usize,
        next: u8,
    }

    let mut extensions = Vec::new();
    let mut kind = packet[6];
    let mut cursor = IPV6_HEADER;
    while matches!(
        kind,
        IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS
    ) {
        if cursor + 2 > packet.len() {
            return Err(io_err("wireguard IPv6 extension header is truncated"));
        }
        let length = (usize::from(packet[cursor + 1]) + 1) * 8;
        if cursor + length > packet.len() {
            return Err(io_err("wireguard IPv6 extension header length is invalid"));
        }
        let next = packet[cursor];
        extensions.push(Extension {
            kind,
            start: cursor,
            end: cursor + length,
            next,
        });
        cursor += length;
        kind = next;
    }
    if kind == IPV6_FRAGMENT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wireguard cannot re-fragment an existing IPv6 fragment",
        ));
    }
    let mut insertion = IPV6_HEADER;
    let mut next_header_field = 6usize;
    let mut fragment_next = packet[6];
    for (index, extension) in extensions.iter().enumerate() {
        let destination_precedes_routing = extension.kind == IPV6_DESTINATION_OPTIONS
            && extensions[index + 1..]
                .iter()
                .any(|later| later.kind == IPV6_ROUTING);
        if !matches!(extension.kind, IPV6_HOP_BY_HOP | IPV6_ROUTING)
            && !destination_precedes_routing
        {
            break;
        }
        insertion = extension.end;
        next_header_field = extension.start;
        fragment_next = extension.next;
    }
    Ok((insertion, next_header_field, fragment_next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_fragments_are_aligned_and_bounded_for_non_aligned_mtu() {
        let mut packet = vec![0; 4_124];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(4_124u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        let fragments = fragment_ip_packet(&packet, 1_280).unwrap();
        assert!(fragments.len() > 1);
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 1_280);
            if index + 1 != fragments.len() {
                assert_eq!((fragment.len() - 20) % 8, 0);
                assert_ne!(u16::from_be_bytes([fragment[6], fragment[7]]) & 0x2000, 0);
            }
        }
    }

    #[test]
    fn ipv6_fragments_include_rfc8200_header_and_bounded_payloads() {
        let mut packet = vec![0; 4_144];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(4_104u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        let fragments = fragment_ip_packet(&packet, 1_280).unwrap();
        assert!(fragments.len() > 1);
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 1_280);
            assert_eq!(fragment[6], IPV6_FRAGMENT);
            assert_eq!(fragment[40], 17);
            let flags = u16::from_be_bytes([fragment[42], fragment[43]]);
            if index + 1 != fragments.len() {
                assert_eq!((fragment.len() - 48) % 8, 0);
                assert_eq!(flags & 1, 1);
            }
        }
    }
}
