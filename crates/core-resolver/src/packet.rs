//! DNS packet parsing and synthesis used by hijack/fake-ip paths.
//!
//! This module intentionally handles packet framing only. Policy, cache and
//! upstream selection stay in [`crate::Resolver`] / [`crate::DnsService`].

use std::net::IpAddr;

use hickory_resolver::proto::{
    rr::Record,
    serialize::binary::{BinEncodable, BinEncoder},
};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
}

pub fn parse_first_question(pkt: &[u8]) -> Option<DnsQuestion> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let (name, name_end) = read_name(pkt, 12)?;
    if name_end + 4 > pkt.len() {
        return None;
    }
    Some(DnsQuestion {
        name,
        qtype: u16::from_be_bytes([pkt[name_end], pkt[name_end + 1]]),
        qclass: u16::from_be_bytes([pkt[name_end + 2], pkt[name_end + 3]]),
        question_end: name_end + 4,
    })
}

pub fn build_empty_response(req: &[u8], question: Option<&DnsQuestion>) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let end = question
        .map(|q| q.question_end.min(req.len()))
        .unwrap_or(req.len());
    let mut resp = req[..end].to_vec();
    let qdcount = if question.is_some() {
        1
    } else {
        u16::from_be_bytes([req[4], req[5]])
    };
    set_response_header(&mut resp, qdcount, 0);
    resp
}

pub fn build_ip_response(
    req: &[u8],
    question: &DnsQuestion,
    ips: &[IpAddr],
    ttl_secs: u32,
) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let answers = ips
        .iter()
        .filter(|ip| ip_matches_qtype(**ip, question.qtype))
        .collect::<Vec<_>>();
    if answers.is_empty() {
        return build_empty_response(req, Some(question));
    }

    let mut resp = req[..question.question_end.min(req.len())].to_vec();
    set_response_header(&mut resp, 1, answers.len() as u16);

    for ip in answers {
        resp.extend_from_slice(&[0xc0, 0x0c]);
        match ip {
            IpAddr::V4(v4) => {
                resp.extend_from_slice(&TYPE_A.to_be_bytes());
                resp.extend_from_slice(&CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&ttl_secs.to_be_bytes());
                resp.extend_from_slice(&4u16.to_be_bytes());
                resp.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                resp.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                resp.extend_from_slice(&CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&ttl_secs.to_be_bytes());
                resp.extend_from_slice(&16u16.to_be_bytes());
                resp.extend_from_slice(&v6.octets());
            }
        }
    }
    resp
}

pub fn build_record_response(req: &[u8], question: &DnsQuestion, records: &[Record]) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let mut encoded = Vec::new();
    let mut answer_count = 0u16;
    for record in records {
        let mut one = Vec::new();
        let mut encoder = BinEncoder::new(&mut one);
        if record.emit(&mut encoder).is_ok() {
            encoded.extend_from_slice(&one);
            answer_count = answer_count.saturating_add(1);
        }
    }
    if answer_count == 0 {
        return build_empty_response(req, Some(question));
    }

    let mut resp = req[..question.question_end.min(req.len())].to_vec();
    set_response_header(&mut resp, 1, answer_count);
    resp.extend_from_slice(&encoded);
    resp
}

pub fn ip_matches_qtype(ip: IpAddr, qtype: u16) -> bool {
    matches!(
        (ip, qtype),
        (IpAddr::V4(_), TYPE_A) | (IpAddr::V6(_), TYPE_AAAA)
    )
}

fn set_response_header(resp: &mut [u8], question_count: u16, answer_count: u16) {
    if resp.len() < 12 {
        return;
    }
    // QR=1, preserve RD from the request; RA=1, RCODE=NOERROR.
    resp[2] = 0x80 | (resp[2] & 0x01);
    resp[3] = 0x80;
    resp[4..6].copy_from_slice(&question_count.to_be_bytes());
    resp[6..8].copy_from_slice(&answer_count.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());
}

fn read_name(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut i = start;
    let mut end_after_pointer = None;

    for _ in 0..128 {
        let len = *pkt.get(i)?;
        if len & 0xc0 == 0xc0 {
            let b2 = *pkt.get(i + 1)?;
            let ptr = (((len & 0x3f) as usize) << 8) | b2 as usize;
            if ptr >= pkt.len() {
                return None;
            }
            end_after_pointer.get_or_insert(i + 2);
            i = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        if len == 0 {
            return Some((labels.join("."), end_after_pointer.unwrap_or(i + 1)));
        }
        let next = i + 1 + len as usize;
        if next > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[i + 1..next]).ok()?;
        labels.push(label.to_ascii_lowercase());
        i = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_first_question() {
        let pkt = query("WWW.Example.COM", TYPE_A);
        let q = parse_first_question(&pkt).unwrap();
        assert_eq!(q.name, "www.example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn builds_trimmed_ip_response() {
        let mut pkt = query("a.com", TYPE_A);
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        let q = parse_first_question(&pkt).unwrap();
        let resp = build_ip_response(&pkt, &q, &["1.2.3.4".parse().unwrap()], 60);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(&resp[resp.len() - 4..], &[1, 2, 3, 4]);
    }
}
