//! Fake-IP DNS 劫持 —— capture.resolver = hijack 时使用。
//!
//! 监听 udp:53 + tcp:53，对 A/AAAA 查询返回 [`core_resolver::FakeIpPool`]
//! 分配的 IP；其它类型透传给上游。
//!
//! MVP 实现：仅处理常见 A/AAAA 查询；CNAME / TXT / MX 透传到 system resolver。

use std::net::SocketAddr;
use std::sync::Arc;

use core_resolver::fake_ip::{AddressFamily, FakeIpPool};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// 启动 Fake DNS server。
pub async fn run_fake_dns(
    bind: SocketAddr,
    pool: Arc<FakeIpPool>,
) -> std::io::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    debug!(target: "capture::dns", addr = %bind, "fake-dns listening");
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if n < 12 {
            continue;
        }
        let req = &buf[..n];
        let Some((qname, qtype)) = parse_first_question(req) else {
            continue;
        };

        let family = match qtype {
            1 => AddressFamily::V4,
            28 => AddressFamily::V6,
            _ => {
                // 其它类型：返回空响应（NOERROR + 0 answer），让客户端重试或回退。
                let resp = build_empty_response(req);
                let _ = sock.send_to(&resp, src).await;
                continue;
            }
        };

        let Some(ip) = pool.alloc(&qname, family) else {
            // Fake 池不接受该域名 / 协议族 —— 返回空响应。
            let resp = build_empty_response(req);
            let _ = sock.send_to(&resp, src).await;
            continue;
        };
        let resp = build_answer(req, ip);
        if let Err(e) = sock.send_to(&resp, src).await {
            warn!(target: "capture::dns", error = %e, "fake-dns send failed");
        }
    }
}

/// 解析 DNS 报文中第一个问题：qname + qtype。
pub fn parse_first_question(pkt: &[u8]) -> Option<(String, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    while i < pkt.len() {
        let len = pkt[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 != 0 {
            // pointer 压缩 —— MVP 不展开
            return None;
        }
        if i + 1 + len > pkt.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(&pkt[i + 1..i + 1 + len]).ok()?);
        i += 1 + len;
    }
    if i + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
    Some((name, qtype))
}

/// 同步处理一个 DNS 查询包；返回响应字节。
///
/// 与 [`run_fake_dns`] 共享解析与应答构造逻辑，但不走 UDP socket —— 给
/// `tun_dispatch::handle_udp` 在 TUN 内部直接拦截 53 端口流量用，避免
/// "TUN 把 DNS 包发到 127.0.0.1:5454"中转的不可达问题。
pub fn synthesize(req: &[u8], pool: &FakeIpPool) -> Vec<u8> {
    if req.len() < 12 {
        return Vec::new();
    }
    let Some((qname, qtype)) = parse_first_question(req) else {
        return build_empty_response(req);
    };
    let family = match qtype {
        1 => AddressFamily::V4,
        28 => AddressFamily::V6,
        _ => return build_empty_response(req),
    };
    let Some(ip) = pool.alloc(&qname, family) else {
        return build_empty_response(req);
    };
    build_answer(req, ip)
}

fn build_empty_response(req: &[u8]) -> Vec<u8> {
    let mut resp = req.to_vec();
    if resp.len() < 4 {
        return resp;
    }
    resp[2] = 0x81; // QR=1, Opcode=0, RD=1
    resp[3] = 0x80; // RA=1, RCODE=0
    // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    resp[6..12].fill(0);
    // 保留 QDCOUNT 与 question
    resp
}

fn build_answer(req: &[u8], ip: std::net::IpAddr) -> Vec<u8> {
    let mut resp = req.to_vec();
    if resp.len() < 12 {
        return resp;
    }
    resp[2] = 0x81;
    resp[3] = 0x80;
    let ancount: u16 = 1;
    resp[6..8].copy_from_slice(&ancount.to_be_bytes());
    resp[8..12].fill(0);

    // pointer 0xc00c 指向 question name
    resp.extend_from_slice(&[0xc0, 0x0c]);
    let (rtype, rdata): (u16, Vec<u8>) = match ip {
        std::net::IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (28, v6.octets().to_vec()),
    };
    resp.extend_from_slice(&rtype.to_be_bytes()); // type
    resp.extend_from_slice(&[0, 1]); // class IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // ttl 60s
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_question_works() {
        // www.example.com A 查询
        let mut pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, // header
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        pkt.extend_from_slice(&[0, 1, 0, 1]); // qtype=A, qclass=IN
        let (name, qtype) = parse_first_question(&pkt).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn build_answer_v4() {
        let pkt = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0,
            0, 1, 0, 1,
        ];
        let resp = build_answer(&pkt, "1.2.3.4".parse().unwrap());
        assert!(resp.len() > pkt.len());
        assert_eq!(resp[7], 1); // ANCOUNT low byte = 1
    }
}
