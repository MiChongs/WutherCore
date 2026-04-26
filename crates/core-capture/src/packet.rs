//! IP / TCP / UDP 报头解析 —— TUN 读包之后的第一道处理。
//!
//! 设计目标：
//! * 不分配（仅借用 buf）；
//! * 同时支持 IPv4 与 IPv6；
//! * 提取出 5-tuple + payload 切片，让上层 NAT / user-stack 后续处理；
//! * 复用 `smoltcp::wire` —— 已经在依赖树中（boringtun 间接引入），
//!   纯 Rust，零 unsafe；自带 checksum / fragment 支持。
//!
//! 使用：
//! ```ignore
//! match parse_ip_packet(&buf[..n]) {
//!     Ok(ParsedPacket { ip, l4: L4::Tcp(tcp), .. }) => { … }
//!     Ok(ParsedPacket { ip, l4: L4::Udp(udp), .. }) => { … }
//!     Ok(_) | Err(_) => continue, // ICMP / 分片 / 校验失败 —— 透传或丢弃
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket,
};

/// IP 版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// 已解析的 IP 报头视图（不持有 payload，借用原 buf）。
#[derive(Debug, Clone, Copy)]
pub struct IpHeader {
    pub version: IpVersion,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// 总长度（IP 头 + payload）。
    pub total_len: usize,
    /// L4 payload 在原 buf 中的起始偏移。
    pub l4_offset: usize,
    /// hop_limit / ttl。
    pub hop_limit: u8,
}

/// L4 报头摘要 —— 只提取 socket 调度需要的字段。
#[derive(Debug, Clone, Copy)]
pub enum L4 {
    Tcp(TcpSummary),
    Udp(UdpSummary),
    Other(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct TcpSummary {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub control: TcpFlags,
    pub window: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpSummary {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ParsedPacket {
    pub ip: IpHeader,
    pub l4: L4,
}

impl ParsedPacket {
    /// 5-tuple `源套接字`。
    pub fn src_socket(&self) -> Option<SocketAddr> {
        let port = match self.l4 {
            L4::Tcp(t) => t.src_port,
            L4::Udp(u) => u.src_port,
            L4::Other(_) => return None,
        };
        Some(SocketAddr::new(self.ip.src, port))
    }
    /// 5-tuple `目标套接字`。
    pub fn dst_socket(&self) -> Option<SocketAddr> {
        let port = match self.l4 {
            L4::Tcp(t) => t.dst_port,
            L4::Udp(u) => u.dst_port,
            L4::Other(_) => return None,
        };
        Some(SocketAddr::new(self.ip.dst, port))
    }
    pub fn network(&self) -> Option<&'static str> {
        match self.l4 {
            L4::Tcp(_) => Some("tcp"),
            L4::Udp(_) => Some("udp"),
            L4::Other(_) => None,
        }
    }
    /// L4 payload 起始偏移（为 udp_forwarder 等模块提供）。
    pub fn l4_payload_offset(&self, l4: &L4) -> usize {
        match l4 {
            L4::Tcp(t) => t.payload_offset,
            L4::Udp(u) => u.payload_offset,
            L4::Other(_) => self.ip.l4_offset,
        }
    }
    /// L4 payload 长度。
    pub fn l4_payload_len(&self, l4: &L4) -> usize {
        match l4 {
            L4::Tcp(t) => t.payload_len,
            L4::Udp(u) => u.payload_len,
            L4::Other(_) => 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer 长度过小 ({actual} < {needed})")]
    Truncated { actual: usize, needed: usize },
    #[error("不支持的 IP 版本 {0}")]
    UnsupportedVersion(u8),
    #[error("smoltcp 解析失败: {0}")]
    Wire(smoltcp::wire::Error),
    #[error("不支持的 L4 协议: {0}")]
    UnsupportedL4(u8),
}

impl From<smoltcp::wire::Error> for ParseError {
    fn from(e: smoltcp::wire::Error) -> Self {
        Self::Wire(e)
    }
}

/// 解析 buf 中的一个 IP 包（buf 必须以 IP 头第一字节开始）。
pub fn parse_ip_packet(buf: &[u8]) -> Result<ParsedPacket, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::Truncated { actual: 0, needed: 1 });
    }
    let version = buf[0] >> 4;
    match version {
        4 => parse_v4(buf),
        6 => parse_v6(buf),
        v => Err(ParseError::UnsupportedVersion(v)),
    }
}

fn parse_v4(buf: &[u8]) -> Result<ParsedPacket, ParseError> {
    let pkt = Ipv4Packet::new_checked(buf)?;
    let repr = Ipv4Repr::parse(&pkt, &smoltcp::phy::ChecksumCapabilities::ignored())?;
    let ihl = (pkt.header_len() as usize).max(20);
    let total_len = pkt.total_len() as usize;
    if buf.len() < total_len {
        return Err(ParseError::Truncated { actual: buf.len(), needed: total_len });
    }
    let payload = &buf[ihl..total_len];

    let ip = IpHeader {
        version: IpVersion::V4,
        src: IpAddr::V4(Ipv4Addr::from(repr.src_addr.0)),
        dst: IpAddr::V4(Ipv4Addr::from(repr.dst_addr.0)),
        protocol: u8::from(repr.next_header),
        total_len,
        l4_offset: ihl,
        hop_limit: repr.hop_limit,
    };
    let l4 = parse_l4(repr.next_header, payload, ihl)?;
    Ok(ParsedPacket { ip, l4 })
}

fn parse_v6(buf: &[u8]) -> Result<ParsedPacket, ParseError> {
    let pkt = Ipv6Packet::new_checked(buf)?;
    let repr = Ipv6Repr::parse(&pkt)?;
    let header_len = pkt.header_len();
    let total_len = header_len + repr.payload_len;
    if buf.len() < total_len {
        return Err(ParseError::Truncated { actual: buf.len(), needed: total_len });
    }
    let payload = &buf[header_len..total_len];
    let ip = IpHeader {
        version: IpVersion::V6,
        src: IpAddr::V6(Ipv6Addr::from(repr.src_addr.0)),
        dst: IpAddr::V6(Ipv6Addr::from(repr.dst_addr.0)),
        protocol: u8::from(repr.next_header),
        total_len,
        l4_offset: header_len,
        hop_limit: repr.hop_limit,
    };
    let l4 = parse_l4(repr.next_header, payload, header_len)?;
    Ok(ParsedPacket { ip, l4 })
}

fn parse_l4(proto: IpProtocol, payload: &[u8], base_offset: usize) -> Result<L4, ParseError> {
    match proto {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload)?;
            let header_len = (tcp.header_len() as usize).max(20);
            let p_len = payload.len().saturating_sub(header_len);
            let summary = TcpSummary {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                seq: tcp.seq_number().0 as u32,
                ack: tcp.ack_number().0 as u32,
                control: TcpFlags {
                    syn: tcp.syn(),
                    ack: tcp.ack(),
                    fin: tcp.fin(),
                    rst: tcp.rst(),
                    psh: tcp.psh(),
                },
                window: tcp.window_len(),
                payload_offset: base_offset + header_len,
                payload_len: p_len,
            };
            Ok(L4::Tcp(summary))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload)?;
            let header_len = 8usize;
            let p_len = (udp.len() as usize).saturating_sub(header_len);
            Ok(L4::Udp(UdpSummary {
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
                payload_offset: base_offset + header_len,
                payload_len: p_len,
            }))
        }
        other => Ok(L4::Other(u8::from(other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造一个 IPv4 + TCP SYN 包：
    /// src 10.0.0.2:54321 → dst 1.1.1.1:443
    fn build_v4_tcp_syn() -> Vec<u8> {
        use smoltcp::wire::{IpAddress, Ipv4Address, Ipv4Repr as Repr, TcpControl, TcpRepr};
        let src_ip = Ipv4Address::new(10, 0, 0, 2);
        let dst_ip = Ipv4Address::new(1, 1, 1, 1);
        let tcp = TcpRepr {
            src_port: 54321,
            dst_port: 443,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        };
        let ip = Repr {
            src_addr: src_ip,
            dst_addr: dst_ip,
            next_header: smoltcp::wire::IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };

        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let mut ipv4_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ipv4_pkt, &smoltcp::phy::ChecksumCapabilities::default());
        let mut tcp_pkt =
            TcpPacket::new_unchecked(&mut ipv4_pkt.payload_mut()[..tcp.buffer_len()]);
        tcp.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
        buf
    }

    #[test]
    fn parse_v4_tcp_syn_extracts_5tuple() {
        let buf = build_v4_tcp_syn();
        let p = parse_ip_packet(&buf).expect("parse ok");
        assert_eq!(p.ip.version, IpVersion::V4);
        assert_eq!(p.ip.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(p.ip.dst, "1.1.1.1".parse::<IpAddr>().unwrap());
        let dst = p.dst_socket().unwrap();
        assert_eq!(dst.port(), 443);
        match p.l4 {
            L4::Tcp(t) => {
                assert!(t.control.syn);
                assert!(!t.control.ack);
                assert_eq!(t.src_port, 54321);
                assert_eq!(t.dst_port, 443);
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn rejects_truncated() {
        let r = parse_ip_packet(&[]);
        assert!(matches!(r, Err(ParseError::Truncated { .. })));
    }

    #[test]
    fn rejects_unknown_version() {
        let r = parse_ip_packet(&[0xF0]);
        assert!(matches!(r, Err(ParseError::UnsupportedVersion(15))));
    }
}
