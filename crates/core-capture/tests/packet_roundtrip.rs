//! 集成测试：构造各种 IP 包并验证 packet.rs 解析正确。
//!
//! 这些 test 不依赖 OS / TUN，纯 in-process，跨平台都能跑。

use core_capture::packet::{parse_ip_packet, IpVersion, L4};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};

fn build_v6_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let src = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Address::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let udp = UdpRepr { src_port, dst_port };
    let ip = Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: smoltcp::wire::IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip.buffer_len() + udp.header_len() + payload.len()];
    let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
    ip.emit(&mut ip_pkt);
    let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..udp.header_len() + payload.len()]);
    udp.emit(
        &mut udp_pkt,
        &IpAddress::Ipv6(src),
        &IpAddress::Ipv6(dst),
        payload.len(),
        |p| p.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    buf
}

fn build_v4_tcp(src_port: u16, dst_port: u16, control: TcpControl) -> Vec<u8> {
    let src = Ipv4Address::new(192, 168, 1, 100);
    let dst = Ipv4Address::new(8, 8, 8, 8);
    let tcp = TcpRepr {
        src_port,
        dst_port,
        control,
        seq_number: TcpSeqNumber(42),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: smoltcp::wire::IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.emit(&mut ip_pkt, &ChecksumCapabilities::default());
    let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp.buffer_len()]);
    tcp.emit(
        &mut tcp_pkt,
        &IpAddress::Ipv4(src),
        &IpAddress::Ipv4(dst),
        &ChecksumCapabilities::default(),
    );
    buf
}

#[test]
fn parses_v6_udp_with_payload() {
    let payload = b"hello-dns";
    let buf = build_v6_udp(53, 53, payload);
    let p = parse_ip_packet(&buf).expect("parse ok");
    assert_eq!(p.ip.version, IpVersion::V6);
    assert_eq!(p.network(), Some("udp"));
    let dst = p.dst_socket().unwrap();
    assert_eq!(dst.port(), 53);
    match p.l4 {
        L4::Udp(u) => {
            assert_eq!(u.src_port, 53);
            assert_eq!(u.dst_port, 53);
            assert_eq!(u.payload_len, payload.len());
            // 反查 payload
            let slice = &buf[u.payload_offset..u.payload_offset + u.payload_len];
            assert_eq!(slice, payload);
        }
        _ => panic!("expected UDP"),
    }
}

#[test]
fn parses_v4_tcp_fin_flag() {
    let buf = build_v4_tcp(33333, 80, TcpControl::Fin);
    let p = parse_ip_packet(&buf).expect("parse ok");
    let net = p.network().unwrap();
    assert_eq!(net, "tcp");
    match p.l4 {
        L4::Tcp(t) => {
            assert!(t.control.fin);
            assert!(!t.control.syn);
        }
        _ => panic!("expected TCP"),
    }
}

#[test]
fn ignores_truncated_buffer() {
    let buf = build_v4_tcp(1, 2, TcpControl::Syn);
    let r = parse_ip_packet(&buf[..10]); // 截断到 IP 头一半
    assert!(r.is_err());
}
