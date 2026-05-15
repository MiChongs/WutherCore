//! 集成测试：构造各种 IP 包并验证 packet.rs 解析正确。
//!
//! 这些 test 不依赖 OS / TUN，纯 in-process，跨平台都能跑。

use core_capture::packet::{
    FrameFormat, IpVersion, L4, encode_tun_ip_frame, parse_ip_packet, parse_tun_frame,
};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
        TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
    },
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
    let mut udp_pkt =
        UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..udp.header_len() + payload.len()]);
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

#[test]
fn parses_linux_tun_pi_prefixed_frame() {
    let ip = build_v4_tcp(33333, 443, TcpControl::Syn);
    let mut frame = vec![0x00, 0x00, 0x08, 0x00];
    frame.extend_from_slice(&ip);

    let parsed = parse_tun_frame(&frame).expect("pi-prefixed tun frame should parse");

    assert_eq!(parsed.format, FrameFormat::LinuxTunPi);
    assert_eq!(parsed.ip_offset, 4);
    assert_eq!(parsed.packet.network(), Some("tcp"));
    assert_eq!(parsed.ip_packet(&frame)[0] >> 4, 4);
}

#[test]
fn parses_ethernet_wrapped_ipv6_frame() {
    let ip = build_v6_udp(12345, 53, b"dns");
    let mut frame = vec![
        0, 1, 2, 3, 4, 5, // dst
        6, 7, 8, 9, 10, 11, // src
        0x86, 0xdd, // IPv6 ethertype
    ];
    frame.extend_from_slice(&ip);

    let parsed = parse_tun_frame(&frame).expect("ethernet-wrapped ipv6 frame should parse");

    assert_eq!(parsed.format, FrameFormat::Ethernet);
    assert_eq!(parsed.ip_offset, 14);
    assert_eq!(parsed.packet.network(), Some("udp"));
    assert_eq!(parsed.ip_packet(&frame)[0] >> 4, 6);
}

#[test]
fn parses_virtio_net_header_prefixed_ipv6_frame() {
    let ip = build_v6_udp(12345, 443, b"virtio-header");
    let mut frame = vec![0; 10];
    frame.extend_from_slice(&ip);

    let parsed = parse_tun_frame(&frame).expect("virtio-net header prefixed frame should parse");

    assert_eq!(parsed.format, FrameFormat::VirtioNetHeader);
    assert_eq!(parsed.ip_offset, 10);
    assert_eq!(parsed.packet.network(), Some("udp"));
    assert_eq!(parsed.ip_packet(&frame)[0] >> 4, 6);
}

#[test]
fn encodes_virtio_net_header_for_tun_write_back() {
    let ip = build_v6_udp(12345, 443, b"virtio-write-back");

    let frame = encode_tun_ip_frame(FrameFormat::VirtioNetHeader, &ip)
        .expect("virtio-net frame should encode");

    assert_eq!(frame.len(), ip.len() + 10);
    assert_eq!(&frame[..10], &[0u8; 10]);
    assert_eq!(&frame[10..], ip.as_slice());

    let parsed = parse_tun_frame(frame.as_ref()).expect("encoded virtio frame should parse");
    assert_eq!(parsed.format, FrameFormat::VirtioNetHeader);
    assert_eq!(parsed.ip_offset, 10);
    assert_eq!(parsed.ip_packet(frame.as_ref()), ip.as_slice());
}

#[test]
fn parses_virtio_net_mrg_rxbuf_header_prefixed_ipv6_frame() {
    let ip = build_v6_udp(12345, 443, b"virtio-mrg-rxbuf");
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&ip);

    let parsed =
        parse_tun_frame(&frame).expect("virtio-net mrg-rxbuf header prefixed frame should parse");

    assert_eq!(parsed.format, FrameFormat::VirtioNetHeaderMrgRxbuf);
    assert_eq!(parsed.ip_offset, 12);
    assert_eq!(parsed.packet.network(), Some("udp"));
    assert_eq!(parsed.ip_packet(&frame)[0] >> 4, 6);
}
