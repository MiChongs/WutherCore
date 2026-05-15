//! TUN UDP 双向转发 —— 把 TUN 看到的 UDP 包通过 outbound socket 发出，
//! 并把 outbound 收到的回包重新封装成 IP/UDP 包写回 TUN。
//!
//! 工作模式：
//! * **Symmetric NAT** —— 默认；每个 (src, dst) 5-tuple 一个独立出站 socket。
//! * **Endpoint-Independent NAT** —— `endpoint_independent_nat: true`；每个
//!   `(src_ip, src_port)` 共享一个出站 socket（[`EimNatTable`]），允许任意外部
//!   源回包，是 STUN-friendly 行为。
//!
//! 重组回包成 IP/UDP 包用 [`smoltcp::wire`]，与 [`crate::packet`] 解析对称。

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet,
        Ipv6Repr, UdpPacket, UdpRepr,
    },
};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{
    eim_nat::{EimKey, EimNatTable},
    tun_io::TunIo,
};

/// UDP forwarder 配置。
pub struct UdpForwarderConfig {
    /// 是否使用 EIM-NAT。
    pub endpoint_independent_nat: bool,
    /// UDP NAT 老化（与 NatTable / EimNatTable 一致）。
    pub udp_timeout: Duration,
}

/// 转发一段 UDP payload：分配/复用 outbound socket，发出。
///
/// 调用者通常是 supervisor 在 dispatch 层；返回 outbound socket 让回包 reader
/// 任务接管。
pub async fn send_one(
    cfg: &UdpForwarderConfig,
    eim: &Arc<EimNatTable>,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> std::io::Result<Arc<UdpSocket>> {
    let outbound = if cfg.endpoint_independent_nat {
        let key = EimKey {
            network: "udp",
            inner_src: src,
        };
        let bind = match dst.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        eim.get_or_insert_with(key, || {
            let std_sock = std::net::UdpSocket::bind(bind)?;
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock).map(Arc::new)
        })?
    } else {
        let bind = match dst.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let std_sock = std::net::UdpSocket::bind(bind)?;
        std_sock.set_nonblocking(true)?;
        Arc::new(UdpSocket::from_std(std_sock)?)
    };
    outbound.send_to(payload, dst).await?;
    let _ = cfg; // udp_timeout 由 EimNatTable / NatTable 自身 ttl 控制
    Ok(outbound)
}

/// 让 reader 任务长期持有：循环 recv_from outbound，并把回包封装成 IP/UDP
/// 写回 TUN。
///
/// `inner_src` 是 TUN 内的"客户端"地址（要把回包送达的目的端口/IP）；
/// `original_dst` 是该 UDP 流原始目标（写回时作为 IP 包的源地址，让客户端识别）。
pub async fn run_return_loop(
    outbound: Arc<UdpSocket>,
    tun: Arc<dyn TunIo>,
    inner_src: SocketAddr,
    original_dst: SocketAddr,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            r = outbound.recv_from(&mut buf) => {
                let (n, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(target: "capture::udp", error = %e, "outbound recv error; exit");
                        break;
                    }
                };
                let payload = &buf[..n];
                // 用 peer 作为 IP 源（让客户端看到"对端响应来自 peer"）
                let pkt = match build_udp_ip_packet(peer, inner_src, payload) {
                    Some(b) => b,
                    None => {
                        warn!(target: "capture::udp", "build packet failed");
                        continue;
                    }
                };
                if let Err(e) = tun.write_packet(&pkt).await {
                    warn!(target: "capture::udp", error = %e, "tun write failed");
                    break;
                }
                let _ = original_dst; // 仅用于日志/标识
            }
        }
    }
}

/// 把 (src, dst, payload) 编成完整 IP+UDP 包字节 —— 公开给 dns_hijack 等同源模块复用。
pub fn build_udp_ip_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Some(build_v4(s, src.port(), d, dst.port(), payload)),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_v6(s, src.port(), d, dst.port(), payload)),
        _ => None,
    }
}

fn build_v4(
    src: std::net::Ipv4Addr,
    src_port: u16,
    dst: std::net::Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let src_addr = Ipv4Address(src.octets());
    let dst_addr = Ipv4Address(dst.octets());
    let udp_repr = UdpRepr { src_port, dst_port };
    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + 8 + payload.len()];
    {
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..8 + payload.len()]);
        udp_repr.emit(
            &mut udp_pkt,
            &IpAddress::Ipv4(src_addr),
            &IpAddress::Ipv4(dst_addr),
            payload.len(),
            |p| p.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
    }
    buf
}

fn build_v6(
    src: std::net::Ipv6Addr,
    src_port: u16,
    dst: std::net::Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let src_addr = Ipv6Address(src.octets());
    let dst_addr = Ipv6Address(dst.octets());
    let udp_repr = UdpRepr { src_port, dst_port };
    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + 8 + payload.len()];
    {
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt);
        let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..8 + payload.len()]);
        udp_repr.emit(
            &mut udp_pkt,
            &IpAddress::Ipv6(src_addr),
            &IpAddress::Ipv6(dst_addr),
            payload.len(),
            |p| p.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IpVersion, L4, parse_ip_packet};

    #[test]
    fn build_and_parse_v4_udp_roundtrip() {
        let buf = build_v4(
            "1.2.3.4".parse().unwrap(),
            53,
            "10.0.0.1".parse().unwrap(),
            53000,
            b"answer",
        );
        let p = parse_ip_packet(&buf).unwrap();
        assert_eq!(p.ip.version, IpVersion::V4);
        let dst = p.dst_socket().unwrap();
        assert_eq!(dst.port(), 53000);
        match p.l4 {
            L4::Udp(u) => assert_eq!(u.payload_len, b"answer".len()),
            _ => panic!("expected udp"),
        }
        let payload =
            &buf[p.l4_payload_offset(&p.l4)..p.l4_payload_offset(&p.l4) + p.l4_payload_len(&p.l4)];
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn build_v6_udp_roundtrip() {
        let buf = build_v6(
            "fd00::1".parse().unwrap(),
            5353,
            "fc00::abcd".parse().unwrap(),
            5354,
            b"hi6",
        );
        let p = parse_ip_packet(&buf).unwrap();
        assert_eq!(p.ip.version, IpVersion::V6);
        match p.l4 {
            L4::Udp(u) => {
                assert_eq!(u.dst_port, 5354);
                assert_eq!(u.payload_len, 3);
            }
            _ => panic!("expected udp"),
        }
    }
}
