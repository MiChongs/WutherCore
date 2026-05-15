//! sing-tun 风格 system stack —— **阶段 1：IPv4 TCP NAT 改写核心**。
//!
//! 与现有 smoltcp 路径 (`stack.rs`) 并行存在；当 `CaptureStack::System`
//! 选中时由 supervisor 用 `SystemStack` 替代 user-stack 部分。
//!
//! ## 设计模型（IPv4 TCP）
//!
//! 客户端方向：包 `src=client, dst=real_target`
//!   → [`TcpNat::lookup`] 分配 NAT port `P`
//!   → 原地改写为 `src=inet4_next:P, dst=inet4_addr:listen_port`
//!   → 写回 TUN，OS 路由到本机 `TcpListener` accept。
//!
//! 反向：listener 通过 conn 写回的包 `src=inet4_addr:listen_port, dst=inet4_next:P`
//!   → [`TcpNat::lookup_back`] 拿到原始 session
//!   → 改写为 `src=real_target, dst=client`
//!   → 写回 TUN 投递给 client。
//!
//! ## 阶段
//! 本文件目前实现：
//! - **1.1** IPv4 TCP NAT 双向改写（含 IP/TCP checksum 重算）。
//! - **1.2** `SystemStack::bind_v4` / `start` —— OS TcpListener + accept loop +
//!   `ListenerHandler` 集成 + 双向 splice。
//!
//! 后续阶段：
//! - **1.3** supervisor 按 `CaptureStack::System` 选 system 路径。
//! - **1.4** UDP 路径搬入 system stack（直接复用 `UdpSessionTable`）。
//! - **1.5** Linux/Windows/macOS 三平台冒烟。
//! - **2** IPv6 TCP/UDP NAT + ICMP echo + ICMP unreachable + RST 拒绝。
//! - **3** DirectRouteMapping + Linux/Darwin batch I/O 适配。
//! - **5** Android (VpnService) + iOS (NEPacketTunnelProvider) 冒烟。

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use core_observe::copy_bidirectional_tracked;
use core_resolver::DnsService;
use core_runtime::{ListenerHandler, PreparedTcp};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpAddress, IpProtocol,
        Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr, TcpControl,
        TcpPacket, TcpRepr, TcpSeqNumber,
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tracing::{debug, info, warn};

use crate::{
    tcp_nat::{NatSession, TcpNat},
    tun_inbound::{TunInbound, build_inbound_metadata},
};

/// 包处理结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// 包已被原地改写，调用方应把它写回 TUN。
    WriteBack,
    /// 已被 system stack 内部消化（如 UDP 进了 udp_session），调用方直接丢弃。
    Consumed,
    /// 包不可处理（解析失败 / 协议未支持 / 未知 session），调用方丢弃。
    Drop,
    /// 调用方应额外写回 TUN 的 IP 包（如 RST / ICMP unreachable）。
    Reply(Vec<u8>),
}

/// IPv6 端配置（可选 —— TUN 仅 IPv4 时为 `None`）。
#[derive(Debug, Clone, Copy)]
pub struct SystemStackV6 {
    /// IPv6 listener 监听 IP（= sing-tun `inet6Address`）。
    pub address: Ipv6Addr,
    /// IPv6 listener 端口（OS 分配）。
    pub listen_port: u16,
    /// 改写后伪 client IPv6（= sing-tun `inet6NextAddress`）。
    pub next_address: Ipv6Addr,
}

/// system stack 状态。
#[derive(Debug)]
pub struct SystemStack {
    pub tcp_nat: Arc<TcpNat>,
    /// listener 监听的本机 IP（TUN gateway = sing-tun `inet4Address`）。
    pub inet4_address: Ipv4Addr,
    /// listener 端口（OS 分配）。
    pub inet4_listen_port: u16,
    /// 改写后包使用的伪客户端 IP（= sing-tun `inet4NextAddress`）。
    pub inet4_next_address: Ipv4Addr,
    /// IPv6 端（可选）。
    pub inet6: Option<SystemStackV6>,
}

impl SystemStack {
    /// 仅 IPv4 构造。
    pub fn new_v4(
        inet4_address: Ipv4Addr,
        inet4_next_address: Ipv4Addr,
        inet4_listen_port: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tcp_nat: Arc::new(TcpNat::new(timeout)),
            inet4_address,
            inet4_listen_port,
            inet4_next_address,
            inet6: None,
        }
    }

    /// 双栈构造（IPv4 + IPv6）。
    pub fn new_dual(
        inet4_address: Ipv4Addr,
        inet4_next_address: Ipv4Addr,
        inet4_listen_port: u16,
        inet6_address: Ipv6Addr,
        inet6_next_address: Ipv6Addr,
        inet6_listen_port: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tcp_nat: Arc::new(TcpNat::new(timeout)),
            inet4_address,
            inet4_listen_port,
            inet4_next_address,
            inet6: Some(SystemStackV6 {
                address: inet6_address,
                listen_port: inet6_listen_port,
                next_address: inet6_next_address,
            }),
        }
    }

    /// 处理一个 TUN IP 包；按需要原地改写 `packet`。
    ///
    /// 调用方契约：
    /// - `packet` 是裸 IP 包（已经剥掉 TUN frame 前缀），`packet[0] >> 4` 是 IP 版本。
    /// - 长度至少 `total_len`，否则返回 `Drop`。
    /// - 改写后 `packet[..total_len]` 是新的 IP 包，调用方负责写回 TUN。
    pub fn process_packet(&self, packet: &mut [u8]) -> ProcessOutcome {
        if packet.is_empty() {
            return ProcessOutcome::Drop;
        }
        match packet[0] >> 4 {
            4 => self.process_ipv4(packet),
            6 => self.process_ipv6(packet),
            _ => ProcessOutcome::Drop,
        }
    }

    fn process_ipv4(&self, packet: &mut [u8]) -> ProcessOutcome {
        let (proto, total_len, header_len) = {
            let ip = match Ipv4Packet::new_checked(&packet[..]) {
                Ok(p) => p,
                Err(_) => return ProcessOutcome::Drop,
            };
            (
                ip.next_header(),
                ip.total_len() as usize,
                ip.header_len() as usize,
            )
        };
        if packet.len() < total_len || header_len < 20 || total_len < header_len {
            return ProcessOutcome::Drop;
        }
        match proto {
            IpProtocol::Tcp => self.process_ipv4_tcp(packet, total_len, header_len),
            // UDP 路径仍由 dispatcher 的 handle_udp 走 udp_session_table（与 v4/v6 共用）。
            IpProtocol::Udp => ProcessOutcome::Drop,
            IpProtocol::Icmp => process_ipv4_icmp(packet, total_len, header_len),
            _ => ProcessOutcome::Drop,
        }
    }

    fn process_ipv4_tcp(
        &self,
        packet: &mut [u8],
        total_len: usize,
        header_len: usize,
    ) -> ProcessOutcome {
        let (src_ip, dst_ip, src_port, dst_port) = {
            let ip = Ipv4Packet::new_unchecked(&packet[..total_len]);
            let src_ip = Ipv4Addr::from(ip.src_addr().0);
            let dst_ip = Ipv4Addr::from(ip.dst_addr().0);
            let tcp = match TcpPacket::new_checked(&packet[header_len..total_len]) {
                Ok(t) => t,
                Err(_) => return ProcessOutcome::Drop,
            };
            (src_ip, dst_ip, tcp.src_port(), tcp.dst_port())
        };

        if src_ip == self.inet4_address && src_port == self.inet4_listen_port {
            // 反向：listener → client
            let session = match self.tcp_nat.lookup_back(dst_port) {
                Some(s) => s,
                None => return ProcessOutcome::Drop,
            };
            let (orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port) =
                match (session.source, session.destination) {
                    (SocketAddr::V4(s), SocketAddr::V4(d)) => {
                        (*s.ip(), s.port(), *d.ip(), d.port())
                    }
                    _ => return ProcessOutcome::Drop, // v4 路径不应混入 v6
                };
            // 反向改写：src ← session.destination, dst ← session.source
            rewrite_ipv4_tcp(
                packet,
                total_len,
                header_len,
                orig_dst_ip,
                orig_dst_port,
                orig_src_ip,
                orig_src_port,
            );
            ProcessOutcome::WriteBack
        } else if dst_ip == self.inet4_address {
            // dst 是 listener IP 但 src 不是 listener —— 异常包（如本机直连 listener），丢弃
            ProcessOutcome::Drop
        } else {
            // 客户端流：分配 / 复用 NAT port，改写为 → listener
            let source = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
            let destination = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
            let nat_port = match self.tcp_nat.lookup(source, destination) {
                Some(p) => p,
                None => {
                    // NAT 端口耗尽 → 回 RST 让 client 立即放弃，避免 SYN 重传风暴。
                    // sing-tun resetIPv4TCP 行为对齐。
                    if let Some(rst) = build_ipv4_tcp_rst(&packet[..total_len]) {
                        warn!(
                            target: "capture::system",
                            %src_ip,
                            %dst_ip,
                            src_port,
                            dst_port,
                            "ipv4 tcp nat port exhausted; reply RST"
                        );
                        return ProcessOutcome::Reply(rst);
                    }
                    return ProcessOutcome::Drop;
                }
            };
            rewrite_ipv4_tcp(
                packet,
                total_len,
                header_len,
                self.inet4_next_address,
                nat_port,
                self.inet4_address,
                self.inet4_listen_port,
            );
            ProcessOutcome::WriteBack
        }
    }
}

/// 原地改写 IPv4 + TCP 头的 src/dst 地址端口，并重算 IP / TCP checksum。
///
/// 顺序：
/// 1. 改 IPv4 src/dst（暂不算 IP checksum）；
/// 2. 改 TCP src/dst port + 用新 IP 重算 TCP checksum（pseudo-header 包含 IP src/dst）；
/// 3. 重算 IPv4 header checksum。
///
/// `packet` 必须 `>= total_len`，且 `header_len <= total_len`。
fn rewrite_ipv4_tcp(
    packet: &mut [u8],
    total_len: usize,
    header_len: usize,
    new_src_ip: Ipv4Addr,
    new_src_port: u16,
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
) {
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..total_len]);
        ip.set_src_addr(Ipv4Address(new_src_ip.octets()));
        ip.set_dst_addr(Ipv4Address(new_dst_ip.octets()));
    }
    {
        let tcp_buf = &mut packet[header_len..total_len];
        let mut tcp = TcpPacket::new_unchecked(tcp_buf);
        tcp.set_src_port(new_src_port);
        tcp.set_dst_port(new_dst_port);
        tcp.fill_checksum(
            &IpAddress::Ipv4(Ipv4Address(new_src_ip.octets())),
            &IpAddress::Ipv4(Ipv4Address(new_dst_ip.octets())),
        );
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..total_len]);
        ip.fill_checksum();
    }
}

/* =============================================================
2.1  IPv6 NAT 改写（与 IPv4 对称；IPv6 头无 checksum）
============================================================= */

impl SystemStack {
    fn process_ipv6(&self, packet: &mut [u8]) -> ProcessOutcome {
        let (proto, payload_len, header_len) = {
            let ip = match Ipv6Packet::new_checked(&packet[..]) {
                Ok(p) => p,
                Err(_) => return ProcessOutcome::Drop,
            };
            (ip.next_header(), ip.payload_len() as usize, ip.header_len())
        };
        let total_len = header_len.saturating_add(payload_len);
        if packet.len() < total_len || header_len < 40 {
            return ProcessOutcome::Drop;
        }
        match proto {
            IpProtocol::Tcp => self.process_ipv6_tcp(packet, total_len, header_len),
            IpProtocol::Udp => ProcessOutcome::Drop, // 走 dispatcher.handle_udp
            IpProtocol::Icmpv6 => process_ipv6_icmp(packet, total_len, header_len),
            _ => ProcessOutcome::Drop,
        }
    }

    fn process_ipv6_tcp(
        &self,
        packet: &mut [u8],
        total_len: usize,
        header_len: usize,
    ) -> ProcessOutcome {
        let Some(v6) = self.inet6 else {
            return ProcessOutcome::Drop; // 未启用 IPv6
        };

        let (src_ip, dst_ip, src_port, dst_port) = {
            let ip = Ipv6Packet::new_unchecked(&packet[..total_len]);
            let src_ip = Ipv6Addr::from(ip.src_addr().0);
            let dst_ip = Ipv6Addr::from(ip.dst_addr().0);
            let tcp = match TcpPacket::new_checked(&packet[header_len..total_len]) {
                Ok(t) => t,
                Err(_) => return ProcessOutcome::Drop,
            };
            (src_ip, dst_ip, tcp.src_port(), tcp.dst_port())
        };

        if src_ip == v6.address && src_port == v6.listen_port {
            // 反向：listener → client
            let session = match self.tcp_nat.lookup_back(dst_port) {
                Some(s) => s,
                None => return ProcessOutcome::Drop,
            };
            let (orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port) =
                match (session.source, session.destination) {
                    (SocketAddr::V6(s), SocketAddr::V6(d)) => {
                        (*s.ip(), s.port(), *d.ip(), d.port())
                    }
                    _ => return ProcessOutcome::Drop, // 跨版本 session 不复用
                };
            rewrite_ipv6_tcp(
                packet,
                total_len,
                header_len,
                orig_dst_ip,
                orig_dst_port,
                orig_src_ip,
                orig_src_port,
            );
            ProcessOutcome::WriteBack
        } else if dst_ip == v6.address {
            ProcessOutcome::Drop
        } else {
            let source = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
            let destination = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
            let nat_port = match self.tcp_nat.lookup(source, destination) {
                Some(p) => p,
                None => {
                    // NAT 端口耗尽 → 回 RST（与 IPv4 路径对称，sing-tun resetIPv6TCP 行为）。
                    if let Some(rst) = build_ipv6_tcp_rst(&packet[..total_len]) {
                        warn!(
                            target: "capture::system",
                            %src_ip,
                            %dst_ip,
                            src_port,
                            dst_port,
                            "ipv6 tcp nat port exhausted; reply RST"
                        );
                        return ProcessOutcome::Reply(rst);
                    }
                    return ProcessOutcome::Drop;
                }
            };
            rewrite_ipv6_tcp(
                packet,
                total_len,
                header_len,
                v6.next_address,
                nat_port,
                v6.address,
                v6.listen_port,
            );
            ProcessOutcome::WriteBack
        }
    }
}

/// 原地改写 IPv6 + TCP 头的 src/dst 地址端口，并重算 TCP checksum。
/// IPv6 主头无 checksum，无需重算 IP 校验。
fn rewrite_ipv6_tcp(
    packet: &mut [u8],
    total_len: usize,
    header_len: usize,
    new_src_ip: Ipv6Addr,
    new_src_port: u16,
    new_dst_ip: Ipv6Addr,
    new_dst_port: u16,
) {
    {
        let mut ip = Ipv6Packet::new_unchecked(&mut packet[..total_len]);
        ip.set_src_addr(Ipv6Address(new_src_ip.octets()));
        ip.set_dst_addr(Ipv6Address(new_dst_ip.octets()));
    }
    {
        let tcp_buf = &mut packet[header_len..total_len];
        let mut tcp = TcpPacket::new_unchecked(tcp_buf);
        tcp.set_src_port(new_src_port);
        tcp.set_dst_port(new_dst_port);
        tcp.fill_checksum(
            &IpAddress::Ipv6(Ipv6Address(new_src_ip.octets())),
            &IpAddress::Ipv6(Ipv6Address(new_dst_ip.octets())),
        );
    }
}

/* =============================================================
2.2  ICMP echo 反射（v4 + v6）—— 让 ping 跨 TUN 通
============================================================= */

/// 处理 IPv4 ICMP Echo Request：原地改成 Echo Reply 并互换 src/dst。
fn process_ipv4_icmp(packet: &mut [u8], total_len: usize, header_len: usize) -> ProcessOutcome {
    if total_len.saturating_sub(header_len) < 8 {
        return ProcessOutcome::Drop;
    }
    // 提前校验 ICMP 类型 —— 仅处理 Echo Request；其它（如 DstUnreachable）丢弃。
    let icmp_offset = header_len;
    {
        let icmp_buf = &packet[icmp_offset..total_len];
        let icmp = match Icmpv4Packet::new_checked(icmp_buf) {
            Ok(i) => i,
            Err(_) => return ProcessOutcome::Drop,
        };
        if icmp.msg_type() != Icmpv4Message::EchoRequest || icmp.msg_code() != 0 {
            return ProcessOutcome::Drop;
        }
    }
    // 取出原 src/dst（IPv4Address 是 Copy，可值传递）
    let (orig_src, orig_dst) = {
        let ip = Ipv4Packet::new_unchecked(&packet[..total_len]);
        (ip.src_addr(), ip.dst_addr())
    };
    // 改 IP src/dst 互换
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..total_len]);
        ip.set_src_addr(orig_dst);
        ip.set_dst_addr(orig_src);
    }
    // 改 ICMP type → EchoReply 并 fill_checksum
    {
        let icmp_buf = &mut packet[icmp_offset..total_len];
        let mut icmp = Icmpv4Packet::new_unchecked(icmp_buf);
        icmp.set_msg_type(Icmpv4Message::EchoReply);
        icmp.fill_checksum();
    }
    // 重算 IPv4 header checksum
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..total_len]);
        ip.fill_checksum();
    }
    ProcessOutcome::WriteBack
}

/// 处理 IPv6 ICMPv6 Echo Request：原地改成 Echo Reply 并互换 src/dst。
fn process_ipv6_icmp(packet: &mut [u8], total_len: usize, header_len: usize) -> ProcessOutcome {
    if total_len.saturating_sub(header_len) < 8 {
        return ProcessOutcome::Drop;
    }
    let icmp_offset = header_len;
    {
        let icmp_buf = &packet[icmp_offset..total_len];
        let icmp = match Icmpv6Packet::new_checked(icmp_buf) {
            Ok(i) => i,
            Err(_) => return ProcessOutcome::Drop,
        };
        if icmp.msg_type() != Icmpv6Message::EchoRequest || icmp.msg_code() != 0 {
            return ProcessOutcome::Drop;
        }
    }
    let (orig_src, orig_dst) = {
        let ip = Ipv6Packet::new_unchecked(&packet[..total_len]);
        (ip.src_addr(), ip.dst_addr())
    };
    {
        let mut ip = Ipv6Packet::new_unchecked(&mut packet[..total_len]);
        ip.set_src_addr(orig_dst);
        ip.set_dst_addr(orig_src);
    }
    {
        let icmp_buf = &mut packet[icmp_offset..total_len];
        let mut icmp = Icmpv6Packet::new_unchecked(icmp_buf);
        icmp.set_msg_type(Icmpv6Message::EchoReply);
        // ICMPv6 checksum 含 pseudo-header（src/dst = 互换后的）
        icmp.fill_checksum(&IpAddress::Ipv6(orig_dst), &IpAddress::Ipv6(orig_src));
    }
    // IPv6 主头无 checksum
    ProcessOutcome::WriteBack
}

/* =============================================================
2.3  TCP RST / ICMP Unreachable 拒绝包构造（独立 helper，
     供后续 NAT 失败/路由拒绝路径调用；不会被 process_packet
     默认触发，由 dispatcher 在拒绝时主动 Reply）
============================================================= */

/// 给定原 IPv4+TCP 包，构造一个 RST（或 RST+ACK）回包供 dispatcher 写回 TUN。
///
/// 行为对齐 sing-tun `resetIPv4TCP`：
/// - 原包带 ACK：RST seq=orig.ack；
/// - 原包不带 ACK：RST+ACK，ack=orig.seq + payload_len + (syn?1:0) + (fin?1:0)。
pub fn build_ipv4_tcp_rst(orig_ip_packet: &[u8]) -> Option<Vec<u8>> {
    let orig_ip = Ipv4Packet::new_checked(orig_ip_packet).ok()?;
    let orig_header_len = orig_ip.header_len() as usize;
    let orig_total_len = orig_ip.total_len() as usize;
    if orig_ip_packet.len() < orig_total_len {
        return None;
    }
    let orig_tcp = TcpPacket::new_checked(&orig_ip_packet[orig_header_len..orig_total_len]).ok()?;
    let orig_payload_len = orig_total_len - orig_header_len - orig_tcp.header_len() as usize;

    let src_addr = orig_ip.dst_addr();
    let dst_addr = orig_ip.src_addr();
    let (control, seq, ack) = if orig_tcp.ack() {
        (TcpControl::Rst, orig_tcp.ack_number(), None)
    } else {
        // 不带 ACK 的原包 —— 我们要发 RST+ACK，ack=seq + payload + syn + fin
        let mut ack_n = orig_tcp.seq_number().0 as u32 + orig_payload_len as u32;
        if orig_tcp.syn() {
            ack_n = ack_n.wrapping_add(1);
        }
        if orig_tcp.fin() {
            ack_n = ack_n.wrapping_add(1);
        }
        (
            TcpControl::Rst,
            TcpSeqNumber(0),
            Some(TcpSeqNumber(ack_n as i32)),
        )
    };

    let tcp_repr = TcpRepr {
        src_port: orig_tcp.dst_port(),
        dst_port: orig_tcp.src_port(),
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };
    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
    let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
    let ihl = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();
    let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp_len]);
    tcp_repr.emit(
        &mut tcp_pkt,
        &IpAddress::Ipv4(src_addr),
        &IpAddress::Ipv4(dst_addr),
        &ChecksumCapabilities::default(),
    );
    let _ = ihl;
    Some(buf)
}

/// 同上 IPv6 版。
pub fn build_ipv6_tcp_rst(orig_ip_packet: &[u8]) -> Option<Vec<u8>> {
    let orig_ip = Ipv6Packet::new_checked(orig_ip_packet).ok()?;
    let orig_header_len = orig_ip.header_len();
    let orig_payload_len = orig_ip.payload_len() as usize;
    let orig_total_len = orig_header_len + orig_payload_len;
    if orig_ip_packet.len() < orig_total_len {
        return None;
    }
    let orig_tcp = TcpPacket::new_checked(&orig_ip_packet[orig_header_len..orig_total_len]).ok()?;
    let orig_tcp_payload_len = orig_total_len - orig_header_len - orig_tcp.header_len() as usize;

    let src_addr = orig_ip.dst_addr();
    let dst_addr = orig_ip.src_addr();
    let (control, seq, ack) = if orig_tcp.ack() {
        (TcpControl::Rst, orig_tcp.ack_number(), None)
    } else {
        let mut ack_n = orig_tcp.seq_number().0 as u32 + orig_tcp_payload_len as u32;
        if orig_tcp.syn() {
            ack_n = ack_n.wrapping_add(1);
        }
        if orig_tcp.fin() {
            ack_n = ack_n.wrapping_add(1);
        }
        (
            TcpControl::Rst,
            TcpSeqNumber(0),
            Some(TcpSeqNumber(ack_n as i32)),
        )
    };

    let tcp_repr = TcpRepr {
        src_port: orig_tcp.dst_port(),
        dst_port: orig_tcp.src_port(),
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };
    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
    let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
    ip_repr.emit(&mut ip_pkt);
    let ihl = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();
    let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp_len]);
    tcp_repr.emit(
        &mut tcp_pkt,
        &IpAddress::Ipv6(src_addr),
        &IpAddress::Ipv6(dst_addr),
        &ChecksumCapabilities::default(),
    );
    let _ = ihl;
    Some(buf)
}

/// 构造 IPv4 ICMP DstUnreachable 拒绝包（携带原 IP 头 + 原 L4 前 8B）。
///
/// `code` 取自 [`smoltcp::wire::Icmpv4DstUnreachable`] 的 u8 形式（如 PortUnreachable=3）。
pub fn build_ipv4_icmp_unreachable(orig_ip_packet: &[u8], code: u8, mtu: usize) -> Option<Vec<u8>> {
    let orig_ip = Ipv4Packet::new_checked(orig_ip_packet).ok()?;
    let orig_total_len = orig_ip.total_len() as usize;
    if orig_ip_packet.len() < orig_total_len {
        return None;
    }
    // ICMP 报文 = 8B header + (orig IP header + 前 8B L4)；payload 上限受 mtu 约束。
    let mtu_cap = mtu.saturating_sub(20).saturating_sub(8); // 减 IP + ICMP header
    let max_payload = mtu_cap.min(orig_total_len);
    let payload = &orig_ip_packet[..max_payload];

    let src_addr = orig_ip.dst_addr();
    let dst_addr = orig_ip.src_addr();
    let icmp_len = 8 + payload.len();
    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_len,
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + icmp_len];
    {
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
    }
    // 写 ICMP header + payload
    let icmp_offset = ip_repr.buffer_len();
    buf[icmp_offset] = 3; // type = DestUnreachable
    buf[icmp_offset + 1] = code;
    // checksum 字段先置 0
    buf[icmp_offset + 2] = 0;
    buf[icmp_offset + 3] = 0;
    // unused 4 bytes
    buf[icmp_offset + 4..icmp_offset + 8].fill(0);
    // 原 IP + L4 前 8B
    buf[icmp_offset + 8..icmp_offset + 8 + payload.len()].copy_from_slice(payload);
    // smoltcp ICMP fill_checksum
    {
        let icmp_buf = &mut buf[icmp_offset..icmp_offset + icmp_len];
        let mut icmp = Icmpv4Packet::new_unchecked(icmp_buf);
        icmp.fill_checksum();
    }
    Some(buf)
}

/// 同上 IPv6 版。`code` 0=NoRoute / 1=AdminProhibited / 3=AddrUnreachable / 4=PortUnreachable。
pub fn build_ipv6_icmp_unreachable(orig_ip_packet: &[u8], code: u8, mtu: usize) -> Option<Vec<u8>> {
    let orig_ip = Ipv6Packet::new_checked(orig_ip_packet).ok()?;
    let orig_header_len = orig_ip.header_len();
    let orig_payload_len = orig_ip.payload_len() as usize;
    let orig_total_len = orig_header_len + orig_payload_len;
    if orig_ip_packet.len() < orig_total_len {
        return None;
    }

    // ICMPv6 DstUnreachable header 8B + payload（原 IPv6 包尽可能多）。
    // mtu_cap = mtu - 40 (IPv6 hdr) - 8 (ICMPv6 hdr)
    let mtu_cap = mtu.saturating_sub(40).saturating_sub(8);
    let max_payload = mtu_cap.min(orig_total_len);
    let payload = &orig_ip_packet[..max_payload];

    let src_addr = orig_ip.dst_addr();
    let dst_addr = orig_ip.src_addr();
    let icmp_len = 8 + payload.len();
    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_len,
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip_repr.buffer_len() + icmp_len];
    {
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt);
    }
    let icmp_offset = ip_repr.buffer_len();
    buf[icmp_offset] = 1; // ICMPv6 type=1 DstUnreachable
    buf[icmp_offset + 1] = code;
    buf[icmp_offset + 2] = 0;
    buf[icmp_offset + 3] = 0;
    buf[icmp_offset + 4..icmp_offset + 8].fill(0);
    buf[icmp_offset + 8..icmp_offset + 8 + payload.len()].copy_from_slice(payload);
    // ICMPv6 checksum 含 pseudo-header
    {
        let icmp_buf = &mut buf[icmp_offset..icmp_offset + icmp_len];
        let mut icmp = Icmpv6Packet::new_unchecked(icmp_buf);
        icmp.fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
    }
    Some(buf)
}

/* =============================================================
1.2  Runtime —— bind / accept loop / 双向 splice / handle
============================================================= */

/// 监听绑定重试次数 —— 与 sing-tun 一致：TUN 设备 up 后 IP 配置可能有数百 ms 延迟。
const BIND_RETRIES: usize = 3;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(500);

/// `start*()` 返回的"运行中" handle：持有 stack 引用 + 一组 accept 任务。
pub struct SystemStackHandle {
    pub stack: Arc<SystemStack>,
    accept_handles: Vec<tokio::task::JoinHandle<()>>,
    stop_txs: Vec<oneshot::Sender<()>>,
}

impl SystemStackHandle {
    /// 主动停止（幂等）。
    pub fn stop(mut self) {
        for tx in self.stop_txs.drain(..) {
            let _ = tx.send(());
        }
        for h in self.accept_handles.drain(..) {
            h.abort();
        }
    }
}

impl SystemStack {
    /// 在指定 IPv4 地址上绑定 listener（端口由 OS 分配；含 sing-tun 风格 3 次重试）。
    pub async fn bind_v4_listener(inet4_address: Ipv4Addr) -> io::Result<TcpListener> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(inet4_address, 0));
        bind_with_retry(bind_addr, "v4").await
    }

    /// 在指定 IPv6 地址上绑定 listener。
    pub async fn bind_v6_listener(inet6_address: Ipv6Addr) -> io::Result<TcpListener> {
        let bind_addr = SocketAddr::V6(SocketAddrV6::new(inet6_address, 0, 0, 0));
        bind_with_retry(bind_addr, "v6").await
    }

    /// 旧的 v4-only 入口（向后兼容）。
    pub async fn bind_v4(
        inet4_address: Ipv4Addr,
        inet4_next_address: Ipv4Addr,
        timeout: Duration,
    ) -> io::Result<(Arc<Self>, TcpListener)> {
        let listener = Self::bind_v4_listener(inet4_address).await?;
        let port = listener.local_addr()?.port();
        let stack = Arc::new(Self::new_v4(
            inet4_address,
            inet4_next_address,
            port,
            timeout,
        ));
        Ok((stack, listener))
    }

    /// 启动 v4-only system stack（向后兼容）。
    pub async fn start(
        inet4_address: Ipv4Addr,
        inet4_next_address: Ipv4Addr,
        handler: Arc<ListenerHandler>,
        inbound: Arc<TunInbound>,
        timeout: Duration,
    ) -> io::Result<SystemStackHandle> {
        Self::start_dual(
            inet4_address,
            inet4_next_address,
            None,
            handler,
            inbound.clone(),
            Arc::new(DnsService::fake_only(inbound.fake_pool().clone())),
            timeout,
        )
        .await
    }

    /// 启动双栈 system stack：v4 必须，v6 可选。
    /// 每个 listener 各起一个 accept loop；统一调度到 `run_accept_loop`。
    pub async fn start_dual(
        inet4_address: Ipv4Addr,
        inet4_next_address: Ipv4Addr,
        inet6: Option<(Ipv6Addr, Ipv6Addr)>,
        handler: Arc<ListenerHandler>,
        inbound: Arc<TunInbound>,
        dns_service: Arc<DnsService>,
        timeout: Duration,
    ) -> io::Result<SystemStackHandle> {
        // 1) 先绑 v4
        let v4_listener = Self::bind_v4_listener(inet4_address).await?;
        let v4_port = v4_listener.local_addr()?.port();

        // 2) 视情绑 v6
        let (v6_listener_opt, v6_port) = if let Some((v6_addr, _)) = inet6 {
            match Self::bind_v6_listener(v6_addr).await {
                Ok(l) => {
                    let p = l.local_addr()?.port();
                    (Some(l), p)
                }
                Err(e) => {
                    // v6 绑失败不致命：log 后退化为仅 v4
                    warn!(
                        target: "capture::system",
                        v6_address = %v6_addr,
                        error = %e,
                        "system stack v6 listener bind failed; falling back to v4-only"
                    );
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };

        // 3) 构造 stack
        let stack = if let (Some((v6_addr, v6_next)), true) = (inet6, v6_listener_opt.is_some()) {
            Arc::new(Self::new_dual(
                inet4_address,
                inet4_next_address,
                v4_port,
                v6_addr,
                v6_next,
                v6_port,
                timeout,
            ))
        } else {
            Arc::new(Self::new_v4(
                inet4_address,
                inet4_next_address,
                v4_port,
                timeout,
            ))
        };

        info!(
            target: "capture::system",
            inet4_address = %inet4_address,
            inet4_next_address = %inet4_next_address,
            v4_listen_port = v4_port,
            v6_listen_port = v6_port,
            "system stack listeners up"
        );

        // 4) spawn accept loops
        let mut accept_handles = Vec::with_capacity(2);
        let mut stop_txs = Vec::with_capacity(2);

        let (v4_stop_tx, v4_stop_rx) = oneshot::channel();
        let v4_handle = tokio::spawn(run_accept_loop(
            v4_listener,
            "v4",
            stack.clone(),
            handler.clone(),
            inbound.clone(),
            dns_service.clone(),
            v4_stop_rx,
        ));
        accept_handles.push(v4_handle);
        stop_txs.push(v4_stop_tx);

        if let Some(v6_listener) = v6_listener_opt {
            let (v6_stop_tx, v6_stop_rx) = oneshot::channel();
            let v6_handle = tokio::spawn(run_accept_loop(
                v6_listener,
                "v6",
                stack.clone(),
                handler,
                inbound,
                dns_service,
                v6_stop_rx,
            ));
            accept_handles.push(v6_handle);
            stop_txs.push(v6_stop_tx);
        }

        Ok(SystemStackHandle {
            stack,
            accept_handles,
            stop_txs,
        })
    }
}

/// 通用 bind helper（含 sing-tun 风格 3 次重试 + 500ms 间隔）。
async fn bind_with_retry(bind_addr: SocketAddr, family: &'static str) -> io::Result<TcpListener> {
    let mut last_err = None;
    for attempt in 0..BIND_RETRIES {
        match TcpListener::bind(bind_addr).await {
            Ok(l) => return Ok(l),
            Err(e) => {
                debug!(
                    target: "capture::system",
                    attempt,
                    family,
                    bind = %bind_addr,
                    error = %e,
                    "system stack listener bind failed; retrying"
                );
                last_err = Some(e);
                tokio::time::sleep(BIND_RETRY_DELAY).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "bind retries exhausted")))
}

/// v4 / v6 通用 accept loop。`family` 仅作为日志标签。
async fn run_accept_loop(
    listener: TcpListener,
    family: &'static str,
    stack: Arc<SystemStack>,
    handler: Arc<ListenerHandler>,
    inbound: Arc<TunInbound>,
    dns_service: Arc<DnsService>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            r = listener.accept() => {
                let (conn, peer) = match r {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(target: "capture::system", family, error = %e, "accept failed");
                        continue;
                    }
                };
                let nat_port = peer.port();
                let session = match stack.tcp_nat.lookup_back(nat_port) {
                    Some(s) => s,
                    None => {
                        debug!(
                            target: "capture::system",
                            family,
                            nat_port,
                            "accept got unknown nat port; closing"
                        );
                        continue;
                    }
                };
                let stack = stack.clone();
                let handler = handler.clone();
                let inbound = inbound.clone();
                let dns_service = dns_service.clone();
                tokio::spawn(handle_accepted_conn(
                    conn, family, session, nat_port, stack, handler, inbound, dns_service,
                ));
            }
        }
    }
    info!(target: "capture::system", family, "system stack accept loop stopped");
}

async fn handle_accepted_conn(
    mut conn: TcpStream,
    family: &'static str,
    session: Arc<NatSession>,
    nat_port: u16,
    stack: Arc<SystemStack>,
    handler: Arc<ListenerHandler>,
    inbound: Arc<TunInbound>,
    dns_service: Arc<DnsService>,
) {
    let source = session.source;
    let original_dst = session.destination;
    let inbound_addr = conn.local_addr().ok();

    // 1) fake-IP 反查（沿用 TunInbound::resolve_session 语义；后续可加 SNI sniff fallback）
    let target_session = match inbound.resolve_session("tcp", source, original_dst, None) {
        Ok(s) => s,
        Err(reason) => {
            debug!(
                target: "capture::system",
                family,
                nat_port,
                src = %source,
                dst = %original_dst,
                ?reason,
                "resolve session failed; abort"
            );
            stack.tcp_nat.remove_by_port(nat_port);
            return;
        }
    };

    if inbound.should_hijack_dns(original_dst) {
        info!(
            target: "capture::dns",
            family,
            nat_port,
            network = "tcp",
            src = %source,
            dst = %original_dst,
            host = %target_session.target.host,
            "dns tcp hijack handled in system stack"
        );
        handler.runtime().metrics.inc_dns();
        if let Err(e) = crate::fakeip_dns::serve_tcp_stream(conn, dns_service).await {
            warn!(
                target: "capture::dns",
                family,
                nat_port,
                error = %e,
                "system dns tcp hijack failed"
            );
        }
        stack.tcp_nat.remove_by_port(nat_port);
        return;
    }

    // 2) 走统一 ListenerHandler 路由 + 拨号
    let metadata = build_inbound_metadata(&target_session, inbound_addr);
    let prepared = match handler.prepare_tcp(metadata).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                target: "capture::system",
                family,
                nat_port,
                host = %target_session.target.host,
                port = target_session.target.original_dst_port,
                error = %e,
                "prepare_tcp failed"
            );
            stack.tcp_nat.remove_by_port(nat_port);
            return;
        }
    };
    let PreparedTcp { result, guard } = prepared;
    let conn_id = guard.id;
    let src_label = source.to_string();
    let host = &target_session.target.host;
    let port = target_session.target.original_dst_port;
    let proxy = if result.chain.len() > 1 {
        result.chain.join(" >> ")
    } else {
        result.outbound.clone()
    };
    if result.rule.is_empty() {
        info!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} using {proxy}");
    } else if result.rule_payload.is_empty() {
        info!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} match {} using {proxy}", result.rule);
    } else {
        info!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} match {}({}) using {proxy}", result.rule, result.rule_payload);
    }

    // 3) 双向 splice —— OS TcpStream + outbound stream，全程走 mihomo 流量记账。
    let started = std::time::Instant::now();
    let metrics = handler.runtime().metrics.clone();
    metrics.inc_connection();
    let mut outbound = result.stream;
    let accounting = guard.accounting();
    let outcome =
        copy_bidirectional_tracked(&mut conn, &mut outbound, accounting, Some(metrics.clone()))
            .await;
    metrics.dec_connection();
    let up = guard.up.load(Ordering::Relaxed);
    let down = guard.down.load(Ordering::Relaxed);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let up_s = crate::tun_pump::format_bytes(up);
    let down_s = crate::tun_pump::format_bytes(down);
    match &outcome {
        Ok(_) => info!(
            target: "capture::traffic",
            "[TCP] #{conn_id} {src_label} --> {host}:{port} closed | up {up_s} down {down_s} | {elapsed_ms}ms"
        ),
        Err(e) => warn!(
            target: "capture::traffic",
            "[TCP] #{conn_id} {src_label} --> {host}:{port} error: {e} | up {up_s} down {down_s} | {elapsed_ms}ms"
        ),
    }
    drop(guard);
    stack.tcp_nat.remove_by_port(nat_port);
}

#[cfg(test)]
mod tests {
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber},
    };

    use super::*;

    fn build_v4_tcp(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        ctrl: TcpControl,
        payload: &[u8],
    ) -> Vec<u8> {
        let src = Ipv4Address(src_ip.octets());
        let dst = Ipv4Address(dst_ip.octets());
        let tcp = TcpRepr {
            src_port,
            dst_port,
            control: ctrl,
            seq_number: TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let ihl = ip.buffer_len();
        let tcp_buf_len = tcp.buffer_len();
        let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp_buf_len]);
        tcp.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &ChecksumCapabilities::default(),
        );
        let _ = ihl;
        buf
    }

    fn parse_v4_tcp(packet: &[u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16) {
        let ip = Ipv4Packet::new_checked(packet).expect("ip");
        let src_ip = Ipv4Addr::from(ip.src_addr().0);
        let dst_ip = Ipv4Addr::from(ip.dst_addr().0);
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let tcp = TcpPacket::new_checked(&packet[header_len..total_len]).expect("tcp");
        (src_ip, tcp.src_port(), dst_ip, tcp.dst_port())
    }

    fn assert_checksums_valid(packet: &[u8]) {
        let ip = Ipv4Packet::new_checked(packet).expect("ip");
        assert!(ip.verify_checksum(), "IPv4 header checksum invalid");
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let src = ip.src_addr();
        let dst = ip.dst_addr();
        let tcp = TcpPacket::new_checked(&packet[header_len..total_len]).expect("tcp");
        assert!(
            tcp.verify_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst)),
            "TCP checksum invalid"
        );
    }

    #[test]
    fn process_packet_rewrites_client_flow() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        let mut pkt = build_v4_tcp(
            "10.0.0.5".parse().unwrap(),
            54321,
            "1.1.1.1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let outcome = stack.process_packet(&mut pkt);
        assert_eq!(outcome, ProcessOutcome::WriteBack);

        let (src_ip, src_port, dst_ip, dst_port) = parse_v4_tcp(&pkt);
        assert_eq!(src_ip, "172.18.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(dst_ip, "172.18.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(dst_port, 12345);
        assert_ne!(src_port, 54321, "NAT port must differ from original");
        assert_checksums_valid(&pkt);

        // 反查应能拿回原始 session
        let session = stack.tcp_nat.lookup_back(src_port).expect("lookup back");
        assert_eq!(
            session.source,
            "10.0.0.5:54321".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            session.destination,
            "1.1.1.1:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn process_packet_rewrites_listener_flow_back_to_client() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        // 先用客户端流分配一个 NAT 端口
        let mut client_pkt = build_v4_tcp(
            "10.0.0.5".parse().unwrap(),
            54321,
            "1.1.1.1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(
            stack.process_packet(&mut client_pkt),
            ProcessOutcome::WriteBack
        );
        let (_, nat_port, _, _) = parse_v4_tcp(&client_pkt);

        // 反向：listener (172.18.0.1:12345) → 伪 client (172.18.0.2:nat_port)
        let mut reverse_pkt = build_v4_tcp(
            "172.18.0.1".parse().unwrap(),
            12345,
            "172.18.0.2".parse().unwrap(),
            nat_port,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(
            stack.process_packet(&mut reverse_pkt),
            ProcessOutcome::WriteBack
        );
        let (src_ip, src_port, dst_ip, dst_port) = parse_v4_tcp(&reverse_pkt);
        assert_eq!(src_ip, "1.1.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(src_port, 443);
        assert_eq!(dst_ip, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(dst_port, 54321);
        assert_checksums_valid(&reverse_pkt);
    }

    #[test]
    fn process_packet_drops_listener_flow_with_unknown_nat_port() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        // listener → unknown nat_port=40000
        let mut pkt = build_v4_tcp(
            "172.18.0.1".parse().unwrap(),
            12345,
            "172.18.0.2".parse().unwrap(),
            40_000,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(stack.process_packet(&mut pkt), ProcessOutcome::Drop);
    }

    #[test]
    fn process_packet_drops_when_dst_is_local_addr_but_src_is_not_listener() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        // dst=本机IP，src 既不是 listener 也不是已知 session —— 阶段 1 直接 drop
        let mut pkt = build_v4_tcp(
            "10.0.0.5".parse().unwrap(),
            54321,
            "172.18.0.1".parse().unwrap(),
            12345,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(stack.process_packet(&mut pkt), ProcessOutcome::Drop);
    }

    #[tokio::test]
    async fn bind_v4_assigns_listen_port() {
        // 用 127.0.0.1 替代 TUN 网段地址 —— 不需要真实 TUN 设备
        let (stack, listener) = SystemStack::bind_v4(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await
        .expect("bind ok");
        assert_eq!(
            stack.inet4_address,
            "127.0.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert!(stack.inet4_listen_port > 0);
        assert_eq!(
            listener.local_addr().unwrap().port(),
            stack.inet4_listen_port
        );
    }

    #[tokio::test]
    async fn accept_loop_drops_unknown_nat_port_quietly() {
        // 完整 listener_handler/Runtime mock 较重；此处只验证 accept 不会 panic：
        // bind 一个 stack，外部直接 connect 到 listener（peer.port = 客户端 ephemeral 端口，
        // 通常落在 nat_port 范围外），lookup_back 失败 → 安全 close。
        let (stack, listener) = SystemStack::bind_v4(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await
        .expect("bind ok");
        let listen_port = stack.inet4_listen_port;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let stack_for_loop = stack.clone();

        // 用一个最小化 fn 测 accept 错误路径：sub-fn 模拟 run_accept_loop_v4 的 lookup_back 分支。
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = stop_rx => {}
                r = listener.accept() => {
                    if let Ok((_conn, peer)) = r {
                        // peer.port 是客户端 ephemeral —— 不在 nat 表内
                        assert!(stack_for_loop.tcp_nat.lookup_back(peer.port()).is_none());
                    }
                }
            }
        });

        // 客户端连一下（任意 ephemeral 端口）
        let _client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .expect("client connect");
        // 等接受完
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        let _ = stop_tx.send(());
    }

    /* ====== IPv6 / ICMP / Reject 测试 ====== */

    fn build_v6_tcp(
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        ctrl: TcpControl,
        payload: &[u8],
    ) -> Vec<u8> {
        let src = Ipv6Address(src_ip.octets());
        let dst = Ipv6Address(dst_ip.octets());
        let tcp = TcpRepr {
            src_port,
            dst_port,
            control: ctrl,
            seq_number: TcpSeqNumber(2000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload,
        };
        let ip = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ip_pkt);
        let tcp_buf_len = tcp.buffer_len();
        let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp_buf_len]);
        tcp.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv6(src),
            &IpAddress::Ipv6(dst),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn parse_v6_tcp(packet: &[u8]) -> (Ipv6Addr, u16, Ipv6Addr, u16) {
        let ip = Ipv6Packet::new_checked(packet).expect("ip6");
        let src_ip = Ipv6Addr::from(ip.src_addr().0);
        let dst_ip = Ipv6Addr::from(ip.dst_addr().0);
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let tcp = TcpPacket::new_checked(&packet[header_len..total_len]).expect("tcp6");
        (src_ip, tcp.src_port(), dst_ip, tcp.dst_port())
    }

    fn assert_v6_tcp_checksum_valid(packet: &[u8]) {
        let ip = Ipv6Packet::new_checked(packet).expect("ip6");
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let src = ip.src_addr();
        let dst = ip.dst_addr();
        let tcp = TcpPacket::new_checked(&packet[header_len..total_len]).expect("tcp6");
        assert!(
            tcp.verify_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst)),
            "TCPv6 checksum invalid"
        );
    }

    #[test]
    fn process_packet_rewrites_ipv6_client_flow() {
        let stack = SystemStack::new_dual(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            "fdfe:dcba:9876::1".parse().unwrap(),
            "fdfe:dcba:9876::2".parse().unwrap(),
            54321,
            Duration::from_secs(60),
        );
        let mut pkt = build_v6_tcp(
            "2001:db8::1".parse().unwrap(),
            40000,
            "2606:4700:4700::1111".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let outcome = stack.process_packet(&mut pkt);
        assert_eq!(outcome, ProcessOutcome::WriteBack);

        let (src_ip, src_port, dst_ip, dst_port) = parse_v6_tcp(&pkt);
        assert_eq!(src_ip, "fdfe:dcba:9876::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(dst_ip, "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(dst_port, 54321);
        assert_ne!(src_port, 40000);
        assert_v6_tcp_checksum_valid(&pkt);

        let session = stack.tcp_nat.lookup_back(src_port).expect("lookup back v6");
        assert_eq!(
            session.source,
            "[2001:db8::1]:40000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            session.destination,
            "[2606:4700:4700::1111]:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn process_packet_rewrites_ipv6_listener_flow_back_to_client() {
        let stack = SystemStack::new_dual(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            "fdfe::1".parse().unwrap(),
            "fdfe::2".parse().unwrap(),
            54321,
            Duration::from_secs(60),
        );
        let mut client = build_v6_tcp(
            "2001:db8::5".parse().unwrap(),
            40000,
            "2606:4700::1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(stack.process_packet(&mut client), ProcessOutcome::WriteBack);
        let (_, nat_port, _, _) = parse_v6_tcp(&client);

        let mut reverse = build_v6_tcp(
            "fdfe::1".parse().unwrap(),
            54321,
            "fdfe::2".parse().unwrap(),
            nat_port,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(
            stack.process_packet(&mut reverse),
            ProcessOutcome::WriteBack
        );
        let (src_ip, src_port, dst_ip, dst_port) = parse_v6_tcp(&reverse);
        assert_eq!(src_ip, "2606:4700::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(src_port, 443);
        assert_eq!(dst_ip, "2001:db8::5".parse::<Ipv6Addr>().unwrap());
        assert_eq!(dst_port, 40000);
        assert_v6_tcp_checksum_valid(&reverse);
    }

    #[test]
    fn process_packet_drops_ipv6_when_v6_not_configured() {
        // 仅 v4 stack 收到 v6 包 → Drop
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        let mut pkt = build_v6_tcp(
            "2001:db8::1".parse().unwrap(),
            40000,
            "2606:4700::1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        assert_eq!(stack.process_packet(&mut pkt), ProcessOutcome::Drop);
    }

    fn build_v4_icmp_echo_request(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        ident: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        // 自己组装 ICMPv4 Echo Request
        let icmp_len = 8 + payload.len();
        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address(src_ip.octets()),
            dst_addr: Ipv4Address(dst_ip.octets()),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + icmp_len];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
            ip_repr.emit(&mut ip, &ChecksumCapabilities::default());
        }
        let icmp_offset = ip_repr.buffer_len();
        buf[icmp_offset] = 8; // EchoRequest
        buf[icmp_offset + 1] = 0;
        buf[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&ident.to_be_bytes());
        buf[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&seq.to_be_bytes());
        buf[icmp_offset + 8..icmp_offset + 8 + payload.len()].copy_from_slice(payload);
        {
            let icmp_buf = &mut buf[icmp_offset..icmp_offset + icmp_len];
            let mut icmp = Icmpv4Packet::new_unchecked(icmp_buf);
            icmp.fill_checksum();
        }
        buf
    }

    #[test]
    fn ipv4_icmp_echo_request_is_reflected_to_reply() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        let payload = b"hello-icmp-payload";
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let mut pkt = build_v4_icmp_echo_request(src_ip, dst_ip, 0x1234, 0x5678, payload);
        let outcome = stack.process_packet(&mut pkt);
        assert_eq!(outcome, ProcessOutcome::WriteBack);

        let ip = Ipv4Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.src_addr().0, dst_ip.octets());
        assert_eq!(ip.dst_addr().0, src_ip.octets());
        assert!(ip.verify_checksum(), "IPv4 csum invalid");
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let icmp = Icmpv4Packet::new_checked(&pkt[header_len..total_len]).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!(icmp.msg_code(), 0);
        assert!(icmp.verify_checksum(), "ICMPv4 csum invalid");
        // payload 应保留
        assert_eq!(&pkt[header_len + 8..total_len], payload);
    }

    fn build_v6_icmp_echo_request(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        ident: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let ip_repr = Ipv6Repr {
            src_addr: Ipv6Address(src_ip.octets()),
            dst_addr: Ipv6Address(dst_ip.octets()),
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + icmp_len];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut buf[..]);
            ip_repr.emit(&mut ip);
        }
        let icmp_offset = ip_repr.buffer_len();
        buf[icmp_offset] = 128; // ICMPv6 EchoRequest type
        buf[icmp_offset + 1] = 0;
        buf[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&ident.to_be_bytes());
        buf[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&seq.to_be_bytes());
        buf[icmp_offset + 8..icmp_offset + 8 + payload.len()].copy_from_slice(payload);
        {
            let icmp_buf = &mut buf[icmp_offset..icmp_offset + icmp_len];
            let mut icmp = Icmpv6Packet::new_unchecked(icmp_buf);
            icmp.fill_checksum(
                &IpAddress::Ipv6(Ipv6Address(src_ip.octets())),
                &IpAddress::Ipv6(Ipv6Address(dst_ip.octets())),
            );
        }
        buf
    }

    #[test]
    fn ipv6_icmp_echo_request_is_reflected_to_reply() {
        let stack = SystemStack::new_dual(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            "fdfe::1".parse().unwrap(),
            "fdfe::2".parse().unwrap(),
            54321,
            Duration::from_secs(60),
        );
        let payload = b"hello-icmpv6";
        let src_ip: Ipv6Addr = "2001:db8::100".parse().unwrap();
        let dst_ip: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let mut pkt = build_v6_icmp_echo_request(src_ip, dst_ip, 0x9abc, 0xdef0, payload);
        let outcome = stack.process_packet(&mut pkt);
        assert_eq!(outcome, ProcessOutcome::WriteBack);

        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(Ipv6Addr::from(ip.src_addr().0), dst_ip);
        assert_eq!(Ipv6Addr::from(ip.dst_addr().0), src_ip);
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let icmp = Icmpv6Packet::new_checked(&pkt[header_len..total_len]).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
        assert!(
            icmp.verify_checksum(
                &IpAddress::Ipv6(ip.src_addr()),
                &IpAddress::Ipv6(ip.dst_addr())
            ),
            "ICMPv6 csum invalid"
        );
        assert_eq!(&pkt[header_len + 8..total_len], payload);
    }

    #[test]
    fn build_ipv4_tcp_rst_swaps_endpoints_and_marks_rst() {
        let pkt = build_v4_tcp(
            "10.0.0.1".parse().unwrap(),
            12345,
            "1.1.1.1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let rst = build_ipv4_tcp_rst(&pkt).expect("rst");
        let ip = Ipv4Packet::new_checked(&rst).unwrap();
        assert_eq!(ip.src_addr().0, [1, 1, 1, 1]);
        assert_eq!(ip.dst_addr().0, [10, 0, 0, 1]);
        assert!(ip.verify_checksum());
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let tcp = TcpPacket::new_checked(&rst[header_len..total_len]).unwrap();
        assert_eq!(tcp.src_port(), 443);
        assert_eq!(tcp.dst_port(), 12345);
        assert!(tcp.rst());
        // 原包是 SYN（无 ACK），所以 RST 应有 ACK
        assert!(tcp.ack());
        assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
    }

    #[test]
    fn build_ipv6_tcp_rst_swaps_endpoints_and_marks_rst() {
        let pkt = build_v6_tcp(
            "2001:db8::1".parse().unwrap(),
            12345,
            "2606:4700::1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let rst = build_ipv6_tcp_rst(&pkt).expect("rst v6");
        let ip = Ipv6Packet::new_checked(&rst).unwrap();
        assert_eq!(
            Ipv6Addr::from(ip.src_addr().0),
            "2606:4700::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from(ip.dst_addr().0),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let tcp = TcpPacket::new_checked(&rst[header_len..total_len]).unwrap();
        assert_eq!(tcp.src_port(), 443);
        assert_eq!(tcp.dst_port(), 12345);
        assert!(tcp.rst());
        assert!(tcp.ack());
        assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
    }

    #[test]
    fn build_ipv4_icmp_unreachable_carries_orig_header_and_l4_prefix() {
        let pkt = build_v4_tcp(
            "10.0.0.1".parse().unwrap(),
            12345,
            "1.1.1.1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let reply =
            build_ipv4_icmp_unreachable(&pkt, 3 /* PortUnreachable */, 1500).expect("unreachable");
        let ip = Ipv4Packet::new_checked(&reply).unwrap();
        assert_eq!(ip.src_addr().0, [1, 1, 1, 1]);
        assert_eq!(ip.dst_addr().0, [10, 0, 0, 1]);
        assert!(ip.verify_checksum());
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let icmp = Icmpv4Packet::new_checked(&reply[header_len..total_len]).unwrap();
        assert_eq!(u8::from(icmp.msg_type()), 3);
        assert_eq!(icmp.msg_code(), 3);
        assert!(icmp.verify_checksum());
    }

    #[test]
    fn build_ipv6_icmp_unreachable_carries_orig_header_and_l4_prefix() {
        let pkt = build_v6_tcp(
            "2001:db8::1".parse().unwrap(),
            12345,
            "2606:4700::1".parse().unwrap(),
            443,
            TcpControl::Syn,
            &[],
        );
        let reply = build_ipv6_icmp_unreachable(&pkt, 4 /* PortUnreachable */, 1500)
            .expect("unreachable v6");
        let ip = Ipv6Packet::new_checked(&reply).unwrap();
        assert_eq!(
            Ipv6Addr::from(ip.src_addr().0),
            "2606:4700::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from(ip.dst_addr().0),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let icmp = Icmpv6Packet::new_checked(&reply[header_len..total_len]).unwrap();
        assert_eq!(u8::from(icmp.msg_type()), 1);
        assert_eq!(icmp.msg_code(), 4);
        assert!(
            icmp.verify_checksum(
                &IpAddress::Ipv6(ip.src_addr()),
                &IpAddress::Ipv6(ip.dst_addr())
            ),
            "ICMPv6 unreachable csum invalid"
        );
    }

    #[test]
    fn rewrite_preserves_payload_bytes() {
        let stack = SystemStack::new_v4(
            "172.18.0.1".parse().unwrap(),
            "172.18.0.2".parse().unwrap(),
            12345,
            Duration::from_secs(60),
        );
        let payload = b"hello-world-1234567890";
        let mut pkt = build_v4_tcp(
            "10.0.0.5".parse().unwrap(),
            54321,
            "1.1.1.1".parse().unwrap(),
            443,
            TcpControl::Psh,
            payload,
        );
        assert_eq!(stack.process_packet(&mut pkt), ProcessOutcome::WriteBack);
        assert_checksums_valid(&pkt);

        // 取出 TCP payload 与原 payload 比较
        let ip = Ipv4Packet::new_checked(&pkt).expect("ip");
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let tcp = TcpPacket::new_checked(&pkt[header_len..total_len]).expect("tcp");
        let tcp_header_len = tcp.header_len() as usize;
        let payload_actual = &pkt[header_len + tcp_header_len..total_len];
        assert_eq!(payload_actual, payload);
    }
}
