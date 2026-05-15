//! GSO 切分（接收方向）—— 把 kernel 投递的"大段"虚拟包按 `gso_size` 切成
//! 一组完整的 IP+TCP/UDP 包，每段独立可走我们的 stack 处理。
//!
//! ## 与 sing-tun 的关系
//! 算法对齐 sing-tun `tun_offload.go::GSOSplit`：
//! - GsoNone / payload < gso_size 走单段 fast path（仅 needs_csum 时补 checksum）；
//! - 其它情况按 gso_size 切分，每段：
//!   1. 拷贝 IP 头 + transport 头；
//!   2. IPv4：递增 ID、改 total_len、重算 IP checksum；IPv6：改 payload_len（无 IP csum）；
//!   3. TCP：递增 seq；非末段清 FIN+PSH 标志；UDP：改 length；
//!   4. 拷贝 payload；
//!   5. 重算 transport checksum（含 pseudo-header）。
//!
//! ## 依赖
//! 用 `smoltcp::wire` 的 `Ipv4Packet/Ipv6Packet/TcpPacket/UdpPacket` 做字段读写 +
//! `fill_checksum` 重算 —— 比 sing-tun 的字节级增量算法慢一些，但代码简单且正确性
//! 由 smoltcp 单测保证。后续如果是 hot path 可改为增量算法。

use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};

use super::vnet_hdr::{GsoType, VIRTIO_NET_HDR_LEN, VirtioNetHdr, parse_virtio_net_hdr};

/// IPv4 头中 ID 字段的偏移（仅用于测试断言；运行时通过 smoltcp `ip.ident()`）。
#[allow(dead_code)]
const IPV4_ID_OFFSET: usize = 4;
/// IPv6 头长（无扩展头）。
const IPV6_FIXED_HEADER_LEN: usize = 40;
/// TCP 头中 flags 字节相对 TCP 头起点的偏移（位 13）。
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;

#[derive(Debug, PartialEq, Eq)]
pub enum GsoSplitError {
    /// `csum_start + csum_offset + 1 >= input.len()` —— 头长度声明错误。
    CsumOffsetOutOfRange { csum_at: usize, input_len: usize },
    /// `input.len() < hdr_len`。
    InputShorterThanHdr { input_len: usize, hdr_len: usize },
    /// `hdr_len < csum_start` —— L3 头比 csum_start 还长，结构不一致。
    HdrLenLessThanCsumStart { hdr_len: u16, csum_start: u16 },
    /// IPv4 包但 GsoType 不是 TcpV4 / UdpL4。
    IpVersionGsoTypeMismatch { ip_version: u8, gso_type: GsoType },
    /// IPv4 头不足 20B / IPv6 头不足 40B。
    IpHeaderTooShort { ip_version: u8, got: usize },
    /// 未知 IP 版本（既不是 4 也不是 6）。
    InvalidIpVersion { version: u8 },
    /// `csum_start + 20 > input.len()` —— TCP 头放不下。
    TcpHeaderOutOfRange,
}

impl std::fmt::Display for GsoSplitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CsumOffsetOutOfRange { csum_at, input_len } => {
                write!(f, "gso: csum_at {csum_at} >= input_len {input_len}")
            }
            Self::InputShorterThanHdr { input_len, hdr_len } => {
                write!(f, "gso: input_len {input_len} < hdr_len {hdr_len}")
            }
            Self::HdrLenLessThanCsumStart {
                hdr_len,
                csum_start,
            } => {
                write!(f, "gso: hdr_len {hdr_len} < csum_start {csum_start}")
            }
            Self::IpVersionGsoTypeMismatch {
                ip_version,
                gso_type,
            } => {
                write!(f, "gso: ip v{ip_version} ⊥ gso_type {gso_type:?}")
            }
            Self::IpHeaderTooShort { ip_version, got } => {
                write!(f, "gso: ipv{ip_version} header too short ({got}B)")
            }
            Self::InvalidIpVersion { version } => write!(f, "gso: invalid ip version {version}"),
            Self::TcpHeaderOutOfRange => write!(f, "gso: tcp header out of range"),
        }
    }
}
impl std::error::Error for GsoSplitError {}

/// GSO 切分入口 —— 返回一组完整的 IP 包。
///
/// 单段（GsoNone 或 payload < gso_size）：返回 `vec![input.to_vec()]`，可能补上
/// transport checksum；多段：每段独立分配 `Vec<u8>`。
///
/// **不分配 fast path**：调用方可先看 `opts.gso_type == GsoType::None && !opts.needs_csum`，
/// 此时直接复用原 buffer，无需进入本函数。
pub fn gso_split(input: &[u8], opts: &VirtioNetHdr) -> Result<Vec<Vec<u8>>, GsoSplitError> {
    // 共通校验
    let csum_at = opts.csum_start as usize + opts.csum_offset as usize;
    if csum_at + 1 >= input.len() {
        return Err(GsoSplitError::CsumOffsetOutOfRange {
            csum_at,
            input_len: input.len(),
        });
    }
    if input.len() < opts.hdr_len as usize {
        return Err(GsoSplitError::InputShorterThanHdr {
            input_len: input.len(),
            hdr_len: opts.hdr_len as usize,
        });
    }
    let payload_len = input.len() - opts.hdr_len as usize;
    let gso_size = opts.gso_size as usize;

    // === 单段 fast path ===
    if matches!(opts.gso_type, GsoType::None) || payload_len <= gso_size.max(1) {
        let mut out = input.to_vec();
        if opts.needs_csum {
            recompute_l4_checksum(&mut out)?;
        }
        return Ok(vec![out]);
    }

    // === 多段切分 ===
    if opts.hdr_len < opts.csum_start {
        return Err(GsoSplitError::HdrLenLessThanCsumStart {
            hdr_len: opts.hdr_len,
            csum_start: opts.csum_start,
        });
    }
    let ip_version = input[0] >> 4;
    match (ip_version, opts.gso_type) {
        (4, GsoType::TcpV4) | (4, GsoType::UdpL4) => {
            if input.len() < 20 {
                return Err(GsoSplitError::IpHeaderTooShort {
                    ip_version: 4,
                    got: input.len(),
                });
            }
        }
        (6, GsoType::TcpV6) | (6, GsoType::UdpL4) => {
            if input.len() < IPV6_FIXED_HEADER_LEN {
                return Err(GsoSplitError::IpHeaderTooShort {
                    ip_version: 6,
                    got: input.len(),
                });
            }
        }
        (4 | 6, _) => {
            return Err(GsoSplitError::IpVersionGsoTypeMismatch {
                ip_version,
                gso_type: opts.gso_type,
            });
        }
        _ => {
            return Err(GsoSplitError::InvalidIpVersion {
                version: ip_version,
            });
        }
    }

    let iphlen = opts.csum_start as usize;
    let hdrlen = opts.hdr_len as usize;
    let is_tcp = matches!(opts.gso_type, GsoType::TcpV4 | GsoType::TcpV6);
    let first_tcp_seq: Option<u32> = if is_tcp {
        if input.len() < opts.csum_start as usize + 20 {
            return Err(GsoSplitError::TcpHeaderOutOfRange);
        }
        Some(u32::from_be_bytes([
            input[iphlen + 4],
            input[iphlen + 5],
            input[iphlen + 6],
            input[iphlen + 7],
        ]))
    } else {
        None
    };

    let mut out_segments: Vec<Vec<u8>> = Vec::new();
    let mut next_data_at = hdrlen;
    let mut seg_index: usize = 0;
    while next_data_at < input.len() {
        let next_end = (next_data_at + gso_size).min(input.len());
        let seg_data_len = next_end - next_data_at;
        let total_len = hdrlen + seg_data_len;

        let mut seg = vec![0u8; total_len];
        // [0..hdrlen] 拷贝头部
        seg[..hdrlen].copy_from_slice(&input[..hdrlen]);
        // [hdrlen..total_len] 拷贝本段 payload
        seg[hdrlen..].copy_from_slice(&input[next_data_at..next_end]);

        match ip_version {
            4 => fix_ipv4(&mut seg, total_len, seg_index)?,
            6 => fix_ipv6(&mut seg, total_len, iphlen)?,
            _ => unreachable!(),
        }

        if is_tcp {
            let base_seq = first_tcp_seq.expect("tcp seq present");
            fix_tcp(
                &mut seg,
                iphlen,
                base_seq,
                gso_size as u32,
                seg_index as u32,
                next_end != input.len(),
            );
        } else {
            // UDP：修改 length 字段（含 UDP 头）= seg_data_len + (hdrlen - iphlen)
            fix_udp(&mut seg, iphlen, hdrlen);
        }

        // 重算 transport checksum
        recompute_l4_checksum(&mut seg)?;

        out_segments.push(seg);
        next_data_at += gso_size;
        seg_index += 1;
    }
    Ok(out_segments)
}

/// IPv4：第 i 段 ID += i；改 total_len；重算 IP checksum。
///
/// 注意：拷贝头部时 IP 头里仍是原 *大段* total_len，所以这里用 `new_unchecked`
/// 再立刻把 total_len 改成本段实际值；后续 `new_checked` / `verify_checksum`
/// 调用方才会通过。
fn fix_ipv4(seg: &mut [u8], total_len: usize, seg_index: usize) -> Result<(), GsoSplitError> {
    if total_len < 20 || seg.len() < total_len {
        return Err(GsoSplitError::IpHeaderTooShort {
            ip_version: 4,
            got: seg.len(),
        });
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut seg[..total_len]);
        if seg_index > 0 {
            let new_ident = ip.ident().wrapping_add(seg_index as u16);
            ip.set_ident(new_ident);
        }
        ip.set_total_len(total_len as u16);
        ip.fill_checksum();
    }
    Ok(())
}

/// IPv6：改 payload_len；无 IP csum。同理用 `new_unchecked`。
fn fix_ipv6(seg: &mut [u8], total_len: usize, iphlen: usize) -> Result<(), GsoSplitError> {
    if total_len < IPV6_FIXED_HEADER_LEN || seg.len() < total_len {
        return Err(GsoSplitError::IpHeaderTooShort {
            ip_version: 6,
            got: seg.len(),
        });
    }
    let mut ip = Ipv6Packet::new_unchecked(&mut seg[..total_len]);
    ip.set_payload_len((total_len - iphlen) as u16);
    Ok(())
}

/// TCP：seq = base_seq + gso_size * seg_index；非末段清 FIN+PSH。
fn fix_tcp(
    seg: &mut [u8],
    iphlen: usize,
    base_seq: u32,
    gso_size: u32,
    seg_index: u32,
    not_last: bool,
) {
    let new_seq = base_seq.wrapping_add(gso_size.wrapping_mul(seg_index));
    seg[iphlen + 4..iphlen + 8].copy_from_slice(&new_seq.to_be_bytes());
    if not_last {
        seg[iphlen + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
    }
}

/// UDP：length = transport_hdr_len + seg_data_len。
fn fix_udp(seg: &mut [u8], iphlen: usize, hdrlen: usize) {
    let udp_hdr_len = (hdrlen - iphlen) as u16; // 通常 8
    let seg_data_len = (seg.len() - hdrlen) as u16;
    let new_len = udp_hdr_len + seg_data_len;
    seg[iphlen + 4..iphlen + 6].copy_from_slice(&new_len.to_be_bytes());
}

/// 用 smoltcp 重算 transport checksum（含 pseudo-header）。
fn recompute_l4_checksum(seg: &mut [u8]) -> Result<(), GsoSplitError> {
    let ip_version = seg[0] >> 4;
    match ip_version {
        4 => {
            let (proto, src, dst, header_len, total_len) = {
                let ip = Ipv4Packet::new_checked(&seg[..]).map_err(|_| {
                    GsoSplitError::IpHeaderTooShort {
                        ip_version: 4,
                        got: seg.len(),
                    }
                })?;
                (
                    ip.next_header(),
                    ip.src_addr(),
                    ip.dst_addr(),
                    ip.header_len() as usize,
                    ip.total_len() as usize,
                )
            };
            let src_addr = IpAddress::Ipv4(Ipv4Address(src.0));
            let dst_addr = IpAddress::Ipv4(Ipv4Address(dst.0));
            l4_fill(&mut seg[header_len..total_len], proto, &src_addr, &dst_addr);
            // IP checksum 已在 fix_ipv4 内重算
            Ok(())
        }
        6 => {
            let (proto, src, dst, header_len, total_len) = {
                let ip = Ipv6Packet::new_checked(&seg[..]).map_err(|_| {
                    GsoSplitError::IpHeaderTooShort {
                        ip_version: 6,
                        got: seg.len(),
                    }
                })?;
                let header_len = ip.header_len();
                let total_len = header_len + ip.payload_len() as usize;
                (
                    ip.next_header(),
                    ip.src_addr(),
                    ip.dst_addr(),
                    header_len,
                    total_len,
                )
            };
            let src_addr = IpAddress::Ipv6(Ipv6Address(src.0));
            let dst_addr = IpAddress::Ipv6(Ipv6Address(dst.0));
            l4_fill(&mut seg[header_len..total_len], proto, &src_addr, &dst_addr);
            Ok(())
        }
        _ => Err(GsoSplitError::InvalidIpVersion {
            version: ip_version,
        }),
    }
}

fn l4_fill(buf: &mut [u8], proto: IpProtocol, src: &IpAddress, dst: &IpAddress) {
    match proto {
        IpProtocol::Tcp => {
            let mut tcp = TcpPacket::new_unchecked(buf);
            tcp.fill_checksum(src, dst);
        }
        IpProtocol::Udp => {
            let mut udp = UdpPacket::new_unchecked(buf);
            udp.fill_checksum(src, dst);
        }
        _ => {} // 其它协议不重算
    }
}

/// 给定 read 拉到的"完整 vnet_hdr 帧"（前 10B 是 virtio_net_hdr，后续是大段 IP 包），
/// 解析头 + 切分 + 拷贝段到 `bufs[..max]`。返回填充槽位数。
///
/// - 解析失败 / 切分失败 → 返回 0，调用方应跳过此帧重 await；
/// - 切出段数 > `max` → 前 `max` 个填入，剩余丢尾并 warn。
///
/// 这是 Linux read_batch 的纯字节级 helper，与 fd / tokio 无关，
/// 在主机（Windows/macOS）上也能跑测试。
pub fn process_vnet_segment(
    raw: &[u8],
    bufs: &mut [&mut [u8]],
    sizes: &mut [usize],
    max: usize,
) -> usize {
    let hdr = match parse_virtio_net_hdr(raw) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(target: "capture::linux::tun", error = %e, "vnet_hdr decode failed; drop");
            return 0;
        }
    };
    if raw.len() < VIRTIO_NET_HDR_LEN {
        return 0;
    }
    let payload = &raw[VIRTIO_NET_HDR_LEN..];
    let segs = match gso_split(payload, &hdr) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "capture::linux::tun", error = %e, "gso_split failed; drop");
            return 0;
        }
    };
    let total = segs.len();
    let to_fill = total.min(max);
    for (i, seg) in segs.into_iter().take(to_fill).enumerate() {
        let dst_len = bufs[i].len();
        let n_seg = seg.len().min(dst_len);
        bufs[i][..n_seg].copy_from_slice(&seg[..n_seg]);
        sizes[i] = n_seg;
    }
    if to_fill < total {
        tracing::debug!(
            target: "capture::linux::tun",
            total,
            dropped = total - to_fill,
            "gso segments exceeded batch slots (PUMP_BATCH_N); tail segments deferred"
        );
    }
    to_fill
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{Ipv4Repr, Ipv6Repr, TcpControl, TcpRepr, TcpSeqNumber, UdpRepr},
    };

    use super::*;

    /* ---------- 构造原始大段（IPv4+TCP）的辅助 ---------- */

    fn build_v4_tcp_segment(payload: &[u8], seq: u32) -> Vec<u8> {
        let src = Ipv4Address([10, 0, 0, 1]);
        let dst = Ipv4Address([1, 1, 1, 1]);
        let tcp = TcpRepr {
            src_port: 30000,
            dst_port: 80,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(0)),
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
        let tcp_buf_len = tcp.buffer_len();
        let mut tcp_pkt = TcpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..tcp_buf_len]);
        tcp.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn build_v6_tcp_segment(payload: &[u8], seq: u32) -> Vec<u8> {
        let src = Ipv6Address(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1).octets());
        let dst = Ipv6Address(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).octets());
        let tcp = TcpRepr {
            src_port: 30000,
            dst_port: 443,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(0)),
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

    fn build_v4_udp_segment(payload: &[u8]) -> Vec<u8> {
        let src = Ipv4Address([10, 0, 0, 1]);
        let dst = Ipv4Address([1, 1, 1, 1]);
        let udp = UdpRepr {
            src_port: 30000,
            dst_port: 53,
        };
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + udp.header_len() + payload.len()];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let udp_buf_len = udp.header_len() + payload.len();
        let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..udp_buf_len]);
        udp.emit(
            &mut udp_pkt,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            payload.len(),
            |p| p.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    /* ---------- helper: 校验段的 IP/transport checksum ---------- */

    fn assert_v4_tcp_checksums(seg: &[u8]) {
        let ip = Ipv4Packet::new_checked(seg).expect("ip");
        assert!(ip.verify_checksum(), "ipv4 checksum invalid");
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let src = IpAddress::Ipv4(ip.src_addr());
        let dst = IpAddress::Ipv4(ip.dst_addr());
        let tcp = TcpPacket::new_checked(&seg[header_len..total_len]).expect("tcp");
        assert!(tcp.verify_checksum(&src, &dst), "tcp checksum invalid");
    }

    fn assert_v6_tcp_checksums(seg: &[u8]) {
        let ip = Ipv6Packet::new_checked(seg).expect("ip6");
        let header_len = ip.header_len();
        let total_len = header_len + ip.payload_len() as usize;
        let src = IpAddress::Ipv6(ip.src_addr());
        let dst = IpAddress::Ipv6(ip.dst_addr());
        let tcp = TcpPacket::new_checked(&seg[header_len..total_len]).expect("tcp6");
        assert!(tcp.verify_checksum(&src, &dst), "tcp6 checksum invalid");
    }

    fn assert_v4_udp_checksums(seg: &[u8]) {
        let ip = Ipv4Packet::new_checked(seg).expect("ip");
        assert!(ip.verify_checksum(), "ipv4 checksum invalid");
        let header_len = ip.header_len() as usize;
        let total_len = ip.total_len() as usize;
        let src = IpAddress::Ipv4(ip.src_addr());
        let dst = IpAddress::Ipv4(ip.dst_addr());
        let udp = UdpPacket::new_checked(&seg[header_len..total_len]).expect("udp");
        assert!(udp.verify_checksum(&src, &dst), "udp checksum invalid");
    }

    /* ---------- GsoNone fast path ---------- */

    #[test]
    fn gso_none_returns_input_as_single_segment() {
        let input = build_v4_tcp_segment(b"hello", 1000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::None,
            hdr_len: 0, // 不会用到
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: false,
        };
        let out = gso_split(&input, &opts).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], input);
    }

    /* ---------- TCPv4 切分 ---------- */

    #[test]
    fn tcpv4_split_two_segments_equal_to_gso_size() {
        // payload = 2*MSS，应切 2 段
        let mss = 100usize;
        let payload = vec![0xabu8; mss * 2];
        let input = build_v4_tcp_segment(&payload, 5000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40, // ipv4(20) + tcp(20)
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let segs = gso_split(&input, &opts).expect("ok");
        assert_eq!(segs.len(), 2, "two segments expected");

        // 段 0
        let seg0 = &segs[0];
        let ip0 = Ipv4Packet::new_checked(seg0.as_slice()).expect("ip0");
        assert_eq!(ip0.total_len() as usize, 40 + mss);
        let tcp0 = TcpPacket::new_checked(&seg0[20..]).expect("tcp0");
        assert_eq!(tcp0.seq_number().0 as u32, 5000);
        assert_v4_tcp_checksums(seg0);

        // 段 1
        let seg1 = &segs[1];
        let ip1 = Ipv4Packet::new_checked(seg1.as_slice()).expect("ip1");
        assert_eq!(ip1.total_len() as usize, 40 + mss);
        let tcp1 = TcpPacket::new_checked(&seg1[20..]).expect("tcp1");
        assert_eq!(tcp1.seq_number().0 as u32, 5000 + mss as u32);
        assert_v4_tcp_checksums(seg1);

        // ID 递增
        let id0 = u16::from_be_bytes([seg0[IPV4_ID_OFFSET], seg0[IPV4_ID_OFFSET + 1]]);
        let id1 = u16::from_be_bytes([seg1[IPV4_ID_OFFSET], seg1[IPV4_ID_OFFSET + 1]]);
        assert_eq!(id1, id0.wrapping_add(1));
    }

    #[test]
    fn tcpv4_split_uneven_last_segment_smaller() {
        let mss = 100usize;
        let payload = vec![0xcdu8; mss * 2 + 30]; // 2 整段 + 30B 尾段
        let input = build_v4_tcp_segment(&payload, 7000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40,
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let segs = gso_split(&input, &opts).expect("ok");
        assert_eq!(segs.len(), 3);
        assert_eq!(
            segs[2].len(),
            40 + 30,
            "last segment carries remainder only"
        );
        for seg in &segs {
            assert_v4_tcp_checksums(seg);
        }
    }

    #[test]
    fn tcpv4_split_clears_fin_psh_on_non_last_segments() {
        let mss = 50usize;
        let mut payload = vec![0u8; mss + 10]; // 2 段
        payload[0] = 1;
        let mut input = build_v4_tcp_segment(&payload, 100);
        // 在原大段上设 FIN+PSH
        input[20 + TCP_FLAGS_OFFSET] |= TCP_FLAG_FIN | TCP_FLAG_PSH;
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40,
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let segs = gso_split(&input, &opts).expect("ok");
        assert_eq!(segs.len(), 2);
        assert_eq!(
            segs[0][20 + TCP_FLAGS_OFFSET] & (TCP_FLAG_FIN | TCP_FLAG_PSH),
            0
        );
        assert_eq!(
            segs[1][20 + TCP_FLAGS_OFFSET] & (TCP_FLAG_FIN | TCP_FLAG_PSH),
            TCP_FLAG_FIN | TCP_FLAG_PSH
        );
    }

    /* ---------- TCPv6 切分 ---------- */

    #[test]
    fn tcpv6_split_two_segments() {
        let mss = 80usize;
        let payload = vec![0xeeu8; mss * 2];
        let input = build_v6_tcp_segment(&payload, 9000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV6,
            hdr_len: 60, // ipv6(40) + tcp(20)
            gso_size: mss as u16,
            csum_start: 40,
            csum_offset: 16,
            needs_csum: true,
        };
        let segs = gso_split(&input, &opts).expect("ok");
        assert_eq!(segs.len(), 2);
        for seg in &segs {
            assert_v6_tcp_checksums(seg);
        }
        // seq 递增
        let s0 = u32::from_be_bytes([segs[0][44], segs[0][45], segs[0][46], segs[0][47]]);
        let s1 = u32::from_be_bytes([segs[1][44], segs[1][45], segs[1][46], segs[1][47]]);
        assert_eq!(s1, s0 + mss as u32);
    }

    /* ---------- UDPv4 切分（USO）---------- */

    #[test]
    fn udpv4_uso_split_two_segments() {
        let mss = 64usize;
        let payload = vec![0x77u8; mss * 2];
        let input = build_v4_udp_segment(&payload);
        let opts = VirtioNetHdr {
            gso_type: GsoType::UdpL4,
            hdr_len: 28, // ipv4(20) + udp(8)
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 6,
            needs_csum: true,
        };
        let segs = gso_split(&input, &opts).expect("ok");
        assert_eq!(segs.len(), 2);
        for seg in &segs {
            assert_v4_udp_checksums(seg);
            // UDP length 字段 = udp_hdr(8) + seg_data(64) = 72
            let udp_len = u16::from_be_bytes([seg[20 + 4], seg[20 + 5]]);
            assert_eq!(udp_len as usize, 8 + mss);
        }
    }

    /* ---------- 错误路径 ---------- */

    #[test]
    fn rejects_csum_offset_out_of_range() {
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40,
            gso_size: 100,
            csum_start: 20,
            csum_offset: 1000, // 远超 input
            needs_csum: true,
        };
        let input = build_v4_tcp_segment(b"x", 0);
        let err = gso_split(&input, &opts).unwrap_err();
        assert!(matches!(err, GsoSplitError::CsumOffsetOutOfRange { .. }));
    }

    #[test]
    fn rejects_input_shorter_than_hdr() {
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 200, // 大于 input 总长
            gso_size: 100,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let input = build_v4_tcp_segment(b"abc", 0);
        let err = gso_split(&input, &opts).unwrap_err();
        assert!(matches!(err, GsoSplitError::InputShorterThanHdr { .. }));
    }

    /* ---------- process_vnet_segment ---------- */

    fn build_vnet_frame(opts: &VirtioNetHdr, payload: Vec<u8>) -> Vec<u8> {
        let mut frame = Vec::with_capacity(VIRTIO_NET_HDR_LEN + payload.len());
        // 写 virtio_net_hdr（小端，与 parse_virtio_net_hdr 对应）
        let flags: u8 = if opts.needs_csum { 0x01 } else { 0x00 };
        frame.push(flags);
        frame.push(opts.gso_type.as_u8());
        frame.extend_from_slice(&opts.hdr_len.to_le_bytes());
        frame.extend_from_slice(&opts.gso_size.to_le_bytes());
        frame.extend_from_slice(&opts.csum_start.to_le_bytes());
        frame.extend_from_slice(&opts.csum_offset.to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn process_vnet_segment_single_packet_fills_one_slot() {
        let payload = build_v4_tcp_segment(b"hello", 5000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::None,
            hdr_len: 40,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: false,
        };
        let frame = build_vnet_frame(&opts, payload.clone());
        let mut buf0 = vec![0u8; 1516];
        let mut buf1 = vec![0u8; 1516];
        let mut bufs: [&mut [u8]; 2] = [&mut buf0[..], &mut buf1[..]];
        let mut sizes = [0usize; 2];
        let n = process_vnet_segment(&frame, &mut bufs, &mut sizes, 2);
        assert_eq!(n, 1);
        assert_eq!(sizes[0], payload.len());
        assert_eq!(&buf0[..sizes[0]], &payload[..]);
        assert_eq!(sizes[1], 0);
    }

    #[test]
    fn process_vnet_segment_gso_split_fills_multiple_slots() {
        let mss = 100usize;
        let payload = vec![0xabu8; mss * 2];
        let big = build_v4_tcp_segment(&payload, 7000);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40,
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let frame = build_vnet_frame(&opts, big);
        let mut buf0 = vec![0u8; 1516];
        let mut buf1 = vec![0u8; 1516];
        let mut buf2 = vec![0u8; 1516];
        let mut bufs: [&mut [u8]; 3] = [&mut buf0[..], &mut buf1[..], &mut buf2[..]];
        let mut sizes = [0usize; 3];
        let n = process_vnet_segment(&frame, &mut bufs, &mut sizes, 3);
        assert_eq!(n, 2, "two GSO segments");
        assert_eq!(sizes[0], 40 + mss);
        assert_eq!(sizes[1], 40 + mss);
        assert_v4_tcp_checksums(&buf0[..sizes[0]]);
        assert_v4_tcp_checksums(&buf1[..sizes[1]]);
    }

    #[test]
    fn process_vnet_segment_overflow_drops_tail() {
        let mss = 50usize;
        let payload = vec![0u8; mss * 4]; // 4 段
        let big = build_v4_tcp_segment(&payload, 1);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 40,
            gso_size: mss as u16,
            csum_start: 20,
            csum_offset: 16,
            needs_csum: true,
        };
        let frame = build_vnet_frame(&opts, big);
        // 只给 2 个槽位，应填 2 段、丢尾 2 段
        let mut buf0 = vec![0u8; 1516];
        let mut buf1 = vec![0u8; 1516];
        let mut bufs: [&mut [u8]; 2] = [&mut buf0[..], &mut buf1[..]];
        let mut sizes = [0usize; 2];
        let n = process_vnet_segment(&frame, &mut bufs, &mut sizes, 2);
        assert_eq!(n, 2);
        assert_v4_tcp_checksums(&buf0[..sizes[0]]);
        assert_v4_tcp_checksums(&buf1[..sizes[1]]);
    }

    #[test]
    fn process_vnet_segment_decode_failure_returns_zero() {
        // 短到不能解析 vnet_hdr
        let mut bufs: [&mut [u8]; 1] = [&mut [0u8; 1516][..]];
        let mut sizes = [0usize; 1];
        let n = process_vnet_segment(&[0u8; 5], &mut bufs, &mut sizes, 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn rejects_ip_version_mismatch_with_gso_type() {
        // IPv6 包但声明 GsoType::TcpV4
        let payload = vec![0u8; 200];
        let input = build_v6_tcp_segment(&payload, 1);
        let opts = VirtioNetHdr {
            gso_type: GsoType::TcpV4,
            hdr_len: 60,
            gso_size: 100,
            csum_start: 40,
            csum_offset: 16,
            needs_csum: true,
        };
        let err = gso_split(&input, &opts).unwrap_err();
        assert!(matches!(
            err,
            GsoSplitError::IpVersionGsoTypeMismatch { .. }
        ));
    }
}
