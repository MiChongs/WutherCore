//! TCP GRO 合并（发送方向）—— 把用户态多个连续同流的 TCP/IP 包合并成一个
//! 大段，让 kernel 经 TUNSETOFFLOAD 启用的 TSO 路径分片输出。
//!
//! ## 与 sing-tun 的关系
//! 算法对齐 sing-tun `tun_offload_linux.go`：`handleTCPGRO` + `tcpPacketsCanCoalesce`
//! + `coalesceTCPPackets`。差异：
//! - sing-tun 用"原地扩展外部 buffer"模式（依赖 outBufs 的可变借用）；
//! - 我们用“GRO 表持有 owned `Vec<u8>`”模式：`push(pkt: Vec<u8>)` → `drain()` 输出最终段，
//!   更符合 Rust 所有权模型。
//!
//! ## 合并条件（与 sing-tun 一致）
//! 1. 同 5-tuple + ack（不同 ack 视为不同流，避免错误合并）
//! 2. 当前 seq == prev.sent_seq（连续段）
//! 3. 当前 payload_len == prev.gso_size（除最后一段外，所有段必须同 MSS）
//! 4. prev 未设 PSH/FIN（否则它是结束段）
//! 5. 合并后总长 <= 65535（IP 字段上限）
//!
//! ## 输出
//! - `num_merged == 1`：作为普通 IP 包输出（`options = None`），调用方走单包路径；
//! - `num_merged > 1`：附 `VirtioNetHdr`（gso_type=TcpV4/TcpV6, gso_size, hdr_len 等），
//!   调用方写 vnet_hdr 后 write 到 fd。

use std::collections::HashMap;

use super::vnet_hdr::{GsoType, VirtioNetHdr};

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
/// IP 总长度（IPv4 total_len / IPv6 fixed header + payload）的硬上限。
const MAX_IP_PACKET_LEN: usize = 65535;
const IPV4_HEADER_MIN: usize = 20;
const IPV6_HEADER_FIXED: usize = 40;
const TCP_HEADER_MIN: usize = 20;
/// UDP 头固定 8 字节（无可变长选项）。
const UDP_HEADER_LEN: usize = 8;

/// TCP 5-tuple + ack key —— 不同 ack 算作独立流，避免把"重传的乱序包"误合并。
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct TcpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    ack: u32,
    is_v6: bool,
}

/// GRO 表中的一项 —— 持有合并 buffer 与元数据。
#[derive(Debug)]
struct TcpGroItem {
    /// 完整 IP+TCP+合并 payload。`buffer.len()` 在合并时增长。
    buffer: Vec<u8>,
    iph_len: u8,
    tcph_len: u8,
    /// 单段 MSS —— 第一段确定后，后续可合并的段必须 payload_len == gso_size。
    gso_size: u16,
    /// 已 merge 的 payload 末尾对应的 seq（= base_seq + total_merged_payload）。
    sent_seq: u32,
    /// 当前合并段是否带 PSH 标志 —— 带 PSH 后不再接受新合并。
    psh_set: bool,
    /// 已合并段数（含首段）。`> 1` 时输出走 GSO 路径。
    num_merged: u16,
    is_v6: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GroError {
    /// IP 版本既不是 4 也不是 6。
    InvalidIpVersion { version: u8 },
    /// IPv4 头部 < 20B / IPv6 头部 < 40B / 缺 TCP 头。
    HeaderTooShort,
    /// TCP 头声明的 data offset 超出 buffer。
    TcpHeaderOutOfRange,
    /// 包总长 > 65535（IP 字段上限）。
    PacketTooLong,
    /// 设了 FIN —— 流尾不合并。
    HasFin,
    /// 空 ACK（payload_len == 0）—— 不合并。
    EmptyAck,
    /// IPv4 IHL field（header length in 32-bit words）非法。
    InvalidIhl,
}

impl std::fmt::Display for GroError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIpVersion { version } => write!(f, "gro: invalid ip version {version}"),
            Self::HeaderTooShort => write!(f, "gro: ip/tcp header too short"),
            Self::TcpHeaderOutOfRange => write!(f, "gro: tcp data offset out of range"),
            Self::PacketTooLong => write!(f, "gro: packet > 65535 bytes"),
            Self::HasFin => write!(f, "gro: has FIN; not merging"),
            Self::EmptyAck => write!(f, "gro: empty ACK; not merging"),
            Self::InvalidIhl => write!(f, "gro: invalid IPv4 IHL"),
        }
    }
}
impl std::error::Error for GroError {}

/// `push()` 的返回 —— 调用方据此调度 buffer。
#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// 当前包被合并到既有 item。
    Coalesced,
    /// 当前包作为新 item 插入。
    Inserted,
}

/// `drain()` 输出的一段 —— 完整 IP+TCP+payload 字节，附可选 GSO 元信息。
#[derive(Debug)]
pub struct GroOutput {
    pub bytes: Vec<u8>,
    /// `None`：单段，作普通 IP 包输出；
    /// `Some`：合并段（num_merged > 1），需要附 vnet_hdr 走 GSO 路径。
    pub options: Option<VirtioNetHdr>,
}

/// TCP GRO 合并表 —— 整个 batch 周期内累计 push，最后一次 drain 出所有段。
#[derive(Debug, Default)]
pub struct TcpGroTable {
    flows: HashMap<TcpFlowKey, Vec<TcpGroItem>>,
}

impl TcpGroTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 解析 + 合并/插入 —— 错误时把原 `Vec<u8>` 通过 `Err` 归还，
    /// 调用方据此 pass-through 此包（直接写）而不复制。
    pub fn push(&mut self, pkt: Vec<u8>) -> Result<PushOutcome, (GroError, Vec<u8>)> {
        let parsed = match parse_tcp_ip(&pkt) {
            Ok(p) => p,
            Err(e) => return Err((e, pkt)),
        };
        let key = TcpFlowKey {
            src_addr: parsed.src_addr,
            dst_addr: parsed.dst_addr,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            ack: parsed.ack,
            is_v6: parsed.is_v6,
        };

        let items = self.flows.entry(key).or_default();
        // 尝试合并到既有 item
        for item in items.iter_mut() {
            if can_coalesce(item, parsed.seq, parsed.payload_len) {
                coalesce(item, &pkt, &parsed);
                return Ok(PushOutcome::Coalesced);
            }
        }
        // 不能合并 → 作为新流首段插入
        items.push(TcpGroItem {
            buffer: pkt,
            iph_len: parsed.iph_len as u8,
            tcph_len: parsed.tcph_len as u8,
            gso_size: parsed.payload_len as u16,
            sent_seq: parsed.seq.wrapping_add(parsed.payload_len as u32),
            psh_set: parsed.flags & TCP_FLAG_PSH != 0,
            num_merged: 1,
            is_v6: parsed.is_v6,
        });
        Ok(PushOutcome::Inserted)
    }

    /// 取出所有段，清空表。每段附 `Option<VirtioNetHdr>`。
    pub fn drain(&mut self) -> Vec<GroOutput> {
        let mut out = Vec::new();
        for (_, items) in self.flows.drain() {
            for item in items {
                let options = if item.num_merged > 1 {
                    Some(VirtioNetHdr {
                        gso_type: if item.is_v6 {
                            GsoType::TcpV6
                        } else {
                            GsoType::TcpV4
                        },
                        hdr_len: (item.iph_len as u16) + (item.tcph_len as u16),
                        gso_size: item.gso_size,
                        csum_start: item.iph_len as u16,
                        csum_offset: 16,  // TCP checksum 字段相对 TCP 头的偏移
                        needs_csum: true, // 合并后 TCP checksum 失效，kernel 重算
                    })
                } else {
                    None
                };
                out.push(GroOutput {
                    bytes: item.buffer,
                    options,
                });
            }
        }
        out
    }
}

/* =============================================================
解析 + 合并 helpers
============================================================= */

struct ParsedTcpIp {
    is_v6: bool,
    iph_len: usize,
    tcph_len: usize,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload_len: usize,
}

fn parse_tcp_ip(pkt: &[u8]) -> Result<ParsedTcpIp, GroError> {
    if pkt.is_empty() {
        return Err(GroError::HeaderTooShort);
    }
    if pkt.len() > MAX_IP_PACKET_LEN {
        return Err(GroError::PacketTooLong);
    }
    let version = pkt[0] >> 4;
    let (is_v6, iph_len, total_len, src_addr, dst_addr) = match version {
        4 => parse_ipv4(pkt)?,
        6 => parse_ipv6(pkt)?,
        v => return Err(GroError::InvalidIpVersion { version: v }),
    };
    if total_len > pkt.len() || total_len < iph_len + TCP_HEADER_MIN {
        return Err(GroError::HeaderTooShort);
    }
    let tcp = &pkt[iph_len..total_len];
    if tcp.len() < TCP_HEADER_MIN {
        return Err(GroError::HeaderTooShort);
    }
    let tcph_len = ((tcp[12] >> 4) as usize) * 4;
    if tcph_len < TCP_HEADER_MIN || tcph_len > tcp.len() {
        return Err(GroError::TcpHeaderOutOfRange);
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];
    let payload_len = tcp.len() - tcph_len;

    if flags & TCP_FLAG_FIN != 0 {
        return Err(GroError::HasFin);
    }
    if payload_len == 0 {
        return Err(GroError::EmptyAck);
    }

    Ok(ParsedTcpIp {
        is_v6,
        iph_len,
        tcph_len,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload_len,
    })
}

fn parse_ipv4(pkt: &[u8]) -> Result<(bool, usize, usize, [u8; 16], [u8; 16]), GroError> {
    if pkt.len() < IPV4_HEADER_MIN {
        return Err(GroError::HeaderTooShort);
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < IPV4_HEADER_MIN || ihl > pkt.len() {
        return Err(GroError::InvalidIhl);
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[..4].copy_from_slice(&pkt[12..16]);
    dst[..4].copy_from_slice(&pkt[16..20]);
    Ok((false, ihl, total_len, src, dst))
}

fn parse_ipv6(pkt: &[u8]) -> Result<(bool, usize, usize, [u8; 16], [u8; 16]), GroError> {
    if pkt.len() < IPV6_HEADER_FIXED {
        return Err(GroError::HeaderTooShort);
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let total_len = IPV6_HEADER_FIXED + payload_len;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    Ok((true, IPV6_HEADER_FIXED, total_len, src, dst))
}

fn can_coalesce(item: &TcpGroItem, seq: u32, payload_len: usize) -> bool {
    // 1. 序列号必须连续
    if seq != item.sent_seq {
        return false;
    }
    // 2. 当前 payload 必须等于 prev.gso_size（同 MSS）
    if payload_len != item.gso_size as usize {
        return false;
    }
    // 3. prev 已设 PSH 表示流尾，不再合并
    if item.psh_set {
        return false;
    }
    // 4. 合并后总长不能超过 65535
    let merged_total = item.buffer.len() + payload_len;
    if merged_total > MAX_IP_PACKET_LEN {
        return false;
    }
    true
}

fn coalesce(item: &mut TcpGroItem, pkt: &[u8], parsed: &ParsedTcpIp) {
    let payload_start = parsed.iph_len + parsed.tcph_len;
    item.buffer.extend_from_slice(&pkt[payload_start..]);

    // 更新 IP 长度字段
    let new_total = item.buffer.len();
    if !parsed.is_v6 {
        // IPv4: total_len 在偏移 [2..4]
        item.buffer[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
    } else {
        // IPv6: payload_len 在偏移 [4..6]（不含固定 40B 头）
        let payload = (new_total - IPV6_HEADER_FIXED) as u16;
        item.buffer[4..6].copy_from_slice(&payload.to_be_bytes());
    }

    item.num_merged += 1;
    item.sent_seq = item.sent_seq.wrapping_add(parsed.payload_len as u32);
    item.psh_set = parsed.flags & TCP_FLAG_PSH != 0;
    // 当前段若带 PSH，把 PSH 同步到 prev TCP 头（让接收端尽快交付）
    if item.psh_set {
        let tcp_flags_off = item.iph_len as usize + 13;
        item.buffer[tcp_flags_off] |= TCP_FLAG_PSH;
    }
}

/* =============================================================
UDP GRO —— 与 sing-tun `udpPacketsCanCoalesce`/`coalesceUDPPackets` 等价。

## 与 TCP GRO 的差异
1. 无 seq/ack —— flow key 仅 5-tuple；
2. 无 PSH/FIN —— 任何 UDP datagram 均可参与（除非校验失败）；
3. 合并条件：
   - 当前 payload_len <= prev.gso_size（GSO 段不能比首段大）；
   - prev 累计 payload 必须是 gso_size 的整数倍（首个 short straggler 之后不能再加）；
   - 合并后总长 <= 65535。
4. 输出 `csum_offset = 6`（UDP 头内 checksum 字段位置）。
============================================================= */

/// UDP 5-tuple key —— UDP 没有 ack/seq，只用 5-tuple + IP 版本区分流。
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct UdpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    is_v6: bool,
}

#[derive(Debug)]
struct UdpGroItem {
    /// 完整 IP+UDP+合并 payload。
    buffer: Vec<u8>,
    iph_len: u8,
    /// 单段 payload 长度 —— 后续 datagram 必须 <= 此值。
    gso_size: u16,
    /// 已合并 datagram 数。`> 1` 时输出走 USO 路径。
    num_merged: u16,
    // 注：UDP 的 GsoType 总是 UdpL4（v4/v6 同 ABI），无需 is_v6 区分。
}

/// UDP GRO 合并表 —— 整个 batch 周期累计 push，最后 drain 出所有段。
#[derive(Debug, Default)]
pub struct UdpGroTable {
    flows: HashMap<UdpFlowKey, Vec<UdpGroItem>>,
}

impl UdpGroTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 解析 + 合并/插入 —— 错误时把原 `Vec<u8>` 通过 `Err` 归还。
    pub fn push(&mut self, pkt: Vec<u8>) -> Result<PushOutcome, (GroError, Vec<u8>)> {
        let parsed = match parse_udp_ip(&pkt) {
            Ok(p) => p,
            Err(e) => return Err((e, pkt)),
        };
        let key = UdpFlowKey {
            src_addr: parsed.src_addr,
            dst_addr: parsed.dst_addr,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            is_v6: parsed.is_v6,
        };

        let items = self.flows.entry(key).or_default();
        for item in items.iter_mut() {
            if can_coalesce_udp(item, parsed.payload_len) {
                coalesce_udp(item, &pkt, &parsed);
                return Ok(PushOutcome::Coalesced);
            }
        }
        items.push(UdpGroItem {
            buffer: pkt,
            iph_len: parsed.iph_len as u8,
            gso_size: parsed.payload_len as u16,
            num_merged: 1,
        });
        Ok(PushOutcome::Inserted)
    }

    /// 取出所有段，清空表。每段附 `Option<VirtioNetHdr>`。
    pub fn drain(&mut self) -> Vec<GroOutput> {
        let mut out = Vec::new();
        for (_, items) in self.flows.drain() {
            for item in items {
                let options = if item.num_merged > 1 {
                    Some(VirtioNetHdr {
                        gso_type: GsoType::UdpL4,
                        hdr_len: (item.iph_len as u16) + (UDP_HEADER_LEN as u16),
                        gso_size: item.gso_size,
                        csum_start: item.iph_len as u16,
                        csum_offset: 6, // UDP checksum 字段相对 UDP 头的偏移
                        needs_csum: true,
                    })
                } else {
                    None
                };
                out.push(GroOutput {
                    bytes: item.buffer,
                    options,
                });
            }
        }
        out
    }
}

struct ParsedUdpIp {
    is_v6: bool,
    iph_len: usize,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
}

fn parse_udp_ip(pkt: &[u8]) -> Result<ParsedUdpIp, GroError> {
    if pkt.is_empty() {
        return Err(GroError::HeaderTooShort);
    }
    if pkt.len() > MAX_IP_PACKET_LEN {
        return Err(GroError::PacketTooLong);
    }
    let version = pkt[0] >> 4;
    let (is_v6, iph_len, total_len, src_addr, dst_addr) = match version {
        4 => parse_ipv4(pkt)?,
        6 => parse_ipv6(pkt)?,
        v => return Err(GroError::InvalidIpVersion { version: v }),
    };
    if total_len > pkt.len() || total_len < iph_len + UDP_HEADER_LEN {
        return Err(GroError::HeaderTooShort);
    }
    let udp = &pkt[iph_len..total_len];
    if udp.len() < UDP_HEADER_LEN {
        return Err(GroError::HeaderTooShort);
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload_len = udp.len() - UDP_HEADER_LEN;

    if payload_len == 0 {
        // UDP 控制报文（无 payload）—— 不参与 GRO，直接走单包路径。
        return Err(GroError::EmptyAck);
    }

    Ok(ParsedUdpIp {
        is_v6,
        iph_len,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        payload_len,
    })
}

fn can_coalesce_udp(item: &UdpGroItem, payload_len: usize) -> bool {
    // 1. 当前 payload 不能大于首段 gso_size
    if payload_len > item.gso_size as usize {
        return false;
    }
    // 2. prev 累计 payload 必须是 gso_size 的整数倍（一旦混入 short straggler，不再合并）
    let prev_payload_len = item.buffer.len() - (item.iph_len as usize) - UDP_HEADER_LEN;
    if prev_payload_len % (item.gso_size as usize) != 0 {
        return false;
    }
    // 3. 合并后总长不能超过 65535
    let merged_total = item.buffer.len() + payload_len;
    if merged_total > MAX_IP_PACKET_LEN {
        return false;
    }
    true
}

/// 入站 IP 包的 L4 分类 —— 仅区分 GRO 关心的 TCP/UDP 与"其他"（ICMP/v6 ext hdr 等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Class {
    Tcp,
    Udp,
    Other,
}

/// 通过 IP 头快速分类（不解析完整 L4 头）。
///
/// IPv6 仅在 `next_header` 直接是 6/17 时归类，遇 extension header 链一律 `Other`，
/// 因为 GRO 路径无法保证扩展头不变（HopByHop/Routing 等会被 kernel 丢回 slow path）。
pub fn classify_for_gro(pkt: &[u8]) -> L4Class {
    if pkt.is_empty() {
        return L4Class::Other;
    }
    let v = pkt[0] >> 4;
    let proto = match v {
        4 if pkt.len() >= 20 => pkt[9],
        6 if pkt.len() >= 40 => pkt[6],
        _ => return L4Class::Other,
    };
    match proto {
        6 => L4Class::Tcp,
        17 => L4Class::Udp,
        _ => L4Class::Other,
    }
}

/// 给 `LinuxTunIo::write_batch` 的统一入口 —— 接受一批 owned `Vec<u8>`，
/// 输出 `[passthrough..., merged_tcp..., merged_udp...]` 顺序的 [`GroOutput`] 列表。
///
/// - TCP/UDP 走对应 GRO 表合并（同流连续段成大段）；
/// - 其他协议或 GRO 拒绝（FIN/EmptyAck/超长等）→ 作单包 passthrough（`options = None`）；
/// - 顺序重排不会破坏 TCP 正确性（同流仍然有序，跨流无序无所谓）。
pub fn merge_for_linux_tun_batch(pkts: Vec<Vec<u8>>) -> Vec<GroOutput> {
    let mut tcp_gro = TcpGroTable::new();
    let mut udp_gro = UdpGroTable::new();
    let mut passthrough: Vec<GroOutput> = Vec::new();

    for pkt in pkts {
        match classify_for_gro(&pkt) {
            L4Class::Tcp => {
                if let Err((_e, original)) = tcp_gro.push(pkt) {
                    passthrough.push(GroOutput {
                        bytes: original,
                        options: None,
                    });
                }
            }
            L4Class::Udp => {
                if let Err((_e, original)) = udp_gro.push(pkt) {
                    passthrough.push(GroOutput {
                        bytes: original,
                        options: None,
                    });
                }
            }
            L4Class::Other => passthrough.push(GroOutput {
                bytes: pkt,
                options: None,
            }),
        }
    }

    let mut out = passthrough;
    out.extend(tcp_gro.drain());
    out.extend(udp_gro.drain());
    out
}

fn coalesce_udp(item: &mut UdpGroItem, pkt: &[u8], parsed: &ParsedUdpIp) {
    let payload_start = parsed.iph_len + UDP_HEADER_LEN;
    item.buffer.extend_from_slice(&pkt[payload_start..]);

    // 更新 IP 长度字段
    let new_total = item.buffer.len();
    if !parsed.is_v6 {
        item.buffer[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
    } else {
        let payload = (new_total - IPV6_HEADER_FIXED) as u16;
        item.buffer[4..6].copy_from_slice(&payload.to_be_bytes());
    }

    // 更新 UDP length 字段（UDP 头偏移 [4..6]，包含 UDP 头 + payload）
    let udp_len_off = item.iph_len as usize + 4;
    let udp_total = (new_total - item.iph_len as usize) as u16;
    item.buffer[udp_len_off..udp_len_off + 2].copy_from_slice(&udp_total.to_be_bytes());

    item.num_merged += 1;
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{
            IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet,
            Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
        },
    };

    use super::*;

    fn build_v4_tcp(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags_psh: bool,
        flags_fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let src = Ipv4Address([10, 0, 0, 1]);
        let dst = Ipv4Address([1, 1, 1, 1]);
        let control = if flags_fin {
            TcpControl::Fin
        } else if flags_psh {
            TcpControl::Psh
        } else {
            TcpControl::None
        };
        let tcp = TcpRepr {
            src_port,
            dst_port,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(ack as i32)),
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

    fn build_v6_tcp(seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let src = Ipv6Address(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1).octets());
        let dst = Ipv6Address(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).octets());
        let tcp = TcpRepr {
            src_port: 30000,
            dst_port: 443,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: Some(TcpSeqNumber(ack as i32)),
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

    /* ---------- 基础合并行为 ---------- */

    #[test]
    fn empty_table_drain_returns_empty() {
        let mut t = TcpGroTable::new();
        assert!(t.is_empty());
        assert!(t.drain().is_empty());
    }

    #[test]
    fn first_packet_inserted() {
        let mut t = TcpGroTable::new();
        let p = build_v4_tcp(30000, 80, 1000, 5, false, false, &[1u8; 100]);
        let r = t.push(p).expect("ok");
        assert_eq!(r, PushOutcome::Inserted);
    }

    #[test]
    fn two_consecutive_segments_coalesce() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0xaau8; 100]);
        let p2 = build_v4_tcp(30000, 80, 1100, 5, false, false, &[0xbbu8; 100]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Coalesced);

        let out = t.drain();
        assert_eq!(out.len(), 1);
        assert!(
            out[0].options.is_some(),
            "merged segment should have GSO opts"
        );
        let opts = out[0].options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::TcpV4);
        assert_eq!(opts.gso_size, 100);
        assert_eq!(opts.hdr_len, 40); // ipv4(20) + tcp(20)
        assert_eq!(opts.csum_start, 20);
        assert_eq!(opts.csum_offset, 16);
        assert!(opts.needs_csum);
        // 合并后 IP total_len = 20 + 20 + 200 = 240
        let total_len = u16::from_be_bytes([out[0].bytes[2], out[0].bytes[3]]);
        assert_eq!(total_len, 240);
        // payload 是 0xaa*100 + 0xbb*100
        let payload = &out[0].bytes[40..];
        assert_eq!(payload.len(), 200);
        assert!(payload[..100].iter().all(|&b| b == 0xaa));
        assert!(payload[100..].iter().all(|&b| b == 0xbb));
    }

    #[test]
    fn discontinuous_seq_does_not_coalesce() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        let p2 = build_v4_tcp(30000, 80, 2000, 5, false, false, &[0u8; 100]); // 不连续
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
        let out = t.drain();
        assert_eq!(out.len(), 2);
        // 两段都是单包（num_merged=1），无 GSO opts
        assert!(out[0].options.is_none());
        assert!(out[1].options.is_none());
    }

    #[test]
    fn different_payload_sizes_do_not_coalesce_to_first() {
        let mut t = TcpGroTable::new();
        // 第 1 段 100B；第 2 段 50B（与 gso_size 不一致）—— 不合并
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        let p2 = build_v4_tcp(30000, 80, 1100, 5, false, false, &[0u8; 50]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
    }

    #[test]
    fn psh_on_prev_blocks_coalesce() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, true, false, &[0u8; 100]); // PSH 在第一段
        let p2 = build_v4_tcp(30000, 80, 1100, 5, false, false, &[0u8; 100]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        // p1 带 PSH → 不再接受合并
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
    }

    #[test]
    fn psh_on_current_propagates_to_merged_segment() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        let p2 = build_v4_tcp(30000, 80, 1100, 5, true, false, &[0u8; 100]); // 末段 PSH
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Coalesced);
        let out = t.drain();
        assert_eq!(out.len(), 1);
        // 合并后段的 TCP flags 字节应有 PSH
        let tcp_flags = out[0].bytes[20 + 13];
        assert!(tcp_flags & TCP_FLAG_PSH != 0);
    }

    #[test]
    fn fin_flagged_packet_returns_error() {
        let mut t = TcpGroTable::new();
        let p = build_v4_tcp(30000, 80, 1000, 5, false, true, &[0u8; 100]);
        let (err, _orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::HasFin);
    }

    #[test]
    fn empty_ack_returns_error() {
        let mut t = TcpGroTable::new();
        let p = build_v4_tcp(30000, 80, 1000, 5, false, false, &[]);
        let (err, _orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::EmptyAck);
    }

    #[test]
    fn different_ack_creates_separate_flow() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        let p2 = build_v4_tcp(30000, 80, 1100, 6, false, false, &[0u8; 100]); // ack 不同
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        // ack=6 是另一条流，独立 item
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
        let out = t.drain();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn different_5_tuple_creates_separate_flow() {
        let mut t = TcpGroTable::new();
        let p1 = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        let p2 = build_v4_tcp(30001, 80, 1100, 5, false, false, &[0u8; 100]); // src_port 不同
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
        let out = t.drain();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn three_segments_coalesce_in_order() {
        let mut t = TcpGroTable::new();
        for i in 0..3u32 {
            let seq = 1000 + i * 100;
            let p = build_v4_tcp(30000, 80, seq, 5, false, false, &[i as u8; 100]);
            t.push(p).expect("ok");
        }
        let out = t.drain();
        assert_eq!(out.len(), 1);
        let opts = out[0].options.as_ref().unwrap();
        assert_eq!(opts.gso_size, 100);
        // 合并后总 payload 300B
        let total_len = u16::from_be_bytes([out[0].bytes[2], out[0].bytes[3]]);
        assert_eq!(total_len, 40 + 300);
    }

    #[test]
    fn ipv6_two_segments_coalesce() {
        let mut t = TcpGroTable::new();
        let p1 = build_v6_tcp(2000, 7, &[0u8; 80]);
        let p2 = build_v6_tcp(2080, 7, &[0u8; 80]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Coalesced);
        let out = t.drain();
        assert_eq!(out.len(), 1);
        let opts = out[0].options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::TcpV6);
        assert_eq!(opts.gso_size, 80);
        assert_eq!(opts.hdr_len, 60); // ipv6(40) + tcp(20)
        assert_eq!(opts.csum_start, 40);
        // payload_len 字段应反映合并后总 payload（不含 IPv6 固定头）
        let v6_payload_len = u16::from_be_bytes([out[0].bytes[4], out[0].bytes[5]]);
        assert_eq!(v6_payload_len, 20 + 160); // tcp(20) + payload(160)
    }

    #[test]
    fn coalesce_respects_max_packet_size() {
        // 构造 1000 段 100B：单 item 容量 = (65535-40)/100 = 654 段；
        // 1000 段会强制至少分裂成 2 个 item。
        let mut t = TcpGroTable::new();
        let mut coalesced = 0;
        let mut inserted = 0;
        for i in 0..1000u32 {
            let seq = 1000 + i * 100;
            let p = build_v4_tcp(30000, 80, seq, 5, false, false, &[0u8; 100]);
            match t.push(p).unwrap() {
                PushOutcome::Coalesced => coalesced += 1,
                PushOutcome::Inserted => inserted += 1,
            }
        }
        assert!(
            inserted >= 2,
            "expected at least one overflow split, got inserted={inserted} coalesced={coalesced}"
        );
        assert!(coalesced > 0);
        let out = t.drain();
        for o in &out {
            assert!(
                o.bytes.len() <= MAX_IP_PACKET_LEN,
                "merged segment {} exceeds 65535",
                o.bytes.len()
            );
        }
    }

    /* ---------- 单段直出 ---------- */

    #[test]
    fn single_packet_output_has_no_gso_options() {
        let mut t = TcpGroTable::new();
        let p = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        t.push(p).expect("ok");
        let out = t.drain();
        assert_eq!(out.len(), 1);
        assert!(
            out[0].options.is_none(),
            "single segment should not have GSO opts"
        );
    }

    /* ---------- 错误路径 ---------- */

    #[test]
    fn invalid_ip_version_returns_error() {
        let mut t = TcpGroTable::new();
        let mut p = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 100]);
        p[0] = (5 << 4) | 5; // 设成 v=5，非法
        let original_len = p.len();
        let (err, orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::InvalidIpVersion { version: 5 });
        // push 失败时归还 Vec —— 长度保持
        assert_eq!(orig.len(), original_len);
    }

    #[test]
    fn truncated_ip_header_returns_error() {
        let mut t = TcpGroTable::new();
        let p = vec![0x45u8; 10]; // 只 10B
        let (err, _orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::HeaderTooShort);
    }

    /* =========================================================
    UDP GRO 测试
    ========================================================= */

    fn build_v4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let src = Ipv4Address([10, 0, 0, 1]);
        let dst = Ipv4Address([1, 1, 1, 1]);
        let udp = UdpRepr { src_port, dst_port };
        let udp_buf_len = UDP_HEADER_LEN + payload.len();
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp_buf_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + udp_buf_len];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..udp_buf_len]);
        udp.emit(
            &mut udp_pkt,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn build_v6_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let src = Ipv6Address(Ipv6Addr::new(0xfd, 0, 0, 0, 0, 0, 0, 1).octets());
        let dst = Ipv6Address(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).octets());
        let udp_buf_len = UDP_HEADER_LEN + payload.len();
        let ip = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp_buf_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + udp_buf_len];
        let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut ip_pkt);
        let udp = UdpRepr { src_port, dst_port };
        let mut udp_pkt = UdpPacket::new_unchecked(&mut ip_pkt.payload_mut()[..udp_buf_len]);
        udp.emit(
            &mut udp_pkt,
            &IpAddress::Ipv6(src),
            &IpAddress::Ipv6(dst),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    #[test]
    fn udp_empty_table_drain_returns_empty() {
        let mut t = UdpGroTable::new();
        assert!(t.is_empty());
        assert!(t.drain().is_empty());
    }

    #[test]
    fn udp_first_packet_inserted() {
        let mut t = UdpGroTable::new();
        let p = build_v4_udp(40000, 53, &[1u8; 100]);
        assert_eq!(t.push(p).unwrap(), PushOutcome::Inserted);
    }

    #[test]
    fn udp_two_equal_segments_coalesce() {
        let mut t = UdpGroTable::new();
        let p1 = build_v4_udp(40000, 53, &[0xaau8; 100]);
        let p2 = build_v4_udp(40000, 53, &[0xbbu8; 100]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Coalesced);

        let out = t.drain();
        assert_eq!(out.len(), 1);
        let opts = out[0].options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::UdpL4);
        assert_eq!(opts.gso_size, 100);
        assert_eq!(opts.hdr_len, 28); // ipv4(20) + udp(8)
        assert_eq!(opts.csum_start, 20);
        assert_eq!(opts.csum_offset, 6);
        assert!(opts.needs_csum);
        // IP total_len = 20 + 8 + 200
        let total_len = u16::from_be_bytes([out[0].bytes[2], out[0].bytes[3]]);
        assert_eq!(total_len, 228);
        // UDP length 字段（偏移 20+4=24..26）= 8 + 200
        let udp_len = u16::from_be_bytes([out[0].bytes[24], out[0].bytes[25]]);
        assert_eq!(udp_len, 208);
        // payload 是 0xaa*100 + 0xbb*100
        let payload = &out[0].bytes[28..];
        assert_eq!(payload.len(), 200);
        assert!(payload[..100].iter().all(|&b| b == 0xaa));
        assert!(payload[100..].iter().all(|&b| b == 0xbb));
    }

    #[test]
    fn udp_third_smaller_segment_coalesces_as_straggler() {
        // 前两段 100B（exact 倍数），第 3 段 80B 作 straggler 仍允许合并
        let mut t = UdpGroTable::new();
        assert_eq!(
            t.push(build_v4_udp(40000, 53, &[0u8; 100])).unwrap(),
            PushOutcome::Inserted
        );
        assert_eq!(
            t.push(build_v4_udp(40000, 53, &[0u8; 100])).unwrap(),
            PushOutcome::Coalesced
        );
        // 80 < gso_size=100，prev_payload=200 是 100 的倍数 → 可合并
        assert_eq!(
            t.push(build_v4_udp(40000, 53, &[0u8; 80])).unwrap(),
            PushOutcome::Coalesced
        );
        let out = t.drain();
        assert_eq!(out.len(), 1);
        // 总 payload 100+100+80 = 280
        let total_len = u16::from_be_bytes([out[0].bytes[2], out[0].bytes[3]]);
        assert_eq!(total_len, 28 + 280);
    }

    #[test]
    fn udp_after_straggler_no_more_merging() {
        // 100, 80(straggler), 100 → 第 3 段不能再合
        let mut t = UdpGroTable::new();
        t.push(build_v4_udp(40000, 53, &[0u8; 100])).unwrap();
        t.push(build_v4_udp(40000, 53, &[0u8; 80])).unwrap();
        // prev_payload=180 不是 100 的倍数 → 拒绝
        assert_eq!(
            t.push(build_v4_udp(40000, 53, &[0u8; 100])).unwrap(),
            PushOutcome::Inserted
        );
        let out = t.drain();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn udp_larger_than_gso_size_does_not_coalesce() {
        let mut t = UdpGroTable::new();
        let p1 = build_v4_udp(40000, 53, &[0u8; 100]);
        let p2 = build_v4_udp(40000, 53, &[0u8; 200]); // > gso_size
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
    }

    #[test]
    fn udp_different_5_tuple_creates_separate_flow() {
        let mut t = UdpGroTable::new();
        let p1 = build_v4_udp(40000, 53, &[0u8; 100]);
        let p2 = build_v4_udp(40001, 53, &[0u8; 100]); // src_port 不同
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Inserted);
        let out = t.drain();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn udp_ipv6_two_segments_coalesce() {
        let mut t = UdpGroTable::new();
        let p1 = build_v6_udp(40000, 53, &[0u8; 80]);
        let p2 = build_v6_udp(40000, 53, &[0u8; 80]);
        assert_eq!(t.push(p1).unwrap(), PushOutcome::Inserted);
        assert_eq!(t.push(p2).unwrap(), PushOutcome::Coalesced);
        let out = t.drain();
        assert_eq!(out.len(), 1);
        let opts = out[0].options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::UdpL4);
        assert_eq!(opts.gso_size, 80);
        assert_eq!(opts.hdr_len, 48); // ipv6(40) + udp(8)
        assert_eq!(opts.csum_start, 40);
        // payload_len 字段 = udp(8) + payload(160)
        let v6_payload_len = u16::from_be_bytes([out[0].bytes[4], out[0].bytes[5]]);
        assert_eq!(v6_payload_len, 8 + 160);
        // UDP length 字段（偏移 40+4=44..46）= 8 + 160
        let udp_len = u16::from_be_bytes([out[0].bytes[44], out[0].bytes[45]]);
        assert_eq!(udp_len, 168);
    }

    #[test]
    fn udp_single_packet_output_has_no_gso_options() {
        let mut t = UdpGroTable::new();
        let p = build_v4_udp(40000, 53, &[0u8; 100]);
        t.push(p).unwrap();
        let out = t.drain();
        assert_eq!(out.len(), 1);
        assert!(out[0].options.is_none());
    }

    #[test]
    fn udp_zero_payload_returns_error() {
        let mut t = UdpGroTable::new();
        let p = build_v4_udp(40000, 53, &[]);
        let (err, _orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::EmptyAck);
    }

    #[test]
    fn udp_invalid_ip_version_returns_error() {
        let mut t = UdpGroTable::new();
        let mut p = build_v4_udp(40000, 53, &[0u8; 100]);
        p[0] = (5 << 4) | 5;
        let (err, _orig) = t.push(p).unwrap_err();
        assert_eq!(err, GroError::InvalidIpVersion { version: 5 });
    }

    /* =========================================================
    merge_for_linux_tun_batch / classify_for_gro 测试
    ========================================================= */

    #[test]
    fn classify_picks_correct_l4_for_v4() {
        let p_tcp = build_v4_tcp(30000, 80, 1000, 5, false, false, &[0u8; 64]);
        let p_udp = build_v4_udp(40000, 53, &[0u8; 64]);
        assert_eq!(classify_for_gro(&p_tcp), L4Class::Tcp);
        assert_eq!(classify_for_gro(&p_udp), L4Class::Udp);
        // ICMP（proto=1）→ Other
        let mut p_icmp = vec![0u8; 28];
        p_icmp[0] = 0x45;
        p_icmp[2..4].copy_from_slice(&28u16.to_be_bytes());
        p_icmp[9] = 1;
        assert_eq!(classify_for_gro(&p_icmp), L4Class::Other);
    }

    #[test]
    fn classify_handles_empty_and_short_input() {
        assert_eq!(classify_for_gro(&[]), L4Class::Other);
        assert_eq!(classify_for_gro(&[0x45u8; 5]), L4Class::Other); // < 20B
    }

    #[test]
    fn classify_v6_with_ext_header_is_other() {
        // next_header = 0 (HopByHop) → Other（GRO 不处理 ext hdr 链）
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 0; // HopByHop
        assert_eq!(classify_for_gro(&p), L4Class::Other);
    }

    #[test]
    fn batch_merges_tcp_and_udp_separately() {
        let mut pkts = Vec::new();
        // 2 段连续 TCP
        pkts.push(build_v4_tcp(
            30000,
            80,
            1000,
            5,
            false,
            false,
            &[0xaau8; 100],
        ));
        pkts.push(build_v4_tcp(
            30000,
            80,
            1100,
            5,
            false,
            false,
            &[0xbbu8; 100],
        ));
        // 2 段同 5-tuple UDP
        pkts.push(build_v4_udp(40000, 53, &[0xccu8; 80]));
        pkts.push(build_v4_udp(40000, 53, &[0xddu8; 80]));
        // 1 段 ICMP（passthrough）
        let mut icmp = vec![0u8; 28];
        icmp[0] = 0x45;
        icmp[2..4].copy_from_slice(&28u16.to_be_bytes());
        icmp[9] = 1;
        pkts.push(icmp);

        let out = merge_for_linux_tun_batch(pkts);
        // ICMP 1 段（passthrough）+ TCP 1 段（合并）+ UDP 1 段（合并）= 3
        assert_eq!(out.len(), 3);

        // 第 1 段是 passthrough（ICMP）
        assert!(out[0].options.is_none());
        // 第 2 段是 TCP merge
        let tcp = &out[1];
        let opts = tcp.options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::TcpV4);
        assert_eq!(opts.gso_size, 100);
        // 第 3 段是 UDP merge
        let udp = &out[2];
        let opts = udp.options.as_ref().unwrap();
        assert_eq!(opts.gso_type, GsoType::UdpL4);
        assert_eq!(opts.gso_size, 80);
    }

    #[test]
    fn batch_passthrough_for_gro_rejected_packets() {
        // FIN TCP / 空 ACK 都进 passthrough
        let mut pkts = Vec::new();
        pkts.push(build_v4_tcp(30000, 80, 1000, 5, false, true, &[0u8; 100])); // FIN
        pkts.push(build_v4_tcp(30001, 80, 1000, 5, false, false, &[])); // 空 ACK
        let out = merge_for_linux_tun_batch(pkts);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| o.options.is_none()));
    }

    #[test]
    fn batch_empty_input_returns_empty() {
        let out = merge_for_linux_tun_batch(vec![]);
        assert!(out.is_empty());
    }

    #[test]
    fn udp_coalesce_respects_max_packet_size() {
        // 1000 段 100B → 强制至少分裂成 2 个 item
        let mut t = UdpGroTable::new();
        let mut inserted = 0;
        let mut coalesced = 0;
        for _ in 0..1000u32 {
            let p = build_v4_udp(40000, 53, &[0u8; 100]);
            match t.push(p).unwrap() {
                PushOutcome::Inserted => inserted += 1,
                PushOutcome::Coalesced => coalesced += 1,
            }
        }
        assert!(inserted >= 2);
        assert!(coalesced > 0);
        let out = t.drain();
        for o in &out {
            assert!(o.bytes.len() <= MAX_IP_PACKET_LEN);
        }
    }
}
