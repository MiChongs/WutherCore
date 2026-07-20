//! TUN 帧格式缓存与统一写回 —— `tun_dispatch` 与 `system_dispatch` 共用。
//!
//! 不同平台 TUN 设备读出来的帧可能带不同前缀（RawIp / Linux PI / Utun AF /
//! VirtIO net header）。读路径由 [`crate::packet::parse_tun_frame`] 自动识别；
//! 写回时必须用**同一帧格式**包装才能保证 OS 收得回来。
//!
//! 这里按 (proto, src, dst) 5-tuple 缓存"读到时的格式"，写回时反查同流：
//! - TCP NAT 改写后的包 src/dst 已经被换掉，直接查不到 → 回退 RawIp（绝大多数
//!   平台是此格式，向下兼容）。
//! - UDP 反向流（外向 src ↔ 内向 dst 互换）也能命中：缓存写入时同时插入正反两个 key。

use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::{
    packet::{FrameFormat, L4, ParsedPacket, encode_tun_ip_frame, parse_ip_packet},
    tun_io::{TunIo, TunIoError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TunFrameFlowKey {
    protocol: u8,
    src: SocketAddr,
    dst: SocketAddr,
}

impl TunFrameFlowKey {
    fn from_packet(packet: &ParsedPacket) -> Option<Self> {
        let protocol = match packet.l4 {
            L4::Tcp(_) => 6,
            L4::Udp(_) => 17,
            L4::Other(_) => return None,
        };
        Some(Self {
            protocol,
            src: packet.src_socket()?,
            dst: packet.dst_socket()?,
        })
    }

    fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TunFrameFormatEntry {
    format: FrameFormat,
    updated_at: Instant,
}

/// 5-tuple → 平台帧格式 的 LRU 缓存。
#[derive(Debug)]
pub struct TunFrameFormatCache {
    inner: Mutex<HashMap<TunFrameFlowKey, TunFrameFormatEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl TunFrameFormatCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// 读入一帧时调用 —— 同时插入正反向 key（让响应方向也能命中）。
    pub fn observe(&self, packet: &ParsedPacket, format: FrameFormat) {
        let Some(key) = TunFrameFlowKey::from_packet(packet) else {
            return;
        };
        let now = Instant::now();
        let entry = TunFrameFormatEntry {
            format,
            updated_at: now,
        };
        let mut inner = self.inner.lock();
        inner.insert(key, entry);
        inner.insert(key.reverse(), entry);
        if inner.len() > self.max_entries {
            self.prune_locked(&mut inner, now);
        }
    }

    /// 给定准备写出的 IP 包反查帧格式；不命中或过期返回 [`FrameFormat::RawIp`]。
    pub fn format_for_ip_packet(&self, ip_packet: &[u8]) -> FrameFormat {
        let Ok(packet) = parse_ip_packet(ip_packet) else {
            return FrameFormat::RawIp;
        };
        let Some(key) = TunFrameFlowKey::from_packet(&packet) else {
            return FrameFormat::RawIp;
        };
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let Some(entry) = inner.get_mut(&key) else {
            return FrameFormat::RawIp;
        };
        if now.duration_since(entry.updated_at) > self.ttl {
            inner.remove(&key);
            return FrameFormat::RawIp;
        }
        entry.updated_at = now;
        entry.format
    }

    fn prune_locked(
        &self,
        inner: &mut HashMap<TunFrameFlowKey, TunFrameFormatEntry>,
        now: Instant,
    ) {
        inner.retain(|_, entry| now.duration_since(entry.updated_at) <= self.ttl);
        if inner.len() <= self.max_entries {
            return;
        }
        let mut by_age: Vec<_> = inner
            .iter()
            .map(|(key, entry)| (*key, entry.updated_at))
            .collect();
        by_age.sort_by_key(|(_, updated_at)| *updated_at);
        let overflow = inner.len().saturating_sub(self.max_entries);
        for (key, _) in by_age.into_iter().take(overflow) {
            inner.remove(&key);
        }
    }
}

/// 统一帧格式写回 —— `pkt` 是裸 IP 包，按缓存命中的格式包装后写入 TUN。
pub async fn write_ip_packet_to_tun(
    device: &Arc<dyn TunIo>,
    frame_formats: &Arc<TunFrameFormatCache>,
    pkt: &[u8],
    write_context: &'static str,
) -> Result<usize, TunIoError> {
    let format = frame_formats.format_for_ip_packet(pkt);
    let frame = match encode_tun_ip_frame(format, pkt) {
        Ok(frame) => frame,
        Err(e) => {
            warn!(
                target: "capture::tun",
                write_context,
                error = %e,
                frame = ?format,
                bytes = pkt.len(),
                "tun frame encode failed; fallback to raw ip"
            );
            Cow::Borrowed(pkt)
        }
    };
    let n = device.write_packet(frame.as_ref()).await?;
    if !matches!(format, FrameFormat::RawIp) {
        debug!(
            target: "capture::traffic",
            frame = ?format,
            ip_bytes = pkt.len(),
            frame_bytes = frame.as_ref().len(),
            "tun packet write"
        );
    }
    Ok(n)
}

/// 批量写一组裸 IP 包 —— 按 frame_format 分流：
/// - 大多数包命中 [`FrameFormat::RawIp`]（Linux IFF_VNET_HDR 启用场景下读路径已剥头），
///   一次性交给 [`TunIo::write_batch`]，平台后端可在内部做 GRO 合并；
/// - 命中其它格式（外部 tap、读路径未剥头等）的包逐个走 [`encode_tun_ip_frame`] 老路径。
///
/// 输入 `pkts` 接受所有权（`Stack::drain_outbound` 本身就返回 owned），
/// 避免合并路径再克隆。任一包失败立即返回错误（已写出的包无法回滚）。
pub async fn write_ip_packets_to_tun_batch(
    device: &Arc<dyn TunIo>,
    frame_formats: &Arc<TunFrameFormatCache>,
    pkts: Vec<Vec<u8>>,
    write_context: &'static str,
) -> Result<usize, TunIoError> {
    if pkts.is_empty() {
        return Ok(0);
    }
    let mut raw_ip: Vec<Vec<u8>> = Vec::with_capacity(pkts.len());
    let mut other: Vec<(FrameFormat, Vec<u8>)> = Vec::new();
    for pkt in pkts {
        let fmt = frame_formats.format_for_ip_packet(&pkt);
        if matches!(fmt, FrameFormat::RawIp) {
            raw_ip.push(pkt);
        } else {
            other.push((fmt, pkt));
        }
    }

    let mut written = 0usize;
    if !raw_ip.is_empty() {
        let n = raw_ip.len();
        device.write_batch(raw_ip).await?;
        written += n;
    }
    for (fmt, pkt) in other {
        let frame = match encode_tun_ip_frame(fmt, &pkt) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    target: "capture::tun",
                    write_context,
                    error = %e,
                    frame = ?fmt,
                    bytes = pkt.len(),
                    "tun frame encode failed; fallback to raw ip"
                );
                Cow::Borrowed(pkt.as_slice())
            }
        };
        device.write_packet(frame.as_ref()).await?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::packet::{IpHeader, IpVersion, UdpSummary, encode_tun_ip_frame, parse_tun_frame};

    #[test]
    fn cache_maps_reverse_udp_flow_for_write_back() {
        let cache = TunFrameFormatCache::new(Duration::from_secs(60), 16);
        let inner_src: SocketAddr = "172.19.0.1:42000".parse().unwrap();
        let outer_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let observed = ParsedPacket {
            ip: IpHeader {
                version: IpVersion::V4,
                src: inner_src.ip(),
                dst: outer_dst.ip(),
                protocol: 17,
                total_len: 0,
                l4_offset: 20,
                hop_limit: 64,
            },
            l4: L4::Udp(UdpSummary {
                src_port: inner_src.port(),
                dst_port: outer_dst.port(),
                payload_offset: 28,
                payload_len: 0,
            }),
        };

        cache.observe(&observed, FrameFormat::VirtioNetHeader);
        let response =
            crate::udp_forwarder::build_udp_ip_packet(outer_dst, inner_src, b"dns-response")
                .unwrap();

        assert_eq!(
            cache.format_for_ip_packet(&response),
            FrameFormat::VirtioNetHeader
        );
        let frame = encode_tun_ip_frame(cache.format_for_ip_packet(&response), &response).unwrap();
        let parsed = parse_tun_frame(frame.as_ref()).unwrap();
        assert_eq!(parsed.format, FrameFormat::VirtioNetHeader);
        assert_eq!(parsed.ip_packet(frame.as_ref()), response.as_slice());
    }

    #[test]
    fn cache_returns_raw_ip_when_unknown_flow() {
        let cache = TunFrameFormatCache::new(Duration::from_secs(60), 16);
        let pkt = crate::udp_forwarder::build_udp_ip_packet(
            "1.1.1.1:53".parse().unwrap(),
            "10.0.0.1:42000".parse().unwrap(),
            b"x",
        )
        .unwrap();
        assert_eq!(cache.format_for_ip_packet(&pkt), FrameFormat::RawIp);
    }

    #[test]
    fn cache_respects_ttl() {
        let cache = TunFrameFormatCache::new(Duration::from_millis(20), 16);
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let observed = ParsedPacket {
            ip: IpHeader {
                version: IpVersion::V4,
                src: src.ip(),
                dst: dst.ip(),
                protocol: 17,
                total_len: 0,
                l4_offset: 20,
                hop_limit: 64,
            },
            l4: L4::Udp(UdpSummary {
                src_port: src.port(),
                dst_port: dst.port(),
                payload_offset: 28,
                payload_len: 0,
            }),
        };
        cache.observe(&observed, FrameFormat::VirtioNetHeader);
        let pkt = crate::udp_forwarder::build_udp_ip_packet(src, dst, b"x").unwrap();
        assert_eq!(
            cache.format_for_ip_packet(&pkt),
            FrameFormat::VirtioNetHeader
        );
        std::thread::sleep(Duration::from_millis(40));
        // TTL 过期后，读取应该返回 RawIp（cache 内部清理过期项）
        assert_eq!(cache.format_for_ip_packet(&pkt), FrameFormat::RawIp);
        let _ = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    }
}
