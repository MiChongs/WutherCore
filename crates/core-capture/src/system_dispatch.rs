//! sing-tun 风格 system stack 的 dispatcher —— 与 [`crate::tun_dispatch::TunDispatcher`]
//! 平行；当 `CaptureStack::System` 被选中时由 supervisor 选用。
//!
//! ## 行为
//! - **TCP**：读 TUN → `SystemStack::process_packet` 原地 NAT 改写 →
//!   `write_ip_packet_to_tun` 回写 → OS listener 接管 TCP 状态机；
//!   accept 后由 [`crate::stack_system::SystemStack::start`] 内部的 accept loop
//!   走 `ListenerHandler.prepare_tcp` 拨号 + 双向 splice。
//! - **UDP**：与 `tun_dispatch::TunDispatcher::handle_udp` 同源逻辑（DNS hijack /
//!   5-tuple session 复用 / FakeIP 反查 / reverse loop）。后续阶段抽公共模块。
//! - **ICMP / IPv6**：阶段 2 实现；当前直接 drop。

use std::{net::SocketAddr, sync::Arc, time::Instant};

use core_runtime::{ListenerHandler, Runtime};
use parking_lot::Mutex;
use tokio::{sync::oneshot, time::MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::{
    eim_nat::EimNatTable,
    engine::CapturePlan,
    frame_cache::{TunFrameFormatCache, write_ip_packet_to_tun},
    nat::NatTable,
    packet::parse_tun_frame,
    stack_system::{ProcessOutcome, SystemStack, SystemStackHandle},
    tun_inbound::{TunInbound, TunPacket},
    tun_io::TunIo,
    tun_pump::{
        PUMP_BATCH_N, TUN_FRAME_FORMAT_MAX_ENTRIES, TUN_FRAME_FORMAT_TTL, TUN_IDLE_LOG_INTERVAL,
        TUN_TRAFFIC_SUMMARY_INTERVAL, TrafficLog,
    },
};

/* =============================================================
流量计数已抽到 tun_pump::TrafficLog。
============================================================= */

/* =============================================================
SystemDispatcher —— 与 TunDispatcher 平行
============================================================= */

pub struct SystemDispatcher {
    pub plan: CapturePlan,
    pub nat: Arc<NatTable>,
    pub eim: Arc<EimNatTable>,
    pub fake_pool: Arc<core_resolver::FakeIpPool>,
    pub dns_service: Arc<core_resolver::DnsService>,
    pub inbound: Arc<TunInbound>,
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
    frame_formats: Arc<TunFrameFormatCache>,
}

impl SystemDispatcher {
    pub fn new(
        plan: CapturePlan,
        nat: Arc<NatTable>,
        eim: Arc<EimNatTable>,
        fake_pool: Arc<core_resolver::FakeIpPool>,
        dns_service: Arc<core_resolver::DnsService>,
        ipset: Arc<dyn crate::ipset::IpSetProvider>,
    ) -> Self {
        let inbound = Arc::new(TunInbound::new(plan.clone(), fake_pool.clone(), ipset));
        let idle = plan.udp_timeout;
        Self {
            plan,
            nat,
            eim,
            fake_pool,
            dns_service,
            inbound,
            udp_sessions: Arc::new(crate::udp_session::UdpSessionTable::new(idle)),
            frame_formats: Arc::new(TunFrameFormatCache::new(
                TUN_FRAME_FORMAT_TTL,
                TUN_FRAME_FORMAT_MAX_ENTRIES,
            )),
        }
    }

    /// 启动：先 bind v4 listener + spawn accept loop（system stack），
    /// 再 spawn TUN pump_loop。
    pub async fn start(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        runtime: Arc<Runtime>,
    ) -> std::io::Result<SystemDispatcherHandles> {
        let inet4 = self.plan.tun_v4_cidr.addr();
        let inet4_next = match next_ipv4(inet4) {
            Some(n) if self.plan.tun_v4_cidr.contains(&n) => n,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "system stack: TUN v4 cidr {} 至少需要 2 个地址（gateway + next）",
                        self.plan.tun_v4_cidr
                    ),
                ));
            }
        };

        // IPv6：从 plan.tun_v6_cidr 推导 inet6_address / inet6_next；
        // cidr 太小（无法分配 next）时退化为仅 v4，仅 warn 不致命。
        let inet6_pair = match self.plan.tun_v6_cidr {
            Some(v6_cidr) => {
                let inet6 = v6_cidr.addr();
                match next_ipv6(inet6) {
                    Some(n) if v6_cidr.contains(&n) => Some((inet6, n)),
                    _ => {
                        warn!(
                            target: "capture::system",
                            v6_cidr = %v6_cidr,
                            "TUN v6 cidr too small for system stack; v6 path disabled"
                        );
                        None
                    }
                }
            }
            None => None,
        };

        let handler = Arc::new(ListenerHandler::new(runtime));

        // 1) 启动 system stack listener + accept loop（双栈）
        let stack_handle = SystemStack::start_dual(
            inet4,
            inet4_next,
            inet6_pair,
            handler.clone(),
            self.inbound.clone(),
            self.dns_service.clone(),
            self.plan.udp_timeout,
        )
        .await?;
        let stack = stack_handle.stack.clone();

        // 2) 启动 TUN pump_loop
        let (stop_pump_tx, stop_pump_rx) = oneshot::channel();
        let me = self.clone();
        let device_for_pump = device.clone();
        let stack_for_pump = stack.clone();
        let handler_for_pump = handler.clone();
        let pump_handle = tokio::spawn(async move {
            me.pump_loop(
                device_for_pump,
                stack_for_pump,
                handler_for_pump,
                stop_pump_rx,
            )
            .await;
        });

        // 3) 启动周期 GC：清理过期 TCP NAT + UDP session。
        let (gc_handle, stop_gc_tx) = crate::gc::spawn_system_gc(
            stack.tcp_nat.clone(),
            self.udp_sessions.clone(),
            self.plan.udp_timeout,
        );

        info!(
            target: "capture::system",
            iface = %device.name(),
            inet4_address = %inet4,
            inet4_next_address = %inet4_next,
            v4_listen_port = stack.inet4_listen_port,
            v6_listen_port = stack.inet6.map(|v| v.listen_port).unwrap_or(0),
            mtu = self.plan.mtu,
            gc_period_ms = crate::gc::purge_period(self.plan.udp_timeout).as_millis() as u64,
            "system dispatcher started"
        );

        Ok(SystemDispatcherHandles {
            pump_handle,
            gc_handle,
            stack_handle: Mutex::new(Some(stack_handle)),
            stop_pump: Some(stop_pump_tx),
            stop_gc: Some(stop_gc_tx),
        })
    }

    async fn pump_loop(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        stack: Arc<SystemStack>,
        handler: Arc<ListenerHandler>,
        mut stop_rx: oneshot::Receiver<()>,
    ) {
        let mtu = self.plan.mtu as usize;
        let buf_cap = mtu + 64;
        // 预分配 PUMP_BATCH_N 个固定容量 buffer；read_batch 内填充实际字节，
        // sizes[i] 记录 IP 包长度。drain-on-ready 后端一次 wakeup 可消费多包。
        let mut storage: Vec<Vec<u8>> = (0..PUMP_BATCH_N).map(|_| vec![0u8; buf_cap]).collect();
        let mut sizes = [0usize; PUMP_BATCH_N];
        let iface = device.name().to_string();
        let mut traffic = TrafficLog::new(Instant::now());
        let mut log_tick = tokio::time::interval(TUN_IDLE_LOG_INTERVAL);
        log_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            target: "capture::system",
            iface = %iface,
            mtu,
            batch = PUMP_BATCH_N,
            "system pump loop started"
        );

        loop {
            // 每轮重建可变借用集合 —— Vec<&mut [u8]> 与 storage 同生命周期，
            // 在 select! 完成后必须显式 drop 让 storage 可重新 index。
            let mut bufs: Vec<&mut [u8]> = storage.iter_mut().map(|v| v.as_mut_slice()).collect();

            let count = tokio::select! {
                _ = &mut stop_rx => break,
                _ = log_tick.tick() => {
                    drop(bufs);
                    let now = Instant::now();
                    if traffic.idle_warning_due(now, TUN_IDLE_LOG_INTERVAL) {
                        warn!(
                            target: "capture::system",
                            iface = %iface,
                            elapsed_ms = now.duration_since(traffic.started_at).as_millis() as u64,
                            "system dispatcher has not read any packet"
                        );
                    } else if traffic.summary_due(now, TUN_TRAFFIC_SUMMARY_INTERVAL) {
                        info!(
                            target: "capture::traffic",
                            "{}",
                            traffic.format_summary(&iface)
                        );
                    }
                    continue;
                }
                r = device.read_batch(&mut bufs, &mut sizes) => {
                    match r {
                        Ok(n) => n,
                        Err(e) => {
                            warn!(target: "capture::system", error = %e, "tun read failed");
                            break;
                        }
                    }
                }
            };
            drop(bufs); // 释放 storage 可变借用，让下面 for 循环可单元素 index

            for i in 0..count {
                let raw_frame = &mut storage[i][..sizes[i]];
                self.process_one_ip_packet(
                    raw_frame,
                    &device,
                    &stack,
                    &handler,
                    &iface,
                    &mut traffic,
                )
                .await;
            }
        }
        info!(
            target: "capture::system",
            iface = %iface,
            packets = traffic.read_packets,
            bytes = traffic.read_bytes,
            "system pump loop stopped"
        );
    }

    /// 处理 1 个 IP 包 —— 从 pump_loop 抽出，方便 batch 路径循环调用。
    async fn process_one_ip_packet(
        &self,
        raw_frame: &mut [u8],
        device: &Arc<dyn TunIo>,
        stack: &Arc<SystemStack>,
        handler: &ListenerHandler,
        iface: &str,
        traffic: &mut TrafficLog,
    ) {
        let n = raw_frame.len();
        if traffic.record_read(n) {
            info!(
                target: "capture::traffic",
                iface = %iface,
                bytes = n,
                "first tun packet read (system stack)"
            );
        }

        let parsed_frame = match parse_tun_frame(raw_frame) {
            Ok(p) => p,
            Err(e) => {
                traffic.record_unparsable();
                debug!(
                    target: "capture::system",
                    bytes = n,
                    error = %e,
                    "drop unparsable tun frame"
                );
                return;
            }
        };
        let parsed = parsed_frame.packet;
        self.frame_formats.observe(&parsed, parsed_frame.format);
        let ip_offset = parsed_frame.ip_offset;
        let ip_len = parsed.ip.total_len;
        let ip_end = ip_offset.saturating_add(ip_len);
        if ip_end > raw_frame.len() {
            traffic.record_unparsable();
            return;
        }

        let packet = match self.inbound.classify_packet(&parsed) {
            Ok(packet) => packet,
            Err(reason) => {
                traffic.record_drop();
                debug!(
                    target: "capture::system",
                    src = %parsed.ip.src,
                    dst = %parsed.ip.dst,
                    ?reason,
                    "packet skipped by TUN inbound policy"
                );
                return;
            }
        };

        match packet {
            TunPacket::Tcp { .. } => {
                traffic.record_tcp();
                let outcome = stack.process_packet(&mut raw_frame[ip_offset..ip_end]);
                match outcome {
                    ProcessOutcome::WriteBack => {
                        let pkt_owned = raw_frame[ip_offset..ip_end].to_vec();
                        if let Err(e) = write_ip_packet_to_tun(
                            device,
                            &self.frame_formats,
                            &pkt_owned,
                            "capture::system",
                        )
                        .await
                        {
                            warn!(target: "capture::system", error = %e, "tun write failed");
                        }
                    }
                    ProcessOutcome::Reply(reply) => {
                        if let Err(e) = write_ip_packet_to_tun(
                            device,
                            &self.frame_formats,
                            &reply,
                            "capture::system",
                        )
                        .await
                        {
                            warn!(target: "capture::system", error = %e, "tun reply write failed");
                        }
                    }
                    ProcessOutcome::Consumed | ProcessOutcome::Drop => {
                        traffic.record_drop();
                    }
                }
            }
            TunPacket::Udp {
                source,
                destination,
                payload_offset,
                payload_len,
                ..
            } => {
                traffic.record_udp();
                if self.inbound.should_hijack_dns(destination) {
                    traffic.record_dns();
                }
                let payload_off = ip_offset + payload_offset;
                let payload_end = payload_off + payload_len;
                if payload_end > raw_frame.len() {
                    traffic.record_drop();
                    return;
                }
                let payload = raw_frame[payload_off..payload_end].to_vec();
                self.handle_udp(device, handler, source, destination, payload)
                    .await;
            }
            TunPacket::Other => {
                traffic.record_other();
                traffic.record_drop();
            }
        }
    }

    /// UDP 路径委托给 [`udp_handle::handle_udp_packet`]，与 TunDispatcher 共用同一实现。
    async fn handle_udp(
        &self,
        device: &Arc<dyn TunIo>,
        handler: &ListenerHandler,
        inner_src: SocketAddr,
        outer_dst: SocketAddr,
        payload: Vec<u8>,
    ) {
        let ctx = crate::udp_handle::UdpDispatchCtx {
            nat: self.nat.clone(),
            udp_sessions: self.udp_sessions.clone(),
            inbound: self.inbound.clone(),
            dns_service: self.dns_service.clone(),
            frame_formats: self.frame_formats.clone(),
        };
        crate::udp_handle::handle_udp_packet(&ctx, device, handler, inner_src, outer_dst, payload)
            .await;
    }
}

pub struct SystemDispatcherHandles {
    pump_handle: tokio::task::JoinHandle<()>,
    gc_handle: tokio::task::JoinHandle<()>,
    stack_handle: Mutex<Option<SystemStackHandle>>,
    stop_pump: Option<oneshot::Sender<()>>,
    stop_gc: Option<oneshot::Sender<()>>,
}

impl SystemDispatcherHandles {
    pub fn stop(mut self) {
        if let Some(tx) = self.stop_pump.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.stop_gc.take() {
            let _ = tx.send(());
        }
        self.pump_handle.abort();
        self.gc_handle.abort();
        if let Some(h) = self.stack_handle.lock().take() {
            h.stop();
        }
    }
}

/// 计算 IPv4 地址 +1（用于 sing-tun 风格的 `inet4NextAddress`）。
fn next_ipv4(addr: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
    let n = u32::from(addr);
    n.checked_add(1).map(std::net::Ipv4Addr::from)
}

/// 计算 IPv6 地址 +1（`inet6NextAddress`）。
fn next_ipv6(addr: std::net::Ipv6Addr) -> Option<std::net::Ipv6Addr> {
    let n = u128::from_be_bytes(addr.octets());
    n.checked_add(1)
        .map(|x| std::net::Ipv6Addr::from(x.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_ipv4_increments_address() {
        assert_eq!(
            next_ipv4("172.18.0.1".parse().unwrap()),
            Some("172.18.0.2".parse().unwrap())
        );
        assert_eq!(
            next_ipv4("10.0.0.255".parse().unwrap()),
            Some("10.0.1.0".parse().unwrap())
        );
        assert_eq!(
            next_ipv4("255.255.255.254".parse().unwrap()),
            Some("255.255.255.255".parse().unwrap())
        );
        assert_eq!(next_ipv4("255.255.255.255".parse().unwrap()), None);
    }

    #[test]
    fn next_ipv6_increments_address() {
        assert_eq!(
            next_ipv6("fdfe:dcba:9876::1".parse().unwrap()),
            Some("fdfe:dcba:9876::2".parse().unwrap())
        );
        // 段尾进位
        assert_eq!(
            next_ipv6("fdfe::ffff".parse().unwrap()),
            Some("fdfe::1:0".parse().unwrap())
        );
        // 地址空间末尾
        let max: std::net::Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(next_ipv6(max), None);
    }
}
