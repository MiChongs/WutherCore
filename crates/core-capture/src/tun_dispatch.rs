//! 从 TUN 直接消费 packet → 派发到 user-stack（TCP）/ udp_forwarder（UDP）。
//!
//! 与 `platform/<os>.rs` 中"engine 自带 packet loop"互补：
//! * 平台 engine 仅做"看到流就 emit CaptureEvent"（轻量探测）；
//! * 本模块负责 *接管* TUN：读包 → 解析 → 按协议路由：
//!   - TCP → 注入 [`UserSpaceStack`]，由其终结后通过 [`SpliceManager`] 与
//!     `ListenerHandler` 的 outbound stream 双向 splice；
//!   - UDP → 调 `udp_send_one` 发出，并 spawn `run_return_loop` 处理回包；
//!   - 其它协议（ICMP）默认丢弃（M4 后续可选回环）。
//!
//! supervisor 决定启用哪种模式：当 `stack ∈ {gvisor, smoltcp, mixed}`
//! 时启用本派发，并把平台 engine 自带的轻量 emit loop 关掉避免重复。

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use core_runtime::{ListenerHandler, Runtime};
use parking_lot::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc, oneshot},
    time::MissedTickBehavior,
};
use tracing::{debug, info, trace, warn};

use crate::{
    eim_nat::EimNatTable,
    engine::CapturePlan,
    frame_cache::{TunFrameFormatCache, write_ip_packets_to_tun_batch},
    nat::NatTable,
    packet::parse_tun_frame,
    stack::{AcceptedTcp, SharedStack, SpliceManager, UserSpaceStack},
    tun_inbound::{TunDropReason, TunInbound, TunPacket, build_inbound_metadata},
    tun_io::TunIo,
    tun_pump::{
        PUMP_BATCH_N, TUN_FRAME_FORMAT_MAX_ENTRIES, TUN_FRAME_FORMAT_TTL, TUN_IDLE_LOG_INTERVAL,
        TUN_TRAFFIC_SUMMARY_INTERVAL, TrafficLog as TunTrafficLogState,
    },
};

pub struct TunDispatcher {
    pub plan: CapturePlan,
    pub stack: SharedStack,
    pub notify: Arc<Notify>,
    pub splices: Arc<SpliceManager>,
    pub nat: Arc<NatTable>,
    pub eim: Arc<EimNatTable>,
    /// supervisor 持有的 fake-IP 池 —— TUN 内 DNS hijack 直接用，避免
    /// 把 53 流量再经 127.0.0.1:5454 中转（中转包根本不会到达）。
    pub fake_pool: Arc<core_resolver::FakeIpPool>,
    /// DNS hijack 的统一处理链。它内部对接 resolver policy/cache/fake-ip。
    pub dns_service: Arc<core_resolver::DnsService>,
    pub inbound: Arc<TunInbound>,
    /// 5-tuple → outbound socket 复用表 —— 同一 QUIC/STUN session 的所有包
    /// 走同一个 outbound socket，与 mihomo `endpoint_independent_nat` 行为对齐。
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
    frame_formats: Arc<TunFrameFormatCache>,
}

impl TunDispatcher {
    pub fn new(
        plan: CapturePlan,
        nat: Arc<NatTable>,
        eim: Arc<EimNatTable>,
        fake_pool: Arc<core_resolver::FakeIpPool>,
        dns_service: Arc<core_resolver::DnsService>,
        ipset: Arc<dyn crate::ipset::IpSetProvider>,
    ) -> Self {
        let v6_addr = plan
            .tun_v6_cidr
            .map(|c| smoltcp::wire::Ipv6Address(c.addr().octets()));
        let stack = Arc::new(Mutex::new(UserSpaceStack::new(
            plan.mtu as usize,
            smoltcp::wire::Ipv4Address(plan.tun_v4_cidr.addr().octets()),
            v6_addr,
        )));
        let idle = plan.udp_timeout;
        let inbound = Arc::new(TunInbound::new(plan.clone(), fake_pool.clone(), ipset));
        Self {
            plan,
            stack,
            notify: Arc::new(Notify::new()),
            splices: SpliceManager::new(),
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

    /// 启动派发循环 —— spawn 多个 task：
    /// 1. **stack driver**：从 TUN 读包 → user_stack.inject + poll；
    /// 2. **accept consumer**：处理 ESTABLISHED TCP，触发 ListenerHandler + splice；
    /// 3. **udp tap**：另一条 TUN 读路径专门处理 UDP（与 stack 共享 TUN 设备时
    ///    必须使用复用方案 —— 本实现采用单 reader + 协议分发，见 `pump_loop`）。
    pub fn start(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        runtime: Arc<Runtime>,
    ) -> TunDispatcherHandles {
        let summary = crate::tun_logging::root_tun_summary(&self.plan);
        info!(
            target: "capture::tun",
            iface = %device.name(),
            stack = %summary.stack,
            mtu = summary.mtu,
            hijack_dns = summary.hijack_dns,
            route_mode = summary.route_mode,
            route_address_count = summary.route_address_count,
            route_address_set_count = summary.route_address_set_count,
            route_exclude_count = summary.route_exclude_count,
            route_exclude_set_count = summary.route_exclude_set_count,
            udp_timeout_ms = self.plan.udp_timeout.as_millis() as u64,
            "tun dispatcher starting"
        );
        let (stop_tx_pump, stop_rx_pump) = oneshot::channel();
        let (stop_tx_accept, stop_rx_accept) = oneshot::channel();
        let (stop_tx_stack, stop_rx_stack) = oneshot::channel();
        let (accept_tx, accept_rx) = mpsc::channel::<AcceptedTcp>(256);

        // Stack driver：负责把 TCP 包注入 stack，写出 stack 包到 TUN。
        // 但此处我们让 pump_loop 直接控制 TUN 读，并把 TCP 包丢给 stack；
        // run_user_stack 仅负责 stack poll + 写出 + accept 上报。我们用一个
        // mpsc 转发 (TCP 包, 真实目标端口) 给 stack driver —— stack driver
        // 用 dst_port 在注入前确保对应端口有 listener。
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel::<(Vec<u8>, u16)>(1024);

        let stack_dev = device.clone();
        let stack_for_driver = self.stack.clone();
        let notify_for_driver = self.notify.clone();
        let frame_formats_for_driver = self.frame_formats.clone();
        let stack_handle = tokio::spawn(async move {
            run_stack_driver(
                stack_dev,
                stack_for_driver,
                notify_for_driver,
                frame_formats_for_driver,
                tcp_in_rx,
                accept_tx,
                stop_rx_stack,
            )
            .await;
        });

        let handler = Arc::new(ListenerHandler::new(runtime.clone()));

        // Accept consumer：fake-IP 反查 + handler.NewConnection + spawn splice。
        let stack_for_accept = self.stack.clone();
        let notify_for_accept = self.notify.clone();
        let splices = self.splices.clone();
        let inbound_for_accept = self.inbound.clone();
        let dns_service_for_accept = self.dns_service.clone();
        let handler_for_accept = handler.clone();
        let accept_handle = tokio::spawn(async move {
            run_accept_consumer(
                accept_rx,
                stack_for_accept,
                notify_for_accept,
                splices,
                handler_for_accept,
                inbound_for_accept,
                dns_service_for_accept,
                stop_rx_accept,
            )
            .await;
        });

        // pump_loop：TUN reader + 协议分发。
        let me = self.clone();
        let handler_for_pump = handler.clone();
        let pump_handle = tokio::spawn(async move {
            me.pump_loop(device, handler_for_pump, tcp_in_tx, stop_rx_pump)
                .await;
        });

        // 周期 GC：清理过期 UDP session。TCP 由 smoltcp 自治。
        let (gc_handle, stop_tx_gc) =
            crate::gc::spawn_tun_gc(self.udp_sessions.clone(), self.plan.udp_timeout);

        TunDispatcherHandles {
            pump_handle,
            stack_handle,
            accept_handle,
            gc_handle,
            stop_pump: Some(stop_tx_pump),
            stop_stack: Some(stop_tx_stack),
            stop_accept: Some(stop_tx_accept),
            stop_gc: Some(stop_tx_gc),
        }
    }

    async fn pump_loop(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        handler: Arc<ListenerHandler>,
        tcp_in_tx: mpsc::Sender<(Vec<u8>, u16)>,
        mut stop_rx: oneshot::Receiver<()>,
    ) {
        let mtu = self.plan.mtu as usize;
        let buf_cap = mtu + 64;
        let mut storage: Vec<Vec<u8>> = (0..PUMP_BATCH_N).map(|_| vec![0u8; buf_cap]).collect();
        let mut sizes = [0usize; PUMP_BATCH_N];
        let iface = device.name().to_string();
        let summary = crate::tun_logging::root_tun_summary(&self.plan);
        let mut traffic = TunTrafficLogState::new(Instant::now());
        let mut log_tick = tokio::time::interval(TUN_IDLE_LOG_INTERVAL);
        log_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            target: "capture::tun",
            iface = %iface,
            mtu,
            batch = PUMP_BATCH_N,
            stack = %summary.stack,
            auto_route = summary.auto_route,
            auto_redirect = summary.auto_redirect,
            strict_route = summary.strict_route,
            route_mode = summary.route_mode,
            "tun pump loop started"
        );
        loop {
            let mut bufs: Vec<&mut [u8]> = storage.iter_mut().map(|v| v.as_mut_slice()).collect();

            let count = tokio::select! {
                _ = &mut stop_rx => break,
                _ = log_tick.tick() => {
                    drop(bufs);
                    let now = Instant::now();
                    if traffic.idle_warning_due(now, TUN_IDLE_LOG_INTERVAL) {
                        warn!(
                            target: "capture::tun",
                            iface = %iface,
                            elapsed_ms = now.duration_since(traffic.started_at).as_millis() as u64,
                            auto_route = summary.auto_route,
                            auto_redirect = summary.auto_redirect,
                            strict_route = summary.strict_route,
                            route_mode = summary.route_mode,
                            table = summary.table,
                            rule_priority = summary.rule_priority,
                            "tun dispatcher has not read any packet"
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
                            warn!(target: "capture::dispatch", error = %e, "tun read failed");
                            break;
                        }
                    }
                }
            };
            drop(bufs);

            for i in 0..count {
                let raw_frame = &storage[i][..sizes[i]];
                self.process_one_ip_packet(
                    raw_frame,
                    &device,
                    &handler,
                    &tcp_in_tx,
                    &iface,
                    &mut traffic,
                )
                .await;
            }
        }
        info!(
            target: "capture::tun",
            iface = %iface,
            packets = traffic.read_packets,
            bytes = traffic.read_bytes,
            tcp_packets = traffic.tcp_packets,
            udp_packets = traffic.udp_packets,
            other_packets = traffic.other_packets,
            dns_packets = traffic.dns_packets,
            dropped_packets = traffic.dropped_packets,
            unparsable_packets = traffic.unparsable_packets,
            "tun pump loop stopped"
        );
    }

    /// 处理 1 个 IP 包 —— 从 pump_loop 抽出，方便 batch 路径循环调用。
    /// smoltcp 路径不在原地改写，所以 raw_frame 是 `&[u8]`。
    async fn process_one_ip_packet(
        &self,
        raw_frame: &[u8],
        device: &Arc<dyn TunIo>,
        handler: &ListenerHandler,
        tcp_in_tx: &mpsc::Sender<(Vec<u8>, u16)>,
        iface: &str,
        traffic: &mut TunTrafficLogState,
    ) {
        let n = raw_frame.len();
        if traffic.record_read(n) {
            info!(
                target: "capture::traffic",
                iface = %iface,
                bytes = n,
                "first tun packet read"
            );
        }
        let parsed_frame = match parse_tun_frame(raw_frame) {
            Ok(p) => p,
            Err(e) => {
                traffic.record_unparsable();
                if traffic.should_log_unparsable_detail() {
                    debug!(
                        target: "capture::traffic",
                        bytes = n,
                        error = %e,
                        head = %hex_head(raw_frame, 24),
                        "drop unparsable tun frame"
                    );
                }
                return;
            }
        };
        let parsed = parsed_frame.packet;
        self.frame_formats.observe(&parsed, parsed_frame.format);
        let pkt_bytes = parsed_frame.ip_packet(raw_frame).to_vec();
        debug!(
            target: "capture::traffic",
            bytes = n,
            ip_bytes = pkt_bytes.len(),
            frame = ?parsed_frame.format,
            ip_offset = parsed_frame.ip_offset,
            src = %parsed.ip.src,
            dst = %parsed.ip.dst,
            "tun packet read"
        );
        let packet = match self.inbound.classify_packet(&parsed) {
            Ok(packet) => packet,
            Err(reason) => {
                traffic.record_drop();
                debug!(
                    target: "capture::tun",
                    src = %parsed.ip.src,
                    dst = %parsed.ip.dst,
                    ?reason,
                    "packet skipped by TUN inbound policy"
                );
                return;
            }
        };
        match packet {
            TunPacket::Tcp { dst_port, .. } => {
                traffic.record_tcp();
                debug!(
                    target: "capture::traffic",
                    dst_port,
                    bytes = n,
                    "dispatch tcp packet to user stack"
                );
                let _ = tcp_in_tx.send((pkt_bytes, dst_port)).await;
                self.notify.notify_one();
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
                let payload_off = payload_offset;
                let payload = pkt_bytes[payload_off..payload_off + payload_len].to_vec();
                debug!(
                    target: "capture::traffic",
                    network = "udp",
                    src = %source,
                    dst = %destination,
                    payload_len,
                    "dispatch udp packet"
                );
                self.handle_udp(device, handler, source, destination, payload)
                    .await;
            }
            TunPacket::Other => {
                traffic.record_other();
                traffic.record_drop();
                debug!(
                    target: "capture::traffic",
                    src = %parsed.ip.src,
                    dst = %parsed.ip.dst,
                    "drop unsupported non-tcp-udp packet"
                );
            }
        }
    }

    /// UDP 派发委托给 [`udp_handle::handle_udp_packet`]，与 SystemDispatcher 共用同一实现。
    async fn handle_udp(
        &self,
        device: &Arc<dyn TunIo>,
        handler: &ListenerHandler,
        inner_src: std::net::SocketAddr,
        outer_dst: std::net::SocketAddr,
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

pub struct TunDispatcherHandles {
    pump_handle: tokio::task::JoinHandle<()>,
    stack_handle: tokio::task::JoinHandle<()>,
    accept_handle: tokio::task::JoinHandle<()>,
    gc_handle: tokio::task::JoinHandle<()>,
    stop_pump: Option<oneshot::Sender<()>>,
    stop_stack: Option<oneshot::Sender<()>>,
    stop_accept: Option<oneshot::Sender<()>>,
    stop_gc: Option<oneshot::Sender<()>>,
}

impl TunDispatcherHandles {
    pub fn stop(mut self) {
        if let Some(tx) = self.stop_pump.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.stop_stack.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.stop_accept.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.stop_gc.take() {
            let _ = tx.send(());
        }
        self.pump_handle.abort();
        self.stack_handle.abort();
        self.accept_handle.abort();
        self.gc_handle.abort();
    }
}

/// 简化的 stack driver —— 接收 (pkt, dst_port)，按目标端口动态确保 listener，
/// 注入 stack，poll，写回 TUN。
async fn run_stack_driver(
    device: Arc<dyn TunIo>,
    stack: SharedStack,
    notify: Arc<Notify>,
    frame_formats: Arc<TunFrameFormatCache>,
    mut tcp_in_rx: mpsc::Receiver<(Vec<u8>, u16)>,
    accept_tx: mpsc::Sender<AcceptedTcp>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            pkt = tcp_in_rx.recv() => {
                let Some((p, dst_port)) = pkt else { break };
                let outs;
                let accepted;
                {
                    let mut s = stack.lock();
                    // ⭐ 注入前先按目标端口准备 listener；smoltcp 没有"任意端口监听"，
                    // 必须为每个真实出现过的目标端口持有至少一个 LISTEN socket。
                    s.ensure_listener_for(dst_port, crate::stack::DEFAULT_LISTENER_POOL);
                    s.inject(p);
                    let _ = s.poll();
                    accepted = s.drain_accepted();
                    // accept 后补一个新 listener 让同端口下一条流也能接进来
                    s.ensure_listener_for(dst_port, crate::stack::DEFAULT_LISTENER_POOL);
                    outs = s.drain_outbound();
                }
                for evt in accepted {
                    let _ = accept_tx.try_send(evt);
                }
                if let Err(e) =
                    write_ip_packets_to_tun_batch(&device, &frame_formats, outs, "capture::stack")
                        .await
                {
                    warn!(target: "capture::stack", error = %e, "tun write batch failed");
                }
            }
            _ = notify.notified() => {
                let outs;
                {
                    let mut s = stack.lock();
                    let _ = s.poll();
                    outs = s.drain_outbound();
                }
                if let Err(e) =
                    write_ip_packets_to_tun_batch(&device, &frame_formats, outs, "capture::stack")
                        .await
                {
                    warn!(target: "capture::stack", error = %e, "tun write batch failed (notify)");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let outs;
                {
                    let mut s = stack.lock();
                    let _ = s.poll();
                    outs = s.drain_outbound();
                }
                let _ = write_ip_packets_to_tun_batch(
                    &device,
                    &frame_formats,
                    outs,
                    "capture::stack",
                )
                .await;
            }
        }
    }
    // 退出前清理（旧 dead code 占位移除）
    let _ = device;
}

async fn read_initial_payload_for_sniff(
    handle: smoltcp::iface::SocketHandle,
    stack: SharedStack,
    notify: Arc<Notify>,
) -> Vec<u8> {
    let mut stream = crate::stack::SmolStream::new(handle, stack, notify);
    let mut buf = vec![0u8; 8192];
    match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            buf
        }
        _ => Vec::new(),
    }
}

fn sniff_host_from_payload(payload: &[u8]) -> Option<String> {
    match core_route::sniff_tcp(payload) {
        core_route::L7Proto::Sni(host) if !host.is_empty() => Some(host),
        _ => None,
    }
}

fn hex_head(buf: &[u8], max: usize) -> String {
    let mut out = String::new();
    for (idx, b) in buf.iter().take(max).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

async fn run_accept_consumer(
    mut accept_rx: mpsc::Receiver<AcceptedTcp>,
    stack: SharedStack,
    notify: Arc<Notify>,
    splices: Arc<SpliceManager>,
    handler: Arc<ListenerHandler>,
    inbound: Arc<TunInbound>,
    dns_service: Arc<core_resolver::DnsService>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            ev = accept_rx.recv() => {
                let Some(ev) = ev else { break };
                // ★ Fake-IP 反查（mihomo `tunnel.preHandleMetadata` 等价）：
                //   把 198.18.x.y 反查回 "www.bilibili.com"，再喂给 outbound。
                //   若 fake-IP 记录缺失，按 mihomo 的 TCP sniff fallback 尝试从
                //   首段 TLS ClientHello 提取 SNI，避免缓存过期时直接断流。
                let mut initial_payload = Vec::new();
                let mut sniff_host = None;
                let target_session = match inbound.resolve_session("tcp", ev.remote, ev.original_dst, None) {
                    Ok(session) => session,
                    Err(TunDropReason::FakeDnsMissing) => {
                        initial_payload = read_initial_payload_for_sniff(
                            ev.handle,
                            stack.clone(),
                            notify.clone(),
                        ).await;
                        sniff_host = sniff_host_from_payload(&initial_payload);
                        match inbound.resolve_session(
                            "tcp",
                            ev.remote,
                            ev.original_dst,
                            sniff_host.as_deref(),
                        ) {
                            Ok(session) => session,
                            Err(_) => {
                                warn!(
                                    target: "capture::accept",
                                    ip = %ev.original_dst.ip(),
                                    port = ev.original_dst.port(),
                                    "fake DNS record missing and sniff failed; abort dial (与 mihomo 一致)"
                                );
                                let mut s = stack.lock();
                                s.close_socket(ev.handle);
                                notify.notify_one();
                                continue;
                            }
                        }
                    }
                    Err(reason) => {
                        debug!(
                            target: "capture::accept",
                            ?reason,
                            dst = %ev.original_dst,
                            "tcp session rejected"
                        );
                        let mut s = stack.lock();
                        s.close_socket(ev.handle);
                        notify.notify_one();
                        continue;
                    }
                };
                debug!(
                    target: "capture::traffic",
                    network = "tcp",
                    src = %ev.remote,
                    dst = %ev.original_dst,
                    host = %target_session.target.host,
                    port = target_session.target.original_dst_port,
                    dns_mode = target_session.target.dns_mode.as_str(),
                    bypass = ?target_session.bypass,
                    handle = ?ev.handle,
                    "tcp accepted -> ListenerHandler.NewConnection"
                );
                if inbound.should_hijack_dns(target_session.original_dst) {
                    info!(
                        target: "capture::dns",
                        network = "tcp",
                        src = %ev.remote,
                        dst = %ev.original_dst,
                        host = %target_session.target.host,
                        "dns tcp hijack handled in tun"
                    );
                    handler.runtime().metrics.inc_dns();
                    let stream = crate::stack::SmolStream::new(
                        ev.handle,
                        stack.clone(),
                        notify.clone(),
                    );
                    if let Err(e) =
                        crate::fakeip_dns::serve_tcp_stream(stream, dns_service.clone()).await
                    {
                        warn!(
                            target: "capture::dns",
                            error = %e,
                            src = %ev.remote,
                            dst = %ev.original_dst,
                            "dns tcp hijack failed"
                        );
                    }
                    continue;
                }
                let prepared = handler
                    .prepare_tcp(build_inbound_metadata(&target_session, Some(ev.local)))
                    .await;
                match prepared {
                    Ok(prepared) => {
                        let core_runtime::PreparedTcp { result, guard } = prepared;
                        {
                            let id = guard.id;
                            let src = ev.remote.to_string();
                            let host = &target_session.target.host;
                            let port = target_session.target.original_dst_port;
                            let proxy = if result.chain.len() > 1 {
                                result.chain.join(" >> ")
                            } else {
                                result.outbound.clone()
                            };
                            if result.rule.is_empty() {
                                info!(target: "capture::traffic", "[TCP] #{id} {src} --> {host}:{port} using {proxy}");
                            } else if result.rule_payload.is_empty() {
                                info!(target: "capture::traffic", "[TCP] #{id} {src} --> {host}:{port} match {} using {proxy}", result.rule);
                            } else {
                                info!(target: "capture::traffic", "[TCP] #{id} {src} --> {host}:{port} match {}({}) using {proxy}", result.rule, result.rule_payload);
                            }
                        }
                        let mut stream = result.stream;
                        if !initial_payload.is_empty() {
                            if let Err(e) = stream.write_all(&initial_payload).await {
                                warn!(
                                    target: "capture::accept",
                                    error = %e,
                                    host = %target_session.target.host,
                                    port = target_session.target.original_dst_port,
                                    "write sniffed initial payload failed"
                                );
                                let mut s = stack.lock();
                                s.close_socket(ev.handle);
                                notify.notify_one();
                                continue;
                            }
                            handler.record_upload(&guard, initial_payload.len() as u64);
                            trace!(
                                target: "capture::traffic",
                                conn_id = guard.id,
                                network = "tcp",
                                upload = initial_payload.len(),
                                "tcp sniffed initial payload replayed"
                            );
                        }
                        if let Some(host) = sniff_host.as_deref() {
                            debug!(
                                target: "capture::accept",
                                sniff_host = %host,
                                "fake-ip missing recovered by TCP SNI sniff"
                            );
                        }
                        splices.spawn_splice(
                            ev.handle,
                            stack.clone(),
                            notify.clone(),
                            stream,
                            Some(guard),
                            Some(handler.runtime().metrics.clone()),
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "capture::accept",
                            error = %e,
                            host = %target_session.target.host,
                            port = target_session.target.original_dst_port,
                            "outbound dial failed"
                        );
                        let mut s = stack.lock();
                        s.close_socket(ev.handle);
                        notify.notify_one();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_traffic_state_reports_idle_until_first_packet() {
        let start = Instant::now();
        let mut state = TunTrafficLogState::new(start);

        assert!(!state.idle_warning_due(
            start + TUN_IDLE_LOG_INTERVAL - Duration::from_millis(1),
            TUN_IDLE_LOG_INTERVAL
        ));
        assert!(state.idle_warning_due(start + TUN_IDLE_LOG_INTERVAL, TUN_IDLE_LOG_INTERVAL));
        assert!(!state.idle_warning_due(
            start + TUN_IDLE_LOG_INTERVAL + Duration::from_millis(1),
            TUN_IDLE_LOG_INTERVAL
        ));

        assert!(state.record_read(128));
        assert!(!state.idle_warning_due(start + TUN_IDLE_LOG_INTERVAL * 2, TUN_IDLE_LOG_INTERVAL));
    }

    #[test]
    fn tun_traffic_state_summarizes_only_new_packets_after_interval() {
        let start = Instant::now();
        let mut state = TunTrafficLogState::new(start);

        assert!(state.record_read(64));
        state.record_tcp();
        assert!(!state.summary_due(
            start + TUN_TRAFFIC_SUMMARY_INTERVAL - Duration::from_millis(1),
            TUN_TRAFFIC_SUMMARY_INTERVAL
        ));
        assert!(state.summary_due(
            start + TUN_TRAFFIC_SUMMARY_INTERVAL,
            TUN_TRAFFIC_SUMMARY_INTERVAL
        ));
        assert!(!state.summary_due(
            start + TUN_TRAFFIC_SUMMARY_INTERVAL * 2,
            TUN_TRAFFIC_SUMMARY_INTERVAL
        ));

        assert!(!state.record_read(96));
        state.record_udp();
        state.record_dns();
        assert!(state.summary_due(
            start + TUN_TRAFFIC_SUMMARY_INTERVAL * 2,
            TUN_TRAFFIC_SUMMARY_INTERVAL
        ));
        assert_eq!(state.read_packets, 2);
        assert_eq!(state.read_bytes, 160);
        assert_eq!(state.tcp_packets, 1);
        assert_eq!(state.udp_packets, 1);
        assert_eq!(state.dns_packets, 1);
    }

    // frame_format_cache 相关测试已迁移到 `frame_cache::tests`。
}
