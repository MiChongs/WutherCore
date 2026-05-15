//! 基于 netstack-smoltcp 的 TUN dispatcher —— 对标 sing-tun gVisor stack。
//!
//! 当 `stack: gvisor` 或 `stack: smoltcp` 时使用。TCP 由 netstack-smoltcp
//! 的用户态 TCP 栈处理（TcpListener + TcpStream），UDP 复用现有 udp_handle 路径。

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use core_runtime::{ListenerHandler, Runtime};
use futures::{SinkExt, StreamExt};
use tokio::{sync::oneshot, time::MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::{
    eim_nat::EimNatTable,
    engine::CapturePlan,
    frame_cache::{TunFrameFormatCache, write_ip_packet_to_tun},
    nat::NatTable,
    packet::parse_tun_frame,
    tun_inbound::{TunDropReason, TunInbound, TunPacket, build_inbound_metadata},
    tun_io::TunIo,
    tun_pump::{
        PUMP_BATCH_N, TUN_FRAME_FORMAT_MAX_ENTRIES, TUN_FRAME_FORMAT_TTL, TUN_IDLE_LOG_INTERVAL,
        TUN_TRAFFIC_SUMMARY_INTERVAL, TrafficLog,
    },
};

pub struct NetstackDispatcher {
    pub plan: CapturePlan,
    pub nat: Arc<NatTable>,
    pub eim: Arc<EimNatTable>,
    pub fake_pool: Arc<core_resolver::FakeIpPool>,
    pub dns_service: Arc<core_resolver::DnsService>,
    pub inbound: Arc<TunInbound>,
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
    frame_formats: Arc<TunFrameFormatCache>,
}

impl NetstackDispatcher {
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

    pub fn start(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        runtime: Arc<Runtime>,
    ) -> NetstackDispatcherHandles {
        let mtu = self.plan.mtu as usize;
        let handler = Arc::new(ListenerHandler::new(runtime.clone()));

        // 构建 netstack-smoltcp 栈
        let (stack, runner, _udp_socket, tcp_listener) = netstack_smoltcp::StackBuilder::default()
            .stack_buffer_size(2048)
            .tcp_buffer_size(1024)
            .mtu(mtu)
            .enable_tcp(true)
            .enable_icmp(true)
            .enable_udp(false) // UDP 走现有 udp_handle 路径
            .build()
            .expect("netstack-smoltcp build failed");

        let tcp_listener = tcp_listener.expect("tcp_listener must be Some when enable_tcp=true");

        // spawn runner（netstack-smoltcp 的后台 TCP 状态机驱动）
        let runner = runner.expect("runner must be Some when enable_tcp=true");
        let runner_handle = tokio::spawn(async move {
            if let Err(e) = runner.await {
                warn!(target: "capture::netstack", error = %e, "netstack runner error");
            }
        });

        // 拆分 stack 为 sink（注入包）+ stream（取出包）
        let (stack_sink, stack_stream) = stack.split();

        // 1) TUN pump → stack inject + UDP handle
        let (stop_tx, stop_rx) = oneshot::channel();
        let me = self.clone();
        let dev_for_pump = device.clone();
        let handler_for_pump = handler.clone();
        let stack_sink = Arc::new(tokio::sync::Mutex::new(stack_sink));
        let sink_for_pump = stack_sink.clone();
        let pump_handle = tokio::spawn(async move {
            me.pump_loop(dev_for_pump, handler_for_pump, sink_for_pump, stop_rx)
                .await;
        });

        // 2) stack outbound → TUN write
        let dev_for_out = device.clone();
        let ff_for_out = self.frame_formats.clone();
        let mut stream = stack_stream;
        let outbound_handle = tokio::spawn(async move {
            while let Some(Ok(pkt)) = stream.next().await {
                if let Err(e) =
                    write_ip_packet_to_tun(&dev_for_out, &ff_for_out, &pkt, "capture::netstack")
                        .await
                {
                    warn!(target: "capture::netstack", error = %e, "tun write failed");
                }
            }
            debug!(target: "capture::netstack", "stack outbound stream ended");
        });

        // 3) TCP accept → fake-IP 反查 → handler.prepare_tcp → splice
        let inbound_for_accept = self.inbound.clone();
        let handler_for_accept = handler.clone();
        let dns_service_for_accept = self.dns_service.clone();
        let metrics = runtime.metrics.clone();
        let accept_handle = tokio::spawn(async move {
            run_tcp_accept_loop(
                tcp_listener,
                handler_for_accept,
                inbound_for_accept,
                dns_service_for_accept,
                metrics,
            )
            .await;
        });

        // 4) GC
        let (gc_handle, stop_gc_tx) =
            crate::gc::spawn_tun_gc(self.udp_sessions.clone(), self.plan.udp_timeout);

        info!(
            target: "capture::netstack",
            iface = %device.name(),
            mtu,
            "netstack dispatcher started (netstack-smoltcp TCP + UDP forwarder)"
        );

        NetstackDispatcherHandles {
            pump_handle,
            outbound_handle,
            accept_handle,
            runner_handle,
            gc_handle,
            stop_pump: Some(stop_tx),
            stop_gc: Some(stop_gc_tx),
        }
    }

    async fn pump_loop(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        handler: Arc<ListenerHandler>,
        stack_sink: Arc<
            tokio::sync::Mutex<
                futures::stream::SplitSink<
                    netstack_smoltcp::Stack,
                    netstack_smoltcp::AnyIpPktFrame,
                >,
            >,
        >,
        mut stop_rx: oneshot::Receiver<()>,
    ) {
        let mtu = self.plan.mtu as usize;
        let buf_cap = mtu + 64;
        let mut storage: Vec<Vec<u8>> = (0..PUMP_BATCH_N).map(|_| vec![0u8; buf_cap]).collect();
        let mut sizes = [0usize; PUMP_BATCH_N];
        let iface = device.name().to_string();
        let mut traffic = TrafficLog::new(Instant::now());
        let mut log_tick = tokio::time::interval(TUN_IDLE_LOG_INTERVAL);
        log_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        info!(
            target: "capture::netstack",
            iface = %iface,
            mtu,
            batch = PUMP_BATCH_N,
            "netstack pump loop started"
        );

        loop {
            let mut bufs: Vec<&mut [u8]> = storage.iter_mut().map(|v| v.as_mut_slice()).collect();
            let count = tokio::select! {
                _ = &mut stop_rx => break,
                _ = log_tick.tick() => {
                    drop(bufs);
                    let now = Instant::now();
                    if traffic.idle_warning_due(now, TUN_IDLE_LOG_INTERVAL) {
                        warn!(target: "capture::netstack", iface = %iface, "no packets read");
                    } else if traffic.summary_due(now, TUN_TRAFFIC_SUMMARY_INTERVAL) {
                        info!(target: "capture::traffic", "{}", traffic.format_summary(&iface));
                    }
                    continue;
                }
                r = device.read_batch(&mut bufs, &mut sizes) => {
                    match r {
                        Ok(n) => n,
                        Err(e) => {
                            warn!(target: "capture::netstack", error = %e, "tun read failed");
                            break;
                        }
                    }
                }
            };
            drop(bufs);

            for i in 0..count {
                let raw_frame = &storage[i][..sizes[i]];
                let n = raw_frame.len();
                if traffic.record_read(n) {
                    info!(target: "capture::traffic", iface = %iface, bytes = n, "first tun packet read");
                }
                let parsed_frame = match parse_tun_frame(raw_frame) {
                    Ok(p) => p,
                    Err(_) => {
                        traffic.record_unparsable();
                        continue;
                    }
                };
                let parsed = parsed_frame.packet;
                self.frame_formats.observe(&parsed, parsed_frame.format);
                let pkt_bytes = parsed_frame.ip_packet(raw_frame).to_vec();

                let packet = match self.inbound.classify_packet(&parsed) {
                    Ok(p) => p,
                    Err(_) => {
                        traffic.record_drop();
                        continue;
                    }
                };

                match packet {
                    TunPacket::Tcp { .. } => {
                        traffic.record_tcp();
                        // 注入 netstack-smoltcp — 它内部驱动 TCP 状态机
                        let mut sink = stack_sink.lock().await;
                        if let Err(e) = sink.send(pkt_bytes).await {
                            debug!(target: "capture::netstack", error = %e, "stack inject failed");
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
                        let payload =
                            pkt_bytes[payload_offset..payload_offset + payload_len].to_vec();
                        self.handle_udp(&device, &handler, source, destination, payload)
                            .await;
                    }
                    TunPacket::Other => {
                        traffic.record_other();
                        traffic.record_drop();
                    }
                }
            }
        }
        info!(target: "capture::netstack", iface = %iface, "pump loop stopped");
    }

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

async fn run_tcp_accept_loop(
    mut tcp_listener: netstack_smoltcp::TcpListener,
    handler: Arc<ListenerHandler>,
    inbound: Arc<TunInbound>,
    dns_service: Arc<core_resolver::DnsService>,
    metrics: Arc<core_observe::Metrics>,
) {
    while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
        let handler = handler.clone();
        let inbound = inbound.clone();
        let dns_service = dns_service.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            handle_netstack_tcp(
                stream,
                remote_addr,
                local_addr,
                handler,
                inbound,
                dns_service,
                metrics,
            )
            .await;
        });
    }
    info!(target: "capture::netstack", "tcp accept loop ended");
}

async fn handle_netstack_tcp(
    mut stream: netstack_smoltcp::TcpStream,
    remote_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    handler: Arc<ListenerHandler>,
    inbound: Arc<TunInbound>,
    dns_service: Arc<core_resolver::DnsService>,
    metrics: Arc<core_observe::Metrics>,
) {
    // local_addr = 原始目标（客户端想去的地方），remote_addr = 客户端源
    let original_dst = local_addr;
    let source = remote_addr;

    if inbound.should_hijack_dns(original_dst) {
        info!(target: "capture::dns", network = "tcp", src = %source, dst = %original_dst, "dns tcp hijack in netstack");
        if let Err(e) = crate::fakeip_dns::serve_tcp_stream(stream, dns_service).await {
            warn!(target: "capture::dns", error = %e, "netstack dns tcp hijack failed");
        }
        return;
    }

    let mut initial_payload = Vec::new();
    let target_session = match inbound.resolve_session("tcp", source, original_dst, None) {
        Ok(s) => s,
        Err(TunDropReason::FakeDnsMissing) => {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 8192];
            let sniff_host =
                match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await
                {
                    Ok(Ok(n)) if n > 0 => {
                        initial_payload = buf[..n].to_vec();
                        match core_route::sniff_tcp(&initial_payload) {
                            core_route::L7Proto::Sni(host) if !host.is_empty() => Some(host),
                            _ => None,
                        }
                    }
                    _ => None,
                };
            match inbound.resolve_session("tcp", source, original_dst, sniff_host.as_deref()) {
                Ok(s) => s,
                Err(reason) => {
                    debug!(target: "capture::netstack", ?reason, dst = %original_dst, "tcp rejected after sniff");
                    return;
                }
            }
        }
        Err(reason) => {
            debug!(target: "capture::netstack", ?reason, dst = %original_dst, "tcp rejected");
            return;
        }
    };

    let metadata = build_inbound_metadata(&target_session, Some(original_dst));
    let prepared = match handler.prepare_tcp(metadata).await {
        Ok(p) => p,
        Err(e) => {
            warn!(target: "capture::netstack", error = %e, host = %target_session.target.host, "prepare_tcp failed");
            return;
        }
    };

    let core_runtime::PreparedTcp { mut result, guard } = prepared;
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
    } else {
        info!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} match {}({}) using {proxy}", result.rule, result.rule_payload);
    }

    // replay sniffed initial payload
    if !initial_payload.is_empty() {
        use tokio::io::AsyncWriteExt;
        if let Err(e) = result.stream.write_all(&initial_payload).await {
            warn!(target: "capture::netstack", error = %e, "replay initial payload failed");
            return;
        }
    }

    let started = std::time::Instant::now();
    metrics.inc_connection();
    let accounting = guard.accounting();
    let mut inbound_stream = stream;
    let mut outbound_stream = result.stream;
    let outcome = core_observe::copy_bidirectional_tracked(
        &mut inbound_stream,
        &mut outbound_stream,
        accounting,
        Some(metrics.clone()),
    )
    .await;
    metrics.dec_connection();
    let up = guard.up.load(std::sync::atomic::Ordering::Relaxed);
    let down = guard.down.load(std::sync::atomic::Ordering::Relaxed);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let up_s = crate::tun_pump::format_bytes(up);
    let down_s = crate::tun_pump::format_bytes(down);
    match &outcome {
        Ok(_) => {
            info!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} closed | up {up_s} down {down_s} | {elapsed_ms}ms")
        }
        Err(e) => {
            warn!(target: "capture::traffic", "[TCP] #{conn_id} {src_label} --> {host}:{port} error: {e} | up {up_s} down {down_s} | {elapsed_ms}ms")
        }
    }
}

pub struct NetstackDispatcherHandles {
    pump_handle: tokio::task::JoinHandle<()>,
    outbound_handle: tokio::task::JoinHandle<()>,
    accept_handle: tokio::task::JoinHandle<()>,
    runner_handle: tokio::task::JoinHandle<()>,
    gc_handle: tokio::task::JoinHandle<()>,
    stop_pump: Option<oneshot::Sender<()>>,
    stop_gc: Option<oneshot::Sender<()>>,
}

impl NetstackDispatcherHandles {
    pub fn stop(mut self) {
        if let Some(tx) = self.stop_pump.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.stop_gc.take() {
            let _ = tx.send(());
        }
        self.pump_handle.abort();
        self.outbound_handle.abort();
        self.accept_handle.abort();
        self.runner_handle.abort();
        self.gc_handle.abort();
    }
}
