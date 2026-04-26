//! 从 TUN 直接消费 packet → 派发到 user-stack（TCP）/ udp_forwarder（UDP）。
//!
//! 与 `platform/<os>.rs` 中"engine 自带 packet loop"互补：
//! * 平台 engine 仅做"看到流就 emit CaptureEvent"（轻量探测）；
//! * 本模块负责 *接管* TUN：读包 → 解析 → 按协议路由：
//!   - TCP → 注入 [`UserSpaceStack`]，由其终结后通过 [`SpliceManager`] 与
//!     `runtime.dial` 的 outbound stream 双向 splice；
//!   - UDP → 调 [`udp_send_one`] 发出，并 spawn [`run_return_loop`] 处理回包；
//!   - 其它协议（ICMP）默认丢弃（M4 后续可选回环）。
//!
//! supervisor 决定启用哪种模式：当 `stack ∈ {gvisor, smoltcp, mixed}`
//! 时启用本派发，并把平台 engine 自带的轻量 emit loop 关掉避免重复。

use std::sync::Arc;
use std::time::Duration;

use core_runtime::Runtime;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, warn};

use crate::eim_nat::EimNatTable;
use crate::engine::CapturePlan;
use crate::nat::{NatEntry, NatTable};
use crate::packet::{parse_ip_packet, L4};
use crate::stack::{AcceptedTcp, SharedStack, SpliceManager, UserSpaceStack};
use crate::tun_io::TunIo;
use crate::udp_forwarder::{run_return_loop, send_one as udp_send_one, UdpForwarderConfig};

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
    /// 5-tuple → outbound socket 复用表 —— 同一 QUIC/STUN session 的所有包
    /// 走同一个 outbound socket，与 mihomo `endpoint_independent_nat` 行为对齐。
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
}

impl TunDispatcher {
    pub fn new(
        plan: CapturePlan,
        nat: Arc<NatTable>,
        eim: Arc<EimNatTable>,
        fake_pool: Arc<core_resolver::FakeIpPool>,
    ) -> Self {
        let stack = Arc::new(Mutex::new(UserSpaceStack::new(
            plan.mtu as usize,
            smoltcp::wire::Ipv4Address(plan.tun_v4_cidr.addr().octets()),
            smoltcp::wire::Ipv6Address(plan.tun_v6_cidr.addr().octets()),
        )));
        let idle = plan.udp_timeout;
        Self {
            plan,
            stack,
            notify: Arc::new(Notify::new()),
            splices: SpliceManager::new(),
            nat,
            eim,
            fake_pool,
            udp_sessions: Arc::new(crate::udp_session::UdpSessionTable::new(idle)),
        }
    }

    /// 启动派发循环 —— spawn 多个 task：
    /// 1. **stack driver**：从 TUN 读包 → user_stack.inject + poll；
    /// 2. **accept consumer**：处理 ESTABLISHED TCP，触发 runtime.dial + splice；
    /// 3. **udp tap**：另一条 TUN 读路径专门处理 UDP（与 stack 共享 TUN 设备时
    ///    必须使用复用方案 —— 本实现采用单 reader + 协议分发，见 `pump_loop`）。
    pub fn start(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        runtime: Arc<Runtime>,
    ) -> TunDispatcherHandles {
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
        let stack_handle = tokio::spawn(async move {
            run_stack_driver(
                stack_dev,
                stack_for_driver,
                notify_for_driver,
                tcp_in_rx,
                accept_tx,
                stop_rx_stack,
            )
            .await;
        });

        // Accept consumer：fake-IP 反查 + dial outbound + spawn splice。
        let runtime_for_accept = runtime.clone();
        let stack_for_accept = self.stack.clone();
        let notify_for_accept = self.notify.clone();
        let splices = self.splices.clone();
        let fake_pool_for_accept = self.fake_pool.clone();
        let accept_handle = tokio::spawn(async move {
            run_accept_consumer(
                accept_rx,
                stack_for_accept,
                notify_for_accept,
                splices,
                runtime_for_accept,
                fake_pool_for_accept,
                stop_rx_accept,
            )
            .await;
        });

        // pump_loop：TUN reader + 协议分发。
        let me = self.clone();
        let runtime_for_pump = runtime.clone();
        let pump_handle = tokio::spawn(async move {
            me.pump_loop(device, runtime_for_pump, tcp_in_tx, stop_rx_pump).await;
        });

        TunDispatcherHandles {
            pump_handle,
            stack_handle,
            accept_handle,
            stop_pump: Some(stop_tx_pump),
            stop_stack: Some(stop_tx_stack),
            stop_accept: Some(stop_tx_accept),
        }
    }

    async fn pump_loop(
        self: Arc<Self>,
        device: Arc<dyn TunIo>,
        runtime: Arc<Runtime>,
        tcp_in_tx: mpsc::Sender<(Vec<u8>, u16)>,
        mut stop_rx: oneshot::Receiver<()>,
    ) {
        let mtu = self.plan.mtu as usize;
        let mut buf = vec![0u8; mtu + 64];
        let cfg = UdpForwarderConfig {
            endpoint_independent_nat: self.plan.endpoint_independent_nat,
            udp_timeout: self.plan.udp_timeout,
        };
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                r = device.read_packet(&mut buf) => {
                    let n = match r {
                        Ok(n) => n,
                        Err(e) => {
                            warn!(target: "capture::dispatch", error = %e, "tun read failed");
                            break;
                        }
                    };
                    let pkt_bytes = buf[..n].to_vec();
                    let parsed = match parse_ip_packet(&pkt_bytes) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    // loopback 排除 / route_address 过滤 —— supervisor 已经在 dispatch
                    // 层做过；这里再守一层避免 user-stack 接管不该接管的流量。
                    let dst_ip = parsed.ip.dst;
                    if self.plan.loopback_addresses.contains(&dst_ip)
                        || self.plan.route_exclude_addresses.iter().any(|n| n.contains(&dst_ip))
                    {
                        continue;
                    }
                    if !self.plan.route_addresses.is_empty()
                        && !self.plan.route_addresses.iter().any(|n| n.contains(&dst_ip))
                    {
                        continue;
                    }
                    match parsed.l4 {
                        L4::Tcp(t) => {
                            // 把整包 + 真实目标端口丢给 user stack；
                            // stack driver 据此动态创建 listener。
                            let _ = tcp_in_tx.send((pkt_bytes, t.dst_port)).await;
                            self.notify.notify_one();
                        }
                        L4::Udp(u) => {
                            let payload_off = parsed.l4_payload_offset(&parsed.l4);
                            let payload_len = parsed.l4_payload_len(&parsed.l4);
                            let payload = pkt_bytes[payload_off..payload_off + payload_len].to_vec();
                            let inner_src = std::net::SocketAddr::new(parsed.ip.src, u.src_port);
                            let outer_dst = std::net::SocketAddr::new(parsed.ip.dst, u.dst_port);
                            self.handle_udp(&cfg, &device, &runtime, inner_src, outer_dst, payload).await;
                        }
                        L4::Other(_) => continue, // ICMP / ICMPv6 暂不处理
                    }
                }
            }
        }
    }

    async fn handle_udp(
        &self,
        _cfg: &UdpForwarderConfig,
        device: &Arc<dyn TunIo>,
        runtime: &Arc<Runtime>,
        inner_src: std::net::SocketAddr,
        outer_dst: std::net::SocketAddr,
        payload: Vec<u8>,
    ) {
        // NAT 表登记（仅记账；session 复用走 udp_sessions）
        let now = std::time::Instant::now();
        let _ = self.nat.insert(NatEntry {
            source: inner_src,
            original_dst: outer_dst,
            fake_host: None,
            network: "udp",
            created_at: now,
            last_seen: now,
        });

        // [1] 53 + hijack_dns → 内联拼 fake-IP 应答，写回 TUN，不出网。
        if outer_dst.port() == 53 && self.plan.hijack_dns {
            let resp = crate::fakeip_dns::synthesize(&payload, &self.fake_pool);
            if !resp.is_empty() {
                if let Some(pkt) =
                    crate::udp_forwarder::build_udp_ip_packet(outer_dst, inner_src, &resp)
                {
                    if let Err(e) = device.write_packet(&pkt).await {
                        warn!(target: "capture::dns", error = %e, "fake-dns write back failed");
                    }
                }
            }
            return;
        }

        // [2] 5-tuple 命中既有 session → 复用 socket，仅 send + 续 last_seen。
        let key = crate::udp_session::UdpFlowKey { src: inner_src, dst: outer_dst };
        if let Some(session) = self.udp_sessions.lookup(&key) {
            let n = payload.len();
            match session
                .socket
                .send_to(&payload, &session.target_host, session.target_port)
                .await
            {
                Ok(_) => {
                    session
                        .guard
                        .up
                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    runtime.metrics.add_up(n as u64);
                    session.touch();
                }
                Err(e) => {
                    debug!(target: "capture::udp", error = %e, "reuse send failed; remove session");
                    self.udp_sessions.remove(&key);
                }
            }
            return;
        }

        // [3] 首包：先 fake-IP 反查再 dial outbound → 注册 session → spawn reverse loop（仅 1 次）。
        let target = crate::dial_meta::build_dial_target(&self.fake_pool, outer_dst, None);
        if target.fake_ip_missing {
            warn!(
                target: "capture::udp",
                ip = %outer_dst.ip(),
                port = outer_dst.port(),
                "udp fake DNS record missing; drop (与 mihomo 一致)"
            );
            return;
        }
        let host = target.host.clone();
        let port = target.original_dst_port;
        let res = match runtime.dial_udp(&host, port).await {
            Ok(r) => r,
            Err(e) => {
                debug!(target: "capture::udp", %host, port, error = %e, "udp dial failed");
                return;
            }
        };
        let meta = core_observe::ConnectionMeta {
            network: "udp".into(),
            kind: "Tun".into(),
            source_ip: inner_src.ip().to_string(),
            source_port: inner_src.port().to_string(),
            destination_ip: outer_dst.ip().to_string(), // 保留原始 fake-IP
            destination_port: outer_dst.port().to_string(),
            inbound_name: "tun".into(),
            host: target.host.clone(),               // 真实 domain
            dns_mode: target.dns_mode.as_str().into(), // "fake-ip" / "normal"
            chains: res.chain.clone(),
            rule: format!("{:?}", res.decision),
            ..core_observe::ConnectionMeta::default()
        };
        let guard = runtime.connections.open(meta);
        let session = Arc::new(crate::udp_session::UdpSession {
            socket: res.socket,
            guard,
            target_host: host.clone(),
            target_port: port,
            last_seen: parking_lot::Mutex::new(std::time::Instant::now()),
        });
        // 首包发送（先 insert 再 send，避免回包先到时找不到 session 把响应丢掉）
        self.udp_sessions.insert(key, session.clone());
        let n = payload.len();
        if let Err(e) = session
            .socket
            .send_to(&payload, &session.target_host, session.target_port)
            .await
        {
            debug!(target: "capture::udp", %host, port, error = %e, "first send failed");
            self.udp_sessions.remove(&key);
            return;
        }
        session
            .guard
            .up
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        runtime.metrics.add_up(n as u64);

        // reverse loop：1 个 session 对应 1 条
        let dev = device.clone();
        let metrics = runtime.metrics.clone();
        let sessions = self.udp_sessions.clone();
        let session_for_loop = session.clone();
        tokio::spawn(async move {
            metrics.inc_connection();
            let cancel = session_for_loop.guard.cancel.clone();
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = cancel.notified() => break,
                    r = session_for_loop.socket.recv_from(&mut buf) => {
                        let n = match r { Ok(n) => n, Err(_) => break };
                        if n == 0 { break }
                        // src=outer_dst（让 app 端 socket 接收），dst=inner_src
                        let pkt = match crate::udp_forwarder::build_udp_ip_packet(
                            outer_dst, inner_src, &buf[..n],
                        ) {
                            Some(b) => b,
                            None => continue,
                        };
                        if let Err(e) = dev.write_packet(&pkt).await {
                            warn!(target: "capture::udp", error = %e, "tun write failed");
                            break;
                        }
                        session_for_loop
                            .guard
                            .down
                            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        metrics.add_down(n as u64);
                        session_for_loop.touch();
                    }
                }
            }
            sessions.remove(&key);
            metrics.dec_connection();
            // session_for_loop 退出作用域 → Arc 引用减 1；若表里也已移除，
            // ConnectionGuard drop → /connections 同步消失。
        });
    }
}

pub struct TunDispatcherHandles {
    pump_handle: tokio::task::JoinHandle<()>,
    stack_handle: tokio::task::JoinHandle<()>,
    accept_handle: tokio::task::JoinHandle<()>,
    stop_pump: Option<oneshot::Sender<()>>,
    stop_stack: Option<oneshot::Sender<()>>,
    stop_accept: Option<oneshot::Sender<()>>,
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
        self.pump_handle.abort();
        self.stack_handle.abort();
        self.accept_handle.abort();
    }
}

/// 简化的 stack driver —— 接收 (pkt, dst_port)，按目标端口动态确保 listener，
/// 注入 stack，poll，写回 TUN。
async fn run_stack_driver(
    device: Arc<dyn TunIo>,
    stack: SharedStack,
    notify: Arc<Notify>,
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
                for pkt in outs {
                    if let Err(e) = device.write_packet(&pkt).await {
                        warn!(target: "capture::stack", error = %e, "tun write failed");
                    }
                }
            }
            _ = notify.notified() => {
                let outs;
                {
                    let mut s = stack.lock();
                    let _ = s.poll();
                    outs = s.drain_outbound();
                }
                for pkt in outs {
                    if let Err(e) = device.write_packet(&pkt).await {
                        warn!(target: "capture::stack", error = %e, "tun write failed (notify)");
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let outs;
                {
                    let mut s = stack.lock();
                    let _ = s.poll();
                    outs = s.drain_outbound();
                }
                for pkt in outs {
                    let _ = device.write_packet(&pkt).await;
                }
            }
        }
    }
    // 退出前清理（旧 dead code 占位移除）
    let _ = device;
}

async fn run_accept_consumer(
    mut accept_rx: mpsc::Receiver<AcceptedTcp>,
    stack: SharedStack,
    notify: Arc<Notify>,
    splices: Arc<SpliceManager>,
    runtime: Arc<Runtime>,
    fake_pool: Arc<core_resolver::FakeIpPool>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            ev = accept_rx.recv() => {
                let Some(ev) = ev else { break };
                // ★ Fake-IP 反查（mihomo `tunnel.preHandleMetadata` 等价）：
                //   把 198.18.x.y 反查回 "www.bilibili.com"，再喂给 outbound。
                //   不反查会让 trojan/vmess 等代理服务器尝试连内部 fake-IP，
                //   表象就是用户报告的"代理可联通但无法出站"。
                let target = crate::dial_meta::build_dial_target(
                    &fake_pool,
                    ev.original_dst,
                    None,
                );
                if target.fake_ip_missing {
                    warn!(
                        target: "capture::accept",
                        ip = %ev.original_dst.ip(),
                        port = ev.original_dst.port(),
                        "fake DNS record missing; abort dial (与 mihomo 一致)"
                    );
                    let mut s = stack.lock();
                    s.close_socket(ev.handle);
                    notify.notify_one();
                    continue;
                }
                debug!(
                    target: "capture::accept",
                    host = %target.host,
                    port = target.original_dst_port,
                    dns_mode = target.dns_mode.as_str(),
                    handle = ?ev.handle,
                    "accept TCP -> dial outbound"
                );
                let dial_res = runtime
                    .dial(&target.host, target.original_dst_port, core_route::NetworkKind::Tcp)
                    .await;
                match dial_res {
                    Ok(res) => {
                        let meta = core_observe::ConnectionMeta {
                            network: "tcp".into(),
                            kind: "Tun".into(),
                            source_ip: ev.remote.ip().to_string(),
                            source_port: ev.remote.port().to_string(),
                            destination_ip: ev.original_dst.ip().to_string(),
                            destination_port: ev.original_dst.port().to_string(),
                            inbound_name: "tun".into(),
                            host: target.host.clone(),               // 真实 domain
                            dns_mode: target.dns_mode.as_str().into(), // "fake-ip"/"normal"/...
                            chains: res.chain.clone(),
                            rule: format!("{:?}", res.decision),
                            ..core_observe::ConnectionMeta::default()
                        };
                        let guard = runtime.connections.open(meta);
                        splices.spawn_splice(
                            ev.handle,
                            stack.clone(),
                            notify.clone(),
                            res.stream,
                            Some(guard),
                            Some(runtime.metrics.clone()),
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "capture::accept",
                            error = %e,
                            host = %target.host,
                            port = target.original_dst_port,
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
