//! TUN UDP 派发的统一入口 —— `tun_dispatch::TunDispatcher::handle_udp` 与
//! `system_dispatch::SystemDispatcher::handle_udp` 的公共实现。
//!
//! ## 流水
//! 1. NAT 表登记（仅记账，不参与决策）；
//! 2. **DNS hijack**：53 + `hijack_dns=true` → 用 `fakeip_dns::synthesize` 内联应答；
//! 3. **5-tuple 命中既有 session** → 复用 outbound socket，仅 send + 续 last_seen；
//! 4. **首包**：fake-IP 反查 / 路由策略 → `ListenerHandler.new_packet` 拨号 →
//!    注册 session → 发首包 → spawn reverse loop（外网回包改写成 IP UDP 写回 TUN）。
//!
//! 与 mihomo / sing-tun 的语义对齐：fake-DNS 缺失直接 drop（不 fallback 系统 DNS）。

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use core_resolver::DnsService;
use core_runtime::ListenerHandler;
use tokio::sync::{mpsc, mpsc::error::TrySendError};
use tracing::{debug, info, trace, warn};

use crate::{
    frame_cache::{TunFrameFormatCache, write_ip_packet_to_tun},
    nat::{NatEntry, NatTable},
    tun_inbound::{TunDropReason, TunInbound, build_inbound_metadata},
    tun_io::TunIo,
    udp_session::{PendingUdpSession, UDP_PENDING_QUEUE_CAPACITY},
};

/// 跨 dispatcher 的 UDP 派发上下文（克隆开销 = 几个 `Arc::clone`）。
#[derive(Clone)]
pub struct UdpDispatchCtx {
    pub nat: Arc<NatTable>,
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
    pub inbound: Arc<TunInbound>,
    pub dns_service: Arc<DnsService>,
    pub frame_formats: Arc<TunFrameFormatCache>,
}

/// 处理一帧 TUN UDP 包：DNS hijack / session 复用 / 首包拨号 + reverse loop。
pub async fn handle_udp_packet(
    ctx: &UdpDispatchCtx,
    device: &Arc<dyn TunIo>,
    handler: &ListenerHandler,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
    payload: Vec<u8>,
) {
    // NAT 表按 flow upsert（仅记账；session 复用走 udp_sessions）。
    let now = Instant::now();
    let _ = ctx.nat.insert(NatEntry {
        source: inner_src,
        original_dst: outer_dst,
        fake_host: None,
        network: "udp",
        created_at: now,
        last_seen: now,
    });

    // [1] 53 + hijack_dns → 内联应答，不出网。
    if ctx.inbound.should_hijack_dns(outer_dst) {
        let resp = crate::fakeip_dns::synthesize(&payload, &ctx.dns_service).await;
        debug!(
            target: "capture::traffic",
            network = "udp",
            src = %inner_src,
            dst = %outer_dst,
            query_bytes = payload.len(),
            response_bytes = resp.len(),
            "dns hijack handled in tun"
        );
        if !resp.is_empty() {
            if let Some(pkt) =
                crate::udp_forwarder::build_udp_ip_packet(outer_dst, inner_src, &resp)
            {
                if let Err(e) =
                    write_ip_packet_to_tun(device, &ctx.frame_formats, &pkt, "capture::dns").await
                {
                    warn!(target: "capture::dns", error = %e, "fake-dns write back failed");
                }
            }
        }
        return;
    }

    // [2] 5-tuple 命中既有 session → 复用
    let key = crate::udp_session::UdpFlowKey {
        src: inner_src,
        dst: outer_dst,
    };
    if let Some(session) = ctx.udp_sessions.lookup(&key) {
        let n = payload.len();
        match session
            .socket
            .send_to(&payload, &session.target_host, session.target_port)
            .await
        {
            Ok(_) => {
                handler.record_upload(&session.guard, n as u64);
                session.touch();
                trace!(
                    target: "capture::traffic",
                    conn_id = session.guard.id,
                    network = "udp",
                    src = %inner_src,
                    dst = %outer_dst,
                    target_host = %session.target_host,
                    target_port = session.target_port,
                    upload = n,
                    "udp session upload"
                );
            }
            Err(e) => {
                debug!(target: "capture::udp", error = %e, "reuse send failed; remove session");
                ctx.udp_sessions.remove(&key);
            }
        }
        return;
    }

    // [2.5] flow 已在拨号中：只入队，不阻塞 TUN pump。
    if let Some(pending) = ctx.udp_sessions.lookup_pending(&key) {
        match pending.try_send(payload) {
            Ok(()) => {
                trace!(
                    target: "capture::traffic",
                    network = "udp",
                    src = %inner_src,
                    dst = %outer_dst,
                    "udp pending packet queued"
                );
            }
            Err(TrySendError::Full(_)) => {
                warn!(
                    target: "capture::udp",
                    network = "udp",
                    src = %inner_src,
                    dst = %outer_dst,
                    capacity = UDP_PENDING_QUEUE_CAPACITY,
                    "udp pending queue full; drop packet"
                );
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    target: "capture::udp",
                    network = "udp",
                    src = %inner_src,
                    dst = %outer_dst,
                    "udp pending queue closed; remove pending flow"
                );
                ctx.udp_sessions.remove_pending(&key);
            }
        }
        return;
    }

    // [3] 首包：先 fake-IP 反查 / 路由策略，payload 入 pending queue 后异步 dial。
    let session_meta = match ctx
        .inbound
        .resolve_session("udp", inner_src, outer_dst, None)
    {
        Ok(s) => s,
        Err(TunDropReason::FakeDnsMissing) => {
            warn!(
                target: "capture::udp",
                ip = %outer_dst.ip(),
                port = outer_dst.port(),
                "udp fake DNS record missing; drop (与 mihomo 一致)"
            );
            return;
        }
        Err(reason) => {
            debug!(
                target: "capture::udp",
                ?reason,
                %outer_dst,
                "udp session rejected"
            );
            return;
        }
    };
    debug!(
        target: "capture::traffic",
        network = "udp",
        src = %inner_src,
        dst = %outer_dst,
        host = %session_meta.target.host,
        port = session_meta.target.original_dst_port,
        dns_mode = session_meta.target.dns_mode.as_str(),
        bypass = ?session_meta.bypass,
        payload_len = payload.len(),
        "udp new packet -> ListenerHandler.NewPacket"
    );
    let (pending, rx) = PendingUdpSession::new(UDP_PENDING_QUEUE_CAPACITY);
    if let Err(e) = pending.try_send(payload) {
        warn!(
            target: "capture::udp",
            error = %e,
            src = %inner_src,
            dst = %outer_dst,
            "udp pending first packet enqueue failed"
        );
        return;
    }
    ctx.udp_sessions.insert_pending(key, pending);
    trace!(
        target: "capture::traffic",
        network = "udp",
        src = %inner_src,
        dst = %outer_dst,
        capacity = UDP_PENDING_QUEUE_CAPACITY,
        "udp pending session created"
    );

    let worker_ctx = ctx.clone();
    let dev = device.clone();
    let worker_handler = (*handler).clone();
    tokio::spawn(async move {
        run_udp_dial_worker(
            worker_ctx,
            dev,
            worker_handler,
            key,
            session_meta,
            rx,
            inner_src,
            outer_dst,
        )
        .await;
    });
}

async fn run_udp_dial_worker(
    ctx: UdpDispatchCtx,
    device: Arc<dyn TunIo>,
    handler: ListenerHandler,
    key: crate::udp_session::UdpFlowKey,
    session_meta: crate::tun_inbound::TunSession,
    mut rx: mpsc::Receiver<Vec<u8>>,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
) {
    debug!(
        target: "capture::udp",
        network = "udp",
        src = %inner_src,
        dst = %outer_dst,
        host = %session_meta.target.host,
        port = session_meta.target.original_dst_port,
        "udp dial worker started"
    );
    let prepared = match handler
        .new_packet(build_inbound_metadata(&session_meta, None))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let host = session_meta.target.host.clone();
            let port = session_meta.target.original_dst_port;
            debug!(target: "capture::udp", "[UDP] dial {host}:{port} failed: {e}");
            ctx.udp_sessions.remove_pending(&key);
            return;
        }
    };
    let session = Arc::new(crate::udp_session::UdpSession {
        socket: prepared.socket,
        guard: prepared.guard,
        target_host: prepared.target_host,
        target_port: prepared.target_port,
        last_seen: parking_lot::Mutex::new(Instant::now()),
    });
    ctx.udp_sessions.insert(key, session.clone());
    ctx.udp_sessions.remove_pending(&key);
    {
        let id = session.guard.id;
        let src = inner_src.to_string();
        let host = &session.target_host;
        let port = session.target_port;
        if let Some(b) = session_meta.bypass {
            info!(target: "capture::traffic", "[UDP] #{id} {src} --> {host}:{port} (bypass: {b:?})");
        } else {
            info!(target: "capture::traffic", "[UDP] #{id} {src} --> {host}:{port}");
        }
    }

    spawn_udp_reverse_loop(
        device,
        ctx.frame_formats.clone(),
        ctx.udp_sessions.clone(),
        session.clone(),
        key,
        inner_src,
        outer_dst,
        handler.runtime().metrics.clone(),
    );

    while let Some(payload) = rx.recv().await {
        let n = payload.len();
        match session
            .socket
            .send_to(&payload, &session.target_host, session.target_port)
            .await
        {
            Ok(_) => {
                handler.record_upload(&session.guard, n as u64);
                session.touch();
                trace!(
                    target: "capture::traffic",
                    conn_id = session.guard.id,
                    network = "udp",
                    upload = n,
                    "udp pending payload sent"
                );
            }
            Err(e) => {
                debug!(
                    target: "capture::udp",
                    host = %session.target_host,
                    port = session.target_port,
                    error = %e,
                    "udp pending payload send failed"
                );
                ctx.udp_sessions.remove(&key);
                break;
            }
        }
    }
}

fn spawn_udp_reverse_loop(
    device: Arc<dyn TunIo>,
    frame_formats: Arc<TunFrameFormatCache>,
    sessions: Arc<crate::udp_session::UdpSessionTable>,
    session_for_loop: Arc<crate::udp_session::UdpSession>,
    key: crate::udp_session::UdpFlowKey,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
    metrics: Arc<core_observe::Metrics>,
) {
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
                    let pkt = match crate::udp_forwarder::build_udp_ip_packet(
                        outer_dst, inner_src, &buf[..n],
                    ) {
                        Some(b) => b,
                        None => continue,
                    };
                    if let Err(e) =
                        write_ip_packet_to_tun(&device, &frame_formats, &pkt, "capture::udp").await
                    {
                        warn!(target: "capture::udp", error = %e, "tun write failed");
                        break;
                    }
                    session_for_loop.guard.record_download(n as u64);
                    metrics.add_down(n as u64);
                    session_for_loop.touch();
                    trace!(
                        target: "capture::traffic",
                        conn_id = session_for_loop.guard.id,
                        network = "udp",
                        download = n,
                        "udp payload returned to tun"
                    );
                }
            }
        }
        let up = session_for_loop.guard.up.load(Ordering::Relaxed);
        let down = session_for_loop.guard.down.load(Ordering::Relaxed);
        let id = session_for_loop.guard.id;
        sessions.remove(&key);
        metrics.dec_connection();
        let up_s = crate::tun_pump::format_bytes(up);
        let down_s = crate::tun_pump::format_bytes(down);
        info!(
            target: "capture::traffic",
            "[UDP] #{id} {inner_src} closed | up {up_s} down {down_s}"
        );
    });
}
