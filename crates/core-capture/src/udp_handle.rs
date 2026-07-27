//! TUN UDP 派发的统一入口 —— `tun_dispatch::TunDispatcher::handle_udp` 与
//! `system_dispatch::SystemDispatcher::handle_udp` 的公共实现。
//!
//! ## 流水
//! 1. NAT 表登记（仅记账，不参与决策）；
//! 2. **DNS hijack**：53 + `hijack_dns=true` → 用 `fakeip_dns::synthesize` 内联应答；
//! 3. 按对称 NAT 或 EIM key 命中 association → 复用 outbound socket；
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
    udp_session::{
        PendingUdpSession, UDP_PENDING_QUEUE_CAPACITY, UDP_SESSION_QUEUE_CAPACITY, UdpDatagram,
        UdpNatKey, UdpSessionReservation,
    },
};

/// 跨 dispatcher 的 UDP 派发上下文（克隆开销 = 几个 `Arc::clone`）。
#[derive(Clone)]
pub struct UdpDispatchCtx {
    pub nat: Arc<NatTable>,
    pub udp_sessions: Arc<crate::udp_session::UdpSessionTable>,
    pub inbound: Arc<TunInbound>,
    pub dns_service: Arc<DnsService>,
    pub frame_formats: Arc<TunFrameFormatCache>,
    pub endpoint_independent_nat: bool,
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

    let key = UdpNatKey::new(inner_src, outer_dst, ctx.endpoint_independent_nat);
    let reservation = ctx.udp_sessions.reserve(key, UDP_PENDING_QUEUE_CAPACITY);
    match reservation {
        UdpSessionReservation::Established(session) => {
            queue_established(ctx, key, session, inner_src, outer_dst, payload);
            return;
        }
        UdpSessionReservation::Pending(pending) => {
            match pending.try_send(UdpDatagram { outer_dst, payload }) {
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
                        "udp pending queue closed"
                    );
                    ctx.udp_sessions.remove_pending_if(key, &pending);
                }
            }
            return;
        }
        UdpSessionReservation::Created { pending, receiver } => {
            if let Err(error) = pending.try_send(UdpDatagram { outer_dst, payload }) {
                warn!(
                    target: "capture::udp",
                    %error,
                    src = %inner_src,
                    dst = %outer_dst,
                    "udp pending first packet enqueue failed"
                );
                ctx.udp_sessions.remove_pending_if(key, &pending);
                return;
            }
            let session_meta = match resolve_udp_session(ctx, inner_src, outer_dst) {
                Some(session) => session,
                None => {
                    ctx.udp_sessions.remove_pending_if(key, &pending);
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
                eim = ctx.endpoint_independent_nat,
                "udp new NAT association -> ListenerHandler.NewPacket"
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
                    pending,
                    session_meta,
                    receiver,
                    inner_src,
                    outer_dst,
                )
                .await;
            });
        }
    }
}

fn resolve_udp_session(
    ctx: &UdpDispatchCtx,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
) -> Option<crate::tun_inbound::TunSession> {
    match ctx
        .inbound
        .resolve_session("udp", inner_src, outer_dst, None)
    {
        Ok(session) => Some(session),
        Err(TunDropReason::FakeDnsMissing) => {
            warn!(
                target: "capture::udp",
                ip = %outer_dst.ip(),
                port = outer_dst.port(),
                "udp fake DNS record missing; drop"
            );
            None
        }
        Err(reason) => {
            debug!(target: "capture::udp", ?reason, %outer_dst, "udp session rejected");
            None
        }
    }
}

fn queue_established(
    ctx: &UdpDispatchCtx,
    key: UdpNatKey,
    session: Arc<crate::udp_session::UdpSession>,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
    payload: Vec<u8>,
) {
    match session.try_send(UdpDatagram { outer_dst, payload }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            warn!(
                target: "capture::udp",
                src = %inner_src,
                dst = %outer_dst,
                capacity = UDP_SESSION_QUEUE_CAPACITY,
                "UDP association send queue full; drop datagram"
            );
        }
        Err(TrySendError::Closed(_)) => {
            ctx.udp_sessions.remove_session_if(key, &session);
        }
    }
}

async fn transmit_datagram(
    ctx: &UdpDispatchCtx,
    handler: &ListenerHandler,
    key: UdpNatKey,
    session: &Arc<crate::udp_session::UdpSession>,
    inner_src: SocketAddr,
    outer_dst: SocketAddr,
    payload: Vec<u8>,
) -> bool {
    let (target_host, target_port, is_new_destination) =
        if let Some((host, port)) = session.destination(outer_dst) {
            (host, port, false)
        } else {
            let Some(meta) = resolve_udp_session(ctx, inner_src, outer_dst) else {
                return false;
            };
            (
                meta.target.host.to_string(),
                meta.target.original_dst_port,
                true,
            )
        };
    let length = payload.len();
    if is_new_destination && !session.socket.supports_multi_target() {
        debug!(
            target: "capture::udp",
            src = %inner_src,
            dst = %outer_dst,
            "outbound UDP carrier is target-bound; rotate EIM association"
        );
        ctx.udp_sessions.remove_session_if(key, session);
        return false;
    }
    if is_new_destination
        && !session.register_destination(outer_dst, target_host.clone(), target_port)
    {
        warn!(
            target: "capture::udp",
            src = %inner_src,
            limit = crate::udp_session::UDP_EIM_DESTINATION_LIMIT,
            "EIM destination limit reached; drop datagram"
        );
        return true;
    }
    match session
        .socket
        .send_to(&payload, &target_host, target_port)
        .await
    {
        Ok(_) => {
            handler.record_upload(&session.guard, length as u64);
            session.touch();
            trace!(
                target: "capture::traffic",
                conn_id = session.guard.id,
                network = "udp",
                src = %inner_src,
                dst = %outer_dst,
                %target_host,
                target_port,
                eim_destinations = session.destination_count(),
                upload = length,
                "udp NAT association upload"
            );
        }
        Err(error) => {
            debug!(target: "capture::udp", %error, "UDP association send failed; remove session");
            ctx.udp_sessions.remove_session_if(key, session);
            return false;
        }
    }
    true
}

async fn run_udp_dial_worker(
    ctx: UdpDispatchCtx,
    device: Arc<dyn TunIo>,
    handler: ListenerHandler,
    key: UdpNatKey,
    pending: Arc<PendingUdpSession>,
    session_meta: crate::tun_inbound::TunSession,
    mut rx: mpsc::Receiver<UdpDatagram>,
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
            ctx.udp_sessions.remove_pending_if(key, &pending);
            return;
        }
    };
    let (session, mut send_rx) = crate::udp_session::UdpSession::new(
        prepared.socket,
        prepared.guard,
        outer_dst,
        prepared.target_host,
        prepared.target_port,
        key.is_endpoint_independent(),
        UDP_SESSION_QUEUE_CAPACITY,
    );
    let session = Arc::new(session);
    if !ctx.udp_sessions.promote(key, &pending, session.clone()) {
        session.cancel();
        return;
    }
    // Promotion removed the pending sender from the table. Drop the worker's
    // last sender so the receiver closes after draining the queued burst.
    drop(pending);
    {
        let id = session.guard.id;
        let src = inner_src.to_string();
        let (host, port) = session
            .destination(outer_dst)
            .expect("initial UDP destination must be registered");
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
        handler.runtime().metrics.clone(),
    );

    while let Some(datagram) = rx.recv().await {
        let destination = datagram.outer_dst;
        if !transmit_datagram(
            &ctx,
            &handler,
            key,
            &session,
            inner_src,
            destination,
            datagram.payload,
        )
        .await
        {
            return;
        }
    }
    let mut cancel = session.cancel_receiver();
    loop {
        if *cancel.borrow() {
            break;
        }
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            },
            datagram = send_rx.recv() => {
                let Some(datagram) = datagram else { break };
                if !transmit_datagram(
                    &ctx,
                    &handler,
                    key,
                    &session,
                    inner_src,
                    datagram.outer_dst,
                    datagram.payload,
                ).await {
                    break;
                }
            }
        }
    }
}

fn spawn_udp_reverse_loop(
    device: Arc<dyn TunIo>,
    frame_formats: Arc<TunFrameFormatCache>,
    sessions: Arc<crate::udp_session::UdpSessionTable>,
    session_for_loop: Arc<crate::udp_session::UdpSession>,
    key: UdpNatKey,
    inner_src: SocketAddr,
    metrics: Arc<core_observe::Metrics>,
) {
    tokio::spawn(async move {
        metrics.inc_connection();
        let mut cancel = session_for_loop.cancel_receiver();
        let mut buf = vec![0u8; 65535];
        loop {
            if *cancel.borrow() {
                break;
            }
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                },
                r = session_for_loop.socket.recv_from_endpoint(&mut buf) => {
                    let (n, transport_source) = match r { Ok(value) => value, Err(_) => break };
                    if n == 0 { break }
                    let Some(logical_source) =
                        session_for_loop.logical_response_source(transport_source)
                    else {
                        debug!(
                            target: "capture::udp",
                            ?transport_source,
                            destinations = session_for_loop.destination_count(),
                            "drop ambiguous endpoint-independent UDP response"
                        );
                        continue;
                    };
                    let pkt = match crate::udp_forwarder::build_udp_ip_packet(
                        logical_source, inner_src, &buf[..n],
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
        sessions.remove_session_if(key, &session_for_loop);
        metrics.dec_connection();
        let up_s = crate::tun_pump::format_bytes(up);
        let down_s = crate::tun_pump::format_bytes(down);
        info!(
            target: "capture::traffic",
            "[UDP] #{id} {inner_src} closed | up {up_s} down {down_s}"
        );
    });
}
