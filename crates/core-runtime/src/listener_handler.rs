//! Unified inbound handoff, equivalent to mihomo's `ListenerHandler`.
//!
//! Inbound protocol implementations should stop making their own routing,
//! connection-table and accounting decisions. They normalize protocol-specific
//! facts into [`InboundMetadata`] and enter this handler through
//! [`ListenerHandler::new_connection`] or [`ListenerHandler::new_packet`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use compact_str::ToCompactString;
use core_observe::{copy_bidirectional_tracked, ConnectionGuard, ConnectionMeta};
use core_route::{FlowContext, L7Proto, NetworkKind};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use crate::engine::{DialResult, RoutePick, Runtime, UdpDialResult};

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[derive(Debug, Clone)]
pub struct InboundMetadata {
    pub network: NetworkKind,
    pub inbound_name: String,
    pub kind: String,
    pub source: SocketAddr,
    pub inbound: Option<SocketAddr>,
    pub destination_ip: Option<IpAddr>,
    pub route_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub host: String,
    pub dns_mode: String,
    pub sniff_host: String,
    pub process: Option<String>,
    pub process_path: Option<String>,
    pub protocol: Option<L7Proto>,
    pub force_direct: bool,
    pub force_direct_reason: String,
    /// mihomo `C.INNER` 对标：WutherCore 内部组件（DNS resolver、ruleset fetch）
    /// 发起的连接。inner 连接跳过 loopback self-capture 检测，因为它们的 source
    /// 地址可能是 TUN gateway IP（已知安全，不是自抓回环）。
    pub is_inner: bool,
}

impl InboundMetadata {
    pub fn tcp(
        inbound_name: impl Into<String>,
        kind: impl Into<String>,
        source: SocketAddr,
        inbound: SocketAddr,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self::new(
            NetworkKind::Tcp,
            inbound_name,
            kind,
            source,
            Some(inbound),
            host,
            port,
        )
    }

    pub fn udp(
        inbound_name: impl Into<String>,
        kind: impl Into<String>,
        source: SocketAddr,
        inbound: Option<SocketAddr>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self::new(
            NetworkKind::Udp,
            inbound_name,
            kind,
            source,
            inbound,
            host,
            port,
        )
    }

    pub fn new(
        network: NetworkKind,
        inbound_name: impl Into<String>,
        kind: impl Into<String>,
        source: SocketAddr,
        inbound: Option<SocketAddr>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        let host = host.into();
        let ip = host.parse::<IpAddr>().ok();
        Self {
            network,
            inbound_name: inbound_name.into(),
            kind: kind.into(),
            source,
            inbound,
            destination_ip: ip,
            route_ip: ip,
            destination_port: port,
            host,
            dns_mode: "normal".into(),
            sniff_host: String::new(),
            process: None,
            process_path: None,
            protocol: None,
            force_direct: false,
            force_direct_reason: String::new(),
            is_inner: false,
        }
    }

    pub fn with_destination_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.destination_ip = ip;
        self
    }

    pub fn with_route_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.route_ip = ip;
        self
    }

    pub fn with_dns_mode(mut self, dns_mode: impl Into<String>) -> Self {
        self.dns_mode = dns_mode.into();
        self
    }

    pub fn with_sniff_host(mut self, sniff_host: impl Into<String>) -> Self {
        self.sniff_host = sniff_host.into();
        self
    }

    pub fn with_process(mut self, process: Option<String>, process_path: Option<String>) -> Self {
        self.process = process;
        self.process_path = process_path;
        self
    }

    pub fn with_protocol(mut self, protocol: Option<L7Proto>) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn with_force_direct(mut self, reason: impl Into<String>) -> Self {
        self.force_direct = true;
        self.force_direct_reason = reason.into();
        self
    }

    pub fn with_inner(mut self) -> Self {
        self.is_inner = true;
        self
    }

    pub fn with_inbound_addr(mut self, inbound: Option<SocketAddr>) -> Self {
        self.inbound = inbound;
        self
    }

    pub fn target_host(&self) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_string();
        }
        if !self.sniff_host.trim().is_empty() {
            return self.sniff_host.trim().to_string();
        }
        self.destination_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    }

    pub fn route_host(&self) -> String {
        if !self.sniff_host.trim().is_empty() {
            return self.sniff_host.trim().to_string();
        }
        self.target_host()
    }

    pub fn flow_context(&self) -> FlowContext {
        let host = self.route_host();
        let ip = self.route_ip.or_else(|| host.parse::<IpAddr>().ok());
        FlowContext {
            host,
            ip,
            port: self.destination_port,
            network: self.network,
            process: self.process.clone(),
            protocol: self.protocol.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ListenerHandler {
    runtime: Arc<Runtime>,
}

pub struct PreparedTcp {
    pub result: DialResult,
    pub guard: ConnectionGuard,
}

pub struct PreparedUdpPacket {
    pub socket: core_outbound::adapter::BoxedUdp,
    pub guard: ConnectionGuard,
    pub target_host: String,
    pub target_port: u16,
}

impl ListenerHandler {
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }

    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    pub fn route(&self, metadata: &InboundMetadata) -> RoutePick {
        self.runtime
            .pick_outbound_for_context(metadata.flow_context())
    }

    pub async fn dial_tcp(&self, metadata: &InboundMetadata) -> io::Result<DialResult> {
        if metadata.force_direct {
            return self
                .runtime
                .dial_direct_with_context(
                    metadata.flow_context(),
                    metadata.force_direct_reason.clone(),
                )
                .await;
        }
        self.runtime
            .dial_with_context(metadata.flow_context())
            .await
    }

    pub async fn dial_udp(&self, metadata: &InboundMetadata) -> io::Result<UdpDialResult> {
        let mut ctx = metadata.flow_context();
        ctx.network = NetworkKind::Udp;
        if metadata.force_direct {
            return self
                .runtime
                .dial_udp_direct_with_context(ctx, metadata.force_direct_reason.clone())
                .await;
        }
        self.runtime.dial_udp_with_context(ctx).await
    }

    pub async fn prepare_tcp(&self, metadata: InboundMetadata) -> io::Result<PreparedTcp> {
        self.reject_loopback_self_capture(&metadata)?;
        let metadata = self.enrich_with_process(metadata, NetworkKind::Tcp).await;
        let result = self.dial_tcp(&metadata).await?;
        let guard = self.open_tcp(&metadata, &result);
        Ok(PreparedTcp { result, guard })
    }

    pub async fn prepare_udp(&self, metadata: InboundMetadata) -> io::Result<PreparedUdpPacket> {
        self.reject_loopback_self_capture(&metadata)?;
        let metadata = self.enrich_with_process(metadata, NetworkKind::Udp).await;
        let target_host = metadata.target_host();
        let target_port = metadata.destination_port;
        let result = self.dial_udp(&metadata).await?;
        if metadata.kind == "Tun" {
            let src_label = if metadata.is_inner {
                "WutherCore".to_string()
            } else {
                metadata.source.to_string()
            };
            let proxy = if result.chain.len() > 1 {
                result.chain.join(" >> ")
            } else {
                result.outbound.clone()
            };
            if result.rule.is_empty() {
                info!(target: "capture::traffic", "[UDP] {} --> {}:{} using {}", src_label, target_host, target_port, proxy);
            } else if result.rule_payload.is_empty() {
                info!(target: "capture::traffic", "[UDP] {} --> {}:{} match {} using {}", src_label, target_host, target_port, result.rule, proxy);
            } else {
                info!(target: "capture::traffic", "[UDP] {} --> {}:{} match {}({}) using {}", src_label, target_host, target_port, result.rule, result.rule_payload, proxy);
            }
        }
        let meta = udp_connection_meta(&metadata, &result);
        let guard = self.runtime.connections.open(meta);
        Ok(PreparedUdpPacket {
            socket: result.socket,
            guard,
            target_host,
            target_port,
        })
    }

    pub async fn new_packet(&self, metadata: InboundMetadata) -> io::Result<PreparedUdpPacket> {
        self.prepare_udp(metadata).await
    }

    fn reject_loopback_self_capture(&self, metadata: &InboundMetadata) -> io::Result<()> {
        if metadata.is_inner {
            tracing::debug!(
                target: "listener::inner",
                network = metadata.network.as_str(),
                src = %metadata.source,
                host = %metadata.target_host(),
                port = metadata.destination_port,
                "bypass loopback check (inner connection from WutherCore)"
            );
            return Ok(());
        }
        let rejected = match metadata.network {
            NetworkKind::Tcp => core_outbound::is_loopback_tcp_source(metadata.source),
            NetworkKind::Udp => core_outbound::is_loopback_udp_source(metadata.source),
        };
        if !rejected {
            return Ok(());
        }

        warn!(
            target: "listener::loopback",
            "[{}] {} --> {}:{} BLOCKED (loopback self-capture via {})",
            metadata.network.as_str().to_uppercase(),
            metadata.source,
            metadata.target_host(),
            metadata.destination_port,
            metadata.inbound_name,
        );
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "loopback self-capture: {} {} -> {}:{}",
                metadata.network.as_str(),
                metadata.source,
                metadata.target_host(),
                metadata.destination_port
            ),
        ))
    }

    pub async fn new_connection<S>(&self, inbound: S, metadata: InboundMetadata) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let prepared = self.prepare_tcp(metadata).await?;
        self.relay_prepared_tcp(inbound, prepared).await
    }

    pub fn open_tcp(&self, metadata: &InboundMetadata, result: &DialResult) -> ConnectionGuard {
        self.runtime
            .connections
            .open(tcp_connection_meta(metadata, result))
    }

    /// 与 mihomo `tunnel.handleTCPConn`/`handleUDPConn` 的 `findProcessMode`
    /// 分支等价：根据全局开关 + 路由规则需求决定是否反查发起进程。结果填进
    /// [`InboundMetadata::process`] / `process_path`，向下穿透到 ConnectionMeta。
    ///
    /// 反查 API 是同步阻塞调用（Linux `/proc` 扫描、Windows `GetExtendedTcpTable`、
    /// macOS `proc_pidfdinfo`），全部走 `spawn_blocking` 防止抢 reactor 线程。
    /// 已在 finder 上层加了 LRU+TTL cache，绝大多数命中走 cache 路径直接返回。
    async fn enrich_with_process(
        &self,
        mut metadata: InboundMetadata,
        _network: NetworkKind,
    ) -> InboundMetadata {
        if metadata.process.is_some() {
            return metadata;
        }
        if metadata.is_inner {
            return metadata;
        }
        let finder = match self.runtime.process_finder.as_ref() {
            Some(f) => f.clone(),
            None => return metadata,
        };
        let proto = match metadata.network {
            NetworkKind::Tcp => core_process::NetworkProto::Tcp,
            NetworkKind::Udp => core_process::NetworkProto::Udp,
        };
        let src_ip = metadata.source.ip();
        let src_port = metadata.source.port();
        // dst tuple 的语义对齐 Android ConnectivityManager.getConnectionOwnerUid
        // 期望的"内核 socket 的 remote 端"：
        // * TUN / TPROXY / Redir：app 直接连原始目标，dst = (destination_ip,
        //   destination_port)；
        // * Mixed / SOCKS / HTTP listener：app 连我们这台机的 listener，dst =
        //   metadata.inbound 的本机地址。
        // 取不到时退回 destination_ip:destination_port —— 非 Android finder 会
        // 忽略 dst，对 Linux/Windows/macOS 路径无副作用。
        let kind = metadata.kind.as_str();
        let dst = if matches!(kind, "Tun" | "TPROXY" | "Redirect") {
            metadata
                .destination_ip
                .map(|ip| (ip, metadata.destination_port))
        } else if let Some(inbound) = metadata.inbound {
            Some((inbound.ip(), inbound.port()))
        } else {
            metadata
                .destination_ip
                .map(|ip| (ip, metadata.destination_port))
        };
        let info = tokio::task::spawn_blocking(move || match dst {
            Some((dst_ip, dst_port)) => {
                finder.find_with_dst(proto, src_ip, src_port, dst_ip, dst_port)
            }
            None => finder.find(proto, src_ip, src_port),
        })
        .await
        .ok()
        .flatten();
        if let Some(info) = info {
            metadata.process = Some(info.name);
            metadata.process_path = Some(info.path);
        }
        metadata
    }

    pub fn record_upload(&self, guard: &ConnectionGuard, size: u64) {
        guard.record_upload(size);
        self.runtime.metrics.add_up(size);
    }

    pub fn record_download(&self, guard: &ConnectionGuard, size: u64) {
        guard.record_download(size);
        self.runtime.metrics.add_down(size);
    }

    pub async fn relay_prepared_tcp<S>(
        &self,
        mut inbound: S,
        mut prepared: PreparedTcp,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let started = std::time::Instant::now();
        let id = prepared.guard.id;
        let accounting = prepared.guard.accounting();
        let outbound = prepared.result.outbound.clone();
        let dial_ms = prepared.result.elapsed.as_millis() as u64;
        self.runtime.metrics.inc_connection();
        // 用 connection table 反查 process+host 标签 —— meta 在 prepare_tcp 阶段
        // 已经填到 table 里，不必让 PreparedTcp 多带 String 字段。
        let label = self.runtime.connections.label_for(id);
        info!(
            target: "relay",
            "[Relay] #{id} {label} via {outbound} (dial {dial_ms}ms)"
        );

        let metrics = self.runtime.metrics.clone();
        let result = copy_bidirectional_tracked(
            &mut inbound,
            &mut prepared.result.stream,
            accounting,
            Some(metrics.clone()),
        )
        .await;
        metrics.dec_connection();

        let up = prepared.guard.up.load(Ordering::Relaxed);
        let down = prepared.guard.down.load(Ordering::Relaxed);
        let total_ms = started.elapsed().as_millis() as u64;
        let up_s = format_bytes(up);
        let down_s = format_bytes(down);
        // close 时再快照一次 label —— 极少数情况 meta 可能已经被 close_all
        // 清掉（在 list 路径里）；那种场景下 label_for 返回 `#id` 兜底。
        let label = self.runtime.connections.label_for(id);
        match &result {
            Ok(_) => info!(
                target: "relay",
                "[Relay] #{id} {label} closed | up {up_s} down {down_s} | {total_ms}ms"
            ),
            Err(e) => warn!(
                target: "relay",
                "[Relay] #{id} {label} error: {e} | up {up_s} down {down_s} | {total_ms}ms"
            ),
        }
        result.map(|_| ())
    }
}

fn tcp_connection_meta(metadata: &InboundMetadata, result: &DialResult) -> ConnectionMeta {
    let (inbound_ip, inbound_port) = inbound_parts(metadata.inbound);
    ConnectionMeta {
        network: "tcp".into(),
        kind: metadata.kind.as_str().into(),
        source_ip: metadata.source.ip().to_compact_string(),
        source_port: metadata.source.port().to_compact_string(),
        destination_ip: destination_ip(metadata),
        destination_port: metadata.destination_port.to_compact_string(),
        inbound_ip,
        inbound_port,
        inbound_name: metadata.inbound_name.as_str().into(),
        host: metadata.target_host().into(),
        dns_mode: metadata.dns_mode.as_str().into(),
        process: metadata.process.as_deref().unwrap_or_default().into(),
        process_path: metadata.process_path.as_deref().unwrap_or_default().into(),
        sniff_host: metadata.sniff_host.as_str().into(),
        remote_destination: result.remote_destination.as_str().into(),
        smart_target: result.smart_target.as_str().into(),
        chains: core_observe::string_list_from(&result.chain),
        provider_chains: core_observe::string_list_from(&result.provider_chains),
        rule: result.rule.as_str().into(),
        rule_payload: result.rule_payload.as_str().into(),
        ..ConnectionMeta::default()
    }
}

fn udp_connection_meta(metadata: &InboundMetadata, result: &UdpDialResult) -> ConnectionMeta {
    let (inbound_ip, inbound_port) = inbound_parts(metadata.inbound);
    ConnectionMeta {
        network: "udp".into(),
        kind: metadata.kind.as_str().into(),
        source_ip: metadata.source.ip().to_compact_string(),
        source_port: metadata.source.port().to_compact_string(),
        destination_ip: destination_ip(metadata),
        destination_port: metadata.destination_port.to_compact_string(),
        inbound_ip,
        inbound_port,
        inbound_name: metadata.inbound_name.as_str().into(),
        host: metadata.target_host().into(),
        dns_mode: metadata.dns_mode.as_str().into(),
        process: metadata.process.as_deref().unwrap_or_default().into(),
        process_path: metadata.process_path.as_deref().unwrap_or_default().into(),
        sniff_host: metadata.sniff_host.as_str().into(),
        remote_destination: result.remote_destination.as_str().into(),
        smart_target: result.smart_target.as_str().into(),
        chains: core_observe::string_list_from(&result.chain),
        provider_chains: core_observe::string_list_from(&result.provider_chains),
        rule: result.rule.as_str().into(),
        rule_payload: result.rule_payload.as_str().into(),
        ..ConnectionMeta::default()
    }
}

fn inbound_parts(addr: Option<SocketAddr>) -> (compact_str::CompactString, compact_str::CompactString) {
    match addr {
        Some(addr) => (
            addr.ip().to_compact_string(),
            addr.port().to_compact_string(),
        ),
        None => (compact_str::CompactString::default(), compact_str::CompactString::default()),
    }
}

fn destination_ip(metadata: &InboundMetadata) -> compact_str::CompactString {
    metadata
        .destination_ip
        .or_else(|| metadata.host.parse::<IpAddr>().ok())
        .map(|ip| ip.to_compact_string())
        .unwrap_or_default()
}
