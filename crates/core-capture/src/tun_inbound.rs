//! TUN 入站会话层。
//!
//! `mihomo-smart` 的 TUN 路径由 `sing-tun` 终结 TCP/UDP 后统一进入
//! `ListenerHandler.NewConnection/NewPacket`，再由 `tunnel.preHandleMetadata`
//! 做 fake-IP 反查、DNS mode 标记、规则匹配和连接统计。本模块把这些语义收束成
//! Rust 侧的单一入口，避免 TUN TCP、TUN UDP、DNS hijack 各自拼一份 metadata。

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use compact_str::ToCompactString;
use core_observe::{ConnectionMeta, string_list_from};
use core_resolver::FakeIpPool;
use core_route::NetworkKind;
use core_runtime::InboundMetadata;

use crate::{
    dial_meta::{DialTarget, build_dial_target},
    engine::CapturePlan,
    ipset::IpSetProvider,
    packet::{L4, ParsedPacket},
};

/// 由 `TunSession` 构造统一的 `InboundMetadata`（TCP/UDP 共用）。
///
/// 此前 `tun_dispatch::tun_listener_metadata` / `stack_system::build_inbound_metadata` /
/// `system_dispatch::build_inbound_metadata` 各持一份副本，现在抽到这里。
///
/// **关于 inner**: 本函数**不**接受 inner 参数。TUN ingress 拿到的数据包
/// src IP 在所有"接口只挂网关 IP"的标准 TUN 拓扑（Android VpnService /
/// Linux 单 IP tun / macOS utun / Windows wintun）下，对用户进程出站和
/// kernel 内部 socket 出站两者都等于网关 IP，无法区分；任何包级反推
/// 都是 100% false positive。`metadata.is_inner` 是发起方的显式 tag
/// （参考 mihomo `metadata.Type = INNER`），目前本仓库内部组件全部走
/// `bind_outbound_socket` 在 socket 层绕过 TUN，根本不会进 listener
/// 路径，因此 `is_inner` 字段当前没有生产 set 点，留作未来"显式 tag
/// 的内部 RPC 走 tunnel"扩展点。
pub fn build_inbound_metadata(
    session: &TunSession,
    inbound_addr: Option<SocketAddr>,
) -> InboundMetadata {
    let network = match session.network {
        "udp" => NetworkKind::Udp,
        _ => NetworkKind::Tcp,
    };
    let route_ip = session.target.host.parse::<IpAddr>().ok();
    let mut metadata = InboundMetadata::new(
        network,
        "tun",
        "Tun",
        session.source,
        inbound_addr,
        session.target.host.clone(),
        session.target.original_dst_port,
    )
    .with_destination_ip(Some(session.target.original_dst_ip))
    .with_route_ip(route_ip)
    .with_dns_mode(session.target.dns_mode.as_str())
    .with_sniff_host(session.sniff_host.clone().unwrap_or_default());
    if let Some(reason) = session.bypass {
        metadata = metadata.with_force_direct(reason.as_rule_payload());
    }
    metadata
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunDropReason {
    Loopback,
    RouteExcluded,
    RouteNotAllowed,
    MissingEndpoint,
    FakeDnsMissing,
    /// `Resolver.ipv6 == false` 时收到的 IPv6 包 —— 全局 IPv6 被禁，
    /// 静默丢弃让 happy-eyeballs 快速回落 IPv4。
    Ipv6Disabled,
    /// 目的地址不是 global unicast —— 与 sing-tun `stack_system.go` 的
    /// `IsGlobalUnicast` 入口过滤一致：unspecified / loopback / multicast /
    /// broadcast / link-local / 0.0.0.0/8 / Class E / TUN 子网广播均拒绝。
    /// 命中场景：广告拦截 DNS 把域名指向 `0.0.0.x`，应用拿到后盲连，
    /// 这里直接丢包，dashboard `/connections` 不再被这些“黑洞重试”淹没。
    NotGlobalUnicast,
}

/// 等价于 Go `netip.Addr.IsGlobalUnicast()`（sing-tun 入口过滤标准），并把两段
/// 实务上不应作为出站目的地的范围一并拦下作为温和扩展：
/// * IPv4 `0.0.0.0/8` —— "this-network"；广告拦截/分流 DNS 经常把域名解析为
///   `0.0.0.x` 黑洞，sing-tun 的 `IsUnspecified` 只命中 `0.0.0.0` 一个，整段
///   拦下覆盖 `0.0.0.1` / `0.0.0.2` 等常见黑洞地址。
/// * IPv4 `240.0.0.0/4` —— Class E 保留段，没有合法目标。
///
/// 私网（RFC1918 / CGNAT / ULA）不过滤 —— 真实 LAN 流量必须放过去。
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_link_local()
                && o[0] != 0
                && o[0] < 240
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast() && !is_v6_link_local(v6)
        }
    }
}

/// IPv6 链路本地段 `fe80::/10` —— Rust stable 还没有 `Ipv6Addr::is_unicast_link_local`，
/// 手动按 RFC 4291 §2.4 判定前 10 位等于 `1111111010`（`fe80..fec0`）。
fn is_v6_link_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunBypassReason {
    RouteExcluded,
    RouteNotAllowed,
    /// Root TUN mode: app's UID is in exclude_uid / not in include_uid.
    UidExcluded,
    UidNotIncluded,
    /// Root TUN mode: app's GID is in exclude_gid / not in include_gid.
    GidExcluded,
    GidNotIncluded,
    /// Root TUN mode: app's package is in exclude_package / not in include_package.
    PackageExcluded,
    PackageNotIncluded,
}

impl TunBypassReason {
    pub fn as_rule_payload(self) -> &'static str {
        match self {
            Self::RouteExcluded => "route-exclude-address",
            Self::RouteNotAllowed => "route-address-not-allowed",
            Self::UidExcluded => "exclude-uid",
            Self::UidNotIncluded => "include-uid-miss",
            Self::GidExcluded => "exclude-gid",
            Self::GidNotIncluded => "include-gid-miss",
            Self::PackageExcluded => "exclude-package",
            Self::PackageNotIncluded => "include-package-miss",
        }
    }
}

impl From<crate::uid_filter::BypassCause> for TunBypassReason {
    fn from(cause: crate::uid_filter::BypassCause) -> Self {
        use crate::uid_filter::BypassCause;
        match cause {
            BypassCause::UidExcluded => Self::UidExcluded,
            BypassCause::UidNotIncluded => Self::UidNotIncluded,
            BypassCause::GidExcluded => Self::GidExcluded,
            BypassCause::GidNotIncluded => Self::GidNotIncluded,
            BypassCause::PackageExcluded => Self::PackageExcluded,
            BypassCause::PackageNotIncluded => Self::PackageNotIncluded,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunPacket {
    Tcp {
        source: SocketAddr,
        destination: SocketAddr,
        dst_port: u16,
        bypass: Option<TunBypassReason>,
    },
    Udp {
        source: SocketAddr,
        destination: SocketAddr,
        payload_offset: usize,
        payload_len: usize,
        bypass: Option<TunBypassReason>,
    },
    Other,
}

#[derive(Debug, Clone)]
pub struct TunSession {
    pub network: &'static str,
    pub source: SocketAddr,
    pub original_dst: SocketAddr,
    pub target: DialTarget,
    pub sniff_host: Option<String>,
    pub bypass: Option<TunBypassReason>,
}

#[derive(Debug, Clone, Default)]
pub struct TunOutboundMeta {
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub remote_destination: String,
    pub smart_target: String,
    pub rule: String,
    pub rule_payload: String,
}

impl From<&core_runtime::engine::DialResult> for TunOutboundMeta {
    fn from(res: &core_runtime::engine::DialResult) -> Self {
        Self {
            chains: res.chain.clone(),
            provider_chains: res.provider_chains.clone(),
            remote_destination: res.remote_destination.clone(),
            smart_target: res.smart_target.clone(),
            rule: res.rule.clone(),
            rule_payload: res.rule_payload.clone(),
        }
    }
}

impl From<&core_runtime::engine::UdpDialResult> for TunOutboundMeta {
    fn from(res: &core_runtime::engine::UdpDialResult) -> Self {
        Self {
            chains: res.chain.clone(),
            provider_chains: res.provider_chains.clone(),
            remote_destination: res.remote_destination.clone(),
            smart_target: res.smart_target.clone(),
            rule: res.rule.clone(),
            rule_payload: res.rule_payload.clone(),
        }
    }
}

pub struct TunInbound {
    plan: CapturePlan,
    fake_pool: Arc<FakeIpPool>,
    ipset: Arc<dyn IpSetProvider>,
    uid_filter: Option<Arc<crate::uid_filter::UidPacketFilter>>,
}

impl TunInbound {
    pub fn new(
        plan: CapturePlan,
        fake_pool: Arc<FakeIpPool>,
        ipset: Arc<dyn IpSetProvider>,
    ) -> Self {
        // Build identity filter for root TUN mode (UID/GID/package per-app filtering)
        let rules = crate::uid_filter::IdentityRules {
            include_uid: plan.filters.include_uid.clone(),
            include_uid_range: plan.filters.include_uid_range.clone(),
            exclude_uid: plan.filters.exclude_uid.clone(),
            exclude_uid_range: plan.filters.exclude_uid_range.clone(),
            include_gid: plan.filters.include_gid.clone(),
            include_gid_range: plan.filters.include_gid_range.clone(),
            exclude_gid: plan.filters.exclude_gid.clone(),
            exclude_gid_range: plan.filters.exclude_gid_range.clone(),
            include_package: plan.filters.include_package.clone(),
            exclude_package: plan.filters.exclude_package.clone(),
        };
        let uid_filter = if rules.is_empty() {
            None
        } else {
            Some(Arc::new(crate::uid_filter::UidPacketFilter::new(rules)))
        };
        Self {
            plan,
            fake_pool,
            ipset,
            uid_filter,
        }
    }

    pub fn plan(&self) -> &CapturePlan {
        &self.plan
    }

    // 历史曾经有 `is_inner_source(src_ip) -> bool` 用 `src_ip == tun_gateway`
    // 反推内部连接 —— 已删除。原因详见 `build_inbound_metadata` 的
    // "关于 inner" 段落。
    //
    // 简述：
    // * Android VpnService / Linux 单 IP tun / macOS utun / Windows wintun
    //   等"接口只挂网关 IP"的标准拓扑里，用户进程出站包的 src IP 与 kernel
    //   内部 socket 出站包的 src IP 都被 OS 选成了 TUN 网关 IP，包级无法区分。
    // * 三个参考实现（mihomo / sing-box / sing-tun）都只把"INNER"当作发起方
    //   显式 tag（mihomo `metadata.Type = INNER`），没有任何一处用包反推；
    //   sing-tun 的 `acceptLoop` 直接 `handler.NewConnectionEx(...)` 不做检测。
    // * 本仓库内部组件（DNS upstream / core-fetch / health-check）全部经
    //   `bind_outbound_socket` 在 socket 层绕过 TUN，正常情况下不会进 ingress
    //   路径；不需要 ingress 端的"安全网"。

    pub fn fake_pool(&self) -> &Arc<FakeIpPool> {
        &self.fake_pool
    }

    /// 与 `CaptureSupervisor::allow_ip` 保持同一语义：loopback 与 exclude 优先，
    /// 静态 CIDR 和动态 route-address-set 任一白名单命中才走代理。
    ///
    /// 注意：包一旦到达 TUN，`route_exclude_address(_set)` 不能通过“丢包”
    /// 表达“不接管”，否则会把原本应走系统网络的目标变成黑洞。这里返回
    /// `Some(TunBypassReason)`，后续由 `ListenerHandler` 强制 DIRECT。
    pub fn route_policy(&self, ip: IpAddr) -> Result<Option<TunBypassReason>, TunDropReason> {
        if self.plan.is_loopback_ip(ip) {
            return Err(TunDropReason::Loopback);
        }
        // sing-tun 入口过滤等价物 —— 与 `stack_system.go::processIPv4*` 的
        // `IsGlobalUnicast` + subnet broadcast drop 一致。Fake-IP（198.18/15）
        // 自身是 global unicast，会通过此关；私网（10/8、172.16/12 等）也通过。
        if !is_global_unicast(ip) || self.plan.is_tun_subnet_broadcast(ip) {
            return Err(TunDropReason::NotGlobalUnicast);
        }
        if self
            .plan
            .route_exclude_addresses
            .iter()
            .any(|n| n.contains(&ip))
        {
            return Ok(Some(TunBypassReason::RouteExcluded));
        }
        for set in &self.plan.route_exclude_address_set {
            if self.ipset.contains(set, ip) {
                return Ok(Some(TunBypassReason::RouteExcluded));
            }
        }
        // Fake-IP 是 TUN 内部增强 DNS 的虚拟目标，真实域名要在 preHandle 阶段
        // 反查后再交给 runtime 路由；不能用 198.18/15 本身套 route-address-set。
        if self.fake_pool.contains(ip) {
            return Ok(None);
        }
        if self.plan.route_addresses.is_empty() && self.plan.route_address_set.is_empty() {
            return Ok(None);
        }
        if self.plan.route_addresses.iter().any(|n| n.contains(&ip)) {
            return Ok(None);
        }
        for set in &self.plan.route_address_set {
            if self.ipset.contains(set, ip) {
                return Ok(None);
            }
        }
        Ok(Some(TunBypassReason::RouteNotAllowed))
    }

    /// 老的布尔入口仍保留给 doctor/tests，但 TUN dispatcher 不再用它来丢掉
    /// route-excluded 流量。
    pub fn allow_ip(&self, ip: IpAddr) -> Result<(), TunDropReason> {
        match self.route_policy(ip)? {
            None => Ok(()),
            // Identity-based bypasses are not produced by route_policy itself —
            // they come from check_uid_bypass. Treat any future identity bypass as PASS.
            Some(TunBypassReason::UidExcluded)
            | Some(TunBypassReason::UidNotIncluded)
            | Some(TunBypassReason::GidExcluded)
            | Some(TunBypassReason::GidNotIncluded)
            | Some(TunBypassReason::PackageExcluded)
            | Some(TunBypassReason::PackageNotIncluded) => Ok(()),
            Some(TunBypassReason::RouteExcluded) => Err(TunDropReason::RouteExcluded),
            Some(TunBypassReason::RouteNotAllowed) => Err(TunDropReason::RouteNotAllowed),
        }
    }

    pub fn classify_packet(&self, parsed: &ParsedPacket) -> Result<TunPacket, TunDropReason> {
        // 全局 IPv6 开关 —— 在最早的 dispatch 入口拦下 IPv6 包，配合 DNS 层
        // 不返回 AAAA + outbound 不连 V6，组成 mihomo `ipv6: false` 的完整行为。
        // 不对 ICMPv6 / RA / NS 做特例（mihomo 也不区分），路由器场景下 OS 自己
        // 走 host stack。注意：放在 `match parsed.l4` 之前，TCP/UDP/Other 全覆盖。
        if !self.plan.ipv6_enabled && matches!(parsed.ip.version, crate::packet::IpVersion::V6) {
            return Err(TunDropReason::Ipv6Disabled);
        }
        match parsed.l4 {
            L4::Tcp(t) => {
                let source = parsed.src_socket().ok_or(TunDropReason::MissingEndpoint)?;
                let destination = parsed.dst_socket().ok_or(TunDropReason::MissingEndpoint)?;
                self.reject_loopback_endpoints(source, destination)?;
                // UID filter: excluded apps bypass (DIRECT), not drop
                let uid_bypass = self.check_uid_bypass(source, true);
                let bypass = uid_bypass.or(self.route_policy(destination.ip())?);
                Ok(TunPacket::Tcp {
                    source,
                    destination,
                    dst_port: t.dst_port,
                    bypass,
                })
            }
            L4::Udp(_) => {
                let source = parsed.src_socket().ok_or(TunDropReason::MissingEndpoint)?;
                let destination = parsed.dst_socket().ok_or(TunDropReason::MissingEndpoint)?;
                self.reject_loopback_endpoints(source, destination)?;
                let uid_bypass = self.check_uid_bypass(source, false);
                let bypass = if uid_bypass.is_some() {
                    uid_bypass
                } else if self.should_hijack_dns(destination) {
                    None
                } else {
                    self.route_policy(destination.ip())?
                };
                Ok(TunPacket::Udp {
                    source,
                    destination,
                    payload_offset: parsed.l4_payload_offset(&parsed.l4),
                    payload_len: parsed.l4_payload_len(&parsed.l4),
                    bypass,
                })
            }
            L4::Other(_) => Ok(TunPacket::Other),
        }
    }

    /// Root TUN mode: check identity-based filters (UID/GID/package).
    ///
    /// **Fallback path only.** The primary kernel-level bypass
    /// (`platform::linux_identity_bypass`) keeps excluded packets out of TUN
    /// entirely. If a packet still arrives here for an excluded UID/GID/package,
    /// kernel rules either failed to install or there's a transient race —
    /// returning `Some(TunBypassReason::*)` forces DIRECT routing as a safety
    /// net so we never black-hole legit apps.
    fn check_uid_bypass(&self, source: SocketAddr, is_tcp: bool) -> Option<TunBypassReason> {
        let filter = self.uid_filter.as_ref()?;
        match filter.decide(source, is_tcp) {
            crate::uid_filter::FilterDecision::Proxy => None,
            crate::uid_filter::FilterDecision::Bypass(cause) => Some(cause.into()),
        }
    }

    pub fn should_hijack_dns(&self, destination: SocketAddr) -> bool {
        self.plan.hijack_dns && destination.port() == 53
    }

    fn reject_loopback_endpoints(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<(), TunDropReason> {
        if self.plan.is_loopback_ip(source.ip()) || self.plan.is_loopback_ip(destination.ip()) {
            return Err(TunDropReason::Loopback);
        }
        Ok(())
    }

    pub fn resolve_session(
        &self,
        network: &'static str,
        source: SocketAddr,
        original_dst: SocketAddr,
        fake_host: Option<&str>,
    ) -> Result<TunSession, TunDropReason> {
        self.reject_loopback_endpoints(source, original_dst)?;
        let target = build_dial_target(&self.fake_pool, original_dst, fake_host);
        if target.fake_ip_missing {
            return Err(TunDropReason::FakeDnsMissing);
        }
        let bypass = self.route_policy(original_dst.ip())?;
        Ok(TunSession {
            network,
            source,
            original_dst,
            target,
            sniff_host: fake_host.map(str::to_string),
            bypass,
        })
    }

    pub fn tcp_meta(
        &self,
        session: &TunSession,
        inbound: SocketAddr,
        outbound: &TunOutboundMeta,
    ) -> ConnectionMeta {
        self.base_meta(session, outbound, inbound)
    }

    pub fn udp_meta(&self, session: &TunSession, outbound: &TunOutboundMeta) -> ConnectionMeta {
        let mut meta = self.base_meta(session, outbound, session.original_dst);
        meta.inbound_ip.clear();
        meta.inbound_port.clear();
        meta
    }

    fn base_meta(
        &self,
        session: &TunSession,
        outbound: &TunOutboundMeta,
        inbound: SocketAddr,
    ) -> ConnectionMeta {
        ConnectionMeta {
            network: session.network.into(),
            kind: "Tun".into(),
            source_ip: session.source.ip().to_compact_string(),
            source_port: session.source.port().to_compact_string(),
            destination_ip: session.original_dst.ip().to_compact_string(),
            destination_port: session.original_dst.port().to_compact_string(),
            inbound_ip: inbound.ip().to_compact_string(),
            inbound_port: inbound.port().to_compact_string(),
            inbound_name: "tun".into(),
            host: session.target.host.as_str().into(),
            dns_mode: session.target.dns_mode.as_str().into(),
            sniff_host: session.sniff_host.as_deref().unwrap_or_default().into(),
            remote_destination: outbound.remote_destination.as_str().into(),
            smart_target: outbound.smart_target.as_str().into(),
            chains: string_list_from(&outbound.chains),
            provider_chains: string_list_from(&outbound.provider_chains),
            rule: outbound.rule.as_str().into(),
            rule_payload: outbound.rule_payload.as_str().into(),
            ..ConnectionMeta::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use core_resolver::fake_ip::{AddressFamily, FakeIpConfig};
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};

    use super::*;
    use crate::packet::{IpHeader, IpVersion, TcpFlags, TcpSummary, UdpSummary};

    #[derive(Debug, Default)]
    struct StaticIpSets {
        sets: HashMap<String, Vec<IpNet>>,
    }

    impl StaticIpSets {
        fn with(mut self, name: &str, cidr: &str) -> Self {
            self.sets
                .entry(name.to_string())
                .or_default()
                .push(cidr.parse().unwrap());
            self
        }
    }

    impl IpSetProvider for StaticIpSets {
        fn contains(&self, name: &str, ip: IpAddr) -> bool {
            self.sets
                .get(name)
                .map(|nets| nets.iter().any(|n| n.contains(&ip)))
                .unwrap_or(false)
        }

        fn names(&self) -> Vec<String> {
            self.sets.keys().cloned().collect()
        }
    }

    fn fresh_pool() -> Arc<FakeIpPool> {
        Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: "198.18.0.0/15".parse::<Ipv4Net>().unwrap(),
            v6_cidr: "fc00:1::/64".parse::<Ipv6Net>().unwrap(),
            ..Default::default()
        }))
    }

    fn base_plan() -> CapturePlan {
        CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            stack: core_config::model::CaptureStack::Mixed,
            tun: core_config::model::TunInboundOptions {
                inet6: true,
                ..Default::default()
            },
            ..core_config::model::Capture::default()
        })
        .unwrap()
    }

    fn tcp_packet(src: &str, dst: &str) -> ParsedPacket {
        ParsedPacket {
            ip: IpHeader {
                version: IpVersion::V4,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                protocol: 6,
                total_len: 40,
                l4_offset: 20,
                hop_limit: 64,
            },
            l4: L4::Tcp(TcpSummary {
                src_port: 50000,
                dst_port: 443,
                seq: 0,
                ack: 0,
                control: TcpFlags::default(),
                window: 1024,
                payload_offset: 40,
                payload_len: 0,
            }),
        }
    }

    fn udp_packet(src: &str, dst: &str, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            ip: IpHeader {
                version: IpVersion::V4,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                protocol: 17,
                total_len: 28,
                l4_offset: 20,
                hop_limit: 64,
            },
            l4: L4::Udp(UdpSummary {
                src_port: 50000,
                dst_port,
                payload_offset: 28,
                payload_len: 0,
            }),
        }
    }

    #[test]
    fn builtin_loopback_ranges_are_rejected_without_user_config() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound.route_policy("127.0.0.2".parse().unwrap()),
            Err(TunDropReason::Loopback)
        );
        assert_eq!(
            inbound.route_policy("::1".parse().unwrap()),
            Err(TunDropReason::Loopback)
        );
    }

    #[test]
    fn classify_packet_rejects_loopback_source_and_destination_before_dispatch() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound.classify_packet(&tcp_packet("127.0.0.2", "8.8.8.8")),
            Err(TunDropReason::Loopback)
        );
        assert_eq!(
            inbound.classify_packet(&tcp_packet("10.0.0.2", "127.0.0.2")),
            Err(TunDropReason::Loopback)
        );
    }

    #[test]
    fn classify_packet_rejects_loopback_dns_before_hijack() {
        let mut plan = base_plan();
        plan.hijack_dns = true;
        let inbound = TunInbound::new(plan, fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound.classify_packet(&udp_packet("10.0.0.2", "127.0.0.1", 53)),
            Err(TunDropReason::Loopback)
        );
    }

    #[test]
    fn resolve_session_rejects_loopback_source_and_destination() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound
                .resolve_session(
                    "tcp",
                    "127.0.0.2:50000".parse().unwrap(),
                    "8.8.8.8:443".parse().unwrap(),
                    None,
                )
                .err(),
            Some(TunDropReason::Loopback)
        );
        assert_eq!(
            inbound
                .resolve_session(
                    "tcp",
                    "10.0.0.2:50000".parse().unwrap(),
                    "127.0.0.2:443".parse().unwrap(),
                    None,
                )
                .err(),
            Some(TunDropReason::Loopback)
        );
    }

    #[test]
    fn route_policy_rejects_non_global_unicast_destinations() {
        // 与 sing-tun `IsGlobalUnicast` 一致：unspecified / multicast / broadcast /
        // link-local / 0.0.0.0/8 / Class E 全部被 ingress 丢弃；私网与 fake-IP 通过。
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());

        for bogus in [
            "0.0.0.0",         // unspecified
            "0.0.0.1",         // 用户报告的"广告拦截 DNS 黑洞"
            "0.255.255.255",   // 0.0.0.0/8 上界
            "224.0.0.1",       // 组播
            "239.255.255.250", // SSDP
            "255.255.255.255", // 全局广播
            "240.0.0.1",       // Class E 保留
            "169.254.1.1",     // IPv4 link-local
            "::",              // IPv6 unspecified
            "ff02::1",         // IPv6 多播
            "fe80::1",         // IPv6 link-local
        ] {
            assert_eq!(
                inbound.route_policy(bogus.parse().unwrap()),
                Err(TunDropReason::NotGlobalUnicast),
                "expected drop for {bogus}",
            );
        }

        for ok in [
            "8.8.8.8",     // 公网
            "10.0.0.1",    // RFC1918
            "172.16.0.1",  // RFC1918
            "192.168.1.1", // RFC1918
            "100.64.0.1",  // CGNAT —— 真实 ISP 段，必须放过
            "198.18.0.1",  // fake-IP pool（global unicast，独立通过）
            "2001:db8::1", // IPv6 公网
        ] {
            assert!(
                inbound.route_policy(ok.parse().unwrap()).is_ok(),
                "expected pass for {ok}",
            );
        }
    }

    #[test]
    fn route_policy_rejects_tun_subnet_broadcast() {
        // TUN /30 → broadcast = network + 3。sing-tun 把它单独 drop，避免
        // app 把 TUN 自身网段广播位当成 unicast 目的地。
        let plan = base_plan();
        let bcast = IpAddr::V4(plan.tun_v4_cidr.broadcast());
        let inbound = TunInbound::new(plan, fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound.route_policy(bcast),
            Err(TunDropReason::NotGlobalUnicast)
        );
    }

    #[test]
    fn classify_packet_drops_zero_network_destination() {
        // `0.0.0.1:8000` 是用户报告的典型场景：广告拦截 DNS 把域名解析为 0.0.0.x，
        // 应用盲连，TUN 收到包后必须直接 drop，不能进入连接表。
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());

        assert_eq!(
            inbound.classify_packet(&tcp_packet("10.0.0.2", "0.0.0.1")),
            Err(TunDropReason::NotGlobalUnicast)
        );
        assert_eq!(
            inbound.classify_packet(&udp_packet("10.0.0.2", "0.0.0.1", 8000)),
            Err(TunDropReason::NotGlobalUnicast)
        );
    }

    #[test]
    fn route_address_sets_are_enforced() {
        let mut plan = base_plan();
        plan.route_address_set = vec!["foreign".into()];
        plan.route_exclude_address_set = vec!["cn".into()];
        let ipset = Arc::new(
            StaticIpSets::default()
                .with("foreign", "8.8.8.0/24")
                .with("cn", "1.1.1.0/24"),
        );
        let inbound = TunInbound::new(plan, fresh_pool(), ipset);

        assert!(inbound.allow_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert_eq!(
            inbound.route_policy("1.1.1.1".parse().unwrap()),
            Ok(Some(TunBypassReason::RouteExcluded))
        );
        assert_eq!(
            inbound.allow_ip("1.1.1.1".parse().unwrap()),
            Err(TunDropReason::RouteExcluded)
        );
        assert_eq!(
            inbound.route_policy("9.9.9.9".parse().unwrap()),
            Ok(Some(TunBypassReason::RouteNotAllowed))
        );
        assert_eq!(
            inbound.allow_ip("9.9.9.9".parse().unwrap()),
            Err(TunDropReason::RouteNotAllowed)
        );
    }

    #[test]
    fn fake_ip_bypasses_route_address_set_until_domain_prehandle() {
        let mut plan = base_plan();
        plan.route_address_set = vec!["foreign".into()];
        let pool = fresh_pool();
        let fake = pool.alloc("example.com", AddressFamily::V4).unwrap();
        let inbound = TunInbound::new(plan, pool, Arc::new(StaticIpSets::default()));

        assert!(inbound.allow_ip(fake).is_ok());
    }

    #[test]
    fn fake_ip_session_uses_domain_but_keeps_original_destination() {
        let pool = fresh_pool();
        let fake = pool.alloc("example.com", AddressFamily::V4).unwrap();
        let inbound = TunInbound::new(base_plan(), pool, crate::ipset::noop());
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let original_dst = SocketAddr::new(fake, 443);

        let session = inbound
            .resolve_session("tcp", source, original_dst, None)
            .unwrap();
        assert_eq!(session.target.host, "example.com");
        assert_eq!(session.original_dst, original_dst);
        assert_eq!(session.target.dns_mode.as_str(), "fake-ip");
        assert_eq!(session.bypass, None);
    }

    #[test]
    fn route_excluded_session_is_marked_for_direct_bypass() {
        let mut plan = base_plan();
        plan.route_exclude_address_set = vec!["cn".into()];
        let ipset = Arc::new(StaticIpSets::default().with("cn", "1.1.1.0/24"));
        let inbound = TunInbound::new(plan, fresh_pool(), ipset);
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let original_dst: SocketAddr = "1.1.1.1:443".parse().unwrap();

        let session = inbound
            .resolve_session("tcp", source, original_dst, None)
            .unwrap();

        assert_eq!(session.bypass, Some(TunBypassReason::RouteExcluded));
    }

    #[test]
    fn fake_ip_missing_is_rejected_before_dial() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let original_dst: SocketAddr = "198.18.0.5:443".parse().unwrap();

        assert_eq!(
            inbound
                .resolve_session("tcp", source, original_dst, None)
                .err(),
            Some(TunDropReason::FakeDnsMissing)
        );
    }

    /// 构造一个最小的 IPv6 TCP 包（载荷端口 443）用于测试 IPv6 开关。
    fn tcp_packet_v6(src: &str, dst: &str) -> ParsedPacket {
        ParsedPacket {
            ip: IpHeader {
                version: IpVersion::V6,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                protocol: 6,
                total_len: 60,
                l4_offset: 40,
                hop_limit: 64,
            },
            l4: L4::Tcp(TcpSummary {
                src_port: 50000,
                dst_port: 443,
                seq: 0,
                ack: 0,
                control: TcpFlags::default(),
                window: 1024,
                payload_offset: 60,
                payload_len: 0,
            }),
        }
    }

    /// 全局 IPv6 开关关闭时，TUN 入口阶段直接丢弃 IPv6 包，TCP/UDP/任何 L4 都一视同仁。
    /// mihomo `ipv6: false` 等价行为：silent drop 让 happy-eyeballs 快速回落 IPv4。
    #[test]
    fn ipv6_disabled_drops_v6_tcp_at_classify() {
        let mut plan = base_plan();
        plan.ipv6_enabled = false;
        let inbound = TunInbound::new(plan, fresh_pool(), crate::ipset::noop());
        let pkt = tcp_packet_v6("2001:db8::1", "2001:db8::2");
        assert_eq!(
            inbound.classify_packet(&pkt),
            Err(TunDropReason::Ipv6Disabled)
        );
    }

    /// 默认 ipv6_enabled = true 时 IPv6 包应正常分类，与 IPv4 同等处理。
    #[test]
    fn ipv6_enabled_passes_v6_through_classify() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());
        let pkt = tcp_packet_v6("2001:db8::1", "2001:db8::2");
        // 不应被 Ipv6Disabled 拦下；其他校验（loopback 等）也要不命中。
        let result = inbound.classify_packet(&pkt);
        assert!(
            !matches!(result, Err(TunDropReason::Ipv6Disabled)),
            "v6 should pass when ipv6_enabled=true, got {result:?}"
        );
    }

    /// IPv4 包与 ipv6 开关无关 —— 关掉 ipv6 不应影响 v4 流量。
    #[test]
    fn ipv6_disabled_does_not_affect_v4_traffic() {
        let mut plan = base_plan();
        plan.ipv6_enabled = false;
        let inbound = TunInbound::new(plan, fresh_pool(), crate::ipset::noop());
        let pkt = tcp_packet("10.0.0.1", "8.8.8.8");
        let result = inbound.classify_packet(&pkt);
        assert!(
            !matches!(result, Err(TunDropReason::Ipv6Disabled)),
            "v4 should never be marked Ipv6Disabled, got {result:?}"
        );
    }

    #[test]
    fn meta_contains_real_session_and_outbound_data() {
        let inbound = TunInbound::new(base_plan(), fresh_pool(), crate::ipset::noop());
        let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let original_dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let session = inbound
            .resolve_session("tcp", source, original_dst, Some("www.google.com"))
            .unwrap();
        let out = TunOutboundMeta {
            chains: vec!["Proxy".into(), "NodeA".into()],
            provider_chains: vec!["ProviderA".into()],
            remote_destination: "www.google.com:443".into(),
            smart_target: "DOMAIN-SUFFIX [google.com]".into(),
            rule: "DOMAIN-SUFFIX".into(),
            rule_payload: "google.com".into(),
        };

        let meta = inbound.tcp_meta(&session, original_dst, &out);
        assert_eq!(meta.network, "tcp");
        assert_eq!(meta.kind, "Tun");
        assert_eq!(meta.source_ip, "10.0.0.2");
        assert_eq!(meta.destination_ip, "8.8.8.8");
        assert_eq!(meta.host, "www.google.com");
        assert_eq!(meta.sniff_host, "www.google.com");
        assert_eq!(meta.chains.as_slice(), ["Proxy", "NodeA"]);
        assert_eq!(meta.provider_chains.as_slice(), ["ProviderA"]);
        assert_eq!(meta.rule_payload, "google.com");
    }
}
