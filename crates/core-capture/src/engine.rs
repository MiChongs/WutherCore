//! Capture 引擎抽象 —— 平台无关协议契约。

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use core_config::model::{
    Capture, CaptureMethod, CaptureStack, CaptureTraffic, TunHttpProxyOptions,
    normalize_auto_redirect_mark,
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("当前平台不支持: {0}")]
    Unsupported(String),
    #[error("doctor 检查失败: {0}")]
    Doctor(String),
    #[error("内核拒绝创建 TUN/TProxy: {0}")]
    DeviceFailed(String),
    #[error("路由表写入失败: {0}")]
    Route(String),
    #[error("NAT 表满 / 失败: {0}")]
    Nat(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("已停止")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EngineKind {
    /// virtual_nic —— 创建一张 TUN 网卡，转发其上 IP 包。
    Tun,
    /// Linux 透明代理：TPROXY socket + nftables / iptables。
    Tproxy,
    /// 仅 TCP 重定向（兼容模式，无法处理 UDP）。
    Redirect,
    /// 不接管，仅诊断。
    None,
}

/// auto_redirect 用的 nftables fwmark 三元组（输入 / 输出 / reset）。
#[derive(Debug, Clone, Default)]
pub struct AutoRedirectMarks {
    pub input: Option<u32>,
    pub output: Option<u32>,
    pub reset: Option<u32>,
    pub nfqueue: Option<u16>,
    pub fallback_rule_index: Option<u32>,
}

/// 接口 / UID / GID / 包名 / MAC 过滤集合 —— 平台后端按支持度生效。
#[derive(Debug, Clone, Default)]
pub struct CaptureFilters {
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub include_uid_range: Vec<(u32, u32)>,
    pub exclude_uid: Vec<u32>,
    pub exclude_uid_range: Vec<(u32, u32)>,
    pub include_gid: Vec<u32>,
    pub include_gid_range: Vec<(u32, u32)>,
    pub exclude_gid: Vec<u32>,
    pub exclude_gid_range: Vec<(u32, u32)>,
    pub include_android_user: Vec<u32>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    pub include_mac: Vec<String>,
    pub exclude_mac: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CapturePlan {
    pub on: bool,
    pub kind: EngineKind,
    pub stack: CaptureStack,
    pub traffic: CaptureTraffic,
    pub mtu: u32,
    pub offload: bool,
    pub hijack_dns: bool,
    pub exclude_cidrs: Vec<ipnet::IpNet>,
    pub exclude_processes: Vec<String>,
    pub interface_name: String,
    pub tun_v4_cidr: ipnet::Ipv4Net,
    pub tun_v6_cidr: Option<ipnet::Ipv6Net>,

    /* ---- sing-box auto_route / auto_redirect ---- */
    pub auto_route: bool,
    pub strict_route: bool,
    pub iproute2_table_index: u32,
    pub iproute2_rule_index: u32,
    pub auto_redirect: bool,
    pub auto_redirect_marks: AutoRedirectMarks,

    /* ---- 路由白/黑名单 ---- */
    pub route_addresses: Vec<ipnet::IpNet>,
    pub route_exclude_addresses: Vec<ipnet::IpNet>,
    pub route_address_set: Vec<String>,
    pub route_exclude_address_set: Vec<String>,
    pub loopback_addresses: Vec<IpAddr>,

    /* ---- NAT ---- */
    pub endpoint_independent_nat: bool,
    pub udp_timeout: Duration,
    pub exclude_mptcp: bool,

    /* ---- 平台过滤 ---- */
    pub filters: CaptureFilters,
    /// 平台 HTTP 代理透传配置（iOS/Android）。
    pub platform_http_proxy: Option<TunHttpProxyOptions>,

    /// 全局 IPv6 开关（mihomo `ipv6: false` 等价行为）。`from_config` 只能拿到
    /// `Capture` 一段配置，无法看到 `Resolver.ipv6`，所以这里默认 `true`，由
    /// 上层（[`crate::supervisor::CaptureSupervisor::build`]）注入实际值。
    ///
    /// 关闭时 TUN dispatcher 在 `tun_inbound::classify_packet` 阶段直接丢掉
    /// 所有 IPv6 包（silent drop，与 mihomo 一致），让应用通过 happy-eyeballs
    /// 快速回落到 IPv4，避免 250ms+ TCP 超时。
    pub ipv6_enabled: bool,
}

impl CapturePlan {
    /// 由 [`Capture`] 配置 + 平台决议得到的执行计划。
    pub fn from_config(c: &Capture) -> Result<Self, CaptureError> {
        let kind = decide_kind(c)?;
        let mut excludes = parse_cidr_list("capture.exclude.cidr", &c.exclude.cidr, c.on)?;
        // §9.1：默认排除 Tailnet。
        for s in ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] {
            let n = s.parse().expect("static Tailnet CIDR must be valid");
            if !excludes.contains(&n) {
                excludes.push(n);
            }
        }

        // 解析 sing-box `address` 列表 —— 首条 v4 + 首条 v6 生效。
        let mut tun_v4: Option<ipnet::Ipv4Net> = None;
        let mut tun_v6: Option<ipnet::Ipv6Net> = None;
        for (index, s) in c.tun.address.iter().enumerate() {
            if let Ok(n) = s.parse::<ipnet::Ipv4Net>() {
                tun_v4.get_or_insert(n);
                continue;
            }
            if let Ok(n) = s.parse::<ipnet::Ipv6Net>() {
                tun_v6.get_or_insert(n);
                continue;
            }
            if c.on {
                return Err(CaptureError::Route(format!(
                    "capture.tun.address[{index}] 不是合法的 IPv4/IPv6 CIDR: {s}"
                )));
            }
        }
        let tun_v4 =
            tun_v4.unwrap_or_else(|| "198.18.0.0/15".parse().expect("static IPv4 TUN CIDR"));
        let tun_v6 = tun_v6.unwrap_or_else(|| "fc00:1::/64".parse().expect("static IPv6 TUN CIDR"));
        let tun_v6: Option<ipnet::Ipv6Net> = if c.tun.inet6 { Some(tun_v6) } else { None };

        let interface_name = c
            .tun
            .interface_name
            .clone()
            .unwrap_or_else(default_iface_name);

        let route_addresses =
            parse_cidr_list("capture.tun.route_address", &c.tun.route_address, c.on)?;
        let route_exclude_addresses = parse_cidr_list(
            "capture.tun.route_exclude_address",
            &c.tun.route_exclude_address,
            c.on,
        )?;
        let loopback_addresses = parse_ip_list(
            "capture.tun.loopback_address",
            &c.tun.loopback_address,
            c.on,
        )?;

        // 配置缺省时回填 sing-tun 默认值；与 mihomo `listener/sing_tun/server.go::202-221`
        // 一致——0 视为未设置，回退到 `tun.DefaultXxx` 常量。
        // 对应 sing-tun `redirect.go::13-16` + `tun.go::70`。
        fn nonzero_or<T: PartialEq + Default + Copy>(v: Option<T>, default_v: T) -> T {
            match v {
                Some(x) if x != T::default() => x,
                _ => default_v,
            }
        }
        fn mark_or_default(
            field: &str,
            value: Option<&str>,
            default: u32,
            strict: bool,
        ) -> Result<u32, CaptureError> {
            match normalize_auto_redirect_mark(value, default) {
                Some(mark) => Ok(mark),
                None if !strict => Ok(default),
                None => Err(CaptureError::Nat(format!(
                    "{field} 不是合法的 u32/十六进制 mark"
                ))),
            }
        }
        let auto_redirect_marks = AutoRedirectMarks {
            input: Some(mark_or_default(
                "capture.tun.auto_redirect_input_mark",
                c.tun.auto_redirect_input_mark.as_deref(),
                core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK,
                c.on,
            )?),
            output: Some(mark_or_default(
                "capture.tun.auto_redirect_output_mark",
                c.tun.auto_redirect_output_mark.as_deref(),
                core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK,
                c.on,
            )?),
            reset: Some(mark_or_default(
                "capture.tun.auto_redirect_reset_mark",
                c.tun.auto_redirect_reset_mark.as_deref(),
                core_config::model::DEFAULT_AUTO_REDIRECT_RESET_MARK,
                c.on,
            )?),
            nfqueue: Some(nonzero_or(
                c.tun.auto_redirect_nfqueue,
                core_config::model::DEFAULT_AUTO_REDIRECT_NFQUEUE,
            )),
            fallback_rule_index: Some(nonzero_or(
                c.tun.auto_redirect_iproute2_fallback_rule_index,
                core_config::model::DEFAULT_IPROUTE2_AUTO_REDIRECT_FALLBACK_RULE_INDEX,
            )),
        };

        let filters = CaptureFilters {
            include_interface: c.tun.include_interface.clone(),
            exclude_interface: c.tun.exclude_interface.clone(),
            include_uid: c.tun.include_uid.clone(),
            include_uid_range: parse_uid_ranges(
                "capture.tun.include_uid_range",
                &c.tun.include_uid_range,
                c.on,
            )?,
            exclude_uid: c.tun.exclude_uid.clone(),
            exclude_uid_range: parse_uid_ranges(
                "capture.tun.exclude_uid_range",
                &c.tun.exclude_uid_range,
                c.on,
            )?,
            include_gid: c.tun.include_gid.clone(),
            include_gid_range: parse_uid_ranges(
                "capture.tun.include_gid_range",
                &c.tun.include_gid_range,
                c.on,
            )?,
            exclude_gid: c.tun.exclude_gid.clone(),
            exclude_gid_range: parse_uid_ranges(
                "capture.tun.exclude_gid_range",
                &c.tun.exclude_gid_range,
                c.on,
            )?,
            include_android_user: c.tun.include_android_user.clone(),
            include_package: c.tun.include_package.clone(),
            exclude_package: c.tun.exclude_package.clone(),
            include_mac: c.tun.include_mac_address.clone(),
            exclude_mac: c.tun.exclude_mac_address.clone(),
        };

        Ok(Self {
            on: c.on,
            kind,
            stack: c.stack,
            traffic: c.traffic,
            // mihomo `server.go::192-195`：MTU 为 0 视为未设置，回退到默认值。
            mtu: nonzero_or(c.mtu, default_mtu(kind)),
            offload: c.offload,
            hijack_dns: matches!(c.resolver, core_config::model::CaptureResolver::Hijack),
            exclude_cidrs: excludes,
            exclude_processes: c.exclude.process.clone(),
            interface_name,
            tun_v4_cidr: tun_v4,
            tun_v6_cidr: tun_v6,

            auto_route: c.tun.auto_route,
            strict_route: c.tun.strict_route,
            // mihomo `server.go::202-208`：0 视为未设置，回退到 sing-tun 默认值。
            iproute2_table_index: nonzero_or(Some(c.tun.iproute2_table_index), 2022),
            iproute2_rule_index: nonzero_or(Some(c.tun.iproute2_rule_index), 9000),
            auto_redirect: c.tun.auto_redirect,
            auto_redirect_marks,

            route_addresses,
            route_exclude_addresses,
            route_address_set: c.tun.route_address_set.clone(),
            route_exclude_address_set: c.tun.route_exclude_address_set.clone(),
            loopback_addresses,

            endpoint_independent_nat: c.tun.endpoint_independent_nat,
            udp_timeout: c.tun.udp_timeout,
            exclude_mptcp: c.tun.exclude_mptcp,

            filters,
            platform_http_proxy: c.tun.platform.as_ref().and_then(|p| p.http_proxy.clone()),
            // Default true; supervisor overrides from `Resolver.ipv6` after build.
            ipv6_enabled: true,
        })
    }

    /// 是否需要 nftables auto_redirect chain。
    pub fn needs_nft_chain(&self) -> bool {
        self.auto_redirect && cfg!(any(target_os = "linux", target_os = "android"))
    }

    /// `route_address` 命中或为空（全开放）才接管。
    pub fn route_allows(&self, ip: IpAddr) -> bool {
        if self.is_loopback_ip(ip) || self.route_exclude_addresses.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        if self.route_addresses.is_empty() {
            return true;
        }
        self.route_addresses.iter().any(|n| n.contains(&ip))
    }

    /// 内置回环地址和用户配置的 `loopback_address` 都不应进入代理出站。
    pub fn is_loopback_ip(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.loopback_addresses.contains(&ip)
    }

    /// TUN 自身网段的子网广播地址 —— sing-tun `stack_system.go` 用
    /// `BroadcastAddr(...)` 算出当前 TUN 接口的广播 IP（如 `198.18.0.0/16` →
    /// `198.18.255.255`）并在 ingress 直接 drop。我们在 `route_policy` 同处拦下，
    /// 避免应用把 TUN 子网广播当成普通 unicast 目的地（dashboard 上会看到
    /// `inbound`/`outbound` IP 一致的“连接到自己网关广播位”的怪条目）。
    /// IPv6 没有 broadcast 概念，统一返回 false。
    pub fn is_tun_subnet_broadcast(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.tun_v4_cidr.broadcast() == v4,
            IpAddr::V6(_) => false,
        }
    }

    pub fn tun_v4_addr_cidr(&self) -> String {
        format!(
            "{}/{}",
            self.tun_v4_cidr.addr(),
            self.tun_v4_cidr.prefix_len()
        )
    }

    pub fn tun_v6_addr_cidr(&self) -> Option<String> {
        self.tun_v6_cidr
            .map(|c| format!("{}/{}", c.addr(), c.prefix_len()))
    }
}

fn parse_cidr_list(
    field: &str,
    items: &[String],
    strict: bool,
) -> Result<Vec<ipnet::IpNet>, CaptureError> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, value)| match value.parse() {
            Ok(network) => Some(Ok(network)),
            Err(_) if !strict => None,
            Err(_) => Some(Err(CaptureError::Route(format!(
                "{field}[{index}] 不是合法的 CIDR: {value}"
            )))),
        })
        .collect()
}

fn parse_ip_list(field: &str, items: &[String], strict: bool) -> Result<Vec<IpAddr>, CaptureError> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, value)| match value.parse() {
            Ok(address) => Some(Ok(address)),
            Err(_) if !strict => None,
            Err(_) => Some(Err(CaptureError::Route(format!(
                "{field}[{index}] 不是合法的 IP 地址: {value}"
            )))),
        })
        .collect()
}

/// `"start:end"` → `(start, end)`。
fn parse_uid_ranges(
    field: &str,
    items: &[String],
    strict: bool,
) -> Result<Vec<(u32, u32)>, CaptureError> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let parsed = value
                .split_once(':')
                .and_then(|(start, end)| Some((start.parse().ok()?, end.parse().ok()?)))
                .filter(|(start, end)| start <= end);
            match parsed {
                Some(range) => Some(Ok(range)),
                None if !strict => None,
                None => Some(Err(CaptureError::Route(format!(
                    "{field}[{index}] 必须是 start:end 闭区间且 start <= end: {value}"
                )))),
            }
        })
        .collect()
}

fn default_mtu(kind: EngineKind) -> u32 {
    // mihomo (`sing-tun server.go::194`) 默认 9000 —— TUN 链路 jumbo frame
    // 显著提升 TCP 吞吐。TPROXY/Redirect 不经 TUN，沿用网卡 MTU 1500。
    match kind {
        EngineKind::Tun => 9000,
        _ => 1500,
    }
}

fn default_iface_name() -> String {
    if cfg!(target_os = "windows") {
        "WutherCoreTun".into()
    } else if cfg!(target_os = "macos") {
        "utun7".into()
    } else {
        "rpktun0".into()
    }
}

fn decide_kind(c: &Capture) -> Result<EngineKind, CaptureError> {
    if !c.on {
        return Ok(EngineKind::None);
    }
    let os = std::env::consts::OS;
    let kind = match c.method {
        CaptureMethod::Auto => match os {
            "linux" | "android" => EngineKind::Tproxy,
            "windows" | "macos" | "ios" => EngineKind::Tun,
            other => return Err(CaptureError::Unsupported(other.into())),
        },
        CaptureMethod::VirtualNic => EngineKind::Tun,
        CaptureMethod::Tproxy => {
            if !matches!(os, "linux" | "android") {
                return Err(CaptureError::Unsupported(format!(
                    "tproxy 仅 Linux/Android；当前 {os}"
                )));
            }
            EngineKind::Tproxy
        }
        CaptureMethod::Redirect => {
            if !matches!(os, "linux" | "android") {
                return Err(CaptureError::Unsupported(format!(
                    "redirect 仅 Linux/Android；当前 {os}"
                )));
            }
            EngineKind::Redirect
        }
    };
    Ok(kind)
}

/// 一次"被接管"的连接事件。Engine 通过 mpsc 把它发给 supervisor。
#[derive(Debug, Clone)]
pub struct CaptureEvent {
    pub original_dst: SocketAddr,
    pub source: SocketAddr,
    pub network: &'static str, // "tcp" / "udp"
    pub fake_host: Option<String>,
}

/// 平台 Engine trait —— 由 platform/* 子模块各自实现。
#[async_trait]
pub trait CaptureEngine: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn plan(&self) -> &CapturePlan;
    /// 启动；事件通过 channel 推出，runtime 用于"自带 dial+splice"的 listener
    /// （TPROXY/Redirect）—— TUN+user-stack 引擎可忽略 runtime（由 TunDispatcher
    /// 持有）。
    async fn start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError>;
    /// 第二阶段激活入口规则。
    ///
    /// TUN 后端必须先让 dispatcher 接管设备读写，再把系统流量导入数据面；
    /// 默认实现为空，只有需要这种两阶段事务的后端才覆写。实现必须能处理
    /// 任意部分启动状态：失败时保留仍归本进程所有的资源账本，允许清理后重试。
    async fn post_start(
        self: Arc<Self>,
        _events: mpsc::Sender<CaptureEvent>,
        _runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        Ok(())
    }
    /// 在 dispatcher 停止前撤销平台入口。
    ///
    /// 需要内核导流规则的后端必须先停止接收新流量，才能安全拆除承载
    /// 数据面的 dispatcher。实现必须幂等，并在部分清理失败时保留未撤销的
    /// 所有权账本，后续调用只重试残余资源。默认实现为空。
    async fn pre_stop(self: Arc<Self>) -> Result<(), CaptureError> {
        Ok(())
    }
    /// 优雅停止：撤销路由 / 清除防火墙规则 / 关 TUN。
    /// 实现必须可重复调用，并安全处理 `start` / `post_start` 的部分成功状态。
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError>;
    /// （仅 TUN engine）返回底层 `TunIo` 设备，供 user-stack / UDP forwarder 直接读写。
    /// 默认 None —— Tproxy/Redirect 等不需要直接访问 TUN。
    fn tun_io(&self) -> Option<Arc<dyn crate::tun_io::TunIo>> {
        None
    }
    fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": format!("{:?}", self.kind()).to_lowercase(),
            "stack": format!("{:?}", self.plan().stack).to_lowercase(),
            "traffic": format!("{:?}", self.plan().traffic).to_lowercase(),
            "mtu": self.plan().mtu,
            "interface": self.plan().interface_name,
        })
    }
}

/// 工具：判断目标 IP 是否被 exclude。
pub fn is_excluded(plan: &CapturePlan, ip: IpAddr) -> bool {
    plan.exclude_cidrs.iter().any(|n| n.contains(&ip))
}

#[cfg(test)]
mod tests {
    use core_config::model::{
        Capture, CaptureExclude, CaptureResolver, TunHttpProxyOptions, TunInboundOptions,
        TunPlatformOptions,
    };

    use super::*;

    fn base() -> Capture {
        Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Hijack,
            stack: CaptureStack::System,
            mtu: Some(9000),
            offload: true,
            exclude: CaptureExclude::default(),
            tun: TunInboundOptions {
                inet6: true,
                ..TunInboundOptions::default()
            },
        }
    }

    #[test]
    fn parses_singbox_full_payload() {
        let mut c = base();
        c.tun.interface_name = Some("tun0".into());
        c.tun.address = vec!["172.18.0.1/30".into(), "fdfe:dcba:9876::1/126".into()];
        c.tun.iproute2_table_index = 2022;
        c.tun.iproute2_rule_index = 9000;
        c.tun.auto_redirect = true;
        c.tun.auto_redirect_input_mark = Some("0x2023".into());
        c.tun.auto_redirect_output_mark = Some("0x2024".into());
        c.tun.auto_redirect_reset_mark = Some("0x2025".into());
        c.tun.auto_redirect_nfqueue = Some(100);
        c.tun.auto_redirect_iproute2_fallback_rule_index = Some(32768);
        c.tun.strict_route = true;
        c.tun.endpoint_independent_nat = false;
        c.tun.udp_timeout = Duration::from_secs(300);
        c.tun.route_address = vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()];
        c.tun.route_exclude_address = vec!["192.168.0.0/16".into(), "fc00::/7".into()];
        c.tun.route_address_set = vec!["geoip-cloudflare".into()];
        c.tun.route_exclude_address_set = vec!["geoip-cn".into()];
        c.tun.include_uid = vec![0];
        c.tun.include_uid_range = vec!["1000:99999".into()];
        c.tun.include_android_user = vec![0, 10];
        c.tun.include_package = vec!["com.android.chrome".into()];
        c.tun.include_mac_address = vec!["00:11:22:33:44:55".into()];
        c.tun.platform = Some(TunPlatformOptions {
            http_proxy: Some(TunHttpProxyOptions {
                enabled: false,
                server: "127.0.0.1".into(),
                server_port: 8080,
                bypass_domain: vec![],
                match_domain: vec![],
            }),
        });

        let plan = CapturePlan::from_config(&c).unwrap();
        assert_eq!(plan.interface_name, "tun0");
        assert_eq!(plan.mtu, 9000);
        // ipnet 解析时保留 host bits；Display 显示 host/prefix。
        assert_eq!(plan.tun_v4_cidr.to_string(), "172.18.0.1/30");
        assert_eq!(
            plan.tun_v6_cidr.unwrap().to_string(),
            "fdfe:dcba:9876::1/126"
        );
        assert_eq!(plan.iproute2_table_index, 2022);
        assert!(plan.auto_redirect);
        assert_eq!(plan.auto_redirect_marks.input, Some(0x2023));
        assert_eq!(plan.auto_redirect_marks.reset, Some(0x2025));
        assert_eq!(plan.auto_redirect_marks.nfqueue, Some(100));
        assert!(plan.strict_route);
        assert_eq!(plan.udp_timeout, Duration::from_secs(300));
        assert_eq!(plan.route_addresses.len(), 2);
        assert_eq!(plan.route_exclude_addresses.len(), 2);
        assert_eq!(plan.route_address_set, vec!["geoip-cloudflare"]);
        assert_eq!(plan.filters.include_uid, vec![0u32]);
        assert_eq!(plan.filters.include_uid_range, vec![(1000u32, 99999u32)]);
        assert_eq!(plan.filters.include_android_user, vec![0u32, 10u32]);
        assert_eq!(plan.filters.include_package, vec!["com.android.chrome"]);
        assert_eq!(plan.filters.include_mac, vec!["00:11:22:33:44:55"]);
        let http = plan.platform_http_proxy.unwrap();
        assert_eq!(http.server, "127.0.0.1");
        assert_eq!(http.server_port, 8080);
    }

    #[test]
    fn tun_interface_cidrs_use_configured_host_addresses() {
        let mut c = base();
        c.tun.address = vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()];
        let plan = CapturePlan::from_config(&c).unwrap();

        assert_eq!(plan.tun_v4_addr_cidr(), "172.19.0.1/30");
        assert_eq!(plan.tun_v6_addr_cidr().unwrap(), "fdfe:dcba:9876::1/126");
    }

    #[test]
    fn first_tun_address_per_family_wins() {
        let mut c = base();
        c.tun.address = vec![
            "172.19.0.1/30".into(),
            "172.20.0.1/30".into(),
            "fdfe:dcba:9876::1/126".into(),
            "fdfe:dcba:9877::1/126".into(),
        ];
        let plan = CapturePlan::from_config(&c).unwrap();

        assert_eq!(plan.tun_v4_addr_cidr(), "172.19.0.1/30");
        assert_eq!(plan.tun_v6_addr_cidr().unwrap(), "fdfe:dcba:9876::1/126");
    }

    #[test]
    fn route_allows_with_blacklist() {
        let mut c = base();
        c.tun.route_exclude_address = vec!["192.168.0.0/16".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        assert!(!plan.route_allows("192.168.1.1".parse().unwrap()));
        assert!(plan.route_allows("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn route_allows_with_whitelist_only() {
        let mut c = base();
        c.tun.route_address = vec!["10.0.0.0/8".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        assert!(plan.route_allows("10.1.2.3".parse().unwrap()));
        assert!(!plan.route_allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn parses_decimal_marks_and_normalizes_zero() {
        assert_eq!(
            normalize_auto_redirect_mark(Some("0x2023"), 7),
            Some(0x2023)
        );
        assert_eq!(normalize_auto_redirect_mark(Some("8227"), 7), Some(8227));
        assert_eq!(normalize_auto_redirect_mark(Some("0"), 7), Some(7));
        assert_eq!(normalize_auto_redirect_mark(Some("garbage"), 7), None);
    }

    #[test]
    fn parses_uid_range() {
        assert_eq!(
            parse_uid_ranges("test.range", &["1000:99999".into(), "0:10".into()], true).unwrap(),
            vec![(1000, 99999), (0, 10)]
        );
        assert!(parse_uid_ranges("test.range", &["bad".into()], true).is_err());
        assert!(parse_uid_ranges("test.range", &["10:0".into()], true).is_err());
    }

    #[test]
    fn parses_gid_filters_into_plan() {
        let mut c = base();
        c.tun.include_gid = vec![3003, 3004];
        c.tun.include_gid_range = vec!["10000:19999".into()];
        c.tun.exclude_gid = vec![1000];
        c.tun.exclude_gid_range = vec!["2000:2099".into()];
        let plan = CapturePlan::from_config(&c).unwrap();
        assert_eq!(plan.filters.include_gid, vec![3003u32, 3004u32]);
        assert_eq!(plan.filters.include_gid_range, vec![(10000u32, 19999u32)]);
        assert_eq!(plan.filters.exclude_gid, vec![1000u32]);
        assert_eq!(plan.filters.exclude_gid_range, vec![(2000u32, 2099u32)]);
    }

    #[test]
    fn active_capture_literals_fail_closed_in_execution_plan() {
        let mut invalid_route = base();
        invalid_route.tun.route_address = vec!["not-a-cidr".into()];
        let error = CapturePlan::from_config(&invalid_route).unwrap_err();
        assert!(error.to_string().contains("route_address[0]"));

        let mut reversed_range = base();
        reversed_range.tun.include_uid_range = vec!["2000:1000".into()];
        let error = CapturePlan::from_config(&reversed_range).unwrap_err();
        assert!(error.to_string().contains("start <= end"));

        let mut invalid_mark = base();
        invalid_mark.tun.auto_redirect_output_mark = Some("not-a-mark".into());
        let error = CapturePlan::from_config(&invalid_mark).unwrap_err();
        assert!(error.to_string().contains("output_mark"));
    }

    #[test]
    fn disabled_capture_ignores_dormant_invalid_literals() {
        let mut capture = base();
        capture.on = false;
        capture.tun.route_address = vec!["not-a-cidr".into()];
        capture.tun.include_uid_range = vec!["backwards".into()];
        capture.tun.auto_redirect_output_mark = Some("not-a-mark".into());

        let plan = CapturePlan::from_config(&capture).unwrap();

        assert!(plan.route_addresses.is_empty());
        assert!(plan.filters.include_uid_range.is_empty());
        assert_eq!(
            plan.auto_redirect_marks.output,
            Some(core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK)
        );
    }

    #[test]
    fn auto_redirect_marks_default_to_sing_tun_constants_when_unset() {
        // 用户未设置任何 auto_redirect 标记 / nfqueue / fallback rule index 时，
        // WutherCore 必须回填 sing-tun 默认值（`redirect.go::13-16` + `tun.go::70`）。
        let plan = CapturePlan::from_config(&base()).unwrap();
        assert_eq!(
            plan.auto_redirect_marks.input,
            Some(core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK)
        );
        assert_eq!(
            plan.auto_redirect_marks.input,
            Some(0x2023),
            "must match sing-tun DefaultAutoRedirectInputMark"
        );
        assert_eq!(
            plan.auto_redirect_marks.output,
            Some(core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK)
        );
        assert_eq!(
            plan.auto_redirect_marks.output,
            Some(0x2024),
            "must match sing-tun DefaultAutoRedirectOutputMark"
        );
        assert_eq!(
            plan.auto_redirect_marks.reset,
            Some(core_config::model::DEFAULT_AUTO_REDIRECT_RESET_MARK)
        );
        assert_eq!(
            plan.auto_redirect_marks.reset,
            Some(0x2025),
            "must match sing-tun DefaultAutoRedirectResetMark"
        );
        assert_eq!(
            plan.auto_redirect_marks.nfqueue,
            Some(core_config::model::DEFAULT_AUTO_REDIRECT_NFQUEUE)
        );
        assert_eq!(
            plan.auto_redirect_marks.nfqueue,
            Some(100),
            "must match sing-tun DefaultAutoRedirectNFQueue"
        );
        assert_eq!(
            plan.auto_redirect_marks.fallback_rule_index,
            Some(core_config::model::DEFAULT_IPROUTE2_AUTO_REDIRECT_FALLBACK_RULE_INDEX)
        );
        assert_eq!(
            plan.auto_redirect_marks.fallback_rule_index,
            Some(32768),
            "must match sing-tun DefaultIPRoute2AutoRedirectFallbackRuleIndex"
        );
    }

    #[test]
    fn empty_gid_filters_are_default() {
        let plan = CapturePlan::from_config(&base()).unwrap();
        assert!(plan.filters.include_gid.is_empty());
        assert!(plan.filters.exclude_gid.is_empty());
        assert!(plan.filters.include_gid_range.is_empty());
        assert!(plan.filters.exclude_gid_range.is_empty());
    }
}
