//! Capture 引擎抽象 —— 平台无关协议契约。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use core_config::model::{Capture, CaptureMethod, CaptureStack, CaptureTraffic, TunHttpProxyOptions};
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
    pub tun_v6_cidr: ipnet::Ipv6Net,

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
}

impl CapturePlan {
    /// 由 [`Capture`] 配置 + 平台决议得到的执行计划。
    pub fn from_config(c: &Capture) -> Result<Self, CaptureError> {
        let kind = decide_kind(c)?;
        let mut excludes: Vec<ipnet::IpNet> = c
            .exclude
            .cidr
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        // §9.1：默认排除 Tailnet。
        for s in ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] {
            if let Ok(n) = s.parse() {
                if !excludes.contains(&n) {
                    excludes.push(n);
                }
            }
        }

        // 解析 sing-box `address` 列表 —— 首条 v4 + 首条 v6 生效。
        let (mut tun_v4, mut tun_v6) = (
            "198.18.0.0/15".parse::<ipnet::Ipv4Net>().unwrap(),
            "fc00:1::/64".parse::<ipnet::Ipv6Net>().unwrap(),
        );
        for s in &c.tun.address {
            if let Ok(n) = s.parse::<ipnet::Ipv4Net>() {
                tun_v4 = n;
            } else if let Ok(n) = s.parse::<ipnet::Ipv6Net>() {
                tun_v6 = n;
            }
        }

        let interface_name = c
            .tun
            .interface_name
            .clone()
            .unwrap_or_else(default_iface_name);

        let route_addresses = parse_cidr_list(&c.tun.route_address);
        let route_exclude_addresses = parse_cidr_list(&c.tun.route_exclude_address);
        let loopback_addresses = c
            .tun
            .loopback_address
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let auto_redirect_marks = AutoRedirectMarks {
            input: c.tun.auto_redirect_input_mark.as_deref().and_then(parse_hex_mark),
            output: c.tun.auto_redirect_output_mark.as_deref().and_then(parse_hex_mark),
            reset: c.tun.auto_redirect_reset_mark.as_deref().and_then(parse_hex_mark),
            nfqueue: c.tun.auto_redirect_nfqueue,
            fallback_rule_index: c.tun.auto_redirect_iproute2_fallback_rule_index,
        };

        let filters = CaptureFilters {
            include_interface: c.tun.include_interface.clone(),
            exclude_interface: c.tun.exclude_interface.clone(),
            include_uid: c.tun.include_uid.clone(),
            include_uid_range: parse_uid_ranges(&c.tun.include_uid_range),
            exclude_uid: c.tun.exclude_uid.clone(),
            exclude_uid_range: parse_uid_ranges(&c.tun.exclude_uid_range),
            include_gid: c.tun.include_gid.clone(),
            include_gid_range: parse_uid_ranges(&c.tun.include_gid_range),
            exclude_gid: c.tun.exclude_gid.clone(),
            exclude_gid_range: parse_uid_ranges(&c.tun.exclude_gid_range),
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
            mtu: c.mtu.unwrap_or(default_mtu(kind)),
            offload: c.offload,
            hijack_dns: matches!(c.resolver, core_config::model::CaptureResolver::Hijack),
            exclude_cidrs: excludes,
            exclude_processes: c.exclude.process.clone(),
            interface_name,
            tun_v4_cidr: tun_v4,
            tun_v6_cidr: tun_v6,

            auto_route: c.tun.auto_route,
            strict_route: c.tun.strict_route,
            iproute2_table_index: c.tun.iproute2_table_index,
            iproute2_rule_index: c.tun.iproute2_rule_index,
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
            platform_http_proxy: c
                .tun
                .platform
                .as_ref()
                .and_then(|p| p.http_proxy.clone()),
        })
    }

    /// 是否需要 nftables auto_redirect chain。
    pub fn needs_nft_chain(&self) -> bool {
        self.auto_redirect
            && cfg!(any(target_os = "linux", target_os = "android"))
    }

    /// `route_address` 命中或为空（全开放）才接管。
    pub fn route_allows(&self, ip: IpAddr) -> bool {
        if self.route_exclude_addresses.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        if self.route_addresses.is_empty() {
            return true;
        }
        self.route_addresses.iter().any(|n| n.contains(&ip))
    }
}

fn parse_cidr_list(items: &[String]) -> Vec<ipnet::IpNet> {
    items.iter().filter_map(|s| s.parse().ok()).collect()
}

/// `"start:end"` → `(start, end)`。
fn parse_uid_ranges(items: &[String]) -> Vec<(u32, u32)> {
    items
        .iter()
        .filter_map(|s| {
            let (a, b) = s.split_once(':')?;
            Some((a.parse().ok()?, b.parse().ok()?))
        })
        .collect()
}

/// `"0x2023"` 或 `"8227"` → `0x2023`。
fn parse_hex_mark(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).ok()
    } else {
        s.parse().ok()
    }
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
        "RPKernelTun".into()
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
    /// 优雅停止：撤销路由 / 清除防火墙规则 / 关 TUN。
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError>;
    /// （仅 TUN engine）返回底层 [`TunIo`] 设备，供 user-stack / UDP forwarder 直接读写。
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
    use super::*;
    use core_config::model::{
        Capture, CaptureExclude, CaptureResolver, TunInboundOptions, TunPlatformOptions,
        TunHttpProxyOptions,
    };

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
            tun: TunInboundOptions::default(),
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
        assert_eq!(plan.tun_v6_cidr.to_string(), "fdfe:dcba:9876::1/126");
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
    fn parses_decimal_marks_too() {
        assert_eq!(parse_hex_mark("0x2023"), Some(0x2023));
        assert_eq!(parse_hex_mark("8227"), Some(8227));
        assert_eq!(parse_hex_mark("garbage"), None);
    }

    #[test]
    fn parses_uid_range() {
        assert_eq!(
            parse_uid_ranges(&["1000:99999".into(), "bad".into(), "0:10".into()]),
            vec![(1000, 99999), (0, 10)]
        );
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
    fn empty_gid_filters_are_default() {
        let plan = CapturePlan::from_config(&base()).unwrap();
        assert!(plan.filters.include_gid.is_empty());
        assert!(plan.filters.exclude_gid.is_empty());
        assert!(plan.filters.include_gid_range.is_empty());
        assert!(plan.filters.exclude_gid_range.is_empty());
    }
}
