use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Serialize;

use crate::engine::CapturePlan;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AndroidIpPrefix {
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AndroidVpnServiceConfig {
    pub interface_name: String,
    pub mtu: u32,
    pub addresses: Vec<AndroidIpPrefix>,
    pub routes: Vec<AndroidIpPrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub allowed_applications: Vec<String>,
    pub disallowed_applications: Vec<String>,
    pub warnings: Vec<String>,
}

impl AndroidIpPrefix {
    fn from_net(net: IpNet) -> Self {
        Self {
            address: net.addr(),
            prefix: net.prefix_len(),
        }
    }
}

pub fn build_vpn_service_config(plan: &CapturePlan) -> AndroidVpnServiceConfig {
    let mut warnings = Vec::new();
    let mut addresses = vec![AndroidIpPrefix::from_net(IpNet::V4(plan.tun_v4_cidr))];
    if let Some(v6) = plan.tun_v6_cidr {
        addresses.push(AndroidIpPrefix::from_net(IpNet::V6(v6)));
    }
    addresses.sort_by_key(prefix_sort_key);

    let mut base_routes = if !plan.route_addresses.is_empty() {
        plan.route_addresses.clone()
    } else if plan.auto_route {
        let mut r = vec!["0.0.0.0/0".parse::<IpNet>().unwrap()];
        if plan.tun_v6_cidr.is_some() {
            r.push("::/0".parse::<IpNet>().unwrap());
        }
        r
    } else {
        warnings.push(
            "auto_route=false 且 route_address 为空；VpnService.Builder 不会添加接管路由".into(),
        );
        Vec::new()
    };
    base_routes.sort_by_key(net_sort_key);

    let mut static_excludes = plan.exclude_cidrs.clone();
    static_excludes.extend(plan.route_exclude_addresses.iter().copied());

    let mut routes = subtract_routes(&base_routes, &static_excludes)
        .into_iter()
        .map(AndroidIpPrefix::from_net)
        .collect::<Vec<_>>();
    routes.sort_by_key(prefix_sort_key);

    let mut dns_servers = Vec::new();
    if plan.hijack_dns {
        dns_servers.push(IpAddr::V4(plan.tun_v4_cidr.addr()));
        if let Some(v6) = plan.tun_v6_cidr {
            dns_servers.push(IpAddr::V6(v6.addr()));
        }
    }

    let (allowed_applications, disallowed_applications) = if !plan
        .filters
        .include_package
        .is_empty()
    {
        if !plan.filters.exclude_package.is_empty() {
            warnings.push(
                    "Android VpnService.Builder 不能同时使用 allowed 与 disallowed app；include_package 生效，exclude_package 已忽略"
                        .into(),
                );
        }
        (plan.filters.include_package.clone(), Vec::new())
    } else {
        (Vec::new(), plan.filters.exclude_package.clone())
    };

    if !plan.route_exclude_address_set.is_empty() {
        warnings.push(
            "route_exclude_address_set 是动态规则集，VpnService.Builder 无法预先拆路由；进入 TUN 后由 ListenerHandler 强制 DIRECT"
                .into(),
        );
    }
    if !plan.route_address_set.is_empty() {
        warnings.push(
            "route_address_set 是动态规则集，VpnService.Builder 无法预先生成白名单路由；进入 TUN 后由 TUN inbound 规则判定"
                .into(),
        );
    }
    if !plan.filters.include_uid.is_empty()
        || !plan.filters.include_uid_range.is_empty()
        || !plan.filters.exclude_uid.is_empty()
        || !plan.filters.exclude_uid_range.is_empty()
        || !plan.filters.include_gid.is_empty()
        || !plan.filters.include_gid_range.is_empty()
        || !plan.filters.exclude_gid.is_empty()
        || !plan.filters.exclude_gid_range.is_empty()
    {
        warnings.push(
            "VpnService.Builder 不支持 UID/GID 过滤；root TUN 路径已通过 /proc/net 查询 UID/GID 实现 PASS-through 等价语义"
                .into(),
        );
    }

    AndroidVpnServiceConfig {
        interface_name: plan.interface_name.clone(),
        mtu: plan.mtu,
        addresses,
        routes,
        dns_servers,
        allowed_applications,
        disallowed_applications,
        warnings,
    }
}

pub fn build_vpn_service_config_json(plan: &CapturePlan) -> Result<String, serde_json::Error> {
    serde_json::to_string(&build_vpn_service_config(plan))
}

fn subtract_routes(includes: &[IpNet], excludes: &[IpNet]) -> Vec<IpNet> {
    let mut out = Vec::new();
    for include in includes {
        let include_range = NetRange::from_net(*include);
        let mut ranges = vec![(include_range.start, include_range.end)];
        for exclude in excludes {
            let exclude_range = NetRange::from_net(*exclude);
            if include_range.bits != exclude_range.bits {
                continue;
            }
            let mut next = Vec::new();
            for (start, end) in ranges {
                if exclude_range.end < start || exclude_range.start > end {
                    next.push((start, end));
                    continue;
                }
                if exclude_range.start > start {
                    next.push((start, exclude_range.start - 1));
                }
                if exclude_range.end < end {
                    next.push((exclude_range.end + 1, end));
                }
            }
            ranges = next;
            if ranges.is_empty() {
                break;
            }
        }
        for (start, end) in ranges {
            out.extend(range_to_cidrs(start, end, include_range.bits));
        }
    }
    out.sort_by_key(net_sort_key);
    out
}

#[derive(Clone, Copy)]
struct NetRange {
    start: u128,
    end: u128,
    bits: u8,
}

impl NetRange {
    fn from_net(net: IpNet) -> Self {
        match net {
            IpNet::V4(n) => {
                let start = u32::from(n.addr()) as u128;
                let host_bits = 32 - n.prefix_len();
                let size = if host_bits == 32 {
                    1u128 << 32
                } else {
                    1u128 << host_bits
                };
                Self {
                    start,
                    end: start + size - 1,
                    bits: 32,
                }
            }
            IpNet::V6(n) => {
                let start = u128::from(n.addr());
                let host_bits = 128 - n.prefix_len();
                let end = if host_bits == 128 {
                    u128::MAX
                } else {
                    start + (1u128 << host_bits) - 1
                };
                Self {
                    start,
                    end,
                    bits: 128,
                }
            }
        }
    }
}

fn range_to_cidrs(start: u128, end: u128, bits: u8) -> Vec<IpNet> {
    if start > end {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = start;
    loop {
        let mut prefix = aligned_prefix(cur, bits);
        while block_end(cur, prefix, bits) > end {
            prefix += 1;
        }
        out.push(net_from_parts(cur, prefix, bits));
        let last = block_end(cur, prefix, bits);
        if last == u128::MAX || last >= end {
            break;
        }
        cur = last + 1;
    }
    out
}

fn aligned_prefix(value: u128, bits: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let trailing = value.trailing_zeros().min(bits as u32) as u8;
    bits - trailing
}

fn block_end(start: u128, prefix: u8, bits: u8) -> u128 {
    let host_bits = bits - prefix;
    if host_bits == 128 {
        u128::MAX
    } else {
        let span = (1u128 << host_bits) - 1;
        start.saturating_add(span)
    }
}

fn net_from_parts(start: u128, prefix: u8, bits: u8) -> IpNet {
    if bits == 32 {
        IpNet::V4(Ipv4Net::new(Ipv4Addr::from(start as u32), prefix).unwrap())
    } else {
        IpNet::V6(Ipv6Net::new(Ipv6Addr::from(start), prefix).unwrap())
    }
}

fn net_sort_key(net: &IpNet) -> (u8, u128, u8) {
    match net {
        IpNet::V4(n) => (4, u32::from(n.addr()) as u128, n.prefix_len()),
        IpNet::V6(n) => (6, u128::from(n.addr()), n.prefix_len()),
    }
}

fn prefix_sort_key(prefix: &AndroidIpPrefix) -> (u8, u128, u8) {
    match prefix.address {
        IpAddr::V4(ip) => (4, u32::from(ip) as u128, prefix.prefix),
        IpAddr::V6(ip) => (6, u128::from(ip), prefix.prefix),
    }
}

#[cfg(test)]
mod tests {
    use core_config::model::{Capture, CaptureMethod, CaptureResolver};

    use super::*;

    fn plan(mut capture: Capture) -> CapturePlan {
        capture.on = true;
        capture.method = CaptureMethod::VirtualNic;
        capture.tun.auto_route = true;
        capture.tun.inet6 = true;
        CapturePlan::from_config(&capture).unwrap()
    }

    #[test]
    fn vpn_service_config_exports_addresses_default_routes_and_hijack_dns() {
        let mut capture = Capture::default();
        capture.resolver = CaptureResolver::Hijack;
        capture.tun.interface_name = Some("rpktun0".into());
        capture.tun.address = vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()];
        let cfg = build_vpn_service_config(&plan(capture));

        assert_eq!(cfg.interface_name, "rpktun0");
        assert_eq!(cfg.addresses.len(), 2);
        assert!(cfg.addresses.contains(&AndroidIpPrefix {
            address: "172.19.0.1".parse().unwrap(),
            prefix: 30,
        }));
        assert!(cfg.addresses.contains(&AndroidIpPrefix {
            address: "fdfe:dcba:9876::1".parse().unwrap(),
            prefix: 126,
        }));
        assert!(routes_cover(&cfg.routes, "8.8.8.8".parse().unwrap()));
        assert!(routes_cover(
            &cfg.routes,
            "2001:4860:4860::8888".parse().unwrap()
        ));
        assert!(!routes_cover(&cfg.routes, "100.64.0.1".parse().unwrap()));
        assert!(!routes_cover(
            &cfg.routes,
            "fd7a:115c:a1e0::1".parse().unwrap()
        ));
        assert_eq!(
            cfg.dns_servers,
            vec![
                "172.19.0.1".parse::<IpAddr>().unwrap(),
                "fdfe:dcba:9876::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn vpn_service_routes_split_static_excludes_for_android_builder() {
        let mut capture = Capture::default();
        capture.tun.address = vec!["172.19.0.1/30".into()];
        capture.tun.route_address = vec!["10.0.0.0/30".into()];
        capture.tun.route_exclude_address = vec!["10.0.0.1/32".into()];
        let cfg = build_vpn_service_config(&plan(capture));

        assert_eq!(
            cfg.routes,
            vec![
                AndroidIpPrefix {
                    address: "10.0.0.0".parse().unwrap(),
                    prefix: 32,
                },
                AndroidIpPrefix {
                    address: "10.0.0.2".parse().unwrap(),
                    prefix: 31,
                }
            ]
        );
    }

    #[test]
    fn vpn_service_uses_allowed_applications_as_android_builder_mode() {
        let mut capture = Capture::default();
        capture.tun.include_package = vec!["com.example.only".into()];
        capture.tun.exclude_package = vec!["com.example.ignored".into()];
        let cfg = build_vpn_service_config(&plan(capture));

        assert_eq!(cfg.allowed_applications, vec!["com.example.only"]);
        assert!(cfg.disallowed_applications.is_empty());
        assert!(cfg.warnings.iter().any(|w| w.contains("exclude_package")));
    }

    fn routes_cover(routes: &[AndroidIpPrefix], ip: IpAddr) -> bool {
        routes.iter().any(|r| match (r.address, ip) {
            (IpAddr::V4(addr), IpAddr::V4(ip)) => Ipv4Net::new(addr, r.prefix)
                .map(|n| n.contains(&ip))
                .unwrap_or(false),
            (IpAddr::V6(addr), IpAddr::V6(ip)) => Ipv6Net::new(addr, r.prefix)
                .map(|n| n.contains(&ip))
                .unwrap_or(false),
            _ => false,
        })
    }
}
