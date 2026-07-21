//! Capture-owned host resource declarations for mesh conflict arbitration.
//!
//! The public API deliberately returns unowned [`ResourceClaim`] values. The
//! process that embeds `core-capture` supplies the host owner identity; all
//! knowledge about platform routes, marks, interfaces, DNS, and firewall
//! mutations remains beside the implementations that perform those mutations.

use std::{
    collections::{BTreeSet, HashSet},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use core_mesh::{FwmarkRange, ResourceClaim, SocketTransport, SystemResource};

use crate::engine::{CaptureFilters, CapturePlan, EngineKind};

pub(crate) const DEFAULT_ROUTE_V4: &str = "0.0.0.0/0";
pub(crate) const DEFAULT_ROUTE_V6: &str = "::/0";
pub(crate) const LINUX_TUN_SPLIT_DEFAULT_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
pub(crate) const LINUX_TUN_SPLIT_DEFAULT_V6: [&str; 2] = ["::/1", "8000::/1"];

/// Return every host resource that the selected capture implementation can
/// reserve on the current platform.
///
/// Route declarations intentionally contain two complementary views:
///
/// - [`SystemResource::RoutePrefix`] names the concrete kernel route object,
///   including its policy table.
/// - [`SystemResource::DefaultRouteV4`] / [`SystemResource::DefaultRouteV6`]
///   name logical ownership of effective catch-all traffic.
///
/// All claims are exclusive, sorted, and deduplicated. Android declarations
/// never execute capability probes: TUN declares the conservative union of the
/// root Linux path and the framework-preconfigured VpnService fallback, while
/// transparent capture declares the fail-closed union of every runtime tier.
/// Linux auto-redirect is likewise a fail-closed union because its
/// nftables/TPROXY/NAT fallback is selected only while installing rules.
pub fn host_resource_claims(plan: &CapturePlan) -> Vec<ResourceClaim> {
    // Keep this guard ahead of even compile-time platform selection. More
    // importantly, Android capability detection is intentionally absent from
    // this declaration path: it may run `modprobe` during later activation.
    if !plan.on || matches!(plan.kind, EngineKind::None) {
        return Vec::new();
    }
    claims_for_platform(plan, current_platform())
}

#[allow(dead_code)] // Every variant is constructed by a different target cfg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPlatform {
    Linux,
    Android,
    Windows,
    Macos,
    Ios,
    Other,
}

/// Compile-time-only platform selection for the pure declaration boundary.
///
/// This is a `const fn` so Android preflight cannot accidentally grow a
/// command-based capability probe.
const fn current_platform() -> HostPlatform {
    #[cfg(target_os = "linux")]
    {
        return HostPlatform::Linux;
    }
    #[cfg(target_os = "android")]
    {
        return HostPlatform::Android;
    }
    #[cfg(target_os = "windows")]
    {
        return HostPlatform::Windows;
    }
    #[cfg(target_os = "macos")]
    {
        return HostPlatform::Macos;
    }
    #[cfg(target_os = "ios")]
    {
        // iOS uses a NetworkExtension-preconfigured fd; the host application,
        // not this crate's platform backend, owns its interface and routes.
        // CaptureSupervisor still owns its private DNS listener.
        return HostPlatform::Ios;
    }
    #[allow(unreachable_code)]
    HostPlatform::Other
}

fn claims_for_platform(plan: &CapturePlan, platform: HostPlatform) -> Vec<ResourceClaim> {
    if !plan.on || matches!(plan.kind, EngineKind::None) {
        return Vec::new();
    }

    let mut claims = BTreeSet::new();
    let supported = match (platform, plan.kind) {
        (HostPlatform::Linux, EngineKind::Tun) => {
            linux_tun_claims(plan, &mut claims);
            true
        }
        (HostPlatform::Android, EngineKind::Tun) => {
            android_tun_claims(plan, &mut claims);
            true
        }
        (HostPlatform::Linux, EngineKind::Tproxy) => {
            linux_tproxy_claims(plan, &mut claims);
            true
        }
        (HostPlatform::Linux, EngineKind::Redirect) => {
            claim(&mut claims, SystemResource::FirewallManager);
            true
        }
        (HostPlatform::Android, EngineKind::Tproxy | EngineKind::Redirect) => {
            android_transparent_claims(&mut claims);
            true
        }
        (HostPlatform::Windows, EngineKind::Tun) => {
            windows_tun_claims(plan, &mut claims);
            if plan.hijack_dns {
                claim(&mut claims, SystemResource::DnsManager);
            }
            true
        }
        (HostPlatform::Macos, EngineKind::Tun) => {
            // macOS chooses the final utunN name only while opening the
            // device. Reserve the namespace before activation instead of
            // pretending that the requested plan name is the real interface.
            claim(&mut claims, SystemResource::InterfaceManager);
            address_prefixes(plan, &mut claims);
            default_route(
                &mut claims,
                DEFAULT_ROUTE_V4,
                SystemResource::DefaultRouteV4,
            );
            true
        }
        // NetworkExtension owns the iOS interface and routes, but the common
        // supervisor still starts its private DNS listener when requested.
        (HostPlatform::Ios, EngineKind::Tun) => true,
        _ => false,
    };

    if supported && plan.hijack_dns {
        capture_dns_listener_claims(platform, &mut claims);
    }

    claims.into_iter().collect()
}

fn windows_tun_claims(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    interface_and_addresses(plan, claims);
    let routes = windows_tun_route_nets(plan);
    if !routes.is_empty() {
        claim(claims, SystemResource::RouteManager);
    }
    for prefix in routes {
        route_prefix_net(claims, None, prefix);
        if prefix.prefix_len() == 0 {
            claim(
                claims,
                if prefix.addr().is_ipv4() {
                    SystemResource::DefaultRouteV4
                } else {
                    SystemResource::DefaultRouteV6
                },
            );
        }
    }
}

fn capture_dns_listener_claims(platform: HostPlatform, claims: &mut BTreeSet<ResourceClaim>) {
    let windows = matches!(platform, HostPlatform::Windows);
    for listen in crate::capture_dns::fake_dns_listen_addrs_for_windows(windows) {
        let address = listen
            .parse()
            .expect("capture DNS listen constants must be valid socket addresses");
        listen_socket_pair(claims, address);
    }
}

fn android_tun_claims(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    // Android opens root /dev/net/tun first and falls back to a fd whose
    // interface, addresses, routes, and DNS were preconfigured by
    // VpnService.Builder. Preflight cannot know which open will succeed, so it
    // reserves the union of both real installation paths.
    linux_tun_claims(plan, claims);
    claim(claims, SystemResource::InterfaceManager);

    let vpn_routes = crate::android_vpn_config::vpn_service_route_nets(plan);
    if !vpn_routes.is_empty() {
        claim(claims, SystemResource::RouteManager);
        for prefix in vpn_routes {
            // Android's framework owns table selection. `None` deliberately
            // means unknown table scope and therefore conflicts conservatively
            // with an overlapping route in any backend-declared table.
            route_prefix_net(claims, None, prefix);
        }
    }
    if plan.hijack_dns {
        // VpnService.Builder.addDnsServer changes the VPN DNS namespace even
        // though the preconfigured device skips Linux DNS management.
        claim(claims, SystemResource::DnsManager);
    }
}

fn linux_tun_claims(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    interface_and_addresses(plan, claims);

    if plan.auto_route {
        claim(claims, SystemResource::RouteManager);
        claim(
            claims,
            SystemResource::RouteTable {
                table: plan.iproute2_table_index,
            },
        );
        for prefix in LINUX_TUN_SPLIT_DEFAULT_V4 {
            route_prefix(claims, Some(plan.iproute2_table_index), prefix);
        }
        if plan.tun_v6_cidr.is_some() {
            for prefix in LINUX_TUN_SPLIT_DEFAULT_V6 {
                route_prefix(claims, Some(plan.iproute2_table_index), prefix);
            }
        }

        // A static route_address-only policy does not own effective default
        // traffic, even though the custom table still contains split defaults.
        if linux_auto_route_is_catch_all(plan) {
            claim(claims, SystemResource::DefaultRouteV4);
            if plan.tun_v6_cidr.is_some() {
                claim(claims, SystemResource::DefaultRouteV6);
            }
        }

        fwmark(claims, tun_outbound_mark(plan));
        if has_linux_identity_filters(&plan.filters) {
            claim(claims, SystemResource::FirewallManager);
        }
    }

    if plan.strict_route {
        // install_strict_route writes IPv4 and IPv6 blackhole ip rules. It does
        // not install a firewall rule.
        claim(claims, SystemResource::RouteManager);
        claim(claims, SystemResource::DefaultRouteV4);
        claim(claims, SystemResource::DefaultRouteV6);
    }

    if plan.auto_redirect {
        // nftables and TPROXY fallbacks install fwmark policy rules into the
        // configured TUN table. They do not create a local-default route (the
        // exact split-default RoutePrefix objects above come only from
        // install_auto_route). NAT REDIRECT may use only the firewall, hence
        // this is the safe union of all successful runtime backends.
        claim(claims, SystemResource::FirewallManager);
        claim(claims, SystemResource::RouteManager);
        claim(
            claims,
            SystemResource::RouteTable {
                table: plan.iproute2_table_index,
            },
        );
        fwmark(
            claims,
            plan.auto_redirect_marks
                .input
                .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK),
        );
        fwmark(claims, tun_outbound_mark(plan));
        fwmark(
            claims,
            plan.auto_redirect_marks
                .reset
                .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_RESET_MARK),
        );
    }
}

fn linux_tproxy_claims(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    let table = crate::tproxy_rules::TPROXY_ROUTE_TABLE;
    claim(claims, SystemResource::RouteManager);
    claim(claims, SystemResource::FirewallManager);
    claim(claims, SystemResource::DefaultRouteV4);
    claim(claims, SystemResource::RouteTable { table });
    route_prefix(claims, Some(table), DEFAULT_ROUTE_V4);
    fwmark(claims, crate::tproxy_rules::TPROXY_FWMARK);
    fwmark(
        claims,
        plan.auto_redirect_marks
            .output
            .unwrap_or(crate::tproxy_rules::TPROXY_FWMARK),
    );

    let address = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        crate::tproxy_rules::TPROXY_PORT,
    ));
    listen_socket_pair(claims, address);

    if plan.ipv6_enabled {
        claim(claims, SystemResource::DefaultRouteV6);
        route_prefix(claims, Some(table), DEFAULT_ROUTE_V6);
        let address = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            crate::tproxy_rules::TPROXY_PORT,
            0,
            0,
        ));
        listen_socket_pair(claims, address);
    }
}

fn android_transparent_claims(claims: &mut BTreeSet<ResourceClaim>) {
    // Runtime capability selection happens only after mesh preflight and may
    // load nf_tproxy modules. A read-only snapshot cannot prove that currently
    // absent modules are not loadable, so reserve the union of all tiers:
    // REDIRECT owns only the firewall, while either TPROXY tier additionally
    // owns both policy-route families, table 100, and mark 1.
    claim(claims, SystemResource::FirewallManager);
    android_tproxy_route_claims(claims);
    claim(claims, SystemResource::DefaultRouteV4);
    claim(claims, SystemResource::DefaultRouteV6);
}

fn android_tproxy_route_claims(claims: &mut BTreeSet<ResourceClaim>) {
    let table = crate::platform::android::TRANSPARENT_ROUTE_TABLE;
    claim(claims, SystemResource::RouteManager);
    claim(claims, SystemResource::RouteTable { table });
    route_prefix(claims, Some(table), DEFAULT_ROUTE_V4);
    route_prefix(claims, Some(table), DEFAULT_ROUTE_V6);
    fwmark(claims, crate::platform::android::TRANSPARENT_FWMARK);
}

fn interface_and_addresses(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    claim(
        claims,
        SystemResource::Interface {
            name: plan.interface_name.clone(),
        },
    );
    address_prefixes(plan, claims);
}

fn address_prefixes(plan: &CapturePlan, claims: &mut BTreeSet<ResourceClaim>) {
    claim(
        claims,
        SystemResource::AddressPrefix {
            prefix: plan.tun_v4_cidr.into(),
        },
    );
    if let Some(prefix) = plan.tun_v6_cidr {
        // Platform setup reads tun_v6_cidr directly. ipv6_enabled only affects
        // packet classification and must not hide an address actually created.
        claim(
            claims,
            SystemResource::AddressPrefix {
                prefix: prefix.into(),
            },
        );
    }
}

fn default_route(claims: &mut BTreeSet<ResourceClaim>, prefix: &str, logical: SystemResource) {
    claim(claims, SystemResource::RouteManager);
    route_prefix(claims, None, prefix);
    claim(claims, logical);
}

fn route_prefix(claims: &mut BTreeSet<ResourceClaim>, table: Option<u32>, prefix: &str) {
    route_prefix_net(
        claims,
        table,
        prefix
            .parse()
            .expect("capture route constants must be valid prefixes"),
    );
}

fn route_prefix_net(
    claims: &mut BTreeSet<ResourceClaim>,
    table: Option<u32>,
    prefix: ipnet::IpNet,
) {
    claim(claims, SystemResource::RoutePrefix { table, prefix });
}

fn listen_socket_pair(claims: &mut BTreeSet<ResourceClaim>, address: SocketAddr) {
    for transport in [SocketTransport::Tcp, SocketTransport::Udp] {
        claim(claims, SystemResource::ListenSocket { transport, address });
    }
}

fn fwmark(claims: &mut BTreeSet<ResourceClaim>, mark: u32) {
    claim(
        claims,
        SystemResource::FwmarkRange {
            range: FwmarkRange::new(mark, mark)
                .expect("a single capture fwmark is always a valid range"),
        },
    );
}

fn claim(claims: &mut BTreeSet<ResourceClaim>, resource: SystemResource) {
    claims.insert(ResourceClaim::exclusive(resource));
}

pub(crate) fn tun_outbound_mark(plan: &CapturePlan) -> u32 {
    plan.auto_redirect_marks
        .output
        .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK)
}

pub(crate) fn linux_auto_route_is_catch_all(plan: &CapturePlan) -> bool {
    plan.route_addresses.is_empty() || !plan.route_address_set.is_empty()
}

/// Exact route set installed by the Windows TUN backend.
///
/// Keep this target-independent so resource arbitration and Windows startup
/// cannot drift even when tests run on a non-Windows host.
pub(crate) fn windows_tun_route_nets(plan: &CapturePlan) -> Vec<ipnet::IpNet> {
    if !plan.auto_route {
        return Vec::new();
    }

    let mut routes = if plan.route_addresses.is_empty() || !plan.route_address_set.is_empty() {
        let mut defaults = vec![
            DEFAULT_ROUTE_V4
                .parse()
                .expect("constant IPv4 default route"),
        ];
        if plan.ipv6_enabled && plan.tun_v6_cidr.is_some() {
            defaults.push(
                DEFAULT_ROUTE_V6
                    .parse()
                    .expect("constant IPv6 default route"),
            );
        }
        defaults
    } else {
        plan.route_addresses.clone()
    };
    routes.retain(|route| {
        route.addr().is_ipv4() || (plan.ipv6_enabled && plan.tun_v6_cidr.is_some())
    });
    let mut seen = HashSet::with_capacity(routes.len());
    routes.retain(|route| seen.insert(*route));
    routes
}

pub(crate) fn has_linux_identity_filters(filters: &CaptureFilters) -> bool {
    !filters.include_uid.is_empty()
        || !filters.include_uid_range.is_empty()
        || !filters.exclude_uid.is_empty()
        || !filters.exclude_uid_range.is_empty()
        || !filters.include_gid.is_empty()
        || !filters.include_gid_range.is_empty()
        || !filters.exclude_gid.is_empty()
        || !filters.exclude_gid_range.is_empty()
        || !filters.include_package.is_empty()
        || !filters.exclude_package.is_empty()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use core_config::model::{Capture, CaptureMethod};

    use super::*;

    fn plan(kind: EngineKind) -> CapturePlan {
        let mut capture = Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            ..Capture::default()
        };
        capture.tun.interface_name = Some("claims-test0".into());
        capture.tun.address = vec!["198.19.0.0/30".into(), "fd00:1234::/126".into()];
        capture.tun.inet6 = true;
        let mut plan = CapturePlan::from_config(&capture).unwrap();
        plan.kind = kind;
        plan.auto_route = false;
        plan.strict_route = false;
        plan.auto_redirect = false;
        plan.hijack_dns = false;
        plan
    }

    fn resources(plan: &CapturePlan, platform: HostPlatform) -> BTreeSet<SystemResource> {
        claims_for_platform(plan, platform)
            .into_iter()
            .map(|claim| {
                assert_eq!(claim.mode, core_mesh::ClaimMode::Exclusive);
                claim.resource
            })
            .collect()
    }

    fn contains_prefix(
        resources: &BTreeSet<SystemResource>,
        table: Option<u32>,
        prefix: &str,
    ) -> bool {
        resources.contains(&SystemResource::RoutePrefix {
            table,
            prefix: prefix.parse().unwrap(),
        })
    }

    fn contains_listener_pair(resources: &BTreeSet<SystemResource>, address: SocketAddr) -> bool {
        [SocketTransport::Tcp, SocketTransport::Udp]
            .into_iter()
            .all(|transport| {
                resources.contains(&SystemResource::ListenSocket { transport, address })
            })
    }

    #[test]
    fn disabled_or_none_capture_has_no_claims() {
        let mut disabled = plan(EngineKind::Tun);
        disabled.on = false;
        for platform in [
            HostPlatform::Linux,
            HostPlatform::Android,
            HostPlatform::Windows,
            HostPlatform::Macos,
            HostPlatform::Ios,
            HostPlatform::Other,
        ] {
            assert!(claims_for_platform(&disabled, platform).is_empty());
            assert!(claims_for_platform(&plan(EngineKind::None), platform).is_empty());
        }
        assert!(host_resource_claims(&disabled).is_empty());
        assert!(host_resource_claims(&plan(EngineKind::None)).is_empty());
    }

    #[test]
    fn platform_selection_is_const_and_cannot_probe_android_capabilities() {
        // This assignment is evaluated in a const context. Adding su, modprobe,
        // filesystem, or process probing to current_platform() would make this
        // test fail to compile.
        const SELECTED: HostPlatform = current_platform();
        let _ = SELECTED;
    }

    #[test]
    fn linux_tun_claims_exact_split_routes_table_addresses_and_output_mark() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.iproute2_table_index = 4242;
        plan.auto_redirect_marks.output = Some(0x55);
        plan.ipv6_enabled = false;
        let resources = resources(&plan, HostPlatform::Linux);

        assert!(resources.contains(&SystemResource::Interface {
            name: "claims-test0".into()
        }));
        assert!(resources.contains(&SystemResource::AddressPrefix {
            prefix: "198.19.0.0/30".parse().unwrap()
        }));
        assert!(resources.contains(&SystemResource::AddressPrefix {
            prefix: "fd00:1234::/126".parse().unwrap()
        }));
        for prefix in LINUX_TUN_SPLIT_DEFAULT_V4
            .into_iter()
            .chain(LINUX_TUN_SPLIT_DEFAULT_V6)
        {
            assert!(contains_prefix(&resources, Some(4242), prefix));
        }
        assert!(resources.contains(&SystemResource::RouteTable { table: 4242 }));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(resources.contains(&SystemResource::DefaultRouteV6));
        assert!(resources.contains(&SystemResource::FwmarkRange {
            range: FwmarkRange::new(0x55, 0x55).unwrap()
        }));
        assert!(!resources.contains(&SystemResource::FirewallManager));
    }

    #[test]
    fn linux_static_route_policy_keeps_real_routes_without_logical_default_claims() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.route_addresses = vec!["203.0.113.0/24".parse().unwrap()];
        let resources = resources(&plan, HostPlatform::Linux);

        assert!(contains_prefix(
            &resources,
            Some(plan.iproute2_table_index),
            "0.0.0.0/1"
        ));
        assert!(!resources.contains(&SystemResource::DefaultRouteV4));
        assert!(!resources.contains(&SystemResource::DefaultRouteV6));
    }

    #[test]
    fn linux_strict_route_owns_policy_routes_not_firewall() {
        let mut plan = plan(EngineKind::Tun);
        plan.strict_route = true;
        plan.tun_v6_cidr = None;
        plan.ipv6_enabled = false;
        let resources = resources(&plan, HostPlatform::Linux);

        assert!(resources.contains(&SystemResource::RouteManager));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(resources.contains(&SystemResource::DefaultRouteV6));
        assert!(!resources.contains(&SystemResource::FirewallManager));
    }

    #[test]
    fn linux_identity_bypass_makes_auto_route_a_firewall_owner() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.filters.exclude_uid.push(1000);
        let resources = resources(&plan, HostPlatform::Linux);

        assert!(resources.contains(&SystemResource::FirewallManager));
    }

    #[test]
    fn linux_auto_redirect_claims_configured_table_firewall_and_all_marks() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_redirect = true;
        plan.iproute2_table_index = 5353;
        plan.auto_redirect_marks.input = Some(0x31);
        plan.auto_redirect_marks.output = Some(0x32);
        plan.auto_redirect_marks.reset = Some(0x33);
        let resources = resources(&plan, HostPlatform::Linux);

        assert!(resources.contains(&SystemResource::RouteManager));
        assert!(resources.contains(&SystemResource::RouteTable { table: 5353 }));
        assert!(resources.contains(&SystemResource::FirewallManager));
        for mark in [0x31, 0x32, 0x33] {
            assert!(resources.contains(&SystemResource::FwmarkRange {
                range: FwmarkRange::new(mark, mark).unwrap()
            }));
        }
    }

    #[test]
    fn linux_tproxy_claims_dual_stack_routes_marks_and_listener_set() {
        let mut plan = plan(EngineKind::Tproxy);
        plan.iproute2_table_index = 9999;
        plan.auto_redirect_marks.output = Some(0x2024);
        plan.ipv6_enabled = true;
        let resources = resources(&plan, HostPlatform::Linux);
        let table = crate::tproxy_rules::TPROXY_ROUTE_TABLE;
        let ipv4 = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            crate::tproxy_rules::TPROXY_PORT,
        ));
        let ipv6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            crate::tproxy_rules::TPROXY_PORT,
            0,
            0,
        ));

        assert!(resources.contains(&SystemResource::RouteTable { table }));
        assert!(!resources.contains(&SystemResource::RouteTable { table: 9999 }));
        assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V4));
        assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V6));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(resources.contains(&SystemResource::DefaultRouteV6));
        for mark in [crate::tproxy_rules::TPROXY_FWMARK, 0x2024] {
            assert!(resources.contains(&SystemResource::FwmarkRange {
                range: FwmarkRange::new(mark, mark).unwrap()
            }));
        }
        assert!(contains_listener_pair(&resources, ipv4));
        assert!(contains_listener_pair(&resources, ipv6));
    }

    #[test]
    fn linux_tproxy_omits_every_ipv6_claim_when_ipv6_is_disabled() {
        let mut plan = plan(EngineKind::Tproxy);
        plan.ipv6_enabled = false;
        let resources = resources(&plan, HostPlatform::Linux);
        let table = crate::tproxy_rules::TPROXY_ROUTE_TABLE;
        let ipv6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            crate::tproxy_rules::TPROXY_PORT,
            0,
            0,
        ));

        assert!(!contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V6));
        assert!(!resources.contains(&SystemResource::DefaultRouteV6));
        assert!(!contains_listener_pair(&resources, ipv6));
    }

    #[test]
    fn linux_redirect_only_mutates_firewall() {
        let resources = resources(&plan(EngineKind::Redirect), HostPlatform::Linux);
        assert_eq!(resources, BTreeSet::from([SystemResource::FirewallManager]));
    }

    #[test]
    fn android_tun_reserves_root_and_vpnservice_route_union() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.hijack_dns = true;
        plan.iproute2_table_index = 6161;
        let vpn_routes = crate::android_vpn_config::vpn_service_route_nets(&plan);
        let resources = resources(&plan, HostPlatform::Android);

        // Root /dev/net/tun path.
        assert!(resources.contains(&SystemResource::RouteTable { table: 6161 }));
        assert!(resources.contains(&SystemResource::InterfaceManager));
        assert!(resources.contains(&SystemResource::Interface {
            name: "claims-test0".into()
        }));
        for prefix in LINUX_TUN_SPLIT_DEFAULT_V4
            .into_iter()
            .chain(LINUX_TUN_SPLIT_DEFAULT_V6)
        {
            assert!(contains_prefix(&resources, Some(6161), prefix));
        }

        // VpnService.Builder fallback path. Its table is selected by Android,
        // so every exact Builder route is declared with unknown table scope.
        assert!(!vpn_routes.is_empty());
        for prefix in vpn_routes {
            assert!(resources.contains(&SystemResource::RoutePrefix {
                table: None,
                prefix,
            }));
        }
        assert!(resources.contains(&SystemResource::DnsManager));
    }

    #[test]
    fn android_vpnservice_static_route_is_claimed_when_auto_route_is_false() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = false;
        plan.route_addresses = vec!["203.0.113.0/24".parse().unwrap()];
        let resources = resources(&plan, HostPlatform::Android);

        assert!(resources.contains(&SystemResource::RouteManager));
        assert!(contains_prefix(&resources, None, "203.0.113.0/24"));
        assert!(!resources.contains(&SystemResource::RouteTable {
            table: plan.iproute2_table_index,
        }));
    }

    #[test]
    fn android_transparent_preflight_is_pure_fail_closed_union() {
        for kind in [EngineKind::Tproxy, EngineKind::Redirect] {
            // HostPlatform::Android carries no detected capability. This pure
            // boundary therefore cannot run su/modprobe, and the result still
            // covers a TPROXY tier that runtime activation may unlock later.
            let mut plan = plan(kind);
            plan.iproute2_table_index = 9999;
            let resources = resources(&plan, HostPlatform::Android);
            let table = crate::platform::android::TRANSPARENT_ROUTE_TABLE;

            assert!(resources.contains(&SystemResource::FirewallManager));
            assert!(resources.contains(&SystemResource::RouteTable { table }));
            assert!(!resources.contains(&SystemResource::RouteTable { table: 9999 }));
            assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V4));
            assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V6));
            assert!(resources.contains(&SystemResource::DefaultRouteV4));
            assert!(resources.contains(&SystemResource::DefaultRouteV6));
            assert!(
                resources.contains(&SystemResource::FwmarkRange {
                    range: FwmarkRange::new(
                        crate::platform::android::TRANSPARENT_FWMARK,
                        crate::platform::android::TRANSPARENT_FWMARK,
                    )
                    .unwrap()
                })
            );
        }
    }

    #[test]
    fn android_transparent_uses_shared_runtime_table_and_mark_constants() {
        let mut plan = plan(EngineKind::Redirect);
        plan.iproute2_table_index = 9999;
        let resources = resources(&plan, HostPlatform::Android);
        let table = crate::platform::android::TRANSPARENT_ROUTE_TABLE;

        assert!(resources.contains(&SystemResource::RouteTable { table }));
        assert!(!resources.contains(&SystemResource::RouteTable { table: 9999 }));
        assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V4));
        assert!(contains_prefix(&resources, Some(table), DEFAULT_ROUTE_V6));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(resources.contains(&SystemResource::DefaultRouteV6));
        assert!(
            resources.contains(&SystemResource::FwmarkRange {
                range: FwmarkRange::new(
                    crate::platform::android::TRANSPARENT_FWMARK,
                    crate::platform::android::TRANSPARENT_FWMARK,
                )
                .unwrap()
            })
        );
    }

    #[test]
    fn windows_tun_without_auto_route_declares_no_route_ownership() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = false;
        let resources = resources(&plan, HostPlatform::Windows);

        assert!(!resources.contains(&SystemResource::RouteManager));
        assert!(!contains_prefix(&resources, None, DEFAULT_ROUTE_V4));
        assert!(!contains_prefix(&resources, None, DEFAULT_ROUTE_V6));
        assert!(!resources.contains(&SystemResource::DefaultRouteV4));
        assert!(!resources.contains(&SystemResource::DefaultRouteV6));
        assert!(resources.contains(&SystemResource::AddressPrefix {
            prefix: "fd00:1234::/126".parse().unwrap()
        }));
        assert!(!resources.contains(&SystemResource::FirewallManager));
    }

    #[test]
    fn windows_tun_claims_the_shared_default_route_set_with_ipv6_gates() {
        let mut dual_stack = plan(EngineKind::Tun);
        dual_stack.auto_route = true;
        dual_stack.ipv6_enabled = true;
        let dual_resources = resources(&dual_stack, HostPlatform::Windows);
        assert!(contains_prefix(&dual_resources, None, DEFAULT_ROUTE_V4));
        assert!(contains_prefix(&dual_resources, None, DEFAULT_ROUTE_V6));
        assert!(dual_resources.contains(&SystemResource::DefaultRouteV4));
        assert!(dual_resources.contains(&SystemResource::DefaultRouteV6));

        dual_stack.ipv6_enabled = false;
        let ipv4_resources = resources(&dual_stack, HostPlatform::Windows);
        assert!(contains_prefix(&ipv4_resources, None, DEFAULT_ROUTE_V4));
        assert!(!contains_prefix(&ipv4_resources, None, DEFAULT_ROUTE_V6));
        assert!(!ipv4_resources.contains(&SystemResource::DefaultRouteV6));

        dual_stack.ipv6_enabled = true;
        dual_stack.tun_v6_cidr = None;
        let no_tun_v6_resources = resources(&dual_stack, HostPlatform::Windows);
        assert!(!contains_prefix(
            &no_tun_v6_resources,
            None,
            DEFAULT_ROUTE_V6
        ));
        assert!(!no_tun_v6_resources.contains(&SystemResource::DefaultRouteV6));
    }

    #[test]
    fn windows_tun_claims_filtered_deduplicated_static_routes() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.route_addresses = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
            "203.0.113.0/24".parse().unwrap(),
        ];
        plan.ipv6_enabled = false;
        let route_nets = windows_tun_route_nets(&plan);
        let resources = resources(&plan, HostPlatform::Windows);

        assert_eq!(route_nets, vec!["203.0.113.0/24".parse().unwrap()]);
        assert!(contains_prefix(&resources, None, "203.0.113.0/24"));
        assert!(!contains_prefix(&resources, None, "2001:db8::/32"));
        assert!(!resources.contains(&SystemResource::DefaultRouteV4));
        assert!(!resources.contains(&SystemResource::DefaultRouteV6));
    }

    #[test]
    fn windows_route_address_set_forces_catch_all_route_claims() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = true;
        plan.route_addresses = vec!["203.0.113.0/24".parse().unwrap()];
        plan.route_address_set = vec!["geoip-cn".into()];
        let resources = resources(&plan, HostPlatform::Windows);

        assert!(contains_prefix(&resources, None, DEFAULT_ROUTE_V4));
        assert!(contains_prefix(&resources, None, DEFAULT_ROUTE_V6));
        assert!(!contains_prefix(&resources, None, "203.0.113.0/24"));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(resources.contains(&SystemResource::DefaultRouteV6));
    }

    #[test]
    fn capture_private_dns_listeners_match_runtime_platform_selection() {
        let mut plan = plan(EngineKind::Tun);
        plan.hijack_dns = true;
        let unix = "127.0.0.1:5454".parse().unwrap();
        for kind in [EngineKind::Tun, EngineKind::Tproxy, EngineKind::Redirect] {
            plan.kind = kind;
            for platform in [HostPlatform::Linux, HostPlatform::Android] {
                let resources = resources(&plan, platform);
                assert!(contains_listener_pair(&resources, unix));
            }
        }
        plan.kind = EngineKind::Tun;
        for platform in [HostPlatform::Macos, HostPlatform::Ios] {
            let resources = resources(&plan, platform);
            assert!(contains_listener_pair(&resources, unix));
        }

        let windows = resources(&plan, HostPlatform::Windows);
        assert!(windows.contains(&SystemResource::DnsManager));
        assert!(contains_listener_pair(
            &windows,
            "127.0.0.1:53".parse().unwrap()
        ));
        assert!(contains_listener_pair(
            &windows,
            "[::1]:53".parse().unwrap()
        ));

        plan.hijack_dns = false;
        let resources = resources(&plan, HostPlatform::Windows);
        assert!(!resources.contains(&SystemResource::DnsManager));
        assert!(!contains_listener_pair(
            &resources,
            "127.0.0.1:53".parse().unwrap()
        ));
    }

    #[test]
    fn macos_tun_claims_actual_v4_default_without_documented_but_unimplemented_pf() {
        let mut plan = plan(EngineKind::Tun);
        plan.auto_route = false;
        plan.hijack_dns = true;
        let resources = resources(&plan, HostPlatform::Macos);

        assert!(contains_prefix(&resources, None, DEFAULT_ROUTE_V4));
        assert!(resources.contains(&SystemResource::DefaultRouteV4));
        assert!(!resources.contains(&SystemResource::DefaultRouteV6));
        assert!(!resources.contains(&SystemResource::DnsManager));
        assert!(!resources.contains(&SystemResource::FirewallManager));
        assert!(resources.contains(&SystemResource::InterfaceManager));
        assert!(!resources.contains(&SystemResource::Interface {
            name: "claims-test0".into()
        }));
    }

    #[test]
    fn unsupported_platform_engine_pairs_claim_nothing() {
        assert!(claims_for_platform(&plan(EngineKind::Tproxy), HostPlatform::Windows).is_empty());
        assert!(claims_for_platform(&plan(EngineKind::Redirect), HostPlatform::Macos).is_empty());
        assert!(claims_for_platform(&plan(EngineKind::Tun), HostPlatform::Other).is_empty());
    }

    #[test]
    fn public_api_uses_the_cfg_selected_platform() {
        let plan = plan(EngineKind::Tun);
        let actual = host_resource_claims(&plan);

        #[cfg(target_os = "linux")]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Linux));
        #[cfg(target_os = "android")]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Android));
        #[cfg(target_os = "windows")]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Windows));
        #[cfg(target_os = "macos")]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Macos));
        #[cfg(target_os = "ios")]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Ios));
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "ios"
        )))]
        assert_eq!(actual, claims_for_platform(&plan, HostPlatform::Other));
    }
}
