//! Android Root TUN policy routing.
//!
//! Android is not a desktop Linux routing environment. `netd` owns a stack of
//! fwmark, UID, input-interface, and output-interface rules whose physical
//! tables change whenever ConnectivityService changes the active network.
//! This backend therefore never guesses `main` or an interface table. Bypass
//! traffic jumps back to netd at its first reserved priority, while only the
//! selected local UIDs are sent to the private TUN table.

#![cfg(target_os = "android")]

use std::collections::HashMap;

use core_config::model::CaptureTraffic;
use tracing::{info, warn};

use crate::{
    engine::{CaptureError, CaptureFilters, CapturePlan},
    linux_netlink::{PolicyFamily, PolicyRule, PolicyRuleLease},
    route_table::{ManagedRoute, RouteTable},
};

/// First priority owned by Android netd. Current AOSP reserves 10000 through
/// 32000. Root TUN rules live before this range and use `goto 10000` to resume
/// Android's own per-UID, per-network selection without hard-coding a table.
pub(crate) const NETD_FIRST_PRIORITY: u32 = 10_000;

/// Bits 21 through 28 are the reserved portion of Android's Fwmark layout.
/// The lower bits are netId and routing flags. The upper three are vendor and
/// wakeup bits. Only this mask can be safely used for an Android-private mark.
const ANDROID_RESERVED_MARK_MASK: u32 = 0x1fe0_0000;
const ANDROID_USER_RANGE: u32 = 100_000;

pub(crate) fn requires_identity_firewall(filters: &CaptureFilters) -> bool {
    !filters.include_gid.is_empty()
        || !filters.include_gid_range.is_empty()
        || !filters.exclude_gid.is_empty()
        || !filters.exclude_gid_range.is_empty()
}

pub(crate) fn install(
    routes: &RouteTable,
    plan: &CapturePlan,
    ipv6_tun: bool,
) -> Result<PolicyRuleLease, CaptureError> {
    validate_android_plan(plan)?;
    if plan.auto_route {
        install_tun_routes(routes, plan, ipv6_tun)?;
    }

    let package_uids = load_package_uids(&plan.filters)?;
    let included_uids = included_uid_ranges(&plan.filters, &package_uids)?;
    let excluded_uids = excluded_uid_ranges(&plan.filters, &package_uids)?;
    let rules = build_rules(plan, ipv6_tun, &included_uids, &excluded_uids)?;
    let count = rules.len();
    let lease = crate::linux_netlink::install_policy_rules(rules).map_err(|error| {
        CaptureError::Route(format!(
            "install Android Root TUN policy via rtnetlink: {error}"
        ))
    })?;

    info!(
        target: "capture::android::route",
        table = plan.iproute2_table_index,
        rule_priority = plan.iproute2_rule_index,
        netd_handoff_priority = NETD_FIRST_PRIORITY,
        outbound_mark = format_args!("{:#x}", crate::resource_claims::tun_outbound_mark(plan)),
        included_uid_ranges = included_uids.len(),
        excluded_uid_ranges = excluded_uids.len(),
        rules = count,
        ipv6 = ipv6_tun,
        "Android Root TUN policy installed with netd handoff"
    );
    Ok(lease)
}

fn validate_android_plan(plan: &CapturePlan) -> Result<(), CaptureError> {
    if plan.iproute2_rule_index >= NETD_FIRST_PRIORITY {
        return Err(CaptureError::Route(format!(
            "Android Root TUN iproute2_rule_index must be below netd priority {NETD_FIRST_PRIORITY}; got {}",
            plan.iproute2_rule_index
        )));
    }
    if plan.iproute2_rule_index < 3 {
        return Err(CaptureError::Route(
            "Android Root TUN iproute2_rule_index must be at least 3".into(),
        ));
    }
    let mark = crate::resource_claims::tun_outbound_mark(plan);
    if mark == 0 || mark & !ANDROID_RESERVED_MARK_MASK != 0 {
        return Err(CaptureError::Route(format!(
            "Android output_mark {mark:#x} overlaps netd fwmark fields; use bits inside {ANDROID_RESERVED_MARK_MASK:#x}"
        )));
    }
    if plan.traffic == CaptureTraffic::Lan && has_uid_filters(&plan.filters) {
        return Err(CaptureError::Unsupported(
            "Android traffic=lan cannot use UID, GID, package, or Android-user filters because forwarded packets have no local socket owner"
                .into(),
        ));
    }
    if plan.traffic != CaptureTraffic::Lan
        && (!plan.filters.include_interface.is_empty()
            || !plan.filters.exclude_interface.is_empty())
    {
        return Err(CaptureError::Unsupported(
            "Android local Root TUN cannot infer an application's eventual output interface during policy lookup; include_interface and exclude_interface require traffic=lan"
                .into(),
        ));
    }
    if requires_identity_firewall(&plan.filters) {
        warn!(
            target: "capture::android::route",
            "GID filters require the Android iptables owner matcher; UID and package filters use native fib rules"
        );
    }
    Ok(())
}

fn has_uid_filters(filters: &CaptureFilters) -> bool {
    !filters.include_uid.is_empty()
        || !filters.include_uid_range.is_empty()
        || !filters.exclude_uid.is_empty()
        || !filters.exclude_uid_range.is_empty()
        || !filters.include_android_user.is_empty()
        || !filters.include_package.is_empty()
        || !filters.exclude_package.is_empty()
        || !filters.include_gid.is_empty()
        || !filters.include_gid_range.is_empty()
        || !filters.exclude_gid.is_empty()
        || !filters.exclude_gid_range.is_empty()
}

fn install_tun_routes(
    routes: &RouteTable,
    plan: &CapturePlan,
    ipv6_tun: bool,
) -> Result<(), CaptureError> {
    let mut cidrs = crate::resource_claims::LINUX_TUN_SPLIT_DEFAULT_V4.to_vec();
    if ipv6_tun {
        cidrs.extend_from_slice(&crate::resource_claims::LINUX_TUN_SPLIT_DEFAULT_V6);
    }
    for cidr in cidrs {
        let dest = cidr.parse().map_err(|error| {
            CaptureError::Route(format!("invalid Android TUN route {cidr}: {error}"))
        })?;
        routes
            .add(ManagedRoute {
                dest,
                gateway: None,
                interface: plan.interface_name.clone(),
                metric: 0,
                table: Some(plan.iproute2_table_index),
            })
            .map_err(CaptureError::Route)?;
    }
    Ok(())
}

fn build_rules(
    plan: &CapturePlan,
    ipv6_tun: bool,
    included_uids: &[(u32, u32)],
    excluded_uids: &[(u32, u32)],
) -> Result<Vec<PolicyRule>, CaptureError> {
    let priority = plan.iproute2_rule_index;
    let table = plan.iproute2_table_index;
    let local = plan.traffic != CaptureTraffic::Lan;
    let capture_iifs = capture_input_interfaces(plan);
    let mut rules = Vec::new();
    let families = if ipv6_tun {
        vec![PolicyFamily::V4, PolicyFamily::V6]
    } else {
        vec![PolicyFamily::V4]
    };

    if plan.auto_route {
        let mark = crate::resource_claims::tun_outbound_mark(plan);
        for family in &families {
            rules.push(
                PolicyRule::goto(*family, priority.saturating_sub(1), NETD_FIRST_PRIORITY)
                    .with_fw_mark_mask(mark, mark)
                    .with_incoming_interface("lo"),
            );
        }

        if !local {
            // LAN mode owns forwarded traffic only. Local applications and
            // packets re-injected from the TUN must resume netd routing.
            for interface in std::iter::once("lo")
                .chain(std::iter::once(plan.interface_name.as_str()))
                .chain(plan.filters.exclude_interface.iter().map(String::as_str))
            {
                for family in &families {
                    rules.push(
                        PolicyRule::goto(*family, priority.saturating_sub(2), NETD_FIRST_PRIORITY)
                            .with_incoming_interface(interface),
                    );
                }
            }
        }

        for net in &plan.route_exclude_addresses {
            let family = family_for_net(net);
            if family == PolicyFamily::V6 && !ipv6_tun {
                continue;
            }
            let base = PolicyRule::goto(family, priority.saturating_sub(2), NETD_FIRST_PRIORITY)
                .with_destination(*net);
            if local {
                rules.push(base.with_incoming_interface("lo"));
            } else if capture_iifs.len() == 1 && capture_iifs[0].is_none() {
                rules.push(base);
            } else {
                for interface in capture_iifs.iter().flatten() {
                    rules.push(base.clone().with_incoming_interface(interface.clone()));
                }
            }
        }

        if local {
            for &(start, end) in excluded_uids {
                for family in &families {
                    rules.push(
                        PolicyRule::goto(*family, priority.saturating_sub(2), NETD_FIRST_PRIORITY)
                            .with_incoming_interface("lo")
                            .with_uid_range(start, end),
                    );
                }
            }
        }

        append_scoped_rules(
            &mut rules,
            PolicyRule::lookup(PolicyFamily::V4, priority.saturating_sub(3), table)
                .with_destination(ipnet::IpNet::V4(plan.tun_v4_cidr)),
            &capture_iifs,
        );
        if let Some(v6) = plan.tun_v6_cidr.filter(|_| ipv6_tun) {
            append_scoped_rules(
                &mut rules,
                PolicyRule::lookup(PolicyFamily::V6, priority.saturating_sub(3), table)
                    .with_destination(ipnet::IpNet::V6(v6)),
                &capture_iifs,
            );
        }

        let capture_destinations: Vec<Option<ipnet::IpNet>> =
            if crate::resource_claims::linux_auto_route_is_catch_all(plan) {
                vec![None]
            } else {
                plan.route_addresses.iter().copied().map(Some).collect()
            };
        append_capture_rules(
            &mut rules,
            &families,
            priority,
            table,
            &capture_iifs,
            included_uids,
            &capture_destinations,
            false,
        );
    }

    if plan.strict_route {
        let strict_destinations: Vec<Option<ipnet::IpNet>> =
            if crate::resource_claims::linux_auto_route_is_catch_all(plan) {
                vec![None]
            } else {
                plan.route_addresses.iter().copied().map(Some).collect()
            };
        append_capture_rules(
            &mut rules,
            &families,
            priority.saturating_add(1),
            table,
            &capture_iifs,
            included_uids,
            &strict_destinations,
            true,
        );
    }

    if rules.is_empty() {
        return Err(CaptureError::Route(
            "Android Root TUN policy produced no rules".into(),
        ));
    }
    Ok(rules)
}

#[allow(clippy::too_many_arguments)]
fn append_capture_rules(
    rules: &mut Vec<PolicyRule>,
    families: &[PolicyFamily],
    priority: u32,
    table: u32,
    input_interfaces: &[Option<String>],
    uid_ranges: &[(u32, u32)],
    destinations: &[Option<ipnet::IpNet>],
    blackhole: bool,
) {
    let uid_selectors: Vec<Option<(u32, u32)>> = if !uid_ranges.is_empty() {
        uid_ranges.iter().copied().map(Some).collect()
    } else {
        vec![None]
    };
    for family in families {
        for destination in destinations {
            if destination.is_some_and(|net| family_for_net(&net) != *family) {
                continue;
            }
            for uid in &uid_selectors {
                for input_interface in input_interfaces {
                    let mut rule = if blackhole {
                        PolicyRule::blackhole(*family, priority)
                    } else {
                        PolicyRule::lookup(*family, priority, table)
                    };
                    if let Some(interface) = input_interface {
                        rule = rule.with_incoming_interface(interface.clone());
                    }
                    if let Some(destination) = destination {
                        rule = rule.with_destination(*destination);
                    }
                    if let Some((start, end)) = uid {
                        rule = rule.with_uid_range(*start, *end);
                    }
                    rules.push(rule);
                }
            }
        }
    }
}

fn append_scoped_rules(
    rules: &mut Vec<PolicyRule>,
    rule: PolicyRule,
    input_interfaces: &[Option<String>],
) {
    for interface in input_interfaces {
        if let Some(interface) = interface {
            rules.push(rule.clone().with_incoming_interface(interface.clone()));
        } else {
            rules.push(rule.clone());
        }
    }
}

fn capture_input_interfaces(plan: &CapturePlan) -> Vec<Option<String>> {
    if plan.traffic != CaptureTraffic::Lan {
        vec![Some("lo".into())]
    } else if plan.filters.include_interface.is_empty() {
        vec![None]
    } else {
        plan.filters
            .include_interface
            .iter()
            .cloned()
            .map(Some)
            .collect()
    }
}

fn family_for_net(net: &ipnet::IpNet) -> PolicyFamily {
    if net.addr().is_ipv6() {
        PolicyFamily::V6
    } else {
        PolicyFamily::V4
    }
}

fn load_package_uids(filters: &CaptureFilters) -> Result<HashMap<String, u32>, CaptureError> {
    let requested = filters
        .include_package
        .iter()
        .chain(&filters.exclude_package)
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Ok(HashMap::new());
    }
    let all = crate::platform::linux_identity_bypass::load_package_to_uid();
    let mut selected = HashMap::new();
    for package in requested {
        let uid = all.get(package).copied().ok_or_else(|| {
            CaptureError::Route(format!(
                "Android package `{package}` is absent from /data/system/packages.list; refusing a partial UID policy"
            ))
        })?;
        selected.insert(package.clone(), uid);
    }
    Ok(selected)
}

fn included_uid_ranges(
    filters: &CaptureFilters,
    package_uids: &HashMap<String, u32>,
) -> Result<Vec<(u32, u32)>, CaptureError> {
    let mut ranges = filters.include_uid_range.clone();
    ranges.extend(filters.include_uid.iter().copied().map(|uid| (uid, uid)));
    append_package_ranges(
        &mut ranges,
        &filters.include_package,
        &filters.include_android_user,
        package_uids,
    )?;
    if ranges.is_empty() {
        for &user in &filters.include_android_user {
            let start = user.checked_mul(ANDROID_USER_RANGE).ok_or_else(|| {
                CaptureError::Route(format!("Android user id {user} overflows UID space"))
            })?;
            let end = start.checked_add(ANDROID_USER_RANGE - 1).ok_or_else(|| {
                CaptureError::Route(format!("Android user id {user} overflows UID space"))
            })?;
            ranges.push((start, end));
        }
    }
    normalize_ranges(ranges)
}

fn excluded_uid_ranges(
    filters: &CaptureFilters,
    package_uids: &HashMap<String, u32>,
) -> Result<Vec<(u32, u32)>, CaptureError> {
    let mut ranges = filters.exclude_uid_range.clone();
    ranges.extend(filters.exclude_uid.iter().copied().map(|uid| (uid, uid)));
    append_package_ranges(
        &mut ranges,
        &filters.exclude_package,
        &filters.include_android_user,
        package_uids,
    )?;
    normalize_ranges(ranges)
}

fn append_package_ranges(
    ranges: &mut Vec<(u32, u32)>,
    packages: &[String],
    users: &[u32],
    package_uids: &HashMap<String, u32>,
) -> Result<(), CaptureError> {
    for package in packages {
        let uid = package_uids[package];
        if users.is_empty() {
            ranges.push((uid, uid));
            continue;
        }
        let app_id = uid % ANDROID_USER_RANGE;
        for &user in users {
            let uid = user
                .checked_mul(ANDROID_USER_RANGE)
                .and_then(|base| base.checked_add(app_id))
                .ok_or_else(|| {
                    CaptureError::Route(format!(
                        "Android user {user} and package `{package}` overflow UID space"
                    ))
                })?;
            ranges.push((uid, uid));
        }
    }
    Ok(())
}

fn normalize_ranges(mut ranges: Vec<(u32, u32)>) -> Result<Vec<(u32, u32)>, CaptureError> {
    for &(start, end) in &ranges {
        if start > end {
            return Err(CaptureError::Route(format!(
                "invalid Android UID range {start}:{end}"
            )));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_ranges_are_sorted_and_merged() {
        assert_eq!(
            normalize_ranges(vec![(20, 30), (1, 4), (5, 8), (25, 40)]).unwrap(),
            [(1, 8), (20, 40)]
        );
    }

    #[test]
    fn android_default_mark_uses_only_reserved_bits() {
        let plan = CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        })
        .unwrap();
        let mark = crate::resource_claims::tun_outbound_mark(&plan);
        assert_ne!(mark, 0);
        assert_eq!(mark & !ANDROID_RESERVED_MARK_MASK, 0);
    }
}
