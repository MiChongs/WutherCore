//! Linux root-managed TUN `auto_redirect` policy routing.
//!
//! The data plane is activated in two phases:
//!
//! 1. [`prepare_routes`] writes split-default routes into an otherwise inactive
//!    custom table. `RouteTable` owns their rollback ledger.
//! 2. [`install`] adds policy rules only after the TUN dispatcher is ready.
//!    Every successful rule is recorded immediately in
//!    [`AutoRedirectRouteLease`], so a partially failed activation remains
//!    exactly retryable by [`uninstall`].
//!
//! The capture selectors deliberately model only locally generated system
//! traffic (`iif lo`) and only TCP/UDP. Forwarded packets, LAN ingress, ICMP,
//! and every other protocol continue through the pre-existing routing policy.

use std::{
    collections::BTreeMap,
    io,
    process::{Command, Stdio},
};

use core_config::model::{
    CaptureTraffic, DEFAULT_AUTO_REDIRECT_OUTPUT_MARK, MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX,
};
use ipnet::IpNet;
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureError, CapturePlan},
    route_table::{ManagedRoute, RouteTable},
};

const IPV4_ROUTE_PROBE_TARGET: &str = "1.1.1.1";
const IPV6_ROUTE_PROBE_TARGET: &str = "2606:4700:4700::1111";
const IPV4_SPLIT_DEFAULTS: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const IPV6_SPLIT_DEFAULTS: [&str; 2] = ["::/1", "8000::/1"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    const fn command_flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    const fn route_probe_target(self) -> &'static str {
        match self {
            Self::V4 => IPV4_ROUTE_PROBE_TARGET,
            Self::V6 => IPV6_ROUTE_PROBE_TARGET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleLayer {
    Dependency,
    Capture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedIpRule {
    family: IpFamily,
    layer: RuleLayer,
    selector: Vec<String>,
}

impl OwnedIpRule {
    fn command(&self, verb: &'static str) -> RuleCommand {
        let mut args = Vec::with_capacity(self.selector.len() + 3);
        args.push(self.family.command_flag().to_owned());
        args.push("rule".to_owned());
        args.push(verb.to_owned());
        args.extend(self.selector.iter().cloned());
        RuleCommand::new("ip", args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRouteProbe {
    lookup_table: String,
    interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BypassLookupTables {
    ipv4: String,
    ipv6: Option<String>,
}

impl BypassLookupTables {
    fn for_family(&self, family: IpFamily) -> Result<&str, CaptureError> {
        match family {
            IpFamily::V4 => Ok(&self.ipv4),
            IpFamily::V6 => self.ipv6.as_deref().ok_or_else(|| {
                route_error("IPv6 policy rule requested without an IPv6 bypass lookup table")
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundInterfaceRestore {
    previous: Option<String>,
    installed: String,
}

/// Exact ownership ledger for the active `auto_redirect` RPDB transaction.
///
/// A lease is intentionally not `Clone`: duplicating it would duplicate rule
/// ownership. When installation fails, the successfully installed prefix stays
/// here for the caller's ordered `pre_stop` retry.
#[derive(Debug, Default)]
pub(crate) struct AutoRedirectRouteLease {
    rules: Vec<OwnedIpRule>,
    bypass_lookup_tables: Option<BypassLookupTables>,
    outbound_interface_restore: Option<OutboundInterfaceRestore>,
}

impl AutoRedirectRouteLease {
    pub(crate) fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.bypass_lookup_tables.is_none()
            && self.outbound_interface_restore.is_none()
    }
}

/// A shell-free command description used by both the production executor and
/// deterministic fault-injection tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleCommand {
    program: &'static str,
    args: Vec<String>,
}

impl RuleCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn program(&self) -> &'static str {
        self.program
    }

    pub(crate) fn args(&self) -> &[String] {
        &self.args
    }
}

/// Captured command result. Exit status, stdout, and stderr are retained so no
/// kernel/iproute2 failure is reduced to an opaque boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleCommandOutput {
    pub(crate) success: bool,
    pub(crate) status: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl RuleCommandOutput {
    #[cfg(test)]
    fn success(stdout: impl Into<String>) -> Self {
        Self {
            success: true,
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[cfg(test)]
    fn failure(status: i32, stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            status: Some(status),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Injectable boundary for every `ip` invocation.
pub(crate) trait RuleExecutor {
    fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput>;
}

#[derive(Debug, Default, Clone, Copy)]
struct SystemRuleExecutor;

impl RuleExecutor for SystemRuleExecutor {
    fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput> {
        let output = Command::new(command.program())
            .args(command.args())
            .stdin(Stdio::null())
            .output()?;
        Ok(RuleCommandOutput {
            success: output.status.success(),
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

trait OutboundInterfaceStore {
    fn get(&self) -> Option<String>;
    fn set(&self, interface: Option<String>);
}

#[derive(Debug, Default, Clone, Copy)]
struct SystemOutboundInterfaceStore;

impl OutboundInterfaceStore for SystemOutboundInterfaceStore {
    fn get(&self) -> Option<String> {
        core_outbound::outbound_interface()
    }

    fn set(&self, interface: Option<String>) {
        core_outbound::set_outbound_interface(interface);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RulePriorities {
    tun_subnet: u32,
    route_bypass: u32,
    outbound_mark: u32,
    capture: u32,
}

/// Prepare the inactive custom route table.
///
/// Every successful route is already owned by `RouteTable`; a later failure is
/// returned without erasing that prefix so the caller's normal route rollback
/// can retry it exactly.
pub(crate) fn prepare_routes(
    routes: &RouteTable,
    plan: &CapturePlan,
    ipv6: bool,
) -> Result<(), CaptureError> {
    validate_plan(plan, ipv6)?;

    for cidr in IPV4_SPLIT_DEFAULTS {
        add_split_default(routes, plan, cidr)?;
    }
    if ipv6 {
        for cidr in IPV6_SPLIT_DEFAULTS {
            add_split_default(routes, plan, cidr)?;
        }
    }
    Ok(())
}

/// Activate the policy-routing transaction with the system `ip` command.
pub(crate) fn install(
    plan: &CapturePlan,
    ipv6: bool,
    lease: &mut AutoRedirectRouteLease,
) -> Result<(), CaptureError> {
    install_with_dependencies(
        plan,
        ipv6,
        lease,
        &SystemRuleExecutor,
        &SystemOutboundInterfaceStore,
    )
}

/// Remove all owned rules in reverse order and restore the previous outbound
/// interface only after every rule is gone.
pub(crate) fn uninstall(lease: &mut AutoRedirectRouteLease) -> Result<(), CaptureError> {
    uninstall_with_dependencies(lease, &SystemRuleExecutor, &SystemOutboundInterfaceStore)
}

fn add_split_default(
    routes: &RouteTable,
    plan: &CapturePlan,
    cidr: &'static str,
) -> Result<(), CaptureError> {
    let dest = cidr.parse::<IpNet>().map_err(|error| {
        route_error(format!(
            "internal split-default CIDR {cidr:?} is invalid: {error}"
        ))
    })?;
    routes
        .add(ManagedRoute {
            dest,
            gateway: None,
            interface: plan.interface_name.clone(),
            metric: 0,
            table: Some(plan.iproute2_table_index),
        })
        .map_err(|error| {
            route_error(format!(
                "add split-default route {cidr} via {} table {}: {error}",
                plan.interface_name, plan.iproute2_table_index
            ))
        })
}

fn install_with_dependencies<E, I>(
    plan: &CapturePlan,
    ipv6: bool,
    lease: &mut AutoRedirectRouteLease,
    executor: &E,
    interfaces: &I,
) -> Result<(), CaptureError>
where
    E: RuleExecutor + ?Sized,
    I: OutboundInterfaceStore + ?Sized,
{
    if !lease.is_empty() {
        return Err(route_error(
            "auto_redirect route lease is already active or awaiting cleanup",
        ));
    }
    validate_plan(plan, ipv6)?;

    let priorities = rule_priorities(plan.iproute2_rule_index)?;
    probe_ip_rule_support(executor, IpFamily::V4, priorities)?;
    if ipv6 {
        probe_ip_rule_support(executor, IpFamily::V6, priorities)?;
    }
    probe_custom_table_ownership(executor, IpFamily::V4, plan)?;
    if ipv6 {
        probe_custom_table_ownership(executor, IpFamily::V6, plan)?;
    }

    let ipv4_route = probe_default_route(executor, IpFamily::V4, plan)?;
    let ipv6_route = if ipv6 {
        Some(probe_default_route(executor, IpFamily::V6, plan)?)
    } else {
        None
    };
    match ipv6_route.as_ref() {
        Some(route) if route.interface != ipv4_route.interface => {
            return Err(route_error(format!(
                "IPv4 and IPv6 default routes use different interfaces ({} vs {}); the current outbound interface binding is not family-specific",
                ipv4_route.interface, route.interface
            )));
        }
        _ => {}
    }
    let bypass_tables = BypassLookupTables {
        ipv4: ipv4_route.lookup_table.clone(),
        ipv6: ipv6_route.as_ref().map(|route| route.lookup_table.clone()),
    };
    let rules = build_rules(plan, ipv6, &bypass_tables)?;

    // Record the reversible global mutation before applying it. Capture rules
    // are installed last, but any earlier rule-add failure is still cleaned by
    // the same lease rather than silently leaking DefaultInterface state.
    lease.bypass_lookup_tables = Some(bypass_tables);
    lease.outbound_interface_restore = Some(OutboundInterfaceRestore {
        previous: interfaces.get(),
        installed: ipv4_route.interface.clone(),
    });
    interfaces.set(Some(ipv4_route.interface));

    for rule in rules {
        let command = rule.command("add");
        execute_checked(executor, "install auto_redirect policy rule", &command)?;
        lease.rules.push(rule);
    }

    info!(
        target: "capture::linux::tun",
        rules = lease.rules.len(),
        ipv6,
        table = plan.iproute2_table_index,
        rule_priority = plan.iproute2_rule_index,
        "auto_redirect local TCP/UDP policy routing installed"
    );
    Ok(())
}

fn uninstall_with_dependencies<E, I>(
    lease: &mut AutoRedirectRouteLease,
    executor: &E,
    interfaces: &I,
) -> Result<(), CaptureError>
where
    E: RuleExecutor + ?Sized,
    I: OutboundInterfaceStore + ?Sized,
{
    if lease.is_empty() {
        return Ok(());
    }

    let mut pending = std::mem::take(&mut lease.rules);
    let mut failures = Vec::new();
    while let Some(layer) = pending.last().map(|rule| rule.layer) {
        let layer_start = pending
            .iter()
            .rposition(|rule| rule.layer != layer)
            .map_or(0, |index| index + 1);
        let layer_rules = pending.split_off(layer_start);
        let mut failed_layer = Vec::new();
        for rule in layer_rules.into_iter().rev() {
            let command = rule.command("del");
            match executor.execute(&command) {
                Ok(output) if output.success => {
                    debug!(
                        target: "capture::linux::tun",
                        command = %render_command(&command),
                        "auto_redirect policy rule removed"
                    );
                }
                Ok(output) if is_absent_delete(&command, &output) => {
                    debug!(
                        target: "capture::linux::tun",
                        command = %render_command(&command),
                        "auto_redirect policy rule was already absent"
                    );
                }
                Ok(output) => {
                    failures.push(command_failure(&command, &output));
                    failed_layer.push(rule);
                }
                Err(error) => {
                    failures.push(format!("spawn {}: {error}", render_command(&command)));
                    failed_layer.push(rule);
                }
            }
        }
        // A surviving capture rule still depends on output-mark bypass and the
        // custom-table routes. Keep every lower layer untouched until all
        // rules in the current layer are gone.
        if !failed_layer.is_empty() {
            failed_layer.reverse();
            pending.extend(failed_layer);
            break;
        }
    }
    lease.rules = pending;

    if lease.rules.is_empty() {
        if let Some(restore) = lease.outbound_interface_restore.take() {
            let current = interfaces.get();
            if current.as_deref() == Some(restore.installed.as_str()) {
                debug!(
                    target: "capture::linux::tun",
                    installed = %restore.installed,
                    previous = ?restore.previous,
                    "restore outbound interface after policy-rule cleanup"
                );
                interfaces.set(restore.previous);
            } else {
                warn!(
                    target: "capture::linux::tun",
                    installed = %restore.installed,
                    current = ?current,
                    "outbound interface changed after auto_redirect activation; preserve newer value"
                );
            }
        }
        lease.bypass_lookup_tables = None;
    }

    if failures.is_empty() {
        Ok(())
    } else {
        warn!(
            target: "capture::linux::tun",
            remaining_rules = lease.rules.len(),
            errors = %failures.join("; "),
            "auto_redirect policy-rule cleanup incomplete"
        );
        Err(route_error(format!(
            "auto_redirect policy-rule cleanup incomplete: {}",
            failures.join("; ")
        )))
    }
}

fn validate_plan(plan: &CapturePlan, ipv6: bool) -> Result<(), CaptureError> {
    if !plan.on || !plan.auto_route || !plan.auto_redirect {
        return Err(route_error(
            "auto_redirect local policy routing requires capture.on, auto_route, and auto_redirect",
        ));
    }
    if plan.traffic != CaptureTraffic::System {
        return Err(route_error(
            "auto_redirect local policy routing supports only traffic=system",
        ));
    }
    if plan.strict_route {
        return Err(route_error(
            "auto_redirect local TCP/UDP policy routing cannot promise strict_route for ICMP/other protocols",
        ));
    }
    if !plan.route_address_set.is_empty() || !plan.route_exclude_address_set.is_empty() {
        return Err(route_error(
            "dynamic route_address_set/route_exclude_address_set must be rejected before auto_redirect activation",
        ));
    }
    if plan.interface_name.trim().is_empty() || plan.interface_name == "lo" {
        return Err(route_error(
            "auto_redirect custom TUN interface must be non-empty and must not be loopback",
        ));
    }
    if plan.iproute2_table_index == 0 || matches!(plan.iproute2_table_index, 253..=255) {
        return Err(route_error(
            "auto_redirect iproute2_table_index must be a non-reserved private table",
        ));
    }
    rule_priorities(plan.iproute2_rule_index)?;
    if ipv6 && (!plan.ipv6_enabled || plan.tun_v6_cidr.is_none()) {
        return Err(route_error(
            "IPv6 policy routing requested without an enabled IPv6 TUN subnet",
        ));
    }
    Ok(())
}

fn rule_priorities(capture: u32) -> Result<RulePriorities, CaptureError> {
    if capture > MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX {
        return Err(route_error(format!(
            "iproute2_rule_index {capture} must precede the Linux main rule priority 32766"
        )));
    }
    let tun_subnet = capture.checked_sub(3).filter(|priority| *priority > 0);
    let Some(tun_subnet) = tun_subnet else {
        return Err(route_error(format!(
            "iproute2_rule_index {capture} is too small; auto_redirect needs four ordered priorities"
        )));
    };
    Ok(RulePriorities {
        tun_subnet,
        route_bypass: capture - 2,
        outbound_mark: capture - 1,
        capture,
    })
}

fn probe_ip_rule_support<E: RuleExecutor + ?Sized>(
    executor: &E,
    family: IpFamily,
    priorities: RulePriorities,
) -> Result<(), CaptureError> {
    let command = RuleCommand::new("ip", [family.command_flag(), "rule", "list"]);
    let output = execute_checked(executor, "probe ip rule support", &command)?;
    let response = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    for unsupported in [
        "unknown",
        "unrecognized",
        "not implemented",
        "no such",
        "feature not available",
        "try `ip address help'",
        "usage:",
    ] {
        if response.contains(unsupported) {
            return Err(route_error(format!(
                "{} ip rule probe returned unsupported output for {}: {}",
                family.label(),
                render_command(&command),
                response.trim()
            )));
        }
    }
    for line in output.stdout.lines() {
        let Some((priority, _)) = line.trim().split_once(':') else {
            continue;
        };
        let Ok(priority) = priority.trim().parse::<u32>() else {
            continue;
        };
        if [
            priorities.tun_subnet,
            priorities.route_bypass,
            priorities.outbound_mark,
            priorities.capture,
        ]
        .contains(&priority)
        {
            return Err(route_error(format!(
                "{} ip rule priority {priority} is already occupied; refusing ambiguous ownership",
                family.label()
            )));
        }
    }
    Ok(())
}

fn probe_custom_table_ownership<E: RuleExecutor + ?Sized>(
    executor: &E,
    family: IpFamily,
    plan: &CapturePlan,
) -> Result<(), CaptureError> {
    let table = plan.iproute2_table_index.to_string();
    let command = RuleCommand::new(
        "ip",
        [
            family.command_flag().to_owned(),
            "route".to_owned(),
            "show".to_owned(),
            "table".to_owned(),
            table.clone(),
        ],
    );
    let output = execute_checked(
        executor,
        "verify auto_redirect private route table",
        &command,
    )?;
    let expected = match family {
        IpFamily::V4 => IPV4_SPLIT_DEFAULTS.as_slice(),
        IpFamily::V6 => IPV6_SPLIT_DEFAULTS.as_slice(),
    };
    let mut seen = Vec::new();
    for line in output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
        let destination = tokens.first().copied().unwrap_or_default();
        let interfaces = tokens
            .windows(2)
            .filter(|pair| pair[0] == "dev")
            .map(|pair| pair[1])
            .collect::<Vec<_>>();
        let metrics = tokens
            .windows(2)
            .filter(|pair| pair[0] == "metric")
            .map(|pair| pair[1])
            .collect::<Vec<_>>();
        let protocols = tokens
            .windows(2)
            .filter(|pair| pair[0] == "proto")
            .map(|pair| pair[1])
            .collect::<Vec<_>>();
        let owns_interface = tokens.iter().filter(|token| **token == "dev").count()
            == interfaces.len()
            && interfaces.as_slice() == [plan.interface_name.as_str()];
        let owns_metric = tokens.iter().filter(|token| **token == "metric").count()
            == metrics.len()
            && matches!(metrics.as_slice(), [] | ["0"]);
        let owns_protocol = tokens.iter().filter(|token| **token == "proto").count()
            == protocols.len()
            && matches!(protocols.as_slice(), [] | ["boot"]);
        let has_gateway = tokens.contains(&"via") || tokens.contains(&"nexthop");
        if !expected.contains(&destination)
            || !owns_interface
            || !owns_metric
            || !owns_protocol
            || has_gateway
        {
            return Err(route_error(format!(
                "{} private table {table} contains an unowned route: {line}",
                family.label()
            )));
        }
        seen.push(destination);
    }
    seen.sort_unstable();
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    if seen != expected_sorted {
        return Err(route_error(format!(
            "{} private table {table} does not contain exactly the owned split-default routes via {}",
            family.label(),
            plan.interface_name
        )));
    }
    Ok(())
}

fn probe_default_route<E: RuleExecutor + ?Sized>(
    executor: &E,
    family: IpFamily,
    plan: &CapturePlan,
) -> Result<DefaultRouteProbe, CaptureError> {
    let command = RuleCommand::new(
        "ip",
        [
            family.command_flag(),
            "route",
            "get",
            family.route_probe_target(),
        ],
    );
    let output = execute_checked(executor, "probe outbound route", &command)?;
    let lookup_table = super::route_probe::outbound_bypass_table_from_route_get(&output.stdout);
    let interface = super::route_probe::outbound_interface_from_route_get(&output.stdout)
        .ok_or_else(|| {
            route_error(format!(
                "{} outbound route probe did not report a dev interface: {}",
                family.label(),
                output.stdout.trim()
            ))
        })?;
    if interface == plan.interface_name {
        return Err(route_error(format!(
            "{} outbound route resolves through the TUN interface {}; refusing a routing loop",
            family.label(),
            interface
        )));
    }
    if table_matches_index(&lookup_table, plan.iproute2_table_index) {
        return Err(route_error(format!(
            "{} outbound bypass table {lookup_table} equals custom TUN table {}; refusing a routing loop",
            family.label(),
            plan.iproute2_table_index
        )));
    }
    verify_default_route_in_table(executor, family, &lookup_table, &interface)?;
    Ok(DefaultRouteProbe {
        lookup_table,
        interface,
    })
}

fn verify_default_route_in_table<E: RuleExecutor + ?Sized>(
    executor: &E,
    family: IpFamily,
    table: &str,
    interface: &str,
) -> Result<(), CaptureError> {
    let command = RuleCommand::new(
        "ip",
        [
            family.command_flag().to_owned(),
            "route".to_owned(),
            "show".to_owned(),
            "table".to_owned(),
            table.to_owned(),
            "default".to_owned(),
        ],
    );
    let output = execute_checked(executor, "verify outbound default route", &command)?;
    let tokens = output.stdout.split_ascii_whitespace().collect::<Vec<_>>();
    let has_default = output
        .stdout
        .lines()
        .any(|line| line.trim_start().starts_with("default "));
    let has_interface = tokens.windows(2).any(|pair| pair == ["dev", interface]);
    if !has_default || !has_interface {
        return Err(route_error(format!(
            "{} bypass table {table} has no usable default route via {interface}",
            family.label()
        )));
    }
    Ok(())
}

fn table_matches_index(table: &str, index: u32) -> bool {
    match table {
        "default" => index == 253,
        "main" => index == 254,
        "local" => index == 255,
        _ => table.parse::<u32>() == Ok(index),
    }
}

fn build_rules(
    plan: &CapturePlan,
    ipv6: bool,
    bypass_tables: &BypassLookupTables,
) -> Result<Vec<OwnedIpRule>, CaptureError> {
    let priorities = rule_priorities(plan.iproute2_rule_index)?;
    let custom_table = plan.iproute2_table_index.to_string();
    let mut rules = Vec::new();

    // Install every real-network dependency before any rule that can direct a
    // packet to the custom TUN table.
    for net in merged_bypass_targets(plan) {
        let family = family_for_net(&net);
        if family == IpFamily::V6 && !ipv6 {
            continue;
        }
        rules.push(destination_rule(
            family,
            priorities.route_bypass,
            Some(&net),
            true,
            None,
            bypass_tables.for_family(family)?,
            RuleLayer::Dependency,
        ));
    }

    let output_mark = plan
        .auto_redirect_marks
        .output
        .filter(|mark| *mark != 0)
        .unwrap_or(DEFAULT_AUTO_REDIRECT_OUTPUT_MARK);
    for family in enabled_families(ipv6) {
        rules.push(mark_rule(
            family,
            priorities.outbound_mark,
            output_mark,
            bypass_tables.for_family(family)?,
        ));
    }

    // Internal TUN peer traffic takes precedence over broad bypass CIDRs (for
    // example 172.16.0.0/12), but remains local-only and TCP/UDP-only.
    for protocol in ["tcp", "udp"] {
        rules.push(destination_rule(
            IpFamily::V4,
            priorities.tun_subnet,
            Some(&IpNet::V4(plan.tun_v4_cidr)),
            true,
            Some(protocol),
            &custom_table,
            RuleLayer::Capture,
        ));
    }
    if ipv6 {
        let tun_v6 = plan.tun_v6_cidr.ok_or_else(|| {
            route_error("IPv6 policy routing requested without an IPv6 TUN subnet")
        })?;
        for protocol in ["tcp", "udp"] {
            rules.push(destination_rule(
                IpFamily::V6,
                priorities.tun_subnet,
                Some(&IpNet::V6(tun_v6)),
                true,
                Some(protocol),
                &custom_table,
                RuleLayer::Capture,
            ));
        }
    }

    let route_addresses = canonical_nets(&plan.route_addresses);
    if route_addresses.is_empty() {
        for family in enabled_families(ipv6) {
            for protocol in ["tcp", "udp"] {
                rules.push(destination_rule(
                    family,
                    priorities.capture,
                    None,
                    true,
                    Some(protocol),
                    &custom_table,
                    RuleLayer::Capture,
                ));
            }
        }
    } else {
        for net in route_addresses {
            let family = family_for_net(&net);
            if family == IpFamily::V6 && !ipv6 {
                continue;
            }
            for protocol in ["tcp", "udp"] {
                rules.push(destination_rule(
                    family,
                    priorities.capture,
                    Some(&net),
                    true,
                    Some(protocol),
                    &custom_table,
                    RuleLayer::Capture,
                ));
            }
        }
    }
    Ok(rules)
}

fn destination_rule(
    family: IpFamily,
    priority: u32,
    destination: Option<&IpNet>,
    local_only: bool,
    protocol: Option<&'static str>,
    lookup: &str,
    layer: RuleLayer,
) -> OwnedIpRule {
    let mut selector = vec!["priority".to_owned(), priority.to_string()];
    if local_only {
        selector.extend(["iif".to_owned(), "lo".to_owned()]);
    }
    if let Some(protocol) = protocol {
        selector.extend(["ipproto".to_owned(), protocol.to_owned()]);
    }
    if let Some(destination) = destination {
        selector.extend(["to".to_owned(), destination.to_string()]);
    }
    selector.extend(["lookup".to_owned(), lookup.to_owned()]);
    OwnedIpRule {
        family,
        layer,
        selector,
    }
}

fn mark_rule(family: IpFamily, priority: u32, mark: u32, lookup: &str) -> OwnedIpRule {
    OwnedIpRule {
        family,
        layer: RuleLayer::Dependency,
        selector: vec![
            "priority".to_owned(),
            priority.to_string(),
            "iif".to_owned(),
            "lo".to_owned(),
            "fwmark".to_owned(),
            format!("{mark:#x}"),
            "lookup".to_owned(),
            lookup.to_owned(),
        ],
    }
}

fn merged_bypass_targets(plan: &CapturePlan) -> Vec<IpNet> {
    let mut targets = plan.exclude_cidrs.clone();
    targets.extend(plan.route_exclude_addresses.iter().copied());
    targets.extend(plan.loopback_addresses.iter().filter_map(|address| {
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        IpNet::new(*address, prefix).ok()
    }));
    canonical_nets(&targets)
}

fn canonical_nets(nets: &[IpNet]) -> Vec<IpNet> {
    let mut unique = BTreeMap::new();
    for net in nets {
        unique.entry(net.to_string()).or_insert(*net);
    }
    unique.into_values().collect()
}

fn family_for_net(net: &IpNet) -> IpFamily {
    match net {
        IpNet::V4(_) => IpFamily::V4,
        IpNet::V6(_) => IpFamily::V6,
    }
}

fn enabled_families(ipv6: bool) -> impl Iterator<Item = IpFamily> {
    [IpFamily::V4, IpFamily::V6]
        .into_iter()
        .filter(move |family| *family == IpFamily::V4 || ipv6)
}

fn execute_checked<E: RuleExecutor + ?Sized>(
    executor: &E,
    phase: &str,
    command: &RuleCommand,
) -> Result<RuleCommandOutput, CaptureError> {
    let output = executor.execute(command).map_err(|error| {
        route_error(format!(
            "{phase}: spawn {}: {error}",
            render_command(command)
        ))
    })?;
    if output.success {
        Ok(output)
    } else {
        Err(route_error(format!(
            "{phase}: {}",
            command_failure(command, &output)
        )))
    }
}

fn command_failure(command: &RuleCommand, output: &RuleCommandOutput) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    format!(
        "{} failed (status={:?}, stderr={:?}, detail={detail:?})",
        render_command(command),
        output.status,
        output.stderr.trim()
    )
}

fn is_absent_delete(command: &RuleCommand, output: &RuleCommandOutput) -> bool {
    let args = command
        .args()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let detail = format!("{}\n{}", output.stderr, output.stdout);
    super::is_absent_ip_rule_delete(command.program(), &args, &detail)
        || detail
            .to_ascii_lowercase()
            .contains("rtnetlink answers: no such process")
}

fn render_command(command: &RuleCommand) -> String {
    std::iter::once(command.program())
        .chain(command.args().iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn route_error(message: impl Into<String>) -> CaptureError {
    CaptureError::Route(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use core_config::model::{Capture, CaptureMethod};

    use crate::route_table::RouteBackend;

    use super::*;

    struct RecordingExecutor<F> {
        handler: F,
        commands: Mutex<Vec<RuleCommand>>,
    }

    impl<F> RecordingExecutor<F> {
        fn new(handler: F) -> Self {
            Self {
                handler,
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<RuleCommand> {
            self.commands.lock().expect("command ledger lock").clone()
        }
    }

    impl<F> RuleExecutor for RecordingExecutor<F>
    where
        F: Fn(&RuleCommand, usize) -> io::Result<RuleCommandOutput>,
    {
        fn execute(&self, command: &RuleCommand) -> io::Result<RuleCommandOutput> {
            let index = {
                let mut commands = self.commands.lock().expect("command ledger lock");
                let index = commands.len();
                commands.push(command.clone());
                index
            };
            (self.handler)(command, index)
        }
    }

    #[derive(Debug)]
    struct FakeInterfaceStore {
        value: Mutex<Option<String>>,
    }

    impl FakeInterfaceStore {
        fn new(value: Option<&str>) -> Self {
            Self {
                value: Mutex::new(value.map(str::to_owned)),
            }
        }

        fn value(&self) -> Option<String> {
            self.value.lock().expect("interface store lock").clone()
        }
    }

    impl OutboundInterfaceStore for FakeInterfaceStore {
        fn get(&self) -> Option<String> {
            self.value()
        }

        fn set(&self, interface: Option<String>) {
            *self.value.lock().expect("interface store lock") = interface;
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRouteBackend {
        added: Mutex<Vec<ManagedRoute>>,
        deleted: Mutex<Vec<ManagedRoute>>,
        calls: AtomicUsize,
        fail_at: Option<usize>,
    }

    impl RecordingRouteBackend {
        fn with_failure(fail_at: usize) -> Self {
            Self {
                fail_at: Some(fail_at),
                ..Self::default()
            }
        }

        fn added(&self) -> Vec<ManagedRoute> {
            self.added.lock().expect("route add ledger lock").clone()
        }
    }

    impl RouteBackend for RecordingRouteBackend {
        fn add(&self, route: &ManagedRoute) -> Result<(), String> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_at == Some(index) {
                return Err(format!("injected add failure at {index}"));
            }
            self.added
                .lock()
                .expect("route add ledger lock")
                .push(route.clone());
            Ok(())
        }

        fn del(&self, route: &ManagedRoute) -> Result<(), String> {
            self.deleted
                .lock()
                .expect("route delete ledger lock")
                .push(route.clone());
            Ok(())
        }
    }

    fn base_plan() -> CapturePlan {
        let mut plan = CapturePlan::from_config(&Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            ..Capture::default()
        })
        .expect("base capture plan");
        plan.on = true;
        plan.auto_route = true;
        plan.auto_redirect = true;
        plan.strict_route = false;
        plan.traffic = CaptureTraffic::System;
        plan.interface_name = "wuther0".to_owned();
        plan.tun_v4_cidr = "198.18.0.1/30".parse().expect("v4 TUN CIDR");
        plan.tun_v6_cidr = Some("fdfe:dcba:9876::1/126".parse().expect("v6 TUN CIDR"));
        plan.ipv6_enabled = true;
        plan.iproute2_table_index = 2_022;
        plan.iproute2_rule_index = 9_000;
        plan.exclude_cidrs.clear();
        plan.route_addresses.clear();
        plan.route_exclude_addresses.clear();
        plan.route_address_set.clear();
        plan.route_exclude_address_set.clear();
        plan.loopback_addresses.clear();
        plan
    }

    fn successful_environment(
        command: &RuleCommand,
        _index: usize,
    ) -> io::Result<RuleCommandOutput> {
        if command
            .args()
            .windows(2)
            .any(|args| args == ["route", "show"])
        {
            let ipv6 = command.args().first().map(String::as_str) == Some("-6");
            if command.args().last().map(String::as_str) == Some("default") {
                let output = if ipv6 {
                    "default via 2001:db8::1 dev eth-test"
                } else {
                    "default via 192.0.2.1 dev eth-test"
                };
                return Ok(RuleCommandOutput::success(output));
            }
            let output = if ipv6 {
                "::/1 dev wuther0 metric 0\n8000::/1 dev wuther0 metric 0"
            } else {
                "0.0.0.0/1 dev wuther0 metric 0\n128.0.0.0/1 dev wuther0 metric 0"
            };
            return Ok(RuleCommandOutput::success(output));
        }
        if command
            .args()
            .windows(2)
            .any(|args| args == ["route", "get"])
        {
            if command.args().first().map(String::as_str) == Some("-6") {
                return Ok(RuleCommandOutput::success(
                    "2606:4700:4700::1111 via 2001:db8::1 dev eth-test table 200 src 2001:db8::2",
                ));
            }
            return Ok(RuleCommandOutput::success(
                "1.1.1.1 via 192.0.2.1 dev eth-test table 100 src 192.0.2.2",
            ));
        }
        Ok(RuleCommandOutput::success(""))
    }

    fn is_rule_command(command: &RuleCommand, verb: &str) -> bool {
        command.args().get(1).map(String::as_str) == Some("rule")
            && command.args().get(2).map(String::as_str) == Some(verb)
    }

    fn argument_after<'a>(command: &'a RuleCommand, needle: &str) -> Option<&'a str> {
        command
            .args()
            .windows(2)
            .find(|pair| pair[0] == needle)
            .map(|pair| pair[1].as_str())
    }

    #[test]
    fn prepare_routes_is_explicit_ipv4_or_dual_stack() {
        let plan = base_plan();
        let v4_backend = Arc::new(RecordingRouteBackend::default());
        let v4_routes = RouteTable::with_backend(v4_backend.clone());
        prepare_routes(&v4_routes, &plan, false).unwrap();
        let v4 = v4_backend.added();
        assert_eq!(
            v4.iter()
                .map(|route| route.dest.to_string())
                .collect::<Vec<_>>(),
            ["0.0.0.0/1", "128.0.0.0/1"]
        );
        assert!(v4.iter().all(|route| {
            route.interface == "wuther0" && route.table == Some(2_022) && route.metric == 0
        }));

        let dual_backend = Arc::new(RecordingRouteBackend::default());
        let dual_routes = RouteTable::with_backend(dual_backend.clone());
        prepare_routes(&dual_routes, &plan, true).unwrap();
        assert_eq!(
            dual_backend
                .added()
                .iter()
                .map(|route| route.dest.to_string())
                .collect::<Vec<_>>(),
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        );
    }

    #[test]
    fn prepare_routes_returns_first_add_failure_and_preserves_owned_prefix() {
        let plan = base_plan();
        let backend = Arc::new(RecordingRouteBackend::with_failure(1));
        let routes = RouteTable::with_backend(backend.clone());

        let error = prepare_routes(&routes, &plan, false).unwrap_err();

        assert!(error.to_string().contains("128.0.0.0/1"));
        assert!(error.to_string().contains("injected add failure at 1"));
        assert_eq!(routes.len(), 1);
        assert_eq!(backend.added()[0].dest.to_string(), "0.0.0.0/1");
    }

    #[test]
    fn capture_rules_are_local_tcp_udp_only_and_never_capture_forward_or_icmp() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, true, &mut lease, &executor, &interfaces).unwrap();

        let capture_priority = plan.iproute2_rule_index.to_string();
        let capture = executor
            .commands()
            .into_iter()
            .filter(|command| {
                is_rule_command(command, "add")
                    && argument_after(command, "priority") == Some(capture_priority.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(capture.len(), 4);
        for command in &capture {
            assert_eq!(argument_after(command, "iif"), Some("lo"));
            assert!(matches!(
                argument_after(command, "ipproto"),
                Some("tcp" | "udp")
            ));
            assert_eq!(
                argument_after(command, "lookup"),
                Some(plan.iproute2_table_index.to_string().as_str())
            );
            assert!(matches!(
                command.args().first().map(String::as_str),
                Some("-4" | "-6")
            ));
        }
        assert!(!executor.commands().iter().any(|command| {
            argument_after(command, "ipproto") == Some("icmp")
                || argument_after(command, "ipproto") == Some("icmpv6")
        }));
        let custom_table = plan.iproute2_table_index.to_string();
        assert!(
            executor
                .commands()
                .iter()
                .filter(|command| {
                    is_rule_command(command, "add")
                        && argument_after(command, "lookup") == Some(custom_table.as_str())
                })
                .all(|command| {
                    argument_after(command, "iif") == Some("lo")
                        && matches!(argument_after(command, "ipproto"), Some("tcp" | "udp"))
                })
        );

        let cleanup = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
    }

    #[test]
    fn bypass_targets_merge_deduplicate_and_convert_loopback_hosts() {
        let mut plan = base_plan();
        plan.exclude_cidrs = vec!["10.0.0.0/8".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        plan.route_exclude_addresses = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ];
        plan.loopback_addresses = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(None);
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, true, &mut lease, &executor, &interfaces).unwrap();

        let bypass_priority = (plan.iproute2_rule_index - 2).to_string();
        let bypass_destinations = executor
            .commands()
            .iter()
            .filter(|command| {
                is_rule_command(command, "add")
                    && argument_after(command, "priority") == Some(bypass_priority.as_str())
            })
            .filter_map(|command| argument_after(command, "to").map(str::to_owned))
            .collect::<Vec<_>>();
        assert_eq!(
            bypass_destinations,
            ["10.0.0.0/8", "127.0.0.1/32", "192.0.2.0/24", "::1/128"]
        );
        assert!(
            executor
                .commands()
                .iter()
                .filter(|command| {
                    argument_after(command, "priority") == Some(bypass_priority.as_str())
                        && argument_after(command, "iif") == Some("lo")
                })
                .count()
                == 4
        );

        let cleanup = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();
    }

    #[test]
    fn static_route_addresses_expand_to_each_family_and_transport() {
        let mut plan = base_plan();
        plan.route_addresses = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8:42::/48".parse().unwrap(),
        ];
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(None);
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, true, &mut lease, &executor, &interfaces).unwrap();

        let capture_priority = plan.iproute2_rule_index.to_string();
        let capture = executor
            .commands()
            .into_iter()
            .filter(|command| {
                is_rule_command(command, "add")
                    && argument_after(command, "priority") == Some(capture_priority.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(capture.len(), 4);
        for destination in ["203.0.113.0/24", "2001:db8:42::/48"] {
            for protocol in ["tcp", "udp"] {
                assert!(capture.iter().any(|command| {
                    argument_after(command, "to") == Some(destination)
                        && argument_after(command, "ipproto") == Some(protocol)
                        && argument_after(command, "iif") == Some("lo")
                }));
            }
        }

        let cleanup = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();
    }

    #[test]
    fn priorities_are_strictly_ordered_and_mark_rules_use_actual_family_tables() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(None);
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, true, &mut lease, &executor, &interfaces).unwrap();

        let priorities = rule_priorities(plan.iproute2_rule_index).unwrap();
        assert!(priorities.tun_subnet < priorities.route_bypass);
        assert!(priorities.route_bypass < priorities.outbound_mark);
        assert!(priorities.outbound_mark < priorities.capture);
        let mark_rules = executor
            .commands()
            .into_iter()
            .filter(|command| {
                is_rule_command(command, "add")
                    && argument_after(command, "priority")
                        == Some(priorities.outbound_mark.to_string().as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(mark_rules.len(), 2);
        assert!(
            mark_rules
                .iter()
                .all(|command| argument_after(command, "iif") == Some("lo"))
        );
        assert!(mark_rules.iter().any(|command| {
            command.args().first().map(String::as_str) == Some("-4")
                && argument_after(command, "lookup") == Some("100")
        }));
        assert!(mark_rules.iter().any(|command| {
            command.args().first().map(String::as_str) == Some("-6")
                && argument_after(command, "lookup") == Some("200")
        }));
        assert_eq!(
            lease.bypass_lookup_tables,
            Some(BypassLookupTables {
                ipv4: "100".to_owned(),
                ipv6: Some("200".to_owned())
            })
        );

        let cleanup = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();
    }

    #[test]
    fn rule_priorities_fail_closed_after_linux_main_rule() {
        assert!(rule_priorities(MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX).is_ok());
        let error = rule_priorities(MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX + 1).unwrap_err();
        assert!(error.to_string().contains("main rule priority 32766"));
    }

    #[test]
    fn every_rule_add_failure_retains_exact_successful_prefix() {
        let plan = base_plan();
        let baseline = RecordingExecutor::new(successful_environment);
        let baseline_interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut baseline_lease = AutoRedirectRouteLease::default();
        install_with_dependencies(
            &plan,
            false,
            &mut baseline_lease,
            &baseline,
            &baseline_interfaces,
        )
        .unwrap();
        let add_count = baseline
            .commands()
            .iter()
            .filter(|command| is_rule_command(command, "add"))
            .count();
        let cleanup = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut baseline_lease, &cleanup, &baseline_interfaces).unwrap();

        for fail_at in 0..add_count {
            let add_seen = Arc::new(AtomicUsize::new(0));
            let counter = add_seen.clone();
            let executor = RecordingExecutor::new(move |command: &RuleCommand, index| {
                if is_rule_command(command, "add") {
                    let add_index = counter.fetch_add(1, Ordering::SeqCst);
                    if add_index == fail_at {
                        return Ok(RuleCommandOutput::failure(
                            77,
                            format!("injected rule add failure {fail_at}"),
                        ));
                    }
                }
                successful_environment(command, index)
            });
            let interfaces = FakeInterfaceStore::new(Some("before0"));
            let mut lease = AutoRedirectRouteLease::default();

            let error = install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces)
                .unwrap_err();

            assert!(error.to_string().contains("status=Some(77)"));
            assert!(
                error
                    .to_string()
                    .contains(&format!("injected rule add failure {fail_at}"))
            );
            assert_eq!(lease.rules.len(), fail_at);
            assert_eq!(interfaces.value(), Some("eth-test".to_owned()));
            let cleanup = RecordingExecutor::new(successful_environment);
            uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();
            assert!(lease.is_empty());
            assert_eq!(interfaces.value(), Some("before0".to_owned()));
        }
    }

    #[test]
    fn uninstall_keeps_dependencies_behind_capture_failure_barrier_and_retries() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces).unwrap();
        let owned = lease.rules.clone();

        let delete_seen = Arc::new(AtomicUsize::new(0));
        let counter = delete_seen.clone();
        let partial_cleanup = RecordingExecutor::new(move |command: &RuleCommand, index| {
            if is_rule_command(command, "del") {
                let delete_index = counter.fetch_add(1, Ordering::SeqCst);
                if delete_index == 0 || delete_index == 2 {
                    return Ok(RuleCommandOutput::failure(
                        13,
                        format!("cleanup denied at {delete_index}"),
                    ));
                }
            }
            successful_environment(command, index)
        });

        let error =
            uninstall_with_dependencies(&mut lease, &partial_cleanup, &interfaces).unwrap_err();
        assert!(error.to_string().contains("cleanup denied at 0"));
        assert!(error.to_string().contains("cleanup denied at 2"));

        let attempted = partial_cleanup.commands();
        let expected_capture = owned
            .iter()
            .filter(|rule| rule.layer == RuleLayer::Capture)
            .rev()
            .map(|rule| rule.command("del"))
            .collect::<Vec<_>>();
        assert_eq!(attempted, expected_capture);
        assert_eq!(
            lease
                .rules
                .iter()
                .filter(|rule| rule.layer == RuleLayer::Dependency)
                .count(),
            owned
                .iter()
                .filter(|rule| rule.layer == RuleLayer::Dependency)
                .count()
        );
        assert_eq!(
            lease
                .rules
                .iter()
                .filter(|rule| rule.layer == RuleLayer::Capture)
                .count(),
            2
        );
        assert_eq!(interfaces.value(), Some("eth-test".to_owned()));
        assert!(lease.bypass_lookup_tables.is_some());

        let retained = lease.rules.clone();
        let retry = RecordingExecutor::new(successful_environment);
        uninstall_with_dependencies(&mut lease, &retry, &interfaces).unwrap();
        assert_eq!(
            retry.commands(),
            retained
                .iter()
                .rev()
                .map(|rule| rule.command("del"))
                .collect::<Vec<_>>()
        );
        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
    }

    #[test]
    fn absent_delete_is_success_and_restores_interface() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces).unwrap();
        let absent = RecordingExecutor::new(|_command: &RuleCommand, _| {
            Ok(RuleCommandOutput::failure(
                2,
                "RTNETLINK answers: No such file or directory",
            ))
        });

        uninstall_with_dependencies(&mut lease, &absent, &interfaces).unwrap();

        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
    }

    #[test]
    fn ip_rule_probe_and_spawn_failures_are_visible_without_mutating_lease() {
        let plan = base_plan();
        let unsupported = RecordingExecutor::new(|_command: &RuleCommand, _| {
            Ok(RuleCommandOutput::success("Usage: ip address help"))
        });
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();
        let error = install_with_dependencies(&plan, false, &mut lease, &unsupported, &interfaces)
            .unwrap_err();
        assert!(error.to_string().contains("unsupported output"));
        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));

        let spawn_failure = RecordingExecutor::new(|_command: &RuleCommand, _| {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing ip binary"))
        });
        let error =
            install_with_dependencies(&plan, false, &mut lease, &spawn_failure, &interfaces)
                .unwrap_err();
        assert!(error.to_string().contains("spawn ip -4 rule list"));
        assert!(error.to_string().contains("missing ip binary"));
        assert!(lease.is_empty());
    }

    #[test]
    fn occupied_rule_priority_fails_before_route_or_interface_mutation() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(|command: &RuleCommand, index| {
            if command
                .args()
                .windows(2)
                .any(|args| args == ["rule", "list"])
            {
                return Ok(RuleCommandOutput::success(
                    "0: from all lookup local\n9000: from all lookup 2022",
                ));
            }
            successful_environment(command, index)
        });
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();

        let error = install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("priority 9000 is already occupied")
        );
        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
        assert!(!executor.commands().iter().any(|command| {
            command
                .args()
                .windows(2)
                .any(|args| args == ["route", "get"])
        }));
    }

    #[test]
    fn private_table_with_unowned_route_fails_closed() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(|command: &RuleCommand, index| {
            if command
                .args()
                .windows(2)
                .any(|args| args == ["route", "show"])
                && command.args().last().map(String::as_str) != Some("default")
            {
                return Ok(RuleCommandOutput::success(
                    "0.0.0.0/1 dev wuther0\n128.0.0.0/1 dev wuther0\n203.0.113.0/24 dev other0",
                ));
            }
            successful_environment(command, index)
        });
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();

        let error = install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces)
            .unwrap_err();

        assert!(error.to_string().contains("contains an unowned route"));
        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
    }

    #[test]
    fn private_table_rejects_duplicate_or_qualified_split_defaults() {
        for (case, private_routes) in [
            (
                "duplicate destination",
                "0.0.0.0/1 dev wuther0 metric 0\n\
                 0.0.0.0/1 dev wuther0 metric 0\n\
                 128.0.0.0/1 dev wuther0 metric 0",
            ),
            (
                "nonzero metric",
                "0.0.0.0/1 dev wuther0 metric 42\n\
                 128.0.0.0/1 dev wuther0 metric 0",
            ),
            (
                "gateway",
                "0.0.0.0/1 via 192.0.2.1 dev wuther0 metric 0\n\
                 128.0.0.0/1 dev wuther0 metric 0",
            ),
            (
                "foreign protocol",
                "0.0.0.0/1 dev wuther0 proto static metric 0\n\
                 128.0.0.0/1 dev wuther0 metric 0",
            ),
        ] {
            let plan = base_plan();
            let executor = RecordingExecutor::new(move |command: &RuleCommand, index| {
                if command
                    .args()
                    .windows(2)
                    .any(|args| args == ["route", "show"])
                    && command.args().last().map(String::as_str) != Some("default")
                {
                    return Ok(RuleCommandOutput::success(private_routes));
                }
                successful_environment(command, index)
            });
            let interfaces = FakeInterfaceStore::new(Some("before0"));
            let mut lease = AutoRedirectRouteLease::default();

            let error = install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces)
                .unwrap_err();

            assert!(
                error.to_string().contains("private table 2022"),
                "{case}: {error}"
            );
            assert!(lease.is_empty(), "{case}");
            assert_eq!(interfaces.value(), Some("before0".to_owned()), "{case}");
            assert!(
                !executor.commands().iter().any(|command| {
                    command
                        .args()
                        .windows(2)
                        .any(|args| args == ["route", "get"])
                }),
                "{case}: route/interface discovery must happen only after ownership validation"
            );
        }
    }

    #[test]
    fn route_get_host_route_without_table_default_is_rejected() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(|command: &RuleCommand, index| {
            if command
                .args()
                .windows(2)
                .any(|args| args == ["route", "show"])
                && command.args().last().map(String::as_str) == Some("default")
            {
                return Ok(RuleCommandOutput::success(""));
            }
            successful_environment(command, index)
        });
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();

        let error = install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces)
            .unwrap_err();

        assert!(error.to_string().contains("has no usable default route"));
        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("before0".to_owned()));
    }

    #[test]
    fn cleanup_preserves_a_newer_outbound_interface_value() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(Some("before0"));
        let mut lease = AutoRedirectRouteLease::default();
        install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces).unwrap();
        interfaces.set(Some("newer0".to_owned()));
        let cleanup = RecordingExecutor::new(successful_environment);

        uninstall_with_dependencies(&mut lease, &cleanup, &interfaces).unwrap();

        assert!(lease.is_empty());
        assert_eq!(interfaces.value(), Some("newer0".to_owned()));
    }

    #[test]
    fn active_or_dirty_lease_is_rejected_before_any_command() {
        let plan = base_plan();
        let executor = RecordingExecutor::new(successful_environment);
        let interfaces = FakeInterfaceStore::new(None);
        let mut lease = AutoRedirectRouteLease {
            rules: Vec::new(),
            bypass_lookup_tables: Some(BypassLookupTables {
                ipv4: "main".to_owned(),
                ipv6: None,
            }),
            outbound_interface_restore: None,
        };

        assert!(
            install_with_dependencies(&plan, false, &mut lease, &executor, &interfaces,).is_err()
        );
        assert!(executor.commands().is_empty());
    }
}
