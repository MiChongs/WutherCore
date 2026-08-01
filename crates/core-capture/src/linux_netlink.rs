//! Native Linux/Android route and policy-rule control.
//!
//! Host network mutations are intentionally performed through rtnetlink
//! instead of parsing or spawning `ip`.  The public surface is synchronous
//! because RouteTable is also used from rollback/drop paths; each transaction
//! owns a short-lived netlink connection on a dedicated thread so it remains
//! safe when called from inside an arbitrary Tokio runtime.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    thread,
};

use futures::TryStreamExt;
#[cfg(target_os = "android")]
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::{
    AddressFamily,
    link::LinkAttribute,
    route::{RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute, RuleMessage, RuleUidRange},
};
use rtnetlink::{Handle, IpVersion, LinkUnspec, RouteMessageBuilder};

use crate::route_table::ManagedRoute;

fn transact<F, Fut, T>(operation: F) -> Result<T, String>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name("capture-netlink".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|error| format!("create netlink runtime: {error}"))?;
            runtime.block_on(async move {
                let (connection, handle, _) =
                    rtnetlink::new_connection().map_err(|error| error.to_string())?;
                tokio::spawn(connection);
                operation(handle).await
            })
        })
        .map_err(|error| format!("spawn netlink transaction: {error}"))?
        .join()
        .map_err(|_| "netlink transaction thread panicked".to_owned())?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyFamily {
    V4,
    V6,
}

impl PolicyFamily {
    fn address_family(self) -> AddressFamily {
        match self {
            Self::V4 => AddressFamily::Inet,
            Self::V6 => AddressFamily::Inet6,
        }
    }

    fn ip_version(self) -> IpVersion {
        match self {
            Self::V4 => IpVersion::V4,
            Self::V6 => IpVersion::V6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyAction {
    Lookup(u32),
    /// Continue evaluation at an existing policy-rule priority.
    ///
    /// Android uses this to hand bypassed traffic back to netd instead of
    /// guessing whether the active physical table is wlan, cellular, VPN, or
    /// a per-UID network table.
    Goto(u32),
    Blackhole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRule {
    pub(crate) family: PolicyFamily,
    pub(crate) priority: u32,
    pub(crate) action: PolicyAction,
    pub(crate) fw_mark: Option<u32>,
    pub(crate) fw_mask: Option<u32>,
    pub(crate) destination: Option<ipnet::IpNet>,
    pub(crate) incoming_interface: Option<String>,
    pub(crate) uid_range: Option<(u32, u32)>,
}

impl PolicyRule {
    pub(crate) fn lookup(family: PolicyFamily, priority: u32, table: u32) -> Self {
        Self {
            family,
            priority,
            action: PolicyAction::Lookup(table),
            fw_mark: None,
            fw_mask: None,
            destination: None,
            incoming_interface: None,
            uid_range: None,
        }
    }

    pub(crate) fn goto(family: PolicyFamily, priority: u32, target: u32) -> Self {
        Self {
            family,
            priority,
            action: PolicyAction::Goto(target),
            fw_mark: None,
            fw_mask: None,
            destination: None,
            incoming_interface: None,
            uid_range: None,
        }
    }

    pub(crate) fn blackhole(family: PolicyFamily, priority: u32) -> Self {
        Self {
            family,
            priority,
            action: PolicyAction::Blackhole,
            fw_mark: None,
            fw_mask: None,
            destination: None,
            incoming_interface: None,
            uid_range: None,
        }
    }

    pub(crate) fn with_fw_mark(mut self, mark: u32) -> Self {
        self.fw_mark = Some(mark);
        self.fw_mask = Some(u32::MAX);
        self
    }

    pub(crate) fn with_fw_mark_mask(mut self, mark: u32, mask: u32) -> Self {
        self.fw_mark = Some(mark);
        self.fw_mask = Some(mask);
        self
    }

    pub(crate) fn with_destination(mut self, destination: ipnet::IpNet) -> Self {
        self.destination = Some(destination);
        self
    }

    pub(crate) fn with_incoming_interface(mut self, interface: impl Into<String>) -> Self {
        self.incoming_interface = Some(interface.into());
        self
    }

    pub(crate) fn with_uid_range(mut self, start: u32, end: u32) -> Self {
        self.uid_range = Some((start, end));
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyRuleLease {
    rules: Vec<PolicyRule>,
}

impl PolicyRuleLease {
    pub(crate) fn remove(&mut self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Ok(());
        }
        remove_policy_rules(&self.rules)?;
        self.rules.clear();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteLookup {
    pub(crate) table: u32,
    pub(crate) interface: Option<String>,
}

async fn interface_index(handle: &Handle, name: &str) -> Result<u32, String> {
    handle
        .link()
        .get()
        .match_name(name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(|error| error.to_string())?
        .map(|link| link.header.index)
        .ok_or_else(|| format!("network interface `{name}` does not exist"))
}

async fn route_message(handle: &Handle, route: &ManagedRoute) -> Result<RouteMessage, String> {
    let index = interface_index(handle, &route.interface).await?;
    let table = route.table.unwrap_or(254);
    let message = match (route.dest, route.gateway) {
        (ipnet::IpNet::V4(dest), gateway) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(dest.network(), dest.prefix_len())
                .output_interface(index)
                .protocol(RouteProtocol::Static)
                .kind(RouteType::Unicast)
                .table_id(table);
            if route.metric != 0 {
                builder = builder.priority(route.metric);
            }
            if let Some(IpAddr::V4(gateway)) = gateway {
                builder = builder.gateway(gateway);
            } else if gateway.is_some() {
                return Err("IPv6 gateway cannot be used by an IPv4 route".into());
            } else {
                // Device-only routes are directly connected. Android netd
                // emits RT_SCOPE_LINK for this shape and several vendor
                // kernels reject the generic RT_SCOPE_UNIVERSE variant.
                builder = builder.scope(RouteScope::Link);
            }
            builder.build()
        }
        (ipnet::IpNet::V6(dest), gateway) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .destination_prefix(dest.network(), dest.prefix_len())
                .output_interface(index)
                .protocol(RouteProtocol::Static)
                .kind(RouteType::Unicast)
                .table_id(table);
            if route.metric != 0 {
                builder = builder.priority(route.metric);
            }
            if let Some(IpAddr::V6(gateway)) = gateway {
                builder = builder.gateway(gateway);
            } else if gateway.is_some() {
                return Err("IPv4 gateway cannot be used by an IPv6 route".into());
            } else {
                builder = builder.scope(RouteScope::Link);
            }
            builder.build()
        }
    };
    Ok(explicit_android_route_table(message, table))
}

#[cfg(target_os = "android")]
fn explicit_android_route_table(mut message: RouteMessage, table: u32) -> RouteMessage {
    message.header.table = 0;
    message
        .attributes
        .retain(|attribute| !matches!(attribute, RouteAttribute::Table(_)));
    message.attributes.push(RouteAttribute::Table(table));
    message
}

#[cfg(not(target_os = "android"))]
fn explicit_android_route_table(message: RouteMessage, _table: u32) -> RouteMessage {
    message
}

pub(crate) fn add_route(route: &ManagedRoute) -> Result<(), String> {
    let route = route.clone();
    transact(move |handle| async move {
        let message = route_message(&handle, &route).await?;
        handle
            .route()
            .add(message)
            .execute()
            .await
            .map_err(|error| error.to_string())
    })
}

pub(crate) fn delete_route(route: &ManagedRoute) -> Result<(), String> {
    let route = route.clone();
    transact(move |handle| async move {
        let message = route_message(&handle, &route).await?;
        handle
            .route()
            .del(message)
            .execute()
            .await
            .map_err(|error| error.to_string())
    })
}

fn set_rule_table(message: &mut RuleMessage, table: u32) {
    if cfg!(target_os = "android") || table > u8::MAX.into() {
        message.attributes.push(RuleAttribute::Table(table));
    } else {
        message.header.table = table as u8;
    }
}

fn policy_rule_message(rule: &PolicyRule) -> Result<RuleMessage, String> {
    let mut message = RuleMessage::default();
    message.header.family = rule.family.address_family();
    message.header.action = match rule.action {
        PolicyAction::Lookup(table) => {
            set_rule_table(&mut message, table);
            RuleAction::ToTable
        }
        PolicyAction::Goto(target) => {
            message.attributes.push(RuleAttribute::Goto(target));
            RuleAction::Goto
        }
        PolicyAction::Blackhole => RuleAction::Blackhole,
    };
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some(mark) = rule.fw_mark {
        message.attributes.push(RuleAttribute::FwMark(mark));
        message
            .attributes
            .push(RuleAttribute::FwMask(rule.fw_mask.unwrap_or(u32::MAX)));
    }
    if let Some(interface) = &rule.incoming_interface {
        message
            .attributes
            .push(RuleAttribute::Iifname(interface.clone()));
    }
    if let Some((start, end)) = rule.uid_range {
        if start > end {
            return Err(format!("invalid policy UID range {start}:{end}"));
        }
        message
            .attributes
            .push(RuleAttribute::UidRange(RuleUidRange { start, end }));
    }
    if let Some(destination) = rule.destination {
        match (rule.family, destination) {
            (PolicyFamily::V4, ipnet::IpNet::V4(destination)) => {
                message.header.dst_len = destination.prefix_len();
                message
                    .attributes
                    .push(RuleAttribute::Destination(IpAddr::V4(
                        destination.network(),
                    )));
            }
            (PolicyFamily::V6, ipnet::IpNet::V6(destination)) => {
                message.header.dst_len = destination.prefix_len();
                message
                    .attributes
                    .push(RuleAttribute::Destination(IpAddr::V6(
                        destination.network(),
                    )));
            }
            _ => {
                return Err(format!(
                    "policy rule address family mismatch: {:?} with {destination}",
                    rule.family
                ));
            }
        }
    }
    Ok(message)
}

async fn add_rule_message(handle: &Handle, message: RuleMessage) -> Result<(), String> {
    let mut request = handle.rule().add();
    *request.message_mut() = message;
    request.execute().await.map_err(|error| error.to_string())
}

fn expected_absence(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "no such process",
        "no such file or directory",
        "not found",
        "does not exist",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

async fn delete_rule_message(handle: &Handle, message: RuleMessage) -> Result<(), String> {
    match handle.rule().del(message).execute().await {
        Ok(()) => Ok(()),
        Err(error) if expected_absence(&error.to_string()) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

async fn ensure_policy_priorities_available(
    handle: &Handle,
    requested: &[PolicyRule],
) -> Result<(), String> {
    for family in [PolicyFamily::V4, PolicyFamily::V6] {
        let priorities = requested
            .iter()
            .filter(|rule| rule.family == family)
            .map(|rule| rule.priority)
            .collect::<Vec<_>>();
        if priorities.is_empty() {
            continue;
        }

        let mut existing = handle.rule().get(family.ip_version()).execute();
        while let Some(message) = existing
            .try_next()
            .await
            .map_err(|error| error.to_string())?
        {
            let Some(priority) = message_rule_priority(&message) else {
                continue;
            };
            if priorities.contains(&priority) {
                return Err(format!(
                    "policy rule priority {priority} for {family:?} is already occupied"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn install_policy_rules(rules: Vec<PolicyRule>) -> Result<PolicyRuleLease, String> {
    let transaction_rules = rules.clone();
    transact(move |handle| async move {
        ensure_policy_priorities_available(&handle, &transaction_rules).await?;
        let mut installed = Vec::with_capacity(transaction_rules.len());
        for rule in &transaction_rules {
            let message = policy_rule_message(rule)?;
            if let Err(error) = add_rule_message(&handle, message.clone()).await {
                for previous in installed.into_iter().rev() {
                    let _ = delete_rule_message(&handle, previous).await;
                }
                return Err(format!(
                    "install policy rule priority {} {:?}: {error}",
                    rule.priority, rule.action
                ));
            }
            installed.push(message);
        }
        Ok(())
    })?;
    Ok(PolicyRuleLease { rules })
}

pub(crate) fn remove_policy_rules(rules: &[PolicyRule]) -> Result<(), String> {
    let rules = rules.to_vec();
    transact(move |handle| async move {
        let mut errors = Vec::new();
        for rule in rules.iter().rev() {
            let message = policy_rule_message(rule)?;
            if let Err(error) = delete_rule_message(&handle, message).await {
                errors.push(format!(
                    "remove policy rule priority {} {:?}: {error}",
                    rule.priority, rule.action
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    })
}

fn message_rule_priority(message: &RuleMessage) -> Option<u32> {
    message.attributes.iter().find_map(|attribute| {
        if let RuleAttribute::Priority(priority) = attribute {
            Some(*priority)
        } else {
            None
        }
    })
}

fn rule_table(message: &RuleMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let RuleAttribute::Table(table) = attribute {
                Some(*table)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(message.header.table))
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let rtnetlink::packet_route::route::RouteAttribute::Table(table) = attribute {
                Some(*table)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(message.header.table))
}

fn route_dump_message(family: PolicyFamily) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = family.address_family();
    message
}

pub(crate) fn recover_owned_policy(
    table: u32,
    rule_priority: u32,
    bypass_tables: Vec<u32>,
    bypass_any_table: bool,
    strict_route: bool,
) -> Result<(), String> {
    transact(move |handle| async move {
        let mut owned = Vec::new();
        for family in [PolicyFamily::V4, PolicyFamily::V6] {
            let mut rules = handle.rule().get(family.ip_version()).execute();
            while let Some(message) = rules.try_next().await.map_err(|error| error.to_string())? {
                if recovery_owns_rule(
                    &message,
                    table,
                    rule_priority,
                    &bypass_tables,
                    bypass_any_table,
                    strict_route,
                ) {
                    owned.push(message);
                }
            }
        }
        let mut errors = Vec::new();
        for message in owned.into_iter().rev() {
            if let Err(error) = delete_rule_message(&handle, message).await {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    })
}

fn recovery_owns_rule(
    message: &RuleMessage,
    table: u32,
    rule_priority: u32,
    bypass_tables: &[u32],
    bypass_any_table: bool,
    strict_route: bool,
) -> bool {
    let Some(priority) = message_rule_priority(message) else {
        return false;
    };
    let lookup_table = rule_table(message);
    let custom_priorities = [rule_priority.saturating_sub(3).max(1), rule_priority];
    let bypass_priorities = [
        rule_priority.saturating_sub(2).max(1),
        rule_priority.saturating_sub(1).max(1),
    ];
    let owns_custom = custom_priorities.contains(&priority) && lookup_table == table;
    let owns_bypass = bypass_priorities.contains(&priority)
        && (bypass_any_table || bypass_tables.contains(&lookup_table));
    let owns_android_netd_handoff = bypass_priorities.contains(&priority)
        && message.header.action == RuleAction::Goto
        && message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RuleAttribute::Goto(target) if *target == 10_000));
    let owns_strict = strict_route
        && priority == rule_priority.saturating_add(1)
        && message.header.action == RuleAction::Blackhole;
    owns_custom || owns_bypass || owns_android_netd_handoff || owns_strict
}

/// Refuse to reuse a routing table that already belongs to Android netd or
/// another process. The caller invokes this before adding any owned route.
pub(crate) fn ensure_route_table_available(table: u32) -> Result<(), String> {
    transact(move |handle| async move {
        for family in [PolicyFamily::V4, PolicyFamily::V6] {
            let message = route_dump_message(family);
            let mut routes = handle.route().get(message).execute();
            while let Some(route) = routes.try_next().await.map_err(|error| error.to_string())? {
                if route_table(&route) == table {
                    return Err(format!(
                        "routing table {table} already contains a route; choose an unused inbounds[].iproute2_table_index"
                    ));
                }
            }
        }
        Ok(())
    })
}

pub(crate) fn flush_route_table(table: u32) -> Result<(), String> {
    transact(move |handle| async move {
        let mut owned = Vec::new();
        for family in [PolicyFamily::V4, PolicyFamily::V6] {
            let message = route_dump_message(family);
            let mut routes = handle.route().get(message).execute();
            while let Some(route) = routes.try_next().await.map_err(|error| error.to_string())? {
                if route_table(&route) == table {
                    owned.push(route);
                }
            }
        }
        let mut errors = Vec::new();
        for route in owned.into_iter().rev() {
            match handle.route().del(route).execute().await {
                Ok(()) => {}
                Err(error) if expected_absence(&error.to_string()) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    })
}

async fn interface_name(handle: &Handle, index: u32) -> Result<Option<String>, String> {
    let Some(link) = handle
        .link()
        .get()
        .match_index(index)
        .execute()
        .try_next()
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    Ok(link.attributes.into_iter().find_map(|attribute| {
        if let LinkAttribute::IfName(name) = attribute {
            Some(name)
        } else {
            None
        }
    }))
}

pub(crate) fn lookup_route(target: IpAddr) -> Result<RouteLookup, String> {
    transact(move |handle| async move {
        let message = match target {
            IpAddr::V4(target) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(target, 32)
                .build(),
            IpAddr::V6(target) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(target, 128)
                .build(),
        };
        let route = handle
            .route()
            .get(message)
            .execute()
            .try_next()
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("kernel returned no route for {target}"))?;
        let output_index = route.attributes.iter().find_map(|attribute| {
            if let rtnetlink::packet_route::route::RouteAttribute::Oif(index) = attribute {
                Some(*index)
            } else {
                None
            }
        });
        let interface = match output_index {
            Some(index) => interface_name(&handle, index).await?,
            None => None,
        };
        let table = route_table(&route);
        if table == 0 {
            return Err(format!(
                "kernel returned an unspecified routing table for {target}"
            ));
        }
        Ok(RouteLookup { table, interface })
    })
}

pub(crate) fn configure_tun_interface(
    interface: String,
    mtu: u32,
    addresses: Vec<ipnet::IpNet>,
) -> Result<(), String> {
    transact(move |handle| async move {
        let index = interface_index(&handle, &interface).await?;
        let link = LinkUnspec::new_with_index(index).mtu(mtu).up().build();
        handle
            .link()
            .change(link)
            .execute()
            .await
            .map_err(|error| format!("configure link `{interface}`: {error}"))?;

        for address in addresses {
            let ip = address.addr();
            let prefix = address.prefix_len();
            let exists = handle
                .address()
                .get()
                .set_link_index_filter(index)
                .set_prefix_length_filter(prefix)
                .set_address_filter(ip)
                .execute()
                .try_next()
                .await
                .map_err(|error| format!("query address {address} on `{interface}`: {error}"))?
                .is_some();
            if !exists {
                handle
                    .address()
                    .add(index, ip, prefix)
                    .execute()
                    .await
                    .map_err(|error| format!("add address {address} to `{interface}`: {error}"))?;
            }
        }
        Ok(())
    })
}

pub(crate) fn delete_interface(interface: String) -> Result<(), String> {
    if interface.is_empty() || interface == "lo" {
        return Ok(());
    }
    transact(move |handle| async move {
        let Some(link) = handle
            .link()
            .get()
            .match_name(interface.clone())
            .execute()
            .try_next()
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        match handle.link().del(link.header.index).execute().await {
            Ok(()) => Ok(()),
            Err(error) if expected_absence(&error.to_string()) => Ok(()),
            Err(error) => Err(format!("delete interface `{interface}`: {error}")),
        }
    })
}

fn tproxy_route(index: u32, ipv6: bool, table: u32) -> RouteMessage {
    if ipv6 {
        RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .output_interface(index)
            .table_id(table)
            .scope(RouteScope::Host)
            .kind(RouteType::Local)
            .build()
    } else {
        RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .output_interface(index)
            .table_id(table)
            .scope(RouteScope::Host)
            .kind(RouteType::Local)
            .build()
    }
}

pub(crate) fn install_tproxy_policy(
    ipv6_enabled: bool,
    mark: u32,
    table: u32,
) -> Result<(), String> {
    transact(move |handle| async move {
        let lo = interface_index(&handle, "lo").await?;
        for ipv6 in [false, true]
            .into_iter()
            .take(if ipv6_enabled { 2 } else { 1 })
        {
            if ipv6 {
                handle
                    .rule()
                    .add()
                    .v6()
                    .fw_mark(mark)
                    .table_id(table)
                    .action(RuleAction::ToTable)
                    .execute()
                    .await
                    .map_err(|error| error.to_string())?;
            } else {
                handle
                    .rule()
                    .add()
                    .v4()
                    .fw_mark(mark)
                    .table_id(table)
                    .action(RuleAction::ToTable)
                    .execute()
                    .await
                    .map_err(|error| error.to_string())?;
            }
            if let Err(error) = handle
                .route()
                .add(tproxy_route(lo, ipv6, table))
                .execute()
                .await
            {
                return Err(error.to_string());
            }
        }
        Ok(())
    })
}

pub(crate) fn remove_tproxy_policy(ipv6_enabled: bool, mark: u32, table: u32) {
    let _ = transact(move |handle| async move {
        let lo = interface_index(&handle, "lo").await?;
        for ipv6 in [false, true]
            .into_iter()
            .take(if ipv6_enabled { 2 } else { 1 })
        {
            if ipv6 {
                let mut request = handle
                    .rule()
                    .add()
                    .v6()
                    .fw_mark(mark)
                    .table_id(table)
                    .action(RuleAction::ToTable);
                let message = request.message_mut().clone();
                let _ = handle.rule().del(message).execute().await;
                let _ = handle
                    .route()
                    .del(tproxy_route(lo, true, table))
                    .execute()
                    .await;
            } else {
                let mut request = handle
                    .rule()
                    .add()
                    .v4()
                    .fw_mark(mark)
                    .table_id(table)
                    .action(RuleAction::ToTable);
                let message = request.message_mut().clone();
                let _ = handle.rule().del(message).execute().await;
                let _ = handle
                    .route()
                    .del(tproxy_route(lo, false, table))
                    .execute()
                    .await;
            }
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_rule_is_native_blackhole_without_fake_default_selector() {
        let message = policy_rule_message(&PolicyRule::blackhole(PolicyFamily::V4, 9001)).unwrap();

        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.action, RuleAction::Blackhole);
        assert_eq!(message.header.dst_len, 0);
        assert_eq!(message_rule_priority(&message), Some(9001));
        assert!(
            !message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RuleAttribute::Destination(_)))
        );
    }

    #[test]
    fn android_sized_table_and_mark_are_encoded_as_netlink_attributes() {
        let message = policy_rule_message(
            &PolicyRule::lookup(PolicyFamily::V4, 8999, 10_517).with_fw_mark(0x2024),
        )
        .unwrap();

        assert_eq!(message.header.action, RuleAction::ToTable);
        assert_eq!(rule_table(&message), 10_517);
        assert!(message.attributes.contains(&RuleAttribute::FwMark(0x2024)));
        assert!(
            message
                .attributes
                .contains(&RuleAttribute::FwMask(u32::MAX))
        );
    }

    #[test]
    #[cfg(target_os = "android")]
    fn android_always_uses_explicit_route_and_rule_table_attributes() {
        let route = explicit_android_route_table(
            RouteMessageBuilder::<Ipv4Addr>::new().table_id(97).build(),
            97,
        );
        assert_eq!(route.header.table, 0);
        assert!(route.attributes.contains(&RouteAttribute::Table(97)));

        let rule = policy_rule_message(&PolicyRule::lookup(PolicyFamily::V4, 9000, 97)).unwrap();
        assert_eq!(rule.header.table, 0);
        assert!(rule.attributes.contains(&RuleAttribute::Table(97)));
    }

    #[test]
    fn android_netd_handoff_encodes_goto_iif_uid_and_partial_mark_mask() {
        let message = policy_rule_message(
            &PolicyRule::goto(PolicyFamily::V4, 8999, 10_000)
                .with_incoming_interface("lo")
                .with_uid_range(10_000, 19_999)
                .with_fw_mark_mask(0x0020_0000, 0x0020_0000),
        )
        .unwrap();

        assert_eq!(message.header.action, RuleAction::Goto);
        assert_eq!(rule_table(&message), 0);
        assert!(message.attributes.contains(&RuleAttribute::Goto(10_000)));
        assert!(
            message
                .attributes
                .contains(&RuleAttribute::Iifname("lo".into()))
        );
        assert!(
            message
                .attributes
                .contains(&RuleAttribute::UidRange(RuleUidRange {
                    start: 10_000,
                    end: 19_999,
                }))
        );
        assert!(
            message
                .attributes
                .contains(&RuleAttribute::FwMask(0x0020_0000))
        );
        assert!(recovery_owns_rule(&message, 2022, 9000, &[], false, false,));
    }

    #[test]
    fn recovery_matches_only_owned_priority_table_pairs() {
        let owned = policy_rule_message(&PolicyRule::lookup(PolicyFamily::V4, 9000, 2022)).unwrap();
        let foreign_table =
            policy_rule_message(&PolicyRule::lookup(PolicyFamily::V4, 9000, 2023)).unwrap();
        let foreign_priority =
            policy_rule_message(&PolicyRule::lookup(PolicyFamily::V4, 8000, 2022)).unwrap();
        let strict = policy_rule_message(&PolicyRule::blackhole(PolicyFamily::V6, 9001)).unwrap();

        assert!(recovery_owns_rule(&owned, 2022, 9000, &[254], false, true));
        assert!(!recovery_owns_rule(
            &foreign_table,
            2022,
            9000,
            &[254],
            false,
            true
        ));
        assert!(!recovery_owns_rule(
            &foreign_priority,
            2022,
            9000,
            &[254],
            false,
            true
        ));
        let legacy_named_bypass =
            policy_rule_message(&PolicyRule::lookup(PolicyFamily::V4, 8999, 10_517)).unwrap();
        assert!(recovery_owns_rule(
            &legacy_named_bypass,
            2022,
            9000,
            &[],
            true,
            true
        ));
        assert!(recovery_owns_rule(&strict, 2022, 9000, &[254], false, true));
        assert!(!recovery_owns_rule(
            &strict,
            2022,
            9000,
            &[254],
            false,
            false
        ));
    }
}
