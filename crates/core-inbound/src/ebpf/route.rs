use core_config::model::EbpfCapabilityOptions;
use futures::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder,
    packet_route::{
        route::{RouteMessage, RouteScope, RouteType},
        rule::{RuleAction, RuleMessage},
    },
};

use super::{EbpfInboundError, capability};

pub(super) struct PolicyRoute {
    mark: u32,
    table: u32,
    priority: u32,
    ipv4: bool,
    ipv6: bool,
    active: bool,
    capability_policy: EbpfCapabilityOptions,
}

impl PolicyRoute {
    pub(super) async fn install(
        capability_policy: &EbpfCapabilityOptions,
        mark: u32,
        table: u32,
        priority: u32,
        ipv4: bool,
        ipv6: bool,
    ) -> Result<Self, EbpfInboundError> {
        capability::ensure_current_thread(capability_policy)?;
        let mut lease = Self {
            mark,
            table,
            priority,
            ipv4,
            ipv6,
            active: false,
            capability_policy: capability_policy.clone(),
        };
        lease.remove_kernel_state().await;

        let handle = netlink_handle().await?;
        let lo = interface_index(&handle, "lo").await?;
        for family_v6 in [false, true] {
            if (!family_v6 && !ipv4) || (family_v6 && !ipv6) {
                continue;
            }
            if let Err(error) = install_rule(&handle, mark, table, priority, family_v6).await {
                lease.active = true;
                lease.remove_kernel_state().await;
                return Err(EbpfInboundError::Route(format!(
                    "install {} fwmark rule: {error}",
                    family_name(family_v6)
                )));
            }
            if let Err(error) = handle
                .route()
                .add(local_route(lo, table, family_v6))
                .execute()
                .await
            {
                lease.active = true;
                lease.remove_kernel_state().await;
                return Err(EbpfInboundError::Route(format!(
                    "install {} local route: {error}",
                    family_name(family_v6)
                )));
            }
        }
        lease.active = true;
        Ok(lease)
    }

    pub(super) async fn remove(mut self) {
        self.remove_kernel_state().await;
        self.active = false;
    }

    async fn remove_kernel_state(&self) {
        if let Err(error) = capability::ensure_current_thread(&self.capability_policy) {
            tracing::warn!(
                target: "inbound::ebpf",
                %error,
                "cannot restore eBPF policy routes because the current runtime thread lacks capabilities"
            );
            return;
        }
        let Ok(handle) = netlink_handle().await else {
            return;
        };
        let Ok(lo) = interface_index(&handle, "lo").await else {
            return;
        };
        for family_v6 in [false, true] {
            if (!family_v6 && !self.ipv4) || (family_v6 && !self.ipv6) {
                continue;
            }
            let rule = rule_message(&handle, self.mark, self.table, self.priority, family_v6);
            let _ = handle.rule().del(rule).execute().await;
            let _ = handle
                .route()
                .del(local_route(lo, self.table, family_v6))
                .execute()
                .await;
        }
    }
}

async fn netlink_handle() -> Result<Handle, EbpfInboundError> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|error| EbpfInboundError::Route(format!("open rtnetlink: {error}")))?;
    tokio::spawn(connection);
    Ok(handle)
}

async fn interface_index(handle: &Handle, name: &str) -> Result<u32, EbpfInboundError> {
    handle
        .link()
        .get()
        .match_name(name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(|error| EbpfInboundError::Route(format!("query interface {name}: {error}")))?
        .map(|link| link.header.index)
        .ok_or_else(|| EbpfInboundError::Route(format!("interface {name} does not exist")))
}

async fn install_rule(
    handle: &Handle,
    mark: u32,
    table: u32,
    priority: u32,
    ipv6: bool,
) -> Result<(), rtnetlink::Error> {
    let request = handle
        .rule()
        .add()
        .fw_mark(mark)
        .table_id(table)
        .priority(priority)
        .action(RuleAction::ToTable);
    if ipv6 {
        request.v6().execute().await
    } else {
        request.v4().execute().await
    }
}

fn rule_message(handle: &Handle, mark: u32, table: u32, priority: u32, ipv6: bool) -> RuleMessage {
    let request = handle
        .rule()
        .add()
        .fw_mark(mark)
        .table_id(table)
        .priority(priority)
        .action(RuleAction::ToTable);
    if ipv6 {
        request.v6().message_mut().clone()
    } else {
        request.v4().message_mut().clone()
    }
}

fn local_route(interface: u32, table: u32, ipv6: bool) -> RouteMessage {
    if ipv6 {
        RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .output_interface(interface)
            .table_id(table)
            .scope(RouteScope::Host)
            .kind(RouteType::Local)
            .build()
    } else {
        RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .output_interface(interface)
            .table_id(table)
            .scope(RouteScope::Host)
            .kind(RouteType::Local)
            .build()
    }
}

fn family_name(ipv6: bool) -> &'static str {
    if ipv6 { "IPv6" } else { "IPv4" }
}
