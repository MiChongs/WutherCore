//! Native Linux/Android route and policy-rule control.
//!
//! Host network mutations are intentionally performed through rtnetlink
//! instead of parsing or spawning `ip`.  The public surface is synchronous
//! because RouteTable is also used from rollback/drop paths; each transaction
//! owns a short-lived netlink connection on a dedicated thread so it remains
//! safe when called from inside an arbitrary Tokio runtime.

use std::{future::Future, net::IpAddr, thread};

use futures::TryStreamExt;
use netlink_packet_route::{
    route::{RouteMessage, RouteScope, RouteType},
    rule::RuleAction,
};
use rtnetlink::{Handle, RouteMessageBuilder};

use crate::route_table::ManagedRoute;

fn transact<F, Fut>(operation: F) -> Result<(), String>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + 'static,
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
                .priority(route.metric)
                .table_id(table);
            if let Some(IpAddr::V4(gateway)) = gateway {
                builder = builder.gateway(gateway);
            } else if gateway.is_some() {
                return Err("IPv6 gateway cannot be used by an IPv4 route".into());
            }
            builder.build()
        }
        (ipnet::IpNet::V6(dest), gateway) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .destination_prefix(dest.network(), dest.prefix_len())
                .output_interface(index)
                .priority(route.metric)
                .table_id(table);
            if let Some(IpAddr::V6(gateway)) = gateway {
                builder = builder.gateway(gateway);
            } else if gateway.is_some() {
                return Err("IPv4 gateway cannot be used by an IPv6 route".into());
            }
            builder.build()
        }
    };
    Ok(message)
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
