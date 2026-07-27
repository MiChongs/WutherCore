use std::{collections::BTreeSet, net::SocketAddr};

use anyhow::{Result, ensure};
use core_config::runtime_plan::RuntimePlan;
use core_mesh::{
    ClaimMode, HostResourceClaim, HostSubsystemId, ResourceClaim, SocketTransport, SystemResource,
};

/// Declare every fixed process-level listener before mesh backends can mutate
/// host networking.
///
/// DNS port `0` is disabled by definition. Mixed and API listeners have an
/// explicit `Option` for disabling, so port `0` is rejected: an OS-assigned
/// port cannot be represented by an exact preflight reservation.
pub(crate) fn listener_resource_claims(plan: &RuntimePlan) -> Result<Vec<HostResourceClaim>> {
    let mut claims = BTreeSet::new();

    if let Some(listen) = plan.resolver.listen.as_deref() {
        let address = core_runtime::parse_dns_listen_addr(listen)
            .map_err(|error| anyhow::anyhow!("DNS listener declaration failed: {error}"))?;
        if let Some(address) = address {
            let owner = host_owner("wuther.dns");
            claims.insert(socket_claim(owner.clone(), SocketTransport::Udp, address));
            claims.insert(socket_claim(owner, SocketTransport::Tcp, address));
        }
    }

    if let Some(mixed) = &plan.listen.mixed {
        let address = mixed
            .socket_addr()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        ensure!(
            address.port() != 0,
            "mixed listener port 0 cannot be reserved; omit listen.local to disable it"
        );
        // SOCKS5 UDP ASSOCIATE uses a separate OS-assigned relay socket, not
        // the configured mixed TCP port.
        claims.insert(socket_claim(
            host_owner("wuther.mixed"),
            SocketTransport::Tcp,
            address,
        ));
    }

    if plan.ui.on {
        if let Some(panel) = &plan.listen.panel {
            let address = panel
                .socket_addr()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            ensure!(
                address.port() != 0,
                "API listener port 0 cannot be reserved; disable ui or omit listen.panel"
            );
            claims.insert(socket_claim(
                host_owner("wuther.api"),
                SocketTransport::Tcp,
                address,
            ));
        }
    }

    debug_assert!(
        claims
            .iter()
            .all(|claim| matches!(claim.claim.mode, ClaimMode::Exclusive))
    );
    Ok(claims.into_iter().collect())
}

fn host_owner(id: &'static str) -> HostSubsystemId {
    HostSubsystemId::new(id).expect("static host subsystem id is valid")
}

fn socket_claim(
    owner: HostSubsystemId,
    transport: SocketTransport,
    address: SocketAddr,
) -> HostResourceClaim {
    HostResourceClaim::new(
        owner,
        ResourceClaim::exclusive(SystemResource::ListenSocket { transport, address }),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn plan(yaml: &str) -> RuntimePlan {
        core_config::loader::load_from_str(yaml).expect("valid runtime plan")
    }

    fn sockets(claims: &[HostResourceClaim]) -> BTreeSet<(String, SocketTransport, SocketAddr)> {
        claims
            .iter()
            .map(|claim| {
                let SystemResource::ListenSocket { transport, address } = &claim.claim.resource
                else {
                    panic!("listener declaration returned a non-socket claim");
                };
                assert!(matches!(claim.claim.mode, ClaimMode::Exclusive));
                (claim.owner.as_str().to_owned(), transport.clone(), *address)
            })
            .collect()
    }

    #[test]
    fn declares_dns_mixed_and_enabled_api_sockets_with_distinct_owners() {
        let plan = plan(
            r#"
version: 1
profile: desktop
listen:
  local:
    host: 127.0.0.1
    port: 7890
    udp: true
  panel: 9090
resolver:
  listen: "127.0.0.1:1053"
route:
  preset: direct
ui:
  on: true
  secret: test-only
"#,
        );

        let claims = listener_resource_claims(&plan).unwrap();
        assert_eq!(
            claims.len(),
            sockets(&claims).len(),
            "claims must be unique"
        );
        assert_eq!(
            sockets(&claims),
            BTreeSet::from([
                (
                    "wuther.api".to_owned(),
                    SocketTransport::Tcp,
                    "127.0.0.1:9090".parse().unwrap(),
                ),
                (
                    "wuther.dns".to_owned(),
                    SocketTransport::Tcp,
                    "127.0.0.1:1053".parse().unwrap(),
                ),
                (
                    "wuther.dns".to_owned(),
                    SocketTransport::Udp,
                    "127.0.0.1:1053".parse().unwrap(),
                ),
                (
                    "wuther.mixed".to_owned(),
                    SocketTransport::Tcp,
                    "127.0.0.1:7890".parse().unwrap(),
                ),
            ])
        );
    }

    #[test]
    fn declares_ipv6_dns_mixed_and_api_sockets() {
        let plan = plan(
            r#"
version: 1
profile: desktop
listen:
  local:
    host: "[::1]"
    port: 7890
    udp: false
  panel: "[::1]:9090"
resolver:
  listen: "[::1]:1053"
route:
  preset: direct
ui:
  on: true
  secret: test-only
"#,
        );

        assert_eq!(
            sockets(&listener_resource_claims(&plan).unwrap()),
            BTreeSet::from([
                (
                    "wuther.api".to_owned(),
                    SocketTransport::Tcp,
                    "[::1]:9090".parse().unwrap(),
                ),
                (
                    "wuther.dns".to_owned(),
                    SocketTransport::Tcp,
                    "[::1]:1053".parse().unwrap(),
                ),
                (
                    "wuther.dns".to_owned(),
                    SocketTransport::Udp,
                    "[::1]:1053".parse().unwrap(),
                ),
                (
                    "wuther.mixed".to_owned(),
                    SocketTransport::Tcp,
                    "[::1]:7890".parse().unwrap(),
                ),
            ])
        );
    }

    #[test]
    fn disabled_dns_and_ui_do_not_declare_sockets() {
        let plan = plan(
            r#"
version: 1
profile: desktop
listen:
  panel: 9090
resolver:
  listen: "127.0.0.1:0"
route:
  preset: direct
ui:
  on: false
"#,
        );

        let claims = listener_resource_claims(&plan).unwrap();
        assert!(
            claims
                .iter()
                .all(|claim| claim.owner.as_str() != "wuther.dns")
        );
        assert!(
            claims
                .iter()
                .all(|claim| claim.owner.as_str() != "wuther.api")
        );
    }

    #[test]
    fn absent_listeners_and_blank_dns_declare_nothing() {
        let plan = plan(
            r#"
version: 1
profile: server
listen:
  panel: false
resolver:
  listen: "   "
route:
  preset: direct
ui:
  on: false
"#,
        );

        assert!(listener_resource_claims(&plan).unwrap().is_empty());
    }

    #[test]
    fn dynamic_mixed_and_api_ports_are_rejected_before_arbitration() {
        let mut mixed = plan(
            r#"
version: 1
profile: desktop
listen:
  local: 7890
route:
  preset: direct
"#,
        );
        mixed.listen.mixed.as_mut().unwrap().port = 0;
        assert!(
            listener_resource_claims(&mixed)
                .unwrap_err()
                .to_string()
                .contains("mixed listener port 0")
        );

        let mut api = plan(
            r#"
version: 1
profile: desktop
listen:
  panel: 9090
route:
  preset: direct
ui:
  on: true
  secret: test-only
"#,
        );
        api.listen.panel.as_mut().unwrap().port = 0;
        assert!(
            listener_resource_claims(&api)
                .unwrap_err()
                .to_string()
                .contains("API listener port 0")
        );
    }

    #[test]
    fn colliding_process_listeners_are_visible_to_mesh_preflight() {
        let plan = plan(
            r#"
version: 1
profile: desktop
listen:
  local: 7890
resolver:
  listen: "127.0.0.1:7890"
route:
  preset: direct
"#,
        );
        let owned = listener_resource_claims(&plan)
            .unwrap()
            .into_iter()
            .map(HostResourceClaim::into_owned)
            .collect::<Vec<_>>();

        let conflicts = core_mesh::detect_conflicts(&owned);

        assert_eq!(conflicts.len(), 1);
        assert_ne!(conflicts[0].left.owner, conflicts[0].right.owner);
        assert!(matches!(
            &conflicts[0].left.claim.resource,
            SystemResource::ListenSocket {
                transport: SocketTransport::Tcp,
                ..
            }
        ));
        assert!(matches!(
            &conflicts[0].right.claim.resource,
            SystemResource::ListenSocket {
                transport: SocketTransport::Tcp,
                ..
            }
        ));
    }

    #[test]
    fn ipv6_wildcard_and_exact_tcp_listeners_conflict() {
        let plan = plan(
            r#"
version: 1
profile: desktop
listen:
  local:
    host: "[::1]"
    port: 7890
resolver:
  listen: "[::]:7890"
route:
  preset: direct
"#,
        );
        let owned = listener_resource_claims(&plan)
            .unwrap()
            .into_iter()
            .map(HostResourceClaim::into_owned)
            .collect::<Vec<_>>();

        let conflicts = core_mesh::detect_conflicts(&owned);

        assert_eq!(conflicts.len(), 1);
        assert_ne!(conflicts[0].left.owner, conflicts[0].right.owner);
    }

    #[test]
    fn invalid_listener_addresses_fail_before_mesh_start() {
        let base = plan(
            r#"
version: 1
profile: desktop
listen:
  local: 7890
  panel: 9090
resolver:
  listen: "127.0.0.1:1053"
route:
  preset: direct
ui:
  on: true
  secret: test-only
"#,
        );

        let mut invalid_dns = base.clone();
        invalid_dns.resolver.listen = Some("not-a-socket".to_owned());
        assert!(
            listener_resource_claims(&invalid_dns)
                .unwrap_err()
                .to_string()
                .contains("DNS listener declaration failed")
        );

        let mut invalid_mixed = base.clone();
        invalid_mixed.listen.mixed.as_mut().unwrap().host = "not-an-ip".to_owned();
        assert!(
            listener_resource_claims(&invalid_mixed)
                .unwrap_err()
                .to_string()
                .contains("非法监听地址")
        );

        let mut invalid_api = base;
        invalid_api.listen.panel.as_mut().unwrap().host = "not-an-ip".to_owned();
        assert!(
            listener_resource_claims(&invalid_api)
                .unwrap_err()
                .to_string()
                .contains("非法面板地址")
        );
    }
}
