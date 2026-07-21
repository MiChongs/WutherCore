//! Deterministic host-resource conflict detection.
//!
//! Claims are compared by resource semantics rather than enum equality: address
//! and route prefixes overlap, wildcard listeners cover concrete addresses, and
//! firewall mark ranges are inclusive. Only claims from different owners can
//! conflict.

#![forbid(unsafe_code)]

use std::{
    borrow::Borrow,
    fmt,
    net::{IpAddr, SocketAddr},
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::model::{
    ClaimMode, FwmarkRange, OwnedResourceClaim, PublicOwnedResourceClaim, PublicSocketTransport,
    SocketTransport, SystemResource, public_custom_string,
};

/// A deterministic description of two incompatible resource claims.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceConflict {
    pub kind: ResourceConflictKind,
    pub incompatibility: ClaimIncompatibility,
    pub left: OwnedResourceClaim,
    pub right: OwnedResourceClaim,
}

/// Resource-specific reason that two claims overlap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum ResourceConflictKind {
    Singleton {
        resource: SingletonResource,
    },
    RouteManager {
        managed_resource: RouteManagedResource,
    },
    FirewallManager {
        range: FwmarkRange,
    },
    InterfaceManager {
        name: String,
    },
    Interface {
        name: String,
    },
    ListenSocket {
        transport: SocketTransport,
        left: SocketAddr,
        right: SocketAddr,
    },
    AddressPrefix {
        left: IpNet,
        right: IpNet,
    },
    AddressRoutePrefix {
        address_prefix: IpNet,
        route_table: Option<u32>,
        route_prefix: IpNet,
    },
    DefaultRoutePrefix {
        family: SingletonResource,
        route_table: Option<u32>,
        route_prefix: IpNet,
    },
    RoutePrefix {
        left_table: Option<u32>,
        right_table: Option<u32>,
        left: IpNet,
        right: IpNet,
    },
    RouteTablePrefix {
        table: u32,
        route_prefix: IpNet,
    },
    RouteTable {
        table: u32,
    },
    FwmarkRange {
        left: FwmarkRange,
        right: FwmarkRange,
    },
}

/// Globally unique host facilities represented by singleton claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SingletonResource {
    RouteManager,
    DefaultRouteV4,
    DefaultRouteV6,
    DnsManager,
    FirewallManager,
    HostsDatabase,
    InterfaceManager,
}

/// Route resource covered by the global route-manager claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum RouteManagedResource {
    DefaultRouteV4,
    DefaultRouteV6,
    RoutePrefix { table: Option<u32>, prefix: IpNet },
    RouteTable { table: u32 },
}

/// Why coordination modes do not permit an overlapping pair to coexist.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum ClaimIncompatibility {
    /// At least one claim requests exclusive ownership.
    Exclusive,
    /// At least one coordinated claim has an empty or whitespace-only key.
    MissingCoordinationKey,
    /// Both claims are coordinated, but their normalized keys differ.
    ///
    /// The values themselves are deliberately not retained because coordination
    /// keys may be credentials or other provider-sensitive material.
    CoordinationKeyMismatch,
}

impl fmt::Debug for ClaimIncompatibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Exclusive => "Exclusive",
            Self::MissingCoordinationKey => "MissingCoordinationKey",
            Self::CoordinationKeyMismatch => "CoordinationKeyMismatch",
        })
    }
}

/// Redacted conflict projection suitable for the public mesh API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicResourceConflict {
    pub kind: PublicResourceConflictKind,
    pub incompatibility: PublicClaimIncompatibility,
    pub left: PublicOwnedResourceClaim,
    pub right: PublicOwnedResourceClaim,
}

impl From<&ResourceConflict> for PublicResourceConflict {
    fn from(value: &ResourceConflict) -> Self {
        Self {
            kind: (&value.kind).into(),
            incompatibility: (&value.incompatibility).into(),
            left: (&value.left).into(),
            right: (&value.right).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum PublicResourceConflictKind {
    Singleton {
        resource: PublicSingletonResource,
    },
    RouteManager {
        managed_resource: PublicRouteManagedResource,
    },
    FirewallManager {
        range: FwmarkRange,
    },
    InterfaceManager {
        name: String,
    },
    Interface {
        name: String,
    },
    ListenSocket {
        transport: PublicSocketTransport,
        left: SocketAddr,
        right: SocketAddr,
    },
    AddressPrefix {
        left: IpNet,
        right: IpNet,
    },
    AddressRoutePrefix {
        address_prefix: IpNet,
        route_table: Option<u32>,
        route_prefix: IpNet,
    },
    DefaultRoutePrefix {
        family: PublicSingletonResource,
        route_table: Option<u32>,
        route_prefix: IpNet,
    },
    RoutePrefix {
        left_table: Option<u32>,
        right_table: Option<u32>,
        left: IpNet,
        right: IpNet,
    },
    RouteTablePrefix {
        table: u32,
        route_prefix: IpNet,
    },
    RouteTable {
        table: u32,
    },
    FwmarkRange {
        left: FwmarkRange,
        right: FwmarkRange,
    },
}

impl From<&ResourceConflictKind> for PublicResourceConflictKind {
    fn from(value: &ResourceConflictKind) -> Self {
        match value {
            ResourceConflictKind::Singleton { resource } => Self::Singleton {
                resource: (*resource).into(),
            },
            ResourceConflictKind::RouteManager { managed_resource } => Self::RouteManager {
                managed_resource: managed_resource.into(),
            },
            ResourceConflictKind::FirewallManager { range } => {
                Self::FirewallManager { range: *range }
            }
            ResourceConflictKind::InterfaceManager { name } => Self::InterfaceManager {
                name: public_custom_string(name),
            },
            ResourceConflictKind::Interface { name } => Self::Interface {
                name: public_custom_string(name),
            },
            ResourceConflictKind::ListenSocket {
                transport,
                left,
                right,
            } => Self::ListenSocket {
                transport: transport.into(),
                left: *left,
                right: *right,
            },
            ResourceConflictKind::AddressPrefix { left, right } => Self::AddressPrefix {
                left: *left,
                right: *right,
            },
            ResourceConflictKind::AddressRoutePrefix {
                address_prefix,
                route_table,
                route_prefix,
            } => Self::AddressRoutePrefix {
                address_prefix: *address_prefix,
                route_table: *route_table,
                route_prefix: *route_prefix,
            },
            ResourceConflictKind::DefaultRoutePrefix {
                family,
                route_table,
                route_prefix,
            } => Self::DefaultRoutePrefix {
                family: (*family).into(),
                route_table: *route_table,
                route_prefix: *route_prefix,
            },
            ResourceConflictKind::RoutePrefix {
                left_table,
                right_table,
                left,
                right,
            } => Self::RoutePrefix {
                left_table: *left_table,
                right_table: *right_table,
                left: *left,
                right: *right,
            },
            ResourceConflictKind::RouteTablePrefix {
                table,
                route_prefix,
            } => Self::RouteTablePrefix {
                table: *table,
                route_prefix: *route_prefix,
            },
            ResourceConflictKind::RouteTable { table } => Self::RouteTable { table: *table },
            ResourceConflictKind::FwmarkRange { left, right } => Self::FwmarkRange {
                left: *left,
                right: *right,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSingletonResource {
    RouteManager,
    DefaultRouteV4,
    DefaultRouteV6,
    DnsManager,
    FirewallManager,
    HostsDatabase,
    InterfaceManager,
}

impl From<SingletonResource> for PublicSingletonResource {
    fn from(value: SingletonResource) -> Self {
        match value {
            SingletonResource::RouteManager => Self::RouteManager,
            SingletonResource::DefaultRouteV4 => Self::DefaultRouteV4,
            SingletonResource::DefaultRouteV6 => Self::DefaultRouteV6,
            SingletonResource::DnsManager => Self::DnsManager,
            SingletonResource::FirewallManager => Self::FirewallManager,
            SingletonResource::HostsDatabase => Self::HostsDatabase,
            SingletonResource::InterfaceManager => Self::InterfaceManager,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "details", rename_all = "snake_case")]
pub enum PublicRouteManagedResource {
    DefaultRouteV4,
    DefaultRouteV6,
    RoutePrefix { table: Option<u32>, prefix: IpNet },
    RouteTable { table: u32 },
}

impl From<&RouteManagedResource> for PublicRouteManagedResource {
    fn from(value: &RouteManagedResource) -> Self {
        match value {
            RouteManagedResource::DefaultRouteV4 => Self::DefaultRouteV4,
            RouteManagedResource::DefaultRouteV6 => Self::DefaultRouteV6,
            RouteManagedResource::RoutePrefix { table, prefix } => Self::RoutePrefix {
                table: *table,
                prefix: *prefix,
            },
            RouteManagedResource::RouteTable { table } => Self::RouteTable { table: *table },
        }
    }
}

/// Public incompatibility reason. Coordination keys are deliberately omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PublicClaimIncompatibility {
    Exclusive,
    MissingCoordination,
    CoordinationMismatch,
}

impl From<&ClaimIncompatibility> for PublicClaimIncompatibility {
    fn from(value: &ClaimIncompatibility) -> Self {
        match value {
            ClaimIncompatibility::Exclusive => Self::Exclusive,
            ClaimIncompatibility::MissingCoordinationKey => Self::MissingCoordination,
            ClaimIncompatibility::CoordinationKeyMismatch => Self::CoordinationMismatch,
        }
    }
}

/// Detect all conflicts between claims from distinct owners.
///
/// Input order and duplicate claims do not affect the result. Overlapping
/// coordinated claims coexist only when both use the same non-empty key.
pub fn detect_conflicts<I, C>(claims: I) -> Vec<ResourceConflict>
where
    I: IntoIterator<Item = C>,
    C: Borrow<OwnedResourceClaim>,
{
    let mut claims: Vec<_> = claims
        .into_iter()
        .map(|claim| claim.borrow().clone())
        .collect();
    claims.sort();
    claims.dedup();

    let mut conflicts = Vec::new();
    for left_index in 0..claims.len() {
        for right_index in (left_index + 1)..claims.len() {
            let left = &claims[left_index];
            let right = &claims[right_index];
            if left.owner == right.owner {
                continue;
            }

            let Some(kind) = overlapping_kind(&left.claim.resource, &right.claim.resource) else {
                continue;
            };
            let Some(incompatibility) = claim_incompatibility(&left.claim.mode, &right.claim.mode)
            else {
                continue;
            };

            conflicts.push(ResourceConflict {
                kind,
                incompatibility,
                left: left.clone(),
                right: right.clone(),
            });
        }
    }

    conflicts.sort();
    conflicts.dedup();
    conflicts
}

fn claim_incompatibility(left: &ClaimMode, right: &ClaimMode) -> Option<ClaimIncompatibility> {
    match (left, right) {
        (ClaimMode::Exclusive, _) | (_, ClaimMode::Exclusive) => {
            Some(ClaimIncompatibility::Exclusive)
        }
        (
            ClaimMode::CoordinatedShared {
                coordination_key: left,
            },
            ClaimMode::CoordinatedShared {
                coordination_key: right,
            },
        ) => {
            let left = left.trim();
            let right = right.trim();
            if left.is_empty() || right.is_empty() {
                Some(ClaimIncompatibility::MissingCoordinationKey)
            } else if left == right {
                None
            } else {
                Some(ClaimIncompatibility::CoordinationKeyMismatch)
            }
        }
    }
}

fn overlapping_kind(left: &SystemResource, right: &SystemResource) -> Option<ResourceConflictKind> {
    use SystemResource::{
        AddressPrefix, DefaultRouteV4, DefaultRouteV6, DnsManager, FirewallManager, FwmarkRange,
        HostsDatabase, Interface, InterfaceManager, ListenSocket, RouteManager, RoutePrefix,
        RouteTable,
    };

    match (left, right) {
        (RouteManager, RouteManager) => Some(singleton(SingletonResource::RouteManager)),
        (RouteManager, DefaultRouteV4) | (DefaultRouteV4, RouteManager) => {
            Some(ResourceConflictKind::RouteManager {
                managed_resource: RouteManagedResource::DefaultRouteV4,
            })
        }
        (RouteManager, DefaultRouteV6) | (DefaultRouteV6, RouteManager) => {
            Some(ResourceConflictKind::RouteManager {
                managed_resource: RouteManagedResource::DefaultRouteV6,
            })
        }
        (RouteManager, RoutePrefix { table, prefix })
        | (RoutePrefix { table, prefix }, RouteManager) => {
            Some(ResourceConflictKind::RouteManager {
                managed_resource: RouteManagedResource::RoutePrefix {
                    table: *table,
                    prefix: *prefix,
                },
            })
        }
        (RouteManager, RouteTable { table }) | (RouteTable { table }, RouteManager) => {
            Some(ResourceConflictKind::RouteManager {
                managed_resource: RouteManagedResource::RouteTable { table: *table },
            })
        }
        (DefaultRouteV4, DefaultRouteV4) => Some(singleton(SingletonResource::DefaultRouteV4)),
        (DefaultRouteV6, DefaultRouteV6) => Some(singleton(SingletonResource::DefaultRouteV6)),
        (DefaultRouteV4, RoutePrefix { table, prefix })
        | (RoutePrefix { table, prefix }, DefaultRouteV4)
            if prefix.addr().is_ipv4() && prefix.prefix_len() == 0 =>
        {
            Some(ResourceConflictKind::DefaultRoutePrefix {
                family: SingletonResource::DefaultRouteV4,
                route_table: *table,
                route_prefix: *prefix,
            })
        }
        (DefaultRouteV6, RoutePrefix { table, prefix })
        | (RoutePrefix { table, prefix }, DefaultRouteV6)
            if prefix.addr().is_ipv6() && prefix.prefix_len() == 0 =>
        {
            Some(ResourceConflictKind::DefaultRoutePrefix {
                family: SingletonResource::DefaultRouteV6,
                route_table: *table,
                route_prefix: *prefix,
            })
        }
        (DnsManager, DnsManager) => Some(singleton(SingletonResource::DnsManager)),
        (FirewallManager, FirewallManager) => Some(singleton(SingletonResource::FirewallManager)),
        (FirewallManager, FwmarkRange { range }) | (FwmarkRange { range }, FirewallManager) => {
            Some(ResourceConflictKind::FirewallManager { range: *range })
        }
        (HostsDatabase, HostsDatabase) => Some(singleton(SingletonResource::HostsDatabase)),
        (InterfaceManager, InterfaceManager) => {
            Some(singleton(SingletonResource::InterfaceManager))
        }
        (InterfaceManager, Interface { name }) | (Interface { name }, InterfaceManager) => {
            Some(ResourceConflictKind::InterfaceManager { name: name.clone() })
        }
        (Interface { name: left }, Interface { name: right }) if left == right => {
            Some(ResourceConflictKind::Interface { name: left.clone() })
        }
        (
            ListenSocket {
                transport: left_transport,
                address: left_address,
            },
            ListenSocket {
                transport: right_transport,
                address: right_address,
            },
        ) if left_transport == right_transport
            && listeners_overlap(*left_address, *right_address) =>
        {
            Some(ResourceConflictKind::ListenSocket {
                transport: left_transport.clone(),
                left: *left_address,
                right: *right_address,
            })
        }
        (
            AddressPrefix {
                prefix: left_prefix,
            },
            AddressPrefix {
                prefix: right_prefix,
            },
        ) if prefixes_overlap(left_prefix, right_prefix) => {
            Some(ResourceConflictKind::AddressPrefix {
                left: *left_prefix,
                right: *right_prefix,
            })
        }
        (
            AddressPrefix {
                prefix: address_prefix,
            },
            RoutePrefix {
                table,
                prefix: route_prefix,
            },
        )
        | (
            RoutePrefix {
                table,
                prefix: route_prefix,
            },
            AddressPrefix {
                prefix: address_prefix,
            },
        ) if prefixes_overlap(address_prefix, route_prefix) => {
            Some(ResourceConflictKind::AddressRoutePrefix {
                address_prefix: *address_prefix,
                route_table: *table,
                route_prefix: *route_prefix,
            })
        }
        (
            RoutePrefix {
                table: left_table,
                prefix: left_prefix,
            },
            RoutePrefix {
                table: right_table,
                prefix: right_prefix,
            },
        ) if route_tables_overlap(*left_table, *right_table)
            && prefixes_overlap(left_prefix, right_prefix) =>
        {
            Some(ResourceConflictKind::RoutePrefix {
                left_table: *left_table,
                right_table: *right_table,
                left: *left_prefix,
                right: *right_prefix,
            })
        }
        (RouteTable { table: left }, RouteTable { table: right }) if left == right => {
            Some(ResourceConflictKind::RouteTable { table: *left })
        }
        (
            RouteTable { table },
            RoutePrefix {
                table: route_table,
                prefix,
            },
        )
        | (
            RoutePrefix {
                table: route_table,
                prefix,
            },
            RouteTable { table },
        ) if route_table.is_none() || route_table == &Some(*table) => {
            Some(ResourceConflictKind::RouteTablePrefix {
                table: *table,
                route_prefix: *prefix,
            })
        }
        (FwmarkRange { range: left }, FwmarkRange { range: right }) if left.overlaps(*right) => {
            Some(ResourceConflictKind::FwmarkRange {
                left: *left,
                right: *right,
            })
        }
        _ => None,
    }
}

fn singleton(resource: SingletonResource) -> ResourceConflictKind {
    ResourceConflictKind::Singleton { resource }
}

fn listeners_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() != right.port() {
        return false;
    }

    let left = normalized_listener_ip(left.ip());
    let right = normalized_listener_ip(right.ip());

    if left.is_ipv4() == right.is_ipv4() {
        return left == right || left.is_unspecified() || right.is_unspecified();
    }

    // An unspecified IPv6 bind commonly accepts IPv4 through dual-stack
    // sockets. Treat it conservatively unless the eventual platform adapter
    // can prove IPV6_V6ONLY is enabled.
    (left.is_ipv6() && left.is_unspecified()) || (right.is_ipv6() && right.is_unspecified())
}

fn normalized_listener_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn route_tables_overlap(left: Option<u32>, right: Option<u32>) -> bool {
    left == right || left.is_none() || right.is_none()
}

fn prefixes_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::model::{BackendId, ResourceClaim};

    fn id(value: &str) -> BackendId {
        BackendId::new(value).unwrap()
    }

    fn exclusive(owner: &str, resource: SystemResource) -> OwnedResourceClaim {
        OwnedResourceClaim::backend(id(owner), ResourceClaim::exclusive(resource))
    }

    fn coordinated(owner: &str, resource: SystemResource, key: &str) -> OwnedResourceClaim {
        OwnedResourceClaim::backend(
            id(owner),
            ResourceClaim {
                resource,
                mode: ClaimMode::CoordinatedShared {
                    coordination_key: key.to_owned(),
                },
            },
        )
    }

    fn prefix(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    #[test]
    fn singleton_claims_conflict_only_between_different_owners() {
        let first = exclusive("alpha", SystemResource::DnsManager);
        let duplicate = first.clone();
        assert!(detect_conflicts([first, duplicate]).is_empty());

        let conflicts = detect_conflicts([
            exclusive("alpha", SystemResource::DnsManager),
            exclusive("beta", SystemResource::DnsManager),
        ]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].kind,
            ResourceConflictKind::Singleton {
                resource: SingletonResource::DnsManager
            }
        );
    }

    #[test]
    fn interface_name_is_an_exact_host_resource() {
        let conflicts = detect_conflicts([
            exclusive(
                "alpha",
                SystemResource::Interface {
                    name: "mesh0".to_owned(),
                },
            ),
            exclusive(
                "beta",
                SystemResource::Interface {
                    name: "mesh0".to_owned(),
                },
            ),
            exclusive(
                "gamma",
                SystemResource::Interface {
                    name: "mesh1".to_owned(),
                },
            ),
        ]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].kind,
            ResourceConflictKind::Interface {
                name: "mesh0".to_owned()
            }
        );
    }

    #[test]
    fn interface_manager_conflicts_with_managers_and_every_exact_interface() {
        let conflicts = detect_conflicts([
            exclusive("manager-alpha", SystemResource::InterfaceManager),
            exclusive("manager-beta", SystemResource::InterfaceManager),
            exclusive(
                "exact-mesh0",
                SystemResource::Interface {
                    name: "mesh0".to_owned(),
                },
            ),
            exclusive(
                "exact-mesh1",
                SystemResource::Interface {
                    name: "mesh1".to_owned(),
                },
            ),
        ]);

        assert_eq!(conflicts.len(), 5);
        assert_eq!(
            conflicts
                .iter()
                .filter(|conflict| matches!(
                    conflict.kind,
                    ResourceConflictKind::Singleton {
                        resource: SingletonResource::InterfaceManager
                    }
                ))
                .count(),
            1
        );

        let mut managed_names = conflicts
            .iter()
            .filter_map(|conflict| match &conflict.kind {
                ResourceConflictKind::InterfaceManager { name } => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        managed_names.sort_unstable();
        assert_eq!(managed_names, ["mesh0", "mesh0", "mesh1", "mesh1"]);

        let public = conflicts
            .iter()
            .map(PublicResourceConflict::from)
            .collect::<Vec<_>>();
        assert!(public.iter().any(|conflict| matches!(
            conflict.kind,
            PublicResourceConflictKind::Singleton {
                resource: PublicSingletonResource::InterfaceManager
            }
        )));
        assert!(public.iter().any(|conflict| matches!(
            &conflict.kind,
            PublicResourceConflictKind::InterfaceManager { name } if name == "mesh0"
        )));
    }

    #[test]
    fn wildcard_listeners_overlap_concrete_and_dual_stack_addresses() {
        let listen = |owner: &str, transport: SocketTransport, address: &str| {
            exclusive(
                owner,
                SystemResource::ListenSocket {
                    transport,
                    address: address.parse().unwrap(),
                },
            )
        };

        let conflicts = detect_conflicts([
            listen("wildcard", SocketTransport::Tcp, "0.0.0.0:8080"),
            listen("loopback", SocketTransport::Tcp, "127.0.0.1:8080"),
            listen("other-ip", SocketTransport::Tcp, "192.0.2.1:8080"),
            listen("udp", SocketTransport::Udp, "0.0.0.0:8080"),
            listen("ipv6", SocketTransport::Tcp, "[::]:8080"),
        ]);

        assert_eq!(conflicts.len(), 5);
        assert!(conflicts.iter().all(|conflict| matches!(
            conflict.kind,
            ResourceConflictKind::ListenSocket {
                transport: SocketTransport::Tcp,
                ..
            }
        )));
    }

    #[test]
    fn ipv4_mapped_ipv6_listeners_share_the_ipv4_binding_namespace() {
        let address = |value: &str| value.parse::<SocketAddr>().unwrap();

        let mapped_loopback = address("[::ffff:127.0.0.1]:8080");
        let mapped_unspecified = address("[::ffff:0.0.0.0]:8080");

        assert!(listeners_overlap(
            mapped_loopback,
            address("127.0.0.1:8080")
        ));
        assert!(listeners_overlap(mapped_loopback, address("0.0.0.0:8080")));
        assert!(listeners_overlap(mapped_loopback, address("[::]:8080")));
        assert!(listeners_overlap(
            mapped_unspecified,
            address("192.0.2.1:8080")
        ));
        assert!(listeners_overlap(
            mapped_unspecified,
            address("[::ffff:192.0.2.1]:8080")
        ));

        assert!(!listeners_overlap(
            mapped_loopback,
            address("192.0.2.1:8080")
        ));
        assert!(!listeners_overlap(
            mapped_loopback,
            address("[2001:db8::1]:8080")
        ));
    }

    #[test]
    fn listener_overlap_preserves_port_transport_and_precise_ipv6_boundaries() {
        let address = |value: &str| value.parse::<SocketAddr>().unwrap();

        assert!(!listeners_overlap(
            address("[::ffff:127.0.0.1]:8080"),
            address("127.0.0.1:8081")
        ));
        assert!(listeners_overlap(
            address("[2001:db8::1]:8080"),
            address("[2001:db8::1]:8080")
        ));
        assert!(!listeners_overlap(
            address("[2001:db8::1]:8080"),
            address("[2001:db8::2]:8080")
        ));
        assert!(!listeners_overlap(
            address("[2001:db8::1]:8080"),
            address("0.0.0.0:8080")
        ));

        let conflicts = detect_conflicts([
            exclusive(
                "mapped-tcp",
                SystemResource::ListenSocket {
                    transport: SocketTransport::Tcp,
                    address: address("[::ffff:127.0.0.1]:8080"),
                },
            ),
            exclusive(
                "native-udp",
                SystemResource::ListenSocket {
                    transport: SocketTransport::Udp,
                    address: address("127.0.0.1:8080"),
                },
            ),
            exclusive(
                "native-other-port",
                SystemResource::ListenSocket {
                    transport: SocketTransport::Tcp,
                    address: address("127.0.0.1:8081"),
                },
            ),
        ]);

        assert!(conflicts.is_empty());
    }

    #[test]
    fn cloudflare_address_prefix_overlaps_tailscale_route_prefix() {
        let conflicts = detect_conflicts([
            exclusive(
                "cloudflare",
                SystemResource::AddressPrefix {
                    prefix: prefix("100.96.0.0/12"),
                },
            ),
            exclusive(
                "tailscale",
                SystemResource::RoutePrefix {
                    table: Some(52),
                    prefix: prefix("100.64.0.0/10"),
                },
            ),
        ]);

        assert_eq!(conflicts.len(), 1);
        assert!(matches!(
            conflicts[0].kind,
            ResourceConflictKind::AddressRoutePrefix { .. }
        ));
    }

    #[test]
    fn route_manager_conflicts_with_managed_route_resources() {
        let conflicts = detect_conflicts([
            exclusive("manager", SystemResource::RouteManager),
            exclusive("default", SystemResource::DefaultRouteV4),
            exclusive(
                "prefix",
                SystemResource::RoutePrefix {
                    table: Some(100),
                    prefix: prefix("10.0.0.0/8"),
                },
            ),
            exclusive("table", SystemResource::RouteTable { table: 254 }),
        ]);

        assert_eq!(conflicts.len(), 3);
        assert!(
            conflicts
                .iter()
                .all(|conflict| matches!(conflict.kind, ResourceConflictKind::RouteManager { .. }))
        );
    }

    #[test]
    fn default_routes_and_reserved_tables_conflict_with_equivalent_route_prefixes() {
        let conflicts = detect_conflicts([
            exclusive("default-v4", SystemResource::DefaultRouteV4),
            exclusive("default-v6", SystemResource::DefaultRouteV6),
            exclusive("table", SystemResource::RouteTable { table: 100 }),
            exclusive(
                "route-v4",
                SystemResource::RoutePrefix {
                    table: Some(100),
                    prefix: prefix("0.0.0.0/0"),
                },
            ),
            exclusive(
                "route-v6",
                SystemResource::RoutePrefix {
                    table: Some(200),
                    prefix: prefix("::/0"),
                },
            ),
        ]);

        assert_eq!(conflicts.len(), 3);
        assert_eq!(
            conflicts
                .iter()
                .filter(|conflict| matches!(
                    conflict.kind,
                    ResourceConflictKind::DefaultRoutePrefix { .. }
                ))
                .count(),
            2
        );
        assert!(conflicts.iter().any(|conflict| matches!(
            conflict.kind,
            ResourceConflictKind::RouteTablePrefix { table: 100, .. }
        )));
    }

    #[test]
    fn firewall_manager_conflicts_with_fwmark_unless_coordinated() {
        let range = FwmarkRange::new(0x100, 0x1ff).unwrap();
        assert_eq!(
            detect_conflicts([
                exclusive("manager", SystemResource::FirewallManager),
                exclusive("marker", SystemResource::FwmarkRange { range }),
            ])
            .len(),
            1
        );

        assert!(
            detect_conflicts([
                coordinated("manager", SystemResource::FirewallManager, "shared-fw"),
                coordinated("marker", SystemResource::FwmarkRange { range }, "shared-fw",),
            ])
            .is_empty()
        );
    }

    #[test]
    fn ipv6_prefixes_overlap_but_address_families_do_not() {
        let ipv6 = detect_conflicts([
            exclusive(
                "alpha",
                SystemResource::AddressPrefix {
                    prefix: prefix("fd00::/8"),
                },
            ),
            exclusive(
                "beta",
                SystemResource::AddressPrefix {
                    prefix: prefix("fd12:3456::/32"),
                },
            ),
        ]);
        assert_eq!(ipv6.len(), 1);

        let mixed = detect_conflicts([
            exclusive(
                "alpha",
                SystemResource::AddressPrefix {
                    prefix: prefix("0.0.0.0/0"),
                },
            ),
            exclusive(
                "beta",
                SystemResource::AddressPrefix {
                    prefix: prefix("::/0"),
                },
            ),
        ]);
        assert!(mixed.is_empty());
    }

    #[test]
    fn route_prefixes_require_overlapping_table_scopes() {
        let route = |owner: &str, table: Option<u32>, value: &str| {
            exclusive(
                owner,
                SystemResource::RoutePrefix {
                    table,
                    prefix: prefix(value),
                },
            )
        };

        assert!(
            detect_conflicts([
                route("alpha", Some(100), "10.0.0.0/8"),
                route("beta", Some(200), "10.1.0.0/16"),
            ])
            .is_empty()
        );
        assert_eq!(
            detect_conflicts([
                route("alpha", None, "10.0.0.0/8"),
                route("beta", Some(200), "10.1.0.0/16"),
            ])
            .len(),
            1
        );
    }

    #[test]
    fn route_table_and_fwmark_ranges_detect_exact_and_boundary_overlap() {
        assert_eq!(
            detect_conflicts([
                exclusive("alpha", SystemResource::RouteTable { table: 51820 }),
                exclusive("beta", SystemResource::RouteTable { table: 51820 }),
            ])
            .len(),
            1
        );

        let range = |owner: &str, start: u32, end: u32| {
            exclusive(
                owner,
                SystemResource::FwmarkRange {
                    range: FwmarkRange::new(start, end).unwrap(),
                },
            )
        };
        assert_eq!(
            detect_conflicts([
                range("alpha", 0x100, 0x1ff),
                range("beta", 0x1ff, 0x2ff),
                range("gamma", 0x300, 0x3ff),
            ])
            .len(),
            1
        );
    }

    #[test]
    fn only_matching_non_empty_coordination_keys_can_share() {
        assert!(
            detect_conflicts([
                coordinated("alpha", SystemResource::FirewallManager, "mesh-fw"),
                coordinated("beta", SystemResource::FirewallManager, " mesh-fw "),
            ])
            .is_empty()
        );

        let mismatched = detect_conflicts([
            coordinated("alpha", SystemResource::FirewallManager, "alpha-key"),
            coordinated("beta", SystemResource::FirewallManager, "beta-key"),
        ]);
        assert_eq!(
            mismatched[0].incompatibility,
            ClaimIncompatibility::CoordinationKeyMismatch
        );

        let missing = detect_conflicts([
            coordinated("alpha", SystemResource::FirewallManager, " "),
            coordinated("beta", SystemResource::FirewallManager, "mesh-fw"),
        ]);
        assert_eq!(
            missing[0].incompatibility,
            ClaimIncompatibility::MissingCoordinationKey
        );
    }

    #[test]
    fn coordination_key_mismatch_debug_is_redacted() {
        let left_secret = "left-secret-coordination-key";
        let right_secret = "right-secret-coordination-key";
        let conflicts = detect_conflicts([
            coordinated("alpha", SystemResource::FirewallManager, left_secret),
            coordinated("beta", SystemResource::FirewallManager, right_secret),
        ]);
        let incompatibility = &conflicts[0].incompatibility;

        let debug = format!("{incompatibility:?}");
        assert_eq!(debug, "CoordinationKeyMismatch");
        assert!(!debug.contains(left_secret));
        assert!(!debug.contains(right_secret));

        let serialized = serde_json::to_string(incompatibility).unwrap();
        assert!(!serialized.contains(left_secret));
        assert!(!serialized.contains(right_secret));
    }

    #[test]
    fn conflict_output_is_stably_sorted_and_input_order_independent() {
        let mut claims = vec![
            exclusive("zeta", SystemResource::DnsManager),
            exclusive("alpha", SystemResource::DnsManager),
            exclusive(
                "middle",
                SystemResource::ListenSocket {
                    transport: SocketTransport::Tcp,
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443),
                },
            ),
            exclusive(
                "beta",
                SystemResource::ListenSocket {
                    transport: SocketTransport::Tcp,
                    address: "127.0.0.1:443".parse().unwrap(),
                },
            ),
        ];

        let expected = detect_conflicts(&claims);
        claims.reverse();
        let actual = detect_conflicts(claims);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 2);
        assert!(actual.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            actual
                .iter()
                .all(|conflict| conflict.left.owner != conflict.right.owner)
        );
    }

    #[test]
    fn public_conflict_never_exposes_coordination_keys() {
        let conflict = detect_conflicts([
            coordinated(
                "alpha",
                SystemResource::FirewallManager,
                "alpha-coordination-secret",
            ),
            coordinated(
                "beta",
                SystemResource::FirewallManager,
                "beta-coordination-secret",
            ),
        ])
        .remove(0);

        let public = PublicResourceConflict::from(&conflict);
        assert_eq!(
            public.incompatibility,
            PublicClaimIncompatibility::CoordinationMismatch
        );
        let serialized = serde_json::to_string(&public).unwrap();
        assert!(!serialized.contains("alpha-coordination-secret"));
        assert!(!serialized.contains("beta-coordination-secret"));
        assert!(!serialized.contains("coordination_key"));
        assert!(serialized.contains("coordination_mismatch"));
    }
}
