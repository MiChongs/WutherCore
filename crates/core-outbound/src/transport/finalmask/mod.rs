//! Xray 26.7.11 final-mask composition.
//!
//! TCP masks are wrapped in reverse declaration order, exactly like
//! `slices.Backward` in upstream. UDP has a separate compiled plan because
//! packet headers must reserve their aggregate prefix once; applying each
//! header as an ordinary nested socket corrupts offsets.

use std::net::SocketAddr;

use core_config::{TcpMaskConfig, UdpMaskConfig};

use crate::adapter::{BoxedStream, BoxedUdp};

mod fragment;
mod header_custom;
mod mkcp;
pub mod quic;
mod quic_socket;
mod realm;
mod salamander;
mod sudoku;
mod udp;
mod udp_hop;
mod xdns;
#[cfg_attr(target_os = "linux", allow(unsafe_code))]
mod xicmp;
mod xmc;

pub async fn wrap_tcp_client(
    mut stream: BoxedStream,
    masks: &[TcpMaskConfig],
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    remote_host: &str,
    remote_port: u16,
) -> std::io::Result<BoxedStream> {
    for mask in masks.iter().rev() {
        stream = match mask {
            TcpMaskConfig::HeaderCustom(config) => {
                header_custom::wrap_client(stream, config, local, remote, remote_host, remote_port)
                    .await?
            }
            TcpMaskConfig::Fragment(config) => {
                fragment::FragmentStream::wrap(stream, config.clone())
            }
            TcpMaskConfig::Sudoku(config) => sudoku::wrap(stream, config)?,
            TcpMaskConfig::Xmc(config) => {
                xmc::wrap_client(stream, config, remote, remote_host, remote_port).await?
            }
        };
    }
    Ok(stream)
}

pub async fn wrap_tcp_server(
    mut stream: BoxedStream,
    masks: &[TcpMaskConfig],
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedStream> {
    for mask in masks.iter().rev() {
        stream = match mask {
            TcpMaskConfig::HeaderCustom(config) => {
                header_custom::wrap_server(stream, config, local, remote).await?
            }
            // Fragment is symmetric at the byte level. The upstream server
            // wrapper retains it (and disables splice) even though servers
            // normally only read first; keeping it here also handles server
            // initiated writes exactly.
            TcpMaskConfig::Fragment(config) => {
                fragment::FragmentStream::wrap(stream, config.clone())
            }
            TcpMaskConfig::Sudoku(config) => sudoku::wrap_server(stream, config)?,
            TcpMaskConfig::Xmc(config) => xmc::wrap_server(stream, config).await?,
        };
    }
    Ok(stream)
}

pub async fn wrap_udp_client(
    mut socket: BoxedUdp,
    masks: &[UdpMaskConfig],
    target: String,
    port: u16,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedUdp> {
    validate_udp_order(masks)?;
    // Build the same wrapper nesting as Xray's reverse manager. Carrier masks
    // such as xdns change the destination address, so they cannot be compiled
    // into a payload-only plan with their neighbours.
    for mask in masks.iter().rev() {
        socket = match mask {
            UdpMaskConfig::Xdns(config) => xdns::wrap_client(socket, config)?,
            UdpMaskConfig::Xicmp(config) => xicmp::wrap_client(socket, config, remote)?,
            UdpMaskConfig::Realm(config) => realm::wrap_client(socket, config, remote).await?,
            ordinary => udp::wrap_client(
                socket,
                std::slice::from_ref(ordinary),
                target.clone(),
                port,
                local,
                remote,
            )?,
        };
    }
    Ok(socket)
}

pub async fn wrap_udp_server(
    mut socket: BoxedUdp,
    masks: &[UdpMaskConfig],
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedUdp> {
    validate_udp_order(masks)?;
    for mask in masks.iter().rev() {
        socket = match mask {
            UdpMaskConfig::Xdns(config) => xdns::wrap_server(socket, config)?,
            UdpMaskConfig::Xicmp(config) => xicmp::wrap_server(socket, config)?,
            UdpMaskConfig::Realm(config) => realm::wrap_server(socket, config).await?,
            ordinary => udp::wrap_server(socket, std::slice::from_ref(ordinary), local, remote)?,
        };
    }
    Ok(socket)
}

/// Open the real UDP packet carrier for a protocol such as Shadowsocks and
/// apply the node's FinalMask policy below that protocol's own framing.  This
/// is deliberately not an `OutboundAdapter::dial_udp` decorator: decorating
/// there would mask application payloads before protocol encryption and would
/// double-wrap QUIC transports that already execute FinalMask internally.
pub(crate) async fn open_policy_udp_client_carrier(
    target_host: String,
    peer: SocketAddr,
) -> std::io::Result<(BoxedUdp, SocketAddr)> {
    let policy = crate::socket_policy::current();
    let nominal_local: SocketAddr = if peer.is_ipv6() {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    };
    let (raw, local) = if let Some(proxy) = policy.as_ref().and_then(|policy| policy.proxy()) {
        let raw =
            crate::socket_policy::dial_udp_through_proxy(proxy, target_host.clone(), peer.port())
                .await?;
        let local = raw.local_addr()?.unwrap_or(nominal_local);
        (raw, local)
    } else {
        open_direct_carrier(target_host.clone(), peer)?
    };
    let masks = policy
        .as_ref()
        .and_then(|policy| policy.settings.finalmask.as_ref())
        .map(|finalmask| finalmask.udp.as_slice())
        .unwrap_or_default();
    if masks.is_empty() {
        return Ok((raw, local));
    }
    let masked = wrap_udp_client(
        raw,
        masks,
        target_host,
        peer.port(),
        Some(local),
        Some(peer),
    )
    .await?;
    Ok((masked, local))
}

fn validate_udp_order(masks: &[UdpMaskConfig]) -> std::io::Result<()> {
    for (index, mask) in masks.iter().enumerate() {
        if matches!(mask, UdpMaskConfig::Realm(_) | UdpMaskConfig::Xicmp(_))
            && index + 1 != masks.len()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} must be the last declared UDP finalmask (Xray outermost level 0)",
                    udp_kind(mask)
                ),
            ));
        }
        if matches!(mask, UdpMaskConfig::Sudoku(_)) && index != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sudoku must be the first declared UDP finalmask (Xray innermost level)",
            ));
        }
    }
    Ok(())
}

pub(crate) use quic_socket::open_direct_carrier;
pub use quic_socket::{QuinnUdpSocket, inbound_udp_carrier};
pub(crate) use udp_hop::UdpHopCarrier;

/// A packet-level execution plan. Header stages contain source indexes in the
/// exact inner-to-outer evaluation order expected by Xray's header manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpPlanStage {
    HeaderAggregate(Vec<usize>),
    Transform { index: usize, kind: &'static str },
}

pub(crate) fn compile_udp_plan(masks: &[UdpMaskConfig]) -> Vec<UdpPlanStage> {
    let mut stages = Vec::new();
    let mut headers = Vec::new();
    let flush = |headers: &mut Vec<usize>, stages: &mut Vec<UdpPlanStage>| {
        if !headers.is_empty() {
            stages.push(UdpPlanStage::HeaderAggregate(std::mem::take(headers)));
        }
    };
    for (index, mask) in masks.iter().enumerate().rev() {
        if is_aggregate_header(mask) {
            headers.push(index);
            continue;
        }
        flush(&mut headers, &mut stages);
        stages.push(UdpPlanStage::Transform {
            index,
            kind: udp_kind(mask),
        });
    }
    flush(&mut headers, &mut stages);
    stages
}

fn is_aggregate_header(mask: &UdpMaskConfig) -> bool {
    matches!(
        mask,
        UdpMaskConfig::MkcpLegacy(_) | UdpMaskConfig::Salamander(_)
    )
}

fn udp_kind(mask: &UdpMaskConfig) -> &'static str {
    match mask {
        UdpMaskConfig::HeaderCustom(_) => "header-custom",
        UdpMaskConfig::MkcpLegacy(_) => "mkcp-legacy",
        UdpMaskConfig::Noise(_) => "noise",
        UdpMaskConfig::Salamander(_) => "salamander",
        UdpMaskConfig::Sudoku(_) => "sudoku",
        UdpMaskConfig::Xdns(_) => "xdns",
        UdpMaskConfig::Xicmp(_) => "xicmp",
        UdpMaskConfig::Realm(_) => "realm",
    }
}

#[cfg(test)]
mod tests {
    use core_config::{
        MkcpLegacyMaskConfig, NoiseMaskConfig, RealmMaskConfig, SalamanderMaskConfig,
        SudokuMaskConfig, XicmpMaskConfig,
    };

    use super::*;

    #[test]
    fn tcp_declarations_are_applied_in_reverse_order() {
        let masks = vec![
            TcpMaskConfig::Fragment(Default::default()),
            TcpMaskConfig::Sudoku(SudokuMaskConfig {
                password: "p".into(),
                ..Default::default()
            }),
        ];
        let order = masks
            .iter()
            .rev()
            .map(|mask| match mask {
                TcpMaskConfig::Fragment(_) => "fragment",
                TcpMaskConfig::Sudoku(_) => "sudoku",
                TcpMaskConfig::HeaderCustom(_) => "header",
                TcpMaskConfig::Xmc(_) => "xmc",
            })
            .collect::<Vec<_>>();
        assert_eq!(order, ["sudoku", "fragment"]);
    }

    #[test]
    fn consecutive_udp_headers_are_aggregated_without_crossing_transforms() {
        let masks = vec![
            UdpMaskConfig::Noise(NoiseMaskConfig::default()),
            UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default()),
            UdpMaskConfig::Salamander(SalamanderMaskConfig::default()),
            UdpMaskConfig::Sudoku(SudokuMaskConfig::default()),
            UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default()),
        ];
        assert_eq!(
            compile_udp_plan(&masks),
            vec![
                UdpPlanStage::HeaderAggregate(vec![4]),
                UdpPlanStage::Transform {
                    index: 3,
                    kind: "sudoku"
                },
                UdpPlanStage::HeaderAggregate(vec![2, 1]),
                UdpPlanStage::Transform {
                    index: 0,
                    kind: "noise"
                },
            ]
        );
    }

    #[test]
    fn udp_carrier_and_sudoku_ordering_matches_xray_levels() {
        let valid = vec![
            UdpMaskConfig::Sudoku(SudokuMaskConfig::default()),
            UdpMaskConfig::Noise(NoiseMaskConfig::default()),
            UdpMaskConfig::Realm(RealmMaskConfig::default()),
        ];
        validate_udp_order(&valid).unwrap();

        let realm_not_outermost = vec![
            UdpMaskConfig::Realm(RealmMaskConfig::default()),
            UdpMaskConfig::Noise(NoiseMaskConfig::default()),
        ];
        assert!(validate_udp_order(&realm_not_outermost).is_err());

        let xicmp_not_outermost = vec![
            UdpMaskConfig::Xicmp(XicmpMaskConfig::default()),
            UdpMaskConfig::MkcpLegacy(MkcpLegacyMaskConfig::default()),
        ];
        assert!(validate_udp_order(&xicmp_not_outermost).is_err());

        let sudoku_not_innermost = vec![
            UdpMaskConfig::Noise(NoiseMaskConfig::default()),
            UdpMaskConfig::Sudoku(SudokuMaskConfig::default()),
        ];
        assert!(validate_udp_order(&sudoku_not_innermost).is_err());
    }
}
