use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use core_config::{AddressPortStrategy, DomainStrategy, HappyEyeballsConfig, OutboundSocketConfig};
use hickory_resolver::TokioAsyncResolver;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    adapter::{
        BoxedStream, apply_outbound_mark_for_addr, protect_socket, resolve_host,
        resolve_host_for_direct,
    },
    loopback::{LoopbackTcpGuard, TrackedTcpStream, register_tcp},
    socket_policy,
    transport::Transport,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpTransport {
    /// DIRECT resolves through the direct-nameserver group.
    for_direct: bool,
}

impl TcpTransport {
    pub fn for_direct() -> Self {
        Self { for_direct: true }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        connect_boxed(host, port, self.for_direct).await
    }
}

/// Unified raw carrier dial. TLS and every plain-TCP protocol use this so
/// final masks can be inserted before TLS rather than after it.
pub(crate) async fn connect_boxed(
    host: &str,
    port: u16,
    for_direct: bool,
) -> std::io::Result<BoxedStream> {
    let started = Instant::now();
    let policy = socket_policy::current();
    let socket_cfg = policy.as_ref().and_then(|p| p.socket()).cloned();
    let (host, port) = rewrite_address_port(host, port, socket_cfg.as_ref()).await;

    if let Some(cfg) = socket_cfg.as_ref()
        && !cfg.dialer_proxy.trim().is_empty()
    {
        let proxy = policy.as_ref().and_then(|p| p.proxy()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "streamSettings.sockopt.dialerProxy `{}` 未注册",
                    cfg.dialer_proxy
                ),
            )
        })?;
        let (proxy_host, proxy_port) =
            resolve_one_for_strategy(&host, port, for_direct, cfg).await?;
        let stream =
            socket_policy::dial_through_proxy(proxy, proxy_host.clone(), proxy_port).await?;
        return apply_final_masks(
            stream,
            policy.as_deref(),
            None,
            None,
            &proxy_host,
            proxy_port,
        )
        .await;
    }

    let mut addrs = resolve_candidates(&host, port, for_direct, socket_cfg.as_ref()).await?;
    let racing = socket_cfg.as_ref().is_some_and(|cfg| {
        addrs.len() >= 2
            && cfg.happy_eyeballs.try_delay_ms > 0
            && cfg.happy_eyeballs.max_concurrent_try > 0
    });
    if !racing
        && socket_cfg
            .as_ref()
            .is_some_and(|cfg| cfg.domain_strategy.use_ip())
        && host.parse::<IpAddr>().is_err()
    {
        let selected = rand::thread_rng().gen_range(0..addrs.len());
        addrs = vec![addrs[selected]];
    }
    let stream = if let Some(cfg) = socket_cfg.as_ref()
        && addrs.len() >= 2
        && cfg.happy_eyeballs.try_delay_ms > 0
        && cfg.happy_eyeballs.max_concurrent_try > 0
    {
        race_connect(addrs, cfg.clone()).await?
    } else {
        sequential_connect(&host, port, &addrs, socket_cfg.clone(), started).await?
    };
    let local = stream.local_addr().ok();
    let remote = stream.peer_addr().ok();
    let _ = stream.set_nodelay(true);
    apply_final_masks(
        Box::pin(stream),
        policy.as_deref(),
        local,
        remote,
        &host,
        port,
    )
    .await
}

async fn resolve_one_for_strategy(
    host: &str,
    port: u16,
    for_direct: bool,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<(String, u16)> {
    if !cfg.domain_strategy.use_ip() || host.parse::<IpAddr>().is_ok() {
        return Ok((host.to_string(), port));
    }
    let addrs = resolve_candidates(host, port, for_direct, Some(cfg)).await?;
    let selected = rand::thread_rng().gen_range(0..addrs.len());
    let selected = addrs[selected];
    Ok((selected.ip().to_string(), selected.port()))
}

async fn apply_final_masks(
    stream: BoxedStream,
    policy: Option<&socket_policy::ActiveStreamPolicy>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    host: &str,
    port: u16,
) -> std::io::Result<BoxedStream> {
    let Some(finalmask) = policy.and_then(|p| p.settings.finalmask.as_ref()) else {
        return Ok(stream);
    };
    crate::transport::finalmask::wrap_tcp_client(stream, &finalmask.tcp, local, remote, host, port)
        .await
}

async fn sequential_connect(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    cfg: Option<OutboundSocketConfig>,
    started: Instant,
) -> std::io::Result<TrackedTcpStream<TcpStream>> {
    let mut last_err = None;
    for (index, addr) in addrs.iter().copied().enumerate() {
        let attempt_started = Instant::now();
        match marked_connect_with_config(addr, Duration::from_secs(10), cfg.clone()).await {
            Ok(stream) => {
                info!(
                    target: "dial::tcp",
                    %host,
                    port,
                    peer = %addr,
                    attempt = index + 1,
                    connect_ms = attempt_started.elapsed().as_millis() as u64,
                    total_ms = started.elapsed().as_millis() as u64,
                    "connected",
                );
                return Ok(stream);
            }
            Err(error) => {
                debug!(
                    target: "dial::tcp",
                    %host,
                    port,
                    peer = %addr,
                    attempt = index + 1,
                    %error,
                    "connect attempt failed",
                );
                last_err = Some(error);
            }
        }
    }
    warn!(target: "dial::tcp", %host, port, tried = addrs.len(), "all candidates failed");
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("connect: no usable address for {host}:{port}"),
        )
    }))
}

async fn resolve_candidates(
    host: &str,
    port: u16,
    for_direct: bool,
    cfg: Option<&OutboundSocketConfig>,
) -> std::io::Result<Vec<SocketAddr>> {
    let strategy = cfg.map(|c| c.domain_strategy).unwrap_or_default();
    let primary = if for_direct {
        resolve_host_for_direct(host, port).await
    } else {
        resolve_host(host, port).await
    };
    let mut addrs = match primary {
        Ok(addrs) => addrs,
        Err(primary_error) if strategy.use_ip() && !strategy.force() => {
            tokio::net::lookup_host((host, port))
                .await
                .map(|iter| iter.collect())
                .map_err(|fallback_error| {
                    std::io::Error::new(
                        fallback_error.kind(),
                        format!(
                            "domainStrategy lookup failed ({primary_error}); system fallback failed: {fallback_error}"
                        ),
                    )
                })?
        }
        Err(error) => return Err(error),
    };

    if strategy.use_ip() {
        addrs.retain(|addr| match addr.ip() {
            IpAddr::V4(_) => strategy.allow_ipv4(),
            IpAddr::V6(_) => strategy.allow_ipv6(),
        });
        if strategy.prefer_ipv6() {
            addrs.sort_by_key(|addr| usize::from(addr.is_ipv4()));
        } else if matches!(
            strategy,
            DomainStrategy::UseIpv4v6 | DomainStrategy::ForceIpv4v6
        ) {
            addrs.sort_by_key(|addr| usize::from(addr.is_ipv6()));
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("domainStrategy {strategy:?} returned no usable address for {host}"),
        ));
    }
    Ok(addrs)
}

async fn rewrite_address_port(
    host: &str,
    port: u16,
    cfg: Option<&OutboundSocketConfig>,
) -> (String, u16) {
    let Some(cfg) = cfg else {
        return (host.to_string(), port);
    };
    let strategy = cfg.address_port_strategy;
    if strategy == AddressPortStrategy::None || host.parse::<IpAddr>().is_ok() {
        return (host.to_string(), port);
    }
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(resolver) => resolver,
        Err(error) => {
            warn!(%error, "addressPortStrategy resolver initialization failed; keeping original target");
            return (host.to_string(), port);
        }
    };
    let result = match strategy {
        AddressPortStrategy::SrvPortOnly
        | AddressPortStrategy::SrvAddressOnly
        | AddressPortStrategy::SrvPortAndAddress => {
            let lookup = resolver.srv_lookup(host).await;
            lookup.map(|records| {
                records.iter().next().map(|record| {
                    (
                        record.target().to_utf8().trim_end_matches('.').to_string(),
                        record.port(),
                    )
                })
            })
        }
        AddressPortStrategy::TxtPortOnly
        | AddressPortStrategy::TxtAddressOnly
        | AddressPortStrategy::TxtPortAndAddress => {
            resolver.txt_lookup(host).await.map(|records| {
                records.iter().find_map(|record| {
                    let value = record
                        .txt_data()
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .collect::<Vec<_>>();
                    parse_txt_target(&String::from_utf8_lossy(&value))
                })
            })
        }
        AddressPortStrategy::None => unreachable!(),
    };
    let replacement = match result {
        Ok(Some(value)) => value,
        Ok(None) => return (host.to_string(), port),
        Err(error) => {
            // Xray deliberately falls back to the original destination when
            // the optional override lookup fails.
            warn!(%host, ?strategy, %error, "addressPortStrategy lookup failed; keeping original target");
            return (host.to_string(), port);
        }
    };
    let replace_address = matches!(
        strategy,
        AddressPortStrategy::SrvAddressOnly
            | AddressPortStrategy::SrvPortAndAddress
            | AddressPortStrategy::TxtAddressOnly
            | AddressPortStrategy::TxtPortAndAddress
    );
    let replace_port = matches!(
        strategy,
        AddressPortStrategy::SrvPortOnly
            | AddressPortStrategy::SrvPortAndAddress
            | AddressPortStrategy::TxtPortOnly
            | AddressPortStrategy::TxtPortAndAddress
    );
    (
        if replace_address {
            replacement.0
        } else {
            host.to_string()
        },
        if replace_port { replacement.1 } else { port },
    )
}

fn parse_txt_target(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    (!host.is_empty()).then(|| (host.to_string(), port))
}

fn interleave_addresses(
    addrs: Vec<SocketAddr>,
    prioritize_ipv6: bool,
    interleave: u32,
) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    if v4.is_empty() || v6.is_empty() {
        return v4.into_iter().chain(v6).collect();
    }
    let (mut first, mut second) = if prioritize_ipv6 {
        (VecDeque::from(v6), VecDeque::from(v4))
    } else {
        (VecDeque::from(v4), VecDeque::from(v6))
    };
    if interleave == 0 {
        return first.into_iter().chain(second).collect();
    }
    let mut out = Vec::with_capacity(first.len() + second.len());
    let take = interleave.max(1) as usize;
    while !first.is_empty() && !second.is_empty() {
        for _ in 0..take {
            if let Some(addr) = first.pop_front() {
                out.push(addr);
            }
        }
        std::mem::swap(&mut first, &mut second);
    }
    out.extend(first);
    out.extend(second);
    out
}

async fn race_connect(
    addrs: Vec<SocketAddr>,
    cfg: OutboundSocketConfig,
) -> std::io::Result<TrackedTcpStream<TcpStream>> {
    let HappyEyeballsConfig {
        prioritize_ipv6,
        interleave,
        try_delay_ms,
        max_concurrent_try,
    } = cfg.happy_eyeballs.clone();
    let mut pending = VecDeque::from(interleave_addresses(addrs, prioritize_ipv6, interleave));
    let max_active = max_concurrent_try.max(1) as usize;
    let delay = Duration::from_millis(try_delay_ms);
    let mut tasks = JoinSet::new();
    let mut last_error = None;
    let mut launch_at = tokio::time::Instant::now();

    loop {
        while tasks.len() < max_active && launch_at <= tokio::time::Instant::now() {
            let Some(addr) = pending.pop_front() else {
                break;
            };
            let task_cfg = cfg.clone();
            tasks.spawn(async move {
                (
                    addr,
                    marked_connect_with_config(addr, Duration::from_secs(10), Some(task_cfg)).await,
                )
            });
            launch_at = tokio::time::Instant::now() + delay;
            if delay != Duration::ZERO {
                break;
            }
        }

        if tasks.is_empty() {
            if pending.is_empty() {
                break;
            }
            tokio::time::sleep_until(launch_at).await;
            continue;
        }

        if pending.is_empty() || tasks.len() >= max_active {
            match tasks.join_next().await {
                Some(Ok((_addr, Ok(stream)))) => {
                    tasks.abort_all();
                    return Ok(stream);
                }
                Some(Ok((_addr, Err(error)))) => {
                    last_error = Some(error);
                    launch_at = tokio::time::Instant::now();
                }
                Some(Err(error)) => {
                    last_error = Some(std::io::Error::other(format!(
                        "Happy Eyeballs task: {error}"
                    )));
                }
                None => break,
            }
        } else {
            tokio::select! {
                joined = tasks.join_next() => match joined {
                    Some(Ok((_addr, Ok(stream)))) => {
                        tasks.abort_all();
                        return Ok(stream);
                    }
                    Some(Ok((_addr, Err(error)))) => {
                        last_error = Some(error);
                        launch_at = tokio::time::Instant::now();
                    }
                    Some(Err(error)) => {
                        last_error = Some(std::io::Error::other(format!("Happy Eyeballs task: {error}")));
                    }
                    None => break,
                },
                _ = tokio::time::sleep_until(launch_at) => {}
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Happy Eyeballs exhausted all candidates",
        )
    }))
}

/// Backwards-compatible direct socket entry used by a few transport tests.
pub async fn marked_connect(
    addr: SocketAddr,
    timeout: Duration,
) -> std::io::Result<TrackedTcpStream<TcpStream>> {
    let cfg = socket_policy::current().and_then(|p| p.socket().cloned());
    marked_connect_with_config(addr, timeout, cfg).await
}

/// Apply the same route protection and node-scoped socket policy as
/// [`marked_connect`], but return the concrete Tokio stream plus its loopback
/// guard for REALITY engines that need ownership of the raw TCP type.
pub async fn marked_connect_raw(
    addr: SocketAddr,
    timeout: Duration,
) -> std::io::Result<(TcpStream, LoopbackTcpGuard)> {
    let cfg = socket_policy::current().and_then(|p| p.socket().cloned());
    marked_connect_raw_with_config(addr, timeout, cfg).await
}

/// Create and bind an inbound TCP listener with Xray-compatible `sockopt`
/// semantics.  The options must be installed before `bind(2)`/`listen(2)` so
/// TProxy, v6-only, TFO and custom socket options affect the listening socket
/// and are inherited by accepted connections where the platform supports it.
pub fn bind_inbound_listener(
    addr: SocketAddr,
    cfg: Option<&OutboundSocketConfig>,
) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let protocol = if cfg.is_some_and(|config| config.tcp_mptcp) {
        Protocol::from(262)
    } else {
        Protocol::TCP
    };
    let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;
    // Xray's Windows setReuseAddr implementation is deliberately a no-op.
    // Enabling SO_REUSEADDR there changes an occupied-port bind from
    // WSAEADDRINUSE into WSAEACCES and bypasses the listener fallback path.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if let Some(cfg) = cfg {
        apply_inbound_socket_config(&socket, addr, cfg)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Create an inbound UDP socket with the listener-relevant subset of Xray's
/// `sockopt`.  This is used by QUIC/H3 before a FinalMask packet carrier is
/// installed, matching `ListenSystemPacket` in Xray-core.
pub fn bind_inbound_udp_socket(
    addr: SocketAddr,
    cfg: Option<&OutboundSocketConfig>,
) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    if let Some(cfg) = cfg {
        if let Some(mode) = cfg.tproxy.as_deref()
            && !matches!(
                mode.trim().to_ascii_lowercase().as_str(),
                "" | "off" | "tproxy" | "redirect"
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown streamSettings.sockopt.tproxy mode `{mode}`"),
            ));
        }
        apply_node_mark(&socket, cfg.mark)?;
        if !cfg.interface.is_empty() {
            bind_named_interface(&socket, addr, &cfg.interface)?;
        }
        if addr.is_ipv6() {
            socket.set_only_v6(cfg.v6only)?;
        } else if cfg.v6only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "streamSettings.sockopt.v6only requires an IPv6 listen address",
            ));
        }
        apply_inbound_tproxy(&socket, addr, cfg.tproxy.as_deref())?;
        apply_custom_sockopts(&socket, if addr.is_ipv4() { "udp4" } else { "udp6" }, cfg)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn apply_inbound_socket_config(
    socket: &Socket,
    addr: SocketAddr,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if let Some(mode) = cfg.tproxy.as_deref()
        && !matches!(
            mode.trim().to_ascii_lowercase().as_str(),
            "" | "off" | "tproxy" | "redirect"
        )
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown streamSettings.sockopt.tproxy mode `{mode}`"),
        ));
    }
    if cfg
        .tcp_keep_alive_idle
        .saturating_mul(cfg.tcp_keep_alive_interval)
        < 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tcpKeepAliveIdle and tcpKeepAliveInterval must not have opposite signs",
        ));
    }
    if cfg.tcp_keep_alive_idle < 0 || cfg.tcp_keep_alive_interval < 0 {
        socket.set_keepalive(false)?;
    } else if cfg.tcp_keep_alive_idle > 0 || cfg.tcp_keep_alive_interval > 0 {
        socket.set_keepalive(true)?;
        let keepalive = TcpKeepalive::new();
        let keepalive = if cfg.tcp_keep_alive_idle > 0 {
            keepalive.with_time(Duration::from_secs(cfg.tcp_keep_alive_idle as u64))
        } else {
            keepalive
        };
        let keepalive = if cfg.tcp_keep_alive_interval > 0 {
            keepalive.with_interval(Duration::from_secs(cfg.tcp_keep_alive_interval as u64))
        } else {
            keepalive
        };
        socket.set_tcp_keepalive(&keepalive)?;
    }

    apply_node_mark(socket, cfg.mark)?;
    if !cfg.interface.is_empty() {
        bind_named_interface(socket, addr, &cfg.interface)?;
    }
    if addr.is_ipv6() {
        socket.set_only_v6(cfg.v6only)?;
    } else if cfg.v6only {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "streamSettings.sockopt.v6only requires an IPv6 listen address",
        ));
    }
    apply_inbound_tcp_platform_options(socket, cfg)?;
    apply_inbound_tproxy(socket, addr, cfg.tproxy.as_deref())?;
    apply_custom_sockopts(socket, if addr.is_ipv4() { "tcp4" } else { "tcp6" }, cfg)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_inbound_tcp_platform_options(
    socket: &Socket,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if cfg.tcp_fast_open.is_some() && cfg.tfo_value() != 0 {
        raw_setsockopt_int(
            socket,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            cfg.tfo_value().max(0),
        )?;
    }
    if !cfg.tcp_congestion.is_empty() {
        socket.set_tcp_congestion(cfg.tcp_congestion.as_bytes())?;
    }
    if cfg.tcp_window_clamp > 0 {
        raw_setsockopt_int(
            socket,
            libc::IPPROTO_TCP,
            libc::TCP_WINDOW_CLAMP,
            cfg.tcp_window_clamp,
        )?;
    }
    if cfg.tcp_user_timeout > 0 {
        socket.set_tcp_user_timeout(Some(Duration::from_millis(cfg.tcp_user_timeout as u64)))?;
    }
    if cfg.tcp_max_seg > 0 {
        raw_setsockopt_int(socket, libc::IPPROTO_TCP, libc::TCP_MAXSEG, cfg.tcp_max_seg)?;
    }
    Ok(())
}

#[cfg(windows)]
fn apply_inbound_tcp_platform_options(
    socket: &Socket,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if cfg.tcp_fast_open.is_some() && cfg.tfo_value() != 0 {
        raw_setsockopt_int(socket, 6, 15, i32::from(cfg.tfo_value() > 0))?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apply_inbound_tcp_platform_options(
    socket: &Socket,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if cfg.tcp_fast_open.is_some() && cfg.tfo_value() != 0 {
        // Darwin TCP_FASTOPEN with the server flag (1).
        raw_setsockopt_int(
            socket,
            libc::IPPROTO_TCP,
            0x105,
            i32::from(cfg.tfo_value() > 0),
        )?;
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn apply_inbound_tcp_platform_options(
    socket: &Socket,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if cfg.tcp_fast_open.is_some() && cfg.tfo_value() != 0 {
        raw_setsockopt_int(socket, libc::IPPROTO_TCP, 1025, cfg.tfo_value().max(0))?;
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
)))]
fn apply_inbound_tcp_platform_options(
    _socket: &Socket,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    if cfg.tcp_fast_open.is_some() && cfg.tfo_value() != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "tcpFastOpen is unsupported on this platform",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_inbound_tproxy(
    socket: &Socket,
    _addr: SocketAddr,
    mode: Option<&str>,
) -> std::io::Result<()> {
    if mode.is_some_and(|mode| matches!(mode.to_ascii_lowercase().as_str(), "tproxy" | "redirect"))
    {
        raw_setsockopt_int(socket, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn apply_inbound_tproxy(
    socket: &Socket,
    addr: SocketAddr,
    mode: Option<&str>,
) -> std::io::Result<()> {
    if mode.is_some_and(|mode| matches!(mode.to_ascii_lowercase().as_str(), "tproxy" | "redirect"))
    {
        // Xray first tries IPV6_BINDANY, then IP_BINDANY.  Select the option
        // from the actual socket family to avoid relying on a failed probe.
        if addr.is_ipv6() {
            raw_setsockopt_int(socket, libc::IPPROTO_IPV6, libc::IPV6_BINDANY, 1)?;
        } else {
            raw_setsockopt_int(socket, libc::IPPROTO_IP, libc::IP_BINDANY, 1)?;
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn apply_inbound_tproxy(
    _socket: &Socket,
    _addr: SocketAddr,
    mode: Option<&str>,
) -> std::io::Result<()> {
    if mode.is_some_and(|mode| matches!(mode.to_ascii_lowercase().as_str(), "tproxy" | "redirect"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "streamSettings.sockopt.tproxy is unsupported on this platform",
        ));
    }
    Ok(())
}

async fn marked_connect_with_config(
    addr: SocketAddr,
    timeout: Duration,
    cfg: Option<OutboundSocketConfig>,
) -> std::io::Result<TrackedTcpStream<TcpStream>> {
    let (stream, guard) = marked_connect_raw_with_config(addr, timeout, cfg).await?;
    Ok(TrackedTcpStream::with_guard(stream, guard))
}

async fn marked_connect_raw_with_config(
    addr: SocketAddr,
    timeout: Duration,
    cfg: Option<OutboundSocketConfig>,
) -> std::io::Result<(TcpStream, LoopbackTcpGuard)> {
    let std_stream = tokio::task::spawn_blocking(move || {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let protocol = if cfg.as_ref().is_some_and(|c| c.tcp_mptcp) {
            Protocol::from(262)
        } else {
            Protocol::TCP
        };
        let sock = Socket::new(domain, Type::STREAM, Some(protocol))?;
        protect_socket(&sock)?;
        apply_outbound_mark_for_addr(&sock, addr)?;
        crate::adapter::bind_outbound_socket(&sock, addr)?;
        if let Some(cfg) = cfg.as_ref() {
            apply_socket_config(&sock, addr, cfg)?;
        }
        sock.connect_timeout(&addr.into(), timeout)?;
        sock.set_nonblocking(true)?;
        Ok::<std::net::TcpStream, std::io::Error>(sock.into())
    })
    .await
    .map_err(|error| std::io::Error::other(format!("spawn_blocking: {error}")))??;
    let stream = TcpStream::from_std(std_stream)?;
    let local = stream.local_addr()?;
    Ok((stream, register_tcp(local)))
}

fn apply_socket_config(
    sock: &Socket,
    peer: SocketAddr,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    // Chrome defaults used by Xray's net.Dialer.
    if cfg.tcp_keep_alive_idle < 0 || cfg.tcp_keep_alive_interval < 0 {
        sock.set_keepalive(false)?;
    } else {
        let idle = if cfg.tcp_keep_alive_idle > 0 {
            cfg.tcp_keep_alive_idle as u64
        } else {
            45
        };
        let interval = if cfg.tcp_keep_alive_interval > 0 {
            cfg.tcp_keep_alive_interval as u64
        } else {
            45
        };
        sock.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(idle))
                .with_interval(Duration::from_secs(interval)),
        )?;
    }

    apply_node_mark(sock, cfg.mark)?;
    if !cfg.interface.is_empty() {
        bind_named_interface(sock, peer, &cfg.interface)?;
    }
    apply_tcp_platform_options(sock, cfg)?;
    apply_custom_sockopts(sock, if peer.is_ipv4() { "tcp4" } else { "tcp6" }, cfg)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_node_mark(sock: &Socket, mark: i32) -> std::io::Result<()> {
    if mark != 0 {
        raw_setsockopt_int(sock, libc::SOL_SOCKET, libc::SO_MARK, mark)?;
    }
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn apply_node_mark(sock: &Socket, mark: i32) -> std::io::Result<()> {
    if mark != 0 {
        raw_setsockopt_int(sock, libc::SOL_SOCKET, libc::SO_USER_COOKIE, mark)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn apply_node_mark(_sock: &Socket, mark: i32) -> std::io::Result<()> {
    if mark != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "streamSettings.sockopt.mark is unsupported on this platform",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_named_interface(sock: &Socket, _peer: SocketAddr, name: &str) -> std::io::Result<()> {
    sock.bind_device(Some(name.as_bytes()))
}

#[cfg(any(windows, target_os = "macos", target_os = "ios"))]
fn bind_named_interface(sock: &Socket, peer: SocketAddr, name: &str) -> std::io::Result<()> {
    let index = if_addrs::get_if_addrs()?
        .into_iter()
        .find(|interface| interface.name == name && interface.ip().is_ipv4() == peer.is_ipv4())
        .and_then(|interface| interface.index)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("network interface `{name}` was not found for {peer}"),
            )
        })?;
    bind_interface_index(sock, peer, index)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    windows,
    target_os = "macos",
    target_os = "ios"
)))]
fn bind_named_interface(_sock: &Socket, _peer: SocketAddr, name: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("interface binding `{name}` is unsupported on this platform"),
    ))
}

#[cfg(windows)]
fn bind_interface_index(sock: &Socket, peer: SocketAddr, index: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    };
    if peer.is_ipv4() {
        raw_setsockopt_u32(sock, IPPROTO_IP as i32, IP_UNICAST_IF as i32, index.to_be())
    } else {
        raw_setsockopt_u32(sock, IPPROTO_IPV6 as i32, IPV6_UNICAST_IF as i32, index)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn bind_interface_index(sock: &Socket, peer: SocketAddr, index: u32) -> std::io::Result<()> {
    if peer.is_ipv4() {
        raw_setsockopt_u32(sock, libc::IPPROTO_IP, 25, index)
    } else {
        raw_setsockopt_u32(sock, libc::IPPROTO_IPV6, 125, index)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_tcp_platform_options(sock: &Socket, cfg: &OutboundSocketConfig) -> std::io::Result<()> {
    let tfo = cfg.tfo_value();
    if tfo != 0 {
        raw_setsockopt_int(
            sock,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            i32::from(tfo > 0),
        )?;
    }
    if !cfg.tcp_congestion.is_empty() {
        sock.set_tcp_congestion(cfg.tcp_congestion.as_bytes())?;
    }
    if cfg.tcp_window_clamp > 0 {
        raw_setsockopt_int(
            sock,
            libc::IPPROTO_TCP,
            libc::TCP_WINDOW_CLAMP,
            cfg.tcp_window_clamp,
        )?;
    }
    if cfg.tcp_user_timeout > 0 {
        sock.set_tcp_user_timeout(Some(Duration::from_millis(cfg.tcp_user_timeout as u64)))?;
    }
    if cfg.tcp_max_seg > 0 {
        raw_setsockopt_int(sock, libc::IPPROTO_TCP, libc::TCP_MAXSEG, cfg.tcp_max_seg)?;
    }
    Ok(())
}

#[cfg(windows)]
fn apply_tcp_platform_options(sock: &Socket, cfg: &OutboundSocketConfig) -> std::io::Result<()> {
    let tfo = cfg.tfo_value();
    if tfo != 0 {
        raw_setsockopt_int(sock, 6, 15, i32::from(tfo > 0))?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apply_tcp_platform_options(sock: &Socket, cfg: &OutboundSocketConfig) -> std::io::Result<()> {
    // Darwin uses TCP_FASTOPEN_CLIENT=0x02 for outbound sockets.
    let tfo = cfg.tfo_value();
    if tfo != 0 {
        raw_setsockopt_int(
            sock,
            libc::IPPROTO_TCP,
            0x105,
            if tfo > 0 { 0x02 } else { 0 },
        )?;
    }
    Ok(())
}

/// Apply the node-scoped options that are meaningful for UDP carrier sockets.
/// TCP-only fields remain handled by `apply_socket_config`.
pub(crate) fn apply_current_udp_socket_config(
    sock: &Socket,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    let Some(cfg) = socket_policy::current().and_then(|policy| policy.socket().cloned()) else {
        return Ok(());
    };
    apply_node_mark(sock, cfg.mark)?;
    let family_addr = match peer {
        Some(peer) => peer,
        None => sock.local_addr()?.as_socket().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot determine UDP socket family for node sockopt",
            )
        })?,
    };
    if !cfg.interface.is_empty() {
        bind_named_interface(sock, family_addr, &cfg.interface)?;
    }
    apply_custom_sockopts(
        sock,
        if family_addr.is_ipv4() {
            "udp4"
        } else {
            "udp6"
        },
        &cfg,
    )
}

#[cfg(target_os = "freebsd")]
fn apply_tcp_platform_options(sock: &Socket, cfg: &OutboundSocketConfig) -> std::io::Result<()> {
    let tfo = cfg.tfo_value();
    if tfo != 0 {
        raw_setsockopt_int(sock, libc::IPPROTO_TCP, 1025, i32::from(tfo > 0))?;
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
)))]
fn apply_tcp_platform_options(_sock: &Socket, cfg: &OutboundSocketConfig) -> std::io::Result<()> {
    if cfg.tfo_value() != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "tcpFastOpen is unsupported on this platform",
        ));
    }
    Ok(())
}

fn apply_custom_sockopts(
    sock: &Socket,
    network: &str,
    cfg: &OutboundSocketConfig,
) -> std::io::Result<()> {
    for custom in &cfg.custom_sockopt {
        if !custom.system.is_empty() && custom.system != xray_os_name() {
            continue;
        }
        if !network.starts_with(&custom.network) {
            continue;
        }
        let level = if custom.level.is_empty() {
            6
        } else {
            custom.level.parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "customSockopt.level must be an integer",
                )
            })?
        };
        let opt = custom.opt.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "customSockopt.opt must be an integer",
            )
        })?;
        match custom.value_type.as_str() {
            "int" => {
                let value = custom.value.parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "customSockopt.value must be an integer for type=int",
                    )
                })?;
                raw_setsockopt_int(sock, level, opt, value)?;
            }
            "str" => raw_setsockopt_string(sock, level, opt, &custom.value)?,
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown customSockopt type `{other}`"),
                ));
            }
        }
    }
    Ok(())
}

fn xray_os_name() -> &'static str {
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        "darwin"
    } else {
        std::env::consts::OS
    }
}

#[cfg(unix)]
fn raw_setsockopt_int(sock: &Socket, level: i32, opt: i32, value: i32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            (&value as *const i32).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn raw_setsockopt_int(sock: &Socket, level: i32, opt: i32, value: i32) -> std::io::Result<()> {
    raw_setsockopt_bytes(sock, level, opt, &value.to_ne_bytes())
}

#[cfg(any(windows, target_os = "macos", target_os = "ios"))]
fn raw_setsockopt_u32(sock: &Socket, level: i32, opt: i32, value: u32) -> std::io::Result<()> {
    raw_setsockopt_bytes(sock, level, opt, &value.to_ne_bytes())
}

#[cfg(unix)]
fn raw_setsockopt_string(sock: &Socket, level: i32, opt: i32, value: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut value = value.as_bytes().to_vec();
    value.push(0);
    let result = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            value.as_ptr().cast(),
            value.len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn raw_setsockopt_string(
    _sock: &Socket,
    _level: i32,
    _opt: i32,
    _value: &str,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "customSockopt type=str is unsupported on Windows",
    ))
}

#[cfg(windows)]
fn raw_setsockopt_bytes(sock: &Socket, level: i32, opt: i32, value: &[u8]) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    let result = unsafe {
        windows_sys::Win32::Networking::WinSock::setsockopt(
            sock.as_raw_socket() as _,
            level,
            opt,
            value.as_ptr(),
            value.len() as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8305_interleave_matches_xray_order() {
        let addresses = vec![
            "192.0.2.1:1".parse().unwrap(),
            "192.0.2.2:1".parse().unwrap(),
            "[2001:db8::1]:1".parse().unwrap(),
            "[2001:db8::2]:1".parse().unwrap(),
        ];
        let got = interleave_addresses(addresses, true, 1);
        assert_eq!(
            got.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "[2001:db8::1]:1",
                "192.0.2.1:1",
                "[2001:db8::2]:1",
                "192.0.2.2:1",
            ]
        );
    }

    #[test]
    fn txt_target_accepts_host_and_bracketed_ipv6() {
        assert_eq!(
            parse_txt_target("example.com:8443"),
            Some(("example.com".into(), 8443))
        );
        assert_eq!(
            parse_txt_target("[2001:db8::1]:443"),
            Some(("2001:db8::1".into(), 443))
        );
    }

    #[test]
    fn zero_interleave_exhausts_the_preferred_family_first() {
        let addresses = vec![
            "192.0.2.1:1".parse().unwrap(),
            "[2001:db8::1]:1".parse().unwrap(),
            "192.0.2.2:1".parse().unwrap(),
            "[2001:db8::2]:1".parse().unwrap(),
        ];
        let got = interleave_addresses(addresses, true, 0);
        assert_eq!(
            got.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "[2001:db8::1]:1",
                "[2001:db8::2]:1",
                "192.0.2.1:1",
                "192.0.2.2:1",
            ]
        );
    }
}
