//! Windows 后端：Wintun + 系统路由表。
//!
//! Startup is transactional: a real tun-rs device must exist, every netsh
//! mutation must succeed, and partial DNS/route state is rolled back before an
//! error reaches the supervisor.

use std::{collections::HashSet, net::IpAddr, process::Command, sync::Arc};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind},
    route_table::{ManagedRoute, RouteTable},
    tun_io::TunIo,
};

pub fn list_interfaces() -> Vec<String> {
    let out = std::process::Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output();
    let mut names = Vec::new();
    if let Ok(o) = out {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines().skip(3) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                names.push(parts[3..].join(" "));
            }
        }
    }
    names
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    match plan.kind {
        EngineKind::Tun => Ok(Arc::new(WindowsTun::new(plan))),
        EngineKind::Tproxy | EngineKind::Redirect => Err(CaptureError::Unsupported(
            "Windows 不支持 tproxy/redirect".into(),
        )),
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct WindowsTun {
    plan: CapturePlan,
    state: Mutex<TunState>,
    routes: Arc<RouteTable>,
}

#[derive(Default)]
struct TunState {
    started: bool,
    device: Option<Arc<dyn TunIo>>,
    /// Original per-interface DNS source and ordered server list.
    saved_dns: Vec<DnsInterfaceState>,
}

impl WindowsTun {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TunState::default()),
            routes: RouteTable::new(),
        }
    }
}

#[async_trait]
impl CaptureEngine for WindowsTun {
    fn kind(&self) -> EngineKind {
        EngineKind::Tun
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    fn tun_io(&self) -> Option<Arc<dyn crate::tun_io::TunIo>> {
        let g = self.state.try_lock().ok()?;
        g.device.clone()
    }
    async fn start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        _runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if g.started {
            return Ok(());
        }
        if !g.saved_dns.is_empty() {
            return Err(CaptureError::DeviceFailed(
                "cannot restart Windows TUN while a previous DNS restore is incomplete".into(),
            ));
        }
        if !self.routes.is_empty() {
            return Err(CaptureError::DeviceFailed(
                "cannot restart Windows TUN while a previous route restore is incomplete".into(),
            ));
        }
        // 在 TUN 创建之前先探物理默认网卡（name + v4/v6 ifindex）—— Windows
        // 上 TUN 起来后默认路由仍可能与物理共存（metric 不同），但提前探一次
        // 给 outbound 全局态注入一个明确的初值更稳妥；后续 net_monitor watcher
        // 会持续追踪变化。submit() 内部会同时刷新 set_outbound_interface 和
        // set_outbound_interface_index。
        let exclude =
            crate::default_iface::ExcludeList::from_plan_iface(self.plan.interface_name.clone());
        let snap = crate::default_iface::probe(&exclude);
        if snap.is_empty() {
            warn!(
                target: "capture::windows",
                "pre-TUN default interface probe returned empty — outbound dials may loop through TUN until net_monitor catches up"
            );
        }
        crate::net_monitor::notify_network_changed_full(snap);

        // tun-rs creates the interface and applies IPv4/IPv6/MTU itself. Do
        // not repeat that work with netsh: the builder already propagates
        // configuration errors, and a second mutation can overwrite an
        // adapter that tun-rs deliberately reused.
        let device = crate::platform::tunrs_io::open(&self.plan)
            .map(|device| device as Arc<dyn TunIo>)
            .map_err(|error| {
                CaptureError::DeviceFailed(format!(
                    "open Windows TUN {}: {error}",
                    self.plan.interface_name
                ))
            })?;

        let mut saved_dns = Vec::new();
        let setup_result: Result<(), CaptureError> = (|| {
            // CaptureSupervisor has already made UDP+TCP 53 live before
            // entering engine.start, so no query is sent to an unbound port.
            if self.plan.hijack_dns {
                saved_dns = snapshot_system_dns().map_err(|error| {
                    CaptureError::DeviceFailed(format!(
                        "snapshot Windows DNS before hijack: {error}"
                    ))
                })?;
                apply_dns_to_all_interfaces(&saved_dns).map_err(|error| {
                    CaptureError::DeviceFailed(format!("apply Windows DNS hijack: {error}"))
                })?;
            }

            for dest in desired_tun_routes(&self.plan) {
                self.routes
                    .add(ManagedRoute {
                        dest,
                        gateway: None,
                        interface: self.plan.interface_name.clone(),
                        metric: 0,
                        table: None,
                    })
                    .map_err(CaptureError::Route)?;
            }
            Ok(())
        })();

        if let Err(error) = setup_result {
            let mut rollback_errors = Vec::new();
            if let Err(route_error) = self.routes.revert_all_checked() {
                rollback_errors.push(format!("revert routes: {route_error}"));
            }
            if !saved_dns.is_empty()
                && let Err(restore_error) = restore_dns_snapshot(&saved_dns)
            {
                rollback_errors.push(format!("restore DNS: {restore_error}"));
                // Preserve recovery data for the supervisor's mandatory
                // engine.stop rollback (and for a later direct retry).
                g.saved_dns = saved_dns.clone();
            }
            if let Err(close_error) = device.close().await {
                rollback_errors.push(format!("close TUN: {close_error}"));
            }
            drop(device);
            return Err(with_rollback_errors(error, rollback_errors));
        }

        // Wintun 的事件级 packet_loop 只发现流，不能转发 payload。
        // virtual_nic 始终由 CaptureSupervisor 的 TunDispatcher 独占读写。
        let _ = events;
        if self.plan.hijack_dns {
            info!(
                target: "capture::windows",
                count = saved_dns.len(),
                "DNS hijacked → 127.0.0.1/::1 (UDP+TCP :53)"
            );
        }
        g.device = Some(device);
        g.saved_dns = saved_dns;
        g.started = true;
        info!(
            target: "capture",
            iface = %self.plan.interface_name,
            "windows tun started"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        let mut cleanup_errors = Vec::new();
        if let Err(error) = self.routes.revert_all_checked() {
            cleanup_errors.push(format!("revert routes: {error}"));
        }

        // Restore the original DNS mode before shutting down the resolver.
        // Keep the snapshot on failure so a direct retry cannot overwrite it.
        if !g.saved_dns.is_empty() {
            match restore_dns_snapshot(&g.saved_dns) {
                Ok(()) => {
                    g.saved_dns.clear();
                    info!(target: "capture::windows", "DNS restored");
                }
                Err(error) => {
                    cleanup_errors.push(format!("restore DNS: {error}"));
                }
            }
        }
        if let Some(device) = g.device.take() {
            if let Err(error) = device.close().await {
                cleanup_errors.push(format!("close TUN: {error}"));
            }
            drop(device);
        }
        g.started = false;
        if !cleanup_errors.is_empty() {
            return Err(CaptureError::DeviceFailed(format!(
                "Windows TUN stopped with cleanup errors: {}",
                cleanup_errors.join("; ")
            )));
        }
        info!(target: "capture", iface = %self.plan.interface_name, "windows tun stopped");
        Ok(())
    }
}

fn desired_tun_routes(plan: &CapturePlan) -> Vec<ipnet::IpNet> {
    if !plan.auto_route {
        return Vec::new();
    }

    let mut routes = if plan.route_addresses.is_empty() || !plan.route_address_set.is_empty() {
        let mut defaults = vec![
            "0.0.0.0/0"
                .parse::<ipnet::IpNet>()
                .expect("constant IPv4 default route"),
        ];
        if plan.ipv6_enabled && plan.tun_v6_cidr.is_some() {
            defaults.push(
                "::/0"
                    .parse::<ipnet::IpNet>()
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

/* ---------------- DNS hijack helpers ---------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DnsSource {
    Automatic,
    Static,
    /// The adapter could not be mapped to its TCP/IP registry key. Preserve
    /// the observed servers as static rather than guessing DHCP and losing
    /// them.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DnsAddressFamily {
    Ipv4,
    Ipv6,
}

impl DnsAddressFamily {
    fn netsh_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    fn hijack_server(self) -> &'static str {
        match self {
            Self::Ipv4 => "127.0.0.1",
            Self::Ipv6 => "::1",
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsInterfaceState {
    interface_index: u32,
    interface_alias: String,
    address_family: DnsAddressFamily,
    source: DnsSource,
    server_addresses: Vec<String>,
}

const DNS_SNAPSHOT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
[Console]::OutputEncoding = $utf8

$adapters = @{}
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
    if ($null -ne $_.ifIndex -and $null -ne $_.InterfaceGuid) {
        $guid = ([guid]$_.InterfaceGuid).ToString('B')
        $adapters[[uint32]$_.ifIndex] = $guid
    }
}

$states = @()
Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
    $family = $null
    $service = $null
    if ([int]$_.AddressFamily -eq 2) {
        $family = 'ipv4'
        $service = 'Tcpip'
    } elseif ([int]$_.AddressFamily -eq 23) {
        $family = 'ipv6'
        $service = 'Tcpip6'
    }
    if ($null -eq $family) {
        return
    }
    $servers = @($_.ServerAddresses | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    $source = 'unknown'
    $guid = $adapters[[uint32]$_.InterfaceIndex]
    if ($null -ne $guid) {
        $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$service\Parameters\Interfaces\$guid"
        if (Test-Path -LiteralPath $path) {
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $nameServer = [string]$properties.NameServer
            if ([string]::IsNullOrWhiteSpace($nameServer)) {
                $source = 'automatic'
            } else {
                $source = 'static'
            }
        }
    }
    if ($source -ne 'unknown' -or $servers.Count -gt 0) {
        $states += [pscustomobject]@{
            interface_index = [uint32]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_family = $family
            source = $source
            server_addresses = @($servers | ForEach-Object { [string]$_ })
        }
    }
}

$json = ConvertTo-Json -InputObject @($states) -Compress -Depth 4
[Console]::Out.Write($json)
"#;

fn snapshot_system_dns() -> Result<Vec<DnsInterfaceState>, String> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            DNS_SNAPSHOT_SCRIPT,
        ])
        .output()
        .map_err(|error| format!("spawn powershell.exe: {error}"))?;
    if !out.status.success() {
        return Err(format!(
            "powershell.exe failed (status={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(out.stdout)
        .map_err(|error| format!("PowerShell DNS snapshot was not UTF-8: {error}"))?;
    parse_dns_snapshot_json(&stdout)
}

fn parse_dns_snapshot_json(input: &str) -> Result<Vec<DnsInterfaceState>, String> {
    let input = input.trim().trim_start_matches('\u{feff}');
    let mut states: Vec<DnsInterfaceState> =
        serde_json::from_str(if input.is_empty() { "[]" } else { input })
            .map_err(|error| format!("parse PowerShell DNS snapshot JSON: {error}"))?;
    let mut interfaces = HashSet::with_capacity(states.len());
    for state in &states {
        if state.interface_index == 0 {
            return Err("DNS snapshot contains interface index 0".into());
        }
        if state.interface_alias.trim().is_empty() {
            return Err(format!(
                "DNS snapshot interface {} has an empty alias",
                state.interface_index
            ));
        }
        if !interfaces.insert((state.interface_index, state.address_family)) {
            return Err(format!(
                "DNS snapshot contains duplicate {:?} interface index {}",
                state.address_family, state.interface_index
            ));
        }
        if state.server_addresses.is_empty() && state.source != DnsSource::Automatic {
            return Err(format!(
                "DNS snapshot {:?} interface {} has no servers and cannot be restored",
                state.address_family, state.interface_index
            ));
        }
        for server in &state.server_addresses {
            let address = server.parse::<IpAddr>().map_err(|error| {
                format!(
                    "DNS snapshot {:?} interface {} has invalid server {server:?}: {error}",
                    state.address_family, state.interface_index
                )
            })?;
            if !state.address_family.contains(address) {
                return Err(format!(
                    "DNS snapshot {:?} interface {} has mismatched server {server:?}",
                    state.address_family, state.interface_index
                ));
            }
        }
    }
    states.sort_unstable_by_key(|state| (state.interface_index, state.address_family));
    Ok(states)
}

fn apply_dns_to_all_interfaces(states: &[DnsInterfaceState]) -> Result<(), String> {
    if states.is_empty() {
        return Err("no DNS-enabled Windows interfaces were discovered".into());
    }
    let mut run = |args: &[String]| run_netsh(args);
    apply_dns_with(states, &mut run)
}

fn restore_dns_snapshot(states: &[DnsInterfaceState]) -> Result<(), String> {
    let mut run = |args: &[String]| run_netsh(args);
    restore_dns_with(states.iter().rev(), &mut run)
}

fn apply_dns_with<F>(states: &[DnsInterfaceState], run: &mut F) -> Result<(), String>
where
    F: FnMut(&[String]) -> Result<(), String>,
{
    if states.is_empty() {
        return Err("no DNS-enabled Windows interfaces were discovered".into());
    }

    for (index, state) in states.iter().enumerate() {
        let command = static_dns_commands(state, &[state.address_family.hijack_server().into()])?
            .into_iter()
            .next()
            .expect("one static DNS server produces one command");
        if let Err(apply_error) = run(&command) {
            let rollback_error = restore_dns_with(states[..=index].iter().rev(), run).err();
            return Err(match rollback_error {
                Some(rollback_error) => format!(
                    "interface {} ({}) failed: {apply_error}; rollback failed: {rollback_error}",
                    state.interface_index, state.interface_alias
                ),
                None => format!(
                    "interface {} ({}) failed: {apply_error}; prior DNS state restored",
                    state.interface_index, state.interface_alias
                ),
            });
        }
    }
    Ok(())
}

fn restore_dns_with<'a, I, F>(states: I, run: &mut F) -> Result<(), String>
where
    I: IntoIterator<Item = &'a DnsInterfaceState>,
    F: FnMut(&[String]) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for state in states {
        let commands = match state.source {
            DnsSource::Automatic => vec![automatic_dns_command(state)],
            DnsSource::Static | DnsSource::Unknown => {
                match static_dns_commands(state, &state.server_addresses) {
                    Ok(commands) => commands,
                    Err(error) => {
                        errors.push(format!(
                            "interface {} ({}): {error}",
                            state.interface_index, state.interface_alias
                        ));
                        continue;
                    }
                }
            }
        };
        for command in commands {
            if let Err(error) = run(&command) {
                errors.push(format!(
                    "interface {} ({}): {error}",
                    state.interface_index, state.interface_alias
                ));
                break;
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn automatic_dns_command(state: &DnsInterfaceState) -> Vec<String> {
    vec![
        "interface".into(),
        state.address_family.netsh_name().into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={}", state.interface_index),
        "source=dhcp".into(),
    ]
}

fn static_dns_commands(
    state: &DnsInterfaceState,
    servers: &[String],
) -> Result<Vec<Vec<String>>, String> {
    let Some(first) = servers.first() else {
        return Err("cannot restore static DNS without a server".into());
    };
    for server in servers {
        let address = server
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid DNS server {server:?}: {error}"))?;
        if !state.address_family.contains(address) {
            return Err(format!(
                "{:?} DNS state cannot use server {server:?}",
                state.address_family
            ));
        }
    }
    let mut commands = vec![vec![
        "interface".into(),
        state.address_family.netsh_name().into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={}", state.interface_index),
        "source=static".into(),
        format!("address={first}"),
        "validate=no".into(),
    ]];
    for (index, server) in servers.iter().enumerate().skip(1) {
        commands.push(vec![
            "interface".into(),
            state.address_family.netsh_name().into(),
            "add".into(),
            "dnsservers".into(),
            format!("name={}", state.interface_index),
            format!("address={server}"),
            format!("index={}", index + 1),
            "validate=no".into(),
        ]);
    }
    Ok(commands)
}

fn run_netsh(args: &[String]) -> Result<(), String> {
    debug!(target: "capture::windows", ?args, "exec netsh");
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|error| format!("spawn netsh: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        Err(format!(
            "netsh failed (status={:?}): {detail}",
            output.status.code()
        ))
    }
}

fn with_rollback_errors(error: CaptureError, rollback_errors: Vec<String>) -> CaptureError {
    if rollback_errors.is_empty() {
        error
    } else {
        CaptureError::DeviceFailed(format!(
            "{error}; startup rollback failed: {}",
            rollback_errors.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_plan(auto_route: bool, inet6: bool) -> CapturePlan {
        let mut capture = core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        };
        capture.tun.auto_route = auto_route;
        capture.tun.inet6 = inet6;
        let mut plan = CapturePlan::from_config(&capture).unwrap();
        plan.ipv6_enabled = inet6;
        plan
    }

    #[test]
    fn desired_routes_respect_auto_route_ipv6_and_explicit_prefixes() {
        assert!(desired_tun_routes(&route_plan(false, true)).is_empty());
        assert_eq!(
            desired_tun_routes(&route_plan(true, true)),
            [
                "0.0.0.0/0".parse::<ipnet::IpNet>().unwrap(),
                "::/0".parse::<ipnet::IpNet>().unwrap(),
            ]
        );

        let mut ipv4_only = route_plan(true, true);
        ipv4_only.ipv6_enabled = false;
        assert_eq!(
            desired_tun_routes(&ipv4_only),
            ["0.0.0.0/0".parse::<ipnet::IpNet>().unwrap()]
        );

        let mut explicit = route_plan(true, true);
        explicit.route_addresses = vec![
            "10.0.0.0/8".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        assert_eq!(
            desired_tun_routes(&explicit),
            [
                "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
                "2001:db8::/32".parse::<ipnet::IpNet>().unwrap(),
            ]
        );
    }

    fn dns_state(
        interface_index: u32,
        address_family: DnsAddressFamily,
        source: DnsSource,
        servers: &[&str],
    ) -> DnsInterfaceState {
        DnsInterfaceState {
            interface_index,
            interface_alias: format!("if-{interface_index}"),
            address_family,
            source,
            server_addresses: servers.iter().map(|server| (*server).into()).collect(),
        }
    }

    #[test]
    fn dns_snapshot_parser_preserves_source_order_and_server_priority() {
        let states = parse_dns_snapshot_json(
            "\u{feff}[
                {
                    \"interface_index\": 17,
                    \"interface_alias\": \"Ethernet\",
                    \"address_family\": \"ipv4\",
                    \"source\": \"static\",
                    \"server_addresses\": [\"9.9.9.9\", \"1.1.1.1\"]
                },
                {
                    \"interface_index\": 4,
                    \"interface_alias\": \"Wi-Fi\",
                    \"address_family\": \"ipv4\",
                    \"source\": \"automatic\",
                    \"server_addresses\": [\"192.168.1.1\"]
                },
                {
                    \"interface_index\": 4,
                    \"interface_alias\": \"Wi-Fi\",
                    \"address_family\": \"ipv6\",
                    \"source\": \"automatic\",
                    \"server_addresses\": []
                }
            ]",
        )
        .unwrap();

        assert_eq!(states[0].interface_index, 4);
        assert_eq!(states[0].address_family, DnsAddressFamily::Ipv4);
        assert_eq!(states[0].source, DnsSource::Automatic);
        assert_eq!(states[1].interface_index, 4);
        assert_eq!(states[1].address_family, DnsAddressFamily::Ipv6);
        assert!(states[1].server_addresses.is_empty());
        assert_eq!(states[2].interface_index, 17);
        assert_eq!(states[2].source, DnsSource::Static);
        assert_eq!(states[2].server_addresses, ["9.9.9.9", "1.1.1.1"]);
    }

    #[test]
    fn dns_snapshot_parser_rejects_duplicate_interfaces_and_invalid_servers() {
        let duplicate = r#"[
            {"interface_index":2,"interface_alias":"a","address_family":"ipv4","source":"automatic","server_addresses":["1.1.1.1"]},
            {"interface_index":2,"interface_alias":"b","address_family":"ipv4","source":"static","server_addresses":["8.8.8.8"]}
        ]"#;
        assert!(
            parse_dns_snapshot_json(duplicate)
                .unwrap_err()
                .contains("duplicate Ipv4 interface index 2")
        );

        let invalid = r#"[
            {"interface_index":3,"interface_alias":"a","address_family":"ipv4","source":"static","server_addresses":["not-an-ip"]}
        ]"#;
        assert!(
            parse_dns_snapshot_json(invalid)
                .unwrap_err()
                .contains("invalid server")
        );

        let mismatched = r#"[
            {"interface_index":3,"interface_alias":"a","address_family":"ipv6","source":"static","server_addresses":["8.8.8.8"]}
        ]"#;
        assert!(
            parse_dns_snapshot_json(mismatched)
                .unwrap_err()
                .contains("mismatched server")
        );
    }

    #[test]
    fn restore_plan_distinguishes_automatic_static_and_unknown_sources() {
        let states = [
            dns_state(1, DnsAddressFamily::Ipv4, DnsSource::Automatic, &[]),
            dns_state(
                2,
                DnsAddressFamily::Ipv4,
                DnsSource::Static,
                &["9.9.9.9", "1.1.1.1"],
            ),
            dns_state(
                3,
                DnsAddressFamily::Ipv6,
                DnsSource::Unknown,
                &["2001:4860:4860::8888"],
            ),
        ];
        let mut calls = Vec::new();
        restore_dns_with(states.iter(), &mut |args| {
            calls.push(args.to_vec());
            Ok(())
        })
        .unwrap();

        assert!(calls[0].iter().any(|arg| arg == "name=1"));
        assert!(calls[0].iter().any(|arg| arg == "source=dhcp"));
        assert!(calls[1].iter().any(|arg| arg == "name=2"));
        assert!(calls[1].iter().any(|arg| arg == "address=9.9.9.9"));
        assert!(calls[2].iter().any(|arg| arg == "index=2"));
        assert!(calls[2].iter().any(|arg| arg == "address=1.1.1.1"));
        assert!(calls[3].iter().any(|arg| arg == "name=3"));
        assert!(calls[3].iter().any(|arg| arg == "ipv6"));
        assert!(
            calls[3]
                .iter()
                .any(|arg| arg == "address=2001:4860:4860::8888")
        );
    }

    #[test]
    fn dns_apply_failure_rolls_back_every_touched_interface_in_reverse() {
        let states = [
            dns_state(1, DnsAddressFamily::Ipv4, DnsSource::Static, &["9.9.9.9"]),
            dns_state(2, DnsAddressFamily::Ipv6, DnsSource::Automatic, &[]),
        ];
        let mut calls = Vec::new();
        let error = apply_dns_with(&states, &mut |args| {
            calls.push(args.to_vec());
            if args.iter().any(|arg| arg == "name=2") && args.iter().any(|arg| arg == "address=::1")
            {
                Err("injected apply failure".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert!(error.contains("injected apply failure"));
        assert!(error.contains("prior DNS state restored"));
        assert_eq!(calls.len(), 4);
        assert!(calls[0].iter().any(|arg| arg == "name=1"));
        assert!(calls[0].iter().any(|arg| arg == "address=127.0.0.1"));
        assert!(calls[1].iter().any(|arg| arg == "name=2"));
        assert!(calls[1].iter().any(|arg| arg == "address=::1"));
        assert!(calls[2].iter().any(|arg| arg == "name=2"));
        assert!(calls[2].iter().any(|arg| arg == "ipv6"));
        assert!(calls[2].iter().any(|arg| arg == "source=dhcp"));
        assert!(calls[3].iter().any(|arg| arg == "name=1"));
        assert!(calls[3].iter().any(|arg| arg == "address=9.9.9.9"));
    }

    #[test]
    fn dns_apply_uses_the_loopback_for_each_address_family() {
        let states = [
            dns_state(1, DnsAddressFamily::Ipv4, DnsSource::Automatic, &[]),
            dns_state(1, DnsAddressFamily::Ipv6, DnsSource::Automatic, &[]),
        ];
        let mut calls = Vec::new();
        apply_dns_with(&states, &mut |args| {
            calls.push(args.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(calls.len(), 2);
        assert!(calls[0].iter().any(|arg| arg == "ipv4"));
        assert!(calls[0].iter().any(|arg| arg == "address=127.0.0.1"));
        assert!(calls[1].iter().any(|arg| arg == "ipv6"));
        assert!(calls[1].iter().any(|arg| arg == "address=::1"));
    }
}
