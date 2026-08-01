//! Linux 后端：TUN（/dev/net/tun, ioctl TUNSETIFF）+ TProxy + nftables / iptables。
//!
//! M4 完整化：
//! * `EngineKind::Tun` —— 通过 root `/dev/net/tun` 或 tun-rs 拿到真实 fd；spawn packet
//!   read loop，把 IP 包解析成 [`CaptureEvent`] 推到 channel；写默认路由。
//! * `EngineKind::Tproxy` —— 安装 nftables 临时规则集，把 mark 流量重定向到本地
//!   tproxy socket；停止时通过 nft delete table 回滚。
//! * `EngineKind::Redirect` —— iptables -t nat REDIRECT，仅 TCP。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind},
    packet::{L4, parse_tun_frame},
    platform::{
        linux_auto_redirect::{self, AutoRedirectBackend, RedirectPorts},
        linux_auto_redirect_route::{self, AutoRedirectRouteLease},
        linux_tproxy::{RedirectTcpListener, bind_tcp_redirect_listener_set, run_tcp_redirect},
    },
    route_table::RouteTable,
    tproxy_rules,
    tun_io::TunIo,
    tun_logging::root_tun_summary,
};

#[cfg(not(target_os = "android"))]
use crate::route_table::ManagedRoute;

pub fn list_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            if let Some(s) = e.file_name().to_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    let engine = match plan.kind {
        EngineKind::Tun => Arc::new(LinuxTun::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::Tproxy => Arc::new(LinuxTproxy::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::Redirect => Arc::new(LinuxRedirect::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::None => return Err(CaptureError::Unsupported("kind=None".into())),
    };
    Ok(engine)
}

/* ---------------- LinuxTun ---------------- */

pub struct LinuxTun {
    plan: CapturePlan,
    state: Mutex<TunState>,
    routes: Arc<RouteTable>,
}

#[derive(Default)]
struct TunState {
    started: bool,
    device: Option<Arc<dyn TunIo>>,
    loop_handle: Option<JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
    platform_preconfigured: bool,
    effective_plan: Option<CapturePlan>,
    redirect_listeners: Vec<RedirectTcpListener>,
    redirect_backend: Option<AutoRedirectBackend>,
    redirect_route_lease: Option<AutoRedirectRouteLease>,
    policy_rule_lease: Option<crate::linux_netlink::PolicyRuleLease>,
    crash_recovery: Option<crate::platform::linux_recovery::LinuxCaptureGuard>,
    redirect_tasks: Option<JoinSet<()>>,
    redirect_stops: Vec<oneshot::Sender<()>>,
}

fn redirect_ports_from_addrs(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Result<RedirectPorts, CaptureError> {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for address in addresses {
        let slot = if address.is_ipv4() {
            &mut ipv4
        } else {
            &mut ipv6
        };
        if slot.replace(address.port()).is_some() {
            return Err(CaptureError::Nat(format!(
                "duplicate TCP REDIRECT listener family: {address}"
            )));
        }
    }
    let ipv4 = ipv4
        .ok_or_else(|| CaptureError::Nat("missing required IPv4 TCP REDIRECT listener".into()))?;
    if ipv4 == 0 || ipv6 == Some(0) {
        return Err(CaptureError::Nat(
            "TCP REDIRECT listener did not receive an ephemeral port".into(),
        ));
    }
    Ok(RedirectPorts::new(ipv4, ipv6))
}

fn validate_auto_redirect_activation(plan: &CapturePlan) -> Result<(), CaptureError> {
    if !plan.auto_redirect {
        return Ok(());
    }
    if cfg!(target_os = "android") {
        return Err(CaptureError::Unsupported(
            "auto_redirect currently supports root-managed Linux only; Android requires a dedicated iptables/VpnService contract".into(),
        ));
    }
    if !plan.auto_route {
        return Err(CaptureError::Nat(
            "TUN auto_redirect requires auto_route".into(),
        ));
    }
    if plan.traffic != core_config::model::CaptureTraffic::System {
        return Err(CaptureError::Unsupported(
            "auto_redirect currently supports traffic=system only".into(),
        ));
    }
    if plan.strict_route {
        return Err(CaptureError::Unsupported(
            "auto_redirect does not yet support strict_route because it installs no policy-routing rule for ICMP/non-TCP-UDP traffic".into(),
        ));
    }
    if !plan.route_address_set.is_empty() || !plan.route_exclude_address_set.is_empty() {
        return Err(CaptureError::Unsupported(
            "auto_redirect dynamic route-set snapshots are not installed".into(),
        ));
    }
    if plan.iproute2_rule_index < 4 {
        return Err(CaptureError::Route(
            "auto_redirect iproute2_rule_index must be at least 4".into(),
        ));
    }
    if plan.iproute2_table_index == 0 || matches!(plan.iproute2_table_index, 253..=255) {
        return Err(CaptureError::Route(format!(
            "auto_redirect requires a non-reserved private routing table; table {} is unsafe",
            plan.iproute2_table_index
        )));
    }
    if plan.exclude_mptcp
        || !plan.exclude_processes.is_empty()
        || !plan.filters.include_interface.is_empty()
        || !plan.filters.exclude_interface.is_empty()
        || !plan.filters.include_uid.is_empty()
        || !plan.filters.include_uid_range.is_empty()
        || !plan.filters.exclude_uid.is_empty()
        || !plan.filters.exclude_uid_range.is_empty()
        || !plan.filters.include_gid.is_empty()
        || !plan.filters.include_gid_range.is_empty()
        || !plan.filters.exclude_gid.is_empty()
        || !plan.filters.exclude_gid_range.is_empty()
        || !plan.filters.include_android_user.is_empty()
        || !plan.filters.include_package.is_empty()
        || !plan.filters.exclude_package.is_empty()
        || !plan.filters.include_mac.is_empty()
        || !plan.filters.exclude_mac.is_empty()
    {
        return Err(CaptureError::Unsupported(
            "auto_redirect cannot activate filters whose full TCP/UDP policy-routing bypass is not transactional".into(),
        ));
    }
    let defaults = (
        core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK,
        core_config::model::DEFAULT_AUTO_REDIRECT_RESET_MARK,
        core_config::model::DEFAULT_AUTO_REDIRECT_NFQUEUE,
        core_config::model::DEFAULT_IPROUTE2_AUTO_REDIRECT_FALLBACK_RULE_INDEX,
    );
    let actual = (
        plan.auto_redirect_marks.input.unwrap_or(defaults.0),
        plan.auto_redirect_marks.reset.unwrap_or(defaults.1),
        plan.auto_redirect_marks.nfqueue.unwrap_or(defaults.2),
        plan.auto_redirect_marks
            .fallback_rule_index
            .unwrap_or(defaults.3),
    );
    if actual != defaults {
        return Err(CaptureError::Unsupported(
            "auto_redirect input/reset/NFQUEUE/fallback fields belong to an unimplemented mark/NFQUEUE data plane".into(),
        ));
    }
    Ok(())
}

impl LinuxTun {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TunState::default()),
            routes: RouteTable::new(),
        }
    }

    /// 调用 `ip tuntap add` 预创建持久化设备（让 ioctl TUNSETIFF 能直接绑定）。
    fn ensure_device_exists(name: &str) {
        if let Some(st) = run_logged(
            "root-tun.ensure-device",
            "ip",
            &["tuntap", "add", "dev", name, "mode", "tun"],
            false,
        ) {
            if !st.success() {
                debug!(target: "capture::linux::tun", iface = %name, "ip tuntap add failed or device already exists");
            }
        }
    }

    fn configure_iface(
        plan: &CapturePlan,
        device: &dyn crate::tun_io::TunIo,
    ) -> Result<(), CaptureError> {
        if device.is_preconfigured() {
            return Ok(());
        }
        let v4 = plan.tun_v4_addr_cidr().parse().map_err(|error| {
            CaptureError::DeviceFailed(format!("invalid effective TUN IPv4 address: {error}"))
        })?;
        let mut addresses = vec![v4];
        if is_ipv6_available(&plan.interface_name)
            && let Some(v6) = plan.tun_v6_addr_cidr()
        {
            addresses.push(v6.parse().map_err(|error| {
                CaptureError::DeviceFailed(format!("invalid effective TUN IPv6 address: {error}"))
            })?);
        }
        crate::linux_netlink::configure_tun_interface(
            plan.interface_name.clone(),
            u32::from(plan.mtu.get()),
            addresses,
        )
        .map_err(|error| {
            CaptureError::DeviceFailed(format!(
                "configure root TUN `{}` via rtnetlink: {error}",
                plan.interface_name
            ))
        })
    }
}

/// Check if IPv6 is available on the system and the given interface.
/// Returns false if:
/// - `/proc/sys/net/ipv6/conf/all/disable_ipv6` is "1"
/// - `/proc/sys/net/ipv6/conf/<iface>/disable_ipv6` is "1"
/// - The IPv6 module is not loaded
fn is_ipv6_available(iface: &str) -> bool {
    // Check global IPv6 disable
    let global =
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6").unwrap_or_default();
    if global.trim() == "1" {
        return false;
    }
    // Check per-interface disable
    let per_iface =
        std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{iface}/disable_ipv6"))
            .unwrap_or_default();
    if per_iface.trim() == "1" {
        return false;
    }
    true
}

/// 探测 `ip rule` 子命令是否被当前 `ip` 工具支持（Android toybox 不带）。
///
/// 仅 `exit==0` 不够 —— toybox 某些版本 `ip rule list` 静默忽略并返回 0，
/// 但 `ip rule add` 会报 `Command "rule" is unknown`。我们额外检查 stderr：
/// 出现 "unknown" / "unrecognized" / "not implemented" 之一即视为不支持。
/// 结果用 `OnceLock` 缓存，避免频繁 spawn。
fn ip_rule_supported() -> bool {
    use std::sync::OnceLock;
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let r = std::process::Command::new("ip")
            .args(["rule", "list"])
            .output();
        let Ok(o) = r else {
            warn!(target: "capture::linux::tun", "ip rule probe failed: cannot spawn ip");
            return false;
        };
        if !o.status.success() {
            warn!(
                target: "capture::linux::tun",
                status = ?o.status.code(),
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "ip rule probe failed"
            );
            return false;
        }
        let stderr_low = String::from_utf8_lossy(&o.stderr).to_lowercase();
        for bad in [
            "unknown",
            "unrecognized",
            "not implemented",
            "no such",
            "feature not available",
            "try `ip address help'",
        ] {
            if stderr_low.contains(bad) {
                warn!(
                    target: "capture::linux::tun",
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "ip rule unsupported by current ip binary"
                );
                return false;
            }
        }
        let stdout_low = String::from_utf8_lossy(&o.stdout).to_lowercase();
        if stdout_low.contains("usage:") || stdout_low.contains("try `ip address help'") {
            warn!(
                target: "capture::linux::tun",
                stdout = %String::from_utf8_lossy(&o.stdout).trim(),
                "ip rule unsupported by current ip binary"
            );
            return false;
        }
        debug!(target: "capture::linux::tun", "ip rule supported");
        true
    })
}

/// 探测 nft / iptables / ip6tables 是否可用。
fn has_tool(name: &str) -> bool {
    let r = std::process::Command::new(name).arg("--version").output();
    matches!(r, Ok(o) if o.status.success())
}

/// 同 `Command::status()`，但抑制 stderr/stdout —— 用于 revert / 探测路径，
/// 避免污染用户终端。
fn run_quiet(prog: &str, args: &[&str]) -> Option<std::process::ExitStatus> {
    std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
}

fn run_logged(
    phase: &'static str,
    prog: &str,
    args: &[&str],
    warn_on_failure: bool,
) -> Option<std::process::ExitStatus> {
    debug!(
        target: "capture::linux::cmd",
        phase,
        cmd = %prog,
        args = ?args,
        "exec"
    );
    let out = match std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            if warn_on_failure {
                warn!(
                    target: "capture::linux::cmd",
                    phase,
                    cmd = %prog,
                    args = ?args,
                    error = %e,
                    "command spawn failed"
                );
            } else {
                debug!(
                    target: "capture::linux::cmd",
                    phase,
                    cmd = %prog,
                    args = ?args,
                    error = %e,
                    "command spawn failed"
                );
            }
            return None;
        }
    };
    if out.status.success() {
        debug!(
            target: "capture::linux::cmd",
            phase,
            cmd = %prog,
            args = ?args,
            status = ?out.status.code(),
            "command ok"
        );
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !warn_on_failure && super::is_absent_ip_rule_delete(prog, args, &stderr) {
            debug!(
                target: "capture::linux::cmd",
                phase,
                cmd = %prog,
                args = ?args,
                status = ?out.status.code(),
                stderr = %stderr.trim(),
                "command already absent"
            );
        } else if warn_on_failure {
            warn!(
                target: "capture::linux::cmd",
                phase,
                cmd = %prog,
                args = ?args,
                status = ?out.status.code(),
                stderr = %stderr.trim(),
                "command failed"
            );
        } else {
            debug!(
                target: "capture::linux::cmd",
                phase,
                cmd = %prog,
                args = ?args,
                status = ?out.status.code(),
                stderr = %stderr.trim(),
                "command failed"
            );
        }
    }
    Some(out.status)
}

fn run_ip_quiet(family_arg: &str, args: &[&str]) -> Option<std::process::ExitStatus> {
    let mut full = Vec::with_capacity(args.len() + usize::from(!family_arg.is_empty()));
    if !family_arg.is_empty() {
        full.push(family_arg);
    }
    full.extend_from_slice(args);
    run_quiet("ip", &full)
}

fn run_ip_logged(
    phase: &'static str,
    family_arg: &str,
    args: &[&str],
    warn_on_failure: bool,
) -> Option<std::process::ExitStatus> {
    let mut full = Vec::with_capacity(args.len() + usize::from(!family_arg.is_empty()));
    if !family_arg.is_empty() {
        full.push(family_arg);
    }
    full.extend_from_slice(args);
    run_logged(phase, "ip", &full, warn_on_failure)
}

#[async_trait]
impl CaptureEngine for LinuxTun {
    fn kind(&self) -> EngineKind {
        EngineKind::Tun
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    fn tun_io(&self) -> Option<Arc<dyn crate::tun_io::TunIo>> {
        // 阻塞读 mutex —— start 完成后此值不再修改。
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
        validate_auto_redirect_activation(&self.plan)?;
        let summary = root_tun_summary(&self.plan);
        info!(
            target: "capture::linux::tun",
            iface = %summary.interface_name,
            stack = %summary.stack,
            mtu = summary.mtu,
            tun_v4 = %summary.tun_v4,
            tun_v6 = %summary.tun_v6,
            auto_route = summary.auto_route,
            auto_redirect = summary.auto_redirect,
            strict_route = summary.strict_route,
            hijack_dns = summary.hijack_dns,
            table = summary.table,
            rule_priority = summary.rule_priority,
            output_mark = %format_args!("{:#x}", summary.output_mark),
            route_mode = summary.route_mode,
            route_address_count = summary.route_address_count,
            route_address_set_count = summary.route_address_set_count,
            route_exclude_count = summary.route_exclude_count,
            route_exclude_set_count = summary.route_exclude_set_count,
            "root tun starting"
        );
        // Crash recovery must run before TUNSETIFF attaches the requested
        // interface. Otherwise a stale journal naming the same interface can
        // delete the newly opened device during recovery.
        #[cfg(not(target_os = "android"))]
        let mut startup_recovery = {
            crate::platform::linux_caps::require_net_admin("Linux Root TUN")
                .map_err(CaptureError::DeviceFailed)?;
            Some(crate::platform::linux_recovery::LinuxCaptureGuard::recover_before_start()?)
        };
        #[cfg(target_os = "android")]
        let mut startup_recovery =
            match crate::platform::linux_caps::has_effective(caps::Capability::CAP_NET_ADMIN) {
                Ok(true) => Some(
                    crate::platform::linux_recovery::LinuxCaptureGuard::recover_before_start()?,
                ),
                Ok(false) => None,
                Err(error) => {
                    warn!(
                        target: "capture::android",
                        error = %error,
                        "cannot inspect CAP_NET_ADMIN; root recovery is unavailable"
                    );
                    None
                }
            };
        // tun-rs DeviceBuilder 内部处理 ip tuntap add + ioctl TUNSETIFF + 地址配置 + offload。
        // Android VpnService fd 仅作为非 root fallback。
        #[cfg(target_os = "android")]
        let device: Arc<dyn crate::tun_io::TunIo> =
            crate::platform::android_tun_io::open(&self.plan)
                .map_err(|e| CaptureError::DeviceFailed(format!("open tun: {e}")))?;
        #[cfg(not(target_os = "android"))]
        let device: Arc<dyn crate::tun_io::TunIo> = crate::platform::tunrs_io::open(&self.plan)
            .map(|d| d as Arc<dyn crate::tun_io::TunIo>)
            .map_err(|e| CaptureError::DeviceFailed(format!("tun-rs open: {e}")))?;

        // root TUN 里 `ip tuntap add` 在 Android toybox/部分 ROM 上经常不可用；
        // TUNSETIFF 会真正创建/绑定接口，所以接口地址和路由必须在 open 之后配置。
        let mut effective_plan = self.plan.clone();
        effective_plan.interface_name = device.name().to_string();
        let manage_linux_config = should_manage_linux_tun_config(device.as_ref());
        // Publish every resource needed by rollback before the first
        // fallible host-network mutation. CaptureSupervisor marks the engine
        // started before awaiting us, so any later error calls stop() and
        // cleans this effective (kernel-selected) interface rather than the
        // requested name.
        g.platform_preconfigured = !manage_linux_config;
        g.effective_plan = Some(effective_plan.clone());
        g.device = Some(device.clone());
        g.started = true;
        info!(
            target: "capture::linux::tun",
            requested_iface = %self.plan.interface_name,
            effective_iface = %effective_plan.interface_name,
            device_mtu = device.mtu(),
            platform_preconfigured = !manage_linux_config,
            "root tun device opened"
        );
        if effective_plan.auto_redirect && !manage_linux_config {
            return Err(CaptureError::Unsupported(
                "auto_redirect requires a root-managed Linux/Android TUN; \
                 a platform-preconfigured/VpnService device already owns capture"
                    .into(),
            ));
        }
        if manage_linux_config {
            crate::platform::linux_caps::require_net_admin("Linux/Android Root TUN")
                .map_err(CaptureError::DeviceFailed)?;
            let mut recovery = startup_recovery.take().ok_or_else(|| {
                CaptureError::DeviceFailed(
                    "root TUN opened without a CAP_NET_ADMIN recovery lock".into(),
                )
            })?;
            #[cfg(target_os = "android")]
            if effective_plan.auto_route {
                // Check before arming the recovery journal. A journal owns its
                // configured table and will flush it during rollback, so it
                // must never be armed for a table already owned by netd.
                crate::linux_netlink::ensure_route_table_available(
                    effective_plan.iproute2_table_index,
                )
                .map_err(|error| {
                    CaptureError::Route(format!("Android private TUN table check: {error}"))
                })?;
            }
            // Persist ownership only after the effective kernel-selected name
            // is known, but before address, route or policy mutation.
            recovery.arm(
                &effective_plan,
                crate::platform::linux_recovery::RecoveryMode::Tun,
            )?;
            g.crash_recovery = Some(recovery);
            Self::configure_iface(&effective_plan, device.as_ref())?;

            // Bind every required address family before routes or firewall
            // hooks can send traffic to the data plane. The actual ports are
            // injected into rules during post_start, after the dispatcher
            // owns TUN packet I/O.
            if effective_plan.auto_redirect {
                let redirect_ipv6 = effective_plan.ipv6_enabled
                    && effective_plan.tun_v6_cidr.is_some()
                    && is_ipv6_available(&effective_plan.interface_name);
                g.redirect_listeners = bind_tcp_redirect_listener_set(redirect_ipv6)?;
            }

            // auto_route：将所有目标流量导入 TUN（按 sing-box 默认拆 0/1 + 128/1 双半区
            // 路由，避免覆盖系统已有的 0/0 默认路由），并写入指定 iproute2 表。
            if (effective_plan.auto_route || effective_plan.strict_route)
                && !effective_plan.auto_redirect
            {
                #[cfg(target_os = "android")]
                {
                    let ipv6_tun = effective_plan
                        .tun_v6_cidr
                        .is_some_and(|_| is_ipv6_available(&effective_plan.interface_name));
                    g.policy_rule_lease = Some(crate::platform::android_route::install(
                        &self.routes,
                        &effective_plan,
                        ipv6_tun,
                    )?);
                }
                #[cfg(not(target_os = "android"))]
                {
                    g.policy_rule_lease =
                        Some(install_root_tun_policy(&self.routes, &effective_plan)?);
                }
            }
            if effective_plan.auto_route && !effective_plan.auto_redirect {
                // 内核级身份旁路：在 OUTPUT/mangle 链上为 excluded UID/GID/package
                // 打 fwmark = tun_outbound_mark，触发 native policy lease 注册的
                // `ip rule fwmark ... lookup main` 把这些包从主路由表送出，根本
                // 不进 TUN（与 mihomo / sing-tun 行为一致）。
                let bypass_mark = tun_outbound_mark(&effective_plan);
                let report =
                    crate::platform::linux_identity_bypass::install(&effective_plan, bypass_mark);
                if !report.backends.is_empty() {
                    info!(
                        target: "capture::linux::tun",
                        bypass_mark = %format_args!("{:#x}", bypass_mark),
                        backends = ?report.backends,
                        resolved_excluded_uids = report.resolved_excluded_uids,
                        all_ok = report.all_ok,
                        "kernel-level identity bypass installed"
                    );
                }
                #[cfg(target_os = "android")]
                if crate::platform::android_route::requires_identity_firewall(
                    &effective_plan.filters,
                ) {
                    let ipv4_ready = report.backends.contains(&"iptables");
                    let ipv6_ready = !effective_plan.ipv6_enabled
                        || effective_plan.tun_v6_cidr.is_none()
                        || report.backends.contains(&"ip6tables");
                    if !report.all_ok || !ipv4_ready || !ipv6_ready {
                        return Err(CaptureError::Unsupported(
                            "Android GID filters require working iptables owner rules for every enabled address family"
                                .into(),
                        ));
                    }
                }
            }
        } else {
            info!(
                target: "capture::linux::tun",
                iface = %effective_plan.interface_name,
                "tun device is platform-preconfigured; skip linux iface/route/rule management"
            );
        }

        // virtual_nic 的事件级 packet_loop 只能发现流，不能转发 payload。
        // 统一由 CaptureSupervisor 的 TunDispatcher 独占 TUN 读写；否则
        // stack=native/system 会只接管默认路由但没有出站转发。
        let dispatcher_owns_tun = true;
        let (stop_tx, stop_rx) = oneshot::channel();
        if !dispatcher_owns_tun {
            let dev_for_loop = device.clone();
            let mtu = usize::from(self.plan.mtu.get());
            let handle = tokio::spawn(async move {
                packet_loop(dev_for_loop, mtu, events, stop_rx).await;
            });
            g.loop_handle = Some(handle);
        } else {
            // 把 stop_rx drop，避免空挂；events 通道由 supervisor 持有但无人写。
            let _ = stop_rx;
            let _ = events;
        }

        g.stop_tx = Some(stop_tx);
        info!(
            target: "capture::linux::tun",
            iface = %effective_plan.interface_name,
            mtu = effective_plan.mtu,
            dispatcher_owns_tun,
            auto_redirect_prebound = g.redirect_listeners.len(),
            "linux tun prepared"
        );
        Ok(())
    }

    async fn post_start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !g.started {
            return Err(CaptureError::Nat(
                "cannot activate auto_redirect before Linux TUN is prepared".into(),
            ));
        }
        let plan = g
            .effective_plan
            .clone()
            .ok_or_else(|| CaptureError::Nat("Linux TUN effective plan is missing".into()))?;
        if !plan.auto_redirect || g.platform_preconfigured {
            return Ok(());
        }
        if g.redirect_backend.is_some() {
            return Ok(());
        }
        validate_auto_redirect_activation(&plan)?;
        if g.redirect_tasks.is_some() || g.redirect_route_lease.is_some() || !self.routes.is_empty()
        {
            return Err(CaptureError::Route(
                "auto_redirect has a partial activation ledger; pre_stop must clean it before retry"
                    .into(),
            ));
        }
        let ports = redirect_ports_from_addrs(
            g.redirect_listeners
                .iter()
                .map(RedirectTcpListener::local_addr),
        )?;
        let redirect_ipv6 = ports.ipv6.is_some();

        let listeners = std::mem::take(&mut g.redirect_listeners);
        let mut tasks = JoinSet::new();
        let mut stops = Vec::with_capacity(listeners.len());
        let inbound_tag: Arc<str> = Arc::from(plan.tag.as_str());
        for listener in listeners {
            let (listener, local_addr) = listener.into_parts();
            let (stop_tx, stop_rx) = oneshot::channel();
            stops.push(stop_tx);
            let events = events.clone();
            let runtime = runtime.clone();
            let inbound_tag = inbound_tag.clone();
            tasks.spawn(async move {
                if let Err(error) =
                    run_tcp_redirect(listener, events, runtime, inbound_tag, stop_rx).await
                {
                    warn!(
                        target: "capture::linux::auto_redirect",
                        %local_addr,
                        %error,
                        "TCP REDIRECT listener stopped with error"
                    );
                }
            });
        }
        g.redirect_tasks = Some(tasks);
        g.redirect_stops = stops;

        // Publish the exact policy-rule ledger before the first fallible route
        // mutation. `pre_stop` can then unwind every partial post_start state.
        g.redirect_route_lease = Some(AutoRedirectRouteLease::default());
        linux_auto_redirect_route::prepare_routes(&self.routes, &plan, redirect_ipv6)?;
        linux_auto_redirect_route::install(
            &plan,
            redirect_ipv6,
            g.redirect_route_lease
                .as_mut()
                .expect("auto_redirect route lease was published"),
        )?;

        // This synchronous, bounded nft transaction contains no await and is
        // deliberately last: no packet can enter until listeners, routes,
        // policy rules, and the dispatcher are all ready.
        let backend = linux_auto_redirect::install(&plan, ports)?;
        g.redirect_backend = Some(backend);
        info!(
            target: "capture::linux::auto_redirect",
            iface = %plan.interface_name,
            ?backend,
            ipv4_port = ports.ipv4,
            ipv6_port = ?ports.ipv6,
            "TUN auto_redirect activated after dispatcher"
        );
        Ok(())
    }

    async fn pre_stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if let Some(backend) = g.redirect_backend {
            // On failure retain the backend, listeners and dispatcher-facing
            // state so CaptureSupervisor can retry without creating a
            // black-hole window.
            linux_auto_redirect::uninstall(backend)?;
            g.redirect_backend = None;
        }

        // Pending listeners exist when start/post_start failed before rules
        // were activated. Dropping them is sufficient because no hook can
        // reference their ports.
        g.redirect_listeners.clear();
        let mut tasks = g.redirect_tasks.take().unwrap_or_else(JoinSet::new);
        let mut stops = std::mem::take(&mut g.redirect_stops);
        stop_listener_tasks(&mut stops, &mut tasks).await;

        if let Some(lease) = g.redirect_route_lease.as_mut() {
            linux_auto_redirect_route::uninstall(lease)?;
        }
        if self.plan.auto_redirect && !self.routes.is_empty() {
            self.routes.revert_all_checked().map_err(|error| {
                CaptureError::Route(format!(
                    "auto_redirect split-default route cleanup incomplete: {error}"
                ))
            })?;
        }
        if g.redirect_route_lease
            .as_ref()
            .is_some_and(AutoRedirectRouteLease::is_empty)
            && self.routes.is_empty()
        {
            g.redirect_route_lease = None;
        }
        Ok(())
    }

    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        self.clone().pre_stop().await?;
        let mut g = self.state.lock().await;
        if !g.started && g.effective_plan.is_none() {
            return Ok(());
        }
        let plan = g
            .effective_plan
            .clone()
            .unwrap_or_else(|| self.plan.clone());
        info!(
            target: "capture::linux::tun",
            iface = %plan.interface_name,
            auto_route = plan.auto_route,
            auto_redirect = plan.auto_redirect,
            strict_route = plan.strict_route,
            "root tun stopping"
        );
        if let Some(tx) = g.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = g.loop_handle.take() {
            h.abort();
        }
        if let Some(d) = g.device.take() {
            let _ = d.close().await;
        }
        let platform_preconfigured = g.platform_preconfigured;
        g.platform_preconfigured = false;
        if platform_preconfigured {
            g.started = false;
            g.effective_plan = None;
            info!(
                target: "capture::linux::tun",
                iface = %plan.interface_name,
                "tun device was platform-preconfigured; skip linux route/rule cleanup"
            );
            info!(target: "capture", iface = %plan.interface_name, "linux tun stopped");
            return Ok(());
        }
        if !plan.auto_redirect {
            if plan.auto_route {
                crate::platform::linux_identity_bypass::revert(&plan);
            }
            if let Some(lease) = g.policy_rule_lease.as_mut()
                && let Err(error) = lease.remove()
            {
                warn!(
                    target: "capture::linux::tun",
                    error = %error,
                    "policy lease cleanup incomplete; crash-recovery sweep will retry"
                );
            }
            if let Err(error) = self.routes.revert_all_checked() {
                warn!(
                    target: "capture::linux::tun",
                    error = %error,
                    "route ledger cleanup incomplete; crash-recovery sweep will retry"
                );
            }
        }
        if let Some(guard) = g.crash_recovery.take() {
            guard.mark_clean()?;
        }
        g.policy_rule_lease = None;
        g.started = false;
        g.effective_plan = None;
        info!(target: "capture", iface = %plan.interface_name, "linux tun stopped");
        Ok(())
    }
}

/* ---------------- auto_route / strict_route / auto_redirect helpers ---------------- */

#[cfg(not(target_os = "android"))]
fn install_root_tun_routes(
    routes: &RouteTable,
    plan: &CapturePlan,
    ipv6_tun: bool,
) -> Result<(), CaptureError> {
    if !plan.auto_route {
        return Ok(());
    }
    let mut cidrs: Vec<&str> = crate::resource_claims::LINUX_TUN_SPLIT_DEFAULT_V4.to_vec();
    if ipv6_tun {
        cidrs.extend_from_slice(&crate::resource_claims::LINUX_TUN_SPLIT_DEFAULT_V6);
    }
    for cidr in cidrs {
        let net = cidr.parse().map_err(|error| {
            CaptureError::Route(format!("invalid built-in TUN route {cidr}: {error}"))
        })?;
        routes
            .add(ManagedRoute {
                dest: net,
                gateway: None,
                interface: plan.interface_name.clone(),
                metric: 0,
                table: Some(plan.iproute2_table_index),
            })
            .map_err(CaptureError::Route)?;
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn install_root_tun_policy(
    routes: &RouteTable,
    plan: &CapturePlan,
) -> Result<crate::linux_netlink::PolicyRuleLease, CaptureError> {
    use crate::linux_netlink::{PolicyFamily, PolicyRule};

    let table = plan.iproute2_table_index;
    let rule_idx = plan.iproute2_rule_index;
    let ipv6_tun = plan
        .tun_v6_cidr
        .filter(|_| is_ipv6_available(&plan.interface_name));
    install_root_tun_routes(routes, plan, ipv6_tun.is_some())?;

    let summary = root_tun_summary(plan);
    info!(
        target: "capture::linux::tun",
        iface = %summary.interface_name,
        table = summary.table,
        rule_priority = summary.rule_priority,
        route_mode = summary.route_mode,
        route_address_count = summary.route_address_count,
        route_address_set_count = summary.route_address_set_count,
        route_exclude_count = summary.route_exclude_count,
        route_exclude_set_count = summary.route_exclude_set_count,
        backend = "rtnetlink",
        "install root tun policy routing"
    );

    let mut rules = Vec::new();
    let mut bypass_v4 = 254;
    let mut bypass_v6 = None;
    if plan.auto_route {
        let outbound_v4 = crate::linux_netlink::lookup_route(
            "1.1.1.1"
                .parse()
                .expect("hard-coded IPv4 route probe must parse"),
        )
        .map_err(|error| {
            CaptureError::Route(format!(
                "kernel netlink lookup returned no IPv4 physical route; refusing to install a TUN catch-all: {error}"
            ))
        })?;
        bypass_v4 = outbound_v4.table;
        let outbound_v6 = crate::linux_netlink::lookup_route(
            "2606:4700:4700::1111"
                .parse()
                .expect("hard-coded IPv6 route probe must parse"),
        )
        .ok();
        bypass_v6 = outbound_v6.as_ref().map(|route| route.table);
        if let Some(interface) = outbound_v4
            .interface
            .or_else(|| outbound_v6.and_then(|route| route.interface))
        {
            debug!(
                target: "capture::linux::tun",
                iface = %interface,
                table_v4 = bypass_v4,
                table_v6 = ?bypass_v6,
                "detected physical outbound routes via rtnetlink"
            );
            core_outbound::set_outbound_interface(Some(interface));
        } else {
            warn!(
                target: "capture::linux::tun",
                table_v4 = bypass_v4,
                table_v6 = ?bypass_v6,
                "route lookup had no single output interface; SO_BINDTODEVICE remains unchanged"
            );
        }

        let out_mark = tun_outbound_mark(plan);
        rules.push(
            PolicyRule::lookup(
                PolicyFamily::V4,
                outbound_bypass_rule_priority(rule_idx),
                bypass_v4,
            )
            .with_fw_mark(out_mark),
        );
        if let Some(table_v6) = bypass_v6 {
            rules.push(
                PolicyRule::lookup(
                    PolicyFamily::V6,
                    outbound_bypass_rule_priority(rule_idx),
                    table_v6,
                )
                .with_fw_mark(out_mark),
            );
        }
        rules.push(
            PolicyRule::lookup(PolicyFamily::V4, tun_subnet_rule_priority(rule_idx), table)
                .with_destination(ipnet::IpNet::V4(plan.tun_v4_cidr)),
        );
        if let Some(v6) = ipv6_tun {
            rules.push(
                PolicyRule::lookup(PolicyFamily::V6, tun_subnet_rule_priority(rule_idx), table)
                    .with_destination(ipnet::IpNet::V6(v6)),
            );
        }
        for net in &plan.route_exclude_addresses {
            let family = policy_family(net);
            let bypass = match family {
                PolicyFamily::V4 => Some(bypass_v4),
                PolicyFamily::V6 => bypass_v6,
            };
            if let Some(bypass) = bypass {
                rules.push(
                    PolicyRule::lookup(family, route_bypass_rule_priority(rule_idx), bypass)
                        .with_destination(*net),
                );
            }
        }
        if auto_route_uses_catch_all_rule(plan) {
            rules.push(PolicyRule::lookup(PolicyFamily::V4, rule_idx, table));
            if ipv6_tun.is_some() {
                rules.push(PolicyRule::lookup(PolicyFamily::V6, rule_idx, table));
            }
        } else {
            for net in &plan.route_addresses {
                if net.addr().is_ipv6() && ipv6_tun.is_none() {
                    continue;
                }
                rules.push(
                    PolicyRule::lookup(policy_family(net), rule_idx, table).with_destination(*net),
                );
            }
        }
    }
    if plan.strict_route {
        let strict_priority = rule_idx.saturating_add(1);
        rules.push(PolicyRule::blackhole(PolicyFamily::V4, strict_priority));
        rules.push(PolicyRule::blackhole(PolicyFamily::V6, strict_priority));
    }

    let lease = crate::linux_netlink::install_policy_rules(rules).map_err(|error| {
        CaptureError::Route(format!("install Root TUN policy via rtnetlink: {error}"))
    })?;
    info!(
        target: "capture::linux",
        table,
        rule_priority = rule_idx,
        bypass_rule_priority = outbound_bypass_rule_priority(rule_idx),
        bypass_lookup_v4 = bypass_v4,
        bypass_lookup_v6 = ?bypass_v6,
        route_bypass_rule_priority = route_bypass_rule_priority(rule_idx),
        outbound_mark = format_args!("{:#x}", tun_outbound_mark(plan)),
        strict_route = plan.strict_route,
        "root TUN policy installed transactionally"
    );
    Ok(lease)
}

fn tun_outbound_mark(plan: &CapturePlan) -> u32 {
    crate::resource_claims::tun_outbound_mark(plan)
}

fn outbound_bypass_rule_priority(rule_idx: u32) -> u32 {
    rule_idx.saturating_sub(1).max(1)
}

fn route_bypass_rule_priority(rule_idx: u32) -> u32 {
    rule_idx.saturating_sub(2).max(1)
}

fn tun_subnet_rule_priority(rule_idx: u32) -> u32 {
    rule_idx.saturating_sub(3).max(1)
}

fn policy_family(net: &ipnet::IpNet) -> crate::linux_netlink::PolicyFamily {
    if net.addr().is_ipv6() {
        crate::linux_netlink::PolicyFamily::V6
    } else {
        crate::linux_netlink::PolicyFamily::V4
    }
}

fn auto_route_uses_catch_all_rule(plan: &CapturePlan) -> bool {
    crate::resource_claims::linux_auto_route_is_catch_all(plan)
}

fn should_manage_linux_tun_config(device: &dyn TunIo) -> bool {
    !device.is_preconfigured()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn auto_redirect_plan() -> CapturePlan {
        let mut capture = core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        };
        capture.tun.auto_route = true;
        capture.tun.auto_redirect = true;
        CapturePlan::from_config(&capture).unwrap()
    }

    #[test]
    fn redirect_listener_ports_require_one_ipv4_and_at_most_one_ipv6() {
        let ports = redirect_ports_from_addrs([
            "0.0.0.0:41001".parse().unwrap(),
            "[::]:41002".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(ports, RedirectPorts::new(41001, Some(41002)));

        assert!(
            redirect_ports_from_addrs(["[::]:41002".parse().unwrap()]).is_err(),
            "IPv4 REDIRECT is mandatory"
        );
        assert!(
            redirect_ports_from_addrs([
                "0.0.0.0:41001".parse().unwrap(),
                "127.0.0.1:41003".parse().unwrap(),
            ])
            .is_err(),
            "duplicate address families must fail closed"
        );
    }

    #[test]
    fn auto_redirect_activation_rechecks_safe_contract() {
        let plan = auto_redirect_plan();
        validate_auto_redirect_activation(&plan).unwrap();

        let mut lan = plan.clone();
        lan.traffic = core_config::model::CaptureTraffic::Lan;
        assert!(validate_auto_redirect_activation(&lan).is_err());

        let mut identity = plan.clone();
        identity.filters.exclude_uid = vec![1000];
        assert!(validate_auto_redirect_activation(&identity).is_err());

        let mut reserved = plan.clone();
        reserved.auto_redirect_marks.reset = Some(0x5151);
        assert!(validate_auto_redirect_activation(&reserved).is_err());

        let mut reserved_table = plan;
        reserved_table.iproute2_table_index = 254;
        assert!(validate_auto_redirect_activation(&reserved_table).is_err());
    }

    struct TunConfigProbe {
        preconfigured: bool,
    }

    #[async_trait::async_trait]
    impl crate::tun_io::TunIo for TunConfigProbe {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, crate::tun_io::TunIoError> {
            Err(crate::tun_io::TunIoError::Closed)
        }

        async fn write_packet(&self, pkt: &[u8]) -> Result<usize, crate::tun_io::TunIoError> {
            Ok(pkt.len())
        }

        fn name(&self) -> &str {
            "probe0"
        }

        fn mtu(&self) -> u32 {
            1500
        }

        async fn close(&self) -> Result<(), crate::tun_io::TunIoError> {
            Ok(())
        }

        fn is_preconfigured(&self) -> bool {
            self.preconfigured
        }
    }

    #[test]
    fn preconfigured_tun_skips_linux_iface_and_route_management() {
        assert!(!should_manage_linux_tun_config(&TunConfigProbe {
            preconfigured: true
        }));
        assert!(should_manage_linux_tun_config(&TunConfigProbe {
            preconfigured: false
        }));
    }

    #[test]
    fn auto_route_bypass_rule_precedes_catch_all_rule() {
        assert_eq!(outbound_bypass_rule_priority(9000), 8999);
        assert_eq!(outbound_bypass_rule_priority(1), 1);
    }

    #[test]
    fn auto_route_exclude_rule_precedes_catch_all_rule() {
        assert_eq!(route_bypass_rule_priority(9000), 8998);
        assert_eq!(route_bypass_rule_priority(1), 1);
    }

    #[test]
    fn tun_outbound_mark_defaults_to_sing_tun_output_mark() {
        let plan = CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        })
        .unwrap();

        assert_eq!(
            tun_outbound_mark(&plan),
            core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
        );
    }

    #[test]
    fn parses_android_route_get_table_name() {
        let out = "8.8.8.8 via 192.168.1.1 dev wlan0 table wlan0 src 192.168.1.23 uid 0";

        assert_eq!(
            crate::platform::route_probe::parse_route_get_table(out),
            Some("wlan0".to_string())
        );
    }

    #[test]
    fn parses_android_route_get_numeric_table() {
        let out = "1.1.1.1 via 10.9.0.1 dev rmnet_data0 table 1017 src 10.9.1.2";

        assert_eq!(
            crate::platform::route_probe::parse_route_get_table(out),
            Some("1017".to_string())
        );
    }

    #[test]
    fn route_get_without_table_uses_implicit_main() {
        let out = "1.1.1.1 via 192.168.0.1 dev eth0 src 192.168.0.2 uid 1000";

        assert_eq!(
            crate::platform::route_probe::parse_route_get_table(out),
            None
        );
    }

    #[test]
    #[cfg(not(target_os = "android"))]
    fn auto_route_installs_split_default_routes_in_custom_table() {
        #[derive(Debug, Default)]
        struct CaptureBackend {
            added: parking_lot::Mutex<Vec<ManagedRoute>>,
        }
        impl crate::route_table::RouteBackend for CaptureBackend {
            fn add(&self, r: &ManagedRoute) -> Result<(), String> {
                self.added.lock().push(r.clone());
                Ok(())
            }
            fn del(&self, _r: &ManagedRoute) -> Result<(), String> {
                Ok(())
            }
        }

        let backend = Arc::new(CaptureBackend::default());
        let routes = RouteTable::with_backend(backend.clone());
        let plan = CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        })
        .unwrap();

        install_root_tun_routes(
            &routes,
            &plan,
            plan.tun_v6_cidr.is_some() && is_ipv6_available(&plan.interface_name),
        )
        .unwrap();

        let added = backend.added.lock();
        let expected_routes =
            if plan.tun_v6_cidr.is_some() && is_ipv6_available(&plan.interface_name) {
                4
            } else {
                2
            };
        assert_eq!(added.len(), expected_routes);
        assert!(
            added
                .iter()
                .all(|r| r.table == Some(plan.iproute2_table_index)),
            "auto_route split defaults must live in the custom table; main table is the outbound mark bypass"
        );
    }

    #[test]
    fn tproxy_rule_failure_drops_prebound_listeners_and_reverts() {
        #[derive(Debug)]
        struct ListenerDropProbe(Arc<AtomicBool>);

        impl Drop for ListenerDropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let listener_dropped = Arc::new(AtomicBool::new(false));
        let rules_reverted = Arc::new(AtomicBool::new(false));
        let dropped = listener_dropped.clone();
        let reverted = rules_reverted.clone();

        let result = prepare_tproxy_start(
            || Ok(ListenerDropProbe(dropped)),
            || Err(CaptureError::Doctor("injected rule failure".into())),
            || reverted.store(true, Ordering::SeqCst),
        );

        assert!(matches!(result, Err(CaptureError::Doctor(_))));
        assert!(listener_dropped.load(Ordering::SeqCst));
        assert!(rules_reverted.load(Ordering::SeqCst));
    }

    #[test]
    fn tproxy_bind_failure_never_installs_or_reverts_rules() {
        let install_called = Arc::new(AtomicBool::new(false));
        let revert_called = Arc::new(AtomicBool::new(false));
        let installed = install_called.clone();
        let reverted = revert_called.clone();

        let result: Result<(), CaptureError> = prepare_tproxy_start(
            || Err(CaptureError::DeviceFailed("address already in use".into())),
            || {
                installed.store(true, Ordering::SeqCst);
                Ok(())
            },
            || reverted.store(true, Ordering::SeqCst),
        );

        assert!(matches!(result, Err(CaptureError::DeviceFailed(_))));
        assert!(!install_called.load(Ordering::SeqCst));
        assert!(!revert_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tproxy_stop_signals_and_joins_all_dual_stack_listener_tasks() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let mut stops = Vec::new();
        let mut tasks = JoinSet::new();

        // IPv4 TCP/UDP plus IPv6 TCP/UDP.
        for _ in 0..4 {
            let (stop_tx, stop_rx) = oneshot::channel();
            stops.push(stop_tx);
            let stopped = stopped.clone();
            tasks.spawn(async move {
                let _ = stop_rx.await;
                stopped.fetch_add(1, Ordering::SeqCst);
            });
        }

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stop_listener_tasks(&mut stops, &mut tasks),
        )
        .await
        .expect("all listeners must stop promptly");

        assert!(stops.is_empty());
        assert!(tasks.is_empty());
        assert_eq!(stopped.load(Ordering::SeqCst), 4);
    }
}

const NFT_REDIRECT_TABLE: &str = "wuthercore_redirect";

fn install_auto_redirect(plan: &CapturePlan) -> Result<(), CaptureError> {
    let marks = &plan.auto_redirect_marks;
    let in_mark = marks
        .input
        .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK);
    let out_mark = tun_outbound_mark(plan);
    let reset_mark = marks
        .reset
        .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_RESET_MARK);

    let mut script = String::new();
    use std::fmt::Write;
    let t = NFT_REDIRECT_TABLE;
    let iface = &plan.interface_name;

    // 1. 创建独立 inet 表 + prerouting / output / mark chain
    let _ = writeln!(script, "add table inet {t}");
    let _ = writeln!(
        script,
        "add chain inet {t} prerouting {{ type filter hook prerouting priority -150; }}"
    );
    let _ = writeln!(
        script,
        "add chain inet {t} output {{ type filter hook output priority -150; }}"
    );
    let _ = writeln!(script, "add chain inet {t} mark_chain");
    let _ = writeln!(
        script,
        "add rule inet {t} prerouting iifname != \"{iface}\" jump mark_chain"
    );

    // 2. include / exclude 接口过滤（mark_chain 入口前拒绝）
    for excl in &plan.filters.exclude_interface {
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain iifname \"{excl}\" return"
        );
    }
    if !plan.filters.include_interface.is_empty() {
        let names: Vec<String> = plan
            .filters
            .include_interface
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect();
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain iifname != {{ {} }} return",
            names.join(", ")
        );
    }

    // 3. UID 过滤（exclude 优先；include 限定）
    for u in &plan.filters.exclude_uid {
        let _ = writeln!(script, "add rule inet {t} mark_chain meta skuid {u} return");
    }
    for (a, b) in &plan.filters.exclude_uid_range {
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain meta skuid {a}-{b} return"
        );
    }
    if !plan.filters.include_uid.is_empty() || !plan.filters.include_uid_range.is_empty() {
        // 把允许的 UID 集生成元素 set
        let mut allow: Vec<String> = plan
            .filters
            .include_uid
            .iter()
            .map(|u| u.to_string())
            .collect();
        for (a, b) in &plan.filters.include_uid_range {
            allow.push(format!("{a}-{b}"));
        }
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain meta skuid != {{ {} }} return",
            allow.join(", ")
        );
    }

    // 3b. GID 过滤（exclude 优先；include 限定）—— mihomo `meta skgid` 等价。
    for g in &plan.filters.exclude_gid {
        let _ = writeln!(script, "add rule inet {t} mark_chain meta skgid {g} return");
    }
    for (a, b) in &plan.filters.exclude_gid_range {
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain meta skgid {a}-{b} return"
        );
    }
    if !plan.filters.include_gid.is_empty() || !plan.filters.include_gid_range.is_empty() {
        let mut allow: Vec<String> = plan
            .filters
            .include_gid
            .iter()
            .map(|g| g.to_string())
            .collect();
        for (a, b) in &plan.filters.include_gid_range {
            allow.push(format!("{a}-{b}"));
        }
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain meta skgid != {{ {} }} return",
            allow.join(", ")
        );
    }

    // 4. loopback_address 排除（保留地址 / lan）
    for ip in &plan.loopback_addresses {
        let proto = match ip {
            std::net::IpAddr::V4(_) => "ip",
            std::net::IpAddr::V6(_) => "ip6",
        };
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain {proto} daddr {ip} return"
        );
    }

    // 4b. MAC 地址过滤（路由器 / LAN 接管场景）。
    for mac in &plan.filters.exclude_mac {
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain ether saddr {mac} return"
        );
    }
    if !plan.filters.include_mac.is_empty() {
        let macs: Vec<String> = plan.filters.include_mac.iter().map(|m| m.clone()).collect();
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain ether saddr != {{ {} }} return",
            macs.join(", ")
        );
    }

    // 4c. Android user → UID 偶合：Android user N 的 UID = N * 100000 + appUid。
    // include_android_user 字段当用户没有显式指定 include_uid 时生效。
    if plan.filters.include_uid.is_empty()
        && plan.filters.include_uid_range.is_empty()
        && !plan.filters.include_android_user.is_empty()
    {
        let mut ranges: Vec<String> = Vec::new();
        for u in &plan.filters.include_android_user {
            let lo = u * 100_000;
            let hi = lo + 99_999;
            ranges.push(format!("{lo}-{hi}"));
        }
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain meta skuid != {{ {} }} return",
            ranges.join(", ")
        );
    }

    // 5. exclude_mptcp：透传 MPTCP 不接管
    if plan.exclude_mptcp {
        let _ = writeln!(
            script,
            "add rule inet {t} mark_chain tcp option mptcp exists return"
        );
    }

    // 6. 主标记：进入 TUN 表
    let _ = writeln!(
        script,
        "add rule inet {t} mark_chain meta mark set {in_mark:#x}"
    );
    let _ = writeln!(
        script,
        "add rule inet {t} mark_chain ct state new tcp flags syn meta mark set {reset_mark:#x}"
    );
    // 7. 出方向：output 上 outbound mark 自身流量直接 accept，避免回环
    let _ = writeln!(
        script,
        "add rule inet {t} output meta mark {out_mark:#x} accept"
    );

    let create = script;
    // —— 后端选择：nft → iptables(+ip6tables) TPROXY → iptables NAT REDIRECT 三级降级。
    let nft_ok = has_tool("nft") && nft_load(&create);
    if nft_ok {
        // ip rule fwmark <in_mark> 走 TUN 自定义表
        if ip_rule_supported() {
            let table_s = plan.iproute2_table_index.to_string();
            let mark_s = format!("{in_mark:#x}");
            for fam in ["", "-6"] {
                let _ = run_ip_quiet(fam, &["rule", "add", "fwmark", &mark_s, "lookup", &table_s]);
            }
            if let Some(fb) = marks.fallback_rule_index {
                let prio_s = fb.to_string();
                for fam in ["", "-6"] {
                    let _ = run_ip_quiet(
                        fam,
                        &["rule", "add", "priority", &prio_s, "lookup", &table_s],
                    );
                }
            }
        }
        if let Some(q) = marks.nfqueue {
            let qs = q.to_string();
            let _ = run_quiet(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_REDIRECT_TABLE,
                    "prerouting",
                    "queue",
                    "num",
                    &qs,
                ],
            );
        }
        info!(
            target: "capture::linux",
            backend = "nftables",
            in_mark = format_args!("{in_mark:#x}"),
            out_mark = format_args!("{out_mark:#x}"),
            reset_mark = format_args!("{reset_mark:#x}"),
            "auto_redirect installed"
        );
        return Ok(());
    }

    // —— 回落 1：iptables + ip6tables TPROXY（双栈、Android root 通用）
    if has_tool("iptables") && install_iptables_tproxy(plan, in_mark, out_mark) {
        if ip_rule_supported() {
            let table_s = plan.iproute2_table_index.to_string();
            let mark_s = format!("{in_mark:#x}");
            for fam in ["", "-6"] {
                let _ = run_ip_quiet(fam, &["rule", "add", "fwmark", &mark_s, "lookup", &table_s]);
            }
        }
        info!(
            target: "capture::linux",
            backend = "iptables-tproxy",
            in_mark = format_args!("{in_mark:#x}"),
            out_mark = format_args!("{out_mark:#x}"),
            "auto_redirect installed (iptables/ip6tables TPROXY fallback; nft 不可用)"
        );
        return Ok(());
    }

    // —— 回落 2：iptables NAT REDIRECT（仅 TCP；UDP 走 fake-ip + TUN）
    if has_tool("iptables") && install_iptables_redirect(plan) {
        warn!(
            target: "capture::linux",
            backend = "iptables-nat-redirect",
            "auto_redirect installed (NAT REDIRECT；仅 TCP；UDP 由 fake-ip+TUN 承担)"
        );
        return Ok(());
    }

    Err(CaptureError::Doctor(
        "auto_redirect 全部后端失败：nft / iptables 都不可用。\
         Android 设备请确认已 root 且安装 magisk 模块 iptables 或 nftables；\
         否则请关掉 auto_redirect，使用 method=virtual_nic + stack=mixed 走纯 TUN。"
            .into(),
    ))
}

/// 把 nft 脚本通过 stdin 喂给 nft -f -；返回是否成功。
fn nft_load(script: &str) -> bool {
    use std::io::Write;
    let child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(script.as_bytes());
    }
    matches!(child.wait(), Ok(s) if s.success())
}

const IPT_CHAIN: &str = "WUTHERCORE_REDIR";
const IPT_TPROXY_PORT: &str = "7894";

/// iptables(+ip6tables) TPROXY 注入：mihomo 等价 Android `IptablesV4V6Tproxy` Tier。
fn install_iptables_tproxy(plan: &CapturePlan, in_mark: u32, out_mark: u32) -> bool {
    let in_mark_s = format!("{in_mark:#x}");
    let out_mark_s = format!("{out_mark:#x}");
    let mut all_ok = true;
    for ipt in iptables_binaries() {
        // 创建 / 复用 chain（已存在 → silent ok）
        let _ = run_quiet(ipt, &["-t", "mangle", "-N", IPT_CHAIN]);
        // 自身流量（mark 命中 out_mark）跳过
        let r1 = run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                IPT_CHAIN,
                "-m",
                "mark",
                "--mark",
                &out_mark_s,
                "-j",
                "RETURN",
            ],
        );
        // loopback / TUN iif 跳过
        let _ = run_quiet(
            ipt,
            &["-t", "mangle", "-A", IPT_CHAIN, "-i", "lo", "-j", "RETURN"],
        );
        let _ = run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                IPT_CHAIN,
                "-i",
                &plan.interface_name,
                "-j",
                "RETURN",
            ],
        );

        // UID/GID exclude
        for u in &plan.filters.exclude_uid {
            let val = u.to_string();
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    IPT_CHAIN,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        for (a, b) in &plan.filters.exclude_uid_range {
            let val = format!("{a}-{b}");
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    IPT_CHAIN,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        for g in &plan.filters.exclude_gid {
            let val = g.to_string();
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    IPT_CHAIN,
                    "-m",
                    "owner",
                    "--gid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        for (a, b) in &plan.filters.exclude_gid_range {
            let val = format!("{a}-{b}");
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    IPT_CHAIN,
                    "-m",
                    "owner",
                    "--gid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        // include_uid / include_gid 用 ! 否定 RETURN 实现"只放行集合"语义。
        if !plan.filters.include_uid.is_empty() || !plan.filters.include_uid_range.is_empty() {
            for u in &plan.filters.include_uid {
                let val = u.to_string();
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        IPT_CHAIN,
                        "-m",
                        "owner",
                        "!",
                        "--uid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
            for (a, b) in &plan.filters.include_uid_range {
                let val = format!("{a}-{b}");
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        IPT_CHAIN,
                        "-m",
                        "owner",
                        "!",
                        "--uid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
        }
        if !plan.filters.include_gid.is_empty() || !plan.filters.include_gid_range.is_empty() {
            for g in &plan.filters.include_gid {
                let val = g.to_string();
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        IPT_CHAIN,
                        "-m",
                        "owner",
                        "!",
                        "--gid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
            for (a, b) in &plan.filters.include_gid_range {
                let val = format!("{a}-{b}");
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        IPT_CHAIN,
                        "-m",
                        "owner",
                        "!",
                        "--gid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
        }

        // TPROXY mark + 投递到本地端口
        let r2 = run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                IPT_CHAIN,
                "-p",
                "tcp",
                "-j",
                "TPROXY",
                "--on-port",
                IPT_TPROXY_PORT,
                "--tproxy-mark",
                &in_mark_s,
            ],
        );
        let r3 = run_quiet(
            ipt,
            &[
                "-t",
                "mangle",
                "-A",
                IPT_CHAIN,
                "-p",
                "udp",
                "-j",
                "TPROXY",
                "--on-port",
                IPT_TPROXY_PORT,
                "--tproxy-mark",
                &in_mark_s,
            ],
        );
        // PREROUTING 跳本 chain
        let r4 = run_quiet(ipt, &["-t", "mangle", "-A", "PREROUTING", "-j", IPT_CHAIN]);
        for r in [r1, r2, r3, r4] {
            if !matches!(r, Some(s) if s.success()) {
                all_ok = false;
            }
        }
    }
    all_ok
}

/// iptables NAT REDIRECT 注入（只 TCP，UDP 不支持）—— Android 旧设备 / kernel 阉割时。
fn install_iptables_redirect(plan: &CapturePlan) -> bool {
    let mut all_ok = true;
    for ipt in iptables_binaries() {
        let _ = run_quiet(ipt, &["-t", "nat", "-N", IPT_CHAIN]);
        let _ = run_quiet(
            ipt,
            &["-t", "nat", "-A", IPT_CHAIN, "-i", "lo", "-j", "RETURN"],
        );
        let _ = run_quiet(
            ipt,
            &[
                "-t",
                "nat",
                "-A",
                IPT_CHAIN,
                "-i",
                &plan.interface_name,
                "-j",
                "RETURN",
            ],
        );
        // UID/GID 排除：owner-match 在 nat 表只对 OUTPUT 链有效。
        for u in &plan.filters.exclude_uid {
            let val = u.to_string();
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-m",
                    "owner",
                    "--uid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        for g in &plan.filters.exclude_gid {
            let val = g.to_string();
            let _ = run_quiet(
                ipt,
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-m",
                    "owner",
                    "--gid-owner",
                    &val,
                    "-j",
                    "RETURN",
                ],
            );
        }
        let r = run_quiet(
            ipt,
            &[
                "-t",
                "nat",
                "-A",
                IPT_CHAIN,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                IPT_TPROXY_PORT,
            ],
        );
        let r2 = run_quiet(ipt, &["-t", "nat", "-A", "PREROUTING", "-j", IPT_CHAIN]);
        for x in [r, r2] {
            if !matches!(x, Some(s) if s.success()) {
                all_ok = false;
            }
        }
    }
    all_ok
}

/// 返回当前可用的 iptables binaries：iptables / ip6tables（v6 可选）。
fn iptables_binaries() -> Vec<&'static str> {
    let mut out = Vec::new();
    if has_tool("iptables") {
        out.push("iptables");
    }
    if has_tool("ip6tables") {
        out.push("ip6tables");
    }
    out
}

fn revert_auto_redirect(plan: &CapturePlan) {
    // nft：best-effort 删表
    let _ = run_quiet("nft", &["delete", "table", "inet", NFT_REDIRECT_TABLE]);

    // iptables 后端 best-effort 卸载（chain 不存在的报错全部静默）
    for ipt in iptables_binaries() {
        for table in ["mangle", "nat"] {
            let _ = run_quiet(ipt, &["-t", table, "-D", "PREROUTING", "-j", IPT_CHAIN]);
            // NAT 模式下 owner-match 写在 OUTPUT 链 → 也撤掉
            for u in &plan.filters.exclude_uid {
                let val = u.to_string();
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "OUTPUT",
                        "-m",
                        "owner",
                        "--uid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
            for g in &plan.filters.exclude_gid {
                let val = g.to_string();
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "OUTPUT",
                        "-m",
                        "owner",
                        "--gid-owner",
                        &val,
                        "-j",
                        "RETURN",
                    ],
                );
            }
            let _ = run_quiet(ipt, &["-t", table, "-F", IPT_CHAIN]);
            let _ = run_quiet(ipt, &["-t", table, "-X", IPT_CHAIN]);
        }
    }

    // ip rule 撤销
    if ip_rule_supported() {
        let table_s = plan.iproute2_table_index.to_string();
        let mark_s = format!(
            "{:#x}",
            plan.auto_redirect_marks
                .input
                .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_INPUT_MARK)
        );
        for fam in ["", "-6"] {
            let _ = run_ip_quiet(fam, &["rule", "del", "fwmark", &mark_s, "lookup", &table_s]);
        }
        if let Some(fb) = plan.auto_redirect_marks.fallback_rule_index {
            let prio_s = fb.to_string();
            for fam in ["", "-6"] {
                let _ = run_ip_quiet(fam, &["rule", "del", "priority", &prio_s]);
            }
        }
    }
}

/// TUN 主 packet loop —— 读 IP 包 → 解析 → 推 [`CaptureEvent`]。
///
/// 注意：本 loop **不做** TCP 终结（user-stack）。它只发现"看到了一个新流"
/// 的事件，让 supervisor 调度 `runtime.dial`。完整的 TCP / UDP 双向转发
/// （smoltcp 用户栈）放在 M4-Phase2，此处先打通"包入/事件出"通道。
async fn packet_loop(
    device: Arc<dyn TunIo>,
    mtu: usize,
    events: mpsc::Sender<CaptureEvent>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut buf = vec![0u8; mtu + 64];
    // 简单去重：只对每个新流（src,dst,proto）发一次事件，避免每包都 dial。
    use std::collections::HashSet;
    let mut seen: HashSet<(std::net::SocketAddr, std::net::SocketAddr, &'static str)> =
        HashSet::new();
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            r = device.read_packet(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(target: "capture::linux::tun", error = %e, "read failed; loop exit");
                        break;
                    }
                };
                let parsed = match parse_tun_frame(&buf[..n]) {
                    Ok(p) => p.packet,
                    Err(_) => continue, // 分片 / ICMP / 校验失败：丢弃
                };
                let net = match parsed.l4 {
                    L4::Tcp(_) => "tcp",
                    L4::Udp(_) => "udp",
                    L4::Other(_) => continue,
                };
                let src = match parsed.src_socket() { Some(s) => s, None => continue };
                let dst = match parsed.dst_socket() { Some(s) => s, None => continue };
                if !seen.insert((src, dst, net)) {
                    continue;
                }
                let evt = CaptureEvent {
                    original_dst: dst,
                    source: src,
                    network: net,
                    fake_host: None,
                };
                if events.send(evt).await.is_err() {
                    debug!(target: "capture::linux::tun", "events channel closed; loop exit");
                    break;
                }
            }
        }
    }
}

/* ---------------- LinuxTproxy ---------------- */

pub struct LinuxTproxy {
    plan: CapturePlan,
    state: Mutex<TproxyState>,
}

#[derive(Default)]
struct TproxyState {
    on: bool,
    listener_tasks: Option<JoinSet<()>>,
    listener_stops: Vec<oneshot::Sender<()>>,
}

struct TproxyRuleCleanup<'a> {
    plan: &'a CapturePlan,
    armed: bool,
}

impl Drop for TproxyRuleCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            LinuxTproxy::revert_rules(self.plan);
        }
    }
}

impl LinuxTproxy {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TproxyState::default()),
        }
    }

    fn install_rules(plan: &CapturePlan, outbound_mark: u32) -> Result<(), CaptureError> {
        if !has_tool("iptables") {
            return Err(CaptureError::Doctor(
                "TPROXY 需要 iptables mangle/TPROXY 支持；当前找不到 iptables".into(),
            ));
        }
        if plan.ipv6_enabled && !has_tool("ip6tables") {
            return Err(CaptureError::Doctor(
                "IPv6 TPROXY 需要 ip6tables mangle/TPROXY 支持；当前找不到 ip6tables".into(),
            ));
        }
        crate::linux_netlink::install_tproxy_policy(
            plan.ipv6_enabled,
            tproxy_rules::TPROXY_FWMARK,
            tproxy_rules::TPROXY_ROUTE_TABLE,
        )
        .map_err(|reason| {
            CaptureError::Doctor(format!(
                "TPROXY native netlink policy-route setup failed: {reason}"
            ))
        })?;

        for cmd in tproxy_rules::setup_commands(plan, outbound_mark)
            .into_iter()
            .filter(|cmd| cmd.program != "ip")
        {
            run_tproxy_command(&cmd).map_err(|reason| {
                crate::linux_netlink::remove_tproxy_policy(
                    plan.ipv6_enabled,
                    tproxy_rules::TPROXY_FWMARK,
                    tproxy_rules::TPROXY_ROUTE_TABLE,
                );
                CaptureError::Doctor(format!(
                    "TPROXY rule command failed: `{}`: {reason}",
                    cmd.render()
                ))
            })?;
        }
        info!(
            target: "capture::tproxy::rules",
            proxy_mark = format_args!("{:#x}", tproxy_rules::TPROXY_FWMARK),
            outbound_mark = format_args!("{outbound_mark:#x}"),
            ipv6 = plan.ipv6_enabled,
            "iptables/ip6tables TPROXY rules installed"
        );
        Ok(())
    }

    fn revert_rules(plan: &CapturePlan) {
        for cmd in tproxy_rules::cleanup_commands(plan)
            .into_iter()
            .filter(|cmd| cmd.program != "ip")
        {
            if let Err(reason) = run_tproxy_command(&cmd) {
                debug!(
                    target: "capture::tproxy::rules",
                    cmd = %cmd.render(),
                    %reason,
                    "TPROXY cleanup command failed"
                );
            }
        }
        crate::linux_netlink::remove_tproxy_policy(
            plan.ipv6_enabled,
            tproxy_rules::TPROXY_FWMARK,
            tproxy_rules::TPROXY_ROUTE_TABLE,
        );
    }
}

fn run_tproxy_command(cmd: &tproxy_rules::TproxyCommand) -> Result<(), String> {
    debug!(target: "capture::tproxy::rules", cmd = %cmd.render(), "exec");
    let output = std::process::Command::new(cmd.program)
        .args(&cmd.args)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        Err(format!("exit status {}", output.status))
    } else {
        Err(format!("exit status {}: {stderr}", output.status))
    }
}

fn prepare_tproxy_start<L>(
    bind: impl FnOnce() -> Result<L, CaptureError>,
    install_rules: impl FnOnce() -> Result<(), CaptureError>,
    revert_rules: impl FnOnce(),
) -> Result<L, CaptureError> {
    let listeners = bind()?;
    if let Err(error) = install_rules() {
        drop(listeners);
        revert_rules();
        return Err(error);
    }
    Ok(listeners)
}

async fn stop_listener_tasks(stops: &mut Vec<oneshot::Sender<()>>, tasks: &mut JoinSet<()>) {
    // Signal every address-family/protocol listener before awaiting any one of
    // them. If this future is cancelled while joining, JoinSet::drop aborts all
    // remaining tasks and the caller's rule cleanup guard removes the routes.
    for stop in stops.drain(..) {
        let _ = stop.send(());
    }
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            warn!(target: "capture", %error, "transparent listener task join failed");
        }
    }
}

#[async_trait]
impl CaptureEngine for LinuxTproxy {
    fn kind(&self) -> EngineKind {
        EngineKind::Tproxy
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if g.on {
            return Ok(());
        }
        crate::platform::linux_caps::require_net_admin("TPROXY capture")
            .map_err(CaptureError::Doctor)?;
        let outbound_mark = self
            .plan
            .auto_redirect_marks
            .output
            .unwrap_or(tproxy_rules::TPROXY_FWMARK);
        let listeners = prepare_tproxy_start(
            || {
                crate::platform::linux_tproxy::bind_tproxy_listener_set(
                    tproxy_rules::TPROXY_PORT,
                    self.plan.ipv6_enabled,
                )
            },
            || Self::install_rules(&self.plan, outbound_mark),
            || Self::revert_rules(&self.plan),
        )?;
        let mut listener_tasks = JoinSet::new();
        let mut listener_stops = Vec::with_capacity(listeners.len() * 2);
        let mut bound_addrs = Vec::with_capacity(listeners.len());
        let inbound_tag: Arc<str> = Arc::from(self.plan.tag.as_str());

        for listeners in listeners {
            let (tcp_listener, udp_socket, bound) = listeners.into_parts();
            let family = if bound.is_ipv6() { "ipv6" } else { "ipv4" };
            bound_addrs.push(bound);

            let (stop_tcp_tx, stop_tcp_rx) = oneshot::channel::<()>();
            listener_stops.push(stop_tcp_tx);
            let evt_tcp = events.clone();
            let rt_tcp = runtime.clone();
            let tcp_inbound_tag = inbound_tag.clone();
            listener_tasks.spawn(async move {
                if let Err(error) = crate::platform::linux_tproxy::run_tcp_tproxy(
                    tcp_listener,
                    evt_tcp,
                    rt_tcp,
                    tcp_inbound_tag,
                    stop_tcp_rx,
                )
                .await
                {
                    warn!(
                        target: "capture::tproxy",
                        family,
                        %error,
                        "tcp tproxy exited"
                    );
                }
            });

            let (stop_udp_tx, stop_udp_rx) = oneshot::channel::<()>();
            listener_stops.push(stop_udp_tx);
            let evt_udp = events.clone();
            let rt_udp = runtime.clone();
            let udp_inbound_tag = inbound_tag.clone();
            listener_tasks.spawn(async move {
                if let Err(error) = crate::platform::linux_tproxy::run_udp_tproxy(
                    udp_socket,
                    evt_udp,
                    rt_udp,
                    udp_inbound_tag,
                    stop_udp_rx,
                )
                .await
                {
                    warn!(
                        target: "capture::tproxy",
                        family,
                        %error,
                        "udp tproxy exited"
                    );
                }
            });
        }

        g.listener_tasks = Some(listener_tasks);
        g.listener_stops = listener_stops;
        g.on = true;
        info!(
            target: "capture",
            addresses = ?bound_addrs,
            "linux tproxy started (dual-protocol listeners ready)"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !g.on {
            return Ok(());
        }
        // Keep cleanup cancellation-safe: after the stop signals are sent,
        // any cancellation while awaiting child tasks still removes policy
        // routing/firewall state through this synchronous Drop guard.
        let mut rule_cleanup = TproxyRuleCleanup {
            plan: &self.plan,
            armed: true,
        };
        let mut listener_tasks = g.listener_tasks.take().unwrap_or_else(JoinSet::new);
        let mut listener_stops = std::mem::take(&mut g.listener_stops);
        g.on = false;
        stop_listener_tasks(&mut listener_stops, &mut listener_tasks).await;
        Self::revert_rules(&self.plan);
        rule_cleanup.armed = false;
        info!(target: "capture", "linux tproxy stopped");
        Ok(())
    }
}

/* ---------------- LinuxRedirect ---------------- */

pub struct LinuxRedirect {
    plan: CapturePlan,
    state: Mutex<RedirectState>,
}

#[derive(Default)]
struct RedirectState {
    on: bool,
    backend: Option<AutoRedirectBackend>,
    listener_tasks: Option<JoinSet<()>>,
    listener_stops: Vec<oneshot::Sender<()>>,
}

impl LinuxRedirect {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(RedirectState::default()),
        }
    }
}

#[async_trait]
impl CaptureEngine for LinuxRedirect {
    fn kind(&self) -> EngineKind {
        EngineKind::Redirect
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if g.on {
            return Ok(());
        }
        crate::platform::linux_caps::require_net_admin("REDIRECT capture")
            .map_err(CaptureError::Doctor)?;
        if g.backend.is_some() || g.listener_tasks.is_some() {
            return Err(CaptureError::Nat(
                "redirect has a partial activation ledger; stop must clean it before retry".into(),
            ));
        }

        // Bind before publishing firewall rules. This proves both enabled
        // address families are serviceable and gives nftables exact ports.
        let listeners = bind_tcp_redirect_listener_set(self.plan.ipv6_enabled)?;
        let ports =
            redirect_ports_from_addrs(listeners.iter().map(RedirectTcpListener::local_addr))?;

        // A checked, atomic nft batch is the publication boundary. If this
        // fails, dropping the pre-bound listeners leaves no host mutation.
        let backend = linux_auto_redirect::install(&self.plan, ports)?;

        let mut listener_tasks = JoinSet::new();
        let mut listener_stops = Vec::with_capacity(listeners.len());
        let mut bound_addrs = Vec::with_capacity(listeners.len());
        let inbound_tag: Arc<str> = Arc::from(self.plan.tag.as_str());
        for listener in listeners {
            let (listener, local_addr) = listener.into_parts();
            bound_addrs.push(local_addr);
            let (stop_tx, stop_rx) = oneshot::channel();
            listener_stops.push(stop_tx);
            let events = events.clone();
            let runtime = runtime.clone();
            let inbound_tag = inbound_tag.clone();
            listener_tasks.spawn(async move {
                if let Err(error) =
                    run_tcp_redirect(listener, events, runtime, inbound_tag, stop_rx).await
                {
                    warn!(
                        target: "capture::redirect",
                        %local_addr,
                        %error,
                        "TCP REDIRECT listener stopped with error"
                    );
                }
            });
        }

        g.backend = Some(backend);
        g.listener_tasks = Some(listener_tasks);
        g.listener_stops = listener_stops;
        g.on = true;
        info!(
            target: "capture::redirect",
            addresses = ?bound_addrs,
            ?backend,
            "linux/android TCP REDIRECT started"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !g.on && g.backend.is_none() && g.listener_tasks.is_none() {
            return Ok(());
        }
        if let Some(backend) = g.backend {
            // Keep the ledger intact on failure so a supervisor retry can
            // finish cleanup instead of forgetting live host rules.
            linux_auto_redirect::uninstall(backend)?;
            g.backend = None;
        }
        let mut listener_tasks = g.listener_tasks.take().unwrap_or_else(JoinSet::new);
        let mut listener_stops = std::mem::take(&mut g.listener_stops);
        g.on = false;
        stop_listener_tasks(&mut listener_stops, &mut listener_tasks).await;
        info!(target: "capture::redirect", "linux/android TCP REDIRECT stopped");
        Ok(())
    }
}
