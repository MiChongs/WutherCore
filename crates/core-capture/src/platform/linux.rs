//! Linux 后端：TUN（/dev/net/tun, ioctl TUNSETIFF）+ TProxy + nftables / iptables。
//!
//! M4 完整化：
//! * `EngineKind::Tun` —— 通过 [`linux_tun_io::open`] 拿到真实 fd；spawn packet
//!   read loop，把 IP 包解析成 [`CaptureEvent`] 推到 channel；写默认路由。
//! * `EngineKind::Tproxy` —— 安装 nftables 临时规则集，把 mark 流量重定向到本地
//!   tproxy socket；停止时通过 nft delete table 回滚。
//! * `EngineKind::Redirect` —— iptables -t nat REDIRECT，仅 TCP。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind},
    packet::{L4, parse_tun_frame},
    platform::linux_tun_io,
    route_table::{ManagedRoute, RouteTable},
    tproxy_rules,
    tun_io::TunIo,
    tun_logging::root_tun_summary,
};

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
        // tun-rs DeviceBuilder（Linux/Windows/macOS）已配好地址 + MTU + link up。
        // Android root 走旧 linux_tun_io（仅 ioctl TUNSETIFF），需要手动配置。
        if device.is_preconfigured() {
            // VpnService：Android framework 已配
            return Ok(());
        }

        // 检查接口是否已经 UP（tun-rs DeviceBuilder 会自动处理）
        let snapshot = log_iface_snapshot(&plan.interface_name);
        if snapshot.contains("UP") && snapshot.contains(&plan.tun_v4_cidr.addr().to_string()) {
            return Ok(());
        }

        // 未配置（Android root linux_tun_io 路径）：手动 addr + mtu + link up
        let v4 = plan.tun_v4_addr_cidr();
        let mtu_s = plan.mtu.to_string();
        let _ = run_logged(
            "root-tun.link-mtu",
            "ip",
            &["link", "set", "dev", &plan.interface_name, "mtu", &mtu_s],
            true,
        );
        let _ = configure_addr_with_ip(false, &v4, &plan.interface_name);
        if let Some(ref v6_cidr) = plan.tun_v6_addr_cidr() {
            if is_ipv6_available(&plan.interface_name) {
                let _ = configure_addr_with_ip(true, v6_cidr, &plan.interface_name);
            } else {
                debug!(
                    target: "capture::linux::tun",
                    iface = %plan.interface_name,
                    "IPv6 disabled on system or interface; skipping v6 addr config"
                );
            }
        }
        let _ = run_logged(
            "root-tun.link-up",
            "ip",
            &["link", "set", "dev", &plan.interface_name, "up"],
            true,
        );
        if cfg!(any(target_os = "linux", target_os = "android")) {
            let _ = linux_tun_io::set_link_up_ioctl(&plan.interface_name);
        }
        let _ = log_iface_snapshot(&plan.interface_name);
        Ok(())
    }
}

fn configure_addr_with_ip(v6: bool, cidr: &str, iface: &str) -> bool {
    let fam_args = if v6 { vec!["-6", "addr"] } else { vec!["addr"] };
    let mut replace_args: Vec<&str> = fam_args.clone();
    replace_args.extend_from_slice(&["replace", cidr, "dev", iface]);
    let r = run_logged("root-tun.addr-replace", "ip", &replace_args, false);
    if matches!(r, Some(s) if s.success()) {
        return true;
    }
    // 回落 add；EEXIST 视为 OK
    let mut add_args: Vec<&str> = fam_args;
    add_args.extend_from_slice(&["add", cidr, "dev", iface]);
    match std::process::Command::new("ip").args(&add_args).output() {
        Ok(out) if out.status.success() => {
            debug!(
                target: "capture::linux::cmd",
                phase = "root-tun.addr-add",
                cmd = "ip",
                args = ?add_args,
                "command ok"
            );
            true
        }
        Ok(out) => {
            let stderr_raw = String::from_utf8_lossy(&out.stderr);
            let stderr = stderr_raw.to_lowercase();
            if stderr.contains("file exists") || stderr.contains("rtnetlink answers: file exists") {
                true
            } else if stderr.contains("permission denied") {
                // SELinux or missing CAP_NET_ADMIN for this address family.
                // On Android, IPv6 addr config often requires root + permissive SELinux.
                debug!(
                    target: "capture::linux::tun",
                    args = ?add_args,
                    stderr = %stderr_raw.trim(),
                    "ip addr config denied (likely IPv6 restricted by SELinux/kernel)"
                );
                false
            } else {
                warn!(
                    target: "capture::linux::tun",
                    args = ?add_args,
                    stderr = %stderr_raw.trim(),
                    "ip addr 配置失败"
                );
                false
            }
        }
        Err(e) => {
            warn!(
                target: "capture::linux::tun",
                args = ?add_args,
                error = %e,
                "ip addr spawn failed"
            );
            false
        }
    }
}

fn log_iface_snapshot(iface: &str) -> String {
    if let Ok(out) = std::process::Command::new("ip")
        .args(["addr", "show", "dev", iface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        debug!(
            target: "capture::linux::tun",
            iface,
            status = ?out.status.code(),
            stdout = %stdout,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "root tun interface snapshot"
        );
        stdout
    } else {
        String::new()
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
        info!(
            target: "capture::linux::tun",
            requested_iface = %self.plan.interface_name,
            effective_iface = %effective_plan.interface_name,
            device_mtu = device.mtu(),
            platform_preconfigured = !manage_linux_config,
            "root tun device opened"
        );
        if manage_linux_config {
            Self::configure_iface(&effective_plan, device.as_ref())?;

            // auto_route：将所有目标流量导入 TUN（按 sing-box 默认拆 0/1 + 128/1 双半区
            // 路由，避免覆盖系统已有的 0/0 默认路由），并写入指定 iproute2 表。
            if effective_plan.auto_route {
                install_auto_route(&self.routes, &effective_plan);
                // 内核级身份旁路：在 OUTPUT/mangle 链上为 excluded UID/GID/package
                // 打 fwmark = tun_outbound_mark，触发 install_auto_route 注册的
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
            }
            // strict_route：在主表里拒绝其它一切，强制流量必经 TUN。
            if effective_plan.strict_route {
                install_strict_route(&effective_plan);
            }
            // auto_redirect：nftables 重定向 + fwmark；输入/输出/reset mark 全量配置。
            if effective_plan.auto_redirect {
                if let Err(e) = install_auto_redirect(&effective_plan) {
                    warn!(target: "capture::linux", error = %e, "auto_redirect install failed");
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
            let mtu = self.plan.mtu as usize;
            let handle = tokio::spawn(async move {
                packet_loop(dev_for_loop, mtu, events, stop_rx).await;
            });
            g.loop_handle = Some(handle);
        } else {
            // 把 stop_rx drop，避免空挂；events 通道由 supervisor 持有但无人写。
            let _ = stop_rx;
            let _ = events;
        }

        g.platform_preconfigured = !manage_linux_config;
        g.device = Some(device);
        g.stop_tx = Some(stop_tx);
        g.started = true;
        info!(
            target: "capture::linux::tun",
            iface = %self.plan.interface_name,
            mtu = self.plan.mtu,
            dispatcher_owns_tun,
            "linux tun started"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        info!(
            target: "capture::linux::tun",
            iface = %self.plan.interface_name,
            auto_route = self.plan.auto_route,
            auto_redirect = self.plan.auto_redirect,
            strict_route = self.plan.strict_route,
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
            info!(
                target: "capture::linux::tun",
                iface = %self.plan.interface_name,
                "tun device was platform-preconfigured; skip linux route/rule cleanup"
            );
            info!(target: "capture", iface = %self.plan.interface_name, "linux tun stopped");
            return Ok(());
        }
        if self.plan.auto_redirect {
            revert_auto_redirect(&self.plan);
        }
        if self.plan.strict_route {
            revert_strict_route(&self.plan);
        }
        // 撤销 auto_route 安装的 main-table bypass rule
        if self.plan.auto_route {
            // 内核级身份旁路：与 install 对称，先于 ip rule 清理顺序由
            // iptables -X 自身管理（与 catch-all 规则无依赖关系）。
            crate::platform::linux_identity_bypass::revert(&self.plan);
        }
        if self.plan.auto_route && ip_rule_supported() {
            let out_mark = tun_outbound_mark(&self.plan);
            let mark_s = format!("{out_mark:#x}");
            let bypass_prio =
                outbound_bypass_rule_priority(self.plan.iproute2_rule_index).to_string();
            let cleanup_tables = outbound_bypass_cleanup_tables();
            for fam in ["", "-6"] {
                for lookup in &cleanup_tables {
                    let _ = run_ip_logged(
                        "root-tun.rule-del.outbound-bypass",
                        fam,
                        &[
                            "rule",
                            "del",
                            "priority",
                            &bypass_prio,
                            "fwmark",
                            &mark_s,
                            "lookup",
                            lookup.as_str(),
                        ],
                        false,
                    );
                    // 兼容清理旧版本写入的无 priority 规则。
                    let _ = run_ip_logged(
                        "root-tun.rule-del.legacy-outbound-bypass",
                        fam,
                        &["rule", "del", "fwmark", &mark_s, "lookup", lookup.as_str()],
                        false,
                    );
                }
                let _ = run_ip_logged(
                    "root-tun.rule-del.legacy-0xff-bypass",
                    fam,
                    &["rule", "del", "fwmark", "0xff", "lookup", "main"],
                    false,
                );
            }
            // TUN 子网规则清理。
            let tun_subnet_prio =
                tun_subnet_rule_priority(self.plan.iproute2_rule_index).to_string();
            let table_s_cleanup = self.plan.iproute2_table_index.to_string();
            let v4_cidr = self.plan.tun_v4_cidr.to_string();
            let _ = run_ip_logged(
                "root-tun.rule-del.tun-subnet",
                "",
                &[
                    "rule",
                    "del",
                    "priority",
                    &tun_subnet_prio,
                    "to",
                    &v4_cidr,
                    "lookup",
                    &table_s_cleanup,
                ],
                false,
            );
            if let Some(v6_cidr) = self.plan.tun_v6_cidr {
                let v6_cidr = v6_cidr.to_string();
                let _ = run_ip_logged(
                    "root-tun.rule-del.tun-subnet",
                    "-6",
                    &[
                        "rule",
                        "del",
                        "priority",
                        &tun_subnet_prio,
                        "to",
                        &v6_cidr,
                        "lookup",
                        &table_s_cleanup,
                    ],
                    false,
                );
            }
            // 静态 route-exclude-address 绕过 TUN 表；动态 set 在用户态强制 DIRECT。
            // Android 的默认网络通常不在 main 表，清理时同时覆盖 main 与当前探测表。
            let route_bypass_prio =
                route_bypass_rule_priority(self.plan.iproute2_rule_index).to_string();
            for net in &self.plan.route_exclude_addresses {
                let dest = net.to_string();
                let fam = route_rule_family(net);
                for lookup in &cleanup_tables {
                    let _ = run_ip_logged(
                        "root-tun.rule-del.route-exclude-bypass",
                        fam,
                        &[
                            "rule",
                            "del",
                            "priority",
                            &route_bypass_prio,
                            "to",
                            &dest,
                            "lookup",
                            lookup.as_str(),
                        ],
                        false,
                    );
                }
            }
            // 主 ip rule（lookup <custom>）也撤掉。
            let prio_s = self.plan.iproute2_rule_index.to_string();
            let table_s = self.plan.iproute2_table_index.to_string();
            if auto_route_uses_catch_all_rule(&self.plan) {
                for fam in ["", "-6"] {
                    let _ = run_ip_logged(
                        "root-tun.rule-del.catch-all",
                        fam,
                        &["rule", "del", "priority", &prio_s, "lookup", &table_s],
                        false,
                    );
                }
            } else {
                for net in &self.plan.route_addresses {
                    let dest = net.to_string();
                    let fam = route_rule_family(net);
                    let _ = run_ip_logged(
                        "root-tun.rule-del.static-route-address",
                        fam,
                        &[
                            "rule", "del", "priority", &prio_s, "to", &dest, "lookup", &table_s,
                        ],
                        false,
                    );
                }
            }
            // 兼容清理旧版本 catch-all 规则。当前配置本身就是 catch-all 时，
            // 上面的 `root-tun.rule-del.catch-all` 已经用完全相同的 selector
            // 删除过；重复执行只会产生误导性的 ENOENT 日志。
            if should_cleanup_legacy_catch_all_rule(&self.plan) {
                for fam in ["", "-6"] {
                    let _ = run_ip_logged(
                        "root-tun.rule-del.legacy-catch-all",
                        fam,
                        &["rule", "del", "priority", &prio_s, "lookup", &table_s],
                        false,
                    );
                }
            }
        }
        self.routes.revert_all();
        let _ = run_quiet(
            "ip",
            &[
                "tuntap",
                "del",
                "dev",
                &self.plan.interface_name,
                "mode",
                "tun",
            ],
        );
        g.started = false;
        info!(target: "capture", iface = %self.plan.interface_name, "linux tun stopped");
        Ok(())
    }
}

/* ---------------- auto_route / strict_route / auto_redirect helpers ---------------- */

fn install_auto_route(routes: &RouteTable, plan: &CapturePlan) {
    // sing-box 风格双半区：0.0.0.0/1 + 128.0.0.0/1 / ::/1 + 8000::/1
    // 避免与已有 0.0.0.0/0 互相覆盖；同时统一使用自定义路由表 + ip rule。
    let table = plan.iproute2_table_index;
    let rule_idx = plan.iproute2_rule_index;
    let mut cidrs: Vec<&str> = vec!["0.0.0.0/1", "128.0.0.0/1"];
    if plan.tun_v6_cidr.is_some() && is_ipv6_available(&plan.interface_name) {
        cidrs.extend_from_slice(&["::/1", "8000::/1"]);
    }
    for cidr in cidrs {
        if let Ok(net) = cidr.parse() {
            let _ = routes.add(ManagedRoute {
                dest: net,
                gateway: None,
                interface: plan.interface_name.clone(),
                metric: 0,
                table: Some(table),
            });
        }
    }
    let table_s = table.to_string();
    let prio_s = rule_idx.to_string();
    if ip_rule_supported() {
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
            "install root tun policy routing"
        );
        // ⭐ 关键：让带 SO_MARK 的 outbound socket 先绕 TUN 走主路由表，否则
        // 所有代理出站连接节点 IP 时都会被 TUN 截走 → 无限自循环。
        // priority 必须小于 catch-all TUN rule；Linux ip rule 按 priority 升序匹配。
        // 探测默认出站接口名，注入全局 SO_BINDTODEVICE（对标 mihomo DefaultInterface）
        if let Some(iface) = probe_outbound_interface() {
            debug!(
                target: "capture::linux::tun",
                iface = %iface,
                "detected default outbound interface for SO_BINDTODEVICE"
            );
            core_outbound::set_outbound_interface(Some(iface));
        }
        let out_mark = tun_outbound_mark(plan);
        let mark_s = format!("{out_mark:#x}");
        let outbound_bypass_table = outbound_bypass_lookup_table();
        let bypass_prio = outbound_bypass_rule_priority(rule_idx).to_string();
        let route_bypass_prio = route_bypass_rule_priority(rule_idx).to_string();
        for fam in ["", "-6"] {
            let _ = run_ip_logged(
                "root-tun.rule-add.outbound-bypass",
                fam,
                &[
                    "rule",
                    "add",
                    "fwmark",
                    &mark_s,
                    "lookup",
                    &outbound_bypass_table,
                    "priority",
                    &bypass_prio,
                ],
                true,
            );
        }
        // ⭐ TUN 自身子网必须走 TUN 表，优先级高于 route-exclude-bypass，否则
        // system stack NAT 内部流量（listener SYN-ACK 发往 inet4_next 172.19.0.2）
        // 会被 172.16.0.0/12 的 exclude 规则截走 → rmnet_data3 → 丢包 → TCP 全死。
        let tun_subnet_prio = tun_subnet_rule_priority(rule_idx).to_string();
        let v4_cidr = plan.tun_v4_cidr.to_string();
        let _ = run_ip_logged(
            "root-tun.rule-add.tun-subnet",
            "",
            &[
                "rule",
                "add",
                "priority",
                &tun_subnet_prio,
                "to",
                &v4_cidr,
                "lookup",
                &table_s,
            ],
            true,
        );
        if let Some(v6_cidr) = plan.tun_v6_cidr {
            let v6_cidr = v6_cidr.to_string();
            let _ = run_ip_logged(
                "root-tun.rule-add.tun-subnet",
                "-6",
                &[
                    "rule",
                    "add",
                    "priority",
                    &tun_subnet_prio,
                    "to",
                    &v6_cidr,
                    "lookup",
                    &table_s,
                ],
                true,
            );
        }
        // 静态 route-exclude-address 必须在策略路由层绕回真实默认网络表；
        // Android 的 main 表经常没有物理默认路由，硬写 main 会让 DIRECT 断网。
        for net in &plan.route_exclude_addresses {
            let dest = net.to_string();
            let fam = route_rule_family(net);
            let _ = run_ip_logged(
                "root-tun.rule-add.route-exclude-bypass",
                fam,
                &[
                    "rule",
                    "add",
                    "priority",
                    &route_bypass_prio,
                    "to",
                    &dest,
                    "lookup",
                    &outbound_bypass_table,
                ],
                true,
            );
        }
        if auto_route_uses_catch_all_rule(plan) {
            for fam in ["", "-6"] {
                let _ = run_ip_logged(
                    "root-tun.rule-add.catch-all",
                    fam,
                    &["rule", "add", "priority", &prio_s, "lookup", &table_s],
                    true,
                );
            }
        } else {
            // 纯静态 route_address 白名单时只把命中目标导入 TUN。
            // 如果配置了 route_address_set，动态集合无法用 ip rule 表达，
            // 必须用 catch-all + 用户态 DIRECT fallback。
            for net in &plan.route_addresses {
                let dest = net.to_string();
                let fam = route_rule_family(net);
                let _ = run_ip_logged(
                    "root-tun.rule-add.static-route-address",
                    fam,
                    &[
                        "rule", "add", "priority", &prio_s, "to", &dest, "lookup", &table_s,
                    ],
                    true,
                );
            }
        }
        info!(
            target: "capture::linux",
            table,
            rule_priority = rule_idx,
            bypass_rule_priority = %bypass_prio,
            bypass_lookup = %outbound_bypass_table,
            route_bypass_rule_priority = %route_bypass_prio,
            outbound_mark = format_args!("{out_mark:#x}"),
            "auto_route installed (TUN table + bypass for outbound mark)"
        );
    } else {
        warn!(
            target: "capture::linux",
            "ip rule 命令不可用（Android toybox 通常不带）—— auto_route 需要策略路由才能避免 TUN 回环，请安装 iproute2/busybox ip"
        );
    }
}

fn tun_outbound_mark(plan: &CapturePlan) -> u32 {
    plan.auto_redirect_marks
        .output
        .unwrap_or(core_config::model::DEFAULT_AUTO_REDIRECT_OUTPUT_MARK)
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

fn outbound_bypass_lookup_table() -> String {
    for (family, target) in [("", "1.1.1.1"), ("-6", "2606:4700:4700::1111")] {
        if let Some(table) = probe_route_get_table(family, target) {
            return table;
        }
    }
    "main".to_string()
}

fn outbound_bypass_cleanup_tables() -> Vec<String> {
    let mut tables = vec!["main".to_string()];
    let current = outbound_bypass_lookup_table();
    if !tables.contains(&current) {
        tables.push(current);
    }
    tables
}

fn probe_route_get_table(family_arg: &str, target: &str) -> Option<String> {
    let mut args = Vec::new();
    if !family_arg.is_empty() {
        args.push(family_arg);
    }
    args.extend_from_slice(&["route", "get", target]);
    let out = match std::process::Command::new("ip").args(&args).output() {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            debug!(
                target: "capture::linux::tun",
                args = ?args,
                status = ?out.status.code(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "default route table probe failed"
            );
            return None;
        }
        Err(e) => {
            debug!(
                target: "capture::linux::tun",
                args = ?args,
                error = %e,
                "default route table probe spawn failed"
            );
            return None;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let table = crate::platform::route_probe::outbound_bypass_table_from_route_get(&stdout);
    debug!(
        target: "capture::linux::tun",
        target,
        lookup_table = %table,
        route_get = %stdout.trim(),
        "detected outbound bypass route table"
    );
    Some(table)
}

fn probe_outbound_interface() -> Option<String> {
    for (family, target) in [("", "1.1.1.1"), ("-6", "2606:4700:4700::1111")] {
        let mut args = Vec::new();
        if !family.is_empty() {
            args.push(family);
        }
        args.extend_from_slice(&["route", "get", target]);
        let out = match std::process::Command::new("ip").args(&args).output() {
            Ok(out) if out.status.success() => out,
            _ => continue,
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(iface) =
            crate::platform::route_probe::outbound_interface_from_route_get(&stdout)
        {
            return Some(iface);
        }
    }
    None
}

fn route_rule_family(net: &ipnet::IpNet) -> &'static str {
    if net.addr().is_ipv6() { "-6" } else { "" }
}

fn auto_route_uses_catch_all_rule(plan: &CapturePlan) -> bool {
    plan.route_addresses.is_empty() || !plan.route_address_set.is_empty()
}

fn should_cleanup_legacy_catch_all_rule(plan: &CapturePlan) -> bool {
    !auto_route_uses_catch_all_rule(plan)
}

fn should_manage_linux_tun_config(device: &dyn TunIo) -> bool {
    !device.is_preconfigured()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

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
    fn legacy_catch_all_cleanup_is_skipped_when_current_mode_uses_catch_all() {
        let plan = CapturePlan::from_config(&core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        })
        .unwrap();

        assert!(auto_route_uses_catch_all_rule(&plan));
        assert!(!should_cleanup_legacy_catch_all_rule(&plan));
    }

    #[test]
    fn legacy_catch_all_cleanup_runs_when_current_mode_uses_static_route_rules() {
        let mut capture = core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            ..core_config::model::Capture::default()
        };
        capture.tun.route_address = vec!["1.1.1.1/32".into()];
        let plan = CapturePlan::from_config(&capture).unwrap();

        assert!(!auto_route_uses_catch_all_rule(&plan));
        assert!(should_cleanup_legacy_catch_all_rule(&plan));
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

        install_auto_route(&routes, &plan);

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
}

fn install_strict_route(plan: &CapturePlan) {
    if !ip_rule_supported() {
        warn!(target: "capture::linux", "strict_route 需要 ip rule 支持，但当前 ip 工具不带 —— 已跳过");
        return;
    }
    let prio_s = (plan.iproute2_rule_index + 1).to_string();
    for fam in ["", "-6"] {
        let _ = run_ip_quiet(
            fam,
            &["rule", "add", "priority", &prio_s, "blackhole", "default"],
        );
    }
    warn!(target: "capture::linux", "strict_route ON：未接管流量将被 drop");
}

fn revert_strict_route(plan: &CapturePlan) {
    if !ip_rule_supported() {
        return;
    }
    let prio_s = (plan.iproute2_rule_index + 1).to_string();
    for fam in ["", "-6"] {
        let _ = run_ip_quiet(fam, &["rule", "del", "priority", &prio_s]);
    }
}

const NFT_REDIRECT_TABLE: &str = "wuthercore_redirect";

fn install_auto_redirect(plan: &CapturePlan) -> Result<(), CaptureError> {
    let marks = &plan.auto_redirect_marks;
    let in_mark = marks.input.unwrap_or(0x2023);
    let out_mark = tun_outbound_mark(plan);
    let reset_mark = marks.reset.unwrap_or(0x2025);

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
        let mark_s = format!("{:#x}", plan.auto_redirect_marks.input.unwrap_or(0x2023));
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
    tcp_handle: Option<JoinHandle<()>>,
    udp_handle: Option<JoinHandle<()>>,
    stop_tcp: Option<oneshot::Sender<()>>,
    stop_udp: Option<oneshot::Sender<()>>,
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
        if !ip_rule_supported() {
            return Err(CaptureError::Doctor(
                "TPROXY 需要 ip rule 支持，用于 fwmark local route".into(),
            ));
        }

        for cmd in tproxy_rules::setup_commands(plan, outbound_mark) {
            run_tproxy_command(&cmd).map_err(|reason| {
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
            "iptables TPROXY rules installed"
        );
        Ok(())
    }

    fn revert_rules(plan: &CapturePlan) {
        for cmd in tproxy_rules::cleanup_commands(plan) {
            if let Err(reason) = run_tproxy_command(&cmd) {
                debug!(
                    target: "capture::tproxy::rules",
                    cmd = %cmd.render(),
                    %reason,
                    "TPROXY cleanup command failed"
                );
            }
        }
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
        let outbound_mark = self
            .plan
            .auto_redirect_marks
            .output
            .unwrap_or(tproxy_rules::TPROXY_FWMARK);
        let bind = crate::platform::linux_tproxy::ipv4_tproxy_bind_addr(tproxy_rules::TPROXY_PORT);
        let listeners = prepare_tproxy_start(
            || crate::platform::linux_tproxy::bind_tproxy_listeners(bind),
            || Self::install_rules(&self.plan, outbound_mark),
            || Self::revert_rules(&self.plan),
        )?;
        let (tcp_listener, udp_socket, bound) = listeners.into_parts();
        let (stop_tcp_tx, stop_tcp_rx) = oneshot::channel::<()>();
        let (stop_udp_tx, stop_udp_rx) = oneshot::channel::<()>();

        // TCP TPROXY listener —— accept 后由 listener 自身 dial+splice，不再
        // 依赖 supervisor 的事件路径（旧逻辑会 dial 然后 drop stream）。
        let evt_tcp = events.clone();
        let rt_tcp = runtime.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = crate::platform::linux_tproxy::run_tcp_tproxy(
                tcp_listener,
                evt_tcp,
                rt_tcp,
                stop_tcp_rx,
            )
            .await
            {
                warn!(target: "capture::tproxy", error = %e, "tcp tproxy exited");
            }
        });
        let evt_udp = events.clone();
        let rt_udp = runtime.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = crate::platform::linux_tproxy::run_udp_tproxy(
                udp_socket,
                evt_udp,
                rt_udp,
                stop_udp_rx,
            )
            .await
            {
                warn!(target: "capture::tproxy", error = %e, "udp tproxy exited");
            }
        });

        g.tcp_handle = Some(tcp_handle);
        g.udp_handle = Some(udp_handle);
        g.stop_tcp = Some(stop_tcp_tx);
        g.stop_udp = Some(stop_udp_tx);
        g.on = true;
        info!(target: "capture", addr = %bound, "linux tproxy started (TCP+UDP listeners ready)");
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
        if let Some(tx) = g.stop_tcp.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = g.stop_udp.take() {
            let _ = tx.send(());
        }
        // No await has occurred yet, so both listeners have received stop
        // before the externally visible state flips to off.
        g.on = false;
        if let Some(h) = g.tcp_handle.take() {
            if let Err(e) = h.await {
                warn!(target: "capture::tproxy", error = %e, "tcp tproxy task join failed");
            }
        }
        if let Some(h) = g.udp_handle.take() {
            if let Err(e) = h.await {
                warn!(target: "capture::tproxy", error = %e, "udp tproxy task join failed");
            }
        }
        Self::revert_rules(&self.plan);
        rule_cleanup.armed = false;
        info!(target: "capture", "linux tproxy stopped");
        Ok(())
    }
}

/* ---------------- LinuxRedirect ---------------- */

pub struct LinuxRedirect {
    plan: CapturePlan,
    state: Mutex<bool>,
}

impl LinuxRedirect {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(false),
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
        _events: mpsc::Sender<CaptureEvent>,
        _runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if *g {
            return Ok(());
        }
        let st = std::process::Command::new("iptables")
            .args(["-t", "nat", "-N", "WUTHERCORE_REDIR"])
            .status()
            .map_err(|e| CaptureError::Doctor(format!("iptables: {e}")))?;
        if !st.success() {
            warn!(target: "capture", "iptables -N 失败（可能已存在）");
        }
        *g = true;
        info!(target: "capture", "linux redirect (TCP-only) started");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !*g {
            return Ok(());
        }
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-F", "WUTHERCORE_REDIR"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-X", "WUTHERCORE_REDIR"])
            .status();
        *g = false;
        info!(target: "capture", "linux redirect stopped");
        Ok(())
    }
}
