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
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};
use crate::packet::{parse_ip_packet, L4};
use crate::platform::linux_tun_io;
use crate::route_table::{ManagedRoute, RouteTable};
use crate::tun_io::TunIo;

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
        if let Some(st) = run_quiet("ip", &["tuntap", "add", "dev", name, "mode", "tun"]) {
            if !st.success() {
                debug!(target: "capture::linux", "ip tuntap add 失败（可能已存在）");
            }
        }
    }

    fn configure_iface(plan: &CapturePlan) -> Result<(), CaptureError> {
        let v4 = format!("{}/{}", plan.tun_v4_cidr.network(), plan.tun_v4_cidr.prefix_len());
        let v6 = format!("{}/{}", plan.tun_v6_cidr.network(), plan.tun_v6_cidr.prefix_len());
        // mtu + up：失败仅记 warn（很多 Android toybox `ip` 缺 `link set` 也能跑 TUN）
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &plan.interface_name, "mtu", &plan.mtu.to_string()])
            .status();
        // addr add：先尝试 `addr replace`（幂等），不支持时回落到 add 再 fall through。
        for fam_args in [vec!["addr"], vec!["-6", "addr"]] {
            let cidr = if fam_args[0] == "-6" { &v6 } else { &v4 };
            let mut replace_args: Vec<&str> = fam_args.clone();
            replace_args.extend_from_slice(&["replace", cidr, "dev", &plan.interface_name]);
            let r = std::process::Command::new("ip").args(&replace_args).status();
            if matches!(r, Ok(s) if s.success()) {
                continue;
            }
            // 回落 add；EEXIST 视为 OK
            let mut add_args: Vec<&str> = fam_args.clone();
            add_args.extend_from_slice(&["add", cidr, "dev", &plan.interface_name]);
            let r2 = std::process::Command::new("ip")
                .args(&add_args)
                .output();
            if let Ok(out) = r2 {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
                    if stderr.contains("file exists") || stderr.contains("rtnetlink answers: file exists") {
                        // 已存在等价成功，沉默
                    } else {
                        warn!(
                            target: "capture",
                            args = ?add_args,
                            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                            "ip addr 配置失败"
                        );
                    }
                }
            }
        }
        // link up
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &plan.interface_name, "up"])
            .status();
        Ok(())
    }
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
        let r = std::process::Command::new("ip").args(["rule", "list"]).output();
        let Ok(o) = r else { return false };
        if !o.status.success() {
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
                return false;
            }
        }
        let stdout_low = String::from_utf8_lossy(&o.stdout).to_lowercase();
        if stdout_low.contains("usage:") || stdout_low.contains("try `ip address help'") {
            return false;
        }
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
        Self::ensure_device_exists(&self.plan.interface_name);
        Self::configure_iface(&self.plan)?;

        // Android 优先 VpnService fd → root /dev/net/tun fallback；
        // 标准 Linux 直接走 /dev/net/tun + ioctl(TUNSETIFF)。
        #[cfg(target_os = "android")]
        let device: Arc<dyn crate::tun_io::TunIo> = crate::platform::android_tun_io::open(&self.plan)
            .map_err(|e| CaptureError::DeviceFailed(format!("open tun: {e}")))?;
        #[cfg(not(target_os = "android"))]
        let device: Arc<dyn crate::tun_io::TunIo> = linux_tun_io::open(&self.plan)
            .map(|d| d as Arc<dyn crate::tun_io::TunIo>)
            .map_err(|e| CaptureError::DeviceFailed(format!("open tun: {e}")))?;

        // auto_route：将所有目标流量导入 TUN（按 sing-box 默认拆 0/1 + 128/1 双半区
        // 路由，避免覆盖系统已有的 0/0 默认路由），并写入指定 iproute2 表。
        if self.plan.auto_route {
            install_auto_route(&self.routes, &self.plan);
        }
        // strict_route：在主表里拒绝其它一切，强制流量必经 TUN。
        if self.plan.strict_route {
            install_strict_route(&self.plan);
        }
        // auto_redirect：nftables 重定向 + fwmark；输入/输出/reset mark 全量配置。
        if self.plan.auto_redirect {
            if let Err(e) = install_auto_redirect(&self.plan) {
                warn!(target: "capture::linux", error = %e, "auto_redirect install failed");
            }
        }

        // 仅在"非用户态栈"模式下跑事件级 packet_loop —— 否则会与
        // CaptureSupervisor 启动的 TunDispatcher 抢同一个 TUN fd 的 read，
        // 导致包被随机分给两个 reader、smoltcp 永远收不到完整握手序列、
        // 出现"拨号成功但应用收不到任何数据"的死锁。
        // 用户态栈接管时，TunDispatcher 独占 TUN 读写并自带 dial+splice。
        let user_stack_active = matches!(
            self.plan.stack,
            core_config::model::CaptureStack::Gvisor
                | core_config::model::CaptureStack::Mixed
                | core_config::model::CaptureStack::Smoltcp
        );
        let (stop_tx, stop_rx) = oneshot::channel();
        if !user_stack_active {
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

        g.device = Some(device);
        g.stop_tx = Some(stop_tx);
        g.started = true;
        info!(
            target: "capture",
            iface = %self.plan.interface_name,
            mtu = self.plan.mtu,
            user_stack_active,
            "linux tun started"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if let Some(tx) = g.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = g.loop_handle.take() {
            h.abort();
        }
        if let Some(d) = g.device.take() {
            let _ = d.close().await;
        }
        if self.plan.auto_redirect {
            revert_auto_redirect(&self.plan);
        }
        if self.plan.strict_route {
            revert_strict_route(&self.plan);
        }
        // 撤销 auto_route 安装的 main-table bypass rule
        if self.plan.auto_route && ip_rule_supported() {
            let out_mark = self.plan.auto_redirect_marks.output.unwrap_or(0xff);
            let mark_s = format!("{out_mark:#x}");
            for fam in ["", "-6"] {
                let _ = run_quiet(
                    "ip",
                    &[fam, "rule", "del", "fwmark", &mark_s, "lookup", "main"],
                );
            }
            // 主 ip rule（fwmark <table> lookup <custom>）也撤掉
            let prio_s = self.plan.iproute2_rule_index.to_string();
            let table_s = self.plan.iproute2_table_index.to_string();
            for fam in ["", "-6"] {
                let _ = run_quiet(
                    "ip",
                    &[fam, "rule", "del", "priority", &prio_s, "lookup", &table_s],
                );
            }
        }
        self.routes.revert_all();
        let _ = run_quiet("ip", &["tuntap", "del", "dev", &self.plan.interface_name, "mode", "tun"]);
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
    for cidr in [
        "0.0.0.0/1",
        "128.0.0.0/1",
        "::/1",
        "8000::/1",
    ] {
        if let Ok(net) = cidr.parse() {
            let _ = routes.add(ManagedRoute {
                dest: net,
                gateway: None,
                interface: plan.interface_name.clone(),
                metric: 0,
            });
        }
    }
    let table_s = table.to_string();
    let prio_s = rule_idx.to_string();
    if ip_rule_supported() {
        for fam in ["", "-6"] {
            let _ = run_quiet("ip", &[fam, "rule", "add", "priority", &prio_s, "lookup", &table_s]);
        }
        // ⭐ 关键：让带 SO_MARK 的 outbound socket 绕 TUN 走主路由表，否则
        // 所有代理出站连接节点 IP 时都会被 TUN 截走 → 无限自循环。
        // mihomo 默认 0xff；这里用 plan.auto_redirect_marks.output（默认 0x2024）。
        let out_mark = plan.auto_redirect_marks.output.unwrap_or(0xff);
        let mark_s = format!("{out_mark:#x}");
        let bypass_prio = (rule_idx + 1).to_string();
        for fam in ["", "-6"] {
            let _ = run_quiet(
                "ip",
                &[
                    fam, "rule", "add",
                    "fwmark", &mark_s,
                    "lookup", "main",
                    "priority", &bypass_prio,
                ],
            );
        }
        info!(
            target: "capture::linux",
            table,
            rule_priority = rule_idx,
            outbound_mark = format_args!("{out_mark:#x}"),
            "auto_route installed (TUN table + main bypass for outbound mark)"
        );
    } else {
        warn!(
            target: "capture::linux",
            "ip rule 命令不可用（Android toybox 通常不带）—— 已跳过 ip rule，仅写 default route"
        );
    }
}

fn install_strict_route(plan: &CapturePlan) {
    if !ip_rule_supported() {
        warn!(target: "capture::linux", "strict_route 需要 ip rule 支持，但当前 ip 工具不带 —— 已跳过");
        return;
    }
    let prio_s = (plan.iproute2_rule_index + 1).to_string();
    for fam in ["", "-6"] {
        let _ = run_quiet("ip", &[fam, "rule", "add", "priority", &prio_s, "blackhole", "default"]);
    }
    warn!(target: "capture::linux", "strict_route ON：未接管流量将被 drop");
}

fn revert_strict_route(plan: &CapturePlan) {
    if !ip_rule_supported() {
        return;
    }
    let prio_s = (plan.iproute2_rule_index + 1).to_string();
    for fam in ["", "-6"] {
        let _ = run_quiet("ip", &[fam, "rule", "del", "priority", &prio_s]);
    }
}

const NFT_REDIRECT_TABLE: &str = "rpkernel_redirect";

fn install_auto_redirect(plan: &CapturePlan) -> Result<(), CaptureError> {
    let marks = &plan.auto_redirect_marks;
    let in_mark = marks.input.unwrap_or(0x2023);
    let out_mark = marks.output.unwrap_or(0x2024);
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
        let mut allow: Vec<String> =
            plan.filters.include_uid.iter().map(|u| u.to_string()).collect();
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
        let mut allow: Vec<String> =
            plan.filters.include_gid.iter().map(|g| g.to_string()).collect();
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
        let macs: Vec<String> = plan
            .filters
            .include_mac
            .iter()
            .map(|m| m.clone())
            .collect();
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
                let _ = run_quiet("ip", &[fam, "rule", "add", "fwmark", &mark_s, "lookup", &table_s]);
            }
            if let Some(fb) = marks.fallback_rule_index {
                let prio_s = fb.to_string();
                for fam in ["", "-6"] {
                    let _ = run_quiet("ip", &[fam, "rule", "add", "priority", &prio_s, "lookup", &table_s]);
                }
            }
        }
        if let Some(q) = marks.nfqueue {
            let qs = q.to_string();
            let _ = run_quiet(
                "nft",
                &["add", "rule", "inet", NFT_REDIRECT_TABLE, "prerouting", "queue", "num", &qs],
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
                let _ = run_quiet("ip", &[fam, "rule", "add", "fwmark", &mark_s, "lookup", &table_s]);
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
         否则请关掉 auto_redirect，使用 method=virtual_nic + stack=mixed 走纯 TUN。".into(),
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

const IPT_CHAIN: &str = "RPKERNEL_REDIR";
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
            &["-t", "mangle", "-A", IPT_CHAIN, "-m", "mark", "--mark", &out_mark_s, "-j", "RETURN"],
        );
        // loopback / TUN iif 跳过
        let _ = run_quiet(ipt, &["-t", "mangle", "-A", IPT_CHAIN, "-i", "lo", "-j", "RETURN"]);
        let _ = run_quiet(
            ipt,
            &["-t", "mangle", "-A", IPT_CHAIN, "-i", &plan.interface_name, "-j", "RETURN"],
        );

        // UID/GID exclude
        for u in &plan.filters.exclude_uid {
            let val = u.to_string();
            let _ = run_quiet(
                ipt,
                &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "--uid-owner", &val, "-j", "RETURN"],
            );
        }
        for (a, b) in &plan.filters.exclude_uid_range {
            let val = format!("{a}-{b}");
            let _ = run_quiet(
                ipt,
                &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "--uid-owner", &val, "-j", "RETURN"],
            );
        }
        for g in &plan.filters.exclude_gid {
            let val = g.to_string();
            let _ = run_quiet(
                ipt,
                &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "--gid-owner", &val, "-j", "RETURN"],
            );
        }
        for (a, b) in &plan.filters.exclude_gid_range {
            let val = format!("{a}-{b}");
            let _ = run_quiet(
                ipt,
                &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "--gid-owner", &val, "-j", "RETURN"],
            );
        }
        // include_uid / include_gid 用 ! 否定 RETURN 实现"只放行集合"语义。
        if !plan.filters.include_uid.is_empty() || !plan.filters.include_uid_range.is_empty() {
            for u in &plan.filters.include_uid {
                let val = u.to_string();
                let _ = run_quiet(
                    ipt,
                    &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "!", "--uid-owner", &val, "-j", "RETURN"],
                );
            }
            for (a, b) in &plan.filters.include_uid_range {
                let val = format!("{a}-{b}");
                let _ = run_quiet(
                    ipt,
                    &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "!", "--uid-owner", &val, "-j", "RETURN"],
                );
            }
        }
        if !plan.filters.include_gid.is_empty() || !plan.filters.include_gid_range.is_empty() {
            for g in &plan.filters.include_gid {
                let val = g.to_string();
                let _ = run_quiet(
                    ipt,
                    &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "!", "--gid-owner", &val, "-j", "RETURN"],
                );
            }
            for (a, b) in &plan.filters.include_gid_range {
                let val = format!("{a}-{b}");
                let _ = run_quiet(
                    ipt,
                    &["-t", "mangle", "-A", IPT_CHAIN, "-m", "owner", "!", "--gid-owner", &val, "-j", "RETURN"],
                );
            }
        }

        // TPROXY mark + 投递到本地端口
        let r2 = run_quiet(
            ipt,
            &["-t", "mangle", "-A", IPT_CHAIN, "-p", "tcp", "-j", "TPROXY", "--on-port", IPT_TPROXY_PORT, "--tproxy-mark", &in_mark_s],
        );
        let r3 = run_quiet(
            ipt,
            &["-t", "mangle", "-A", IPT_CHAIN, "-p", "udp", "-j", "TPROXY", "--on-port", IPT_TPROXY_PORT, "--tproxy-mark", &in_mark_s],
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
        let _ = run_quiet(ipt, &["-t", "nat", "-A", IPT_CHAIN, "-i", "lo", "-j", "RETURN"]);
        let _ = run_quiet(
            ipt,
            &["-t", "nat", "-A", IPT_CHAIN, "-i", &plan.interface_name, "-j", "RETURN"],
        );
        // UID/GID 排除：owner-match 在 nat 表只对 OUTPUT 链有效。
        for u in &plan.filters.exclude_uid {
            let val = u.to_string();
            let _ = run_quiet(
                ipt,
                &["-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", &val, "-j", "RETURN"],
            );
        }
        for g in &plan.filters.exclude_gid {
            let val = g.to_string();
            let _ = run_quiet(
                ipt,
                &["-t", "nat", "-A", "OUTPUT", "-m", "owner", "--gid-owner", &val, "-j", "RETURN"],
            );
        }
        let r = run_quiet(
            ipt,
            &["-t", "nat", "-A", IPT_CHAIN, "-p", "tcp", "-j", "REDIRECT", "--to-ports", IPT_TPROXY_PORT],
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
                        "-t", "nat", "-D", "OUTPUT",
                        "-m", "owner", "--uid-owner", &val, "-j", "RETURN",
                    ],
                );
            }
            for g in &plan.filters.exclude_gid {
                let val = g.to_string();
                let _ = run_quiet(
                    ipt,
                    &[
                        "-t", "nat", "-D", "OUTPUT",
                        "-m", "owner", "--gid-owner", &val, "-j", "RETURN",
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
            plan.auto_redirect_marks.input.unwrap_or(0x2023)
        );
        for fam in ["", "-6"] {
            let _ = run_quiet("ip", &[fam, "rule", "del", "fwmark", &mark_s, "lookup", &table_s]);
        }
        if let Some(fb) = plan.auto_redirect_marks.fallback_rule_index {
            let prio_s = fb.to_string();
            for fam in ["", "-6"] {
                let _ = run_quiet("ip", &[fam, "rule", "del", "priority", &prio_s]);
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
                let parsed = match parse_ip_packet(&buf[..n]) {
                    Ok(p) => p,
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

impl LinuxTproxy {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TproxyState::default()),
        }
    }

    fn install_rules() -> Result<(), CaptureError> {
        // 试探使用 nft；失败则回退 iptables。
        let nft = std::process::Command::new("nft")
            .args(["add", "table", "inet", "rpkernel"])
            .status();
        if let Ok(st) = nft {
            if st.success() {
                info!(target: "capture", "nftables table rpkernel created");
                return Ok(());
            }
        }
        let ipt = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-N", "RPKERNEL"])
            .status();
        if ipt.map(|s| s.success()).unwrap_or(false) {
            info!(target: "capture", "iptables chain RPKERNEL created");
            return Ok(());
        }
        Err(CaptureError::Doctor(
            "nft 与 iptables 都不可用 —— 请安装 nftables / iptables".into(),
        ))
    }

    fn revert_rules() {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "rpkernel"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-F", "RPKERNEL"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-X", "RPKERNEL"])
            .status();
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
        Self::install_rules()?;

        // 启动 TCP TPROXY 监听 :7894（默认；与 nft 规则中的端口一致）。
        let bind_tcp: std::net::SocketAddr = "127.0.0.1:7894".parse().unwrap();
        let bind_udp: std::net::SocketAddr = "127.0.0.1:7894".parse().unwrap();
        let (stop_tcp_tx, mut stop_tcp_rx) = oneshot::channel::<()>();
        let (stop_udp_tx, mut stop_udp_rx) = oneshot::channel::<()>();

        // TCP TPROXY listener —— accept 后由 listener 自身 dial+splice，不再
        // 依赖 supervisor 的事件路径（旧逻辑会 dial 然后 drop stream）。
        let evt_tcp = events.clone();
        let rt_tcp = runtime.clone();
        let tcp_handle = tokio::spawn(async move {
            tokio::select! {
                _ = &mut stop_tcp_rx => {}
                r = crate::platform::linux_tproxy::run_tcp_tproxy(bind_tcp, evt_tcp, rt_tcp) => {
                    if let Err(e) = r {
                        warn!(target: "capture::tproxy", error = %e, "tcp tproxy exited");
                    }
                }
            }
        });
        let evt_udp = events.clone();
        let udp_handle = tokio::spawn(async move {
            tokio::select! {
                _ = &mut stop_udp_rx => {}
                r = crate::platform::linux_tproxy::run_udp_tproxy(bind_udp, evt_udp) => {
                    if let Err(e) = r {
                        warn!(target: "capture::tproxy", error = %e, "udp tproxy exited");
                    }
                }
            }
        });

        g.tcp_handle = Some(tcp_handle);
        g.udp_handle = Some(udp_handle);
        g.stop_tcp = Some(stop_tcp_tx);
        g.stop_udp = Some(stop_udp_tx);
        g.on = true;
        info!(target: "capture", "linux tproxy started (TCP+UDP listeners on :7894)");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !g.on {
            return Ok(());
        }
        if let Some(tx) = g.stop_tcp.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = g.stop_udp.take() {
            let _ = tx.send(());
        }
        if let Some(h) = g.tcp_handle.take() {
            h.abort();
        }
        if let Some(h) = g.udp_handle.take() {
            h.abort();
        }
        Self::revert_rules();
        g.on = false;
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
            .args(["-t", "nat", "-N", "RPKERNEL_REDIR"])
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
            .args(["-t", "nat", "-F", "RPKERNEL_REDIR"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-X", "RPKERNEL_REDIR"])
            .status();
        *g = false;
        info!(target: "capture", "linux redirect stopped");
        Ok(())
    }
}
