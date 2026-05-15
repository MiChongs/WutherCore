//! Android 后端：root 模式完整透明代理能力。
//!
//! 行为：
//! 1. [`detect_capability`] 通过 `su -c` 执行多个探测命令收集 [`AndroidCapability`]；
//! 2. [`AndroidCapability::select_tier`] 选最高可用 root Tier；
//! 3. [`AndroidCapture::start`] 调用对应 Tier 的 install_rules：
//!    - **NftablesFull**：`nft add table inet wuthercore` + 双栈 TPROXY chain
//!    - **IptablesV4V6Tproxy**：`iptables` + `ip6tables` 双栈 TPROXY
//!    - **IptablesV4V6Redirect**：`iptables -t nat REDIRECT` + `ip6tables -t nat REDIRECT`
//!    - **IptablesV4Only**：仅 v4 NAT REDIRECT
//! 4. [`AndroidCapture::stop`] 严格按 Tier 卸载规则，恢复路由表。
//!
//! 跨平台编译：本文件在所有平台都参与构建，但 `su -c` 命令调用使用 `cfg(target_os = "android")` 守护；
//! 其它平台下 `detect_capability()` 返回空能力，`install_rules` 仅写日志。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use crate::{
    android_caps::{AndroidCapability, AndroidTier},
    engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind},
};

pub fn list_interfaces() -> Vec<String> {
    // Android 没有 /sys/class/net 用户可读 —— 通过 ip 命令或 `getifaddrs`
    if let Ok(out) = std::process::Command::new("ip").arg("link").output() {
        let txt = String::from_utf8_lossy(&out.stdout);
        return txt
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter_map(|s| s.split('@').next())
            .map(|s| s.trim_end_matches(':').to_string())
            .collect();
    }
    vec![]
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    match plan.kind {
        // Tun → 走 Linux engine 拿真实 TunIo（root /dev/net/tun 优先；VpnService fd fallback）。
        #[cfg(target_os = "android")]
        EngineKind::Tun => crate::platform::linux::build_engine(plan),
        // 非 Android 主机调试编译时，Tun 走 stub AndroidCapture（不会真正生效）。
        #[cfg(not(target_os = "android"))]
        EngineKind::Tun => Ok(Arc::new(AndroidCapture::new(plan))),
        EngineKind::Tproxy | EngineKind::Redirect => Ok(Arc::new(AndroidCapture::new(plan))),
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct AndroidCapture {
    plan: CapturePlan,
    capability: AndroidCapability,
    tier: Option<AndroidTier>,
    state: Mutex<bool>,
}

impl AndroidCapture {
    pub fn new(plan: CapturePlan) -> Self {
        let capability = detect_capability();
        let tier = capability.select_tier();
        info!(
            target: "capture::android",
            tier = tier_label(tier),
            ipv6 = tier.map(|t| t.supports_ipv6()).unwrap_or(false),
            udp = tier.map(|t| t.supports_udp_transparent()).unwrap_or(false),
            requires_root = tier.map(|t| t.requires_root()).unwrap_or(false),
            "android capture tier selected"
        );
        for note in capability.explain_degradation(tier) {
            warn!(target: "capture::android", "{}", note);
        }
        Self {
            plan,
            capability,
            tier,
            state: Mutex::new(false),
        }
    }

    pub fn capability(&self) -> &AndroidCapability {
        &self.capability
    }
    pub fn tier(&self) -> Option<AndroidTier> {
        self.tier
    }

    fn install(&self) -> Result<(), CaptureError> {
        let Some(tier) = self.tier else {
            return Err(CaptureError::Unsupported(
                "Android root transparent capture requires root and nftables/iptables; use virtual_nic/VpnService for non-root capture".into(),
            ));
        };
        match tier {
            AndroidTier::NftablesFull => install_nft_full(&self.plan),
            AndroidTier::IptablesV4V6Tproxy => install_iptables_v4v6_tproxy(&self.plan),
            AndroidTier::IptablesV4V6Redirect => install_iptables_v4v6_redirect(&self.plan),
            AndroidTier::IptablesV4Only => install_iptables_v4_only(&self.plan),
        }
    }

    fn revert(&self) {
        match self.tier {
            None => {}
            Some(tier) => match tier {
                AndroidTier::NftablesFull => revert_nft_full(),
                AndroidTier::IptablesV4V6Tproxy
                | AndroidTier::IptablesV4V6Redirect
                | AndroidTier::IptablesV4Only => revert_iptables_all(),
            },
        }
    }
}

#[async_trait]
impl CaptureEngine for AndroidCapture {
    fn kind(&self) -> EngineKind {
        self.plan.kind
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
        self.install()?;
        *g = true;
        info!(
            target: "capture::android",
            tier = tier_label(self.tier),
            "android capture started"
        );
        Ok(())
    }

    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !*g {
            return Ok(());
        }
        self.revert();
        *g = false;
        info!(
            target: "capture::android",
            tier = tier_label(self.tier),
            "android capture stopped"
        );
        Ok(())
    }

    fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": format!("{:?}", self.kind()).to_lowercase(),
            "android_tier": tier_label(self.tier),
            "ipv6": self.tier.map(|t| t.supports_ipv6()).unwrap_or(false),
            "udp_transparent": self.tier.map(|t| t.supports_udp_transparent()).unwrap_or(false),
            "capability": self.capability,
        })
    }
}

fn tier_label(tier: Option<AndroidTier>) -> &'static str {
    tier.map(|t| t.label()).unwrap_or("unsupported")
}

/* ============================================================
Capability 探测（通过 su -c 执行命令）
============================================================ */

#[cfg(target_os = "android")]
pub fn detect_capability() -> AndroidCapability {
    let mut c = AndroidCapability::default();

    // root
    c.has_root = run_su("id").map(|o| o.contains("uid=0")).unwrap_or(false);
    if !c.has_root {
        c.notes.push("su 不可用".into());
        return c;
    }

    // iptables / ip6tables / nft
    c.has_iptables = run_su("iptables --version").is_ok();
    c.has_ip6tables = run_su("ip6tables --version").is_ok();
    c.has_nftables = run_su("nft --version").is_ok();

    // 内核 IPv6 NAT：ip6tables -t nat -L 不报错 = 支持
    c.kernel_ipv6_nat = run_su("ip6tables -t nat -L -n").is_ok();

    // TPROXY 内核模块
    c.kernel_tproxy = run_su("grep -q TPROXY /proc/net/ip_tables_matches").is_ok()
        || run_su("modprobe nf_tproxy_ipv4").is_ok();
    c.kernel_tproxy_v6 = run_su("grep -q TPROXY /proc/net/ip6_tables_matches").is_ok()
        || run_su("modprobe nf_tproxy_ipv6").is_ok();

    // -m owner --uid-owner
    c.uid_owner_match = run_su("iptables -m owner --help 2>&1 | grep -q uid-owner").is_ok();

    // tun 模块
    c.tun_module = run_su("test -c /dev/tun || test -c /dev/net/tun").is_ok();

    // raw socket（一般 root 都行）
    c.raw_socket_supported = c.has_root;

    c
}

#[cfg(not(target_os = "android"))]
pub fn detect_capability() -> AndroidCapability {
    AndroidCapability::default()
}

#[cfg(target_os = "android")]
fn run_su(cmd: &str) -> Result<String, ()> {
    let out = std::process::Command::new("su")
        .args(["-c", cmd])
        .output()
        .map_err(|_| ())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(())
    }
}

#[cfg(target_os = "android")]
fn run_su_must(cmd: &str) -> Result<(), CaptureError> {
    let out = std::process::Command::new("su")
        .args(["-c", cmd])
        .output()
        .map_err(|e| CaptureError::Doctor(format!("su spawn: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(CaptureError::Doctor(format!(
            "su -c {cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )))
    }
}

#[cfg(not(target_os = "android"))]
fn run_su_must(_cmd: &str) -> Result<(), CaptureError> {
    Ok(())
}

/* ============================================================
Per-Tier 安装/撤销（Android target 才真执行）
============================================================ */

const NFT_TABLE: &str = "wuthercore";
const IPT_CHAIN: &str = "WUTHERCORE";

fn install_nft_full(plan: &CapturePlan) -> Result<(), CaptureError> {
    info!(target: "capture::android", "Tier=NftablesFull installing");
    // 1. 创建 inet 表
    run_su_must(&format!("nft add table inet {NFT_TABLE}"))?;
    // 2. prerouting chain 含 TPROXY (IPv4 + IPv6)
    run_su_must(&format!(
        "nft 'add chain inet {NFT_TABLE} prerouting {{ type filter hook prerouting priority -150; }}'"
    ))?;
    // 3. mark fwmark 1（与 ip rule 路由表配合）
    run_su_must(&format!(
        "nft 'add rule inet {NFT_TABLE} prerouting meta l4proto tcp tproxy ip to 127.0.0.1:7894 meta mark set 1 accept'"
    ))?;
    if plan.kind == EngineKind::Tproxy {
        run_su_must(&format!(
            "nft 'add rule inet {NFT_TABLE} prerouting meta l4proto tcp tproxy ip6 to [::1]:7894 meta mark set 1 accept'"
        ))?;
    }
    // 4. ip rule fwmark 1 lookup 100
    run_su_must("ip rule add fwmark 1 lookup 100")?;
    run_su_must("ip route add local default dev lo table 100")?;
    run_su_must("ip -6 rule add fwmark 1 lookup 100")?;
    run_su_must("ip -6 route add local default dev lo table 100")?;
    Ok(())
}

fn revert_nft_full() {
    let _ = run_su_must(&format!("nft delete table inet {NFT_TABLE}"));
    let _ = run_su_must("ip rule del fwmark 1 lookup 100");
    let _ = run_su_must("ip route del local default dev lo table 100");
    let _ = run_su_must("ip -6 rule del fwmark 1 lookup 100");
    let _ = run_su_must("ip -6 route del local default dev lo table 100");
}

fn install_iptables_v4v6_tproxy(_plan: &CapturePlan) -> Result<(), CaptureError> {
    info!(target: "capture::android", "Tier=IptablesV4V6Tproxy installing");
    // v4
    run_su_must(&format!("iptables -t mangle -N {IPT_CHAIN}"))?;
    run_su_must(&format!(
        "iptables -t mangle -A {IPT_CHAIN} -p tcp -j TPROXY --on-port 7894 --tproxy-mark 1"
    ))?;
    run_su_must(&format!("iptables -t mangle -A PREROUTING -j {IPT_CHAIN}"))?;
    // v6
    run_su_must(&format!("ip6tables -t mangle -N {IPT_CHAIN}"))?;
    run_su_must(&format!(
        "ip6tables -t mangle -A {IPT_CHAIN} -p tcp -j TPROXY --on-port 7894 --tproxy-mark 1"
    ))?;
    run_su_must(&format!("ip6tables -t mangle -A PREROUTING -j {IPT_CHAIN}"))?;
    // route table
    run_su_must("ip rule add fwmark 1 lookup 100")?;
    run_su_must("ip route add local default dev lo table 100")?;
    run_su_must("ip -6 rule add fwmark 1 lookup 100")?;
    run_su_must("ip -6 route add local default dev lo table 100")?;
    Ok(())
}

fn install_iptables_v4v6_redirect(_plan: &CapturePlan) -> Result<(), CaptureError> {
    info!(target: "capture::android", "Tier=IptablesV4V6Redirect installing");
    run_su_must(&format!("iptables -t nat -N {IPT_CHAIN}"))?;
    run_su_must(&format!(
        "iptables -t nat -A {IPT_CHAIN} -p tcp -j REDIRECT --to-ports 7894"
    ))?;
    run_su_must(&format!("iptables -t nat -A PREROUTING -j {IPT_CHAIN}"))?;
    run_su_must(&format!("ip6tables -t nat -N {IPT_CHAIN}"))?;
    run_su_must(&format!(
        "ip6tables -t nat -A {IPT_CHAIN} -p tcp -j REDIRECT --to-ports 7894"
    ))?;
    run_su_must(&format!("ip6tables -t nat -A PREROUTING -j {IPT_CHAIN}"))?;
    Ok(())
}

fn install_iptables_v4_only(_plan: &CapturePlan) -> Result<(), CaptureError> {
    info!(target: "capture::android", "Tier=IptablesV4Only installing (IPv6 traffic will go direct)");
    run_su_must(&format!("iptables -t nat -N {IPT_CHAIN}"))?;
    run_su_must(&format!(
        "iptables -t nat -A {IPT_CHAIN} -p tcp -j REDIRECT --to-ports 7894"
    ))?;
    run_su_must(&format!("iptables -t nat -A PREROUTING -j {IPT_CHAIN}"))?;
    Ok(())
}

fn revert_iptables_all() {
    for ipt in ["iptables", "ip6tables"] {
        for table in ["mangle", "nat"] {
            let _ = run_su_must(&format!("{ipt} -t {table} -D PREROUTING -j {IPT_CHAIN}"));
            let _ = run_su_must(&format!("{ipt} -t {table} -F {IPT_CHAIN}"));
            let _ = run_su_must(&format!("{ipt} -t {table} -X {IPT_CHAIN}"));
        }
    }
    let _ = run_su_must("ip rule del fwmark 1 lookup 100");
    let _ = run_su_must("ip route del local default dev lo table 100");
    let _ = run_su_must("ip -6 rule del fwmark 1 lookup 100");
    let _ = run_su_must("ip -6 route del local default dev lo table 100");
}
