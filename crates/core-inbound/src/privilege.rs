//! 进程权限检测 + Android root 提权 + 平台能力诊断。
//!
//! ## 设计目标
//!
//! 1. **跨平台**：Linux / Android / macOS / iOS / Windows 一律一个 [`PrivilegeReport::detect()`]。
//! 2. **诚实**：不假装拥有权限；检测失败时 `level = User` 并把所有受限能力降级。
//! 3. **Android 诚实探测 su**：[`try_request_root_android`] 调用 `su -c id`，
//!    成功只表示可执行 root 子命令；不会把当前进程伪装成 uid=0。
//! 4. **零 unsafe**：Unix 用 `nix` 封装，Windows 走外部命令检测。

use serde::Serialize;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PrivilegeLevel {
    /// Linux/macOS root（uid=0），Windows Administrator，或当前进程持有等价权限。
    Elevated,
    /// 受限：低位端口受限，无法改路由表，无法创建 raw/TPROXY socket。
    User,
}

impl PrivilegeLevel {
    pub fn is_elevated(&self) -> bool {
        matches!(self, Self::Elevated)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivilegeReport {
    pub level: PrivilegeLevel,
    pub platform: &'static str,
    pub username: String,
    pub uid: Option<u32>,
    pub can_bind_low_ports: bool,
    pub can_create_tun: bool,
    pub can_modify_routes: bool,
    pub can_iptables: bool,
    /// Android：是否检测到 `su` 可执行（不一定有 root，需调 try_request_root 验证）。
    pub android_su_present: bool,
    /// Linux capabilities 概要（如 "CAP_NET_ADMIN"）。
    pub capabilities: Vec<String>,
    pub notes: Vec<String>,
}

impl PrivilegeReport {
    pub fn is_elevated(&self) -> bool {
        self.level.is_elevated()
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
fn detect_unix() -> PrivilegeReport {
    use nix::unistd::{User, geteuid};

    let euid = geteuid();
    let uid = euid.as_raw();
    let username = User::from_uid(euid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| format!("uid:{uid}"));
    let elevated = uid == 0;

    let mut notes = Vec::new();
    let su_present = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .any(|p| p.join("su").exists());

    let capabilities = read_linux_capabilities();
    if !elevated && !capabilities.is_empty() {
        notes.push(format!(
            "non-root with capabilities: {}",
            capabilities.join(", ")
        ));
    }

    PrivilegeReport {
        level: if elevated {
            PrivilegeLevel::Elevated
        } else {
            PrivilegeLevel::User
        },
        platform: std::env::consts::OS,
        username,
        uid: Some(uid),
        can_bind_low_ports: elevated || capabilities.iter().any(|c| c == "cap_net_bind_service"),
        can_create_tun: elevated || capabilities.iter().any(|c| c == "cap_net_admin"),
        can_modify_routes: elevated || capabilities.iter().any(|c| c == "cap_net_admin"),
        can_iptables: elevated || capabilities.iter().any(|c| c == "cap_net_admin"),
        android_su_present: cfg!(target_os = "android") && su_present,
        capabilities,
        notes,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_linux_capabilities() -> Vec<String> {
    // /proc/self/status 中的 CapEff 是 hex 位掩码；解析常见位即可。
    let content = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let cap_eff = content
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let bits = u64::from_str_radix(&cap_eff, 16).unwrap_or(0);
    let mut caps = Vec::new();
    // bit 编号见 capabilities(7)
    if bits & (1 << 13) != 0 {
        caps.push("cap_net_admin".into());
    }
    if bits & (1 << 10) != 0 {
        caps.push("cap_net_bind_service".into());
    }
    if bits & (1 << 12) != 0 {
        caps.push("cap_net_raw".into());
    }
    if bits & (1 << 21) != 0 {
        caps.push("cap_sys_admin".into());
    }
    caps
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_linux_capabilities() -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn detect_windows() -> PrivilegeReport {
    let username = std::env::var("USERNAME").unwrap_or_default();
    // 用 net session 检测 admin（不需要 unsafe）：成功列出会话 = admin
    let net_session = std::process::Command::new("net")
        .args(["session"])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let elevated = net_session;
    let mut notes = Vec::new();
    if !elevated {
        notes.push("以非管理员运行；TUN/路由相关功能将不可用".into());
    }

    PrivilegeReport {
        level: if elevated {
            PrivilegeLevel::Elevated
        } else {
            PrivilegeLevel::User
        },
        platform: "windows",
        username,
        uid: None,
        can_bind_low_ports: true, // Windows 默认允许（除非端口被占用）
        can_create_tun: elevated,
        can_modify_routes: elevated,
        can_iptables: false,
        android_su_present: false,
        capabilities: vec![],
        notes,
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "windows"
)))]
fn detect_other() -> PrivilegeReport {
    PrivilegeReport {
        level: PrivilegeLevel::User,
        platform: std::env::consts::OS,
        username: std::env::var("USER").unwrap_or_default(),
        uid: None,
        can_bind_low_ports: false,
        can_create_tun: false,
        can_modify_routes: false,
        can_iptables: false,
        android_su_present: false,
        capabilities: vec![],
        notes: vec!["平台未识别，所有特权能力默认关闭".into()],
    }
}

impl PrivilegeReport {
    pub fn detect() -> Self {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd"
        ))]
        {
            return detect_unix();
        }
        #[cfg(target_os = "windows")]
        {
            return detect_windows();
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "windows"
        )))]
        {
            return detect_other();
        }
    }
}

/// Android 平台：尝试通过 `su -c id` 提权。
/// 成功返回 Ok(()) 仅表示宿主允许 spawn `su` 子进程做特权操作。
/// 注意：本进程的 uid / capabilities 不会因此变化；ROOT TUN 打开 `/dev/net/tun`
/// 与 ioctl 配置仍要求当前进程本身具备 uid=0 或 CAP_NET_ADMIN，或者走 VpnService fd。
#[cfg(target_os = "android")]
pub async fn try_request_root_android() -> Result<(), String> {
    let out = tokio::process::Command::new("su")
        .args(["-c", "id"])
        .output()
        .await
        .map_err(|e| format!("spawn su: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && stdout.contains("uid=0") {
        info!(target: "privilege", "android su available; root commands enabled");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        warn!(target: "privilege", stderr = %stderr, "android su failed; falling back to VpnService");
        Err(stderr.into_owned())
    }
}

/// 非 Android 平台的 stub —— 直接根据当前进程 euid 判断。
#[cfg(not(target_os = "android"))]
pub async fn try_request_root_android() -> Result<(), String> {
    Err("非 Android 平台不需要 su 提权".into())
}

/// 启动钩子：尝试拿到最高权限并打印诊断。Android 优先 root → 失败降级。
pub async fn ensure_best_effort_privilege() -> PrivilegeReport {
    let mut report = PrivilegeReport::detect();
    debug!(target: "privilege", report = ?report, "initial privilege report");
    if cfg!(target_os = "android") && !report.is_elevated() {
        match try_request_root_android().await {
            Ok(_) => {
                warn!(
                    target: "privilege",
                    "android su available, but current process is still unprivileged; ROOT TUN needs uid=0/CAP_NET_ADMIN or VpnService fd"
                );
                report.notes.push(
                    "android su available for explicit root subprocess commands; current process uid/capabilities unchanged".into(),
                );
            }
            Err(e) => {
                report
                    .notes
                    .push(format!("android su failed → VpnService fallback: {e}"));
            }
        }
    }
    info!(
        target: "privilege",
        platform = report.platform,
        level = ?report.level,
        user = %report.username,
        can_bind_low = report.can_bind_low_ports,
        can_tun = report.can_create_tun,
        can_route = report.can_modify_routes,
        "privilege detected"
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_runs_on_host() {
        let r = PrivilegeReport::detect();
        // 不强制断言 elevated（host 可能非 root），但字段必须填上
        assert!(!r.platform.is_empty());
        assert!(matches!(
            r.level,
            PrivilegeLevel::Elevated | PrivilegeLevel::User
        ));
    }

    #[tokio::test]
    async fn ensure_best_effort_returns_report() {
        let r = ensure_best_effort_privilege().await;
        assert!(!r.platform.is_empty());
    }

    #[tokio::test]
    async fn android_stub_on_non_android_errs() {
        if !cfg!(target_os = "android") {
            assert!(try_request_root_android().await.is_err());
        }
    }
}
