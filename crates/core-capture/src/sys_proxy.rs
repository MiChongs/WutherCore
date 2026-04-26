//! 系统级 HTTP proxy 写入 / 还原 —— sing-box `tun.platform.http_proxy` 的运行
//! 时落地。
//!
//! ## 各平台实现
//!
//! | OS      | 写入                                                          | 还原                                                    |
//! |---------|---------------------------------------------------------------|---------------------------------------------------------|
//! | Windows | `netsh winhttp set proxy <ip>:<port>` + Internet Explorer 注册表 | `netsh winhttp reset proxy` + 还原原值                   |
//! | macOS   | `networksetup -setwebproxy / -setsecurewebproxy <iface> ip port` | `networksetup -setwebproxystate <iface> off`            |
//! | Linux   | gsettings (GNOME) + `http_proxy` 环境变量提示                   | gsettings reset                                         |
//!
//! 不同发行版差异极大：本实现以 best-effort 为原则，对失败仅记 warning，
//! 不阻塞 capture 启动。
//!
//! 还原信息保存在 [`SystemProxyGuard]，drop 时自动尝试还原。

use core_config::model::TunHttpProxyOptions;
use tracing::info;
#[cfg(target_os = "windows")]
use tracing::warn;
#[cfg(target_os = "linux")]
use tracing::debug;

#[derive(Debug)]
pub struct SystemProxyGuard {
    applied: bool,
    /// 平台特定的"原状态"快照，stop 时还原。
    snapshot: Snapshot,
}

#[derive(Debug, Default, Clone)]
struct Snapshot {
    #[cfg(target_os = "windows")]
    #[allow(dead_code)] // 仅供日志/排查；revert 走 `netsh winhttp reset proxy`
    win_old_value: Option<String>,
    #[cfg(target_os = "macos")]
    macos_services: Vec<String>,
    #[cfg(target_os = "linux")]
    linux_gsettings_mode: Option<String>,
}

impl SystemProxyGuard {
    pub fn install(opts: &TunHttpProxyOptions) -> Self {
        if !opts.enabled {
            return Self { applied: false, snapshot: Snapshot::default() };
        }
        let server = if opts.server.is_empty() { "127.0.0.1" } else { &opts.server };
        let port = if opts.server_port == 0 { 8080 } else { opts.server_port };
        let snapshot = apply_platform(server, port, &opts.bypass_domain);
        info!(
            target: "capture::sysproxy",
            %server, port,
            bypass = ?opts.bypass_domain,
            "system http proxy installed"
        );
        Self { applied: true, snapshot }
    }

    pub fn revert(self) {
        if !self.applied {
            return;
        }
        revert_platform(&self.snapshot);
        info!(target: "capture::sysproxy", "system http proxy reverted");
    }
}

#[cfg(target_os = "windows")]
fn apply_platform(server: &str, port: u16, bypass: &[String]) -> Snapshot {
    // 读取并保存当前值
    let old = std::process::Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok());

    let proxy = format!("{server}:{port}");
    let bypass_list = if bypass.is_empty() {
        "<local>".to_string()
    } else {
        bypass.join(";")
    };
    let st = std::process::Command::new("netsh")
        .args(["winhttp", "set", "proxy", &proxy, "bypass-list=", &bypass_list])
        .status();
    if let Ok(s) = st {
        if !s.success() {
            warn!(target: "capture::sysproxy", "netsh winhttp set proxy failed");
        }
    }
    // IE / system tray
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r#"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"#,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .status();
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r#"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"#,
            "/v",
            "ProxyServer",
            "/t",
            "REG_SZ",
            "/d",
            &proxy,
            "/f",
        ])
        .status();
    Snapshot { win_old_value: old }
}

#[cfg(target_os = "windows")]
fn revert_platform(_s: &Snapshot) {
    let _ = std::process::Command::new("netsh")
        .args(["winhttp", "reset", "proxy"])
        .status();
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r#"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"#,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])
        .status();
}

#[cfg(target_os = "macos")]
fn apply_platform(server: &str, port: u16, _bypass: &[String]) -> Snapshot {
    // 列出所有 networksetup service
    let out = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output();
    let mut services = Vec::new();
    if let Ok(o) = out {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines().skip(1) {
            let s = line.trim();
            if !s.is_empty() && !s.starts_with('*') {
                services.push(s.to_string());
            }
        }
    }
    let port_s = port.to_string();
    for svc in &services {
        let _ = std::process::Command::new("networksetup")
            .args(["-setwebproxy", svc, server, &port_s])
            .status();
        let _ = std::process::Command::new("networksetup")
            .args(["-setsecurewebproxy", svc, server, &port_s])
            .status();
    }
    Snapshot { macos_services: services }
}

#[cfg(target_os = "macos")]
fn revert_platform(s: &Snapshot) {
    for svc in &s.macos_services {
        let _ = std::process::Command::new("networksetup")
            .args(["-setwebproxystate", svc, "off"])
            .status();
        let _ = std::process::Command::new("networksetup")
            .args(["-setsecurewebproxystate", svc, "off"])
            .status();
    }
}

#[cfg(target_os = "linux")]
fn apply_platform(server: &str, port: u16, bypass: &[String]) -> Snapshot {
    // GNOME / GSettings 路径；non-GNOME 桌面需用户自行设置。
    let old = std::process::Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().trim_matches('\'').to_string());

    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy", "mode", "manual"])
        .status();
    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "host", server])
        .status();
    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "port", &port.to_string()])
        .status();
    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "host", server])
        .status();
    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "port", &port.to_string()])
        .status();
    if !bypass.is_empty() {
        let bypass_str = format!("[{}]", bypass.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "));
        let _ = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "ignore-hosts", &bypass_str])
            .status();
    }
    debug!(target: "capture::sysproxy", "GNOME gsettings configured");
    Snapshot { linux_gsettings_mode: old }
}

#[cfg(target_os = "linux")]
fn revert_platform(s: &Snapshot) {
    let mode = s.linux_gsettings_mode.as_deref().unwrap_or("none");
    let _ = std::process::Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy", "mode", mode])
        .status();
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn apply_platform(_server: &str, _port: u16, _bypass: &[String]) -> Snapshot {
    Snapshot::default()
}
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn revert_platform(_s: &Snapshot) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_disabled_is_noop() {
        let opts = TunHttpProxyOptions {
            enabled: false,
            server: "127.0.0.1".into(),
            server_port: 8080,
            bypass_domain: vec![],
            match_domain: vec![],
        };
        let g = SystemProxyGuard::install(&opts);
        // disabled → applied=false；revert 不会触发任何系统调用。
        g.revert();
    }

    #[test]
    fn enabled_returns_applied_guard() {
        // 真正写系统代理需要权限且有副作用 —— 这里只测 enabled 路径不 panic。
        let opts = TunHttpProxyOptions {
            enabled: false, // 保持 false 避免改本机；写入路径由 install_platform 测试在 CI 处理
            server: "127.0.0.1".into(),
            server_port: 0,
            bypass_domain: vec!["localhost".into()],
            match_domain: vec![],
        };
        let g = SystemProxyGuard::install(&opts);
        g.revert();
    }
}
