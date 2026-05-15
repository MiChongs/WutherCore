//! Doctor —— 启动前/启动后诊断。
//!
//! §9.3 路由冲突处理：
//! 1. 检测 tailscale0 / tailscaled
//! 2. capture 是否会接管 100.64.0.0/10
//! 3. resolver 是否会污染 MagicDNS
//! 4. default route 是否覆盖 Tailnet

use core_config::model::{Capture, Mesh};
use serde::Serialize;

use crate::engine::{CaptureError, CapturePlan, EngineKind};

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub platform: String,
    pub kind: String,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
    pub interfaces: Vec<String>,
}

impl DoctorReport {
    pub fn ok(&self) -> bool {
        self.blockers.is_empty()
    }
}

pub fn diagnose(c: &Capture, mesh: &Mesh) -> Result<DoctorReport, CaptureError> {
    let plan = CapturePlan::from_config(c)?;
    let mut warnings = vec![];
    let mut blockers = vec![];
    let interfaces = list_interfaces();

    if plan.kind == EngineKind::None {
        return Ok(DoctorReport {
            platform: std::env::consts::OS.into(),
            kind: "none".into(),
            warnings,
            blockers,
            interfaces,
        });
    }

    // Tailscale 冲突
    if let Some(ts) = mesh.tailscale.as_ref() {
        if ts.on && !ts.keep_tailnet_direct {
            warnings.push(
                "Tailscale 已启用但 keep_tailnet_direct=false，可能导致 Tailnet 被代理".into(),
            );
        }
    }
    if interfaces
        .iter()
        .any(|n| n.starts_with("tailscale") || n == "ts0" || n == "Tailscale")
    {
        if !plan
            .exclude_cidrs
            .iter()
            .any(|n| n.to_string() == "100.64.0.0/10")
        {
            blockers.push(
                "检测到 tailscale0 接口，但 capture.exclude.cidr 未包含 100.64.0.0/10".into(),
            );
        }
    }

    // sing-box 字段一致性检查
    if plan.auto_redirect && !cfg!(any(target_os = "linux", target_os = "android")) {
        warnings.push(format!(
            "auto_redirect 仅在 Linux/Android 生效（当前 {}）",
            std::env::consts::OS
        ));
    }
    if plan.strict_route && !plan.auto_route {
        warnings.push("strict_route=true 但 auto_route=false：可能切断所有流量".into());
    }
    let marks = &plan.auto_redirect_marks;
    if let (Some(i), Some(o)) = (marks.input, marks.output) {
        if i == o {
            blockers.push(format!(
                "auto_redirect_input_mark 与 output_mark 重叠 ({i:#x})"
            ));
        }
    }
    if !plan.route_addresses.is_empty() && plan.strict_route {
        warnings
            .push("route_address 白名单 + strict_route 同时启用：白名单外的目标全部被 drop".into());
    }
    if !c.tun.include_uid.is_empty() && !cfg!(any(target_os = "linux", target_os = "android")) {
        warnings.push("include_uid / exclude_uid 仅在 Linux/Android 生效".into());
    }
    let has_gid_filter = !c.tun.include_gid.is_empty()
        || !c.tun.exclude_gid.is_empty()
        || !c.tun.include_gid_range.is_empty()
        || !c.tun.exclude_gid_range.is_empty();
    if has_gid_filter && !cfg!(any(target_os = "linux", target_os = "android")) {
        warnings.push("include_gid / exclude_gid 仅在 Linux/Android 生效".into());
    }
    if !c.tun.include_package.is_empty() && !cfg!(target_os = "android") {
        warnings.push("include_package / exclude_package 仅在 Android 生效".into());
    }

    // 平台特定 doctor
    match plan.kind {
        EngineKind::Tproxy | EngineKind::Redirect => {
            if !cfg!(target_os = "linux") && !cfg!(target_os = "android") {
                blockers.push(format!("{:?} 仅 Linux/Android", plan.kind));
            } else {
                if !has_tool("nft") && !has_tool("iptables") {
                    blockers.push(
                        "缺少 nft 或 iptables —— OpenWrt 请安装 kmod-nft-tproxy 或 iptables-mod-tproxy"
                            .into(),
                    );
                }
            }
        }
        EngineKind::Tun => {
            #[cfg(target_os = "linux")]
            {
                if !std::path::Path::new("/dev/net/tun").exists() {
                    blockers.push("/dev/net/tun 不存在，请加载 tun 内核模块".into());
                }
            }
            #[cfg(target_os = "windows")]
            {
                if !has_tool("netsh") {
                    warnings.push("未找到 netsh；可能无法自动写路由表".into());
                }
            }
            #[cfg(target_os = "macos")]
            {
                // utun 由内核内置，无需检查 dev 节点
            }
        }
        EngineKind::None => {}
    }

    Ok(DoctorReport {
        platform: std::env::consts::OS.into(),
        kind: format!("{:?}", plan.kind).to_lowercase(),
        warnings,
        blockers,
        interfaces,
    })
}

fn has_tool(name: &str) -> bool {
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path_env).any(|p| {
        let mut full = p.join(name);
        if cfg!(windows) {
            full.set_extension("exe");
        }
        full.is_file()
    })
}

fn list_interfaces() -> Vec<String> {
    // 平台无关：只列出名字。具体实现见 platform/*。
    crate::platform::list_interfaces()
}

#[cfg(test)]
mod tests {
    use core_config::model::{
        Capture, CaptureExclude, CaptureMethod, CaptureResolver, CaptureStack, CaptureTraffic,
        Mesh, TunInboundOptions,
    };

    use super::*;

    fn capture(on: bool) -> Capture {
        Capture {
            on,
            method: CaptureMethod::Auto,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Hijack,
            stack: CaptureStack::Native,
            mtu: None,
            offload: true,
            exclude: CaptureExclude::default(),
            tun: TunInboundOptions::default(),
        }
    }

    #[test]
    fn off_returns_kind_none() {
        let r = diagnose(&capture(false), &Mesh::default()).unwrap();
        assert_eq!(r.kind, "none");
        assert!(r.ok());
    }

    #[test]
    fn detects_overlapping_redirect_marks() {
        let mut c = capture(true);
        c.method = CaptureMethod::VirtualNic;
        c.tun.auto_redirect = true;
        c.tun.auto_redirect_input_mark = Some("0x1".into());
        c.tun.auto_redirect_output_mark = Some("0x1".into());
        let r = diagnose(&c, &Mesh::default()).unwrap();
        assert!(r.blockers.iter().any(|b| b.contains("重叠")));
    }

    #[test]
    fn warns_strict_route_without_auto_route() {
        let mut c = capture(true);
        c.method = CaptureMethod::VirtualNic;
        c.tun.strict_route = true;
        c.tun.auto_route = false;
        let r = diagnose(&c, &Mesh::default()).unwrap();
        assert!(r.warnings.iter().any(|w| w.contains("strict_route")));
    }

    #[test]
    fn diagnose_accepts_gid_filters() {
        // 在 Linux/Android 上不该有 GID 警告；其它平台应有警告。
        let mut c = capture(true);
        c.method = CaptureMethod::VirtualNic;
        c.tun.exclude_gid = vec![1000];
        c.tun.include_gid_range = vec!["3000:3999".into()];
        let r = diagnose(&c, &Mesh::default()).unwrap();
        let has_gid_warn = r.warnings.iter().any(|w| w.contains("gid"));
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert!(!has_gid_warn, "Linux/Android 应直接接受 gid 字段");
        } else {
            assert!(has_gid_warn, "其它平台应提示 gid 不生效");
        }
    }
}
