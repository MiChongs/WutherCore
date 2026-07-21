//! 平台后端 —— 由 cfg(target_os) 选择具体实现。
//!
//! 每个平台模块需要导出：
//! * `pub fn build_engine(plan, deps) -> Result<Arc<dyn CaptureEngine>, CaptureError>`
//! * `pub fn list_interfaces() -> Vec<String>`
//!
//! 另有 `*_tun_io` 子模块负责跨平台 `TunIo` 实现，供 supervisor packet loop 使用。

use std::sync::Arc;

use crate::engine::{CaptureEngine, CaptureError, CapturePlan};

// Linux 与 Android 共享 /dev/net/tun + nftables 路径。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
// Linux TUN auto_redirect 的规则生成器在测试构建中也参与编译，便于在
// 非 Linux 主机验证命令账本；真实安装入口仅由 Linux/Android 后端调用。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) mod linux_auto_redirect;
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) mod linux_auto_redirect_route;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_identity_bypass;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_tproxy;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_tun_io;

// `virtio_net_hdr` 编解码 —— 跨平台编译，为单元测试提供主机可达的入口；
// 实际仅 Linux/Android 在 read/write 路径上引用。
pub mod vnet_hdr;
// GSO 接收方向切分（kernel 投递大段 → 切成多个完整 IP 包）。
// 阶段 3.5a：纯算法；3.5b 接到 Linux read_batch。
pub mod gso_split;
// GRO 发送方向合并（用户态多个连续段 → 合并成大段，让 kernel TSO 分片）。
// 阶段 3.6b：纯算法，未接 dispatcher / write 路径。
pub mod gro_merge;
pub(crate) mod route_probe;
pub mod tunrs_io;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod windows_tun_io;
#[cfg(target_os = "windows")]
pub mod wintun_abi;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod ios_bridge;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos_tun_io;

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
)))]
pub mod stub;

// Android 模块：所有平台都参与编译（提供类型 + cfg 守护命令调用），
// 让 select_tier 等纯逻辑可在任何主机做单元测试；实际 build_engine 仍受
// `target_os` 限制。
pub mod android;
#[cfg(target_os = "android")]
pub mod android_jni;
pub mod android_tun_io;
#[cfg(target_os = "android")]
pub mod vpnservice_tun_io;

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    #[cfg(not(target_os = "linux"))]
    if plan.auto_redirect {
        return Err(CaptureError::Unsupported(
            "capture.tun.auto_redirect is supported only by root-managed Linux TUN".into(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        return linux::build_engine(plan);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::build_engine(plan);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::build_engine(plan);
    }
    #[cfg(target_os = "android")]
    {
        // Tun → Linux engine（带真实 TunIo）；Tproxy/Redirect → AndroidCapture（4-tier nft）
        return android::build_engine(plan);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        return stub::build_engine(plan);
    }
}

pub fn list_interfaces() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        return linux::list_interfaces();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::list_interfaces();
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::list_interfaces();
    }
    #[cfg(target_os = "android")]
    {
        return crate::platform::android::list_interfaces();
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        return stub::list_interfaces();
    }
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn is_absent_ip_rule_delete(prog: &str, args: &[&str], stderr: &str) -> bool {
    if prog != "ip" {
        return false;
    }
    let args = strip_ip_family_prefix(args);
    if args.len() < 2 || args[0] != "rule" || args[1] != "del" {
        return false;
    }
    stderr.to_ascii_lowercase().contains("no such file")
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn strip_ip_family_prefix<'a, 'b>(args: &'a [&'b str]) -> &'a [&'b str] {
    match args {
        ["-4" | "-6", rest @ ..] => rest,
        ["-f", _family, rest @ ..] => rest,
        _ => args,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::build_engine;
    use super::is_absent_ip_rule_delete;

    #[test]
    fn ip_rule_delete_no_such_file_is_expected_cleanup_absence() {
        assert!(is_absent_ip_rule_delete(
            "ip",
            &["rule", "del", "fwmark", "0xff", "lookup", "main"],
            "RTNETLINK answers: No such file or directory\n",
        ));
        assert!(is_absent_ip_rule_delete(
            "ip",
            &["-6", "rule", "del", "priority", "9099", "lookup", "main"],
            "RTNETLINK answers: No such file or directory\n",
        ));
    }

    #[test]
    fn ip_rule_delete_other_failure_is_not_expected_cleanup_absence() {
        assert!(!is_absent_ip_rule_delete(
            "ip",
            &["rule", "del", "fwmark", "0xff", "lookup", "main"],
            "Operation not permitted\n",
        ));
        assert!(!is_absent_ip_rule_delete(
            "nft",
            &["rule", "del", "fwmark", "0xff", "lookup", "main"],
            "RTNETLINK answers: No such file or directory\n",
        ));
        assert!(!is_absent_ip_rule_delete(
            "ip",
            &["rule", "add", "fwmark", "0xff", "lookup", "main"],
            "RTNETLINK answers: No such file or directory\n",
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_low_level_engine_build_rejects_auto_redirect() {
        let capture = core_config::model::Capture {
            on: true,
            method: core_config::model::CaptureMethod::VirtualNic,
            traffic: core_config::model::CaptureTraffic::System,
            tun: core_config::model::TunInboundOptions {
                auto_route: true,
                auto_redirect: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let plan = crate::engine::CapturePlan::from_config(&capture).unwrap();

        let error = match build_engine(plan) {
            Ok(_) => panic!("non-Linux auto_redirect must fail at the platform boundary"),
            Err(error) => error,
        };
        assert!(matches!(error, crate::engine::CaptureError::Unsupported(_)));
        assert!(error.to_string().contains("root-managed Linux"));
    }
}
