//! 平台后端 —— 由 cfg(target_os) 选择具体实现。
//!
//! 每个平台模块需要导出：
//! * `pub fn build_engine(plan, deps) -> Result<Arc<dyn CaptureEngine>, CaptureError>`
//! * `pub fn list_interfaces() -> Vec<String>`
//!
//! 另有 `*_tun_io` 子模块负责跨平台 [`TunIo`] 实现，供 supervisor packet loop 使用。

use std::sync::Arc;

use crate::engine::{CaptureEngine, CaptureError, CapturePlan};

// Linux 与 Android 共享 /dev/net/tun + nftables 路径。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_tun_io;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux_tproxy;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod wintun_abi;
#[cfg(target_os = "windows")]
pub mod windows_tun_io;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos_tun_io;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod ios_bridge;

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
pub mod android_tun_io;
#[cfg(target_os = "android")]
pub mod android_jni;
#[cfg(target_os = "android")]
pub mod vpnservice_tun_io;

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
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
