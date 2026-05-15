//! Android TUN 设备 I/O ——
//!
//! 优先级：
//! 1. **root 模式**：优先复用 Linux 的 `/dev/net/tun` + `ioctl(TUNSETIFF)`。
//! 2. **VpnService fd 注入 fallback**：宿主 App（Java/Kotlin）通过 [`set_vpn_fd`] 把
//!    `ParcelFileDescriptor` 的 fd（dup 后所有权交本进程）传过来。直接包成
//!    `OwnedFd` + `AsyncFd`，无需 root。
//! 3. 都不可用：返回 `Unsupported`。

#[cfg(target_os = "android")]
use std::os::fd::RawFd;
use std::sync::Arc;

#[cfg(target_os = "android")]
use parking_lot::Mutex;
#[cfg(target_os = "android")]
use tracing::{info, warn};

use crate::{
    engine::CapturePlan,
    tun_io::{TunIo, TunIoError},
};

#[cfg(target_os = "android")]
static INJECTED_FD: Mutex<Option<RawFd>> = Mutex::new(None);

/// 由 JNI 调用：注入 VpnService 创建的 fd（dup 后所有权交本进程）。
/// 多次调用以最后一次为准。
#[cfg(target_os = "android")]
pub fn set_vpn_fd(fd: RawFd) {
    *INJECTED_FD.lock() = Some(fd);
}

/// 取出 VpnService fd（take 语义，只能取一次）。
#[cfg(target_os = "android")]
pub fn take_injected_fd() -> Option<RawFd> {
    INJECTED_FD.lock().take()
}

#[cfg(target_os = "android")]
pub fn open(plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    use crate::platform::linux_tun_io::LinuxTunIo;

    // 1. root /dev/net/tun 优先。即使宿主曾注入 VpnService fd，root virtual_nic
    // 也不应被 fd 抢入口，否则 native 会拿到一张 Android framework 已配置过的
    // 网卡并继续执行 Linux route/rule，造成互相覆盖。
    match LinuxTunIo::open(&plan.interface_name, plan.mtu, plan.offload) {
        Ok(dev) => {
            info!(
                target: "capture::android",
                iface = %dev.name(),
                mtu = dev.mtu(),
                "opening TUN from root /dev/net/tun"
            );
            return Ok(Arc::new(dev));
        }
        Err(root_err) => {
            warn!(
                target: "capture::android",
                iface = %plan.interface_name,
                mtu = plan.mtu,
                error = %root_err,
                "root /dev/net/tun open failed; checking VpnService fd fallback"
            );
        }
    }

    // 2. 非 root / root TUN 不可用时，才使用 VpnService fd。
    if let Some(fd) = INJECTED_FD.lock().take() {
        info!(
            target: "capture::android",
            iface = %plan.interface_name,
            mtu = plan.mtu,
            fd,
            "opening TUN from VpnService fd"
        );
        if !core_outbound::has_socket_protector() {
            warn!(
                target: "capture::android",
                "VpnService fd injected but socket protector is not registered; outbound sockets may loop back into VPN"
            );
        }
        let dev = crate::platform::vpnservice_tun_io::VpnServiceTunIo::from_raw_fd(
            fd,
            plan.interface_name.clone(),
            plan.mtu,
        )?;
        return Ok(Arc::new(dev));
    }
    Err(TunIoError::Open(
        "android root /dev/net/tun unavailable and no VpnService fd injected".into(),
    ))
}

#[cfg(not(target_os = "android"))]
pub fn open(_plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    Err(TunIoError::Unsupported("非 Android 平台".into()))
}
