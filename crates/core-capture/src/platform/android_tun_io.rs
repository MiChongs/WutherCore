//! Android TUN 设备 I/O ——
//!
//! 优先级：
//! 1. **VpnService fd 注入**：宿主 App（Java/Kotlin）通过 [`set_vpn_fd`] 把
//!    `ParcelFileDescriptor` 的 fd（dup 后所有权交本进程）传过来。直接包成
//!    `OwnedFd` + `AsyncFd`，无需 root。
//! 2. **root 模式**：`detect_capability().has_root` → 复用 Linux 的
//!    `/dev/net/tun` + `ioctl(TUNSETIFF)`。
//! 3. 都不可用：返回 `Unsupported`。

use std::sync::Arc;

#[cfg(target_os = "android")]
use std::os::fd::RawFd;
#[cfg(target_os = "android")]
use parking_lot::Mutex;

use crate::engine::CapturePlan;
use crate::tun_io::{TunIo, TunIoError};

#[cfg(target_os = "android")]
static INJECTED_FD: Mutex<Option<RawFd>> = Mutex::new(None);

/// 由 JNI 调用：注入 VpnService 创建的 fd（dup 后所有权交本进程）。
/// 多次调用以最后一次为准。
#[cfg(target_os = "android")]
pub fn set_vpn_fd(fd: RawFd) {
    *INJECTED_FD.lock() = Some(fd);
}

#[cfg(target_os = "android")]
pub fn open(plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    use crate::platform::linux_tun_io::LinuxTunIo;

    // 1. 优先 VpnService fd（绝大多数移动端场景）
    if let Some(fd) = INJECTED_FD.lock().take() {
        let dev = crate::platform::vpnservice_tun_io::VpnServiceTunIo::from_raw_fd(
            fd,
            plan.interface_name.clone(),
            plan.mtu,
        )?;
        return Ok(Arc::new(dev));
    }
    // 2. root 模式
    let dev = LinuxTunIo::open(&plan.interface_name, plan.mtu)
        .map_err(|e| TunIoError::Open(format!("android (root) tun open: {e}")))?;
    Ok(Arc::new(dev))
}

#[cfg(not(target_os = "android"))]
pub fn open(_plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    Err(TunIoError::Unsupported("非 Android 平台".into()))
}
