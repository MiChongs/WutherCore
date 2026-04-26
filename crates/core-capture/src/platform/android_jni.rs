//! Android JNI 入口 —— 暴露给宿主 App（Java/Kotlin）的 native 函数。
//!
//! Java 端约定：
//! ```java
//! package org.rpkernel;
//! public class VpnBridge {
//!     static { System.loadLibrary("rpkernel"); }
//!     // 把 ParcelFileDescriptor.detachFd() 得到的 fd 交给 native。
//!     public static native void setVpnFd(int fd);
//!     // （可选）通知 native 可以开始工作 —— 实际 capture supervisor 启动由
//!     // proxy-core::main 控制。
//!     public static native int nativeStart();
//!     public static native void nativeStop();
//! }
//! ```
//!
//! ## 类型对齐
//!
//! JNI extern 函数签名遵循 `Java_<package_underscored>_<Class>_<method>`。
//! 这里定义最小集合；完整 JNI（JNIEnv、jobject 等）由宿主 App 接管复杂参数。

#![cfg(target_os = "android")]
#![allow(unsafe_code)]
#![allow(non_snake_case)]

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

static STARTED: AtomicBool = AtomicBool::new(false);

/// `void setVpnFd(int fd)` —— 把 ParcelFileDescriptor.detachFd() 的 fd 交给本进程。
#[no_mangle]
pub extern "system" fn Java_org_rpkernel_VpnBridge_setVpnFd(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
    fd: i32,
) {
    if fd < 0 {
        return;
    }
    crate::platform::android_tun_io::set_vpn_fd(fd as RawFd);
}

/// `int nativeStart()` —— 标记 native 已就绪；返回 0 / 非 0 表示状态。
#[no_mangle]
pub extern "system" fn Java_org_rpkernel_VpnBridge_nativeStart(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
) -> i32 {
    STARTED.store(true, Ordering::SeqCst);
    0
}

/// `void nativeStop()` —— 仅做标记；真正停止由上层 supervisor 完成。
#[no_mangle]
pub extern "system" fn Java_org_rpkernel_VpnBridge_nativeStop(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
) {
    STARTED.store(false, Ordering::SeqCst);
}

pub fn is_started() -> bool {
    STARTED.load(Ordering::SeqCst)
}
