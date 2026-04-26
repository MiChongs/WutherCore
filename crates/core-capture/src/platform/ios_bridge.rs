//! iOS NEPacketTunnelProvider 桥 —— 与 Android JNI 对称的 C ABI 入口。
//!
//! Swift / Objective-C 端约定：
//! ```swift
//! @_silgen_name("rpkernel_set_packet_tunnel_fd")
//! func rpkernel_set_packet_tunnel_fd(_ fd: Int32)
//!
//! @_silgen_name("rpkernel_native_start")
//! func rpkernel_native_start() -> Int32
//!
//! @_silgen_name("rpkernel_native_stop")
//! func rpkernel_native_stop()
//! ```
//!
//! `NEPacketTunnelProvider` 在 `startTunnel(options:)` 中：
//! 1. 配置 `NEPacketTunnelNetworkSettings`；
//! 2. 通过 `setTunnelNetworkSettings` 拿到 utun fd（可借助 `dup` + 私有 API 或
//!    直接走 `packetFlow.readPackets/writePackets`）；
//! 3. 调用 `rpkernel_set_packet_tunnel_fd(fd)`；
//! 4. 调用 `rpkernel_native_start()` 让 Rust 接管。
//!
//! 为兼容性留两个版本：fd 直注入（需要 entitlement）+ packetFlow 通道。

#![cfg(any(target_os = "ios", target_os = "macos"))]
#![allow(unsafe_code)]
#![allow(non_snake_case)]

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

static STARTED: AtomicBool = AtomicBool::new(false);
static INJECTED_FD: Mutex<Option<RawFd>> = Mutex::new(None);

#[no_mangle]
pub extern "C" fn rpkernel_set_packet_tunnel_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    *INJECTED_FD.lock() = Some(fd as RawFd);
}

#[no_mangle]
pub extern "C" fn rpkernel_native_start() -> i32 {
    STARTED.store(true, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "C" fn rpkernel_native_stop() {
    STARTED.store(false, Ordering::SeqCst);
}

pub fn is_started() -> bool {
    STARTED.load(Ordering::SeqCst)
}

/// 给 macos_tun_io / 未来 ios_tun_io 调用：是否注入了 PacketTunnel fd。
pub fn take_injected_fd() -> Option<RawFd> {
    INJECTED_FD.lock().take()
}
