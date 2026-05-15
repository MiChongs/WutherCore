//! 平台事件驱动 default-iface 变化探测 —— 与 polling 互补，把响应延迟从
//! 2s（POLL_INTERVAL）压到 ~ms。
//!
//! ## 实现思路
//! 三个平台都把 OS 路由 / 接口变化事件投递到一个 `tokio::sync::Notify`，
//! 主任务 `notified().await` 之后简单去抖（100ms）→ 重新跑跨平台
//! [`crate::default_iface::probe`] → [`crate::net_monitor::global().submit`].
//! 这样回调 / netlink 收包路径只做 notify_one，所有的解析与全局态更新都在
//! 一个 tokio task 内顺序完成，不需要锁也没有竞争。
//!
//! ## 平台覆盖
//! * Windows：`NotifyRouteChange2` + `NotifyIpInterfaceChange`（windows-sys
//!   IP Helper API），系统线程 callback。
//! * Linux / Android：`AF_NETLINK` socket 订阅
//!   `RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK`，
//!   tokio `AsyncFd` 接管 IO。
//! * macOS / iOS：`PF_ROUTE`（`AF_ROUTE/SOCK_RAW`）socket，BSD route socket
//!   原生事件流，AsyncFd 接管。
//!
//! polling watcher 仍然保留作兜底（事件驱动注册失败、首次初值同步、
//! 探测稳态校验）。

#![allow(unsafe_code)]

use std::time::Duration;

use crate::{default_iface::ExcludeList, net_monitor::global};

/// 100ms 去抖 —— 网络切换时一波路由 / 接口事件风暴（add / del / link up /
/// link down 等），合并成一次 probe。
const DEBOUNCE: Duration = Duration::from_millis(100);

/// 启动当前平台的事件驱动 watcher。失败 / 不支持时不报错，调用方可继续依赖
/// polling 兜底。
pub fn start(exclude: ExcludeList) {
    #[cfg(target_os = "windows")]
    {
        windows_impl::start(exclude);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_impl::start(exclude);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        darwin_impl::start(exclude);
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = exclude;
    }
}

/* ============================================================
   Windows: NotifyRouteChange2 + NotifyIpInterfaceChange
============================================================ */
#[cfg(target_os = "windows")]
mod windows_impl {
    use std::{ffi::c_void, sync::Arc};

    use tokio::sync::Notify;
    use tracing::{info, warn};
    use windows_sys::Win32::{
        Foundation::{HANDLE, NO_ERROR},
        NetworkManagement::IpHelper::{
            MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
            NotifyIpInterfaceChange, NotifyRouteChange2,
        },
        Networking::WinSock::AF_UNSPEC,
    };

    use super::*;

    pub fn start(exclude: ExcludeList) {
        let notify = Arc::new(Notify::new());
        // Box::into_raw 拿到 'static 指针；进程生命周期持有，不显式 cancel。
        let ctx_ptr = Box::into_raw(Box::new(notify.clone())) as *const c_void;

        let mut route_handle: HANDLE = std::ptr::null_mut();
        let mut iface_handle: HANDLE = std::ptr::null_mut();

        let r1 = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC as u16,
                Some(route_callback),
                ctx_ptr,
                0,
                &mut route_handle,
            )
        };
        let r2 = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC as u16,
                Some(iface_callback),
                ctx_ptr,
                0,
                &mut iface_handle,
            )
        };
        if r1 != NO_ERROR || r2 != NO_ERROR {
            warn!(
                target: "capture::net_monitor",
                route_err = r1,
                iface_err = r2,
                "Windows event-driven registration failed; polling-only fallback active"
            );
            return;
        }

        info!(
            target: "capture::net_monitor",
            "Windows event-driven watcher armed (NotifyRouteChange2 + NotifyIpInterfaceChange)"
        );

        // 句柄 leak —— 进程级，stop 路径不需要显式 unregister。
        let _ = (route_handle, iface_handle);

        spawn_debounce_loop(notify, exclude);
    }

    unsafe extern "system" fn route_callback(
        caller_context: *const c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        _ntype: MIB_NOTIFICATION_TYPE,
    ) {
        if caller_context.is_null() {
            return;
        }
        let notify = unsafe { &*(caller_context as *const Arc<Notify>) };
        notify.notify_one();
    }

    unsafe extern "system" fn iface_callback(
        caller_context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _ntype: MIB_NOTIFICATION_TYPE,
    ) {
        if caller_context.is_null() {
            return;
        }
        let notify = unsafe { &*(caller_context as *const Arc<Notify>) };
        notify.notify_one();
    }
}

/* ============================================================
   Linux / Android: netlink RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK
============================================================ */
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux_impl {
    use std::{os::fd::AsRawFd, sync::Arc};

    use tokio::{io::unix::AsyncFd, sync::Notify};
    use tracing::{info, warn};

    use super::*;

    pub fn start(exclude: ExcludeList) {
        let notify = Arc::new(Notify::new());
        match open_netlink_socket() {
            Ok(fd) => {
                info!(
                    target: "capture::net_monitor",
                    "Linux event-driven watcher armed (RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK)"
                );
                tokio::spawn(netlink_loop(fd, notify.clone()));
                spawn_debounce_loop(notify, exclude);
            }
            Err(e) => {
                warn!(
                    target: "capture::net_monitor",
                    error = %e,
                    "netlink socket open failed; polling-only fallback active"
                );
            }
        }
    }

    fn open_netlink_socket() -> nix::Result<std::os::fd::OwnedFd> {
        use nix::sys::socket::{
            AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, socket,
        };
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )?;
        // 直接用内核裸值 —— libc crate 在 Android target 下未导出这些常量，
        // 但 RTMGRP_* 是 linux/rtnetlink.h 的稳定 ABI。
        // RTMGRP_LINK = 0x1, RTMGRP_IPV4_ROUTE = 0x40, RTMGRP_IPV6_ROUTE = 0x400
        const RTMGRP_LINK: u32 = 0x1;
        const RTMGRP_IPV4_ROUTE: u32 = 0x40;
        const RTMGRP_IPV6_ROUTE: u32 = 0x400;
        let groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_LINK;
        let addr = NetlinkAddr::new(0, groups);
        bind(fd.as_raw_fd(), &addr)?;
        Ok(fd)
    }

    async fn netlink_loop(fd: std::os::fd::OwnedFd, notify: Arc<Notify>) {
        let async_fd = match AsyncFd::new(fd) {
            Ok(f) => f,
            Err(e) => {
                warn!(target: "capture::net_monitor", error = %e, "AsyncFd::new failed");
                return;
            }
        };
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    warn!(target: "capture::net_monitor", error = %e, "netlink readable wait failed");
                    return;
                }
            };
            // try_io 处理 WOULDBLOCK 自动重新注册兴趣。
            let res = guard.try_io(|inner| {
                let raw_fd = inner.get_ref().as_raw_fd();
                // SAFETY: raw recv 调用，buf 在栈上有效，长度精确传入。
                let n = unsafe {
                    libc::recv(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(_n)) => {
                    // 收到任意 RTM_* 消息 —— 不需要解析消息体，只要"动了"就 notify。
                    notify.notify_one();
                }
                Ok(Err(e)) => {
                    warn!(target: "capture::net_monitor", error = %e, "netlink recv error");
                }
                Err(_would_block) => {
                    // try_io 返回 Err 表示 readable 是 spurious，循环回去再等。
                }
            }
        }
    }
}

/* ============================================================
   Darwin: PF_ROUTE socket
============================================================ */
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod darwin_impl {
    use std::{
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::Arc,
    };

    use tokio::{io::unix::AsyncFd, sync::Notify};
    use tracing::{info, warn};

    use super::*;

    pub fn start(exclude: ExcludeList) {
        let notify = Arc::new(Notify::new());
        match open_route_socket() {
            Ok(fd) => {
                info!(
                    target: "capture::net_monitor",
                    "macOS event-driven watcher armed (PF_ROUTE)"
                );
                tokio::spawn(route_loop(fd, notify.clone()));
                spawn_debounce_loop(notify, exclude);
            }
            Err(e) => {
                warn!(
                    target: "capture::net_monitor",
                    error = %e,
                    "PF_ROUTE socket open failed; polling-only fallback active"
                );
            }
        }
    }

    fn open_route_socket() -> std::io::Result<OwnedFd> {
        // socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC) —— BSD route socket。
        // PF_ROUTE = 17, SOCK_RAW = 3, AF_UNSPEC = 0；libc 全有常量。
        // SAFETY: 标准 socket(2) 调用；返回值 -1 视为错误。
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // 设为 nonblocking，AsyncFd 才能正确轮询。
        // SAFETY: raw 是有效 fd（上面检查过），fcntl 标准用法。
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFL, 0);
            if flags < 0 || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(raw);
                return Err(err);
            }
        }
        // SAFETY: 我们刚刚验证了 raw 是有效 fd，且没有别处持有所有权。
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    async fn route_loop(fd: OwnedFd, notify: Arc<Notify>) {
        let async_fd = match AsyncFd::new(fd) {
            Ok(f) => f,
            Err(e) => {
                warn!(target: "capture::net_monitor", error = %e, "AsyncFd::new failed");
                return;
            }
        };
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    warn!(target: "capture::net_monitor", error = %e, "PF_ROUTE readable wait failed");
                    return;
                }
            };
            let res = guard.try_io(|inner| {
                let raw_fd = inner.get_ref().as_raw_fd();
                // SAFETY: read 标准调用，buf 在栈上有效。
                let n =
                    unsafe { libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(_n)) => notify.notify_one(),
                Ok(Err(e)) => {
                    warn!(target: "capture::net_monitor", error = %e, "PF_ROUTE read error")
                }
                Err(_) => {} // spurious wakeup
            }
        }
    }
}

/* ============================================================
   Common debounce loop
============================================================ */

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn spawn_debounce_loop(notify: std::sync::Arc<tokio::sync::Notify>, exclude: ExcludeList) {
    tokio::spawn(async move {
        loop {
            notify.notified().await;
            // 去抖：网络切换时一波回调风暴（Wi-Fi → Ethernet 经常 5-15 个事件
            // 在 50-100ms 内连发），合并成一次 probe。
            tokio::time::sleep(DEBOUNCE).await;
            // 在 sleep 期间到来的额外 notify 已经合并掉了（Notify::notify_one 是
            // 幂等：未 await 时多次调用相当于一次）。
            let cur = crate::default_iface::probe(&exclude);
            global().submit(cur);
        }
    });
}
