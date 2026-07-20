//! Per-platform process lookup —— 1:1 对齐 mihomo `component/process`。
//!
//! ## 输入 / 输出
//!
//! 输入是 (proto, src_ip, src_port)。返回 [`ProcessInfo`]（含 process name + 路径
//! + uid）。语义与 mihomo `FindProcessName(network, srcIP, srcPort)` 完全一致。
//!
//! ## 平台
//!
//! | 平台 | API | 备注 |
//! |------|-----|------|
//! | Windows | `iphlpapi::GetExtendedTcpTable` / `GetExtendedUdpTable` | 含 PID；OpenProcess + QueryFullProcessImageName 拿路径 |
//! | Linux | 解析 `/proc/net/tcp{,6}` / `udp{,6}` → inode → walk `/proc/*/fd/` | 全 safe；Android 同源（受权限限制） |
//! | macOS | `libproc::proc_listpids` + `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidpath` | unsafe FFI，跟 sing-box 一致 |
//! | 其他 | NoopFinder | 永远返回 None |
//!
//! ## 调用契约
//!
//! [`ProcessFinder::find`] 必须是同步的：调用方负责 `spawn_blocking` 包装。原因：
//!
//! 1. Windows / macOS 的底层 API 是 blocking 系统调用，async wrapper 也只是
//!    `spawn_blocking` 的别名；
//! 2. Linux `/proc` 解析涉及多个 syscall，单次 call 1-10ms，hot-path 上必须
//!    `spawn_blocking` 否则抢 reactor 线程；
//! 3. 把 async 决策下放给调用方而不是 trait —— 调用方知道 cache 是否命中、是否
//!    已经在 blocking pool 上下文里。
//!
//! ## 缓存
//!
//! `CachedFinder` 给任何 `ProcessFinder` 加 LRU + TTL 包装。默认 1024 条 / 10s。
//! TTL 不能太长 —— 同一 (proto, ip, port) 在 10s 内可能被另一个进程重用（apps
//! 关闭后 socket 进入 TIME_WAIT，30s 后端口可重用；mihomo 也用 ~10s）。

use std::{net::IpAddr, sync::Arc};

pub mod cache;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "macos")]
mod macos;

/// 协议族 —— 与 mihomo `network` 字符串等价。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProto {
    Tcp,
    Udp,
}

impl NetworkProto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// 反查到的进程信息。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    /// 进程名（basename，e.g. `chrome.exe` / `Code` / `com.tencent.mm`）。
    pub name: String,
    /// 进程完整路径（platform-specific，可能为空）。
    pub path: String,
    /// owning user id —— Windows 不可靠 (=0)；Linux / macOS 真值。
    pub uid: u32,
}

impl ProcessInfo {
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.path.is_empty()
    }
}

/// 反查 trait —— 同步调用契约（调用方负责 spawn_blocking）。
pub trait ProcessFinder: Send + Sync {
    /// 同步反查；找不到返回 `None`，平台不支持也返回 `None`（不区分）。
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo>;

    /// 带目的端口的反查 —— 仅 Android `ConnectivityManager.getConnectionOwnerUid`
    /// 等需要 5-tuple 的实现需要覆盖；其它平台默认转发到 [`Self::find`]。
    /// 调用方 (listener_handler) 优先用这个，让 Android 在非 root 跨 app 场景
    /// 也能查到。
    fn find_with_dst(
        &self,
        proto: NetworkProto,
        src_ip: IpAddr,
        src_port: u16,
        _dst_ip: IpAddr,
        _dst_port: u16,
    ) -> Option<ProcessInfo> {
        self.find(proto, src_ip, src_port)
    }
}

/// 平台无关的 noop —— Linux 容器、未知 OS 等场景的兜底，永远返回 None。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFinder;

impl ProcessFinder for NoopFinder {
    fn find(&self, _proto: NetworkProto, _ip: IpAddr, _port: u16) -> Option<ProcessInfo> {
        None
    }
}

/// 工厂：按当前 target_os 选择对应实现。返回的 finder 已经包了 `CachedFinder`
/// （1024 条 / 10s TTL），调用方不必再加 cache。
pub fn create_finder() -> Arc<dyn ProcessFinder> {
    let inner = create_finder_uncached();
    Arc::new(cache::CachedFinder::new(
        inner,
        1024,
        std::time::Duration::from_secs(10),
    ))
}

/// 不带 cache 的工厂 —— 测试用。
pub fn create_finder_uncached() -> Arc<dyn ProcessFinder> {
    #[cfg(target_os = "windows")]
    {
        return Arc::new(windows::WindowsFinder::new());
    }
    #[cfg(target_os = "linux")]
    {
        return Arc::new(linux::LinuxFinder::new());
    }
    #[cfg(target_os = "android")]
    {
        return Arc::new(android::AndroidFinder::new());
    }
    #[cfg(target_os = "macos")]
    {
        return Arc::new(macos::MacosFinder::new());
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    )))]
    {
        Arc::new(NoopFinder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_finder_returns_none() {
        let f = NoopFinder;
        assert!(
            f.find(NetworkProto::Tcp, "127.0.0.1".parse().unwrap(), 1)
                .is_none()
        );
    }

    #[test]
    fn create_finder_constructs_arc() {
        // platform-specific finder must construct without panic.
        let _ = create_finder();
    }
}
