//! Linux TUN 设备 I/O —— `/dev/net/tun` + `ioctl(TUNSETIFF)`。
//!
//! 流程：
//! 1. 打开 `/dev/net/tun` 得到字符设备 fd；
//! 2. 通过 `ioctl(TUNSETIFF, ifr)` 把 fd 绑定到指定网卡名；
//!    `ifr.flags = IFF_TUN | IFF_NO_PI`（无 protocol info 头）；
//! 3. 把 fd 设为 O_NONBLOCK；
//! 4. 包装成 `tokio::io::unix::AsyncFd` 异步读写。
//!
//! ## unsafe 政策
//!
//! 仅 `unsafe_ioctl_tunsetiff` 局部使用 unsafe（`libc::ioctl` 调用 + `ifreq`
//! 字段填充）。其它代码全在 safe 区域。

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::engine::CapturePlan;
use crate::tun_io::{TunIo, TunIoError};

const IFF_TUN: i32 = 0x0001;
const IFF_NO_PI: i32 = 0x1000;
const IFF_TUN_EXCL: i32 = 0x4000;
const IFNAMSIZ: usize = 16;
// SIOCSIFMTU = 0x8922（<linux/sockios.h>），通过控制 socket(AF_INET, SOCK_DGRAM)
// 调用即可；与 sing-tun 保持一致，避免 `ip link set` 命令路径在阉割工具链下静默失败。
const SIOCSIFMTU: libc::Ioctl = 0x8922 as libc::Ioctl;

// ioctl 编号：定义在 <linux/if_tun.h>，由 _IOW('T', 202, int) 组成。
// 直接使用常量避免引入 nix 的 macro。
//
// 注意：`libc::ioctl` 在 glibc 上的 `request` 参数类型为 `c_ulong`（u64 on x86_64），
// 而在 Bionic（Android）上是 `c_int`（i32）。统一用 `libc::Ioctl`（类型别名）规避。
const TUNSETIFF: libc::Ioctl = 0x4004_54CA as libc::Ioctl;

#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: i16,
    _pad: [u8; 22],
}

pub struct LinuxTunIo {
    name: String,
    mtu: u32,
    fd: AsyncFd<OwnedFd>,
}

pub fn open(plan: &CapturePlan) -> Result<Arc<LinuxTunIo>, TunIoError> {
    let dev = LinuxTunIo::open(&plan.interface_name, plan.mtu)?;
    Ok(Arc::new(dev))
}

/// 尝试 ioctl(TUNSETIFF) 绑定 fd 到 name。三段式：
/// 1. 优先 `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`，与 mihomo/sing-tun 一致；
/// 2. EBUSY 时 `ip tuntap del` 清理残留，再用 EXCL 重试；
/// 3. 仍 EBUSY → 去掉 EXCL 重试（兼容 Android 持久化 TUN 与容器场景）。
fn try_attach(name: &str) -> Result<(OwnedFd, String), TunIoError> {
    fn do_open(name: &str, exclusive: bool) -> Result<(OwnedFd, String), TunIoError> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc_o_nonblock())
            .open("/dev/net/tun")
            .map_err(|e| TunIoError::Open(format!("open /dev/net/tun: {e}")))?;
        let owned: OwnedFd = f.into();
        let raw = owned.as_raw_fd();
        let bound = unsafe_ioctl_tunsetiff(raw, name, exclusive)
            .map_err(|e| TunIoError::Open(format!("ioctl TUNSETIFF: {e}")))?;
        Ok((owned, bound))
    }
    // 第 1 步：EXCL
    match do_open(name, true) {
        Ok(v) => return Ok(v),
        Err(TunIoError::Open(msg)) if is_ebusy(&msg) => {
            tracing::warn!(target: "capture::linux::tun", iface = %name, "EBUSY (exclusive); tuntap del then retry");
            let _ = std::process::Command::new("ip")
                .args(["tuntap", "del", "dev", name, "mode", "tun"])
                .status();
        }
        Err(e) => return Err(e),
    }
    // 第 2 步：del 后再 EXCL
    match do_open(name, true) {
        Ok(v) => return Ok(v),
        Err(TunIoError::Open(msg)) if is_ebusy(&msg) => {
            tracing::warn!(target: "capture::linux::tun", iface = %name, "EBUSY again; retry without EXCL");
        }
        Err(e) => return Err(e),
    }
    // 第 3 步：去掉 EXCL（与 Android VpnService 等场景兼容）
    do_open(name, false)
}

fn is_ebusy(msg: &str) -> bool {
    let l = msg.to_lowercase();
    l.contains("device or resource busy") || l.contains("(os error 16)")
}

impl LinuxTunIo {
    pub fn open(name: &str, mtu: u32) -> Result<Self, TunIoError> {
        if name.len() >= IFNAMSIZ {
            return Err(TunIoError::Open(format!(
                "interface name 太长（{} ≥ {IFNAMSIZ}）",
                name.len()
            )));
        }
        // 1+2. 打开 /dev/net/tun + ioctl(TUNSETIFF)，EBUSY 自愈
        let (owned, bound_name) = try_attach(name)?;
        let raw = owned.as_raw_fd();

        // 3. 设为 nonblocking（OpenOptions 已带 O_NONBLOCK，这里二次保险）
        if let Err(e) = set_nonblocking(raw) {
            return Err(TunIoError::Open(format!("set O_NONBLOCK: {e}")));
        }

        // 4. 直接 ioctl(SIOCSIFMTU) 设 MTU —— 不依赖 `ip link set`，
        //    与 mihomo 一致。失败仅 warn，让 supervisor 在外层 fallback `ip link set`。
        if let Err(e) = unsafe_set_mtu(&bound_name, mtu) {
            tracing::warn!(
                target: "capture::linux::tun",
                iface = %bound_name, mtu, error = %e,
                "ioctl SIOCSIFMTU failed; supervisor 将尝试 `ip link set` 兜底"
            );
        }

        // 5. 包装成 AsyncFd
        let async_fd = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| TunIoError::Open(format!("AsyncFd: {e}")))?;

        Ok(Self { name: bound_name, mtu, fd: async_fd })
    }
}

#[async_trait]
impl TunIo for LinuxTunIo {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(TunIoError::Read)?;
            match guard.try_io(|inner| read_fd(inner.as_raw_fd(), buf)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Read(e)),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(TunIoError::Write)?;
            match guard.try_io(|inner| write_fd(inner.as_raw_fd(), pkt)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Write(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn name(&self) -> &str { &self.name }
    fn mtu(&self) -> u32 { self.mtu }
    async fn close(&self) -> Result<(), TunIoError> { Ok(()) }
}

/* ---------------- unsafe 区 ---------------- */

#[allow(unsafe_code)]
fn unsafe_ioctl_tunsetiff(fd: RawFd, name: &str, exclusive: bool) -> std::io::Result<String> {
    // SAFETY:
    // * `IfReq` 是 repr(C)，与 Linux <linux/if.h> 中 `struct ifreq` 兼容字段顺序。
    // * `ioctl` 接收 fd 与 *mut IfReq；req 在调用结束前不会移动（栈上局部变量）。
    // * 失败时返回 -1，errno 由 last_os_error 读取。
    let mut flags = IFF_TUN | IFF_NO_PI;
    if exclusive {
        flags |= IFF_TUN_EXCL;
    }
    let mut ifr = IfReq {
        ifr_name: [0u8; IFNAMSIZ],
        ifr_flags: flags as i16,
        _pad: [0u8; 22],
    };
    let bytes = name.as_bytes();
    ifr.ifr_name[..bytes.len()].copy_from_slice(bytes);
    let rc = unsafe {
        libc::ioctl(
            fd,
            TUNSETIFF,
            &mut ifr as *mut IfReq as *mut libc::c_void,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // 内核可能改写 ifr_name（如重命名后），按 NUL 截取。
    let end = ifr
        .ifr_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ifr.ifr_name.len());
    let final_name = std::str::from_utf8(&ifr.ifr_name[..end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .to_string();
    Ok(final_name)
}

#[repr(C)]
struct IfReqMtu {
    ifr_name: [u8; IFNAMSIZ],
    ifr_mtu: i32,
    _pad: [u8; 20],
}

#[allow(unsafe_code)]
fn unsafe_set_mtu(name: &str, mtu: u32) -> std::io::Result<()> {
    if name.len() >= IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: 控制 socket 临时打开 + setsockopt 风格 ioctl；req 栈上局部，
    // 内核只读 ifr_name + ifr_mtu。
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut req = IfReqMtu {
        ifr_name: [0u8; IFNAMSIZ],
        ifr_mtu: mtu as i32,
        _pad: [0u8; 20],
    };
    let bytes = name.as_bytes();
    req.ifr_name[..bytes.len()].copy_from_slice(bytes);
    let rc = unsafe {
        libc::ioctl(
            s,
            SIOCSIFMTU,
            &mut req as *mut IfReqMtu as *mut libc::c_void,
        )
    };
    let saved = std::io::Error::last_os_error();
    unsafe {
        libc::close(s);
    }
    if rc < 0 {
        return Err(saved);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl 仅读写 fd 标志位；`O_NONBLOCK` 是合法值。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: read(2) 只写 buf 范围内的字节；buf 大小由 len() 给出。
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[allow(unsafe_code)]
fn write_fd(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    // SAFETY: write(2) 只读 buf 范围内的字节。
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn libc_o_nonblock() -> i32 {
    libc::O_NONBLOCK
}
