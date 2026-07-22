//! macOS / iOS utun 设备 I/O —— `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
//! + `ioctl(CTLIOCGINFO)` 拿到 utun 控制 id + `connect(struct sockaddr_ctl)`。
//!
//! 与 Linux 不同：utun 包含 4 字节 protocol family 前缀（AF_INET / AF_INET6），
//! 因此 read/write 都要剥离/添加这 4 字节。
//!
//! ## unsafe 政策
//!
//! 仅 `unsafe_open_utun` + `unsafe_read/write` 使用 unsafe；其它逻辑全在 safe 区。

use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    engine::CapturePlan,
    tun_io::{TunIo, TunIoError},
};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
// _IOC(IOC_INOUT,'N',3,sizeof(struct ctl_info)) ↦ 0xC0644E03（macOS）
const CTLIOCGINFO: u64 = 0xC064_4E03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct MacUtunIo {
    name: String,
    mtu: u32,
    fd: AsyncFd<OwnedFd>,
}

pub fn open(plan: &CapturePlan) -> Result<Arc<MacUtunIo>, TunIoError> {
    // 1. 优先：iOS NEPacketTunnelProvider 注入的 fd（需要 entitlement）。
    if let Some(fd) = crate::platform::ios_bridge::take_injected_fd() {
        let dev = MacUtunIo::from_injected_fd(fd, plan.interface_name.clone(), plan.mtu)?;
        return Ok(Arc::new(dev));
    }
    // 2. 默认：自己 socket(PF_SYSTEM, SYSPROTO_CONTROL) 打开 utun。
    let dev = MacUtunIo::open(&plan.interface_name, plan.mtu)?;
    Ok(Arc::new(dev))
}

impl MacUtunIo {
    /// 用 NEPacketTunnelProvider 注入的 fd 构造 —— fd 已经绑好 utun，无需 ioctl。
    #[allow(unsafe_code)]
    pub fn from_injected_fd(fd: i32, name: String, mtu: u32) -> Result<Self, TunIoError> {
        // SAFETY: fd 由 Swift 侧 dup 给本进程，所有权交本进程；不会被宿主再 close。
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(owned.as_raw_fd())
            .map_err(|e| TunIoError::Open(format!("set O_NONBLOCK: {e}")))?;
        let async_fd = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| TunIoError::Open(format!("AsyncFd: {e}")))?;
        Ok(Self {
            name,
            mtu,
            fd: async_fd,
        })
    }

    pub fn open(name_hint: &str, mtu: u32) -> Result<Self, TunIoError> {
        // utun 接口名形如 utun7。从 hint 中提取数字 unit；空时用 0（让内核自选）。
        let unit = parse_utun_unit(name_hint).unwrap_or(0);
        let (owned_fd, final_name) =
            unsafe_open_utun(unit).map_err(|e| TunIoError::Open(format!("utun open: {e}")))?;
        let raw = owned_fd.as_raw_fd();
        set_nonblocking(raw).map_err(|e| TunIoError::Open(format!("set O_NONBLOCK: {e}")))?;
        let async_fd = AsyncFd::with_interest(owned_fd, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| TunIoError::Open(format!("AsyncFd: {e}")))?;
        Ok(Self {
            name: final_name,
            mtu,
            fd: async_fd,
        })
    }
}

#[async_trait]
impl TunIo for MacUtunIo {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        // mihomo 一致：用 readv 把 4 字节 AF 头读到栈上 [u8; 4]、payload 直接到上层 buf
        // —— 零堆分配，热路径性能与 Linux 持平。
        if buf.is_empty() {
            return Err(TunIoError::Read(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buf empty",
            )));
        }
        let mut head = [0u8; 4];
        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            match guard.try_io(|inner| readv_fd(inner.as_raw_fd(), &mut head, buf)) {
                Ok(Ok(n)) if n >= 4 => return Ok(n - 4),
                Ok(Ok(_short)) => continue,
                Ok(Err(e)) => return Err(TunIoError::Read(e)),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        // 4 字节 AF 头放栈上（big-endian uint32）；writev 把 [head, pkt] 一次性发给内核。
        let af: u32 = match pkt.first().map(|b| b >> 4) {
            Some(4) => libc::AF_INET as u32,
            Some(6) => libc::AF_INET6 as u32,
            _ => libc::AF_INET as u32,
        };
        let head = af.to_be_bytes();
        loop {
            let mut guard = self.fd.writable().await.map_err(TunIoError::Write)?;
            match guard.try_io(|inner| writev_fd(inner.as_raw_fd(), &head, pkt)) {
                Ok(Ok(n)) => return Ok(n.saturating_sub(4)), // 报告"用户视角"长度
                Ok(Err(e)) => return Err(TunIoError::Write(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u32 {
        self.mtu
    }
    async fn close(&self) -> Result<(), TunIoError> {
        Ok(())
    }

    /// macOS drain-on-ready —— 第一次 `readable()` 后非阻塞 `try_io` 循环，
    /// 每次 readv 拉一个完整 utun frame（4B AF 头 + IP 包），直到 WouldBlock。
    /// 与 Linux 非 vnet 路径思路一致；utun 没有 GSO，没有特殊路径。
    async fn read_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> Result<usize, TunIoError> {
        let max = bufs.len().min(sizes.len());
        if max == 0 {
            return Ok(0);
        }
        let mut count = 0usize;
        // `head` 在 inner 循环多次复用；每次 readv 完整覆盖 4 字节，无 stale 数据。
        let mut head = [0u8; 4];
        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            while count < max {
                let res = guard.try_io(|inner| readv_fd(inner.as_raw_fd(), &mut head, bufs[count]));
                match res {
                    Ok(Ok(n)) if n >= 4 => {
                        sizes[count] = n - 4;
                        count += 1;
                    }
                    Ok(Ok(_)) => continue, // 短帧（< 4B AF 头）—— 跳过继续 drain
                    Ok(Err(e)) => return Err(TunIoError::Read(e)),
                    Err(_would_block) => break, // tokio 已清 readiness
                }
            }
            if count > 0 {
                return Ok(count);
            }
        }
    }
}

fn parse_utun_unit(hint: &str) -> Option<u32> {
    let digits: String = hint.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok().map(|n: u32| n + 1) // unit 为 1-based
    }
}

/* ---------------- unsafe 区 ---------------- */

#[allow(unsafe_code)]
fn unsafe_open_utun(unit: u32) -> std::io::Result<(OwnedFd, String)> {
    // SAFETY: 全部 syscall 都是平凡调用；CtlInfo / SockaddrCtl 字段顺序与
    // <sys/sys_domain.h> / <sys/kern_control.h> 中的定义一致。
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0u8; 96],
    };
    info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
    let rc = unsafe {
        libc::ioctl(
            fd,
            CTLIOCGINFO as libc::c_ulong,
            &mut info as *mut CtlInfo as *mut libc::c_void,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = SockaddrCtl {
        sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: unit,
        sc_reserved: [0u32; 5],
    };
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrCtl as *const libc::sockaddr,
            std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 读回最终接口名：getsockopt(UTUN_OPT_IFNAME)
    let mut ifname = [0u8; 32];
    let mut len: libc::socklen_t = ifname.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            ifname.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = ifname
        .iter()
        .take(len as usize)
        .position(|&b| b == 0)
        .unwrap_or(len as usize);
    let final_name = std::str::from_utf8(&ifname[..end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .to_string();
    Ok((owned, final_name))
}

#[allow(unsafe_code)]
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl 仅读写 fd 标志位。
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
fn readv_fd(fd: RawFd, head: &mut [u8; 4], payload: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: iovec 描述的两段缓冲都在调用栈上，长度合法；readv 至多写入对应字节。
    let iov = [
        libc::iovec {
            iov_base: head.as_mut_ptr() as *mut libc::c_void,
            iov_len: head.len(),
        },
        libc::iovec {
            iov_base: payload.as_mut_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        },
    ];
    let n = unsafe { libc::readv(fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[allow(unsafe_code)]
fn writev_fd(fd: RawFd, head: &[u8; 4], payload: &[u8]) -> std::io::Result<usize> {
    // SAFETY: 两段缓冲都是调用方提供，writev 只读对应长度。
    let iov = [
        libc::iovec {
            iov_base: head.as_ptr() as *mut libc::c_void,
            iov_len: head.len(),
        },
        libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        },
    ];
    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}
