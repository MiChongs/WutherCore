//! Android VpnService 注入 fd 的 [`TunIo`] 包装。
//!
//! VpnService 创建的 fd 已经是绑好 TUN 网卡的字符设备，**无需** ioctl(TUNSETIFF)；
//! 只需设置非阻塞 + 包成 [`tokio::io::unix::AsyncFd`]。

#![cfg(target_os = "android")]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::tun_io::{TunIo, TunIoError};

pub struct VpnServiceTunIo {
    name: String,
    mtu: u32,
    fd: AsyncFd<OwnedFd>,
}

impl VpnServiceTunIo {
    #[allow(unsafe_code)]
    pub fn from_raw_fd(fd: RawFd, name: String, mtu: u32) -> Result<Self, TunIoError> {
        // SAFETY: 调用约定：fd 已 dup 给本进程；不会再被 Java 侧关闭。
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(owned.as_raw_fd())
            .map_err(|e| TunIoError::Open(format!("set O_NONBLOCK: {e}")))?;
        let async_fd = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| TunIoError::Open(format!("AsyncFd: {e}")))?;
        Ok(Self { name, mtu, fd: async_fd })
    }
}

#[async_trait]
impl TunIo for VpnServiceTunIo {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            match guard.try_io(|inner| read_fd(inner.as_raw_fd(), buf)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Read(e)),
                Err(_would_block) => continue,
            }
        }
    }
    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self.fd.writable().await.map_err(TunIoError::Write)?;
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
fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: read(2) 只写 buf 范围内的字节。
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
