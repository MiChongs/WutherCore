//! Linux TUN 设备 I/O —— `/dev/net/tun` + `ioctl(TUNSETIFF)`。
//!
//! 流程：
//! 1. 打开 `/dev/net/tun` 得到字符设备 fd；
//! 2. 通过 `ioctl(TUNSETIFF, ifr)` 把 fd 绑定到指定网卡名；
//!    `ifr.flags = IFF_TUN | IFF_NO_PI`（无 protocol info 头）；
//!    `offload=true` 时再加 `IFF_VNET_HDR`；
//! 3. 把 fd 设为 O_NONBLOCK；
//! 4. 包装成 `tokio::io::unix::AsyncFd` 异步读写。
//!
//! ## virtio_net_hdr + GSO/GRO 完整路径
//!
//! `IFF_VNET_HDR` 开启后，每个 read/write 都带 10 字节 `virtio_net_hdr` 前缀。
//! `offload=true` 时还会调 `TUNSETOFFLOAD` 启用 `TUN_F_CSUM | TSO4|TSO6 | USO4|USO6`，
//! 让内核与用户态都能在大段（最大 64KiB）粒度上做 TCP/UDP 分片：
//! - **读路径**：kernel 投递大段 vnet_hdr+IP，[`process_vnet_segment`] 解析后按
//!   `gso_size` 拆成多个完整 IP 包填入 `read_batch` 的 `bufs`；
//! - **写路径**：用户态合并多段同流 TCP/UDP 走 [`merge_for_linux_tun_batch`] →
//!   `writev(iov[0]=vnet_hdr, iov[1]=合并段)` 一次 syscall 让 kernel TSO/USO 切分。
//!
//! 启用失败的 fallback：TCP offload 失败 → 重开 fd 不带 IFF_VNET_HDR；
//! UDP USO 失败 → 仅 warn，TCP GSO 保留。
//!
//! ## unsafe 政策
//!
//! 仅 `unsafe_ioctl_tunsetiff` 局部使用 unsafe（`libc::ioctl` 调用 + `ifreq`
//! 字段填充）。其它代码全在 safe 区域。

use std::{
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::Arc,
};

use async_trait::async_trait;
use tokio::io::{Interest, unix::AsyncFd};

use crate::{
    engine::CapturePlan,
    tun_io::{TunIo, TunIoError},
};

const IFF_TUN: i32 = 0x0001;
const IFF_NO_PI: i32 = 0x1000;
const IFF_VNET_HDR: i32 = 0x4000;
const IFF_TUN_EXCL: i32 = 0x8000;
const IFNAMSIZ: usize = 16;
// SIOCSIFMTU = 0x8922（<linux/sockios.h>），通过控制 socket(AF_INET, SOCK_DGRAM)
// 调用即可；与 sing-tun 保持一致，避免 `ip link set` 命令路径在阉割工具链下静默失败。
const SIOCSIFMTU: libc::Ioctl = 0x8922 as libc::Ioctl;
const SIOCGIFFLAGS: libc::Ioctl = 0x8913 as libc::Ioctl;
const SIOCSIFFLAGS: libc::Ioctl = 0x8914 as libc::Ioctl;
const SIOCSIFADDR: libc::Ioctl = 0x8916 as libc::Ioctl;
const SIOCSIFNETMASK: libc::Ioctl = 0x891c as libc::Ioctl;
const IFF_UP_FLAG: i16 = 0x1;

// ioctl 编号：定义在 <linux/if_tun.h>，由 _IOW('T', n, type) 组成。
// 直接使用常量避免引入 nix 的 macro。
//
// 注意：`libc::ioctl` 在 glibc 上的 `request` 参数类型为 `c_ulong`（u64 on x86_64），
// 而在 Bionic（Android）上是 `c_int`（i32）。统一用 `libc::Ioctl`（类型别名）规避。
const TUNSETIFF: libc::Ioctl = 0x4004_54CA as libc::Ioctl;
/// `_IOW('T', 208, unsigned int)` —— 启用 TUN 设备的 offload 特性（TSO/USO）。
/// 必须在 `IFF_VNET_HDR` 已启用、`TUNSETIFF` 已绑定后调用。
const TUNSETOFFLOAD: libc::Ioctl = 0x4004_54D0 as libc::Ioctl;

// TUN_F_* 标志（<linux/if_tun.h>）—— TUNSETOFFLOAD 的位图参数。
const TUN_F_CSUM: u32 = 0x01;
const TUN_F_TSO4: u32 = 0x02;
const TUN_F_TSO6: u32 = 0x04;
const TUN_F_USO4: u32 = 0x20;
const TUN_F_USO6: u32 = 0x40;
/// TCP 段大段输出 + 校验和卸载（与 sing-tun `tunTCPOffloads` 一致）。
const TCP_OFFLOAD: u32 = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
/// UDP 段大段输出（与 sing-tun `tunUDPOffloads` 一致）；TCP 之上叠加。
const UDP_OFFLOAD: u32 = TUN_F_USO4 | TUN_F_USO6;

use crate::platform::{
    gro_merge::{GroOutput, merge_for_linux_tun_batch},
    gso_split::process_vnet_segment,
    vnet_hdr::{VIRTIO_NET_HDR_LEN, ZERO_VNET_HDR, encode_vnet_hdr_bytes, strip_vnet_hdr},
};

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
    /// 是否启用了 IFF_VNET_HDR —— 决定 read/write 是否需要处理 10 字节前缀。
    vnet_hdr: bool,
}

pub fn open(plan: &CapturePlan) -> Result<Arc<LinuxTunIo>, TunIoError> {
    let dev = LinuxTunIo::open(&plan.interface_name, plan.mtu, plan.offload)?;
    Ok(Arc::new(dev))
}

pub fn set_link_up_ioctl(name: &str) -> std::io::Result<()> {
    unsafe_set_link_up(name)
}

pub fn set_ipv4_addr_ioctl(name: &str, net: ipnet::Ipv4Net) -> std::io::Result<()> {
    unsafe_set_ipv4_addr(name, net.addr(), net.prefix_len())
}

/// 尝试 ioctl(TUNSETIFF) 绑定 fd 到 name。三段式：
/// 1. 优先 `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`，与 mihomo/sing-tun 一致；
/// 2. EBUSY 时 `ip tuntap del` 清理残留，再用 EXCL 重试；
/// 3. 仍 EBUSY → 去掉 EXCL 重试（兼容 Android 持久化 TUN 与容器场景）。
fn try_attach(name: &str, vnet_hdr: bool) -> Result<(OwnedFd, String), TunIoError> {
    fn do_open(
        name: &str,
        exclusive: bool,
        vnet_hdr: bool,
    ) -> Result<(OwnedFd, String), TunIoError> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc_o_nonblock())
            .open("/dev/net/tun")
            .map_err(|e| TunIoError::Open(format!("open /dev/net/tun: {e}")))?;
        let owned: OwnedFd = f.into();
        let raw = owned.as_raw_fd();
        let bound = unsafe_ioctl_tunsetiff(raw, name, exclusive, vnet_hdr)
            .map_err(|e| TunIoError::Open(format!("ioctl TUNSETIFF: {e}")))?;
        Ok((owned, bound))
    }
    // 第 1 步：EXCL
    match do_open(name, true, vnet_hdr) {
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
    match do_open(name, true, vnet_hdr) {
        Ok(v) => return Ok(v),
        Err(TunIoError::Open(msg)) if is_ebusy(&msg) => {
            tracing::warn!(target: "capture::linux::tun", iface = %name, "EBUSY again; retry without EXCL");
        }
        Err(e) => return Err(e),
    }
    // 第 3 步：去掉 EXCL（与 Android VpnService 等场景兼容）
    do_open(name, false, vnet_hdr)
}

fn is_ebusy(msg: &str) -> bool {
    let l = msg.to_lowercase();
    l.contains("device or resource busy") || l.contains("(os error 16)")
}

impl LinuxTunIo {
    pub fn open(name: &str, mtu: u32, offload: bool) -> Result<Self, TunIoError> {
        if name.len() >= IFNAMSIZ {
            return Err(TunIoError::Open(format!(
                "interface name 太长（{} ≥ {IFNAMSIZ}）",
                name.len()
            )));
        }
        // 1+2. 打开 /dev/net/tun + ioctl(TUNSETIFF)，EBUSY 自愈
        let (owned, bound_name) = try_attach(name, offload)?;

        // 3. 设为 nonblocking（OpenOptions 已带 O_NONBLOCK，这里二次保险）
        if let Err(e) = set_nonblocking(owned.as_raw_fd()) {
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

        // 5. offload 启用 —— `IFF_VNET_HDR` 已加上，再调 TUNSETOFFLOAD 让 kernel
        //    投递 TSO/USO 大段。与 sing-tun `enableGSO` 行为对齐：
        //    - TCP offload 失败 → drop fd 后重新 try_attach(vnet_hdr=false)，
        //      彻底放弃 IFF_VNET_HDR（避免内核仍发 10B 零头但读路径不剥造成坏帧）；
        //    - UDP USO 失败 → 仅 warn，TCP GSO 保留。
        let (final_owned, final_name, vnet_hdr_active, udp_offload_active) = if offload {
            let try_fd = owned.as_raw_fd();
            match try_enable_offload(try_fd) {
                Ok(udp_ok) => (owned, bound_name, true, udp_ok),
                Err(e) => {
                    tracing::warn!(
                        target: "capture::linux::tun",
                        error = %e,
                        iface = %bound_name,
                        "TUNSETOFFLOAD failed; reopening fd without IFF_VNET_HDR"
                    );
                    drop(owned); // 关闭原 fd（带 IFF_VNET_HDR）
                    let (o2, n2) = try_attach(name, false).map_err(|err| {
                        TunIoError::Open(format!("offload fallback reopen failed: {err}"))
                    })?;
                    if let Err(set_e) = set_nonblocking(o2.as_raw_fd()) {
                        return Err(TunIoError::Open(format!(
                            "set O_NONBLOCK after reopen: {set_e}"
                        )));
                    }
                    (o2, n2, false, false)
                }
            }
        } else {
            (owned, bound_name, false, false)
        };

        // 6. 包装成 AsyncFd
        let final_raw = final_owned.as_raw_fd();
        let async_fd = AsyncFd::with_interest(final_owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| TunIoError::Open(format!("AsyncFd: {e}")))?;

        tracing::info!(
            target: "capture::linux::tun",
            requested_iface = %name,
            bound_iface = %final_name,
            mtu,
            offload_requested = offload,
            vnet_hdr_active,
            tcp_gso = vnet_hdr_active,
            udp_gso = udp_offload_active,
            fd = final_raw,
            "TUN fd attached"
        );

        Ok(Self {
            name: final_name,
            mtu,
            fd: async_fd,
            vnet_hdr: vnet_hdr_active,
        })
    }
}

/// 启用 TUN offload 特性 —— 返回 `Ok(udp_ok)`：
/// - `Ok(true)`：TCP + UDP USO 都启用；
/// - `Ok(false)`：TCP 启用但 UDP USO 失败（仅 warn 不致命）；
/// - `Err`：TCP 启用失败 —— 调用方应当 reopen fd 不带 IFF_VNET_HDR。
fn try_enable_offload(fd: RawFd) -> std::io::Result<bool> {
    unsafe_set_offload(fd, TCP_OFFLOAD)?;
    match unsafe_set_offload(fd, TCP_OFFLOAD | UDP_OFFLOAD) {
        Ok(()) => Ok(true),
        Err(_) => {
            // UDP USO requires Linux 6.2+; expected to fail on older kernels.
            // TCP GSO (TSO4/TSO6) is still active — no performance loss for TCP.
            tracing::debug!(
                target: "capture::linux::tun",
                "UDP USO not supported by kernel; TCP GSO active"
            );
            Ok(false)
        }
    }
}

#[async_trait]
impl TunIo for LinuxTunIo {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        if !self.vnet_hdr {
            return self.read_raw(buf).await;
        }
        // vnet_hdr 模式：先 read 到带前缀的临时缓冲，按 vnet_hdr::strip_vnet_hdr 校验后
        // 剥前 10 字节落到 `buf`。`gso_type != NONE` 视为异常并丢包（阶段 3.4 才实现）。
        let mut staging = vec![0u8; buf.len() + VIRTIO_NET_HDR_LEN];
        let n = self.read_raw(&mut staging).await?;
        match strip_vnet_hdr(&staging, n, buf) {
            Ok(payload_len) => Ok(payload_len),
            Err(e) => {
                tracing::warn!(target: "capture::linux::tun", error = %e, "vnet_hdr decode failed");
                Err(TunIoError::Read(std::io::Error::new(
                    if matches!(
                        e,
                        crate::platform::vnet_hdr::VnetDecodeError::UnsupportedGso { .. }
                    ) {
                        std::io::ErrorKind::Unsupported
                    } else {
                        std::io::ErrorKind::InvalidData
                    },
                    e,
                )))
            }
        }
    }

    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        if !self.vnet_hdr {
            return self.write_raw(pkt).await;
        }
        // vnet_hdr 模式：用 writev 双 iovec —— iov[0]=ZERO_VNET_HDR(10B), iov[1]=pkt，
        // 一次 syscall + 零拷贝合帧（kernel TUN 驱动按 frame 边界处理 writev）。
        let n = self.write_vnet_iovec(&ZERO_VNET_HDR, pkt).await?;
        Ok(n.saturating_sub(VIRTIO_NET_HDR_LEN))
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

    /// Linux drain-on-ready —— 第一次 readable 后反复 `try_io` 直到 `WouldBlock`，
    /// 一次唤醒消费多包以摊销 wakeup/select 开销。
    ///
    /// vnet_hdr 模式（IFF_VNET_HDR 启用）：单次 read 拉一个 virtio_net_hdr+大段，
    /// 经 `gso_split` 切分成多个完整 IP 包填入 bufs。kernel 已合并多个 segment，
    /// 所以这条路径本身就是 batch；不再 drain（drain + GSO 同时做会复杂化错误处理）。
    async fn read_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> Result<usize, TunIoError> {
        let max = bufs.len().min(sizes.len());
        if max == 0 {
            return Ok(0);
        }

        if self.vnet_hdr {
            return self.read_batch_vnet(bufs, sizes, max).await;
        }

        // 非 vnet：drain-on-ready
        let mut count = 0usize;
        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            while count < max {
                let res = guard.try_io(|inner| read_fd(inner.as_raw_fd(), bufs[count]));
                match res {
                    Ok(Ok(n)) => {
                        sizes[count] = n;
                        count += 1;
                    }
                    Ok(Err(e)) => return Err(TunIoError::Read(e)),
                    Err(_would_block) => break,
                }
            }
            if count > 0 {
                return Ok(count);
            }
        }
    }

    /// Linux GRO 批量写 —— vnet_hdr 启用时，对同流连续段合并成大段，让 kernel
    /// 走 TSO/USO 切分；其余包带零头单独写。非 vnet_hdr 退化逐包 `write_packet`。
    async fn write_batch(&self, pkts: Vec<Vec<u8>>) -> Result<usize, TunIoError> {
        let count = pkts.len();
        if count == 0 {
            return Ok(0);
        }
        if !self.vnet_hdr {
            for pkt in &pkts {
                self.write_packet(pkt).await?;
            }
            return Ok(count);
        }

        let outputs = merge_for_linux_tun_batch(pkts);
        for out in outputs {
            self.write_gro_output(&out).await?;
        }
        Ok(count)
    }
}

impl LinuxTunIo {
    /// vnet_hdr 模式的 batch read：拉一个 GSO 大段 + 切分多段填 bufs。
    ///
    /// staging buffer 65546B（64KiB + virtio_net_hdr 10B）—— GSO max 段长。
    /// 切出段数超过剩余槽位时，前面填满后丢尾并 warn（罕见，PUMP_BATCH_N=8 默认下
    /// 单大段切 >8 才触发；生产观察到频繁 warn 时上调 PUMP_BATCH_N）。
    async fn read_batch_vnet(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
        max: usize,
    ) -> Result<usize, TunIoError> {
        const STAGING_CAP: usize = 65536 + VIRTIO_NET_HDR_LEN;
        let mut staging = vec![0u8; STAGING_CAP];

        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            let n = match guard.try_io(|inner| read_fd(inner.as_raw_fd(), &mut staging)) {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(TunIoError::Read(e)),
                Err(_would_block) => continue, // 重 await
            };
            let count = process_vnet_segment(&staging[..n], bufs, sizes, max);
            if count > 0 {
                return Ok(count);
            }
            // 解析失败或切分错 → 当作"丢包"，继续等下一个段
        }
    }
}

impl LinuxTunIo {
    /// 写一个 GRO 合并输出 —— `out.options = Some(hdr)` 时附 GSO 元数据头（10B），
    /// 否则附零头；统一走 `writev` 双 iovec 一次写出，避免分配 + 合帧拷贝。
    async fn write_gro_output(&self, out: &GroOutput) -> Result<usize, TunIoError> {
        let head: [u8; VIRTIO_NET_HDR_LEN] = match out.options.as_ref() {
            Some(hdr) => encode_vnet_hdr_bytes(hdr),
            None => ZERO_VNET_HDR,
        };
        let n = self.write_vnet_iovec(&head, &out.bytes).await?;
        Ok(n.saturating_sub(VIRTIO_NET_HDR_LEN))
    }

    /// `writev(2)` 双 iovec 写出：iov[0]=10B vnet_hdr，iov[1]=IP 包。
    /// `EWOULDBLOCK` 时由 `AsyncFd::writable` 重新就绪。
    async fn write_vnet_iovec(&self, head: &[u8], body: &[u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self.fd.writable().await.map_err(TunIoError::Write)?;
            match guard.try_io(|inner| writev_fd(inner.as_raw_fd(), head, body)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Write(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// 不带 vnet_hdr 处理的原始 read。
    async fn read_raw(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self.fd.readable().await.map_err(TunIoError::Read)?;
            match guard.try_io(|inner| read_fd(inner.as_raw_fd(), buf)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Read(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// 不带 vnet_hdr 处理的原始 write。
    async fn write_raw(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        loop {
            let mut guard = self.fd.writable().await.map_err(TunIoError::Write)?;
            match guard.try_io(|inner| write_fd(inner.as_raw_fd(), pkt)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TunIoError::Write(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

/* ---------------- unsafe 区 ---------------- */

#[allow(unsafe_code)]
fn unsafe_ioctl_tunsetiff(
    fd: RawFd,
    name: &str,
    exclusive: bool,
    vnet_hdr: bool,
) -> std::io::Result<String> {
    // SAFETY:
    // * `IfReq` 是 repr(C)，与 Linux <linux/if.h> 中 `struct ifreq` 兼容字段顺序。
    // * `ioctl` 接收 fd 与 *mut IfReq；req 在调用结束前不会移动（栈上局部变量）。
    // * 失败时返回 -1，errno 由 last_os_error 读取。
    let mut flags = IFF_TUN | IFF_NO_PI;
    if vnet_hdr {
        flags |= IFF_VNET_HDR;
    }
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
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut IfReq as *mut libc::c_void) };
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

#[repr(C)]
struct IfReqAddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_addr: libc::sockaddr,
    _pad: [u8; 8],
}

fn fill_if_name(dst: &mut [u8; IFNAMSIZ], name: &str) -> std::io::Result<()> {
    if name.len() >= IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    let bytes = name.as_bytes();
    dst[..bytes.len()].copy_from_slice(bytes);
    Ok(())
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
    fill_if_name(&mut req.ifr_name, name)?;
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
fn unsafe_set_link_up(name: &str) -> std::io::Result<()> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut req = IfReq {
        ifr_name: [0u8; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0u8; 22],
    };
    let fill_result = fill_if_name(&mut req.ifr_name, name);
    if let Err(e) = fill_result {
        unsafe {
            libc::close(s);
        }
        return Err(e);
    }
    let get_rc =
        unsafe { libc::ioctl(s, SIOCGIFFLAGS, &mut req as *mut IfReq as *mut libc::c_void) };
    if get_rc < 0 {
        let saved = std::io::Error::last_os_error();
        unsafe {
            libc::close(s);
        }
        return Err(saved);
    }
    req.ifr_flags |= IFF_UP_FLAG;
    let set_rc =
        unsafe { libc::ioctl(s, SIOCSIFFLAGS, &mut req as *mut IfReq as *mut libc::c_void) };
    let saved = std::io::Error::last_os_error();
    unsafe {
        libc::close(s);
    }
    if set_rc < 0 {
        return Err(saved);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn unsafe_set_ipv4_addr(name: &str, addr: Ipv4Addr, prefix: u8) -> std::io::Result<()> {
    unsafe_set_ipv4_sockaddr(name, SIOCSIFADDR, addr)?;
    unsafe_set_ipv4_sockaddr(name, SIOCSIFNETMASK, ipv4_netmask(prefix))?;
    Ok(())
}

#[allow(unsafe_code)]
fn unsafe_set_ipv4_sockaddr(
    name: &str,
    request: libc::Ioctl,
    addr: Ipv4Addr,
) -> std::io::Result<()> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut req = IfReqAddr {
        ifr_name: [0u8; IFNAMSIZ],
        ifr_addr: ipv4_sockaddr(addr),
        _pad: [0u8; 8],
    };
    let fill_result = fill_if_name(&mut req.ifr_name, name);
    if let Err(e) = fill_result {
        unsafe {
            libc::close(s);
        }
        return Err(e);
    }
    let rc = unsafe { libc::ioctl(s, request, &mut req as *mut IfReqAddr as *mut libc::c_void) };
    let saved = std::io::Error::last_os_error();
    unsafe {
        libc::close(s);
    }
    if rc < 0 {
        return Err(saved);
    }
    Ok(())
}

fn ipv4_sockaddr(addr: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe_sockaddr_from_in(sin)
}

#[allow(unsafe_code)]
fn unsafe_sockaddr_from_in(addr: libc::sockaddr_in) -> libc::sockaddr {
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr) }
}

fn ipv4_netmask(prefix: u8) -> Ipv4Addr {
    let prefix = prefix.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

#[allow(unsafe_code)]
fn unsafe_set_offload(fd: RawFd, flags: u32) -> std::io::Result<()> {
    // SAFETY: TUNSETOFFLOAD 接收 unsigned int 直接传值（IoctlSetInt 风格，非指针）。
    // libc::ioctl 是 variadic；第三个参数按 c_ulong 传入，内核只读不改。
    let rc = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, flags as libc::c_ulong) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
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

/// `writev(2)` 双 iovec 实现 —— TUN char dev 把 iov 串接成单 frame 写入，
/// 用于 vnet_hdr (10B) + IP 包的零拷贝合帧。
#[allow(unsafe_code)]
fn writev_fd(fd: RawFd, head: &[u8], body: &[u8]) -> std::io::Result<usize> {
    // SAFETY:
    // * 两个 iovec 在调用结束前不移动（栈上局部）；
    // * `iov_base` 仅指向 `head` / `body` 现有数据，writev 是只读语义；
    // * `*const u8 → *mut c_void` 是 libc::iovec 的 ABI 要求（kernel 不会写入）。
    let iov = [
        libc::iovec {
            iov_base: head.as_ptr() as *mut libc::c_void,
            iov_len: head.len(),
        },
        libc::iovec {
            iov_base: body.as_ptr() as *mut libc::c_void,
            iov_len: body.len(),
        },
    ];
    let n = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn libc_o_nonblock() -> i32 {
    libc::O_NONBLOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_to_netmask_covers_common_tun_prefixes() {
        assert_eq!(ipv4_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(ipv4_netmask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(ipv4_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
