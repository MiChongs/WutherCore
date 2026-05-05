//! tun-rs 适配器 —— 把 `tun_rs::AsyncDevice` 桥接到 WutherCore 的 `TunIo` trait。
//!
//! 替代手写的 linux_tun_io / windows_tun_io / macos_tun_io / vpnservice_tun_io，
//! tun-rs 内部处理 vnet_hdr / GSO split / GRO merge / 平台差异。
//!
//! ## 日志
//! - 设备创建/关闭：`INFO capture::tunrs` — 设备名、MTU、offload、fd 等
//! - I/O 错误：`WARN capture::tunrs` — 读写失败时的错误详情
//! - 流量统计：不在此层——由上层 `TunPump::TrafficLog` 周期汇总

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tracing::{info, warn};

use crate::engine::CapturePlan;
use crate::tun_io::{TunIo, TunIoError};

/// tun-rs I/O 统计（原子计数，无锁）
struct IoStats {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_errors: AtomicU64,
    tx_errors: AtomicU64,
}

impl IoStats {
    fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        }
    }
}

pub struct TunRsDevice {
    inner: tun_rs::AsyncDevice,
    name: String,
    mtu: u32,
    preconfigured: bool,
    stats: IoStats,
    // Linux（非 Android）offload：batch I/O 需要 staging buffer + GROTable。
    // tun-rs 只在 target_os="linux" 时导出 GROTable / recv_multiple / send_multiple。
    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    offload_buffer: tokio::sync::Mutex<Vec<u8>>,
    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    gro_table: tokio::sync::Mutex<tun_rs::GROTable>,
}

impl TunRsDevice {
    pub fn new(inner: tun_rs::AsyncDevice, name: String, mtu: u32, preconfigured: bool) -> Self {
        Self {
            inner,
            name,
            mtu,
            preconfigured,
            stats: IoStats::new(),
            #[cfg(all(target_os = "linux", not(target_os = "android")))]
            offload_buffer: tokio::sync::Mutex::new(vec![0u8; 10 + 65535]),
            #[cfg(all(target_os = "linux", not(target_os = "android")))]
            gro_table: tokio::sync::Mutex::new(tun_rs::GROTable::default()),
        }
    }

    fn format_stats(&self) -> String {
        let rx_p = self.stats.rx_packets.load(Ordering::Relaxed);
        let rx_b = self.stats.rx_bytes.load(Ordering::Relaxed);
        let tx_p = self.stats.tx_packets.load(Ordering::Relaxed);
        let tx_b = self.stats.tx_bytes.load(Ordering::Relaxed);
        let rx_e = self.stats.rx_errors.load(Ordering::Relaxed);
        let tx_e = self.stats.tx_errors.load(Ordering::Relaxed);
        format!(
            "rx {rx_p} pkts ({}) tx {tx_p} pkts ({}) err rx:{rx_e} tx:{tx_e}",
            crate::tun_pump::format_bytes(rx_b),
            crate::tun_pump::format_bytes(tx_b),
        )
    }
}

#[async_trait]
impl TunIo for TunRsDevice {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        match self.inner.recv(buf).await {
            Ok(n) => {
                self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.stats.rx_errors.fetch_add(1, Ordering::Relaxed);
                warn!(target: "capture::tunrs", iface = %self.name, error = %e, "tun read failed");
                Err(TunIoError::Read(e))
            }
        }
    }

    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        match self.inner.send(pkt).await {
            Ok(n) => {
                self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
                warn!(target: "capture::tunrs", iface = %self.name, error = %e, bytes = pkt.len(), "tun write failed");
                Err(TunIoError::Write(e))
            }
        }
    }

    async fn read_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> Result<usize, TunIoError> {
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        {
            let mut ob = self.offload_buffer.lock().await;
            match self.inner.recv_multiple(&mut ob, bufs, sizes, 0).await {
                Ok(n) => {
                    let total_bytes: u64 = sizes[..n].iter().map(|&s| s as u64).sum();
                    self.stats.rx_packets.fetch_add(n as u64, Ordering::Relaxed);
                    self.stats.rx_bytes.fetch_add(total_bytes, Ordering::Relaxed);
                    return Ok(n);
                }
                Err(e) => {
                    self.stats.rx_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(target: "capture::tunrs", iface = %self.name, error = %e, "tun batch read failed");
                    return Err(TunIoError::Read(e));
                }
            }
        }
        #[cfg(not(all(target_os = "linux", not(target_os = "android"))))]
        {
            if bufs.is_empty() {
                return Ok(0);
            }
            match self.inner.recv(bufs[0]).await {
                Ok(n) => {
                    sizes[0] = n;
                    self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    Ok(1)
                }
                Err(e) => {
                    self.stats.rx_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(target: "capture::tunrs", iface = %self.name, error = %e, "tun read failed");
                    Err(TunIoError::Read(e))
                }
            }
        }
    }

    async fn write_batch(&self, pkts: Vec<Vec<u8>>) -> Result<usize, TunIoError> {
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        {
            let mut gro = self.gro_table.lock().await;
            let total_bytes: u64 = pkts.iter().map(|p| p.len() as u64).sum();
            let count = pkts.len();
            let mut owned = pkts;
            match self.inner.send_multiple(&mut gro, &mut owned, 0).await {
                Ok(n) => {
                    self.stats.tx_packets.fetch_add(count as u64, Ordering::Relaxed);
                    self.stats.tx_bytes.fetch_add(total_bytes, Ordering::Relaxed);
                    return Ok(n);
                }
                Err(e) => {
                    self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(target: "capture::tunrs", iface = %self.name, error = %e, count, "tun batch write failed");
                    return Err(TunIoError::Write(e));
                }
            }
        }
        #[cfg(not(all(target_os = "linux", not(target_os = "android"))))]
        {
            let count = pkts.len();
            let mut total_bytes = 0u64;
            for pkt in &pkts {
                match self.inner.send(pkt).await {
                    Ok(n) => {
                        total_bytes += n as u64;
                    }
                    Err(e) => {
                        self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(target: "capture::tunrs", iface = %self.name, error = %e, "tun write failed");
                        return Err(TunIoError::Write(e));
                    }
                }
            }
            self.stats.tx_packets.fetch_add(count as u64, Ordering::Relaxed);
            self.stats.tx_bytes.fetch_add(total_bytes, Ordering::Relaxed);
            Ok(count)
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn is_preconfigured(&self) -> bool {
        self.preconfigured
    }

    async fn close(&self) -> Result<(), TunIoError> {
        info!(
            target: "capture::tunrs",
            iface = %self.name,
            stats = %self.format_stats(),
            "tun-rs device closing"
        );
        Ok(())
    }
}

/// 用 tun-rs DeviceBuilder 创建 TUN 设备。
/// DeviceBuilder 在 Android 上不可用（tun-rs 不导出），Android 走 android_tun_io。
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
))]
pub fn open(plan: &CapturePlan) -> Result<Arc<TunRsDevice>, TunIoError> {
    let mut builder = tun_rs::DeviceBuilder::new();
    builder = builder
        .name(&plan.interface_name)
        .mtu(plan.mtu as u16)
        .ipv4(
            plan.tun_v4_cidr.addr().to_string(),
            plan.tun_v4_cidr.prefix_len(),
            None,
        );

    if let Some(v6) = plan.tun_v6_cidr {
        builder = builder.ipv6(v6.addr().to_string(), v6.prefix_len());
    }

    #[cfg(target_os = "linux")]
    if plan.offload {
        builder = builder.offload(true);
    }

    let device = builder.build_async().map_err(TunIoError::Read)?;
    let name = plan.interface_name.clone();
    let mtu = plan.mtu;

    let offload_str = if plan.offload { "on" } else { "off" };
    let v6_str = plan
        .tun_v6_cidr
        .map(|c| c.to_string())
        .unwrap_or_else(|| "disabled".into());
    info!(
        target: "capture::tunrs",
        "[TUN] {name} created | MTU {mtu} | v4 {} | v6 {v6_str} | offload {offload_str} | backend tun-rs",
        plan.tun_v4_cidr,
    );

    Ok(Arc::new(TunRsDevice::new(device, name, mtu, false)))
}

/// Android：DeviceBuilder 不可用，委托给 android_tun_io（内部处理 root / VpnService）。
#[cfg(target_os = "android")]
pub fn open(plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    info!(
        target: "capture::tunrs",
        "[TUN] {} opening via android_tun_io (root/VpnService fallback)",
        plan.interface_name,
    );
    crate::platform::android_tun_io::open(plan)
}

/// 从已有 fd 创建 TUN 设备（Android VpnService / iOS PacketTunnelProvider）。
///
/// # Safety
/// fd 必须是合法的、已打开的 TUN 设备文件描述符。
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn from_fd(
    fd: std::os::unix::io::RawFd,
    name: String,
    mtu: u32,
) -> Result<Arc<TunRsDevice>, TunIoError> {
    let device = unsafe { tun_rs::AsyncDevice::from_fd(fd) }.map_err(TunIoError::Read)?;

    info!(
        target: "capture::tunrs",
        "[TUN] {name} from fd={fd} | MTU {mtu} | preconfigured | backend tun-rs"
    );

    Ok(Arc::new(TunRsDevice::new(device, name, mtu, true)))
}
