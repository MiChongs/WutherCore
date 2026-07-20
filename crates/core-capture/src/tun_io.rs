//! 跨平台 TUN 设备 I/O 抽象 —— 平台后端实现 `TunIo`，capture 引擎只看见
//! 异步 read/write IP 包接口。
//!
//! 设计要点（§8.2 TUN / virtual_nic）：
//! * 读 / 写都基于 IP 包（不是 ethernet frame）；
//! * MTU 由 `TunConfig` 控制，read buffer 自动按 MTU + 16B 余量分配；
//! * 平台后端在 `open` 中完成"创建设备 + 配置地址 + 绑定 fd"原子动作；
//! * Drop 时自动 stop & cleanup。
//!
//! ## 平台支持矩阵
//!
//! | OS         | 后端                                           | 状态        |
//! |------------|-----------------------------------------------|-------------|
//! | Linux      | `/dev/net/tun` + `ioctl(TUNSETIFF)`           | M4 已实现   |
//! | Android    | root `/dev/net/tun` 或 VpnService fd 注入       | 部分        |
//! | macOS      | `socket(PF_SYSTEM, SYSPROTO_CONTROL, utun)`   | M4 已实现   |
//! | iOS        | NEPacketTunnelProvider FFI                    | 桥接占位    |
//! | Windows    | `Wintun.dll` 动态加载                          | M4-Phase2   |

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::engine::CapturePlan;

#[derive(Debug, Error)]
pub enum TunIoError {
    #[error("打开 TUN 设备失败: {0}")]
    Open(String),
    #[error("读 TUN 失败: {0}")]
    Read(std::io::Error),
    #[error("写 TUN 失败: {0}")]
    Write(std::io::Error),
    #[error("当前平台不支持 TUN: {0}")]
    Unsupported(String),
    #[error("已关闭")]
    Closed,
}

/// 跨平台 TUN 设备 I/O —— `read_packet` 返回一个完整 IP 包，
/// `write_packet` 写入一个完整 IP 包。
///
/// # 批量 I/O
/// 阶段 3.4 起新增 [`read_batch`](TunIo::read_batch)，允许一次系统级唤醒消费
/// 多个 IP 包以摊销 wakeup/select 开销。trait 提供默认实现退化到 `read_packet`，
/// 因此所有平台后端无需修改即可获得 API；性能敏感的后端（Linux）可重写以做
/// drain-on-ready / GSO 切分。
#[async_trait]
pub trait TunIo: Send + Sync {
    /// 读一个 IP 包；返回填充后的 buf 切片长度。`buf` 至少 MTU + 16B。
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError>;
    /// 写一个 IP 包。
    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError>;
    /// 设备名（绑定后才返回最终名）。
    fn name(&self) -> &str;
    /// MTU。
    fn mtu(&self) -> u32;
    /// 设备是否已由宿主平台完成地址/路由配置。
    ///
    /// Linux/root TUN 返回 `false`，由 native 后端负责 `ip addr`、`ip route`、
    /// `ip rule`。Android VpnService fd 返回 `true`，因为接口和路由已经由
    /// Android framework 根据宿主 App 的 `VpnService.Builder` 配置完成。
    fn is_preconfigured(&self) -> bool {
        false
    }
    /// 关闭设备 —— 幂等。
    async fn close(&self) -> Result<(), TunIoError>;

    /// 一次性读多个 IP 包。每个 `bufs[i]` 必须 >= MTU + 16B；返回填充的包数 N，
    /// 满足 `sizes[0..N]` 是各包的 IP 字节数，`bufs[i][..sizes[i]]` 是包内容。
    ///
    /// # 默认实现
    /// 调用一次 [`read_packet`](TunIo::read_packet) 写入 `bufs[0]`，返回 1。
    ///
    /// # 平台覆盖
    /// - Linux：drain-on-ready，第一个 packet 到达后非阻塞 try_io 直到 WouldBlock；
    /// - 其它：暂走默认（macOS/Windows/iOS/Android via VpnService）。
    ///
    /// # 错误语义
    /// - `bufs.is_empty()` → 直接 `Ok(0)`（不当作错误）；
    /// - 任何包级 I/O 失败立即返回 Err（已读到的数据丢弃）。
    async fn read_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> Result<usize, TunIoError> {
        if bufs.is_empty() || sizes.is_empty() {
            return Ok(0);
        }
        let n = self.read_packet(bufs[0]).await?;
        sizes[0] = n;
        Ok(1)
    }

    /// 一次性写多个 IP 包 —— 平台后端可在此做 GRO 合并 + vnet_hdr 帧化。
    ///
    /// # 默认实现
    /// 退化到逐包 [`write_packet`](TunIo::write_packet)，按输入顺序写出。
    /// 任一包失败立即返回错误（已写出的数据无法回滚）。
    ///
    /// # 平台覆盖
    /// - Linux（`IFF_VNET_HDR` 启用）：用 [`crate::platform::gro_merge::merge_for_linux_tun_batch`]
    ///   合并 TCP/UDP 同流连续段，写带 GSO 元数据的大段帧；
    /// - 其它平台：暂走默认。
    ///
    /// # 错误语义
    /// - `pkts.is_empty()` → 直接 `Ok(0)`；
    /// - 返回 `Ok(N)` 表示 *逻辑上* 接受的输入包数（与合并后实际 syscall 次数无关）。
    async fn write_batch(&self, pkts: Vec<Vec<u8>>) -> Result<usize, TunIoError> {
        let count = pkts.len();
        for pkt in pkts {
            self.write_packet(&pkt).await?;
        }
        Ok(count)
    }
}

/// 由平台后端调用：根据 [`CapturePlan`] 打开 TUN 设备。
///
/// 出错时 supervisor 应记录 warning 并放弃 packet loop，而不是 panic
/// （平台规则安装可能仍部分有效，留着会在 stop 时回滚）。
pub fn open_tun_device(plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    // 统一使用 tun-rs 跨平台后端。
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
    ))]
    {
        return crate::platform::tunrs_io::open(plan).map(|d| d as Arc<dyn TunIo>);
    }
    // Android: DeviceBuilder 不可用，走 android_tun_io（内部处理 root/VpnService）。
    #[cfg(target_os = "android")]
    {
        return crate::platform::android_tun_io::open(plan);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "android"
    )))]
    {
        let _ = plan;
        Err(TunIoError::Unsupported(std::env::consts::OS.into()))
    }
}

/* ============================================================
测试用 NoopTun —— 让 supervisor 在 unit-test 下能跑完整流程
============================================================ */

/// 永远返回 `Closed` 的占位 TUN，仅供测试 / Windows 暂未支持时降级。
pub struct NoopTun {
    name: String,
    mtu: u32,
}

impl NoopTun {
    pub fn new(name: impl Into<String>, mtu: u32) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            mtu,
        })
    }
}

#[async_trait]
impl TunIo for NoopTun {
    async fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, TunIoError> {
        // 阻塞直到取消（让 select! 正常等待 stop_rx）。
        std::future::pending::<()>().await;
        Err(TunIoError::Closed)
    }
    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        Ok(pkt.len()) // 静默丢弃
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
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    #[tokio::test]
    async fn noop_tun_close_is_ok() {
        let t = NoopTun::new("noop0", 1500);
        assert_eq!(t.name(), "noop0");
        assert_eq!(t.mtu(), 1500);
        assert!(
            !t.is_preconfigured(),
            "normal TUN devices must be managed by the native backend"
        );
        t.close().await.unwrap();
        assert_eq!(t.write_packet(&[1, 2, 3]).await.unwrap(), 3);
    }

    /// 单元测试用 mock —— 按顺序返回固定 payload；超过 frame 数量后 hang
    /// （仿真 NoopTun 的 pending 行为）。
    struct MockTun {
        frames: Mutex<std::collections::VecDeque<Vec<u8>>>,
    }
    impl MockTun {
        fn with_frames(frames: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                frames: Mutex::new(frames.into()),
            })
        }
    }
    #[async_trait]
    impl TunIo for MockTun {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
            // 弹出一帧；空队列时 pending（超时由调用方控制）
            let frame = {
                let mut q = self.frames.lock();
                q.pop_front()
            };
            match frame {
                Some(f) => {
                    let n = f.len().min(buf.len());
                    buf[..n].copy_from_slice(&f[..n]);
                    Ok(n)
                }
                None => {
                    std::future::pending::<()>().await;
                    Err(TunIoError::Closed)
                }
            }
        }
        async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
            Ok(pkt.len())
        }
        fn name(&self) -> &str {
            "mock"
        }
        fn mtu(&self) -> u32 {
            1500
        }
        async fn close(&self) -> Result<(), TunIoError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn read_batch_default_fallback_returns_one_packet() {
        let mock = MockTun::with_frames(vec![vec![1, 2, 3, 4]]);
        let mut buf0 = vec![0u8; 1516];
        let mut buf1 = vec![0u8; 1516];
        let mut bufs = [&mut buf0[..], &mut buf1[..]];
        let mut sizes = [0usize; 2];
        let n = (mock.as_ref() as &dyn TunIo)
            .read_batch(&mut bufs, &mut sizes)
            .await
            .expect("ok");
        assert_eq!(n, 1, "default impl returns exactly one packet");
        assert_eq!(sizes[0], 4);
        assert_eq!(&buf0[..4], &[1, 2, 3, 4]);
        assert_eq!(sizes[1], 0, "second slot untouched");
    }

    #[tokio::test]
    async fn read_batch_zero_buffers_returns_ok_zero() {
        let mock = MockTun::with_frames(vec![]);
        let mut bufs: [&mut [u8]; 0] = [];
        let mut sizes: [usize; 0] = [];
        let n = (mock.as_ref() as &dyn TunIo)
            .read_batch(&mut bufs, &mut sizes)
            .await
            .expect("ok");
        assert_eq!(n, 0, "empty bufs ⇒ Ok(0), not error");
    }
}
