//! 跨平台 TUN 设备 I/O 抽象 —— 平台后端实现 `TunIo`，capture 引擎只看见
//! 异步 read/write IP 包接口。
//!
//! 设计要点（§8.2 TUN / virtual_nic）：
//! * 读 / 写都基于 IP 包（不是 ethernet frame）；
//! * MTU 由 [`TunConfig`] 控制，read buffer 自动按 MTU + 16B 余量分配；
//! * 平台后端在 `open` 中完成"创建设备 + 配置地址 + 绑定 fd"原子动作；
//! * Drop 时自动 stop & cleanup。
//!
//! ## 平台支持矩阵
//!
//! | OS         | 后端                                           | 状态        |
//! |------------|-----------------------------------------------|-------------|
//! | Linux      | `/dev/net/tun` + `ioctl(TUNSETIFF)`           | M4 已实现   |
//! | Android    | 同 Linux（`AndroidTier::VpnService` 走 fd 注入）| 部分        |
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
    /// 关闭设备 —— 幂等。
    async fn close(&self) -> Result<(), TunIoError>;
}

/// 由平台后端调用：根据 [`CapturePlan`] 打开 TUN 设备。
///
/// 出错时 supervisor 应记录 warning 并放弃 packet loop，而不是 panic
/// （平台规则安装可能仍部分有效，留着会在 stop 时回滚）。
pub fn open_tun_device(plan: &CapturePlan) -> Result<Arc<dyn TunIo>, TunIoError> {
    #[cfg(target_os = "linux")]
    {
        return crate::platform::linux_tun_io::open(plan).map(|d| d as Arc<dyn TunIo>);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return crate::platform::macos_tun_io::open(plan).map(|d| d as Arc<dyn TunIo>);
    }
    #[cfg(target_os = "windows")]
    {
        return crate::platform::windows_tun_io::open(plan).map(|d| d as Arc<dyn TunIo>);
    }
    #[cfg(target_os = "android")]
    {
        return crate::platform::android_tun_io::open(plan).map(|d| d as Arc<dyn TunIo>);
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
        Arc::new(Self { name: name.into(), mtu })
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
    fn name(&self) -> &str { &self.name }
    fn mtu(&self) -> u32 { self.mtu }
    async fn close(&self) -> Result<(), TunIoError> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_tun_close_is_ok() {
        let t = NoopTun::new("noop0", 1500);
        assert_eq!(t.name(), "noop0");
        assert_eq!(t.mtu(), 1500);
        t.close().await.unwrap();
        assert_eq!(t.write_packet(&[1, 2, 3]).await.unwrap(), 3);
    }
}
