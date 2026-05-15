//! Windows TUN 设备 I/O —— Wintun.dll 完整 ABI 接入（mihomo 等价模型）。
//!
//! ## 架构（与之前 spawn_blocking 模型的关键差异）
//! mihomo / wireguard-windows / sing-tun 都用 **单专用 OS 线程** 阻塞
//! `WintunReceivePacket` + `WintunGetReadWaitEvent`，把每个包通过 mpsc 推到
//! tokio 异步侧。本实现照搬：
//! * `open()` spawn 一个 `wintun-recv-<iface>` std::thread，无限循环 `recv(MAX)`，
//!   每个包 `tx.blocking_send(Vec<u8>)` 推进 `mpsc::channel<Vec<u8>>(2048)`；
//! * `read_packet` 异步从 `Receiver<Vec<u8>>` 拉一个包，复制到上层 buf；
//! * `write_packet` 仍同步 `WintunSendPacket`（wintun 写是非阻塞的环形缓冲 push）；
//!   遇到 ring full 时 200µs 退避重试 3 次再回 WouldBlock。
//!
//! ## 旧 spawn_blocking 模型的问题
//! 1. tokio 默认 spawn_blocking 池 512 线程；高并发每个包都 spawn → 抢占 reactor。
//! 2. 每次 recv 设了 500ms 超时，一旦 idle 立刻"伪 TimedOut"，supervisor 把这条
//!    错误当 fatal 退出 dispatcher loop。
//! 3. `JoinHandle::await` 又拿不到 wintun ReadWaitEvent 的真实唤醒。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use super::wintun_abi::{Wintun, WintunSession};
use crate::{
    engine::CapturePlan,
    tun_io::{TunIo, TunIoError},
};

const RECV_QUEUE: usize = 2048;
const WRITE_RETRY_BACKOFF_US: u64 = 200;
const WRITE_RETRY: usize = 3;

pub struct WindowsTunIo {
    name: String,
    mtu: u32,
    session: Arc<WintunSession>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

pub fn open(plan: &CapturePlan) -> Result<Arc<WindowsTunIo>, TunIoError> {
    let wintun = Wintun::load().ok_or_else(|| {
        TunIoError::Unsupported(
            "Wintun.dll 未找到 —— 请将 wintun.dll 放到进程目录或 system32".into(),
        )
    })?;
    let adapter = wintun
        .create_adapter(&plan.interface_name, "WutherCore")
        .ok_or_else(|| TunIoError::Open("WintunCreateAdapter 返回 NULL".into()))?;
    // capacity 0x400000（4MiB）；wintun 推荐 0x20000 .. 0x4000000。
    let session = Arc::new(adapter)
        .start_session(0x40_0000)
        .ok_or_else(|| TunIoError::Open("WintunStartSession 返回 NULL".into()))?;

    // 专用接收线程 —— 永久阻塞 `WintunReceivePacket`，把每个包推进 mpsc。
    let (tx, rx) = mpsc::channel::<Vec<u8>>(RECV_QUEUE);
    let session_for_thread = session.clone();
    let iface_name = plan.interface_name.clone();
    std::thread::Builder::new()
        .name(format!("wintun-recv-{}", iface_name))
        .spawn(move || {
            loop {
                match session_for_thread.recv(u32::MAX) {
                    Some(pkt) => {
                        // tx 满 → 老消费者已死 / tokio runtime 已停 → 退出。
                        if tx.blocking_send(pkt).is_err() {
                            debug!(target: "capture::windows", "wintun-recv: tokio receiver closed");
                            break;
                        }
                    }
                    None => {
                        // session ended（adapter close 触发），结束线程。
                        debug!(target: "capture::windows", "wintun-recv: session ended");
                        break;
                    }
                }
            }
        })
        .map_err(|e| TunIoError::Open(format!("spawn wintun-recv thread: {e}")))?;

    Ok(Arc::new(WindowsTunIo {
        name: plan.interface_name.clone(),
        mtu: plan.mtu,
        session,
        rx: Mutex::new(rx),
    }))
}

#[async_trait]
impl TunIo for WindowsTunIo {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunIoError> {
        let mut rx = self.rx.lock().await;
        let pkt = rx.recv().await.ok_or_else(|| {
            TunIoError::Read(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wintun recv channel closed",
            ))
        })?;
        let n = pkt.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt[..n]);
        Ok(n)
    }

    async fn write_packet(&self, pkt: &[u8]) -> Result<usize, TunIoError> {
        // ring full 时短退避重试（避免数据包级别立即丢弃）。
        for attempt in 0..=WRITE_RETRY {
            if self.session.send(pkt) {
                return Ok(pkt.len());
            }
            if attempt < WRITE_RETRY {
                tokio::time::sleep(std::time::Duration::from_micros(WRITE_RETRY_BACKOFF_US)).await;
            }
        }
        warn!(target: "capture::windows", retries = WRITE_RETRY, "wintun send ring full after backoff");
        Err(TunIoError::Write(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "wintun ring full",
        )))
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

    /// Windows wintun batch read —— 一次 lock 内：先 `recv().await` 等第一包，
    /// 再 `try_recv()` drain 已入队的包，直到 channel 空或 bufs 满。
    /// 摊销 mpsc + Mutex lock 开销；channel 容量 `RECV_QUEUE=2048` 足够。
    async fn read_batch(
        &self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> Result<usize, TunIoError> {
        let max = bufs.len().min(sizes.len());
        if max == 0 {
            return Ok(0);
        }
        let mut rx = self.rx.lock().await;

        // 第一包：阻塞 await（与 read_packet 一致）
        let first = rx.recv().await.ok_or_else(|| {
            TunIoError::Read(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wintun recv channel closed",
            ))
        })?;
        let n0 = first.len().min(bufs[0].len());
        bufs[0][..n0].copy_from_slice(&first[..n0]);
        sizes[0] = n0;
        let mut count = 1usize;

        // 后续：try_recv drain
        while count < max {
            match rx.try_recv() {
                Ok(pkt) => {
                    let n = pkt.len().min(bufs[count].len());
                    bufs[count][..n].copy_from_slice(&pkt[..n]);
                    sizes[count] = n;
                    count += 1;
                }
                Err(_) => break, // Empty 或 Disconnected
            }
        }
        Ok(count)
    }
}
