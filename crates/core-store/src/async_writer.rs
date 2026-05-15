//! 异步批量写入器 —— 性能关键路径。
//!
//! 调用方（Smart 的 record_success 等热路径）通过 mpsc 把 [`WriteOp`]
//! 推过来；后台 worker 在以下任一条件触发 flush：
//! 1. 本批积累 >= 256 项；
//! 2. 距上次 flush 已 200ms；
//! 3. 收到 shutdown 信号。
//!
//! 这样保证：写热路径只有一次原子入队（mpsc），数据库提交批量化。

use std::{sync::Arc, time::Duration};

use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tracing::{debug, warn};

use crate::store::{BatchOp, Store};

#[derive(Debug, Clone)]
pub enum WriteOp {
    Batch(Vec<BatchOp>),
    Single(BatchOp),
}

/// 异步写入器；启动时 spawn 一条后台协程。
pub struct AsyncWriter {
    tx: mpsc::Sender<WriteOp>,
    handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<Notify>,
}

impl AsyncWriter {
    pub fn spawn(store: Arc<Store>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<WriteOp>(4096);
        let shutdown = Arc::new(Notify::new());
        let me = Arc::new(Self {
            tx,
            handle: parking_lot::Mutex::new(None),
            shutdown: shutdown.clone(),
        });
        let store_for_task = store;
        let shutdown_for_task = shutdown;
        let handle = tokio::spawn(async move {
            run_loop(store_for_task, rx, shutdown_for_task).await;
        });
        *me.handle.lock() = Some(handle);
        me
    }

    /// 入队一个批次（不等待落盘）。返回 false 表示通道已关闭。
    pub fn enqueue(&self, op: BatchOp) -> bool {
        self.tx.try_send(WriteOp::Single(op)).is_ok()
    }

    pub fn enqueue_batch(&self, ops: Vec<BatchOp>) -> bool {
        if ops.is_empty() {
            return true;
        }
        self.tx.try_send(WriteOp::Batch(ops)).is_ok()
    }

    /// 优雅停止：通知 worker、等其完成最后一次 flush。
    pub async fn shutdown(&self) {
        self.shutdown.notify_one();
        // 关闭通道
        let handle = self.handle.lock().take();
        if let Some(h) = handle {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
    }
}

const FLUSH_THRESHOLD: usize = 256;
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

async fn run_loop(store: Arc<Store>, mut rx: mpsc::Receiver<WriteOp>, shutdown: Arc<Notify>) {
    let mut buffer: Vec<BatchOp> = Vec::with_capacity(FLUSH_THRESHOLD);
    let mut tick = tokio::time::interval(FLUSH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                while let Ok(op) = rx.try_recv() {
                    match op {
                        WriteOp::Single(op) => buffer.push(op),
                        WriteOp::Batch(ops) => buffer.extend(ops),
                    }
                }
                flush(&store, &mut buffer);
                debug!(target: "store::writer", "shutdown flush done");
                return;
            }
            _ = tick.tick() => {
                flush(&store, &mut buffer);
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(WriteOp::Single(op)) => buffer.push(op),
                    Some(WriteOp::Batch(ops)) => buffer.extend(ops),
                    None => {
                        flush(&store, &mut buffer);
                        return;
                    }
                }
                if buffer.len() >= FLUSH_THRESHOLD {
                    flush(&store, &mut buffer);
                }
            }
        }
    }
}

fn flush(store: &Arc<Store>, buffer: &mut Vec<BatchOp>) {
    if buffer.is_empty() {
        return;
    }
    let n = buffer.len();
    let drained: Vec<BatchOp> = buffer.drain(..).collect();
    match store.write_batch(&drained) {
        Ok(()) => debug!(target: "store::writer", n, "flushed"),
        Err(e) => warn!(target: "store::writer", error = %e, "flush failed; data lost"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blobs::NodeStatsBlob, store::Store};

    #[tokio::test]
    async fn enqueue_and_flush_persists() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-aw-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::open(&path).unwrap();
        let writer = AsyncWriter::spawn(store.clone());
        for i in 0..32 {
            let blob = NodeStatsBlob {
                samples: i,
                ..Default::default()
            };
            assert!(writer.enqueue(BatchOp::PutNodeStats(format!("N{i}"), blob)));
        }
        writer.shutdown().await;
        let stats = store.approximate_stats().unwrap();
        assert_eq!(stats.smart_node_stats, 32);
    }
}
