//! 全局日志广播总线 —— Clash `/logs` WebSocket 兼容。
//!
//! tracing 的 layer 会把每条事件转成 [`LogEvent`] 推入 broadcast；
//! API 层订阅后流式发送给 dashboard。
//!
//! 容量 256 —— Yacd / metacubexd 默认 1s/帧拉取，很难塞满；满时旧消息覆盖。

use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    /// "debug" / "info" / "warning" / "error" / "silent"
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct LogBus {
    tx: broadcast::Sender<LogEvent>,
}

impl LogBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }
    pub fn push(&self, level: impl Into<String>, payload: impl Into<String>) {
        let _ = self.tx.send(LogEvent {
            level: level.into(),
            payload: payload.into(),
        });
    }
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for LogBus {
    fn default() -> Self {
        Self::new(256)
    }
}
