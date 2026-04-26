//! core-observe —— tracing / metrics / 连接表 / 事件总线骨架。
//!
//! §11.7 要求：日志使用异步通道与采样，禁止在转发热路径同步写磁盘。
//! 该模块提供：
//! * `init_tracing` —— 标准 stdout JSON/text 双格式初始化。
//! * `metrics` —— 简单原子计数器，用于 inbound/outbound/route。
//! * `connections` —— 全局连接表（DashMap）+ 软上限。
//! * 事件总线（broadcast）暂留接口。

#![forbid(unsafe_code)]

pub mod connections;
pub mod copy_counted;
pub mod log_bus;
pub mod metrics;
pub mod tracing_init;

pub use connections::{
    ConnectionEntry, ConnectionGuard, ConnectionMeta, ConnectionSnapshot, ConnectionTable,
    RateSample,
};
pub use copy_counted::copy_bidirectional_counted;
pub use log_bus::{LogBus, LogEvent};
pub use metrics::{current_rss_bytes, Metrics};
pub use tracing_init::{init_tracing, init_tracing_with_bus};
