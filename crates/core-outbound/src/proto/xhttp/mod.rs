//! XHTTP transport —— 完整实现，与 mihomo `transport/xhttp/` 等价。
//!
//! XHTTP 是 v2ray/xray 设计的高性能 HTTP 传输层。它**不是独立的代理协议**，
//! 而是一个**底层传输**，把 VLESS / VMess / Trojan 等协议的字节流封装在
//! 普通 HTTP/2（或 HTTP/1.1、HTTP/3）请求中传输，主要用于 CDN 友好穿透与防探测。
//!
//! ## 三种工作模式
//!
//! * **stream-one**：单一长连接 POST，request body / response body 双向流式
//! * **stream-up**：上行 POST + 独立下行 GET 长连接（解决 CDN response header 阻塞问题）
//! * **packet-up**：上行多次短 POST + 下行 GET 长连接（CDN 最友好）
//!
//! ## Placement 系统
//!
//! 所有元数据（session_id、seq、uplink data、x-padding）都可独立放在：
//! * `path` / `query` / `header` / `cookie` / `body` / `queryInHeader` / `auto`
//!
//! ## X-Padding（防探测）
//!
//! 两种生成方法：
//! * **repeat-x**：N 个 'X'（HPACK Huffman 编码后长度不变）
//! * **tokenish**：随机 base62，调整使 Huffman 编码长度接近 target
//!
//! ## 模块划分
//!
//! * `config.rs` —— Config / ReuseConfig / Range 解析 / Placement 常量
//! * `xpadding.rs` —— XPadding 生成 + HPACK Huffman 长度估算
//! * `request.rs` —— PreparedRequest + apply_meta / apply_x_padding /
//!   fill_stream_request / fill_packet_request / fill_download_request
//! * `upload_queue.rs` —— 服务端按 seq 重排接收 packet
//! * `conn.rs` —— WaitReader（异步初始化的 reader）+ PipeWriter + XConn 组合
//! * `client.rs` —— XhttpClient + dial 三种模式 + PacketUpWriter

mod browser_headers;
pub mod client;
pub mod config;
pub mod conn;
mod download_policy;
mod h3;
pub mod request;
pub mod upload_queue;
pub mod xmux;
pub mod xpadding;

pub use client::XhttpClient;
pub use config::{Config, Range, ReuseConfig};
pub use xpadding::{PaddingMethod, generate_padding};
