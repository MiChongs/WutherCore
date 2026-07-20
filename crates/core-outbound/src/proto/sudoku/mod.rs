//! Sudoku 出站 —— 完整实现，与 mihomo `transport/sudoku` 互通。
//!
//! ## 协议总览
//!
//! Sudoku 是一个基于字节表混淆 + AEAD 记录连接的代理协议，由 mihomo 私有实现：
//!
//! 1. **字节表混淆 (Sudoku obfs)**：
//!    - 每个字节 → 4x4 数独网格 → 4 个 hint 字节
//!    - hint 字节插入随机 padding
//!    - ASCII / Entropy / Custom 三种 byte layout
//! 2. **AEAD RecordConn**：
//!    - chacha20-poly1305 / aes-128-gcm / none
//!    - epoch + seq nonce
//!    - 自动 32 MiB 后 bump epoch
//!    - 严格按序 + 防重放
//! 3. **KIP 握手**：
//!    - X25519 ECDH + nonce
//!    - 时间戳防重放（±60s）
//!    - 特性协商（OpenTCP / Mux / UoT / KeepAlive）
//!    - Table hint 支持多表轮换
//! 4. **HTTP mask (legacy)**：
//!    - 在 sudoku 流之前注入伪装 HTTP/1.1 请求头
//! 5. **Session 类型**：TCP / UoT (UDP over TCP) / Multiplex
//!
//! ## 实现范围（**完整**）
//!
//! * Grid 生成 (288 网格)
//! * Layout: ASCII / Entropy / Custom (8-char pattern: 2x+2p+4v)
//! * Encode table: 256 字节 → 多个 `[u8; 4]` 编码
//! * Decode map: sorted hints u32 → byte
//! * Padding pool 随机插入
//! * RecordConn: AEAD + epoch + seq + 自动密钥更新
//! * KIP ClientHello / ServerHello + X25519 + HKDF
//! * HTTP mask legacy 模式
//! * 客户端握手完整流程：HTTP mask → sudoku obfs → PSK RecordConn →
//!   ClientHello → ServerHello → 派生 session keys → rekey →
//!   发送 OpenTCP cmd

pub mod conn;
pub mod grid;
pub mod httpmask;
pub mod kip;
pub mod layout;
pub mod outbound;
pub mod record;
pub mod table;

pub use outbound::SudokuOutbound;
pub use record::AeadMethod;
pub use table::Table;
