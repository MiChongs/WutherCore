//! 出站协议适配器集合。
//!
//! **真实现**（与 mihomo / xray / sing-box 互通）：
//! * [`shadowsocks`] —— SS AEAD（aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305）
//! * [`ss2022`]      —— SIP022 (2022-blake3-{aes-128-gcm, aes-256-gcm, chacha20-poly1305})
//! * [`ssr`]         —— ShadowsocksR (origin + plain obfs + aes-cfb)
//! * [`snell`]       —— Snell v3
//! * [`trojan`]      —— Trojan over TLS
//! * [`vless`]       —— VLESS over TLS / TCP / WebSocket
//! * [`vmess`]       —— VMess AEAD (aes-128-gcm / chacha20-poly1305 / none)
//! * [`anytls`]      —— AnyTLS single-stream
//!
//! **占位**（dial 返回明确的"协议尚未实现"）：
//! * Hysteria v1 / Hysteria2 / TUIC（基于 QUIC，需 quinn 集成 PR）
//! * WireGuard（需 boringtun 集成 PR）
//! * SSH（需 russh 集成 PR）
//! * Mieru / Sudoku / Trusttunnel（冷门协议，单独 PR）
//!
//! 上述占位由 [`crate::stub::StubOutbound`] 提供，dial 时给出
//! `ErrorKind::Unsupported` 与协议名，避免静默失败。

pub mod addr;
pub mod anytls;
pub mod hysteria;
pub mod hysteria2;
pub mod mieru;
pub mod shadowsocks;
pub mod snell;
pub mod ss2022;
pub mod ssh;
pub mod ssr;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod wireguard;
pub mod vmess;
pub mod vmess_kdf;
pub mod vmess_legacy;
