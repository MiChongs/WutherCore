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
//! * [`anytls`]      —— AnyTLS v2（动态 padding、会话池、SYNACK、UoT v2）
//! * [`wireguard`]   —— 用户态 WireGuard（多 peer、TCP/UDP、IPv4/IPv6、服务端 API）

pub mod addr;
pub mod anytls;
pub mod hysteria;
pub mod hysteria2;
pub mod mieru;
#[cfg(feature = "with_naive")]
pub mod naive;
pub mod shadowsocks;
pub mod snell;
pub mod ss2022;
pub mod ssh;
pub mod ssr;
pub mod sudoku;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod vmess_kdf;
pub mod vmess_legacy;
pub mod wireguard;
pub mod xhttp;
#[cfg(feature = "with_young")]
pub mod young;
