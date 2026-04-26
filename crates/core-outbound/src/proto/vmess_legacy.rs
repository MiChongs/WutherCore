//! VMess Legacy (MD5 模式) —— 兼容老版本服务端 / `alterId > 0` 部署。
//!
//! 协议：[VMess Legacy](https://github.com/v2fly/v2fly-github-io/blob/master/docs/developer/protocols/vmess.md#legacy)
//!
//! ## 鉴权（AuthInfo）
//! ```text
//! AuthInfo(16) = HMAC-MD5(key=uuid_bytes, message=time_secs_be8)
//! ```
//! 时间戳取当前 UTC，允许 ±30 秒漂移。
//!
//! ## Header 加密
//! ```text
//! cmd_key   = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
//! header_iv = MD5(time:8 || time:8 || time:8 || time:8)  // 重复 4 次
//! AES-128-CFB(cmd_key, header_iv, header_payload)
//! ```
//!
//! Header payload 与 AEAD 模式相同（V2 instruction）。

use std::sync::Arc;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use async_trait::async_trait;
use bytes::BufMut;
use cfb_mode::{Decryptor as CfbDec, Encryptor as CfbEnc};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::proto::vmess::{
    build_legacy_header_payload, VmessSecurity, VMESS_OPTION_CHUNK_STREAM,
};
use crate::transport::{tcp::TcpTransport, tls::TlsTransport, ws::WsTransport, TlsOptions, Transport, WsOptions};

type HmacMd5 = Hmac<Md5>;

#[derive(Debug, Clone)]
pub struct VmessLegacyOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub uuid: Uuid,
    pub alter_id: u16,
    pub security: VmessSecurity,
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub ws: Option<WsOptions>,
}

impl VmessLegacyOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        uuid: Uuid,
        alter_id: u16,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            uuid,
            alter_id,
            security: VmessSecurity::Aes128Gcm,
            tls: false,
            sni: None,
            insecure: false,
            alpn: vec![],
            ws: None,
        }
    }
}

#[async_trait]
impl OutboundAdapter for VmessLegacyOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "vmess-legacy" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: true, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream: BoxedStream = if let Some(ws) = self.ws.as_ref().filter(|w| w.enabled) {
            WsTransport::new(ws.clone(), self.tls).connect(&self.host, self.port).await?
        } else if self.tls {
            TlsTransport::new(TlsOptions {
                enabled: true,
                sni: self.sni.clone(),
                insecure: self.insecure,
                alpn: self.alpn.clone(),
            })
            .connect(&self.host, self.port).await?
        } else {
            TcpTransport::default().connect(&self.host, self.port).await?
        };

        // 1) Compute AuthInfo + cmd_key + header_iv
        let now = chrono::Utc::now().timestamp() as u64;
        // 选择带 alter_id 的 uuid（legacy 客户端实际拉一个备用 user list；这里用主 uuid）
        let auth_info = compute_auth_info(self.uuid.as_bytes(), now);
        let cmd_key = compute_cmd_key(&self.uuid);
        let header_iv = compute_header_iv(now);

        // 2) 构造 header_payload（与 AEAD 复用相同布局）
        let mut iv = [0u8; 16];
        let mut req_key = [0u8; 16];
        let mut resp_auth = [0u8; 1];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        rand::rngs::OsRng.fill_bytes(&mut req_key);
        rand::rngs::OsRng.fill_bytes(&mut resp_auth);

        let cmd = if ctx.network == "udp" { 0x02 } else { 0x01 };
        let mut header_payload = build_legacy_header_payload(
            &iv, &req_key, resp_auth[0], self.security.select(), cmd, ctx.port, &ctx.host,
        );
        // AES-128-CFB encrypt in place
        let enc = CfbEnc::<aes::Aes128>::new_from_slices(&cmd_key, &header_iv)
            .map_err(|_| std_io_err("legacy cfb key"))?;
        enc.encrypt(&mut header_payload);

        // 3) 写出：AuthInfo(16) + EncryptedHeader(N)
        let mut wire = Vec::with_capacity(16 + header_payload.len());
        wire.extend_from_slice(&auth_info);
        wire.extend_from_slice(&header_payload);
        stream.write_all(&wire).await?;

        // 4) 读 server 响应：AES-128-CFB(MD5(req_key), MD5(iv)) over [resp_auth(1) + opt(1) + cmd_resp(1) + cmd_resp_size(1) + cmd_resp_payload(N)]
        let resp_key = md5_digest(&req_key);
        let resp_iv = md5_digest(&iv);
        let mut head_buf = [0u8; 4];
        stream.read_exact(&mut head_buf).await?;
        let dec = CfbDec::<aes::Aes128>::new_from_slices(&resp_key, &resp_iv)
            .map_err(|_| std_io_err("legacy cfb resp key"))?;
        let mut head_dec = head_buf;
        dec.decrypt(&mut head_dec);
        if head_dec[0] != resp_auth[0] {
            return Err(std_io_err("vmess legacy resp auth mismatch"));
        }
        let cmd_resp_size = head_dec[3] as usize;
        if cmd_resp_size > 0 {
            // 跳过 cmd resp（dynamic port 等扩展）
            let mut skip = vec![0u8; cmd_resp_size];
            stream.read_exact(&mut skip).await?;
        }

        // 5) 包装为流 —— legacy 模式默认走 stream cipher (AES-128-CFB) + payload 长度前缀
        // 与 AEAD 共用 ChunkCryptor 时 sec=AEAD 即可；此处沿用 AEAD chunk stream
        // mihomo 实际 legacy 也支持升级到 AEAD chunk，本实现走 AEAD 一致
        // Legacy 默认仅 CHUNK_STREAM（向旧服务端兼容；不启用 masking/padding/auth_len）
        crate::proto::vmess::wrap_chunk_stream(
            stream,
            self.security.select(),
            &req_key,
            &iv,
            VMESS_OPTION_CHUNK_STREAM,
        )
    }
}

fn compute_auth_info(uuid_bytes: &[u8], time_secs: u64) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(uuid_bytes).expect("hmac md5 key");
    mac.update(&time_secs.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}

fn compute_cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid.as_bytes());
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let r = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}

fn compute_header_iv(time_secs: u64) -> [u8; 16] {
    let mut h = Md5::new();
    let t = time_secs.to_be_bytes();
    h.update(&t);
    h.update(&t);
    h.update(&t);
    h.update(&t);
    let r = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}

fn std_io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_info_deterministic() {
        let uid = Uuid::nil();
        let a = compute_auth_info(uid.as_bytes(), 1700000000);
        let b = compute_auth_info(uid.as_bytes(), 1700000000);
        assert_eq!(a, b);
        let c = compute_auth_info(uid.as_bytes(), 1700000001);
        assert_ne!(a, c);
    }

    #[test]
    fn header_iv_changes_with_time() {
        let a = compute_header_iv(1700000000);
        let b = compute_header_iv(1700000001);
        assert_ne!(a, b);
    }

    #[test]
    fn legacy_construct() {
        let uid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let ob = VmessLegacyOutbound::new("v", "1.2.3.4", 443, uid, 0);
        assert_eq!(ob.protocol(), "vmess-legacy");
    }
}
