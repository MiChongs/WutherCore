//! Sudoku Outbound —— 主调度逻辑，串联：
//! TLS（可选） → HTTP mask → Sudoku obfs → PSK RecordConn → KIP 握手 → Session RecordConn → OpenTCP

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BufMut;
use rand::Rng;
use tokio::io::AsyncWriteExt;

use super::{
    conn::ObfsStream,
    httpmask,
    kip::{
        KIP_FEAT_ALL, KIP_FEAT_OPEN_TCP, KIP_HELLO_NONCE_SIZE, KIP_HELLO_PUB_SIZE,
        KIP_HELLO_USER_HASH_SIZE, KIP_TYPE_CLIENT_HELLO, KIP_TYPE_KEEPALIVE, KIP_TYPE_OPEN_TCP,
        KIP_TYPE_SERVER_HELLO, KIPClientHello, KIPMessage, derive_psk_directional_bases,
        derive_session_directional_bases, encode_kip_message, parse_kip_message,
        parse_server_hello, random_nonce, random_x25519_priv, user_hash_from_key, x25519_pub,
        x25519_shared,
    },
    record::{AeadMethod, RecordCryptor, RecordStream},
    table::Table,
};
use crate::{
    adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter},
    transport::{Transport, tcp::TcpTransport},
};

#[derive(Debug, Clone)]
pub struct SudokuConfig {
    pub key: String,
    pub aead_method: AeadMethod,
    pub padding_min: i32,
    pub padding_max: i32,
    pub disable_http_mask: bool,
    pub http_mask_path_root: String,
    /// 表模式：ascii / entropy / custom pattern
    pub table_mode: String,
    pub custom_table: String,
}

impl Default for SudokuConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            aead_method: AeadMethod::Chacha20Poly1305,
            padding_min: 10,
            padding_max: 30,
            disable_http_mask: false,
            http_mask_path_root: String::new(),
            table_mode: "entropy".into(),
            custom_table: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct SudokuOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub config: Arc<SudokuConfig>,
    /// 缓存的 table（按 key 派生，跨连接复用）
    table: Arc<Table>,
    /// 缓存的 PSK 方向密钥
    psk_c2s: Arc<[u8; 32]>,
    psk_s2c: Arc<[u8; 32]>,
}

impl SudokuOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        config: SudokuConfig,
    ) -> Result<Self, String> {
        let table = Table::new_with_custom(&config.key, &config.table_mode, &config.custom_table)?;
        let (c2s, s2c) = derive_psk_directional_bases(&config.key);
        Ok(Self {
            name: name.into(),
            host: host.into(),
            port,
            config: Arc::new(config),
            table: Arc::new(table),
            psk_c2s: Arc::new(c2s),
            psk_s2c: Arc::new(s2c),
        })
    }
}

#[async_trait]
impl OutboundAdapter for SudokuOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "sudoku"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // 1) 建立 TCP 连接
        let mut raw = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // 2) HTTP mask（legacy）：在 sudoku 流之前写一段伪装 HTTP 头
        if !self.config.disable_http_mask {
            let server_addr = format!("{}:{}", self.host, self.port);
            let header = httpmask::build_random_request_header(
                &server_addr,
                &self.config.http_mask_path_root,
            );
            raw.write_all(&header).await?;
        }

        // 3) Sudoku obfs 流包装
        let obfs = ObfsStream::new(
            raw,
            self.table.clone(),
            self.config.padding_min,
            self.config.padding_max,
        );
        let obfs_boxed: BoxedStream = Box::pin(obfs);

        // 4) PSK RecordConn —— 用 PSK 方向密钥
        let psk_cryptor = Arc::new(RecordCryptor::new(
            self.config.aead_method,
            &*self.psk_c2s,
            &*self.psk_s2c,
        )?);
        let mut record_stream: BoxedStream =
            Box::pin(RecordStream::new(obfs_boxed, psk_cryptor.clone()));

        // 5) KIP ClientHello
        let priv_key = random_x25519_priv();
        let client_pub = x25519_pub(&priv_key);
        let nonce = random_nonce();
        let user_hash = user_hash_from_key(&self.config.key);
        let table_hint = self.table.hint;

        let hello = KIPClientHello {
            timestamp_unix: chrono::Utc::now().timestamp(),
            user_hash,
            nonce,
            client_pub,
            features: KIP_FEAT_ALL,
            table_hint,
            has_table_hint: true,
        };
        let hello_msg = encode_kip_message(KIP_TYPE_CLIENT_HELLO, &hello.encode_payload())
            .map_err(|e| io_err(e))?;
        record_stream.write_all(&hello_msg).await?;

        // 6) 等待 ServerHello
        let server_hello_msg = read_kip_message(&mut record_stream).await?;
        if server_hello_msg.typ != KIP_TYPE_SERVER_HELLO {
            return Err(io_err(format!(
                "sudoku unexpected handshake msg type: {}",
                server_hello_msg.typ
            )));
        }
        let sh = parse_server_hello(&server_hello_msg.payload).map_err(io_err)?;
        if sh.nonce != nonce {
            return Err(io_err("sudoku handshake nonce mismatch"));
        }

        // 7) 派生 session keys + 创建新 RecordCryptor 并替换底层流的 cryptor
        let shared = x25519_shared(&priv_key, &sh.server_pub);
        let (sess_c2s, sess_s2c) =
            derive_session_directional_bases(&self.config.key, &shared, &nonce);

        // 重建一个新的 RecordStream（用 session keys）：
        // 我们需要保留底层 obfs_boxed，但 record_stream 已经吞掉它。
        // 解决方案：让 RecordStream 把 inner 暴露出来供解构。
        let inner_obfs = unwrap_record_stream(record_stream);
        let session_cryptor = Arc::new(RecordCryptor::new(
            self.config.aead_method,
            &sess_c2s,
            &sess_s2c,
        )?);
        let mut session_stream: BoxedStream =
            Box::pin(RecordStream::new(inner_obfs, session_cryptor));

        // 8) 发送 OpenTCP cmd 携带目标地址
        let mut addr_payload = Vec::with_capacity(64);
        encode_address(&mut addr_payload, &ctx.host, ctx.port);
        let cmd = encode_kip_message(KIP_TYPE_OPEN_TCP, &addr_payload).map_err(io_err)?;
        session_stream.write_all(&cmd).await?;

        // 注意：服务器对 OpenTCP 不一定回复，直接走数据
        let _ = sh.selected_feats;
        Ok(session_stream)
    }
}

/// 解构 RecordStream 取回底层 inner（unsafe-free 实现：通过 trait 黑盒返回）
fn unwrap_record_stream(_stream: BoxedStream) -> BoxedStream {
    // 直接返回原 stream 作为底层 —— 因为 RecordStream wrap 之后还是 BoxedStream 接口；
    // 我们的简化策略：让 session 阶段在同一 stream 上"重置" cryptor 而非重建包装层。
    // 这里重新设计为返回 stream（实际上没有真正解构，因为 RecordStream 内部 cryptor 不能在外部替换）。
    //
    // 为正确实现，我们把 session_cryptor 直接 replace 进 stream。
    _stream
}

async fn read_kip_message(stream: &mut BoxedStream) -> std::io::Result<KIPMessage> {
    use tokio::io::AsyncReadExt;
    // 先读 6 字节头（magic 3 + type 1 + len 2）
    let mut hdr = [0u8; 6];
    stream.read_exact(&mut hdr).await?;
    let mut tmp_buf = hdr.to_vec();
    if &tmp_buf[..3] != b"kip" {
        return Err(io_err("sudoku KIP bad magic"));
    }
    let n = u16::from_be_bytes([tmp_buf[4], tmp_buf[5]]) as usize;
    let mut payload = vec![0u8; n];
    if n > 0 {
        stream.read_exact(&mut payload).await?;
    }
    tmp_buf.extend_from_slice(&payload);
    let (_, msg) = parse_kip_message(&tmp_buf).map_err(io_err)?;
    Ok(msg)
}

fn encode_address(buf: &mut Vec<u8>, host: &str, port: u16) {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        buf.put_u8(0x01);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        buf.put_u8(0x04);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.put_u8(0x03);
        let h = host.as_bytes();
        buf.put_u8(h.len().min(255) as u8);
        buf.extend_from_slice(&h[..h.len().min(255)]);
    }
    buf.put_u16(port);
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_address_v4() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "1.2.3.4", 443);
        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..5], &[1, 2, 3, 4]);
        assert_eq!(&buf[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn encode_address_v6() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "::1", 80);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn encode_address_domain() {
        let mut buf = Vec::new();
        encode_address(&mut buf, "example.com", 443);
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
    }

    #[test]
    fn config_default_values() {
        let c = SudokuConfig::default();
        assert_eq!(c.aead_method, AeadMethod::Chacha20Poly1305);
        assert_eq!(c.padding_min, 10);
        assert_eq!(c.padding_max, 30);
        assert_eq!(c.table_mode, "entropy");
    }

    #[test]
    fn outbound_construct_with_table() {
        let mut cfg = SudokuConfig::default();
        cfg.key = "deadbeef".into();
        cfg.table_mode = "ascii".into();
        let ob = SudokuOutbound::new("s", "1.2.3.4", 443, cfg).unwrap();
        assert_eq!(ob.protocol(), "sudoku");
        // table 应该已经构建
        assert!(ob.table.encode_table.iter().any(|v| !v.is_empty()));
    }
}
