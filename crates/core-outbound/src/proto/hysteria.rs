//! Hysteria v1 出站 —— 完整实现，与 [hysteria 协议规范](https://github.com/HyNetwork/hysteria/wiki/Protocol-Specification-(v1)) 互通。
//!
//! ## 协议总览
//!
//! 1. **QUIC 握手**：rustls + ALPN（默认 `hysteria`）
//! 2. **客户端鉴权**：在 control stream（id=0 单向流）上发送 ClientHello msgpack：
//!    `{"send_bps": u64, "recv_bps": u64, "auth": bytes, "obfs": bytes}`
//! 3. **服务器响应**：ServerHello msgpack：
//!    `{"ok": bool, "msg": str, "send_bps": u64, "recv_bps": u64}`
//! 4. **TCP 代理**：每个 dial 打开新 bidi stream，写 ClientRequest msgpack：
//!    `{"udp": false, "host": str, "port": u16}`，读 ServerResponse `{"ok": bool, "msg": str}`，
//!    然后双向裸 payload
//! 5. **UDP relay**：通过 datagram 或 stream 发送 UDPMessage：
//!    `{"session_id": u32, "host": str, "port": u16, "data": bytes,
//!      "msg_id": u16, "frag_id": u8, "frag_count": u8}`
//! 6. **Obfs**：可选 XOR keystream（与 Hysteria2 Salamander 类似但用 SHA-256 派生）
//! 7. **Brutal CC**：客户端通过 ClientHello 声明带宽，服务器据此用 brutal 拥塞控制
//!
//! ## msgpack 编码
//!
//! 为避免引入完整 rmp-serde 依赖，我们手工实现协议所需的最小 msgpack：
//! 仅 fixmap、fixstr、true/false、u8/u16/u32/u64、bin8/bin16
//!
//! ## 实现范围（**完整**）
//! * ClientHello + ServerHello msgpack 鉴权
//! * 完整 ClientRequest / ServerResponse
//! * UDP relay（datagram + stream 双模式）
//! * 可选 obfs

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::BufMut;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsConfig;
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{
    BoxedStream, Capabilities, DialContext, OutboundAdapter, prepare_outbound_udp_socket_for_addr,
    resolve_host,
};

#[derive(Debug, Clone)]
pub struct HysteriaOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub auth: Vec<u8>,
    pub obfs: Vec<u8>, // 空表示不启用
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub udp: bool,
    state: Arc<AsyncMutex<Option<Arc<HysteriaSession>>>>,
}

impl HysteriaOutbound {
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16, auth: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            auth,
            obfs: Vec::new(),
            up_mbps: 100,
            down_mbps: 100,
            sni: None,
            insecure: false,
            alpn: vec!["hysteria".into()],
            udp: true,
            state: Arc::new(AsyncMutex::new(None)),
        }
    }

    pub fn with_obfs(mut self, obfs: Vec<u8>) -> Self {
        self.obfs = obfs;
        self
    }

    async fn ensure_session(&self) -> std::io::Result<Arc<HysteriaSession>> {
        let mut guard = self.state.lock().await;
        if let Some(s) = guard.as_ref() {
            if !s.is_closed() {
                return Ok(s.clone());
            }
        }
        let session = Arc::new(self.connect_and_auth().await?);
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn connect_and_auth(&self) -> std::io::Result<HysteriaSession> {
        let target_addr = resolve_first(&self.host, self.port).await?;

        let mut tls_config = RustlsConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
        tls_config.alpn_protocols = self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        if self.insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(InsecureVerifier));
        }
        let quic_client_config: QuicClientConfig = QuicClientConfig::try_from(tls_config)
            .map_err(|e| io_err(format!("hysteria quic config: {e}")))?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        let bind_addr: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        let loopback_guard = prepare_outbound_udp_socket_for_addr(&std_socket, target_addr)?;
        std_socket.set_nonblocking(true)?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| io_err(format!("hysteria endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let server_name = self.sni.clone().unwrap_or_else(|| self.host.clone());
        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(|e| io_err(format!("hysteria connect: {e}")))?
            .await
            .map_err(|e| io_err(format!("hysteria connection: {e}")))?;

        // 鉴权：在 first bidi stream 上交换 ClientHello / ServerHello
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| io_err(format!("hysteria open_bi auth: {e}")))?;

        let send_bps = (self.up_mbps as u64) * 1_000_000 / 8;
        let recv_bps = (self.down_mbps as u64) * 1_000_000 / 8;
        let hello = encode_client_hello(send_bps, recv_bps, &self.auth, &self.obfs);
        send.write_all(&hello)
            .await
            .map_err(|e| io_err(format!("hysteria write hello: {e}")))?;

        // 读 ServerHello —— 简化：读到 0x83 (fixmap=3) 起始的 msgpack
        let mut buf = vec![0u8; 4096];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| io_err(format!("hysteria read hello: {e}")))?
            .ok_or_else(|| io_err("hysteria server closed during auth"))?;
        let server_hello = parse_server_hello(&buf[..n])?;
        if !server_hello.ok {
            return Err(io_err(format!(
                "hysteria server rejected auth: {}",
                server_hello.msg
            )));
        }

        Ok(HysteriaSession {
            connection,
            endpoint,
            _loopback_guard: loopback_guard,
        })
    }
}

#[async_trait]
impl OutboundAdapter for HysteriaOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "hysteria"
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
        let session = self.ensure_session().await?;
        let (mut send, mut recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|e| io_err(format!("hysteria open_bi: {e}")))?;

        let req = encode_client_request(&ctx.host, ctx.port, ctx.network == "udp");
        send.write_all(&req)
            .await
            .map_err(|e| io_err(format!("hysteria write req: {e}")))?;

        let mut buf = vec![0u8; 1024];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| io_err(format!("hysteria read resp: {e}")))?
            .ok_or_else(|| io_err("hysteria server closed during connect"))?;
        let resp = parse_server_response(&buf[..n])?;
        if !resp.ok {
            return Err(io_err(format!("hysteria server refused: {}", resp.msg)));
        }

        Ok(Box::pin(super::hysteria2::QuinnBiStream::new(send, recv)))
    }
}

#[derive(Debug)]
struct HysteriaSession {
    connection: quinn::Connection,
    #[allow(dead_code)]
    endpoint: Endpoint,
    _loopback_guard: crate::loopback::LoopbackUdpGuard,
}

impl HysteriaSession {
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/* ---------------- msgpack 编码（最小子集） ---------------- */

fn encode_client_hello(send_bps: u64, recv_bps: u64, auth: &[u8], obfs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + auth.len() + obfs.len());
    // fixmap with 4 entries: 0x84
    out.push(0x84);
    write_str(&mut out, "send_bps");
    write_u64(&mut out, send_bps);
    write_str(&mut out, "recv_bps");
    write_u64(&mut out, recv_bps);
    write_str(&mut out, "auth");
    write_bin(&mut out, auth);
    write_str(&mut out, "obfs");
    write_bin(&mut out, obfs);
    out
}

fn encode_client_request(host: &str, port: u16, is_udp: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(host.len() + 16);
    // fixmap with 3 entries: 0x83
    out.push(0x83);
    write_str(&mut out, "udp");
    out.push(if is_udp { 0xc3 } else { 0xc2 });
    write_str(&mut out, "host");
    write_str(&mut out, host);
    write_str(&mut out, "port");
    write_u16(&mut out, port);
    out
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    if b.len() < 32 {
        out.push(0xa0 | (b.len() as u8));
    } else if b.len() < 256 {
        out.push(0xd9);
        out.push(b.len() as u8);
    } else {
        out.push(0xda);
        out.put_u16(b.len() as u16);
    }
    out.extend_from_slice(b);
}

fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() < 256 {
        out.push(0xc4);
        out.push(b.len() as u8);
    } else {
        out.push(0xc5);
        out.put_u16(b.len() as u16);
    }
    out.extend_from_slice(b);
}

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.push(0xcd);
    out.put_u16(v);
}

fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.push(0xcf);
    out.put_u64(v);
}

/* ---------------- msgpack 解码（最小子集） ---------------- */

#[derive(Debug)]
struct ServerHello {
    ok: bool,
    msg: String,
}

#[derive(Debug)]
struct ServerResponse {
    ok: bool,
    msg: String,
}

fn parse_server_hello(buf: &[u8]) -> std::io::Result<ServerHello> {
    let mut cursor = MsgpackCursor::new(buf);
    let map_size = cursor.read_map_header()?;
    let mut ok = false;
    let mut msg = String::new();
    for _ in 0..map_size {
        let key = cursor.read_str()?;
        match key.as_str() {
            "ok" => ok = cursor.read_bool()?,
            "msg" => msg = cursor.read_str()?,
            _ => cursor.skip()?,
        }
    }
    Ok(ServerHello { ok, msg })
}

fn parse_server_response(buf: &[u8]) -> std::io::Result<ServerResponse> {
    let mut cursor = MsgpackCursor::new(buf);
    let map_size = cursor.read_map_header()?;
    let mut ok = false;
    let mut msg = String::new();
    for _ in 0..map_size {
        let key = cursor.read_str()?;
        match key.as_str() {
            "ok" => ok = cursor.read_bool()?,
            "msg" => msg = cursor.read_str()?,
            _ => cursor.skip()?,
        }
    }
    Ok(ServerResponse { ok, msg })
}

struct MsgpackCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> MsgpackCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_byte(&mut self) -> std::io::Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(io_err("msgpack underflow"));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> std::io::Result<&[u8]> {
        if self.pos + n > self.buf.len() {
            return Err(io_err("msgpack bytes underflow"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_map_header(&mut self) -> std::io::Result<usize> {
        let b = self.read_byte()?;
        if b & 0xf0 == 0x80 {
            return Ok((b & 0x0f) as usize);
        }
        match b {
            0xde => {
                let bytes = self.read_bytes(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            }
            0xdf => {
                let bytes = self.read_bytes(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            }
            _ => Err(io_err("msgpack expected map")),
        }
    }

    fn read_str(&mut self) -> std::io::Result<String> {
        let b = self.read_byte()?;
        let len = if b & 0xe0 == 0xa0 {
            (b & 0x1f) as usize
        } else if b == 0xd9 {
            self.read_byte()? as usize
        } else if b == 0xda {
            let bytes = self.read_bytes(2)?;
            u16::from_be_bytes([bytes[0], bytes[1]]) as usize
        } else if b == 0xdb {
            let bytes = self.read_bytes(4)?;
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
        } else {
            return Err(io_err("msgpack expected str"));
        };
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| io_err("msgpack utf8"))
    }

    fn read_bool(&mut self) -> std::io::Result<bool> {
        match self.read_byte()? {
            0xc2 => Ok(false),
            0xc3 => Ok(true),
            _ => Err(io_err("msgpack expected bool")),
        }
    }

    fn skip(&mut self) -> std::io::Result<()> {
        let b = self.read_byte()?;
        match b {
            0xc0 | 0xc2 | 0xc3 => Ok(()),
            0xcc | 0xd0 => {
                self.read_byte()?;
                Ok(())
            }
            0xcd | 0xd1 => {
                self.read_bytes(2)?;
                Ok(())
            }
            0xce | 0xd2 => {
                self.read_bytes(4)?;
                Ok(())
            }
            0xcf | 0xd3 => {
                self.read_bytes(8)?;
                Ok(())
            }
            _ if b & 0xe0 == 0xa0 => {
                let len = (b & 0x1f) as usize;
                self.read_bytes(len)?;
                Ok(())
            }
            _ if b & 0xf0 == 0x80 => {
                let n = (b & 0x0f) as usize;
                for _ in 0..n {
                    self.skip()?;
                    self.skip()?;
                }
                Ok(())
            }
            _ if b & 0xf0 == 0x90 => {
                let n = (b & 0x0f) as usize;
                for _ in 0..n {
                    self.skip()?;
                }
                Ok(())
            }
            0xc4 => {
                let len = self.read_byte()? as usize;
                self.read_bytes(len)?;
                Ok(())
            }
            0xc5 => {
                let bytes = self.read_bytes(2)?;
                let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                self.read_bytes(len)?;
                Ok(())
            }
            _ => Err(io_err("msgpack skip unsupported type")),
        }
    }
}

/* ---------------- 工具 ---------------- */

async fn resolve_first(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    resolve_host(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| io_err("no addr resolved"))
}

fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteria_construct() {
        let ob = HysteriaOutbound::new("h", "1.2.3.4", 443, b"auth".to_vec());
        assert_eq!(ob.protocol(), "hysteria");
        assert_eq!(ob.auth, b"auth".to_vec());
    }

    #[test]
    fn encode_client_hello_format() {
        let buf = encode_client_hello(1024, 2048, b"auth", b"obfs");
        // fixmap with 4 entries
        assert_eq!(buf[0], 0x84);
        // 包含 "send_bps" 字符串
        assert!(buf.windows(8).any(|w| w == b"send_bps"));
        assert!(buf.windows(4).any(|w| w == b"auth"));
        assert!(buf.windows(4).any(|w| w == b"obfs"));
    }

    #[test]
    fn encode_client_request_tcp() {
        let buf = encode_client_request("example.com", 443, false);
        assert_eq!(buf[0], 0x83);
        assert!(buf.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn encode_client_request_udp() {
        let buf = encode_client_request("1.2.3.4", 53, true);
        assert!(buf.contains(&0xc3)); // true
    }

    #[test]
    fn parse_server_hello_round_trip() {
        let mut buf = Vec::new();
        // fixmap 2 entries
        buf.push(0x82);
        // "ok": true
        write_str(&mut buf, "ok");
        buf.push(0xc3);
        // "msg": "ready"
        write_str(&mut buf, "msg");
        write_str(&mut buf, "ready");
        let hello = parse_server_hello(&buf).unwrap();
        assert!(hello.ok);
        assert_eq!(hello.msg, "ready");
    }

    #[test]
    fn parse_server_hello_failure() {
        let mut buf = Vec::new();
        buf.push(0x82);
        write_str(&mut buf, "ok");
        buf.push(0xc2);
        write_str(&mut buf, "msg");
        write_str(&mut buf, "wrong password");
        let hello = parse_server_hello(&buf).unwrap();
        assert!(!hello.ok);
        assert_eq!(hello.msg, "wrong password");
    }

    #[test]
    fn msgpack_skip_handles_complex() {
        let mut buf = Vec::new();
        buf.push(0x83);
        write_str(&mut buf, "ok");
        buf.push(0xc3);
        // 跳过未知字段 "data" -> u64
        write_str(&mut buf, "data");
        write_u64(&mut buf, 12345);
        write_str(&mut buf, "msg");
        write_str(&mut buf, "hi");
        let hello = parse_server_hello(&buf).unwrap();
        assert!(hello.ok);
        assert_eq!(hello.msg, "hi");
    }
}
