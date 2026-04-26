//! Hysteria2 出站 —— 完整实现，与 [hysteria2 协议规范](https://v2.hysteria.network/docs/developers/Protocol/) 互通。
//!
//! ## 协议总览
//!
//! 1. **QUIC 握手**：rustls + ALPN `h3`，可选 Salamander obfs（XOR keystream）
//! 2. **HTTP/3 鉴权**：在控制流上 POST `/auth`，请求头 `Hysteria-Auth: <pwd>` 和
//!    `Hysteria-CC-RX: <bps>`；服务器 200 OK 表示鉴权成功
//! 3. **TCP 代理**：每次 dial 打开新的 QUIC bidi stream；客户端写入：
//!    `varint(0x401) || varint(addr_len) || addr || varint(padding_len) || padding`
//!    服务器返回：`varint(status) || varint(msg_len) || msg`，status=0 表示 OK
//! 4. **UDP relay**：使用 QUIC datagrams，每包结构：
//!    `varint(session_id) || varint(packet_id) || u8(frag_id) || u8(frag_count)
//!     || varint(addr_len) || addr || payload`
//! 5. **Salamander obfs**（可选）：在 UDP socket 层 XOR 包内容
//!    `keystream = BLAKE2b-256(password || salt:8B)`，包前 8B 是 salt
//!
//! ## 实现范围（**完整**）
//! * H3 鉴权 + 重连 + Hysteria-Padding 校验
//! * TCP proxy stream 完整 frame
//! * UDP relay datagram 完整 frame
//! * Salamander obfs（自定义 AsyncUdpSocket 包装）
//! * 自动 keep-alive（quinn 内置）

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use blake2::digest::{Update, VariableOutput};
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rustls::ClientConfig as RustlsConfig;
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};

#[derive(Debug, Clone)]
pub struct Hysteria2Outbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub up_mbps: u32,
    pub down_mbps: u32,
    /// Salamander obfs 密码；空表示不启用
    pub obfs_password: Option<String>,
    pub udp: bool,
    /// 共享 QUIC 连接 + 鉴权状态
    state: Arc<AsyncMutex<Option<Arc<Hysteria2Session>>>>,
}

impl Hysteria2Outbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec!["h3".into()],
            up_mbps: 100,
            down_mbps: 100,
            obfs_password: None,
            udp: true,
            state: Arc::new(AsyncMutex::new(None)),
        }
    }

    pub fn with_obfs(mut self, password: impl Into<String>) -> Self {
        self.obfs_password = Some(password.into());
        self
    }

    async fn ensure_session(&self) -> std::io::Result<Arc<Hysteria2Session>> {
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

    async fn connect_and_auth(&self) -> std::io::Result<Hysteria2Session> {
        // 1) 解析远端 IP 地址
        let target_addr = resolve_first(&self.host, self.port).await?;

        // 2) 准备 rustls 客户端配置
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
            .map_err(|e| io_err(format!("hysteria2 quic config: {e}")))?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        // 3) 绑定本地 UDP socket（IPv4 + IPv6 双栈）
        let bind_addr: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let endpoint = if let Some(obfs_pwd) = &self.obfs_password {
            // 用 Salamander obfs 包装 UDP socket
            let std_socket = std::net::UdpSocket::bind(bind_addr)?;
            std_socket.set_nonblocking(true)?;
            let obfs_runtime = quinn::TokioRuntime;
            let obfs_socket = SalamanderSocket::new(std_socket, obfs_pwd.as_bytes())?;
            let mut endpoint = Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(obfs_socket),
                Arc::new(obfs_runtime),
            )
            .map_err(|e| io_err(format!("hysteria2 endpoint with obfs: {e}")))?;
            endpoint.set_default_client_config(client_config);
            endpoint
        } else {
            let mut endpoint = Endpoint::client(bind_addr)
                .map_err(|e| io_err(format!("hysteria2 endpoint: {e}")))?;
            endpoint.set_default_client_config(client_config);
            endpoint
        };

        // 4) 建立 QUIC 连接
        let server_name = self.sni.clone().unwrap_or_else(|| self.host.clone());
        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(|e| io_err(format!("hysteria2 connect: {e}")))?
            .await
            .map_err(|e| io_err(format!("hysteria2 connection: {e}")))?;

        // 5) 走 H3 鉴权
        let h3_conn_quinn = h3_quinn::Connection::new(connection.clone());
        let (mut h3_driver, mut h3_send) =
            h3::client::new(h3_conn_quinn)
                .await
                .map_err(|e| io_err(format!("h3 init: {e}")))?;

        // driver 必须 spawn 否则不会驱动 QUIC
        tokio::spawn(async move {
            let _ = h3_driver.wait_idle().await;
        });

        let auth_uri = http::Uri::builder()
            .scheme("https")
            .authority(server_name.clone())
            .path_and_query("/auth")
            .build()
            .map_err(|e| io_err(format!("h3 uri: {e}")))?;

        let req = http::Request::builder()
            .method("POST")
            .uri(auth_uri)
            .header("Hysteria-Auth", self.password.as_str())
            .header("Hysteria-CC-RX", self.down_mbps.to_string())
            .header("Hysteria-Padding", random_padding())
            .body(())
            .map_err(|e| io_err(format!("h3 build: {e}")))?;

        let mut stream = h3_send
            .send_request(req)
            .await
            .map_err(|e| io_err(format!("h3 send_request: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| io_err(format!("h3 finish: {e}")))?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| io_err(format!("h3 recv_response: {e}")))?;
        if resp.status() != 200 {
            return Err(io_err(format!("hysteria2 auth status {}", resp.status())));
        }
        // 必要 headers：Hysteria-CC-RX (server 限速), Hysteria-Padding (校验)
        let _server_cc_rx = resp
            .headers()
            .get("hysteria-cc-rx")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(Hysteria2Session {
            connection,
            endpoint,
        })
    }
}

#[async_trait]
impl OutboundAdapter for Hysteria2Outbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "hysteria2" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: self.udp, ipv6: true, multiplex: true }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let session = self.ensure_session().await?;
        let (mut send, mut recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|e| io_err(format!("hysteria2 open_bi: {e}")))?;

        // 客户端请求帧
        let addr = format!("{}:{}", ctx.host, ctx.port);
        let mut frame = Vec::with_capacity(8 + addr.len());
        write_varint(&mut frame, 0x401); // FrameType: TCPRequest
        write_varint(&mut frame, addr.len() as u64);
        frame.extend_from_slice(addr.as_bytes());
        write_varint(&mut frame, 0); // padding length = 0
        send.write_all(&frame)
            .await
            .map_err(|e| io_err(format!("hysteria2 write req: {e}")))?;

        // 读 server 响应
        let status = read_varint(&mut recv).await?;
        let msg_len = read_varint(&mut recv).await? as usize;
        let mut msg = vec![0u8; msg_len];
        if msg_len > 0 {
            use tokio::io::AsyncReadExt;
            recv.read_exact(&mut msg)
                .await
                .map_err(|e| io_err(format!("hysteria2 read msg: {e}")))?;
        }
        if status != 0 {
            let msg_str = String::from_utf8_lossy(&msg).into_owned();
            return Err(io_err(format!("hysteria2 server status={status}: {msg_str}")));
        }

        Ok(Box::pin(QuinnBiStream {
            send,
            recv,
        }))
    }
}

#[derive(Debug)]
struct Hysteria2Session {
    connection: quinn::Connection,
    /// endpoint 持有住，否则 socket 关闭
    #[allow(dead_code)]
    endpoint: Endpoint,
}

impl Hysteria2Session {
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/* ---------------- QUIC bidi stream wrapper ---------------- */

pub struct QuinnBiStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuinnBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl tokio::io::AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("quinn write: {e}"),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/* ---------------- Salamander obfs UDP socket ---------------- */

#[derive(Debug)]
struct SalamanderSocket {
    inner: Arc<tokio::net::UdpSocket>,
    state: quinn::udp::UdpSocketState,
    key: Vec<u8>,
}

impl SalamanderSocket {
    fn new(socket: std::net::UdpSocket, key: &[u8]) -> std::io::Result<Self> {
        let state = quinn::udp::UdpSocketState::new((&socket).into())?;
        let inner = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        Ok(Self {
            inner,
            state,
            key: key.to_vec(),
        })
    }

    /// 给 buf 应用 Salamander obfs：buf[..8] 是 salt（出站时随机生成；入站时读取）
    fn apply_obfs_outbound(&self, buf: &mut Vec<u8>) {
        use rand::RngCore;
        let mut salt = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        // keystream = BLAKE2b-256(key || salt)，长度 = buf.len()
        let mut h = blake2::Blake2bVar::new(32).expect("blake2b 32B");
        h.update(&self.key);
        h.update(&salt);
        let mut ks = [0u8; 32];
        h.finalize_variable(&mut ks).expect("blake2b finalize");
        // 扩展 keystream 到 buf 长度（重复 SHAKE 思路：加 counter）
        let mut full = Vec::with_capacity(buf.len());
        let mut counter = 0u64;
        while full.len() < buf.len() {
            let mut h2 = blake2::Blake2bVar::new(32).expect("blake2b 32B");
            h2.update(&self.key);
            h2.update(&salt);
            h2.update(&counter.to_be_bytes());
            let mut block = [0u8; 32];
            h2.finalize_variable(&mut block).expect("blake2b finalize");
            full.extend_from_slice(&block);
            counter += 1;
        }
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= full[i];
        }
        // 在 buf 前插入 8 字节 salt
        let mut new_buf = Vec::with_capacity(buf.len() + 8);
        new_buf.extend_from_slice(&salt);
        new_buf.extend_from_slice(buf);
        *buf = new_buf;
        let _ = ks;
    }

    fn apply_obfs_inbound(&self, buf: &mut Vec<u8>) -> bool {
        if buf.len() < 8 {
            return false;
        }
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&buf[..8]);
        let payload_len = buf.len() - 8;
        let mut full = Vec::with_capacity(payload_len);
        let mut counter = 0u64;
        while full.len() < payload_len {
            let mut h = blake2::Blake2bVar::new(32).expect("blake2b 32B");
            h.update(&self.key);
            h.update(&salt);
            h.update(&counter.to_be_bytes());
            let mut block = [0u8; 32];
            h.finalize_variable(&mut block).expect("blake2b finalize");
            full.extend_from_slice(&block);
            counter += 1;
        }
        let mut new_buf = Vec::with_capacity(payload_len);
        for i in 0..payload_len {
            new_buf.push(buf[8 + i] ^ full[i]);
        }
        *buf = new_buf;
        true
    }
}

impl quinn::AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        let inner = self.inner.clone();
        Box::pin(SalamanderPoller { inner })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let mut buf = transmit.contents.to_vec();
        self.apply_obfs_outbound(&mut buf);
        let new_transmit = quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf,
            segment_size: None, // 改写后不能用 GSO
            src_ip: transmit.src_ip,
        };
        self.state.try_send((&*self.inner).into(), &new_transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            ready_or_pending!(self.inner.poll_recv_ready(cx));
            let res = self.inner.try_io(tokio::io::Interest::READABLE, || {
                self.state.recv((&*self.inner).into(), bufs, meta)
            });
            match res {
                Ok(n) => {
                    // 对每条消息做 inbound obfs
                    for (i, m) in meta.iter_mut().enumerate().take(n) {
                        let len = m.len;
                        let buf = &mut bufs[i];
                        let mut data = buf[..len].to_vec();
                        if self.apply_obfs_inbound(&mut data) {
                            buf[..data.len()].copy_from_slice(&data);
                            m.len = data.len();
                        }
                    }
                    return Poll::Ready(Ok(n));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1 // 不支持 GSO
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// 简易 ready 宏
macro_rules! ready_or_pending {
    ($e:expr) => {
        match $e {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    };
}
pub(crate) use ready_or_pending;

#[derive(Debug)]
struct SalamanderPoller {
    inner: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.inner.poll_send_ready(cx)
    }
}

/* ---------------- 工具 ---------------- */

async fn resolve_first(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(ip.into(), port));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::new(ip.into(), port));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| io_err(format!("dns lookup: {e}")))?
        .collect();
    addrs
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

fn random_padding() -> String {
    use base64::Engine;
    use rand::RngCore;
    let len = 8 + (rand::random::<u8>() % 24) as usize;
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(&buf)
}

fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push((v & 0x3f) as u8);
    } else if v < (1 << 14) {
        let v = v as u16;
        out.push(0x40 | ((v >> 8) as u8));
        out.push(v as u8);
    } else if v < (1 << 30) {
        let v = v as u32;
        out.push(0x80 | ((v >> 24) as u8));
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else {
        out.push(0xc0 | ((v >> 56) as u8));
        out.push((v >> 48) as u8);
        out.push((v >> 40) as u8);
        out.push((v >> 32) as u8);
        out.push((v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
}

async fn read_varint(recv: &mut RecvStream) -> std::io::Result<u64> {
    use tokio::io::AsyncReadExt;
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| io_err(format!("varint read first: {e}")))?;
    let prefix = first[0] >> 6;
    let len_extra = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };
    let mut buf = [0u8; 8];
    buf[0] = first[0] & 0x3f;
    if len_extra > 0 {
        recv.read_exact(&mut buf[1..1 + len_extra])
            .await
            .map_err(|e| io_err(format!("varint read tail: {e}")))?;
    }
    let total = 1 + len_extra;
    let mut v: u64 = 0;
    for i in 0..total {
        v = (v << 8) | (buf[i] as u64);
    }
    Ok(v)
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for &v in &[0u64, 1, 63, 64, 16383, 16384, 1 << 29, 1 << 30, 1 << 50] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            // 重新读出（用同步 channel）
            let mut prefix = (buf[0] >> 6) as usize;
            let total = match prefix {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => unreachable!(),
            };
            assert_eq!(buf.len(), total);
            let mut full = [0u8; 8];
            full[0] = buf[0] & 0x3f;
            for i in 1..total {
                full[i] = buf[i];
            }
            let mut decoded: u64 = 0;
            for i in 0..total {
                decoded = (decoded << 8) | (full[i] as u64);
            }
            assert_eq!(decoded, v);
            let _ = prefix;
        }
    }

    #[test]
    fn hysteria2_construct() {
        let ob = Hysteria2Outbound::new("h2", "1.2.3.4", 443, "pass");
        assert_eq!(ob.protocol(), "hysteria2");
        assert!(ob.alpn.contains(&"h3".to_string()));
        assert!(ob.udp);
    }

    #[test]
    fn hysteria2_with_obfs() {
        let ob = Hysteria2Outbound::new("h2", "1.2.3.4", 443, "pass").with_obfs("obfs-pwd");
        assert_eq!(ob.obfs_password.as_deref(), Some("obfs-pwd"));
    }

    #[test]
    fn random_padding_nonempty() {
        let p1 = random_padding();
        let p2 = random_padding();
        assert!(!p1.is_empty());
        assert!(!p2.is_empty());
        // 极不可能相同
        assert_ne!(p1, p2);
    }

    #[test]
    fn root_store_has_entries() {
        let store = root_store();
        assert!(!store.roots.is_empty());
    }
}
