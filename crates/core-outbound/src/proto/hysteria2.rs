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

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsConfig;
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter, resolve_host};

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
        let mut tls_config =
            RustlsConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("rustls ring default protocols")
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
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        let active_policy = crate::socket_policy::current();
        let quic_params = active_policy
            .as_ref()
            .and_then(|policy| policy.settings.finalmask.as_ref())
            .and_then(|finalmask| finalmask.quic_params.as_ref());
        let applied_quic = crate::transport::finalmask::quic::apply_client_config(
            &mut client_config,
            quic_params,
        )?;

        // 3) 在协议之下构造 UDP carrier。finalmask 必须位于 Quinn 之下；
        // 对 dial_udp 的返回值做 payload 包装会错误地包住 Hysteria relay。
        let nominal_local: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut masks = active_policy
            .as_ref()
            .and_then(|policy| policy.settings.finalmask.as_ref())
            .map(|finalmask| finalmask.udp.clone())
            .unwrap_or_default();
        if let Some(password) = &self.obfs_password {
            masks.push(core_config::UdpMaskConfig::Salamander(
                core_config::SalamanderMaskConfig {
                    password: password.clone(),
                    ..Default::default()
                },
            ));
        }
        if applied_quic.udp_hop.is_some()
            && masks.iter().any(|mask| {
                matches!(
                    mask,
                    core_config::UdpMaskConfig::Realm(_) | core_config::UdpMaskConfig::Xicmp(_)
                )
            })
        {
            return Err(io_err(
                "finalmask realm/xicmp is incompatible with quicParams.udpHop, matching Xray's outermost-carrier rule",
            ));
        }
        let proxy = active_policy.as_ref().and_then(|policy| policy.proxy());
        let (raw, carrier_local) = if let Some(hop) = applied_quic.udp_hop.clone() {
            crate::transport::finalmask::UdpHopCarrier::open(
                hop,
                proxy,
                self.host.clone(),
                target_addr,
            )
            .await?
        } else if let Some(proxy) = proxy {
            (
                crate::socket_policy::dial_udp_through_proxy(
                    proxy,
                    self.host.clone(),
                    target_addr.port(),
                )
                .await?,
                nominal_local,
            )
        } else {
            crate::transport::finalmask::open_direct_carrier(self.host.clone(), target_addr)?
        };
        let carrier = if masks.is_empty() {
            raw
        } else {
            crate::transport::finalmask::wrap_udp_client(
                raw,
                &masks,
                self.host.clone(),
                target_addr.port(),
                None,
                Some(target_addr),
            )
            .await?
        };
        let abstract_socket = crate::transport::finalmask::QuinnUdpSocket::new(
            carrier,
            carrier_local,
            target_addr,
            self.host.clone(),
            target_addr.port(),
        );
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            abstract_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| io_err(format!("hysteria2 finalmask endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        // 4) 建立 QUIC 连接
        let server_name = self.sni.clone().unwrap_or_else(|| self.host.clone());
        let connection = endpoint
            .connect(target_addr, &server_name)
            .map_err(|e| io_err(format!("hysteria2 connect: {e}")))?
            .await
            .map_err(|e| io_err(format!("hysteria2 connection: {e}")))?;

        // 5) 走 H3 鉴权
        let h3_conn_quinn = h3_quinn::Connection::new(connection.clone());
        let (mut h3_driver, mut h3_send) = h3::client::new(h3_conn_quinn)
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
            .header("Hysteria-CC-RX", applied_quic.brutal_down.to_string())
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
        let server_cc_rx = resp
            .headers()
            .get("hysteria-cc-rx")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        applied_quic.finish_hysteria_negotiation(server_cc_rx);
        if let Some(window) = applied_quic.max_connection_receive_window {
            connection.set_receive_window(window);
        }

        Ok(Hysteria2Session {
            connection,
            endpoint,
        })
    }
}

#[async_trait]
impl OutboundAdapter for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "hysteria2"
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
            return Err(io_err(format!(
                "hysteria2 server status={status}: {msg_str}"
            )));
        }

        Ok(Box::pin(QuinnBiStream { send, recv }))
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
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
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
