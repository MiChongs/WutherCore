//! Shadowsocks SIP003/SIP004/SIP022 outbound backed by shadowsocks-rust.
//!
//! The upstream implementation is deliberately used as the single crypto and
//! framing implementation so every cipher enabled by the workspace feature set
//! has identical TCP/UDP behaviour to shadowsocks-rust.

use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use shadowsocks::{
    config::{ServerAddr, ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    net::UdpSocket as ShadowUdpSocket,
    plugin::{Plugin, PluginConfig, PluginMode},
    relay::{
        socks5::Address,
        tcprelay::proxy_stream::client::ProxyClientStream,
        udprelay::proxy_socket::{ProxySocket, UdpSocketType},
    },
};

use crate::{
    adapter::{
        BoxedStream, BoxedUdp, Capabilities, DialContext, OutboundAdapter, UdpSocketLike,
        resolve_host,
    },
    transport::{Transport, tcp::TcpTransport},
};

#[derive(Debug, Clone)]
pub struct ShadowsocksOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub method: CipherKind,
    pub password: String,
    pub udp: bool,
    pub plugin: Option<PluginConfig>,
    plugin_process: Arc<tokio::sync::Mutex<Option<Plugin>>>,
}

impl ShadowsocksOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        method: CipherKind,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let outbound = Self {
            name: name.into(),
            host: host.into(),
            port,
            method,
            password: password.into(),
            udp: true,
            plugin: None,
            plugin_process: Arc::new(tokio::sync::Mutex::new(None)),
        };
        // Validate password/key material immediately, especially the exact
        // base64 key length and EIH chain required by AEAD-2022.
        outbound.server_config()?;
        Ok(outbound)
    }

    pub fn parse_method(method: &str) -> io::Result<CipherKind> {
        method.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks cipher `{method}`"),
            )
        })
    }

    fn server_config(&self) -> io::Result<ServerConfig> {
        ServerConfig::new(
            ServerAddr::DomainName(self.host.clone(), self.port),
            self.password.clone(),
            self.method,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    pub fn set_plugin(&mut self, plugin: Option<PluginConfig>) {
        self.plugin = plugin;
    }

    async fn transport_endpoint(&self, udp: bool) -> io::Result<SocketAddr> {
        let Some(plugin_config) = &self.plugin else {
            return resolve_host(&self.host, self.port)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no server address resolved")
                });
        };
        if udp && !plugin_config.plugin_mode.enable_udp() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "SIP003 plugin `{}` is not configured for UDP",
                    plugin_config.plugin
                ),
            ));
        }
        if !udp && !plugin_config.plugin_mode.enable_tcp() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "SIP003 plugin `{}` is not configured for TCP",
                    plugin_config.plugin
                ),
            ));
        }
        let mut process = self.plugin_process.lock().await;
        if process.is_none() {
            let remote = ServerAddr::DomainName(self.host.clone(), self.port);
            let started = Plugin::start(plugin_config, &remote, PluginMode::Client)?;
            if !started
                .wait_started(std::time::Duration::from_secs(10))
                .await
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("SIP003 plugin `{}` startup timed out", plugin_config.plugin),
                ));
            }
            *process = Some(started);
        }
        Ok(process
            .as_ref()
            .expect("plugin was initialized")
            .local_addr())
    }
}

#[async_trait]
impl OutboundAdapter for ShadowsocksOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        if self.method.is_aead_2022() {
            "ss2022"
        } else {
            "shadowsocks"
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: self.udp,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> io::Result<BoxedStream> {
        let endpoint = self.transport_endpoint(false).await?;
        let stream = TcpTransport::default()
            .connect(&endpoint.ip().to_string(), endpoint.port())
            .await?;
        let server = self.server_config()?;
        let target = Address::from((ctx.host.clone(), ctx.port));
        let stream = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            stream,
            &server,
            target,
        );
        tracing::info!(
            target: "dial::shadowsocks",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %format!("{}:{}", self.host, self.port),
            target = %format!("{}:{}", ctx.host, ctx.port),
            method = %self.method,
            "Shadowsocks TCP stream established",
        );
        Ok(Box::pin(stream))
    }

    async fn dial_udp(&self, ctx: DialContext) -> io::Result<BoxedUdp> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "outbound `{}`/shadowsocks udp disabled by config",
                    self.name
                ),
            ));
        }
        let server_addr = self.transport_endpoint(true).await?;
        let (reservation, loopback_guard) = crate::create_outbound_udp_socket(server_addr)?;
        // Preserve the exact socket prepared by the runtime. Recreating it in
        // shadowsocks-rust would lose Android VPN protection, interface/mark
        // binding and the loopback guard's observed local endpoint.
        let socket = ShadowUdpSocket::from(tokio::net::UdpSocket::from_std(reservation)?);
        let server = self.server_config()?;
        let socket = ProxySocket::from_socket(
            UdpSocketType::Client,
            Context::new_shared(ServerType::Local),
            &server,
            socket,
        );
        tracing::info!(
            target: "dial::shadowsocks",
            id = ctx.dial_id,
            proxy = %self.name,
            server = %server_addr,
            method = %self.method,
            "Shadowsocks UDP association established",
        );
        Ok(Box::new(ShadowsocksUdp {
            socket,
            recv_buf: tokio::sync::Mutex::new(vec![0u8; 65_536]),
            loopback_guard,
        }))
    }
}

struct ShadowsocksUdp {
    socket: ProxySocket<ShadowUdpSocket>,
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    loopback_guard: crate::loopback::LoopbackUdpGuard,
}

#[async_trait]
impl UdpSocketLike for ShadowsocksUdp {
    async fn send_to(&self, buf: &[u8], target: &str, port: u16) -> io::Result<usize> {
        self.socket
            .send(&Address::from((target.to_owned(), port)), buf)
            .await
            .map_err(io::Error::other)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_from_endpoint(buf).await.map(|(length, _)| length)
    }

    async fn recv_from_endpoint(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        // The encrypted datagram is larger than the caller's plaintext
        // buffer. Always receive into a full UDP packet buffer first, then
        // apply ordinary datagram truncation semantics to the destination.
        let mut packet = self.recv_buf.lock().await;
        let (payload_len, source, _) = self
            .socket
            .recv(&mut packet)
            .await
            .map_err(io::Error::other)?;
        let copied = payload_len.min(buf.len());
        buf[..copied].copy_from_slice(&packet[..copied]);
        let endpoint = match source {
            Address::SocketAddress(address) => Some(address),
            Address::DomainNameAddress(_, _) => None,
        };
        Ok((copied, endpoint))
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }

    async fn close(&self) -> io::Result<()> {
        let _ = &self.loopback_guard;
        Ok(())
    }

    fn supports_multi_target(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::relay::{
        tcprelay::proxy_stream::server::ProxyServerStream, udprelay::options::UdpSocketControlData,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    fn context(host: &str, port: u16, network: &'static str) -> DialContext {
        DialContext {
            host: host.into(),
            port,
            network,
            dial_id: 1,
        }
    }

    #[test]
    fn accepts_every_enabled_cipher_family() {
        for method in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "aes-128-ccm",
            "aes-256-ccm",
            "aes-128-gcm-siv",
            "aes-256-gcm-siv",
            "xchacha20-ietf-poly1305",
            "sm4-gcm",
            "sm4-ccm",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "camellia-128-cfb",
            "camellia-192-cfb",
            "camellia-256-cfb",
            "rc4-md5",
            "chacha20-ietf",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
            "2022-blake3-chacha8-poly1305",
        ] {
            assert!(
                ShadowsocksOutbound::parse_method(method).is_ok(),
                "method {method} must be registered"
            );
        }
    }

    #[test]
    fn rejects_bad_2022_key_at_construction() {
        let method = ShadowsocksOutbound::parse_method("2022-blake3-aes-128-gcm").unwrap();
        let error =
            ShadowsocksOutbound::new("ss", "127.0.0.1", 8388, method, "not-base64").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn official_server_interoperates_with_outbound_tcp() {
        let method = ShadowsocksOutbound::parse_method("aes-256-gcm").unwrap();
        let server_config = ServerConfig::new(
            ServerAddr::DomainName("127.0.0.1".into(), 0),
            "tcp-password",
            method,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let key = server_config.key().to_vec();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                stream,
                method,
                &key,
            );
            let target = stream.handshake().await.unwrap();
            assert_eq!(target, Address::from(("echo.example".to_owned(), 443)));
            let mut request = [0u8; 12];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"outbound-tcp");
            stream.write_all(&request).await.unwrap();
        });
        let outbound = ShadowsocksOutbound::new(
            "ss",
            server_addr.ip().to_string(),
            server_addr.port(),
            method,
            "tcp-password",
        )
        .unwrap();
        let mut stream = outbound
            .dial_tcp(context("echo.example", 443, "tcp"))
            .await
            .unwrap();
        stream.write_all(b"outbound-tcp").await.unwrap();
        let mut response = [0u8; 12];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"outbound-tcp");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn official_server_interoperates_with_prepared_outbound_udp_socket() {
        let method = ShadowsocksOutbound::parse_method("2022-blake3-aes-128-gcm").unwrap();
        let password = "MDEyMzQ1Njc4OWFiY2RlZg==";
        let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = raw.local_addr().unwrap();
        let server_config =
            ServerConfig::new(ServerAddr::SocketAddr(server_addr), password, method).unwrap();
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &server_config,
            ShadowUdpSocket::from(raw),
        );
        let server = tokio::spawn(async move {
            let mut packet = [0u8; 256];
            let (length, client, target, _, control) =
                proxy.recv_from_with_ctrl(&mut packet).await.unwrap();
            assert_eq!(target, Address::from(("dns.example".to_owned(), 53)));
            assert_eq!(&packet[..length], b"outbound-udp");
            let request_control = control.unwrap_or_default();
            let mut response_control = UdpSocketControlData::default();
            response_control.client_session_id = request_control.client_session_id;
            response_control.server_session_id = 7;
            response_control.packet_id = 0;
            response_control.user = request_control.user;
            proxy
                .send_to_with_ctrl(client, &target, &response_control, &packet[..length])
                .await
                .unwrap();
        });
        let outbound = ShadowsocksOutbound::new(
            "ss2022",
            server_addr.ip().to_string(),
            server_addr.port(),
            method,
            password,
        )
        .unwrap();
        let socket = outbound
            .dial_udp(context("dns.example", 53, "udp"))
            .await
            .unwrap();
        socket
            .send_to(b"outbound-udp", "dns.example", 53)
            .await
            .unwrap();
        let mut response = [0u8; 64];
        let length = socket.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"outbound-udp");
        assert!(socket.local_addr().unwrap().is_some());
        server.await.unwrap();
    }
}
