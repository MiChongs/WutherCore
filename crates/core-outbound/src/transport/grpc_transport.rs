//! Xray gRPC (`gun`) outbound transport.
//!
//! Protobuf and gRPC semantics are delegated to `core-grpc` (tonic/prost);
//! this module only supplies WutherCore's TCP/TLS carrier and connection pool.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use core_grpc::client::{GrpcClientConfig, GrpcClientConnection};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::{
    adapter::BoxedStream,
    transport::{TlsOptions, Transport, tcp::TcpTransport, tls::TlsTransport},
};

use super::browser_identity::browser_identity;

#[derive(Debug, Clone)]
pub struct GrpcOptions {
    pub enabled: bool,
    /// Xray `authority`. Takes precedence over the compatibility `host`.
    pub authority: String,
    /// Legacy WutherCore spelling retained for existing profiles.
    pub host: String,
    pub service_name: String,
    pub multi_mode: bool,
    pub idle_timeout: Duration,
    pub health_check_timeout: Duration,
    pub permit_without_stream: bool,
    pub initial_window_size: Option<u32>,
    pub user_agent: String,
    pub max_message_size: usize,
    pub queue_capacity: usize,
}

impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            authority: String::new(),
            host: String::new(),
            service_name: String::new(),
            multi_mode: false,
            idle_timeout: Duration::ZERO,
            health_check_timeout: Duration::ZERO,
            permit_without_stream: false,
            initial_window_size: None,
            user_agent: String::new(),
            max_message_size: core_grpc::DEFAULT_MAX_MESSAGE_SIZE,
            queue_capacity: core_grpc::DEFAULT_QUEUE_CAPACITY,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedConnection {
    host: String,
    port: u16,
    client: GrpcClientConnection,
}

pub struct GrpcTransport {
    opts: GrpcOptions,
    tls: TlsOptions,
    connection: Arc<Mutex<Option<CachedConnection>>>,
}

impl std::fmt::Debug for GrpcTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcTransport")
            .field("opts", &self.opts)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl GrpcTransport {
    pub fn new(opts: GrpcOptions, tls: TlsOptions) -> Self {
        Self {
            opts,
            tls,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    /// Open one gRPC tunnel over an already authenticated carrier.
    ///
    /// REALITY, finalmask and other outer transports use this entry point so
    /// the gRPC protobuf/HTTP2 stack is shared instead of reimplemented.
    pub async fn connect_over<S>(
        &self,
        carrier: S,
        host: &str,
        port: u16,
    ) -> std::io::Result<BoxedStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = self.client_config(host, port);
        config.validate()?;
        let connection = GrpcClientConnection::handshake(carrier, config).await?;
        Ok(Box::pin(connection.open_tunnel().await?))
    }

    async fn get_or_connect(&self, host: &str, port: u16) -> std::io::Result<GrpcClientConnection> {
        let client_config = self.client_config(host, port);
        client_config.validate()?;
        let mut cached = self.connection.lock().await;
        if let Some(connection) = cached.as_ref()
            && connection.host == host
            && connection.port == port
            && !connection.client.is_closed()
        {
            return Ok(connection.client.clone());
        }

        let carrier = if self.tls.enabled {
            let mut tls = self.tls.clone();
            tls.enabled = true;
            if tls.alpn.is_empty() {
                tls.alpn.push("h2".into());
            } else if !tls.alpn.iter().any(|protocol| protocol == "h2") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "gRPC over TLS requires `h2` in ALPN",
                ));
            }
            TlsTransport::new(tls).connect(host, port).await?
        } else {
            TcpTransport::default().connect(host, port).await?
        };
        let client = GrpcClientConnection::handshake(carrier, client_config).await?;
        *cached = Some(CachedConnection {
            host: host.to_owned(),
            port,
            client: client.clone(),
        });
        Ok(client)
    }

    fn authority(&self, host: &str, port: u16) -> String {
        if !self.opts.authority.is_empty() {
            return self.opts.authority.clone();
        }
        if !self.opts.host.is_empty() {
            return self.opts.host.clone();
        }
        if let Some(server_name) = self.tls.sni.as_ref().filter(|value| !value.is_empty()) {
            return server_name.clone();
        }
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            host.to_owned()
        }
    }

    fn client_config(&self, host: &str, port: u16) -> GrpcClientConfig {
        GrpcClientConfig {
            authority: self.authority(host, port),
            service_name: self.opts.service_name.clone(),
            multi_mode: self.opts.multi_mode,
            user_agent: resolved_user_agent(&self.opts.user_agent),
            idle_timeout: self.opts.idle_timeout,
            health_check_timeout: self.opts.health_check_timeout,
            permit_without_stream: self.opts.permit_without_stream,
            initial_window_size: self.opts.initial_window_size,
            max_message_size: self.opts.max_message_size,
            queue_capacity: self.opts.queue_capacity,
        }
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let mut reconnect = false;
        loop {
            let client = self.get_or_connect(host, port).await?;
            match client.open_tunnel().await {
                Ok(stream) => return Ok(Box::pin(stream)),
                Err(error) if !reconnect && client.is_closed() => {
                    reconnect = true;
                    *self.connection.lock().await = None;
                    tracing::debug!(%error, "retrying gRPC tunnel on a fresh HTTP/2 connection");
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn resolved_user_agent(configured: &str) -> Option<String> {
    let identity = browser_identity();
    match configured {
        "" | "chrome" => Some(identity.chrome_ua.clone()),
        "firefox" => Some(identity.firefox_ua.clone()),
        "edge" => Some(identity.edge_ua.clone()),
        "golang" => None,
        _ => Some(configured.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grpc::server::{GrpcServerConfig, TunnelHandler, serve_connection};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn options_default_is_bounded_and_xray_compatible() {
        let options = GrpcOptions::default();
        assert!(!options.enabled);
        assert!(!options.multi_mode);
        assert_eq!(options.max_message_size, 4 * 1024 * 1024);
        assert_eq!(options.queue_capacity, 8);
    }

    #[test]
    fn authority_precedence_matches_xray() {
        let mut options = GrpcOptions {
            authority: "explicit.example".into(),
            host: "legacy.example".into(),
            ..Default::default()
        };
        let mut tls = TlsOptions {
            sni: Some("sni.example".into()),
            ..Default::default()
        };
        let transport = GrpcTransport::new(options.clone(), tls.clone());
        assert_eq!(
            transport.authority("origin.example", 443),
            "explicit.example"
        );

        options.authority.clear();
        let transport = GrpcTransport::new(options.clone(), tls.clone());
        assert_eq!(transport.authority("origin.example", 443), "legacy.example");

        options.host.clear();
        let transport = GrpcTransport::new(options, tls.clone());
        assert_eq!(transport.authority("origin.example", 443), "sni.example");

        tls.sni = None;
        let transport = GrpcTransport::new(GrpcOptions::default(), tls);
        assert_eq!(transport.authority("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn user_agent_aliases_do_not_append_library_suffixes() {
        assert!(resolved_user_agent("chrome").unwrap().contains("Chrome/"));
        assert!(resolved_user_agent("firefox").unwrap().contains("Firefox/"));
        assert!(resolved_user_agent("edge").unwrap().contains("Edg/"));
        assert_eq!(resolved_user_agent("golang"), None);
        assert_eq!(resolved_user_agent("custom/1").as_deref(), Some("custom/1"));
        assert_eq!(
            resolved_user_agent("Chrome").as_deref(),
            Some("Chrome"),
            "Xray special user-agent aliases are case-sensitive"
        );
    }

    #[tokio::test]
    async fn tls_requires_h2_alpn_before_opening_a_socket() {
        let transport = GrpcTransport::new(
            GrpcOptions::default(),
            TlsOptions {
                enabled: true,
                alpn: vec!["http/1.1".into()],
                ..Default::default()
            },
        );
        let error = match transport.connect("127.0.0.1", 9).await {
            Ok(_) => panic!("non-h2 ALPN must fail before dialing"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("requires `h2`"));
    }

    #[tokio::test]
    async fn caller_supplied_carrier_uses_the_real_grpc_stack() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let handler: TunnelHandler = Arc::new(|mut stream, _context| {
            Box::pin(async move {
                let (mut read, mut write) = tokio::io::split(&mut stream);
                tokio::io::copy(&mut read, &mut write).await?;
                Ok(())
            })
        });
        let server_task = tokio::spawn(serve_connection(
            server,
            "127.0.0.1:12345".parse().unwrap(),
            GrpcServerConfig::default(),
            handler,
        ));
        let transport = GrpcTransport::new(GrpcOptions::default(), TlsOptions::default());
        let mut stream = transport
            .connect_over(client, "carrier.example", 443)
            .await
            .unwrap();
        stream.write_all(b"carrier-round-trip").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0_u8; 18];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"carrier-round-trip");
        stream.shutdown().await.unwrap();
        server_task.abort();
    }
}
