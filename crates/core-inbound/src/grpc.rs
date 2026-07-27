//! Xray gRPC (`gun`) inbound backed by the reusable VLESS server.
//!
//! This module owns listener/runtime composition. Wire framing remains in
//! `core-grpc`, so TLS, REALITY, finalmask and other authenticated carriers can
//! call the same `serve_connection` API without duplicating protobuf logic.

use std::{fmt, io, net::SocketAddr, sync::Arc};

use core_config::model::{GrpcListen as GrpcListenConfig, GrpcListenSecurity};
use core_grpc::{
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_QUEUE_CAPACITY,
    server::{GrpcServerConfig, TunnelHandler, serve_connection},
};
use core_runtime::Runtime;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    XrayServerTlsAcceptor,
    reality::RealityListener,
    vless::{VlessConnectionContext, VlessInboundConfig, serve_vless_stream},
};

#[derive(Clone)]
enum GrpcCarrierSecurity {
    Cleartext,
    Tls(Arc<XrayServerTlsAcceptor>),
    Reality(RealityListener),
}

impl fmt::Debug for GrpcCarrierSecurity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cleartext => "none",
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        })
    }
}

#[derive(Clone)]
pub struct GrpcListener {
    listen: SocketAddr,
    server: GrpcServerConfig,
    vless: Arc<VlessInboundConfig>,
    carrier: GrpcCarrierSecurity,
}

impl fmt::Debug for GrpcListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcListener")
            .field("listen", &self.listen)
            .field("server", &self.server)
            .field("vless", &self.vless)
            .field("carrier", &self.carrier)
            .finish()
    }
}

impl GrpcListener {
    pub fn from_config(config: &GrpcListenConfig) -> io::Result<Self> {
        if !config.protocol.eq_ignore_ascii_case("vless") {
            return Err(invalid_input(format!(
                "unsupported gRPC inner protocol `{}`",
                config.protocol
            )));
        }
        let host = config.host.trim().trim_matches(['[', ']']);
        let ip = host
            .parse()
            .map_err(|error| invalid_input(format!("invalid gRPC listen host: {error}")))?;
        let listen = SocketAddr::new(ip, config.port);
        if listen.port() == 0 {
            return Err(invalid_input("gRPC listen port must be non-zero"));
        }

        let settings = &config.grpc_settings;
        // Xray only consumes `permit_without_stream` in the gRPC dialer
        // (`dial.go`). Its server (`hub.go`) does not apply that client-side
        // keepalive permission, so retaining the parsed value without mapping
        // it into the inbound HTTP/2 builder is intentional compatibility.
        let server = GrpcServerConfig {
            service_name: settings.service_name.clone().unwrap_or_default(),
            idle_timeout: settings
                .idle_timeout
                .as_ref()
                .map(|value| value.duration())
                .unwrap_or_default(),
            health_check_timeout: settings
                .health_check_timeout
                .as_ref()
                .map(|value| value.duration())
                .unwrap_or_default(),
            initial_window_size: settings.initial_window_size,
            max_concurrent_streams: config.max_concurrent_streams,
            max_header_list_size: config.max_header_list_size,
            max_message_size: settings
                .max_message_size
                .unwrap_or(DEFAULT_MAX_MESSAGE_SIZE),
            queue_capacity: settings.queue_capacity.unwrap_or(DEFAULT_QUEUE_CAPACITY),
            max_connections: config.max_connections,
            trusted_x_forwarded_for: config.trusted_x_forwarded_for.clone(),
        };
        server.validate()?;
        let vless = Arc::new(VlessInboundConfig::from_uuid_strings(
            &config.users,
            config.handshake_timeout,
            config.max_mux_sessions,
        )?);
        let carrier = match config.security {
            GrpcListenSecurity::None => {
                if config.tls_settings.is_some()
                    || config.reality_settings.is_some()
                    || config.require_client_certificate
                {
                    return Err(invalid_input(
                        "gRPC security=none cannot include TLS, REALITY or client-certificate settings",
                    ));
                }
                GrpcCarrierSecurity::Cleartext
            }
            GrpcListenSecurity::Tls => {
                if config.reality_settings.is_some() {
                    return Err(invalid_input(
                        "gRPC security=tls cannot include realitySettings",
                    ));
                }
                let mut settings = config
                    .tls_settings
                    .clone()
                    .ok_or_else(|| invalid_input("gRPC security=tls requires tlsSettings"))?;
                require_h2_alpn(&mut settings)?;
                let acceptor = XrayServerTlsAcceptor::from_xray_settings(
                    settings,
                    config.require_client_certificate,
                )?;
                GrpcCarrierSecurity::Tls(Arc::new(acceptor))
            }
            GrpcListenSecurity::Reality => {
                if config.tls_settings.is_some() || config.require_client_certificate {
                    return Err(invalid_input(
                        "gRPC security=reality cannot include TLS or client-certificate settings",
                    ));
                }
                let mut settings =
                    config.reality_settings.as_deref().cloned().ok_or_else(|| {
                        invalid_input("gRPC security=reality requires realitySettings")
                    })?;
                settings.host = config.host.clone();
                settings.port = config.port;
                settings.protocol = "vless".into();
                settings.users = config.users.clone();
                GrpcCarrierSecurity::Reality(RealityListener::from_config(&settings)?)
            }
        };
        Ok(Self {
            listen,
            server,
            vless,
            carrier,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    pub fn server_config(&self) -> &GrpcServerConfig {
        &self.server
    }
}

/// Run an h2c, TLS/ECH or REALITY gRPC listener until its task is cancelled.
pub async fn run_grpc(listener: GrpcListener, runtime: Arc<Runtime>) -> io::Result<()> {
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    run_grpc_with_cancellation(listener, runtime, cancellation).await
}

/// Run a gRPC listener with explicit cancellation, used by the application and
/// deterministic end-to-end tests.
pub async fn run_grpc_with_cancellation(
    listener: GrpcListener,
    runtime: Arc<Runtime>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let socket = TcpListener::bind(listener.listen).await?;
    let local = socket.local_addr()?;
    info!(
        addr = %local,
        service = %listener.server.service_name,
        security = ?listener.carrier,
        "gRPC inbound listening"
    );

    let runtime_for_handler = runtime.clone();
    let vless = listener.vless.clone();
    let handler_cancellation = cancellation.clone();
    let handler: TunnelHandler = Arc::new(move |stream, context| {
        let runtime = runtime_for_handler.clone();
        let vless = vless.clone();
        let cancellation = handler_cancellation.clone();
        Box::pin(async move {
            serve_vless_stream(
                stream,
                VlessConnectionContext {
                    source: context.remote_addr,
                    local,
                },
                vless,
                runtime,
                cancellation,
            )
            .await
        })
    });

    let permits = Arc::new(Semaphore::new(listener.server.max_connections));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Err(error))) => {
                        debug!(%error, "gRPC connection ended with an error");
                    }
                    Some(Err(error)) => {
                        debug!(%error, "gRPC connection task failed");
                    }
                    _ => {}
                }
            }
            accepted = socket.accept() => {
                let (stream, peer_addr) = accepted?;
                if let Err(error) = stream.set_nodelay(true) {
                    debug!(%peer_addr, %error, "cannot configure accepted gRPC socket");
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(
                        %peer_addr,
                        limit = listener.server.max_connections,
                        "gRPC connection limit reached"
                    );
                    drop(stream);
                    continue;
                };
                let connection_config = listener.server.clone();
                let connection_handler = handler.clone();
                let carrier = listener.carrier.clone();
                let cancellation = cancellation.clone();
                let handshake_timeout = listener.vless.handshake_timeout();
                let connection_local = stream.local_addr().unwrap_or(local);
                connections.spawn(async move {
                    let _permit = permit;
                    serve_accepted_carrier(
                        carrier,
                        stream,
                        peer_addr,
                        connection_local,
                        connection_config,
                        connection_handler,
                        handshake_timeout,
                        cancellation,
                    )
                    .await
                });
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_accepted_carrier(
    carrier: GrpcCarrierSecurity,
    stream: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    config: GrpcServerConfig,
    handler: TunnelHandler,
    handshake_timeout: std::time::Duration,
    cancellation: CancellationToken,
) -> io::Result<()> {
    match carrier {
        GrpcCarrierSecurity::Cleartext => {
            serve_connection(stream, peer_addr, config, handler).await
        }
        GrpcCarrierSecurity::Tls(acceptor) => {
            let stream = tokio::time::timeout(handshake_timeout, acceptor.accept(stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "gRPC TLS handshake timeout")
                })??;
            serve_connection(stream, peer_addr, config, handler).await
        }
        GrpcCarrierSecurity::Reality(listener) => {
            let stream = tokio::time::timeout(
                handshake_timeout,
                listener.accept_carrier(stream, peer_addr, local_addr, cancellation),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC REALITY handshake timeout"))?
            .map_err(|error| io::Error::other(format!("gRPC REALITY carrier: {error:#}")))?;
            serve_connection(stream, peer_addr, config, handler).await
        }
    }
}

fn require_h2_alpn(settings: &mut core_config::model::XhttpDownloadTlsSettings) -> io::Result<()> {
    if settings.alpn.is_none() {
        settings.alpn = Some(vec!["h2".into()]);
    } else if !settings
        .alpn
        .as_ref()
        .is_some_and(|alpn| alpn.iter().any(|value| value == "h2"))
    {
        return Err(invalid_input(
            "gRPC TLS alpn must contain h2; HTTP/1.1 fallback is not permitted",
        ));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::{
        CompatDuration, GrpcListenSecurity, GrpcTransportSettings, XhttpDownloadTlsCertificate,
        XhttpDownloadTlsSettings, XhttpTlsCertificateUsage,
    };
    use std::time::Duration;

    fn valid_config() -> GrpcListenConfig {
        GrpcListenConfig {
            host: "127.0.0.1".into(),
            port: 443,
            protocol: "vless".into(),
            users: vec!["4f164e20-31aa-4e72-a9b1-a3c0871d2e8d".into()],
            grpc_settings: GrpcTransportSettings {
                service_name: Some("escaped/服务".into()),
                idle_timeout: Some(CompatDuration::Seconds(30)),
                health_check_timeout: Some(CompatDuration::Human(Duration::from_secs(5))),
                permit_without_stream: Some(true),
                initial_window_size: Some(65_535),
                max_message_size: Some(32 * 1024),
                queue_capacity: Some(4),
                ..GrpcTransportSettings::default()
            },
            security: GrpcListenSecurity::None,
            tls_settings: None,
            require_client_certificate: false,
            reality_settings: None,
            handshake_timeout: Duration::from_secs(10),
            max_mux_sessions: 64,
            max_connections: 128,
            max_concurrent_streams: 32,
            max_header_list_size: 16 * 1024,
            trusted_x_forwarded_for: vec!["x-wuther-trusted".into()],
        }
    }

    #[test]
    fn maps_every_server_setting() {
        let listener = GrpcListener::from_config(&valid_config()).unwrap();
        let server = listener.server_config();
        assert_eq!(server.service_name, "escaped/服务");
        assert_eq!(server.idle_timeout, Duration::from_secs(30));
        assert_eq!(server.health_check_timeout, Duration::from_secs(5));
        assert_eq!(server.initial_window_size, Some(65_535));
        assert_eq!(server.max_message_size, 32 * 1024);
        assert_eq!(server.queue_capacity, 4);
        assert_eq!(server.max_connections, 128);
        assert_eq!(server.max_concurrent_streams, 32);
        assert_eq!(server.max_header_list_size, 16 * 1024);
        assert_eq!(
            server.trusted_x_forwarded_for,
            ["x-wuther-trusted".to_string()]
        );
    }

    #[test]
    fn rejects_unknown_inner_protocol_and_bad_uuid() {
        let mut config = valid_config();
        config.protocol = "trojan".into();
        assert!(GrpcListener::from_config(&config).is_err());
        config.protocol = "vless".into();
        config.users = vec!["not-a-uuid".into()];
        assert!(GrpcListener::from_config(&config).is_err());
    }

    #[test]
    fn tls_uses_the_shared_acceptor_and_requires_h2() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["grpc.example".into()]).unwrap();
        let certificate = XhttpDownloadTlsCertificate {
            certificate: Some(cert.pem().lines().map(str::to_owned).collect()),
            key: Some(
                key_pair
                    .serialize_pem()
                    .lines()
                    .map(str::to_owned)
                    .collect(),
            ),
            usage: Some(XhttpTlsCertificateUsage::Encipherment),
            ..XhttpDownloadTlsCertificate::default()
        };

        let mut config = valid_config();
        config.security = GrpcListenSecurity::Tls;
        config.tls_settings = Some(XhttpDownloadTlsSettings {
            certificates: vec![certificate.clone()],
            ..XhttpDownloadTlsSettings::default()
        });
        assert!(GrpcListener::from_config(&config).is_ok());

        config.tls_settings = Some(XhttpDownloadTlsSettings {
            certificates: vec![certificate],
            alpn: Some(vec!["http/1.1".into()]),
            ..XhttpDownloadTlsSettings::default()
        });
        assert!(GrpcListener::from_config(&config).is_err());
    }

    #[test]
    fn security_settings_never_silently_downgrade() {
        let mut config = valid_config();
        config.tls_settings = Some(XhttpDownloadTlsSettings::default());
        assert!(GrpcListener::from_config(&config).is_err());

        config.security = GrpcListenSecurity::Tls;
        config.tls_settings = None;
        assert!(GrpcListener::from_config(&config).is_err());

        config.security = GrpcListenSecurity::Reality;
        assert!(GrpcListener::from_config(&config).is_err());
    }
}
