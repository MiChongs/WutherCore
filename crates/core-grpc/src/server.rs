use std::{
    convert::Infallible,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use futures::{Stream, StreamExt, future::BoxFuture};
use http::{
    HeaderMap, Request, Response, StatusCode,
    header::{CONTENT_TYPE, HOST, HeaderName, HeaderValue, USER_AGENT},
};
use hyper::{body::Incoming, server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tonic::{
    Request as GrpcRequest, Response as GrpcResponse, Status, Streaming,
    body::Body,
    codec::ProstCodec,
    server::{Grpc, StreamingService},
};

use crate::{
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_QUEUE_CAPACITY, MAX_MESSAGE_SIZE_LIMIT, MAX_QUEUE_CAPACITY,
    MIN_MESSAGE_SIZE,
    path::grpc_method_paths,
    proto::{Hunk, MultiHunk},
    stream::{GrpcTunnelStream, InboundMessages, hunk_outbound, multi_hunk_outbound},
};

// grpc-go substitutes this value when KeepaliveParams is enabled with Time=0.
// Xray enables KeepaliveParams when either timeout field is non-zero, so a
// health-check-only configuration must still emit a ping every two hours.
const GRPC_GO_DEFAULT_SERVER_KEEPALIVE_TIME: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Debug, Clone)]
pub struct GrpcServerConfig {
    pub service_name: String,
    pub idle_timeout: Duration,
    pub health_check_timeout: Duration,
    pub initial_window_size: Option<u32>,
    pub max_concurrent_streams: u32,
    pub max_header_list_size: u32,
    pub max_message_size: usize,
    pub queue_capacity: usize,
    /// Local defensive bound for [`serve_tcp_listener`].
    pub max_connections: usize,
    /// Xray semantics: each entry is a trusted marker header name.  The
    /// presence of any marker permits the first X-Forwarded-For address.
    pub trusted_x_forwarded_for: Vec<String>,
}

impl Default for GrpcServerConfig {
    fn default() -> Self {
        Self {
            service_name: String::new(),
            idle_timeout: Duration::ZERO,
            health_check_timeout: Duration::ZERO,
            initial_window_size: None,
            max_concurrent_streams: 1024,
            max_header_list_size: 64 * 1024,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            max_connections: 4096,
            trusted_x_forwarded_for: Vec::new(),
        }
    }
}

impl GrpcServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        let paths = grpc_method_paths(&self.service_name);
        for path in [paths.tun_path(), paths.tun_multi_path()] {
            path.parse::<http::uri::PathAndQuery>().map_err(|error| {
                invalid_input(format!("invalid gRPC method path `{path}`: {error}"))
            })?;
        }
        for (name, value) in [
            ("idle_timeout", self.idle_timeout),
            ("health_check_timeout", self.health_check_timeout),
        ] {
            if value.subsec_nanos() != 0 {
                return Err(invalid_input(format!(
                    "gRPC {name} must be an integral number of seconds"
                )));
            }
            if value.as_secs() > i32::MAX as u64 {
                return Err(invalid_input(format!(
                    "gRPC {name} exceeds Xray's int32 seconds range"
                )));
            }
        }
        if self
            .initial_window_size
            .is_some_and(|value| value > i32::MAX as u32)
        {
            return Err(invalid_input(
                "gRPC initial_window_size exceeds HTTP/2/Xray's int32 range",
            ));
        }
        if self.max_concurrent_streams == 0 {
            return Err(invalid_input(
                "gRPC max_concurrent_streams must be non-zero",
            ));
        }
        if self.max_header_list_size == 0 {
            return Err(invalid_input("gRPC max_header_list_size must be non-zero"));
        }
        if !(MIN_MESSAGE_SIZE..=MAX_MESSAGE_SIZE_LIMIT).contains(&self.max_message_size) {
            return Err(invalid_input(format!(
                "gRPC max_message_size must be in {MIN_MESSAGE_SIZE}..={MAX_MESSAGE_SIZE_LIMIT}"
            )));
        }
        if self.queue_capacity == 0 || self.queue_capacity > MAX_QUEUE_CAPACITY {
            return Err(invalid_input(format!(
                "gRPC queue_capacity must be in 1..={MAX_QUEUE_CAPACITY}"
            )));
        }
        if self.max_connections == 0 || self.max_connections > 65_535 {
            return Err(invalid_input("gRPC max_connections must be in 1..=65535"));
        }
        for marker in &self.trusted_x_forwarded_for {
            HeaderName::from_bytes(marker.as_bytes()).map_err(|error| {
                invalid_input(format!(
                    "invalid trustedXForwardedFor marker `{marker}`: {error}"
                ))
            })?;
        }
        Ok(())
    }
}

/// Serve a cleartext HTTP/2 gRPC listener with bounded connection tasks.
///
/// TLS, REALITY, finalmask and PROXY protocol callers should accept and wrap
/// their carrier themselves, then call [`serve_connection`].
pub async fn serve_tcp_listener(
    listener: TcpListener,
    config: GrpcServerConfig,
    handler: TunnelHandler,
    cancellation: CancellationToken,
) -> io::Result<()> {
    config.validate()?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Err(error))) => {
                        tracing::debug!(%error, "gRPC connection ended with an error");
                    }
                    Some(Err(error)) => {
                        tracing::debug!(%error, "gRPC connection task failed");
                    }
                    _ => {}
                }
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted?;
                stream.set_nodelay(true)?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(
                        %peer_addr,
                        limit = config.max_connections,
                        "gRPC connection limit reached"
                    );
                    drop(stream);
                    continue;
                };
                let connection_config = config.clone();
                let connection_handler = handler.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(
                        stream,
                        peer_addr,
                        connection_config,
                        connection_handler,
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

#[derive(Debug, Clone)]
pub struct GrpcRequestContext {
    pub peer_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub method_path: String,
    pub authority: Option<String>,
    pub user_agent: Option<String>,
}

pub type TunnelHandler = Arc<
    dyn Fn(GrpcTunnelStream, GrpcRequestContext) -> BoxFuture<'static, io::Result<()>>
        + Send
        + Sync,
>;

/// Serve one already-accepted carrier as an HTTP/2 gRPC connection.
pub async fn serve_connection<S>(
    io: S,
    peer_addr: SocketAddr,
    config: GrpcServerConfig,
    handler: TunnelHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.validate()?;
    let paths = grpc_method_paths(&config.service_name);
    let tun_path = paths.tun_path();
    let tun_multi_path = paths.tun_multi_path();
    let config = Arc::new(config);
    let service_config = config.clone();

    let service = service_fn(move |request: Request<Incoming>| {
        let handler = handler.clone();
        let config = service_config.clone();
        let tun_path = tun_path.clone();
        let tun_multi_path = tun_multi_path.clone();
        async move {
            let path = request.uri().path().to_string();
            let response = if path == tun_path {
                let context = request_context(&request, peer_addr, &config.trusted_x_forwarded_for);
                let service = HunkRpc {
                    handler,
                    context,
                    max_message_size: config.max_message_size,
                    queue_capacity: config.queue_capacity,
                };
                Grpc::new(ProstCodec::<Hunk, Hunk>::default())
                    .max_decoding_message_size(config.max_message_size)
                    .max_encoding_message_size(config.max_message_size)
                    .streaming(service, request)
                    .await
            } else if path == tun_multi_path {
                let context = request_context(&request, peer_addr, &config.trusted_x_forwarded_for);
                let service = MultiHunkRpc {
                    handler,
                    context,
                    max_message_size: config.max_message_size,
                    queue_capacity: config.queue_capacity,
                };
                Grpc::new(ProstCodec::<MultiHunk, MultiHunk>::default())
                    .max_decoding_message_size(config.max_message_size)
                    .max_encoding_message_size(config.max_message_size)
                    .streaming(service, request)
                    .await
            } else {
                unimplemented_response()
            };
            Ok::<_, Infallible>(response)
        }
    });

    let mut server = http2::Builder::new(TokioExecutor::new());
    server.timer(TokioTimer::new());
    if let Some(window) = config.initial_window_size {
        server.initial_stream_window_size(window);
    }
    if !config.idle_timeout.is_zero() || !config.health_check_timeout.is_zero() {
        server.keep_alive_interval(if config.idle_timeout.is_zero() {
            GRPC_GO_DEFAULT_SERVER_KEEPALIVE_TIME
        } else {
            config.idle_timeout
        });
    }
    if !config.health_check_timeout.is_zero() {
        server.keep_alive_timeout(config.health_check_timeout);
    }
    server.max_concurrent_streams(config.max_concurrent_streams);
    server.max_header_list_size(config.max_header_list_size);
    server
        .serve_connection(TokioIo::new(io), service)
        .await
        .map_err(|error| io::Error::other(format!("gRPC HTTP/2 server connection: {error}")))
}

#[derive(Clone)]
struct HunkRpc {
    handler: TunnelHandler,
    context: GrpcRequestContext,
    max_message_size: usize,
    queue_capacity: usize,
}

impl StreamingService<Hunk> for HunkRpc {
    type Response = Hunk;
    type ResponseStream = Pin<Box<dyn Stream<Item = Result<Hunk, Status>> + Send + 'static>>;
    type Future =
        Pin<Box<dyn Future<Output = Result<GrpcResponse<Self::ResponseStream>, Status>> + Send>>;

    fn call(&mut self, request: GrpcRequest<Streaming<Hunk>>) -> Self::Future {
        let handler = self.handler.clone();
        let context = self.context.clone();
        let max_message_size = self.max_message_size;
        let queue_capacity = self.queue_capacity;
        Box::pin(async move {
            let (outbound, response_stream) = hunk_outbound(queue_capacity);
            let stream = GrpcTunnelStream::new(
                InboundMessages::Hunk(request.into_inner()),
                outbound,
                max_message_size,
            );
            spawn_handler(handler, stream, context);
            let response: Self::ResponseStream = response_stream.map(Ok).boxed();
            Ok(GrpcResponse::new(response))
        })
    }
}

#[derive(Clone)]
struct MultiHunkRpc {
    handler: TunnelHandler,
    context: GrpcRequestContext,
    max_message_size: usize,
    queue_capacity: usize,
}

impl StreamingService<MultiHunk> for MultiHunkRpc {
    type Response = MultiHunk;
    type ResponseStream = Pin<Box<dyn Stream<Item = Result<MultiHunk, Status>> + Send + 'static>>;
    type Future =
        Pin<Box<dyn Future<Output = Result<GrpcResponse<Self::ResponseStream>, Status>> + Send>>;

    fn call(&mut self, request: GrpcRequest<Streaming<MultiHunk>>) -> Self::Future {
        let handler = self.handler.clone();
        let context = self.context.clone();
        let max_message_size = self.max_message_size;
        let queue_capacity = self.queue_capacity;
        Box::pin(async move {
            let (outbound, response_stream) = multi_hunk_outbound(queue_capacity);
            let stream = GrpcTunnelStream::new(
                InboundMessages::Multi(request.into_inner()),
                outbound,
                max_message_size,
            );
            spawn_handler(handler, stream, context);
            let response: Self::ResponseStream = response_stream.map(Ok).boxed();
            Ok(GrpcResponse::new(response))
        })
    }
}

fn spawn_handler(handler: TunnelHandler, stream: GrpcTunnelStream, context: GrpcRequestContext) {
    tokio::spawn(async move {
        if let Err(error) = handler(stream, context).await {
            tracing::debug!(%error, "gRPC tunnel handler ended with an error");
        }
    });
}

fn request_context(
    request: &Request<Incoming>,
    peer_addr: SocketAddr,
    trusted_markers: &[String],
) -> GrpcRequestContext {
    let remote_addr = trusted_forwarded_address(request.headers(), peer_addr, trusted_markers)
        .unwrap_or(peer_addr);
    GrpcRequestContext {
        peer_addr,
        remote_addr,
        method_path: request.uri().path().to_string(),
        authority: request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_owned())
            .or_else(|| {
                request
                    .headers()
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            }),
        user_agent: request
            .headers()
            .get(USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    }
}

fn trusted_forwarded_address(
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    trusted_markers: &[String],
) -> Option<SocketAddr> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())?;
    let trusted = trusted_markers.iter().any(|marker| {
        HeaderName::from_bytes(marker.as_bytes())
            .ok()
            .is_some_and(|name| headers.contains_key(name))
    });
    if !trusted {
        if trusted_markers.is_empty() {
            tracing::warn!(
                %peer_addr,
                "ignored X-Forwarded-For because trustedXForwardedFor is empty"
            );
        } else {
            tracing::warn!(
                %peer_addr,
                "ignored potentially forged X-Forwarded-For"
            );
        }
        return None;
    }
    // Xray takes the substring before the first comma verbatim. In
    // particular, surrounding whitespace is not silently normalized.
    let first = forwarded.split(',').next()?.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(first, 0))
}

fn unimplemented_response() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    response
        .headers_mut()
        .insert("grpc-status", HeaderValue::from_static("12"));
    response.headers_mut().insert(
        "grpc-message",
        HeaderValue::from_static("unimplemented%20gRPC%20method"),
    );
    response
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::client::{GrpcClientConfig, GrpcClientConnection};

    fn echo_handler(contexts: Arc<Mutex<Vec<GrpcRequestContext>>>) -> TunnelHandler {
        Arc::new(move |mut stream, context| {
            let contexts = contexts.clone();
            Box::pin(async move {
                contexts.lock().unwrap().push(context);
                let mut buffer = [0u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await?;
                    if read == 0 {
                        stream.shutdown().await?;
                        return Ok(());
                    }
                    stream.write_all(&buffer[..read]).await?;
                    stream.flush().await?;
                }
            })
        })
    }

    async fn round_trip(multi_mode: bool) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let peer: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let contexts = Arc::new(Mutex::new(Vec::new()));
        let server_config = GrpcServerConfig {
            service_name: "/test/service/TunX|TunMultiX".into(),
            idle_timeout: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            max_message_size: 257,
            trusted_x_forwarded_for: vec!["x-trusted-cdn".into()],
            ..Default::default()
        };
        let server = tokio::spawn(serve_connection(
            server_io,
            peer,
            server_config,
            echo_handler(contexts.clone()),
        ));
        let client = GrpcClientConnection::handshake(
            client_io,
            GrpcClientConfig {
                authority: "grpc.example".into(),
                service_name: if multi_mode {
                    "/test/service/TunMultiX".into()
                } else {
                    "/test/service/TunX".into()
                },
                multi_mode,
                user_agent: Some("exact-agent/1".into()),
                idle_timeout: Duration::from_secs(30),
                health_check_timeout: Duration::from_secs(5),
                permit_without_stream: true,
                max_message_size: 257,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut tunnel = client.open_tunnel().await.unwrap();
        let payload = vec![0x5a; 128 * 1024 + 17];
        tunnel.write_all(&payload).await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        tunnel.shutdown().await.unwrap();
        drop(tunnel);
        drop(client);
        server.await.unwrap().unwrap();

        let contexts = contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].peer_addr, peer);
        assert_eq!(contexts[0].remote_addr, peer);
        assert_eq!(contexts[0].authority.as_deref(), Some("grpc.example"));
        assert_eq!(contexts[0].user_agent.as_deref(), Some("exact-agent/1"));
        assert_eq!(
            contexts[0].method_path,
            if multi_mode {
                "/test/service/TunMultiX"
            } else {
                "/test/service/TunX"
            }
        );
    }

    #[tokio::test]
    async fn tonic_tun_round_trip() {
        round_trip(false).await;
    }

    #[tokio::test]
    async fn tonic_tun_multi_round_trip() {
        round_trip(true).await;
    }

    #[test]
    fn server_validation_rejects_unrepresentable_xray_values() {
        for invalid in [
            GrpcServerConfig {
                idle_timeout: Duration::from_millis(500),
                ..Default::default()
            },
            GrpcServerConfig {
                health_check_timeout: Duration::from_secs(i32::MAX as u64 + 1),
                ..Default::default()
            },
            GrpcServerConfig {
                max_connections: 0,
                ..Default::default()
            },
            GrpcServerConfig {
                queue_capacity: MAX_QUEUE_CAPACITY + 1,
                ..Default::default()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn trusted_x_forwarded_for_matches_xray_marker_semantics() {
        let peer = "127.0.0.1:12345".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.7, 198.51.100.9"),
        );

        assert_eq!(
            trusted_forwarded_address(&headers, peer, &["x-forwarded-for".to_owned()]),
            Some("192.0.2.7:0".parse().unwrap())
        );
        assert_eq!(
            trusted_forwarded_address(&headers, peer, &["x-trusted-cdn".to_owned()]),
            None
        );

        headers.insert("x-trusted-cdn", HeaderValue::from_static("1"));
        assert_eq!(
            trusted_forwarded_address(&headers, peer, &["X-Trusted-CDN".to_owned()]),
            Some("192.0.2.7:0".parse().unwrap())
        );

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static(" 192.0.2.7,198.51.100.9"),
        );
        assert_eq!(
            trusted_forwarded_address(&headers, peer, &["x-trusted-cdn".to_owned()]),
            None,
            "Xray does not trim the first forwarded address"
        );
    }

    #[tokio::test]
    async fn bounded_tcp_listener_stops_and_aborts_open_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let contexts = Arc::new(Mutex::new(Vec::new()));
        let cancellation = CancellationToken::new();
        let server = tokio::spawn(serve_tcp_listener(
            listener,
            GrpcServerConfig {
                service_name: "listener-test".into(),
                max_connections: 1,
                ..Default::default()
            },
            echo_handler(contexts),
            cancellation.clone(),
        ));
        let carrier = tokio::net::TcpStream::connect(address).await.unwrap();
        let client = GrpcClientConnection::handshake(
            carrier,
            GrpcClientConfig {
                authority: "listener.test".into(),
                service_name: "listener-test".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut tunnel = client.open_tunnel().await.unwrap();
        tunnel.write_all(b"alive").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = [0_u8; 5];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"alive");

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("gRPC listener did not stop")
            .unwrap()
            .unwrap();
    }
}
