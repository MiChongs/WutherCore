use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use http::{
    Request, Response, Uri,
    header::{HeaderValue, USER_AGENT},
    uri::PathAndQuery,
};
use hyper::{
    body::Incoming,
    client::conn::http2::{self, SendRequest},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tonic::{Request as GrpcRequest, body::Body, client::Grpc, codec::ProstCodec};
use tower::Service;

use crate::{
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_QUEUE_CAPACITY, MAX_MESSAGE_SIZE_LIMIT, MAX_QUEUE_CAPACITY,
    MIN_MESSAGE_SIZE,
    path::grpc_method_paths,
    stream::{GrpcTunnelStream, InboundMessages, hunk_outbound, multi_hunk_outbound},
};

#[derive(Debug, Clone)]
pub struct GrpcClientConfig {
    /// HTTP/2 `:authority`, already resolved using Xray's authority/SNI/host
    /// precedence.
    pub authority: String,
    pub service_name: String,
    pub multi_mode: bool,
    /// Exact User-Agent value. `None` omits the header entirely.
    pub user_agent: Option<String>,
    pub idle_timeout: Duration,
    pub health_check_timeout: Duration,
    pub permit_without_stream: bool,
    pub initial_window_size: Option<u32>,
    pub max_message_size: usize,
    pub queue_capacity: usize,
}

impl Default for GrpcClientConfig {
    fn default() -> Self {
        Self {
            authority: String::new(),
            service_name: String::new(),
            multi_mode: false,
            user_agent: None,
            idle_timeout: Duration::ZERO,
            health_check_timeout: Duration::ZERO,
            permit_without_stream: false,
            initial_window_size: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

impl GrpcClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.authority.is_empty() {
            return Err(invalid_input("gRPC authority is empty"));
        }
        let uri = self.origin()?;
        if uri.authority().is_none() {
            return Err(invalid_input("gRPC authority is not a valid URI authority"));
        }
        let paths = grpc_method_paths(&self.service_name);
        let method_path = if self.multi_mode {
            paths.tun_multi_path()
        } else {
            paths.tun_path()
        };
        parse_path(&method_path)?;
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
        if self.health_check_timeout.is_zero() && !self.idle_timeout.is_zero() {
            // grpc-go uses its own default timeout when Time is configured but
            // Timeout is zero. Hyper's default is 20 seconds; leave it unset.
        }
        if let Some(user_agent) = self.user_agent.as_ref() {
            HeaderValue::from_str(user_agent)
                .map_err(|error| invalid_input(format!("invalid gRPC user-agent: {error}")))?;
        }
        Ok(())
    }

    fn origin(&self) -> io::Result<Uri> {
        format!("http://{}", self.authority)
            .parse()
            .map_err(|error| invalid_input(format!("invalid gRPC authority: {error}")))
    }
}

#[derive(Clone)]
struct ExactHeaderService {
    sender: SendRequest<Body>,
    user_agent: Option<HeaderValue>,
}

impl Service<Request<Body>> for ExactHeaderService {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Incoming>, hyper::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        match self.user_agent.as_ref() {
            Some(user_agent) => {
                request.headers_mut().insert(USER_AGENT, user_agent.clone());
            }
            None => {
                request.headers_mut().remove(USER_AGENT);
            }
        }
        Box::pin(self.sender.send_request(request))
    }
}

/// A reusable tonic gRPC connection over a caller-provided carrier.
#[derive(Clone)]
pub struct GrpcClientConnection {
    sender: SendRequest<Body>,
    config: GrpcClientConfig,
    origin: Uri,
    user_agent: Option<HeaderValue>,
}

impl std::fmt::Debug for GrpcClientConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcClientConnection")
            .field("authority", &self.config.authority)
            .field("service_name", &self.config.service_name)
            .field("multi_mode", &self.config.multi_mode)
            .field("user_agent", &self.config.user_agent)
            .finish_non_exhaustive()
    }
}

impl GrpcClientConnection {
    pub async fn handshake<S>(io: S, config: GrpcClientConfig) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        config.validate()?;
        let origin = config.origin()?;
        let user_agent = config
            .user_agent
            .as_ref()
            .map(|value| HeaderValue::from_str(value))
            .transpose()
            .map_err(|error| invalid_input(format!("invalid gRPC user-agent: {error}")))?;

        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if let Some(window) = config.initial_window_size {
            builder.initial_stream_window_size(window);
        }
        if !config.idle_timeout.is_zero() {
            builder.keep_alive_interval(config.idle_timeout);
        }
        if !config.health_check_timeout.is_zero() {
            builder.keep_alive_timeout(config.health_check_timeout);
        }
        builder.keep_alive_while_idle(config.permit_without_stream);

        let (sender, connection) = builder
            .handshake(TokioIo::new(io))
            .await
            .map_err(|error| io::Error::other(format!("gRPC HTTP/2 handshake: {error}")))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "gRPC HTTP/2 client connection ended");
            }
        });

        Ok(Self {
            sender,
            config,
            origin,
            user_agent,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub async fn open_tunnel(&self) -> io::Result<GrpcTunnelStream> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "gRPC HTTP/2 connection is closed",
            ));
        }
        if self.config.multi_mode {
            self.open_multi_tunnel().await
        } else {
            self.open_hunk_tunnel().await
        }
    }

    async fn open_hunk_tunnel(&self) -> io::Result<GrpcTunnelStream> {
        let (outbound, request_stream) = hunk_outbound(self.config.queue_capacity);
        let path = grpc_method_paths(&self.config.service_name).tun_path();
        let mut client = self.dispatcher();
        let path = parse_path(&path)?;
        client
            .ready()
            .await
            .map_err(|error| io::Error::other(format!("gRPC service readiness: {error}")))?;
        let (response_tx, response_rx) = oneshot::channel();
        let response_task = tokio::spawn(async move {
            let response = client
                .streaming(
                    GrpcRequest::new(request_stream),
                    path,
                    ProstCodec::default(),
                )
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_to_io);
            let _ = response_tx.send(response);
        });
        Ok(GrpcTunnelStream::new(
            InboundMessages::HunkPending(response_rx),
            outbound,
            self.config.max_message_size,
        )
        .with_response_task(response_task.abort_handle()))
    }

    async fn open_multi_tunnel(&self) -> io::Result<GrpcTunnelStream> {
        let (outbound, request_stream) = multi_hunk_outbound(self.config.queue_capacity);
        let path = grpc_method_paths(&self.config.service_name).tun_multi_path();
        let mut client = self.dispatcher();
        let path = parse_path(&path)?;
        client
            .ready()
            .await
            .map_err(|error| io::Error::other(format!("gRPC service readiness: {error}")))?;
        let (response_tx, response_rx) = oneshot::channel();
        let response_task = tokio::spawn(async move {
            let response = client
                .streaming(
                    GrpcRequest::new(request_stream),
                    path,
                    ProstCodec::default(),
                )
                .await
                .map(tonic::Response::into_inner)
                .map_err(status_to_io);
            let _ = response_tx.send(response);
        });
        Ok(GrpcTunnelStream::new(
            InboundMessages::MultiPending(response_rx),
            outbound,
            self.config.max_message_size,
        )
        .with_response_task(response_task.abort_handle()))
    }

    fn dispatcher(&self) -> Grpc<ExactHeaderService> {
        let service = ExactHeaderService {
            sender: self.sender.clone(),
            user_agent: self.user_agent.clone(),
        };
        Grpc::with_origin(service, self.origin.clone())
            .max_encoding_message_size(self.config.max_message_size)
            .max_decoding_message_size(self.config.max_message_size)
    }
}

fn parse_path(path: &str) -> io::Result<PathAndQuery> {
    path.parse()
        .map_err(|error| invalid_input(format!("invalid gRPC method path `{path}`: {error}")))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn status_to_io(status: tonic::Status) -> io::Error {
    let kind = match status.code() {
        tonic::Code::Cancelled => io::ErrorKind::ConnectionAborted,
        tonic::Code::DeadlineExceeded => io::ErrorKind::TimedOut,
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => {
            io::ErrorKind::InvalidData
        }
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            io::ErrorKind::PermissionDenied
        }
        tonic::Code::ResourceExhausted => io::ErrorKind::OutOfMemory,
        tonic::Code::Unimplemented => io::ErrorKind::Unsupported,
        tonic::Code::Unavailable => io::ErrorKind::ConnectionRefused,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("gRPC tunnel setup: {status}"))
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, future::Future, pin::Pin};

    use futures::Stream;
    use hyper::{server::conn::http2 as server_http2, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic::{
        Request as GrpcRequest, Response as GrpcResponse, Status, Streaming,
        codec::ProstCodec,
        server::{Grpc, StreamingService},
    };

    use super::*;
    use crate::proto::Hunk;

    #[derive(Clone)]
    struct DelayedHeadersRpc;

    impl StreamingService<Hunk> for DelayedHeadersRpc {
        type Response = Hunk;
        type ResponseStream = Pin<Box<dyn Stream<Item = Result<Hunk, Status>> + Send + 'static>>;
        type Future = Pin<
            Box<dyn Future<Output = Result<GrpcResponse<Self::ResponseStream>, Status>> + Send>,
        >;

        fn call(&mut self, request: GrpcRequest<Streaming<Hunk>>) -> Self::Future {
            Box::pin(async move {
                let mut request = request.into_inner();
                let first = request
                    .message()
                    .await?
                    .ok_or_else(|| Status::invalid_argument("request body ended"))?;
                let response: Self::ResponseStream = Box::pin(tokio_stream::iter([Ok(first)]));
                Ok(GrpcResponse::new(response))
            })
        }
    }

    #[test]
    fn validation_rejects_header_injection_and_empty_limits() {
        let invalid_header = GrpcClientConfig {
            authority: "example.com".into(),
            user_agent: Some("ok\r\nx: injected".into()),
            ..Default::default()
        };
        assert!(invalid_header.validate().is_err());

        let invalid_limit = GrpcClientConfig {
            authority: "example.com".into(),
            max_message_size: 0,
            ..Default::default()
        };
        assert!(invalid_limit.validate().is_err());

        for invalid in [
            GrpcClientConfig {
                authority: "example.com".into(),
                idle_timeout: Duration::from_millis(500),
                ..Default::default()
            },
            GrpcClientConfig {
                authority: "example.com".into(),
                health_check_timeout: Duration::from_secs(i32::MAX as u64 + 1),
                ..Default::default()
            },
            GrpcClientConfig {
                authority: "example.com".into(),
                initial_window_size: Some(i32::MAX as u32 + 1),
                ..Default::default()
            },
            GrpcClientConfig {
                authority: "example.com".into(),
                max_message_size: MAX_MESSAGE_SIZE_LIMIT + 1,
                ..Default::default()
            },
            GrpcClientConfig {
                authority: "example.com".into(),
                queue_capacity: MAX_QUEUE_CAPACITY + 1,
                ..Default::default()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn authority_accepts_domain_ipv4_and_bracketed_ipv6() {
        for authority in [
            "example.com",
            "example.com:443",
            "192.0.2.1",
            "[2001:db8::1]:443",
        ] {
            GrpcClientConfig {
                authority: authority.into(),
                ..Default::default()
            }
            .validate()
            .unwrap();
        }
    }

    #[tokio::test]
    async fn open_returns_before_response_headers_to_avoid_xray_bidi_deadlock() {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server = tokio::spawn(async move {
            let service = service_fn(|request| async move {
                let response = Grpc::new(ProstCodec::<Hunk, Hunk>::default())
                    .streaming(DelayedHeadersRpc, request)
                    .await;
                Ok::<_, Infallible>(response)
            });
            let mut builder = server_http2::Builder::new(TokioExecutor::new());
            builder.timer(TokioTimer::new());
            builder
                .serve_connection(TokioIo::new(server_io), service)
                .await
                .unwrap();
        });

        let client = GrpcClientConnection::handshake(
            client_io,
            GrpcClientConfig {
                authority: "delayed.example".into(),
                service_name: "delayed".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut tunnel = tokio::time::timeout(Duration::from_millis(250), client.open_tunnel())
            .await
            .expect("open_tunnel waited for response headers")
            .unwrap();
        tunnel.write_all(b"unlocks-response").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = vec![0; b"unlocks-response".len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"unlocks-response");
        tunnel.shutdown().await.unwrap();
        drop(tunnel);
        drop(client);
        server.await.unwrap();
    }
}
