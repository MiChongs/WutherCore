//! Runtime wiring for configured XHTTP listeners.
//!
//! Startup is deliberately split into a synchronous preparation phase and a
//! background serving phase: certificates, ALPN and sockets are all validated
//! and bound before a handle is returned. A caller therefore never reports a
//! listener as ready while its real bind or TLS setup can still fail later.

use std::{io, net::SocketAddr, sync::Arc};

use core_config::{
    model::{
        XHTTP_MAX_ACTIVE_CONNECTIONS, XHTTP_MAX_ACTIVE_HTTP_STREAMS, XHTTP_MAX_CONCURRENT_STREAMS,
        XhttpListenAlpn,
    },
    runtime_plan::{XhttpListenPlan, XhttpListenTargetPlan},
};
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    xhttp::{AcceptedXhttpStream, HttpVersionPolicy, XhttpAcceptReceiver, XhttpServer},
    xhttp_cors::CorsPolicy,
    xhttp_tls::{self, PreparedTlsAcceptor},
};

enum BoundTransport {
    Cleartext {
        listener: TcpListener,
        policy: HttpVersionPolicy,
    },
    Tls {
        listener: TcpListener,
        acceptor: TlsAcceptor,
        policy: HttpVersionPolicy,
    },
    BoringTls {
        listener: TcpListener,
        acceptor: boring::ssl::SslAcceptor,
        policy: HttpVersionPolicy,
    },
    Http3(quinn::Endpoint),
}

/// Running XHTTP listener and all of its logical Raw relays.
///
/// Dropping the handle is fail-safe and cancels the transport immediately.
/// Prefer [`Self::shutdown`] when the caller can await orderly task cleanup.
pub struct XhttpListenerHandle {
    tag: String,
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    server: XhttpServer,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl XhttpListenerHandle {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.cancel();
        self.server.close();
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("XHTTP listener task failed: {error}"),
            )
        })?
    }
}

impl Drop for XhttpListenerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.server.close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Prepare and start every enabled listener.
///
/// If any later listener fails to prepare, all earlier handles are shut down
/// before the startup error is returned. This makes duplicate ports and bad
/// credentials transactional from the process' point of view.
pub async fn start_xhttp_listeners(
    plans: &[XhttpListenPlan],
    runtime: Arc<Runtime>,
) -> io::Result<Vec<XhttpListenerHandle>> {
    let mut handles = Vec::new();
    for plan in plans.iter().filter(|plan| plan.enabled) {
        match start_xhttp_listener(plan, Arc::clone(&runtime)).await {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                for handle in &mut handles {
                    let _ = handle.shutdown().await;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("XHTTP listener `{}` startup failed: {error}", plan.tag),
                ));
            }
        }
    }
    Ok(handles)
}

/// Validate credentials and ALPN, pre-bind the configured TCP/UDP socket, then
/// spawn transport serving plus the lossless logical-stream accept loop.
pub async fn start_xhttp_listener(
    plan: &XhttpListenPlan,
    runtime: Arc<Runtime>,
) -> io::Result<XhttpListenerHandle> {
    validate_runtime_plan(plan)?;
    let target = plan
        .target
        .clone()
        .ok_or_else(|| invalid_input("enabled XHTTP Raw listener requires a fixed target"))?;
    let config =
        core_outbound::registry::typed_xhttp_config(&plan.settings).map_err(invalid_input)?;
    let cors_policy = match plan.cors_origins.as_deref() {
        None => CorsPolicy::XrayCompatible,
        Some(origins) => CorsPolicy::configured(origins),
    };
    let (mut server, receiver) =
        XhttpServer::new_with_cors(config, Some(plan.accept_queue), cors_policy)?;
    server.configure_listener_resources(
        plan.max_active_connections,
        plan.max_concurrent_streams,
        plan.max_active_http_streams,
        plan.http_idle_timeout,
    )?;
    let address = plan
        .socket_addr()
        .map_err(|error| invalid_input(error.to_string()))?;
    let transport = prepare_transport(plan, address).await?;
    let local_addr = transport_local_addr(&transport)?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_listener(
        server.clone(),
        receiver,
        transport,
        ListenerHandler::new(runtime),
        plan.tag.clone(),
        target,
        plan.max_active_relays,
        shutdown.clone(),
    ));
    info!(
        target: "inbound::xhttp",
        tag = %plan.tag,
        addr = %local_addr,
        alpn = ?plan.alpn.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "XHTTP Raw listener ready"
    );
    Ok(XhttpListenerHandle {
        tag: plan.tag.clone(),
        local_addr,
        shutdown,
        server,
        task: Some(task),
    })
}

fn validate_runtime_plan(plan: &XhttpListenPlan) -> io::Result<()> {
    if !plan.enabled {
        return Err(invalid_input("cannot start a disabled XHTTP listener"));
    }
    if plan.target.is_none() {
        return Err(invalid_input(
            "enabled XHTTP Raw listener requires target.host and target.port",
        ));
    }
    if plan.max_active_relays == 0 {
        return Err(invalid_input(
            "XHTTP listener max-active-relays must be greater than zero",
        ));
    }
    if plan.max_active_connections == 0 {
        return Err(invalid_input(
            "XHTTP listener max-active-connections must be greater than zero",
        ));
    }
    if plan.max_active_connections > XHTTP_MAX_ACTIVE_CONNECTIONS {
        return Err(invalid_input(format!(
            "XHTTP listener max-active-connections must not exceed {XHTTP_MAX_ACTIVE_CONNECTIONS}"
        )));
    }
    if plan.max_concurrent_streams == 0 {
        return Err(invalid_input(
            "XHTTP listener max-concurrent-streams must be greater than zero",
        ));
    }
    if plan.max_concurrent_streams > XHTTP_MAX_CONCURRENT_STREAMS {
        return Err(invalid_input(format!(
            "XHTTP listener max-concurrent-streams must not exceed {XHTTP_MAX_CONCURRENT_STREAMS}"
        )));
    }
    if plan.max_active_http_streams == 0 {
        return Err(invalid_input(
            "XHTTP listener max-active-http-streams must be greater than zero",
        ));
    }
    if plan.max_active_http_streams > XHTTP_MAX_ACTIVE_HTTP_STREAMS {
        return Err(invalid_input(format!(
            "XHTTP listener max-active-http-streams must not exceed {XHTTP_MAX_ACTIVE_HTTP_STREAMS}"
        )));
    }
    if plan.http_idle_timeout.is_zero() {
        return Err(invalid_input(
            "XHTTP listener http-idle-timeout must be greater than zero",
        ));
    }
    let bind = plan
        .socket_addr()
        .map_err(|error| invalid_input(error.to_string()))?;
    if !bind.ip().is_loopback() && !plan.allow_unauthenticated_non_loopback {
        return Err(invalid_input(format!(
            "XHTTP Raw listener {} is unauthenticated on a non-loopback address; set allow-unauthenticated-non-loopback=true explicitly",
            bind.ip()
        )));
    }
    if plan.alpn.is_empty() {
        return Err(invalid_input("XHTTP listener ALPN cannot be empty"));
    }
    let h3_count = plan
        .alpn
        .iter()
        .filter(|value| **value == XhttpListenAlpn::H3)
        .count();
    if h3_count > 0 && !plan.uses_http3() {
        return Err(invalid_input(
            "XHTTP h3 ALPN must be the listener's only ALPN",
        ));
    }
    if plan.uses_http3() && (plan.cleartext || plan.tls.is_none()) {
        return Err(invalid_input("XHTTP h3 requires TLS credentials"));
    }
    if plan.cleartext && plan.tls.is_some() {
        return Err(invalid_input(
            "XHTTP cleartext listener cannot also configure TLS",
        ));
    }
    if !plan.cleartext && plan.tls.is_none() {
        return Err(invalid_input(
            "XHTTP TLS listener requires certificate and private key",
        ));
    }
    Ok(())
}

async fn prepare_transport(
    plan: &XhttpListenPlan,
    address: SocketAddr,
) -> io::Result<BoundTransport> {
    if plan.uses_http3() {
        let tls = xhttp_tls::build_quic(
            plan.tls.as_ref().expect("validated h3 listener has TLS"),
            &[XhttpListenAlpn::H3],
        )?;
        let quic_crypto = QuicServerConfig::try_from(tls).map_err(|error| {
            invalid_input(format!("invalid XHTTP h3 TLS configuration: {error}"))
        })?;
        let max_idle_timeout = plan.http_idle_timeout.try_into().map_err(|_| {
            invalid_input(format!(
                "XHTTP h3 http-idle-timeout {:?} exceeds QUIC's supported range",
                plan.http_idle_timeout
            ))
        })?;
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        transport_config.max_idle_timeout(Some(max_idle_timeout));
        transport_config
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(plan.max_concurrent_streams));
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        server_config.transport_config(Arc::new(transport_config));
        let endpoint = quinn::Endpoint::server(server_config, address).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("bind XHTTP h3 UDP listener {address}: {error}"),
            )
        })?;
        return Ok(BoundTransport::Http3(endpoint));
    }

    let policy = tcp_http_version_policy(&plan.alpn)?;
    if plan.cleartext {
        let listener = bind_tcp(address).await?;
        return Ok(BoundTransport::Cleartext { listener, policy });
    }

    let tls = xhttp_tls::build(
        plan.tls
            .as_ref()
            .expect("validated TLS listener has credentials"),
        &plan.alpn,
        false,
    )?;
    let listener = bind_tcp(address).await?;
    Ok(match tls {
        PreparedTlsAcceptor::Rustls(acceptor) => BoundTransport::Tls {
            listener,
            acceptor,
            policy,
        },
        PreparedTlsAcceptor::Boring(acceptor) => BoundTransport::BoringTls {
            listener,
            acceptor,
            policy,
        },
    })
}

fn tcp_http_version_policy(alpn: &[XhttpListenAlpn]) -> io::Result<HttpVersionPolicy> {
    let allow_http1 = alpn.contains(&XhttpListenAlpn::Http1);
    let allow_http2 = alpn.contains(&XhttpListenAlpn::H2);
    HttpVersionPolicy::from_allowances(allow_http1, allow_http2)
        .ok_or_else(|| invalid_input("XHTTP TCP listener ALPN must allow http/1.1 or h2"))
}

async fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("bind XHTTP TCP listener {address}: {error}"),
        )
    })
}

fn transport_local_addr(transport: &BoundTransport) -> io::Result<SocketAddr> {
    match transport {
        BoundTransport::Cleartext { listener, .. } => listener.local_addr(),
        BoundTransport::Tls { listener, .. } => listener.local_addr(),
        BoundTransport::BoringTls { listener, .. } => listener.local_addr(),
        BoundTransport::Http3(endpoint) => endpoint.local_addr(),
    }
}

async fn run_listener(
    server: XhttpServer,
    mut receiver: XhttpAcceptReceiver,
    transport: BoundTransport,
    handler: ListenerHandler,
    tag: String,
    target: XhttpListenTargetPlan,
    max_active_relays: usize,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let transport_server = server.clone();
    let transport_shutdown = shutdown.child_token();
    let mut transport_task = tokio::spawn(async move {
        match transport {
            BoundTransport::Cleartext { listener, policy } => {
                transport_server
                    .serve_listener_with_policy(listener, transport_shutdown, policy)
                    .await
            }
            BoundTransport::Tls {
                listener,
                acceptor,
                policy,
            } => {
                transport_server
                    .serve_tls_listener_with_policy(listener, acceptor, transport_shutdown, policy)
                    .await
            }
            BoundTransport::BoringTls {
                listener,
                acceptor,
                policy,
            } => {
                transport_server
                    .serve_boring_tls_listener_with_policy(
                        listener,
                        acceptor,
                        transport_shutdown,
                        policy,
                    )
                    .await
            }
            BoundTransport::Http3(endpoint) => {
                transport_server
                    .serve_h3_endpoint(endpoint, transport_shutdown)
                    .await
            }
        }
    });
    let mut relays = JoinSet::new();
    let mut transport_result = None;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = &mut transport_task => {
                transport_result = Some(flatten_join(result, "XHTTP transport task"));
                break;
            }
            accepted = receiver.accept(), if relays.len() < max_active_relays => {
                let Some(accepted) = accepted else {
                    break;
                };
                spawn_raw_relay(
                    &mut relays,
                    handler.clone(),
                    tag.clone(),
                    target.clone(),
                    accepted,
                );
            }
            completed = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(target: "inbound::xhttp", tag = %tag, error = %error, "XHTTP Raw relay task failed");
                }
            }
        }
    }

    shutdown.cancel();
    server.close();
    receiver.close();
    let result = match transport_result {
        Some(result) => result,
        None => flatten_join(transport_task.await, "XHTTP transport task"),
    };
    relays.abort_all();
    while relays.join_next().await.is_some() {}
    result
}

fn spawn_raw_relay(
    relays: &mut JoinSet<()>,
    handler: ListenerHandler,
    tag: String,
    target: XhttpListenTargetPlan,
    accepted: AcceptedXhttpStream,
) {
    relays.spawn(async move {
        let metadata = InboundMetadata::tcp(
            tag.clone(),
            "XHTTP",
            accepted.peer_addr,
            accepted.local_addr,
            target.host,
            target.port,
        );
        debug!(
            target: "inbound::xhttp",
            tag = %tag,
            peer = %accepted.peer_addr,
            mode = accepted.mode,
            version = ?accepted.version,
            session = ?accepted.session_id,
            "accepted XHTTP Raw logical stream"
        );
        if let Err(error) = handler.new_connection(accepted.stream, metadata).await {
            debug!(
                target: "inbound::xhttp",
                tag = %tag,
                peer = %accepted.peer_addr,
                error = %error,
                "XHTTP Raw relay ended"
            );
        }
    });
}

fn flatten_join(
    result: Result<io::Result<()>, tokio::task::JoinError>,
    context: &str,
) -> io::Result<()> {
    result.map_err(|error| {
        io::Error::new(io::ErrorKind::Other, format!("{context} failed: {error}"))
    })?
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use bytes::{Buf, Bytes};
    use core_config::runtime_plan::RuntimePlan;
    use core_runtime::Runtime;
    use futures::stream;
    use http::{
        HeaderMap, Method, Request, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
            ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, HOST, ORIGIN, VARY,
        },
    };
    use http_body_util::{BodyExt as _, Full, StreamBody};
    use hyper::body::Frame;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        sync::mpsc,
        task::JoinHandle,
        time::timeout,
    };
    use tokio_rustls::{TlsConnector, client::TlsStream};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const TEST_PATH: &str = "/runtime/";

    struct EchoServer {
        address: SocketAddr,
        task: JoinHandle<()>,
    }

    impl Drop for EchoServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_echo_server() -> EchoServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.into_split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        EchoServer { address, task }
    }

    struct ObservedTarget {
        address: SocketAddr,
        accepted: mpsc::Receiver<TcpStream>,
        task: JoinHandle<()>,
    }

    impl Drop for ObservedTarget {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_observed_target() -> ObservedTarget {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if stream.write_all(b"!").await.is_err() {
                    continue;
                }
                if accepted_tx.send(stream).await.is_err() {
                    break;
                }
            }
        });
        ObservedTarget {
            address,
            accepted,
            task,
        }
    }

    struct TlsFiles {
        directory: PathBuf,
        cert_path: PathBuf,
        key_path: PathBuf,
        cert_der: CertificateDer<'static>,
    }

    impl TlsFiles {
        fn valid(name: &str) -> Self {
            let directory = unique_temp_directory(name);
            fs::create_dir_all(&directory).unwrap();
            let cert_path = directory.join("cert.pem");
            let key_path = directory.join("key.pem");
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            fs::write(&cert_path, cert.pem()).unwrap();
            fs::write(&key_path, key_pair.serialize_pem()).unwrap();
            Self {
                directory,
                cert_path,
                key_path,
                cert_der: cert.der().clone(),
            }
        }

        fn invalid(name: &str) -> Self {
            let directory = unique_temp_directory(name);
            fs::create_dir_all(&directory).unwrap();
            let cert_path = directory.join("cert.pem");
            let key_path = directory.join("key.pem");
            fs::write(&cert_path, b"not a certificate").unwrap();
            fs::write(&key_path, b"not a private key").unwrap();
            Self {
                directory,
                cert_path,
                key_path,
                cert_der: CertificateDer::from(Vec::<u8>::new()),
            }
        }
    }

    impl Drop for TlsFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn unique_temp_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wuthercore-xhttp-listener-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn yaml_path(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "''"))
    }

    fn compile_plan(
        listen_port: u16,
        target: SocketAddr,
        alpn: &str,
        tls: Option<&TlsFiles>,
        tag: &str,
    ) -> RuntimePlan {
        let security = match tls {
            Some(files) => format!(
                "      tls:\n        cert: {}\n        key: {}",
                yaml_path(&files.cert_path),
                yaml_path(&files.key_path)
            ),
            None => "      cleartext: true".to_owned(),
        };
        let yaml = format!(
            r#"
version: 1
profile: server
listen:
  panel: false
  xhttp:
    - enabled: true
      address: 127.0.0.1
      port: {listen_port}
{security}
      alpn: [{alpn}]
      target: {{host: 127.0.0.1, port: {target_port}}}
      tag: {tag}
      settings:
        host: localhost
        path: /runtime
        mode: stream-one
        xPaddingBytes: 4
route:
  preset: direct
"#,
            target_port = target.port()
        );
        core_config::loader::load_from_str(&yaml).unwrap_or_else(|error| {
            panic!("compile test XHTTP listener plan:\n{yaml}\nerror: {error}")
        })
    }

    async fn reserve_tcp_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn reserve_udp_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap().port()
    }

    async fn start_single(
        plan: &RuntimePlan,
    ) -> (Arc<Runtime>, XhttpListenerHandle, XhttpListenPlan) {
        let runtime = Arc::new(Runtime::build(plan.clone()).unwrap());
        let listener_plan = plan.listen.xhttp[0].clone();
        let handle = start_xhttp_listener(&listener_plan, Arc::clone(&runtime))
            .await
            .unwrap();
        (runtime, handle, listener_plan)
    }

    async fn stop_single(mut handle: XhttpListenerHandle, runtime: Arc<Runtime>) {
        timeout(TEST_TIMEOUT, handle.shutdown())
            .await
            .expect("XHTTP listener shutdown timeout")
            .expect("XHTTP listener shutdown");
        runtime.shutdown().await;
    }

    fn xhttp_request(scheme: &str, address: SocketAddr, payload: Bytes) -> Request<Full<Bytes>> {
        Request::builder()
            .method(Method::POST)
            .uri(format!(
                "{scheme}://localhost:{}{TEST_PATH}",
                address.port()
            ))
            .header(HOST, format!("localhost:{}", address.port()))
            .header(
                "referer",
                format!("{scheme}://localhost/runtime/?x_padding=XXXX"),
            )
            .body(Full::new(payload))
            .unwrap()
    }

    async fn h1_round_trip<I>(io: I, address: SocketAddr, scheme: &str, payload: Bytes) -> Bytes
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let response = timeout(
            TEST_TIMEOUT,
            sender.send_request(xhttp_request(scheme, address, payload)),
        )
        .await
        .expect("HTTP/1 response headers timeout")
        .expect("HTTP/1 request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = timeout(TEST_TIMEOUT, response.into_body().collect())
            .await
            .expect("HTTP/1 response body timeout")
            .expect("HTTP/1 response body")
            .to_bytes();
        drop(sender);
        driver.abort();
        body
    }

    async fn h2_round_trip<I>(io: I, address: SocketAddr, scheme: &str, payload: Bytes) -> Bytes
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let response = timeout(
            TEST_TIMEOUT,
            sender.send_request(xhttp_request(scheme, address, payload)),
        )
        .await
        .expect("HTTP/2 response headers timeout")
        .expect("HTTP/2 request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = timeout(TEST_TIMEOUT, response.into_body().collect())
            .await
            .expect("HTTP/2 response body timeout")
            .expect("HTTP/2 response body")
            .to_bytes();
        drop(sender);
        driver.abort();
        body
    }

    async fn h1_options_headers(address: SocketAddr, origin: &str) -> HeaderMap {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri(format!("http://localhost:{}{TEST_PATH}", address.port()))
            .header(HOST, format!("localhost:{}", address.port()))
            .header(ORIGIN, origin)
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(ACCESS_CONTROL_REQUEST_HEADERS, "X-XHTTP-Session")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = timeout(TEST_TIMEOUT, sender.send_request(request))
            .await
            .expect("CORS OPTIONS response headers timeout")
            .expect("CORS OPTIONS request");
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        timeout(TEST_TIMEOUT, response.into_body().collect())
            .await
            .expect("CORS OPTIONS response body timeout")
            .expect("CORS OPTIONS response body");
        drop(sender);
        driver.abort();
        headers
    }

    async fn open_pending_raw_stream(address: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST {TEST_PATH} HTTP/1.1\r\nHost: localhost:{}\r\n\
                     Referer: http://localhost/runtime/?x_padding=XXXX\r\n\
                     Content-Length: 1048576\r\n\r\nping",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let response = timeout(TEST_TIMEOUT, async {
            let mut response = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0, "XHTTP response ended before its headers");
                response.extend_from_slice(&buffer[..read]);
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    return response;
                }
            }
        })
        .await
        .expect("pending XHTTP response headers timeout");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "pending XHTTP request failed: {}",
            String::from_utf8_lossy(&response)
        );
        stream
    }

    async fn wait_for_connection_count(runtime: &Runtime, expected: usize) {
        timeout(TEST_TIMEOUT, async {
            loop {
                if runtime.connections.list().len() == expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "runtime connection count never became {expected}; current={}",
                runtime.connections.list().len()
            )
        });
    }

    fn vary_contains(headers: &HeaderMap, name: &str) -> bool {
        headers
            .get_all(VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case(name))
    }

    async fn tls_connect(
        address: SocketAddr,
        files: &TlsFiles,
        alpn: &'static [u8],
    ) -> TlsStream<TcpStream> {
        try_tls_connect_with_alpns(address, files, vec![alpn.to_vec()])
            .await
            .unwrap()
    }

    async fn try_tls_connect_with_alpns(
        address: SocketAddr,
        files: &TlsFiles,
        alpns: Vec<Vec<u8>>,
    ) -> io::Result<TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(files.cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpns;
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(address).await.unwrap();
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .map_err(io::Error::other)
    }

    async fn raw_http_status<I>(
        io: &mut I,
        address: SocketAddr,
        version: &str,
    ) -> Option<StatusCode>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let request = format!(
            "POST {TEST_PATH} {version}\r\nHost: localhost:{}\r\n\
             Referer: https://localhost/runtime/?x_padding=XXXX\r\n\
             Content-Length: 1048576\r\n\r\nping",
            address.port()
        );
        if io.write_all(request.as_bytes()).await.is_err() || io.flush().await.is_err() {
            return None;
        }

        let response = timeout(Duration::from_secs(2), async {
            let mut response = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                match io.read(&mut buffer).await {
                    Ok(0) | Err(_) => return response,
                    Ok(read) => {
                        response.extend_from_slice(&buffer[..read]);
                        if response.windows(4).any(|window| window == b"\r\n\r\n") {
                            return response;
                        }
                    }
                }
            }
        })
        .await
        .ok()?;
        let status = std::str::from_utf8(&response)
            .ok()?
            .split("\r\n")
            .next()?
            .split_ascii_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        StatusCode::from_u16(status).ok()
    }

    async fn assert_no_logical_flow(runtime: &Runtime) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        while tokio::time::Instant::now() < deadline {
            assert!(
                runtime.connections.list().is_empty(),
                "disallowed HTTP version entered the XHTTP accepted-stream channel"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn assert_h2_rejected<I>(io: I, address: SocketAddr, runtime: &Runtime)
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .expect("HTTP/2 handshake");
        let driver = tokio::spawn(async move { connection.await });
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost:{}{TEST_PATH}", address.port()))
            .header(HOST, format!("localhost:{}", address.port()))
            .header("referer", "https://localhost/runtime/?x_padding=XXXX")
            .body(StreamBody::new(stream::pending::<
                Result<Frame<Bytes>, Infallible>,
            >()))
            .unwrap();
        let response = timeout(Duration::from_secs(2), sender.send_request(request))
            .await
            .expect("disallowed HTTP/2 request response timeout")
            .expect("disallowed HTTP/2 request");
        assert_eq!(
            response.status(),
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "disallowed HTTP/2 request reached the XHTTP handler"
        );
        assert_no_logical_flow(runtime).await;
        drop(sender);
        driver.abort();
    }

    #[tokio::test]
    async fn cleartext_h1_raw_echo_routes_through_connection_table() {
        let echo = spawn_echo_server().await;
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h1", None, "raw-h1");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();

        let mut client = TcpStream::connect(address).await.unwrap();
        let payload = b"raw-h1-runtime-echo";
        client
            .write_all(
                format!(
                    "POST {TEST_PATH} HTTP/1.1\r\nHost: localhost:{}\r\n\
                     Referer: http://localhost/runtime/?x_padding=XXXX\r\n\
                     Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    address.port(),
                    payload.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        client.write_all(b"\r\n").await.unwrap();
        client.flush().await.unwrap();

        let response = timeout(TEST_TIMEOUT, async {
            let mut response = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = client.read(&mut buffer).await.unwrap();
                assert!(read > 0, "HTTP/1 response ended before echo");
                response.extend_from_slice(&buffer[..read]);
                if response
                    .windows(payload.len())
                    .any(|window| window == payload)
                {
                    return response;
                }
            }
        })
        .await
        .expect("HTTP/1 raw echo timeout");
        assert!(response.starts_with(b"HTTP/1.1 200"));

        let entries = runtime.connections.list();
        assert_eq!(entries.len(), 1);
        let metadata = &entries[0].meta;
        assert_eq!(metadata.kind.as_str(), "XHTTP");
        assert_eq!(metadata.inbound_name.as_str(), "raw-h1");
        assert_eq!(metadata.host.as_str(), "127.0.0.1");
        assert_eq!(
            metadata.destination_port.as_str(),
            echo.address.port().to_string()
        );

        client.write_all(b"0\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn max_active_relays_holds_the_next_logical_stream_until_capacity_is_released() {
        let mut target = spawn_observed_target().await;
        let port = reserve_tcp_port().await;
        let mut plan = compile_plan(port, target.address, "h1", None, "relay-limit");
        plan.listen.xhttp[0].max_active_relays = 1;
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();

        let first_client = open_pending_raw_stream(address).await;
        let first_target = timeout(TEST_TIMEOUT, target.accepted.recv())
            .await
            .expect("first Raw relay never dialed its target")
            .expect("target accept channel closed");
        wait_for_connection_count(&runtime, 1).await;

        let second_client = open_pending_raw_stream(address).await;
        assert!(
            timeout(Duration::from_millis(250), target.accepted.recv())
                .await
                .is_err(),
            "second Raw relay dialed its target while the first relay was active"
        );
        assert_eq!(
            runtime.connections.list().len(),
            1,
            "max-active-relays=1 admitted a second active runtime connection"
        );

        drop(first_client);
        drop(first_target);
        let second_target = timeout(TEST_TIMEOUT, target.accepted.recv())
            .await
            .expect("second Raw relay did not start after capacity was released")
            .expect("target accept channel closed");
        wait_for_connection_count(&runtime, 1).await;

        drop(second_client);
        drop(second_target);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn configured_cors_policy_is_enforced_by_the_real_h1_listener() {
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let compatible_port = reserve_tcp_port().await;
        let compatible_plan =
            compile_plan(compatible_port, target, "h1", None, "cors-xray-compatible");
        let (compatible_runtime, compatible_handle, _) = start_single(&compatible_plan).await;
        let compatible = h1_options_headers(
            compatible_handle.local_addr(),
            "HTTPS://Console.Example:443",
        )
        .await;
        assert_eq!(
            compatible[ACCESS_CONTROL_ALLOW_ORIGIN],
            "HTTPS://Console.Example:443"
        );
        assert!(vary_contains(&compatible, "Origin"));
        assert_eq!(compatible[ACCESS_CONTROL_ALLOW_METHODS], "POST");
        assert_eq!(compatible[ACCESS_CONTROL_ALLOW_HEADERS], "X-XHTTP-Session");
        stop_single(compatible_handle, compatible_runtime).await;

        let disabled_port = reserve_tcp_port().await;
        let mut disabled_plan = compile_plan(disabled_port, target, "h1", None, "cors-disabled");
        disabled_plan.listen.xhttp[0].cors_origins = Some(Vec::new());
        let (disabled_runtime, disabled_handle, _) = start_single(&disabled_plan).await;
        let disabled =
            h1_options_headers(disabled_handle.local_addr(), "https://console.example").await;
        assert!(!disabled.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(!disabled.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert!(!disabled.contains_key(ACCESS_CONTROL_ALLOW_METHODS));
        assert!(!disabled.contains_key(ACCESS_CONTROL_ALLOW_HEADERS));
        stop_single(disabled_handle, disabled_runtime).await;

        let allowlist_port = reserve_tcp_port().await;
        let mut allowlist_plan = compile_plan(allowlist_port, target, "h1", None, "cors-allowlist");
        allowlist_plan.listen.xhttp[0].cors_origins =
            Some(vec!["https://console.example".to_owned()]);
        let (allowlist_runtime, allowlist_handle, _) = start_single(&allowlist_plan).await;
        let allowlist_address = allowlist_handle.local_addr();
        let matched = h1_options_headers(allowlist_address, "HTTPS://Console.Example:443").await;
        assert_eq!(
            matched[ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://console.example"
        );
        assert!(vary_contains(&matched, "Origin"));
        assert_eq!(matched[ACCESS_CONTROL_ALLOW_METHODS], "POST");
        assert_eq!(matched[ACCESS_CONTROL_ALLOW_HEADERS], "X-XHTTP-Session");

        let rejected = h1_options_headers(allowlist_address, "https://other.example").await;
        assert!(!rejected.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(!rejected.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS));
        stop_single(allowlist_handle, allowlist_runtime).await;

        let wildcard_port = reserve_tcp_port().await;
        let mut wildcard_plan =
            compile_plan(wildcard_port, target, "h1", None, "cors-cookie-wildcard");
        wildcard_plan.listen.xhttp[0].cors_origins = Some(vec!["*".to_owned()]);
        wildcard_plan.listen.xhttp[0].settings.session_id_placement = Some("cookie".to_owned());
        let (wildcard_runtime, wildcard_handle, _) = start_single(&wildcard_plan).await;
        let wildcard =
            h1_options_headers(wildcard_handle.local_addr(), "HTTPS://App.Example:443").await;
        assert_eq!(wildcard[ACCESS_CONTROL_ALLOW_ORIGIN], "https://app.example");
        assert_eq!(wildcard[ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
        assert!(vary_contains(&wildcard, "Origin"));
        stop_single(wildcard_handle, wildcard_runtime).await;
    }

    #[tokio::test]
    async fn cleartext_h2c_raw_echo() {
        let echo = spawn_echo_server().await;
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h2", None, "raw-h2c");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();
        let stream = TcpStream::connect(address).await.unwrap();
        let payload = Bytes::from_static(b"raw-h2c-runtime-echo");

        let response = h2_round_trip(stream, address, "http", payload.clone()).await;
        assert_eq!(response, payload);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn tls_h1_raw_echo() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("tls-h1");
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h1", Some(&files), "raw-tls-h1");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();
        let stream = tls_connect(address, &files, b"http/1.1").await;
        let payload = Bytes::from_static(b"raw-tls-h1-runtime-echo");

        let response = h1_round_trip(stream, address, "https", payload.clone()).await;
        assert_eq!(response, payload);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn tls_h2_raw_echo() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("tls-h2");
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h2", Some(&files), "raw-tls-h2");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();
        let stream = tls_connect(address, &files, b"h2").await;
        let payload = Bytes::from_static(b"raw-tls-h2-runtime-echo");

        let response = h2_round_trip(stream, address, "https", payload.clone()).await;
        assert_eq!(response, payload);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn combined_default_tls_alpn_prefers_h2_like_xray() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("tls-default-alpn");
        let port = reserve_tcp_port().await;
        let plan = compile_plan(
            port,
            echo.address,
            "h2, http/1.1",
            Some(&files),
            "raw-tls-default-alpn",
        );
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();
        let stream =
            try_tls_connect_with_alpns(address, &files, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
                .await
                .unwrap();
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "Xray default client offers h2 first and requires an H2 transport"
        );
        let payload = Bytes::from_static(b"default-alpn-h2-echo");
        let response = h2_round_trip(stream, address, "https", payload.clone()).await;
        assert_eq!(response, payload);
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn cleartext_policy_rejects_cross_protocol_and_http10_without_logical_flow() {
        let echo = spawn_echo_server().await;

        let h2_port = reserve_tcp_port().await;
        let h2_plan = compile_plan(h2_port, echo.address, "h2", None, "clear-h2-only");
        let (h2_runtime, h2_handle, _) = start_single(&h2_plan).await;
        let h2_address = h2_handle.local_addr();

        let mut h1 = TcpStream::connect(h2_address).await.unwrap();
        assert_eq!(
            raw_http_status(&mut h1, h2_address, "HTTP/1.1").await,
            Some(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
        );
        assert_no_logical_flow(&h2_runtime).await;
        drop(h1);

        let mut h10 = TcpStream::connect(h2_address).await.unwrap();
        assert_eq!(
            raw_http_status(&mut h10, h2_address, "HTTP/1.0").await,
            Some(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
        );
        assert_no_logical_flow(&h2_runtime).await;
        drop(h10);
        stop_single(h2_handle, h2_runtime).await;

        let h1_port = reserve_tcp_port().await;
        let h1_plan = compile_plan(h1_port, echo.address, "h1", None, "clear-h1-only");
        let (h1_runtime, h1_handle, _) = start_single(&h1_plan).await;
        let h1_address = h1_handle.local_addr();
        let mut h10 = TcpStream::connect(h1_address).await.unwrap();
        assert_eq!(
            raw_http_status(&mut h10, h1_address, "HTTP/1.0").await,
            Some(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
        );
        assert_no_logical_flow(&h1_runtime).await;
        drop(h10);
        let h2 = TcpStream::connect(h1_address).await.unwrap();
        assert_h2_rejected(h2, h1_address, &h1_runtime).await;
        stop_single(h1_handle, h1_runtime).await;
    }

    #[tokio::test]
    async fn tls_h2_policy_requires_alpn_and_rejects_http1_without_logical_flow() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("tls-h2-policy");
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h2", Some(&files), "tls-h2-only");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();

        if let Ok(mut no_alpn) = try_tls_connect_with_alpns(address, &files, Vec::new()).await {
            assert!(no_alpn.get_ref().1.alpn_protocol().is_none());
            assert_ne!(
                raw_http_status(&mut no_alpn, address, "HTTP/1.1").await,
                Some(StatusCode::OK)
            );
            drop(no_alpn);
        }
        assert_no_logical_flow(&runtime).await;

        if let Ok(mut wrong_alpn) =
            try_tls_connect_with_alpns(address, &files, vec![b"http/1.1".to_vec()]).await
        {
            assert!(wrong_alpn.get_ref().1.alpn_protocol().is_none());
            assert_ne!(
                raw_http_status(&mut wrong_alpn, address, "HTTP/1.1").await,
                Some(StatusCode::OK)
            );
            drop(wrong_alpn);
        }
        assert_no_logical_flow(&runtime).await;

        let mut negotiated_h2 = tls_connect(address, &files, b"h2").await;
        assert_eq!(
            negotiated_h2.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );
        assert_eq!(
            raw_http_status(&mut negotiated_h2, address, "HTTP/1.1").await,
            Some(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
        );
        assert_no_logical_flow(&runtime).await;
        drop(negotiated_h2);

        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn tls_http1_policy_rejects_h2_and_http10_without_logical_flow() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("tls-h1-policy");
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h1", Some(&files), "tls-http1-only");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();

        let h2_framing = tls_connect(address, &files, b"http/1.1").await;
        assert_eq!(
            h2_framing.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        assert_h2_rejected(h2_framing, address, &runtime).await;

        let mut h10 = tls_connect(address, &files, b"http/1.1").await;
        assert_eq!(
            raw_http_status(&mut h10, address, "HTTP/1.0").await,
            Some(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
        );
        assert_no_logical_flow(&runtime).await;
        drop(h10);

        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn h3_raw_echo() {
        let echo = spawn_echo_server().await;
        let files = TlsFiles::valid("h3");
        let port = reserve_udp_port().await;
        let plan = compile_plan(port, echo.address, "h3", Some(&files), "raw-h3");
        let (runtime, handle, _) = start_single(&plan).await;
        let address = handle.local_addr();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(files.cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let connection = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver_task = tokio::spawn(async move { driver.wait_idle().await });
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost{TEST_PATH}"))
            .header(HOST, "localhost")
            .header("referer", "https://localhost/runtime/?x_padding=XXXX")
            .body(())
            .unwrap();
        let payload = Bytes::from_static(b"raw-h3-runtime-echo");
        let mut stream = sender.send_request(request).await.unwrap();
        stream.send_data(payload.clone()).await.unwrap();
        stream.finish().await.unwrap();
        let response = timeout(TEST_TIMEOUT, stream.recv_response())
            .await
            .expect("HTTP/3 response timeout")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut echoed = Vec::new();
        while let Some(mut data) = timeout(TEST_TIMEOUT, stream.recv_data())
            .await
            .expect("HTTP/3 response body timeout")
            .unwrap()
        {
            let remaining = data.remaining();
            echoed.extend_from_slice(&data.copy_to_bytes(remaining));
        }
        assert_eq!(echoed, payload);

        connection.close(quinn::VarInt::from_u32(0), b"test complete");
        endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        driver_task.abort();
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn h3_transport_uses_configured_http_idle_timeout() {
        let files = TlsFiles::valid("h3-idle-timeout");
        let port = reserve_udp_port().await;
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut plan = compile_plan(port, target, "h3", Some(&files), "h3-idle-timeout");
        plan.listen.xhttp[0].http_idle_timeout = Duration::from_millis(150);
        let (runtime, handle, listener_plan) = start_single(&plan).await;
        assert_eq!(listener_plan.http_idle_timeout, Duration::from_millis(150));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(files.cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let connection = endpoint
            .connect(handle.local_addr(), "localhost")
            .unwrap()
            .await
            .unwrap();

        let error = timeout(Duration::from_secs(2), connection.closed())
            .await
            .expect("configured QUIC idle timeout did not close the connection");
        assert_eq!(error, quinn::ConnectionError::TimedOut);

        endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn h3_per_connection_stream_limit_holds_n_plus_one_until_release() {
        let files = TlsFiles::valid("h3-stream-limit");
        let port = reserve_udp_port().await;
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut plan = compile_plan(port, target, "h3", Some(&files), "h3-stream-limit");
        plan.listen.xhttp[0].max_concurrent_streams = 1;
        plan.listen.xhttp[0].max_active_http_streams = 4;
        let (runtime, handle, listener_plan) = start_single(&plan).await;
        assert_eq!(listener_plan.max_concurrent_streams, 1);
        assert_eq!(listener_plan.max_active_http_streams, 4);

        let mut roots = rustls::RootCertStore::empty();
        roots.add(files.cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let connection = endpoint
            .connect(handle.local_addr(), "localhost")
            .unwrap()
            .await
            .unwrap();

        let (mut first_send, mut first_recv) = connection.open_bi().await.unwrap();
        let second_connection = connection.clone();
        let second = tokio::spawn(async move { second_connection.open_bi().await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !second.is_finished(),
            "max-concurrent-streams=1 admitted a second HTTP/3 bidi stream"
        );

        let reset_code = quinn::VarInt::from_u32(0x10);
        let _ = first_send.reset(reset_code);
        let _ = first_recv.stop(reset_code);
        drop(first_send);
        drop(first_recv);
        let (mut second_send, mut second_recv) = timeout(TEST_TIMEOUT, second)
            .await
            .expect("second HTTP/3 bidi stream was not released")
            .expect("second HTTP/3 open task panicked")
            .expect("second HTTP/3 bidi stream failed");
        let _ = second_send.reset(reset_code);
        let _ = second_recv.stop(reset_code);

        connection.close(quinn::VarInt::from_u32(0), b"test complete");
        endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
        stop_single(handle, runtime).await;
    }

    #[tokio::test]
    async fn duplicate_listener_port_fails_transactionally_during_startup() {
        let port = reserve_tcp_port().await;
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let plan = compile_plan(port, target, "h1", None, "first");
        let runtime = Arc::new(Runtime::build(plan.clone()).unwrap());
        let first = plan.listen.xhttp[0].clone();
        let mut duplicate = first.clone();
        duplicate.tag = "duplicate".into();

        let error = start_xhttp_listeners(&[first, duplicate], Arc::clone(&runtime))
            .await
            .err()
            .expect("duplicate XHTTP port must fail startup");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("duplicate"));

        let rebound = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("transactional rollback must release first listener");
        drop(rebound);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_validation_defends_relay_limit_and_non_loopback_raw_bind() {
        let port = reserve_tcp_port().await;
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let plan = compile_plan(port, target, "h1", None, "runtime-defense");
        let base = plan.listen.xhttp[0].clone();

        let mut zero_relays = base.clone();
        zero_relays.max_active_relays = 0;
        let error = validate_runtime_plan(&zero_relays)
            .expect_err("max-active-relays=0 must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("max-active-relays"));

        let mut zero_connections = base.clone();
        zero_connections.max_active_connections = 0;
        let error = validate_runtime_plan(&zero_connections)
            .expect_err("max-active-connections=0 must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("max-active-connections"));

        let mut excessive_connections = base.clone();
        excessive_connections.max_active_connections = XHTTP_MAX_ACTIVE_CONNECTIONS + 1;
        let error = validate_runtime_plan(&excessive_connections)
            .expect_err("excessive max-active-connections must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("must not exceed"));

        let mut zero_concurrent_streams = base.clone();
        zero_concurrent_streams.max_concurrent_streams = 0;
        let error = validate_runtime_plan(&zero_concurrent_streams)
            .expect_err("max-concurrent-streams=0 must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("max-concurrent-streams"));

        let mut excessive_concurrent_streams = base.clone();
        excessive_concurrent_streams.max_concurrent_streams = XHTTP_MAX_CONCURRENT_STREAMS + 1;
        let error = validate_runtime_plan(&excessive_concurrent_streams)
            .expect_err("excessive max-concurrent-streams must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("must not exceed"));

        let mut zero_active_http_streams = base.clone();
        zero_active_http_streams.max_active_http_streams = 0;
        let error = validate_runtime_plan(&zero_active_http_streams)
            .expect_err("max-active-http-streams=0 must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("max-active-http-streams"));

        let mut excessive_active_http_streams = base.clone();
        excessive_active_http_streams.max_active_http_streams = XHTTP_MAX_ACTIVE_HTTP_STREAMS + 1;
        let error = validate_runtime_plan(&excessive_active_http_streams)
            .expect_err("excessive max-active-http-streams must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("must not exceed"));

        let mut zero_idle_timeout = base.clone();
        zero_idle_timeout.http_idle_timeout = Duration::ZERO;
        let error = validate_runtime_plan(&zero_idle_timeout)
            .expect_err("http-idle-timeout=0 must be rejected at runtime");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("http-idle-timeout"));

        let mut public_raw = base;
        public_raw.address = "0.0.0.0".to_owned();
        public_raw.allow_unauthenticated_non_loopback = false;
        let error = validate_runtime_plan(&public_raw)
            .expect_err("unauthenticated non-loopback Raw bind must require explicit opt-in");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("allow-unauthenticated-non-loopback=true")
        );

        public_raw.allow_unauthenticated_non_loopback = true;
        validate_runtime_plan(&public_raw)
            .expect("explicit non-loopback unauthenticated opt-in should pass runtime validation");
    }

    #[tokio::test]
    async fn bad_certificate_and_invalid_alpn_fail_before_background_start() {
        let files = TlsFiles::invalid("invalid");
        let port = reserve_tcp_port().await;
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let plan = compile_plan(port, target, "h1", Some(&files), "bad-cert");
        let runtime = Arc::new(Runtime::build(plan.clone()).unwrap());
        let error = start_xhttp_listener(&plan.listen.xhttp[0], Arc::clone(&runtime))
            .await
            .err()
            .expect("bad certificate must fail startup");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("certificate"));

        let mut invalid_alpn = plan.listen.xhttp[0].clone();
        invalid_alpn.cleartext = true;
        invalid_alpn.tls = None;
        invalid_alpn.alpn.clear();
        let error = start_xhttp_listener(&invalid_alpn, Arc::clone(&runtime))
            .await
            .err()
            .expect("empty ALPN must fail before bind");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("ALPN"));
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn handle_shutdown_cancels_active_listener_and_logical_relay() {
        let echo = spawn_echo_server().await;
        let port = reserve_tcp_port().await;
        let plan = compile_plan(port, echo.address, "h1", None, "shutdown");
        let (runtime, mut handle, _) = start_single(&plan).await;
        let address = handle.local_addr();
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!(
                    "POST {TEST_PATH} HTTP/1.1\r\nHost: localhost:{}\r\n\
                     Referer: http://localhost/runtime/?x_padding=XXXX\r\n\
                     Transfer-Encoding: chunked\r\n\r\n4\r\nping\r\n",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.flush().await.unwrap();

        timeout(TEST_TIMEOUT, async {
            loop {
                if !runtime.connections.list().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("logical relay was not registered");
        timeout(TEST_TIMEOUT, handle.shutdown())
            .await
            .expect("listener shutdown timeout")
            .expect("listener shutdown");
        assert!(runtime.connections.list().is_empty());
        assert!(
            TcpStream::connect(address).await.is_err(),
            "listener still accepts TCP after structured shutdown"
        );
        runtime.shutdown().await;
    }
}
