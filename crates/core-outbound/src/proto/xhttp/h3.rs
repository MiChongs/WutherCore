//! XHTTP 的 HTTP/3 客户端。
//!
//! 该实现使用 Quinn + `h3`/`h3-quinn` 建立真实 QUIC/H3 连接；请求流的
//! send/recv half 独立驱动，因此 `stream-one` 可以同时上传和下载。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use h3::error::Code;
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, IdleTimeout, TransportConfig, VarInt,
    crypto::rustls::QuicClientConfig,
};
use tokio::sync::mpsc;

use super::{
    conn::{IoFailure, IoState, ResponseReader},
    xmux::ManagedConnection,
};
use crate::{
    adapter::{prepare_outbound_udp_socket_for_addr, resolve_host},
    loopback::LoopbackUdpGuard,
    transport::{TlsOptions, ech::resolve_ech_config, tls::build_tls_client_config},
};

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

const H3_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum CancelRace<T> {
    Completed(T),
    Cancelled,
}

pub(crate) struct H3Client {
    endpoint: Endpoint,
    connection: quinn::Connection,
    sender: H3SendRequest,
    closed: Arc<AtomicBool>,
    _loopback_guard: LoopbackUdpGuard,
}

impl H3Client {
    pub(crate) async fn connect_with_tls_options(
        host: &str,
        port: u16,
        mut tls_options: TlsOptions,
        keep_alive: Option<Duration>,
    ) -> io::Result<Self> {
        let server_name = tls_options
            .sni
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(host)
            .to_owned();
        tls_options.resolved_ech_config_list = resolve_ech_config(&tls_options, host).await?;
        let tls = build_h3_tls_config(&tls_options)?;

        let quic_crypto = QuicClientConfig::try_from(tls)
            .map_err(|error| io_err(format!("xhttp h3 QUIC TLS config: {error}")))?;
        let mut quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
        let mut transport = TransportConfig::default();
        // Xray's quic-go path defaults to standard BBR. Quinn defaults to
        // Cubic, so select its BBR controller explicitly for wire/runtime
        // behavior parity rather than inheriting the library default.
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(300))
                .map_err(|error| io_err(format!("xhttp h3 idle timeout: {error}")))?,
        ));
        transport.keep_alive_interval(keep_alive);
        quic_config.transport_config(Arc::new(transport));

        let addresses = resolve_host(host, port).await?;
        let mut last_error = None;

        for address in addresses {
            match connect_one(address, &server_name, quic_config.clone()).await {
                Ok((endpoint, connection, loopback_guard)) => {
                    let h3_connection = h3_quinn::Connection::new(connection.clone());
                    let (mut driver, sender) = with_setup_timeout("handshake", async move {
                        h3::client::new(h3_connection)
                            .await
                            .map_err(|error| io_err(format!("xhttp h3 handshake: {error}")))
                    })
                    .await?;
                    let closed = Arc::new(AtomicBool::new(false));
                    let driver_closed = closed.clone();
                    tokio::spawn(async move {
                        let _ = driver.wait_idle().await;
                        driver_closed.store(true, Ordering::Release);
                    });
                    return Ok(Self {
                        endpoint,
                        connection,
                        sender,
                        closed,
                        _loopback_guard: loopback_guard,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("xhttp h3: no usable address for {host}:{port}"),
            )
        }))
    }

    /// 打开流式请求并返回响应体。`upload` 为 None 时发送空请求体。
    pub(crate) async fn open_stream(
        &self,
        request: http::Request<()>,
        upload: Option<mpsc::Receiver<Bytes>>,
        state: Arc<IoState>,
    ) -> io::Result<ResponseReader> {
        let mut sender = self.sender.clone();
        let stream = match race_cancellation(&state, sender.send_request(request)).await {
            CancelRace::Completed(result) => {
                result.map_err(|error| io_err(format!("xhttp h3 send request: {error}")))?
            }
            CancelRace::Cancelled => {
                return Err(cancelled_error(&state, "xhttp h3 request cancelled"));
            }
        };
        let (mut send, mut recv) = stream.split();

        if let Some(mut upload) = upload {
            let upload_state = state.clone();
            tokio::spawn(async move {
                loop {
                    if upload_state.is_cancelled() {
                        send.stop_stream(Code::H3_REQUEST_CANCELLED);
                        return;
                    }
                    let item = match upload.try_recv() {
                        Ok(data) => Some(data),
                        Err(mpsc::error::TryRecvError::Disconnected) => None,
                        Err(mpsc::error::TryRecvError::Empty) => {
                            match race_cancellation(&upload_state, upload.recv()).await {
                                CancelRace::Completed(item) => item,
                                CancelRace::Cancelled => {
                                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                    return;
                                }
                            }
                        }
                    };
                    match item {
                        Some(data) => {
                            if upload_state.is_cancelled() {
                                send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                            match race_cancellation(&upload_state, send.send_data(data)).await {
                                CancelRace::Completed(Ok(())) => {}
                                CancelRace::Completed(Err(error)) => {
                                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                    upload_state.fail(IoFailure::other(format!(
                                        "xhttp h3 upload body: {error}"
                                    )));
                                    return;
                                }
                                CancelRace::Cancelled => {
                                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                    return;
                                }
                            }
                        }
                        None => {
                            if upload_state.is_cancelled() {
                                send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                            match race_cancellation(&upload_state, send.finish()).await {
                                CancelRace::Completed(Ok(())) => {}
                                CancelRace::Completed(Err(error)) => {
                                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                    upload_state.fail(IoFailure::other(format!(
                                        "xhttp h3 finish upload: {error}"
                                    )));
                                }
                                CancelRace::Cancelled => {
                                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                                }
                            }
                            return;
                        }
                    }
                }
            });
        } else {
            match race_cancellation(&state, send.finish()).await {
                CancelRace::Completed(Ok(())) => {}
                CancelRace::Completed(Err(error)) => {
                    return Err(io_err(format!("xhttp h3 finish request: {error}")));
                }
                CancelRace::Cancelled => {
                    send.stop_stream(Code::H3_REQUEST_CANCELLED);
                    recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return Err(cancelled_error(&state, "xhttp h3 request cancelled"));
                }
            }
        }

        let (reader, body_tx) = ResponseReader::channel(8, state.clone());
        tokio::spawn(async move {
            if state.is_cancelled() {
                recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                return;
            }
            let response = match race_cancellation(&state, recv.recv_response()).await {
                CancelRace::Completed(response) => response,
                CancelRace::Cancelled => {
                    recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return;
                }
            };
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    let failure = IoFailure::other(format!("xhttp h3 response headers: {error}"));
                    recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                    state.fail(failure.clone());
                    let _ = body_tx.try_send(Err(failure));
                    return;
                }
            };
            if response.status() != http::StatusCode::OK {
                let failure =
                    IoFailure::other(format!("xhttp h3 unexpected status {}", response.status()));
                recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                state.fail(failure.clone());
                let _ = body_tx.try_send(Err(failure));
                return;
            }

            loop {
                if state.is_cancelled() {
                    recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return;
                }
                let item = match race_cancellation(&state, recv.recv_data()).await {
                    CancelRace::Completed(item) => item,
                    CancelRace::Cancelled => {
                        recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                        return;
                    }
                };
                match item {
                    Ok(Some(mut data)) => {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if bytes.is_empty() {
                            continue;
                        }
                        match race_cancellation(&state, body_tx.send(Ok(bytes))).await {
                            CancelRace::Completed(Ok(())) => {}
                            CancelRace::Completed(Err(_)) => {
                                state.cancel();
                                recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                            CancelRace::Cancelled => {
                                recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let failure = IoFailure::other(format!("xhttp h3 response body: {error}"));
                        recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                        state.fail(failure.clone());
                        let _ = body_tx.try_send(Err(failure));
                        return;
                    }
                }
            }
        });
        Ok(reader)
    }

    /// 发送 packet-up 的一次性请求并完整消费响应。
    pub(crate) async fn post_packet(
        &self,
        request: http::Request<()>,
        body: Bytes,
        state: Arc<IoState>,
    ) -> io::Result<()> {
        let mut sender = self.sender.clone();
        let mut stream = match race_cancellation(&state, sender.send_request(request)).await {
            CancelRace::Completed(result) => {
                result.map_err(|error| io_err(format!("xhttp h3 packet request: {error}")))?
            }
            CancelRace::Cancelled => {
                return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
            }
        };
        if !body.is_empty() {
            match race_cancellation(&state, stream.send_data(body)).await {
                CancelRace::Completed(Ok(())) => {}
                CancelRace::Completed(Err(error)) => {
                    return Err(io_err(format!("xhttp h3 packet body: {error}")));
                }
                CancelRace::Cancelled => {
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
                }
            }
        }
        match race_cancellation(&state, stream.finish()).await {
            CancelRace::Completed(Ok(())) => {}
            CancelRace::Completed(Err(error)) => {
                return Err(io_err(format!("xhttp h3 finish packet: {error}")));
            }
            CancelRace::Cancelled => {
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
            }
        }

        let response = match race_cancellation(&state, stream.recv_response()).await {
            CancelRace::Completed(response) => {
                response.map_err(|error| io_err(format!("xhttp h3 packet response: {error}")))?
            }
            CancelRace::Cancelled => {
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
            }
        };
        if response.status() != http::StatusCode::OK {
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            return Err(io_err(format!(
                "xhttp h3 packet unexpected status {}",
                response.status()
            )));
        }
        loop {
            if state.is_cancelled() {
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
            }
            let item = match race_cancellation(&state, stream.recv_data()).await {
                CancelRace::Completed(item) => item,
                CancelRace::Cancelled => {
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return Err(cancelled_error(&state, "xhttp h3 packet upload cancelled"));
                }
            };
            match item {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(error) => {
                    return Err(io_err(format!("xhttp h3 packet response body: {error}")));
                }
            }
        }
    }
}

fn build_h3_tls_config(options: &TlsOptions) -> io::Result<rustls::ClientConfig> {
    if options.alpn != ["h3"] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "xhttp H3 requires the sole ALPN value h3, got {:?}",
                options.alpn
            ),
        ));
    }
    build_tls_client_config(options)
}

async fn race_cancellation<T>(
    state: &IoState,
    operation: impl Future<Output = T>,
) -> CancelRace<T> {
    if state.is_cancelled() {
        return CancelRace::Cancelled;
    }
    tokio::select! {
        biased;
        _ = state.cancelled() => CancelRace::Cancelled,
        output = operation => CancelRace::Completed(output),
    }
}

fn cancelled_error(state: &IoState, fallback: &'static str) -> io::Error {
    state
        .error()
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::Interrupted, fallback))
}

async fn with_setup_timeout<T>(
    stage: &'static str,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    with_timeout(stage, H3_SETUP_TIMEOUT, operation).await
}

async fn with_timeout<T>(
    stage: &'static str,
    duration: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("xhttp h3 {stage} timed out after {duration:?}"),
        )),
    }
}

impl ManagedConnection for H3Client {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.connection.close_reason().is_some()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.connection
            .close(VarInt::from_u32(0), b"xhttp XMUX connection retired");
        self.endpoint
            .close(VarInt::from_u32(0), b"xhttp XMUX endpoint retired");
    }
}

async fn connect_one(
    address: SocketAddr,
    server_name: &str,
    config: QuinnClientConfig,
) -> io::Result<(Endpoint, quinn::Connection, LoopbackUdpGuard)> {
    let bind_address: SocketAddr = if address.is_ipv6() {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    };
    let socket = std::net::UdpSocket::bind(bind_address)?;
    let loopback_guard = prepare_outbound_udp_socket_for_addr(&socket, address)?;
    socket.set_nonblocking(true)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|error| io_err(format!("xhttp h3 endpoint: {error}")))?;
    endpoint.set_default_client_config(config);
    let connecting = endpoint
        .connect(address, server_name)
        .map_err(|error| io_err(format!("xhttp h3 connect setup: {error}")))?;
    let connection = with_setup_timeout("QUIC connect", async move {
        connecting
            .await
            .map_err(|error| io_err(format!("xhttp h3 connect {address}: {error}")))
    })
    .await?;
    Ok((endpoint, connection, loopback_guard))
}

fn io_err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::sync::Notify;

    use super::*;

    #[test]
    fn h3_session_resumption_is_disabled_unless_explicitly_enabled() {
        let disabled = build_h3_tls_config(&TlsOptions {
            alpn: vec!["h3".into()],
            ..Default::default()
        })
        .unwrap();
        let enabled = build_h3_tls_config(&TlsOptions {
            alpn: vec!["h3".into()],
            enable_session_resumption: true,
            ..Default::default()
        })
        .unwrap();

        let disabled = format!("{:?}", disabled.resumption);
        let enabled = format!("{:?}", enabled.resumption);
        assert!(disabled.contains("NoClientSessionStorage"));
        assert!(disabled.contains("Disabled"));
        assert!(enabled.contains("ClientSessionMemoryCache"));
    }

    struct PendingProbe {
        polled: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }

    impl Future for PendingProbe {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polled.notify_one();
            Poll::Pending
        }
    }

    impl Drop for PendingProbe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct PanicOnPoll;

    impl Future for PanicOnPoll {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("cancelled operation must not be polled");
        }
    }

    #[tokio::test]
    async fn already_cancelled_state_does_not_poll_operation() {
        let state = IoState::shared();
        state.cancel();

        assert!(matches!(
            race_cancellation(&state, PanicOnPoll).await,
            CancelRace::Cancelled
        ));
    }

    #[tokio::test]
    async fn cancellation_drops_pending_operation_before_return() {
        let state = IoState::shared();
        let polled = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let task = {
            let state = state.clone();
            let polled = polled.clone();
            let dropped = dropped.clone();
            tokio::spawn(async move {
                let outcome = race_cancellation(&state, PendingProbe { polled, dropped }).await;
                assert!(matches!(outcome, CancelRace::Cancelled));
            })
        };

        polled.notified().await;
        state.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancellation race did not finish")
            .expect("cancellation task panicked");
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn setup_timeout_is_timed_out_and_drops_operation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = with_timeout(
            "test setup",
            Duration::ZERO,
            PendingProbe {
                polled: Arc::new(Notify::new()),
                dropped: dropped.clone(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("test setup"));
        assert!(dropped.load(Ordering::Acquire));
    }
}
