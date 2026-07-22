use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::buffer::SliceReader;
use crate::donor::{
    CipherSuite, RealityServerConnection, RealityServerCryptoConfig, extract_server_cipher_suite,
    extract_server_key_share, mldsa65_verify_from_seed,
};
use crate::framing::{ClientHelloLimits, read_client_hello_forwarded};

const X25519: u16 = 0x001d;
const X25519_MLKEM768: u16 = 0x11ec;
const MAX_TLS13_RECORD: usize = 16_640;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProxyProtocolVersion {
    #[default]
    None,
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_second: u64,
    pub burst_bytes: u64,
}

impl FallbackLimit {
    fn validate(self) -> Result<(), RealityServerError> {
        if self.bytes_per_second == 0 && (self.after_bytes != 0 || self.burst_bytes != 0) {
            return Err(RealityServerError::Configuration(
                "fallback after/burst requires a non-zero byte rate".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RealityServerLimits {
    pub client_hello: ClientHelloLimits,
    pub handshake_timeout: Duration,
    pub target_handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_target_records: usize,
    pub max_target_handshake_bytes: usize,
    pub application_buffer_bytes: usize,
    pub max_concurrent_handshakes: usize,
}

impl Default for RealityServerLimits {
    fn default() -> Self {
        Self {
            client_hello: ClientHelloLimits::default(),
            handshake_timeout: Duration::from_secs(10),
            target_handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
            max_target_records: 12,
            max_target_handshake_bytes: 96 * 1024,
            application_buffer_bytes: 256 * 1024,
            max_concurrent_handshakes: 1024,
        }
    }
}

#[derive(Clone)]
pub struct RealityServerConfig {
    pub camouflage_target: String,
    pub private_key: [u8; 32],
    pub server_names: HashSet<String>,
    pub short_ids: Vec<[u8; 8]>,
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub max_time_difference: Option<Duration>,
    pub mldsa65_seed: Option<[u8; 32]>,
    pub cipher_suites: Vec<CipherSuite>,
    pub proxy_protocol: ProxyProtocolVersion,
    pub fallback_upload: FallbackLimit,
    pub fallback_download: FallbackLimit,
    pub limits: RealityServerLimits,
}

impl fmt::Debug for RealityServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerConfig")
            .field("camouflage_target", &self.camouflage_target)
            .field("private_key", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("short_id_count", &self.short_ids.len())
            .field("min_client_version", &self.min_client_version)
            .field("max_client_version", &self.max_client_version)
            .field("max_time_difference", &self.max_time_difference)
            .field("has_mldsa65_seed", &self.mldsa65_seed.is_some())
            .field("cipher_suites", &self.cipher_suites)
            .field("proxy_protocol", &self.proxy_protocol)
            .field("fallback_upload", &self.fallback_upload)
            .field("fallback_download", &self.fallback_download)
            .field("limits", &self.limits)
            .finish()
    }
}

impl Drop for RealityServerConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.short_ids.zeroize();
        if let Some(seed) = &mut self.mldsa65_seed {
            seed.zeroize();
        }
    }
}

impl RealityServerConfig {
    fn validate(&self) -> Result<(), RealityServerError> {
        if self.camouflage_target.trim().is_empty() {
            return Err(RealityServerError::Configuration(
                "camouflage target is empty".into(),
            ));
        }
        if self.private_key.iter().all(|byte| *byte == 0) {
            return Err(RealityServerError::Configuration(
                "X25519 private key is all zero".into(),
            ));
        }
        if self.server_names.is_empty() || self.server_names.iter().any(|name| name.is_empty()) {
            return Err(RealityServerError::Configuration(
                "serverNames must not be empty".into(),
            ));
        }
        if self.short_ids.is_empty() {
            return Err(RealityServerError::Configuration(
                "shortIds must not be empty".into(),
            ));
        }
        if let (Some(min), Some(max)) = (self.min_client_version, self.max_client_version)
            && min > max
        {
            return Err(RealityServerError::Configuration(
                "minimum client version exceeds maximum".into(),
            ));
        }
        if self.mldsa65_seed.as_ref() == Some(&self.private_key) {
            return Err(RealityServerError::Configuration(
                "ML-DSA-65 seed must differ from the X25519 private key".into(),
            ));
        }
        if self.limits.handshake_timeout.is_zero()
            || self.limits.target_handshake_timeout.is_zero()
            || self.limits.idle_timeout.is_zero()
            || self.limits.max_target_records < 3
            || self.limits.max_target_handshake_bytes < 1024
            || self.limits.application_buffer_bytes == 0
            || self.limits.max_concurrent_handshakes == 0
        {
            return Err(RealityServerError::Configuration(
                "invalid REALITY resource limits".into(),
            ));
        }
        let hello = self.limits.client_hello;
        if hello.max_records == 0
            || hello.max_record_payload == 0
            || hello.max_record_payload > MAX_TLS13_RECORD
            || hello.max_handshake_bytes < 4
            || hello.max_handshake_bytes > u16::MAX as usize
            || hello.max_wire_bytes < 5
        {
            return Err(RealityServerError::Configuration(
                "invalid ClientHello resource limits".into(),
            ));
        }
        self.fallback_upload.validate()?;
        self.fallback_download.validate()?;
        if let Some(seed) = &self.mldsa65_seed {
            mldsa65_verify_from_seed(seed).map_err(RealityServerError::Io)?;
        }
        Ok(())
    }

    /// Derive the base64-ready 1,952-byte verification key for clients.
    pub fn mldsa65_verify_key(&self) -> Result<Option<Vec<u8>>, RealityServerError> {
        self.mldsa65_seed
            .as_ref()
            .map(mldsa65_verify_from_seed)
            .transpose()
            .map_err(RealityServerError::Io)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealityServerError {
    #[error("REALITY configuration error: {0}")]
    Configuration(String),
    #[error("REALITY I/O error: {0}")]
    Io(#[source] io::Error),
    #[error("REALITY connection cancelled")]
    Cancelled,
    #[error("REALITY handshake timed out")]
    HandshakeTimeout,
    #[error("REALITY camouflage fallback started: {reason}")]
    FallbackStarted { reason: String },
}

impl From<io::Error> for RealityServerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone)]
pub struct RealityServer {
    config: Arc<RealityServerConfig>,
    handshakes: Arc<Semaphore>,
}

impl RealityServer {
    pub fn new(config: RealityServerConfig) -> Result<Self, RealityServerError> {
        config.validate()?;
        let max = config.limits.max_concurrent_handshakes;
        Ok(Self {
            config: Arc::new(config),
            handshakes: Arc::new(Semaphore::new(max)),
        })
    }

    pub fn config(&self) -> &RealityServerConfig {
        &self.config
    }

    /// Accept a generic inbound stream and dial the configured camouflage TCP target.
    pub async fn accept<S>(
        &self,
        client: S,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        cancellation: CancellationToken,
    ) -> Result<AcceptedRealityStream, RealityServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let permit = self.acquire_permit(&cancellation).await?;
        let connect = TcpStream::connect(&self.config.camouflage_target);
        let target = tokio::select! {
            _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
            result = tokio::time::timeout(self.config.limits.target_handshake_timeout, connect) => {
                result.map_err(|_| RealityServerError::HandshakeTimeout)??
            }
        };
        self.accept_with_target_inner(client, target, peer_addr, local_addr, cancellation, permit)
            .await
    }

    /// Accept a generic inbound stream using an already connected camouflage stream.
    /// This is the protocol-neutral API used by inbounds and deterministic tests.
    pub async fn accept_with_target<S, T>(
        &self,
        client: S,
        target: T,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        cancellation: CancellationToken,
    ) -> Result<AcceptedRealityStream, RealityServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let permit = self.acquire_permit(&cancellation).await?;
        self.accept_with_target_inner(client, target, peer_addr, local_addr, cancellation, permit)
            .await
    }

    async fn acquire_permit(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<OwnedSemaphorePermit, RealityServerError> {
        let permit = tokio::select! {
            _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
            permit = self.handshakes.clone().acquire_owned() => permit.map_err(|_| RealityServerError::Cancelled)?,
        };
        Ok(permit)
    }

    async fn accept_with_target_inner<S, T>(
        &self,
        mut client: S,
        mut target: T,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        cancellation: CancellationToken,
        permit: OwnedSemaphorePermit,
    ) -> Result<AcceptedRealityStream, RealityServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let proxy_header = write_proxy_header(
            &mut target,
            self.config.proxy_protocol,
            peer_addr,
            local_addr,
        );
        tokio::select! {
            _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
            result = tokio::time::timeout(self.config.limits.target_handshake_timeout, proxy_header) => {
                result.map_err(|_| RealityServerError::HandshakeTimeout)??;
            }
        }

        let mut recorded = Vec::new();
        let mut forwarded = 0usize;
        let hello_result = {
            let mut recording = RecordingRead::new(&mut client, &mut recorded);
            tokio::select! {
                _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
                result = tokio::time::timeout(
                    self.config.limits.handshake_timeout,
                    read_client_hello_forwarded(
                        &mut recording,
                        &mut target,
                        self.config.limits.client_hello,
                        &mut forwarded,
                    ),
                ) => result,
            }
        };

        let hello = match hello_result {
            Err(_) => {
                let forward = forward_recorded_suffix(&mut target, &recorded, forwarded);
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
                    result = tokio::time::timeout(self.config.limits.target_handshake_timeout, forward) => {
                        result.map_err(|_| RealityServerError::HandshakeTimeout)??;
                    }
                }
                self.start_fallback(
                    client,
                    target,
                    Vec::new(),
                    permit,
                    cancellation,
                    "ClientHello timeout".to_owned(),
                );
                return Err(RealityServerError::FallbackStarted {
                    reason: "ClientHello timeout".into(),
                });
            }
            Ok(Err(error)) => {
                let forward = forward_recorded_suffix(&mut target, &recorded, forwarded);
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
                    result = tokio::time::timeout(self.config.limits.target_handshake_timeout, forward) => {
                        result.map_err(|_| RealityServerError::HandshakeTimeout)??;
                    }
                }
                let reason = format!("invalid ClientHello: {error}");
                self.start_fallback(
                    client,
                    target,
                    Vec::new(),
                    permit,
                    cancellation,
                    reason.clone(),
                );
                return Err(RealityServerError::FallbackStarted { reason });
            }
            Ok(Ok(hello)) => hello,
        };

        tokio::select! {
            _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
            result = tokio::time::timeout(self.config.limits.target_handshake_timeout, target.flush()) => {
                result.map_err(|_| RealityServerError::HandshakeTimeout)??;
            }
        }

        if !hello.supports_tls13() {
            return self.fallback(
                client,
                target,
                permit,
                cancellation,
                "client does not support TLS 1.3",
            );
        }
        if !self.config.server_names.contains(hello.server_name()) {
            return self.fallback(
                client,
                target,
                permit,
                cancellation,
                "SNI is not authorized",
            );
        }

        let canonical = match hello.canonical_record() {
            Ok(record) => record,
            Err(error) => {
                return self.fallback(client, target, permit, cancellation, error.to_string());
            }
        };
        let mut crypto = RealityServerConnection::new(RealityServerCryptoConfig {
            private_key: self.config.private_key,
            short_ids: self.config.short_ids.clone(),
            certificate_server_name: hello.server_name().to_owned(),
            max_time_diff: self.config.max_time_difference,
            min_client_version: self.config.min_client_version,
            max_client_version: self.config.max_client_version,
            cipher_suites: self.config.cipher_suites.clone(),
            mldsa65_seed: self.config.mldsa65_seed,
        })?;

        if let Err(error) = crypto.validate_client_hello(&canonical) {
            return self.fallback(
                client,
                target,
                permit,
                cancellation,
                format!("authentication rejected: {error}"),
            );
        }

        let target_records =
            match collect_target_template(&mut target, &self.config.limits, &cancellation).await {
                Ok(records) => records,
                Err((records, error)) => {
                    if cancellation.is_cancelled() {
                        return Err(RealityServerError::Cancelled);
                    }
                    let reason = format!("camouflage target handshake unusable: {error}");
                    self.start_fallback(
                        client,
                        target,
                        records,
                        permit,
                        cancellation,
                        reason.clone(),
                    );
                    return Err(RealityServerError::FallbackStarted { reason });
                }
            };

        if let Err(error) = crypto.build_server_response(target_records.clone()) {
            let reason = format!("failed to mirror camouflage handshake: {error}");
            self.start_fallback(
                client,
                target,
                target_records,
                permit,
                cancellation,
                reason.clone(),
            );
            return Err(RealityServerError::FallbackStarted { reason });
        }
        drop(target);

        let handshake = perform_crypto_handshake(&mut client, &mut crypto, &cancellation);
        tokio::select! {
            _ = cancellation.cancelled() => return Err(RealityServerError::Cancelled),
            result = tokio::time::timeout(self.config.limits.handshake_timeout, handshake) => {
                result.map_err(|_| RealityServerError::HandshakeTimeout)??;
            }
        }

        let authenticated = crypto.authenticated_client().ok_or_else(|| {
            RealityServerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "authenticated metadata missing",
            ))
        })?;
        let negotiated_group = crypto.negotiated_group().unwrap_or(X25519);
        let (application, pump_side) =
            tokio::io::duplex(self.config.limits.application_buffer_bytes);
        let idle_timeout = self.config.limits.idle_timeout;
        tokio::spawn(run_crypto_pump(
            client,
            pump_side,
            crypto,
            cancellation,
            idle_timeout,
            permit,
        ));

        Ok(AcceptedRealityStream {
            stream: application,
            server_name: hello.server_name().to_owned(),
            client_version: authenticated.version,
            short_id: authenticated.short_id,
            hybrid_key_exchange: negotiated_group == X25519_MLKEM768,
            mldsa65: self.config.mldsa65_seed.is_some(),
        })
    }

    fn fallback<S, T, R>(
        &self,
        client: S,
        target: T,
        permit: OwnedSemaphorePermit,
        cancellation: CancellationToken,
        reason: R,
    ) -> Result<AcceptedRealityStream, RealityServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        R: Into<String>,
    {
        let reason = reason.into();
        self.start_fallback(
            client,
            target,
            Vec::new(),
            permit,
            cancellation,
            reason.clone(),
        );
        Err(RealityServerError::FallbackStarted { reason })
    }

    fn start_fallback<S, T>(
        &self,
        client: S,
        target: T,
        target_prefix: Vec<Bytes>,
        permit: OwnedSemaphorePermit,
        cancellation: CancellationToken,
        reason: String,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let policy = FallbackPolicy {
            upload: self.config.fallback_upload,
            download: self.config.fallback_download,
            idle_timeout: self.config.limits.idle_timeout,
        };
        tokio::spawn(async move {
            tracing::debug!(%reason, "REALITY transparent fallback started");
            run_fallback(client, target, target_prefix, policy, cancellation, permit).await;
        });
    }
}

#[derive(Clone, Copy)]
struct FallbackPolicy {
    upload: FallbackLimit,
    download: FallbackLimit,
    idle_timeout: Duration,
}

async fn forward_recorded_suffix<W: AsyncWrite + Unpin + ?Sized>(
    target: &mut W,
    recorded: &[u8],
    forwarded: usize,
) -> io::Result<()> {
    let suffix = recorded.get(forwarded..).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "forwarded ClientHello byte count overflow",
        )
    })?;
    if !suffix.is_empty() {
        target.write_all(suffix).await?;
    }
    target.flush().await
}

pub struct AcceptedRealityStream {
    stream: DuplexStream,
    server_name: String,
    client_version: [u8; 3],
    short_id: [u8; 8],
    hybrid_key_exchange: bool,
    mldsa65: bool,
}

impl AcceptedRealityStream {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    pub fn client_version(&self) -> [u8; 3] {
        self.client_version
    }
    pub fn short_id(&self) -> [u8; 8] {
        self.short_id
    }
    pub fn used_hybrid_key_exchange(&self) -> bool {
        self.hybrid_key_exchange
    }
    pub fn used_mldsa65(&self) -> bool {
        self.mldsa65
    }
}

impl Drop for AcceptedRealityStream {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
}

impl AsyncRead for AcceptedRealityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AcceptedRealityStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct RecordingRead<'a, S> {
    inner: &'a mut S,
    recorded: &'a mut Vec<u8>,
}

impl<'a, S> RecordingRead<'a, S> {
    fn new(inner: &'a mut S, recorded: &'a mut Vec<u8>) -> Self {
        Self { inner, recorded }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingRead<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.recorded.extend_from_slice(&buf.filled()[before..]);
        }
        result
    }
}

async fn write_proxy_header<W: AsyncWrite + Unpin + ?Sized>(
    target: &mut W,
    version: ProxyProtocolVersion,
    source: SocketAddr,
    destination: SocketAddr,
) -> io::Result<()> {
    let header = proxy_header(version, source, destination)?;
    if !header.is_empty() {
        target.write_all(&header).await?;
    }
    Ok(())
}

fn proxy_header(
    version: ProxyProtocolVersion,
    source: SocketAddr,
    destination: SocketAddr,
) -> io::Result<Vec<u8>> {
    match version {
        ProxyProtocolVersion::None => Ok(Vec::new()),
        ProxyProtocolVersion::V1 => match (source.ip(), destination.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(format!(
                "PROXY TCP4 {src} {dst} {} {}\r\n",
                source.port(),
                destination.port()
            )
            .into_bytes()),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(format!(
                "PROXY TCP6 {src} {dst} {} {}\r\n",
                source.port(),
                destination.port()
            )
            .into_bytes()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXY protocol source and destination address families differ",
            )),
        },
        ProxyProtocolVersion::V2 => {
            let mut out = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            out.push(0x21);
            match (source.ip(), destination.ip()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    out.push(0x11);
                    out.extend_from_slice(&12u16.to_be_bytes());
                    out.extend_from_slice(&src.octets());
                    out.extend_from_slice(&dst.octets());
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    out.push(0x21);
                    out.extend_from_slice(&36u16.to_be_bytes());
                    out.extend_from_slice(&src.octets());
                    out.extend_from_slice(&dst.octets());
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "PROXY protocol source and destination address families differ",
                    ));
                }
            }
            out.extend_from_slice(&source.port().to_be_bytes());
            out.extend_from_slice(&destination.port().to_be_bytes());
            Ok(out)
        }
    }
}

async fn collect_target_template<T: AsyncRead + Unpin + ?Sized>(
    target: &mut T,
    limits: &RealityServerLimits,
    cancellation: &CancellationToken,
) -> Result<Vec<Bytes>, (Vec<Bytes>, io::Error)> {
    let deadline = Instant::now() + limits.target_handshake_timeout;
    let mut records = Vec::new();
    let mut total = 0usize;
    let mut encrypted = 0usize;

    for _ in 0..limits.max_target_records {
        let mut header = [0u8; 5];
        if let Err((filled, error)) =
            read_exact_until(target, &mut header, deadline, cancellation).await
        {
            if filled != 0 {
                records.push(Bytes::copy_from_slice(&header[..filled]));
            }
            return Err((records, error));
        }
        let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if body_len == 0 || body_len > MAX_TLS13_RECORD {
            records.push(Bytes::copy_from_slice(&header));
            return Err((
                records,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid target TLS record length",
                ),
            ));
        }
        total = match total.checked_add(5 + body_len) {
            Some(total) if total <= limits.max_target_handshake_bytes => total,
            _ => {
                records.push(Bytes::copy_from_slice(&header));
                return Err((
                    records,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "target handshake byte limit exceeded",
                    ),
                ));
            }
        };
        let mut record = Vec::with_capacity(5 + body_len);
        record.extend_from_slice(&header);
        record.resize(5 + body_len, 0);
        if let Err((filled, error)) =
            read_exact_until(target, &mut record[5..], deadline, cancellation).await
        {
            record.truncate(5 + filled);
            records.push(Bytes::from(record));
            return Err((records, error));
        }
        let record = Bytes::from(record);
        if records.is_empty() {
            if let Err(error) = validate_target_server_hello(&record) {
                records.push(record);
                return Err((records, error));
            }
        }
        if record[0] == 23 {
            encrypted += 1;
        }
        let combined = record[0] == 23 && record.len() > 512;
        records.push(record);
        if combined || encrypted >= 4 {
            return Ok(records);
        }
    }
    Err((
        records,
        io::Error::new(
            io::ErrorKind::InvalidData,
            "target TLS record-count limit exceeded",
        ),
    ))
}

async fn read_exact_until<T: AsyncRead + Unpin + ?Sized>(
    stream: &mut T,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), (usize, io::Error)> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let read = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err((filled, io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            result = tokio::time::timeout_at(deadline, stream.read(&mut buffer[filled..])) => result,
        };
        let count = match read {
            Err(_) => {
                return Err((
                    filled,
                    io::Error::new(io::ErrorKind::TimedOut, "target handshake timeout"),
                ));
            }
            Ok(Err(error)) => return Err((filled, error)),
            Ok(Ok(0)) => {
                return Err((
                    filled,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "camouflage target closed"),
                ));
            }
            Ok(Ok(count)) => count,
        };
        filled += count;
    }
    Ok(())
}

fn validate_target_server_hello(record: &[u8]) -> io::Result<()> {
    if record.len() < 9 || record[0] != 22 || record[5] != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target did not return ServerHello",
        ));
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record_len + 5 != record.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target ServerHello record length mismatch",
        ));
    }
    let mut hello = SliceReader::new(&record[5..]);
    if hello.read_u8()? != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target first handshake is not ServerHello",
        ));
    }
    let handshake_len = hello.read_u24_be()?;
    if handshake_len != hello.remaining() || hello.read_u16_be()? != 0x0303 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid target ServerHello framing",
        ));
    }
    hello.skip(32)?;
    let session_len = hello.read_u8()? as usize;
    if session_len > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid target ServerHello session ID",
        ));
    }
    hello.skip(session_len)?;
    let parsed_cipher = hello.read_u16_be()?;
    if hello.read_u8()? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target selected non-null compression",
        ));
    }
    let extensions_len = hello.read_u16_be()? as usize;
    if extensions_len != hello.remaining() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target ServerHello extensions length mismatch",
        ));
    }
    let mut extensions = SliceReader::new(hello.read_slice(extensions_len)?);
    let mut tls13 = false;
    let mut key_share = None;
    while extensions.remaining() != 0 {
        if extensions.remaining() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated target ServerHello extension",
            ));
        }
        let kind = extensions.read_u16_be()?;
        let value_len = extensions.read_u16_be()? as usize;
        let value = extensions.read_slice(value_len)?;
        match kind {
            43 => {
                if tls13 || value != TLS_1_3_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "target did not negotiate TLS 1.3",
                    ));
                }
                tls13 = true;
            }
            51 => {
                if key_share.is_some() || value.len() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid target ServerHello key share",
                    ));
                }
                let group = u16::from_be_bytes([value[0], value[1]]);
                let len = u16::from_be_bytes([value[2], value[3]]) as usize;
                if len != value.len() - 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "target key-share length mismatch",
                    ));
                }
                key_share = Some((group, len));
            }
            _ => {}
        }
    }
    if !tls13 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target ServerHello lacks TLS 1.3 version",
        ));
    }
    let cipher = extract_server_cipher_suite(record)?;
    if cipher != parsed_cipher || CipherSuite::from_id(cipher).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target selected unsupported TLS cipher",
        ));
    }
    let (group, key) = extract_server_key_share(record)?;
    if key_share != Some((group, key.len())) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inconsistent target key share",
        ));
    }
    match (group, key.len()) {
        (X25519, 32) | (X25519_MLKEM768, 1120) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target selected unsupported TLS key share",
        )),
    }
}

async fn perform_crypto_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    crypto: &mut RealityServerConnection,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    flush_crypto(stream, crypto, cancellation).await?;
    let mut input = vec![0u8; MAX_TLS13_RECORD + 5];
    while crypto.is_handshaking() {
        let n = tokio::select! {
            _ = cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
            result = stream.read(&mut input) => result?,
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed during REALITY handshake",
            ));
        }
        feed_crypto(crypto, &input[..n])?;
        crypto.process_new_packets()?;
        flush_crypto(stream, crypto, cancellation).await?;
    }
    Ok(())
}

fn feed_crypto(crypto: &mut RealityServerConnection, data: &[u8]) -> io::Result<()> {
    let mut cursor = io::Cursor::new(data);
    while cursor.position() < data.len() as u64 {
        let n = crypto.read_tls(&mut cursor)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "REALITY TLS input stalled",
            ));
        }
    }
    Ok(())
}

async fn flush_crypto<S: AsyncWrite + Unpin>(
    stream: &mut S,
    crypto: &mut RealityServerConnection,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    while crypto.wants_write() {
        let mut ciphertext = Vec::new();
        let n = crypto.write_tls(&mut ciphertext)?;
        if n == 0 {
            break;
        }
        tokio::select! {
            _ = cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
            result = stream.write_all(&ciphertext) => result?,
        }
    }
    stream.flush().await
}

async fn flush_crypto_with_timeout<S: AsyncWrite + Unpin>(
    stream: &mut S,
    crypto: &mut RealityServerConnection,
    cancellation: &CancellationToken,
    idle_timeout: Duration,
) -> io::Result<()> {
    tokio::time::timeout(idle_timeout, flush_crypto(stream, crypto, cancellation))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "REALITY network write idle timeout",
            )
        })?
}

enum PumpEvent {
    Network(io::Result<usize>),
    Application(io::Result<usize>),
    Cancelled,
}

async fn run_crypto_pump<S>(
    network: S,
    mut application: DuplexStream,
    mut crypto: RealityServerConnection,
    cancellation: CancellationToken,
    idle_timeout: Duration,
    _permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut network_read, mut network_write) = tokio::io::split(network);
    let mut network_buffer = vec![0u8; MAX_TLS13_RECORD + 5];
    let mut application_buffer = vec![0u8; 32 * 1024];
    let mut network_open = true;
    let mut application_open = true;

    while network_open || application_open {
        let plaintext = match take_plaintext(&mut crypto) {
            Ok(plaintext) => plaintext,
            Err(_) => break,
        };
        if !plaintext.is_empty() {
            let result = tokio::select! {
                _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
                result = tokio::time::timeout(idle_timeout, application.write_all(&plaintext)) => {
                    result.unwrap_or_else(|_| {
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "application write idle timeout",
                        ))
                    })
                }
            };
            if result.is_err() {
                break;
            }
        }
        let event = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                _ = cancellation.cancelled() => PumpEvent::Cancelled,
                result = network_read.read(&mut network_buffer), if network_open => PumpEvent::Network(result),
                result = application.read(&mut application_buffer), if application_open => PumpEvent::Application(result),
            }
        }).await;
        let Ok(event) = event else { break };
        match event {
            PumpEvent::Cancelled => break,
            PumpEvent::Network(Ok(0)) | PumpEvent::Network(Err(_)) => {
                network_open = false;
                let _ = application.shutdown().await;
            }
            PumpEvent::Network(Ok(n)) => {
                if feed_crypto(&mut crypto, &network_buffer[..n]).is_err()
                    || crypto.process_new_packets().is_err()
                {
                    break;
                }
                if flush_crypto_with_timeout(
                    &mut network_write,
                    &mut crypto,
                    &cancellation,
                    idle_timeout,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            PumpEvent::Application(Ok(0)) | PumpEvent::Application(Err(_)) => {
                application_open = false;
                crypto.send_close_notify();
                let _ = flush_crypto_with_timeout(
                    &mut network_write,
                    &mut crypto,
                    &cancellation,
                    idle_timeout,
                )
                .await;
                let _ = tokio::time::timeout(idle_timeout, network_write.shutdown()).await;
            }
            PumpEvent::Application(Ok(n)) => {
                let write = crypto.writer().write_all(&application_buffer[..n]);
                if write.is_err()
                    || flush_crypto_with_timeout(
                        &mut network_write,
                        &mut crypto,
                        &cancellation,
                        idle_timeout,
                    )
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

fn take_plaintext(crypto: &mut RealityServerConnection) -> io::Result<Vec<u8>> {
    let available = crypto.plaintext_bytes_to_read();
    let mut plaintext = vec![0; available];
    if available != 0 {
        crypto.reader().read_exact(&mut plaintext)?;
    }
    Ok(plaintext)
}

async fn run_fallback<S, T>(
    client: S,
    target: T,
    target_prefix: Vec<Bytes>,
    policy: FallbackPolicy,
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, mut client_write) = tokio::io::split(client);
    let (target_read, target_write) = tokio::io::split(target);
    for record in target_prefix {
        let write =
            tokio::time::timeout(policy.idle_timeout, client_write.write_all(&record)).await;
        if !matches!(write, Ok(Ok(()))) {
            return;
        }
    }
    let upload_cancel = cancellation.clone();
    let download_cancel = cancellation.clone();
    let upload_task = copy_limited(
        client_read,
        target_write,
        policy.upload,
        policy.idle_timeout,
        upload_cancel,
    );
    let download_task = copy_limited(
        target_read,
        client_write,
        policy.download,
        policy.idle_timeout,
        download_cancel,
    );
    let _ = tokio::join!(upload_task, download_task);
}

struct TokenBucket {
    exempt_remaining: u64,
    rate: u64,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(limit: FallbackLimit) -> Self {
        let capacity = limit.burst_bytes.max(limit.bytes_per_second) as f64;
        Self {
            exempt_remaining: limit.after_bytes,
            rate: limit.bytes_per_second,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        }
    }

    async fn account(&mut self, bytes: usize, cancellation: &CancellationToken) -> io::Result<()> {
        if self.rate == 0 {
            return Ok(());
        }
        if self.exempt_remaining > 0 {
            self.exempt_remaining = self.exempt_remaining.saturating_sub(bytes as u64);
            return Ok(());
        }
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * self.rate as f64)
            .min(self.capacity);
        self.updated = now;
        let needed = bytes as f64;
        if self.tokens < needed {
            let wait = Duration::from_secs_f64((needed - self.tokens) / self.rate as f64);
            tokio::select! {
                _ = cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
                _ = tokio::time::sleep(wait) => {}
            }
            self.tokens = 0.0;
            self.updated = Instant::now();
        } else {
            self.tokens -= needed;
        }
        Ok(())
    }
}

async fn copy_limited<R, W>(
    mut reader: R,
    mut writer: W,
    limit: FallbackLimit,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bucket = TokenBucket::new(limit);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut copied = 0u64;
    loop {
        let n = tokio::select! {
            _ = cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
            result = tokio::time::timeout(idle_timeout, reader.read(&mut buffer)) => {
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fallback read idle timeout"))??
            },
        };
        if n == 0 {
            tokio::time::timeout(idle_timeout, writer.shutdown())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "fallback shutdown timeout")
                })??;
            return Ok(copied);
        }
        bucket.account(n, &cancellation).await?;
        tokio::select! {
            _ = cancellation.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
            result = tokio::time::timeout(idle_timeout, writer.write_all(&buffer[..n])) => {
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fallback write idle timeout"))??;
            },
        }
        copied = copied.saturating_add(n as u64);
    }
}

const TLS_1_3_VERSION: &[u8] = &[0x03, 0x04];

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn proxy_v1_ipv4_golden() {
        let source = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 1234);
        let destination = SocketAddr::new(Ipv4Addr::new(198, 51, 100, 2).into(), 443);
        assert_eq!(
            proxy_header(ProxyProtocolVersion::V1, source, destination).unwrap(),
            b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 443\r\n"
        );
    }

    #[test]
    fn proxy_v2_ipv6_golden() {
        let source = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 7);
        let destination = SocketAddr::new("2001:db8::1".parse().unwrap(), 443);
        let header = proxy_header(ProxyProtocolVersion::V2, source, destination).unwrap();
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
        assert_eq!(&header[48..], &[0, 7, 1, 187]);
    }

    #[test]
    fn proxy_header_rejects_mixed_address_families() {
        let source = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1234);
        let destination = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        assert!(proxy_header(ProxyProtocolVersion::V1, source, destination).is_err());
        assert!(proxy_header(ProxyProtocolVersion::V2, source, destination).is_err());
    }

    #[tokio::test]
    async fn target_partial_record_is_preserved_for_fallback() {
        let partial = [22, 3, 3, 0, 10, 2, 0, 0];
        let (mut writer, mut reader) = tokio::io::duplex(partial.len());
        writer.write_all(&partial).await.unwrap();
        drop(writer);

        let error = collect_target_template(
            &mut reader,
            &RealityServerLimits::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        let preserved: Vec<u8> = error
            .0
            .iter()
            .flat_map(|bytes| bytes.iter().copied())
            .collect();
        assert_eq!(preserved, partial);
        assert_eq!(error.1.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn configuration_rejects_equal_secret_seeds() {
        let secret = [9; 32];
        let config = RealityServerConfig {
            camouflage_target: "127.0.0.1:443".into(),
            private_key: secret,
            server_names: HashSet::from(["example.com".into()]),
            short_ids: vec![[0; 8]],
            min_client_version: None,
            max_client_version: None,
            max_time_difference: None,
            mldsa65_seed: Some(secret),
            cipher_suites: Vec::new(),
            proxy_protocol: ProxyProtocolVersion::None,
            fallback_upload: FallbackLimit::default(),
            fallback_download: FallbackLimit::default(),
            limits: RealityServerLimits::default(),
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("short_ids"));
        assert!(RealityServer::new(config).is_err());
    }
}
