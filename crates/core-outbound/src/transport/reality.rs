use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use core_reality::{
    RealityClient, RealityClientConfig, RealityClientError, RealityConnectionLifetime,
};
use tracing::{debug, info, warn};

use crate::adapter::{BoxedStream, resolve_host};
use crate::transport::Transport;
use crate::transport::tcp::marked_connect_raw;

#[derive(Clone)]
pub struct RealityOptions {
    pub config: RealityClientConfig,
}

impl fmt::Debug for RealityOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityOptions")
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone)]
pub struct RealityTransport {
    client: RealityClient,
}

impl fmt::Debug for RealityTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityTransport")
            .field("client", &self.client)
            .finish()
    }
}

impl RealityTransport {
    pub fn new(options: RealityOptions) -> io::Result<Self> {
        let client = RealityClient::new(options.config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Transport for RealityTransport {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxedStream> {
        let started = Instant::now();
        let addresses = resolve_host(host, port).await?;
        let mut last_error = None;
        for (attempt, address) in addresses.iter().copied().enumerate() {
            let attempt_started = Instant::now();
            let (stream, guard) = match marked_connect_raw(address, Duration::from_secs(10)).await {
                Ok(stream) => stream,
                Err(error) => {
                    debug!(
                        target: "dial::reality",
                        %host,
                        port,
                        peer = %address,
                        attempt = attempt + 1,
                        error = %error,
                        "REALITY TCP connect attempt failed",
                    );
                    last_error = Some(error);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let lifetime: RealityConnectionLifetime = Arc::new(guard);
            match self
                .client
                .connect_with_lifetime(stream, Some(lifetime))
                .await
            {
                Ok(stream) => {
                    info!(
                        target: "dial::reality",
                        %host,
                        port,
                        peer = %address,
                        attempt = attempt + 1,
                        handshake_ms = attempt_started.elapsed().as_millis() as u64,
                        total_ms = started.elapsed().as_millis() as u64,
                        fingerprint = %self.client.config().fingerprint,
                        "REALITY authenticated",
                    );
                    return Ok(Box::pin(stream));
                }
                Err(error) => {
                    let cover_started =
                        matches!(error, RealityClientError::InvalidConnectionProcessed);
                    debug!(
                        target: "dial::reality",
                        %host,
                        port,
                        peer = %address,
                        attempt = attempt + 1,
                        error = %error,
                        "REALITY handshake attempt failed",
                    );
                    let error = io::Error::new(io::ErrorKind::ConnectionAborted, error);
                    if cover_started {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }
        warn!(
            target: "dial::reality",
            %host,
            port,
            attempts = addresses.len(),
            total_ms = started.elapsed().as_millis() as u64,
            "all REALITY candidates failed",
        );
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("REALITY connect: no usable address for {host}:{port}"),
            )
        }))
    }
}
