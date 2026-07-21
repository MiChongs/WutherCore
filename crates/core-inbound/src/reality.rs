//! REALITY inbound listener with an authenticated VLESS inner protocol.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use core_config::model::RealityListen as RealityListenConfig;
use core_reality::{
    ClientHelloLimits, FallbackLimit, ProxyProtocolVersion, RealityServer, RealityServerConfig,
    RealityServerError, RealityServerLimits, decode_private_key, decode_short_id,
};
use core_runtime::Runtime;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::vless::{VlessConnectionContext, VlessInboundConfig, serve_vless_stream};

#[derive(Clone)]
pub struct RealityListener {
    listen: SocketAddr,
    server: RealityServer,
    target: CamouflageTarget,
    vless: Arc<VlessInboundConfig>,
}

impl fmt::Debug for RealityListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityListener")
            .field("listen", &self.listen)
            .field("server", &self.server.config())
            .field("target", &self.target)
            .field("vless", &self.vless)
            .finish()
    }
}

#[derive(Clone, Debug)]
enum CamouflageTarget {
    Tcp(String),
    #[cfg(unix)]
    Unix(String),
}

impl RealityListener {
    pub fn from_config(config: &RealityListenConfig) -> io::Result<Self> {
        let listen = format!("{}:{}", config.host, config.port)
            .parse()
            .map_err(|error| invalid_input(format!("invalid REALITY listen address: {error}")))?;
        let target = config
            .target
            .as_ref()
            .or(config.dest.as_ref())
            .ok_or_else(|| invalid_input("REALITY target/dest is missing"))?
            .normalized();
        let target_type = config.target_type.as_deref().unwrap_or(
            if target.starts_with('/') || target.starts_with('@') {
                "unix"
            } else {
                "tcp"
            },
        );
        let target = match target_type {
            "tcp" => CamouflageTarget::Tcp(target.clone()),
            #[cfg(unix)]
            "unix" => CamouflageTarget::Unix(target.clone()),
            #[cfg(not(unix))]
            "unix" => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "REALITY unix target is not supported on this platform",
                ));
            }
            other => {
                return Err(invalid_input(format!(
                    "unsupported REALITY target type `{other}`"
                )));
            }
        };
        let private_key = decode_private_key(&config.private_key)?;
        let short_ids = config
            .short_ids
            .iter()
            .map(|short_id| decode_short_id(short_id))
            .collect::<io::Result<Vec<_>>>()?;
        let min_client_version = config
            .min_client_ver
            .as_deref()
            .map(parse_version)
            .transpose()?
            .or(Some([26, 3, 27]));
        let max_client_version = config
            .max_client_ver
            .as_deref()
            .map(parse_version)
            .transpose()?;
        let mldsa65_seed = config
            .mldsa65_seed
            .as_deref()
            .map(decode_32_base64url)
            .transpose()?;
        let proxy_protocol = match config.xver {
            0 => ProxyProtocolVersion::None,
            1 => ProxyProtocolVersion::V1,
            2 => ProxyProtocolVersion::V2,
            value => {
                return Err(invalid_input(format!(
                    "REALITY xver must be 0, 1 or 2, got {value}"
                )));
            }
        };
        let limits = RealityServerLimits {
            client_hello: ClientHelloLimits {
                max_record_payload: config.limits.max_client_hello_record_payload,
                max_handshake_bytes: config.limits.max_client_hello_bytes,
                max_wire_bytes: config.limits.max_client_hello_wire_bytes,
                max_records: config.limits.max_client_hello_records,
            },
            handshake_timeout: config.limits.handshake_timeout,
            target_handshake_timeout: config.limits.target_handshake_timeout,
            idle_timeout: config.limits.idle_timeout,
            max_target_records: config.limits.max_target_records,
            max_target_handshake_bytes: config.limits.max_target_handshake_bytes,
            application_buffer_bytes: config.limits.application_buffer_bytes,
            max_concurrent_handshakes: config.limits.max_concurrent_handshakes,
        };
        let server = RealityServer::new(RealityServerConfig {
            camouflage_target: target_address(&target).to_owned(),
            private_key,
            server_names: config.server_names.iter().cloned().collect::<HashSet<_>>(),
            short_ids,
            min_client_version,
            max_client_version,
            max_time_difference: (config.max_time_diff_ms != 0)
                .then(|| Duration::from_millis(config.max_time_diff_ms)),
            mldsa65_seed,
            cipher_suites: Vec::new(),
            proxy_protocol,
            fallback_upload: FallbackLimit {
                after_bytes: config.limit_fallback_upload.after_bytes,
                bytes_per_second: config.limit_fallback_upload.bytes_per_sec,
                burst_bytes: config.limit_fallback_upload.burst_bytes_per_sec,
            },
            fallback_download: FallbackLimit {
                after_bytes: config.limit_fallback_download.after_bytes,
                bytes_per_second: config.limit_fallback_download.bytes_per_sec,
                burst_bytes: config.limit_fallback_download.burst_bytes_per_sec,
            },
            limits,
        })
        .map_err(reality_error)?;
        let vless = Arc::new(VlessInboundConfig::from_uuid_strings(
            &config.users,
            config.limits.handshake_timeout,
            config
                .limits
                .max_concurrent_handshakes
                .min(u16::MAX as usize),
        )?);
        Ok(Self {
            listen,
            server,
            target,
            vless,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen
    }
}

fn target_address(target: &CamouflageTarget) -> &str {
    match target {
        CamouflageTarget::Tcp(address) => address,
        #[cfg(unix)]
        CamouflageTarget::Unix(path) => path,
    }
}

pub async fn run_reality(listener: RealityListener, runtime: Arc<Runtime>) -> io::Result<()> {
    let socket = TcpListener::bind(listener.listen).await?;
    let bound = socket.local_addr()?;
    info!(addr = %bound, "REALITY inbound listening");
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = socket.accept() => {
                let (stream, peer) = accepted?;
                let local = stream.local_addr()?;
                let _ = stream.set_nodelay(true);
                let listener = listener.clone();
                let runtime = runtime.clone();
                let cancellation = cancellation.clone();
                connections.spawn(async move {
                    if let Err(error) = authenticate_and_serve(
                        listener,
                        stream,
                        peer,
                        local,
                        runtime,
                        cancellation,
                    ).await {
                        match error.downcast_ref::<RealityServerError>() {
                            Some(RealityServerError::FallbackStarted { reason }) => {
                                debug!(%peer, %reason, "REALITY camouflage fallback");
                            }
                            _ => debug!(%peer, error = %error, "REALITY connection failed"),
                        }
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "REALITY connection task panicked");
                }
            }
        }
    }
}

async fn authenticate_and_serve(
    listener: RealityListener,
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    runtime: Arc<Runtime>,
    cancellation: CancellationToken,
) -> anyhow::Result<()> {
    let inner_cancellation = cancellation.clone();
    let accepted = match &listener.target {
        CamouflageTarget::Tcp(address) => {
            let target = tokio::time::timeout(
                listener.server.config().limits.target_handshake_timeout,
                TcpStream::connect(address),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "camouflage target timeout"))??;
            listener
                .server
                .accept_with_target(stream, target, peer, local, cancellation)
                .await?
        }
        #[cfg(unix)]
        CamouflageTarget::Unix(path) => {
            let target = tokio::time::timeout(
                listener.server.config().limits.target_handshake_timeout,
                tokio::net::UnixStream::connect(path),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "camouflage target timeout"))??;
            listener
                .server
                .accept_with_target(stream, target, peer, local, cancellation)
                .await?
        }
    };
    serve_vless_stream(
        accepted,
        VlessConnectionContext {
            source: peer,
            local,
        },
        listener.vless,
        runtime,
        inner_cancellation,
    )
    .await?;
    Ok(())
}

fn parse_version(value: &str) -> io::Result<[u8; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid_input(format!(
            "invalid REALITY client version `{value}`"
        )));
    }
    let mut version = [0u8; 3];
    for (index, part) in parts.iter().enumerate() {
        version[index] = part
            .parse()
            .map_err(|_| invalid_input(format!("invalid REALITY client version `{value}`")))?;
    }
    Ok(version)
}

fn decode_32_base64url(value: &str) -> io::Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| invalid_input(format!("invalid base64url key: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| invalid_input("REALITY key must decode to 32 bytes"))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn reality_error(error: RealityServerError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::{RealityFallbackLimit, RealityResourceLimits, RealityTarget};

    fn valid_config() -> RealityListenConfig {
        RealityListenConfig {
            host: "127.0.0.1".into(),
            port: 443,
            protocol: "vless".into(),
            users: vec!["11111111-1111-1111-1111-111111111111".into()],
            target: Some(RealityTarget::Address("127.0.0.1:8443".into())),
            dest: None,
            target_type: Some("tcp".into()),
            show: false,
            master_key_log: None,
            xver: 0,
            server_names: vec!["example.com".into()],
            private_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            min_client_ver: Some("26.3.27".into()),
            max_client_ver: None,
            max_time_diff_ms: 60_000,
            short_ids: vec!["0123456789abcdef".into()],
            mldsa65_seed: None,
            limit_fallback_upload: RealityFallbackLimit::default(),
            limit_fallback_download: RealityFallbackLimit::default(),
            limits: RealityResourceLimits::default(),
        }
    }

    #[test]
    fn listener_config_builds_and_redacts_secrets() {
        let listener = RealityListener::from_config(&valid_config()).unwrap();
        let debug = format!("{listener:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("BwcHBwcH"));
    }

    #[test]
    fn listener_rejects_unknown_xver_defensively() {
        let mut config = valid_config();
        config.xver = 3;
        assert!(RealityListener::from_config(&config).is_err());
    }
}
