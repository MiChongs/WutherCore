//! Xray XHTTP 2026 客户端。
//!
//! 支持 HTTP/1.1、HTTP/2、HTTP/3，以及 `stream-one`、`stream-up`、
//! `packet-up` 三种模式。HTTP 版本、XMUX 生命周期、packet-up 并发与
//! downloadSettings 都会实际改变网络行为，而不是仅保存配置字段。

use std::{
    collections::BTreeMap,
    future::Future,
    io, mem,
    net::IpAddr,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http::{HeaderName, HeaderValue, StatusCode, Uri, uri::Authority};
use http_body_util::BodyExt;
use hyper::body::{Body as HyperBody, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioTimer;
use parking_lot::Mutex;
use rand::Rng;
use tokio::{
    io::{AsyncWrite, ReadBuf},
    sync::{Notify, OnceCell, mpsc},
    task::JoinSet,
    time::Instant,
};

use super::{
    config::{
        Config, DownloadRealitySettings, DownloadSettings, DownloadTlsSettings, Range, XmuxConfig,
    },
    conn::{IoFailure, IoState, PipeWriter, ResponseReader, XConn},
    download_policy::{validate_download_runtime, validate_primary_tls_runtime},
    h3::H3Client,
    request::{PreparedRequest, fill_download_request, fill_packet_request, fill_stream_request},
    xmux::{ManagedConnection, XmuxLease, XmuxLimits, XmuxManager, XmuxSampleRange},
};
use crate::{
    adapter::BoxedStream,
    transport::{
        TlsOptions, Transport, parse_pinned_peer_cert_sha256, parse_verify_peer_cert_by_name,
        tcp::TcpTransport, tls::TlsTransport,
    },
};

// Match Go net/http's deterministic per-host idle defaults. Packet-up may have
// more active requests, but active senders are checked out of this pool and do
// not count toward the number of TCP connections retained while idle.
const H1_UPLOAD_MAX_IDLE_SENDERS: usize = 2;
const H1_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_PACKET_ACK_BODY_BYTES: usize = 64 * 1024;
const XHTTP_DEFAULT_TLS_ALPN: [&str; 2] = ["h2", "http/1.1"];

/// Xray `decideHTTPVersion` 的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    Http1,
    Http2,
    Http3,
}

impl HttpVersion {
    fn scheme(self, tls: bool) -> &'static str {
        if tls || self == Self::Http3 {
            "https"
        } else {
            "http"
        }
    }
}

/// 与 Xray 当前实现一致的 HTTP 版本决策。
///
/// - Reality 固定 H2（本项目尚无 Reality 握手时会在 dial 阶段明确报错）
/// - 明文固定 H1
/// - TLS 且仅配置 `http/1.1` 时用 H1
/// - TLS 且仅配置 `h3` 时用 H3
/// - 其他 TLS 组合用 H2
pub fn decide_http_version(tls: bool, has_reality: bool, alpn: &[String]) -> HttpVersion {
    if has_reality {
        return HttpVersion::Http2;
    }
    if !tls {
        return HttpVersion::Http1;
    }
    if alpn.len() == 1 {
        if alpn[0].eq_ignore_ascii_case("http/1.1") {
            return HttpVersion::Http1;
        }
        if alpn[0].eq_ignore_ascii_case("h3") {
            return HttpVersion::Http3;
        }
    }
    HttpVersion::Http2
}

fn effective_xhttp_alpn(tls: bool, configured: &[String]) -> Vec<String> {
    if tls && configured.is_empty() {
        XHTTP_DEFAULT_TLS_ALPN
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        configured.to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DialProfile {
    dial_host: String,
    port: u16,
    authority: String,
    tls: bool,
    sni: Option<String>,
    insecure: bool,
    alpn: Vec<String>,
    enable_session_resumption: bool,
    fingerprint: Option<String>,
    pinned_peer_cert_sha256: Vec<[u8; 32]>,
    verify_peer_cert_by_name: Vec<String>,
    tls_settings: Option<DownloadTlsSettings>,
    version: HttpVersion,
}

impl DialProfile {
    fn url(&self, path: &str) -> String {
        format!(
            "{}://{}{}",
            self.version.scheme(self.tls),
            self.authority,
            path
        )
    }
}

/// hyper 请求体：流式、一次性或空 body。
pub enum XhttpBody {
    Stream(RequestBody),
    OneShot(OneShotBody),
    Empty,
}

impl HyperBody for XhttpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Stream(body) => Pin::new(body).poll_frame(cx),
            Self::OneShot(body) => Pin::new(body).poll_frame(cx),
            Self::Empty => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Empty)
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::OneShot(body) => body.size_hint(),
            Self::Empty => SizeHint::with_exact(0),
            Self::Stream(_) => SizeHint::default(),
        }
    }
}

/// 一个 outbound 对应一个 XHTTP 客户端与两个惰性 XMUX pool。
pub struct XhttpClient {
    pub cfg: Arc<Config>,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub enable_session_resumption: bool,
    pub fingerprint: Option<String>,
    pub pinned_peer_cert_sha256: Vec<[u8; 32]>,
    pub verify_peer_cert_by_name: Vec<String>,
    pub tls_settings: Option<DownloadTlsSettings>,
    pub reality_settings: Option<DownloadRealitySettings>,
    upload_pool: OnceCell<Arc<XmuxManager<HttpConnection>>>,
    download_pool: OnceCell<Arc<XmuxManager<HttpConnection>>>,
}

impl XhttpClient {
    pub fn new(cfg: Config, host: impl Into<String>, port: u16) -> Self {
        Self {
            cfg: Arc::new(cfg),
            host: host.into(),
            port,
            tls: true,
            sni: None,
            insecure: false,
            alpn: Vec::new(),
            enable_session_resumption: false,
            fingerprint: None,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            tls_settings: None,
            reality_settings: None,
            upload_pool: OnceCell::new(),
            download_pool: OnceCell::new(),
        }
    }

    /// 建立一条 XHTTP 逻辑流。
    pub async fn dial(&self, has_reality: bool) -> io::Result<BoxedStream> {
        if has_reality {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xhttp Reality security requires a Reality TLS handshake; this build does not \
                 expose one and will not pretend to use ordinary TLS",
            ));
        }

        // Transport 也可被库用户直接构造，不能依赖 registry 预先做过默认值
        // 展开；在真正拨号前幂等地完成 extra、默认值及字段校验。
        let cfg = Arc::new(
            (*self.cfg)
                .clone()
                .into_normalized()
                .map_err(invalid_input)?,
        );
        let mode = cfg.effective_mode(false).to_owned();
        if mode == "packet-up" {
            // Xray 在创建任何 packet-up transport 前要求范围下界大于 0。
            // Rust 返回确定性配置错误，不能随机抽到 0 后才失败。
            packet_up_ranges(&cfg)?;
        }
        let profile = self.primary_profile(&cfg, false)?;
        let upload_pool = self.upload_pool(cfg.clone(), profile.clone()).await?;

        match mode.as_str() {
            "stream-one" => self.dial_stream_one(cfg, profile, upload_pool).await,
            "stream-up" => self.dial_stream_up(cfg, profile, upload_pool).await,
            "packet-up" => self.dial_packet_up(cfg, profile, upload_pool).await,
            mode => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported xhttp mode: {mode}"),
            )),
        }
    }

    async fn dial_stream_one(
        &self,
        cfg: Arc<Config>,
        profile: DialProfile,
        pool: Arc<XmuxManager<HttpConnection>>,
    ) -> io::Result<BoxedStream> {
        let lease = request_lease(&pool, None).await?;
        let state = IoState::shared();
        let (writer, upload) = PipeWriter::channel(8, state.clone());
        let mut request = PreparedRequest::new(
            cfg.normalized_uplink_http_method(),
            &profile.url(&cfg.normalized_path()),
            &profile.authority,
        );
        fill_stream_request(&cfg, &mut request, "").map_err(io_err)?;
        let reader = lease
            .connection()
            .open_stream(request, Some(upload), state.clone())
            .await?;

        let close_state = state.clone();
        Ok(Box::pin(XConn::new(reader, writer).with_on_close(
            move || {
                close_state.cancel();
                drop(lease);
            },
        )))
    }

    async fn dial_stream_up(
        &self,
        cfg: Arc<Config>,
        profile: DialProfile,
        upload_pool: Arc<XmuxManager<HttpConnection>>,
    ) -> io::Result<BoxedStream> {
        let session_id = generate_session_id(&cfg)?;
        let upload_lease = request_lease(&upload_pool, None).await?;
        let (download_cfg, download_profile, download_pool, independent) = self
            .download_context(cfg.clone(), profile.clone(), upload_pool.clone())
            .await?;
        let download_lease = if independent {
            request_lease(&download_pool, None).await?
        } else {
            request_lease(&download_pool, Some(upload_lease.clone())).await?
        };

        let state = IoState::shared();
        let mut download_request = PreparedRequest::new(
            "GET",
            &download_profile.url(&download_cfg.normalized_path()),
            &download_profile.authority,
        );
        fill_download_request(&download_cfg, &mut download_request, &session_id).map_err(io_err)?;
        let reader = download_lease
            .connection()
            .open_stream(download_request, None, state.clone())
            .await?;

        let (writer, upload) = PipeWriter::channel(8, state.clone());
        let mut upload_request = PreparedRequest::new(
            cfg.normalized_uplink_http_method(),
            &profile.url(&cfg.normalized_path()),
            &profile.authority,
        );
        fill_stream_request(&cfg, &mut upload_request, &session_id).map_err(io_err)?;
        let upload_connection = upload_lease.connection().clone();
        let upload_state = state.clone();
        tokio::spawn(async move {
            match upload_connection
                .open_stream(upload_request, Some(upload), upload_state.clone())
                .await
            {
                Ok(mut response) => {
                    let mut sink = tokio::io::sink();
                    if let Err(error) = tokio::io::copy(&mut response, &mut sink).await {
                        upload_state.fail(IoFailure::new(error.kind(), error.to_string()));
                    }
                }
                Err(error) => {
                    upload_state.fail(IoFailure::new(error.kind(), error.to_string()));
                }
            }
        });

        let close_state = state.clone();
        Ok(Box::pin(XConn::new(reader, writer).with_on_close(
            move || {
                close_state.cancel();
                drop(upload_lease);
                drop(download_lease);
            },
        )))
    }

    async fn dial_packet_up(
        &self,
        cfg: Arc<Config>,
        profile: DialProfile,
        upload_pool: Arc<XmuxManager<HttpConnection>>,
    ) -> io::Result<BoxedStream> {
        let session_id = generate_session_id(&cfg)?;
        // packet-up 尚未发送上行请求，不应提前扣减 hMaxRequestTimes。
        let upload_lease = Arc::new(upload_pool.acquire().await?);
        let (download_cfg, download_profile, download_pool, independent) = self
            .download_context(cfg.clone(), profile.clone(), upload_pool.clone())
            .await?;
        let download_lease = if independent {
            request_lease(&download_pool, None).await?
        } else {
            request_lease(&download_pool, Some(upload_lease.clone())).await?
        };

        let state = IoState::shared();
        let mut download_request = PreparedRequest::new(
            "GET",
            &download_profile.url(&download_cfg.normalized_path()),
            &download_profile.authority,
        );
        fill_download_request(&download_cfg, &mut download_request, &session_id).map_err(io_err)?;
        let reader = download_lease
            .connection()
            .open_stream(download_request, None, state.clone())
            .await?;

        let writer = PacketUpWriter::new(
            cfg,
            profile,
            session_id,
            upload_pool,
            upload_lease,
            state.clone(),
        )?;
        let close_state = state.clone();
        Ok(Box::pin(XConn::new(reader, writer).with_on_close(
            move || {
                close_state.cancel();
                drop(download_lease);
            },
        )))
    }

    fn primary_profile(&self, cfg: &Config, has_reality: bool) -> io::Result<DialProfile> {
        let tls_settings = self.tls.then_some(self.tls_settings.as_ref()).flatten();
        if let Some(settings) = tls_settings {
            validate_primary_tls_runtime(settings)?;
        }
        let insecure = self.insecure
            || tls_settings
                .and_then(|settings| settings.allow_insecure)
                .unwrap_or(false);
        if self.tls && !has_reality && insecure {
            return Err(invalid_input(
                "xhttp TLS allowInsecure=true has been removed by Xray; use \
                 pinnedPeerCertSha256 or verifyPeerCertByName",
            ));
        }
        let configured_alpn = if self.alpn.is_empty() {
            tls_settings
                .and_then(|settings| settings.alpn.clone())
                .unwrap_or_default()
        } else {
            self.alpn.clone()
        };
        let alpn = effective_xhttp_alpn(self.tls, &configured_alpn);
        let version = decide_http_version(self.tls, has_reality, &alpn);
        if version == HttpVersion::Http3 && !self.tls {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp HTTP/3 requires TLS",
            ));
        }
        let http_host = if cfg.host.is_empty() {
            self.sni.as_deref().unwrap_or(&self.host)
        } else {
            &cfg.host
        };
        Ok(DialProfile {
            dial_host: self.host.clone(),
            port: self.port,
            authority: authority_for(http_host)?,
            tls: self.tls,
            sni: tls_settings
                .and_then(|settings| settings.server_name.clone())
                .filter(|value| !value.is_empty())
                .or_else(|| self.sni.clone()),
            // Ordinary XHTTP TLS never reaches rustls's NoVerify path. Reality
            // has its own authenticated handshake and is dispatched earlier.
            insecure: false,
            alpn,
            enable_session_resumption: tls_settings
                .and_then(|settings| settings.enable_session_resumption)
                .unwrap_or(self.enable_session_resumption),
            fingerprint: tls_settings
                .and_then(|settings| settings.fingerprint.clone())
                .or_else(|| self.fingerprint.clone()),
            pinned_peer_cert_sha256: if self.pinned_peer_cert_sha256.is_empty() {
                parse_pinned_peer_cert_sha256(
                    tls_settings.and_then(|settings| settings.pinned_peer_cert_sha256.as_deref()),
                )?
            } else {
                self.pinned_peer_cert_sha256.clone()
            },
            verify_peer_cert_by_name: if self.verify_peer_cert_by_name.is_empty() {
                parse_verify_peer_cert_by_name(
                    tls_settings.and_then(|settings| settings.verify_peer_cert_by_name.as_deref()),
                )
            } else {
                self.verify_peer_cert_by_name.clone()
            },
            tls_settings: tls_settings.cloned(),
            version,
        })
    }

    fn profile_from_download(
        &self,
        settings: &DownloadSettings,
        cfg: &Config,
    ) -> io::Result<DialProfile> {
        validate_download_runtime(settings)?;
        let effective_network = if settings.method.trim().is_empty() {
            settings.network.trim()
        } else {
            settings.method.trim()
        };
        if !effective_network.is_empty()
            && !effective_network.eq_ignore_ascii_case("xhttp")
            && !effective_network.eq_ignore_ascii_case("splithttp")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "xhttp downloadSettings method/network must be xhttp, got {effective_network}"
                ),
            ));
        }
        if let Some(transport) = &settings.transport {
            if !transport.kind.is_empty()
                && !transport.kind.eq_ignore_ascii_case("xhttp")
                && !transport.kind.eq_ignore_ascii_case("splithttp")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "xhttp downloadSettings transport must be xhttp, got {}",
                        transport.kind
                    ),
                ));
            }
        }

        let security = settings.security.trim();
        let tls = security.eq_ignore_ascii_case("tls");
        // 与 Xray StreamConfig 一致，SecurityType 是唯一选择器。未选 TLS 时
        // 即使 JSON 中残留 tlsSettings/realitySettings，也必须保持明文。
        let tls_settings = tls.then_some(settings.tls.as_ref()).flatten();
        let dial_host = (!settings.address.is_empty())
            .then(|| settings.address.clone())
            .ok_or_else(|| {
                invalid_input(
                    "xhttp downloadSettings requires a non-empty address; host only controls \
                     HTTP authority",
                )
            })?;
        let port = settings
            .port
            .filter(|port| *port != 0)
            .ok_or_else(|| invalid_input("xhttp downloadSettings requires a non-zero port"))?;
        let sni = tls_settings
            .and_then(|value| value.server_name.clone())
            .filter(|value| !value.is_empty());
        let configured_alpn = if !settings.alpn.is_empty() {
            settings.alpn.clone()
        } else {
            tls_settings
                .and_then(|value| value.alpn.clone())
                .unwrap_or_default()
        };
        let alpn = effective_xhttp_alpn(tls, &configured_alpn);
        let http_host = if !cfg.host.is_empty() {
            cfg.host.as_str()
        } else if !settings.host.is_empty() {
            settings.host.as_str()
        } else {
            sni.as_deref().unwrap_or(&dial_host)
        };
        let authority = authority_for(http_host)?;
        let version = decide_http_version(tls, false, &alpn);
        Ok(DialProfile {
            dial_host,
            port,
            authority,
            tls,
            sni,
            insecure: false,
            alpn,
            enable_session_resumption: tls_settings
                .and_then(|value| value.enable_session_resumption)
                .unwrap_or(false),
            fingerprint: tls_settings.and_then(|value| value.fingerprint.clone()),
            pinned_peer_cert_sha256: parse_pinned_peer_cert_sha256(
                tls_settings.and_then(|value| value.pinned_peer_cert_sha256.as_deref()),
            )?,
            verify_peer_cert_by_name: parse_verify_peer_cert_by_name(
                tls_settings.and_then(|value| value.verify_peer_cert_by_name.as_deref()),
            ),
            tls_settings: tls_settings.cloned(),
            version,
        })
    }

    async fn upload_pool(
        &self,
        cfg: Arc<Config>,
        profile: DialProfile,
    ) -> io::Result<Arc<XmuxManager<HttpConnection>>> {
        self.upload_pool
            .get_or_try_init(|| async move { build_pool(cfg, profile) })
            .await
            .cloned()
    }

    async fn download_context(
        &self,
        cfg: Arc<Config>,
        primary_profile: DialProfile,
        upload_pool: Arc<XmuxManager<HttpConnection>>,
    ) -> io::Result<(
        Arc<Config>,
        DialProfile,
        Arc<XmuxManager<HttpConnection>>,
        bool,
    )> {
        let Some(settings) = cfg.download_settings.as_deref() else {
            return Ok((cfg, primary_profile, upload_pool, false));
        };
        let download_cfg = Arc::new(
            cfg.download_xhttp_config()
                .map_err(io_err)?
                .resolved()
                .map_err(io_err)?,
        );
        download_cfg.validate().map_err(io_err)?;
        let profile = self.profile_from_download(settings, &download_cfg)?;
        let pool = self
            .download_pool
            .get_or_try_init(|| {
                let download_cfg = download_cfg.clone();
                let profile = profile.clone();
                async move { build_pool(download_cfg, profile) }
            })
            .await?
            .clone();
        Ok((download_cfg, profile, pool, true))
    }
}

fn build_pool(
    cfg: Arc<Config>,
    profile: DialProfile,
) -> io::Result<Arc<XmuxManager<HttpConnection>>> {
    let limits = xmux_limits(&cfg.xmux)?;
    let keep_alive = keep_alive_interval(profile.version, limits.h_keep_alive_period);
    let factory_profile = Arc::new(profile);
    Ok(Arc::new(XmuxManager::new(limits, move || {
        let profile = factory_profile.clone();
        async move {
            let connection = HttpConnection::connect((*profile).clone(), keep_alive).await?;
            Ok(Arc::new(connection))
        }
    })))
}

fn xmux_limits(config: &XmuxConfig) -> io::Result<XmuxLimits> {
    Ok(XmuxLimits {
        max_concurrency: sample_range(&config.max_concurrency)?,
        max_connections: sample_range(&config.max_connections)?,
        c_max_reuse_times: xmux_sample_range(&config.c_max_reuse_times)?,
        h_max_request_times: xmux_sample_range(&config.h_max_request_times)?,
        h_max_reusable_secs: xmux_sample_range(&config.h_max_reusable_secs)?,
        h_keep_alive_period: config.h_keep_alive_period,
    })
}

fn sample_range(value: &str) -> io::Result<i64> {
    i64::try_from(Range::parse(value, "").map_err(io_err)?.rand()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xhttp XMUX range exceeds i64: {value}"),
        )
    })
}

fn xmux_sample_range(value: &str) -> io::Result<XmuxSampleRange> {
    let range = Range::parse(value, "").map_err(io_err)?;
    let min = i64::try_from(range.min)
        .map_err(|_| invalid_input(format!("xhttp XMUX range exceeds i64: {value}")))?;
    let max = i64::try_from(range.max)
        .map_err(|_| invalid_input(format!("xhttp XMUX range exceeds i64: {value}")))?;
    Ok(XmuxSampleRange { min, max })
}

fn keep_alive_interval(version: HttpVersion, configured_secs: i64) -> Option<Duration> {
    if configured_secs < 0 {
        return None;
    }
    if configured_secs > 0 {
        return Some(Duration::from_secs(configured_secs as u64));
    }
    match version {
        HttpVersion::Http1 => None,
        HttpVersion::Http2 => Some(Duration::from_secs(45)),
        HttpVersion::Http3 => Some(Duration::from_secs(10)),
    }
}

fn packet_up_ranges(cfg: &Config) -> io::Result<(Range, Option<Range>)> {
    let max_each_post = cfg.normalized_sc_max_each_post_bytes().map_err(io_err)?;
    if max_each_post.min == 0 {
        return Err(invalid_input(
            "xhttp scMaxEachPostBytes.from must be greater than zero in packet-up mode",
        ));
    }
    let interval = cfg.normalized_sc_min_posts_interval_ms().map_err(io_err)?;
    // Xray gates the entire random sampling/sleep block on From > 0.
    let interval = (interval.min > 0).then_some(interval);
    Ok((max_each_post, interval))
}

async fn request_lease(
    pool: &Arc<XmuxManager<HttpConnection>>,
    current: Option<Arc<XmuxLease<HttpConnection>>>,
) -> io::Result<Arc<XmuxLease<HttpConnection>>> {
    if let Some(current) = current {
        if current.consume_request() {
            return Ok(current);
        }
    }
    loop {
        let lease = Arc::new(pool.acquire().await?);
        if lease.consume_request() {
            return Ok(lease);
        }
    }
}

enum HttpConnection {
    H1(Http1Client),
    H2(Http2Client),
    H3(H3Client),
}

impl HttpConnection {
    async fn connect(profile: DialProfile, keep_alive: Option<Duration>) -> io::Result<Self> {
        match profile.version {
            HttpVersion::Http1 => Ok(Self::H1(Http1Client::new(profile))),
            HttpVersion::Http2 => {
                if !profile.tls {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "xhttp cleartext HTTP/2 is not selected by Xray version rules",
                    ));
                }
                Ok(Self::H2(Http2Client::connect(profile, keep_alive).await?))
            }
            HttpVersion::Http3 => Ok(Self::H3(
                H3Client::connect_with_tls_options(
                    &profile.dial_host,
                    profile.port,
                    tls_options_for_profile(&profile),
                    keep_alive,
                )
                .await?,
            )),
        }
    }

    async fn open_stream(
        &self,
        mut request: PreparedRequest,
        upload: Option<mpsc::Receiver<Bytes>>,
        state: Arc<IoState>,
    ) -> io::Result<ResponseReader> {
        match self {
            Self::H1(client) => {
                apply_streaming_upload_compat(&mut request, HttpVersion::Http1, upload.is_some());
                client.open_stream(request, upload, state).await
            }
            Self::H2(client) => {
                apply_streaming_upload_compat(&mut request, HttpVersion::Http2, upload.is_some());
                client.open_stream(request, upload, state).await
            }
            Self::H3(client) => {
                apply_streaming_upload_compat(&mut request, HttpVersion::Http3, upload.is_some());
                let request = build_h3_request(request)?;
                client.open_stream(request, upload, state).await
            }
        }
    }

    async fn post_packet(
        &self,
        mut request: PreparedRequest,
        state: Arc<IoState>,
    ) -> io::Result<()> {
        match self {
            Self::H1(client) => client.post_packet(request, state).await,
            Self::H2(client) => client.post_packet(request, state).await,
            Self::H3(client) => {
                let body = Bytes::from(request.body.take().unwrap_or_default());
                let request = build_h3_request(request)?;
                client.post_packet(request, body, state).await
            }
        }
    }
}

impl ManagedConnection for HttpConnection {
    fn is_closed(&self) -> bool {
        match self {
            Self::H1(client) => client.is_closed(),
            Self::H2(client) => client.is_closed(),
            Self::H3(client) => client.is_closed(),
        }
    }

    fn close(&self) {
        match self {
            Self::H1(client) => client.close(),
            Self::H2(client) => client.close(),
            Self::H3(client) => client.close(),
        }
    }
}

struct Http1Client {
    profile: DialProfile,
    upload_pool: Arc<Http1UploadPool>,
}

type Http1Sender = hyper::client::conn::http1::SendRequest<XhttpBody>;

struct IdleHttp1Sender {
    sender: Http1Sender,
    idle_since: Instant,
}

struct Http1UploadPool {
    idle: Mutex<Vec<IdleHttp1Sender>>,
    idle_timeout: Duration,
    closed: AtomicBool,
    reaper_running: AtomicBool,
    changed: Notify,
}

impl Http1UploadPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(Vec::with_capacity(H1_UPLOAD_MAX_IDLE_SENDERS)),
            idle_timeout: H1_UPLOAD_IDLE_TIMEOUT,
            closed: AtomicBool::new(false),
            reaper_running: AtomicBool::new(false),
            changed: Notify::new(),
        })
    }

    #[cfg(test)]
    fn new_with_idle_timeout(idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(Vec::with_capacity(H1_UPLOAD_MAX_IDLE_SENDERS)),
            idle_timeout,
            closed: AtomicBool::new(false),
            reaper_running: AtomicBool::new(false),
            changed: Notify::new(),
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn take(&self, now: Instant) -> Option<Http1Sender> {
        let mut discarded = Vec::new();
        let selected = {
            let mut idle = self.idle.lock();
            purge_h1_idle_senders(&mut idle, now, self.idle_timeout, &mut discarded);
            if self.is_closed() {
                discarded.extend(idle.drain(..).map(|entry| entry.sender));
                None
            } else {
                idle.pop().map(|entry| entry.sender)
            }
        };
        // Dropping the last SendRequest closes its H1 connection driver. Keep
        // that work outside the pool lock.
        drop(discarded);
        self.changed.notify_one();
        selected
    }

    fn put(self: &Arc<Self>, sender: Http1Sender, now: Instant) {
        let mut discarded = Vec::new();
        let retained = if sender.is_closed() || self.is_closed() {
            discarded.push(sender);
            false
        } else {
            let mut idle = self.idle.lock();
            purge_h1_idle_senders(&mut idle, now, self.idle_timeout, &mut discarded);
            if self.is_closed() || idle.len() >= H1_UPLOAD_MAX_IDLE_SENDERS {
                discarded.push(sender);
                false
            } else {
                idle.push(IdleHttp1Sender {
                    sender,
                    idle_since: now,
                });
                true
            }
        };
        drop(discarded);
        self.changed.notify_one();
        if retained {
            self.ensure_reaper();
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let discarded = {
            let mut idle = self.idle.lock();
            mem::take(&mut *idle)
        };
        self.changed.notify_waiters();
        drop(discarded);
    }

    fn ensure_reaper(self: &Arc<Self>) {
        if self
            .reaper_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.reap().await;
        });
    }

    async fn reap(self: Arc<Self>) {
        loop {
            // Enable the waiter before observing the pool so close/return/take
            // cannot lose a notification between the state check and await.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();

            let mut discarded = Vec::new();
            let next_expiry = {
                let mut idle = self.idle.lock();
                purge_h1_idle_senders(&mut idle, Instant::now(), self.idle_timeout, &mut discarded);
                if self.is_closed() {
                    discarded.extend(idle.drain(..).map(|entry| entry.sender));
                    None
                } else {
                    idle.iter()
                        .map(|entry| entry.idle_since + self.idle_timeout)
                        .min()
                }
            };
            drop(discarded);

            let Some(next_expiry) = next_expiry else {
                self.reaper_running.store(false, Ordering::Release);
                // A return may have observed the old `true` immediately before
                // the store. Recheck after publishing `false` and retain this
                // task if nobody else won the restart race.
                if self.is_closed() || self.idle.lock().is_empty() {
                    return;
                }
                if self
                    .reaper_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return;
                }
                continue;
            };

            tokio::select! {
                _ = tokio::time::sleep_until(next_expiry) => {}
                _ = &mut changed => {}
            }
        }
    }

    #[cfg(test)]
    fn idle_len(&self) -> usize {
        self.idle.lock().len()
    }
}

fn purge_h1_idle_senders(
    idle: &mut Vec<IdleHttp1Sender>,
    now: Instant,
    idle_timeout: Duration,
    discarded: &mut Vec<Http1Sender>,
) {
    let entries = mem::take(idle);
    for entry in entries {
        let expired = now.saturating_duration_since(entry.idle_since) >= idle_timeout;
        if expired || entry.sender.is_closed() {
            discarded.push(entry.sender);
        } else {
            idle.push(entry);
        }
    }
}

impl Http1Client {
    fn new(profile: DialProfile) -> Self {
        Self {
            profile,
            upload_pool: Http1UploadPool::new(),
        }
    }

    async fn sender(
        &self,
        state: Option<Arc<IoState>>,
    ) -> io::Result<hyper::client::conn::http1::SendRequest<XhttpBody>> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp H1 connection group retired",
            ));
        }
        let stream = connect_tcp(&self.profile).await?;
        let (sender, connection) = hyper::client::conn::http1::handshake(HyperTokioIo::new(stream))
            .await
            .map_err(|error| io_err(format!("xhttp H1 handshake: {error}")))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                if let Some(state) = state {
                    state.fail(IoFailure::other(format!(
                        "xhttp H1 connection driver: {error}"
                    )));
                }
            }
        });
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp H1 connection group retired during setup",
            ));
        }
        Ok(sender)
    }

    async fn open_stream(
        &self,
        request: PreparedRequest,
        upload: Option<mpsc::Receiver<Bytes>>,
        state: Arc<IoState>,
    ) -> io::Result<ResponseReader> {
        let mut sender = self.sender(Some(state.clone())).await?;
        let body = upload
            .map(|rx| XhttpBody::Stream(RequestBody { rx }))
            .unwrap_or(XhttpBody::Empty);
        let request = build_hyper_request(request, body, HttpVersion::Http1)?;
        // `send_request` resolves only after response headers arrive. XHTTP
        // servers may intentionally wait for the first upload byte before
        // sending those headers, so drive it in the background and return the
        // logical stream as soon as TCP/H1 setup has completed.
        Ok(deferred_hyper_response(
            async move { sender.send_request(request).await },
            state,
            "H1",
        ))
    }

    async fn post_packet(&self, request: PreparedRequest, state: Arc<IoState>) -> io::Result<()> {
        let mut last_error = None;
        for attempt in 0..2 {
            let mut sender = self.upload_pool.take(Instant::now());
            if sender.is_none() {
                sender = Some(self.sender(None).await?);
            }
            let mut sender = sender.expect("H1 sender initialized");
            let retry_request = clone_prepared(&request);
            let body = Bytes::from(retry_request.body.clone().unwrap_or_default());
            let hyper_request = build_hyper_request(
                retry_request,
                XhttpBody::OneShot(OneShotBody::new(body)),
                HttpVersion::Http1,
            )?;
            match sender.send_request(hyper_request).await {
                Ok(response) => {
                    ensure_ok(response.status(), "xhttp H1 packet")?;
                    drain_packet_ack_body(response.into_body(), &state, "H1").await?;
                    if !sender.is_closed() && !self.is_closed() && !state.is_cancelled() {
                        self.upload_pool.put(sender, Instant::now());
                    }
                    return Ok(());
                }
                Err(error) => {
                    last_error = Some(io_err(format!("xhttp H1 packet request: {error}")));
                    if attempt == 0 {
                        continue;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io_err("xhttp H1 packet request failed")))
    }
}

impl ManagedConnection for Http1Client {
    fn is_closed(&self) -> bool {
        self.upload_pool.is_closed()
    }

    fn close(&self) {
        self.upload_pool.close();
    }
}

impl Drop for Http1Client {
    fn drop(&mut self) {
        self.upload_pool.close();
    }
}

struct Http2Client {
    sender: hyper::client::conn::http2::SendRequest<XhttpBody>,
    closed: Arc<AtomicBool>,
}

impl Http2Client {
    async fn connect(profile: DialProfile, keep_alive: Option<Duration>) -> io::Result<Self> {
        let stream = connect_tcp(&profile).await?;
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor);
        // Hyper's HTTP/2 keepalive machinery panics at runtime when an
        // interval is configured without a timer. XHTTP enables keepalive by
        // default for H2, so the timer is part of the transport contract rather
        // than an optional test-only convenience.
        builder.timer(TokioTimer::new());
        if let Some(interval) = keep_alive {
            builder.keep_alive_interval(interval);
            builder.keep_alive_while_idle(true);
        }
        let (sender, connection) = builder
            .handshake(HyperTokioIo::new(stream))
            .await
            .map_err(|error| io_err(format!("xhttp H2 handshake: {error}")))?;
        let closed = Arc::new(AtomicBool::new(false));
        let driver_closed = closed.clone();
        tokio::spawn(async move {
            let _ = connection.await;
            driver_closed.store(true, Ordering::Release);
        });
        Ok(Self { sender, closed })
    }

    async fn open_stream(
        &self,
        request: PreparedRequest,
        upload: Option<mpsc::Receiver<Bytes>>,
        state: Arc<IoState>,
    ) -> io::Result<ResponseReader> {
        let body = upload
            .map(|rx| XhttpBody::Stream(RequestBody { rx }))
            .unwrap_or(XhttpBody::Empty);
        let request = build_hyper_request(request, body, HttpVersion::Http2)?;
        let mut sender = self.sender.clone();
        Ok(deferred_hyper_response(
            async move { sender.send_request(request).await },
            state,
            "H2",
        ))
    }

    async fn post_packet(&self, request: PreparedRequest, state: Arc<IoState>) -> io::Result<()> {
        if state.is_cancelled() {
            return Err(cancelled_packet_error());
        }
        let body = Bytes::from(request.body.clone().unwrap_or_default());
        let request = build_hyper_request(
            request,
            XhttpBody::OneShot(OneShotBody::new(body)),
            HttpVersion::Http2,
        )?;
        let mut sender = self.sender.clone();
        let response = tokio::select! {
            _ = state.cancelled() => return Err(cancelled_packet_error()),
            response = sender.send_request(request) => {
                response.map_err(|error| io_err(format!("xhttp H2 packet request: {error}")))?
            }
        };
        ensure_ok(response.status(), "xhttp H2 packet")?;
        drain_packet_ack_body(response.into_body(), &state, "H2").await?;
        Ok(())
    }
}

fn cancelled_packet_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "xhttp packet upload cancelled")
}

async fn drain_packet_ack_body<B>(
    mut body: B,
    state: &Arc<IoState>,
    version: &'static str,
) -> io::Result<()>
where
    B: HyperBody<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut received = 0_usize;
    loop {
        let frame = tokio::select! {
            _ = state.cancelled() => return Err(cancelled_packet_error()),
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let frame = frame
            .map_err(|error| io_err(format!("xhttp {version} packet response body: {error}")))?;
        if let Some(data) = frame.data_ref() {
            received = received.saturating_add(data.len());
            if received > MAX_PACKET_ACK_BODY_BYTES {
                return Err(io_err(format!(
                    "xhttp {version} packet response body exceeds {MAX_PACKET_ACK_BODY_BYTES} bytes"
                )));
            }
        }
    }
}

impl ManagedConnection for Http2Client {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.sender.is_closed()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

fn tls_options_for_profile(profile: &DialProfile) -> TlsOptions {
    TlsOptions {
        enabled: true,
        sni: profile
            .sni
            .clone()
            .or_else(|| Some(profile.dial_host.clone())),
        insecure: profile.insecure,
        alpn: profile.alpn.clone(),
        enable_session_resumption: profile.enable_session_resumption,
        fingerprint: profile.fingerprint.clone().unwrap_or_default(),
        pinned_peer_cert_sha256: profile.pinned_peer_cert_sha256.clone(),
        verify_peer_cert_by_name: profile.verify_peer_cert_by_name.clone(),
        xray_settings: profile.tls_settings.clone(),
        resolved_ech_config_list: None,
    }
}

async fn connect_tcp(profile: &DialProfile) -> io::Result<BoxedStream> {
    if profile.tls {
        TlsTransport::new(tls_options_for_profile(profile))
            .connect(&profile.dial_host, profile.port)
            .await
    } else {
        TcpTransport::default()
            .connect(&profile.dial_host, profile.port)
            .await
    }
}

fn deferred_hyper_response<F>(
    response: F,
    state: Arc<IoState>,
    version: &'static str,
) -> ResponseReader
where
    F: Future<Output = Result<hyper::Response<Incoming>, hyper::Error>> + Send + 'static,
{
    let (reader, tx) = ResponseReader::channel(8, state.clone());
    tokio::spawn(async move {
        let response = tokio::select! {
            _ = state.cancelled() => return,
            response = response => response,
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let failure = IoFailure::other(format!("xhttp {version} request: {error}"));
                let _ = tx.send(Err(failure.clone())).await;
                state.fail(failure);
                return;
            }
        };
        if response.status() != StatusCode::OK {
            let failure = IoFailure::other(format!(
                "xhttp {version} stream unexpected status {}",
                response.status()
            ));
            let _ = tx.send(Err(failure.clone())).await;
            state.fail(failure);
            return;
        }
        pump_hyper_body(response.into_body(), tx, state).await;
    });
    reader
}

async fn pump_hyper_body(
    mut body: Incoming,
    tx: mpsc::Sender<Result<Bytes, IoFailure>>,
    state: Arc<IoState>,
) {
    loop {
        tokio::select! {
            _ = state.cancelled() => return,
            frame = body.frame() => {
                match frame {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if !data.is_empty() && tx.send(Ok(data)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Err(error)) => {
                        let failure = IoFailure::other(format!(
                            "xhttp response body: {error}"
                        ));
                        let _ = tx.send(Err(failure.clone())).await;
                        state.fail(failure);
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

/// packet-up 有界写端及完成屏障。
pub struct PacketUpWriter {
    writer: PipeWriter,
    max_write: usize,
    progress: Arc<UploadProgress>,
    state: Arc<IoState>,
    flush: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

impl PacketUpWriter {
    fn new(
        cfg: Arc<Config>,
        profile: DialProfile,
        session_id: String,
        pool: Arc<XmuxManager<HttpConnection>>,
        initial_lease: Arc<XmuxLease<HttpConnection>>,
        state: Arc<IoState>,
    ) -> io::Result<Self> {
        let (max_each_post, interval) = packet_up_ranges(&cfg)?;
        let max_write = max_each_post.rand();
        let capacity = cfg.normalized_sc_max_buffered_posts().max(1);
        let (writer, rx) = PipeWriter::channel(capacity, state.clone());
        let progress = Arc::new(UploadProgress::default());
        tokio::spawn(run_packet_worker(
            rx,
            cfg,
            profile,
            session_id,
            pool,
            initial_lease,
            state.clone(),
            progress.clone(),
            capacity,
            max_write,
            interval,
        ));
        Ok(Self {
            writer,
            max_write,
            progress,
            state,
            flush: None,
        })
    }
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = data.len().min(self.max_write);
        match Pin::new(&mut self.writer).poll_write(cx, &data[..length]) {
            Poll::Ready(Ok(written)) => {
                self.progress
                    .accepted
                    .fetch_add(written as u64, Ordering::AcqRel);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush.is_none() {
            let target = self.progress.accepted.load(Ordering::Acquire);
            let progress = self.progress.clone();
            let state = self.state.clone();
            self.flush = Some(Box::pin(
                async move { progress.wait_until(target, state).await },
            ));
        }
        let future = self.flush.as_mut().expect("flush future initialized");
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(result) => {
                self.flush = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.writer).poll_shutdown(cx),
            other => other,
        }
    }
}

#[derive(Default)]
struct UploadProgress {
    accepted: AtomicU64,
    completed: AtomicU64,
    out_of_order: Mutex<BTreeMap<u64, u64>>,
    notify: tokio::sync::Notify,
}

impl UploadProgress {
    fn complete_range(&self, start: u64, length: u64) {
        let end = start.saturating_add(length);
        let mut out_of_order = self.out_of_order.lock();
        let mut contiguous = self.completed.load(Ordering::Acquire);
        if end <= contiguous {
            return;
        }
        out_of_order.insert(start, end);
        while let Some(end) = out_of_order.remove(&contiguous) {
            contiguous = end;
        }
        self.completed.store(contiguous, Ordering::Release);
        drop(out_of_order);
        self.notify.notify_waiters();
    }

    async fn wait_until(&self, target: u64, state: Arc<IoState>) -> io::Result<()> {
        loop {
            let notified = self.notify.notified();
            if let Some(error) = state.error() {
                return Err(error);
            }
            if self.completed.load(Ordering::Acquire) >= target {
                return Ok(());
            }
            tokio::select! {
                _ = notified => {}
                _ = state.cancelled() => {
                    return Err(state.error().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::Interrupted, "xhttp upload cancelled")
                    }));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_packet_worker(
    mut rx: mpsc::Receiver<Bytes>,
    cfg: Arc<Config>,
    profile: DialProfile,
    session_id: String,
    pool: Arc<XmuxManager<HttpConnection>>,
    initial_lease: Arc<XmuxLease<HttpConnection>>,
    state: Arc<IoState>,
    progress: Arc<UploadProgress>,
    max_in_flight: usize,
    max_write: usize,
    interval: Option<Range>,
) {
    let mut lease = initial_lease;
    let mut sequence = 0_u64;
    let mut byte_offset = 0_u64;
    let mut requests = JoinSet::new();
    let mut input_closed = false;
    let mut pending = None;
    let mut last_started = None;

    loop {
        if input_closed && requests.is_empty() {
            return;
        }
        if input_closed || requests.len() >= max_in_flight {
            tokio::select! {
                _ = state.cancelled() => {
                    requests.abort_all();
                    return;
                }
                result = requests.join_next(), if !requests.is_empty() => {
                    if !finish_packet_task(result, &state, &progress) {
                        requests.abort_all();
                        return;
                    }
                }
            }
            continue;
        }

        let first = if let Some(data) = pending.take() {
            data
        } else {
            let data = tokio::select! {
                _ = state.cancelled() => {
                    requests.abort_all();
                    return;
                }
                result = requests.join_next(), if !requests.is_empty() => {
                    if !finish_packet_task(result, &state, &progress) {
                        requests.abort_all();
                        return;
                    }
                    continue;
                }
                data = rx.recv() => data,
            };
            let Some(data) = data else {
                input_closed = true;
                continue;
            };
            data
        };
        let data =
            coalesce_packet(first, &mut rx, max_write, &mut pending, &mut input_closed).await;

        if let (Some(last), Some(interval)) = (last_started, interval) {
            let delay = Duration::from_millis(interval.rand() as u64);
            let deadline = last + delay;
            if Instant::now() < deadline {
                tokio::select! {
                    _ = state.cancelled() => {
                        requests.abort_all();
                        return;
                    }
                    _ = tokio::time::sleep_until(deadline) => {}
                }
            }
        }

        if !lease.consume_request() {
            let next = tokio::select! {
                _ = state.cancelled() => {
                    requests.abort_all();
                    return;
                }
                next = request_lease(&pool, None) => next,
            };
            match next {
                Ok(next) => lease = next,
                Err(error) => {
                    state.fail(IoFailure::new(error.kind(), error.to_string()));
                    requests.abort_all();
                    return;
                }
            }
        }
        if state.is_cancelled() {
            requests.abort_all();
            return;
        }
        let mut request = PreparedRequest::new(
            cfg.normalized_uplink_http_method(),
            &profile.url(&cfg.normalized_path()),
            &profile.authority,
        );
        if let Err(error) = fill_packet_request(
            &cfg,
            &mut request,
            &session_id,
            &sequence.to_string(),
            &data,
        ) {
            state.fail(IoFailure::other(error));
            requests.abort_all();
            return;
        }
        if state.is_cancelled() {
            requests.abort_all();
            return;
        }
        sequence += 1;
        last_started = Some(Instant::now());
        let start = byte_offset;
        let length = data.len() as u64;
        byte_offset = byte_offset.saturating_add(length);
        let connection = lease.connection().clone();
        let keep_lease = lease.clone();
        let request_state = state.clone();
        requests.spawn(async move {
            let _keep_lease = keep_lease;
            PacketTaskResult {
                start,
                length,
                result: connection.post_packet(request, request_state).await,
            }
        });
    }
}

struct PacketTaskResult {
    start: u64,
    length: u64,
    result: io::Result<()>,
}

fn finish_packet_task(
    result: Option<Result<PacketTaskResult, tokio::task::JoinError>>,
    state: &Arc<IoState>,
    progress: &Arc<UploadProgress>,
) -> bool {
    match result {
        Some(Ok(PacketTaskResult {
            start,
            length,
            result: Ok(()),
        })) => {
            progress.complete_range(start, length);
            true
        }
        Some(Ok(PacketTaskResult {
            result: Err(error), ..
        })) => {
            state.fail(IoFailure::new(error.kind(), error.to_string()));
            false
        }
        Some(Err(error)) => {
            state.fail(IoFailure::other(format!(
                "xhttp packet upload task failed: {error}"
            )));
            false
        }
        None => true,
    }
}

async fn coalesce_packet(
    first: Bytes,
    rx: &mut mpsc::Receiver<Bytes>,
    max_write: usize,
    pending: &mut Option<Bytes>,
    input_closed: &mut bool,
) -> Bytes {
    debug_assert!(!first.is_empty() && first.len() <= max_write);
    if first.len() == max_write {
        return first;
    }

    // 给同一调度批次内连续的 AsyncWrite 一次进入有界队列的机会，随后
    // 非阻塞地合并；不会为凑满 POST 人为增加网络延迟。
    tokio::task::yield_now().await;
    // `max_write` is a protocol limit, not the amount of data currently
    // queued. Reserving it eagerly lets a valid high limit turn a one-byte
    // application write into a multi-gigabyte allocation.
    let mut packet = BytesMut::with_capacity(first.len());
    packet.extend_from_slice(&first);
    while packet.len() < max_write {
        match rx.try_recv() {
            Ok(next) if packet.len() + next.len() <= max_write => {
                packet.extend_from_slice(&next);
            }
            Ok(next) => {
                let remaining = max_write - packet.len();
                packet.extend_from_slice(&next[..remaining]);
                *pending = Some(next.slice(remaining..));
                break;
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                *input_closed = true;
                break;
            }
        }
    }
    packet.freeze()
}

pub struct RequestBody {
    rx: mpsc::Receiver<Bytes>,
}

impl HyperBody for RequestBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.rx
            .poll_recv(cx)
            .map(|item| item.map(|data| Ok(Frame::data(data))))
    }
}

pub struct OneShotBody {
    data: Option<Bytes>,
    length: u64,
}

impl OneShotBody {
    pub fn new(data: Bytes) -> Self {
        Self {
            length: data.len() as u64,
            data: Some(data),
        }
    }
}

impl HyperBody for OneShotBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.data.take() {
            Some(data) if !data.is_empty() => Poll::Ready(Some(Ok(Frame::data(data)))),
            _ => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(Bytes::is_empty)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.length)
    }
}

fn apply_streaming_upload_compat(
    request: &mut PreparedRequest,
    version: HttpVersion,
    has_streaming_upload: bool,
) {
    if version != HttpVersion::Http1 || !has_streaming_upload {
        return;
    }
    // Go's HTTP/1 server otherwise consumes the entire request body before
    // flushing response headers unless the handler explicitly enables full
    // duplex. Pinned Xray does not call EnableFullDuplex, while XHTTP
    // stream-one/stream-up deliberately keep their upload body open.
    // `Expect: 100-continue` takes Go's close-after-reply path, which skips
    // that pre-read and permits request and response bodies to progress
    // concurrently.
    request.set_header("Expect", "100-continue");
}

fn build_hyper_request(
    prepared: PreparedRequest,
    body: XhttpBody,
    version: HttpVersion,
) -> io::Result<hyper::Request<XhttpBody>> {
    let rendered = if version == HttpVersion::Http1 {
        prepared.origin_form()
    } else {
        prepared.absolute_url()
    };
    let uri = Uri::from_str(&rendered).map_err(|error| {
        let kind = if version == HttpVersion::Http1 {
            "H1 request target"
        } else {
            "request URI"
        };
        invalid_input(format!("xhttp {kind}: {error}"))
    })?;
    let mut request = hyper::Request::builder()
        .method(prepared.method.as_str())
        .uri(uri)
        .body(body)
        .map_err(|error| invalid_input(format!("xhttp request build: {error}")))?;
    apply_prepared_headers(
        &prepared,
        request.headers_mut(),
        version == HttpVersion::Http1,
    )?;
    if let Some(length) = prepared.content_length {
        request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string())
                .map_err(|error| invalid_input(format!("xhttp content-length: {error}")))?,
        );
    }
    Ok(request)
}

fn build_h3_request(prepared: PreparedRequest) -> io::Result<http::Request<()>> {
    let rendered = prepared.absolute_url();
    let mut request = http::Request::builder()
        .method(prepared.method.as_str())
        .uri(rendered.as_str())
        .body(())
        .map_err(|error| invalid_input(format!("xhttp H3 request build: {error}")))?;
    apply_prepared_headers(&prepared, request.headers_mut(), false)?;
    if let Some(length) = prepared.content_length {
        request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string())
                .map_err(|error| invalid_input(format!("xhttp content-length: {error}")))?,
        );
    }
    Ok(request)
}

fn apply_prepared_headers(
    prepared: &PreparedRequest,
    headers: &mut http::HeaderMap,
    include_host: bool,
) -> io::Result<()> {
    if include_host {
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(&prepared.host)
                .map_err(|error| invalid_input(format!("xhttp Host header: {error}")))?,
        );
    }
    for (name, value) in &prepared.headers {
        let name = HeaderName::try_from(name.as_str())
            .map_err(|error| invalid_input(format!("xhttp header name: {error}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| invalid_input(format!("xhttp header value: {error}")))?;
        // PreparedRequest mirrors Go's http.Header.Set semantics: the last
        // value for a case-insensitive field is authoritative.
        headers.insert(name, value);
    }
    if !prepared.cookies.is_empty() {
        let existing = headers
            .get(http::header::COOKIE)
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok());
        let value = prepared
            .cookie_header(existing)
            .expect("generated cookies guarantee a Cookie header");
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&value)
                .map_err(|error| invalid_input(format!("xhttp Cookie header: {error}")))?,
        );
    }
    Ok(())
}

fn clone_prepared(request: &PreparedRequest) -> PreparedRequest {
    request.clone()
}

fn ensure_ok(status: StatusCode, context: &str) -> io::Result<()> {
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(io_err(format!("{context} unexpected status {status}")))
    }
}

fn authority_for(host: &str) -> io::Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(invalid_input("xhttp HTTP host cannot be empty"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(if ip.is_ipv6() {
            format!("[{host}]")
        } else {
            host.to_owned()
        });
    }
    // Xray 的直接客户端不会按目标端口自动改写 requestURL.Host；只有
    // browser dialer 才追加非默认端口。用户显式写入的端口原样保留。
    Authority::from_str(host)
        .map(|value| value.to_string())
        .map_err(|error| invalid_input(format!("invalid xhttp HTTP authority: {error}")))
}

fn generate_session_id(cfg: &Config) -> io::Result<String> {
    if cfg.session_id_table.is_empty() {
        return Ok(uuid::Uuid::new_v4().to_string());
    }
    let table = match cfg.session_id_table.as_str() {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        value => value,
    };
    if table.is_empty() || !table.is_ascii() {
        return Err(invalid_input(
            "xhttp sessionIDTable must be non-empty ASCII",
        ));
    }
    let length = Range::parse(&cfg.session_id_length, "")
        .map_err(io_err)?
        .rand();
    if length == 0 {
        return Err(invalid_input(
            "xhttp sessionIDLength must be greater than zero when sessionIDTable is set",
        ));
    }
    let bytes = table.as_bytes();
    let mut rng = rand::thread_rng();
    Ok((0..length)
        .map(|_| bytes[rng.gen_range(0..bytes.len())] as char)
        .collect())
}

struct HyperTokioIo<S> {
    inner: S,
}

impl<S> HyperTokioIo<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> hyper::rt::Read for HyperTokioIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut temporary = vec![0_u8; buffer.remaining().min(16 * 1024)];
        let mut read_buffer = ReadBuf::new(&mut temporary);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buffer) {
            Poll::Ready(Ok(())) => {
                buffer.put_slice(read_buffer.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> hyper::rt::Write for HyperTokioIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn io_err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::super::config::{
        DownloadRealitySettings, DownloadSocketSettings, DownloadTlsSettings,
    };
    use super::*;

    fn test_h1_profile() -> DialProfile {
        DialProfile {
            dial_host: "127.0.0.1".into(),
            port: 80,
            authority: "127.0.0.1".into(),
            tls: false,
            sni: None,
            insecure: false,
            alpn: Vec::new(),
            enable_session_resumption: false,
            fingerprint: None,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            tls_settings: None,
            version: HttpVersion::Http1,
        }
    }

    async fn test_h1_sender() -> (Http1Sender, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(1024);
        let (sender, connection) = hyper::client::conn::http1::handshake(HyperTokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        (sender, peer)
    }

    #[tokio::test]
    async fn h1_idle_pool_concurrent_returns_never_exceed_limit() {
        let pool = Http1UploadPool::new();
        let now = Instant::now();
        let mut peers = Vec::new();
        let mut returns = JoinSet::new();
        for _ in 0..32 {
            let (sender, peer) = test_h1_sender().await;
            peers.push(peer);
            let pool = pool.clone();
            returns.spawn(async move {
                pool.put(sender, now);
            });
        }
        while let Some(result) = returns.join_next().await {
            result.unwrap();
        }

        assert_eq!(pool.idle_len(), H1_UPLOAD_MAX_IDLE_SENDERS);
        pool.close();
        assert_eq!(pool.idle_len(), 0);
        drop(peers);
    }

    #[tokio::test]
    async fn h1_idle_pool_reuses_healthy_and_rejects_expired_senders() {
        let pool = Http1UploadPool::new();
        let now = Instant::now();
        let (healthy, healthy_peer) = test_h1_sender().await;
        pool.put(healthy, now);
        assert!(pool.take(now + H1_UPLOAD_IDLE_TIMEOUT / 2).is_some());

        let (expired, expired_peer) = test_h1_sender().await;
        pool.put(expired, now);
        assert!(pool.take(now + H1_UPLOAD_IDLE_TIMEOUT).is_none());
        assert_eq!(pool.idle_len(), 0);
        pool.close();
        drop((healthy_peer, expired_peer));
    }

    #[tokio::test]
    async fn h1_idle_pool_reaper_actively_drops_expired_sender() {
        let pool = Http1UploadPool::new_with_idle_timeout(Duration::ZERO);
        let (sender, peer) = test_h1_sender().await;
        pool.put(sender, Instant::now());
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.idle_len() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("H1 idle sender reaper did not run");
        pool.close();
        drop(peer);
    }

    #[tokio::test]
    async fn h1_client_close_drains_pool_and_rejects_late_return() {
        let client = Http1Client::new(test_h1_profile());
        let now = Instant::now();
        let (first, first_peer) = test_h1_sender().await;
        let (second, second_peer) = test_h1_sender().await;
        client.upload_pool.put(first, now);
        client.upload_pool.put(second, now);
        assert_eq!(client.upload_pool.idle_len(), H1_UPLOAD_MAX_IDLE_SENDERS);

        client.close();
        assert!(client.is_closed());
        assert_eq!(client.upload_pool.idle_len(), 0);

        let (late, late_peer) = test_h1_sender().await;
        client.upload_pool.put(late, now);
        assert_eq!(client.upload_pool.idle_len(), 0);
        drop((first_peer, second_peer, late_peer));
    }

    #[test]
    fn version_decision_matches_xray() {
        assert_eq!(decide_http_version(false, false, &[]), HttpVersion::Http1);
        assert_eq!(
            decide_http_version(true, false, &["http/1.1".into()]),
            HttpVersion::Http1
        );
        assert_eq!(
            decide_http_version(true, false, &["h3".into()]),
            HttpVersion::Http3
        );
        assert_eq!(decide_http_version(true, false, &[]), HttpVersion::Http2);
        assert_eq!(
            decide_http_version(true, false, &["h2".into(), "http/1.1".into()]),
            HttpVersion::Http2
        );
        assert_eq!(
            decide_http_version(true, true, &["h3".into()]),
            HttpVersion::Http2
        );
    }

    #[test]
    fn primary_tls_defaults_alpn_and_never_uses_removed_insecure_mode() {
        let client = XhttpClient::new(Config::default(), "example.com", 443);
        let profile = client.primary_profile(&Config::default(), false).unwrap();
        assert_eq!(profile.version, HttpVersion::Http2);
        assert_eq!(profile.alpn, ["h2", "http/1.1"]);
        assert!(!profile.insecure);
        assert!(!profile.enable_session_resumption);

        let tls = tls_options_for_profile(&profile);
        assert_eq!(tls.alpn, profile.alpn);
        assert!(!tls.insecure);
        assert!(!tls.enable_session_resumption);

        let mut removed = client;
        removed.insecure = true;
        let error = removed
            .primary_profile(&Config::default(), false)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("allowInsecure=true has been removed")
        );
    }

    #[test]
    fn primary_typed_tls_fields_reach_the_real_dial_profile() {
        let mut client = XhttpClient::new(Config::default(), "192.0.2.10", 443);
        client.tls_settings = Some(DownloadTlsSettings {
            server_name: Some("tls.example".into()),
            alpn: Some(vec!["http/1.1".into()]),
            enable_session_resumption: Some(true),
            fingerprint: Some("chrome".into()),
            pinned_peer_cert_sha256: Some("22".repeat(32)),
            verify_peer_cert_by_name: Some("tls.example, 192.0.2.10".into()),
            ..Default::default()
        });

        let profile = client.primary_profile(&Config::default(), false).unwrap();
        assert_eq!(profile.dial_host, "192.0.2.10");
        assert_eq!(profile.sni.as_deref(), Some("tls.example"));
        assert_eq!(profile.alpn, ["http/1.1"]);
        assert_eq!(profile.version, HttpVersion::Http1);
        assert!(profile.enable_session_resumption);
        assert_eq!(profile.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(profile.pinned_peer_cert_sha256, [[0x22; 32]]);
        assert_eq!(
            profile.verify_peer_cert_by_name,
            ["tls.example", "192.0.2.10"]
        );
    }

    #[test]
    fn primary_advanced_tls_fields_are_validated_and_preserved_before_network_io() {
        let mut client = XhttpClient::new(Config::default(), "example.com", 443);
        client.tls_settings = Some(DownloadTlsSettings {
            min_version: Some("1.2".into()),
            max_version: Some("1.3".into()),
            curve_preferences: Some(vec!["X25519MLKEM768".into(), "X25519".into()]),
            ..Default::default()
        });
        let profile = client.primary_profile(&Config::default(), false).unwrap();
        let tls = profile.tls_settings.as_ref().unwrap();
        assert_eq!(tls.min_version.as_deref(), Some("1.2"));
        assert_eq!(tls.max_version.as_deref(), Some("1.3"));
        assert_eq!(
            tls.curve_preferences.as_deref(),
            Some(["X25519MLKEM768".into(), "X25519".into()].as_slice())
        );

        client.tls_settings = Some(DownloadTlsSettings {
            ech_config_list: Some("AA==".into()),
            ..Default::default()
        });
        let error = client
            .primary_profile(&Config::default(), false)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("echConfigList"));
    }

    #[test]
    fn authority_handles_defaults_custom_ports_and_ipv6() {
        assert_eq!(authority_for("example.com").unwrap(), "example.com");
        assert_eq!(
            authority_for("example.com:8443").unwrap(),
            "example.com:8443"
        );
        assert_eq!(authority_for("::1").unwrap(), "[::1]");
    }

    #[test]
    fn host_header_is_only_emitted_for_h1() {
        let prepared =
            PreparedRequest::new("GET", "https://example.com/resource?x=1", "example.com");
        let h1 = build_hyper_request(
            clone_prepared(&prepared),
            XhttpBody::Empty,
            HttpVersion::Http1,
        )
        .unwrap();
        assert_eq!(h1.uri(), "/resource?x=1");
        assert_eq!(h1.headers()[http::header::HOST], "example.com");

        let h2 = build_hyper_request(
            clone_prepared(&prepared),
            XhttpBody::Empty,
            HttpVersion::Http2,
        )
        .unwrap();
        assert_eq!(h2.uri().authority().unwrap(), "example.com");
        assert!(!h2.headers().contains_key(http::header::HOST));

        let h3 = build_h3_request(prepared).unwrap();
        assert_eq!(h3.uri().authority().unwrap(), "example.com");
        assert!(!h3.headers().contains_key(http::header::HOST));
    }

    #[test]
    fn h1_h2_and_h3_share_go_compatible_url_and_cookie_rendering() {
        let cfg = Config::default();
        let mut prepared = PreparedRequest::new("POST", "https://example.com/p%2F/", "example.com");
        super::super::request::apply_meta(&cfg, &mut prepared, "%2F", "17");
        prepared.add_header("Cookie", "user=1");
        prepared.add_cookie("sid", "a b,c\";d\\e\t\0%");

        let h1 = build_hyper_request(
            clone_prepared(&prepared),
            XhttpBody::Empty,
            HttpVersion::Http1,
        )
        .unwrap();
        let h2 = build_hyper_request(
            clone_prepared(&prepared),
            XhttpBody::Empty,
            HttpVersion::Http2,
        )
        .unwrap();
        let h3 = build_h3_request(prepared).unwrap();

        assert_eq!(h1.uri(), "/p%252F/%252F/17");
        assert_eq!(h2.uri(), "https://example.com/p%252F/%252F/17");
        assert_eq!(h3.uri(), "https://example.com/p%252F/%252F/17");
        for headers in [h1.headers(), h2.headers(), h3.headers()] {
            assert_eq!(headers[http::header::COOKIE], "user=1; sid=\"a b,cde%\"");
        }
    }

    #[test]
    fn expect_continue_is_only_added_to_h1_streaming_uploads() {
        let prepared = PreparedRequest::new("POST", "https://example.com/resource", "example.com");

        let mut h1_stream = clone_prepared(&prepared);
        apply_streaming_upload_compat(&mut h1_stream, HttpVersion::Http1, true);
        let (_h1_tx, h1_rx) = mpsc::channel(1);
        let h1 = build_hyper_request(
            h1_stream,
            XhttpBody::Stream(RequestBody { rx: h1_rx }),
            HttpVersion::Http1,
        )
        .unwrap();
        assert_eq!(h1.headers()[http::header::EXPECT], "100-continue");

        let mut h2_stream = clone_prepared(&prepared);
        apply_streaming_upload_compat(&mut h2_stream, HttpVersion::Http2, true);
        let (_h2_tx, h2_rx) = mpsc::channel(1);
        let h2 = build_hyper_request(
            h2_stream,
            XhttpBody::Stream(RequestBody { rx: h2_rx }),
            HttpVersion::Http2,
        )
        .unwrap();
        assert!(!h2.headers().contains_key(http::header::EXPECT));

        let mut h3_stream = clone_prepared(&prepared);
        apply_streaming_upload_compat(&mut h3_stream, HttpVersion::Http3, true);
        let h3 = build_h3_request(h3_stream).unwrap();
        assert!(!h3.headers().contains_key(http::header::EXPECT));

        let h1_packet = build_hyper_request(
            prepared,
            XhttpBody::OneShot(OneShotBody::new(Bytes::from_static(b"packet"))),
            HttpVersion::Http1,
        )
        .unwrap();
        assert!(!h1_packet.headers().contains_key(http::header::EXPECT));
    }

    #[test]
    fn prepared_headers_use_set_semantics_and_merge_generated_cookies() {
        let mut prepared =
            PreparedRequest::new("GET", "https://example.com/resource", "example.com");
        prepared.add_header("X-Test", "first");
        prepared.add_header("x-test", "last");
        prepared.add_header("Cookie", "user=kept");
        prepared.add_cookie("generated", "merged");

        let request = build_hyper_request(prepared, XhttpBody::Empty, HttpVersion::Http2).unwrap();
        let test_values = request
            .headers()
            .get_all("x-test")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(test_values, ["last"]);
        assert_eq!(
            request.headers()[http::header::COOKIE],
            "user=kept; generated=merged"
        );
    }

    #[test]
    fn keepalive_defaults_match_xray_by_http_version() {
        assert_eq!(keep_alive_interval(HttpVersion::Http1, 0), None);
        assert_eq!(
            keep_alive_interval(HttpVersion::Http2, 0),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            keep_alive_interval(HttpVersion::Http3, 0),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            keep_alive_interval(HttpVersion::Http2, 7),
            Some(Duration::from_secs(7))
        );
        assert_eq!(keep_alive_interval(HttpVersion::Http3, -1), None);
    }

    #[test]
    fn xmux_connection_lifecycle_ranges_are_not_sampled_at_manager_build() {
        let limits = xmux_limits(&XmuxConfig {
            c_max_reuse_times: "2-4".into(),
            h_max_request_times: "5-7".into(),
            h_max_reusable_secs: "10-12".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(limits.c_max_reuse_times, XmuxSampleRange { min: 2, max: 4 });
        assert_eq!(
            limits.h_max_request_times,
            XmuxSampleRange { min: 5, max: 7 }
        );
        assert_eq!(
            limits.h_max_reusable_secs,
            XmuxSampleRange { min: 10, max: 12 }
        );
    }

    #[test]
    fn configured_session_id_uses_table_and_length() {
        let mut cfg = Config::default();
        cfg.session_id_table = "number".into();
        cfg.session_id_length = "12".into();
        let id = generate_session_id(&cfg).unwrap();
        assert_eq!(id.len(), 12);
        assert!(id.bytes().all(|value| value.is_ascii_digit()));
    }

    #[tokio::test]
    async fn reality_fails_explicitly() {
        let client = XhttpClient::new(Config::default(), "example.com", 443);
        let error = match client.dial(true).await {
            Ok(_) => panic!("Reality must not silently fall back to ordinary TLS"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("Reality"));
    }

    #[test]
    fn download_tls_fingerprint_is_executable_and_sockopt_fails_closed() {
        let client = XhttpClient::new(Config::default(), "primary.example", 443);

        let fingerprint = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            security: "tls".into(),
            tls: Some(DownloadTlsSettings {
                fingerprint: Some("chrome".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let profile = client
            .profile_from_download(&fingerprint, &Config::default())
            .unwrap();
        assert_eq!(profile.fingerprint.as_deref(), Some("chrome"));

        let sockopt = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            socket: Some(DownloadSocketSettings {
                mark: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = client
            .profile_from_download(&sockopt, &Config::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("sockopt"));
    }

    #[test]
    fn download_requires_address_and_host_only_overrides_http_authority() {
        let client = XhttpClient::new(Config::default(), "primary.example", 443);
        let host_only = DownloadSettings {
            host: "download.example".into(),
            port: Some(8080),
            ..Default::default()
        };
        let error = client
            .profile_from_download(&host_only, &Config::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("requires a non-empty address"));

        let address_and_host = DownloadSettings {
            address: "192.0.2.10".into(),
            host: "cdn.example".into(),
            port: Some(443),
            security: "tls".into(),
            ..Default::default()
        };
        let profile = client
            .profile_from_download(&address_and_host, &Config::default())
            .unwrap();
        assert_eq!(profile.dial_host, "192.0.2.10");
        assert_eq!(profile.authority, "cdn.example");
        assert_eq!(profile.port, 443);
        assert_eq!(profile.version, HttpVersion::Http2);
    }

    #[test]
    fn download_security_type_is_the_only_security_selector() {
        let client = XhttpClient::new(Config::default(), "primary.example", 443);
        let inactive_settings = DownloadSettings {
            address: "download.example".into(),
            port: Some(80),
            tls: Some(DownloadTlsSettings {
                fingerprint: Some("chrome".into()),
                ..Default::default()
            }),
            reality: Some(DownloadRealitySettings {
                public_key: Some("unused".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let profile = client
            .profile_from_download(&inactive_settings, &Config::default())
            .unwrap();
        assert!(!profile.tls);
        assert_eq!(profile.version, HttpVersion::Http1);

        let tls_without_settings = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            security: "tls".into(),
            ..Default::default()
        };
        let profile = client
            .profile_from_download(&tls_without_settings, &Config::default())
            .unwrap();
        assert!(profile.tls);
        assert_eq!(profile.version, HttpVersion::Http2);
        assert_eq!(profile.alpn, ["h2", "http/1.1"]);
        assert!(!profile.insecure);
        assert!(!profile.enable_session_resumption);

        let reality = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            security: "reality".into(),
            ..Default::default()
        };
        let error = client
            .profile_from_download(&reality, &Config::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn download_method_precedence_and_supported_tls_fields_are_applied() {
        let client = XhttpClient::new(Config::default(), "primary.example", 443);
        let settings = DownloadSettings {
            address: "192.0.2.10".into(),
            host: "cdn.example".into(),
            port: Some(443),
            method: "xhttp".into(),
            network: "tcp".into(),
            security: "tls".into(),
            tls: Some(DownloadTlsSettings {
                server_name: Some("tls.example".into()),
                allow_insecure: Some(false),
                alpn: Some(vec!["http/1.1".into()]),
                enable_session_resumption: Some(true),
                pinned_peer_cert_sha256: Some("11".repeat(32)),
                verify_peer_cert_by_name: Some("tls.example, 127.0.0.1".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let profile = client
            .profile_from_download(&settings, &Config::default())
            .unwrap();
        assert_eq!(profile.dial_host, "192.0.2.10");
        assert_eq!(profile.authority, "cdn.example");
        assert_eq!(profile.sni.as_deref(), Some("tls.example"));
        assert!(!profile.insecure);
        assert_eq!(profile.alpn, ["http/1.1"]);
        assert!(profile.enable_session_resumption);
        assert_eq!(profile.version, HttpVersion::Http1);
        let tls = tls_options_for_profile(&profile);
        assert_eq!(tls.alpn, ["http/1.1"]);
        assert!(tls.enable_session_resumption);
        assert_eq!(tls.pinned_peer_cert_sha256, [[0x11; 32]]);
        assert_eq!(tls.verify_peer_cert_by_name, ["tls.example", "127.0.0.1"]);

        let mut removed = settings.clone();
        removed.tls.as_mut().unwrap().allow_insecure = Some(true);
        let error = client
            .profile_from_download(&removed, &Config::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("allowInsecure=true"));

        let rejected = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            method: "tcp".into(),
            network: "xhttp".into(),
            ..Default::default()
        };
        assert_eq!(
            client
                .profile_from_download(&rejected, &Config::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let malformed_pin = DownloadSettings {
            address: "download.example".into(),
            port: Some(443),
            security: "tls".into(),
            tls: Some(DownloadTlsSettings {
                pinned_peer_cert_sha256: Some("00".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = client
            .profile_from_download(&malformed_pin, &Config::default())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("expected 32"));
    }

    #[test]
    fn packet_ranges_reject_zero_max_post_lower_bound_and_disable_zero_interval() {
        let invalid = Config {
            sc_max_each_post_bytes: "0-1024".into(),
            ..Default::default()
        };
        let error = packet_up_ranges(&invalid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("from"));

        let no_interval = Config {
            sc_min_posts_interval_ms: "0-30".into(),
            ..Default::default()
        };
        assert_eq!(packet_up_ranges(&no_interval).unwrap().1, None);

        let interval = Config {
            sc_min_posts_interval_ms: "1-30".into(),
            ..Default::default()
        };
        assert_eq!(
            packet_up_ranges(&interval).unwrap().1,
            Some(Range::new(1, 30))
        );
    }

    #[tokio::test]
    async fn packet_dial_rejects_zero_lower_bound_before_network_io() {
        let cfg = Config {
            mode: "packet-up".into(),
            sc_max_each_post_bytes: "0-1024".into(),
            ..Default::default()
        };
        let mut client = XhttpClient::new(cfg, "invalid.test", 80);
        client.tls = false;
        let error = match client.dial(false).await {
            Ok(_) => panic!("zero lower bound must be rejected before dialing"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn packet_writer_splits_before_entering_bounded_queue() {
        let state = IoState::shared();
        let (inner, mut rx) = PipeWriter::channel(1, state.clone());
        let progress = Arc::new(UploadProgress::default());
        let mut writer = PacketUpWriter {
            writer: inner,
            max_write: 4,
            progress: progress.clone(),
            state,
            flush: None,
        };
        let written = writer.write(b"abcdefgh").await.unwrap();
        assert_eq!(written, 4);
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"abcd"));
        assert_eq!(progress.accepted.load(Ordering::Acquire), 4);
    }

    #[tokio::test]
    async fn packet_worker_batches_queued_writes_and_preserves_remainder() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from_static(b"ab")).await.unwrap();
        tx.send(Bytes::from_static(b"cdef")).await.unwrap();
        let first = rx.recv().await.unwrap();
        let mut pending = None;
        let mut input_closed = false;
        let packet = coalesce_packet(first, &mut rx, 4, &mut pending, &mut input_closed).await;
        assert_eq!(packet, Bytes::from_static(b"abcd"));
        assert_eq!(pending, Some(Bytes::from_static(b"ef")));
        assert!(!input_closed);
    }

    #[tokio::test]
    async fn packet_worker_batches_many_single_byte_writes() {
        let (tx, mut rx) = mpsc::channel(128);
        for _ in 0..100 {
            tx.send(Bytes::from_static(b"x")).await.unwrap();
        }
        drop(tx);

        let mut pending = None;
        let mut input_closed = false;
        let mut posts = 0;
        let mut bytes = 0;
        while bytes < 100 {
            let first = match pending.take() {
                Some(data) => data,
                None => rx.recv().await.unwrap(),
            };
            let packet = coalesce_packet(first, &mut rx, 32, &mut pending, &mut input_closed).await;
            posts += 1;
            bytes += packet.len();
        }
        assert_eq!(bytes, 100);
        assert_eq!(posts, 4);
        assert!(input_closed);
    }

    #[tokio::test]
    async fn packet_coalescing_does_not_reserve_the_configured_maximum() {
        let (_tx, mut rx) = mpsc::channel(1);
        let mut pending = None;
        let mut input_closed = false;
        let packet = coalesce_packet(
            Bytes::from_static(b"x"),
            &mut rx,
            usize::MAX,
            &mut pending,
            &mut input_closed,
        )
        .await;
        assert_eq!(packet, Bytes::from_static(b"x"));
    }

    #[tokio::test]
    async fn packet_ack_body_has_a_hard_streaming_limit() {
        let state = IoState::shared();
        let body =
            http_body_util::Full::new(Bytes::from(vec![0_u8; MAX_PACKET_ACK_BODY_BYTES + 1]));
        let error = drain_packet_ack_body(body, &state, "test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    struct PendingAckBody;

    impl HyperBody for PendingAckBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn packet_ack_body_wait_is_cancelled_with_the_logical_stream() {
        let state = IoState::shared();
        state.cancel();
        let error = tokio::time::timeout(
            Duration::from_millis(100),
            drain_packet_ack_body(PendingAckBody, &state, "test"),
        )
        .await
        .expect("cancelled ACK drain stayed pending")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn packet_flush_progress_only_advances_contiguously() {
        let progress = UploadProgress::default();
        progress.complete_range(4, 4);
        assert_eq!(progress.completed.load(Ordering::Acquire), 0);
        progress.complete_range(0, 4);
        assert_eq!(progress.completed.load(Ordering::Acquire), 8);
    }

    #[tokio::test]
    async fn packet_flush_reports_connection_error_even_for_empty_barrier() {
        let progress = UploadProgress::default();
        let state = IoState::shared();
        state.fail(IoFailure::other("packet transport failed"));
        let error = progress.wait_until(0, state).await.unwrap_err();
        assert!(error.to_string().contains("packet transport failed"));
    }

    #[tokio::test]
    async fn packet_worker_cancellation_interrupts_a_pending_xmux_factory() {
        const FIRST_PACKET: &[u8] = b"first-packet-marker";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let first_request_done = Arc::new(Notify::new());
        let server_done = first_request_done.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request
                .windows(FIRST_PACKET.len())
                .any(|window| window == FIRST_PACKET)
            {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "packet request closed before its body arrived");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            server_done.notify_one();
        });

        let mut profile = test_h1_profile();
        profile.port = address.port();
        let factory_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory_entered = Arc::new(Notify::new());
        let pool = {
            let factory_calls = factory_calls.clone();
            let factory_entered = factory_entered.clone();
            let profile = profile.clone();
            Arc::new(XmuxManager::new(
                XmuxLimits {
                    max_connections: 2,
                    h_max_request_times: XmuxSampleRange::fixed(1),
                    ..Default::default()
                },
                move || {
                    let call = factory_calls.fetch_add(1, Ordering::AcqRel);
                    let factory_entered = factory_entered.clone();
                    let profile = profile.clone();
                    async move {
                        if call == 0 {
                            Ok(Arc::new(HttpConnection::H1(Http1Client::new(profile))))
                        } else {
                            factory_entered.notify_one();
                            std::future::pending::<io::Result<Arc<HttpConnection>>>().await
                        }
                    }
                },
            ))
        };
        let initial_lease = Arc::new(pool.acquire().await.unwrap());
        let state = IoState::shared();
        let progress = Arc::new(UploadProgress::default());
        let cfg = Arc::new(Config {
            mode: "packet-up".into(),
            path: "/".into(),
            x_padding_bytes: "1".into(),
            ..Default::default()
        });
        let (tx, rx) = mpsc::channel(2);
        let worker = tokio::spawn(run_packet_worker(
            rx,
            cfg,
            profile,
            "cancel-session".into(),
            pool,
            initial_lease,
            state.clone(),
            progress,
            1,
            64,
            None,
        ));

        tx.send(Bytes::from_static(FIRST_PACKET)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), first_request_done.notified())
            .await
            .expect("first packet POST did not complete");
        tx.send(Bytes::from_static(b"second")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), factory_entered.notified())
            .await
            .expect("worker did not enter the replacement XMUX factory");

        state.cancel();
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("cancelled packet worker remained stuck in the XMUX factory")
            .expect("packet worker task panicked");
        assert_eq!(factory_calls.load(Ordering::Acquire), 2);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cleartext_h1_stream_one_returns_before_response_headers() {
        const FIRST_BODY: &[u8] = b"xhttp-first-body-byte";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending H1 headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            assert!(headers.starts_with("post / http/1.1\r\n"));
            assert!(headers.contains("transfer-encoding: chunked\r\n"));
            assert!(!headers.contains("content-length:"));
            assert!(headers.contains("expect: 100-continue\r\n"));
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();

            // 固定 Xray 的 Go HTTP/1 服务端会借助 Expect 标记跳过响应前
            // 的完整请求体预读；同时它仍可能等首个上行字节后才发响应头。
            // hyper 必须忽略这个中间响应，dial 也必须先返回 stream，让
            // 调用者可以发送首字节并继续等待最终 200。
            while !request[header_end..]
                .windows(FIRST_BODY.len())
                .any(|window| window == FIRST_BODY)
            {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending first H1 body bytes");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            // stream-one 的请求体在逻辑连接关闭前不会 EOF；服务器必须允许
            // 响应与仍在上传的 chunked body 并行存在。
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut cfg = Config::default();
        cfg.mode = "stream-one".into();
        cfg.path = "/".into();
        let mut client = XhttpClient::new(cfg, "127.0.0.1", address.port());
        client.tls = false;
        let mut stream = tokio::time::timeout(Duration::from_secs(5), client.dial(false))
            .await
            .expect("H1 dial waited for response headers")
            .unwrap();
        stream.write_all(FIRST_BODY).await.unwrap();
        let mut response = [0_u8; 5];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
            .await
            .expect("H1 response timed out")
            .unwrap();
        assert_eq!(&response, b"hello");
        server.await.unwrap();
    }
}
