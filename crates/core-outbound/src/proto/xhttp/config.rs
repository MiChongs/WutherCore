//! XHTTP Config —— 与 mihomo `transport/xhttp/config.go` 等价。
//!
//! XHTTP 是 v2ray/xray 设计的高性能 HTTP 传输层，把代理流量伪装成普通 HTTP/1.1、
//! HTTP/2 或 HTTP/3 流量。三种工作模式：
//!
//! * **stream-one**：单一长连接 POST，请求/响应 body 双向流式
//! * **stream-up**：上行 POST + 下行独立 GET 长连接
//! * **packet-up**：上行多次短 POST，下行 GET 长连接（CDN 友好）
//!
//! ## Placement（数据放置位置）
//!
//! session_id / seq / uplink_data / x_padding 都可放在不同位置：
//! * `path`：拼接到 URL 路径
//! * `query`：URL 查询参数
//! * `header`：HTTP 头
//! * `cookie`：Cookie
//! * `body`：请求体
//! * `queryInHeader`：放在某个 header 里的 URL query（如 Referer）

use std::collections::BTreeMap;

use http::{HeaderName, HeaderValue};
use rand::Rng;

pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub const PLACEMENT_COOKIE: &str = "cookie";
pub const PLACEMENT_HEADER: &str = "header";
pub const PLACEMENT_QUERY: &str = "query";
pub const PLACEMENT_PATH: &str = "path";
pub const PLACEMENT_BODY: &str = "body";
pub const PLACEMENT_AUTO: &str = "auto";
/// 业务层 packet-up 缓冲 POST 上限，保证可安全传给 Tokio 有界队列。
pub const XHTTP_MAX_BUFFERED_POSTS: i64 = 1_000_000;
/// 单次 XHTTP padding 的业务上限，避免可信配置错误触发超大连续字符串分配。
pub const XHTTP_MAX_PADDING_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmuxConfig {
    pub max_concurrency: String,
    pub max_connections: String,
    pub c_max_reuse_times: String,
    pub h_max_request_times: String,
    pub h_max_reusable_secs: String,
    /// Xray 允许负值表示禁用 keepalive。
    pub h_keep_alive_period: i64,
}

impl Default for XmuxConfig {
    fn default() -> Self {
        Self {
            max_concurrency: String::new(),
            max_connections: String::new(),
            c_max_reuse_times: String::new(),
            h_max_request_times: String::new(),
            h_max_reusable_secs: String::new(),
            h_keep_alive_period: 0,
        }
    }
}

impl XmuxConfig {
    fn is_zero(&self) -> bool {
        self.max_concurrency.is_empty()
            && self.max_connections.is_empty()
            && self.c_max_reuse_times.is_empty()
            && self.h_max_request_times.is_empty()
            && self.h_max_reusable_secs.is_empty()
            && self.h_keep_alive_period == 0
    }

    fn apply_xray_defaults(&mut self) {
        if self.is_zero() {
            self.max_connections = "6".into();
            self.h_max_request_times = "600-900".into();
            self.h_max_reusable_secs = "1800-3000".into();
        }
    }
}

/// 旧内部名字仅保留为源码兼容别名；配置与注册统一使用 Xray 的 XMUX。
pub type ReuseConfig = XmuxConfig;

pub type DownloadTlsSettings = core_config::model::XhttpDownloadTlsSettings;
pub type DownloadRealitySettings = core_config::model::XhttpDownloadRealitySettings;
pub type DownloadSocketSettings = core_config::model::XhttpDownloadSocketSettings;
pub type DownloadFinalMask = core_config::model::XhttpFinalMask;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadTransportSettings {
    pub kind: String,
    pub host: String,
    pub path: String,
    pub service: String,
    pub xhttp: Option<Box<Config>>,
}

/// Xray `internet.StreamConfig` 的下载方向运行时表示。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadSettings {
    pub address: String,
    pub host: String,
    pub port: Option<u16>,
    pub method: String,
    pub network: String,
    pub transport: Option<DownloadTransportSettings>,
    /// Xray 的顶层 `downloadSettings.xhttpSettings` 兼容别名。
    ///
    /// 运行时保留它而不是在映射时覆盖 `transport.xhttp`，这样两种来源可以在
    /// 应用默认值后再次做语义等价校验。
    pub xhttp_settings: Option<Box<Config>>,
    pub security: String,
    pub tls: Option<DownloadTlsSettings>,
    pub reality: Option<DownloadRealitySettings>,
    pub alpn: Vec<String>,
    pub socket: Option<DownloadSocketSettings>,
    pub final_mask: Option<DownloadFinalMask>,
}

impl DownloadSettings {
    pub fn xhttp_config(&self) -> Option<&Config> {
        self.xhttp_settings.as_deref().or_else(|| {
            self.transport
                .as_ref()
                .and_then(|transport| transport.xhttp.as_deref())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub host: String,
    pub path: String,
    /// "auto" | "stream-one" | "stream-up" | "packet-up"
    pub mode: String,
    pub headers: BTreeMap<String, String>,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,

    /// "100-1000" 默认
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    /// "repeat-x" | "tokenish"
    pub x_padding_method: String,

    pub uplink_http_method: String, // 默认 POST

    pub session_placement: String, // Xray sessionIDPlacement，默认 path
    pub session_key: String,       // Xray sessionIDKey
    pub session_id_table: String,
    pub session_id_length: String,
    pub seq_placement: String, // 默认 path
    pub seq_key: String,
    pub uplink_data_placement: String, // 默认 auto
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,

    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: String,
    pub server_max_header_bytes: i32,

    pub xmux: XmuxConfig,
    pub download_settings: Option<Box<DownloadSettings>>,
    /// Xray `extra` 是另一个强类型 SplitHTTPConfig；外层只覆盖 host/path/mode。
    pub extra: Option<Box<Config>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: String::new(),
            mode: String::new(),
            headers: BTreeMap::new(),
            no_grpc_header: false,
            no_sse_header: false,
            x_padding_bytes: String::new(),
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".into(),
            x_padding_header: "X-Padding".into(),
            x_padding_placement: PLACEMENT_QUERY_IN_HEADER.into(),
            x_padding_method: "repeat-x".into(),
            uplink_http_method: "POST".into(),
            session_placement: PLACEMENT_PATH.into(),
            session_key: String::new(),
            session_id_table: String::new(),
            session_id_length: String::new(),
            seq_placement: PLACEMENT_PATH.into(),
            seq_key: String::new(),
            uplink_data_placement: PLACEMENT_AUTO.into(),
            uplink_data_key: String::new(),
            uplink_chunk_size: String::new(),
            sc_max_each_post_bytes: String::new(),
            sc_min_posts_interval_ms: String::new(),
            sc_max_buffered_posts: 0,
            sc_stream_up_server_secs: String::new(),
            server_max_header_bytes: 0,
            xmux: XmuxConfig::default(),
            download_settings: None,
            extra: None,
        }
    }
}

impl Config {
    pub fn normalized_mode(&self) -> &str {
        if self.mode.is_empty() {
            "auto"
        } else {
            &self.mode
        }
    }

    pub fn effective_mode(&self, has_reality: bool) -> &str {
        let mode = self.normalized_mode();
        if mode != "auto" {
            return mode;
        }
        if has_reality {
            if self.download_settings.is_some() {
                "stream-up"
            } else {
                "stream-one"
            }
        } else {
            "packet-up"
        }
    }

    pub fn normalized_path(&self) -> String {
        // Xray stores `path` and its optional raw query in one config string,
        // but normalizes them independently. Appending the metadata slash to
        // the whole string would turn `/p?token=1` into `/p?token=1/` and put
        // that slash inside the query instead of the URL path.
        let (raw_path, raw_query) = self
            .path
            .split_once('?')
            .map_or((self.path.as_str(), None), |(path, query)| {
                (path, (!query.is_empty()).then_some(query))
            });
        let mut path = raw_path.to_owned();
        if path.is_empty() {
            path = "/".into();
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if (self.normalized_session_placement() == PLACEMENT_PATH
            || self.normalized_seq_placement() == PLACEMENT_PATH)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        if let Some(query) = raw_query {
            path.push('?');
            path.push_str(query);
        }
        path
    }

    pub fn normalized_uplink_http_method(&self) -> &str {
        if self.uplink_http_method.is_empty() {
            "POST"
        } else {
            &self.uplink_http_method
        }
    }

    pub fn normalized_x_padding_key(&self) -> &str {
        if self.x_padding_key.is_empty() {
            "x_padding"
        } else {
            &self.x_padding_key
        }
    }

    pub fn normalized_x_padding_header(&self) -> &str {
        if self.x_padding_header.is_empty() {
            "X-Padding"
        } else {
            &self.x_padding_header
        }
    }

    pub fn normalized_x_padding_placement(&self) -> &str {
        if self.x_padding_placement.is_empty() {
            PLACEMENT_QUERY_IN_HEADER
        } else {
            &self.x_padding_placement
        }
    }

    pub fn normalized_x_padding_method(&self) -> &str {
        if self.x_padding_method.is_empty() {
            "repeat-x"
        } else {
            &self.x_padding_method
        }
    }

    pub fn normalized_session_placement(&self) -> &str {
        if self.session_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.session_placement
        }
    }

    pub fn normalized_seq_placement(&self) -> &str {
        if self.seq_placement.is_empty() {
            PLACEMENT_PATH
        } else {
            &self.seq_placement
        }
    }

    pub fn normalized_uplink_data_placement(&self) -> &str {
        if self.uplink_data_placement.is_empty() {
            PLACEMENT_AUTO
        } else {
            &self.uplink_data_placement
        }
    }

    pub fn normalized_session_key(&self) -> &str {
        if !self.session_key.is_empty() {
            return &self.session_key;
        }
        match self.normalized_session_placement() {
            PLACEMENT_HEADER => "X-Session",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session",
            _ => "",
        }
    }

    pub fn normalized_seq_key(&self) -> &str {
        if !self.seq_key.is_empty() {
            return &self.seq_key;
        }
        match self.normalized_seq_placement() {
            PLACEMENT_HEADER => "X-Seq",
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq",
            _ => "",
        }
    }

    pub fn normalized_uplink_data_key(&self) -> &str {
        if !self.uplink_data_key.is_empty() {
            return &self.uplink_data_key;
        }
        match self.normalized_uplink_data_placement() {
            PLACEMENT_COOKIE => "x_data",
            PLACEMENT_AUTO | PLACEMENT_HEADER => "X-Data",
            _ => "",
        }
    }

    pub fn normalized_x_padding_bytes(&self) -> Result<Range, String> {
        let range = Range::parse(&self.x_padding_bytes, "100-1000")?;
        let normalized = if range.max == 0 {
            Range::new(100, 1000)
        } else {
            range
        };
        if normalized.max > XHTTP_MAX_PADDING_BYTES {
            return Err(format!(
                "xPaddingBytes cannot exceed {XHTTP_MAX_PADDING_BYTES}"
            ));
        }
        Ok(normalized)
    }

    pub fn normalized_sc_max_each_post_bytes(&self) -> Result<Range, String> {
        let r = Range::parse(&self.sc_max_each_post_bytes, "1000000")?;
        if r.max == 0 {
            return Ok(Range::new(1_000_000, 1_000_000));
        }
        Ok(r)
    }

    pub fn normalized_sc_min_posts_interval_ms(&self) -> Result<Range, String> {
        let r = Range::parse(&self.sc_min_posts_interval_ms, "30")?;
        if r.max == 0 {
            return Ok(Range::new(30, 30));
        }
        Ok(r)
    }

    pub fn normalized_uplink_chunk_size(&self) -> Result<Range, String> {
        let mut r = Range::parse(&self.uplink_chunk_size, "")?;
        if r.max == 0 {
            return match self.normalized_uplink_data_placement() {
                PLACEMENT_COOKIE => Ok(Range::new(2 * 1024, 3 * 1024)),
                PLACEMENT_HEADER => Ok(Range::new(3 * 1000, 4 * 1000)),
                _ => self.normalized_sc_max_each_post_bytes(),
            };
        }
        if r.min < 64 {
            r.min = 64;
            if r.max < 64 {
                r.max = 64;
            }
        }
        Ok(r)
    }

    pub fn normalized_sc_max_buffered_posts(&self) -> usize {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts as usize
        }
    }

    pub fn normalized_sc_stream_up_server_secs(&self) -> Result<Range, String> {
        let range = Range::parse(&self.sc_stream_up_server_secs, "20-80")?;
        if range.max == 0 {
            Ok(Range::new(20, 80))
        } else {
            Ok(range)
        }
    }

    pub fn normalized_server_max_header_bytes(&self) -> usize {
        if self.server_max_header_bytes <= 0 {
            8192
        } else {
            self.server_max_header_bytes as usize
        }
    }

    /// 下载方向独立 XHTTP 配置；未设置时沿用上行配置。
    pub fn download_xhttp_config(&self) -> Result<&Config, String> {
        match self.download_settings.as_deref() {
            Some(settings) => settings
                .xhttp_config()
                .ok_or_else(|| "downloadSettings is missing independent XHTTP config".into()),
            None => Ok(self),
        }
    }

    pub fn resolved(&self) -> Result<Config, String> {
        let Some(extra) = &self.extra else {
            return Ok(self.clone());
        };
        // Xray unmarshals exactly one `extra` object, then copies only the
        // outer host/path/mode. It never calls Build recursively on
        // `extra.extra`, so a nested block must be ignored rather than win.
        let mut effective = (**extra).clone();
        effective.host.clone_from(&self.host);
        effective.path.clone_from(&self.path);
        effective.mode.clone_from(&self.mode);
        effective.extra = None;
        Ok(effective)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.resolved()?.validate_effective(0)
    }

    /// 解析 `extra`、应用 Xray 默认值并完成全部构建期校验。
    pub fn into_normalized(self) -> Result<Config, String> {
        let mut config = self.resolved()?;
        config.apply_xray_defaults()?;
        config.validate_effective(0)?;
        Ok(config)
    }

    fn apply_xray_defaults(&mut self) -> Result<(), String> {
        if self.mode.is_empty() {
            self.mode = "auto".into();
        }
        if self.x_padding_key.is_empty() {
            self.x_padding_key = "x_padding".into();
        }
        if self.x_padding_header.is_empty() {
            self.x_padding_header = "X-Padding".into();
        }
        if self.x_padding_placement.is_empty() {
            self.x_padding_placement = PLACEMENT_QUERY_IN_HEADER.into();
        }
        if self.x_padding_method.is_empty() {
            self.x_padding_method = "repeat-x".into();
        }
        if self.uplink_http_method.is_empty() {
            self.uplink_http_method = "POST".into();
        } else {
            self.uplink_http_method.make_ascii_uppercase();
        }
        if self.session_placement.is_empty() {
            self.session_placement = PLACEMENT_PATH.into();
        }
        if self.seq_placement.is_empty() {
            self.seq_placement = PLACEMENT_PATH.into();
        }
        if self.uplink_data_placement.is_empty() {
            self.uplink_data_placement = PLACEMENT_AUTO.into();
        }
        if self.uplink_data_key.is_empty() {
            self.uplink_data_key = match self.uplink_data_placement.as_str() {
                PLACEMENT_COOKIE => "x_data".into(),
                PLACEMENT_AUTO | PLACEMENT_HEADER => "X-Data".into(),
                _ => String::new(),
            };
        }
        self.xmux.apply_xray_defaults();
        if let Some(download) = &mut self.download_settings {
            if download.security.is_empty() {
                download.security = "none".into();
            }
            if let Some(xhttp) = download.xhttp_settings.take() {
                download.xhttp_settings = Some(Box::new((*xhttp).into_normalized()?));
            }
            if let Some(transport) = &mut download.transport {
                if let Some(xhttp) = transport.xhttp.take() {
                    transport.xhttp = Some(Box::new((*xhttp).into_normalized()?));
                }
            }
        }
        Ok(())
    }

    fn validate_effective(&self, depth: usize) -> Result<(), String> {
        if depth > 8 {
            return Err("xhttp.downloadSettings recursion exceeds 8 levels".into());
        }
        let mode = self.normalized_mode();
        if !matches!(mode, "auto" | "packet-up" | "stream-up" | "stream-one") {
            return Err(format!("unsupported xhttp mode: {mode}"));
        }
        for (name, value) in &self.headers {
            if is_managed_xhttp_header(name) {
                return Err(format!(
                    "xhttp headers cannot contain managed header {name}"
                ));
            }
            HeaderName::try_from(name.as_str())
                .map_err(|error| format!("invalid xhttp header name {name:?}: {error}"))?;
            HeaderValue::try_from(value.as_str())
                .map_err(|error| format!("invalid xhttp header value for {name}: {error}"))?;
        }

        let raw_x_padding = Range::parse(&self.x_padding_bytes, "")?;
        if raw_x_padding.max > 0 && raw_x_padding.min == 0 {
            return Err("xPaddingBytes cannot be disabled with a partial-zero range".into());
        }
        validate_choice(
            "xPaddingPlacement",
            if self.x_padding_placement.is_empty() {
                None
            } else {
                Some(self.x_padding_placement.as_str())
            },
            &["cookie", "header", "query", "queryInHeader"],
        )?;
        validate_choice(
            "xPaddingMethod",
            if self.x_padding_method.is_empty() {
                None
            } else {
                Some(self.x_padding_method.as_str())
            },
            &["repeat-x", "tokenish"],
        )?;
        validate_choice(
            "sessionIDPlacement",
            if self.session_placement.is_empty() {
                None
            } else {
                Some(self.session_placement.as_str())
            },
            &["path", "cookie", "header", "query"],
        )?;
        validate_choice(
            "seqPlacement",
            if self.seq_placement.is_empty() {
                None
            } else {
                Some(self.seq_placement.as_str())
            },
            &["path", "cookie", "header", "query"],
        )?;
        validate_choice(
            "uplinkDataPlacement",
            if self.uplink_data_placement.is_empty() {
                None
            } else {
                Some(self.uplink_data_placement.as_str())
            },
            &["auto", "body", "cookie", "header"],
        )?;

        let data_placement = self.normalized_uplink_data_placement();
        if matches!(data_placement, PLACEMENT_COOKIE | PLACEMENT_HEADER) && mode != "packet-up" {
            return Err(format!(
                "uplinkDataPlacement={data_placement} requires packet-up mode"
            ));
        }
        let method = self.normalized_uplink_http_method();
        http::Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("invalid uplinkHTTPMethod: {method}"))?;
        if method.eq_ignore_ascii_case("GET") && mode != "packet-up" {
            return Err("uplinkHTTPMethod=GET requires packet-up mode".into());
        }

        self.normalized_x_padding_bytes()?;
        self.normalized_sc_max_each_post_bytes()?;
        self.normalized_sc_min_posts_interval_ms()?;
        self.normalized_sc_stream_up_server_secs()?;
        self.normalized_uplink_chunk_size()?;
        if self.sc_max_buffered_posts < 0 {
            return Err("scMaxBufferedPosts cannot be negative".into());
        }
        if self.sc_max_buffered_posts > XHTTP_MAX_BUFFERED_POSTS {
            return Err(format!(
                "scMaxBufferedPosts cannot exceed {XHTTP_MAX_BUFFERED_POSTS}"
            ));
        }
        if self.server_max_header_bytes < 0 {
            return Err("serverMaxHeaderBytes cannot be negative".into());
        }

        validate_range_string("xmux.maxConcurrency", &self.xmux.max_concurrency)?;
        validate_range_string("xmux.maxConnections", &self.xmux.max_connections)?;
        validate_range_string("xmux.cMaxReuseTimes", &self.xmux.c_max_reuse_times)?;
        validate_range_string("xmux.hMaxRequestTimes", &self.xmux.h_max_request_times)?;
        validate_range_string("xmux.hMaxReusableSecs", &self.xmux.h_max_reusable_secs)?;
        let max_concurrency = Range::parse(&self.xmux.max_concurrency, "")?;
        let max_connections = Range::parse(&self.xmux.max_connections, "")?;
        if max_concurrency.max > 0 && max_connections.max > 0 {
            return Err("xmux.maxConnections conflicts with xmux.maxConcurrency".into());
        }

        if !self.session_id_table.is_empty() {
            let (alphabet, predefined) = expanded_session_id_table(&self.session_id_table);
            if !predefined {
                if !alphabet.is_ascii() {
                    return Err("custom sessionIDTable must contain ASCII only".into());
                }
            }
            let length = Range::parse(&self.session_id_length, "")?;
            if length.min == 0 {
                return Err("sessionIDLength.from must be greater than 0".into());
            }
            if !session_id_room_is_sufficient(alphabet, length.min, length.max) {
                return Err("possible session ID space must contain at least 31 bits".into());
            }
        } else {
            validate_range_string("sessionIDLength", &self.session_id_length)?;
        }

        if let Some(download) = &self.download_settings {
            if mode == "stream-one" {
                return Err("downloadSettings cannot be used in stream-one mode".into());
            }
            download.validate(depth + 1)?;
        }
        Ok(())
    }
}

impl DownloadSettings {
    pub(crate) fn validate(&self, depth: usize) -> Result<(), String> {
        let endpoint = if self.address.trim().is_empty() {
            self.host.trim()
        } else {
            self.address.trim()
        };
        if endpoint.is_empty() {
            return Err("downloadSettings requires address or host".into());
        }
        if self.port.is_none() || self.port == Some(0) {
            return Err("downloadSettings.port is required and cannot be zero".into());
        }
        if !self.security.is_empty()
            && !["none", "tls", "reality"]
                .iter()
                .any(|allowed| self.security.eq_ignore_ascii_case(allowed))
        {
            return Err(format!(
                "unsupported downloadSettings.security: {}",
                self.security
            ));
        }
        if self.security.eq_ignore_ascii_case("tls")
            && self
                .tls
                .as_ref()
                .and_then(|settings| settings.allow_insecure)
                .unwrap_or(false)
        {
            return Err(
                "downloadSettings.tlsSettings.allowInsecure=true has been removed by Xray; use \
                 pinnedPeerCertSha256 or verifyPeerCertByName"
                    .into(),
            );
        }
        if self.alpn.iter().any(|value| value.trim().is_empty()) {
            return Err("downloadSettings.alpn cannot contain empty values".into());
        }
        if self
            .tls
            .as_ref()
            .and_then(|settings| settings.alpn.as_ref())
            .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
        {
            return Err("downloadSettings.tlsSettings.alpn cannot contain empty values".into());
        }
        if let Some(tls_alpn) = self
            .tls
            .as_ref()
            .and_then(|settings| settings.alpn.as_ref())
            .filter(|values| !values.is_empty())
        {
            if !self.alpn.is_empty() && self.alpn != *tls_alpn {
                return Err(
                    "downloadSettings.alpn conflicts with non-empty tlsSettings.alpn".into(),
                );
            }
        }
        let effective_network = if self.method.trim().is_empty() {
            self.network.trim()
        } else {
            self.method.trim()
        };
        if !effective_network.is_empty()
            && !effective_network.eq_ignore_ascii_case("xhttp")
            && !effective_network.eq_ignore_ascii_case("splithttp")
        {
            return Err(format!(
                "downloadSettings.method/network must be xhttp or splithttp, got {effective_network}"
            ));
        }
        if let Some(transport) = self.transport.as_ref() {
            let kind = transport.kind.trim();
            if !kind.is_empty()
                && !kind.eq_ignore_ascii_case("xhttp")
                && !kind.eq_ignore_ascii_case("splithttp")
            {
                return Err(format!(
                    "downloadSettings.transport.kind must be xhttp or splithttp, got {kind}"
                ));
            }
            if !transport.service.trim().is_empty() {
                return Err(
                    "downloadSettings.transport.service is gRPC-only and unsupported by XHTTP"
                        .into(),
                );
            }
        }
        let direct_xhttp = self.xhttp_settings.as_deref();
        let transport_xhttp = self
            .transport
            .as_ref()
            .and_then(|transport| transport.xhttp.as_deref());
        if let (Some(direct), Some(nested)) = (direct_xhttp, transport_xhttp) {
            if direct.resolved()? != nested.resolved()? {
                return Err("downloadSettings.xhttpSettings conflicts with transport.xhttp".into());
            }
        }
        let xhttp = direct_xhttp
            .or(transport_xhttp)
            .ok_or_else(|| "downloadSettings requires independent XHTTP config".to_string())?;
        let effective_xhttp = xhttp.resolved()?;
        if let Some(transport) = self.transport.as_ref() {
            for (field, generic, nested) in [
                (
                    "host",
                    transport.host.as_str(),
                    effective_xhttp.host.as_str(),
                ),
                (
                    "path",
                    transport.path.as_str(),
                    effective_xhttp.path.as_str(),
                ),
            ] {
                if !generic.trim().is_empty() && !nested.trim().is_empty() && generic != nested {
                    return Err(format!(
                        "downloadSettings.transport.{field} conflicts with independent XHTTP {field}"
                    ));
                }
            }
        }
        effective_xhttp.validate_effective(depth)?;
        Ok(())
    }
}

fn validate_choice(field: &str, value: Option<&str>, allowed: &[&str]) -> Result<(), String> {
    if let Some(value) = value {
        if !allowed.contains(&value) {
            return Err(format!("unsupported {field}: {value}"));
        }
    }
    Ok(())
}

fn validate_range_string(field: &str, value: &str) -> Result<(), String> {
    Range::parse(value, "")
        .map(|_| ())
        .map_err(|error| format!("{field}: {error}"))
}

const MANAGED_XHTTP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "keep-alive",
    "upgrade",
    "trailer",
    "te",
    "http2-settings",
    "expect",
];

fn is_managed_xhttp_header(name: &str) -> bool {
    MANAGED_XHTTP_HEADERS
        .iter()
        .any(|managed| name.eq_ignore_ascii_case(managed))
}

fn expanded_session_id_table(table: &str) -> (&str, bool) {
    match table {
        "ALPHABET" => ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", true),
        "Alphabet" => ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true),
        "BASE36" => ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", true),
        "Base62" => (
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            true,
        ),
        "HEX" => ("0123456789ABCDEF", true),
        "alphabet" => ("abcdefghijklmnopqrstuvwxyz", true),
        "base36" => ("0123456789abcdefghijklmnopqrstuvwxyz", true),
        "hex" => ("0123456789abcdef", true),
        "number" => ("0123456789", true),
        custom => (custom, false),
    }
}

fn session_id_room_is_sufficient(table: &str, min_length: usize, max_length: usize) -> bool {
    const REQUIRED: u128 = 2u128 << 30;
    if min_length > max_length {
        return false;
    }

    let base = table.len() as u128;
    if base == 0 {
        return false;
    }
    if base == 1 {
        return (max_length - min_length) as u128 + 1 >= REQUIRED;
    }

    let mut term = pow_capped(base, min_length, REQUIRED);
    let mut room = 0u128;
    for _ in min_length..=max_length {
        room = room.checked_add(term).unwrap_or(REQUIRED).min(REQUIRED);
        if room >= REQUIRED {
            return true;
        }
        term = term.checked_mul(base).unwrap_or(REQUIRED).min(REQUIRED);
    }
    false
}

fn pow_capped(mut base: u128, mut exponent: usize, cap: u128) -> u128 {
    let mut result = 1u128;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result.checked_mul(base).unwrap_or(cap).min(cap);
            if result >= cap {
                return cap;
            }
        }
        exponent >>= 1;
        if exponent > 0 {
            base = base.checked_mul(base).unwrap_or(cap).min(cap);
        }
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub min: usize,
    pub max: usize,
}

impl Range {
    pub fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    pub fn rand(self) -> usize {
        if self.min == self.max {
            self.min
        } else {
            let mut rng = rand::thread_rng();
            // Xray common/crypto.RandBetween uses [from, to).
            self.min + rng.gen_range(0..(self.max - self.min))
        }
    }

    pub fn parse(s: &str, fallback: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Self::parse_inner(fallback);
        }
        Self::parse_inner(trimmed)
    }

    fn parse_inner(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self { min: 0, max: 0 });
        }
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 1 {
            let v: usize = parts[0]
                .trim()
                .parse()
                .map_err(|e| format!("invalid range: {e}"))?;
            if v > i32::MAX as usize {
                return Err(format!("range exceeds int32: {trimmed}"));
            }
            return Ok(Self { min: v, max: v });
        }
        if parts.len() != 2 {
            return Err(format!("invalid range: {trimmed}"));
        }
        let min: usize = parts[0]
            .trim()
            .parse()
            .map_err(|e| format!("invalid range min: {e}"))?;
        let max: usize = parts[1]
            .trim()
            .parse()
            .map_err(|e| format!("invalid range max: {e}"))?;
        if min > i32::MAX as usize || max > i32::MAX as usize {
            return Err(format!("range exceeds int32: {trimmed}"));
        }
        if max < min {
            return Err(format!("invalid range (min>max): {trimmed}"));
        }
        Ok(Self { min, max })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_download_settings() -> DownloadSettings {
        DownloadSettings {
            address: "download.example.com".into(),
            port: Some(443),
            network: "xhttp".into(),
            transport: Some(DownloadTransportSettings {
                kind: "xhttp".into(),
                xhttp: Some(Box::new(Config::default())),
                ..Default::default()
            }),
            security: "tls".into(),
            ..Default::default()
        }
    }

    #[test]
    fn range_parse_single() {
        let r = Range::parse("42", "0").unwrap();
        assert_eq!(r, Range::new(42, 42));
        assert_eq!(r.rand(), 42);
    }

    #[test]
    fn range_parse_min_max() {
        let r = Range::parse("10-100", "0").unwrap();
        assert_eq!(r.min, 10);
        assert_eq!(r.max, 100);
        for _ in 0..10 {
            let v = r.rand();
            assert!(v >= 10 && v <= 100);
        }
    }

    #[test]
    fn range_fallback() {
        let r = Range::parse("", "5-10").unwrap();
        assert_eq!(r.min, 5);
        assert_eq!(r.max, 10);
    }

    #[test]
    fn range_invalid() {
        assert!(Range::parse("abc", "0").is_err());
        assert!(Range::parse("100-50", "0").is_err());
        assert!(Range::parse("1-2-3", "0").is_err());
    }

    #[test]
    fn config_normalized_mode() {
        let mut c = Config::default();
        assert_eq!(c.normalized_mode(), "auto");
        c.mode = "packet-up".into();
        assert_eq!(c.normalized_mode(), "packet-up");
    }

    #[test]
    fn config_effective_mode() {
        let c = Config::default();
        assert_eq!(c.effective_mode(false), "packet-up");
        assert_eq!(c.effective_mode(true), "stream-one");
        let mut c2 = c.clone();
        c2.download_settings = Some(Box::new(valid_download_settings()));
        assert_eq!(c2.effective_mode(true), "stream-up");
    }

    #[test]
    fn config_normalized_path() {
        let mut c = Config::default();
        assert_eq!(c.normalized_path(), "/");
        c.path = "abc".into();
        assert_eq!(c.normalized_path(), "/abc/");
        c.path = "/a/b".into();
        assert_eq!(c.normalized_path(), "/a/b/");
        c.path = "/c/".into();
        assert_eq!(c.normalized_path(), "/c/");
        c.path = "/api?token=one&keep=two".into();
        assert_eq!(c.normalized_path(), "/api/?token=one&keep=two");
        c.path = "?token=one".into();
        assert_eq!(c.normalized_path(), "/?token=one");
    }

    #[test]
    fn config_default_session_keys() {
        let mut c = Config::default();
        c.session_placement = "header".into();
        assert_eq!(c.normalized_session_key(), "X-Session");
        c.session_placement = "cookie".into();
        assert_eq!(c.normalized_session_key(), "x_session");
        c.session_key = "custom".into();
        assert_eq!(c.normalized_session_key(), "custom");
    }

    #[test]
    fn session_id_table_matches_xray_ascii_and_room_validation() {
        for (table, length, expected_error) in
            [("HEX", "1-6", "31 bits"), ("字母", "8-12", "ASCII")]
        {
            let config = Config {
                session_id_table: table.into(),
                session_id_length: length.into(),
                ..Default::default()
            };
            let error = config.validate().unwrap_err();
            assert!(
                error.contains(expected_error),
                "unexpected error for {table}: {error}"
            );
        }

        // Xray accepts duplicate and URL-reserved ASCII and uses the raw table
        // length when calculating the configured session-ID room.
        let xray_compatible_custom = Config {
            session_id_table: "aaaaaaaaaaaaaaaa/?#[]@!$&'()*+,;=".into(),
            session_id_length: "8-12".into(),
            ..Default::default()
        };
        xray_compatible_custom.validate().unwrap();

        let summed_binary_range = Config {
            session_id_table: "ab".into(),
            session_id_length: "30-32".into(),
            ..Default::default()
        };
        summed_binary_range.validate().unwrap();

        let insufficient_binary_range = Config {
            session_id_table: "ab".into(),
            session_id_length: "29-30".into(),
            ..Default::default()
        };
        assert!(
            insufficient_binary_range
                .validate()
                .unwrap_err()
                .contains("31 bits")
        );

        for (table, shortest) in [
            ("ALPHABET", 7),
            ("Alphabet", 6),
            ("BASE36", 6),
            ("Base62", 6),
            ("HEX", 8),
            ("alphabet", 7),
            ("base36", 6),
            ("hex", 8),
            ("number", 10),
        ] {
            let config = Config {
                session_id_table: table.into(),
                session_id_length: format!("{shortest}-{}", shortest + 4),
                ..Default::default()
            };
            config
                .validate()
                .unwrap_or_else(|error| panic!("{table} should be safe: {error}"));
        }
    }

    #[test]
    fn sc_max_buffered_posts_enforces_business_limit() {
        let at_limit = Config {
            sc_max_buffered_posts: XHTTP_MAX_BUFFERED_POSTS,
            ..Default::default()
        };
        at_limit.validate().unwrap();

        let above_limit = Config {
            sc_max_buffered_posts: XHTTP_MAX_BUFFERED_POSTS + 1,
            ..Default::default()
        };
        assert_eq!(
            above_limit.validate().unwrap_err(),
            "scMaxBufferedPosts cannot exceed 1000000"
        );
    }

    #[test]
    fn x_padding_enforces_allocation_limit() {
        let at_limit = Config {
            x_padding_bytes: XHTTP_MAX_PADDING_BYTES.to_string(),
            ..Default::default()
        };
        assert_eq!(
            at_limit.normalized_x_padding_bytes().unwrap(),
            Range::new(XHTTP_MAX_PADDING_BYTES, XHTTP_MAX_PADDING_BYTES)
        );
        at_limit.validate().unwrap();

        let above_limit = Config {
            x_padding_bytes: (XHTTP_MAX_PADDING_BYTES + 1).to_string(),
            ..Default::default()
        };
        assert_eq!(
            above_limit.validate().unwrap_err(),
            "xPaddingBytes cannot exceed 1048576"
        );
    }

    #[test]
    fn headers_reject_managed_and_malformed_values_at_config_time() {
        for name in [
            "hOsT",
            "CONTENT-LENGTH",
            "Transfer-Encoding",
            "Connection",
            "Proxy-Connection",
            "Keep-Alive",
            "Upgrade",
            "Trailer",
            "TE",
            "HTTP2-Settings",
            "Expect",
        ] {
            let config = Config {
                headers: BTreeMap::from([(name.into(), "value".into())]),
                ..Default::default()
            };
            let error = config.validate().unwrap_err();
            assert!(
                error.contains("managed header"),
                "managed header {name} was not rejected correctly: {error}"
            );
        }

        for (name, value) in [
            ("bad name", "value"),
            ("X-Test", "ok\r\nInjected: yes"),
            ("X-Test", "bad\u{7f}value"),
        ] {
            let config = Config {
                headers: BTreeMap::from([(name.into(), value.into())]),
                ..Default::default()
            };
            assert!(
                config.validate().is_err(),
                "malformed header should fail: {name:?}={value:?}"
            );
        }

        let safe = Config {
            headers: BTreeMap::from([("X-Custom_~".into(), "visible\tvalue".into())]),
            ..Default::default()
        };
        safe.validate().unwrap();
    }

    #[test]
    fn config_uplink_chunk_default_for_cookie() {
        let mut c = Config::default();
        c.uplink_data_placement = "cookie".into();
        let r = c.normalized_uplink_chunk_size().unwrap();
        assert_eq!(r.min, 2 * 1024);
        assert_eq!(r.max, 3 * 1024);
    }

    #[test]
    fn config_uplink_chunk_min_floor() {
        let mut c = Config::default();
        c.uplink_chunk_size = "10-50".into();
        let r = c.normalized_uplink_chunk_size().unwrap();
        assert_eq!(r.min, 64);
        assert_eq!(r.max, 64);
    }

    #[test]
    fn x_padding_zero_defaults_but_partial_zero_range_is_rejected() {
        let mut disabled = Config::default();
        disabled.x_padding_bytes = "0".into();
        disabled.validate().unwrap();
        assert_eq!(
            disabled.normalized_x_padding_bytes().unwrap(),
            Range::new(100, 1000)
        );

        let mut ranged = Config::default();
        ranged.x_padding_bytes = "0-1000".into();
        assert!(
            ranged
                .validate()
                .unwrap_err()
                .contains("cannot be disabled")
        );
    }

    #[test]
    fn normalized_defaults_are_materialized_with_exact_header_units() {
        let config = Config {
            mode: "packet-up".into(),
            x_padding_key: String::new(),
            x_padding_header: String::new(),
            x_padding_placement: String::new(),
            x_padding_method: String::new(),
            uplink_data_placement: PLACEMENT_HEADER.into(),
            uplink_data_key: String::new(),
            ..Default::default()
        }
        .into_normalized()
        .unwrap();
        assert_eq!(config.x_padding_key, "x_padding");
        assert_eq!(config.x_padding_header, "X-Padding");
        assert_eq!(config.x_padding_placement, PLACEMENT_QUERY_IN_HEADER);
        assert_eq!(config.x_padding_method, "repeat-x");
        assert_eq!(config.uplink_data_key, "X-Data");
        assert_eq!(
            config.normalized_uplink_chunk_size().unwrap(),
            Range::new(3000, 4000)
        );
    }

    #[test]
    fn xmux_defaults_only_apply_when_entire_group_is_absent() {
        let absent = Config::default().into_normalized().unwrap();
        assert_eq!(absent.xmux.max_connections, "6");
        assert_eq!(absent.xmux.h_max_request_times, "600-900");
        assert_eq!(absent.xmux.h_max_reusable_secs, "1800-3000");

        let explicit_concurrency = Config {
            xmux: XmuxConfig {
                max_concurrency: "8".into(),
                ..Default::default()
            },
            ..Default::default()
        }
        .into_normalized()
        .unwrap();
        assert_eq!(explicit_concurrency.xmux.max_concurrency, "8");
        assert!(explicit_concurrency.xmux.max_connections.is_empty());
        assert!(explicit_concurrency.xmux.h_max_request_times.is_empty());

        let negative_keepalive = Config {
            xmux: XmuxConfig {
                h_keep_alive_period: -1,
                ..Default::default()
            },
            ..Default::default()
        };
        negative_keepalive.validate().unwrap();
    }

    #[test]
    fn sc_range_may_start_at_zero_like_pinned_xray() {
        let config = Config {
            sc_max_each_post_bytes: "0-1000000".into(),
            ..Default::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn download_security_empty_normalizes_to_none_and_tls_rejects_removed_insecure() {
        let mut empty = valid_download_settings();
        empty.security.clear();
        empty.tls = Some(DownloadTlsSettings {
            allow_insecure: Some(true),
            ..Default::default()
        });
        let normalized = Config {
            download_settings: Some(Box::new(empty)),
            ..Default::default()
        }
        .into_normalized()
        .unwrap();
        assert_eq!(
            normalized.download_settings.as_deref().unwrap().security,
            "none"
        );

        for allow_insecure in [None, Some(false)] {
            let mut download = valid_download_settings();
            download.tls = Some(DownloadTlsSettings {
                allow_insecure,
                ..Default::default()
            });
            download.validate(0).unwrap();
        }

        let mut removed = valid_download_settings();
        removed.tls = Some(DownloadTlsSettings {
            allow_insecure: Some(true),
            ..Default::default()
        });
        let error = removed.validate(0).unwrap_err();
        assert!(error.contains("allowInsecure=true has been removed"));
    }

    #[test]
    fn download_settings_are_strongly_required_and_never_fall_back() {
        let mut missing_endpoint = Config::default();
        missing_endpoint.download_settings = Some(Box::new(DownloadSettings {
            port: Some(443),
            transport: Some(DownloadTransportSettings {
                xhttp: Some(Box::new(Config::default())),
                ..Default::default()
            }),
            ..Default::default()
        }));
        assert!(missing_endpoint.validate().unwrap_err().contains("address"));

        let mut missing_port = Config::default();
        let mut download = valid_download_settings();
        download.port = None;
        missing_port.download_settings = Some(Box::new(download));
        assert!(missing_port.validate().unwrap_err().contains("port"));

        let mut missing_xhttp = Config::default();
        let mut download = valid_download_settings();
        download.transport.as_mut().unwrap().xhttp = None;
        missing_xhttp.download_settings = Some(Box::new(download));
        assert!(
            missing_xhttp
                .download_xhttp_config()
                .unwrap_err()
                .contains("independent XHTTP")
        );
        assert!(
            missing_xhttp
                .validate()
                .unwrap_err()
                .contains("independent XHTTP")
        );

        let mut valid = Config::default();
        valid.download_settings = Some(Box::new(valid_download_settings()));
        valid.validate().unwrap();
        assert!(!std::ptr::eq(
            valid.download_xhttp_config().unwrap(),
            &valid
        ));

        let mut invalid_kind = Config::default();
        let mut download = valid_download_settings();
        download.transport.as_mut().unwrap().kind = "grpc".into();
        invalid_kind.download_settings = Some(Box::new(download));
        assert!(
            invalid_kind
                .validate()
                .unwrap_err()
                .contains("transport.kind")
        );

        let mut grpc_service = Config::default();
        let mut download = valid_download_settings();
        download.transport.as_mut().unwrap().service = "download-service".into();
        grpc_service.download_settings = Some(Box::new(download));
        assert!(
            grpc_service
                .validate()
                .unwrap_err()
                .contains("transport.service")
        );
    }

    #[test]
    fn download_xhttp_aliases_compare_after_runtime_normalization() {
        let mut equivalent = Config::default();
        let mut download = valid_download_settings();
        download.xhttp_settings = Some(Box::new(Config {
            mode: "auto".into(),
            ..Default::default()
        }));
        equivalent.download_settings = Some(Box::new(download));
        equivalent.into_normalized().unwrap();

        let mut conflicting = Config::default();
        let mut download = valid_download_settings();
        download.xhttp_settings = Some(Box::new(Config {
            path: "/direct".into(),
            ..Default::default()
        }));
        conflicting.download_settings = Some(Box::new(download));
        assert!(
            conflicting
                .into_normalized()
                .unwrap_err()
                .contains("xhttpSettings")
        );
    }

    #[test]
    fn download_runtime_rejects_generic_transport_and_alpn_conflicts() {
        let mut host_conflict = Config::default();
        let mut download = valid_download_settings();
        let transport = download.transport.as_mut().unwrap();
        transport.host = "generic.example".into();
        transport.xhttp.as_mut().unwrap().host = "nested.example".into();
        host_conflict.download_settings = Some(Box::new(download));
        assert!(
            host_conflict
                .validate()
                .unwrap_err()
                .contains("transport.host")
        );

        let mut path_conflict = Config::default();
        let mut download = valid_download_settings();
        let transport = download.transport.as_mut().unwrap();
        transport.path = "/generic".into();
        transport.xhttp.as_mut().unwrap().path = "/nested".into();
        path_conflict.download_settings = Some(Box::new(download));
        assert!(
            path_conflict
                .validate()
                .unwrap_err()
                .contains("transport.path")
        );

        let mut alpn_conflict = Config::default();
        let mut download = valid_download_settings();
        download.alpn = vec!["h2".into(), "http/1.1".into()];
        download.tls = Some(Default::default());
        download.tls.as_mut().unwrap().alpn = Some(vec!["h2".into()]);
        alpn_conflict.download_settings = Some(Box::new(download));
        assert!(
            alpn_conflict
                .validate()
                .unwrap_err()
                .contains("tlsSettings.alpn")
        );
    }

    #[test]
    fn extra_supplies_body_while_outer_routing_fields_win() {
        let config = Config {
            host: "outer.example".into(),
            path: "/outer".into(),
            mode: "packet-up".into(),
            headers: BTreeMap::from([("X-Ignored".into(), "outer".into())]),
            extra: Some(Box::new(Config {
                host: "inner.example".into(),
                path: "/inner".into(),
                mode: "stream-up".into(),
                headers: BTreeMap::from([("X-Source".into(), "extra".into())]),
                no_sse_header: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        let resolved = config.resolved().unwrap();
        assert_eq!(resolved.host, "outer.example");
        assert_eq!(resolved.path, "/outer");
        assert_eq!(resolved.mode, "packet-up");
        assert_eq!(
            resolved.headers.get("X-Source").map(String::as_str),
            Some("extra")
        );
        assert!(resolved.no_sse_header);
        assert!(resolved.extra.is_none());
    }

    #[test]
    fn nested_extra_is_not_recursively_built() {
        let config = Config {
            host: "outer.example".into(),
            path: "/outer".into(),
            mode: "packet-up".into(),
            extra: Some(Box::new(Config {
                headers: BTreeMap::from([("X-Level".into(), "first".into())]),
                extra: Some(Box::new(Config {
                    headers: BTreeMap::from([("X-Level".into(), "second".into())]),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };
        let resolved = config.resolved().unwrap();
        assert_eq!(
            resolved.headers.get("X-Level").map(String::as_str),
            Some("first")
        );
        assert_eq!(resolved.host, "outer.example");
        assert_eq!(resolved.path, "/outer");
        assert_eq!(resolved.mode, "packet-up");
        assert!(resolved.extra.is_none());
    }

    #[test]
    fn random_range_uses_exclusive_upper_bound() {
        for _ in 0..128 {
            assert_eq!(Range::new(7, 8).rand(), 7);
        }
        assert_eq!(Range::new(9, 9).rand(), 9);
    }
}
