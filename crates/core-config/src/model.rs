//! 配置数据模型 —— 直接对应 §5 字段完整说明。
//!
//! 所有 field 默认值通过 `Profile::apply_defaults` 注入，
//! 模型本身只负责"原样反序列化 + 短写法/长写法兼容"。

use std::{collections::BTreeMap, fmt, time::Duration};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// 顶层配置 —— 用户实际写的 YAML。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// 必填，目前固定为 `1`。
    pub version: u32,
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub log: Option<Log>,
    #[serde(default)]
    pub listen: Option<Listen>,
    #[serde(default)]
    pub feeds: BTreeMap<String, FeedSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupSpec>,
    /// Mihomo 顶层 `rule-providers` 兼容入口。编译阶段会归一化进
    /// `route.sets`，不会原样进入 [`crate::runtime_plan::RuntimePlan`]。
    #[serde(
        default,
        rename = "rule-providers",
        alias = "rule_providers",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub rule_providers: BTreeMap<String, MihomoRuleProviderSpec>,
    #[serde(default)]
    pub route: Option<Route>,
    #[serde(default)]
    pub resolver: Option<Resolver>,
    #[serde(default)]
    pub capture: Option<Capture>,
    #[serde(default)]
    pub smart: Option<Smart>,
    #[serde(default)]
    pub ui: Option<Ui>,
    #[serde(default)]
    pub mesh: Option<Mesh>,
    /// 反查发起进程名 / 路径 —— 与 mihomo `find-process-mode` 1:1。
    /// `off`（默认）跳过反查；`strict` 仅当路由规则用到 process 字段时反查；
    /// `always` 每条连接都反查。Off 时 dashboard `process` 列永远空。
    #[serde(default, rename = "find-process-mode", alias = "find_process_mode")]
    pub find_process_mode: FindProcessMode,
}

/// `find-process-mode` 三态 —— 与 mihomo `C.FindProcessMode` 一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindProcessMode {
    /// 永不反查（mihomo 默认）。
    #[default]
    Off,
    /// 仅当 `route.steps` 用到 `process` 匹配时反查。
    Strict,
    /// 每条 TCP/UDP 连接都反查。
    Always,
}

impl FindProcessMode {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Desktop,
    Router,
    Server,
    Mobile,
}

impl Default for Profile {
    fn default() -> Self {
        Profile::Desktop
    }
}

/* ---------------- log ---------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl LogLevel {
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Text
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogFile {
    #[serde(default)]
    pub on: bool,
    #[serde(default = "default_log_file_path")]
    pub path: String,
}

impl Default for LogFile {
    fn default() -> Self {
        Self {
            on: false,
            path: default_log_file_path(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default)]
    pub level: LogLevel,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default = "default_true")]
    pub stdout: bool,
    #[serde(default)]
    pub file: LogFile,
    #[serde(default)]
    pub format: LogFormat,
    /// 周期性打印连接表聚合摘要的间隔。`0s` = 关（默认）。
    /// 推荐值 30s ~ 5m；< 1s 视为关，避免日志洪水。
    /// 输出 target=`conntable`，level=info：总数 / top-N 目的地 / top-N 进程 /
    /// by-rule / by-outbound / 长连接清单。
    #[serde(
        default,
        with = "humantime_serde",
        rename = "connection-summary-interval",
        alias = "connection_summary_interval"
    )]
    pub connection_summary_interval: Duration,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            on: true,
            level: LogLevel::Info,
            filter: None,
            stdout: true,
            file: LogFile::default(),
            format: LogFormat::Text,
            connection_summary_interval: Duration::ZERO,
        }
    }
}

/* ---------------- listen ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default)]
    pub local: Option<ListenLocal>,
    #[serde(default)]
    pub panel: Option<PanelBind>,
    /// XHTTP/SplitHTTP 服务端监听。既接受单个对象，也接受对象数组。
    #[serde(
        default,
        alias = "split-http",
        alias = "split_http",
        alias = "splithttp"
    )]
    pub xhttp: Option<XhttpListenSet>,
    #[serde(default)]
    pub share: Option<Share>,
    #[serde(default)]
    pub auth: Vec<String>,
    /// REALITY 是一层入站流安全协议；每个条目独立监听并在认证后交给
    /// `protocol` 指定的内层代理协议。
    #[serde(default, alias = "reality-inbounds", alias = "reality_inbounds")]
    pub reality: Vec<RealityListen>,
    /// WireGuard 服务端入站。每个条目绑定一个 UDP 端口，并把已认证对端的
    /// IPv4/IPv6 包交给 WutherCore 的 TCP/UDP 路由运行时。
    #[serde(default, alias = "wireguard-inbounds", alias = "wireguard_inbounds")]
    pub wireguard: Vec<WireGuardListen>,
    /// Young 原生入站。传输层是 Firefox 使用的 Mozilla Neqo HTTP/3/WebTransport。
    #[serde(default, alias = "young-inbounds", alias = "young_inbounds")]
    pub young: Vec<YoungListen>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardListen {
    #[serde(default = "default_wireguard_listen_host")]
    pub host: String,
    pub port: u16,
    #[serde(rename = "privateKey", alias = "private_key", alias = "private-key")]
    pub private_key: String,
    pub peers: Vec<WireGuardListenPeer>,
    #[serde(default = "default_wireguard_mtu")]
    pub mtu: usize,
    #[serde(
        default = "default_wireguard_packet_queue",
        rename = "packetQueue",
        alias = "packet_queue",
        alias = "packet-queue"
    )]
    pub packet_queue: usize,
    #[serde(
        default = "default_wireguard_handshake_rate_limit",
        rename = "handshakeRateLimit",
        alias = "handshake_rate_limit",
        alias = "handshake-rate-limit"
    )]
    pub handshake_rate_limit: u64,
}

impl std::fmt::Debug for WireGuardListen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardListen")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("private_key", &"<redacted>")
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("packet_queue", &self.packet_queue)
            .field("handshake_rate_limit", &self.handshake_rate_limit)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardListenPeer {
    #[serde(rename = "publicKey", alias = "public_key", alias = "public-key")]
    pub public_key: String,
    #[serde(
        default,
        rename = "presharedKey",
        alias = "preshared_key",
        alias = "preshared-key"
    )]
    pub preshared_key: Option<String>,
    #[serde(rename = "allowedIPs", alias = "allowed_ips", alias = "allowed-ips")]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub reserved: Vec<u8>,
    #[serde(
        default,
        rename = "persistentKeepalive",
        alias = "persistent_keepalive",
        alias = "persistent-keepalive"
    )]
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for WireGuardListenPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardListenPeer")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "<redacted>"),
            )
            .field("allowed_ips", &self.allowed_ips)
            .field("reserved", &self.reserved)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YoungListen {
    #[serde(default = "default_young_listen_host")]
    pub host: String,
    pub port: u16,
    #[serde(
        rename = "nssDatabase",
        alias = "nss_database",
        alias = "nss-database",
        alias = "nss-db"
    )]
    pub nss_database: String,
    #[serde(
        rename = "certificateNickname",
        alias = "certificate_nickname",
        alias = "certificate-nickname",
        alias = "certificate"
    )]
    pub certificate_nickname: String,
    pub authority: String,
    #[serde(default = "default_young_path")]
    pub path: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(
        default = "default_young_clock_skew",
        with = "humantime_serde",
        rename = "clockSkew",
        alias = "clock_skew",
        alias = "clock-skew"
    )]
    pub clock_skew: Duration,
    #[serde(
        default = "default_young_idle_timeout",
        with = "humantime_serde",
        rename = "idleTimeout",
        alias = "idle_timeout",
        alias = "idle-timeout"
    )]
    pub idle_timeout: Duration,
    #[serde(
        default = "default_young_max_streams",
        rename = "maxStreams",
        alias = "max_streams",
        alias = "max-streams"
    )]
    pub max_streams: u64,
    #[serde(
        default = "default_young_max_sessions",
        rename = "maxSessions",
        alias = "max_sessions",
        alias = "max-sessions"
    )]
    pub max_sessions: usize,
    #[serde(
        default = "default_young_max_flows",
        rename = "maxFlowsPerSession",
        alias = "max_flows_per_session",
        alias = "max-flows-per-session"
    )]
    pub max_flows_per_session: usize,
    #[serde(
        default = "default_young_decoy_status",
        rename = "decoyStatus",
        alias = "decoy_status",
        alias = "decoy-status"
    )]
    pub decoy_status: u16,
    #[serde(
        default = "default_young_decoy_body",
        rename = "decoyBody",
        alias = "decoy_body",
        alias = "decoy-body"
    )]
    pub decoy_body: String,
}

impl std::fmt::Debug for YoungListen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("YoungListen")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("nss_database", &self.nss_database)
            .field("certificate_nickname", &self.certificate_nickname)
            .field("authority", &self.authority)
            .field("path", &self.path)
            .field("user_count", &self.users.len())
            .field("clock_skew", &self.clock_skew)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_streams", &self.max_streams)
            .field("max_sessions", &self.max_sessions)
            .field("max_flows_per_session", &self.max_flows_per_session)
            .field("decoy_status", &self.decoy_status)
            .field("decoy_body_bytes", &self.decoy_body.len())
            .finish()
    }
}

/// Xray REALITY 服务端监听配置。
///
/// 字段名同时接受 Xray 的 camelCase 与本项目常用的 snake/kebab 写法；
/// 未知字段一律拒绝，避免把密钥或限速字段拼错后静默降级。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityListen {
    #[serde(default = "default_reality_listen_host")]
    pub host: String,
    pub port: u16,
    #[serde(default = "default_reality_inner_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub target: Option<RealityTarget>,
    #[serde(default)]
    pub dest: Option<RealityTarget>,
    #[serde(default, rename = "type", alias = "target_type", alias = "target-type")]
    pub target_type: Option<String>,
    #[serde(default)]
    pub show: bool,
    #[serde(
        default,
        rename = "masterKeyLog",
        alias = "master_key_log",
        alias = "master-key-log"
    )]
    pub master_key_log: Option<String>,
    #[serde(default)]
    pub xver: u8,
    #[serde(
        default,
        rename = "serverNames",
        alias = "server_names",
        alias = "server-names"
    )]
    pub server_names: Vec<String>,
    #[serde(
        default,
        rename = "privateKey",
        alias = "private_key",
        alias = "private-key"
    )]
    pub private_key: String,
    #[serde(
        default,
        rename = "minClientVer",
        alias = "min_client_ver",
        alias = "min-client-ver"
    )]
    pub min_client_ver: Option<String>,
    #[serde(
        default,
        rename = "maxClientVer",
        alias = "max_client_ver",
        alias = "max-client-ver"
    )]
    pub max_client_ver: Option<String>,
    /// 与 Xray 一致，单位为毫秒；0 表示不限制时钟差。
    #[serde(
        default,
        rename = "maxTimeDiff",
        alias = "max_time_diff",
        alias = "max-time-diff"
    )]
    pub max_time_diff_ms: u64,
    #[serde(default, rename = "shortIds", alias = "short_ids", alias = "short-ids")]
    pub short_ids: Vec<String>,
    #[serde(
        default,
        rename = "mldsa65Seed",
        alias = "mldsa65_seed",
        alias = "mldsa65-seed"
    )]
    pub mldsa65_seed: Option<String>,
    #[serde(
        default,
        rename = "limitFallbackUpload",
        alias = "limit_fallback_upload",
        alias = "limit-fallback-upload"
    )]
    pub limit_fallback_upload: RealityFallbackLimit,
    #[serde(
        default,
        rename = "limitFallbackDownload",
        alias = "limit_fallback_download",
        alias = "limit-fallback-download"
    )]
    pub limit_fallback_download: RealityFallbackLimit,
    #[serde(default)]
    pub limits: RealityResourceLimits,
}

impl std::fmt::Debug for RealityListen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityListen")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("user_count", &self.users.len())
            .field("target", &self.target)
            .field("dest", &self.dest)
            .field("target_type", &self.target_type)
            .field("show", &self.show)
            .field(
                "master_key_log",
                &self.master_key_log.as_ref().map(|_| "<redacted>"),
            )
            .field("xver", &self.xver)
            .field("server_names", &self.server_names)
            .field("private_key", &"<redacted>")
            .field("min_client_ver", &self.min_client_ver)
            .field("max_client_ver", &self.max_client_ver)
            .field("max_time_diff_ms", &self.max_time_diff_ms)
            .field("short_id_count", &self.short_ids.len())
            .field("has_mldsa65_seed", &self.mldsa65_seed.is_some())
            .field("limit_fallback_upload", &self.limit_fallback_upload)
            .field("limit_fallback_download", &self.limit_fallback_download)
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RealityTarget {
    Port(u16),
    Address(String),
}

impl RealityTarget {
    pub fn normalized(&self) -> String {
        match self {
            Self::Port(port) => format!("localhost:{port}"),
            Self::Address(address) => address.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RealityFallbackLimit {
    #[serde(
        default,
        rename = "afterBytes",
        alias = "after_bytes",
        alias = "after-bytes"
    )]
    pub after_bytes: u64,
    #[serde(
        default,
        rename = "bytesPerSec",
        alias = "bytes_per_sec",
        alias = "bytes-per-sec"
    )]
    pub bytes_per_sec: u64,
    #[serde(
        default,
        rename = "burstBytesPerSec",
        alias = "burst_bytes_per_sec",
        alias = "burst-bytes-per-sec"
    )]
    pub burst_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RealityResourceLimits {
    #[serde(
        default = "default_reality_handshake_timeout",
        with = "humantime_serde",
        alias = "handshake-timeout",
        alias = "handshakeTimeout"
    )]
    pub handshake_timeout: Duration,
    #[serde(
        default = "default_reality_target_handshake_timeout",
        with = "humantime_serde",
        alias = "target-handshake-timeout",
        alias = "targetHandshakeTimeout"
    )]
    pub target_handshake_timeout: Duration,
    #[serde(
        default = "default_reality_idle_timeout",
        with = "humantime_serde",
        alias = "idle-timeout",
        alias = "idleTimeout"
    )]
    pub idle_timeout: Duration,
    #[serde(
        default = "default_reality_max_client_hello_records",
        alias = "max-client-hello-records",
        alias = "maxClientHelloRecords"
    )]
    pub max_client_hello_records: usize,
    #[serde(
        default = "default_reality_max_client_hello_record_payload",
        alias = "max-client-hello-record-payload",
        alias = "maxClientHelloRecordPayload"
    )]
    pub max_client_hello_record_payload: usize,
    #[serde(
        default = "default_reality_max_client_hello_bytes",
        alias = "max-client-hello-bytes",
        alias = "maxClientHelloBytes"
    )]
    pub max_client_hello_bytes: usize,
    #[serde(
        default = "default_reality_max_client_hello_wire_bytes",
        alias = "max-client-hello-wire-bytes",
        alias = "maxClientHelloWireBytes"
    )]
    pub max_client_hello_wire_bytes: usize,
    #[serde(
        default = "default_reality_max_target_records",
        alias = "max-target-records",
        alias = "maxTargetRecords"
    )]
    pub max_target_records: usize,
    #[serde(
        default = "default_reality_max_target_handshake_bytes",
        alias = "max-target-handshake-bytes",
        alias = "maxTargetHandshakeBytes"
    )]
    pub max_target_handshake_bytes: usize,
    #[serde(
        default = "default_reality_application_buffer_bytes",
        alias = "application-buffer-bytes",
        alias = "applicationBufferBytes"
    )]
    pub application_buffer_bytes: usize,
    #[serde(
        default = "default_reality_max_concurrent_handshakes",
        alias = "max-concurrent-handshakes",
        alias = "maxConcurrentHandshakes"
    )]
    pub max_concurrent_handshakes: usize,
}

impl Default for RealityResourceLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: default_reality_handshake_timeout(),
            target_handshake_timeout: default_reality_target_handshake_timeout(),
            idle_timeout: default_reality_idle_timeout(),
            max_client_hello_records: default_reality_max_client_hello_records(),
            max_client_hello_record_payload: default_reality_max_client_hello_record_payload(),
            max_client_hello_bytes: default_reality_max_client_hello_bytes(),
            max_client_hello_wire_bytes: default_reality_max_client_hello_wire_bytes(),
            max_target_records: default_reality_max_target_records(),
            max_target_handshake_bytes: default_reality_max_target_handshake_bytes(),
            application_buffer_bytes: default_reality_application_buffer_bytes(),
            max_concurrent_handshakes: default_reality_max_concurrent_handshakes(),
        }
    }
}

/// listen.local 支持端口写法 / 完整对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListenLocal {
    Port(u16),
    Detail(ListenLocalDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListenLocalDetail {
    #[serde(default = "default_localhost")]
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub auth: Vec<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
}

/// `listen.xhttp` 的单项/数组兼容表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpListenSet {
    One(XhttpListener),
    Many(Vec<XhttpListener>),
}

impl XhttpListenSet {
    pub fn into_vec(self) -> Vec<XhttpListener> {
        match self {
            Self::One(listener) => vec![listener],
            Self::Many(listeners) => listeners,
        }
    }
}

/// 配置层允许的单监听 accept 队列上限，低于 Tokio mpsc 在所有支持平台的上限。
pub const XHTTP_MAX_ACCEPT_QUEUE: usize = 1_000_000;
/// 配置层允许的 packet-up 缓冲 POST 数量上限。
pub const XHTTP_MAX_BUFFERED_POSTS: i64 = 1_000_000;
/// 单次 XHTTP padding 的业务上限，避免可信配置错误触发超大连续字符串分配。
pub const XHTTP_MAX_PADDING_BYTES: u32 = 1_048_576;
/// 配置层允许的单监听底层连接上限，低于 Tokio semaphore 在所有支持平台的上限。
pub const XHTTP_MAX_ACTIVE_CONNECTIONS: usize = 1_000_000;
/// 配置层允许的单连接 H2/H3 并发流上限。
pub const XHTTP_MAX_CONCURRENT_STREAMS: u32 = 1_000_000;
/// 配置层允许的单监听全局活动 HTTP 流上限。
pub const XHTTP_MAX_ACTIVE_HTTP_STREAMS: usize = 1_000_000;

/// XHTTP 服务端监听配置。
///
/// `settings` 直接复用出站使用的完整 [`XhttpConfig`]，不会把字段降级为
/// `serde_json::Value` 或字符串 map。TLS 的 `cert` / `key` 都是文件路径；
/// 文件读取留给运行时，配置编译阶段负责要求路径非空且成对出现。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpListener {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_localhost", alias = "host", alias = "bind")]
    pub address: String,
    pub port: u16,
    /// 明确允许无 TLS 的 HTTP/1.1 或 h2c。默认 false，避免静默降级。
    #[serde(default)]
    pub cleartext: bool,
    /// Raw 服务端尚未提供协议级认证；监听非回环地址时必须显式确认风险。
    #[serde(
        default,
        rename = "allow-unauthenticated-non-loopback",
        alias = "allow_unauthenticated_non_loopback",
        alias = "allowUnauthenticatedNonLoopback"
    )]
    pub allow_unauthenticated_non_loopback: bool,
    #[serde(default)]
    pub tls: Option<XhttpListenTls>,
    #[serde(default = "default_xhttp_listen_alpn")]
    pub alpn: Vec<XhttpListenAlpn>,
    /// XHTTP 传输解封后的固定 TCP 目标。
    ///
    /// VLESS、VMess、Trojan 等代理协议拥有各自的认证、编解码和 UDP
    /// 语义，必须在各协议监听中显式选择 XHTTP 传输；这里不会注册一个
    /// 没有真实服务端实现的 `inner-protocol` 枚举。
    #[serde(default)]
    pub target: Option<XhttpListenTarget>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(
        default = "default_xhttp_accept_queue",
        rename = "accept-queue",
        alias = "accept_queue",
        alias = "backlog"
    )]
    pub accept_queue: usize,
    /// 单个监听允许同时保持的活动 relay 上限。
    #[serde(
        default = "default_xhttp_max_active_relays",
        rename = "max-active-relays",
        alias = "max_active_relays",
        alias = "maxActiveRelays"
    )]
    pub max_active_relays: usize,
    /// 单个监听允许同时保持的底层 TCP/TLS/QUIC 连接上限。
    #[serde(
        default = "default_xhttp_max_active_connections",
        rename = "max-active-connections",
        alias = "max_active_connections",
        alias = "maxActiveConnections"
    )]
    pub max_active_connections: usize,
    /// 单个 H2/H3 底层连接允许同时处理的 HTTP 流上限。
    #[serde(
        default = "default_xhttp_max_concurrent_streams",
        rename = "max-concurrent-streams",
        alias = "max_concurrent_streams",
        alias = "maxConcurrentStreams"
    )]
    pub max_concurrent_streams: u32,
    /// 单个监听跨全部底层连接允许同时处理的 HTTP 流上限。
    #[serde(
        default = "default_xhttp_max_active_http_streams",
        rename = "max-active-http-streams",
        alias = "max_active_http_streams",
        alias = "maxActiveHttpStreams"
    )]
    pub max_active_http_streams: usize,
    /// 已无活动 HTTP 请求/流时，底层连接可保持空闲的最长时间。
    #[serde(
        default = "default_xhttp_http_idle_timeout",
        rename = "http-idle-timeout",
        alias = "http_idle_timeout",
        alias = "httpIdleTimeout",
        with = "humantime_serde"
    )]
    pub http_idle_timeout: Duration,
    /// 浏览器 CORS 策略。缺省时使用 XrayCompatible；显式空数组禁用 CORS；
    /// 非空数组为 allowlist，`*` 必须独占。
    #[serde(
        default,
        rename = "cors-origins",
        alias = "cors_origins",
        alias = "corsOrigins",
        skip_serializing_if = "Option::is_none"
    )]
    pub cors_origins: Option<Vec<String>>,
    #[serde(
        default,
        rename = "settings",
        alias = "config",
        alias = "xhttpSettings",
        alias = "xhttp-settings",
        alias = "splithttpSettings",
        alias = "splithttp-settings"
    )]
    pub settings: XhttpConfig,
}

/// XHTTP Raw 内层透明字节隧道的固定目标。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpListenTarget {
    #[serde(alias = "address")]
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpListenTls {
    /// 旧版单证书 PEM 路径；与 `certificates` 中的 encipherment 条目互斥。
    #[serde(
        default,
        rename = "cert",
        alias = "certificate",
        alias = "cert-path",
        alias = "cert_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub cert_path: Option<String>,
    /// 旧版单私钥 PEM 路径。
    #[serde(
        default,
        rename = "key",
        alias = "private-key",
        alias = "private_key",
        alias = "key-path",
        alias = "key_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_path: Option<String>,
    /// Xray TLS 全量字段（证书、版本、套件、曲线、ECH、key log 等）。
    #[serde(default, flatten)]
    pub settings: XhttpDownloadTlsSettings,
    /// 使用 `usage=verify` 证书作为客户端 CA 并强制双向 TLS。
    #[serde(
        default,
        rename = "requireClientCertificate",
        alias = "require-client-certificate",
        alias = "require_client_certificate",
        skip_serializing_if = "Option::is_none"
    )]
    pub require_client_certificate: Option<bool>,
}

/// 规范序列化值与 TLS ALPN wire name 保持一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XhttpListenAlpn {
    #[serde(rename = "http/1.1", alias = "h1", alias = "http1")]
    Http1,
    #[serde(rename = "h2", alias = "http/2")]
    H2,
    #[serde(rename = "h3", alias = "http/3")]
    H3,
}

impl XhttpListenAlpn {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PanelBind {
    Off(bool),
    Port(u16),
    Address(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Share {
    False,
    Home,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ShareValue {
    Bool(bool),
    Tag(Share),
}

/* ---------------- feeds ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeedSpec {
    Url(String),
    Detail(FeedDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedDetail {
    pub url: String,
    #[serde(default = "default_feed_every", with = "humantime_serde")]
    pub every: Duration,
    #[serde(default = "default_feed_via")]
    pub via: String,
    #[serde(default)]
    pub keep: FeedFilter,
    #[serde(default)]
    pub drop: FeedFilter,
    #[serde(default)]
    pub rename: FeedRename,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedFilter {
    #[serde(default)]
    pub name_has: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedRename {
    #[serde(default)]
    pub add_prefix: Option<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/* ---------------- nodes ---------------- */

/// 手动节点；支持纯 URI 字符串或结构化对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NodeSpec {
    Uri(String),
    Detail(NodeDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeDetail {
    pub name: String,
    #[serde(default)]
    pub link: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub login: Option<NodeLogin>,
    #[serde(default)]
    pub secure: Option<NodeSecure>,
    #[serde(default)]
    pub transport: Option<NodeTransport>,
    #[serde(default)]
    pub network: Option<NodeNetwork>,
    /// 协议专属字段。标量保持文本语义，数组/对象会被编译为 JSON 后交给
    /// 对应协议注册器做严格校验；用于 WireGuard peers/allowed-ips 等结构。
    #[serde(default, alias = "protocol-options", alias = "protocol_options")]
    pub params: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeLogin {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeSecure {
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub utls: Option<String>,
    #[serde(default)]
    pub reality: Option<bool>,
    #[serde(
        default,
        rename = "realitySettings",
        alias = "reality_settings",
        alias = "reality-settings"
    )]
    pub reality_settings: Option<RealityClientSettings>,
    #[serde(default)]
    pub ech: Option<bool>,
    /// Xray-compatible TLS client settings. The legacy flat `sni`,
    /// `fingerprint`, and `utls` fields above remain accepted and are merged
    /// into this strongly typed object during runtime-plan compilation.
    #[serde(
        default,
        rename = "tls-settings",
        alias = "tls_settings",
        alias = "tlsSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_settings: Option<XhttpDownloadTlsSettings>,
}

/// Xray REALITY 客户端字段。`password` 是 Xray 新名称，`publicKey` 为兼容旧名称；
/// 编译阶段会做冲突检测与统一解码。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityClientSettings {
    #[serde(default = "default_reality_fingerprint", alias = "fp")]
    pub fingerprint: String,
    #[serde(
        default,
        rename = "serverName",
        alias = "server_name",
        alias = "server-name",
        alias = "sni"
    )]
    pub server_name: String,
    #[serde(default, alias = "pbk")]
    pub password: Option<String>,
    #[serde(
        default,
        rename = "publicKey",
        alias = "public_key",
        alias = "public-key"
    )]
    pub public_key: Option<String>,
    #[serde(
        default,
        rename = "shortId",
        alias = "short_id",
        alias = "short-id",
        alias = "sid"
    )]
    pub short_id: String,
    #[serde(
        default,
        rename = "mldsa65Verify",
        alias = "mldsa65_verify",
        alias = "mldsa65-verify",
        alias = "pqv"
    )]
    pub mldsa65_verify: Option<String>,
    #[serde(
        default = "default_reality_spider_x",
        rename = "spiderX",
        alias = "spider_x",
        alias = "spider-x",
        alias = "spx"
    )]
    pub spider_x: String,
    #[serde(default)]
    pub show: bool,
    #[serde(
        default,
        rename = "masterKeyLog",
        alias = "master_key_log",
        alias = "master-key-log"
    )]
    pub master_key_log: Option<String>,
}

impl Default for RealityClientSettings {
    fn default() -> Self {
        Self {
            fingerprint: default_reality_fingerprint(),
            server_name: String::new(),
            password: None,
            public_key: None,
            short_id: String::new(),
            mldsa65_verify: None,
            spider_x: default_reality_spider_x(),
            show: false,
            master_key_log: None,
        }
    }
}

impl std::fmt::Debug for RealityClientSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityClientSettings")
            .field("fingerprint", &self.fingerprint)
            .field("server_name", &self.server_name)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "public_key",
                &self.public_key.as_ref().map(|_| "<redacted>"),
            )
            .field("short_id", &"<redacted>")
            .field("has_mldsa65_verify", &self.mldsa65_verify.is_some())
            .field("spider_x", &self.spider_x)
            .field("show", &self.show)
            .field(
                "master_key_log",
                &self.master_key_log.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeTransport {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    /// XHTTP/SplitHTTP 的一等强类型配置。`xhttpSettings` 与
    /// `splithttpSettings` 用于直接接收 Xray 风格配置。
    #[serde(
        default,
        rename = "xhttp",
        alias = "xhttpSettings",
        alias = "xhttp-settings",
        alias = "splithttpSettings",
        alias = "splithttp-settings"
    )]
    pub xhttp: Option<XhttpConfig>,
}

/// Xray `Int32Range` 的无损配置表示。
///
/// 接受 JSON/YAML 整数（`64`）或范围字符串（`"64-128"`），序列化时使用
/// 同样的规范形式。XHTTP 的范围均为非负 int32；反向范围和溢出值直接报错，
/// 不做静默交换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhttpRange {
    pub from: u32,
    pub to: u32,
}

impl XhttpRange {
    pub const fn new(from: u32, to: u32) -> Self {
        Self { from, to }
    }

    fn parse_str(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("范围不能为空".into());
        }
        let parse_bound = |raw: &str| -> Result<u32, String> {
            let parsed = raw
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("非法非负整数 `{raw}`"))?;
            if parsed > i32::MAX as u64 {
                return Err(format!("范围值 {parsed} 超出 int32 上限"));
            }
            Ok(parsed as u32)
        };

        let (from, to) = if let Some((left, right)) = value.split_once('-') {
            if right.contains('-') {
                return Err(format!("非法范围 `{value}`"));
            }
            (parse_bound(left)?, parse_bound(right)?)
        } else {
            let value = parse_bound(value)?;
            (value, value)
        };
        if from > to {
            return Err(format!("范围下界 {from} 不能大于上界 {to}"));
        }
        Ok(Self { from, to })
    }
}

impl fmt::Display for XhttpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.from == self.to {
            write!(f, "{}", self.from)
        } else {
            write!(f, "{}-{}", self.from, self.to)
        }
    }
}

impl Serialize for XhttpRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.from == self.to {
            serializer.serialize_u32(self.from)
        } else {
            serializer.serialize_str(&self.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for XhttpRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RangeVisitor;

        impl<'de> serde::de::Visitor<'de> for RangeVisitor {
            type Value = XhttpRange;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("非负 int32 整数或 `from-to` 范围字符串")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value > i32::MAX as u64 {
                    return Err(E::custom(format!("范围值 {value} 超出 int32 上限")));
                }
                Ok(XhttpRange::new(value as u32, value as u32))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value < 0 {
                    return Err(E::custom("XHTTP 范围不接受负数"));
                }
                self.visit_u64(value as u64)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                XhttpRange::parse_str(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(RangeVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpXmuxConfig {
    #[serde(
        default,
        rename = "maxConcurrency",
        alias = "max-concurrency",
        alias = "max_concurrency",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_concurrency: Option<XhttpRange>,
    #[serde(
        default,
        rename = "maxConnections",
        alias = "max-connections",
        alias = "max_connections",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections: Option<XhttpRange>,
    #[serde(
        default,
        rename = "cMaxReuseTimes",
        alias = "c-max-reuse-times",
        alias = "c_max_reuse_times",
        skip_serializing_if = "Option::is_none"
    )]
    pub c_max_reuse_times: Option<XhttpRange>,
    #[serde(
        default,
        rename = "hMaxRequestTimes",
        alias = "h-max-request-times",
        alias = "h_max_request_times",
        skip_serializing_if = "Option::is_none"
    )]
    pub h_max_request_times: Option<XhttpRange>,
    #[serde(
        default,
        rename = "hMaxReusableSecs",
        alias = "h-max-reusable-secs",
        alias = "h_max_reusable_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub h_max_reusable_secs: Option<XhttpRange>,
    #[serde(
        default,
        rename = "hKeepAlivePeriod",
        alias = "h-keep-alive-period",
        alias = "h_keep_alive_period",
        skip_serializing_if = "Option::is_none"
    )]
    pub h_keep_alive_period: Option<i64>,
}

/// Xray finalmask 使用的有符号范围。接受整数或 `"from-to"` 字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XhttpSignedRange {
    pub left: i32,
    pub right: i32,
}

impl XhttpSignedRange {
    pub const fn new(left: i32, right: i32) -> Self {
        Self { left, right }
    }

    pub const fn normalized(self) -> (i32, i32) {
        if self.left <= self.right {
            (self.left, self.right)
        } else {
            (self.right, self.left)
        }
    }
}

impl Serialize for XhttpSignedRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.left == self.right {
            serializer.serialize_i32(self.left)
        } else {
            serializer.serialize_str(&format!("{}-{}", self.left, self.right))
        }
    }
}

impl<'de> Deserialize<'de> for XhttpSignedRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Integer(i32),
            Text(String),
        }

        match Input::deserialize(deserializer)? {
            Input::Integer(value) => Ok(Self::new(value, value)),
            Input::Text(value) => {
                let value = value.trim();
                if let Ok(single) = value.parse::<i32>() {
                    return Ok(Self::new(single, single));
                }
                for (index, character) in value.char_indices().skip(1) {
                    if character != '-' {
                        continue;
                    }
                    let left = value[..index].parse::<i32>();
                    let right = value[index + 1..].parse::<i32>();
                    if let (Ok(left), Ok(right)) = (left, right) {
                        return Ok(Self::new(left, right));
                    }
                }
                Err(serde::de::Error::custom(format!(
                    "invalid signed integer range `{value}`"
                )))
            }
        }
    }
}

fn deserialize_optional_xray_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Input {
        Many(Vec<String>),
        CommaSeparated(String),
    }

    Ok(
        Option::<Input>::deserialize(deserializer)?.map(|input| match input {
            Input::Many(values) => values,
            // Pinned Xray `StringList.UnmarshalJSON` intentionally does not trim.
            Input::CommaSeparated(value) => value.split(',').map(str::to_owned).collect(),
        }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpRealityTarget {
    Port(u16),
    Address(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpTcpFastOpen {
    Enabled(bool),
    QueueLength(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XhttpTlsCertificateUsage {
    #[serde(rename = "encipherment")]
    Encipherment,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "issue")]
    Issue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadTlsCertificate {
    #[serde(
        default,
        rename = "certificateFile",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Vec<String>>,
    #[serde(default, rename = "keyFile", skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<XhttpTlsCertificateUsage>,
    #[serde(
        default,
        rename = "ocspStapling",
        skip_serializing_if = "Option::is_none"
    )]
    pub ocsp_stapling: Option<u64>,
    #[serde(
        default,
        rename = "oneTimeLoading",
        skip_serializing_if = "Option::is_none"
    )]
    pub one_time_loading: Option<bool>,
    #[serde(
        default,
        rename = "buildChain",
        skip_serializing_if = "Option::is_none"
    )]
    pub build_chain: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadCustomSockopt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadHappyEyeballs {
    #[serde(
        default,
        rename = "prioritizeIPv6",
        skip_serializing_if = "Option::is_none"
    )]
    pub prioritize_ipv6: Option<bool>,
    #[serde(
        default,
        rename = "tryDelayMs",
        skip_serializing_if = "Option::is_none"
    )]
    pub try_delay_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interleave: Option<u32>,
    #[serde(
        default,
        rename = "maxConcurrentTry",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_concurrent_try: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XhttpTproxyMode {
    #[serde(rename = "off", alias = "")]
    Off,
    #[serde(rename = "tproxy")]
    Tproxy,
    #[serde(rename = "redirect")]
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XhttpDomainStrategy {
    #[serde(rename = "AsIs", alias = "asis")]
    AsIs,
    #[serde(rename = "UseIP", alias = "useip")]
    UseIp,
    #[serde(rename = "UseIPv4", alias = "useipv4")]
    UseIpv4,
    #[serde(rename = "UseIPv6", alias = "useipv6")]
    UseIpv6,
    #[serde(rename = "UseIPv4v6", alias = "useipv4v6")]
    UseIpv4v6,
    #[serde(rename = "UseIPv6v4", alias = "useipv6v4")]
    UseIpv6v4,
    #[serde(rename = "ForceIP", alias = "forceip")]
    ForceIp,
    #[serde(rename = "ForceIPv4", alias = "forceipv4")]
    ForceIpv4,
    #[serde(rename = "ForceIPv6", alias = "forceipv6")]
    ForceIpv6,
    #[serde(rename = "ForceIPv4v6", alias = "forceipv4v6")]
    ForceIpv4v6,
    #[serde(rename = "ForceIPv6v4", alias = "forceipv6v4")]
    ForceIpv6v4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XhttpAddressPortStrategy {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "srvPortOnly", alias = "srvportonly")]
    SrvPortOnly,
    #[serde(rename = "srvAddressOnly", alias = "srvaddressonly")]
    SrvAddressOnly,
    #[serde(rename = "srvPortAndAddress", alias = "srvportandaddress")]
    SrvPortAndAddress,
    #[serde(rename = "txtPortOnly", alias = "txtportonly")]
    TxtPortOnly,
    #[serde(rename = "txtAddressOnly", alias = "txtaddressonly")]
    TxtAddressOnly,
    #[serde(rename = "txtPortAndAddress", alias = "txtportandaddress")]
    TxtPortAndAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XhttpMaskPacketEncoding {
    #[serde(rename = "array")]
    Array,
    #[serde(rename = "str")]
    String,
    #[serde(rename = "hex")]
    Hex,
    #[serde(rename = "base64")]
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpMaskPacket {
    Bytes(Vec<u8>),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpMaskDomain {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum XhttpPortList {
    One(u16),
    List(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpMaskTransformArg {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub encoding: Option<XhttpMaskPacketEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<XhttpMaskPacket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u64: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<Box<XhttpMaskTransform>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpMaskTransform {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<XhttpMaskTransformArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpMaskTcpItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rand: Option<i32>,
    #[serde(default, rename = "randRange", skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub encoding: Option<XhttpMaskPacketEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<XhttpMaskTransform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet: Option<XhttpMaskPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpHeaderCustomTcp {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<Vec<XhttpMaskTcpItem>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<Vec<XhttpMaskTcpItem>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<Vec<XhttpMaskTcpItem>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpFragmentMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lengths: Vec<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delays: Vec<XhttpSignedRange>,
    #[serde(default, rename = "maxSplit", skip_serializing_if = "Option::is_none")]
    pub max_split: Option<XhttpSignedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpSudokuMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ascii: Option<String>,
    #[serde(
        default,
        rename = "customTable",
        alias = "custom_table",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_table: Option<String>,
    #[serde(
        default,
        rename = "customTables",
        alias = "custom_tables",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_tables: Vec<String>,
    #[serde(
        default,
        rename = "paddingMin",
        alias = "padding_min",
        skip_serializing_if = "Option::is_none"
    )]
    pub padding_min: Option<u32>,
    #[serde(
        default,
        rename = "paddingMax",
        alias = "padding_max",
        skip_serializing_if = "Option::is_none"
    )]
    pub padding_max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpXmcMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum XhttpTcpMask {
    #[serde(rename = "header-custom")]
    HeaderCustom {
        #[serde(default)]
        settings: XhttpHeaderCustomTcp,
    },
    #[serde(rename = "fragment")]
    Fragment {
        #[serde(default)]
        settings: XhttpFragmentMask,
    },
    #[serde(rename = "sudoku")]
    Sudoku {
        #[serde(default)]
        settings: XhttpSudokuMask,
    },
    #[serde(rename = "xmc")]
    Xmc {
        #[serde(default)]
        settings: XhttpXmcMask,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpMaskUdpItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rand: Option<i32>,
    #[serde(default, rename = "randRange", skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub encoding: Option<XhttpMaskPacketEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<XhttpMaskTransform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet: Option<XhttpMaskPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpHeaderCustomUdp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client: Vec<XhttpMaskUdpItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server: Vec<XhttpMaskUdpItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpMkcpLegacyMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpNoiseItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rand: Option<XhttpSignedRange>,
    #[serde(default, rename = "randRange", skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<XhttpSignedRange>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub encoding: Option<XhttpMaskPacketEncoding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet: Option<XhttpMaskPacket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay: Option<XhttpSignedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpNoiseMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<XhttpSignedRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub noise: Vec<XhttpNoiseItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpSalamanderMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(
        default,
        rename = "packetSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub packet_size: Option<XhttpSignedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpXdnsMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<XhttpMaskDomain>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpXicmpMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dgram: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpRealmMask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, rename = "stunServers", skip_serializing_if = "Vec::is_empty")]
    pub stun_servers: Vec<String>,
    #[serde(default, rename = "tlsConfig", skip_serializing_if = "Option::is_none")]
    pub tls_config: Option<Box<XhttpDownloadTlsSettings>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum XhttpUdpMask {
    #[serde(rename = "header-custom")]
    HeaderCustom {
        #[serde(default)]
        settings: XhttpHeaderCustomUdp,
    },
    #[serde(rename = "mkcp-legacy")]
    MkcpLegacy {
        #[serde(default)]
        settings: XhttpMkcpLegacyMask,
    },
    #[serde(rename = "noise")]
    Noise {
        #[serde(default)]
        settings: XhttpNoiseMask,
    },
    #[serde(rename = "salamander")]
    Salamander {
        #[serde(default)]
        settings: XhttpSalamanderMask,
    },
    #[serde(rename = "sudoku")]
    Sudoku {
        #[serde(default)]
        settings: XhttpSudokuMask,
    },
    #[serde(rename = "xdns")]
    Xdns {
        #[serde(default)]
        settings: XhttpXdnsMask,
    },
    #[serde(rename = "xicmp")]
    Xicmp {
        #[serde(default)]
        settings: XhttpXicmpMask,
    },
    #[serde(rename = "realm")]
    Realm {
        #[serde(default)]
        settings: XhttpRealmMask,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpUdpHop {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<XhttpPortList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<XhttpSignedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpQuicParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,
    #[serde(
        default,
        rename = "bbrProfile",
        skip_serializing_if = "Option::is_none"
    )]
    pub bbr_profile: Option<String>,
    #[serde(default, rename = "brutalUp", skip_serializing_if = "Option::is_none")]
    pub brutal_up: Option<String>,
    #[serde(
        default,
        rename = "brutalDown",
        skip_serializing_if = "Option::is_none"
    )]
    pub brutal_down: Option<String>,
    #[serde(default, rename = "udpHop", skip_serializing_if = "Option::is_none")]
    pub udp_hop: Option<XhttpUdpHop>,
    #[serde(
        default,
        rename = "initStreamReceiveWindow",
        skip_serializing_if = "Option::is_none"
    )]
    pub init_stream_receive_window: Option<u64>,
    #[serde(
        default,
        rename = "maxStreamReceiveWindow",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_stream_receive_window: Option<u64>,
    #[serde(
        default,
        rename = "initConnectionReceiveWindow",
        skip_serializing_if = "Option::is_none"
    )]
    pub init_connection_receive_window: Option<u64>,
    #[serde(
        default,
        rename = "maxConnectionReceiveWindow",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connection_receive_window: Option<u64>,
    #[serde(
        default,
        rename = "maxIdleTimeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_idle_timeout: Option<i64>,
    #[serde(
        default,
        rename = "keepAlivePeriod",
        skip_serializing_if = "Option::is_none"
    )]
    pub keep_alive_period: Option<i64>,
    #[serde(
        default,
        rename = "disablePathMTUDiscovery",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_path_mtu_discovery: Option<bool>,
    #[serde(
        default,
        rename = "maxIncomingStreams",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_incoming_streams: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpFinalMask {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp: Vec<XhttpTcpMask>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<XhttpUdpMask>,
    #[serde(
        default,
        rename = "quicParams",
        skip_serializing_if = "Option::is_none"
    )]
    pub quic_params: Option<XhttpQuicParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadTlsSettings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<XhttpDownloadTlsCertificate>,
    #[serde(
        default,
        rename = "serverName",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_name: Option<String>,
    #[serde(
        default,
        rename = "allowInsecure",
        alias = "allow-insecure",
        alias = "allow_insecure",
        alias = "insecure",
        alias = "skip-cert-verify",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_insecure: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_xray_string_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(
        default,
        rename = "enableSessionResumption",
        alias = "enable-session-resumption",
        alias = "enable_session_resumption",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_session_resumption: Option<bool>,
    #[serde(
        default,
        rename = "disableSystemRoot",
        alias = "disable-system-root",
        alias = "disable_system_root",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_system_root: Option<bool>,
    #[serde(
        default,
        rename = "minVersion",
        alias = "min-version",
        alias = "min_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_version: Option<String>,
    #[serde(
        default,
        rename = "maxVersion",
        alias = "max-version",
        alias = "max_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_version: Option<String>,
    #[serde(
        default,
        rename = "cipherSuites",
        alias = "cipher-suites",
        alias = "cipher_suites",
        skip_serializing_if = "Option::is_none"
    )]
    pub cipher_suites: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        rename = "rejectUnknownSni",
        alias = "rejectUnknownSNI",
        alias = "reject-unknown-sni",
        alias = "reject_unknown_sni",
        skip_serializing_if = "Option::is_none"
    )]
    pub reject_unknown_sni: Option<bool>,
    #[serde(
        default,
        rename = "curvePreferences",
        alias = "curve-preferences",
        alias = "curve_preferences",
        deserialize_with = "deserialize_optional_xray_string_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub curve_preferences: Option<Vec<String>>,
    #[serde(
        default,
        rename = "masterKeyLog",
        alias = "master-key-log",
        alias = "master_key_log",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_key_log: Option<String>,
    #[serde(
        default,
        rename = "pinnedPeerCertSha256",
        alias = "pinned-peer-cert-sha256",
        alias = "pinned_peer_cert_sha256",
        skip_serializing_if = "Option::is_none"
    )]
    pub pinned_peer_cert_sha256: Option<String>,
    #[serde(
        default,
        rename = "verifyPeerCertByName",
        alias = "verify-peer-cert-by-name",
        alias = "verify_peer_cert_by_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(
        default,
        rename = "echServerKeys",
        alias = "ech-server-keys",
        alias = "ech_server_keys",
        skip_serializing_if = "Option::is_none"
    )]
    pub ech_server_keys: Option<String>,
    #[serde(
        default,
        rename = "echConfigList",
        alias = "ech-config-list",
        alias = "ech_config_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub ech_config_list: Option<String>,
    #[serde(
        default,
        rename = "echSockopt",
        alias = "ech-sockopt",
        alias = "ech_sockopt",
        alias = "echSocketSettings",
        alias = "ech-socket-settings",
        alias = "ech_socket_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub ech_socket_settings: Option<Box<XhttpDownloadSocketSettings>>,
}

impl XhttpDownloadTlsSettings {
    /// Validate the complete Xray TLS object before it crosses into a transport
    /// backend.  This deliberately rejects values that Xray's Go builder would
    /// silently skip: accepting a misspelled cipher or curve is much more
    /// dangerous than failing the configuration at startup.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_at("tlsSettings")
    }

    /// Validate the subset consumed by Xray's outbound/client TLS path.
    ///
    /// `rejectUnknownSni` and `echServerKeys` are server-only fields carried by
    /// the shared TLS object. Xray leaves them inert for clients, so an
    /// outbound must not parse or reject their values. Client-side
    /// `echSockopt` remains active and is validated with `echConfigList`.
    pub fn validate_client(&self) -> Result<(), String> {
        self.validate_client_at("tlsSettings")
    }

    fn validate_client_at(&self, path: &str) -> Result<(), String> {
        let mut client = self.clone();
        client.reject_unknown_sni = None;
        client.ech_server_keys = None;
        client.validate_at(path)
    }

    pub(crate) fn validate_at(&self, path: &str) -> Result<(), String> {
        if self.allow_insecure.unwrap_or(false) {
            return Err(format!(
                "{path}.allowInsecure=true 已被 Xray 移除；请使用 pinnedPeerCertSha256 或 verifyPeerCertByName"
            ));
        }

        if let Some(alpn) = &self.alpn {
            let mut seen = std::collections::HashSet::with_capacity(alpn.len());
            for value in alpn {
                if value.is_empty() || value.len() > usize::from(u8::MAX) {
                    return Err(format!("{path}.alpn 每项必须包含 1..=255 字节"));
                }
                if !seen.insert(value) {
                    return Err(format!("{path}.alpn 包含重复值 `{value}`"));
                }
            }
        }

        let min = parse_xhttp_tls_version(self.min_version.as_deref(), "minVersion", path)?;
        let max = parse_xhttp_tls_version(self.max_version.as_deref(), "maxVersion", path)?;
        if min.zip(max).is_some_and(|(min, max)| min > max) {
            return Err(format!("{path}.minVersion 不能高于 maxVersion"));
        }

        if let Some(cipher_suites) = self.cipher_suites.as_deref() {
            if cipher_suites.trim().is_empty() {
                return Err(format!("{path}.cipherSuites 不能是空字符串"));
            }
            for cipher in cipher_suites.split(':').map(str::trim) {
                if cipher.is_empty() || !is_xray_tls_cipher(cipher) {
                    return Err(format!(
                        "{path}.cipherSuites 包含未知或空的密码套件 `{cipher}`"
                    ));
                }
            }
        }

        if let Some(curves) = &self.curve_preferences {
            if curves.is_empty() {
                return Err(format!("{path}.curvePreferences 不能是空列表"));
            }
            let mut seen = std::collections::HashSet::with_capacity(curves.len());
            for curve in curves {
                let normalized = curve.to_ascii_lowercase();
                if !matches!(
                    normalized.as_str(),
                    "curvep256"
                        | "curvep384"
                        | "curvep521"
                        | "x25519"
                        | "x25519mlkem768"
                        | "secp256r1mlkem768"
                        | "secp384r1mlkem1024"
                ) {
                    return Err(format!("{path}.curvePreferences 包含未知曲线 `{curve}`"));
                }
                if !seen.insert(normalized) {
                    return Err(format!("{path}.curvePreferences 包含重复曲线 `{curve}`"));
                }
            }
        }

        if self
            .master_key_log
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(format!("{path}.masterKeyLog 不能是空路径"));
        }

        for (index, certificate) in self.certificates.iter().enumerate() {
            validate_xhttp_tls_certificate(certificate, &format!("{path}.certificates[{index}]"))?;
        }

        if let Some(value) = self.ech_config_list.as_deref() {
            validate_ech_config_source(value, &format!("{path}.echConfigList"))?;
            if self.ech_socket_settings.is_some() && !value.contains("://") {
                return Err(format!(
                    "{path}.echSockopt 只能与 echConfigList 的 DNS URL 来源一起使用"
                ));
            }
        } else if self.ech_socket_settings.is_some() {
            return Err(format!(
                "{path}.echSockopt 只能与 echConfigList 的 DNS URL 来源一起使用"
            ));
        }
        if let Some(value) = self.ech_server_keys.as_deref() {
            let decoded = decode_xray_base64(value)
                .map_err(|error| format!("{path}.echServerKeys 不是合法 base64: {error}"))?;
            if decoded.is_empty() {
                return Err(format!("{path}.echServerKeys 解码后不能为空"));
            }
            validate_ech_server_key_list(&decoded, &format!("{path}.echServerKeys"))?;
        }

        if self.disable_system_root.unwrap_or(false)
            && !self
                .certificates
                .iter()
                .any(|certificate| certificate.usage == Some(XhttpTlsCertificateUsage::Verify))
            && self
                .pinned_peer_cert_sha256
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!(
                "{path}.disableSystemRoot=true 时必须提供 usage=verify 的证书或 pinnedPeerCertSha256"
            ));
        }
        Ok(())
    }
}

fn parse_xhttp_tls_version(
    value: Option<&str>,
    field: &str,
    path: &str,
) -> Result<Option<u8>, String> {
    let Some(value) = value else { return Ok(None) };
    let rank = match value.trim() {
        "1.0" => 10,
        "1.1" => 11,
        "1.2" => 12,
        "1.3" => 13,
        _ => return Err(format!("{path}.{field} 仅支持 1.0、1.1、1.2、1.3")),
    };
    Ok(Some(rank))
}

fn is_xray_tls_cipher(value: &str) -> bool {
    matches!(
        value,
        "TLS_RSA_WITH_RC4_128_SHA"
            | "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            | "TLS_RSA_WITH_AES_128_CBC_SHA"
            | "TLS_RSA_WITH_AES_256_CBC_SHA"
            | "TLS_RSA_WITH_AES_128_CBC_SHA256"
            | "TLS_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
            | "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
            | "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
            | "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
            | "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            | "TLS_AES_128_GCM_SHA256"
            | "TLS_AES_256_GCM_SHA384"
            | "TLS_CHACHA20_POLY1305_SHA256"
    )
}

fn validate_xhttp_tls_certificate(
    certificate: &XhttpDownloadTlsCertificate,
    path: &str,
) -> Result<(), String> {
    if certificate.certificate_file.is_some() && certificate.certificate.is_some() {
        return Err(format!(
            "{path}.certificateFile 与 certificate 不能同时设置"
        ));
    }
    if certificate.key_file.is_some() && certificate.key.is_some() {
        return Err(format!("{path}.keyFile 与 key 不能同时设置"));
    }
    if certificate
        .certificate_file
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
        || certificate.certificate.as_ref().is_some_and(|value| {
            value.is_empty() || value.iter().all(|line| line.trim().is_empty())
        })
    {
        return Err(format!("{path} 的证书内容不能为空"));
    }
    if certificate
        .key_file
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
        || certificate.key.as_ref().is_some_and(|value| {
            value.is_empty() || value.iter().all(|line| line.trim().is_empty())
        })
    {
        return Err(format!("{path} 的私钥内容不能为空"));
    }
    let has_certificate =
        certificate.certificate_file.is_some() || certificate.certificate.is_some();
    let has_key = certificate.key_file.is_some() || certificate.key.is_some();
    match certificate
        .usage
        .unwrap_or(XhttpTlsCertificateUsage::Encipherment)
    {
        XhttpTlsCertificateUsage::Verify => {
            if !has_certificate {
                return Err(format!("{path} usage=verify 时必须提供证书"));
            }
            if has_key {
                return Err(format!("{path} usage=verify 不能携带私钥"));
            }
        }
        XhttpTlsCertificateUsage::Encipherment | XhttpTlsCertificateUsage::Issue => {
            if !has_certificate || !has_key {
                return Err(format!("{path} 必须同时提供证书链与私钥"));
            }
        }
    }
    Ok(())
}

fn validate_ech_config_source(value: &str, path: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{path} 不能为空"));
    }
    if !value.contains("://") {
        let decoded = decode_xray_base64(value)
            .map_err(|error| format!("{path} 不是合法 base64: {error}"))?;
        if decoded.is_empty() {
            return Err(format!("{path} 解码后不能为空"));
        }
        validate_ech_config_list(&decoded, path)?;
        return Ok(());
    }

    let source = value.rsplit_once('+').map_or(value, |(_, source)| source);
    let url = url::Url::parse(source).map_err(|error| format!("{path} URL 非法: {error}"))?;
    if !matches!(url.scheme(), "https" | "h2c" | "udp") {
        return Err(format!("{path} DNS 来源只支持 https://、h2c:// 或 udp://"));
    }
    if url.host_str().is_none() {
        return Err(format!("{path} DNS URL 缺少主机"));
    }
    Ok(())
}

fn validate_ech_config_list(bytes: &[u8], path: &str) -> Result<(), String> {
    let declared = bytes
        .get(..2)
        .map(|length| usize::from(u16::from_be_bytes([length[0], length[1]])))
        .ok_or_else(|| format!("{path} 缺少 ECHConfigList 长度"))?;
    if declared == 0 || declared != bytes.len().saturating_sub(2) {
        return Err(format!("{path} 的 ECHConfigList 外层长度不匹配"));
    }
    let mut cursor = 2_usize;
    let mut count = 0_usize;
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor + 4)
            .ok_or_else(|| format!("{path} 包含截断的 ECHConfig"))?;
        let version = u16::from_be_bytes([header[0], header[1]]);
        if version != 0xfe0d {
            return Err(format!(
                "{path} 包含不支持的 ECHConfig 版本 0x{version:04x}"
            ));
        }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor = cursor
            .checked_add(4)
            .and_then(|cursor| cursor.checked_add(length))
            .filter(|cursor| *cursor <= bytes.len())
            .ok_or_else(|| format!("{path} 包含截断的 ECHConfig 内容"))?;
        count += 1;
    }
    if count == 0 || cursor != bytes.len() {
        return Err(format!("{path} 不包含完整的 ECHConfig"));
    }
    Ok(())
}

fn validate_ech_server_key_list(bytes: &[u8], path: &str) -> Result<(), String> {
    let mut cursor = 0_usize;
    let mut count = 0_usize;
    while cursor < bytes.len() {
        let key_length = read_ech_u16(bytes, &mut cursor, path, "私钥")?;
        if key_length == 0 {
            return Err(format!("{path} 包含空的 ECH 私钥"));
        }
        cursor = cursor
            .checked_add(key_length)
            .filter(|cursor| *cursor <= bytes.len())
            .ok_or_else(|| format!("{path} 包含截断的 ECH 私钥"))?;
        let config_length = read_ech_u16(bytes, &mut cursor, path, "配置")?;
        if config_length < 4 {
            return Err(format!("{path} 包含过短的 ECH 配置"));
        }
        let end = cursor
            .checked_add(config_length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| format!("{path} 包含截断的 ECH 配置"))?;
        let version = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        if version != 0xfe0d {
            return Err(format!(
                "{path} 包含不支持的 ECHConfig 版本 0x{version:04x}"
            ));
        }
        let inner_length = usize::from(u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]));
        if inner_length + 4 != config_length {
            return Err(format!("{path} 的 ECH 配置内层长度不匹配"));
        }
        cursor = end;
        count += 1;
    }
    if count == 0 {
        return Err(format!("{path} 不包含 ECH 密钥"));
    }
    Ok(())
}

fn read_ech_u16(
    bytes: &[u8],
    cursor: &mut usize,
    path: &str,
    label: &str,
) -> Result<usize, String> {
    let length = bytes
        .get(*cursor..*cursor + 2)
        .map(|value| usize::from(u16::from_be_bytes([value[0], value[1]])))
        .ok_or_else(|| format!("{path} 缺少 ECH {label}长度"))?;
    *cursor += 2;
    Ok(length)
}

fn decode_xray_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpRealityLimitFallback {
    #[serde(
        default,
        rename = "afterBytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub after_bytes: Option<u64>,
    #[serde(
        default,
        rename = "bytesPerSec",
        skip_serializing_if = "Option::is_none"
    )]
    pub bytes_per_sec: Option<u64>,
    #[serde(
        default,
        rename = "burstBytesPerSec",
        skip_serializing_if = "Option::is_none"
    )]
    pub burst_bytes_per_sec: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadRealitySettings {
    #[serde(
        default,
        rename = "masterKeyLog",
        skip_serializing_if = "Option::is_none"
    )]
    pub master_key_log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<XhttpRealityTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<XhttpRealityTarget>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub transport_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xver: Option<u64>,
    #[serde(default, rename = "serverNames", skip_serializing_if = "Vec::is_empty")]
    pub server_names: Vec<String>,
    #[serde(
        default,
        rename = "privateKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<String>,
    #[serde(
        default,
        rename = "minClientVer",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_client_ver: Option<String>,
    #[serde(
        default,
        rename = "maxClientVer",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_client_ver: Option<String>,
    #[serde(
        default,
        rename = "maxTimeDiff",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_time_diff: Option<u64>,
    #[serde(default, rename = "shortIds", skip_serializing_if = "Vec::is_empty")]
    pub short_ids: Vec<String>,
    #[serde(
        default,
        rename = "mldsa65Seed",
        skip_serializing_if = "Option::is_none"
    )]
    pub mldsa65_seed: Option<String>,
    #[serde(
        default,
        rename = "limitFallbackUpload",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit_fallback_upload: Option<XhttpRealityLimitFallback>,
    #[serde(
        default,
        rename = "limitFallbackDownload",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit_fallback_download: Option<XhttpRealityLimitFallback>,
    #[serde(
        default,
        rename = "serverName",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(
        default,
        rename = "publicKey",
        alias = "public-key",
        alias = "public_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key: Option<String>,
    #[serde(
        default,
        rename = "shortId",
        alias = "short-id",
        alias = "short_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        rename = "mldsa65Verify",
        skip_serializing_if = "Option::is_none"
    )]
    pub mldsa65_verify: Option<String>,
    #[serde(
        default,
        rename = "spiderX",
        alias = "spider-x",
        alias = "spider_x",
        skip_serializing_if = "Option::is_none"
    )]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadSocketSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<i32>,
    #[serde(
        default,
        rename = "tcpFastOpen",
        alias = "tfo",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_fast_open: Option<XhttpTcpFastOpen>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tproxy: Option<XhttpTproxyMode>,
    #[serde(
        default,
        rename = "acceptProxyProtocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub accept_proxy_protocol: Option<bool>,
    #[serde(
        default,
        rename = "tcpMptcp",
        alias = "tcp-mptcp",
        alias = "tcp_mptcp",
        alias = "mptcp",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_mptcp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(
        default,
        rename = "domainStrategy",
        alias = "domain-strategy",
        alias = "domain_strategy",
        alias = "ip-family",
        alias = "ip_family",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_strategy: Option<XhttpDomainStrategy>,
    #[serde(
        default,
        rename = "dialerProxy",
        alias = "dialer-proxy",
        alias = "dialer_proxy",
        skip_serializing_if = "Option::is_none"
    )]
    pub dialer_proxy: Option<String>,
    #[serde(
        default,
        rename = "tcpKeepAliveInterval",
        alias = "tcp-keep-alive-interval",
        alias = "tcp_keep_alive_interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive_interval: Option<i32>,
    #[serde(
        default,
        rename = "tcpKeepAliveIdle",
        alias = "tcp-keep-alive-idle",
        alias = "tcp_keep_alive_idle",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive_idle: Option<i32>,
    #[serde(
        default,
        rename = "tcpWindowClamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_window_clamp: Option<i32>,
    #[serde(
        default,
        rename = "tcpUserTimeout",
        alias = "tcp-user-timeout",
        alias = "tcp_user_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_user_timeout: Option<i32>,
    #[serde(
        default,
        rename = "tcpMaxSeg",
        alias = "tcp-max-seg",
        alias = "tcp_max_seg",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_max_seg: Option<i32>,
    #[serde(
        default,
        rename = "tcpCongestion",
        alias = "tcp-congestion",
        alias = "tcp_congestion",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_congestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub penetrate: Option<bool>,
    #[serde(
        default,
        rename = "customSockopt",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_sockopt: Vec<XhttpDownloadCustomSockopt>,
    #[serde(
        default,
        rename = "addressPortStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub address_port_strategy: Option<XhttpAddressPortStrategy>,
    #[serde(
        default,
        rename = "happyEyeballs",
        skip_serializing_if = "Option::is_none"
    )]
    pub happy_eyeballs: Option<XhttpDownloadHappyEyeballs>,
    #[serde(
        default,
        rename = "trustedXForwardedFor",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub trusted_x_forwarded_for: Vec<String>,
}

/// Xray `internet.StreamConfig` 在 XHTTP `downloadSettings` 中可执行的强类型子集。
///
/// 下载方向可指定独立目标、传输和安全参数；`xhttpSettings` 与
/// `transport.xhttp` 都是强类型 XHTTP 配置。兼容输入可同时提供两种别名，
/// 但解析 `extra` 后的有效配置必须等价。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownloadSettings {
    #[serde(default, alias = "server", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(
        default,
        alias = "protocolName",
        alias = "protocol-name",
        alias = "protocol_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub network: Option<String>,
    #[serde(
        default,
        alias = "transportSettings",
        alias = "transport-settings",
        alias = "transport_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub transport: Option<Box<NodeTransport>>,
    #[serde(
        default,
        rename = "xhttpSettings",
        alias = "xhttp-settings",
        alias = "splithttpSettings",
        alias = "splithttp-settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub xhttp_settings: Option<Box<XhttpConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(
        default,
        rename = "tlsSettings",
        alias = "tls-settings",
        alias = "tls_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_settings: Option<XhttpDownloadTlsSettings>,
    #[serde(
        default,
        rename = "realitySettings",
        alias = "reality-settings",
        alias = "reality_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub reality_settings: Option<XhttpDownloadRealitySettings>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_xray_string_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub alpn: Option<Vec<String>>,
    #[serde(
        default,
        rename = "sockopt",
        alias = "socketSettings",
        alias = "socket-settings",
        alias = "socket_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub socket_settings: Option<XhttpDownloadSocketSettings>,
    #[serde(
        default,
        rename = "finalmask",
        alias = "finalMask",
        skip_serializing_if = "Option::is_none"
    )]
    pub final_mask: Option<XhttpFinalMask>,
}

/// Xray XHTTP/SplitHTTP 完整配置。
///
/// 字段规范名使用 Xray JSON camelCase；同时接受 Friendly YAML 使用过的
/// kebab-case 与早期 snake_case 名称。没有 `Value`/任意 map 逃生字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XhttpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(
        default,
        rename = "xPaddingBytes",
        alias = "x-padding-bytes",
        alias = "x_padding_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_bytes: Option<XhttpRange>,
    #[serde(
        default,
        rename = "xPaddingObfsMode",
        alias = "x-padding-obfs-mode",
        alias = "x_padding_obfs_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_obfs_mode: Option<bool>,
    #[serde(
        default,
        rename = "xPaddingKey",
        alias = "x-padding-key",
        alias = "x_padding_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_key: Option<String>,
    #[serde(
        default,
        rename = "xPaddingHeader",
        alias = "x-padding-header",
        alias = "x_padding_header",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_header: Option<String>,
    #[serde(
        default,
        rename = "xPaddingPlacement",
        alias = "x-padding-placement",
        alias = "x_padding_placement",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_placement: Option<String>,
    #[serde(
        default,
        rename = "xPaddingMethod",
        alias = "x-padding-method",
        alias = "x_padding_method",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_padding_method: Option<String>,
    #[serde(
        default,
        rename = "uplinkHTTPMethod",
        alias = "uplinkHttpMethod",
        alias = "uplink-http-method",
        alias = "uplink_http_method",
        skip_serializing_if = "Option::is_none"
    )]
    pub uplink_http_method: Option<String>,
    #[serde(
        default,
        rename = "sessionIDPlacement",
        alias = "sessionIdPlacement",
        alias = "session-placement",
        alias = "session-id-placement",
        alias = "session_id_placement",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_id_placement: Option<String>,
    #[serde(
        default,
        rename = "sessionIDKey",
        alias = "sessionIdKey",
        alias = "session-key",
        alias = "session-id-key",
        alias = "session_id_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_id_key: Option<String>,
    #[serde(
        default,
        rename = "sessionIDTable",
        alias = "sessionIdTable",
        alias = "session-table",
        alias = "session-id-table",
        alias = "session_id_table",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_id_table: Option<String>,
    #[serde(
        default,
        rename = "sessionIDLength",
        alias = "sessionIdLength",
        alias = "session-length",
        alias = "session-id-length",
        alias = "session_id_length",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_id_length: Option<XhttpRange>,
    #[serde(
        default,
        rename = "seqPlacement",
        alias = "seq-placement",
        alias = "seq_placement",
        skip_serializing_if = "Option::is_none"
    )]
    pub seq_placement: Option<String>,
    #[serde(
        default,
        rename = "seqKey",
        alias = "seq-key",
        alias = "seq_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub seq_key: Option<String>,
    #[serde(
        default,
        rename = "uplinkDataPlacement",
        alias = "uplink-data-placement",
        alias = "uplink_data_placement",
        skip_serializing_if = "Option::is_none"
    )]
    pub uplink_data_placement: Option<String>,
    #[serde(
        default,
        rename = "uplinkDataKey",
        alias = "uplink-data-key",
        alias = "uplink_data_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub uplink_data_key: Option<String>,
    #[serde(
        default,
        rename = "uplinkChunkSize",
        alias = "uplink-chunk-size",
        alias = "uplink_chunk_size",
        skip_serializing_if = "Option::is_none"
    )]
    pub uplink_chunk_size: Option<XhttpRange>,
    #[serde(
        default,
        rename = "noGRPCHeader",
        alias = "noGrpcHeader",
        alias = "no-grpc-header",
        alias = "no_grpc_header",
        skip_serializing_if = "Option::is_none"
    )]
    pub no_grpc_header: Option<bool>,
    #[serde(
        default,
        rename = "noSSEHeader",
        alias = "noSseHeader",
        alias = "no-sse-header",
        alias = "no_sse_header",
        skip_serializing_if = "Option::is_none"
    )]
    pub no_sse_header: Option<bool>,
    #[serde(
        default,
        rename = "scMaxEachPostBytes",
        alias = "sc-max-each-post-bytes",
        alias = "sc_max_each_post_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_max_each_post_bytes: Option<XhttpRange>,
    #[serde(
        default,
        rename = "scMinPostsIntervalMs",
        alias = "sc-min-posts-interval-ms",
        alias = "sc_min_posts_interval_ms",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_min_posts_interval_ms: Option<XhttpRange>,
    #[serde(
        default,
        rename = "scMaxBufferedPosts",
        alias = "sc-max-buffered-posts",
        alias = "sc_max_buffered_posts",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_max_buffered_posts: Option<i64>,
    #[serde(
        default,
        rename = "scStreamUpServerSecs",
        alias = "sc-stream-up-server-secs",
        alias = "sc_stream_up_server_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub sc_stream_up_server_secs: Option<XhttpRange>,
    #[serde(
        default,
        rename = "serverMaxHeaderBytes",
        alias = "server-max-header-bytes",
        alias = "server_max_header_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_max_header_bytes: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux: Option<XhttpXmuxConfig>,
    #[serde(
        default,
        rename = "downloadSettings",
        alias = "download-settings",
        alias = "downloadConfig",
        alias = "download-config",
        alias = "download_config",
        skip_serializing_if = "Option::is_none"
    )]
    pub download_settings: Option<Box<XhttpDownloadSettings>>,
    /// Xray 的兼容覆盖块。它仍是强类型 SplitHTTPConfig，不是任意 JSON。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Box<XhttpConfig>>,
}

impl XhttpConfig {
    pub fn validate(&self) -> Result<(), String> {
        let effective = self.resolve_extra_at("xhttp")?;
        effective.validate_effective_at("xhttp", 0)
    }

    pub fn resolved(&self) -> Result<Self, String> {
        self.resolve_extra_at("xhttp")
    }

    fn resolve_extra_at(&self, _path: &str) -> Result<Self, String> {
        let Some(extra) = &self.extra else {
            return Ok(self.clone());
        };
        // 固定 Xray Build 只反序列化一层 extra；extra 内再嵌套的 extra 不会
        // 被递归 Build。主体来自第一层，外层仅覆盖 host/path/mode。
        let mut effective = (**extra).clone();
        effective.host = self.host.clone();
        effective.path = self.path.clone();
        effective.mode = self.mode.clone();
        effective.extra = None;
        Ok(effective)
    }

    fn validate_effective_at(&self, path: &str, depth: usize) -> Result<(), String> {
        if depth > 8 {
            return Err(format!("{path}.downloadSettings 递归层数不能超过 8"));
        }

        let mode = self.mode.as_deref().unwrap_or("auto");
        if !matches!(mode, "auto" | "packet-up" | "stream-up" | "stream-one") {
            return Err(format!("{path}.mode 不支持 `{mode}`"));
        }
        if let Some(headers) = &self.headers {
            for (name, value) in headers {
                if is_managed_xhttp_header(name) {
                    return Err(format!(
                        "{path}.headers 不能包含托管的 Host/framing/hop-by-hop 请求头 `{name}`"
                    ));
                }
                if !is_valid_http_header_name(name) {
                    return Err(format!("{path}.headers 包含非法请求头名称 `{name}`"));
                }
                if !is_valid_http_header_value(value) {
                    return Err(format!("{path}.headers.{name} 包含非法请求头值"));
                }
            }
        }
        if self
            .x_padding_bytes
            .is_some_and(|range| range.to > 0 && range.from == 0)
        {
            return Err(format!(
                "{path}.xPaddingBytes 显式非零范围的上下界都必须大于 0"
            ));
        }
        if self
            .x_padding_bytes
            .is_some_and(|range| range.to > XHTTP_MAX_PADDING_BYTES)
        {
            return Err(format!(
                "{path}.xPaddingBytes 不能大于 {XHTTP_MAX_PADDING_BYTES}"
            ));
        }
        validate_choice(
            path,
            "xPaddingPlacement",
            self.x_padding_placement.as_deref(),
            &["cookie", "header", "query", "queryInHeader"],
        )?;
        validate_choice(
            path,
            "xPaddingMethod",
            self.x_padding_method.as_deref(),
            &["repeat-x", "tokenish"],
        )?;
        validate_choice(
            path,
            "sessionIDPlacement",
            self.session_id_placement.as_deref(),
            &["path", "cookie", "header", "query"],
        )?;
        validate_choice(
            path,
            "seqPlacement",
            self.seq_placement.as_deref(),
            &["path", "cookie", "header", "query"],
        )?;
        validate_choice(
            path,
            "uplinkDataPlacement",
            self.uplink_data_placement.as_deref(),
            &["auto", "body", "cookie", "header"],
        )?;

        if matches!(
            self.uplink_data_placement.as_deref(),
            Some("cookie" | "header")
        ) && mode != "packet-up"
        {
            return Err(format!(
                "{path}.uplinkDataPlacement 仅能在 packet-up 模式使用"
            ));
        }
        if self
            .uplink_http_method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("GET"))
            && mode != "packet-up"
        {
            return Err(format!(
                "{path}.uplinkHTTPMethod=GET 仅能在 packet-up 模式使用"
            ));
        }

        if let Some(table) = self
            .session_id_table
            .as_deref()
            .filter(|table| !table.is_empty())
        {
            let (alphabet, predefined) = expanded_session_id_table(table);
            if !predefined {
                if !alphabet.is_ascii() {
                    return Err(format!(
                        "{path}.sessionIDTable 自定义字符表只能包含 ASCII 字符"
                    ));
                }
            }
            let length = self
                .session_id_length
                .ok_or_else(|| format!("{path}.sessionIDTable 非空时必须设置 sessionIDLength"))?;
            if length.from == 0 {
                return Err(format!("{path}.sessionIDLength 下界必须大于 0"));
            }
            if !session_id_room_is_sufficient(alphabet, length.from, length.to) {
                return Err(format!(
                    "{path}.sessionIDTable 与 sessionIDLength 的可选 ID 空间小于 31-bit"
                ));
            }
        }

        if self.server_max_header_bytes.is_some_and(|value| value < 0) {
            return Err(format!("{path}.serverMaxHeaderBytes 不能为负数"));
        }
        if self.sc_max_buffered_posts.is_some_and(|value| value < 0) {
            return Err(format!("{path}.scMaxBufferedPosts 不能为负数"));
        }
        if self
            .sc_max_buffered_posts
            .is_some_and(|value| value > XHTTP_MAX_BUFFERED_POSTS)
        {
            return Err(format!(
                "{path}.scMaxBufferedPosts 不能大于 {XHTTP_MAX_BUFFERED_POSTS}"
            ));
        }
        if let Some(xmux) = &self.xmux {
            if xmux.max_connections.is_some_and(|range| range.to > 0)
                && xmux.max_concurrency.is_some_and(|range| range.to > 0)
            {
                return Err(format!(
                    "{path}.xmux.maxConnections 与 maxConcurrency 不能同时启用"
                ));
            }
        }
        if let Some(download) = &self.download_settings {
            if mode == "stream-one" {
                return Err(format!("{path}.downloadSettings 不能用于 stream-one 模式"));
            }
            download.validate_at(&format!("{path}.downloadSettings"), depth + 1)?;
        }
        Ok(())
    }
}

impl XhttpDownloadSettings {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_at("xhttp.downloadSettings", 0)
    }

    fn validate_at(&self, path: &str, depth: usize) -> Result<(), String> {
        if self
            .address
            .as_deref()
            .or(self.host.as_deref())
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!("{path} 必须设置非空 address 或 host"));
        }
        if self.port.is_none_or(|port| port == 0) {
            return Err(format!("{path}.port 必须设置且不能为 0"));
        }
        if let Some(security) = self.security.as_deref() {
            if !security.is_empty()
                && !["none", "tls", "reality"]
                    .iter()
                    .any(|allowed| security.eq_ignore_ascii_case(allowed))
            {
                return Err(format!("{path}.security 不支持 `{security}`"));
            }
        }
        if self
            .security
            .as_deref()
            .is_some_and(|security| security.eq_ignore_ascii_case("tls"))
        {
            if let Some(tls) = &self.tls_settings {
                tls.validate_client_at(&format!("{path}.tlsSettings"))?;
            }
        }
        let effective_network = self
            .method
            .as_deref()
            .or(self.network.as_deref())
            .map(str::trim);
        if let Some(network) = effective_network {
            if network.is_empty()
                || (!network.eq_ignore_ascii_case("xhttp")
                    && !network.eq_ignore_ascii_case("splithttp"))
            {
                return Err(format!(
                    "{path}.method/network 必须为 xhttp 或 splithttp，实际为 `{network}`"
                ));
            }
        }
        if self
            .alpn
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
        {
            return Err(format!("{path}.alpn 不能包含空值"));
        }
        if self
            .tls_settings
            .as_ref()
            .and_then(|settings| settings.alpn.as_ref())
            .is_some_and(|values| values.iter().any(|value| value.trim().is_empty()))
        {
            return Err(format!("{path}.tlsSettings.alpn 不能包含空值"));
        }
        if let (Some(alpn), Some(tls_alpn)) = (
            self.alpn.as_ref().filter(|values| !values.is_empty()),
            self.tls_settings
                .as_ref()
                .and_then(|settings| settings.alpn.as_ref())
                .filter(|values| !values.is_empty()),
        ) {
            if alpn != tls_alpn {
                return Err(format!(
                    "{path}.alpn 与 tlsSettings.alpn 同时非空时必须等价"
                ));
            }
        }

        let transport = self.transport.as_deref();
        if let Some(kind) = transport
            .and_then(|transport| transport.kind.as_deref())
            .map(str::trim)
            .filter(|kind| !kind.is_empty())
        {
            if !kind.eq_ignore_ascii_case("xhttp") && !kind.eq_ignore_ascii_case("splithttp") {
                return Err(format!(
                    "{path}.transport.kind 必须为 xhttp 或 splithttp，实际为 `{kind}`"
                ));
            }
        }
        if transport
            .and_then(|transport| transport.service.as_deref())
            .is_some_and(|service| !service.trim().is_empty())
        {
            return Err(format!(
                "{path}.transport.service 仅适用于 gRPC，XHTTP downloadSettings 不支持该字段"
            ));
        }

        let transport_xhttp = transport.and_then(|transport| transport.xhttp.as_ref());
        let mut direct_effective = self
            .xhttp_settings
            .as_deref()
            .map(|config| config.resolve_extra_at(&format!("{path}.xhttpSettings")))
            .transpose()?;
        let mut transport_effective = transport_xhttp
            .map(|config| config.resolve_extra_at(&format!("{path}.transport.xhttp")))
            .transpose()?;
        if let Some(transport) = transport {
            for effective in [&mut direct_effective, &mut transport_effective]
                .into_iter()
                .flatten()
            {
                if effective
                    .host
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    effective.host.clone_from(&transport.host);
                }
                if effective
                    .path
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    effective.path.clone_from(&transport.path);
                }
            }
        }
        if let (Some(direct), Some(nested)) = (&direct_effective, &transport_effective) {
            if direct != nested {
                return Err(format!(
                    "{path}.xhttpSettings 与 transport.xhttp 同时设置时必须语义等价"
                ));
            }
        }
        let effective = direct_effective
            .as_ref()
            .or(transport_effective.as_ref())
            .ok_or_else(|| format!("{path} 必须设置独立 xhttpSettings"))?;

        if let Some(transport) = transport {
            for (field, generic, nested) in [
                ("host", transport.host.as_deref(), effective.host.as_deref()),
                ("path", transport.path.as_deref(), effective.path.as_deref()),
            ] {
                if let (Some(generic), Some(nested)) = (
                    generic.filter(|value| !value.trim().is_empty()),
                    nested.filter(|value| !value.trim().is_empty()),
                ) {
                    if generic != nested {
                        return Err(format!(
                            "{path}.transport.{field} 与独立 XHTTP 配置的 {field} 同时非空时必须等价"
                        ));
                    }
                }
            }
        }

        effective.validate_effective_at(&format!("{path}.xhttpSettings"), depth + 1)?;
        Ok(())
    }
}

fn validate_choice(
    path: &str,
    field: &str,
    value: Option<&str>,
    allowed: &[&str],
) -> Result<(), String> {
    if let Some(value) = value {
        if !allowed.contains(&value) {
            return Err(format!("{path}.{field} 不支持 `{value}`"));
        }
    }
    Ok(())
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

fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
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

fn session_id_room_is_sufficient(table: &str, min_length: u32, max_length: u32) -> bool {
    const REQUIRED: u128 = 2u128 << 30;
    if min_length > max_length {
        return false;
    }

    let base = table.len() as u128;
    if base == 0 {
        return false;
    }
    if base == 1 {
        return u128::from(max_length - min_length) + 1 >= REQUIRED;
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

fn pow_capped(mut base: u128, mut exponent: u32, cap: u128) -> u128 {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeNetwork {
    #[serde(default)]
    pub udp: Option<bool>,
    #[serde(default)]
    pub tfo: Option<bool>,
    #[serde(default)]
    pub mptcp: Option<bool>,
    #[serde(default)]
    pub mark: Option<u32>,
    #[serde(default)]
    pub ip_family: Option<String>,
}

/* ---------------- groups ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    #[serde(default = "default_choose")]
    pub choose: ChooseStrategy,
    #[serde(default)]
    pub r#use: Vec<String>,
    #[serde(default)]
    pub prefer: Vec<String>,
    #[serde(default)]
    pub avoid: Vec<String>,
    #[serde(default)]
    pub check: Option<String>,
    #[serde(default)]
    pub sticky: Option<String>,
    #[serde(default)]
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChooseStrategy {
    Manual,
    Smart,
    Fast,
    Stable,
    Spread,
    Chain,
}

/* ---------------- route ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default = "default_route_preset")]
    pub preset: String,
    #[serde(default = "default_route_final")]
    pub r#final: String,
    #[serde(default)]
    pub steps: Vec<RouteStepEntry>,
    /// 外部规则集 —— mihomo / sing-box / 自定义 payload。
    /// 在 `steps` 中通过 `set:<name> -> <action>` 引用。
    #[serde(default)]
    pub sets: BTreeMap<String, RuleSetSpec>,
    /// sing-box `route.rule_set` 兼容入口。编译阶段按 `tag` 展开并合并进
    /// [`Self::sets`]；运行时只保留统一后的 `sets`。
    #[serde(
        default,
        rename = "rule_set",
        alias = "rule-set",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub rule_set: Vec<SingboxRuleSetSpec>,
}

/// 单条路由规则条目 —— 接受四种写法（混用合法）：
///
/// 1. **WutherCore DSL 字符串**：`"port:53 -> direct"`、`"set:openai -> ai"`。
/// 2. **mihomo classical 字符串**：`"DST-PORT,53,DNS_Hijack"`（policy 内嵌）。
/// 3. **mihomo classical mapping**：`{match: "DST-PORT,53", outbound: DNS_Hijack}`。
/// 4. **typed-key mapping**（推荐写法）：
///    ```yaml
///    - {port: 53, outbound: DNS_Hijack}                       # 单值
///    - {port: [53, 5353], outbound: DNS_Hijack}               # OR within field
///    - {suffix: example.com, port: 443, outbound: direct}     # AND across fields
///    - {match: "DST-PORT,53", network: udp, outbound: hijack} # match + typed AND
///    ```
///    具名字段同时设置时按 AND 组合；列表值在单字段内按 OR 组合。
///
/// 四种形式都在 `compile_route` 阶段编译为 `RouteStep`；object 形式不会经过
/// DSL 字符串再解析，省掉一次 round-trip。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RouteStepEntry {
    Line(String),
    Object(RouteStepObject),
}

/// 路由规则对象。所有匹配字段均可选；至少需要一项匹配源（`match` 或具名字段），
/// `outbound` 必填。多个匹配源同时存在时按 AND 组合（核心引擎以 `RouteMatcher::And`
/// 表示，可短路求值）。具名字段值若为列表，按 OR 组合（`RouteMatcher::Or`）。
///
/// `deny_unknown_fields` 故意启用：拼写错误（如 `port-num:`）会立刻报错而非被
/// 当成"无匹配源"静默通过；命中即配置错误。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteStepObject {
    /// mihomo classical 完整字符串：`TYPE,VALUE` —— 与具名字段可叠加（AND）。
    #[serde(default, alias = "rule")]
    pub r#match: Option<String>,

    /// 严格相等的域名。
    #[serde(default)]
    pub domain: Option<MatcherValue>,
    /// 域名后缀。canonical: `suffix`；mihomo 友好别名 `domain-suffix` / `domain_suffix`。
    #[serde(default, alias = "domain-suffix", alias = "domain_suffix")]
    pub suffix: Option<MatcherValue>,
    /// 子串关键字。canonical: `keyword`；mihomo 友好别名 `domain-keyword`。
    #[serde(default, alias = "domain-keyword", alias = "domain_keyword")]
    pub keyword: Option<MatcherValue>,
    /// IP CIDR。canonical: `ip`；别名 `cidr` / `ip-cidr`。
    #[serde(default, alias = "cidr", alias = "ip-cidr", alias = "ip_cidr")]
    pub ip: Option<MatcherValue>,
    /// 目的端口（单个 `53` 或区间 `1000-2000`）。canonical: `port`；别名 `dst-port`。
    #[serde(default, alias = "dst-port", alias = "dst_port")]
    pub port: Option<MatcherValue>,
    /// 进程名。canonical: `process`；别名 `process-name`。
    #[serde(default, alias = "process-name", alias = "process_name")]
    pub process: Option<MatcherValue>,
    /// 外部规则集名（`route.sets.<name>`）。canonical: `set`；别名 `rule-set`。
    #[serde(default, alias = "rule-set", alias = "rule_set")]
    pub set: Option<MatcherValue>,
    /// 网络协议（`tcp` / `udp`）。
    #[serde(default)]
    pub network: Option<String>,
    /// L7 协议指纹（`tls` / `quic` / `stun` / `http` / `webrtc`...）。
    #[serde(default)]
    pub proto: Option<String>,

    /// 出站 / 分组名 / `direct` / `block`。
    #[serde(alias = "proxy", alias = "target", alias = "action")]
    pub outbound: String,
}

/// 单个或多个值的统一表示 —— 让 `port: 53`、`port: "53"`、`port: [53, "5353"]`
/// 都能解析。列表值在编译阶段会被包裹成 `RouteMatcher::Or`，匹配时短路求值。
///
/// 自实现 `Deserialize` 而非 `derive(untagged)`，是为了把整型 / 布尔自动转成字符串
/// —— YAML 写 `port: 53` 时值是 i64，不会自动落到 `Single(String)` 上，
/// 用户体验上为难。统一收敛成字符串，编译期再把 port 解析回 u16。
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum MatcherValue {
    Single(String),
    List(Vec<String>),
}

impl MatcherValue {
    /// 拷贝为 `Vec<String>`，方便消费侧统一处理。
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::List(v) => v.clone(),
        }
    }
}

impl<'de> Deserialize<'de> for MatcherValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = MatcherValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string / integer / boolean, or a list of those")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<MatcherValue, E> {
                Ok(MatcherValue::Single(v.to_string()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<MatcherValue, E> {
                Ok(MatcherValue::Single(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<MatcherValue, E> {
                Ok(MatcherValue::Single(v.to_string()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<MatcherValue, E> {
                Ok(MatcherValue::Single(v.to_string()))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<MatcherValue, E> {
                Ok(MatcherValue::Single(v.to_string()))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<MatcherValue, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut list = Vec::new();
                while let Some(elem) = seq.next_element::<serde_yaml::Value>()? {
                    let s = match elem {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(serde::de::Error::custom(format!(
                                "matcher list item must be scalar, got {other:?}"
                            )));
                        }
                    };
                    list.push(s);
                }
                Ok(MatcherValue::List(list))
            }
        }

        deserializer.deserialize_any(V)
    }
}

impl From<&str> for RouteStepEntry {
    fn from(s: &str) -> Self {
        RouteStepEntry::Line(s.to_string())
    }
}

impl From<String> for RouteStepEntry {
    fn from(s: String) -> Self {
        RouteStepEntry::Line(s)
    }
}

/// `route.sets.<name>` 配置 —— 与 `core_ruleset::RulesetSpec` 一一对应，
/// 这里只做 YAML 反序列化所需的最小字段；运行时由 core-ruleset 编译。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSpec {
    /// 远程来源；与 `path` 同时出现时，`path` 是该远程规则集的显式缓存。
    #[serde(default)]
    pub url: Option<String>,
    /// `url` 为空时是本地来源；`url` 存在时是远程缓存位置。
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub payload: Vec<String>,
    #[serde(default = "default_ruleset_type")]
    pub r#type: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "default_ruleset_every", with = "humantime_serde")]
    pub every: Duration,
    #[serde(default = "default_feed_via")]
    pub via: String,
}

/// sing-box `route.rule_set[]` 原始配置。
///
/// 这里保留上游字段名与互斥关系；`runtime_plan` 编译阶段会严格校验后转换成
/// [`RuleSetSpec`]。因此 sing-box 的 source-kind `type` 不会与 WutherCore
/// 表示 behavior 的 `RuleSetSpec::type` 混淆。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingboxRuleSetSpec {
    /// `inline` / `local` / `remote`；inline 可省略。
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    pub tag: SingboxRuleSetTags,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub rules: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub update_interval: Option<CompatDuration>,
    #[serde(default)]
    pub download_detour: Option<String>,
    /// 兼容任务所需的 `http_client.download_detour`。使用 `Value` 是为了让
    /// 归一化层能对 string/object 与不支持的嵌套字段给出精确错误。
    #[serde(default)]
    pub http_client: Option<serde_yaml::Value>,
}

/// sing-box 1.14+ 允许一个 local/remote 配置用 tag 列表批量定义规则集。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SingboxRuleSetTags {
    One(String),
    Many(Vec<String>),
}

/// Mihomo 顶层 `rule-providers.<name>` 原始配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MihomoRuleProviderSpec {
    /// `http` / `file` / `inline`。
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub payload: Option<Vec<String>>,
    pub behavior: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub interval: Option<CompatDuration>,
    #[serde(default)]
    pub proxy: Option<String>,
}

/// 上游刷新周期兼容表示：Mihomo 使用整数秒，sing-box 使用 duration 字符串。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompatDuration {
    Seconds(u64),
    Human(#[serde(with = "humantime_serde")] Duration),
}

impl CompatDuration {
    pub fn duration(&self) -> Duration {
        match self {
            Self::Seconds(seconds) => Duration::from_secs(*seconds),
            Self::Human(duration) => *duration,
        }
    }
}

fn default_ruleset_type() -> String {
    "domain".into()
}
fn default_ruleset_every() -> Duration {
    Duration::from_secs(24 * 3600)
}

/* ---------------- resolver ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    #[serde(default = "default_resolver_mode")]
    pub mode: ResolverMode,
    #[serde(default = "default_fake")]
    pub fake: FakeMode,
    #[serde(default = "default_cache", with = "humantime_serde")]
    pub cache: Duration,
    #[serde(default = "default_true")]
    pub ipv6: bool,
    #[serde(
        default = "default_ipv6_timeout",
        with = "humantime_serde",
        rename = "ipv6-timeout"
    )]
    pub ipv6_timeout: Duration,
    #[serde(default = "default_true", rename = "use-hosts")]
    pub use_hosts: bool,
    #[serde(default = "default_true", rename = "use-system-hosts")]
    pub use_system_hosts: bool,
    #[serde(default)]
    pub hosts: serde_yaml::Mapping,
    #[serde(default, rename = "fake-ip-filter")]
    pub fake_ip_filter: Vec<String>,
    #[serde(default, rename = "fake-ip-filter-mode")]
    pub fake_ip_filter_mode: FakeIpFilterMode,
    #[serde(default, rename = "prefer-h3")]
    pub prefer_h3: bool,
    #[serde(default)]
    pub nameserver: Vec<String>,
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(default, rename = "fallback-filter")]
    pub fallback_filter: ResolverFallbackFilter,
    #[serde(default, rename = "default-nameserver")]
    pub default_nameserver: Vec<String>,
    #[serde(default, rename = "nameserver-policy")]
    pub nameserver_policy: serde_yaml::Mapping,
    #[serde(default, rename = "proxy-server-nameserver")]
    pub proxy_server_nameserver: Vec<String>,
    #[serde(default, rename = "proxy-server-nameserver-policy")]
    pub proxy_server_nameserver_policy: serde_yaml::Mapping,
    #[serde(default, rename = "direct-nameserver")]
    pub direct_nameserver: Vec<String>,
    #[serde(default, rename = "direct-nameserver-follow-policy")]
    pub direct_nameserver_follow_policy: bool,
    /// 命名 DNS server。字符串是兼容/简洁写法；对象写法可让同一个 endpoint
    /// 通过多个代理出口查询。
    #[serde(default = "default_resolver_servers")]
    pub servers: BTreeMap<String, ResolverServer>,
    /// 可嵌套 DNS group。列表是简洁写法；对象写法可覆盖策略、超时和并发上限。
    #[serde(default)]
    pub groups: BTreeMap<String, ResolverGroup>,
    #[serde(default)]
    pub rules: Vec<serde_yaml::Value>,
    /// 标准 DNS 监听地址，对标 mihomo `dns.listen`。
    /// 例：`0.0.0.0:1053`、`127.0.0.1:53`、`[::]:5353`。
    /// 空 / None / 空串 = 不启动独立 DNS server。
    /// 同地址同时承载 UDP 和 TCP（与 mihomo 一致）。
    #[serde(default)]
    pub listen: Option<String>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Normal,
            fake: FakeMode::Auto,
            cache: default_cache(),
            ipv6: true,
            ipv6_timeout: default_ipv6_timeout(),
            use_hosts: true,
            use_system_hosts: true,
            hosts: serde_yaml::Mapping::new(),
            fake_ip_filter: Vec::new(),
            fake_ip_filter_mode: FakeIpFilterMode::default(),
            prefer_h3: false,
            nameserver: vec!["ali".into()],
            fallback: vec!["cloudflare".into()],
            fallback_filter: ResolverFallbackFilter::default(),
            default_nameserver: Vec::new(),
            nameserver_policy: serde_yaml::Mapping::new(),
            proxy_server_nameserver: Vec::new(),
            proxy_server_nameserver_policy: serde_yaml::Mapping::new(),
            direct_nameserver: Vec::new(),
            direct_nameserver_follow_policy: false,
            servers: default_resolver_servers(),
            groups: BTreeMap::new(),
            rules: Vec::new(),
            listen: None,
        }
    }
}

/// DNS 成员选择策略。
///
/// `random` 是均匀随机；`adaptive` 使用查询过程中学习到的平均 RTT 做加权随机，
/// 与 AdGuard dnsproxy 的 load-balance 算法一致：平均 RTT 越小，权重越大。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverStrategy {
    RoundRobin,
    Random,
    Parallel,
    #[default]
    Adaptive,
    /// 兼容旧的顺序故障转移语义。
    #[serde(alias = "fallback")]
    Sequential,
    /// 并发收集所有成功答案。
    All,
}

fn default_dns_group_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_dns_max_parallel() -> usize {
    2
}

/// 命名 server 的兼容字符串写法或高级多出口写法。
#[derive(Debug, Clone, Serialize)]
pub enum ResolverServer {
    Simple(String),
    Advanced(ResolverServerAdvanced),
}

impl<'de> Deserialize<'de> for ResolverServer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(endpoint) => Ok(Self::Simple(endpoint)),
            serde_yaml::Value::Mapping(_) => {
                serde_yaml::from_value::<ResolverServerAdvanced>(value)
                    .map(Self::Advanced)
                    .map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::custom(
                "DNS server 必须是 endpoint 字符串，或包含 endpoint/exits 的对象",
            )),
        }
    }
}

impl ResolverServer {
    pub fn endpoint(&self) -> &str {
        match self {
            Self::Simple(endpoint) => endpoint,
            Self::Advanced(config) => &config.endpoint,
        }
    }

    pub fn exits(&self) -> &[String] {
        match self {
            Self::Simple(_) => &[],
            Self::Advanced(config) => &config.exits,
        }
    }

    pub fn strategy(&self) -> ResolverStrategy {
        match self {
            Self::Simple(_) => ResolverStrategy::Sequential,
            Self::Advanced(config) => config.strategy,
        }
    }

    pub fn timeout(&self) -> Duration {
        match self {
            Self::Simple(_) => default_dns_group_timeout(),
            Self::Advanced(config) => config.timeout,
        }
    }

    pub fn max_parallel(&self) -> usize {
        match self {
            Self::Simple(_) => 1,
            Self::Advanced(config) => config.max_parallel.max(1),
        }
    }
}

impl From<String> for ResolverServer {
    fn from(value: String) -> Self {
        Self::Simple(value)
    }
}

impl From<&str> for ResolverServer {
    fn from(value: &str) -> Self {
        Self::Simple(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverServerAdvanced {
    /// 唯一 DNS 服务 endpoint。服务级冗余应由 `resolver.groups` 表达。
    #[serde(alias = "address", alias = "upstream")]
    pub endpoint: String,
    /// 访问该 endpoint 的代理节点数组；空数组表示沿用默认直连 DNS socket。
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        alias = "outbound",
        alias = "outbounds",
        alias = "nodes"
    )]
    pub exits: Vec<String>,
    #[serde(default)]
    pub strategy: ResolverStrategy,
    #[serde(default = "default_dns_group_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(
        default = "default_dns_max_parallel",
        rename = "max-parallel",
        alias = "max_parallel"
    )]
    pub max_parallel: usize,
}

/// DNS group 的简洁列表写法或高级对象写法。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResolverGroup {
    Simple(Vec<String>),
    Advanced(ResolverGroupAdvanced),
}

impl ResolverGroup {
    pub fn members(&self) -> &[String] {
        match self {
            Self::Simple(members) => members,
            Self::Advanced(config) => &config.members,
        }
    }

    pub fn strategy(&self) -> ResolverStrategy {
        match self {
            Self::Simple(_) => ResolverStrategy::Adaptive,
            Self::Advanced(config) => config.strategy,
        }
    }

    pub fn timeout(&self) -> Duration {
        match self {
            Self::Simple(_) => default_dns_group_timeout(),
            Self::Advanced(config) => config.timeout,
        }
    }

    pub fn max_parallel(&self) -> usize {
        match self {
            Self::Simple(_) => default_dns_max_parallel(),
            Self::Advanced(config) => config.max_parallel.max(1),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverGroupAdvanced {
    /// 成员可以引用命名 server、其它 group，或直接写 endpoint。
    #[serde(
        default,
        deserialize_with = "deserialize_string_or_vec",
        alias = "member",
        alias = "servers",
        alias = "upstreams"
    )]
    pub members: Vec<String>,
    #[serde(default)]
    pub strategy: ResolverStrategy,
    #[serde(default = "default_dns_group_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(
        default = "default_dns_max_parallel",
        rename = "max-parallel",
        alias = "max_parallel"
    )]
    pub max_parallel: usize,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverFallbackFilter {
    #[serde(default = "default_true")]
    pub geoip: bool,
    #[serde(default = "default_geoip_code", rename = "geoip-code")]
    pub geoip_code: String,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
}

impl Default for ResolverFallbackFilter {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: default_geoip_code(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
            geosite: Vec::new(),
        }
    }
}

fn default_geoip_code() -> String {
    "CN".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    System,
    #[serde(alias = "secure")]
    #[serde(alias = "smart")]
    Normal,
    Fake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FakeMode {
    Off,
    Auto,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
}

impl Default for FakeIpFilterMode {
    fn default() -> Self {
        Self::Blacklist
    }
}

/* ---------------- capture ---------------- */

/// Capture / TUN 入站 —— 兼容 mihomo / sing-box 常用 `inbounds[type=tun]` 字段。
///
/// Friendly 字段（顶层）保留 WutherCore 简洁语义；`tun` 子字段对齐 sing-box JSON。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    #[serde(default)]
    pub on: bool,
    #[serde(default = "default_capture_method")]
    pub method: CaptureMethod,
    #[serde(default = "default_capture_traffic")]
    pub traffic: CaptureTraffic,
    #[serde(default = "default_capture_resolver")]
    pub resolver: CaptureResolver,
    #[serde(default = "default_capture_stack")]
    pub stack: CaptureStack,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default = "default_true")]
    pub offload: bool,
    #[serde(default)]
    pub exclude: CaptureExclude,
    /// sing-box 兼容子配置（详见 <https://sing-box.sagernet.org/configuration/inbound/tun/>）。
    #[serde(default)]
    pub tun: TunInboundOptions,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            on: false,
            method: CaptureMethod::Auto,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Hijack,
            stack: CaptureStack::Mixed,
            mtu: None,
            offload: true,
            exclude: CaptureExclude::default(),
            tun: TunInboundOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMethod {
    Auto,
    #[serde(rename = "virtual_nic")]
    VirtualNic,
    Tproxy,
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureTraffic {
    System,
    Lan,
    Apps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureResolver {
    Off,
    Hijack,
}

/// TCP/UDP 栈选择 —— 对标 sing-tun `stack` 字段。
///
/// sing-tun 实现：
/// - `system` = TCP 走 OS 内核 NAT + TcpListener accept，UDP 走 OS 转发
/// - `mixed`  = TCP 同 system，UDP 走 gVisor 用户态
/// - `gvisor` = TCP + UDP 全部走 gVisor 用户态
///
/// WutherCore 映射：
/// - `system` / `mixed` / `native` → SystemDispatcher（TCP NAT + OS accept + UDP forwarder）
/// - `gvisor` / `smoltcp` → TunDispatcher（smoltcp 用户态 TCP，仅测试/备用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStack {
    /// sing-tun `system` 栈：TCP NAT 改写 + OS TcpListener accept。
    System,
    /// sing-tun `mixed` 栈：TCP 同 system，UDP forwarder。推荐默认值。
    Mixed,
    /// 等价 system（向后兼容旧配置）。
    Native,
    /// smoltcp 用户态 TCP 栈（测试/备用）。
    Smoltcp,
    /// gVisor 占位（当前等价 smoltcp）。
    Gvisor,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureExclude {
    #[serde(default)]
    pub cidr: Vec<String>,
    #[serde(default)]
    pub process: Vec<String>,
}

/* -------- sing-box 风格 TUN 字段模型（各数据面按能力校验） -------- */

/// sing-tun auto_redirect input mark 默认值（`DefaultAutoRedirectInputMark`）。
///
/// auto_redirect mark/NFQUEUE 数据面的连接入站 mark。当前 Linux 安全子集
/// 使用 TCP NAT REDIRECT、UDP TUN，并且不为 ICMP/其他协议添加导流 rule；
/// 后者继续按已有主路由策略处理。显式配置
/// input mark 会在配置编译阶段失败，避免伪装成已生效。
pub const DEFAULT_AUTO_REDIRECT_INPUT_MARK: u32 = 0x2023;

/// sing-tun auto_redirect output mark 默认值（`DefaultAutoRedirectOutputMark`）。
///
/// auto_redirect 的连接出站 mark；同时复用于 TUN outbound socket 的
/// auto_route 绕行，避免代理自身流量再次进入 TUN。
pub const DEFAULT_AUTO_REDIRECT_OUTPUT_MARK: u32 = 0x2024;

/// sing-tun auto_redirect reset mark 默认值（`DefaultAutoRedirectResetMark`）。
///
/// auto_redirect 预匹配的连接 reset mark。只有启用配套 NFQUEUE
/// 预匹配消费者时才生效；当前数据面保留该字段但不会静默安装队列规则。
pub const DEFAULT_AUTO_REDIRECT_RESET_MARK: u32 = 0x2025;

/// sing-tun auto_redirect nfqueue 默认编号（`DefaultAutoRedirectNFQueue`）。
///
/// NFQUEUE 预匹配消费者的默认队列编号。当前数据面尚未提供消费者，因此
/// 显式配置该字段会在配置编译阶段失败，避免把流量送入无人读取的队列。
pub const DEFAULT_AUTO_REDIRECT_NFQUEUE: u16 = 100;

/// sing-tun fallback ip rule 优先级（`DefaultIPRoute2AutoRedirectFallbackRuleIndex`）。
///
/// 系统 main 表 (32766) / default 表 (32767) 之后的兜底 rule 优先级；当
/// auto_redirect mark 模式下 main+default 都没有路由时，由 32768 这条 rule
/// 把流量送回 TUN 表。对应 sing-tun `tun.go::70`。
pub const DEFAULT_IPROUTE2_AUTO_REDIRECT_FALLBACK_RULE_INDEX: u32 = 32768;

/// Linux 内置 `main` rule 默认优先级为 32766；capture rule 必须排在它之前。
pub const MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX: u32 = 32765;

/// 解析 sing-box/mihomo 兼容的十进制或 `0x` 十六进制 mark。
pub fn parse_auto_redirect_mark(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// 解析并归一化 auto_redirect mark。
///
/// sing-tun 与 mihomo 都把未设置或显式 `0` 视作“使用默认值”。无效文本返回
/// `None`，由配置编译器决定是否在当前激活的数据面上报错。
pub fn normalize_auto_redirect_mark(value: Option<&str>, default: u32) -> Option<u32> {
    match value {
        None => Some(default),
        Some(value) => {
            parse_auto_redirect_mark(value).map(|mark| if mark == 0 { default } else { mark })
        }
    }
}

/// sing-box `inbounds[type=tun]` 兼容字段映射 —— 见
/// <https://sing-box.sagernet.org/configuration/inbound/tun/>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundOptions {
    /// `interface_name` —— 优先级高于 WutherCore 默认 `rpktun0/utun7/WutherCoreTun`。
    #[serde(default)]
    pub interface_name: Option<String>,
    /// `address` —— TUN 接口 v4 / v6 CIDR 列表（首条 v4 / 首条 v6 生效）。
    #[serde(default)]
    pub address: Vec<String>,
    /// `inet6` —— 是否在 TUN 上启用 IPv6。关闭后不配 v6 地址 / 路由 / 规则 / listener。
    #[serde(default = "default_true")]
    pub inet6: bool,

    /* ---- 路由接管 ---- */
    /// `auto_route` —— 自动写默认路由（0.0.0.0/0 + ::/0 → tun）。
    #[serde(default = "default_true")]
    pub auto_route: bool,
    /// `iproute2_table_index` —— Linux 自定义路由表 id（默认 2022）。
    #[serde(default = "default_iproute2_table")]
    pub iproute2_table_index: u32,
    /// `iproute2_rule_index` —— `ip rule` 优先级起始 id。
    #[serde(default = "default_iproute2_rule")]
    pub iproute2_rule_index: u32,
    /// `auto_redirect` —— 在 auto_route TUN 数据面上，为 TCP 注入
    /// nftables NAT REDIRECT。当前安全契约只把本机 UDP 送入 TUN；
    /// ICMP/其他协议不新增导流 rule，继续按已有主路由策略处理。
    #[serde(default)]
    pub auto_redirect: bool,
    /// `auto_redirect_input_mark` —— 保留的 mark/NFQUEUE 入站 mark；当前
    /// Linux REDIRECT 安全子集不消费，显式配置会失败。
    #[serde(default)]
    pub auto_redirect_input_mark: Option<String>,
    /// `auto_redirect_output_mark` —— 跳过 redirect chain 的 fwmark。
    #[serde(default)]
    pub auto_redirect_output_mark: Option<String>,
    /// `auto_redirect_reset_mark` —— NFQUEUE 预匹配的连接 reset mark（保留字段）。
    #[serde(default)]
    pub auto_redirect_reset_mark: Option<String>,
    /// `auto_redirect_nfqueue` —— NFQUEUE 预匹配队列编号（当前无消费者）。
    #[serde(default)]
    pub auto_redirect_nfqueue: Option<u16>,
    /// `auto_redirect_iproute2_fallback_rule_index` —— fallback ip rule 优先级。
    #[serde(default)]
    pub auto_redirect_iproute2_fallback_rule_index: Option<u32>,
    /// `strict_route` —— 严格防泄漏；任何未接管流量被 drop。
    #[serde(default)]
    pub strict_route: bool,
    /// `route_address` —— 仅这些 CIDR 走 TUN（白名单）。空 = 全部。
    #[serde(default)]
    pub route_address: Vec<String>,
    /// `route_exclude_address` —— 这些 CIDR 不走 TUN（黑名单）。
    #[serde(default)]
    pub route_exclude_address: Vec<String>,
    /// `route_address_set` —— 白名单引用 ruleset（动态 IP 集）。
    #[serde(default)]
    pub route_address_set: Vec<String>,
    /// `route_exclude_address_set` —— 黑名单引用 ruleset。
    #[serde(default)]
    pub route_exclude_address_set: Vec<String>,

    /* ---- NAT / 性能 ---- */
    /// `endpoint_independent_nat` —— 全锥 NAT；UDP 打洞场景需开。
    #[serde(default)]
    pub endpoint_independent_nat: bool,
    /// `udp_timeout` —— UDP NAT 老化（默认 5m）。
    #[serde(default = "default_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,
    /// `exclude_mptcp` —— 透传 MPTCP 不接管。
    #[serde(default)]
    pub exclude_mptcp: bool,
    /// `loopback_address` —— 哪些 IP 视为 loopback 不接管（如保留地址）。
    #[serde(default)]
    pub loopback_address: Vec<String>,

    /* ---- 接口过滤 ---- */
    /// `include_interface` —— 仅接管这些上行接口的流量。
    #[serde(default)]
    pub include_interface: Vec<String>,
    /// `exclude_interface` —— 排除这些接口。
    #[serde(default)]
    pub exclude_interface: Vec<String>,

    /* ---- UID 过滤（Linux/Android）---- */
    #[serde(default)]
    pub include_uid: Vec<u32>,
    /// 形如 `"1000:99999"`，闭区间。
    #[serde(default)]
    pub include_uid_range: Vec<String>,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default)]
    pub exclude_uid_range: Vec<String>,

    /* ---- GID 过滤（Linux/Android）—— 与 UID 同语义，作用于 `meta skgid` ---- */
    #[serde(default)]
    pub include_gid: Vec<u32>,
    #[serde(default)]
    pub include_gid_range: Vec<String>,
    #[serde(default)]
    pub exclude_gid: Vec<u32>,
    #[serde(default)]
    pub exclude_gid_range: Vec<String>,

    /* ---- Android 专属 ---- */
    /// `include_android_user` —— 仅接管这些 Android user id 的流量（双开 / 工作资料）。
    #[serde(default)]
    pub include_android_user: Vec<u32>,
    /// `include_package` —— Android 包名白名单。
    #[serde(default)]
    pub include_package: Vec<String>,
    /// `exclude_package` —— Android 包名黑名单。
    #[serde(default)]
    pub exclude_package: Vec<String>,

    /* ---- LAN MAC 过滤（路由器场景）---- */
    #[serde(default)]
    pub include_mac_address: Vec<String>,
    #[serde(default)]
    pub exclude_mac_address: Vec<String>,

    /* ---- 平台桥 ---- */
    /// `platform.http_proxy` —— iOS/Android 系统代理透传。
    #[serde(default)]
    pub platform: Option<TunPlatformOptions>,
}

impl Default for TunInboundOptions {
    fn default() -> Self {
        Self {
            interface_name: None,
            address: Vec::new(),
            inet6: true,
            auto_route: true,
            iproute2_table_index: default_iproute2_table(),
            iproute2_rule_index: default_iproute2_rule(),
            auto_redirect: false,
            auto_redirect_input_mark: None,
            auto_redirect_output_mark: None,
            auto_redirect_reset_mark: None,
            auto_redirect_nfqueue: None,
            auto_redirect_iproute2_fallback_rule_index: None,
            strict_route: false,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            route_address_set: Vec::new(),
            route_exclude_address_set: Vec::new(),
            endpoint_independent_nat: false,
            udp_timeout: default_udp_timeout(),
            exclude_mptcp: false,
            loopback_address: Vec::new(),
            include_interface: Vec::new(),
            exclude_interface: Vec::new(),
            include_uid: Vec::new(),
            include_uid_range: Vec::new(),
            exclude_uid: Vec::new(),
            exclude_uid_range: Vec::new(),
            include_gid: Vec::new(),
            include_gid_range: Vec::new(),
            exclude_gid: Vec::new(),
            exclude_gid_range: Vec::new(),
            include_android_user: Vec::new(),
            include_package: Vec::new(),
            exclude_package: Vec::new(),
            include_mac_address: Vec::new(),
            exclude_mac_address: Vec::new(),
            platform: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunPlatformOptions {
    #[serde(default)]
    pub http_proxy: Option<TunHttpProxyOptions>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunHttpProxyOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
    #[serde(default)]
    pub bypass_domain: Vec<String>,
    #[serde(default)]
    pub match_domain: Vec<String>,
}

/* ---------------- smart ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smart {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default = "default_smart_goal")]
    pub goal: SmartGoal,
    #[serde(default = "default_smart_learn", with = "humantime_serde")]
    pub learn: Duration,
    #[serde(default = "default_smart_sticky")]
    pub sticky: SmartSticky,
    #[serde(default = "default_true")]
    pub explain: bool,
}

impl Default for Smart {
    fn default() -> Self {
        Self {
            on: true,
            goal: SmartGoal::Balanced,
            learn: default_smart_learn(),
            sticky: SmartSticky::Site,
            explain: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmartGoal {
    Balanced,
    Speed,
    Stability,
    LowCost,
    Privacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmartSticky {
    Off,
    Site,
    Session,
}

/* ---------------- ui ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_dashboard")]
    pub dashboard: String,
    #[serde(default)]
    pub api: UiApi,
    #[serde(default)]
    pub cors: Vec<String>,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            on: true,
            secret: None,
            dashboard: default_dashboard(),
            api: UiApi::default(),
            cors: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiApi {
    #[serde(default = "default_true")]
    pub native: bool,
    #[serde(default = "default_true")]
    pub clash_compat: bool,
}

impl Default for UiApi {
    fn default() -> Self {
        Self {
            native: true,
            clash_compat: true,
        }
    }
}

/* ---------------- mesh ---------------- */

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mesh {
    #[serde(default)]
    pub tailscale: Option<MeshTailscale>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshTailscale {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default = "default_tailscale_mode")]
    pub mode: TailscaleMode,
    #[serde(default = "default_true")]
    pub keep_tailnet_direct: bool,
    #[serde(default)]
    pub expose_as_node: bool,
    #[serde(default)]
    pub userspace_proxy: Option<TailscaleUserspaceProxy>,
}

impl Default for MeshTailscale {
    fn default() -> Self {
        Self {
            on: true,
            mode: TailscaleMode::Auto,
            keep_tailnet_direct: true,
            expose_as_node: false,
            userspace_proxy: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TailscaleMode {
    Auto,
    Localapi,
    Userspace,
    Tsnet,
    Off,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailscaleUserspaceProxy {
    #[serde(default)]
    pub socks: Option<String>,
    #[serde(default)]
    pub http: Option<String>,
}

/* ---------------- defaults ---------------- */

fn default_localhost() -> String {
    "127.0.0.1".into()
}
fn default_reality_listen_host() -> String {
    "0.0.0.0".into()
}

fn default_wireguard_listen_host() -> String {
    "0.0.0.0".into()
}

fn default_wireguard_mtu() -> usize {
    1_420
}

fn default_wireguard_packet_queue() -> usize {
    1_024
}

fn default_wireguard_handshake_rate_limit() -> u64 {
    100
}
fn default_young_listen_host() -> String {
    "0.0.0.0".into()
}
fn default_young_path() -> String {
    "/assets".into()
}
fn default_young_clock_skew() -> Duration {
    Duration::from_secs(120)
}
fn default_young_idle_timeout() -> Duration {
    Duration::from_secs(5 * 60)
}
fn default_young_max_streams() -> u64 {
    1024
}
fn default_young_max_sessions() -> usize {
    4096
}
fn default_young_max_flows() -> usize {
    1024
}
fn default_young_decoy_status() -> u16 {
    404
}
fn default_young_decoy_body() -> String {
    "<!doctype html><html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>".into()
}
fn default_reality_inner_protocol() -> String {
    "vless".into()
}
fn default_reality_fingerprint() -> String {
    "chrome".into()
}
fn default_reality_spider_x() -> String {
    "/".into()
}
fn default_reality_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_reality_target_handshake_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_reality_idle_timeout() -> Duration {
    Duration::from_secs(5 * 60)
}
fn default_reality_max_client_hello_records() -> usize {
    16
}
fn default_reality_max_client_hello_record_payload() -> usize {
    16_640
}
fn default_reality_max_client_hello_bytes() -> usize {
    u16::MAX as usize
}
fn default_reality_max_client_hello_wire_bytes() -> usize {
    96 * 1024
}
fn default_reality_max_target_records() -> usize {
    12
}
fn default_reality_max_target_handshake_bytes() -> usize {
    96 * 1024
}
fn default_reality_application_buffer_bytes() -> usize {
    256 * 1024
}
fn default_reality_max_concurrent_handshakes() -> usize {
    1024
}
fn default_true() -> bool {
    true
}
fn default_xhttp_listen_alpn() -> Vec<XhttpListenAlpn> {
    // Xray TLS defaults to h2 before http/1.1. rustls follows server
    // preference, so reversing this order silently downgrades Xray's default
    // H2 client to H1 and makes its H2 transport fail after negotiation.
    vec![XhttpListenAlpn::H2, XhttpListenAlpn::Http1]
}
fn default_xhttp_accept_queue() -> usize {
    256
}
fn default_xhttp_max_active_relays() -> usize {
    256
}
fn default_xhttp_max_active_connections() -> usize {
    1024
}
fn default_xhttp_max_concurrent_streams() -> u32 {
    128
}
fn default_xhttp_max_active_http_streams() -> usize {
    1024
}
fn default_xhttp_http_idle_timeout() -> Duration {
    Duration::from_secs(90)
}
fn default_log_file_path() -> String {
    "data/logs/wuthercore.log".into()
}
fn default_feed_every() -> Duration {
    Duration::from_secs(12 * 3600)
}
fn default_feed_via() -> String {
    "direct".into()
}
fn default_choose() -> ChooseStrategy {
    ChooseStrategy::Smart
}
fn default_route_preset() -> String {
    "cn_smart".into()
}
fn default_route_final() -> String {
    "main".into()
}
fn default_resolver_mode() -> ResolverMode {
    ResolverMode::Normal
}
fn default_fake() -> FakeMode {
    FakeMode::Auto
}
fn default_cache() -> Duration {
    Duration::from_secs(24 * 3600)
}
fn default_ipv6_timeout() -> Duration {
    Duration::from_millis(100)
}
fn default_resolver_servers() -> BTreeMap<String, ResolverServer> {
    // 与 mihomo 一致：IP host 直连，SNI 默认 = host（rustls IpAddress + IP-SAN cert
    // 验证）；也支持写域名（构造时 system DNS bootstrap 一次）。
    BTreeMap::from([
        (
            "ali".into(),
            ResolverServer::from("https://223.5.5.5/dns-query"),
        ),
        (
            "cloudflare".into(),
            ResolverServer::from("https://1.1.1.1/dns-query"),
        ),
    ])
}
fn default_capture_method() -> CaptureMethod {
    CaptureMethod::Auto
}
fn default_capture_traffic() -> CaptureTraffic {
    CaptureTraffic::System
}
fn default_capture_resolver() -> CaptureResolver {
    CaptureResolver::Hijack
}
fn default_capture_stack() -> CaptureStack {
    CaptureStack::Mixed
}
fn default_iproute2_table() -> u32 {
    2022
}
fn default_iproute2_rule() -> u32 {
    9000
}
fn default_udp_timeout() -> Duration {
    Duration::from_secs(5 * 60)
}
fn default_smart_goal() -> SmartGoal {
    SmartGoal::Balanced
}
fn default_smart_learn() -> Duration {
    Duration::from_secs(14 * 24 * 3600)
}
fn default_smart_sticky() -> SmartSticky {
    SmartSticky::Site
}
fn default_dashboard() -> String {
    "auto".into()
}
fn default_tailscale_mode() -> TailscaleMode {
    TailscaleMode::Auto
}

#[cfg(test)]
mod xhttp_config_tests {
    use super::*;

    const FULL_XHTTP_YAML: &str = r#"
host: cdn.example.com
path: /split
mode: packet-up
headers:
  User-Agent: Wuther
xPaddingBytes: 100-1000
xPaddingObfsMode: true
xPaddingKey: x_padding
xPaddingHeader: X-Padding
xPaddingPlacement: queryInHeader
xPaddingMethod: tokenish
uplinkHTTPMethod: POST
sessionIDPlacement: header
sessionIDKey: X-Session
sessionIDTable: Base62
sessionIDLength: 16-24
seqPlacement: query
seqKey: x_seq
uplinkDataPlacement: header
uplinkDataKey: X-Data
uplinkChunkSize: 3000-4000
noGRPCHeader: true
noSSEHeader: true
scMaxEachPostBytes: 1000000
scMinPostsIntervalMs: 30-60
scMaxBufferedPosts: 30
scStreamUpServerSecs: 20-80
serverMaxHeaderBytes: 16384
xmux:
  maxConcurrency: 0
  maxConnections: 4-8
  cMaxReuseTimes: 16
  hMaxRequestTimes: 600-900
  hMaxReusableSecs: 1800-3000
  hKeepAlivePeriod: -1
downloadSettings:
  address: download.example.com
  host: download-cdn.example.com
  port: 443
  network: xhttp
  security: tls
  tlsSettings:
    serverName: download.example.com
    allowInsecure: false
    alpn: [h2, h3]
  alpn: [h2, h3]
  sockopt:
    mark: 123
    tfo: true
    tcpMptcp: false
    domainStrategy: UseIP
  xhttpSettings:
    path: /download
    mode: packet-up
"#;

    #[test]
    fn xhttp_yaml_and_json_round_trip_all_fields() {
        let config: XhttpConfig = serde_yaml::from_str(FULL_XHTTP_YAML).unwrap();
        config.validate().unwrap();
        assert_eq!(config.x_padding_bytes, Some(XhttpRange::new(100, 1000)));
        assert_eq!(
            config
                .xmux
                .as_ref()
                .and_then(|xmux| xmux.h_keep_alive_period),
            Some(-1)
        );
        assert_eq!(
            config
                .download_settings
                .as_ref()
                .and_then(|settings| settings.port),
            Some(443)
        );

        let yaml = serde_yaml::to_string(&config).unwrap();
        let from_yaml: XhttpConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(from_yaml, config);

        let json = serde_json::to_string(&config).unwrap();
        let from_json: XhttpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, config);
        assert!(json.contains("\"noGRPCHeader\":true"));
        assert!(json.contains("\"sessionIDLength\":\"16-24\""));
    }

    #[test]
    fn xhttp_accepts_kebab_and_legacy_aliases() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
x-padding-bytes: 256
no-grpc-header: true
no_sse_header: true
uplink-http-method: POST
session-placement: cookie
session-key: sid
session-id-table: Base62
session-id-length: 16
seq_placement: header
seq_key: X-Seq
uplink-data-placement: body
sc-max-each-post-bytes: 1048576
server-max-header-bytes: 8192
xmux:
  max-connections: 4-6
  h_keep_alive_period: -1
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.x_padding_bytes, Some(XhttpRange::new(256, 256)));
        assert_eq!(config.session_id_placement.as_deref(), Some("cookie"));
        assert_eq!(
            config.xmux.as_ref().and_then(|xmux| xmux.max_connections),
            Some(XhttpRange::new(4, 6))
        );
    }

    #[test]
    fn xhttp_rejects_unknown_nested_fields_and_bad_ranges() {
        let unknown = serde_yaml::from_str::<XhttpConfig>(
            r#"
xmux:
  maxConnections: 4
  typoLimit: 8
"#,
        );
        assert!(unknown.is_err());

        for value in ["-1", "10-1", "1-2-3", "2147483648"] {
            let yaml = format!("xPaddingBytes: {value:?}");
            assert!(
                serde_yaml::from_str::<XhttpConfig>(&yaml).is_err(),
                "{value} should fail"
            );
        }
    }

    #[test]
    fn xhttp_download_stream_config_registers_every_strict_nested_family() {
        let json = r#"
        {
          "address": "download.example.com",
          "port": 443,
          "method": "xhttp",
          "network": "tcp",
          "security": "tls",
          "tlsSettings": {
            "certificates": [{
              "certificateFile": "cert.pem",
              "certificate": ["CERT"],
              "keyFile": "key.pem",
              "key": ["KEY"],
              "usage": "verify",
              "ocspStapling": 3600,
              "oneTimeLoading": true,
              "buildChain": true
            }],
            "serverName": "download.example.com",
            "allowInsecure": false,
            "alpn": ["h2"],
            "enableSessionResumption": true,
            "disableSystemRoot": true,
            "minVersion": "1.2",
            "maxVersion": "1.3",
            "cipherSuites": "TLS_AES_128_GCM_SHA256",
            "fingerprint": "chrome",
            "rejectUnknownSni": true,
            "curvePreferences": ["X25519"],
            "masterKeyLog": "keys.log",
            "pinnedPeerCertSha256": "00",
            "verifyPeerCertByName": "peer.example.com",
            "echServerKeys": "AA==",
            "echConfigList": "AA==",
            "echSockopt": {"mark": 1}
          },
          "realitySettings": {
            "masterKeyLog": "reality.keys",
            "show": true,
            "target": 443,
            "dest": "origin.example.com:443",
            "type": "tcp",
            "xver": 1,
            "serverNames": ["origin.example.com"],
            "privateKey": "private",
            "minClientVer": "1.0.0",
            "maxClientVer": "2.0.0",
            "maxTimeDiff": 1000,
            "shortIds": ["01234567"],
            "mldsa65Seed": "seed",
            "limitFallbackUpload": {
              "afterBytes": 1,
              "bytesPerSec": 2,
              "burstBytesPerSec": 3
            },
            "limitFallbackDownload": {
              "afterBytes": 4,
              "bytesPerSec": 5,
              "burstBytesPerSec": 6
            },
            "fingerprint": "chrome",
            "serverName": "origin.example.com",
            "password": "password",
            "publicKey": "public",
            "shortId": "01234567",
            "mldsa65Verify": "verify",
            "spiderX": "/index"
          },
          "sockopt": {
            "mark": 1,
            "tcpFastOpen": 256,
            "tproxy": "redirect",
            "acceptProxyProtocol": true,
            "domainStrategy": "ForceIPv6v4",
            "dialerProxy": "direct",
            "tcpKeepAliveInterval": 30,
            "tcpKeepAliveIdle": 60,
            "tcpCongestion": "bbr",
            "tcpWindowClamp": 4096,
            "tcpMaxSeg": 1400,
            "penetrate": true,
            "tcpUserTimeout": 1000,
            "v6only": true,
            "interface": "eth0",
            "tcpMptcp": true,
            "customSockopt": [{
              "system": "linux",
              "network": "tcp",
              "level": "SOL_SOCKET",
              "opt": "SO_MARK",
              "value": "1",
              "type": "int"
            }],
            "addressPortStrategy": "srvPortAndAddress",
            "happyEyeballs": {
              "prioritizeIPv6": true,
              "tryDelayMs": 250,
              "interleave": 2,
              "maxConcurrentTry": 8
            },
            "trustedXForwardedFor": ["127.0.0.1"]
          },
          "finalmask": {
            "tcp": [
              {
                "type": "header-custom",
                "settings": {
                  "clients": [[{
                    "delay": "1-2",
                    "randRange": "0-255",
                    "capture": "hello",
                    "type": "str",
                    "packet": "hello"
                  }]],
                  "servers": [[{"rand": 4}]],
                  "errors": [[{"reuse": "hello"}]]
                }
              },
              {
                "type": "fragment",
                "settings": {
                  "packets": "1-2",
                  "length": "10-20",
                  "delay": "1-2",
                  "lengths": [8, "16-32"],
                  "delays": [0, "1-2"],
                  "maxSplit": "2-4"
                }
              },
              {
                "type": "sudoku",
                "settings": {
                  "password": "secret",
                  "ascii": "abc",
                  "customTable": "table",
                  "customTables": ["one", "two"],
                  "paddingMin": 1,
                  "paddingMax": 2
                }
              },
              {
                "type": "xmc",
                "settings": {
                  "hostname": "mc.example.com",
                  "usernames": ["Dream"],
                  "password": "secret"
                }
              }
            ],
            "udp": [
              {
                "type": "header-custom",
                "settings": {
                  "mode": "standalone",
                  "client": [{"type": "array", "packet": [1, 2]}],
                  "server": [{
                    "transform": {
                      "op": "concat",
                      "args": [
                        {"type": "str", "bytes": "prefix"},
                        {"u64": 1},
                        {"reuse": "saved"},
                        {"metadata": "payload"},
                        {"transform": {"op": "identity", "args": [{"metadata": "x"}]}}
                      ]
                    }
                  }]
                }
              },
              {"type": "mkcp-legacy", "settings": {"header": "dns", "value": "dns.example"}},
              {
                "type": "noise",
                "settings": {
                  "reset": "1-2",
                  "noise": [{
                    "rand": "2-4",
                    "randRange": "0-255",
                    "type": "hex",
                    "packet": "deadbeef",
                    "delay": "1-3"
                  }]
                }
              },
              {"type": "salamander", "settings": {"password": "secret", "packetSize": "1200-1400"}},
              {"type": "sudoku", "settings": {"password": "secret"}},
              {
                "type": "xdns",
                "settings": {
                  "domain": ["one.example", "two.example"],
                  "domains": ["dns.example"],
                  "resolvers": ["8.8.8.8+udp://53"]
                }
              },
              {"type": "xicmp", "settings": {"dgram": true, "ips": ["127.0.0.1"]}},
              {
                "type": "realm",
                "settings": {
                  "url": "realm://token@realm.example/id",
                  "stunServers": ["stun.example:3478"],
                  "tlsConfig": {"serverName": "realm.example"}
                }
              }
            ],
            "quicParams": {
              "congestion": "bbr",
              "debug": true,
              "bbrProfile": "default",
              "brutalUp": "100mbps",
              "brutalDown": "200mbps",
              "udpHop": {"ports": "20000-30000,443", "interval": "10-20"},
              "initStreamReceiveWindow": 1,
              "maxStreamReceiveWindow": 2,
              "initConnectionReceiveWindow": 3,
              "maxConnectionReceiveWindow": 4,
              "maxIdleTimeout": 5,
              "keepAlivePeriod": 6,
              "disablePathMTUDiscovery": true,
              "maxIncomingStreams": 7
            }
          },
          "xhttpSettings": {"path": "/download", "mode": "packet-up"}
        }"#;

        let settings: XhttpDownloadSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.method.as_deref(), Some("xhttp"));
        assert_eq!(
            settings
                .tls_settings
                .as_ref()
                .map(|tls| tls.certificates.len()),
            Some(1)
        );
        assert_eq!(
            settings
                .socket_settings
                .as_ref()
                .map(|socket| socket.custom_sockopt.len()),
            Some(1)
        );
        let final_mask = settings.final_mask.as_ref().unwrap();
        assert_eq!(final_mask.tcp.len(), 4);
        assert_eq!(final_mask.udp.len(), 8);
        assert!(final_mask.quic_params.is_some());

        let serialized = serde_json::to_string(&settings).unwrap();
        let round_trip: XhttpDownloadSettings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(round_trip, settings);
    }

    #[test]
    fn xhttp_download_nested_models_reject_unknown_fields() {
        for json in [
            r#"{"tlsSettings":{"serverNmae":"example.com"}}"#,
            r#"{"tlsSettings":{"certificates":[{"certificateTypo":[]}]}}"#,
            r#"{"realitySettings":{"publicKye":"value"}}"#,
            r#"{"realitySettings":{"limitFallbackUpload":{"afterBytez":1}}}"#,
            r#"{"sockopt":{"tcpFastOepn":true}}"#,
            r#"{"sockopt":{"happyEyeballs":{"tryDelayMss":1}}}"#,
            r#"{"sockopt":{"customSockopt":[{"levle":"1"}]}}"#,
            r#"{"finalmask":{"unknown":[]}}"#,
            r#"{"finalmask":{"tcp":[{"type":"fragment","settings":{"lenght":1}}]}}"#,
            r#"{"finalmask":{"udp":[{"type":"noise","settings":{"rest":1}}]}}"#,
            r#"{"finalmask":{"quicParams":{"maxIdleTimout":1}}}"#,
        ] {
            assert!(
                serde_json::from_str::<XhttpDownloadSettings>(json).is_err(),
                "unknown nested field should fail: {json}"
            );
        }
    }

    #[test]
    fn xhttp_download_method_takes_precedence_over_network() {
        let accepted: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  method: xhttp
  network: tcp
  xhttpSettings:
    mode: packet-up
"#,
        )
        .unwrap();
        accepted.validate().unwrap();

        let rejected: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  method: tcp
  network: xhttp
  xhttpSettings:
    mode: packet-up
"#,
        )
        .unwrap();
        assert!(rejected.validate().unwrap_err().contains("method/network"));
    }

    #[test]
    fn xhttp_download_empty_security_is_none_and_removed_allow_insecure_fails_for_tls() {
        let empty_security: XhttpDownloadSettings = serde_json::from_str(
            r#"{
                "address":"download.example",
                "port":443,
                "security":"",
                "tlsSettings":{"allowInsecure":true},
                "xhttpSettings":{"mode":"packet-up"}
            }"#,
        )
        .unwrap();
        empty_security.validate().unwrap();

        for allow_insecure in [None, Some(false)] {
            let mut tls = empty_security.clone();
            tls.security = Some("tls".into());
            tls.tls_settings.as_mut().unwrap().allow_insecure = allow_insecure;
            tls.validate().unwrap();
        }

        let mut removed = empty_security;
        removed.security = Some("tls".into());
        let error = removed.validate().unwrap_err();
        assert!(error.contains("allowInsecure=true 已被 Xray 移除"));
    }

    #[test]
    fn xhttp_download_transport_rejects_non_xhttp_kind_and_grpc_service() {
        let invalid_kind: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  transport:
    kind: grpc
    xhttp:
      mode: packet-up
"#,
        )
        .unwrap();
        assert!(
            invalid_kind
                .validate()
                .unwrap_err()
                .contains("transport.kind")
        );

        let grpc_service: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  transport:
    kind: xhttp
    service: download-service
    xhttp:
      mode: packet-up
"#,
        )
        .unwrap();
        assert!(
            grpc_service
                .validate()
                .unwrap_err()
                .contains("transport.service")
        );
    }

    #[test]
    fn xhttp_download_accepts_equivalent_compatibility_aliases() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  alpn: [h2]
  tlsSettings:
    alpn: [h2]
  transport:
    kind: xhttp
    host: cdn.example.com
    path: /download
    xhttp:
      host: cdn.example.com
      path: /download
      mode: packet-up
  xhttpSettings:
    mode: packet-up
"#,
        )
        .unwrap();

        config.validate().unwrap();
    }

    #[test]
    fn xhttp_download_rejects_conflicting_xhttp_aliases() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  transport:
    kind: xhttp
    xhttp:
      mode: stream-up
  xhttpSettings:
    mode: packet-up
"#,
        )
        .unwrap();

        assert!(config.validate().unwrap_err().contains("必须语义等价"));
    }

    #[test]
    fn xhttp_download_rejects_conflicting_generic_host_or_path() {
        for (generic, nested, expected_field) in [
            (
                "host: generic.example.com",
                "host: nested.example.com",
                "transport.host",
            ),
            ("path: /generic", "path: /nested", "transport.path"),
        ] {
            let yaml = format!(
                r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  transport:
    kind: xhttp
    {generic}
    xhttp:
      {nested}
      mode: packet-up
"#
            );
            let config: XhttpConfig = serde_yaml::from_str(&yaml).unwrap();
            assert!(
                config.validate().unwrap_err().contains(expected_field),
                "{expected_field} conflict must fail"
            );
        }
    }

    #[test]
    fn xhttp_download_rejects_conflicting_top_level_and_tls_alpn() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
mode: packet-up
downloadSettings:
  address: download.example.com
  port: 443
  alpn: [h2, http/1.1]
  tlsSettings:
    alpn: [h2]
  xhttpSettings:
    mode: packet-up
"#,
        )
        .unwrap();

        assert!(config.validate().unwrap_err().contains("tlsSettings.alpn"));
    }

    #[test]
    fn xhttp_session_id_table_matches_xray_ascii_and_room_validation() {
        for (table, length, expected_error) in [
            ("HEX", XhttpRange::new(1, 6), "31-bit"),
            ("字母", XhttpRange::new(8, 12), "ASCII"),
        ] {
            let config = XhttpConfig {
                session_id_table: Some(table.into()),
                session_id_length: Some(length),
                ..Default::default()
            };
            let error = config.validate().unwrap_err();
            assert!(
                error.contains(expected_error),
                "unexpected error for {table}: {error}"
            );
        }

        // Xray counts table bytes exactly as configured: duplicate bytes and
        // URL-reserved ASCII are accepted and participate in roomSize.
        let xray_compatible_custom = XhttpConfig {
            session_id_table: Some("aaaaaaaaaaaaaaaa/?#[]@!$&'()*+,;=".into()),
            session_id_length: Some(XhttpRange::new(8, 12)),
            ..Default::default()
        };
        xray_compatible_custom.validate().unwrap();

        let empty_table_uses_uuid_even_without_length = XhttpConfig {
            session_id_table: Some(String::new()),
            ..Default::default()
        };
        empty_table_uses_uuid_even_without_length
            .validate()
            .unwrap();

        let summed_binary_range = XhttpConfig {
            session_id_table: Some("ab".into()),
            session_id_length: Some(XhttpRange::new(30, 32)),
            ..Default::default()
        };
        summed_binary_range.validate().unwrap();

        let insufficient_binary_range = XhttpConfig {
            session_id_table: Some("ab".into()),
            session_id_length: Some(XhttpRange::new(29, 30)),
            ..Default::default()
        };
        assert!(
            insufficient_binary_range
                .validate()
                .unwrap_err()
                .contains("31-bit")
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
            let config = XhttpConfig {
                session_id_table: Some(table.into()),
                session_id_length: Some(XhttpRange::new(shortest, shortest + 4)),
                ..Default::default()
            };
            config
                .validate()
                .unwrap_or_else(|error| panic!("{table} should be safe: {error}"));
        }
    }

    #[test]
    fn xhttp_sc_max_buffered_posts_enforces_business_limit() {
        let at_limit = XhttpConfig {
            sc_max_buffered_posts: Some(XHTTP_MAX_BUFFERED_POSTS),
            ..Default::default()
        };
        at_limit.validate().unwrap();

        let above_limit = XhttpConfig {
            sc_max_buffered_posts: Some(XHTTP_MAX_BUFFERED_POSTS + 1),
            ..Default::default()
        };
        assert!(
            above_limit
                .validate()
                .unwrap_err()
                .contains("scMaxBufferedPosts 不能大于 1000000")
        );
    }

    #[test]
    fn xhttp_padding_enforces_allocation_limit() {
        let at_limit = XhttpConfig {
            x_padding_bytes: Some(XhttpRange::new(
                XHTTP_MAX_PADDING_BYTES,
                XHTTP_MAX_PADDING_BYTES,
            )),
            ..Default::default()
        };
        at_limit.validate().unwrap();

        let above_limit = XhttpConfig {
            x_padding_bytes: Some(XhttpRange::new(
                XHTTP_MAX_PADDING_BYTES,
                XHTTP_MAX_PADDING_BYTES + 1,
            )),
            ..Default::default()
        };
        assert!(
            above_limit
                .validate()
                .unwrap_err()
                .contains("xPaddingBytes 不能大于 1048576")
        );
    }

    #[test]
    fn xhttp_headers_reject_managed_and_malformed_values_at_config_time() {
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
            let config = XhttpConfig {
                headers: Some(BTreeMap::from([(name.into(), "value".into())])),
                ..Default::default()
            };
            let error = config.validate().unwrap_err();
            assert!(
                error.contains("Host/framing/hop-by-hop"),
                "managed header {name} was not rejected correctly: {error}"
            );
        }

        for (name, value) in [
            ("bad name", "value"),
            ("X-Test", "ok\r\nInjected: yes"),
            ("X-Test", "bad\u{7f}value"),
        ] {
            let config = XhttpConfig {
                headers: Some(BTreeMap::from([(name.into(), value.into())])),
                ..Default::default()
            };
            assert!(
                config.validate().is_err(),
                "malformed header should fail: {name:?}={value:?}"
            );
        }

        let safe = XhttpConfig {
            headers: Some(BTreeMap::from([(
                "X-Custom_~".into(),
                "visible\tvalue".into(),
            )])),
            ..Default::default()
        };
        safe.validate().unwrap();
    }

    #[test]
    fn xhttp_semantic_conflicts_fail_validation() {
        let both_limits: XhttpConfig = serde_yaml::from_str(
            r#"
xmux:
  maxConcurrency: 2
  maxConnections: 4
"#,
        )
        .unwrap();
        assert!(both_limits.validate().unwrap_err().contains("不能同时启用"));

        let bad_download: XhttpConfig = serde_yaml::from_str(
            r#"
mode: stream-one
downloadSettings:
  xhttpSettings:
    path: /down
"#,
        )
        .unwrap();
        assert!(bad_download.validate().unwrap_err().contains("stream-one"));

        let partial_zero_padding: XhttpConfig =
            serde_yaml::from_str("xPaddingBytes: 0-1000").unwrap();
        assert!(
            partial_zero_padding
                .validate()
                .unwrap_err()
                .contains("xPaddingBytes")
        );
        let exact_zero_padding: XhttpConfig = serde_yaml::from_str("xPaddingBytes: 0").unwrap();
        exact_zero_padding.validate().unwrap();

        let sc_zero_lower_bound: XhttpConfig =
            serde_yaml::from_str("scMaxEachPostBytes: 0-1000000").unwrap();
        sc_zero_lower_bound.validate().unwrap();

        let mixed_case_host: XhttpConfig =
            serde_yaml::from_str("headers: {hOsT: forbidden.example}").unwrap();
        assert!(mixed_case_host.validate().unwrap_err().contains("Host"));

        for yaml in [
            "mode: stream-up\nuplinkDataPlacement: header",
            "mode: stream-up\nuplinkHTTPMethod: GET",
        ] {
            let config: XhttpConfig = serde_yaml::from_str(yaml).unwrap();
            assert!(
                config.validate().unwrap_err().contains("packet-up"),
                "config should be packet-up only: {yaml}"
            );
        }
    }

    #[test]
    fn xhttp_extra_is_typed_and_only_outer_routing_fields_override() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
host: outer.example
path: /outer
mode: packet-up
headers:
  X-Ignored: outer
extra:
  host: inner.example
  path: /inner
  mode: stream-up
  headers:
    X-Source: extra
  noSSEHeader: true
"#,
        )
        .unwrap();
        let resolved = config.resolved().unwrap();
        assert_eq!(resolved.host.as_deref(), Some("outer.example"));
        assert_eq!(resolved.path.as_deref(), Some("/outer"));
        assert_eq!(resolved.mode.as_deref(), Some("packet-up"));
        assert_eq!(
            resolved
                .headers
                .as_ref()
                .and_then(|headers| headers.get("X-Source"))
                .map(String::as_str),
            Some("extra")
        );
        assert_eq!(resolved.no_sse_header, Some(true));
        assert!(resolved.extra.is_none());
    }

    #[test]
    fn xhttp_nested_extra_stops_after_the_first_level() {
        let config: XhttpConfig = serde_yaml::from_str(
            r#"
host: outer.example
path: /outer
mode: packet-up
extra:
  headers:
    X-Level: first
  extra:
    headers:
      X-Level: second
"#,
        )
        .unwrap();
        let resolved = config.resolved().unwrap();
        assert_eq!(
            resolved
                .headers
                .as_ref()
                .and_then(|headers| headers.get("X-Level"))
                .map(String::as_str),
            Some("first")
        );
        assert_eq!(resolved.host.as_deref(), Some("outer.example"));
        assert_eq!(resolved.path.as_deref(), Some("/outer"));
        assert_eq!(resolved.mode.as_deref(), Some("packet-up"));
        assert!(resolved.extra.is_none());
    }

    #[test]
    fn xhttp_listener_accepts_single_or_array_and_json_uses_wire_alpn_names() {
        let single: Listen = serde_yaml::from_str(
            r#"
xhttp:
  address: 127.0.0.1
  port: 8443
  tls:
    cert: cert.pem
    key: key.pem
  alpn: [h1, h2]
  tag: edge
  accept-queue: 512
  allowUnauthenticatedNonLoopback: true
  max_active_relays: 1024
  maxActiveConnections: 2048
  maxConcurrentStreams: 96
  max_active_http_streams: 4096
  http_idle_timeout: 45s
  corsOrigins:
    - https://console.example
  settings:
    path: /split
    mode: packet-up
    xPaddingBytes: 0
"#,
        )
        .unwrap();
        let XhttpListenSet::One(listener) = single.xhttp.as_ref().unwrap() else {
            panic!("single listen.xhttp must remain a single object");
        };
        assert_eq!(listener.alpn, [XhttpListenAlpn::Http1, XhttpListenAlpn::H2]);
        assert!(listener.allow_unauthenticated_non_loopback);
        assert_eq!(listener.max_active_relays, 1024);
        assert_eq!(listener.max_active_connections, 2048);
        assert_eq!(listener.max_concurrent_streams, 96);
        assert_eq!(listener.max_active_http_streams, 4096);
        assert_eq!(listener.http_idle_timeout, Duration::from_secs(45));
        assert_eq!(
            listener.cors_origins,
            Some(vec!["https://console.example".into()])
        );
        assert_eq!(
            listener.settings.x_padding_bytes,
            Some(XhttpRange::new(0, 0))
        );

        let json = serde_json::to_string(&single).unwrap();
        assert!(json.contains("\"http/1.1\""));
        assert!(!json.contains("\"h1\""));
        assert!(json.contains("\"allow-unauthenticated-non-loopback\":true"));
        assert!(json.contains("\"max-active-relays\":1024"));
        assert!(json.contains("\"max-active-connections\":2048"));
        assert!(json.contains("\"max-concurrent-streams\":96"));
        assert!(json.contains("\"max-active-http-streams\":4096"));
        assert!(json.contains("\"http-idle-timeout\":\"45s\""));
        assert!(json.contains("\"cors-origins\":[\"https://console.example\"]"));
        assert!(!json.contains("\"allowUnauthenticatedNonLoopback\""));
        assert!(!json.contains("\"max_active_relays\""));
        assert!(!json.contains("\"maxActiveConnections\""));
        assert!(!json.contains("\"maxConcurrentStreams\""));
        assert!(!json.contains("\"max_active_http_streams\""));
        assert!(!json.contains("\"http_idle_timeout\""));
        assert!(!json.contains("\"corsOrigins\""));
        let from_json: Listen = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json.xhttp, single.xhttp);

        let json_aliases: Listen = serde_json::from_str(
            r#"{
                "xhttp": {
                    "address": "127.0.0.1",
                    "port": 8080,
                    "cleartext": true,
                    "max_active_connections": 32,
                    "max_concurrent_streams": 64,
                    "maxActiveHttpStreams": 512,
                    "httpIdleTimeout": "12s"
                }
            }"#,
        )
        .unwrap();
        let Some(XhttpListenSet::One(json_aliases)) = json_aliases.xhttp else {
            panic!("JSON aliases must deserialize to one XHTTP listener");
        };
        assert_eq!(json_aliases.max_active_connections, 32);
        assert_eq!(json_aliases.max_concurrent_streams, 64);
        assert_eq!(json_aliases.max_active_http_streams, 512);
        assert_eq!(json_aliases.http_idle_timeout, Duration::from_secs(12));

        let many: Listen = serde_yaml::from_str(
            r#"
xhttp:
  - {address: 127.0.0.1, port: 8080, cleartext: true}
  - address: "::"
    port: 8443
    tls: {cert: cert.pem, key: key.pem}
    alpn: [h3]
"#,
        )
        .unwrap();
        let Some(XhttpListenSet::Many(listeners)) = many.xhttp else {
            panic!("array listen.xhttp must remain an array");
        };
        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners[0].alpn,
            [XhttpListenAlpn::H2, XhttpListenAlpn::Http1]
        );
        assert_eq!(listeners[0].accept_queue, 256);
        assert!(!listeners[0].allow_unauthenticated_non_loopback);
        assert_eq!(listeners[0].max_active_relays, 256);
        assert_eq!(listeners[0].max_active_connections, 1024);
        assert_eq!(listeners[0].max_concurrent_streams, 128);
        assert_eq!(listeners[0].max_active_http_streams, 1024);
        assert_eq!(listeners[0].http_idle_timeout, Duration::from_secs(90));
        assert_eq!(listeners[0].cors_origins, None);
    }

    #[test]
    fn xhttp_listener_security_fields_roundtrip_through_yaml_aliases() {
        let listen: Listen = serde_yaml::from_str(
            r#"
xhttp:
  address: 127.0.0.1
  port: 8080
  cleartext: true
  allow_unauthenticated_non_loopback: true
  maxActiveRelays: 64
  max_active_connections: 128
  max_concurrent_streams: 32
  maxActiveHttpStreams: 256
  httpIdleTimeout: 30s
  cors_origins:
    - " https://one.example "
    - https://two.example:8443
"#,
        )
        .unwrap();
        let yaml = serde_yaml::to_string(&listen).unwrap();
        assert!(yaml.contains("allow-unauthenticated-non-loopback: true"));
        assert!(yaml.contains("max-active-relays: 64"));
        assert!(yaml.contains("max-active-connections: 128"));
        assert!(yaml.contains("max-concurrent-streams: 32"));
        assert!(yaml.contains("max-active-http-streams: 256"));
        assert!(yaml.contains("http-idle-timeout: 30s"));
        assert!(yaml.contains("cors-origins:"));
        assert!(!yaml.contains("allow_unauthenticated_non_loopback"));
        assert!(!yaml.contains("maxActiveRelays"));
        assert!(!yaml.contains("max_active_connections"));
        assert!(!yaml.contains("max_concurrent_streams"));
        assert!(!yaml.contains("maxActiveHttpStreams"));
        assert!(!yaml.contains("httpIdleTimeout"));
        assert!(!yaml.contains("cors_origins"));
        let roundtrip: Listen = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(roundtrip.xhttp, listen.xhttp);
    }

    #[test]
    fn xhttp_listener_distinguishes_default_and_explicitly_disabled_cors() {
        let omitted: Listen = serde_yaml::from_str(
            r#"
xhttp:
  address: 127.0.0.1
  port: 8080
  cleartext: true
"#,
        )
        .unwrap();
        let explicit_empty: Listen = serde_yaml::from_str(
            r#"
xhttp:
  address: 127.0.0.1
  port: 8080
  cleartext: true
  cors-origins: []
"#,
        )
        .unwrap();

        let Some(XhttpListenSet::One(omitted)) = omitted.xhttp else {
            panic!("omitted CORS listener must deserialize");
        };
        let Some(XhttpListenSet::One(explicit_empty)) = explicit_empty.xhttp else {
            panic!("explicitly empty CORS listener must deserialize");
        };
        assert_eq!(omitted.cors_origins, None);
        assert_eq!(explicit_empty.cors_origins, Some(Vec::new()));

        let omitted_json = serde_json::to_value(&omitted).unwrap();
        assert!(omitted_json.get("cors-origins").is_none());
        let explicit_json = serde_json::to_value(&explicit_empty).unwrap();
        assert_eq!(explicit_json["cors-origins"], serde_json::json!([]));
    }

    #[test]
    fn xhttp_listener_rejects_unknown_and_unimplemented_protocol_fields() {
        assert!(
            serde_yaml::from_str::<Listen>(
                r#"
xhttp:
  address: 127.0.0.1
  port: 8080
  cleartext: true
  typo-field: true
"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Listen>(
                r#"{"xhttp":{"address":"127.0.0.1","port":8080,"cleartext":true,"inner-protocol":"vless"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Listen>(
                r#"{"xhttp":{"address":"127.0.0.1","port":8080,"cleartext":true,"protocol":"trojan"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn xhttp_tls_advanced_fields_and_listener_aliases_are_typed() {
        let listen: Listen = serde_yaml::from_str(
            r#"
xhttp:
  address: 127.0.0.1
  port: 8443
  alpn: [h2]
  tls:
    certificates:
      - certificate: [CERT]
        key: [KEY]
        usage: encipherment
      - certificateFile: ca.pem
        usage: verify
    require_client_certificate: true
    server_name: service.example
    enable-session-resumption: true
    disable_system_root: true
    min-version: "1.2"
    max_version: "1.3"
    cipher-suites: TLS_AES_128_GCM_SHA256
    curve_preferences: X25519,curvep256
    master-key-log: none
    rejectUnknownSNI: true
"#,
        )
        .unwrap();
        let Some(XhttpListenSet::One(listener)) = listen.xhttp else {
            panic!("advanced listener TLS must deserialize");
        };
        let tls = listener.tls.expect("listener TLS");
        assert_eq!(tls.require_client_certificate, Some(true));
        assert_eq!(tls.settings.server_name.as_deref(), Some("service.example"));
        assert_eq!(tls.settings.min_version.as_deref(), Some("1.2"));
        assert_eq!(tls.settings.max_version.as_deref(), Some("1.3"));
        assert_eq!(
            tls.settings.curve_preferences.as_deref(),
            Some(["X25519".to_owned(), "curvep256".to_owned()].as_slice())
        );
        tls.settings.validate().unwrap();

        let canonical = serde_json::to_value(&tls).unwrap();
        assert_eq!(canonical["requireClientCertificate"], true);
        assert_eq!(canonical["serverName"], "service.example");
        assert_eq!(canonical["enableSessionResumption"], true);
        assert_eq!(canonical["disableSystemRoot"], true);
        assert_eq!(
            canonical["curvePreferences"],
            serde_json::json!(["X25519", "curvep256"])
        );
    }

    #[test]
    fn xhttp_tls_validation_rejects_ambiguous_or_unexecutable_values() {
        fn error(settings: XhttpDownloadTlsSettings) -> String {
            settings.validate().expect_err("TLS settings must fail")
        }

        let cases = [
            (
                XhttpDownloadTlsSettings {
                    min_version: Some("1.3".into()),
                    max_version: Some("1.2".into()),
                    ..Default::default()
                },
                "minVersion 不能高于",
            ),
            (
                XhttpDownloadTlsSettings {
                    cipher_suites: Some("TLS_AES_128_GCM_SHA256:TYPO".into()),
                    ..Default::default()
                },
                "未知或空的密码套件",
            ),
            (
                XhttpDownloadTlsSettings {
                    curve_preferences: Some(vec!["X25519".into(), "x25519".into()]),
                    ..Default::default()
                },
                "重复曲线",
            ),
            (
                XhttpDownloadTlsSettings {
                    certificates: vec![XhttpDownloadTlsCertificate {
                        certificate_file: Some("cert.pem".into()),
                        certificate: Some(vec!["CERT".into()]),
                        key_file: Some("key.pem".into()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                "certificateFile 与 certificate 不能同时设置",
            ),
            (
                XhttpDownloadTlsSettings {
                    certificates: vec![XhttpDownloadTlsCertificate {
                        certificate: Some(vec!["CA".into()]),
                        key: Some(vec!["KEY".into()]),
                        usage: Some(XhttpTlsCertificateUsage::Verify),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                "usage=verify 不能携带私钥",
            ),
            (
                XhttpDownloadTlsSettings {
                    ech_config_list: Some("AA==".into()),
                    ..Default::default()
                },
                "缺少 ECHConfigList 长度",
            ),
            (
                XhttpDownloadTlsSettings {
                    ech_config_list: Some("AAEAAA==".into()),
                    ..Default::default()
                },
                "ECHConfigList 外层长度不匹配",
            ),
            (
                XhttpDownloadTlsSettings {
                    ech_config_list: Some(
                        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==".into(),
                    ),
                    ech_socket_settings: Some(Box::default()),
                    ..Default::default()
                },
                "echSockopt 只能与",
            ),
            (
                XhttpDownloadTlsSettings {
                    ech_config_list: Some("tcp://1.1.1.1".into()),
                    ..Default::default()
                },
                "只支持 https://、h2c:// 或 udp://",
            ),
            (
                XhttpDownloadTlsSettings {
                    ech_server_keys: Some("AA==".into()),
                    ..Default::default()
                },
                "缺少 ECH 私钥长度",
            ),
            (
                XhttpDownloadTlsSettings {
                    disable_system_root: Some(true),
                    ..Default::default()
                },
                "disableSystemRoot=true",
            ),
        ];
        for (settings, expected) in cases {
            let actual = error(settings);
            assert!(
                actual.contains(expected),
                "expected {expected:?}, got {actual}"
            );
        }
    }

    #[test]
    fn xhttp_tls_accepts_xray_ech_direct_dns_and_server_key_vectors() {
        const ECH_CONFIG_LIST: &str = "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";
        const ECH_SERVER_KEYS: &str = "ACCfHeuM9VY1sx9pq24z7wCeitcoGS2rEjeUS8d8P6kfggA+/g0AOgAAIAAguy8p4+MFfgQZ1S/F9EEYd2+NthzqT992B5uTYGxaYkgACAABAAEAAQADAAdlY2guY29tAAA=";

        for settings in [
            XhttpDownloadTlsSettings {
                ech_config_list: Some(ECH_CONFIG_LIST.into()),
                ..Default::default()
            },
            XhttpDownloadTlsSettings {
                ech_config_list: Some("hidden.example+https://1.1.1.1/dns-query".into()),
                ech_socket_settings: Some(Box::default()),
                ..Default::default()
            },
            XhttpDownloadTlsSettings {
                ech_server_keys: Some(ECH_SERVER_KEYS.into()),
                ..Default::default()
            },
        ] {
            settings.validate().unwrap();
        }
    }

    #[test]
    fn xhttp_tls_client_validation_ignores_server_only_fields() {
        let settings = XhttpDownloadTlsSettings {
            reject_unknown_sni: Some(true),
            ech_server_keys: Some("intentionally-not-a-server-key-list".into()),
            ..Default::default()
        };
        settings.validate_client().unwrap();
        assert!(settings.validate().unwrap_err().contains("echServerKeys"));
    }
}
