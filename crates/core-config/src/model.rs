//! 配置数据模型 —— 直接对应 §5 字段完整说明。
//!
//! 所有 field 默认值通过 `Profile::apply_defaults` 注入，
//! 模型本身只负责"原样反序列化 + 短写法/长写法兼容"。

use std::{collections::BTreeMap, time::Duration};

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
    #[serde(default)]
    pub share: Option<Share>,
    #[serde(default)]
    pub auth: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeSecure {
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub utls: Option<String>,
    #[serde(default)]
    pub reality: Option<bool>,
    #[serde(default)]
    pub ech: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeTransport {
    #[serde(default = "default_transport")]
    pub kind: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeNetwork {
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub mptcp: bool,
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
    #[serde(default)]
    pub url: Option<String>,
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
    #[serde(default = "default_resolver_servers")]
    pub servers: BTreeMap<String, String>,
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
            rules: Vec::new(),
            listen: None,
        }
    }
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

/// Capture / TUN 入站 —— 与 mihomo / sing-box `inbounds[type=tun]` 字段全量对齐。
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

/* ---------------- sing-box 完整 TUN 字段 ---------------- */

/// sing-tun auto_redirect input mark 默认值（`DefaultAutoRedirectInputMark`）。
///
/// 进入 redirect chain 的入站 fwmark；TUN 抓包后由 nftables / iptables 给
/// 入站方向的会话打标，`ip rule fwmark <input_mark> lookup <tun_table>` 把这
/// 些会话回送到 TUN 表完成代理。对应 sing-tun `redirect.go::13`。
pub const DEFAULT_AUTO_REDIRECT_INPUT_MARK: u32 = 0x2023;

/// sing-tun auto_redirect output mark 默认值（`DefaultAutoRedirectOutputMark`）。
///
/// TUN auto_route 下 outbound socket 必须使用同一个 mark 绕开 TUN 路由表；
/// 即使未启用 auto_redirect，也复用该默认值保证与 mihomo/sing-tun 行为一致。
/// 对应 sing-tun `redirect.go::14`。
pub const DEFAULT_AUTO_REDIRECT_OUTPUT_MARK: u32 = 0x2024;

/// sing-tun auto_redirect reset mark 默认值（`DefaultAutoRedirectResetMark`）。
///
/// 用于 conntrack RST 包标记，避免 TPROXY 模式下 reset 包反复进入 redirect
/// chain。对应 sing-tun `redirect.go::15`。
pub const DEFAULT_AUTO_REDIRECT_RESET_MARK: u32 = 0x2025;

/// sing-tun auto_redirect nfqueue 默认编号（`DefaultAutoRedirectNFQueue`）。
///
/// nf_queue 用户态 fast-fail 队列编号；对应 sing-tun `redirect.go::16`。
pub const DEFAULT_AUTO_REDIRECT_NFQUEUE: u16 = 100;

/// sing-tun fallback ip rule 优先级（`DefaultIPRoute2AutoRedirectFallbackRuleIndex`）。
///
/// 系统 main 表 (32766) / default 表 (32767) 之后的兜底 rule 优先级；当
/// auto_redirect mark 模式下 main+default 都没有路由时，由 32768 这条 rule
/// 把流量送回 TUN 表。对应 sing-tun `tun.go::70`。
pub const DEFAULT_IPROUTE2_AUTO_REDIRECT_FALLBACK_RULE_INDEX: u32 = 32768;

/// sing-box `inbounds[type=tun]` 全字段映射 —— 见
/// <https://sing-box.sagernet.org/configuration/inbound/tun/>
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// `auto_redirect` —— 自动注入 nftables redirect 规则（更优于 `auto_route`）。
    #[serde(default)]
    pub auto_redirect: bool,
    /// `auto_redirect_input_mark` —— 进入 redirect chain 的 fwmark（hex 字串如 `"0x2023"`）。
    #[serde(default)]
    pub auto_redirect_input_mark: Option<String>,
    /// `auto_redirect_output_mark` —— 跳过 redirect chain 的 fwmark。
    #[serde(default)]
    pub auto_redirect_output_mark: Option<String>,
    /// `auto_redirect_reset_mark` —— RST 包 fwmark（用于 conntrack reset）。
    #[serde(default)]
    pub auto_redirect_reset_mark: Option<String>,
    /// `auto_redirect_nfqueue` —— nfqueue 编号（用户态 fast-fail）。
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
fn default_true() -> bool {
    true
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
fn default_resolver_servers() -> BTreeMap<String, String> {
    // 与 mihomo 一致：IP host 直连，SNI 默认 = host（rustls IpAddress + IP-SAN cert
    // 验证）；也支持写域名（构造时 system DNS bootstrap 一次）。
    BTreeMap::from([
        ("ali".into(), "https://223.5.5.5/dns-query".into()),
        ("cloudflare".into(), "https://1.1.1.1/dns-query".into()),
    ])
}
fn default_transport() -> String {
    "tcp".into()
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
