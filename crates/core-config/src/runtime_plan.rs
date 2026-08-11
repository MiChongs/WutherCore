//! 把用户友好的 YAML 编译成运行时计划 (`RuntimePlan`)。
//!
//! 流程对应 §3.4：YAML -> profile 默认值 -> feeds/nodes 展开 ->
//! 节点 URI 解析 -> groups 选择器 -> route 规则图 -> resolver 策略 ->
//! capture 接管计划 -> smart 评分器 -> runtime graph。
//!
//! 这里产出的结构是给 `core-runtime` / `core-route` / `core-outbound`
//! 共同消费的 *已展开* 数据，而非 YAML 原貌。

use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use indexmap::IndexSet;
use petgraph::{
    algo::{astar, toposort},
    graphmap::DiGraphMap,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ConfigError, ConfigResult},
    model::*,
    node_uri::{
        NodeProtocol, ParsedNode, parse_uri, validate_reality_client_settings, validate_young_node,
    },
    stream_settings::NodeStreamSettings,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub version: u32,
    pub profile: Profile,
    pub name: String,
    pub log: Option<Log>,
    pub database: DatabaseConfig,
    /// Canonical typed inbound declarations as written by the user. Runtime
    /// listener and transparent plans below are compiled from this catalog.
    pub inbounds: Vec<Inbound>,
    pub listen: ListenPlan,
    pub feeds: BTreeMap<String, FeedDetail>,
    pub nodes: Vec<ParsedNode>,
    pub groups: BTreeMap<String, GroupPlan>,
    pub route: RoutePlan,
    pub resolver: Resolver,
    pub capture: Capture,
    pub smart: Smart,
    pub ui: Ui,
    pub mesh: Mesh,
    pub find_process_mode: crate::model::FindProcessMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenPlan {
    pub mixed: Option<MixedListen>,
    #[serde(default)]
    pub reality: Vec<RealityListen>,
    #[serde(default)]
    pub wireguard: Vec<WireGuardListenPlan>,
    #[serde(default)]
    pub young: Vec<YoungListen>,
    pub grpc: Vec<GrpcListen>,
    pub panel: Option<PanelListen>,
    pub xhttp: Vec<XhttpListenPlan>,
    pub shadowsocks: Vec<ShadowsocksListenPlan>,
    pub share: Share,
    pub auth: Vec<UserPass>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksListenPlan {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub mode: String,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub plugin_args: Vec<String>,
    pub plugin_mode: Option<String>,
    pub plugin_startup_timeout: Duration,
    pub users: Vec<ShadowsocksUser>,
    pub handshake_timeout: Duration,
    pub udp_timeout: Duration,
    pub max_connections: usize,
    pub max_udp_associations: usize,
    pub tag: String,
}

impl ShadowsocksListenPlan {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        parse_shadowsocks_socket(&self.address, self.port).ok_or_else(|| {
            ConfigError::invalid(format!(
                "非法 Shadowsocks 监听地址: {}:{}",
                self.address, self.port
            ))
        })
    }

    pub fn enable_tcp(&self) -> bool {
        matches!(self.mode.as_str(), "tcp_only" | "tcp_and_udp")
    }

    pub fn enable_udp(&self) -> bool {
        matches!(self.mode.as_str(), "udp_only" | "tcp_and_udp")
    }
}

fn parse_shadowsocks_socket(address: &str, port: u16) -> Option<SocketAddr> {
    address
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, port))
        .or_else(|_| format!("{address}:{port}").parse())
        .ok()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WireGuardListenPlan {
    pub bind: SocketAddr,
    pub private_key: [u8; 32],
    pub peers: Vec<WireGuardListenPeerPlan>,
    pub mtu: usize,
    pub packet_queue: usize,
    pub handshake_rate_limit: u64,
}

impl std::fmt::Debug for WireGuardListenPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardListenPlan")
            .field("bind", &self.bind)
            .field("private_key", &"<redacted>")
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("packet_queue", &self.packet_queue)
            .field("handshake_rate_limit", &self.handshake_rate_limit)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WireGuardListenPeerPlan {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub reserved: [u8; 3],
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for WireGuardListenPeerPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardListenPeerPlan")
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

impl YoungListen {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        let host = self.host.trim();
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        let ip = host
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::invalid(format!("非法 Young 监听 IP: {}", self.host)))?;
        Ok(SocketAddr::new(ip, self.port))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedListen {
    pub tag: String,
    pub host: String,
    pub port: u16,
    pub udp: bool,
    pub stream_settings: Option<NodeStreamSettings>,
}

impl MixedListen {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|_| ConfigError::invalid(format!("非法监听地址: {}:{}", self.host, self.port)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelListen {
    pub host: String,
    pub port: u16,
}

impl PanelListen {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|_| ConfigError::invalid(format!("非法面板地址: {}:{}", self.host, self.port)))
    }
}

/// 已完成结构和语义校验的 XHTTP 服务端监听计划。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpListenPlan {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub cleartext: bool,
    pub allow_unauthenticated_non_loopback: bool,
    pub tls: Option<XhttpListenTlsPlan>,
    pub alpn: Vec<XhttpListenAlpn>,
    pub target: Option<XhttpListenTargetPlan>,
    pub tag: String,
    pub accept_queue: usize,
    pub max_active_relays: usize,
    pub max_active_connections: usize,
    pub max_concurrent_streams: u32,
    pub max_active_http_streams: usize,
    #[serde(with = "humantime_serde")]
    pub http_idle_timeout: Duration,
    /// `None` 使用 XrayCompatible；`Some([])` 禁用 CORS；非空值为 allowlist。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors_origins: Option<Vec<String>>,
    /// Listener-side socket policy plus the FinalMask layer below HTTP/TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<NodeStreamSettings>,
    /// 与客户端/出站共享同一个完整强类型 XHTTP 配置。
    pub settings: XhttpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XhttpListenTargetPlan {
    pub host: String,
    pub port: u16,
}

impl XhttpListenPlan {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        let ip = self
            .address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| {
                ConfigError::invalid(format!(
                    "非法 XHTTP 监听地址: {}:{}",
                    self.address, self.port
                ))
            })?;
        Ok(SocketAddr::new(ip, self.port))
    }

    pub fn uses_http3(&self) -> bool {
        self.alpn == [XhttpListenAlpn::H3]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpListenTlsPlan {
    /// 旧版单证书/私钥路径；新配置优先使用 settings.certificates。
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub settings: crate::model::XhttpDownloadTlsSettings,
    pub require_client_certificate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPlan {
    pub name: String,
    pub choose: ChooseStrategy,
    /// 已展开的具体节点、provider 占位符和下级组名，保持配置顺序。
    pub members: Vec<String>,
    #[serde(default)]
    pub min_members: usize,
    #[serde(default)]
    pub max_members: usize,
    #[serde(default)]
    pub default_selected: String,
    #[serde(default = "default_group_plan_empty_fallback")]
    pub empty_fallback: String,
    #[serde(default = "default_true")]
    pub lazy: bool,
    #[serde(default)]
    pub weights: BTreeMap<String, u32>,
    pub prefer: Vec<String>,
    pub avoid: Vec<String>,
    pub check: Option<String>,
    #[serde(default)]
    pub expected_status: String,
    #[serde(default = "default_group_plan_interval")]
    pub interval: Duration,
    #[serde(default = "default_group_plan_idle_timeout")]
    pub idle_timeout: Duration,
    #[serde(default = "default_group_plan_tolerance")]
    pub tolerance: u32,
    #[serde(default)]
    pub unified_delay: Option<bool>,
    #[serde(default = "default_group_plan_strategy")]
    pub strategy: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub exclude_filter: String,
    #[serde(default)]
    pub exclude_type: String,
    #[serde(default = "default_group_plan_max_failed_times")]
    pub max_failed_times: u32,
    #[serde(default = "default_group_plan_test_timeout")]
    pub test_timeout: Duration,
    #[serde(default)]
    pub disable_udp: bool,
    pub sticky: Option<String>,
    pub path: Vec<String>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub icon: String,
}

fn default_group_plan_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_group_plan_idle_timeout() -> Duration {
    Duration::from_secs(10 * 60)
}

fn default_group_plan_tolerance() -> u32 {
    50
}

fn default_group_plan_strategy() -> String {
    "consistent-hashing".to_string()
}

fn default_group_plan_max_failed_times() -> u32 {
    5
}

fn default_group_plan_test_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_group_plan_empty_fallback() -> String {
    "BLOCK".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePlan {
    pub preset: String,
    pub r#final: String,
    /// 编译后的规则；preset 已经展开为 steps。
    pub steps: Vec<RouteStep>,
    /// Compiled Mihomo `sub-rules`, evaluated as ordered branches.
    #[serde(default)]
    pub sub_rules: BTreeMap<String, Vec<RouteStep>>,
    /// route.sets 原样保留，由 core-ruleset 接管。
    #[serde(default)]
    pub sets: BTreeMap<String, RuleSetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStep {
    pub matcher: RouteMatcher,
    pub action: RouteAction,
    /// 原始用户行，便于 explain 输出。
    pub source: String,
    #[serde(default)]
    pub options: RouteRuleOptions,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRuleOptions {
    pub no_resolve: bool,
    pub no_log: bool,
    pub no_track: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RouteMatcher {
    /// 兜底
    Any,
    /// 局域网 / 本机 / mDNS / 私有地址。
    Home,
    /// 中国大陆常用域名/IP 集。
    Cn,
    /// 广告/跟踪。
    Ads,
    /// 内置服务别名：telegram/youtube/...
    Service(String),
    Domain(String),
    Suffix(String),
    /// mihomo `DOMAIN-KEYWORD` —— 子串匹配（大小写不敏感）。
    Keyword(String),
    /// mihomo `DOMAIN-REGEX` —— regexp2 风格、大小写不敏感。
    DomainRegex(String),
    /// mihomo `DOMAIN-WILDCARD` —— `*`/`?` 可跨标签匹配。
    DomainWildcard(String),
    /// GeoSite 数据通过同名外部 domain/MRS 规则集提供。
    GeoSite(String),
    Cidr(String),
    /// mihomo `SRC-IP-CIDR`，只匹配连接源地址。
    SrcCidr(String),
    /// 从 IP 地址末端开始比较前缀位数（mihomo `IP-SUFFIX`）。
    IpSuffix(String),
    SrcIpSuffix(String),
    /// GeoIP / ASN 数据通过外部 ipcidr/MRS 规则集或已注入元数据匹配。
    GeoIp(String),
    SrcGeoIp(String),
    IpAsn(u32),
    SrcIpAsn(u32),
    Port(u16),
    /// `DST-PORT,LOW-HIGH` —— 闭区间端口范围。
    PortRange(u16, u16),
    /// mihomo `SRC-PORT`，只匹配连接源端口。
    SrcPort(u16),
    SrcPortRange(u16, u16),
    InPort(u16),
    InPortRange(u16, u16),
    Network(String),
    Dscp(u8),
    InUser(String),
    InName(String),
    InType(String),
    Uid(u32),
    RematchName(String),
    Process(String),
    /// mihomo `PROCESS-PATH`，完整路径精确匹配。
    ProcessPath(String),
    ProcessRegex(String),
    ProcessPathRegex(String),
    ProcessWildcard(String),
    ProcessPathWildcard(String),
    /// 外部规则集（`route.sets.<name>`）。
    Set(String),
    /// mihomo `RULE-SET,...,src`：将 provider 的目标 IP 语义应用到源 IP。
    SrcSet(String),
    /// L7 协议指纹（stun/dtls/quic/tls/sni/http/webrtc）。
    Proto(String),
    /// AND 组合 —— 所有子 matcher 都命中才算命中（短路求值）。
    /// 由 typed-key object 形式中多个具名字段联合产生。
    And(Vec<RouteMatcher>),
    /// OR 组合 —— 任一子 matcher 命中即算命中（短路求值）。
    /// 由具名字段的列表值产生（如 `port: [53, 5353]`）。
    Or(Vec<RouteMatcher>),
    /// NOT 组合 —— 子 matcher 的三态结果取反，延迟依赖保持不变。
    Not(Box<RouteMatcher>),
    /// 逻辑规则内部的 mihomo `no-resolve`。顶层规则仍同时保留在
    /// [`RouteRuleOptions`]，以便 Clash API 展示该标志。
    NoResolve(Box<RouteMatcher>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Block,
    Group(String),
    Pass,
    PassRule,
    /// Internal control-flow action used by Mihomo `SUB-RULE`.
    SubRule(String),
}

/* ---------------- compile ---------------- */

/// 用户配置 -> RuntimePlan。要求 [`crate::profile::apply_defaults`] 已执行。
pub fn compile(mut cfg: UserConfig) -> ConfigResult<RuntimePlan> {
    validate_database(&cfg.database)?;
    normalize_inbounds(&mut cfg)?;
    let inbounds = cfg.inbounds.clone();
    let listen = compile_listen(&cfg)?;
    let feeds = compile_feeds(&cfg.feeds)?;
    let nodes = compile_nodes(&cfg.nodes)?;
    let groups = compile_groups(&cfg, &nodes)?;
    let mut cfg_route = cfg.route.take().unwrap_or_default();
    crate::ruleset_compat::merge_compatible_rule_sets(
        &mut cfg_route.sets,
        std::mem::take(&mut cfg_route.rule_set),
        std::mem::take(&mut cfg.rule_providers),
    )?;
    let route_sets = cfg_route.sets.clone();
    let route = compile_route(cfg_route, &groups, route_sets)?;
    let resolver = cfg.resolver.unwrap_or_default();
    validate_resolver_group_exits(&resolver)?;
    let capture = cfg.capture.unwrap_or_default();
    validate_capture_platform(&capture)?;
    let smart = cfg.smart.unwrap_or_default();
    let ui = cfg.ui.unwrap_or_default();
    validate_ui_secret_for_bind(&listen, &ui)?;
    let mesh = cfg.mesh.unwrap_or_default();
    let find_process_mode = cfg.find_process_mode;
    Ok(RuntimePlan {
        version: cfg.version,
        profile: cfg.profile,
        name: cfg.name.unwrap_or_else(|| "wuthercore".into()),
        log: cfg.log,
        database: cfg.database,
        inbounds,
        listen,
        feeds,
        nodes,
        groups,
        route,
        resolver,
        capture,
        smart,
        ui,
        mesh,
        find_process_mode,
    })
}

fn normalize_inbounds(cfg: &mut UserConfig) -> ConfigResult<()> {
    if cfg.inbounds.is_empty() {
        return Ok(());
    }

    let mut tags = HashSet::new();
    let mut mixed = None;
    let mut transparent = None;
    let mut kernel_ingress = None;

    for (index, inbound) in cfg.inbounds.iter().enumerate() {
        let path = format!("inbounds[{index}]");
        let tag = inbound.tag().trim();
        if tag.is_empty() {
            return Err(ConfigError::invalid("inbound tag 不能为空").at(format!("{path}.tag")));
        }
        if tag.len() > 128 {
            return Err(
                ConfigError::invalid("inbound tag 不能超过 128 字节").at(format!("{path}.tag"))
            );
        }
        if !tags.insert(tag.to_owned()) {
            return Err(ConfigError::invalid(format!("inbound tag `{tag}` 重复"))
                .at(format!("{path}.tag"))
                .hint("每个 inbound 必须使用唯一 tag，供路由规则和连接表引用"));
        }

        match inbound {
            Inbound::Mixed(options) if options.enabled => {
                if mixed.replace((index, options.clone())).is_some() {
                    return Err(
                        ConfigError::invalid("当前运行时只允许一个启用的 mixed inbound")
                            .at(path)
                            .hint("HTTP 和 SOCKS5 已由 mixed 在同一端口同时提供"),
                    );
                }
            }
            Inbound::Tun(options) | Inbound::Tproxy(options) | Inbound::Redirect(options) => {
                if options.enabled && kernel_ingress.replace((index, inbound.kind())).is_some() {
                    return Err(ConfigError::invalid(
                        "同一进程只能启用一个 tun、tproxy、redirect 或 ebpf inbound",
                    )
                    .at(path)
                    .hint("这些入站共同接管宿主网络命名空间，不能叠加"));
                }
                if transparent.replace((index, inbound.clone())).is_some() {
                    return Err(ConfigError::invalid(
                        "同一进程只能声明一个 tun、tproxy 或 redirect inbound",
                    )
                    .at(path)
                    .hint("透明入站共同占用宿主路由和防火墙资源，不能叠加"));
                }
            }
            Inbound::Ebpf(options) if options.enabled => {
                if kernel_ingress.replace((index, inbound.kind())).is_some() {
                    return Err(ConfigError::invalid(
                        "同一进程只能启用一个 tun、tproxy、redirect 或 ebpf inbound",
                    )
                    .at(path)
                    .hint("这些入站共同接管宿主网络命名空间，不能叠加"));
                }
                validate_ebpf_inbound(options, &path, std::env::consts::OS)?;
            }
            Inbound::Ebpf(_) => {}
            Inbound::Mixed(_) => {}
        }
    }

    let listen = cfg.listen.get_or_insert_with(|| Listen {
        local: None,
        panel: None,
        xhttp: None,
        shadowsocks: None,
        share: None,
        auth: Vec::new(),
        reality: Vec::new(),
        wireguard: Vec::new(),
        young: Vec::new(),
        grpc: Vec::new(),
    });
    if let Some((index, options)) = mixed {
        if listen.local.is_some() {
            return Err(ConfigError::invalid(
                "inbounds[type=mixed] 与旧 listen.local 不能同时配置",
            )
            .at(format!("inbounds[{index}]"))
            .hint("删除 listen.local，并把监听地址、端口和用户放入 mixed inbound"));
        }
        if !listen.auth.is_empty() && !options.users.is_empty() {
            return Err(
                ConfigError::invalid("mixed inbound users 与旧 listen.auth 不能同时配置")
                    .at(format!("inbounds[{index}].users")),
            );
        }
        let mut usernames = HashSet::new();
        for (user_index, user) in options.users.iter().enumerate() {
            if user.username.trim().is_empty()
                || user.password.is_empty()
                || user.username.contains(':')
                || !usernames.insert(user.username.clone())
            {
                return Err(ConfigError::invalid(
                    "mixed inbound 用户名必须非空、唯一且不能包含冒号，密码不能为空",
                )
                .at(format!("inbounds[{index}].users[{user_index}]")));
            }
        }
        if !options.users.is_empty() {
            listen.auth = options
                .users
                .iter()
                .map(|user| format!("{}:{}", user.username, user.password))
                .collect();
        }
        listen.local = Some(ListenLocal::Detail(ListenLocalDetail {
            tag: Some(options.tag),
            host: options.listen,
            port: options.listen_port,
            auth: Vec::new(),
            udp: options.udp,
            stream_settings: options.stream_settings,
        }));
    }

    if let Some((index, inbound)) = transparent {
        if cfg.capture.is_some() {
            return Err(
                ConfigError::invalid("透明 inbound 与旧 capture 配置不能同时存在")
                    .at(format!("inbounds[{index}]"))
                    .hint("删除 capture，并把原 capture.tun 字段直接放到 inbound 条目中"),
            );
        }
        cfg.capture = inbound.transparent_capture();
    }
    Ok(())
}

fn validate_ebpf_inbound(options: &EbpfInboundOptions, path: &str, os: &str) -> ConfigResult<()> {
    if !matches!(os, "linux" | "android") {
        return Err(
            ConfigError::new(crate::error::ConfigErrorKind::UnsupportedPlatform(format!(
                "eBPF inbound 仅支持 Linux/Android；当前平台为 {os}"
            )))
            .at(path),
        );
    }
    if options.redirect_address.is_empty() {
        return Err(
            ConfigError::invalid("redirect_address 至少需要一个 IPv4 或 IPv6 CIDR")
                .at(format!("{path}.redirect_address")),
        );
    }
    let mut has_v4 = false;
    let mut has_v6 = false;
    for (index, value) in options.redirect_address.iter().enumerate() {
        match value.parse::<ipnet::IpNet>() {
            Ok(ipnet::IpNet::V4(_)) => has_v4 = true,
            Ok(ipnet::IpNet::V6(_)) => has_v6 = true,
            Err(_) => {
                return Err(ConfigError::invalid(format!(
                    "redirect_address[{index}] 不是合法 CIDR: {value}"
                ))
                .at(format!("{path}.redirect_address[{index}]")));
            }
        }
    }
    if !has_v4 && !has_v6 {
        return Err(
            ConfigError::invalid("redirect_address 没有可用的 IP 地址族")
                .at(format!("{path}.redirect_address")),
        );
    }
    for (field, values) in [
        ("include_uid_range", &options.include_uid_range),
        ("exclude_uid_range", &options.exclude_uid_range),
    ] {
        if values.len() > 256 {
            return Err(ConfigError::invalid(format!("{field} 最多允许 256 个区间"))
                .at(format!("{path}.{field}")));
        }
        let mut ranges = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            let valid = value
                .split_once(':')
                .and_then(|(start, end)| {
                    Some((start.parse::<u32>().ok()?, end.parse::<u32>().ok()?))
                })
                .is_some_and(|(start, end)| start <= end);
            if !valid {
                return Err(ConfigError::invalid(format!(
                    "{field}[{index}] 必须是 start:end 闭区间: {value}"
                ))
                .at(format!("{path}.{field}[{index}]")));
            }
            if !ranges.insert(value.as_str()) {
                return Err(
                    ConfigError::invalid(format!("{field} 不能包含重复区间: {value}"))
                        .at(format!("{path}.{field}[{index}]")),
                );
            }
        }
    }
    if !options.cgroup_path.to_string_lossy().starts_with('/') {
        return Err(ConfigError::invalid("cgroup_path 必须是绝对路径")
            .at(format!("{path}.cgroup_path"))
            .hint("通常使用 /sys/fs/cgroup"));
    }
    if options.mark == 0 {
        return Err(ConfigError::invalid("mark 不能为 0").at(format!("{path}.mark")));
    }
    if matches!(options.route_table, 0 | 253..=255) {
        return Err(
            ConfigError::invalid("route_table 不能为 0 或 Linux 保留表 253..=255")
                .at(format!("{path}.route_table")),
        );
    }
    if !(1..=32_765).contains(&options.rule_priority) {
        return Err(ConfigError::invalid(
            "rule_priority 必须在 1..=32765，且排在 Linux main rule 之前",
        )
        .at(format!("{path}.rule_priority")));
    }
    if !(1_024..=1_048_576).contains(&options.map_capacity) {
        return Err(ConfigError::invalid("map_capacity 必须在 1024..=1048576")
            .at(format!("{path}.map_capacity")));
    }
    validate_ebpf_shared_network(
        &options.shared_network,
        options.map_capacity,
        &format!("{path}.shared_network"),
    )?;
    for (field, values) in [
        ("include_uid", &options.include_uid),
        ("exclude_uid", &options.exclude_uid),
    ] {
        if values.len() > options.map_capacity as usize {
            return Err(
                ConfigError::invalid(format!("{field} 条目数不能超过 map_capacity"))
                    .at(format!("{path}.{field}")),
            );
        }
        let mut exact = HashSet::new();
        for (index, uid) in values.iter().enumerate() {
            if !exact.insert(*uid) {
                return Err(
                    ConfigError::invalid(format!("{field} 不能包含重复 UID: {uid}"))
                        .at(format!("{path}.{field}[{index}]")),
                );
            }
        }
    }
    let mut names = HashSet::new();
    for (index, name) in options.bypass_rule_set.iter().enumerate() {
        if name.trim().is_empty() || !names.insert(name.as_str()) {
            return Err(
                ConfigError::invalid("bypass_rule_set 不能包含空名称或重复名称")
                    .at(format!("{path}.bypass_rule_set[{index}]")),
            );
        }
    }
    Ok(())
}

fn validate_ebpf_shared_network(
    shared: &EbpfSharedNetworkOptions,
    map_capacity: u32,
    path: &str,
) -> ConfigResult<()> {
    if !shared.enabled {
        return Ok(());
    }
    if shared.include_interface.is_empty() {
        return Err(
            ConfigError::invalid("启用共享网络接管时 include_interface 不能为空")
                .at(format!("{path}.include_interface"))
                .hint("热点可使用 ap*、wlan*，USB 共享可使用 rndis*、usb*"),
        );
    }
    for (field, patterns) in [
        ("include_interface", &shared.include_interface),
        ("exclude_interface", &shared.exclude_interface),
    ] {
        let mut unique = HashSet::new();
        for (index, pattern) in patterns.iter().enumerate() {
            if pattern.trim().is_empty() || !unique.insert(pattern.as_str()) {
                return Err(
                    ConfigError::invalid(format!("{field} 不能包含空值或重复模式"))
                        .at(format!("{path}.{field}[{index}]")),
                );
            }
            Glob::new(pattern).map_err(|error| {
                ConfigError::invalid(format!("{field}[{index}] 不是合法 glob: {error}"))
                    .at(format!("{path}.{field}[{index}]"))
            })?;
        }
    }
    for (field, addresses) in [
        ("include_source_address", &shared.include_source_address),
        ("exclude_source_address", &shared.exclude_source_address),
    ] {
        if addresses.len() > map_capacity as usize {
            return Err(
                ConfigError::invalid(format!("{field} 条目数不能超过 map_capacity"))
                    .at(format!("{path}.{field}")),
            );
        }
        let mut unique = HashSet::new();
        for (index, value) in addresses.iter().enumerate() {
            if value.parse::<ipnet::IpNet>().is_err() {
                return Err(ConfigError::invalid(format!(
                    "{field}[{index}] 不是合法 CIDR: {value}"
                ))
                .at(format!("{path}.{field}[{index}]")));
            }
            if !unique.insert(value.as_str()) {
                return Err(
                    ConfigError::invalid(format!("{field} 不能包含重复 CIDR: {value}"))
                        .at(format!("{path}.{field}[{index}]")),
                );
            }
        }
    }
    if !(Duration::from_secs(1)..=Duration::from_secs(300))
        .contains(&shared.interface_refresh_interval)
    {
        return Err(
            ConfigError::invalid("interface_refresh_interval 必须在 1s..=5m")
                .at(format!("{path}.interface_refresh_interval")),
        );
    }
    if shared.tc_priority == 0 {
        return Err(
            ConfigError::invalid("tc_priority 必须在 1..=65535").at(format!("{path}.tc_priority"))
        );
    }
    Ok(())
}

fn validate_resolver_group_exits(resolver: &Resolver) -> ConfigResult<()> {
    for (server_name, server) in &resolver.servers {
        for exit in server.exits() {
            // provider 节点在配置编译后才加载，因此未知名称必须保留到运行时
            // 解析；已定义 group 则由 RuntimeDnsOutboundProvider 递归展开。
            if exit.trim().is_empty() {
                return Err(ConfigError::invalid(format!(
                    "resolver.servers.{server_name}.exits 不能包含空名称"
                ))
                .at(format!("resolver.servers.{server_name}.exits"))
                .hint("DNS 出口可引用 DIRECT、BLOCK、静态节点、provider 节点或策略组"));
            }
        }
    }
    Ok(())
}

fn validate_database(database: &DatabaseConfig) -> ConfigResult<()> {
    if !database.enabled {
        return Ok(());
    }
    if database.path.as_os_str().is_empty() {
        return Err(ConfigError::invalid("database.path 不能为空")
            .at("database.path")
            .hint("填写 Turso 数据库文件路径，例如 data/state/wuthercore.db"));
    }
    if database.busy_timeout.is_zero() {
        return Err(ConfigError::invalid("database.busy-timeout 必须大于 0")
            .at("database.busy-timeout")
            .hint("推荐保持默认值 5s"));
    }
    if database.max_write_attempts == 0 {
        return Err(
            ConfigError::invalid("database.max-write-attempts 必须大于 0")
                .at("database.max-write-attempts")
                .hint("推荐保持默认值 12"),
        );
    }
    Ok(())
}

fn compile_listen(cfg: &UserConfig) -> ConfigResult<ListenPlan> {
    let listen = cfg.listen.clone().unwrap_or(Listen {
        local: None,
        panel: None,
        xhttp: None,
        shadowsocks: None,
        share: None,
        auth: vec![],
        reality: vec![],
        wireguard: vec![],
        young: vec![],
        grpc: vec![],
    });

    let share = listen.share.unwrap_or(Share::False);
    let host_for = |share: Share| -> &'static str {
        match share {
            Share::False => "127.0.0.1",
            Share::Home | Share::All => "0.0.0.0",
        }
    };

    let mixed = listen.local.map(|l| match l {
        ListenLocal::Port(p) => MixedListen {
            tag: default_mixed_inbound_tag(),
            host: host_for(share).into(),
            port: p,
            udp: true,
            stream_settings: None,
        },
        ListenLocal::Detail(d) => MixedListen {
            tag: d.tag.unwrap_or_else(default_mixed_inbound_tag),
            host: if d.host.is_empty() {
                host_for(share).into()
            } else {
                d.host
            },
            port: d.port,
            udp: d.udp,
            stream_settings: d.stream_settings,
        },
    });
    if mixed.as_ref().is_some_and(|listener| listener.port == 0) {
        return Err(ConfigError::invalid(
            "listen.local 端口不能为 0；删除 local 配置可禁用 Mixed 入站",
        ));
    }

    let panel = match listen.panel {
        None | Some(PanelBind::Off(false)) => None,
        Some(PanelBind::Off(true)) => Some(PanelListen {
            host: host_for(share).into(),
            port: 9090,
        }),
        Some(PanelBind::Port(port)) => Some(PanelListen {
            host: host_for(share).into(),
            port,
        }),
        Some(PanelBind::Address(addr)) => {
            let socket: SocketAddr = addr
                .parse()
                .map_err(|_| ConfigError::invalid(format!("非法 listen.panel 地址: {addr}")))?;
            let host = match socket.ip() {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            Some(PanelListen {
                host,
                port: socket.port(),
            })
        }
    };
    if panel.as_ref().is_some_and(|listener| listener.port == 0) {
        return Err(ConfigError::invalid(
            "listen.panel 端口不能为 0；设为 false 可禁用 API 入站",
        ));
    }

    let xhttp = compile_xhttp_listeners(listen.xhttp)?;
    let shadowsocks = compile_shadowsocks_listeners(listen.shadowsocks)?;

    let auth = listen
        .auth
        .iter()
        .filter_map(|s| {
            s.split_once(':').map(|(u, p)| UserPass {
                user: u.into(),
                pass: p.into(),
            })
        })
        .collect();

    let reality = compile_reality_listeners(&listen.reality)?;
    let wireguard = compile_wireguard_listeners(&listen.wireguard)?;
    let young = compile_young_listeners(&listen.young)?;
    let grpc = compile_grpc_listeners(&listen.grpc)?;

    Ok(ListenPlan {
        mixed,
        reality,
        wireguard,
        young,
        grpc,
        panel,
        xhttp,
        shadowsocks,
        share,
        auth,
    })
}

fn compile_shadowsocks_listeners(
    listeners: Option<ShadowsocksListenSet>,
) -> ConfigResult<Vec<ShadowsocksListenPlan>> {
    let listeners = listeners
        .map(ShadowsocksListenSet::into_vec)
        .unwrap_or_default();
    let mut plans = Vec::with_capacity(listeners.len());
    let mut tags = HashSet::new();
    let mut tcp_sockets = HashSet::new();
    let mut udp_sockets = HashSet::new();
    for (index, listener) in listeners.into_iter().enumerate() {
        let path = format!("listen.shadowsocks[{index}]");
        let method = listener.method.to_ascii_lowercase();
        let cipher = method
            .parse::<shadowsocks::crypto::CipherKind>()
            .map_err(|_| {
                ConfigError::invalid(format!(
                    "{path}.method 不支持 Shadowsocks 加密方法 `{method}`"
                ))
            })?;
        shadowsocks::config::ServerConfig::new(
            shadowsocks::config::ServerAddr::DomainName(listener.address.clone(), listener.port),
            listener.password.clone(),
            cipher,
        )
        .map_err(|error| ConfigError::invalid(format!("{path}.password/ method 无效: {error}")))?;
        let mode = match listener
            .mode
            .to_ascii_lowercase()
            .replace('-', "_")
            .as_str()
        {
            "tcp" | "tcp_only" => "tcp_only",
            "udp" | "udp_only" => "udp_only",
            "tcp_and_udp" | "tcp_udp" => "tcp_and_udp",
            other => {
                return Err(ConfigError::invalid(format!(
                    "{path}.mode `{other}` 必须为 tcp_only、udp_only 或 tcp_and_udp"
                )));
            }
        }
        .to_owned();
        let plugin_mode = listener
            .plugin_mode
            .as_deref()
            .map(|value| value.to_ascii_lowercase().replace('-', "_"))
            .map(|value| match value.as_str() {
                "tcp" | "tcp_only" => Ok("tcp_only".to_owned()),
                "udp" | "udp_only" => Ok("udp_only".to_owned()),
                "tcp_and_udp" | "tcp_udp" => Ok("tcp_and_udp".to_owned()),
                other => Err(ConfigError::invalid(format!(
                    "{path}.plugin-mode `{other}` 必须为 tcp_only、udp_only 或 tcp_and_udp"
                ))),
            })
            .transpose()?;
        if let Some(plugin) = listener.plugin.as_deref() {
            if plugin.trim().is_empty() {
                return Err(ConfigError::invalid(format!("{path}.plugin 不能为空")));
            }
            if plugin.contains('\0') || listener.plugin_args.iter().any(|arg| arg.contains('\0')) {
                return Err(ConfigError::invalid(format!(
                    "{path}.plugin/plugin-args 不能包含 NUL 字符"
                )));
            }
            if listener.plugin_startup_timeout.is_zero() {
                return Err(ConfigError::invalid(format!(
                    "{path}.plugin-startup-timeout 不能为 0"
                )));
            }
            if plugin_mode.as_deref().unwrap_or(&mode) != mode {
                return Err(ConfigError::invalid(format!(
                    "{path}.plugin-mode 必须与 mode 一致，避免绕过插件暴露未封装载体"
                )));
            }
        } else if listener.plugin_opts.is_some()
            || !listener.plugin_args.is_empty()
            || listener.plugin_mode.is_some()
        {
            return Err(ConfigError::invalid(format!(
                "{path} 配置 plugin-opts/plugin-args/plugin-mode 时必须同时配置 plugin"
            )));
        }
        if listener.enabled {
            if listener.port == 0 {
                return Err(ConfigError::invalid(format!("{path}.port 不能为 0")));
            }
            if listener.handshake_timeout.is_zero() || listener.udp_timeout.is_zero() {
                return Err(ConfigError::invalid(format!("{path} 超时必须大于 0")));
            }
            if listener.max_connections == 0 || listener.max_udp_associations == 0 {
                return Err(ConfigError::invalid(format!("{path} 并发上限必须大于 0")));
            }
        }
        if !listener.users.is_empty() && !cipher.is_aead_2022() {
            return Err(ConfigError::invalid(format!(
                "{path}.users 仅适用于 Shadowsocks 2022 EIH"
            )));
        }
        let mut user_names = HashSet::new();
        for (user_index, user) in listener.users.iter().enumerate() {
            if user.name.trim().is_empty() || !user_names.insert(user.name.clone()) {
                return Err(ConfigError::invalid(format!(
                    "{path}.users[{user_index}].name 为空或重复"
                )));
            }
            let parsed_user = shadowsocks::config::ServerUser::with_encoded_key(
                &user.name, &user.key,
            )
            .map_err(|error| {
                ConfigError::invalid(format!("{path}.users[{user_index}].key 无效: {error}"))
            })?;
            if parsed_user.key().len() != cipher.key_len() {
                return Err(ConfigError::invalid(format!(
                    "{path}.users[{user_index}].key 解码后必须为 {} 字节，实际为 {} 字节",
                    cipher.key_len(),
                    parsed_user.key().len()
                )));
            }
        }
        let tag = listener
            .tag
            .unwrap_or_else(|| format!("shadowsocks-{}", index + 1));
        if !tags.insert(tag.clone()) {
            return Err(ConfigError::invalid(format!("{path}.tag `{tag}` 重复")));
        }
        let socket = parse_shadowsocks_socket(&listener.address, listener.port)
            .ok_or_else(|| ConfigError::invalid(format!("{path} 监听地址无效")))?;
        if listener.enabled
            && matches!(mode.as_str(), "tcp_only" | "tcp_and_udp")
            && !tcp_sockets.insert(socket)
        {
            return Err(ConfigError::invalid(format!(
                "{path} TCP 监听地址重复: {socket}"
            )));
        }
        if listener.enabled
            && matches!(mode.as_str(), "udp_only" | "tcp_and_udp")
            && !udp_sockets.insert(socket)
        {
            return Err(ConfigError::invalid(format!(
                "{path} UDP 监听地址重复: {socket}"
            )));
        }
        plans.push(ShadowsocksListenPlan {
            enabled: listener.enabled,
            address: listener.address,
            port: listener.port,
            method,
            password: listener.password,
            mode,
            plugin: listener.plugin,
            plugin_opts: listener.plugin_opts,
            plugin_args: listener.plugin_args,
            plugin_mode,
            plugin_startup_timeout: listener.plugin_startup_timeout,
            users: listener.users,
            handshake_timeout: listener.handshake_timeout,
            udp_timeout: listener.udp_timeout,
            max_connections: listener.max_connections,
            max_udp_associations: listener.max_udp_associations,
            tag,
        });
    }
    Ok(plans)
}

fn compile_wireguard_listeners(
    listeners: &[WireGuardListen],
) -> ConfigResult<Vec<WireGuardListenPlan>> {
    let mut result = Vec::with_capacity(listeners.len());
    let mut binds = HashSet::new();
    for (index, source) in listeners.iter().enumerate() {
        let location = format!("listen.wireguard[{index}]");
        let host = source.host.trim().parse::<IpAddr>().map_err(|_| {
            ConfigError::invalid("WireGuard 服务端 host 必须是 IPv4 或 IPv6 地址")
                .at(format!("{location}.host"))
        })?;
        if source.port == 0 {
            return Err(ConfigError::invalid("WireGuard 服务端监听端口不能为 0")
                .at(format!("{location}.port")));
        }
        let bind = SocketAddr::new(host, source.port);
        if !binds.insert(bind) {
            return Err(ConfigError::invalid("重复的 WireGuard 服务端监听地址").at(location));
        }
        let private_key =
            decode_wireguard_key(&source.private_key, &format!("{location}.privateKey"))?;
        if private_key == [0; 32] {
            return Err(ConfigError::invalid("WireGuard privateKey 不能全为 0")
                .at(format!("{location}.privateKey")));
        }
        if source.peers.is_empty() || source.peers.len() > 256 {
            return Err(ConfigError::invalid("WireGuard peers 数量必须在 1..=256")
                .at(format!("{location}.peers")));
        }
        if !(576..=65_535).contains(&source.mtu) {
            return Err(ConfigError::invalid("WireGuard mtu 必须在 576..=65535")
                .at(format!("{location}.mtu")));
        }
        if !(16..=65_536).contains(&source.packet_queue) {
            return Err(
                ConfigError::invalid("WireGuard packetQueue 必须在 16..=65536")
                    .at(format!("{location}.packetQueue")),
            );
        }
        if !(1..=1_000_000).contains(&source.handshake_rate_limit) {
            return Err(
                ConfigError::invalid("WireGuard handshakeRateLimit 必须在 1..=1000000")
                    .at(format!("{location}.handshakeRateLimit")),
            );
        }

        let mut peers = Vec::with_capacity(source.peers.len());
        let mut public_keys = HashSet::new();
        let mut exact_routes = HashSet::new();
        let mut has_ipv6 = false;
        for (peer_index, peer) in source.peers.iter().enumerate() {
            let peer_location = format!("{location}.peers[{peer_index}]");
            let public_key =
                decode_wireguard_key(&peer.public_key, &format!("{peer_location}.publicKey"))?;
            if public_key == [0; 32] || !public_keys.insert(public_key) {
                return Err(ConfigError::invalid(
                    "WireGuard 对端公钥不能全为 0，且每个监听器内必须唯一",
                )
                .at(format!("{peer_location}.publicKey")));
            }
            let preshared_key = peer
                .preshared_key
                .as_deref()
                .map(|key| decode_wireguard_key(key, &format!("{peer_location}.presharedKey")))
                .transpose()?;
            if peer.allowed_ips.is_empty() {
                return Err(
                    ConfigError::invalid("WireGuard 对端至少需要一个 allowedIPs")
                        .at(format!("{peer_location}.allowedIPs")),
                );
            }
            let mut allowed_ips = Vec::with_capacity(peer.allowed_ips.len());
            for (route_index, route) in peer.allowed_ips.iter().enumerate() {
                let network = route.parse::<ipnet::IpNet>().map_err(|error| {
                    ConfigError::invalid(format!("非法 WireGuard allowedIPs：{error}"))
                        .at(format!("{peer_location}.allowedIPs[{route_index}]"))
                })?;
                let network = network.trunc();
                has_ipv6 |= network.addr().is_ipv6();
                if !exact_routes.insert(network) {
                    return Err(ConfigError::invalid(
                        "同一 WireGuard allowedIPs 不能分配给多个对端",
                    )
                    .at(format!("{peer_location}.allowedIPs[{route_index}]")));
                }
                allowed_ips.push(network);
            }
            let reserved: [u8; 3] = match peer.reserved.as_slice() {
                [] => [0; 3],
                [a, b, c] => [*a, *b, *c],
                _ => {
                    return Err(
                        ConfigError::invalid("WireGuard reserved 必须为空或恰好 3 个字节")
                            .at(format!("{peer_location}.reserved")),
                    );
                }
            };
            peers.push(WireGuardListenPeerPlan {
                public_key,
                preshared_key,
                allowed_ips,
                reserved,
                persistent_keepalive: peer.persistent_keepalive,
            });
        }
        if has_ipv6 && source.mtu < 1_280 {
            return Err(
                ConfigError::invalid("WireGuard IPv6 allowedIPs 要求 mtu 至少为 1280")
                    .at(format!("{location}.mtu")),
            );
        }
        result.push(WireGuardListenPlan {
            bind,
            private_key,
            peers,
            mtu: source.mtu,
            packet_queue: source.packet_queue,
            handshake_rate_limit: source.handshake_rate_limit,
        });
    }
    Ok(result)
}

fn decode_wireguard_key(value: &str, location: &str) -> ConfigResult<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose};

    let value = value.trim();
    let decoded = general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')))
        .map_err(|error| {
            ConfigError::invalid(format!("WireGuard 密钥不是合法 base64：{error}")).at(location)
        })?;
    decoded
        .try_into()
        .map_err(|_| ConfigError::invalid("WireGuard 密钥必须解码为 32 字节").at(location))
}

fn compile_young_listeners(listeners: &[YoungListen]) -> ConfigResult<Vec<YoungListen>> {
    let mut output = Vec::with_capacity(listeners.len());
    let mut bound = std::collections::HashSet::new();
    let mut nss_database: Option<&str> = None;
    for (index, listener) in listeners.iter().enumerate() {
        let location = format!("listen.young[{index}]");
        if listener.port == 0 {
            return Err(ConfigError::invalid("Young 入站端口不能为 0").at(location));
        }
        if listener.host.trim().is_empty() {
            return Err(ConfigError::invalid("Young 入站 host 不能为空").at(location));
        }
        let listen_addr = listener
            .socket_addr()
            .map_err(|error| error.at(location.clone()))?;
        if !bound.insert(listen_addr) {
            return Err(ConfigError::invalid("重复的 Young 监听地址").at(location));
        }
        if listener.nss_database.trim().is_empty()
            || listener.certificate_nickname.trim().is_empty()
        {
            return Err(ConfigError::invalid(
                "Young 入站必须配置 nssDatabase 与 certificateNickname",
            )
            .at(location));
        }
        if let Some(existing) = nss_database {
            if existing != listener.nss_database {
                return Err(ConfigError::invalid(
                    "同一进程的全部 Young 入站必须使用同一个 nssDatabase",
                )
                .at(format!("{location}.nssDatabase")));
            }
        } else {
            nss_database = Some(&listener.nss_database);
        }
        if listener.authority.trim().is_empty() {
            return Err(ConfigError::invalid("Young authority 不能为空")
                .at(format!("{location}.authority")));
        }
        if !listener.path.starts_with('/') || listener.path.len() > 512 {
            return Err(
                ConfigError::invalid("Young path 必须以 / 开头且不超过 512 字节")
                    .at(format!("{location}.path")),
            );
        }
        if listener.users.is_empty() {
            return Err(
                ConfigError::invalid("Young 入站至少需要一个 256 位 users 密钥")
                    .at(format!("{location}.users")),
            );
        }
        let keys = listener
            .users
            .iter()
            .enumerate()
            .map(|(user_index, user)| {
                core_young::YoungKey::parse_base64url(user).map_err(|error| {
                    ConfigError::invalid(format!("非法 Young 256 位密钥：{error}"))
                        .at(format!("{location}.users[{user_index}]"))
                })
            })
            .collect::<ConfigResult<Vec<_>>>()?;
        core_young::KeyRing::new(keys).map_err(|error| {
            ConfigError::invalid(format!("Young users key ring 无效：{error}"))
                .at(format!("{location}.users"))
        })?;
        if !(Duration::from_secs(10)..=Duration::from_secs(10 * 60)).contains(&listener.clock_skew)
        {
            return Err(ConfigError::invalid("Young clockSkew 必须在 10s..=10m")
                .at(format!("{location}.clockSkew")));
        }
        if listener.idle_timeout < Duration::from_secs(10)
            || listener.max_streams == 0
            || listener.max_sessions == 0
            || listener.max_flows_per_session == 0
        {
            return Err(ConfigError::invalid("Young idleTimeout/资源上限无效").at(location));
        }
        if listener.padding_min == 0
            || listener.padding_min > listener.padding_max
            || usize::from(listener.padding_max) > core_young::MAX_PADDING_BYTES
            || listener.padding_scheme_length == 0
            || usize::from(listener.padding_scheme_length) > core_young::MAX_PADDING_SCHEME_LENGTH
        {
            return Err(ConfigError::invalid(
                "Young paddingMin/paddingMax/paddingSchemeLength 无效",
            )
            .at(location));
        }
        if !(100..=599).contains(&listener.decoy_status) || listener.decoy_body.len() > 1024 * 1024
        {
            return Err(ConfigError::invalid("Young decoyStatus/decoyBody 无效").at(location));
        }
        output.push(listener.clone());
    }
    Ok(output)
}

fn compile_grpc_listeners(listeners: &[GrpcListen]) -> ConfigResult<Vec<GrpcListen>> {
    const MIN_MESSAGE_SIZE: usize = 3;
    const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;
    const MAX_QUEUE_CAPACITY: usize = 1024;

    let mut out = Vec::with_capacity(listeners.len());
    let mut bound = HashSet::new();
    for (index, source) in listeners.iter().enumerate() {
        let location = format!("listen.grpc[{index}]");
        if source.port == 0 {
            return Err(ConfigError::invalid("gRPC 监听端口不能为 0").at(location));
        }
        let host = source.host.trim();
        if host.is_empty() {
            return Err(ConfigError::invalid("gRPC 监听地址不能为空").at(location));
        }
        let address = parse_listener_address(host, source.port).map_err(|error| {
            ConfigError::invalid(format!("非法 gRPC 监听地址 `{host}`: {error}"))
                .at(format!("{location}.host"))
        })?;
        if !bound.insert(address) {
            return Err(ConfigError::invalid("重复的 gRPC 监听地址").at(location));
        }
        if !source.protocol.eq_ignore_ascii_case("vless") {
            return Err(ConfigError::invalid(format!(
                "gRPC 入站目前只接受完整实现的 VLESS 内层协议，收到 `{}`",
                source.protocol
            ))
            .at(format!("{location}.protocol")));
        }
        if source.users.is_empty() {
            return Err(
                ConfigError::invalid("gRPC VLESS 入站至少需要一个 users UUID").at(location),
            );
        }
        let mut users = HashSet::with_capacity(source.users.len());
        for (user_index, user) in source.users.iter().enumerate() {
            let parsed = uuid::Uuid::parse_str(user).map_err(|error| {
                ConfigError::invalid(format!("非法 VLESS UUID: {error}"))
                    .at(format!("{location}.users[{user_index}]"))
            })?;
            if !users.insert(parsed) {
                return Err(ConfigError::invalid("gRPC VLESS users 中存在重复 UUID")
                    .at(format!("{location}.users[{user_index}]")));
            }
        }
        if source.handshake_timeout.is_zero() {
            return Err(ConfigError::invalid("handshakeTimeout 必须大于 0")
                .at(format!("{location}.handshakeTimeout")));
        }
        if source.max_mux_sessions == 0 || source.max_mux_sessions > u16::MAX as usize {
            return Err(ConfigError::invalid("maxMuxSessions 必须在 1..=65535")
                .at(format!("{location}.maxMuxSessions")));
        }
        if source.max_connections == 0 || source.max_connections > u16::MAX as usize {
            return Err(ConfigError::invalid("maxConnections 必须在 1..=65535")
                .at(format!("{location}.maxConnections")));
        }
        if source.max_concurrent_streams == 0 {
            return Err(ConfigError::invalid("maxConcurrentStreams 必须大于 0")
                .at(format!("{location}.maxConcurrentStreams")));
        }
        if source.max_header_list_size == 0 {
            return Err(ConfigError::invalid("maxHeaderListSize 必须大于 0")
                .at(format!("{location}.maxHeaderListSize")));
        }

        let settings = &source.grpc_settings;
        for (name, value) in [
            ("idle_timeout", settings.idle_timeout.as_ref()),
            (
                "health_check_timeout",
                settings.health_check_timeout.as_ref(),
            ),
        ] {
            if let Some(value) = value {
                let duration = value.duration();
                if duration.subsec_nanos() != 0 || duration.as_secs() > i32::MAX as u64 {
                    return Err(ConfigError::invalid(format!(
                        "{name} 必须是 0..={} 范围内的整数秒",
                        i32::MAX
                    ))
                    .at(format!("{location}.grpcSettings.{name}")));
                }
            }
        }
        if settings
            .initial_window_size
            .is_some_and(|value| value > i32::MAX as u32)
        {
            return Err(
                ConfigError::invalid("initial_windows_size 超出 Xray int32 范围")
                    .at(format!("{location}.grpcSettings.initial_windows_size")),
            );
        }
        if let Some(value) = settings.max_message_size
            && !(MIN_MESSAGE_SIZE..=MAX_MESSAGE_SIZE).contains(&value)
        {
            return Err(ConfigError::invalid(format!(
                "max_message_size 必须在 {MIN_MESSAGE_SIZE}..={MAX_MESSAGE_SIZE}"
            ))
            .at(format!("{location}.grpcSettings.max_message_size")));
        }
        if let Some(value) = settings.queue_capacity
            && (value == 0 || value > MAX_QUEUE_CAPACITY)
        {
            return Err(ConfigError::invalid(format!(
                "queue_capacity 必须在 1..={MAX_QUEUE_CAPACITY}"
            ))
            .at(format!("{location}.grpcSettings.queue_capacity")));
        }
        if settings
            .authority
            .as_deref()
            .is_some_and(|value| has_header_injection(value))
        {
            return Err(ConfigError::invalid("authority 含非法控制字符")
                .at(format!("{location}.grpcSettings.authority")));
        }
        if settings
            .user_agent
            .as_deref()
            .is_some_and(has_header_injection)
        {
            return Err(ConfigError::invalid("user_agent 含非法控制字符")
                .at(format!("{location}.grpcSettings.user_agent")));
        }
        for (header_index, header) in source.trusted_x_forwarded_for.iter().enumerate() {
            if !is_http_header_name(header) {
                return Err(
                    ConfigError::invalid("trustedXForwardedFor 含非法 HTTP 头名称")
                        .at(format!("{location}.trustedXForwardedFor[{header_index}]")),
                );
            }
        }

        let mut normalized = source.clone();
        normalized.host = host.to_owned();
        normalized.protocol = "vless".into();
        match source.security {
            GrpcListenSecurity::None => {
                if source.tls_settings.is_some()
                    || source.reality_settings.is_some()
                    || source.require_client_certificate
                {
                    return Err(ConfigError::invalid(
                        "security=none 不能同时配置 tlsSettings、realitySettings 或 requireClientCertificate",
                    )
                    .at(format!("{location}.security")));
                }
            }
            GrpcListenSecurity::Tls => {
                if source.reality_settings.is_some() {
                    return Err(
                        ConfigError::invalid("security=tls 不能同时配置 realitySettings")
                            .at(format!("{location}.realitySettings")),
                    );
                }
                let mut tls = source.tls_settings.clone().ok_or_else(|| {
                    ConfigError::invalid("security=tls 必须配置 tlsSettings")
                        .at(format!("{location}.tlsSettings"))
                })?;
                match tls.alpn.as_mut() {
                    None => tls.alpn = Some(vec!["h2".into()]),
                    Some(alpn) if !alpn.iter().any(|value| value == "h2") => {
                        return Err(ConfigError::invalid(
                            "gRPC TLS 的 alpn 必须包含 h2，禁止静默回退到 HTTP/1.1",
                        )
                        .at(format!("{location}.tlsSettings.alpn")));
                    }
                    Some(_) => {}
                }
                tls.validate().map_err(|error| {
                    ConfigError::invalid(format!("gRPC TLS 配置非法：{error}"))
                        .at(format!("{location}.tlsSettings"))
                })?;
                normalized.tls_settings = Some(tls);
            }
            GrpcListenSecurity::Reality => {
                if source.tls_settings.is_some() || source.require_client_certificate {
                    return Err(ConfigError::invalid(
                        "security=reality 不能同时配置 tlsSettings 或 requireClientCertificate",
                    )
                    .at(format!("{location}.security")));
                }
                let mut reality = source.reality_settings.as_deref().cloned().ok_or_else(|| {
                    ConfigError::invalid("security=reality 必须配置 realitySettings")
                        .at(format!("{location}.realitySettings"))
                })?;
                reality.host = normalized.host.clone();
                reality.port = normalized.port;
                reality.protocol = "vless".into();
                reality.users = normalized.users.clone();
                let mut validated = compile_reality_listeners(&[reality])?;
                normalized.reality_settings = Some(Box::new(validated.remove(0)));
            }
        }
        out.push(normalized);
    }
    Ok(out)
}

fn parse_listener_address(host: &str, port: u16) -> Result<SocketAddr, std::net::AddrParseError> {
    host.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, port))
}

fn has_header_injection(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
}

fn is_http_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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

fn compile_reality_listeners(listeners: &[RealityListen]) -> ConfigResult<Vec<RealityListen>> {
    use base64::Engine as _;

    let mut out = Vec::with_capacity(listeners.len());
    let mut bound = std::collections::HashSet::new();
    for (index, source) in listeners.iter().enumerate() {
        let location = format!("listen.reality[{index}]");
        if source.port == 0 {
            return Err(ConfigError::invalid("REALITY 监听端口不能为 0").at(location));
        }
        if source.host.trim().is_empty() {
            return Err(ConfigError::invalid("REALITY 监听地址不能为空").at(location));
        }
        if !bound.insert((source.host.clone(), source.port)) {
            return Err(ConfigError::invalid("重复的 REALITY 监听地址").at(location));
        }
        if source.show {
            return Err(ConfigError::invalid(
                "REALITY show 会输出握手密钥材料，WutherCore 出于密钥安全不提供该选项",
            )
            .at(format!("{location}.show")));
        }
        if source
            .master_key_log
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value != "none")
        {
            return Err(ConfigError::invalid(
                "REALITY masterKeyLog 会把会话密钥写入磁盘，WutherCore 出于密钥安全不提供该选项",
            )
            .at(format!("{location}.masterKeyLog")));
        }
        if source.xver > 2 {
            return Err(ConfigError::invalid("REALITY xver 只能是 0、1 或 2")
                .at(format!("{location}.xver")));
        }
        if !source.protocol.eq_ignore_ascii_case("vless") {
            return Err(ConfigError::invalid(format!(
                "当前 REALITY 入站只接受已完整实现的 VLESS 内层协议，收到 `{}`",
                source.protocol
            ))
            .at(format!("{location}.protocol")));
        }
        if source.users.is_empty() {
            return Err(
                ConfigError::invalid("VLESS-over-REALITY 至少需要一个 users UUID")
                    .at(format!("{location}.users")),
            );
        }
        for (user_index, user) in source.users.iter().enumerate() {
            uuid::Uuid::parse_str(user).map_err(|error| {
                ConfigError::invalid(format!("非法 VLESS UUID：{error}"))
                    .at(format!("{location}.users[{user_index}]"))
            })?;
        }
        let target = match (&source.target, &source.dest) {
            (Some(target), Some(dest)) if target != dest => {
                return Err(
                    ConfigError::invalid("REALITY target 与 dest 同时配置但值不一致").at(location),
                );
            }
            (Some(target), _) | (_, Some(target)) => target.normalized(),
            (None, None) => {
                return Err(ConfigError::invalid("REALITY 缺少 target/dest")
                    .at(format!("{location}.target")));
            }
        };
        let target_type = source
            .target_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| {
                if target.starts_with('@') || target.starts_with('/') {
                    "unix".to_owned()
                } else {
                    "tcp".to_owned()
                }
            });
        if !matches!(target_type.as_str(), "tcp" | "unix") {
            return Err(ConfigError::invalid(format!(
                "REALITY type 只接受 tcp 或 unix，收到 `{target_type}`"
            ))
            .at(format!("{location}.type")));
        }
        if target_type == "tcp" && target.rsplit_once(':').is_none() {
            return Err(ConfigError::invalid("REALITY TCP target 必须包含端口")
                .at(format!("{location}.target")));
        }
        if target_type == "unix" && cfg!(windows) {
            return Err(
                ConfigError::invalid("当前 Windows 平台不支持 REALITY unix target")
                    .at(format!("{location}.type")),
            );
        }
        if source.server_names.is_empty()
            || source
                .server_names
                .iter()
                .any(|name| name.trim().is_empty())
        {
            return Err(ConfigError::invalid("REALITY serverNames 不能为空")
                .at(format!("{location}.serverNames")));
        }
        let private_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&source.private_key)
            .map_err(|error| {
                ConfigError::invalid(format!("REALITY privateKey 不是合法 base64url：{error}"))
                    .at(format!("{location}.privateKey"))
            })?;
        if private_key.len() != 32 {
            return Err(
                ConfigError::invalid("REALITY privateKey 必须解码为 32 字节")
                    .at(format!("{location}.privateKey")),
            );
        }
        if source.short_ids.is_empty() {
            return Err(ConfigError::invalid("REALITY shortIds 不能为空")
                .at(format!("{location}.shortIds")));
        }
        for (short_index, short_id) in source.short_ids.iter().enumerate() {
            validate_reality_short_id(short_id).map_err(|message| {
                ConfigError::invalid(message).at(format!("{location}.shortIds[{short_index}]"))
            })?;
        }
        let min = parse_reality_version(
            source.min_client_ver.as_deref().unwrap_or("26.3.27"),
            &format!("{location}.minClientVer"),
        )?;
        let max = source
            .max_client_ver
            .as_deref()
            .map(|version| parse_reality_version(version, &format!("{location}.maxClientVer")))
            .transpose()?;
        if max.is_some_and(|max| min > max) {
            return Err(
                ConfigError::invalid("REALITY minClientVer 不能大于 maxClientVer").at(location),
            );
        }
        if let Some(seed) = &source.mldsa65_seed {
            if seed == &source.private_key {
                return Err(
                    ConfigError::invalid("REALITY mldsa65Seed 不能与 privateKey 相同")
                        .at(format!("{location}.mldsa65Seed")),
                );
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seed)
                .map_err(|error| {
                    ConfigError::invalid(format!("REALITY mldsa65Seed 不是合法 base64url：{error}"))
                        .at(format!("{location}.mldsa65Seed"))
                })?;
            if decoded.len() != 32 {
                return Err(
                    ConfigError::invalid("REALITY mldsa65Seed 必须解码为 32 字节")
                        .at(format!("{location}.mldsa65Seed")),
                );
            }
        }
        validate_reality_fallback_limit(
            source.limit_fallback_upload,
            &format!("{location}.limitFallbackUpload"),
        )?;
        validate_reality_fallback_limit(
            source.limit_fallback_download,
            &format!("{location}.limitFallbackDownload"),
        )?;
        validate_reality_resource_limits(source.limits, &format!("{location}.limits"))?;
        validate_reality_listener_stream_settings(source.stream_settings.as_ref(), &location)?;

        let mut normalized = source.clone();
        normalized.target = Some(RealityTarget::Address(target));
        normalized.dest = None;
        normalized.target_type = Some(target_type);
        normalized.min_client_ver = Some(format!("{}.{}.{}", min[0], min[1], min[2]));
        normalized.max_client_ver =
            max.map(|version| format!("{}.{}.{}", version[0], version[1], version[2]));
        out.push(normalized);
    }
    Ok(out)
}

fn validate_reality_short_id(value: &str) -> Result<(), String> {
    if value.len() > 16 || value.len() % 2 != 0 {
        return Err("REALITY shortId 必须是 0 到 16 个偶数长度十六进制字符".into());
    }
    hex::decode(value)
        .map(|_| ())
        .map_err(|error| format!("REALITY shortId 不是合法十六进制：{error}"))
}

fn parse_reality_version(value: &str, location: &str) -> ConfigResult<[u8; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(ConfigError::invalid(format!(
            "REALITY 客户端版本必须是 1 到 3 段十进制数字，收到 `{value}`"
        ))
        .at(location));
    }
    let mut version = [0u8; 3];
    for (index, part) in parts.iter().enumerate() {
        version[index] = part.parse().map_err(|_| {
            ConfigError::invalid(format!("REALITY 客户端版本段必须小于 256：`{value}`"))
                .at(location)
        })?;
    }
    Ok(version)
}

fn validate_reality_fallback_limit(
    limit: RealityFallbackLimit,
    location: &str,
) -> ConfigResult<()> {
    if limit.bytes_per_sec == 0 && (limit.after_bytes != 0 || limit.burst_bytes_per_sec != 0) {
        return Err(ConfigError::invalid(
            "REALITY 回落 afterBytes/burstBytesPerSec 要求 bytesPerSec 非零",
        )
        .at(location));
    }
    Ok(())
}

fn validate_reality_resource_limits(
    limits: RealityResourceLimits,
    location: &str,
) -> ConfigResult<()> {
    if limits.handshake_timeout.is_zero()
        || limits.target_handshake_timeout.is_zero()
        || limits.idle_timeout.is_zero()
        || limits.max_client_hello_records == 0
        || limits.max_client_hello_record_payload == 0
        || limits.max_client_hello_record_payload > 16_640
        || limits.max_client_hello_bytes < 4
        || limits.max_client_hello_bytes > u16::MAX as usize
        || limits.max_client_hello_wire_bytes < 5
        || limits.max_target_records < 3
        || limits.max_target_handshake_bytes < 1024
        || limits.application_buffer_bytes == 0
        || limits.max_concurrent_handshakes == 0
    {
        return Err(ConfigError::invalid("非法 REALITY 资源上限").at(location));
    }
    Ok(())
}

fn compile_xhttp_cors_origins(
    origins: Option<Vec<String>>,
    path: &str,
) -> ConfigResult<Option<Vec<String>>> {
    let Some(origins) = origins else {
        return Ok(None);
    };
    let mut normalized = Vec::with_capacity(origins.len());
    for (index, origin) in origins.into_iter().enumerate() {
        if origin.chars().any(char::is_control) {
            return Err(ConfigError::invalid(format!(
                "{path}.cors-origins[{index}] 必须是不含控制字符的 ASCII origin"
            )));
        }
        let origin = origin.trim().to_string();
        if origin.is_empty() {
            return Err(ConfigError::invalid(format!(
                "{path}.cors-origins[{index}] 不能为空"
            )));
        }
        if !origin.is_ascii() {
            return Err(ConfigError::invalid(format!(
                "{path}.cors-origins[{index}] 必须是不含控制字符的 ASCII origin"
            )));
        }
        normalized.push(origin);
    }

    if normalized.iter().any(|origin| origin == "*") {
        if normalized.len() == 1 {
            return Ok(Some(normalized));
        }
        return Err(ConfigError::invalid(format!(
            "{path}.cors-origins 中 `*` 必须是唯一项，不能与其它 origin 混用"
        )));
    }

    let mut seen = std::collections::HashSet::with_capacity(normalized.len());
    let mut canonical = Vec::with_capacity(normalized.len());
    for (index, origin) in normalized.iter().enumerate() {
        let parsed = url::Url::parse(origin).map_err(|_| {
            ConfigError::invalid(format!(
                "{path}.cors-origins[{index}] `{origin}` 不是有效的 HTTP(S) origin"
            ))
        })?;
        let has_authority_only = origin
            .split_once("://")
            .is_some_and(|(_, authority)| !authority.is_empty() && !authority.contains('/'));
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !has_authority_only
        {
            return Err(ConfigError::invalid(format!(
                "{path}.cors-origins[{index}] `{origin}` 必须是明确的 HTTP(S) origin（scheme://host[:port]）"
            )));
        }
        // Browser Origin serialization lower-cases scheme/host and removes a
        // default port. Store exactly that form so matching is not accidentally
        // case-sensitive and equivalent spellings cannot bypass duplicate
        // detection.
        let serialized = parsed.origin().ascii_serialization();
        if !seen.insert(serialized.clone()) {
            return Err(ConfigError::invalid(format!(
                "{path}.cors-origins 包含等价的重复 origin `{origin}`（规范形式 `{serialized}`）"
            )));
        }
        canonical.push(serialized);
    }

    Ok(Some(canonical))
}

fn compile_xhttp_listeners(
    listeners: Option<XhttpListenSet>,
) -> ConfigResult<Vec<XhttpListenPlan>> {
    let listeners = listeners.map(XhttpListenSet::into_vec).unwrap_or_default();
    let mut plans = Vec::with_capacity(listeners.len());
    let mut tags = std::collections::HashSet::with_capacity(listeners.len());

    for (index, listener) in listeners.into_iter().enumerate() {
        let path = format!("listen.xhttp[{index}]");
        let address = listener.address.trim().to_string();
        if address.is_empty() {
            return Err(ConfigError::invalid(format!("{path}.address 不能为空")));
        }
        let normalized_address = address
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let bind_ip = normalized_address
            .parse::<std::net::IpAddr>()
            .map_err(|_| {
                ConfigError::invalid(format!(
                    "{path}.address 必须是可绑定的 IPv4/IPv6 地址，不能是 `{address}`"
                ))
            })?;
        if listener.port == 0 {
            return Err(ConfigError::invalid(format!("{path}.port 不能为 0")));
        }
        if listener.accept_queue == 0 {
            return Err(ConfigError::invalid(format!(
                "{path}.accept-queue 必须大于 0"
            )));
        }
        if listener.accept_queue > XHTTP_MAX_ACCEPT_QUEUE {
            return Err(ConfigError::invalid(format!(
                "{path}.accept-queue 不能大于 {XHTTP_MAX_ACCEPT_QUEUE}"
            )));
        }
        if listener.max_active_relays == 0 {
            return Err(ConfigError::invalid(format!(
                "{path}.max-active-relays 必须大于 0"
            )));
        }
        if listener.max_active_connections == 0 {
            return Err(ConfigError::invalid(format!(
                "{path}.max-active-connections 必须大于 0"
            )));
        }
        if listener.max_active_connections > XHTTP_MAX_ACTIVE_CONNECTIONS {
            return Err(ConfigError::invalid(format!(
                "{path}.max-active-connections 不能大于 {XHTTP_MAX_ACTIVE_CONNECTIONS}"
            )));
        }
        if listener.max_concurrent_streams == 0 {
            return Err(ConfigError::invalid(format!(
                "{path}.max-concurrent-streams 必须大于 0"
            )));
        }
        if listener.max_concurrent_streams > XHTTP_MAX_CONCURRENT_STREAMS {
            return Err(ConfigError::invalid(format!(
                "{path}.max-concurrent-streams 不能大于 {XHTTP_MAX_CONCURRENT_STREAMS}"
            )));
        }
        if listener.max_active_http_streams == 0 {
            return Err(ConfigError::invalid(format!(
                "{path}.max-active-http-streams 必须大于 0"
            )));
        }
        if listener.max_active_http_streams > XHTTP_MAX_ACTIVE_HTTP_STREAMS {
            return Err(ConfigError::invalid(format!(
                "{path}.max-active-http-streams 不能大于 {XHTTP_MAX_ACTIVE_HTTP_STREAMS}"
            )));
        }
        if listener.http_idle_timeout.is_zero() {
            return Err(ConfigError::invalid(format!(
                "{path}.http-idle-timeout 必须大于 0 秒"
            )));
        }
        let cors_origins = compile_xhttp_cors_origins(listener.cors_origins, &path)?;

        if listener.cleartext && listener.tls.is_some() {
            return Err(ConfigError::invalid(format!(
                "{path}.cleartext=true 与 tls 不能同时设置"
            )));
        }
        if listener.enabled && !listener.cleartext && listener.tls.is_none() {
            return Err(ConfigError::invalid(format!(
                "{path} 已启用，必须设置 tls.cert/tls.key 或显式 cleartext=true"
            )));
        }
        let tls = listener
            .tls
            .map(|tls| {
                let cert_path = tls
                    .cert_path
                    .map(|value| {
                        let value = value.trim().to_string();
                        if value.is_empty() {
                            Err(ConfigError::invalid(format!(
                                "{path}.tls.cert 证书路径不能为空"
                            )))
                        } else {
                            Ok(value)
                        }
                    })
                    .transpose()?;
                let key_path = tls
                    .key_path
                    .map(|value| {
                        let value = value.trim().to_string();
                        if value.is_empty() {
                            Err(ConfigError::invalid(format!(
                                "{path}.tls.key 私钥路径不能为空"
                            )))
                        } else {
                            Ok(value)
                        }
                    })
                    .transpose()?;
                if cert_path.is_some() != key_path.is_some() {
                    return Err(ConfigError::invalid(format!(
                        "{path}.tls.cert 与 tls.key 必须同时设置"
                    )));
                }
                tls.settings.validate().map_err(|error| {
                    ConfigError::invalid(format!("{path}.tls 配置无效: {error}"))
                })?;
                let encipherment_count = tls
                    .settings
                    .certificates
                    .iter()
                    .filter(|certificate| {
                        certificate.usage.unwrap_or(
                            crate::model::XhttpTlsCertificateUsage::Encipherment,
                        ) == crate::model::XhttpTlsCertificateUsage::Encipherment
                    })
                    .count();
                let issuer_count = tls
                    .settings
                    .certificates
                    .iter()
                    .filter(|certificate| {
                        certificate.usage
                            == Some(crate::model::XhttpTlsCertificateUsage::Issue)
                    })
                    .count();
                if cert_path.is_some() && encipherment_count != 0 {
                    return Err(ConfigError::invalid(format!(
                        "{path}.tls.cert/key 与 tls.certificates 的 encipherment 证书不能同时设置"
                    )));
                }
                if issuer_count != 0 && (cert_path.is_some() || encipherment_count != 0) {
                    return Err(ConfigError::invalid(format!(
                        "{path}.tls usage=issue 动态 CA 不能与静态 encipherment/cert-key 身份混用"
                    )));
                }
                if cert_path.is_none() && encipherment_count == 0 && issuer_count == 0 {
                    return Err(ConfigError::invalid(format!(
                        "{path}.tls 必须提供 cert/key、usage=encipherment 证书或 usage=issue 动态 CA"
                    )));
                }
                let require_client_certificate =
                    tls.require_client_certificate.unwrap_or(false);
                if require_client_certificate
                    && !tls.settings.certificates.iter().any(|certificate| {
                        certificate.usage
                            == Some(crate::model::XhttpTlsCertificateUsage::Verify)
                    })
                {
                    return Err(ConfigError::invalid(format!(
                        "{path}.tls.requireClientCertificate=true 时必须提供 usage=verify 的客户端 CA"
                    )));
                }
                Ok(XhttpListenTlsPlan {
                    cert_path,
                    key_path,
                    settings: tls.settings,
                    require_client_certificate,
                })
            })
            .transpose()?;

        if listener.alpn.is_empty() {
            return Err(ConfigError::invalid(format!("{path}.alpn 不能为空")));
        }
        let mut seen_alpn = std::collections::HashSet::with_capacity(listener.alpn.len());
        for alpn in &listener.alpn {
            if !seen_alpn.insert(*alpn) {
                return Err(ConfigError::invalid(format!(
                    "{path}.alpn 包含重复值 `{}`",
                    alpn.as_str()
                )));
            }
        }
        let has_h3 = listener.alpn.contains(&XhttpListenAlpn::H3);
        if has_h3 && listener.alpn.len() != 1 {
            return Err(ConfigError::invalid(format!(
                "{path}.alpn=h3 必须独占该监听项，不能与 http/1.1 或 h2 混合"
            )));
        }
        if has_h3 && (listener.cleartext || tls.is_none()) {
            return Err(ConfigError::invalid(format!(
                "{path}.alpn=h3 必须使用 TLS，不能启用 cleartext"
            )));
        }

        validate_xhttp_listener_stream_settings(listener.stream_settings.as_ref(), has_h3, &path)?;

        listener
            .settings
            .validate()
            .map_err(|error| ConfigError::invalid(format!("{path}.settings 配置无效: {error}")))?;

        let target = listener
            .target
            .map(|target| {
                let host = target
                    .host
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string();
                if host.is_empty() || host.chars().any(char::is_control) {
                    return Err(ConfigError::invalid(format!(
                        "{path}.target.host 不能为空或包含控制字符"
                    )));
                }
                if target.port == 0 {
                    return Err(ConfigError::invalid(format!("{path}.target.port 不能为 0")));
                }
                Ok(XhttpListenTargetPlan {
                    host,
                    port: target.port,
                })
            })
            .transpose()?;
        if listener.enabled {
            if target.is_none() {
                return Err(ConfigError::invalid(format!(
                    "{path}.target 是 enabled XHTTP Raw 适配器的必填固定目标"
                )));
            }
            if !bind_ip.is_loopback() && !listener.allow_unauthenticated_non_loopback {
                return Err(ConfigError::invalid(format!(
                    "{path} 的 enabled raw 监听绑定非回环地址 `{normalized_address}`；必须显式设置 allow-unauthenticated-non-loopback=true"
                )));
            }
        }

        let tag = listener
            .tag
            .map(|tag| tag.trim().to_string())
            .unwrap_or_else(|| format!("xhttp-{}", index + 1));
        if tag.is_empty() {
            return Err(ConfigError::invalid(format!("{path}.tag 不能为空")));
        }
        if !tags.insert(tag.clone()) {
            return Err(ConfigError::invalid(format!(
                "{path}.tag `{tag}` 与其它 XHTTP 监听重复"
            )));
        }

        plans.push(XhttpListenPlan {
            enabled: listener.enabled,
            address: normalized_address,
            port: listener.port,
            cleartext: listener.cleartext,
            allow_unauthenticated_non_loopback: listener.allow_unauthenticated_non_loopback,
            tls,
            alpn: listener.alpn,
            target,
            tag,
            accept_queue: listener.accept_queue,
            max_active_relays: listener.max_active_relays,
            max_active_connections: listener.max_active_connections,
            max_concurrent_streams: listener.max_concurrent_streams,
            max_active_http_streams: listener.max_active_http_streams,
            http_idle_timeout: listener.http_idle_timeout,
            cors_origins,
            stream_settings: listener.stream_settings,
            settings: listener.settings,
        });
    }

    Ok(plans)
}

fn compile_feeds(feeds: &BTreeMap<String, FeedSpec>) -> ConfigResult<BTreeMap<String, FeedDetail>> {
    feeds
        .iter()
        .map(|(k, v)| {
            let detail = match v {
                FeedSpec::Url(u) => FeedDetail {
                    url: u.clone(),
                    payload: Vec::new(),
                    every: Duration::from_secs(12 * 3600),
                    via: "direct".into(),
                    keep: Default::default(),
                    drop: Default::default(),
                    rename: Default::default(),
                    age_secret_key: None,
                    size_limit: None,
                    headers: Default::default(),
                    filter: None,
                    exclude_filter: None,
                    exclude_type: None,
                    overrides: Default::default(),
                },
                FeedSpec::Detail(d) => d.clone(),
            };
            if detail.url.trim().is_empty() && detail.payload.is_empty() {
                return Err(
                    ConfigError::invalid("订阅必须配置 url/path 或内联 nodes/payload")
                        .at(format!("feeds.{k}")),
                );
            }
            if let Some(client_id) = detail.overrides.client_id.as_deref() {
                validate_anytls_client_id(client_id, &format!("feeds.{k}.override.clientId"))?;
            }
            if let Some(secret_keys) = detail.age_secret_key.as_deref() {
                validate_age_secret_keys(secret_keys, &format!("feeds.{k}.age-secret-key"))?;
            }
            for (field, value) in [
                ("filter", detail.filter.as_deref()),
                ("exclude-filter", detail.exclude_filter.as_deref()),
            ] {
                if let Some(value) = value {
                    for pattern in value.split('`').filter(|pattern| !pattern.is_empty()) {
                        fancy_regex::Regex::new(pattern).map_err(|error| {
                            ConfigError::invalid(format!(
                                "订阅 {field} 正则 `{pattern}` 无效: {error}"
                            ))
                            .at(format!("feeds.{k}.{field}"))
                        })?;
                    }
                }
            }
            for (index, replacement) in detail.overrides.proxy_name.iter().enumerate() {
                fancy_regex::Regex::new(&replacement.pattern).map_err(|error| {
                    ConfigError::invalid(format!(
                        "订阅 proxy-name 正则 `{}` 无效: {error}",
                        replacement.pattern
                    ))
                    .at(format!("feeds.{k}.override.proxy-name[{index}].pattern"))
                })?;
            }
            for (name, values) in &detail.headers {
                if name.trim().is_empty()
                    || values
                        .values()
                        .iter()
                        .any(|value| value.contains(['\r', '\n']))
                {
                    return Err(
                        ConfigError::invalid("订阅请求头名称不能为空，值不能包含换行")
                            .at(format!("feeds.{k}.header")),
                    );
                }
            }
            Ok((k.clone(), detail))
        })
        .collect()
}

fn validate_age_secret_keys(value: &str, location: &str) -> ConfigResult<()> {
    let mut count = 0usize;
    for line in value.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        let (hrp, key) = bech32::decode(line).map_err(|error| {
            ConfigError::invalid(format!("age 私钥 Bech32 编码无效: {error}")).at(location)
        })?;
        let supported = ["age-secret-key-", "age-secret-key-pq-"]
            .iter()
            .any(|expected| hrp.as_str().eq_ignore_ascii_case(expected));
        if !supported || key.len() != 32 {
            return Err(ConfigError::invalid(
                "仅支持 32 字节的 X25519 或 ML-KEM-768/X25519 age 私钥",
            )
            .at(location));
        }
    }
    if count == 0 {
        return Err(ConfigError::invalid("age-secret-key 不能为空").at(location));
    }
    Ok(())
}

fn validate_anytls_client_id(value: &str, location: &str) -> ConfigResult<()> {
    const SETTINGS_FIXED_LEN: usize = "v=2\nclient=\npadding-md5=".len() + 32;
    const MAX_CLIENT_ID_LEN: usize = u16::MAX as usize - SETTINGS_FIXED_LEN;

    if value.trim().is_empty() {
        return Err(ConfigError::invalid("AnyTLS clientId 不能为空").at(location));
    }
    if value.contains(['\r', '\n', '\0']) {
        return Err(ConfigError::invalid("AnyTLS clientId 不能包含换行符或 NUL").at(location));
    }
    if value.len() > MAX_CLIENT_ID_LEN {
        return Err(ConfigError::invalid(format!(
            "AnyTLS clientId 不能超过 {MAX_CLIENT_ID_LEN} 个 UTF-8 字节"
        ))
        .at(location));
    }
    Ok(())
}

fn compile_nodes(specs: &[NodeSpec]) -> ConfigResult<Vec<ParsedNode>> {
    let mut out = Vec::with_capacity(specs.len());
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        let mut node = compile_node_spec(spec)?;
        if !seen.insert(node.name.clone()) {
            // 同名节点自动追加序号
            let mut i = 2;
            loop {
                let candidate = format!("{}-{}", node.name, i);
                if seen.insert(candidate.clone()) {
                    node.name = candidate;
                    break;
                }
                i += 1;
            }
        }
        out.push(node);
    }
    validate_dialer_proxy_graph(&out)?;
    Ok(out)
}

/// Compile one native node declaration into the same normalized representation
/// used by local configuration and subscription feeds.
///
/// Keeping this conversion public prevents feed parsers from maintaining a
/// second, weaker implementation of WutherCore's structured node model.
pub fn compile_node_spec(spec: &NodeSpec) -> ConfigResult<ParsedNode> {
    let node = match spec {
        NodeSpec::Uri(uri) => parse_uri(uri),
        NodeSpec::Detail(detail) => detail_to_parsed(detail),
    }?;
    validate_young_node(&node)?;
    Ok(node)
}

fn validate_dialer_proxy_graph(nodes: &[ParsedNode]) -> ConfigResult<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let by_name = nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    for node in nodes {
        let Some(proxy) = node
            .stream_settings
            .as_ref()
            .and_then(|stream| stream.sockopt.as_ref())
            .map(|sockopt| sockopt.dialer_proxy.trim())
            .filter(|proxy| !proxy.is_empty())
        else {
            continue;
        };
        if !by_name.contains_key(proxy)
            && !matches!(proxy.to_ascii_uppercase().as_str(), "DIRECT" | "BLOCK")
        {
            return Err(ConfigError::bad_node(format!(
                "node {} 的 streamSettings.sockopt.dialerProxy 引用了不存在的 outbound `{proxy}`",
                node.name
            )));
        }
    }

    fn visit<'a>(
        name: &'a str,
        by_name: &BTreeMap<&'a str, &'a ParsedNode>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name) {
            return Err(format!("dialerProxy 检测到循环链：{name}"));
        }
        if let Some(next) = by_name
            .get(name)
            .and_then(|node| node.stream_settings.as_ref())
            .and_then(|stream| stream.sockopt.as_ref())
            .map(|sockopt| sockopt.dialer_proxy.trim())
            .filter(|next| by_name.contains_key(next))
        {
            visit(next, by_name, visiting, visited)?;
        }
        visiting.remove(name);
        visited.insert(name);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in by_name.keys().copied() {
        visit(name, &by_name, &mut visiting, &mut visited).map_err(ConfigError::bad_node)?;
    }
    Ok(())
}

fn detail_to_parsed(d: &NodeDetail) -> ConfigResult<ParsedNode> {
    let from_link = d.link.is_some();
    let mut node = if let Some(link) = &d.link {
        let mut n = parse_uri(link)?;
        n.name = d.name.clone();
        n
    } else {
        let proto = d
            .protocol
            .as_deref()
            .map(NodeProtocol::from_scheme)
            .ok_or_else(|| ConfigError::bad_node(format!("node {} 缺少 protocol", d.name)))?;
        let (host, port) = match d.address.as_deref() {
            Some(address) => parse_node_address(&d.name, address)?,
            None if proto == NodeProtocol::Wireguard && d.params.contains_key("peers") => {
                ("0.0.0.0".into(), 1)
            }
            None => {
                return Err(ConfigError::bad_node(format!(
                    "node {} 缺少 address",
                    d.name
                )));
            }
        };
        ParsedNode::new(d.name.clone(), proto, host, port)
    };

    if from_link {
        if let Some(protocol) = d.protocol.as_deref() {
            let protocol = NodeProtocol::from_scheme(protocol);
            if protocol != node.protocol {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 protocol={} 与 link 协议 {} 冲突",
                    d.name,
                    protocol.as_str(),
                    node.protocol.as_str()
                )));
            }
        }
        if let Some(address) = d.address.as_deref() {
            let (host, port) = parse_node_address(&d.name, address)?;
            node.host = host;
            node.port = port;
        }
    }
    for (key, value) in &d.params {
        let value = match value {
            serde_json::Value::String(value) => value.clone(),
            serde_json::Value::Bool(value) => value.to_string(),
            serde_json::Value::Number(value) => value.to_string(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                serde_json::to_string(value).map_err(|error| {
                    ConfigError::bad_node(format!("node {} params.{key} 无法编码: {error}", d.name))
                })?
            }
            serde_json::Value::Null => {
                return Err(ConfigError::bad_node(format!(
                    "node {} params.{key} 不能为 null",
                    d.name
                )));
            }
        };
        node.params.insert(key.clone(), value);
    }
    if let Some(login) = &d.login {
        if let Some(user) = &login.user {
            node.user = Some(user.clone());
        }
        if let Some(password) = &login.password {
            node.password = Some(password.clone());
        }
        if let Some(uuid) = &login.uuid {
            node.uuid = Some(uuid.clone());
        }
        if let Some(private_key) = &login.private_key {
            if let Some(existing) = node.params.get("private-key")
                && existing != private_key
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 login.private-key 与 params.private-key 冲突",
                    d.name
                )));
            }
            node.params
                .insert("private-key".into(), private_key.clone());
        }
    }
    if let Some(secure) = &d.secure {
        let reality_enabled = secure.reality.unwrap_or(false) || secure.reality_settings.is_some();
        if secure.reality == Some(false) && secure.reality_settings.is_some() {
            return Err(ConfigError::bad_node(format!(
                "node {} 同时禁用 reality 并提供 realitySettings",
                d.name
            )));
        }
        let tls_material = !reality_enabled
            && (secure.tls_settings.is_some()
                || secure.sni.is_some()
                || secure.fingerprint.is_some()
                || secure.utls.is_some()
                || secure.ech == Some(true));
        if secure.tls == Some(false) && tls_material {
            return Err(ConfigError::bad_node(format!(
                "node {} 显式禁用 TLS，但仍提供了 TLS/ECH 配置",
                d.name
            )));
        }
        let explicit_tls = secure.tls.unwrap_or(tls_material);
        if explicit_tls && reality_enabled {
            return Err(ConfigError::bad_node(format!(
                "node {} 不能同时启用普通 TLS 与 REALITY",
                d.name
            )));
        }
        if reality_enabled && secure.tls_settings.is_some() {
            return Err(ConfigError::bad_node(format!(
                "node {} 不能同时配置 tlsSettings 与 REALITY",
                d.name
            )));
        }

        node.tls = explicit_tls || reality_enabled;
        let mut tls_settings = secure.tls_settings.clone().unwrap_or_default();
        if !reality_enabled && let Some(sni) = &secure.sni {
            if tls_settings
                .server_name
                .as_ref()
                .is_some_and(|nested| nested != sni)
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 secure.sni 与 secure.tls-settings.serverName 冲突",
                    d.name
                )));
            }
            tls_settings.server_name = Some(sni.clone());
            node.sni = Some(sni.clone());
        } else if !reality_enabled && let Some(server_name) = tls_settings.server_name.clone() {
            node.sni = Some(server_name);
        }
        if let (Some(fingerprint), Some(utls)) = (&secure.fingerprint, &secure.utls)
            && !fingerprint.eq_ignore_ascii_case(utls)
        {
            return Err(ConfigError::bad_node(format!(
                "node {} 的 secure.fingerprint 与 secure.utls 冲突",
                d.name
            )));
        }
        if !reality_enabled && let Some(fingerprint) = &secure.fingerprint {
            if tls_settings
                .fingerprint
                .as_ref()
                .is_some_and(|nested| !nested.eq_ignore_ascii_case(fingerprint))
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 secure.fingerprint 与 secure.tls-settings.fingerprint 冲突",
                    d.name
                )));
            }
            tls_settings.fingerprint = Some(fingerprint.clone());
            node.params
                .insert("fingerprint".into(), fingerprint.clone());
        }
        if !reality_enabled && let Some(utls) = &secure.utls {
            if tls_settings
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| !fingerprint.eq_ignore_ascii_case(utls))
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 secure.utls 与 TLS fingerprint 冲突",
                    d.name
                )));
            }
            tls_settings.fingerprint = Some(utls.clone());
            node.params.insert("utls".into(), utls.clone());
        }
        if let Some(ech) = secure.ech {
            if ech && reality_enabled {
                return Err(ConfigError::bad_node(format!(
                    "node {} 不能同时启用 ECH 与 REALITY",
                    d.name
                )));
            }
            if ech && tls_settings.ech_config_list.is_none() {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 secure.ech=true 必须同时提供 tlsSettings.echConfigList",
                    d.name
                )));
            }
            if !ech && tls_settings.ech_config_list.is_some() {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 secure.ech=false 与 tlsSettings.echConfigList 冲突",
                    d.name
                )));
            }
            if ech {
                node.params.insert("ech".into(), "true".into());
            }
        }

        if reality_enabled {
            let mut reality = secure.reality_settings.clone().ok_or_else(|| {
                ConfigError::bad_node(format!(
                    "node {} 启用了 reality 但缺少 realitySettings",
                    d.name
                ))
            })?;
            if let Some(sni) = &secure.sni {
                if !reality.server_name.is_empty() && &reality.server_name != sni {
                    return Err(ConfigError::bad_node(format!(
                        "node {} 的 secure.sni 与 realitySettings.serverName 冲突",
                        d.name
                    )));
                }
                reality.server_name = sni.clone();
            }
            if let Some(fingerprint) = secure.fingerprint.as_ref().or(secure.utls.as_ref()) {
                if !reality.fingerprint.is_empty()
                    && !reality.fingerprint.eq_ignore_ascii_case(fingerprint)
                    && !reality.fingerprint.eq_ignore_ascii_case("chrome")
                {
                    return Err(ConfigError::bad_node(format!(
                        "node {} 的 secure fingerprint/utls 与 realitySettings.fingerprint 冲突",
                        d.name
                    )));
                }
                reality.fingerprint = fingerprint.clone();
            }
            validate_reality_client_settings(&reality)
                .map_err(|error| error.at(format!("nodes.{}.secure.realitySettings", d.name)))?;
            node.sni = Some(reality.server_name.clone());
            node.params.insert("reality".into(), "true".into());
            node.params.insert("security".into(), "reality".into());
            node.reality_settings = Some(xhttp_reality_settings(&reality));
            node.reality = Some(reality);
        } else {
            if secure.reality == Some(false) {
                node.params.insert("reality".into(), "false".into());
                if node.params.get("security").map(String::as_str) == Some("reality") {
                    node.params.remove("security");
                }
            }
            if secure.tls_settings.is_some()
                || secure.sni.is_some()
                || secure.fingerprint.is_some()
                || secure.utls.is_some()
            {
                tls_settings.validate().map_err(|error| {
                    ConfigError::bad_node(format!("node {} TLS 配置非法: {error}", d.name))
                })?;
                node.tls_settings = Some(tls_settings);
            }
        }
    }
    if let Some(transport) = &d.transport {
        if let Some(kind) = transport.kind.as_deref() {
            if kind.trim().is_empty() {
                return Err(ConfigError::bad_node(format!(
                    "node {} transport.kind 不能为空",
                    d.name
                )));
            }
            node.transport = kind.to_string();
        }
        if let Some(host) = &transport.host {
            node.transport_host = Some(host.clone());
            node.params.insert("host".into(), host.clone());
        }
        if let Some(path) = &transport.path {
            node.transport_path = Some(path.clone());
            node.params.insert("path".into(), path.clone());
        }
        if let Some(service) = &transport.service {
            node.transport_service = Some(service.clone());
            node.params.insert("serviceName".into(), service.clone());
        }
        if let Some(xhttp) = &transport.xhttp {
            if let Some(kind) = transport.kind.as_deref() {
                if !matches!(kind.to_ascii_lowercase().as_str(), "xhttp" | "splithttp") {
                    return Err(ConfigError::bad_node(format!(
                        "node {} 同时配置 transport.kind={} 与 xhttp",
                        d.name, kind
                    )));
                }
            }
            if let (Some(common), Some(specific)) =
                (transport.host.as_deref(), xhttp.host.as_deref())
            {
                if common != specific {
                    return Err(ConfigError::bad_node(format!(
                        "node {} transport.host 与 xhttp.host 冲突",
                        d.name
                    )));
                }
            }
            if let (Some(common), Some(specific)) =
                (transport.path.as_deref(), xhttp.path.as_deref())
            {
                if common != specific {
                    return Err(ConfigError::bad_node(format!(
                        "node {} transport.path 与 xhttp.path 冲突",
                        d.name
                    )));
                }
            }
            xhttp.validate().map_err(|error| {
                ConfigError::bad_node(format!("node {} XHTTP 配置非法: {error}", d.name))
            })?;
            node.xhttp = Some(xhttp.clone());
            node.transport = "xhttp".into();
        }
        if let Some(grpc) = transport.grpc_settings.as_ref() {
            if transport.kind.as_deref().is_some_and(|kind| {
                !kind.eq_ignore_ascii_case("grpc") && !kind.eq_ignore_ascii_case("gun")
            }) {
                return Err(ConfigError::bad_node(format!(
                    "node {} 配置了 grpcSettings，但 transport.kind 不是 grpc/gun",
                    d.name
                )));
            }
            if transport.xhttp.is_some() {
                return Err(ConfigError::bad_node(format!(
                    "node {} 不能同时配置 XHTTP 与 gRPC 传输",
                    d.name
                )));
            }
            node.transport = "grpc".into();
            insert_optional_param(&mut node, "authority", grpc.authority.as_ref())?;
            insert_optional_param(&mut node, "serviceName", grpc.service_name.as_ref())?;
            insert_optional_param(
                &mut node,
                "multiMode",
                grpc.multi_mode.as_ref().map(bool::to_string).as_ref(),
            )?;
            insert_grpc_duration_param(&mut node, "idle_timeout", grpc.idle_timeout.as_ref())?;
            insert_grpc_duration_param(
                &mut node,
                "health_check_timeout",
                grpc.health_check_timeout.as_ref(),
            )?;
            insert_optional_param(
                &mut node,
                "permit_without_stream",
                grpc.permit_without_stream
                    .as_ref()
                    .map(bool::to_string)
                    .as_ref(),
            )?;
            insert_optional_param(
                &mut node,
                "initial_windows_size",
                grpc.initial_window_size
                    .as_ref()
                    .map(u32::to_string)
                    .as_ref(),
            )?;
            if grpc
                .initial_window_size
                .is_some_and(|value| value > i32::MAX as u32)
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 gRPC initial_windows_size 超出 int32 范围",
                    d.name
                )));
            }
            insert_optional_param(&mut node, "user_agent", grpc.user_agent.as_ref())?;
            if grpc
                .max_message_size
                .is_some_and(|value| !(3..=64 * 1024 * 1024).contains(&value))
                || grpc
                    .queue_capacity
                    .is_some_and(|value| value == 0 || value > 1024)
            {
                return Err(ConfigError::bad_node(format!(
                    "node {} 的 gRPC 资源上限非法",
                    d.name
                )));
            }
            insert_optional_param(
                &mut node,
                "max_message_size",
                grpc.max_message_size
                    .as_ref()
                    .map(usize::to_string)
                    .as_ref(),
            )?;
            insert_optional_param(
                &mut node,
                "queue_capacity",
                grpc.queue_capacity.as_ref().map(usize::to_string).as_ref(),
            )?;
        }
    }
    if let Some(network) = &d.network {
        if let Some(udp) = network.udp {
            node.udp = udp;
        }
        if let Some(tfo) = network.tfo {
            node.params.insert("tfo".into(), tfo.to_string());
        }
        if let Some(mptcp) = network.mptcp {
            node.params.insert("mptcp".into(), mptcp.to_string());
        }
        if let Some(mark) = network.mark {
            node.params.insert("mark".into(), mark.to_string());
        }
        if let Some(ip_family) = &network.ip_family {
            node.params.insert("ip-family".into(), ip_family.clone());
        }
    }
    apply_stream_settings(&mut node, &d.name, d.stream_settings.as_ref())?;
    Ok(node)
}

fn xhttp_reality_settings(settings: &RealityClientSettings) -> XhttpDownloadRealitySettings {
    XhttpDownloadRealitySettings {
        master_key_log: settings.master_key_log.clone(),
        show: Some(settings.show),
        server_name: Some(settings.server_name.clone()),
        password: settings.password.clone(),
        public_key: settings.public_key.clone(),
        short_id: Some(settings.short_id.clone()),
        fingerprint: Some(settings.fingerprint.clone()),
        mldsa65_verify: settings.mldsa65_verify.clone(),
        spider_x: Some(settings.spider_x.clone()),
        ..XhttpDownloadRealitySettings::default()
    }
}

fn parse_node_address(name: &str, address: &str) -> ConfigResult<(String, u16)> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| ConfigError::bad_node(format!("node {name} address 缺少端口: {address}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ConfigError::bad_node(format!("node {name} 端口非法: {port}")))?;
    Ok((
        host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port,
    ))
}

fn insert_optional_param(
    node: &mut ParsedNode,
    key: &str,
    value: Option<&String>,
) -> ConfigResult<()> {
    if let Some(value) = value {
        if let Some(existing) = node.params.get(key)
            && existing != value
        {
            return Err(ConfigError::bad_node(format!(
                "node {} 的 transport.{key} 配置冲突：`{existing}` 与 `{value}`",
                node.name
            )));
        }
        node.params.insert(key.to_string(), value.clone());
    }
    Ok(())
}

fn validate_reality_listener_stream_settings(
    settings: Option<&NodeStreamSettings>,
    path: &str,
) -> ConfigResult<()> {
    use crate::stream_settings::{AddressPortStrategy, DomainStrategy};

    let Some(settings) = settings else {
        return Ok(());
    };
    if let Some(network) = settings.network.as_deref()
        && !network.is_empty()
        && !network.eq_ignore_ascii_case("tcp")
        && !network.eq_ignore_ascii_case("raw")
    {
        return Err(ConfigError::invalid(format!(
            "{path}.streamSettings.network 必须是 tcp/raw，实际为 `{network}`"
        )));
    }
    validate_stream_settings(path, settings).map_err(|error| {
        ConfigError::invalid(format!("{path}.streamSettings 配置无效: {error}"))
    })?;

    if let Some(finalmask) = settings.finalmask.as_ref()
        && (!finalmask.udp.is_empty() || finalmask.quic_params.is_some())
    {
        return Err(ConfigError::invalid(format!(
            "{path}.streamSettings 的 UDP finalmask/quicParams 不能用于 TCP REALITY 监听"
        )));
    }
    if let Some(sockopt) = settings.sockopt.as_ref()
        && (!matches!(sockopt.domain_strategy, DomainStrategy::AsIs)
            || !sockopt.dialer_proxy.trim().is_empty()
            || sockopt.penetrate
            || !matches!(sockopt.address_port_strategy, AddressPortStrategy::None)
            || sockopt.happy_eyeballs != Default::default()
            || !sockopt.trusted_x_forwarded_for.is_empty())
    {
        return Err(ConfigError::invalid(format!(
            "{path}.streamSettings.sockopt 包含 REALITY 入站无法执行的出站拨号/HTTP 字段"
        )));
    }
    Ok(())
}

fn insert_grpc_duration_param(
    node: &mut ParsedNode,
    key: &str,
    value: Option<&CompatDuration>,
) -> ConfigResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let duration = value.duration();
    if duration.subsec_nanos() != 0 || duration.as_secs() > i32::MAX as u64 {
        return Err(ConfigError::bad_node(format!(
            "node {} 的 gRPC {key} 必须是 int32 范围内的整秒数",
            node.name
        )));
    }
    insert_optional_param(node, key, Some(&duration.as_secs().to_string()))
}

fn validate_xhttp_listener_stream_settings(
    settings: Option<&NodeStreamSettings>,
    uses_http3: bool,
    path: &str,
) -> ConfigResult<()> {
    use crate::stream_settings::{AddressPortStrategy, DomainStrategy};

    let Some(settings) = settings else {
        return Ok(());
    };
    if let Some(network) = settings.network.as_deref()
        && !network.is_empty()
        && !network.eq_ignore_ascii_case("xhttp")
        && !network.eq_ignore_ascii_case("splithttp")
    {
        return Err(ConfigError::invalid(format!(
            "{path}.streamSettings.network 必须是 xhttp/splithttp，实际为 `{network}`"
        )));
    }
    // Reuse the canonical mask and platform validation so listener and node
    // configurations cannot drift on fragment ranges, XMC credentials, XDNS,
    // QUIC limits or platform-specific socket options.
    validate_stream_settings(path, settings).map_err(|error| {
        ConfigError::invalid(format!("{path}.streamSettings 配置无效: {error}"))
    })?;

    if let Some(sockopt) = settings.sockopt.as_ref() {
        let outbound_only = !matches!(sockopt.domain_strategy, DomainStrategy::AsIs)
            || !sockopt.dialer_proxy.trim().is_empty()
            || sockopt.penetrate
            || !matches!(sockopt.address_port_strategy, AddressPortStrategy::None)
            || sockopt.happy_eyeballs != Default::default();
        if outbound_only {
            return Err(ConfigError::invalid(format!(
                "{path}.streamSettings.sockopt 包含仅出站拨号可执行的 domainStrategy/dialerProxy/penetrate/addressPortStrategy/happyEyeballs"
            )));
        }
        if uses_http3
            && (sockopt.tcp_fast_open.is_some()
                || sockopt.tcp_keep_alive_interval != 0
                || sockopt.tcp_keep_alive_idle != 0
                || !sockopt.tcp_congestion.is_empty()
                || sockopt.tcp_window_clamp != 0
                || sockopt.tcp_user_timeout != 0
                || sockopt.tcp_max_seg != 0
                || sockopt.tcp_mptcp
                || sockopt.accept_proxy_protocol)
        {
            return Err(ConfigError::invalid(format!(
                "{path}.streamSettings.sockopt 的 TCP/PROXY 字段不能用于 H3 UDP 监听"
            )));
        }
    }

    if let Some(finalmask) = settings.finalmask.as_ref() {
        if uses_http3 {
            if !finalmask.tcp.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "{path}.streamSettings.finalmask.tcp 不能用于 H3 UDP 监听"
                )));
            }
            if finalmask
                .quic_params
                .as_ref()
                .is_some_and(|params| match &params.udp_hop.ports {
                    crate::stream_settings::PortListValue::Empty => false,
                    crate::stream_settings::PortListValue::Text(value) => !value.trim().is_empty(),
                    crate::stream_settings::PortListValue::Number(_) => true,
                })
            {
                return Err(ConfigError::invalid(format!(
                    "{path}.streamSettings.finalmask.quicParams.udpHop 只改变客户端目标端口，不能在服务端监听中执行"
                )));
            }
        } else if !finalmask.udp.is_empty() || finalmask.quic_params.is_some() {
            return Err(ConfigError::invalid(format!(
                "{path}.streamSettings 的 UDP finalmask/quicParams 不能用于 TCP XHTTP 监听"
            )));
        }
    }
    Ok(())
}

fn apply_stream_settings(
    node: &mut ParsedNode,
    node_name: &str,
    stream: Option<&crate::stream_settings::NodeStreamSettings>,
) -> ConfigResult<()> {
    if let Some(stream) = stream {
        if let Some(network) = stream.network.as_deref() {
            node.transport = match network.to_ascii_lowercase().as_str() {
                "raw" | "tcp" => "tcp".to_string(),
                other => other.to_string(),
            };
        }
        validate_stream_settings(node_name, stream)?;
        node.stream_settings = Some(stream.clone());
    }
    Ok(())
}

fn validate_stream_settings(
    node_name: &str,
    stream: &crate::stream_settings::NodeStreamSettings,
) -> ConfigResult<()> {
    use crate::stream_settings::{TcpMaskConfig, UdpMaskConfig};

    if let Some(sockopt) = &stream.sockopt {
        for (index, name) in sockopt.trusted_x_forwarded_for.iter().enumerate() {
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ConfigError::bad_node(format!(
                    "node {node_name} trustedXForwardedFor[{index}] 不是合法 HTTP 请求头名称：{error}"
                ))
            })?;
        }
        if sockopt
            .tcp_keep_alive_idle
            .saturating_mul(sockopt.tcp_keep_alive_interval)
            < 0
        {
            return Err(ConfigError::bad_node(format!(
                "node {node_name} tcpKeepAliveIdle 与 tcpKeepAliveInterval 必须同时启用或同时禁用"
            )));
        }
        for custom in &sockopt.custom_sockopt {
            if custom.opt.is_empty() {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} customSockopt.opt 不能为空"
                )));
            }
            if !matches!(custom.value_type.as_str(), "int" | "str") {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} customSockopt.type 仅支持 int 或 str"
                )));
            }
            #[cfg(target_os = "windows")]
            if custom.value_type == "str"
                && (custom.system.is_empty() || custom.system.eq_ignore_ascii_case("windows"))
            {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} 在 Windows 上不支持字符串 customSockopt；配置不会被静默忽略"
                )));
            }
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "ios"
        )))]
        if !sockopt.interface.is_empty() {
            return Err(ConfigError::bad_node(format!(
                "node {node_name} 在当前平台不支持 sockopt.interface；配置不会被静默忽略"
            )));
        }

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
        if sockopt.mark != 0 {
            return Err(ConfigError::bad_node(format!(
                "node {node_name} 在当前平台不支持 sockopt.mark；配置不会被静默忽略"
            )));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        if sockopt.tcp_mptcp {
            return Err(ConfigError::bad_node(format!(
                "node {node_name} 在当前平台不支持 tcpMptcp；配置不会被静默忽略"
            )));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        if sockopt.tcp_window_clamp > 0
            || sockopt.tcp_user_timeout > 0
            || sockopt.tcp_max_seg > 0
            || !sockopt.tcp_congestion.is_empty()
        {
            return Err(ConfigError::bad_node(format!(
                "node {node_name} 配置了当前平台不支持的 Linux TCP 选项（congestion/window/user-timeout/MSS）"
            )));
        }
    }

    if let Some(finalmask) = &stream.finalmask {
        for mask in &finalmask.tcp {
            match mask {
                TcpMaskConfig::Fragment(cfg) => {
                    let packets = cfg.packets.trim();
                    if !packets.is_empty() && !packets.eq_ignore_ascii_case("tlshello") {
                        let valid = packets
                            .parse::<i64>()
                            .ok()
                            .map(|value| value != 0)
                            .unwrap_or_else(|| {
                                packets
                                    .split_once('-')
                                    .and_then(|(from, to)| {
                                        Some((
                                            from.trim().parse::<i64>().ok()?,
                                            to.trim().parse::<i64>().ok()?,
                                        ))
                                    })
                                    .is_some_and(|(from, _)| from != 0)
                            });
                        if !valid {
                            return Err(ConfigError::bad_node(format!(
                                "node {node_name} fragment.packets 必须是 tlshello、非零整数或整数范围"
                            )));
                        }
                    }
                    let lengths = if cfg.lengths.is_empty() {
                        std::slice::from_ref(&cfg.length)
                    } else {
                        cfg.lengths.as_slice()
                    };
                    if lengths.last().is_none_or(|range| range.from == 0) {
                        return Err(ConfigError::bad_node(format!(
                            "node {node_name} fragment 最后一个 lengths 项的最小值不能为 0"
                        )));
                    }
                }
                TcpMaskConfig::Xmc(cfg) if cfg.password.is_empty() => {
                    return Err(ConfigError::bad_node(format!(
                        "node {node_name} xmc.password 不能为空"
                    )));
                }
                _ => {}
            }
        }
        for mask in &finalmask.udp {
            if let UdpMaskConfig::Xdns(cfg) = mask {
                if cfg.domain.is_some() {
                    return Err(ConfigError::bad_node(format!(
                        "node {node_name} finalmask.xdns.domain 已被 Xray 26.7.11 移除；请分别使用 domains（服务端）和 resolvers（客户端）"
                    )));
                }
                if cfg.domains.is_empty() && cfg.resolvers.is_empty() {
                    return Err(ConfigError::bad_node(format!(
                        "node {node_name} xdns.domains 与 resolvers 不能同时为空"
                    )));
                }
                if let Some(resolver) = cfg
                    .resolvers
                    .iter()
                    .find(|resolver| !resolver.contains("+udp://"))
                {
                    return Err(ConfigError::bad_node(format!(
                        "node {node_name} xdns resolver `{resolver}` 缺少 +udp://"
                    )));
                }
            }
        }
        if let Some(quic) = &finalmask.quic_params {
            let profile = quic.bbr_profile.to_ascii_lowercase();
            if !matches!(
                profile.as_str(),
                "" | "conservative" | "standard" | "aggressive"
            ) {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.bbrProfile 非法"
                )));
            }
            let congestion = quic.congestion.to_ascii_lowercase();
            if !matches!(
                congestion.as_str(),
                "" | "brutal" | "force-brutal" | "reno" | "bbr"
            ) {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.congestion 非法"
                )));
            }
            for (field, value) in [
                ("initStreamReceiveWindow", quic.init_stream_receive_window),
                ("maxStreamReceiveWindow", quic.max_stream_receive_window),
                (
                    "initConnectionReceiveWindow",
                    quic.init_connection_receive_window,
                ),
                (
                    "maxConnectionReceiveWindow",
                    quic.max_connection_receive_window,
                ),
            ] {
                if value > 0 && value < 16_384 {
                    return Err(ConfigError::bad_node(format!(
                        "node {node_name} quicParams.{field} 至少为 16384"
                    )));
                }
            }
            if quic.max_idle_timeout != 0 && !(4..=120).contains(&quic.max_idle_timeout) {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.maxIdleTimeout 必须在 4..=120"
                )));
            }
            if quic.keep_alive_period != 0 && !(2..=60).contains(&quic.keep_alive_period) {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.keepAlivePeriod 必须在 2..=60"
                )));
            }
            if quic.max_incoming_streams != 0 && quic.max_incoming_streams < 8 {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.maxIncomingStreams 至少为 8"
                )));
            }
            if (quic.udp_hop.interval.from != 0 && quic.udp_hop.interval.from < 5)
                || (quic.udp_hop.interval.to != 0 && quic.udp_hop.interval.to < 5)
            {
                return Err(ConfigError::bad_node(format!(
                    "node {node_name} quicParams.udpHop.interval 的非零值至少为 5"
                )));
            }
        }
    }
    Ok(())
}

fn compile_groups(
    cfg: &UserConfig,
    nodes: &[ParsedNode],
) -> ConfigResult<BTreeMap<String, GroupPlan>> {
    let mut out = BTreeMap::new();
    let valid_feeds: std::collections::HashSet<&str> =
        cfg.feeds.keys().map(|s| s.as_str()).collect();
    let valid_groups: std::collections::HashSet<&str> =
        cfg.groups.keys().map(|s| s.as_str()).collect();
    for (name, g) in &cfg.groups {
        if g.interval < Duration::from_secs(1) {
            return Err(
                ConfigError::invalid(format!("groups.{name}.interval 必须至少为 1s"))
                    .at(format!("groups.{name}.interval")),
            );
        }
        if g.idle_timeout < g.interval {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.idle-timeout 不能小于 interval"
            ))
            .at(format!("groups.{name}.idle-timeout")));
        }
        if g.max_failed_times == 0 {
            return Err(
                ConfigError::invalid(format!("groups.{name}.max-failed-times 必须大于 0"))
                    .at(format!("groups.{name}.max-failed-times")),
            );
        }
        if g.max_members != 0 && g.max_members < g.min_members {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.max-members 不能小于 min-members"
            ))
            .at(format!("groups.{name}.max-members")));
        }
        if g.weights.values().any(|weight| *weight == 0) {
            return Err(
                ConfigError::invalid(format!("groups.{name}.weights 的权重必须大于 0"))
                    .at(format!("groups.{name}.weights")),
            );
        }
        if let Some(check) = g.check.as_deref() {
            let parsed = url::Url::parse(check).map_err(|error| {
                ConfigError::invalid(format!("groups.{name}.check URL 非法: {error}"))
                    .at(format!("groups.{name}.check"))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(ConfigError::invalid(format!(
                    "groups.{name}.check 只支持带主机名的 http/https URL"
                ))
                .at(format!("groups.{name}.check")));
            }
        }
        validate_group_expected_status(&g.expected_status).map_err(|message| {
            ConfigError::invalid(format!("groups.{name}.expected-status: {message}"))
                .at(format!("groups.{name}.expected-status"))
        })?;
        if g.choose == ChooseStrategy::Spread
            && !matches!(
                g.strategy.as_str(),
                "consistent-hashing"
                    | "consistent_hashing"
                    | "round-robin"
                    | "round_robin"
                    | "sticky-sessions"
                    | "sticky_sessions"
            )
        {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.strategy 不支持 `{}`",
                g.strategy
            ))
            .at(format!("groups.{name}.strategy"))
            .hint("可用值: consistent-hashing、round-robin、sticky-sessions"));
        }
        if let Some(sticky) = g.sticky.as_deref()
            && !matches!(sticky, "off" | "site" | "session")
        {
            return Err(
                ConfigError::invalid(format!("groups.{name}.sticky 不支持 `{sticky}`"))
                    .at(format!("groups.{name}.sticky"))
                    .hint("可用值: off、site、session"),
            );
        }
        if g.choose == ChooseStrategy::Chain {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.choose = chain 尚未实现多跳 relay"
            ))
            .at(format!("groups.{name}.choose"))
            .hint(
                "请改用 manual / smart / fast / stable / spread / random / weighted；\
                     多跳链路实现前不会静默退化为单跳",
            ));
        }
        let include_nodes = compile_group_globs(name, "include-nodes", &g.include_nodes)?;
        let exclude_nodes = compile_group_globs(name, "exclude-nodes", &g.exclude_nodes)?;
        let include_providers =
            compile_group_globs(name, "include-providers", &g.include_providers)?;
        let exclude_providers =
            compile_group_globs(name, "exclude-providers", &g.exclude_providers)?;
        let include_groups = compile_group_globs(name, "include-groups", &g.include_groups)?;
        let exclude_groups = compile_group_globs(name, "exclude-groups", &g.exclude_groups)?;
        for pattern in g.weights.keys() {
            compile_group_globs(name, "weights", std::slice::from_ref(pattern))?;
        }

        let mut members = IndexSet::new();
        for src in g.proxies.iter().chain(&g.r#use) {
            if src == "nodes" {
                for n in nodes {
                    members.insert(n.name.clone());
                }
                continue;
            }
            if valid_feeds.contains(src.as_str()) {
                // feeds 节点在运行时按需展开（订阅刷新），这里只做引用记录。
                members.insert(format!("feed:{src}"));
                continue;
            }
            // manual 分流策略组可以引用其它组。典型结构是：
            // 分流策略组 -> 地区节点组 -> provider/static nodes。
            if valid_groups.contains(src.as_str()) {
                members.insert(src.clone());
                continue;
            }
            // 也允许直接引用具体节点名
            if nodes.iter().any(|n| &n.name == src) {
                members.insert(src.clone());
                continue;
            }
            let valid: Vec<String> = valid_feeds
                .iter()
                .map(|s| s.to_string())
                .chain(valid_groups.iter().map(|s| s.to_string()))
                .chain(std::iter::once("nodes".into()))
                .collect();
            return Err(
                ConfigError::unknown_ref(format!("groups.{name}.use 引用了 \"{src}\""))
                    .at(format!("groups.{name}"))
                    .hint(format!(
                        "可用来源只有 {} 或具体的 node 名",
                        valid.join(", ")
                    )),
            );
        }

        let include_all_nodes = g.include_all || g.include_all_proxies;
        let include_all_providers = g.include_all || g.include_all_providers;
        let mut sorted_nodes: Vec<&ParsedNode> = nodes.iter().collect();
        sorted_nodes.sort_by(|left, right| left.name.cmp(&right.name));
        for node in sorted_nodes {
            if (include_all_nodes || include_nodes.is_match(&node.name))
                && !exclude_nodes.is_match(&node.name)
            {
                members.insert(node.name.clone());
            }
        }
        for provider in cfg.feeds.keys() {
            if (include_all_providers || include_providers.is_match(provider))
                && !exclude_providers.is_match(provider)
            {
                members.insert(format!("feed:{provider}"));
            }
        }
        for group_name in cfg.groups.keys() {
            if group_name != name
                && include_groups.is_match(group_name)
                && !exclude_groups.is_match(group_name)
            {
                members.insert(group_name.clone());
            }
        }
        members.retain(|member| {
            if let Some(provider) = member.strip_prefix("feed:") {
                return !exclude_providers.is_match(provider);
            }
            if valid_groups.contains(member.as_str()) {
                return !exclude_groups.is_match(member);
            }
            !exclude_nodes.is_match(member)
        });
        let members: Vec<String> = members.into_iter().collect();

        if !g.default_selected.is_empty() && !members.contains(&g.default_selected) {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.default-selected `{}` 不在编译后的成员中",
                g.default_selected
            ))
            .at(format!("groups.{name}.default-selected")));
        }
        if valid_groups.contains(g.empty_fallback.as_str()) {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.empty-fallback 不能引用另一个策略组"
            ))
            .at(format!("groups.{name}.empty-fallback")));
        }
        let fallback_is_known = matches!(
            g.empty_fallback.to_ascii_uppercase().as_str(),
            "DIRECT" | "BLOCK" | "REJECT"
        ) || nodes.iter().any(|node| node.name == g.empty_fallback);
        if !fallback_is_known {
            return Err(ConfigError::unknown_ref(format!(
                "groups.{name}.empty-fallback 引用了未知 outbound `{}`",
                g.empty_fallback
            ))
            .at(format!("groups.{name}.empty-fallback")));
        }
        out.insert(
            name.clone(),
            GroupPlan {
                name: name.clone(),
                choose: g.choose,
                members,
                min_members: g.min_members,
                max_members: g.max_members,
                default_selected: g.default_selected.clone(),
                empty_fallback: g.empty_fallback.clone(),
                lazy: g.lazy,
                weights: g.weights.clone(),
                prefer: g.prefer.clone(),
                avoid: g.avoid.clone(),
                check: g.check.clone(),
                expected_status: g.expected_status.clone(),
                interval: g.interval,
                idle_timeout: g.idle_timeout,
                tolerance: g.tolerance,
                unified_delay: g.unified_delay,
                strategy: g.strategy.clone(),
                filter: g.filter.clone(),
                exclude_filter: g.exclude_filter.clone(),
                exclude_type: g.exclude_type.clone(),
                max_failed_times: g.max_failed_times,
                test_timeout: g.test_timeout,
                disable_udp: g.disable_udp,
                sticky: g.sticky.clone(),
                path: g.path.clone(),
                hidden: g.hidden,
                icon: normalize_group_icon(&g.icon).map_err(|message| {
                    ConfigError::invalid(format!("groups.{name}.icon: {message}"))
                        .at(format!("groups.{name}.icon"))
                })?,
            },
        );
    }
    validate_group_graph(&out)?;
    Ok(out)
}

fn compile_group_globs(group: &str, field: &str, patterns: &[String]) -> ConfigResult<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|error| {
            ConfigError::invalid(format!(
                "groups.{group}.{field} glob `{pattern}` 非法: {error}"
            ))
            .at(format!("groups.{group}.{field}"))
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|error| {
        ConfigError::invalid(format!("groups.{group}.{field} 编译失败: {error}"))
            .at(format!("groups.{group}.{field}"))
    })
}

fn validate_group_graph(groups: &BTreeMap<String, GroupPlan>) -> ConfigResult<()> {
    let mut graph = DiGraphMap::<&str, ()>::new();
    for name in groups.keys() {
        graph.add_node(name);
    }
    for (name, group) in groups {
        for member in &group.members {
            if groups.contains_key(member) {
                graph.add_edge(name, member, ());
            }
        }
    }
    if let Err(cycle) = toposort(&graph, None) {
        let start = cycle.node_id();
        let cycle_path = graph
            .neighbors(start)
            .find_map(|child| {
                if child == start {
                    return Some(vec![start, start]);
                }
                astar(&graph, child, |node| node == start, |_| 1usize, |_| 0usize).map(
                    |(_, path)| {
                        let mut cycle = Vec::with_capacity(path.len() + 1);
                        cycle.push(start);
                        cycle.extend(path);
                        cycle
                    },
                )
            })
            .unwrap_or_else(|| vec![start, start]);
        return Err(ConfigError::invalid(format!(
            "策略组存在循环引用: {}",
            cycle_path.join(" -> ")
        ))
        .at(format!("groups.{start}.use"))
        .hint("分流策略组可以引用节点组，但下级组不能反向引用上层组"));
    }

    for (name, group) in groups {
        let nested_groups: Vec<&str> = group
            .members
            .iter()
            .filter_map(|member| groups.contains_key(member).then_some(member.as_str()))
            .collect();
        if !nested_groups.is_empty() && group.choose != ChooseStrategy::Manual {
            return Err(ConfigError::invalid(format!(
                "groups.{name} 引用了下级策略组，但 choose 不是 manual"
            ))
            .at(format!("groups.{name}.choose"))
            .hint("上层分流策略组请使用 manual；smart、fast、stable、spread 节点组应直接引用订阅或节点"));
        }
    }
    Ok(())
}

fn validate_group_expected_status(expression: &str) -> Result<(), String> {
    let expression = expression.trim();
    if expression.is_empty() || expression == "*" {
        return Ok(());
    }
    for part in expression.split('/') {
        let part = part.trim();
        if part.is_empty() {
            return Err("存在空状态码片段".into());
        }
        let (start, end) = if let Some((start, end)) = part.split_once('-') {
            let start = start
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("非法状态码 `{part}`"))?;
            let end = end
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("非法状态码 `{part}`"))?;
            (start, end)
        } else {
            let status = part
                .parse::<u16>()
                .map_err(|_| format!("非法状态码 `{part}`"))?;
            (status, status)
        };
        if start < 100 || end > 599 || start > end {
            return Err(format!(
                "状态码范围 `{part}` 必须位于 100..=599 且起点不大于终点"
            ));
        }
    }
    Ok(())
}

const MAX_INLINE_GROUP_ICON_BYTES: usize = 8 * 1024 * 1024;

fn normalize_group_icon(icon: &str) -> Result<String, String> {
    use base64::engine::general_purpose;

    let icon = icon.trim();
    if icon.is_empty() {
        return Ok(String::new());
    }

    if icon.starts_with("data:") {
        let (header, payload) = icon
            .split_once(',')
            .ok_or_else(|| "data URI 缺少逗号分隔的 Base64 内容".to_string())?;
        if !header.starts_with("data:image/") || !header.ends_with(";base64") {
            return Err("只接受 data:image/<type>;base64,<payload> 图像".into());
        }
        let bytes = decode_group_icon_base64(payload)
            .ok_or_else(|| "data URI 包含无效的 Base64".to_string())?;
        return canonical_group_icon_data_uri(bytes, &general_purpose::STANDARD);
    }

    let explicit = icon.strip_prefix("base64:");
    if let Some(payload) = explicit {
        let bytes = decode_group_icon_base64(payload)
            .ok_or_else(|| "base64: 后的内容不是有效 Base64".to_string())?;
        return canonical_group_icon_data_uri(bytes, &general_purpose::STANDARD);
    }

    // 原始 Base64 只有在解码后确实是已知图像时才视作内联图标。普通 URL、
    // 文件路径和 dashboard 自定义标识原样保留。
    if icon.len() >= 24
        && icon.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-' | b'=')
        })
        && let Some(bytes) = decode_group_icon_base64(icon)
        && infer_group_icon_mime(&bytes).is_some()
    {
        return canonical_group_icon_data_uri(bytes, &general_purpose::STANDARD);
    }

    Ok(icon.to_string())
}

fn canonical_group_icon_data_uri(
    bytes: Vec<u8>,
    encoder: &base64::engine::GeneralPurpose,
) -> Result<String, String> {
    use base64::Engine as _;

    if bytes.len() > MAX_INLINE_GROUP_ICON_BYTES {
        return Err(format!(
            "内联图标解码后为 {} bytes，最大允许 {} bytes",
            bytes.len(),
            MAX_INLINE_GROUP_ICON_BYTES
        ));
    }
    let mime = infer_group_icon_mime(&bytes)
        .ok_or_else(|| "Base64 内容不是 PNG、JPEG、GIF、WebP、SVG、ICO 或 BMP 图像".to_string())?;
    Ok(format!("data:{mime};base64,{}", encoder.encode(bytes)))
}

fn decode_group_icon_base64(value: &str) -> Option<Vec<u8>> {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    };

    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(compact.as_bytes()).ok())
}

fn infer_group_icon_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.starts_with(&[0, 0, 1, 0]) {
        return Some("image/x-icon");
    }
    if bytes.starts_with(b"BM") {
        return Some("image/bmp");
    }
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with("<svg") || (trimmed.starts_with("<?xml") && trimmed.contains("<svg")) {
        return Some("image/svg+xml");
    }
    None
}

fn compile_route(
    route: Route,
    groups: &BTreeMap<String, GroupPlan>,
    sets: BTreeMap<String, RuleSetSpec>,
) -> ConfigResult<RoutePlan> {
    let preset = if route.preset.is_empty() {
        "cn_smart".to_string()
    } else {
        route.preset
    };
    let mut steps = Vec::new();
    let sub_rule_names = route.sub_rules.keys().cloned().collect::<HashSet<_>>();

    let final_target = route.r#final.clone();
    if !groups.contains_key(&final_target) && final_target != "direct" && final_target != "block" {
        return Err(ConfigError::bad_route(format!(
            "route.final = \"{final_target}\" 未定义为分组"
        ))
        .hint("把 final 改为已有分组名，或新增 groups.<name>"));
    }

    let fallback = match preset.as_str() {
        "cn_smart" => {
            steps.push(rs(
                RouteMatcher::Home,
                RouteAction::Direct,
                "preset:cn_smart home",
            ));
            steps.push(rs(
                RouteMatcher::Cn,
                RouteAction::Direct,
                "preset:cn_smart cn",
            ));
            Some(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:cn_smart any",
            ))
        }
        "global" => {
            steps.push(rs(
                RouteMatcher::Home,
                RouteAction::Direct,
                "preset:global home",
            ));
            Some(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:global any",
            ))
        }
        "direct" => Some(rs(
            RouteMatcher::Any,
            RouteAction::Direct,
            "preset:direct any",
        )),
        "privacy" => {
            steps.push(rs(
                RouteMatcher::Home,
                RouteAction::Direct,
                "preset:privacy home",
            ));
            Some(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:privacy any",
            ))
        }
        "custom" => None,
        other => {
            return Err(ConfigError::bad_route(format!("未知 preset: {other}"))
                .hint("可选 preset: cn_smart / global / direct / privacy / custom"));
        }
    };

    for entry in &route.steps {
        let entry_steps = match entry {
            RouteStepEntry::Line(s) => parse_step_line(s, groups, &sub_rule_names, &final_target)?,
            RouteStepEntry::Object(obj) => compile_object(obj, groups, &final_target)?,
        };
        steps.extend(entry_steps);
    }

    let mut sub_rules = BTreeMap::new();
    for (name, entries) in &route.sub_rules {
        if name.trim().is_empty() {
            return Err(ConfigError::bad_route("sub-rules 名称不能为空"));
        }
        let mut compiled = Vec::new();
        for entry in entries {
            let entry_steps = match entry {
                RouteStepEntry::Line(line) => {
                    parse_step_line(line, groups, &sub_rule_names, &final_target)
                        .map_err(|error| error.at(format!("sub-rules.{name}")))?
                }
                RouteStepEntry::Object(object) => compile_object(object, groups, &final_target)
                    .map_err(|error| error.at(format!("sub-rules.{name}")))?,
            };
            compiled.extend(entry_steps);
        }
        sub_rules.insert(name.clone(), compiled);
    }
    validate_sub_rule_graph(&sub_rules)?;

    if !steps.iter().any(|s| matches!(s.matcher, RouteMatcher::Any)) {
        steps.push(fallback.unwrap_or_else(|| {
            rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "auto-fallback",
            )
        }));
    }

    Ok(RoutePlan {
        preset,
        r#final: final_target,
        steps,
        sub_rules,
        sets,
    })
}

fn rs(matcher: RouteMatcher, action: RouteAction, src: &str) -> RouteStep {
    RouteStep {
        matcher,
        action,
        source: src.into(),
        options: RouteRuleOptions::default(),
    }
}

fn parse_step_line(
    line: &str,
    groups: &BTreeMap<String, GroupPlan>,
    sub_rules: &HashSet<String>,
    final_target: &str,
) -> ConfigResult<Vec<RouteStep>> {
    // mihomo classical 字符串：`TYPE,VALUE[,POLICY[,no-resolve]]`，policy 内嵌而非
    // 用 `->` 显式分隔。这里在调用 `split_once("->")` 之前先尝试识别：若整行不含
    // `->` 且首段是已知的 classical TYPE，把它就地改写成 `TYPE,VALUE -> POLICY` 形式
    // 复用统一的左/右两段拆分逻辑。
    if !line.contains("->") {
        if let Some((rewritten, options)) = try_classical_to_dsl(line) {
            let mut steps = parse_step_line(&rewritten, groups, sub_rules, final_target)?;
            for step in &mut steps {
                step.options = options;
                step.source = line.into();
            }
            return Ok(steps);
        }
        return Err(
            ConfigError::bad_route(format!("规则缺少 -> : {line}")).hint(
                "使用 `<左侧> -> <分组|direct|block>`，或 mihomo classical `TYPE,VALUE,POLICY`",
            ),
        );
    }

    let (lhs, rhs) = line
        .split_once("->")
        .ok_or_else(|| ConfigError::bad_route(format!("规则缺少 -> : {line}")))?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    let options = classical_rule_options(lhs);

    // 共享 LHS 解析（DSL `port:53` / classical `DST-PORT,53` / 别名 `sni:foo`...）。
    // 与 `compile_object` 的 `match` 字段同源，避免两套语法漂移。
    let matchers = parse_match_lhs(lhs)?;

    let is_sub_rule = lhs
        .split(',')
        .next()
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("SUB-RULE"));
    let action = if is_sub_rule {
        if !sub_rules.contains(rhs) {
            return Err(
                ConfigError::bad_route(format!("SUB-RULE 引用了未定义的 sub-rules.{rhs}"))
                    .at(format!("steps: {line}")),
            );
        }
        RouteAction::SubRule(rhs.into())
    } else {
        resolve_action(rhs, groups, final_target).map_err(|e| e.at(format!("steps: {line}")))?
    };

    Ok(matchers
        .into_iter()
        .map(|matcher| RouteStep {
            matcher,
            action: action.clone(),
            source: line.into(),
            options,
        })
        .collect())
}

fn validate_sub_rule_graph(sub_rules: &BTreeMap<String, Vec<RouteStep>>) -> ConfigResult<()> {
    fn visit(
        name: &str,
        sub_rules: &BTreeMap<String, Vec<RouteStep>>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> ConfigResult<()> {
        if visited.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_owned()) {
            return Err(ConfigError::bad_route(format!(
                "sub-rules 存在循环引用，回到 `{name}`"
            )));
        }
        if let Some(steps) = sub_rules.get(name) {
            for step in steps {
                if let RouteAction::SubRule(target) = &step.action {
                    visit(target, sub_rules, visiting, visited)?;
                }
            }
        }
        visiting.remove(name);
        visited.insert(name.to_owned());
        Ok(())
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for name in sub_rules.keys() {
        visit(name, sub_rules, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn split_values(raw: &str) -> Vec<&str> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// 把 `direct` / `block` / `<group_name>` 等 RHS 字符串解析成 [`RouteAction`]。
/// 抽出来给 `parse_step_line` 与 `compile_object` 共享。
fn resolve_action(
    rhs: &str,
    groups: &BTreeMap<String, GroupPlan>,
    final_target: &str,
) -> ConfigResult<RouteAction> {
    match rhs {
        value if value.eq_ignore_ascii_case("direct") => Ok(RouteAction::Direct),
        value
            if value.eq_ignore_ascii_case("block")
                || value.eq_ignore_ascii_case("reject")
                || value.eq_ignore_ascii_case("reject-drop") =>
        {
            Ok(RouteAction::Block)
        }
        value if value.eq_ignore_ascii_case("pass") => Ok(RouteAction::Pass),
        value if value.eq_ignore_ascii_case("pass-rule") => Ok(RouteAction::PassRule),
        // 兜底 final 时允许引用 `main` 作为分组名占位（preset 会自动注入）
        "main" if !groups.contains_key("main") && final_target == "main" => {
            Ok(RouteAction::Group("main".into()))
        }
        name if groups.contains_key(name) => Ok(RouteAction::Group(name.into())),
        other => Err(
            ConfigError::bad_route(format!("规则右侧引用未定义 group: {other}"))
                .hint("把右侧改为已存在的分组、direct 或 block"),
        ),
    }
}

/// typed-key object 形式编译入口 —— 直接产出 [`RouteStep`]，不绕 DSL string。
///
/// **语义**：
/// - 同字段列表值（`port: [53, 5353]`）→ [`RouteMatcher::Or`]，短路求值
/// - 不同字段同时设置 → [`RouteMatcher::And`]，短路求值
/// - 单字段单值 → 直接对应单个 [`RouteMatcher`]
/// - 没有任何匹配字段 → 报错（防止打错字段名导致空规则静默通过）
///
/// 性能上相比"展开成多条独立 RouteStep"的优势：
/// `{port: [53, 5353], outbound: X}` 只产生 1 条 RouteStep，引擎遍历步表时
/// 只调用一次 `step_matches`，由 `Or` 内部短路决定结果——避免在步表上 N 次线性扫描。
fn compile_object(
    obj: &RouteStepObject,
    groups: &BTreeMap<String, GroupPlan>,
    final_target: &str,
) -> ConfigResult<Vec<RouteStep>> {
    let action = resolve_action(obj.outbound.trim(), groups, final_target)
        .map_err(|e| e.at(format!("steps: object → {}", obj.outbound)))?;

    let source = format_object_source(obj);
    let mut clauses: Vec<RouteMatcher> = Vec::new();
    let mut inline_options = RouteRuleOptions::default();

    if let Some(m_str) = &obj.r#match {
        // 复用已有的 classical / DSL 解析路径；`match` 字段允许写 `DST-PORT,53`
        // 也可以是 `port:53`、`domain:foo.com` 等 WutherCore DSL（此处不带箭头）。
        inline_options = classical_rule_options(m_str);
        clauses.extend(parse_match_lhs(m_str.trim())?);
    }
    if let Some(v) = &obj.domain {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Domain(s.into()))
        })?);
    }
    if let Some(v) = &obj.suffix {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Suffix(s.into()))
        })?);
    }
    if let Some(v) = &obj.keyword {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Keyword(s.into()))
        })?);
    }
    if let Some(v) = &obj.regex {
        clauses.push(matcher_from_values(v, |s| {
            validate_mihomo_domain_regex(s)?;
            Ok(RouteMatcher::DomainRegex(s.into()))
        })?);
    }
    if let Some(v) = &obj.ip {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Cidr(normalize_classical_cidr(s)?))
        })?);
    }
    if let Some(v) = &obj.source_ip {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::SrcCidr(normalize_classical_cidr(s)?))
        })?);
    }
    if let Some(v) = &obj.port {
        // port 字段单独处理：值字符串里可能有 `1000-2000` 区间，要分流到 PortRange。
        clauses.push(matcher_from_values(v, |s| parse_classical_port(s))?);
    }
    if let Some(v) = &obj.source_port {
        clauses.push(matcher_from_values(v, parse_classical_source_port)?);
    }
    if let Some(v) = &obj.process {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Process(s.into()))
        })?);
    }
    if let Some(v) = &obj.process_path {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::ProcessPath(s.into()))
        })?);
    }
    if let Some(v) = &obj.set {
        clauses.push(matcher_from_values(v, |s| Ok(RouteMatcher::Set(s.into())))?);
    }
    if let Some(s) = &obj.network {
        clauses.push(RouteMatcher::Network(s.clone()));
    }
    if let Some(s) = &obj.proto {
        clauses.push(RouteMatcher::Proto(s.clone()));
    }

    if clauses.is_empty() {
        return Err(ConfigError::bad_route(format!(
            "规则对象缺少匹配字段: outbound={}",
            obj.outbound
        ))
        .hint("加上 `match`/`domain`/`suffix`/`keyword`/`regex`/`ip`/`source-ip`/`port`/`source-port`/`process`/`process-path`/`set`/`network`/`proto` 之一"));
    }

    let final_matcher = if clauses.len() == 1 {
        clauses.into_iter().next().unwrap()
    } else {
        RouteMatcher::And(clauses)
    };

    Ok(vec![RouteStep {
        matcher: final_matcher,
        action,
        source,
        options: RouteRuleOptions {
            no_resolve: obj.no_resolve || inline_options.no_resolve,
            no_log: obj.no_log || inline_options.no_log,
            no_track: obj.no_track || inline_options.no_track,
        },
    }])
}

/// `MatcherValue` → 单个 matcher 或 `Or(...)` 包裹的多个。
/// `build` 闭包负责把单个字符串值变成 `RouteMatcher`，便于 port 这种值需要再解析的字段复用。
fn matcher_from_values<F>(v: &MatcherValue, build: F) -> ConfigResult<RouteMatcher>
where
    F: Fn(&str) -> ConfigResult<RouteMatcher>,
{
    let raws = v.to_vec();
    if raws.is_empty() {
        return Err(ConfigError::bad_route("规则字段值为空列表").hint("至少给一个值"));
    }
    let mut built = Vec::with_capacity(raws.len());
    for raw in &raws {
        built.push(build(raw.trim())?);
    }
    Ok(if built.len() == 1 {
        built.into_iter().next().unwrap()
    } else {
        RouteMatcher::Or(built)
    })
}

/// LHS-only 解析：`parse_step_line` 要拆 `->`，本函数只处理左侧（DSL 或 classical）。
/// 抽出来给 `compile_object` 的 `match` 字段复用。
fn parse_match_lhs(lhs: &str) -> ConfigResult<Vec<RouteMatcher>> {
    Ok(match lhs {
        "home" => vec![RouteMatcher::Home],
        "cn" => vec![RouteMatcher::Cn],
        "ads" => vec![RouteMatcher::Ads],
        "any" | "*" | "final" | "default" => vec![RouteMatcher::Any],
        s if s.starts_with("domain:") => split_values(&s[7..])
            .into_iter()
            .map(|v| RouteMatcher::Domain(v.into()))
            .collect(),
        s if s.starts_with("domain-suffix:") => split_values(&s[14..])
            .into_iter()
            .map(|v| RouteMatcher::Suffix(v.into()))
            .collect(),
        s if s.starts_with("domain-regex:") => split_values(&s[13..])
            .into_iter()
            .map(|v| {
                validate_mihomo_domain_regex(v)?;
                Ok(RouteMatcher::DomainRegex(v.into()))
            })
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("domain-keyword:") => split_values(&s[15..])
            .into_iter()
            .map(|v| RouteMatcher::Keyword(v.into()))
            .collect(),
        s if s.starts_with("keyword:") => split_values(&s[8..])
            .into_iter()
            .map(|v| RouteMatcher::Keyword(v.into()))
            .collect(),
        s if s.starts_with("domain-wildcard:") => split_values(&s[16..])
            .into_iter()
            .map(|v| {
                validate_wildcard(v, "DOMAIN-WILDCARD")?;
                Ok(RouteMatcher::DomainWildcard(v.into()))
            })
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("suffix:") => split_values(&s[7..])
            .into_iter()
            .map(|v| RouteMatcher::Suffix(v.into()))
            .collect(),
        s if s.starts_with("ip:") => split_values(&s[3..])
            .into_iter()
            .map(|v| normalize_classical_cidr(v).map(RouteMatcher::Cidr))
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("source-ip:") => split_values(&s[10..])
            .into_iter()
            .map(|v| normalize_classical_cidr(v).map(RouteMatcher::SrcCidr))
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("src-ip:") => split_values(&s[7..])
            .into_iter()
            .map(|v| normalize_classical_cidr(v).map(RouteMatcher::SrcCidr))
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("src-ip-cidr:") => split_values(&s[12..])
            .into_iter()
            .map(|v| normalize_classical_cidr(v).map(RouteMatcher::SrcCidr))
            .collect::<ConfigResult<Vec<_>>>()?,
        s if s.starts_with("port:") => {
            vec![parse_classical_port(s[5..].trim())?]
        }
        s if s.starts_with("source-port:") => {
            vec![parse_classical_source_port(s[12..].trim())?]
        }
        s if s.starts_with("src-port:") => {
            vec![parse_classical_source_port(s[9..].trim())?]
        }
        s if s.starts_with("network:") => split_values(&s[8..])
            .into_iter()
            .map(|v| RouteMatcher::Network(v.into()))
            .collect(),
        s if s.starts_with("process:") => split_values(&s[8..])
            .into_iter()
            .map(|v| RouteMatcher::Process(v.into()))
            .collect(),
        s if s.starts_with("process-path:") => split_values(&s[13..])
            .into_iter()
            .map(|v| RouteMatcher::ProcessPath(v.into()))
            .collect(),
        s if s.starts_with("set:") => split_values(&s[4..])
            .into_iter()
            .map(|v| RouteMatcher::Set(v.into()))
            .collect(),
        s if s.starts_with("proto:") => split_values(&s[6..])
            .into_iter()
            .map(|v| RouteMatcher::Proto(v.into()))
            .collect(),
        s if s.starts_with("sni:") => split_values(&s[4..])
            .into_iter()
            .map(|v| RouteMatcher::Suffix(v.into()))
            .collect(),
        s if is_classical_lhs(s) => parse_classical_lhs(s)?,
        "telegram" | "youtube" | "netflix" | "github" | "apple" | "google" => {
            vec![RouteMatcher::Service(lhs.into())]
        }
        other => vec![RouteMatcher::Service(other.into())],
    })
}

/// 给 [`RouteStep::source`] 用的人类可读摘要，标出哪些字段被设了。
fn format_object_source(obj: &RouteStepObject) -> String {
    let mut parts = Vec::new();
    if obj.r#match.is_some() {
        parts.push("match");
    }
    if obj.domain.is_some() {
        parts.push("domain");
    }
    if obj.suffix.is_some() {
        parts.push("suffix");
    }
    if obj.keyword.is_some() {
        parts.push("keyword");
    }
    if obj.regex.is_some() {
        parts.push("regex");
    }
    if obj.ip.is_some() {
        parts.push("ip");
    }
    if obj.source_ip.is_some() {
        parts.push("source-ip");
    }
    if obj.port.is_some() {
        parts.push("port");
    }
    if obj.source_port.is_some() {
        parts.push("source-port");
    }
    if obj.process.is_some() {
        parts.push("process");
    }
    if obj.process_path.is_some() {
        parts.push("process-path");
    }
    if obj.set.is_some() {
        parts.push("set");
    }
    if obj.network.is_some() {
        parts.push("network");
    }
    if obj.proto.is_some() {
        parts.push("proto");
    }
    format!("object[{}] -> {}", parts.join("+"), obj.outbound)
}

/// mihomo classical 已知 TYPE 列表 —— 大小写敏感（mihomo 也只接受大写）。
/// 用 `&str` 数组而非 enum，是因为只在解析阶段做一次 dispatch，不需要中间表示。
const CLASSICAL_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "GEOIP",
    "SRC-GEOIP",
    "IP-ASN",
    "SRC-IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "IP-SUFFIX",
    "SRC-IP-SUFFIX",
    "SRC-PORT",
    "DST-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "DSCP",
    "UID",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-PATH-WILDCARD",
    "REMATCH-NAME",
    "NETWORK",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "SUB-RULE",
    "MATCH",
];

/// 判定一段 LHS（已 trim、已剥掉 `->` 右侧）是否是 mihomo classical 写法。
/// 只看首段是否在 [`CLASSICAL_TYPES`] 中；`MATCH` 没有 value，单独识别。
fn is_classical_lhs(s: &str) -> bool {
    if s.eq_ignore_ascii_case("MATCH") {
        return true;
    }
    let head = s.split(',').next().unwrap_or("").trim();
    CLASSICAL_TYPES.iter().any(|t| head.eq_ignore_ascii_case(t))
}

/// 解析 mihomo classical LHS（不含 `->` 与 policy）为 [`RouteMatcher`] 列表。
/// 失败返回带 hint 的 [`ConfigError`]。
fn parse_classical_lhs(lhs: &str) -> ConfigResult<Vec<RouteMatcher>> {
    parse_classical_lhs_inner(lhs, false)
}

fn parse_classical_lhs_inner(
    lhs: &str,
    preserve_no_resolve: bool,
) -> ConfigResult<Vec<RouteMatcher>> {
    if lhs.eq_ignore_ascii_case("MATCH") {
        return Ok(vec![RouteMatcher::Any]);
    }
    let parts = split_top_level_commas(lhs);
    let kind = parts.first().copied().unwrap_or("");
    let kind_uc = kind.to_ascii_uppercase();
    if kind_uc == "SUB-RULE" {
        if parts.len() != 2 {
            return Err(ConfigError::bad_route(format!(
                "SUB-RULE 必须包含一条括号包裹的条件: `{lhs}`"
            )));
        }
        let payload = strip_one_parenthesis_pair(parts[1]).ok_or_else(|| {
            ConfigError::bad_route(format!("SUB-RULE 条件需要外层括号: `{}`", parts[1]))
        })?;
        let mut matchers = parse_classical_lhs(payload)?;
        if matchers.len() != 1 {
            return Err(ConfigError::bad_route(format!(
                "SUB-RULE 条件必须编译为单个 matcher: `{payload}`"
            )));
        }
        return Ok(matchers.drain(..).collect());
    }
    if matches!(kind_uc.as_str(), "AND" | "OR" | "NOT") {
        let value = parts.get(1).copied().unwrap_or("");
        if value.is_empty() {
            return Err(ConfigError::bad_route(format!(
                "逻辑规则 `{kind_uc}` 缺少子规则: `{lhs}`"
            )));
        }
        if parts.len() != 2 {
            return Err(ConfigError::bad_route(format!(
                "逻辑规则 `{kind_uc}` 含有多余字段: `{lhs}`"
            )));
        }
        let children = parse_classical_logical_children(value)?;
        let matcher = match kind_uc.as_str() {
            "AND" if children.len() >= 2 => RouteMatcher::And(children),
            "OR" if children.len() >= 2 => RouteMatcher::Or(children),
            "NOT" if children.len() == 1 => {
                RouteMatcher::Not(Box::new(children.into_iter().next().unwrap()))
            }
            "NOT" => {
                return Err(ConfigError::bad_route("NOT 必须且只能包含一条子规则"));
            }
            _ => {
                return Err(ConfigError::bad_route(format!(
                    "{kind_uc} 至少需要两条子规则"
                )));
            }
        };
        return Ok(vec![matcher]);
    }
    let mut value_end = parts.len();
    let mut source_modifier = false;
    let mut no_resolve_modifier = false;
    while value_end > 2 {
        let option = parts[value_end - 1];
        if option.eq_ignore_ascii_case("no-resolve") {
            no_resolve_modifier = true;
            value_end -= 1;
            continue;
        }
        if option.eq_ignore_ascii_case("no-log") || option.eq_ignore_ascii_case("no-track") {
            value_end -= 1;
            continue;
        }
        if option.eq_ignore_ascii_case("src")
            && matches!(
                kind_uc.as_str(),
                "IP-CIDR" | "IP-CIDR6" | "IP-SUFFIX" | "GEOIP" | "IP-ASN" | "RULE-SET"
            )
        {
            source_modifier = true;
            value_end -= 1;
            continue;
        }
        break;
    }
    let value = parts.get(1..value_end).unwrap_or_default().join(",");
    if value.is_empty() {
        return Err(
            ConfigError::bad_route(format!("classical 规则缺少 value: `{lhs}`"))
                .hint("形如 `DOMAIN-SUFFIX,example.com` 或 `DST-PORT,53`"),
        );
    }
    for option in parts.iter().skip(value_end) {
        if option.eq_ignore_ascii_case("no-resolve")
            || option.eq_ignore_ascii_case("no-log")
            || option.eq_ignore_ascii_case("no-track")
            || (option.eq_ignore_ascii_case("src") && source_modifier)
        {
            continue;
        }
        return Err(ConfigError::bad_route(format!(
            "classical 规则 `{kind_uc}` 的附加字段 `{option}` 不受支持"
        )));
    }
    if no_resolve_modifier
        && !matches!(
            kind_uc.as_str(),
            "IP-CIDR" | "IP-CIDR6" | "IP-SUFFIX" | "GEOIP" | "IP-ASN" | "RULE-SET"
        )
    {
        return Err(ConfigError::bad_route(format!(
            "`no-resolve` 只能用于目标 IP 规则，不能用于 `{kind_uc}`"
        )));
    }
    let m = match kind_uc.as_str() {
        "DOMAIN" => RouteMatcher::Domain(value),
        "DOMAIN-SUFFIX" => RouteMatcher::Suffix(value),
        "DOMAIN-KEYWORD" => RouteMatcher::Keyword(value),
        "DOMAIN-REGEX" => {
            validate_mihomo_domain_regex(&value)?;
            RouteMatcher::DomainRegex(value)
        }
        "DOMAIN-WILDCARD" => {
            validate_wildcard(&value, "DOMAIN-WILDCARD")?;
            RouteMatcher::DomainWildcard(value)
        }
        "GEOSITE" => RouteMatcher::GeoSite(value),
        "GEOIP" if source_modifier => RouteMatcher::SrcGeoIp(value),
        "GEOIP" => RouteMatcher::GeoIp(value),
        "SRC-GEOIP" => RouteMatcher::SrcGeoIp(value),
        "IP-ASN" if source_modifier => RouteMatcher::SrcIpAsn(parse_asn(&value)?),
        "IP-ASN" => RouteMatcher::IpAsn(parse_asn(&value)?),
        "SRC-IP-ASN" => RouteMatcher::SrcIpAsn(parse_asn(&value)?),
        "IP-CIDR" | "IP-CIDR6" if source_modifier => {
            RouteMatcher::SrcCidr(normalize_classical_cidr(&value)?)
        }
        "IP-CIDR" | "IP-CIDR6" => RouteMatcher::Cidr(normalize_classical_cidr(&value)?),
        "SRC-IP-CIDR" => RouteMatcher::SrcCidr(normalize_classical_cidr(&value)?),
        "IP-SUFFIX" if source_modifier => {
            RouteMatcher::SrcIpSuffix(normalize_classical_ip_suffix(&value)?)
        }
        "IP-SUFFIX" => RouteMatcher::IpSuffix(normalize_classical_ip_suffix(&value)?),
        "SRC-IP-SUFFIX" => RouteMatcher::SrcIpSuffix(normalize_classical_ip_suffix(&value)?),
        "SRC-PORT" => parse_classical_source_port(&value)?,
        "DST-PORT" => parse_classical_port(&value)?,
        "IN-PORT" => parse_classical_in_port(&value)?,
        "IN-TYPE" => RouteMatcher::InType(value),
        "IN-USER" => RouteMatcher::InUser(value),
        "IN-NAME" => RouteMatcher::InName(value),
        "DSCP" => RouteMatcher::Dscp(parse_u8_rule_value(&value, "DSCP")?),
        "UID" => RouteMatcher::Uid(
            value
                .parse()
                .map_err(|_| ConfigError::bad_route(format!("非法 UID: `{value}`")))?,
        ),
        "PROCESS-NAME" => RouteMatcher::Process(value),
        "PROCESS-PATH" => RouteMatcher::ProcessPath(value),
        "PROCESS-NAME-REGEX" => {
            validate_regex(&value, "PROCESS-NAME-REGEX")?;
            RouteMatcher::ProcessRegex(value)
        }
        "PROCESS-PATH-REGEX" => {
            validate_regex(&value, "PROCESS-PATH-REGEX")?;
            RouteMatcher::ProcessPathRegex(value)
        }
        "PROCESS-NAME-WILDCARD" => {
            validate_wildcard(&value, "PROCESS-NAME-WILDCARD")?;
            RouteMatcher::ProcessWildcard(value)
        }
        "PROCESS-PATH-WILDCARD" => {
            validate_wildcard(&value, "PROCESS-PATH-WILDCARD")?;
            RouteMatcher::ProcessPathWildcard(value)
        }
        "REMATCH-NAME" => RouteMatcher::RematchName(value),
        "NETWORK" => RouteMatcher::Network(value),
        "RULE-SET" if source_modifier => RouteMatcher::SrcSet(value),
        "RULE-SET" => RouteMatcher::Set(value),
        other => {
            return Err(
                ConfigError::bad_route(format!("未知 classical TYPE: `{other}`"))
                    .hint("受支持的 TYPE 见 README route 章节"),
            );
        }
    };
    if preserve_no_resolve && no_resolve_modifier {
        Ok(vec![RouteMatcher::NoResolve(Box::new(m))])
    } else {
        Ok(vec![m])
    }
}

fn split_top_level_commas(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(value[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out
}

fn strip_one_parenthesis_pair(value: &str) -> Option<&str> {
    let value = value.trim();
    if !value.starts_with('(') || !value.ends_with(')') {
        return None;
    }
    let mut depth = 0usize;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 && index + ch.len_utf8() != value.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then(|| &value[1..value.len() - 1])
}

fn parse_classical_logical_children(value: &str) -> ConfigResult<Vec<RouteMatcher>> {
    let inner = strip_one_parenthesis_pair(value).ok_or_else(|| {
        ConfigError::bad_route(format!("逻辑规则需要外层括号: `{value}`"))
            .hint("例如 AND,((DOMAIN,example.com),(NETWORK,TCP))")
    })?;
    let mut children = Vec::new();
    for raw in split_top_level_commas(inner) {
        let child = strip_one_parenthesis_pair(raw)
            .ok_or_else(|| ConfigError::bad_route(format!("逻辑子规则需要括号: `{raw}`")))?;
        let parsed = parse_classical_lhs_inner(child, true)?;
        if parsed.len() != 1 {
            return Err(ConfigError::bad_route(format!(
                "逻辑子规则必须编译为单个 matcher: `{child}`"
            )));
        }
        children.push(parsed.into_iter().next().unwrap());
    }
    Ok(children)
}

fn validate_wildcard(pattern: &str, kind: &str) -> ConfigResult<()> {
    if pattern.is_empty() {
        return Err(ConfigError::bad_route(format!("{kind} 不能为空")));
    }
    if pattern.contains(['[', ']', '{', '}']) {
        return Err(ConfigError::bad_route(format!(
            "{kind} 只支持 `*` 和 `?` 通配符: `{pattern}`"
        )));
    }
    let mut builder = globset::GlobBuilder::new(pattern);
    builder
        .case_insensitive(true)
        .literal_separator(false)
        .backslash_escape(true);
    builder
        .build()
        .map(|_| ())
        .map_err(|error| ConfigError::bad_route(format!("非法 {kind} `{pattern}`: {error}")))
}

fn validate_regex(pattern: &str, kind: &str) -> ConfigResult<()> {
    regex::Regex::new(pattern)
        .map(|_| ())
        .map_err(|error| ConfigError::bad_route(format!("非法 {kind} `{pattern}`: {error}")))
}

fn parse_asn(value: &str) -> ConfigResult<u32> {
    value
        .trim()
        .trim_start_matches(|ch: char| ch == 'A' || ch == 'a')
        .trim_start_matches(|ch: char| ch == 'S' || ch == 's')
        .parse()
        .map_err(|_| ConfigError::bad_route(format!("非法 ASN: `{value}`")))
}

fn parse_u8_rule_value(value: &str, kind: &str) -> ConfigResult<u8> {
    value
        .parse()
        .map_err(|_| ConfigError::bad_route(format!("非法 {kind}: `{value}`")))
}

fn normalize_classical_cidr(value: &str) -> ConfigResult<String> {
    let value = value.trim();
    if let Ok(net) = value.parse::<ipnet::IpNet>() {
        return Ok(net.to_string());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(ip) => format!("{ip}/32"),
            IpAddr::V6(ip) => format!("{ip}/128"),
        });
    }
    Err(ConfigError::bad_route(format!("非法 IP/CIDR: `{value}`")))
}

fn normalize_classical_ip_suffix(value: &str) -> ConfigResult<String> {
    let (address, bits) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| ConfigError::bad_route(format!("IP-SUFFIX 缺少位数: `{value}`")))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ConfigError::bad_route(format!("非法 IP-SUFFIX 地址: `{value}`")))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| ConfigError::bad_route(format!("非法 IP-SUFFIX 位数: `{value}`")))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if bits > maximum {
        return Err(ConfigError::bad_route(format!(
            "IP-SUFFIX 位数超过 IPv{} 上限: `{value}`",
            if address.is_ipv4() { 4 } else { 6 }
        )));
    }
    Ok(format!("{address}/{bits}"))
}

fn validate_mihomo_domain_regex(pattern: &str) -> ConfigResult<()> {
    let mut builder = fancy_regex::RegexBuilder::new(pattern);
    builder
        .case_insensitive(true)
        .oniguruma_mode(true)
        .backtrack_limit(1_000_000)
        .delegate_size_limit(8 * 1024 * 1024);
    builder
        .build()
        .map(|_| ())
        .map_err(|error| ConfigError::bad_route(format!("非法 DOMAIN-REGEX `{pattern}`: {error}")))
}

/// 解析 `DST-PORT,53` 中的 value：单端口或 `LOW-HIGH` 闭区间。
fn parse_classical_port(value: &str) -> ConfigResult<RouteMatcher> {
    let parts = value
        .split(['/', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        return parts
            .into_iter()
            .map(parse_classical_port)
            .collect::<ConfigResult<Vec<_>>>()
            .map(RouteMatcher::Or);
    }
    if let Some((lo, hi)) = value.split_once('-') {
        let lo: u16 = lo
            .trim()
            .parse()
            .map_err(|_| ConfigError::bad_route(format!("非法端口范围下界: `{value}`")))?;
        let hi: u16 = hi
            .trim()
            .parse()
            .map_err(|_| ConfigError::bad_route(format!("非法端口范围上界: `{value}`")))?;
        if lo > hi {
            return Err(ConfigError::bad_route(format!(
                "端口范围下界大于上界: `{value}`"
            )));
        }
        Ok(RouteMatcher::PortRange(lo, hi))
    } else {
        let p: u16 = value
            .parse()
            .map_err(|_| ConfigError::bad_route(format!("非法端口: `{value}`")))?;
        Ok(RouteMatcher::Port(p))
    }
}

fn parse_classical_source_port(value: &str) -> ConfigResult<RouteMatcher> {
    Ok(map_port_matcher(parse_classical_port(value)?, true))
}

fn parse_classical_in_port(value: &str) -> ConfigResult<RouteMatcher> {
    Ok(map_in_port_matcher(parse_classical_port(value)?))
}

fn map_port_matcher(matcher: RouteMatcher, source: bool) -> RouteMatcher {
    match matcher {
        RouteMatcher::Port(port) if source => RouteMatcher::SrcPort(port),
        RouteMatcher::PortRange(lo, hi) if source => RouteMatcher::SrcPortRange(lo, hi),
        RouteMatcher::Or(parts) => RouteMatcher::Or(
            parts
                .into_iter()
                .map(|part| map_port_matcher(part, source))
                .collect(),
        ),
        matcher => matcher,
    }
}

fn map_in_port_matcher(matcher: RouteMatcher) -> RouteMatcher {
    match matcher {
        RouteMatcher::Port(port) => RouteMatcher::InPort(port),
        RouteMatcher::PortRange(lo, hi) => RouteMatcher::InPortRange(lo, hi),
        RouteMatcher::Or(parts) => {
            RouteMatcher::Or(parts.into_iter().map(map_in_port_matcher).collect())
        }
        matcher => matcher,
    }
}

/// 把 mihomo classical 三段式 `TYPE,VALUE,POLICY[,FLAG]` 改写为 WutherCore 的统一
/// 箭头形式 `TYPE,VALUE -> POLICY`。`MATCH,POLICY` 也走这条路。
///
/// 已知 flag 会写入 [`RouteRuleOptions`]。其中 `no-resolve` 会直接改变按序路由的
/// DNS 延迟解析行为；如果它出现在逻辑子规则中，还会保留为 matcher 修饰节点。
fn classical_rule_options(lhs: &str) -> RouteRuleOptions {
    let mut options = RouteRuleOptions::default();
    for option in split_top_level_commas(lhs).into_iter().skip(2) {
        if option.eq_ignore_ascii_case("no-resolve") {
            options.no_resolve = true;
        } else if option.eq_ignore_ascii_case("no-log") {
            options.no_log = true;
        } else if option.eq_ignore_ascii_case("no-track") {
            options.no_track = true;
        }
    }
    options
}

fn try_classical_to_dsl(line: &str) -> Option<(String, RouteRuleOptions)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let head = trimmed.split(',').next().unwrap_or("").trim();
    let is_classical = head.eq_ignore_ascii_case("MATCH")
        || CLASSICAL_TYPES.iter().any(|t| head.eq_ignore_ascii_case(t));
    if !is_classical {
        return None;
    }

    // 拆出 policy（最后一段或倒数第二段，取决于有无 no-resolve flag）
    let parts = split_top_level_commas(trimmed);
    let mut options = RouteRuleOptions::default();
    let (lhs_parts, policy) = if head.eq_ignore_ascii_case("MATCH") {
        // MATCH,POLICY  →  lhs=MATCH, policy=parts[1]
        if parts.len() < 2 {
            return None;
        }
        for option in parts.iter().skip(2) {
            if option.eq_ignore_ascii_case("no-log") {
                options.no_log = true;
            } else if option.eq_ignore_ascii_case("no-track") {
                options.no_track = true;
            } else {
                return None;
            }
        }
        (vec!["MATCH"], parts[1])
    } else {
        // TYPE,VALUE[,POLICY[,no-resolve]]
        if parts.len() < 3 {
            // 无 policy；object 形式或 hybrid 形式不会进这里（已带 `->`），
            // 这种纯 classical 但缺 policy 的写法属于配置错误，让外层报错。
            return None;
        }
        // 末段若是 no-resolve / src 之类的 flag，往前挪一段当 policy
        let mut policy_idx = parts.len() - 1;
        let mut source_modifier = false;
        while policy_idx > 1 {
            let option = parts[policy_idx];
            if option.eq_ignore_ascii_case("no-resolve") {
                options.no_resolve = true;
            } else if option.eq_ignore_ascii_case("no-log") {
                options.no_log = true;
            } else if option.eq_ignore_ascii_case("no-track") {
                options.no_track = true;
            } else if option.eq_ignore_ascii_case("src") {
                source_modifier = true;
            } else {
                break;
            }
            policy_idx -= 1;
        }
        let mut lhs = parts[..policy_idx].to_vec();
        if source_modifier {
            lhs.push("src");
        }
        (lhs, parts[policy_idx])
    };

    Some((format!("{} -> {}", lhs_parts.join(","), policy), options))
}

/// 非本机 API 面板暴露时必须配置 `ui.secret`，避免空 secret 的全开控制面。
fn validate_ui_secret_for_bind(listen: &ListenPlan, ui: &Ui) -> ConfigResult<()> {
    if !ui.on {
        return Ok(());
    }
    let Some(panel) = listen.panel.as_ref() else {
        return Ok(());
    };
    if is_loopback_bind_host(&panel.host) {
        return Ok(());
    }
    let secret_ok = ui
        .secret
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    if secret_ok {
        return Ok(());
    }
    Err(ConfigError::invalid(
        "管理 API 绑定了非本机地址，但 ui.secret 为空；拒绝启动以避免未鉴权控制面",
    )
    .at("ui.secret")
    .hint(
        "为 ui.secret 设置足够长的随机串，或把 listen.panel / listen.share 限制在 127.0.0.1 / ::1；\
             share: home|all 会把面板绑到 0.0.0.0",
    ))
}

fn is_loopback_bind_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

fn validate_capture_platform(c: &Capture) -> ConfigResult<()> {
    validate_capture_platform_for_os(c, std::env::consts::OS)
}

fn validate_capture_platform_for_os(c: &Capture, os: &str) -> ConfigResult<()> {
    if !c.on {
        return Ok(());
    }
    validate_capture_literals(c)?;

    if c.tun.auto_redirect {
        if !c.tun.auto_route {
            return Err(
                ConfigError::invalid("capture.tun.auto_redirect 依赖 auto_route")
                    .hint("启用 capture.tun.auto_route，或关闭 auto_redirect"),
            );
        }
        if c.method != CaptureMethod::VirtualNic {
            return Err(ConfigError::invalid(
                "capture.tun.auto_redirect 只属于 TUN 数据面，要求 capture.method=virtual_nic",
            )
            .hint("独立 TPROXY/REDIRECT 是不同入口；不要用 auto_redirect 替代"));
        }
        if os != "linux" {
            return Err(
                ConfigError::new(crate::error::ConfigErrorKind::UnsupportedPlatform(format!(
                    "capture.tun.auto_redirect 当前仅支持 root-managed Linux；当前平台为 {os}"
                )))
                .hint("关闭 auto_redirect；Android root/VpnService 数据面将在独立能力中实现"),
            );
        }
        if c.traffic != CaptureTraffic::System {
            return Err(ConfigError::invalid(
                "capture.tun.auto_redirect 当前只支持 traffic=system 的本机 TCP/UDP 数据面",
            )
            .hint("LAN/Apps 需要独立的全协议 policy-routing 过滤能力，不能仅靠 NAT return"));
        }
        if c.tun.strict_route {
            return Err(ConfigError::invalid(
                "capture.tun.auto_redirect 当前不支持 strict_route",
            )
            .hint("当前不为 ICMP/非 TCP-UDP 协议安装导流 rule，它们按已有主路由策略处理；启用 strict_route 会产生虚假的防泄漏承诺"));
        }
        if !c.tun.route_address_set.is_empty() || !c.tun.route_exclude_address_set.is_empty() {
            return Err(ConfigError::invalid(
                "auto_redirect 暂不能安全同步 route_address_set/route_exclude_address_set 的动态 IP 快照",
            )
            .hint("关闭 auto_redirect 可继续由 TUN 路由层使用动态规则集；内核 nft set 同步完成前禁止静默忽略"));
        }
        if c.tun.auto_redirect_nfqueue.is_some() {
            return Err(ConfigError::invalid(
                "auto_redirect_nfqueue 需要配套 NFQUEUE 用户态消费者，当前数据面未启用该能力",
            )
            .hint("删除 auto_redirect_nfqueue；TCP REDIRECT 与 UDP TUN 数据面不依赖 NFQUEUE"));
        }
        if c.tun.auto_redirect_input_mark.is_some()
            || c.tun.auto_redirect_reset_mark.is_some()
            || c.tun.auto_redirect_iproute2_fallback_rule_index.is_some()
        {
            return Err(ConfigError::invalid(
                "显式 auto_redirect input/reset/fallback 配置属于 NFQUEUE/mark 数据面，当前 TCP REDIRECT 后端不会消费",
            )
            .hint("删除这些保留字段；auto_redirect_output_mark 已完整用于 outbound 绕行"));
        }
        if c.tun.exclude_mptcp {
            return Err(ConfigError::invalid(
                "auto_redirect 暂不支持 exclude_mptcp 的全协议旁路语义",
            ));
        }
        if !c.exclude.process.is_empty() {
            return Err(ConfigError::invalid(
                "auto_redirect 暂不支持按进程名做内核级全协议旁路",
            ));
        }
        let has_interface_filters =
            !c.tun.include_interface.is_empty() || !c.tun.exclude_interface.is_empty();
        let has_mac_filters =
            !c.tun.include_mac_address.is_empty() || !c.tun.exclude_mac_address.is_empty();
        if has_interface_filters || has_mac_filters {
            return Err(ConfigError::invalid(
                "traffic=system auto_redirect 暂不支持 interface/MAC 过滤",
            )
            .hint("NAT 链 return 不能撤销 auto_route，禁止把 TCP 快路径过滤误当成全协议旁路"));
        }
        let has_identity_filters = !c.tun.include_uid.is_empty()
            || !c.tun.include_uid_range.is_empty()
            || !c.tun.exclude_uid.is_empty()
            || !c.tun.exclude_uid_range.is_empty()
            || !c.tun.include_gid.is_empty()
            || !c.tun.include_gid_range.is_empty()
            || !c.tun.exclude_gid.is_empty()
            || !c.tun.exclude_gid_range.is_empty()
            || !c.tun.include_android_user.is_empty()
            || !c.tun.include_package.is_empty()
            || !c.tun.exclude_package.is_empty();
        if has_identity_filters {
            return Err(ConfigError::invalid(
                "auto_redirect 身份过滤尚未具备双栈、可回滚的 policy-routing 事务",
            )
            .hint("删除 UID/GID/Android user/package 过滤；该能力会以独立提交补全"));
        }
        let rule_index = if c.tun.iproute2_rule_index == 0 {
            9000
        } else {
            c.tun.iproute2_rule_index
        };
        if rule_index < 4 {
            return Err(ConfigError::invalid(
                "auto_redirect iproute2_rule_index 必须至少为 4，才能保留 TUN 子网和 bypass 优先级",
            ));
        }
        if rule_index > MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX {
            return Err(ConfigError::invalid(format!(
                "auto_redirect iproute2_rule_index={rule_index} 必须小于 Linux main rule 优先级 32766"
            ))
            .hint("使用 4..=32765 的空闲优先级，例如默认值 9000"));
        }
        let table_index = if c.tun.iproute2_table_index == 0 {
            2022
        } else {
            c.tun.iproute2_table_index
        };
        if matches!(table_index, 253..=255) {
            return Err(ConfigError::invalid(format!(
                "auto_redirect iproute2_table_index={table_index} 是 Linux 保留路由表，不能作为 TUN 私有表"
            ))
            .hint("使用独立的自定义表号，例如默认值 2022"));
        }
        validate_auto_redirect_marks(&c.tun)?;
    }

    let ok = match c.method {
        CaptureMethod::Auto | CaptureMethod::VirtualNic => true,
        CaptureMethod::Tproxy | CaptureMethod::Redirect => os == "linux" || os == "android",
    };
    if !ok {
        return Err(
            ConfigError::new(crate::error::ConfigErrorKind::UnsupportedPlatform(format!(
                "capture.method={:?} 在当前平台 ({os}) 不支持",
                c.method
            )))
            .hint("改成 method: auto 或 method: virtual_nic"),
        );
    }
    Ok(())
}

fn validate_capture_literals(c: &Capture) -> ConfigResult<()> {
    fn cidrs(field: &str, values: &[String]) -> ConfigResult<()> {
        for (index, value) in values.iter().enumerate() {
            value.parse::<ipnet::IpNet>().map_err(|_| {
                ConfigError::invalid(format!("{field}[{index}] 不是合法的 CIDR: {value}"))
            })?;
        }
        Ok(())
    }

    fn addresses(field: &str, values: &[String]) -> ConfigResult<()> {
        for (index, value) in values.iter().enumerate() {
            if value.parse::<ipnet::Ipv4Net>().is_err() && value.parse::<ipnet::Ipv6Net>().is_err()
            {
                return Err(ConfigError::invalid(format!(
                    "{field}[{index}] 不是合法的 IPv4/IPv6 CIDR: {value}"
                )));
            }
        }
        Ok(())
    }

    fn ips(field: &str, values: &[String]) -> ConfigResult<()> {
        for (index, value) in values.iter().enumerate() {
            value.parse::<std::net::IpAddr>().map_err(|_| {
                ConfigError::invalid(format!("{field}[{index}] 不是合法的 IP 地址: {value}"))
            })?;
        }
        Ok(())
    }

    fn ranges(field: &str, values: &[String]) -> ConfigResult<()> {
        for (index, value) in values.iter().enumerate() {
            let valid = value
                .split_once(':')
                .and_then(|(start, end)| {
                    Some((start.parse::<u32>().ok()?, end.parse::<u32>().ok()?))
                })
                .is_some_and(|(start, end)| start <= end);
            if !valid {
                return Err(ConfigError::invalid(format!(
                    "{field}[{index}] 必须是 start:end 闭区间且 start <= end: {value}"
                )));
            }
        }
        Ok(())
    }

    cidrs("capture.exclude.cidr", &c.exclude.cidr)?;
    addresses("capture.tun.address", &c.tun.address)?;
    cidrs("capture.tun.route_address", &c.tun.route_address)?;
    cidrs(
        "capture.tun.route_exclude_address",
        &c.tun.route_exclude_address,
    )?;
    ips("capture.tun.loopback_address", &c.tun.loopback_address)?;
    ranges("capture.tun.include_uid_range", &c.tun.include_uid_range)?;
    ranges("capture.tun.exclude_uid_range", &c.tun.exclude_uid_range)?;
    ranges("capture.tun.include_gid_range", &c.tun.include_gid_range)?;
    ranges("capture.tun.exclude_gid_range", &c.tun.exclude_gid_range)?;
    Ok(())
}

fn validate_auto_redirect_marks(tun: &TunInboundOptions) -> ConfigResult<()> {
    fn parse(name: &str, value: Option<&str>, default: u32) -> ConfigResult<u32> {
        normalize_auto_redirect_mark(value, default)
            .ok_or_else(|| ConfigError::invalid(format!("{name} 不是合法的 u32/十六进制 mark")))
    }

    let _input = parse(
        "auto_redirect_input_mark",
        tun.auto_redirect_input_mark.as_deref(),
        DEFAULT_AUTO_REDIRECT_INPUT_MARK,
    )?;
    let _output = parse(
        "auto_redirect_output_mark",
        tun.auto_redirect_output_mark.as_deref(),
        DEFAULT_AUTO_REDIRECT_OUTPUT_MARK,
    )?;
    let _reset = parse(
        "auto_redirect_reset_mark",
        tun.auto_redirect_reset_mark.as_deref(),
        DEFAULT_AUTO_REDIRECT_RESET_MARK,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::apply_defaults;

    const TEST_ECH_CONFIG_LIST: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";

    fn base64url_bytes(byte: u8, len: usize) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![byte; len])
    }

    #[test]
    fn group_icon_accepts_and_normalizes_base64_png() {
        let icon = normalize_group_icon(
            "base64:iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        )
        .unwrap();
        assert!(icon.starts_with("data:image/png;base64,iVBOR"));
    }

    #[test]
    fn group_icon_rejects_non_image_base64() {
        let error = normalize_group_icon("base64:aGVsbG8gd29ybGQ=").unwrap_err();
        assert!(error.contains("不是 PNG"));
    }

    fn valid_reality_listener() -> RealityListen {
        serde_yaml::from_str(&format!(
            r#"
port: 2443
protocol: vless
users: [11111111-1111-1111-1111-111111111111]
target: camouflage.example:443
serverNames: [camouflage.example]
privateKey: {}
shortIds: [0123456789abcdef]
"#,
            base64url_bytes(7, 32)
        ))
        .unwrap()
    }

    fn compile_cfg(yaml: &str) -> RuntimePlan {
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        compile(cfg).unwrap()
    }

    fn auto_redirect_capture() -> Capture {
        let mut capture = Capture {
            on: true,
            method: CaptureMethod::VirtualNic,
            ..Capture::default()
        };
        capture.tun.auto_route = true;
        capture.tun.auto_redirect = true;
        capture
    }

    #[test]
    fn omitted_tun_and_empty_tun_have_identical_serde_defaults() {
        let omitted: Capture = serde_yaml::from_str("{}").unwrap();
        let empty: Capture = serde_yaml::from_str("tun: {}").unwrap();

        assert_eq!(omitted.tun.inet6, empty.tun.inet6);
        assert_eq!(omitted.tun.auto_route, empty.tun.auto_route);
        assert_eq!(
            omitted.tun.iproute2_table_index,
            empty.tun.iproute2_table_index
        );
        assert_eq!(
            omitted.tun.iproute2_rule_index,
            empty.tun.iproute2_rule_index
        );
        assert_eq!(omitted.tun.udp_timeout, empty.tun.udp_timeout);
        assert!(omitted.tun.inet6);
        assert!(omitted.tun.auto_route);
        assert_eq!(omitted.tun.iproute2_table_index, 2022);
        assert_eq!(omitted.tun.iproute2_rule_index, 9000);
        assert_eq!(omitted.tun.udp_timeout, Duration::from_secs(5 * 60));
    }

    #[test]
    fn auto_redirect_requires_auto_route() {
        let mut capture = auto_redirect_capture();
        capture.tun.auto_route = false;

        let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();

        assert!(error.to_string().contains("依赖 auto_route"));
    }

    #[test]
    fn auto_redirect_requires_virtual_nic_data_plane() {
        let mut capture = auto_redirect_capture();
        capture.method = CaptureMethod::Tproxy;

        let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();

        assert!(error.to_string().contains("method=virtual_nic"));
    }

    #[test]
    fn auto_redirect_platform_contract_is_explicit() {
        let capture = auto_redirect_capture();

        validate_capture_platform_for_os(&capture, "linux").unwrap();
        let android = validate_capture_platform_for_os(&capture, "android").unwrap_err();
        let error = validate_capture_platform_for_os(&capture, "windows").unwrap_err();

        assert!(android.to_string().contains("root-managed Linux"));
        assert!(error.to_string().contains("root-managed Linux"));
    }

    #[test]
    fn disabled_capture_ignores_dormant_auto_redirect_fields() {
        let mut capture = auto_redirect_capture();
        capture.on = false;
        capture.method = CaptureMethod::Redirect;
        capture.tun.auto_route = false;
        capture.tun.auto_redirect_nfqueue = Some(100);
        capture.tun.auto_redirect_input_mark = Some("not-a-mark".into());

        validate_capture_platform_for_os(&capture, "windows").unwrap();
    }

    #[test]
    fn auto_redirect_rejects_dynamic_route_sets_until_kernel_snapshots_exist() {
        for exclude in [false, true] {
            let mut capture = auto_redirect_capture();
            if exclude {
                capture.tun.route_exclude_address_set = vec!["geoip-private".into()];
            } else {
                capture.tun.route_address_set = vec!["geoip-proxy".into()];
            }

            let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();

            assert!(error.to_string().contains("动态 IP 快照"));
        }
    }

    #[test]
    fn auto_redirect_rejects_unowned_nfqueue_configuration() {
        let mut capture = auto_redirect_capture();
        capture.tun.auto_redirect_nfqueue = Some(100);

        let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();

        assert!(error.to_string().contains("NFQUEUE 用户态消费者"));
    }

    #[test]
    fn auto_redirect_rejects_unimplemented_cross_protocol_contracts() {
        let mut lan = auto_redirect_capture();
        lan.traffic = CaptureTraffic::Lan;
        assert!(
            validate_capture_platform_for_os(&lan, "linux")
                .unwrap_err()
                .to_string()
                .contains("traffic=system")
        );

        let mut strict = auto_redirect_capture();
        strict.tun.strict_route = true;
        assert!(
            validate_capture_platform_for_os(&strict, "linux")
                .unwrap_err()
                .to_string()
                .contains("strict_route")
        );

        let mut interface = auto_redirect_capture();
        interface.tun.exclude_interface = vec!["eth0".into()];
        assert!(
            validate_capture_platform_for_os(&interface, "linux")
                .unwrap_err()
                .to_string()
                .contains("interface/MAC")
        );

        let mut identity = auto_redirect_capture();
        identity.tun.exclude_uid = vec![1000];
        assert!(
            validate_capture_platform_for_os(&identity, "linux")
                .unwrap_err()
                .to_string()
                .contains("身份过滤")
        );
    }

    #[test]
    fn auto_redirect_rejects_reserved_mark_data_plane_fields() {
        for field in ["input", "reset", "fallback"] {
            let mut capture = auto_redirect_capture();
            match field {
                "input" => capture.tun.auto_redirect_input_mark = Some("0x2023".into()),
                "reset" => capture.tun.auto_redirect_reset_mark = Some("0x2025".into()),
                "fallback" => {
                    capture.tun.auto_redirect_iproute2_fallback_rule_index = Some(32768);
                }
                _ => unreachable!(),
            }

            assert!(
                validate_capture_platform_for_os(&capture, "linux")
                    .unwrap_err()
                    .to_string()
                    .contains("保留字段")
            );
        }
    }

    #[test]
    fn auto_redirect_rejects_linux_reserved_route_tables() {
        for table in 253..=255 {
            let mut capture = auto_redirect_capture();
            capture.tun.iproute2_table_index = table;
            let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();
            assert!(error.to_string().contains("Linux 保留路由表"));
        }
    }

    #[test]
    fn auto_redirect_rule_priority_must_precede_linux_main_rule() {
        let mut capture = auto_redirect_capture();
        capture.tun.iproute2_rule_index = MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX;
        validate_capture_platform_for_os(&capture, "linux").unwrap();

        capture.tun.iproute2_rule_index = MAX_IPROUTE2_AUTO_REDIRECT_RULE_INDEX + 1;
        let error = validate_capture_platform_for_os(&capture, "linux").unwrap_err();
        assert!(error.to_string().contains("main rule 优先级 32766"));
    }

    #[test]
    fn active_capture_literals_fail_closed() {
        let mut invalid_cidr = auto_redirect_capture();
        invalid_cidr.tun.route_address = vec!["not-a-cidr".into()];
        assert!(
            validate_capture_platform_for_os(&invalid_cidr, "linux")
                .unwrap_err()
                .to_string()
                .contains("route_address[0]")
        );

        let mut reversed_range = auto_redirect_capture();
        reversed_range.tun.include_uid_range = vec!["2000:1000".into()];
        assert!(
            validate_capture_platform_for_os(&reversed_range, "linux")
                .unwrap_err()
                .to_string()
                .contains("start <= end")
        );
    }

    #[test]
    fn auto_redirect_marks_are_parsed_and_zero_uses_defaults() {
        let mut invalid = auto_redirect_capture();
        invalid.tun.auto_redirect_output_mark = Some("0xnot-hex".into());
        assert!(
            validate_capture_platform_for_os(&invalid, "linux")
                .unwrap_err()
                .to_string()
                .contains("不是合法")
        );

        let mut zero = auto_redirect_capture();
        zero.tun.auto_redirect_output_mark = Some("0".into());
        validate_capture_platform_for_os(&zero, "linux").unwrap();
        assert_eq!(
            normalize_auto_redirect_mark(
                zero.tun.auto_redirect_output_mark.as_deref(),
                DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
            ),
            Some(DEFAULT_AUTO_REDIRECT_OUTPUT_MARK)
        );

        let mut valid = auto_redirect_capture();
        valid.tun.auto_redirect_output_mark = Some("50".into());
        validate_capture_platform_for_os(&valid, "linux").unwrap();
    }

    #[test]
    fn reality_server_all_xray_fields_survive_normalization() {
        let source: RealityListen = serde_yaml::from_str(&format!(
            r#"
host: 127.0.0.1
port: 2443
protocol: vless
users: [11111111-1111-1111-1111-111111111111]
dest: camouflage.example:443
type: tcp
show: false
masterKeyLog: none
xver: 2
serverNames: [camouflage.example, www.example.com]
privateKey: {}
minClientVer: "26.3"
maxClientVer: "26.9.1"
maxTimeDiff: 45000
shortIds: [0123456789abcdef, ""]
mldsa65Seed: {}
limitFallbackUpload:
  afterBytes: 100
  bytesPerSec: 1000
  burstBytesPerSec: 2000
limitFallbackDownload:
  afterBytes: 200
  bytesPerSec: 3000
  burstBytesPerSec: 4000
limits:
  handshakeTimeout: 11s
  targetHandshakeTimeout: 6s
  idleTimeout: 7s
  maxClientHelloRecords: 8
  maxClientHelloRecordPayload: 16000
  maxClientHelloBytes: 60000
  maxClientHelloWireBytes: 70000
  maxTargetRecords: 4
  maxTargetHandshakeBytes: 8192
  applicationBufferBytes: 65536
  maxConcurrentHandshakes: 12
"#,
            base64url_bytes(7, 32),
            base64url_bytes(8, 32),
        ))
        .unwrap();

        let normalized = compile_reality_listeners(&[source]).unwrap().remove(0);
        assert_eq!(normalized.host, "127.0.0.1");
        assert_eq!(normalized.port, 2443);
        assert_eq!(normalized.protocol, "vless");
        assert_eq!(normalized.users.len(), 1);
        assert_eq!(
            normalized.target,
            Some(RealityTarget::Address("camouflage.example:443".into()))
        );
        assert_eq!(normalized.dest, None);
        assert_eq!(normalized.target_type.as_deref(), Some("tcp"));
        assert!(!normalized.show);
        assert_eq!(normalized.master_key_log.as_deref(), Some("none"));
        assert_eq!(normalized.xver, 2);
        assert_eq!(normalized.server_names.len(), 2);
        assert_eq!(normalized.min_client_ver.as_deref(), Some("26.3.0"));
        assert_eq!(normalized.max_client_ver.as_deref(), Some("26.9.1"));
        assert_eq!(normalized.max_time_diff_ms, 45_000);
        assert_eq!(normalized.short_ids, ["0123456789abcdef", ""]);
        assert!(normalized.mldsa65_seed.is_some());
        assert_eq!(normalized.limit_fallback_upload.after_bytes, 100);
        assert_eq!(normalized.limit_fallback_upload.bytes_per_sec, 1_000);
        assert_eq!(normalized.limit_fallback_upload.burst_bytes_per_sec, 2_000);
        assert_eq!(normalized.limit_fallback_download.after_bytes, 200);
        assert_eq!(normalized.limits.handshake_timeout, Duration::from_secs(11));
        assert_eq!(
            normalized.limits.target_handshake_timeout,
            Duration::from_secs(6)
        );
        assert_eq!(normalized.limits.idle_timeout, Duration::from_secs(7));
        assert_eq!(normalized.limits.max_client_hello_records, 8);
        assert_eq!(normalized.limits.max_client_hello_record_payload, 16_000);
        assert_eq!(normalized.limits.max_client_hello_bytes, 60_000);
        assert_eq!(normalized.limits.max_client_hello_wire_bytes, 70_000);
        assert_eq!(normalized.limits.max_target_records, 4);
        assert_eq!(normalized.limits.max_target_handshake_bytes, 8_192);
        assert_eq!(normalized.limits.application_buffer_bytes, 65_536);
        assert_eq!(normalized.limits.max_concurrent_handshakes, 12);
    }

    #[test]
    fn reality_listener_stream_settings_are_preserved_and_fail_closed() {
        let mut source = valid_reality_listener();
        source.stream_settings = Some(
            serde_json::from_value(serde_json::json!({
                "network": "raw",
                "sockopt": {"acceptProxyProtocol": true},
                "finalmask": {
                    "tcp": [{"type": "sudoku", "settings": {"password": "secret"}}]
                }
            }))
            .unwrap(),
        );
        let normalized = compile_reality_listeners(&[source.clone()])
            .unwrap()
            .remove(0);
        let settings = normalized.stream_settings.expect("REALITY streamSettings");
        assert!(settings.sockopt.unwrap().accept_proxy_protocol);
        assert!(matches!(
            &settings.finalmask.unwrap().tcp[..],
            [crate::stream_settings::TcpMaskConfig::Sudoku(_)]
        ));

        source.stream_settings = Some(
            serde_json::from_value(serde_json::json!({
                "network": "raw",
                "finalmask": {"udp": [{"type": "noise"}]}
            }))
            .unwrap(),
        );
        assert!(compile_reality_listeners(&[source]).is_err());
    }

    #[test]
    fn reality_server_snake_aliases_work_and_unknown_fields_fail() {
        let source: RealityListen = serde_yaml::from_str(&format!(
            r#"
port: 2443
users: [11111111-1111-1111-1111-111111111111]
target: camouflage.example:443
target_type: tcp
server_names: [camouflage.example]
private_key: {}
min_client_ver: "26.3.27"
max_time_diff: 1000
short_ids: ["00"]
limit_fallback_upload: {{bytes_per_sec: 1}}
limits: {{max_client_hello_records: 4}}
"#,
            base64url_bytes(7, 32)
        ))
        .unwrap();
        let normalized = compile_reality_listeners(&[source]).unwrap().remove(0);
        assert_eq!(normalized.target_type.as_deref(), Some("tcp"));
        assert_eq!(normalized.max_time_diff_ms, 1_000);
        assert_eq!(normalized.limit_fallback_upload.bytes_per_sec, 1);
        assert_eq!(normalized.limits.max_client_hello_records, 4);

        let unknown = format!(
            "port: 2443\nusers: []\ntarget: a:1\nserverNames: [a]\nprivateKey: {}\nshortIds: ['']\nserverNmaes: [typo]\n",
            base64url_bytes(7, 32)
        );
        assert!(serde_yaml::from_str::<RealityListen>(&unknown).is_err());
    }

    #[test]
    fn reality_server_rejects_conflicts_dangerous_options_and_bad_bounds() {
        let valid = valid_reality_listener();

        let mut conflict = valid.clone();
        conflict.dest = Some(RealityTarget::Address("other.example:443".into()));
        assert!(compile_reality_listeners(&[conflict]).is_err());

        let mut show = valid.clone();
        show.show = true;
        assert!(compile_reality_listeners(&[show]).is_err());

        let mut key_log = valid.clone();
        key_log.master_key_log = Some("reality.keys".into());
        assert!(compile_reality_listeners(&[key_log]).is_err());

        let mut xver = valid.clone();
        xver.xver = 3;
        assert!(compile_reality_listeners(&[xver]).is_err());

        let mut versions = valid.clone();
        versions.min_client_ver = Some("27.0.0".into());
        versions.max_client_ver = Some("26.9.9".into());
        assert!(compile_reality_listeners(&[versions]).is_err());

        let mut fallback = valid.clone();
        fallback.limit_fallback_upload.after_bytes = 1;
        assert!(compile_reality_listeners(&[fallback]).is_err());

        let mut limits = valid.clone();
        limits.limits.max_client_hello_bytes = u16::MAX as usize + 1;
        assert!(compile_reality_listeners(&[limits]).is_err());

        let mut equal_seed = valid;
        equal_seed.mldsa65_seed = Some(equal_seed.private_key.clone());
        assert!(compile_reality_listeners(&[equal_seed]).is_err());
    }

    #[test]
    fn reality_client_rejects_key_alias_and_security_conflicts() {
        let key = base64url_bytes(7, 32);
        let mut settings = RealityClientSettings {
            server_name: "camouflage.example".into(),
            password: Some(key.clone()),
            short_id: "0123456789abcdef".into(),
            spider_x: "/news?p=8&c=2".into(),
            ..RealityClientSettings::default()
        };
        validate_reality_client_settings(&settings).unwrap();

        settings.public_key = Some(base64url_bytes(8, 32));
        assert!(validate_reality_client_settings(&settings).is_err());
        settings.public_key = None;
        settings.show = true;
        assert!(validate_reality_client_settings(&settings).is_err());
        settings.show = false;
        settings.master_key_log = Some("reality.keys".into());
        assert!(validate_reality_client_settings(&settings).is_err());

        let mut reality = settings;
        reality.master_key_log = None;
        let detail = NodeDetail {
            name: "reality-client".into(),
            protocol: Some("vless".into()),
            address: Some("127.0.0.1:443".into()),
            secure: Some(NodeSecure {
                fingerprint: Some("chrome".into()),
                utls: Some("firefox".into()),
                reality: Some(true),
                reality_settings: Some(reality),
                ..NodeSecure::default()
            }),
            ..NodeDetail::default()
        };
        assert!(detail_to_parsed(&detail).is_err());
    }

    #[test]
    fn reality_client_camel_and_snake_fields_deserialize_without_loss() {
        let key = base64url_bytes(7, 32);
        let verify = base64url_bytes(9, 1952);
        let settings: RealityClientSettings = serde_yaml::from_str(&format!(
            r#"
fp: chrome
server_name: camouflage.example
pbk: {key}
short-id: 0123456789abcdef
mldsa65_verify: {verify}
spiderX: /cover?p=4
show: false
master_key_log: none
"#
        ))
        .unwrap();
        validate_reality_client_settings(&settings).unwrap();
        assert_eq!(settings.fingerprint, "chrome");
        assert_eq!(settings.server_name, "camouflage.example");
        assert_eq!(settings.password.as_deref(), Some(key.as_str()));
        assert_eq!(settings.short_id, "0123456789abcdef");
        assert_eq!(settings.mldsa65_verify.as_deref(), Some(verify.as_str()));
        assert_eq!(settings.spider_x, "/cover?p=4");
        assert_eq!(settings.master_key_log.as_deref(), Some("none"));

        assert!(
            serde_yaml::from_str::<RealityClientSettings>(&format!(
                "serverName: a\npassword: {key}\nshortId: ''\nspiderX: /\npublicKye: typo\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn structured_xhttp_is_preserved_without_string_map_loss() {
        let plan = compile_cfg(&format!(
            r#"
version: 1
profile: desktop
nodes:
  - name: xhttp-full
    protocol: vless
    address: origin.example.com:443
    login:
      uuid: 11111111-1111-1111-1111-111111111111
      private_key: secret-key
    secure:
      tls: true
      sni: sni.example.com
      fingerprint: chrome
      ech: true
      tls-settings:
        enable-session-resumption: true
        pinned-peer-cert-sha256: "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"
        verify-peer-cert-by-name: "edge.example.com, 127.0.0.1"
        ech-config-list: "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA=="
    transport:
      kind: xhttp
      host: cdn.example.com
      path: /split
      service: grpc-compat
      xhttp:
        host: cdn.example.com
        path: /split
        mode: packet-up
        xPaddingBytes: 100-200
        noSSEHeader: true
        xmux:
          maxConnections: 4-8
    network:
      udp: false
      tfo: true
      mptcp: true
      mark: 123
      ip_family: ipv4
"#
        ));
        let node = &plan.nodes[0];
        assert_eq!(node.transport, "xhttp");
        assert_eq!(node.transport_host.as_deref(), Some("cdn.example.com"));
        assert_eq!(node.transport_path.as_deref(), Some("/split"));
        assert_eq!(node.transport_service.as_deref(), Some("grpc-compat"));
        assert_eq!(
            node.params.get("private-key").map(String::as_str),
            Some("secret-key")
        );
        assert_eq!(
            node.params.get("fingerprint").map(String::as_str),
            Some("chrome")
        );
        assert_ne!(
            node.params.get("security").map(String::as_str),
            Some("reality")
        );
        let tls = node.tls_settings.as_ref().unwrap();
        assert_eq!(tls.server_name.as_deref(), Some("sni.example.com"));
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(tls.enable_session_resumption, Some(true));
        assert_eq!(
            tls.verify_peer_cert_by_name.as_deref(),
            Some("edge.example.com, 127.0.0.1")
        );
        assert_eq!(
            tls.ech_config_list.as_deref(),
            Some(
                "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA=="
            )
        );
        assert_eq!(node.params.get("tfo").map(String::as_str), Some("true"));
        assert!(!node.udp);
        let xhttp = node.xhttp.as_ref().unwrap();
        assert_eq!(xhttp.mode.as_deref(), Some("packet-up"));
        assert_eq!(
            xhttp.x_padding_bytes,
            Some(crate::model::XhttpRange::new(100, 200))
        );
    }

    #[test]
    fn structured_ech_toggle_requires_executable_settings_and_rejects_conflicts() {
        let mut detail = NodeDetail {
            name: "ech-client".into(),
            protocol: Some("vless".into()),
            address: Some("127.0.0.1:443".into()),
            secure: Some(NodeSecure {
                tls: Some(true),
                ech: Some(true),
                ..NodeSecure::default()
            }),
            ..NodeDetail::default()
        };
        assert!(detail_to_parsed(&detail).is_err());

        let secure = detail.secure.as_mut().unwrap();
        secure.tls_settings = Some(XhttpDownloadTlsSettings {
            ech_config_list: Some(TEST_ECH_CONFIG_LIST.into()),
            ..XhttpDownloadTlsSettings::default()
        });
        assert!(detail_to_parsed(&detail).is_ok());

        detail.secure.as_mut().unwrap().ech = Some(false);
        assert!(detail_to_parsed(&detail).is_err());
    }

    #[test]
    fn structured_fields_explicitly_override_link() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes:
  - name: overridden
    link: "vless://11111111-1111-1111-1111-111111111111@old.example.com:443?security=tls&type=ws&host=old.example.com&path=%2Fold#old"
    protocol: vless
    address: new.example.com:8443
    login:
      uuid: 22222222-2222-2222-2222-222222222222
    secure:
      tls: false
    transport:
      kind: xhttp
      host: new-cdn.example.com
      path: /new
      xhttp:
        mode: packet-up
        noGRPCHeader: true
    network:
      udp: false
"#,
        );
        let node = &plan.nodes[0];
        assert_eq!(node.name, "overridden");
        assert_eq!(node.host, "new.example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(
            node.uuid.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert!(!node.tls);
        assert!(node.sni.is_none());
        assert_eq!(node.transport, "xhttp");
        assert_eq!(
            node.params.get("host").map(String::as_str),
            Some("new-cdn.example.com")
        );
        assert_eq!(node.params.get("path").map(String::as_str), Some("/new"));
        assert_eq!(
            node.xhttp.as_ref().and_then(|config| config.no_grpc_header),
            Some(true)
        );
        assert!(!node.udp);
    }

    #[test]
    fn link_protocol_and_duplicate_xhttp_fields_report_conflicts() {
        let mut protocol_conflict: UserConfig = serde_yaml::from_str(
            r#"
version: 1
nodes:
  - name: bad
    link: "vless://11111111-1111-1111-1111-111111111111@example.com:443"
    protocol: vmess
"#,
        )
        .unwrap();
        apply_defaults(&mut protocol_conflict);
        assert!(
            compile(protocol_conflict)
                .unwrap_err()
                .to_string()
                .contains("与 link 协议")
        );

        let mut field_conflict: UserConfig = serde_yaml::from_str(
            r#"
version: 1
nodes:
  - name: bad-xhttp
    protocol: vless
    address: example.com:443
    transport:
      kind: xhttp
      host: common.example
      xhttp:
        host: specific.example
"#,
        )
        .unwrap();
        apply_defaults(&mut field_conflict);
        assert!(
            compile(field_conflict)
                .unwrap_err()
                .to_string()
                .contains("transport.host 与 xhttp.host 冲突")
        );
    }

    #[test]
    fn xhttp_listen_single_and_array_compile_to_strict_runtime_plans() {
        let plan = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    - enabled: true
      address: 127.0.0.1
      port: 8080
      cleartext: true
      alpn: [h1, h2]
      target: {host: 127.0.0.1, port: 9000}
      tag: local-raw
      accept-queue: 384
      max-active-relays: 64
      max-active-connections: 128
      max-concurrent-streams: 32
      max-active-http-streams: 96
      http-idle-timeout: 45s
      cors-origins:
        - " https://console.example "
        - http://127.0.0.1:3000
      settings:
        path: /raw
        mode: packet-up
        xPaddingBytes: 0
    - enabled: true
      address: "::"
      port: 8443
      allow-unauthenticated-non-loopback: true
      tls:
        cert: certs/server.pem
        key: certs/server-key.pem
      alpn: [h3]
      target: {address: echo.internal, port: 9001}
      settings:
        path: /vless
        mode: stream-one
"#,
        );
        assert_eq!(plan.listen.xhttp.len(), 2);

        let tcp = &plan.listen.xhttp[0];
        assert!(tcp.enabled);
        assert!(tcp.cleartext);
        assert!(tcp.tls.is_none());
        assert_eq!(tcp.alpn, [XhttpListenAlpn::Http1, XhttpListenAlpn::H2]);
        assert_eq!(
            tcp.target.as_ref(),
            Some(&XhttpListenTargetPlan {
                host: "127.0.0.1".into(),
                port: 9000,
            })
        );
        assert_eq!(tcp.tag, "local-raw");
        assert_eq!(tcp.accept_queue, 384);
        assert!(!tcp.allow_unauthenticated_non_loopback);
        assert_eq!(tcp.max_active_relays, 64);
        assert_eq!(tcp.max_active_connections, 128);
        assert_eq!(tcp.max_concurrent_streams, 32);
        assert_eq!(tcp.max_active_http_streams, 96);
        assert_eq!(tcp.http_idle_timeout, Duration::from_secs(45));
        assert_eq!(
            tcp.cors_origins,
            Some(vec![
                "https://console.example".into(),
                "http://127.0.0.1:3000".into()
            ])
        );
        assert_eq!(tcp.settings.x_padding_bytes, Some(XhttpRange::new(0, 0)));
        assert_eq!(
            tcp.socket_addr().unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );

        let h3 = &plan.listen.xhttp[1];
        assert!(h3.uses_http3());
        assert_eq!(h3.address, "::");
        assert_eq!(h3.tag, "xhttp-2");
        assert!(h3.allow_unauthenticated_non_loopback);
        assert_eq!(h3.max_active_relays, 256);
        assert_eq!(h3.max_active_connections, 1024);
        assert_eq!(h3.max_concurrent_streams, 128);
        assert_eq!(h3.max_active_http_streams, 1024);
        assert_eq!(h3.http_idle_timeout, Duration::from_secs(90));
        assert_eq!(h3.cors_origins, None);
        assert_eq!(
            h3.target.as_ref(),
            Some(&XhttpListenTargetPlan {
                host: "echo.internal".into(),
                port: 9001,
            })
        );
        assert_eq!(
            h3.tls.as_ref().and_then(|tls| tls.cert_path.as_deref()),
            Some("certs/server.pem")
        );
        assert_eq!(h3.socket_addr().unwrap(), "[::]:8443".parse().unwrap());
    }

    #[test]
    fn xhttp_listener_stream_settings_cover_tcp_h3_and_trusted_xff() {
        let plan = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    - enabled: false
      address: 127.0.0.1
      port: 8080
      streamSettings:
        network: xhttp
        sockopt:
          acceptProxyProtocol: true
          trustedXForwardedFor: [X-Trusted-CDN]
        finalmask:
          tcp:
            - type: sudoku
              settings: {password: tcp-secret}
    - enabled: false
      address: "::1"
      port: 8443
      tls: {cert: cert.pem, key: key.pem}
      alpn: [h3]
      streamSettings:
        network: splithttp
        finalmask:
          udp:
            - type: salamander
              settings: {password: udp-secret}
          quicParams:
            congestion: reno
            maxIncomingStreams: 32
"#,
        );
        let tcp = plan.listen.xhttp[0]
            .stream_settings
            .as_ref()
            .expect("TCP listener streamSettings");
        assert_eq!(
            tcp.sockopt.as_ref().unwrap().trusted_x_forwarded_for,
            ["X-Trusted-CDN"]
        );
        assert!(matches!(
            &tcp.finalmask.as_ref().unwrap().tcp[..],
            [crate::stream_settings::TcpMaskConfig::Sudoku(_)]
        ));

        let h3 = plan.listen.xhttp[1]
            .stream_settings
            .as_ref()
            .expect("H3 listener streamSettings");
        assert!(matches!(
            &h3.finalmask.as_ref().unwrap().udp[..],
            [crate::stream_settings::UdpMaskConfig::Salamander(_)]
        ));
        assert_eq!(
            h3.finalmask
                .as_ref()
                .unwrap()
                .quic_params
                .as_ref()
                .unwrap()
                .max_incoming_streams,
            32
        );

        let mut invalid = plan.listen.xhttp[0].stream_settings.clone().unwrap();
        invalid.finalmask.as_mut().unwrap().udp =
            vec![serde_json::from_value(serde_json::json!({"type": "noise"})).unwrap()];
        assert!(validate_xhttp_listener_stream_settings(Some(&invalid), false, "test").is_err());

        invalid.finalmask.as_mut().unwrap().udp.clear();
        invalid.sockopt.as_mut().unwrap().trusted_x_forwarded_for = vec!["bad header".into()];
        assert!(validate_xhttp_listener_stream_settings(Some(&invalid), false, "test").is_err());
    }

    #[test]
    fn xhttp_listen_security_h3_and_shared_settings_are_validated() {
        fn compile_error(listener: &str) -> String {
            let yaml = format!(
                "version: 1\nprofile: server\nlisten:\n  xhttp:\n{}",
                listener
                    .lines()
                    .map(|line| format!("    {line}\n"))
                    .collect::<String>()
            );
            let mut cfg: UserConfig = serde_yaml::from_str(&yaml).unwrap();
            apply_defaults(&mut cfg);
            compile(cfg).unwrap_err().to_string()
        }

        let cases = [
            (
                "address: 127.0.0.1\nport: 8080",
                "必须设置 tls.cert/tls.key 或显式 cleartext=true",
            ),
            (
                "address: 127.0.0.1\nport: 8080\ncleartext: true\ntls: {cert: cert.pem, key: key.pem}",
                "不能同时设置",
            ),
            (
                "address: 127.0.0.1\nport: 8443\ntls: {cert: cert.pem, key: key.pem}\nalpn: [h2, h3]",
                "必须独占",
            ),
            (
                "address: 127.0.0.1\nport: 8443\ncleartext: true\nalpn: [h3]",
                "必须使用 TLS",
            ),
            (
                "address: 127.0.0.1\nport: 8443\ntls: {cert: '', key: key.pem}",
                "证书路径不能为空",
            ),
            (
                "address: 127.0.0.1\nport: 0\ncleartext: true",
                "port 不能为 0",
            ),
            (
                "address: 127.0.0.1\nport: 8080\ncleartext: true\naccept-queue: 0",
                "accept-queue 必须大于 0",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\naccept-queue: 1000001",
                "accept-queue 不能大于 1000000",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-active-relays: 0",
                "max-active-relays 必须大于 0",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-active-connections: 0",
                "max-active-connections 必须大于 0",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-active-connections: 1000001",
                "max-active-connections 不能大于 1000000",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-concurrent-streams: 0",
                "max-concurrent-streams 必须大于 0",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-concurrent-streams: 1000001",
                "max-concurrent-streams 不能大于 1000000",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-active-http-streams: 0",
                "max-active-http-streams 必须大于 0",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nmax-active-http-streams: 1000001",
                "max-active-http-streams 不能大于 1000000",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nsettings: {scMaxBufferedPosts: 1000001}",
                "scMaxBufferedPosts 不能大于 1000000",
            ),
            (
                "enabled: false\naddress: 127.0.0.1\nport: 8080\nhttp-idle-timeout: 0s",
                "http-idle-timeout 必须大于 0 秒",
            ),
            (
                "address: 127.0.0.1\nport: 8080\ncleartext: true\nsettings: {mode: unsupported}",
                "mode 不支持",
            ),
        ];
        for (yaml, expected) in cases {
            let error = compile_error(yaml);
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn xhttp_accept_queue_accepts_business_limit() {
        let plan = compile_cfg(
            r#"
version: 1
listen:
  xhttp:
    enabled: false
    address: 127.0.0.1
    port: 8080
    accept-queue: 1000000
"#,
        );
        assert_eq!(plan.listen.xhttp[0].accept_queue, XHTTP_MAX_ACCEPT_QUEUE);
    }

    #[test]
    fn disabled_xhttp_listener_may_omit_security_and_target() {
        let plan = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    enabled: false
    address: 0.0.0.0
    port: 8080
"#,
        );
        assert_eq!(plan.listen.xhttp.len(), 1);
        assert!(!plan.listen.xhttp[0].enabled);
        assert!(!plan.listen.xhttp[0].allow_unauthenticated_non_loopback);
    }

    #[test]
    fn enabled_xhttp_raw_adapter_is_fail_closed_and_requires_typed_target() {
        fn compile_error(listener: &str) -> String {
            let yaml = format!(
                "version: 1\nprofile: server\nlisten:\n  xhttp:\n{}",
                listener
                    .lines()
                    .map(|line| format!("    {line}\n"))
                    .collect::<String>()
            );
            let mut cfg: UserConfig = serde_yaml::from_str(&yaml).unwrap();
            apply_defaults(&mut cfg);
            compile(cfg).unwrap_err().to_string()
        }

        let missing = compile_error("address: 127.0.0.1\nport: 8080\ncleartext: true");
        assert!(missing.contains("target 是 enabled XHTTP Raw 适配器的必填"));

        let bad_target = compile_error(
            "address: 127.0.0.1\nport: 8080\ncleartext: true\ntarget: {host: '', port: 0}",
        );
        assert!(bad_target.contains("target.host"));
    }

    #[test]
    fn enabled_raw_non_loopback_requires_explicit_unauthenticated_opt_in() {
        let missing_opt_in = r#"
version: 1
profile: server
listen:
  xhttp:
    address: 0.0.0.0
    port: 8080
    cleartext: true
    target: {host: 127.0.0.1, port: 9000}
"#;
        let mut cfg: UserConfig = serde_yaml::from_str(missing_opt_in).unwrap();
        apply_defaults(&mut cfg);
        let error = compile(cfg).unwrap_err().to_string();
        assert!(error.contains("allow-unauthenticated-non-loopback=true"));

        let opted_in = missing_opt_in.replace(
            "    cleartext: true",
            "    cleartext: true\n    allowUnauthenticatedNonLoopback: true",
        );
        let plan = compile_cfg(&opted_in);
        let listener = &plan.listen.xhttp[0];
        assert_eq!(listener.address, "0.0.0.0");
        assert!(listener.allow_unauthenticated_non_loopback);

        let loopback = missing_opt_in.replace("0.0.0.0", "\"[::1]\"");
        let plan = compile_cfg(&loopback);
        assert_eq!(
            plan.listen.xhttp[0].socket_addr().unwrap(),
            "[::1]:8080".parse().unwrap()
        );
        assert!(!plan.listen.xhttp[0].allow_unauthenticated_non_loopback);
    }

    #[test]
    fn xhttp_cors_origins_are_normalized_and_strictly_validated() {
        let omitted = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    enabled: false
    address: 127.0.0.1
    port: 8080
"#,
        );
        assert_eq!(omitted.listen.xhttp[0].cors_origins, None);

        let disabled = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    enabled: false
    address: 127.0.0.1
    port: 8080
    cors-origins: []
"#,
        );
        assert_eq!(disabled.listen.xhttp[0].cors_origins, Some(Vec::new()));

        let wildcard = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    enabled: false
    address: 127.0.0.1
    port: 8080
    cors-origins: [" * "]
"#,
        );
        assert_eq!(
            wildcard.listen.xhttp[0].cors_origins,
            Some(vec!["*".into()])
        );

        let canonical = compile_cfg(
            r#"
version: 1
profile: server
listen:
  xhttp:
    enabled: false
    address: 127.0.0.1
    port: 8080
    cors-origins: [" HTTPS://Console.Example:443 "]
"#,
        );
        assert_eq!(
            canonical.listen.xhttp[0].cors_origins,
            Some(vec!["https://console.example".into()])
        );

        fn compile_error(cors_yaml: &str) -> String {
            let yaml = format!(
                "version: 1\nprofile: server\nlisten:\n  xhttp:\n    enabled: false\n    address: 127.0.0.1\n    port: 8080\n    cors-origins: {cors_yaml}\n"
            );
            let mut cfg: UserConfig = serde_yaml::from_str(&yaml).unwrap();
            apply_defaults(&mut cfg);
            compile(cfg).unwrap_err().to_string()
        }

        let cases = [
            ("['  ']", "不能为空"),
            ("['https://one.example', '*']", "`*` 必须是唯一项"),
            (
                "['https://one.example', ' https://one.example ']",
                "重复 origin",
            ),
            (
                "['https://ONE.example:443', 'https://one.example']",
                "重复 origin",
            ),
            ("['console.example']", "不是有效"),
            (
                "['https://one.example/path']",
                "必须是明确的 HTTP(S) origin",
            ),
            (
                "['https://例子.example']",
                "必须是不含控制字符的 ASCII origin",
            ),
            (
                r#"["https://one.example\u007f"]"#,
                "必须是不含控制字符的 ASCII origin",
            ),
            (
                r#"["\thttps://one.example"]"#,
                "必须是不含控制字符的 ASCII origin",
            ),
        ];
        for (cors, expected) in cases {
            let error = compile_error(cors);
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error} for {cors}"
            );
        }
    }

    #[test]
    fn cn_smart_preset_expanded() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
"#,
        );
        let kinds: Vec<_> = plan.route.steps.iter().map(|s| &s.matcher).collect();
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Home)));
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Cn)));
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Any)));
    }

    #[test]
    fn fixed_process_listeners_reject_dynamic_port_zero() {
        for yaml in [
            r#"
version: 1
profile: desktop
listen:
  local: 0
"#,
            r#"
version: 1
profile: desktop
listen:
  panel: 0
"#,
        ] {
            let error = crate::loader::load_from_str(yaml).unwrap_err();
            assert!(error.to_string().contains("端口不能为 0"));
        }
    }

    #[test]
    fn young_listener_compiles_with_ipv6_and_key_ring() {
        let plan = compile_cfg(&format!(
            r#"
version: 1
profile: server
listen:
  young:
    - host: "::1"
      port: 2443
      nssDatabase: data/nss
      certificateNickname: young.example
      authority: young.example
      path: /assets
      users: [{}]
"#,
            base64url_bytes(9, 32)
        ));
        assert_eq!(plan.listen.young.len(), 1);
        assert_eq!(
            plan.listen.young[0].socket_addr().unwrap(),
            "[::1]:2443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            plan.listen.young[0].padding_min,
            core_young::DEFAULT_PADDING_MIN
        );
        assert_eq!(
            plan.listen.young[0].padding_max,
            core_young::DEFAULT_PADDING_MAX
        );
        assert_eq!(
            plan.listen.young[0].padding_scheme_length,
            core_young::DEFAULT_PADDING_SCHEME_LENGTH
        );
    }

    #[test]
    fn young_listener_rejects_invalid_padding_scheme() {
        for padding in [
            "paddingMin: 0",
            "paddingMin: 513\n      paddingMax: 512",
            "paddingMax: 4097",
            "paddingSchemeLength: 0",
            "paddingSchemeLength: 257",
        ] {
            let error = crate::loader::load_from_str(&format!(
                r#"
version: 1
profile: server
listen:
  young:
    - port: 2443
      nssDatabase: data/nss
      certificateNickname: young.example
      authority: young.example
      users: [{}]
      {padding}
"#,
                base64url_bytes(9, 32)
            ))
            .unwrap_err();
            assert!(error.to_string().contains("padding"));
        }
    }

    #[test]
    fn young_listener_rejects_duplicate_keys_and_mixed_nss_databases() {
        let key = base64url_bytes(11, 32);
        let duplicate = crate::loader::load_from_str(&format!(
            r#"
version: 1
profile: server
listen:
  young:
    - port: 2443
      nssDatabase: data/nss
      certificateNickname: young.example
      authority: young.example
      users: [{key}, {key}]
"#
        ))
        .unwrap_err();
        assert!(duplicate.to_string().contains("重复 key id"));

        let mixed_databases = crate::loader::load_from_str(&format!(
            r#"
version: 1
profile: server
listen:
  young:
    - port: 2443
      nssDatabase: data/nss-a
      certificateNickname: young-a.example
      authority: young-a.example
      users: [{key}]
    - port: 2444
      nssDatabase: data/nss-b
      certificateNickname: young-b.example
      authority: young-b.example
      users: [{key}]
"#
        ))
        .unwrap_err();
        assert!(
            mixed_databases
                .to_string()
                .contains("必须使用同一个 nssDatabase")
        );
    }

    #[test]
    fn panel_address_is_validated_and_preserves_ipv6() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: not-a-socket
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("非法 listen.panel 地址"));

        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
listen:
  panel: "[::1]:9090"
"#,
        );
        assert_eq!(
            plan.listen.panel.unwrap().socket_addr().unwrap(),
            "[::1]:9090".parse().unwrap()
        );
    }

    #[test]
    fn non_loopback_panel_requires_ui_secret() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: 9090
  share: home
ui:
  on: true
"#,
        )
        .unwrap_err();
        let msg = error.to_string();
        assert!(
            msg.contains("ui.secret") || msg.contains("未鉴权"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn non_loopback_panel_with_secret_is_allowed() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
listen:
  panel: 9090
  share: home
ui:
  on: true
  secret: "test-secret-please-change"
"#,
        );
        assert_eq!(plan.listen.panel.as_ref().unwrap().host, "0.0.0.0");
        assert_eq!(plan.ui.secret.as_deref(), Some("test-secret-please-change"));
    }

    #[test]
    fn loopback_panel_allows_empty_secret() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
listen:
  panel: "127.0.0.1:9090"
  share: false
ui:
  on: true
"#,
        );
        assert!(plan.ui.secret.is_none() || plan.ui.secret.as_deref() == Some(""));
    }

    #[test]
    fn choose_chain_is_rejected_at_compile() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#A"]
groups:
  relay:
    choose: chain
    use: [nodes]
    path: [A]
route:
  preset: direct
"#,
        )
        .unwrap_err();
        let msg = error.to_string();
        assert!(
            msg.contains("chain") && msg.contains("尚未实现"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn group_sticky_rejects_unknown_scope() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
listen:
  panel: false
nodes: ["direct://0.0.0.0:0#A"]
groups:
  main:
    choose: smart
    use: [nodes]
    sticky: forever
route:
  preset: direct
"#,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("sticky") && message.contains("forever"));
    }

    #[test]
    fn custom_steps_compile() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
  ads_block:
    choose: smart
    use: [nodes]
route:
  preset: custom
  steps:
    - "home -> direct"
    - "ads -> block"
    - "domain:example.com -> direct"
    - "any -> main"
"#,
        );
        assert_eq!(plan.route.preset, "custom");
        assert!(
            plan.route
                .steps
                .iter()
                .any(|s| matches!(s.matcher, RouteMatcher::Domain(ref d) if d == "example.com"))
        );
    }

    #[test]
    fn preset_fallback_is_after_user_rules() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
  ai:
    choose: smart
    use: [nodes]
route:
  preset: cn_smart
  final: main
  steps:
    - "set:openai -> ai"
"#,
        );

        let set_pos = plan
            .route
            .steps
            .iter()
            .position(|s| matches!(s.matcher, RouteMatcher::Set(ref name) if name == "openai"))
            .unwrap();
        let any_pos = plan
            .route
            .steps
            .iter()
            .position(|s| matches!(s.matcher, RouteMatcher::Any))
            .unwrap();
        assert!(set_pos < any_pos);
    }

    #[test]
    fn route_aliases_used_by_examples_compile() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: custom
  steps:
    - "domain-suffix: lan,local,arpa -> direct"
    - "default -> main"
"#,
        );

        assert!(matches!(plan.route.steps[0].matcher, RouteMatcher::Suffix(ref s) if s == "lan"));
        assert!(matches!(plan.route.steps[1].matcher, RouteMatcher::Suffix(ref s) if s == "local"));
        assert!(matches!(plan.route.steps[2].matcher, RouteMatcher::Suffix(ref s) if s == "arpa"));
        assert!(matches!(plan.route.steps[3].matcher, RouteMatcher::Any));
    }

    /// 用户报的最直接形式：`{match: "DST-PORT,53", outbound: <group>}`。
    /// outbound 引用一个真实分组（不是直接拨 DNS_Hijack，因为本测试只校验解析路径）。
    #[test]
    fn route_step_object_form_with_dst_port_classical() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack:
    choose: smart
    use: [nodes]
  main:
    choose: smart
    use: [nodes]
route:
  preset: custom
  final: main
  steps:
    - {match: "DST-PORT,53", outbound: hijack}
    - "any -> main"
"#,
        );
        let step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::Port(53)))
            .expect("DST-PORT,53 应被解析为 Port(53)");
        assert!(matches!(step.action, RouteAction::Group(ref g) if g == "hijack"));
    }

    /// mihomo 字符串内嵌 policy 的写法 —— `"DST-PORT,53,hijack"` 也要等价生效。
    #[test]
    fn route_step_string_form_classical_inline_policy() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack:
    choose: smart
    use: [nodes]
  main:
    choose: smart
    use: [nodes]
route:
  preset: custom
  final: main
  steps:
    - "DST-PORT,53,hijack"
    - "MATCH,main"
"#,
        );
        assert!(
            plan.route
                .steps
                .iter()
                .any(|s| matches!(s.matcher, RouteMatcher::Port(53))
                    && matches!(s.action, RouteAction::Group(ref g) if g == "hijack"))
        );
    }

    /// 端口范围、关键字、IP-CIDR 三类都跑一遍，覆盖新增 matcher。
    #[test]
    fn route_step_classical_extended_kinds() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: custom
  final: main
  steps:
    - {match: "DST-PORT,1000-2000", outbound: direct}
    - {match: "DOMAIN-KEYWORD,google", outbound: main}
    - {match: "IP-CIDR,1.2.3.0/24", outbound: direct}
    - {match: "IP-CIDR,4.4.4.0/24,no-resolve", outbound: direct}
    - "MATCH,main"
"#,
        );
        let kinds: Vec<&RouteMatcher> = plan.route.steps.iter().map(|s| &s.matcher).collect();
        assert!(
            kinds
                .iter()
                .any(|m| matches!(m, RouteMatcher::PortRange(1000, 2000)))
        );
        assert!(
            kinds
                .iter()
                .any(|m| matches!(m, RouteMatcher::Keyword(k) if k == "google"))
        );
        // 两条 IP-CIDR：第二条尾部 `no-resolve` 必须保留到规则选项。
        assert_eq!(
            kinds
                .iter()
                .filter(|m| matches!(m, RouteMatcher::Cidr(_)))
                .count(),
            2
        );
        assert!(plan.route.steps.iter().any(|step| {
            matches!(&step.matcher, RouteMatcher::Cidr(c) if c == "4.4.4.0/24")
                && step.options.no_resolve
        }));
    }

    /// `no-resolve` flag 在内嵌 policy 的 string 形式里要被识别并保留。
    #[test]
    fn route_step_classical_string_form_preserves_no_resolve_flag() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: custom
  final: main
  steps:
    - "IP-CIDR,5.5.5.0/24,direct,no-resolve"
    - "MATCH,main"
"#,
        );
        let cidr = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::Cidr(ref c) if c == "5.5.5.0/24"))
            .expect("IP-CIDR with no-resolve flag 应被解析");
        assert!(matches!(cidr.action, RouteAction::Direct));
        assert!(cidr.options.no_resolve);
    }

    #[test]
    fn logical_child_preserves_no_resolve_modifier() {
        let matcher = parse_classical_lhs("AND,((IP-CIDR,1.1.1.0/24,no-resolve),(NETWORK,tcp))")
            .unwrap()
            .pop()
            .unwrap();
        let RouteMatcher::And(children) = matcher else {
            panic!("expected AND matcher");
        };
        assert!(matches!(
            &children[0],
            RouteMatcher::NoResolve(child)
                if matches!(child.as_ref(), RouteMatcher::Cidr(cidr) if cidr == "1.1.1.0/24")
        ));
        assert!(
            parse_classical_lhs("DOMAIN,example.com,no-resolve").is_err(),
            "no-resolve must be rejected for non target-IP rules"
        );
    }

    /// 用户报的最直接形式：typed-key shorthand `{port: 53, outbound: ...}`
    /// —— 不需要 mihomo classical TYPE 字符串。
    #[test]
    fn route_step_typed_key_port_shorthand() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack: {choose: smart, use: [nodes]}
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {port: 53, outbound: hijack}
    - "any -> main"
"#,
        );
        let step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::Port(53)))
            .expect("typed-key port:53 应解析为 Port(53)");
        assert!(matches!(step.action, RouteAction::Group(ref g) if g == "hijack"));
    }

    /// typed-key 字段全集冒烟 —— 每种匹配字段单独写一条，确保都解析成对应 matcher。
    #[test]
    fn route_step_typed_key_all_field_kinds() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
  ai: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  sets:
    ads: {payload: ["DOMAIN-SUFFIX,doubleclick.net"]}
  steps:
    - {domain: example.com, outbound: direct}
    - {suffix: cn, outbound: direct}
    - {keyword: google, outbound: ai}
    - {regex: "^(?!blocked\\.)api[0-9]+\\.example\\.com$", outbound: ai}
    - {ip: 10.0.0.0/8, outbound: direct}
    - {source-ip: 192.168.0.0/16, outbound: direct}
    - {port: 80, outbound: main}
    - {source-port: 1000-2000, outbound: main}
    - {process: chrome, outbound: ai}
    - {process-path: "C:\\Apps\\chrome.exe", outbound: ai}
    - {set: ads, outbound: block}
    - {network: udp, outbound: main}
    - {proto: quic, outbound: main}
    - "any -> main"
"#,
        );
        let m: Vec<&RouteMatcher> = plan.route.steps.iter().map(|s| &s.matcher).collect();
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Domain(d) if d == "example.com"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Suffix(s) if s == "cn"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Keyword(k) if k == "google"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::DomainRegex(r) if r.contains("api[0-9]+")))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Cidr(c) if c == "10.0.0.0/8"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::SrcCidr(c) if c == "192.168.0.0/16"))
        );
        assert!(m.iter().any(|x| matches!(x, RouteMatcher::Port(80))));
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::SrcPortRange(1000, 2000)))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Process(p) if p == "chrome"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::ProcessPath(p) if p == r"C:\Apps\chrome.exe"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Set(s) if s == "ads"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Network(n) if n == "udp"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Proto(p) if p == "quic"))
        );
    }

    #[test]
    fn mihomo_complete_rule_surface_and_sub_rules_compile() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  sets:
    provider: {payload: ["DOMAIN-SUFFIX,provider.example"]}
  sub-rules:
    tcp-branch:
      - "DOMAIN-SUFFIX,sub.example,DIRECT"
  steps:
    - "DOMAIN,exact.example,DIRECT"
    - "DOMAIN-SUFFIX,suffix.example,DIRECT"
    - "DOMAIN-KEYWORD,keyword,DIRECT"
    - "DOMAIN-WILDCARD,*.wild.example,DIRECT"
    - "DOMAIN-REGEX,^api[0-9]+\\.example$,DIRECT"
    - "GEOSITE,cn,DIRECT"
    - "GEOIP,CN,DIRECT"
    - "SRC-GEOIP,CN,DIRECT"
    - "IP-CIDR,10.0.0.0/8,DIRECT"
    - "SRC-IP-CIDR,192.168.0.0/16,DIRECT"
    - "IP-SUFFIX,8.8.8.8/24,DIRECT"
    - "SRC-IP-SUFFIX,192.168.1.1/16,DIRECT"
    - "IP-ASN,13335,DIRECT"
    - "SRC-IP-ASN,9808,DIRECT"
    - "DST-PORT,80/443,DIRECT"
    - "SRC-PORT,1000-2000,DIRECT"
    - "IN-PORT,7890,DIRECT"
    - "IN-TYPE,SOCKS/HTTP,DIRECT"
    - "IN-USER,user,DIRECT"
    - "IN-NAME,mixed-in,DIRECT"
    - "PROCESS-NAME,curl,DIRECT"
    - "PROCESS-PATH,/usr/bin/curl,DIRECT"
    - "PROCESS-NAME-WILDCARD,*curl*,DIRECT"
    - "PROCESS-PATH-WILDCARD,/usr/*/curl,DIRECT"
    - "PROCESS-NAME-REGEX,curl$,DIRECT"
    - "PROCESS-PATH-REGEX,.*bin/curl,DIRECT"
    - "UID,1000,DIRECT"
    - "NETWORK,udp,DIRECT"
    - "DSCP,4,DIRECT"
    - "REMATCH-NAME,dns,DIRECT"
    - "RULE-SET,provider,DIRECT"
    - "AND,((DOMAIN,logic.example),(NETWORK,TCP)),DIRECT"
    - "OR,((DST-PORT,53),(DST-PORT,853)),DIRECT"
    - "NOT,((DOMAIN,blocked.example)),DIRECT"
    - "SUB-RULE,(NETWORK,tcp),tcp-branch"
    - "MATCH,main"
"#,
        );
        assert!(plan.route.steps.len() >= 35);
        assert!(plan.route.steps.iter().any(
            |step| matches!(&step.action, RouteAction::SubRule(name) if name == "tcp-branch")
        ));
        assert_eq!(plan.route.sub_rules["tcp-branch"].len(), 1);
    }

    #[test]
    fn sub_rule_cycle_is_rejected() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  sub-rules:
    a: ["SUB-RULE,(MATCH),b"]
    b: ["SUB-RULE,(MATCH),a"]
  steps:
    - "SUB-RULE,(MATCH),a"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("循环引用"));
    }

    #[test]
    fn group_graph_compiles_ordered_sources_and_advanced_policies() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes:
  - {name: HK-1, protocol: direct, address: "127.0.0.1:1"}
  - {name: US-1, protocol: direct, address: "127.0.0.1:1"}
feeds:
  primary: https://example.invalid/provider.yaml
groups:
  香港节点:
    choose: weighted
    proxies: [HK-1]
    include-providers: [pri*]
    weights: {"HK-*": 10, "*": 1}
    empty-fallback: DIRECT
  美国节点:
    choose: random
    include-nodes: ["US-*"]
    empty-fallback: DIRECT
  人工智能:
    choose: manual
    proxies: [美国节点, 香港节点]
    default-selected: 美国节点
  全部地区:
    choose: manual
    include-groups: ["*节点"]
    exclude-groups: ["测试*"]
route:
  preset: global
  final: 人工智能
"#,
        );

        assert_eq!(
            plan.groups["人工智能"].members,
            vec!["美国节点".to_string(), "香港节点".to_string()]
        );
        assert_eq!(plan.groups["人工智能"].default_selected, "美国节点");
        assert_eq!(
            plan.groups["香港节点"].members,
            vec!["HK-1".to_string(), "feed:primary".to_string()]
        );
        assert_eq!(
            plan.groups["全部地区"].members,
            vec!["美国节点".to_string(), "香港节点".to_string()]
        );
    }

    #[test]
    fn group_graph_reports_the_actual_cycle_path() {
        let error = crate::loader::load_from_str(
            r#"
version: 1
profile: desktop
groups:
  入口: {choose: manual, proxies: [地区]}
  地区: {choose: manual, proxies: [回退]}
  回退: {choose: manual, proxies: [入口]}
route: {preset: global, final: 入口}
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("循环引用"), "{error}");
        assert!(error.contains("入口"), "{error}");
        assert!(error.contains("地区"), "{error}");
        assert!(error.contains("回退"), "{error}");
    }

    /// mihomo 友好别名（hyphen 形式）应与 canonical 等价。
    #[test]
    fn route_step_typed_key_hyphen_aliases() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack: {choose: smart, use: [nodes]}
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {dst-port: 53, outbound: hijack}
    - {domain-suffix: example.com, outbound: direct}
    - {domain-keyword: google, outbound: main}
    - {domain-regex: "^api\\.example\\.com$", outbound: main}
    - {ip-cidr: 10.0.0.0/8, outbound: direct}
    - {src-ip-cidr: 192.168.0.0/16, outbound: direct}
    - {src-port: 1024-2048, outbound: direct}
    - {process-name: chrome.exe, outbound: direct}
    - {process-path: "C:\\Apps\\chrome.exe", outbound: direct}
    - "any -> main"
"#,
        );
        let m: Vec<&RouteMatcher> = plan.route.steps.iter().map(|s| &s.matcher).collect();
        assert!(m.iter().any(|x| matches!(x, RouteMatcher::Port(53))));
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Suffix(s) if s == "example.com"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Keyword(k) if k == "google"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::DomainRegex(r) if r.contains("api")))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Cidr(c) if c == "10.0.0.0/8"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::SrcCidr(c) if c == "192.168.0.0/16"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::SrcPortRange(1024, 2048)))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Process(p) if p == "chrome.exe"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::ProcessPath(p) if p == r"C:\Apps\chrome.exe"))
        );
    }

    /// 列表值 → `Or(...)` 包装。`port: [53, 5353]` 应只产生一条 RouteStep。
    #[test]
    fn route_step_typed_key_list_value_becomes_or() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack: {choose: smart, use: [nodes]}
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {port: [53, 5353], outbound: hijack}
    - "any -> main"
"#,
        );
        let or_step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::Or(_)))
            .expect("port: [..] 应包成 Or(...)");
        if let RouteMatcher::Or(parts) = &or_step.matcher {
            assert_eq!(parts.len(), 2);
            assert!(matches!(parts[0], RouteMatcher::Port(53)));
            assert!(matches!(parts[1], RouteMatcher::Port(5353)));
        }
        assert!(matches!(or_step.action, RouteAction::Group(ref g) if g == "hijack"));
    }

    /// 多字段 → `And(...)` 包装，跨字段 AND；端口 + 协议联合命中才触发。
    #[test]
    fn route_step_typed_key_multi_field_becomes_and() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  hijack: {choose: smart, use: [nodes]}
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {port: 53, network: udp, outbound: hijack}
    - "any -> main"
"#,
        );
        let and_step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::And(_)))
            .expect("多字段 typed object 应包成 And(...)");
        if let RouteMatcher::And(parts) = &and_step.matcher {
            assert_eq!(parts.len(), 2);
            // 顺序与 compile_object 写入顺序一致：port, network
            assert!(matches!(parts[0], RouteMatcher::Port(53)));
            assert!(matches!(parts[1], RouteMatcher::Network(ref n) if n == "udp"));
        }
    }

    /// 列表 + 多字段 → `And([Or([...]), other])` 嵌套。
    #[test]
    fn route_step_typed_key_list_and_multi_field_nests_or_inside_and() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {port: [53, 5353], suffix: example.com, outbound: direct}
    - "any -> main"
"#,
        );
        let and_step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::And(_)))
            .expect("应包成 And");
        if let RouteMatcher::And(parts) = &and_step.matcher {
            // compile_object 的写入顺序：match, domain, suffix, keyword, ip, port, ...
            // 此处 suffix 在前、port 在后；不依赖具体顺序的更稳健写法是 any() 检查
            assert!(parts.iter().any(|m| matches!(m, RouteMatcher::Or(_))));
            assert!(
                parts
                    .iter()
                    .any(|m| matches!(m, RouteMatcher::Suffix(s) if s == "example.com"))
            );
        }
    }

    /// `match` 字段允许 WutherCore DSL（不只是 mihomo classical），且可以与 typed-key AND。
    #[test]
    fn route_step_typed_key_match_combines_with_typed_fields() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {match: "port:443", suffix: example.com, outbound: direct}
    - "any -> main"
"#,
        );
        let and_step = plan
            .route
            .steps
            .iter()
            .find(|s| matches!(s.matcher, RouteMatcher::And(_)))
            .expect("match + typed 应 AND 在一起");
        if let RouteMatcher::And(parts) = &and_step.matcher {
            assert_eq!(parts.len(), 2);
            assert!(matches!(parts[0], RouteMatcher::Port(443)));
            assert!(matches!(parts[1], RouteMatcher::Suffix(ref s) if s == "example.com"));
        }
    }

    /// typed-key 区间端口 —— `port: 1000-2000` 应解析成 PortRange。
    #[test]
    fn route_step_typed_key_port_range() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {port: 1000-2000, outbound: direct}
    - "any -> main"
"#,
        );
        assert!(
            plan.route
                .steps
                .iter()
                .any(|s| matches!(s.matcher, RouteMatcher::PortRange(1000, 2000)))
        );
    }

    /// 缺失匹配字段 → 报错（防止打错字段名静默通过）。
    #[test]
    fn route_step_typed_key_missing_match_errors() {
        let yaml = r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {outbound: main}
"#;
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        let err = compile(cfg).unwrap_err().to_string();
        assert!(err.contains("缺少匹配字段"), "err={err}");
    }

    #[test]
    fn route_step_classical_source_regex_and_process_path_compile() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main: {choose: smart, use: [nodes]}
route:
  preset: custom
  final: main
  steps:
    - {match: "SRC-IP-CIDR,192.168.0.0/16", outbound: direct}
    - {match: "SRC-PORT,1234-2345", outbound: main}
    - {match: "DOMAIN-REGEX,^(?!api0\\.)api[0-9]+\\.example\\.com$", outbound: main}
    - {match: "PROCESS-PATH,C:\\Apps\\browser.exe", outbound: direct}
    - "any -> main"
"#,
        );
        let matchers: Vec<&RouteMatcher> =
            plan.route.steps.iter().map(|step| &step.matcher).collect();
        assert!(
            matchers
                .iter()
                .any(|m| matches!(m, RouteMatcher::SrcCidr(c) if c == "192.168.0.0/16"))
        );
        assert!(
            matchers
                .iter()
                .any(|m| matches!(m, RouteMatcher::SrcPortRange(1234, 2345)))
        );
        assert!(
            matchers
                .iter()
                .any(|m| matches!(m, RouteMatcher::DomainRegex(_)))
        );
        assert!(matchers.iter().any(
            |m| matches!(m, RouteMatcher::ProcessPath(path) if path == r"C:\Apps\browser.exe")
        ));
    }

    #[test]
    fn final_must_exist_as_group() {
        let yaml = r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: cn_smart
  final: ghost
"#;
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        let err = compile(cfg).unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn structured_wireguard_node_preserves_all_protocol_options() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes:
  - name: wg-full
    protocol: wireguard
    login:
      private_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    params:
      local-address: [10.0.0.2/32, "fd00::2/128"]
      mtu: 1280
      workers: 4
      remote-dns-resolve: true
      dns: [10.0.0.53]
      peers:
        - server: 192.0.2.1
          port: 51820
          public-key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
          allowed-ips: [10.0.0.0/8]
          reserved: [1, 2, 3]
"#,
        );
        let node = &plan.nodes[0];
        assert_eq!(node.protocol, NodeProtocol::Wireguard);
        assert_eq!(node.host, "0.0.0.0");
        assert_eq!(node.params.get("workers").map(String::as_str), Some("4"));
        assert_eq!(
            node.params.get("private-key").map(String::as_str),
            Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        );
        let peers: serde_json::Value =
            serde_json::from_str(node.params.get("peers").unwrap()).unwrap();
        assert_eq!(peers.as_array().unwrap().len(), 1);
        assert_eq!(peers[0]["reserved"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn wireguard_inbound_compiles_every_server_field() {
        let plan = compile_cfg(
            r#"
version: 1
profile: server
listen:
  wireguard:
    - host: "::1"
      port: 51820
      privateKey: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
      mtu: 1280
      packetQueue: 2048
      handshakeRateLimit: 250
      peers:
        - publicKey: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
          presharedKey: AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
          allowedIPs: [10.77.0.2/32, "fd77::2/128"]
          reserved: [1, 2, 3]
          persistentKeepalive: 25
route: {preset: direct}
"#,
        );
        let listener = &plan.listen.wireguard[0];
        assert_eq!(listener.bind, "[::1]:51820".parse().unwrap());
        assert_eq!(listener.private_key, [1; 32]);
        assert_eq!(listener.mtu, 1280);
        assert_eq!(listener.packet_queue, 2048);
        assert_eq!(listener.handshake_rate_limit, 250);
        assert_eq!(listener.peers[0].public_key, [2; 32]);
        assert_eq!(listener.peers[0].preshared_key, Some([3; 32]));
        assert_eq!(listener.peers[0].reserved, [1, 2, 3]);
        assert_eq!(listener.peers[0].persistent_keepalive, Some(25));
        assert_eq!(listener.peers[0].allowed_ips.len(), 2);
    }

    #[test]
    fn wireguard_inbound_rejects_unknown_and_ambiguous_routes() {
        let unknown = r#"
version: 1
profile: server
listen:
  wireguard:
    - host: 127.0.0.1
      port: 51820
      privateKey: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
      silentlyIgnored: true
      peers: []
route: {preset: direct}
"#;
        let error = serde_yaml::from_str::<UserConfig>(unknown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("silentlyIgnored"), "error = {error}");

        let duplicated = r#"
version: 1
profile: server
listen:
  wireguard:
    - host: 127.0.0.1
      port: 51820
      privateKey: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
      peers:
        - publicKey: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
          allowedIPs: [10.77.0.0/24]
        - publicKey: AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
          allowedIPs: [10.77.0.0/24]
route: {preset: direct}
"#;
        let mut config: UserConfig = serde_yaml::from_str(duplicated).unwrap();
        apply_defaults(&mut config);
        let error = compile(config).unwrap_err().to_string();
        assert!(error.contains("不能分配给多个对端"), "error = {error}");
    }

    #[test]
    fn link_node_keeps_structured_stream_settings() {
        let detail: NodeDetail = serde_json::from_str(
            r#"{
                "name":"linked",
                "link":"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ignored",
                "streamSettings":{"network":"raw","sockopt":{"domainStrategy":"UseIPv4"}}
            }"#,
        )
        .unwrap();
        let node = detail_to_parsed(&detail).unwrap();
        assert_eq!(node.name, "linked");
        assert_eq!(node.transport, "tcp");
        assert_eq!(
            node.stream_settings
                .unwrap()
                .sockopt
                .unwrap()
                .domain_strategy,
            crate::stream_settings::DomainStrategy::UseIpv4
        );
    }

    #[test]
    fn dialer_proxy_cycle_is_rejected_before_registry_build() {
        let make = |name: &str, proxy: &str| {
            let mut node = ParsedNode::new(name, NodeProtocol::Direct, "127.0.0.1", 1);
            node.stream_settings = Some(crate::stream_settings::NodeStreamSettings {
                sockopt: Some(crate::stream_settings::OutboundSocketConfig {
                    dialer_proxy: proxy.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            });
            node
        };
        let error = validate_dialer_proxy_graph(&[make("a", "b"), make("b", "a")])
            .unwrap_err()
            .to_string();
        assert!(error.contains("循环链"), "error={error}");
    }

    #[test]
    fn shadowsocks_listener_registers_all_fields_and_aliases() {
        let plan = crate::loader::load_from_str(
            r#"
version: 1
profile: server
listen:
  panel: false
  ss:
    host: 127.0.0.1
    port: 8388
    method: aes-256-gcm
    password: secret
    mode: tcp-and-udp
    plugin: v2ray-plugin
    plugin_opts: server;tls;host=cdn.example
    plugin_args: [--loglevel, warning]
    plugin_mode: tcp-and-udp
    plugin_startup_timeout: 7s
    handshake_timeout: 3s
    udp_timeout: 45s
    max_connections: 23
    max_udp_associations: 29
    tag: full-ss
route: {preset: direct, final: direct}
"#,
        )
        .unwrap();
        let listener = &plan.listen.shadowsocks[0];
        assert_eq!(listener.tag, "full-ss");
        assert_eq!(listener.mode, "tcp_and_udp");
        assert_eq!(listener.plugin.as_deref(), Some("v2ray-plugin"));
        assert_eq!(
            listener.plugin_opts.as_deref(),
            Some("server;tls;host=cdn.example")
        );
        assert_eq!(listener.plugin_args, ["--loglevel", "warning"]);
        assert_eq!(listener.plugin_mode.as_deref(), Some("tcp_and_udp"));
        assert_eq!(listener.plugin_startup_timeout, Duration::from_secs(7));
        assert_eq!(listener.handshake_timeout, Duration::from_secs(3));
        assert_eq!(listener.udp_timeout, Duration::from_secs(45));
        assert_eq!(listener.max_connections, 23);
        assert_eq!(listener.max_udp_associations, 29);
        assert!(listener.enable_tcp() && listener.enable_udp());
        assert_eq!(
            parse_shadowsocks_socket("::1", 8388),
            Some("[::1]:8388".parse().unwrap())
        );
    }

    #[test]
    fn shadowsocks_listener_rejects_bad_cipher_key_users_and_unknown_fields() {
        for (fragment, expected) in [
            ("method: missing\n    password: secret", "method"),
            (
                "method: 2022-blake3-aes-128-gcm\n    password: bad-base64",
                "password",
            ),
            (
                "method: aes-128-gcm\n    password: secret\n    users: [{name: alice, key: YWJjZA==}]",
                "users",
            ),
            (
                "method: 2022-blake3-aes-128-gcm\n    password: YWJjZGVmZ2hpamtsbW5vcA==\n    users: [{name: alice, key: YWJjZA==}]",
                "16 字节",
            ),
            (
                "method: aes-128-gcm\n    password: secret\n    plugin-opts: server",
                "必须同时配置 plugin",
            ),
            (
                "method: aes-128-gcm\n    password: secret\n    mode: tcp_and_udp\n    plugin: v2ray-plugin\n    plugin-mode: tcp_only",
                "必须与 mode 一致",
            ),
            (
                "method: aes-128-gcm\n    password: secret\n    plugin: v2ray-plugin\n    plugin-startup-timeout: 0s",
                "不能为 0",
            ),
            (
                "method: aes-128-gcm\n    password: secret\n    typo-field: true",
                "did not match",
            ),
        ] {
            let yaml = format!(
                "version: 1\nprofile: server\nlisten:\n  panel: false\n  shadowsocks:\n    port: 8388\n    {fragment}\nroute: {{preset: direct, final: direct}}\n"
            );
            let result = crate::loader::load_from_str(&yaml);
            let error = result.unwrap_err().to_string();
            assert!(error.contains(expected), "error={error}");
        }
    }

    #[test]
    fn ebpf_inbound_validation_is_native_and_capacity_bounded() {
        let mut options: EbpfInboundOptions = serde_json::from_value(serde_json::json!({
            "tag": "ebpf-in",
            "redirect_address": ["127.128.0.0/9", "2001:db8:2030::/64"],
            "include_uid": [1000, 1001],
            "include_uid_range": ["10000:19999"],
            "bypass_rule_set": ["cnip"]
        }))
        .unwrap();
        validate_ebpf_inbound(&options, "inbounds[0]", "linux").unwrap();
        assert!(
            validate_ebpf_inbound(&options, "inbounds[0]", "windows")
                .unwrap_err()
                .to_string()
                .contains("仅支持 Linux/Android")
        );

        options.include_uid = vec![1000, 1000];
        assert!(
            validate_ebpf_inbound(&options, "inbounds[0]", "android")
                .unwrap_err()
                .to_string()
                .contains("重复 UID")
        );
    }

    #[test]
    fn ebpf_shared_network_validates_interface_and_source_filters() {
        let mut options: EbpfInboundOptions = serde_json::from_value(serde_json::json!({
            "shared_network": {
                "enabled": true,
                "include_interface": ["ap*", "rndis*"],
                "exclude_interface": ["rmnet*"],
                "include_source_address": ["192.168.43.0/24", "fd00:43::/64"],
                "exclude_source_address": ["192.168.43.1/32"],
                "interface_refresh_interval": "2s",
                "tc_priority": 1
            }
        }))
        .unwrap();
        validate_ebpf_inbound(&options, "inbounds[0]", "android").unwrap();

        options.shared_network.include_interface = vec!["[".into()];
        assert!(
            validate_ebpf_inbound(&options, "inbounds[0]", "linux")
                .unwrap_err()
                .to_string()
                .contains("合法 glob")
        );
        options.shared_network.include_interface = vec!["ap*".into()];
        options.shared_network.include_source_address = vec!["192.168.43.999/24".into()];
        assert!(
            validate_ebpf_inbound(&options, "inbounds[0]", "linux")
                .unwrap_err()
                .to_string()
                .contains("合法 CIDR")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn ebpf_inbound_is_not_lowered_into_legacy_capture() {
        let plan = crate::loader::load_from_str(
            r#"
version: 1
profile: router
inbounds:
  - type: ebpf
    tag: ebpf-in
    redirect_address: [127.128.0.0/9]
listen: {panel: false}
route: {preset: direct, final: direct}
ui: {on: false}
"#,
        )
        .unwrap();
        assert!(matches!(plan.inbounds.as_slice(), [Inbound::Ebpf(_)]));
        assert!(!plan.capture.on);
    }
}
