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

use serde::{Deserialize, Serialize};

use crate::{
    error::{ConfigError, ConfigResult},
    model::*,
    node_uri::{NodeProtocol, ParsedNode, parse_uri, validate_reality_client_settings},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub version: u32,
    pub profile: Profile,
    pub name: String,
    pub log: Option<Log>,
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
    pub young: Vec<YoungListen>,
    pub grpc: Vec<GrpcListen>,
    pub panel: Option<PanelListen>,
    pub xhttp: Vec<XhttpListenPlan>,
    pub share: Share,
    pub auth: Vec<UserPass>,
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
    pub host: String,
    pub port: u16,
    pub udp: bool,
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
    /// 已展开成的具体 node 名集合。
    pub members: Vec<String>,
    pub prefer: Vec<String>,
    pub avoid: Vec<String>,
    pub check: Option<String>,
    pub sticky: Option<String>,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePlan {
    pub preset: String,
    pub r#final: String,
    /// 编译后的规则；preset 已经展开为 steps。
    pub steps: Vec<RouteStep>,
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
    Cidr(String),
    Port(u16),
    /// `DST-PORT,LOW-HIGH` —— 闭区间端口范围。
    PortRange(u16, u16),
    Network(String),
    Process(String),
    /// 外部规则集（`route.sets.<name>`）。
    Set(String),
    /// L7 协议指纹（stun/dtls/quic/tls/sni/http/webrtc）。
    Proto(String),
    /// AND 组合 —— 所有子 matcher 都命中才算命中（短路求值）。
    /// 由 typed-key object 形式中多个具名字段联合产生。
    And(Vec<RouteMatcher>),
    /// OR 组合 —— 任一子 matcher 命中即算命中（短路求值）。
    /// 由具名字段的列表值产生（如 `port: [53, 5353]`）。
    Or(Vec<RouteMatcher>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Block,
    Group(String),
}

/* ---------------- compile ---------------- */

/// 用户配置 -> RuntimePlan。要求 [`crate::profile::apply_defaults`] 已执行。
pub fn compile(mut cfg: UserConfig) -> ConfigResult<RuntimePlan> {
    let listen = compile_listen(&cfg)?;
    let feeds = compile_feeds(&cfg.feeds);
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

fn compile_listen(cfg: &UserConfig) -> ConfigResult<ListenPlan> {
    let listen = cfg.listen.clone().unwrap_or(Listen {
        local: None,
        panel: None,
        xhttp: None,
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
            host: host_for(share).into(),
            port: p,
            udp: true,
        },
        ListenLocal::Detail(d) => MixedListen {
            host: if d.host.is_empty() {
                host_for(share).into()
            } else {
                d.host
            },
            port: d.port,
            udp: d.udp,
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
        share,
        auth,
    })
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
            settings: listener.settings,
        });
    }

    Ok(plans)
}

fn compile_feeds(feeds: &BTreeMap<String, FeedSpec>) -> BTreeMap<String, FeedDetail> {
    feeds
        .iter()
        .map(|(k, v)| {
            let detail = match v {
                FeedSpec::Url(u) => FeedDetail {
                    url: u.clone(),
                    every: Duration::from_secs(12 * 3600),
                    via: "direct".into(),
                    keep: Default::default(),
                    drop: Default::default(),
                    rename: Default::default(),
                },
                FeedSpec::Detail(d) => d.clone(),
            };
            (k.clone(), detail)
        })
        .collect()
}

fn compile_nodes(specs: &[NodeSpec]) -> ConfigResult<Vec<ParsedNode>> {
    let mut out = Vec::with_capacity(specs.len());
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        let mut node = match spec {
            NodeSpec::Uri(u) => parse_uri(u)?,
            NodeSpec::Detail(d) => detail_to_parsed(d)?,
        };
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
    Ok(out)
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

fn compile_groups(
    cfg: &UserConfig,
    nodes: &[ParsedNode],
) -> ConfigResult<BTreeMap<String, GroupPlan>> {
    let mut out = BTreeMap::new();
    let valid_feeds: std::collections::HashSet<&str> =
        cfg.feeds.keys().map(|s| s.as_str()).collect();
    for (name, g) in &cfg.groups {
        if g.choose == ChooseStrategy::Chain {
            return Err(ConfigError::invalid(format!(
                "groups.{name}.choose = chain 尚未实现多跳 relay"
            ))
            .at(format!("groups.{name}.choose"))
            .hint(
                "请改用 manual / smart / fast / stable / spread；\
                     多跳链路实现前不会静默退化为单跳",
            ));
        }
        let mut members = Vec::new();
        for src in &g.r#use {
            if src == "nodes" {
                for n in nodes {
                    members.push(n.name.clone());
                }
                continue;
            }
            if valid_feeds.contains(src.as_str()) {
                // feeds 节点在运行时按需展开（订阅刷新），这里只做引用记录。
                members.push(format!("feed:{src}"));
                continue;
            }
            // 也允许直接引用具体节点名
            if nodes.iter().any(|n| &n.name == src) {
                members.push(src.clone());
                continue;
            }
            let valid: Vec<String> = valid_feeds
                .iter()
                .map(|s| s.to_string())
                .chain(std::iter::once("nodes".into()))
                .collect();
            return Err(
                ConfigError::unknown_ref(format!("groups.{name}.use 引用了 \"{src}\""))
                    .at(format!("groups.{name}"))
                    .hint(format!(
                        "可用来源只有 {} 或具体的 node 名",
                        valid.join("、")
                    )),
            );
        }
        out.insert(
            name.clone(),
            GroupPlan {
                name: name.clone(),
                choose: g.choose,
                members,
                prefer: g.prefer.clone(),
                avoid: g.avoid.clone(),
                check: g.check.clone(),
                sticky: g.sticky.clone(),
                path: g.path.clone(),
            },
        );
    }
    Ok(out)
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
            RouteStepEntry::Line(s) => parse_step_line(s, groups, &final_target)?,
            RouteStepEntry::Object(obj) => compile_object(obj, groups, &final_target)?,
        };
        steps.extend(entry_steps);
    }

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
        sets,
    })
}

fn rs(matcher: RouteMatcher, action: RouteAction, src: &str) -> RouteStep {
    RouteStep {
        matcher,
        action,
        source: src.into(),
    }
}

fn parse_step_line(
    line: &str,
    groups: &BTreeMap<String, GroupPlan>,
    final_target: &str,
) -> ConfigResult<Vec<RouteStep>> {
    // mihomo classical 字符串：`TYPE,VALUE[,POLICY[,no-resolve]]`，policy 内嵌而非
    // 用 `->` 显式分隔。这里在调用 `split_once("->")` 之前先尝试识别：若整行不含
    // `->` 且首段是已知的 classical TYPE，把它就地改写成 `TYPE,VALUE -> POLICY` 形式
    // 复用统一的左/右两段拆分逻辑。
    if !line.contains("->") {
        if let Some(rewritten) = try_classical_to_dsl(line) {
            return parse_step_line(&rewritten, groups, final_target);
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

    // 共享 LHS 解析（DSL `port:53` / classical `DST-PORT,53` / 别名 `sni:foo`...）。
    // 与 `compile_object` 的 `match` 字段同源，避免两套语法漂移。
    let matchers = parse_match_lhs(lhs)?;

    let action =
        resolve_action(rhs, groups, final_target).map_err(|e| e.at(format!("steps: {line}")))?;

    Ok(matchers
        .into_iter()
        .map(|matcher| RouteStep {
            matcher,
            action: action.clone(),
            source: line.into(),
        })
        .collect())
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
        "direct" => Ok(RouteAction::Direct),
        "block" => Ok(RouteAction::Block),
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

    if let Some(m_str) = &obj.r#match {
        // 复用已有的 classical / DSL 解析路径；`match` 字段允许写 `DST-PORT,53`
        // 也可以是 `port:53`、`domain:foo.com` 等 WutherCore DSL（此处不带箭头）。
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
    if let Some(v) = &obj.ip {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Cidr(s.into()))
        })?);
    }
    if let Some(v) = &obj.port {
        // port 字段单独处理：值字符串里可能有 `1000-2000` 区间，要分流到 PortRange。
        clauses.push(matcher_from_values(v, |s| parse_classical_port(s))?);
    }
    if let Some(v) = &obj.process {
        clauses.push(matcher_from_values(v, |s| {
            Ok(RouteMatcher::Process(s.into()))
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
        .hint("加上 `match`/`domain`/`suffix`/`keyword`/`ip`/`port`/`process`/`set`/`network`/`proto` 之一"));
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
        s if s.starts_with("suffix:") => split_values(&s[7..])
            .into_iter()
            .map(|v| RouteMatcher::Suffix(v.into()))
            .collect(),
        s if s.starts_with("ip:") => split_values(&s[3..])
            .into_iter()
            .map(|v| RouteMatcher::Cidr(v.into()))
            .collect(),
        s if s.starts_with("port:") => {
            vec![parse_classical_port(s[5..].trim())?]
        }
        s if s.starts_with("network:") => split_values(&s[8..])
            .into_iter()
            .map(|v| RouteMatcher::Network(v.into()))
            .collect(),
        s if s.starts_with("process:") => split_values(&s[8..])
            .into_iter()
            .map(|v| RouteMatcher::Process(v.into()))
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
    if obj.ip.is_some() {
        parts.push("ip");
    }
    if obj.port.is_some() {
        parts.push("port");
    }
    if obj.process.is_some() {
        parts.push("process");
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
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "SRC-PORT",
    "DST-PORT",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "NETWORK",
    "RULE-SET",
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
    if lhs.eq_ignore_ascii_case("MATCH") {
        return Ok(vec![RouteMatcher::Any]);
    }
    let mut parts = lhs.splitn(2, ',');
    let kind = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    if value.is_empty() {
        return Err(
            ConfigError::bad_route(format!("classical 规则缺少 value: `{lhs}`"))
                .hint("形如 `DOMAIN-SUFFIX,example.com` 或 `DST-PORT,53`"),
        );
    }

    let kind_uc = kind.to_ascii_uppercase();
    let m = match kind_uc.as_str() {
        "DOMAIN" => RouteMatcher::Domain(value.into()),
        "DOMAIN-SUFFIX" => RouteMatcher::Suffix(value.into()),
        "DOMAIN-KEYWORD" => RouteMatcher::Keyword(value.into()),
        "IP-CIDR" | "IP-CIDR6" => RouteMatcher::Cidr(value.into()),
        "DST-PORT" => parse_classical_port(value)?,
        "PROCESS-NAME" => RouteMatcher::Process(value.into()),
        "NETWORK" => RouteMatcher::Network(value.into()),
        "RULE-SET" => RouteMatcher::Set(value.into()),
        // mihomo 标准里有但 WutherCore 当前 FlowContext 还没暴露的字段
        "SRC-IP-CIDR" | "SRC-PORT" => {
            return Err(ConfigError::bad_route(format!(
                "暂不支持 source-side classical 规则: `{kind_uc}`"
            ))
            .hint("WutherCore FlowContext 当前仅暴露 dst 端信息；如确需匹配源 IP/端口请改用 RULE-SET 外部规则集"));
        }
        "DOMAIN-REGEX" | "PROCESS-PATH" => {
            return Err(
                ConfigError::bad_route(format!("classical 规则 `{kind_uc}` 暂未实现"))
                    .hint("可用 DOMAIN-KEYWORD / PROCESS-NAME 替代，或写入 set: 外部规则集"),
            );
        }
        other => {
            return Err(
                ConfigError::bad_route(format!("未知 classical TYPE: `{other}`"))
                    .hint("受支持的 TYPE 见 README route 章节"),
            );
        }
    };
    Ok(vec![m])
}

/// 解析 `DST-PORT,53` 中的 value：单端口或 `LOW-HIGH` 闭区间。
fn parse_classical_port(value: &str) -> ConfigResult<RouteMatcher> {
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

/// 把 mihomo classical 三段式 `TYPE,VALUE,POLICY[,FLAG]` 改写为 WutherCore 的统一
/// 箭头形式 `TYPE,VALUE -> POLICY`。`MATCH,POLICY` 也走这条路。
///
/// 已知 flag（如 `no-resolve`）在 WutherCore 不需要——本项目所有 IP 规则解析后再匹配，
/// 在此默默丢弃，不报错（mihomo 也仅把它当作不强制 DNS 解析的提示）。
fn try_classical_to_dsl(line: &str) -> Option<String> {
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
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    let (lhs_parts, policy) = if head.eq_ignore_ascii_case("MATCH") {
        // MATCH,POLICY  →  lhs=MATCH, policy=parts[1]
        if parts.len() < 2 {
            return None;
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
        let policy_idx = if matches!(
            parts
                .last()
                .copied()
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str(),
            "no-resolve" | "src"
        ) {
            parts.len() - 2
        } else {
            parts.len() - 1
        };
        let lhs_slice = &parts[..policy_idx];
        (lhs_slice.to_vec(), parts[policy_idx])
    };

    Some(format!("{} -> {}", lhs_parts.join(","), policy))
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
        // 两条 IP-CIDR：第二条尾部 `no-resolve` 在 mapping 形式下不会触发解析路径
        // （outbound 已显式给出），但写出来不应该出错。
        assert_eq!(
            kinds
                .iter()
                .filter(|m| matches!(m, RouteMatcher::Cidr(_)))
                .count(),
            2
        );
    }

    /// `no-resolve` flag 在内嵌 policy 的 string 形式里要被识别并丢弃。
    #[test]
    fn route_step_classical_string_form_strips_no_resolve_flag() {
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
    - {ip: 10.0.0.0/8, outbound: direct}
    - {port: 80, outbound: main}
    - {process: chrome, outbound: ai}
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
                .any(|x| matches!(x, RouteMatcher::Cidr(c) if c == "10.0.0.0/8"))
        );
        assert!(m.iter().any(|x| matches!(x, RouteMatcher::Port(80))));
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Process(p) if p == "chrome"))
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
    - {ip-cidr: 10.0.0.0/8, outbound: direct}
    - {process-name: chrome.exe, outbound: direct}
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
                .any(|x| matches!(x, RouteMatcher::Cidr(c) if c == "10.0.0.0/8"))
        );
        assert!(
            m.iter()
                .any(|x| matches!(x, RouteMatcher::Process(p) if p == "chrome.exe"))
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
    fn route_step_classical_unsupported_kind_errors() {
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
    - {match: "SRC-PORT,1234", outbound: main}
"#;
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        let err = compile(cfg).unwrap_err().to_string();
        assert!(err.contains("SRC-PORT"), "err = {err}");
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
}
