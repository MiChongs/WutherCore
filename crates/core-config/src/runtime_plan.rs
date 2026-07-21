//! 把用户友好的 YAML 编译成运行时计划 (`RuntimePlan`)。
//!
//! 流程对应 §3.4：YAML -> profile 默认值 -> feeds/nodes 展开 ->
//! 节点 URI 解析 -> groups 选择器 -> route 规则图 -> resolver 策略 ->
//! capture 接管计划 -> smart 评分器 -> runtime graph。
//!
//! 这里产出的结构是给 `core-runtime` / `core-route` / `core-outbound`
//! 共同消费的 *已展开* 数据，而非 YAML 原貌。

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    error::{ConfigError, ConfigResult},
    model::*,
    node_uri::{NodeProtocol, ParsedNode, parse_uri},
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
    pub panel: Option<PanelListen>,
    pub share: Share,
    pub auth: Vec<UserPass>,
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
        share: None,
        auth: vec![],
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

    Ok(ListenPlan {
        mixed,
        panel,
        share,
        auth,
    })
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
    if let Some(link) = &d.link {
        let mut n = parse_uri(link)?;
        n.name = d.name.clone();
        return Ok(n);
    }
    let proto = d
        .protocol
        .as_deref()
        .map(NodeProtocol::from_scheme)
        .ok_or_else(|| ConfigError::bad_node(format!("node {} 缺少 protocol", d.name)))?;
    let address = d
        .address
        .as_deref()
        .ok_or_else(|| ConfigError::bad_node(format!("node {} 缺少 address", d.name)))?;
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        ConfigError::bad_node(format!("node {} address 缺少端口: {}", d.name, address))
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| ConfigError::bad_node(format!("node {} 端口非法: {}", d.name, port)))?;
    let mut node = ParsedNode::new(
        d.name.clone(),
        proto,
        host.trim_matches(|c| c == '[' || c == ']'),
        port,
    );
    if let Some(login) = &d.login {
        node.user = login.user.clone();
        node.password = login.password.clone();
        node.uuid = login.uuid.clone();
    }
    if let Some(secure) = &d.secure {
        node.tls = secure.tls;
        node.sni = secure.sni.clone();
    }
    if let Some(transport) = &d.transport {
        node.transport = transport.kind.clone();
    }
    if let Some(network) = &d.network {
        node.udp = network.udp;
    }
    Ok(node)
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
            return Err(
                ConfigError::invalid(format!(
                    "groups.{name}.choose = chain 尚未实现多跳 relay"
                ))
                .at(format!("groups.{name}.choose"))
                .hint(
                    "请改用 manual / smart / fast / stable / spread；\
                     多跳链路实现前不会静默退化为单跳",
                ),
            );
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
    Err(
        ConfigError::invalid(
            "管理 API 绑定了非本机地址，但 ui.secret 为空；拒绝启动以避免未鉴权控制面",
        )
        .at("ui.secret")
        .hint(
            "为 ui.secret 设置足够长的随机串，或把 listen.panel / listen.share 限制在 127.0.0.1 / ::1；\
             share: home|all 会把面板绑到 0.0.0.0",
        ),
    )
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
        assert_eq!(
            plan.ui.secret.as_deref(),
            Some("test-secret-please-change")
        );
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
}
