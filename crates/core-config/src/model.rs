//! 配置数据模型 —— 直接对应 §5 字段完整说明。
//!
//! 所有 field 默认值通过 [`profile::Profile::apply_defaults`] 注入，
//! 模型本身只负责"原样反序列化 + 短写法/长写法兼容"。

use std::collections::BTreeMap;
use std::time::Duration;

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
    pub steps: Vec<String>,
    /// 外部规则集 —— mihomo / sing-box / 自定义 payload。
    /// 在 [`steps`] 中通过 `set:<name> -> <action>` 引用。
    #[serde(default)]
    pub sets: BTreeMap<String, RuleSetSpec>,
}

/// route.sets.<name> 配置 —— 与 [`core-ruleset::RulesetSpec`] 一一对应，
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

fn default_ruleset_type() -> String { "domain".into() }
fn default_ruleset_every() -> Duration { Duration::from_secs(24 * 3600) }

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
    #[serde(default)]
    pub mainland: Option<String>,
    #[serde(default)]
    pub overseas: Option<String>,
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Smart,
            fake: FakeMode::Auto,
            cache: default_cache(),
            mainland: Some("ali".into()),
            overseas: Some("cloudflare".into()),
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    System,
    Secure,
    Fake,
    Smart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FakeMode {
    Off,
    Auto,
    Force,
}

/* ---------------- capture ---------------- */

/// Capture / TUN 入站 —— 与 mihomo / sing-box `inbounds[type=tun]` 字段全量对齐。
///
/// Friendly 字段（顶层）保留 RPKernel 简洁语义；`tun` 子字段对齐 sing-box JSON。
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
    /// sing-box 兼容子配置（详见 https://sing-box.sagernet.org/configuration/inbound/tun/）。
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
            stack: CaptureStack::Native,
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

/// 用户态/系统态 TCP 栈选择 —— 完整对齐 sing-box `stack`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStack {
    /// 系统栈（Linux native + ip route 接管），最低延迟。
    Native,
    /// gVisor 用户态栈（跨平台、强隔离）。
    Gvisor,
    /// smoltcp 用户态栈（嵌入式 / 低资源）。
    Smoltcp,
    /// sing-box `system` 栈：等价 native，明确语义。
    System,
    /// sing-box `mixed` 栈：TCP gvisor + UDP system 透明转发。
    Mixed,
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

/// sing-box `inbounds[type=tun]` 全字段映射 —— 见
/// https://sing-box.sagernet.org/configuration/inbound/tun/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundOptions {
    /// `interface_name` —— 优先级高于 RPKernel 默认 `rpktun0/utun7/RPKernelTun`。
    #[serde(default)]
    pub interface_name: Option<String>,
    /// `address` —— TUN 接口 v4 / v6 CIDR 列表（首条 v4 / 首条 v6 生效）。
    #[serde(default)]
    pub address: Vec<String>,

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
    ResolverMode::Smart
}
fn default_fake() -> FakeMode {
    FakeMode::Auto
}
fn default_cache() -> Duration {
    Duration::from_secs(24 * 3600)
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
    CaptureStack::Native
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
