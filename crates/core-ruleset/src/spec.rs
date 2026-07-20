//! 用户配置 → 运行时规则集规范。

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 单条规则集的来源 & 类型 & 刷新策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetSpec {
    /// 远程来源。与 `path` 同时设置时，`path` 是该远程规则集的显式缓存位置。
    #[serde(default)]
    pub url: Option<String>,
    /// `url` 为空时是本地来源；`url` 存在时是远程响应的显式缓存位置
    /// （兼容 Mihomo HTTP provider）。
    #[serde(default)]
    pub path: Option<String>,

    /// 内联 payload —— 直接在 YAML 列出。如：
    /// ```yaml
    /// route:
    ///   sets:
    ///     my-direct:
    ///       type: domain
    ///       payload:
    ///         - "DOMAIN-SUFFIX,example.com"
    ///         - "DOMAIN,localhost"
    /// ```
    #[serde(default)]
    pub payload: Vec<String>,

    /// 规则集类型：domain / ipcidr / classical / mixed。
    #[serde(default = "default_type")]
    pub r#type: RulesetType,

    /// 抓取与解析格式；不写时按文件后缀/魔数自动嗅探。
    #[serde(default)]
    pub format: Option<String>,

    /// 自动刷新周期；最小 5m，最大 30d。
    #[serde(default = "default_every", with = "humantime_serde")]
    pub every: Duration,

    /// 抓取通道（保留 —— 与 feeds.via 同义）。
    #[serde(default = "default_via")]
    pub via: String,
}

fn default_type() -> RulesetType {
    RulesetType::Domain
}
fn default_every() -> Duration {
    Duration::from_secs(24 * 3600)
}
fn default_via() -> String {
    "direct".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RulesetType {
    /// 纯域名（domain / domain_suffix / domain_keyword 混合）
    Domain,
    /// 仅 IP CIDR
    Ipcidr,
    /// mihomo 经典：每行 `KIND,VALUE[,policy]`，类型混合
    Classical,
    /// 上述全混（与 classical 行为相同，区分仅作语义提示）
    Mixed,
}
