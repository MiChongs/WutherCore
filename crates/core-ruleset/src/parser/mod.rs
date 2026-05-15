//! 多格式 → 统一 [`ClassicalEntry`] 列表 / 预编译 succinct 结构。
//!
//! 大部分文本格式（yaml / txt / sing-box JSON / WutherCore RRS）在解析后产出
//! 统一的 `Vec<ClassicalEntry>`，再交给 [`crate::matcher::RulesetMatcher::compile`]
//! 编入 trie/regex/cidr 等实际索引。
//!
//! mihomo MRS 是个例外：它本身就是 *预编译* 的 succinct trie / 排序 IpRange
//! 列表。展开成 `Vec<ClassicalEntry>` 既会丢失 wildcard 语义，也会爆内存
//! （一个 geosite-cn 就 70k+ 条目）。所以我们引入 [`RulesetCompiled`] 包装：
//! * `Classical(Vec<ClassicalEntry>)` —— 文本格式走老路径。
//! * `Mrs(MrsPayload)` —— MRS 走 Arc 共享的预编译结构，零拷贝挂到 matcher。

use thiserror::Error;

use crate::{format::RulesetFormat, matcher::ClassicalEntry};

pub mod binary;
pub mod mrs;
pub mod sb_json;
pub mod txt;
pub mod yaml;

pub use mrs::MrsPayload;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("YAML 解析失败: {0}")]
    Yaml(String),
    #[error("JSON 解析失败: {0}")]
    Json(String),
    #[error("非法行 \"{0}\"")]
    BadLine(String),
    #[error("尚未实现该二进制格式: {0}")]
    UnsupportedBinary(&'static str),
    #[error("二进制解析失败: {0}")]
    Other(String),
    #[error("未知格式")]
    Unknown,
}

/// 解析结果 —— 兼容文本与预编译两种产物。manager 用这个统一入口。
pub enum RulesetCompiled {
    Classical(Vec<ClassicalEntry>),
    Mrs(MrsPayload),
}

/// 旧 API：把所有格式都当成"文本→entries"。MRS 因为不可展开，会返回错误。
/// 仍保留是为了让单元测试和 yaml/txt fast-path 兼容。
pub fn parse_ruleset(
    format: RulesetFormat,
    body: &[u8],
) -> Result<Vec<ClassicalEntry>, ParseError> {
    match format {
        RulesetFormat::Yaml => yaml::parse(body),
        RulesetFormat::Text => txt::parse(body),
        RulesetFormat::SingboxJson => sb_json::parse(body),
        RulesetFormat::Mrs => binary::parse_mrs(body),
        RulesetFormat::Srs => binary::parse_srs(body),
        RulesetFormat::Rrs => crate::rrs::decode(body),
        RulesetFormat::Unknown => Err(ParseError::Unknown),
    }
}

/// 新 API：MRS 走预编译产物，文本格式走 entries。manager 用这个。
pub fn parse_ruleset_compiled(
    format: RulesetFormat,
    body: &[u8],
) -> Result<RulesetCompiled, ParseError> {
    match format {
        RulesetFormat::Mrs => mrs::parse(body).map(RulesetCompiled::Mrs),
        // 其它格式继续走 entries 路径
        _ => parse_ruleset(format, body).map(RulesetCompiled::Classical),
    }
}
