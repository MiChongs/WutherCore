//! 多格式 → classical 列表 / 语义 IR / 预编译 succinct 结构。
//!
//! yaml / txt / WutherCore RRS 产出 `Vec<ClassicalEntry>`；sing-box JSON 产出
//! [`RulesetProgram`]，保留复合 AND / OR / invert；MRS 保留上游预编译结构。
//!
//! mihomo MRS 是个例外：它本身就是 *预编译* 的 succinct trie / 排序 IpRange
//! 列表。展开成 `Vec<ClassicalEntry>` 既会丢失 wildcard 语义，也会爆内存
//! （一个 geosite-cn 就 70k+ 条目）。所以我们引入 [`RulesetCompiled`] 包装：
//! * `Classical(Vec<ClassicalEntry>)` —— 文本格式走老路径。
//! * `Mrs(MrsPayload)` —— MRS 走 Arc 共享的预编译结构，零拷贝挂到 matcher。

use thiserror::Error;

use crate::{
    format::RulesetFormat, ir::RulesetProgram, matcher::ClassicalEntry, spec::RulesetType,
};

pub mod binary;
pub mod mrs;
pub mod sb_json;
pub mod srs;
pub mod txt;
pub mod yaml;

pub use mrs::MrsPayload;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("YAML 解析失败: {0}")]
    Yaml(String),
    #[error("JSON 解析失败: {0}")]
    Json(String),
    #[error("文本不是有效 UTF-8: {0}")]
    Utf8(String),
    #[error("sing-box rule-set 缺少必填 version")]
    MissingVersion,
    #[error("不支持的 sing-box rule-set version: {0}（仅支持 1..=5）")]
    UnsupportedVersion(u64),
    #[error("sing-box headless rule 字段暂不能求值: {0}")]
    UnsupportedField(&'static str),
    #[error("sing-box headless rule 非法: {0}")]
    InvalidRule(String),
    #[error("非法行 \"{0}\"")]
    BadLine(String),
    #[error("尚未实现该二进制格式: {0}")]
    UnsupportedBinary(&'static str),
    #[error("二进制解析失败: {0}")]
    Other(String),
    #[error("未知格式")]
    Unknown,
}

/// 解析结果 —— 兼容 classical、语义 IR 与预编译 MRS。manager 用这个统一入口。
pub enum RulesetCompiled {
    Classical(Vec<ClassicalEntry>),
    Semantic(RulesetProgram),
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
        RulesetFormat::SingboxJson => Err(ParseError::InvalidRule(
            "sing-box JSON 含复合布尔语义，不能无损转换为 Vec<ClassicalEntry>；请使用 \
             parse_ruleset_compiled"
                .into(),
        )),
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
        RulesetFormat::SingboxJson => sb_json::parse(body).map(RulesetCompiled::Semantic),
        RulesetFormat::Srs => srs::parse(body).map(RulesetCompiled::Semantic),
        // 其它格式继续走 entries 路径
        _ => parse_ruleset(format, body).map(RulesetCompiled::Classical),
    }
}

/// 按规则集声明的 behavior/type 解析。
///
/// Mihomo 的 YAML/TEXT provider 只靠文件格式无法判定每一行的语义：
/// `domain`、`ipcidr` 与 `classical` 使用不同语法。其它格式本身携带完整语义
/// （sing-box JSON/SRS、MRS）或属于 WutherCore 原生格式，因此保持原路径。
pub fn parse_ruleset_compiled_for_type(
    format: RulesetFormat,
    body: &[u8],
    ruleset_type: RulesetType,
) -> Result<RulesetCompiled, ParseError> {
    match format {
        RulesetFormat::Yaml => {
            yaml::parse_for_type(body, ruleset_type).map(RulesetCompiled::Classical)
        }
        RulesetFormat::Text => {
            txt::parse_for_type(body, ruleset_type).map(RulesetCompiled::Classical)
        }
        _ => parse_ruleset_compiled(format, body),
    }
}
