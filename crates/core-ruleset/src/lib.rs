//! core-ruleset —— 外部规则集系统。
//!
//! ## 支持的格式
//!
//! | 格式 | 来源 | 状态 |
//! |---|---|---|
//! | **YAML payload** (`payload: [...]`) | mihomo / Clash | ✅ 完整 |
//! | **TXT / LIST**（每行一条 mihomo 规则） | mihomo / Clash | ✅ 完整 |
//! | **JSON**（`{"version":N, "rules":[...]}`） | sing-box | ✅ v1–v5 语义保持；暂不能求值的官方字段显式报错 |
//! | **MRS**（mihomo binary v1） | mihomo | ✅ 完整：zstd + succinct domain trie + ipcidr range list |
//! | **SRS**（sing-box binary v1–v5） | sing-box | ✅ 全部官方字段；有界 zlib + compact domain/IP set + logical 语义保持 |
//! | **inline payload**（YAML 内联 list） | WutherCore 自定义 | ✅ |
//!
//! ## 支持的规则类型（与 mihomo 对齐）
//!
//! * `domain`              精确域名
//! * `domain_suffix`       后缀（`.example.com` 命中 `a.example.com`）
//! * `domain_keyword`      子串
//! * `domain_regex`        正则
//! * `ip_cidr`             v4/v6 CIDR
//! * `process_name`        进程名
//! * `port`                destination/source 单端口或区间
//! * `network`             TCP / UDP / ICMP
//! * `classical`（混合）   每行 `KIND,VALUE[,policy]`
//!
//! ## 高速 matcher
//!
//! * 后缀 trie：O(m)（m=域名段数）
//! * 关键字：长度短时线性；长时 Aho-Corasick（依需求扩展）
//! * 精确：FxHashSet
//! * CIDR：按掩码长度桶分组 + IpNet 线性，10w 条规模 100µs 命中

#![forbid(unsafe_code)]

pub mod fetch;
pub mod format;
pub mod ir;
pub mod manager;
pub mod matcher;
pub mod parser;
pub mod rrs;
pub mod spec;

pub use fetch::{FetchError, fetch_ruleset};
pub use format::{RulesetFormat, detect_format};
pub use ir::{
    PortRange, RulesetExpr, RulesetInterfaceAddress, RulesetMatchContext, RulesetPredicate,
    RulesetProgram,
};
pub use manager::{RulesetManager, RulesetSink, RulesetUpdate};
pub use matcher::{ClassicalEntry, RulesetIndex, RulesetMatcher};
pub use parser::{ParseError, RulesetCompiled, parse_ruleset, parse_ruleset_compiled};
pub use spec::{RulesetSpec, RulesetType};
