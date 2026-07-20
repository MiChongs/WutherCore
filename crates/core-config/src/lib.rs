//! core-config —— Friendly YAML 配置层
//!
//! 设计目标参见 `RP内核设计文档.md` §3-§5、§13：
//! * 用户视角只暴露 10 个词：listen / feeds / nodes / groups / route /
//!   resolver / capture / smart / ui / mesh。
//! * 默认值由 `profile` (desktop/router/server/mobile) 决定。
//! * 短写法自动展开为长写法；URI 节点自动解析为结构化节点。
//! * 校验失败时给出"位置 + 原因 + 修复"三段式人能看懂的错误。

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod error;
pub mod loader;
pub mod migrate;
pub mod model;
pub mod node_uri;
pub mod profile;
mod ruleset_compat;
pub mod runtime_plan;

pub use error::{ConfigError, ConfigErrorKind, ConfigResult};
pub use loader::{load_from_path, load_from_str};
pub use model::*;
pub use runtime_plan::RuntimePlan;
