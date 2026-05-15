use std::fmt;

use thiserror::Error;

/// 三段式 friendly 错误：错误描述 + 位置 + 修复建议。
#[derive(Debug, Error)]
pub struct ConfigError {
    pub kind: ConfigErrorKind,
    pub location: Option<String>,
    pub hint: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigErrorKind {
    #[error("YAML 解析失败: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("配置版本不被支持: {0}")]
    UnsupportedVersion(u32),
    #[error("配置缺少必填字段: {0}")]
    MissingField(&'static str),
    #[error("非法字段值: {0}")]
    InvalidValue(String),
    #[error("引用未定义: {0}")]
    UnknownRef(String),
    #[error("协议不支持或解析失败: {0}")]
    BadNode(String),
    #[error("路由规则非法: {0}")]
    BadRoute(String),
    #[error("平台不支持当前能力: {0}")]
    UnsupportedPlatform(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "错误：{}", self.kind)?;
        if let Some(loc) = &self.location {
            write!(f, "\n位置：{}", loc)?;
        }
        if let Some(hint) = &self.hint {
            write!(f, "\n修复：{}", hint)?;
        }
        Ok(())
    }
}

impl ConfigError {
    pub fn new(kind: ConfigErrorKind) -> Self {
        Self {
            kind,
            location: None,
            hint: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn invalid<S: Into<String>>(msg: S) -> Self {
        Self::new(ConfigErrorKind::InvalidValue(msg.into()))
    }

    pub fn unknown_ref<S: Into<String>>(name: S) -> Self {
        Self::new(ConfigErrorKind::UnknownRef(name.into()))
    }

    pub fn bad_node<S: Into<String>>(msg: S) -> Self {
        Self::new(ConfigErrorKind::BadNode(msg.into()))
    }

    pub fn bad_route<S: Into<String>>(msg: S) -> Self {
        Self::new(ConfigErrorKind::BadRoute(msg.into()))
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::new(ConfigErrorKind::Yaml(e))
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ConfigErrorKind::Io(e))
    }
}

pub type ConfigResult<T> = Result<T, ConfigError>;
