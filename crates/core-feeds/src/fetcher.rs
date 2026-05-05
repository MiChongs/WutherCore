//! 实际拉取订阅 —— HTTP/HTTPS/file/本地路径。
//!
//! HTTP 路径除了把 body 拿回来，还会顺便把响应头里的订阅用量
//! ([`SubscriptionUserinfo`])、`ETag`、`Content-Type` 等元信息一并解析返回。
//!
//! 走 `core_fetch` 而不是 reqwest —— `core_fetch` 内置 hyper + tokio-rustls
//! + `bind_outbound_socket`，四大平台都能让 TCP 真正绕过 TUN（含 Windows，
//! reqwest 0.12 没暴露 IP_UNICAST_IF 注入点做不到）。

use std::time::Duration;

use thiserror::Error;
use tracing::{debug, warn};

use crate::userinfo::SubscriptionUserinfo;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP 请求失败: {0}")]
    Http(String),
    #[error("非 2xx 状态: {0}")]
    Status(u16),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("URL 非法: {0}")]
    BadUrl(String),
}

impl From<core_fetch::FetchError> for FetchError {
    fn from(e: core_fetch::FetchError) -> Self {
        match e {
            core_fetch::FetchError::Status(code) => Self::Status(code),
            core_fetch::FetchError::BadUrl(s) => Self::BadUrl(s),
            core_fetch::FetchError::Io(e) => Self::Io(e),
            other => Self::Http(other.to_string()),
        }
    }
}

/// 默认 UA —— 模拟主流客户端，避免被机场屏蔽。
pub const DEFAULT_UA: &str = concat!(
    "WutherCore/",
    env!("CARGO_PKG_VERSION"),
    " (clash-meta-compatible)"
);

/// 一次抓取的完整结果 —— body + 关键响应头。
#[derive(Debug, Clone, Default)]
pub struct FetchResult {
    /// 响应原文。
    pub bytes: Vec<u8>,
    /// 解析出的订阅用量；本地路径 / 缺头时为 None。
    pub userinfo: Option<SubscriptionUserinfo>,
    /// `ETag` 响应头（保留以便后续条件 GET 实现）。
    pub etag: Option<String>,
    /// `Content-Type` 响应头（解析器格式嗅探可参考）。
    pub content_type: Option<String>,
}

impl FetchResult {
    /// 仅含 body —— 本地路径用。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            userinfo: None,
            etag: None,
            content_type: None,
        }
    }
}

/// 兼容旧 API —— core-runtime 之前会注入 reqwest::Client；现在所有 HTTP 经
/// `core_fetch`（自身已用 net_monitor 同步的 outbound 全局态），不再需要外部
/// 注入。保留空 stub 避免老调用点编译失败，未来可删。
#[deprecated(note = "core-feeds 改走 core_fetch；此函数保留只为编译兼容，无效果")]
pub fn set_shared_http_client<T>(_client: T) {}

/// 抓取一次订阅原文 + 元信息。
pub async fn fetch_feed(url: &str, timeout: Duration) -> Result<FetchResult, FetchError> {
    if url.starts_with("file://") {
        let path = url.trim_start_matches("file://");
        debug!(target: "feeds", path, "fetch from file");
        return Ok(FetchResult::from_bytes(std::fs::read(path)?));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        // 本地路径
        if std::path::Path::new(url).exists() {
            return Ok(FetchResult::from_bytes(std::fs::read(url)?));
        }
        return Err(FetchError::BadUrl(url.into()));
    }

    debug!(target: "feeds", url, "fetch http");
    let opts = core_fetch::FetchOptions {
        user_agent: DEFAULT_UA.to_string(),
        timeout,
        connect_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let resp = match core_fetch::fetch(url, &opts).await {
        Ok(r) => r,
        Err(core_fetch::FetchError::Status(code)) => {
            warn!(target: "feeds", url, code, "feed http error");
            return Err(FetchError::Status(code));
        }
        Err(e) => return Err(FetchError::from(e)),
    };

    let userinfo = SubscriptionUserinfo::from_headers(
        resp.headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let etag = resp.headers.get("etag").cloned();
    let content_type = resp.headers.get("content-type").cloned();

    if let Some(ui) = &userinfo {
        debug!(
            target: "feeds",
            url,
            upload = ui.upload,
            download = ui.download,
            total = ui.total,
            expire = ui.expire,
            "subscription userinfo extracted"
        );
    }

    Ok(FetchResult {
        bytes: resp.bytes,
        userinfo,
        etag,
        content_type,
    })
}
