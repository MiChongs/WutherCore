//! 实际拉取订阅 —— HTTP/HTTPS/file/本地路径。
//!
//! HTTP 路径除了把 body 拿回来，还会顺便把响应头里的订阅用量
//! ([`SubscriptionUserinfo`])、`ETag`、`Content-Type` 等元信息一并解析返回。

use std::sync::OnceLock;
use std::time::Duration;

use thiserror::Error;
use tracing::{debug, warn};

use crate::userinfo::SubscriptionUserinfo;

static SHARED_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn set_shared_http_client(client: reqwest::Client) {
    let _ = SHARED_CLIENT.set(client);
}

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

    let client = if let Some(c) = SHARED_CLIENT.get() {
        c.clone()
    } else {
        reqwest::Client::builder()
            .user_agent(DEFAULT_UA)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .gzip(true)
            .brotli(true)
            .build()
            .map_err(|e| FetchError::Http(e.to_string()))?
    };

    debug!(target: "feeds", url, "fetch http");
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        warn!(target: "feeds", url, code, "feed http error");
        return Err(FetchError::Status(code));
    }

    // 头要在 body consume 前抓出来 —— resp.bytes() 之后 resp 不可再用。
    let headers = resp.headers().clone();
    let userinfo = SubscriptionUserinfo::from_headers(
        headers
            .iter()
            .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?))),
    );
    let etag = headers
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;

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
        bytes: bytes.to_vec(),
        userinfo,
        etag,
        content_type,
    })
}
