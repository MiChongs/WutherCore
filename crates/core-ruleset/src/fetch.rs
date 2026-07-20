//! 规则集抓取 —— core-feeds 同构（HTTP/HTTPS/file/本地路径）。
//!
//! HTTP 走 `core_fetch` 自研 client（hyper + tokio-rustls + bind_outbound_socket）
//! 而不是 reqwest，关掉 Windows 上的 TUN 自循环。

use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

use thiserror::Error;
use tracing::{debug, info, warn};

pub const MAX_RULESET_BODY_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP: {0}")]
    Http(String),
    #[error("HTTP 状态: {0}")]
    Status(u16),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("规则集超过上限 ({limit} bytes)")]
    BodyTooLarge { limit: usize },
}

impl From<core_fetch::FetchError> for FetchError {
    fn from(e: core_fetch::FetchError) -> Self {
        match e {
            core_fetch::FetchError::Status(c) => Self::Status(c),
            core_fetch::FetchError::BadUrl(s) => Self::BadUrl(s),
            core_fetch::FetchError::Io(e) => Self::Io(e),
            core_fetch::FetchError::BodyTooLarge { limit } => Self::BodyTooLarge { limit },
            other => Self::Http(other.to_string()),
        }
    }
}

/// 兼容旧 API —— core-runtime 之前会注入 reqwest::Client；现在所有 HTTP 经
/// `core_fetch`，不再需要外部注入。保留空 stub 防老调用点编译失败，可删。
#[deprecated(note = "core-ruleset 改走 core_fetch；此函数保留只为编译兼容，无效果")]
pub fn set_shared_http_client<T>(_client: T) {}

/// 抓取规则集 body。HTTP/HTTPS 走 core_fetch，`file://` 与本地路径走 fs::read。
///
/// 全程 INFO 级日志：
/// * `begin`   —— 即将抓取的 URL
/// * `done`    —— 完成时输出耗时与字节数
/// * `failed`  —— 失败时输出错误
///
/// 这样在 `RUST_LOG=info` 默认配置下，用户启动时就能看到所有规则集的抓取过程，
/// 不会出现"配了 sets 但启动后毫无动静"的状态。
pub async fn fetch_ruleset(src: &str, timeout: Duration) -> Result<Vec<u8>, FetchError> {
    let started = Instant::now();
    if src.starts_with("file://") {
        let path = src.trim_start_matches("file://");
        debug!(target: "ruleset::fetch", path, "load file://");
        let body = read_local_limited(Path::new(path), MAX_RULESET_BODY_BYTES)?;
        info!(target: "ruleset::fetch", scheme = "file", path, bytes = body.len(), "loaded");
        return Ok(body);
    }
    if !(src.starts_with("http://") || src.starts_with("https://")) {
        if Path::new(src).exists() {
            let body = read_local_limited(Path::new(src), MAX_RULESET_BODY_BYTES)?;
            info!(target: "ruleset::fetch", scheme = "fs", path = src, bytes = body.len(), "loaded");
            return Ok(body);
        }
        return Err(FetchError::BadUrl(src.into()));
    }
    info!(target: "ruleset::fetch", url = src, timeout_ms = timeout.as_millis() as u64, "begin");
    let opts = core_fetch::FetchOptions {
        user_agent: concat!("WutherCore-ruleset/", env!("CARGO_PKG_VERSION")).to_string(),
        timeout,
        connect_timeout: Duration::from_secs(10),
        max_body_bytes: MAX_RULESET_BODY_BYTES,
        ..Default::default()
    };
    let resp = match core_fetch::fetch(src, &opts).await {
        Ok(r) => r,
        Err(core_fetch::FetchError::Status(code)) => {
            warn!(
                target: "ruleset::fetch",
                url = src,
                status = code,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "non-2xx"
            );
            return Err(FetchError::Status(code));
        }
        Err(e) => {
            warn!(
                target: "ruleset::fetch",
                url = src,
                elapsed_ms = started.elapsed().as_millis() as u64,
                error = %e,
                "send failed"
            );
            return Err(FetchError::from(e));
        }
    };
    info!(
        target: "ruleset::fetch",
        url = src,
        status = resp.status,
        bytes = resp.bytes.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "done"
    );
    Ok(resp.bytes)
}

pub(crate) fn read_local_limited(path: &Path, limit: usize) -> Result<Vec<u8>, FetchError> {
    let file = std::fs::File::open(path)?;
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = file.take(read_limit);
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(FetchError::BodyTooLarge { limit });
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ruleset_read_is_bounded() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-ruleset-fetch-limit-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"123456").unwrap();

        let err = read_local_limited(&path, 5).unwrap_err();
        assert!(matches!(err, FetchError::BodyTooLarge { limit: 5 }));

        let _ = std::fs::remove_file(path);
    }
}
