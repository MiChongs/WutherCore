//! 规则集抓取 —— 与 core-feeds 同构（HTTP/HTTPS/file/本地路径）。

use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{debug, info, warn};

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
}

/// 抓取规则集 body。HTTP/HTTPS 走 reqwest，`file://` 与本地路径走 fs::read。
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
        let body = std::fs::read(path)?;
        info!(target: "ruleset::fetch", scheme = "file", path, bytes = body.len(), "loaded");
        return Ok(body);
    }
    if !(src.starts_with("http://") || src.starts_with("https://")) {
        if std::path::Path::new(src).exists() {
            let body = std::fs::read(src)?;
            info!(target: "ruleset::fetch", scheme = "fs", path = src, bytes = body.len(), "loaded");
            return Ok(body);
        }
        return Err(FetchError::BadUrl(src.into()));
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("RPKernel-ruleset/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .gzip(true)
        .brotli(true)
        .build()
        .map_err(|e| FetchError::Http(e.to_string()))?;
    info!(target: "ruleset::fetch", url = src, timeout_ms = timeout.as_millis() as u64, "begin");
    let resp = match client.get(src).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                target: "ruleset::fetch",
                url = src,
                elapsed_ms = started.elapsed().as_millis() as u64,
                error = %e,
                "send failed"
            );
            return Err(FetchError::Http(e.to_string()));
        }
    };
    let status = resp.status();
    if !status.is_success() {
        warn!(
            target: "ruleset::fetch",
            url = src,
            status = status.as_u16(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "non-2xx"
        );
        return Err(FetchError::Status(status.as_u16()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    info!(
        target: "ruleset::fetch",
        url = src,
        status = status.as_u16(),
        bytes = bytes.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "done"
    );
    Ok(bytes.to_vec())
}
