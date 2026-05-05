//! 规则集抓取 —— core-feeds 同构（HTTP/HTTPS/file/本地路径）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use once_cell::sync::Lazy;
use thiserror::Error;
use tracing::{debug, info, warn};

/// 共享 HTTP client —— 由 core-runtime 在启动 / 网络变化时注入；用 ArcSwapOption
/// 而不是 OnceLock，让 net_monitor 检测到默认网卡切换时能 hot-swap 整个 client
/// （reqwest::ClientBuilder::interface(name) 在 build 时绑定 SO_BINDTODEVICE /
/// IP_BOUND_IF，无法 in-place 改 iface，必须 rebuild）。
static SHARED_CLIENT: Lazy<ArcSwapOption<reqwest::Client>> = Lazy::new(ArcSwapOption::empty);

/// 注入 / 替换共享 client。重复调用会 swap 旧 client；旧 client 被丢弃但
/// 已经在飞行中的请求仍正常完成。
pub fn set_shared_http_client(client: reqwest::Client) {
    SHARED_CLIENT.store(Some(Arc::new(client)));
}

fn get_or_build_client(timeout: Duration) -> Result<reqwest::Client, FetchError> {
    if let Some(c) = SHARED_CLIENT.load_full() {
        return Ok((*c).clone());
    }
    reqwest::Client::builder()
        .user_agent(concat!("WutherCore-ruleset/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .gzip(true)
        .brotli(true)
        .build()
        .map_err(|e| FetchError::Http(e.to_string()))
}

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
    let client = get_or_build_client(timeout)?;
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
