//! 订阅磁盘缓存 —— 抓取失败时回退到上一次成功内容；同时持久化"上次刷新时间"
//! 等元数据，保证重启后按 `every` 错峰拉取。
//!
//! 文件布局：
//! ```text
//!   data/feeds/
//!       primary.cache      — 上次成功获取的原始 payload（可能是 yaml/txt/json/sub64）
//!       primary.meta.json  — { "last_refreshed_ms": 1714512345000,
//!                              "raw_size": 12345,
//!                              "etag": "...", "content_type": "text/yaml",
//!                              "url_hash": "..." }
//!   ...
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct FeedDiskCache {
    root: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedMeta {
    /// epoch millis 上次成功 fetch 的时间。
    #[serde(default)]
    pub last_refreshed_ms: u64,
    #[serde(default)]
    pub raw_size: u64,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// URL 摘要（仅用于检测配置 url 改动后丢弃旧缓存）。
    #[serde(default)]
    pub url_hash: Option<String>,
}

impl FeedMeta {
    /// 当前距上次刷新已过去多久。`last_refreshed_ms == 0` 时返回 None。
    pub fn elapsed(&self) -> Option<Duration> {
        if self.last_refreshed_ms == 0 {
            return None;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now_ms < self.last_refreshed_ms {
            // 时钟回拨：当作"刚刚刷新"处理，避免 every 内反复拉取。
            return Some(Duration::from_millis(0));
        }
        Some(Duration::from_millis(now_ms.saturating_sub(self.last_refreshed_ms)))
    }
}

impl FeedDiskCache {
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{}.cache", safe_name(name)))
    }
    fn meta_path_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{}.meta.json", safe_name(name)))
    }

    pub fn save(&self, name: &str, data: &[u8]) {
        let path = self.path_for(name);
        if let Err(e) = std::fs::write(&path, data) {
            warn!(target: "feeds::cache", error = %e, path = %path.display(), "save failed");
        } else {
            debug!(target: "feeds::cache", path = %path.display(), bytes = data.len(), "saved");
        }
    }

    pub fn load(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.path_for(name);
        std::fs::read(&path).ok()
    }

    /// 一次性写 raw + meta —— 推荐 fetch 成功后调用，保证两份一致。
    pub fn save_with_meta(&self, name: &str, data: &[u8], meta: &FeedMeta) {
        self.save(name, data);
        self.save_meta(name, meta);
    }

    pub fn save_meta(&self, name: &str, meta: &FeedMeta) {
        let path = self.meta_path_for(name);
        match serde_json::to_vec_pretty(meta) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, bytes) {
                    warn!(target: "feeds::cache", error = %e, path = %path.display(), "save meta failed");
                }
            }
            Err(e) => warn!(target: "feeds::cache", error = %e, "serialize meta failed"),
        }
    }

    pub fn load_meta(&self, name: &str) -> Option<FeedMeta> {
        let path = self.meta_path_for(name);
        let bytes = std::fs::read(&path).ok()?;
        match serde_json::from_slice::<FeedMeta>(&bytes) {
            Ok(m) => Some(m),
            Err(e) => {
                warn!(target: "feeds::cache", error = %e, path = %path.display(), "parse meta failed; treating as missing");
                None
            }
        }
    }

    /// 删除一个 feed 的 cache + meta（用于 url 改变时清旧）。
    pub fn forget(&self, name: &str) {
        let _ = std::fs::remove_file(self.path_for(name));
        let _ = std::fs::remove_file(self.meta_path_for(name));
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect::<String>()
}

/// 计算 url 的 8 位摘要 —— 仅用于 meta.url_hash 比对，不要求加密强度。
pub fn url_digest(url: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    url.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "rpkernel-feeds-cache-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn save_load_meta_roundtrip() {
        let root = tmp();
        let c = FeedDiskCache::new(&root).unwrap();
        let m = FeedMeta {
            last_refreshed_ms: 1_700_000_000_000,
            raw_size: 42,
            etag: Some("W/\"abc\"".into()),
            content_type: Some("text/yaml".into()),
            url_hash: Some(url_digest("https://example.com/sub")),
        };
        c.save_meta("a", &m);
        let got = c.load_meta("a").unwrap();
        assert_eq!(got.last_refreshed_ms, m.last_refreshed_ms);
        assert_eq!(got.etag.as_deref(), Some("W/\"abc\""));
        assert_eq!(got.url_hash, m.url_hash);
    }

    #[test]
    fn missing_meta_returns_none() {
        let c = FeedDiskCache::new(tmp()).unwrap();
        assert!(c.load_meta("never").is_none());
    }

    #[test]
    fn elapsed_handles_zero_and_clock_skew() {
        let mut m = FeedMeta::default();
        assert!(m.elapsed().is_none());
        // 极未来时间 → 时钟回拨保护。
        m.last_refreshed_ms = u64::MAX / 2;
        assert!(m.elapsed().is_some());
    }

    #[test]
    fn forget_removes_both_files() {
        let root = tmp();
        let c = FeedDiskCache::new(&root).unwrap();
        c.save_with_meta("x", b"hi", &FeedMeta::default());
        assert!(c.load("x").is_some());
        c.forget("x");
        assert!(c.load("x").is_none());
        assert!(c.load_meta("x").is_none());
    }

    #[test]
    fn url_digest_stable() {
        assert_eq!(url_digest("https://a"), url_digest("https://a"));
        assert_ne!(url_digest("https://a"), url_digest("https://b"));
    }
}
