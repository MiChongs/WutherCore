//! 规则集编排：拉取 → 解析 → 编译 → 推送给索引；后台周期刷新。

use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use parking_lot::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{
    fetch::{MAX_RULESET_BODY_BYTES, fetch_ruleset, read_local_limited},
    format::detect_format,
    matcher::{RulesetIndex, RulesetMatcher},
    parser::{RulesetCompiled, parse_ruleset_compiled},
    spec::RulesetSpec,
};

#[derive(Debug, Clone)]
pub struct RulesetUpdate {
    pub name: String,
    pub size: usize,
    pub from_cache: bool,
}

pub trait RulesetSink: Send + Sync {
    fn on_update(&self, update: RulesetUpdate);
}

pub struct RulesetManager {
    sets: BTreeMap<String, RulesetSpec>,
    cache_dir: Option<PathBuf>,
    index: Arc<RulesetIndex>,
    sink: RwLock<Option<Arc<dyn RulesetSink>>>,
    handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl RulesetManager {
    pub fn new(
        sets: BTreeMap<String, RulesetSpec>,
        cache_dir: Option<PathBuf>,
        index: Arc<RulesetIndex>,
    ) -> Arc<Self> {
        if let Some(d) = &cache_dir {
            let _ = std::fs::create_dir_all(d);
        }
        Arc::new(Self {
            sets,
            cache_dir,
            index,
            sink: RwLock::new(None),
            handles: parking_lot::Mutex::new(Vec::new()),
        })
    }

    pub fn set_sink(self: &Arc<Self>, sink: Arc<dyn RulesetSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn index(&self) -> Arc<RulesetIndex> {
        self.index.clone()
    }

    /// 启动：每个规则集独立后台协程，立刻拉一次 + 按 `every` 周期刷新。
    ///
    /// 启动时同步行为：
    /// * 内联 `payload` —— 直接 compile，命中后写入 index。
    /// * 远程 `url` / 本地 `path` —— spawn 一个后台任务；若磁盘缓存命中则
    ///   先用缓存编译（dashboard 立即可用），随后拉网刷新。
    ///
    /// 启动一定会输出一行 INFO 日志，列出每个 set 的 url/path/payload 概况，
    /// 方便用户在配了 `route.sets` 但启动后毫无动静时第一时间发现是否走到了这里。
    pub fn start(self: Arc<Self>) {
        info!(
            target: "ruleset",
            count = self.sets.len(),
            cache_dir = ?self.cache_dir,
            "ruleset manager starting (initial fetch + periodic refresh)"
        );
        if self.sets.is_empty() {
            return;
        }
        // 1) 内联 payload 立刻 compile
        for (name, spec) in &self.sets {
            if !spec.payload.is_empty() && spec.url.is_none() && spec.path.is_none() {
                let entries = self.parse_inline(spec);
                let m = Arc::new(RulesetMatcher::compile(name.clone(), entries));
                self.index.insert(m.clone());
                if let Some(sink) = self.sink.read().clone() {
                    sink.on_update(RulesetUpdate {
                        name: name.clone(),
                        size: m.stats().domains,
                        from_cache: false,
                    });
                }
                info!(target: "ruleset", name, source = "inline", size = m.stats().domains, "compiled");
            }
        }
        // 2) 远程 / 文件 set —— 每个独立后台 task
        for (name, spec) in self.sets.clone() {
            if spec.url.is_none() && spec.path.is_none() {
                continue;
            }
            let source_hint = spec.url.as_deref().or(spec.path.as_deref());
            match self.compile_cache(&name, &spec, source_hint) {
                Ok((matcher, size)) => {
                    self.index.insert(matcher);
                    let update = RulesetUpdate {
                        name: name.clone(),
                        size,
                        from_cache: true,
                    };
                    if let Some(sink) = self.sink.read().clone() {
                        sink.on_update(update);
                    }
                    info!(
                        target: "ruleset",
                        name = %name,
                        size,
                        source = "cache",
                        "compiled last valid cache before refresh"
                    );
                }
                Err(error) => {
                    debug!(
                        target: "ruleset",
                        name = %name,
                        error = %error,
                        "no valid startup cache"
                    );
                }
            }
            let src_label = spec
                .url
                .clone()
                .or_else(|| spec.path.clone())
                .unwrap_or_else(|| "<inline>".into());
            info!(
                target: "ruleset",
                name = %name,
                src = %src_label,
                every_secs = spec.every.as_secs(),
                "spawn refresh task"
            );
            let me = self.clone();
            let handle = tokio::spawn(async move {
                me.run_one(name, spec).await;
            });
            self.handles.lock().push(handle);
        }
    }

    pub fn stop(&self) {
        for h in self.handles.lock().drain(..) {
            h.abort();
        }
    }

    fn parse_inline(&self, spec: &RulesetSpec) -> Vec<crate::matcher::ClassicalEntry> {
        spec.payload
            .iter()
            .filter_map(|s| crate::parser::txt::parse_line(s))
            .collect()
    }

    async fn run_one(self: Arc<Self>, name: String, spec: RulesetSpec) {
        loop {
            match self.refresh_once(&name, &spec).await {
                Ok(update) => {
                    info!(target: "ruleset", name = %name, size = update.size, from_cache = update.from_cache, "compiled");
                    if let Some(sink) = self.sink.read().clone() {
                        sink.on_update(update);
                    }
                }
                Err(e) => warn!(target: "ruleset", name = %name, error = %e, "refresh failed"),
            }
            tokio::time::sleep(clamp_interval(spec.every)).await;
        }
    }

    /// 一次完整的拉取 + 解析 + 编译 + 入索引。
    pub async fn refresh_once(
        &self,
        name: &str,
        spec: &RulesetSpec,
    ) -> Result<RulesetUpdate, String> {
        let timeout = Duration::from_secs(30);
        let src = spec.url.as_deref().or(spec.path.as_deref());
        let Some(src) = src else {
            let entries: Vec<_> = self.parse_inline(spec);
            let m = Arc::new(RulesetMatcher::compile(name.to_string(), entries));
            let stats = m.stats();
            let total = stats.domains + stats.suffixes + stats.cidr_v4 + stats.cidr_v6;
            self.index.insert(m);
            return Ok(RulesetUpdate {
                name: name.to_string(),
                size: total,
                from_cache: false,
            });
        };

        let fetched = fetch_ruleset(src, timeout).await;
        let (matcher, total, from_cache) = match fetched {
            Ok(body) => match self.compile_body(name, spec, Some(src), &body) {
                Ok((matcher, total)) => {
                    // 只有完整解析、编译成功的响应才有资格替换最后可用缓存。
                    // 网络层成功不代表内容是合法规则集。
                    if let Some(cache_path) = self.cache_path(name) {
                        if let Err(error) = write_cache_atomically(&cache_path, &body) {
                            warn!(
                                target: "ruleset",
                                name,
                                path = %cache_path.display(),
                                error = %error,
                                "validated ruleset cache write failed"
                            );
                        }
                    }
                    (matcher, total, false)
                }
                Err(parse_error) => {
                    warn!(
                        target: "ruleset",
                        name,
                        error = %parse_error,
                        "fetched ruleset is invalid; keeping cache and trying last valid copy"
                    );
                    let (matcher, total) =
                        self.compile_cache(name, spec, Some(src))
                            .map_err(|cache_error| {
                                format!(
                                    "fetched ruleset invalid: {parse_error}; cache unavailable or \
                                 invalid: {cache_error}"
                                )
                            })?;
                    (matcher, total, true)
                }
            },
            Err(fetch_error) => {
                warn!(
                    target: "ruleset",
                    name,
                    error = %fetch_error,
                    "ruleset fetch failed; trying last valid cache"
                );
                let (matcher, total) = self.compile_cache(name, spec, Some(src)).map_err(
                    |cache_error| {
                        format!(
                            "ruleset fetch failed: {fetch_error}; cache unavailable or invalid: \
                             {cache_error}"
                        )
                    },
                )?;
                (matcher, total, true)
            }
        };

        self.index.insert(matcher);
        Ok(RulesetUpdate {
            name: name.to_string(),
            size: total,
            from_cache,
        })
    }

    fn cache_path(&self, name: &str) -> Option<PathBuf> {
        self.cache_dir.as_ref().map(|dir| dir.join(safe_name(name)))
    }

    fn compile_cache(
        &self,
        name: &str,
        spec: &RulesetSpec,
        source_hint: Option<&str>,
    ) -> Result<(Arc<RulesetMatcher>, usize), String> {
        let path = self
            .cache_path(name)
            .ok_or_else(|| "cache directory is not configured".to_string())?;
        let body = read_local_limited(&path, MAX_RULESET_BODY_BYTES)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        self.compile_body(name, spec, source_hint, &body)
    }

    fn compile_body(
        &self,
        name: &str,
        spec: &RulesetSpec,
        source_hint: Option<&str>,
        body: &[u8],
    ) -> Result<(Arc<RulesetMatcher>, usize), String> {
        let format = detect_format(spec.format.as_deref(), source_hint, body);
        debug!(target: "ruleset", name, ?format, bytes = body.len(), "parse");
        let compiled = parse_ruleset_compiled(format, body).map_err(|e| e.to_string())?;
        // 统计 size：classical 用 Vec.len()；语义格式用顶层 rule 数；
        // MRS 用 payload.count（header 字段）。
        let total = match &compiled {
            RulesetCompiled::Classical(v) => v.len(),
            RulesetCompiled::Semantic(program) => program.rule_count(),
            RulesetCompiled::Mrs(p) => p.count(),
        };
        if let RulesetCompiled::Mrs(p) = &compiled {
            debug!(
                target: "ruleset",
                name,
                behavior = p.behavior_label(),
                count = p.count(),
                approx_bytes = p.approx_bytes(),
                "parsed mihomo MRS"
            );
        }
        let m = Arc::new(RulesetMatcher::compile_any(name.to_string(), compiled));
        Ok((m, total))
    }
}

fn clamp_interval(d: Duration) -> Duration {
    let min = Duration::from_secs(5 * 60);
    let max = Duration::from_secs(30 * 24 * 3600);
    if d < min {
        min
    } else if d > max {
        max
    } else {
        d
    }
}

fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write_cache_atomically(path: &Path, body: &[u8]) -> std::io::Result<()> {
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ruleset");
    let temp = path.with_file_name(format!(".{name}.tmp-{}-{id}", std::process::id()));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn temp_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wuthercore-ruleset-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validated_cache_replace_is_atomic_and_cleans_temporary_file() {
        let dir = temp_test_dir("atomic-cache");
        let path = dir.join("rules");
        std::fs::write(&path, b"old").unwrap();

        write_cache_atomically(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn inline_payload_compiles_immediately() {
        let mut sets = BTreeMap::new();
        sets.insert(
            "my-direct".to_string(),
            RulesetSpec {
                url: None,
                path: None,
                payload: vec![
                    "DOMAIN-SUFFIX,example.com".into(),
                    "+.qq.com".into(),
                    "10.0.0.0/8".into(),
                ],
                r#type: crate::spec::RulesetType::Mixed,
                format: None,
                every: Duration::from_secs(3600),
                via: "direct".into(),
            },
        );
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(sets, None, idx.clone());
        mgr.clone().start();
        // 内联立刻命中
        let m = idx.get("my-direct").unwrap();
        assert!(m.matches("a.example.com", None, None, None));
        assert!(m.matches("im.qq.com", None, None, None));
        assert!(m.matches("", "10.1.2.3".parse().ok(), None, None));
        mgr.stop();
    }

    #[tokio::test]
    async fn startup_cache_is_available_before_network_refresh() {
        let dir = temp_test_dir("startup-cache");
        std::fs::write(
            dir.join("startup_set"),
            b"payload:\n  - DOMAIN-SUFFIX,startup.example\n",
        )
        .unwrap();
        let mut sets = BTreeMap::new();
        sets.insert(
            "startup_set".into(),
            RulesetSpec {
                url: Some("http://127.0.0.1:9/rules.yaml".into()),
                path: None,
                payload: vec![],
                r#type: crate::spec::RulesetType::Mixed,
                format: Some("yaml".into()),
                every: Duration::from_secs(3600),
                via: "direct".into(),
            },
        );
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(sets, Some(dir.clone()), idx.clone());

        mgr.clone().start();

        let matcher = idx
            .get("startup_set")
            .expect("cache must be compiled synchronously");
        assert!(matcher.matches("www.startup.example", None, None, None));
        mgr.stop();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn refresh_local_yaml_works() {
        let dir = temp_test_dir("local");
        let p = dir.join("test.yaml");
        std::fs::write(
            &p,
            b"payload:\n  - DOMAIN-SUFFIX,test.com\n  - 192.168.0.0/16\n",
        )
        .unwrap();
        let mut sets = BTreeMap::new();
        sets.insert(
            "rs1".into(),
            RulesetSpec {
                url: None,
                path: Some(p.display().to_string()),
                payload: vec![],
                r#type: crate::spec::RulesetType::Mixed,
                format: Some("yaml".into()),
                every: Duration::from_secs(3600),
                via: "direct".into(),
            },
        );
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(sets.clone(), Some(dir.clone()), idx.clone());
        let spec = sets.get("rs1").unwrap().clone();
        let upd = mgr.refresh_once("rs1", &spec).await.unwrap();
        assert_eq!(upd.size, 2);
        let m = idx.get("rs1").unwrap();
        assert!(m.matches("a.test.com", None, None, None));
        assert!(m.matches("", "192.168.5.10".parse().ok(), None, None));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn invalid_refresh_uses_and_preserves_last_valid_cache() {
        let dir = temp_test_dir("cache-fallback");
        let source = dir.join("source.yaml");
        std::fs::write(&source, b"payload: [").unwrap();
        let cached = b"payload:\n  - DOMAIN-SUFFIX,cached.example\n";
        std::fs::write(dir.join("safe_set"), cached).unwrap();

        let spec = RulesetSpec {
            url: None,
            path: Some(source.display().to_string()),
            payload: vec![],
            r#type: crate::spec::RulesetType::Mixed,
            format: Some("yaml".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(BTreeMap::new(), Some(dir.clone()), idx.clone());

        let update = mgr.refresh_once("safe_set", &spec).await.unwrap();
        assert!(update.from_cache);
        assert_eq!(std::fs::read(dir.join("safe_set")).unwrap(), cached);
        assert!(
            idx.get("safe_set")
                .unwrap()
                .matches("www.cached.example", None, None, None)
        );

        let fresh = b"payload:\n  - DOMAIN-SUFFIX,fresh.example\n";
        std::fs::write(&source, fresh).unwrap();
        let update = mgr.refresh_once("safe_set", &spec).await.unwrap();
        assert!(!update.from_cache);
        assert_eq!(std::fs::read(dir.join("safe_set")).unwrap(), fresh);
        let matcher = idx.get("safe_set").unwrap();
        assert!(matcher.matches("www.fresh.example", None, None, None));
        assert!(!matcher.matches("www.cached.example", None, None, None));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn invalid_refresh_without_cache_keeps_index_unchanged() {
        let dir = temp_test_dir("cache-miss");
        let source = dir.join("source.yaml");
        std::fs::write(&source, b"payload: [").unwrap();
        let spec = RulesetSpec {
            url: None,
            path: Some(source.display().to_string()),
            payload: vec![],
            r#type: crate::spec::RulesetType::Mixed,
            format: Some("yaml".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(BTreeMap::new(), Some(dir.clone()), idx.clone());

        let error = mgr.refresh_once("missing_cache", &spec).await.unwrap_err();
        assert!(error.contains("fetched ruleset invalid"));
        assert!(idx.get("missing_cache").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }
}
