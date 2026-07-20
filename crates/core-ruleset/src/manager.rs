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
    parser::{RulesetCompiled, parse_ruleset_compiled_for_type},
    spec::{RulesetSpec, RulesetType},
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
                match self.compile_inline(name, spec) {
                    Ok((matcher, size)) => {
                        self.index.insert(matcher);
                        if let Some(sink) = self.sink.read().clone() {
                            sink.on_update(RulesetUpdate {
                                name: name.clone(),
                                size,
                                from_cache: false,
                            });
                        }
                        info!(target: "ruleset", name, source = "inline", size, "compiled");
                    }
                    Err(error) => {
                        warn!(
                            target: "ruleset",
                            name,
                            source = "inline",
                            error = %error,
                            "inline ruleset rejected"
                        );
                    }
                }
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
            let (matcher, total) = self.compile_inline(name, spec)?;
            self.index.insert(matcher);
            return Ok(RulesetUpdate {
                name: name.to_string(),
                size: total,
                from_cache: false,
            });
        };
        if spec.url.is_some() && !spec.via.trim().eq_ignore_ascii_case("direct") {
            return Err(format!(
                "download via `{}` is unsupported: core-fetch currently supports direct only",
                spec.via
            ));
        }

        let fetched = fetch_ruleset(src, timeout).await;
        let (matcher, total, from_cache) = match fetched {
            Ok(body) => match self.compile_body(name, spec, Some(src), &body) {
                Ok((matcher, total)) => {
                    // 只有完整解析、编译成功的响应才有资格替换最后可用缓存。
                    // 网络层成功不代表内容是合法规则集。
                    if let Some(cache_path) = self.cache_path(name, spec) {
                        match write_cache_atomically(&cache_path, &body) {
                            Ok(()) => {}
                            Err(error) => {
                                warn!(
                                    target: "ruleset",
                                    name,
                                    path = %cache_path.display(),
                                    error = %error,
                                    "validated ruleset cache write failed"
                                );
                            }
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

    fn cache_path(&self, name: &str, spec: &RulesetSpec) -> Option<PathBuf> {
        // Mihomo HTTP provider（以及 WutherCore 原生 url+path）的 path 表示
        // 显式缓存位置；只有 path 单独出现时它才是本地源，绝不能被缓存覆盖。
        if let (Some(_), Some(path)) = (&spec.url, &spec.path) {
            return Some(PathBuf::from(path));
        }
        self.cache_dir.as_ref().map(|dir| dir.join(safe_name(name)))
    }

    fn compile_cache(
        &self,
        name: &str,
        spec: &RulesetSpec,
        source_hint: Option<&str>,
    ) -> Result<(Arc<RulesetMatcher>, usize), String> {
        let path = self
            .cache_path(name, spec)
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
        let compiled = parse_ruleset_compiled_for_type(format, body, spec.r#type)
            .map_err(|e| e.to_string())?;
        self.compile_parsed(name, spec, compiled)
    }

    fn compile_inline(
        &self,
        name: &str,
        spec: &RulesetSpec,
    ) -> Result<(Arc<RulesetMatcher>, usize), String> {
        let normalized_format = spec
            .format
            .as_deref()
            .map(|format| format.trim().to_ascii_lowercase());
        match normalized_format.as_deref() {
            None | Some("yaml" | "yml" | "text" | "txt" | "list") => {
                let entries = crate::parser::txt::parse_lines_for_type(
                    spec.payload.iter().map(String::as_str),
                    spec.r#type,
                )
                .map_err(|error| error.to_string())?;
                self.compile_parsed(name, spec, RulesetCompiled::Classical(entries))
            }
            Some("json" | "singbox" | "sing-box") => {
                let body = spec.payload.join("\n");
                self.compile_body(name, spec, None, body.as_bytes())
            }
            Some("mrs" | "srs" | "rrs" | "mihomo-binary" | "singbox-binary") => Err(format!(
                "binary format `{}` cannot be represented by inline YAML payload",
                spec.format.as_deref().unwrap_or("binary")
            )),
            Some(other) => Err(format!("unknown inline ruleset format `{other}`")),
        }
    }

    fn compile_parsed(
        &self,
        name: &str,
        spec: &RulesetSpec,
        compiled: RulesetCompiled,
    ) -> Result<(Arc<RulesetMatcher>, usize), String> {
        if let RulesetCompiled::Mrs(payload) = &compiled {
            let expected = match spec.r#type {
                RulesetType::Domain => "domain",
                RulesetType::Ipcidr => "ipcidr",
                RulesetType::Classical | RulesetType::Mixed => {
                    return Err(format!(
                        "MRS ruleset `{name}` requires type domain or ipcidr, configured type is {:?}",
                        spec.r#type
                    ));
                }
            };
            if payload.behavior_label() != expected {
                return Err(format!(
                    "MRS behavior `{}` does not match configured RulesetType `{expected}` for `{name}`",
                    payload.behavior_label()
                ));
            }
        }
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

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
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

    #[tokio::test]
    async fn singbox_inline_source_json_preserves_semantic_rules() {
        let spec = RulesetSpec {
            url: None,
            path: None,
            payload: vec![
                r#"{"version":5,"rules":[{"domain_suffix":"example.com","port":443}]}"#.into(),
            ],
            r#type: crate::spec::RulesetType::Mixed,
            format: Some("json".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(BTreeMap::new(), None, idx.clone());

        let update = mgr.refresh_once("singbox-inline", &spec).await.unwrap();
        assert_eq!(update.size, 1);
        let matcher = idx.get("singbox-inline").unwrap();
        assert!(matcher.matches("www.example.com", None, Some(443), None));
        assert!(!matcher.matches("www.example.com", None, Some(80), None));
    }

    #[tokio::test]
    async fn invalid_inline_item_is_reported_instead_of_dropped() {
        let spec = RulesetSpec {
            url: None,
            path: None,
            payload: vec!["NOT-A-RULE".into()],
            r#type: crate::spec::RulesetType::Classical,
            format: Some("text".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let mgr = RulesetManager::new(BTreeMap::new(), None, RulesetIndex::new());

        let error = mgr.refresh_once("invalid-inline", &spec).await.unwrap_err();
        assert!(error.contains("line 1"), "{error}");
        assert!(error.contains("NOT-A-RULE"), "{error}");
    }

    #[test]
    fn mihomo_yaml_and_text_are_dispatched_by_declared_behavior() {
        let mgr = RulesetManager::new(BTreeMap::new(), None, RulesetIndex::new());
        let mut spec = RulesetSpec {
            url: None,
            path: Some("provider.yaml".into()),
            payload: vec![],
            r#type: crate::spec::RulesetType::Domain,
            format: Some("yaml".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let yaml =
            b"payload:\n  - '.blogger.com'\n  - '*.*.microsoft.com'\n  - books.itunes.apple.com\n";
        let (matcher, size) = mgr
            .compile_body("domain", &spec, spec.path.as_deref(), yaml)
            .unwrap();
        assert_eq!(size, 3);
        assert!(matcher.matches("www.blogger.com", None, None, None));
        assert!(!matcher.matches("blogger.com", None, None, None));
        assert!(matcher.matches("a.b.microsoft.com", None, None, None));
        assert!(!matcher.matches("a.microsoft.com", None, None, None));

        spec.r#type = crate::spec::RulesetType::Ipcidr;
        spec.format = Some("text".into());
        spec.path = Some("provider.txt".into());
        let (matcher, size) = mgr
            .compile_body(
                "ip",
                &spec,
                spec.path.as_deref(),
                b"192.0.2.1\n2001:db8::/32\n",
            )
            .unwrap();
        assert_eq!(size, 2);
        assert!(matcher.matches("", Some("192.0.2.1".parse().unwrap()), None, None));
        assert!(matcher.matches("", Some("2001:db8::1".parse().unwrap()), None, None));

        spec.r#type = crate::spec::RulesetType::Domain;
        let error = mgr
            .compile_body("wrong-domain", &spec, spec.path.as_deref(), b"10.0.0.0/8\n")
            .unwrap_err();
        assert!(error.contains("does not accept IP"), "{error}");

        spec.r#type = crate::spec::RulesetType::Classical;
        let error = mgr
            .compile_body(
                "unsupported-classical",
                &spec,
                spec.path.as_deref(),
                b"GEOIP,CN\n",
            )
            .unwrap_err();
        assert!(error.contains("unsupported classical rule kind"), "{error}");
    }

    #[test]
    fn mrs_payload_behavior_must_match_configured_ruleset_type() {
        let mgr = RulesetManager::new(BTreeMap::new(), None, RulesetIndex::new());
        let domain_body = include_bytes!("../tests/data/sample_domain.mrs");
        let ip_body = include_bytes!("../tests/data/sample_ipcidr.mrs");

        let mut spec = RulesetSpec {
            url: Some("https://rules.example/domain.mrs".into()),
            path: None,
            payload: vec![],
            r#type: crate::spec::RulesetType::Domain,
            format: Some("mrs".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        assert!(
            mgr.compile_body("domain", &spec, spec.url.as_deref(), domain_body)
                .is_ok()
        );

        spec.r#type = crate::spec::RulesetType::Ipcidr;
        let error = mgr
            .compile_body("domain", &spec, spec.url.as_deref(), domain_body)
            .unwrap_err();
        assert!(error.contains("does not match"), "{error}");
        assert!(error.contains("domain"), "{error}");
        assert!(error.contains("ipcidr"), "{error}");

        spec.r#type = crate::spec::RulesetType::Domain;
        let error = mgr
            .compile_body("ip", &spec, spec.url.as_deref(), ip_body)
            .unwrap_err();
        assert!(error.contains("does not match"), "{error}");

        spec.r#type = crate::spec::RulesetType::Mixed;
        let error = mgr
            .compile_body("domain", &spec, spec.url.as_deref(), domain_body)
            .unwrap_err();
        assert!(error.contains("requires type domain or ipcidr"), "{error}");
    }

    #[test]
    fn http_provider_path_is_used_as_its_explicit_cache() {
        let dir = temp_test_dir("explicit-provider-cache");
        let cache_path = dir.join("nested").join("provider.yaml");
        write_cache_atomically(&cache_path, b"payload:\n  - '+.explicit-cache.example'\n").unwrap();
        let spec = RulesetSpec {
            url: Some("http://127.0.0.1:9/provider.yaml".into()),
            path: Some(cache_path.display().to_string()),
            payload: vec![],
            r#type: crate::spec::RulesetType::Domain,
            format: Some("yaml".into()),
            every: Duration::from_secs(3600),
            via: "direct".into(),
        };
        let mgr = RulesetManager::new(BTreeMap::new(), None, RulesetIndex::new());

        assert_eq!(mgr.cache_path("provider", &spec), Some(cache_path.clone()));
        let (matcher, size) = mgr
            .compile_cache("provider", &spec, spec.url.as_deref())
            .unwrap();
        assert_eq!(size, 1);
        assert!(matcher.matches("www.explicit-cache.example", None, None, None));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn non_direct_download_via_is_an_explicit_manager_error() {
        let spec = RulesetSpec {
            url: Some("https://rules.example/domain.yaml".into()),
            path: None,
            payload: vec![],
            r#type: crate::spec::RulesetType::Domain,
            format: Some("yaml".into()),
            every: Duration::from_secs(3600),
            via: "proxy-group".into(),
        };
        let mgr = RulesetManager::new(BTreeMap::new(), None, RulesetIndex::new());

        let error = mgr.refresh_once("proxied", &spec).await.unwrap_err();
        assert!(error.contains("proxy-group"), "{error}");
        assert!(error.contains("direct only"), "{error}");
    }
}
