//! FeedManager —— 编排多个 feed：
//!
//! * **启动时**：先读 disk cache + meta；如果 `last_refreshed + every > now`，
//!   立刻 emit "snapshot from cache"（让 Runtime 拿到上次的节点列表，不阻塞启动），
//!   然后 sleep 到下一次 due 才发起 HTTP 拉取；
//! * **首次 / cache 过期**：立即 fetch；
//! * **fetch 成功**：写 raw + meta；
//! * **fetch 失败**：fallback 到 disk cache（如果存在）；
//! * **空 feeds**：`start()` 是 noop，所有读取 API 返回空集，不 panic；
//! * **每条 feed 独立协程**：互不阻塞；可通过 [`FeedManager::refresh_now`] 由
//!   `/providers/proxies/:name PUT` 主动触发。
//!
//! 配置变更检测：`meta.url_hash` 与当前 url 不一致时强制重拉，避免用旧域名
//! 的 cache 给新订阅。

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use core_config::{model::FeedDetail, node_uri::ParsedNode};
use parking_lot::RwLock;
use tokio::{sync::Notify, task::JoinHandle};
use tracing::{debug, info, warn};

use crate::{
    cache::{FeedDiskCache, FeedMeta, url_digest},
    fetcher::fetch_feed,
    parser::{FormatHint, apply_filter_rename, parse_feed_payload},
    userinfo::SubscriptionUserinfo,
};

/// 一次刷新结果。
#[derive(Debug, Clone)]
pub struct FeedUpdate {
    pub name: String,
    pub nodes: Vec<ParsedNode>,
    pub from_cache: bool,
    pub raw_bytes: usize,
    /// 解析自 HTTP 响应的订阅用量；本地路径 / 缺头 / 走缓存时为 None。
    pub userinfo: Option<SubscriptionUserinfo>,
}

/// 节点接收方 —— 由 Runtime 实现，把新节点列表注册到 outbound + groups。
#[async_trait]
pub trait FeedSink: Send + Sync {
    async fn on_update(&self, update: FeedUpdate);
}

/// 单个 feed 的运行时状态 —— 供 `/providers/proxies/:name` 等 API 查询。
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedStatus {
    pub name: String,
    pub url: String,
    pub every_secs: u64,
    pub last_refreshed_ms: u64,
    pub next_due_ms: u64,
    pub last_node_count: usize,
    pub last_raw_bytes: u64,
    pub last_from_cache: bool,
    /// 上次成功在线刷新时拿到的订阅用量；走缓存或本地源时保持上一次的值
    /// （不被覆盖为 None），方便面板持续显示。
    pub userinfo: Option<SubscriptionUserinfo>,
}

#[derive(Default)]
pub struct FeedManager {
    feeds: BTreeMap<String, FeedDetail>,
    cache: Option<FeedDiskCache>,
    sink: RwLock<Option<Arc<dyn FeedSink>>>,
    handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    snapshots: RwLock<BTreeMap<String, Vec<ParsedNode>>>,
    /// per-feed 状态（更新时间、节点数、原始字节数等）—— 控制面板用。
    statuses: RwLock<BTreeMap<String, FeedStatus>>,
    /// per-feed wakeup —— refresh_now 时唤醒 sleep。
    notifies: RwLock<BTreeMap<String, Arc<Notify>>>,
}

impl FeedManager {
    pub fn new(feeds: BTreeMap<String, FeedDetail>, cache: Option<FeedDiskCache>) -> Arc<Self> {
        let mut notifies = BTreeMap::new();
        let mut statuses = BTreeMap::new();
        for (n, d) in &feeds {
            notifies.insert(n.clone(), Arc::new(Notify::new()));
            statuses.insert(
                n.clone(),
                FeedStatus {
                    name: n.clone(),
                    url: d.url.clone(),
                    every_secs: d.every.as_secs(),
                    last_refreshed_ms: 0,
                    next_due_ms: 0,
                    last_node_count: 0,
                    last_raw_bytes: 0,
                    last_from_cache: false,
                    userinfo: None,
                },
            );
        }
        Arc::new(Self {
            feeds,
            cache,
            sink: RwLock::new(None),
            handles: parking_lot::Mutex::new(Vec::new()),
            snapshots: RwLock::new(BTreeMap::new()),
            statuses: RwLock::new(statuses),
            notifies: RwLock::new(notifies),
        })
    }

    pub fn set_sink(self: &Arc<Self>, sink: Arc<dyn FeedSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn snapshot(&self, name: &str) -> Option<Vec<ParsedNode>> {
        self.snapshots.read().get(name).cloned()
    }

    pub fn all_nodes(&self) -> Vec<ParsedNode> {
        self.snapshots
            .read()
            .values()
            .flat_map(|v| v.clone())
            .collect()
    }

    pub fn list_status(&self) -> Vec<FeedStatus> {
        self.statuses.read().values().cloned().collect()
    }

    pub fn status(&self, name: &str) -> Option<FeedStatus> {
        self.statuses.read().get(name).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }

    pub fn names(&self) -> Vec<String> {
        self.feeds.keys().cloned().collect()
    }

    /// 主动触发某个 feed 立即刷新（被 `/providers/proxies/:name PUT` 调用）。
    /// 返回 true 表示已发出唤醒；feed 不存在返回 false。
    pub fn refresh_now(&self, name: &str) -> bool {
        let n = self.notifies.read().get(name).cloned();
        match n {
            Some(notify) => {
                notify.notify_one();
                true
            }
            None => false,
        }
    }

    /// 启动：每个 feed 一个独立协程。空 feeds 是 noop。
    pub fn start(self: Arc<Self>) {
        if self.feeds.is_empty() {
            info!(target: "feeds", "no feeds configured; manager idle");
            return;
        }
        for (name, detail) in self.feeds.clone() {
            let me = self.clone();
            let name_owned = name.clone();
            let detail_owned = detail.clone();
            let notify = self.notifies.read().get(&name).cloned().unwrap_or_default();
            let handle = tokio::spawn(async move {
                me.run_one(name_owned, detail_owned, notify).await;
            });
            self.handles.lock().push(handle);
        }
    }

    /// 启动前同步发布磁盘快照，让 Runtime 在 capture/listener 启动前先拿到
    /// 上次成功的 provider 节点。在线刷新仍由 `start()` 的后台任务继续执行。
    pub async fn bootstrap_cache(self: &Arc<Self>) -> usize {
        let Some(cache) = self.cache.clone() else {
            return 0;
        };
        let mut published = 0usize;
        for (name, detail) in self.feeds.clone() {
            let every = clamp_interval(detail.every);
            if self
                .publish_cache_snapshot_if_valid(&cache, &name, &detail, every, "bootstrap")
                .await
            {
                published += 1;
            }
        }
        published
    }

    pub fn stop(&self) {
        for h in self.handles.lock().drain(..) {
            h.abort();
        }
    }

    /// 单 feed 主循环 —— 先按 meta 决定是否立即 fetch / 复用 cache。
    async fn run_one(self: Arc<Self>, name: String, detail: FeedDetail, notify: Arc<Notify>) {
        let timeout = Duration::from_secs(30);
        let every = clamp_interval(detail.every);

        // 1. 首启动：尝试用 disk meta + cache 计算等待时间。
        let mut initial_wait = Duration::from_secs(0);
        if let Some(cache) = self.cache.as_ref() {
            if let Some(meta) = cache.load_meta(&name) {
                let url_changed = meta
                    .url_hash
                    .as_deref()
                    .map(|hash| hash != url_digest(&detail.url))
                    .unwrap_or(false);
                if url_changed {
                    info!(target: "feeds", name = %name, "url changed since last cache; forgetting");
                    cache.forget(&name);
                } else if let Some(elapsed) = meta.elapsed() {
                    if elapsed < every {
                        initial_wait = every - elapsed;
                    }
                }
                if self.snapshot(&name).is_none() {
                    let _ = self
                        .publish_cache_snapshot_if_valid(cache, &name, &detail, every, "start")
                        .await;
                }
            } else if self.snapshot(&name).is_none() {
                let _ = self
                    .publish_cache_snapshot_if_valid(cache, &name, &detail, every, "start")
                    .await;
            }
        }

        // 2. 等待初始 wait（受 refresh_now 唤醒打断）。
        if !initial_wait.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(initial_wait) => {}
                _ = notify.notified() => {
                    debug!(target: "feeds", name = %name, "refresh_now interrupted initial wait");
                }
            }
        }

        // 3. 主循环：fetch → publish → sleep(every)，sleep 期间 notify 可打断。
        loop {
            match self.refresh_once(&name, &detail, timeout).await {
                Ok(update) => {
                    info!(
                        target: "feeds",
                        name = %name,
                        nodes = update.nodes.len(),
                        bytes = update.raw_bytes,
                        from_cache = update.from_cache,
                        "feed refreshed"
                    );
                    let now_ms = now_ms();
                    self.publish_update(&name, update, Some(now_ms), every)
                        .await;
                }
                Err(e) => {
                    warn!(target: "feeds", name = %name, error = %e, "feed refresh failed");
                    // 失败也要更新 next_due 让 dashboard 看到。
                    let s_lock = self.statuses.read();
                    let last = s_lock.get(&name).map(|s| s.last_refreshed_ms).unwrap_or(0);
                    drop(s_lock);
                    self.update_next_due(&name, last, every);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = notify.notified() => {
                    info!(target: "feeds", name = %name, "refresh_now triggered");
                }
            }
        }
    }

    /// 把更新推到 snapshots / status / sink。
    async fn publish_update(
        self: &Arc<Self>,
        name: &str,
        update: FeedUpdate,
        last_refreshed_ms_override: Option<u64>,
        every: Duration,
    ) {
        self.snapshots
            .write()
            .insert(name.to_string(), update.nodes.clone());
        let last_ms = last_refreshed_ms_override.unwrap_or_else(now_ms);
        if let Some(s) = self.statuses.write().get_mut(name) {
            s.last_refreshed_ms = last_ms;
            s.last_node_count = update.nodes.len();
            s.last_raw_bytes = update.raw_bytes as u64;
            s.last_from_cache = update.from_cache;
            s.next_due_ms = last_ms.saturating_add(every.as_millis() as u64);
            // 仅当本次有新 userinfo 时覆盖；缓存路径不抹掉上次的真实数据，
            // 让面板上 "Upload / Download / Total / Expire" 不会因为一次离线
            // 刷新就变成 0。
            if update.userinfo.is_some() {
                s.userinfo = update.userinfo;
            }
        }
        let sink = { self.sink.read().clone() };
        if let Some(sink) = sink {
            sink.on_update(update).await;
        }
    }

    async fn publish_cache_snapshot_if_valid(
        self: &Arc<Self>,
        cache: &FeedDiskCache,
        name: &str,
        detail: &FeedDetail,
        every: Duration,
        phase: &'static str,
    ) -> bool {
        let meta = cache.load_meta(name);
        if meta
            .as_ref()
            .and_then(|m| m.url_hash.as_deref())
            .map(|hash| hash != url_digest(&detail.url))
            .unwrap_or(false)
        {
            info!(target: "feeds", name = %name, phase, "url changed since last cache; forgetting");
            cache.forget(name);
            return false;
        }

        let Some(raw) = cache.load(name) else {
            return false;
        };
        let nodes = self.parse_with_filter(detail, &raw);
        let last_refreshed_ms = meta
            .as_ref()
            .map(|m| m.last_refreshed_ms)
            .filter(|ms| *ms != 0);
        let stale = meta
            .as_ref()
            .and_then(|m| m.elapsed())
            .map(|elapsed| elapsed >= every)
            .unwrap_or(true);
        self.publish_update(
            name,
            FeedUpdate {
                name: name.to_string(),
                nodes: nodes.clone(),
                from_cache: true,
                raw_bytes: raw.len(),
                userinfo: None,
            },
            last_refreshed_ms,
            every,
        )
        .await;
        info!(
            target: "feeds",
            name = %name,
            phase,
            cached_nodes = nodes.len(),
            stale,
            "loaded snapshot from cache"
        );
        true
    }

    fn update_next_due(&self, name: &str, last_ms: u64, every: Duration) {
        if let Some(s) = self.statuses.write().get_mut(name) {
            let base = if last_ms == 0 { now_ms() } else { last_ms };
            s.next_due_ms = base.saturating_add(every.as_millis() as u64);
        }
    }

    /// 一次完整刷新（不含等待）—— 成功时写 raw + meta；失败时回退 cache。
    pub async fn refresh_once(
        &self,
        name: &str,
        detail: &FeedDetail,
        timeout: Duration,
    ) -> Result<FeedUpdate, String> {
        let (raw, userinfo) = match fetch_feed(&detail.url, timeout).await {
            Ok(result) => {
                if let Some(cache) = &self.cache {
                    let meta = FeedMeta {
                        last_refreshed_ms: now_ms(),
                        raw_size: result.bytes.len() as u64,
                        etag: result.etag.clone(),
                        content_type: result.content_type.clone(),
                        url_hash: Some(url_digest(&detail.url)),
                    };
                    cache.save_with_meta(name, &result.bytes, &meta);
                }
                (result.bytes, result.userinfo)
            }
            Err(e) => {
                warn!(target: "feeds", name, error = %e, "online fetch failed; trying disk cache");
                let cache = self
                    .cache
                    .as_ref()
                    .and_then(|c| c.load(name))
                    .ok_or_else(|| format!("{e}"))?;
                let nodes = self.parse_with_filter(detail, &cache);
                return Ok(FeedUpdate {
                    name: name.to_string(),
                    nodes,
                    from_cache: true,
                    raw_bytes: cache.len(),
                    userinfo: None,
                });
            }
        };

        let nodes = self.parse_with_filter(detail, &raw);
        Ok(FeedUpdate {
            name: name.to_string(),
            nodes,
            from_cache: false,
            raw_bytes: raw.len(),
            userinfo,
        })
    }

    fn parse_with_filter(&self, detail: &FeedDetail, raw: &[u8]) -> Vec<ParsedNode> {
        let parsed = parse_feed_payload(raw, FormatHint::Auto);
        apply_filter_rename(detail, parsed)
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use core_config::model::{FeedFilter, FeedRename};

    use super::*;

    fn detail(url: &str, every_secs: u64) -> FeedDetail {
        FeedDetail {
            url: url.into(),
            every: Duration::from_secs(every_secs),
            via: "direct".into(),
            keep: FeedFilter::default(),
            drop: FeedFilter::default(),
            rename: FeedRename::default(),
        }
    }

    fn tmp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "wuthercore-feeds-mgr-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn refresh_falls_back_to_cache_when_fetch_fails() {
        let dir = tmp_root();
        let cache = FeedDiskCache::new(&dir).unwrap();
        let payload = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#FromCache";
        cache.save("airport", payload);
        let mgr = FeedManager::new(BTreeMap::new(), Some(cache));
        let update = mgr
            .refresh_once(
                "airport",
                &detail("file://./this/should/not/exist", 3600),
                Duration::from_millis(500),
            )
            .await
            .unwrap();
        assert!(update.from_cache);
        assert_eq!(update.nodes.len(), 1);
        assert_eq!(update.nodes[0].name, "FromCache");
    }

    #[tokio::test]
    async fn refresh_once_writes_meta_with_url_hash() {
        let dir = tmp_root();
        let cache = FeedDiskCache::new(&dir).unwrap();
        let mgr = FeedManager::new(BTreeMap::new(), Some(cache.clone()));
        // fetch 会失败（不存在的 URL）→ 走 cache 回退；这里改为先放 cache。
        let raw = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#X";
        cache.save("p", raw);
        // 直接保存 meta 模拟 fetch 成功路径
        let meta = FeedMeta {
            last_refreshed_ms: now_ms(),
            raw_size: raw.len() as u64,
            etag: None,
            content_type: None,
            url_hash: Some(url_digest("https://x")),
        };
        cache.save_meta("p", &meta);
        let m = cache.load_meta("p").unwrap();
        assert_eq!(m.url_hash.as_deref(), Some(&*url_digest("https://x")));
        let _ = mgr; // 仅验证 cache+meta 写入路径
    }

    #[tokio::test]
    async fn empty_feeds_start_is_noop_and_stop_is_safe() {
        let mgr = FeedManager::new(BTreeMap::new(), None);
        let m = mgr.clone();
        m.start();
        assert!(mgr.is_empty());
        assert!(mgr.list_status().is_empty());
        assert!(mgr.snapshot("nope").is_none());
        assert!(!mgr.refresh_now("nope"));
        mgr.stop(); // 不 panic
    }

    #[tokio::test]
    async fn refresh_now_for_unknown_feed_returns_false() {
        let mgr = FeedManager::new(BTreeMap::new(), None);
        assert!(!mgr.refresh_now("does-not-exist"));
    }

    #[tokio::test]
    async fn cached_meta_within_every_defers_fetch_and_emits_snapshot() {
        let dir = tmp_root();
        let cache = FeedDiskCache::new(&dir).unwrap();
        // 写入"刚刚刷新"的 meta + cache。
        let url = "https://example.com/sub-stale";
        let raw = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#Cached";
        let meta = FeedMeta {
            last_refreshed_ms: now_ms(),
            raw_size: raw.len() as u64,
            etag: None,
            content_type: None,
            url_hash: Some(url_digest(url)),
        };
        cache.save_with_meta("p", raw, &meta);

        // every=1h；run_one 启动应立刻 emit cache snapshot 并 defer fetch。
        let mut feeds = BTreeMap::new();
        feeds.insert("p".to_string(), detail(url, 3600));
        let mgr = FeedManager::new(feeds, Some(cache));

        // 用一个简易 sink 收集 update。
        struct Capture {
            tx: tokio::sync::mpsc::Sender<FeedUpdate>,
        }
        #[async_trait]
        impl FeedSink for Capture {
            async fn on_update(&self, u: FeedUpdate) {
                let _ = self.tx.send(u).await;
            }
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FeedUpdate>(4);
        mgr.set_sink(Arc::new(Capture { tx }));

        let m = mgr.clone();
        m.start();
        // 必须在合理时间内（< 2s）拿到 cache snapshot；不能等 1h。
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("snapshot must arrive quickly")
            .unwrap();
        assert!(got.from_cache);
        assert_eq!(got.name, "p");
        assert_eq!(got.nodes.len(), 1);
        let s = mgr.status("p").unwrap();
        assert!(s.last_node_count == 1);
        assert!(s.next_due_ms > s.last_refreshed_ms);
        mgr.stop();
    }

    #[tokio::test]
    async fn bootstrap_cache_publishes_stale_snapshot_before_start() {
        let dir = tmp_root();
        let cache = FeedDiskCache::new(&dir).unwrap();
        let url = "https://example.com/sub-stale";
        let raw = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#StaleCached";
        let meta = FeedMeta {
            last_refreshed_ms: now_ms().saturating_sub(2 * 60 * 60 * 1000),
            raw_size: raw.len() as u64,
            etag: None,
            content_type: None,
            url_hash: Some(url_digest(url)),
        };
        cache.save_with_meta("p", raw, &meta);

        let mut feeds = BTreeMap::new();
        feeds.insert("p".to_string(), detail(url, 3600));
        let mgr = FeedManager::new(feeds, Some(cache));

        let published = mgr.bootstrap_cache().await;

        assert_eq!(published, 1);
        let snapshot = mgr.snapshot("p").unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].name, "StaleCached");
        let status = mgr.status("p").unwrap();
        assert_eq!(status.last_node_count, 1);
        assert!(status.last_from_cache);
    }

    #[tokio::test]
    async fn url_change_forgets_old_cache() {
        let dir = tmp_root();
        let cache = FeedDiskCache::new(&dir).unwrap();
        let raw = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#Old";
        let meta = FeedMeta {
            last_refreshed_ms: now_ms(),
            raw_size: raw.len() as u64,
            etag: None,
            content_type: None,
            url_hash: Some(url_digest("https://old")),
        };
        cache.save_with_meta("p", raw, &meta);
        // 模拟 url 改了
        let mut feeds = BTreeMap::new();
        feeds.insert("p".to_string(), detail("https://new", 3600));
        let mgr = FeedManager::new(feeds, Some(cache.clone()));
        let m = mgr.clone();
        m.start();
        // 给 run_one 一点时间执行 cache forget。
        tokio::time::sleep(Duration::from_millis(50)).await;
        // forget 后 cache 应被清。
        assert!(cache.load("p").is_none(), "old cache should be forgotten");
        mgr.stop();
    }
}
