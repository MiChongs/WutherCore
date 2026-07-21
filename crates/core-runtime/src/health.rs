//! URLTest（节点测速）—— 与 mihomo `adapter/adapter.go` + `outboundgroup/urltest.go`
//! 行为对齐。
//!
//! ## 关键特性
//!
//! * **协议**：默认 `HEAD`；`http://` / `https://` 都支持；HTTPS 使用 `tokio-rustls`
//!   完成 SNI/ALPN 握手（与 mihomo 的 `http.Transport.TLSClientConfig` 等价）。
//! * **expected_status**：解析 `"200/204/401-429"` 等 mihomo 风格表达式；
//!   响应状态码必须命中范围才算 alive。空集合（`""` / `"*"`）跳过校验。
//! * **unified_delay**：第一次 HEAD 后立刻在同一连接（keep-alive）再 HEAD 一次，
//!   仅以第二次的耗时为准 —— 排除 TCP/TLS 握手噪声，结果更接近"稳态延迟"。
//!   与 mihomo `UnifiedDelay` 默认关闭相同；`UrlTestOpts::unified_delay = true` 启用。
//! * **跨 URL 的 per-(node, url) 状态**：`alive` 原子位 + 历史 ring；
//!   `last_delay_for_url(node, url)` 死节点返回 `u32::MAX`（与 mihomo
//!   `LastDelayForTestUrl` 返回 `0xFFFF` 等价的语义，宽度扩为 u32 适应 ms）。
//! * **fast() + tolerance + singledo**：[`UrlTester::pick_fast`] 复刻 mihomo
//!   `urltest.go fast(touch)` —— 取 `last_delay_for_url` 最小者；当且仅当
//!   `current.delay > new_min + tolerance` 时切换；10s `single_flight` window
//!   防止热路径反复扫描。
//! * **memory safe**：100% 安全 Rust（unsafe-free），仅依赖 `tokio_rustls` 完成
//!   TLS。`tokio::sync::Semaphore` 限并发，避免压垮上游。

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use core_outbound::adapter::{BoxedStream, DialContext};
use parking_lot::{Mutex, RwLock};
use rustls::{ClientConfig, pki_types::ServerName};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::{engine::Runtime, int_ranges::IntRanges};

/// `LastDelayForTestUrl` 死节点返回值；与 mihomo `0xFFFF` 等价语义但宽度扩为 u32。
pub const DEAD_DELAY: u32 = u32::MAX;
/// 拨号失败后的短期 dead TTL —— 避免 Manual/粘性策略反复撞同一坏节点。
pub const TEMP_DEAD_TTL: Duration = Duration::from_secs(30);
/// 单个节点最多保留多少条历史（与 mihomo `defaultHistoriesNum = 10`）。
pub const HISTORY_CAP: usize = 10;
/// `single_flight` 缓存窗口（与 mihomo `singledo.NewSingle(time.Second * 10)`）。
pub const FAST_PICK_TTL: Duration = Duration::from_secs(10);
/// 默认 tolerance（与 mihomo `URLTest tolerance` 默认 0；这里给一个保守值）。
pub const DEFAULT_TOLERANCE_MS: u32 = 50;

#[derive(Debug, Error, Clone)]
pub enum DelayError {
    #[error("节点未注册: {0}")]
    UnknownNode(String),
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("dial 失败: {0}")]
    Dial(String),
    #[error("HTTP 失败: {0}")]
    Http(String),
    #[error("TLS 失败: {0}")]
    Tls(String),
    #[error("expected_status 不命中: {0}")]
    StatusMismatch(u16),
    #[error("超时")]
    Timeout,
    #[error("连接已关闭")]
    Closed,
}

/// 默认配置。
#[derive(Debug, Clone)]
pub struct UrlTestConfig {
    pub default_url: String,
    pub default_timeout: Duration,
    pub max_parallel: usize,
    /// 默认 expected_status —— mihomo 默认空集（任何状态都算 alive）。
    pub default_expected_status: IntRanges,
    /// 默认 unified_delay —— mihomo `UnifiedDelay` 默认 false。
    pub default_unified_delay: bool,
}

impl Default for UrlTestConfig {
    fn default() -> Self {
        Self {
            // 与 mihomo 一致：默认 HTTPS generate_204（防 ISP 劫持）。
            default_url: "https://www.gstatic.com/generate_204".into(),
            default_timeout: Duration::from_secs(5),
            max_parallel: 64,
            default_expected_status: IntRanges::empty(),
            default_unified_delay: false,
        }
    }
}

/// 单次测试的可选项 —— 与 mihomo `URLTest(ctx, url, expectedStatus)` + 隐藏的
/// `UnifiedDelay` 全局开关合并到一个结构。
#[derive(Debug, Clone, Default)]
pub struct UrlTestOpts {
    pub url: Option<String>,
    pub timeout: Option<Duration>,
    pub expected_status: Option<IntRanges>,
    pub unified_delay: Option<bool>,
}

/* ========================================================================
Per-(node, url) statistics —— 对齐 mihomo `Proxy.extra` map。
======================================================================== */

#[derive(Debug)]
pub struct NodeUrlStats {
    pub alive: AtomicBool,
    pub last_delay_ms: AtomicU32, // 0 = 未测；DEAD_DELAY = 死
    pub last_seen_ms: AtomicU64,
    /// 临时 dead 截止时间（unix ms）；0 表示无临时 dead。
    temp_dead_until_ms: AtomicU64,
    history: Mutex<std::collections::VecDeque<HistoryEntry>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub time_ms: u64,
    pub delay_ms: u32,
}

impl Default for NodeUrlStats {
    fn default() -> Self {
        Self {
            alive: AtomicBool::new(true),
            last_delay_ms: AtomicU32::new(0),
            last_seen_ms: AtomicU64::new(0),
            temp_dead_until_ms: AtomicU64::new(0),
            history: Mutex::new(std::collections::VecDeque::with_capacity(HISTORY_CAP)),
        }
    }
}

impl NodeUrlStats {
    pub fn record(&self, delay_ms: u32, alive: bool) {
        let now = now_ms();
        self.alive.store(alive, Ordering::Release);
        self.last_delay_ms
            .store(if alive { delay_ms } else { DEAD_DELAY }, Ordering::Release);
        self.last_seen_ms.store(now, Ordering::Release);
        if alive {
            self.temp_dead_until_ms.store(0, Ordering::Release);
        }
        let mut g = self.history.lock();
        g.push_back(HistoryEntry {
            time_ms: now,
            delay_ms: if alive { delay_ms } else { 0 },
        });
        while g.len() > HISTORY_CAP {
            g.pop_front();
        }
    }

    /// 拨号失败后的短期排除，不永久杀死节点。
    pub fn mark_temp_dead(&self, ttl: Duration) {
        let until = now_ms().saturating_add(ttl.as_millis() as u64);
        self.temp_dead_until_ms.store(until, Ordering::Release);
        self.alive.store(false, Ordering::Release);
        self.last_delay_ms.store(DEAD_DELAY, Ordering::Release);
        self.last_seen_ms.store(now_ms(), Ordering::Release);
    }

    pub fn last_delay(&self) -> u32 {
        if self.is_alive() {
            self.last_delay_ms.load(Ordering::Acquire)
        } else {
            DEAD_DELAY
        }
    }
    pub fn is_alive(&self) -> bool {
        let until = self.temp_dead_until_ms.load(Ordering::Acquire);
        if until != 0 {
            let now = now_ms();
            if now < until {
                return false;
            }
            // TTL 过期：清掉临时 dead，回到 alive=true（除非正式 probe 仍标记失败）。
            self.temp_dead_until_ms.store(0, Ordering::Release);
            // 若 last formal record 是 failure 且没有成功过，仍看 alive 原子位。
            // mark_temp_dead 把 alive 置 false；TTL 到期后恢复 true。
            self.alive.store(true, Ordering::Release);
            return true;
        }
        self.alive.load(Ordering::Acquire)
    }
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.history.lock().iter().cloned().collect()
    }
}

/* ========================================================================
FastPickCache —— mihomo singledo.Single 的最小复刻。
======================================================================== */

#[derive(Debug, Clone)]
struct FastPickResult {
    node: String,
    delay: u32,
}

#[derive(Debug, Default)]
struct FastPickEntry {
    last: Option<(Instant, FastPickResult)>,
}

/* ========================================================================
UrlTester
======================================================================== */

#[derive(Debug)]
pub struct UrlTester {
    pub cfg: RwLock<UrlTestConfig>,
    pub sem: Arc<Semaphore>,
    /// (node, url) → stats
    stats: RwLock<HashMap<(String, String), Arc<NodeUrlStats>>>,
    /// group_name → cached fast-pick
    fast_pick: RwLock<HashMap<String, FastPickEntry>>,
}

impl UrlTester {
    pub fn new(cfg: UrlTestConfig) -> Arc<Self> {
        let sem = Arc::new(Semaphore::new(cfg.max_parallel));
        Arc::new(Self {
            cfg: RwLock::new(cfg),
            sem,
            stats: RwLock::new(HashMap::new()),
            fast_pick: RwLock::new(HashMap::new()),
        })
    }

    pub fn current_config(&self) -> UrlTestConfig {
        self.cfg.read().clone()
    }

    /// 取（或新建）一条 (node, url) stats。
    pub fn ensure_stats(&self, node: &str, url: &str) -> Arc<NodeUrlStats> {
        let key = (node.to_string(), url.to_string());
        if let Some(s) = self.stats.read().get(&key) {
            return s.clone();
        }
        let mut g = self.stats.write();
        g.entry(key)
            .or_insert_with(|| Arc::new(NodeUrlStats::default()))
            .clone()
    }

    /// `LastDelayForTestUrl(node, url)` —— 与 mihomo 同名方法语义。
    pub fn last_delay_for_url(&self, node: &str, url: &str) -> u32 {
        self.stats
            .read()
            .get(&(node.to_string(), url.to_string()))
            .map(|s| s.last_delay())
            .unwrap_or(DEAD_DELAY)
    }

    pub fn alive_for_url(&self, node: &str, url: &str) -> bool {
        self.stats
            .read()
            .get(&(node.to_string(), url.to_string()))
            .map(|s| s.is_alive())
            .unwrap_or(true)
    }

    /// 将节点在默认 probe URL 上标记为短期 dead，供 dial 失败后的排除集使用。
    pub fn mark_temp_dead(&self, node: &str) {
        let url = self.cfg.read().default_url.clone();
        self.mark_temp_dead_for_url(node, &url);
    }

    pub fn mark_temp_dead_for_url(&self, node: &str, url: &str) {
        let stats = self.ensure_stats(node, url);
        stats.mark_temp_dead(TEMP_DEAD_TTL);
        debug!(
            target: "urltest",
            node,
            url,
            ttl_secs = TEMP_DEAD_TTL.as_secs(),
            "marked temporarily dead after dial failure"
        );
    }

    pub fn history(&self, node: &str, url: &str) -> Vec<HistoryEntry> {
        self.stats
            .read()
            .get(&(node.to_string(), url.to_string()))
            .map(|s| s.history())
            .unwrap_or_default()
    }

    /// 兼容旧调用：测一个节点，仅按 url+timeout。返回 ms。
    pub async fn test_node(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        url: Option<&str>,
        to: Option<Duration>,
    ) -> Result<u32, DelayError> {
        self.test_node_with(
            runtime,
            node,
            UrlTestOpts {
                url: url.map(|s| s.to_string()),
                timeout: to,
                ..Default::default()
            },
        )
        .await
    }

    /// 与 mihomo `Proxy.URLTest(ctx, url, expectedStatus)` 等价。
    pub async fn test_node_with(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        opts: UrlTestOpts,
    ) -> Result<u32, DelayError> {
        let cfg = self.cfg.read().clone();
        let url = opts.url.unwrap_or_else(|| cfg.default_url.clone());
        let limit = opts.timeout.unwrap_or(cfg.default_timeout);
        let expected = opts
            .expected_status
            .unwrap_or(cfg.default_expected_status.clone());
        let unified = opts.unified_delay.unwrap_or(cfg.default_unified_delay);

        let parsed = parse_test_url(&url)?;
        let ob = runtime
            .outbounds
            .read()
            .get(node)
            .ok_or_else(|| DelayError::UnknownNode(node.to_string()))?;

        let _permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DelayError::Closed)?;

        let stats = self.ensure_stats(node, &url);

        let started = Instant::now();
        let result = timeout(limit, async {
            let dial_ctx = DialContext::tcp(parsed.host.clone(), parsed.port);
            let stream = ob
                .dial_tcp(dial_ctx)
                .await
                .map_err(|e| DelayError::Dial(e.to_string()))?;
            run_probe(stream, &parsed, &expected, unified, started).await
        })
        .await;

        let outcome = match result {
            Err(_) => Err(DelayError::Timeout),
            Ok(r) => r,
        };

        match &outcome {
            Ok(ms) => {
                stats.record(*ms, true);
                runtime
                    .smart
                    .record_probe_for(node, Duration::from_millis(*ms as u64));
                debug!(target: "urltest", node, url, ms, unified, "probe ok");
            }
            Err(e) => {
                stats.record(0, false);
                runtime.smart.record_probe_failure_for(node, e.to_string());
                debug!(target: "urltest", node, url, error = %e, "probe failed");
            }
        }

        outcome
    }

    /// 并行测一组节点；按节点名返回结果。结果顺序与 nodes 一致。
    pub async fn test_many(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        self.test_many_with(
            runtime,
            nodes,
            UrlTestOpts {
                url,
                timeout: to,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn test_many_with(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        opts: UrlTestOpts,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let mut set = JoinSet::new();
        for name in nodes {
            let me = self.clone();
            let rt = runtime.clone();
            let n = name.clone();
            let o = opts.clone();
            set.spawn(async move {
                let r = me.test_node_with(&rt, &n, o).await;
                (n, r)
            });
        }
        let mut out = Vec::with_capacity(nodes.len());
        while let Some(j) = set.join_next().await {
            match j {
                Ok(pair) => out.push(pair),
                Err(e) => warn!(target: "urltest", error = %e, "join task failed"),
            }
        }
        out
    }

    pub async fn test_all(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let names: Vec<String> = runtime
            .outbounds
            .read()
            .names()
            .filter(|n| *n != "DIRECT" && *n != "BLOCK")
            .map(|s| s.to_string())
            .collect();
        self.test_many(runtime, &names, url, to).await
    }

    /* ====================================================================
    fast() —— mihomo URLTest 选点逻辑 + tolerance + 10s singledo 缓存。
    ==================================================================== */

    /// 在已知 last_delay 表中按 `tolerance` 选最快节点。
    /// 与 mihomo `urltest.go fast(touch)` 行为一致：
    /// * 当前 fast 死了 / 不在候选 / 当前延迟比最小者大 `> tolerance` → 切换；
    /// * 否则保持。
    /// `singledo` 窗口：10s 内重复调用同 group 直接复用上次结果。
    pub fn pick_fast(
        &self,
        group: &str,
        members: &[String],
        url: &str,
        tolerance: u32,
    ) -> Option<String> {
        // 1. singledo 命中？
        {
            let g = self.fast_pick.read();
            if let Some(e) = g.get(group) {
                if let Some((when, ref r)) = e.last {
                    if when.elapsed() < FAST_PICK_TTL && members.iter().any(|m| m == &r.node) {
                        return Some(r.node.clone());
                    }
                }
            }
        }

        // 2. 全表扫描
        let mut best: Option<(String, u32)> = None;
        for m in members {
            let d = self.last_delay_for_url(m, url);
            if d == DEAD_DELAY {
                continue;
            }
            match &best {
                None => best = Some((m.clone(), d)),
                Some((_, bd)) => {
                    if d < *bd {
                        best = Some((m.clone(), d));
                    }
                }
            }
        }

        // 3. tolerance：保留旧 fast 如果新最优只是略快。
        let mut g = self.fast_pick.write();
        let entry = g.entry(group.to_string()).or_default();
        let (final_node, final_delay) = match (entry.last.as_ref().map(|(_, r)| r.clone()), best) {
            (Some(prev), Some((_nb, nd)))
                if members.iter().any(|m| m == &prev.node)
                    && self.alive_for_url(&prev.node, url)
                    && prev.delay <= nd.saturating_add(tolerance) =>
            {
                (prev.node, prev.delay)
            }
            (_, Some((nb, nd))) => (nb, nd),
            (Some(prev), None) => return Some(prev.node), // 全 dead 时保留上一个
            (None, None) => return None,
        };
        entry.last = Some((
            Instant::now(),
            FastPickResult {
                node: final_node.clone(),
                delay: final_delay,
            },
        ));
        Some(final_node)
    }

    /// 强制让下一次 `pick_fast` 重新扫描（mihomo `fastSingle.Reset()` 等价）。
    pub fn invalidate_fast_pick(&self, group: &str) {
        self.fast_pick.write().remove(group);
    }
}

/// 后台周期任务：每 interval 跑一次 test_all。
///
/// 启动延迟 500ms（足够 outbound registry / DialResolver 注入完成），
/// 然后立即跑首轮——之前 3s 延迟意味着 dashboard 在前 3s 加载时看到全空 history，
/// 加上每轮 60s 间隔，体感是"长时间显示 timeout"。mihomo 的对应行为是按需 Touch
/// 触发首测，这里改用启动即跑。
pub fn spawn_periodic(
    tester: Arc<UrlTester>,
    runtime: Arc<Runtime>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        loop {
            let started = Instant::now();
            let results = tester.test_all(&runtime, None, None).await;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            info!(
                target: "urltest",
                tested = results.len(),
                ok,
                ms = started.elapsed().as_millis() as u64,
                "url test round finished"
            );
            tokio::time::sleep(interval).await;
        }
    })
}

/* ========================================================================
URL 解析 + HTTP/HTTPS 探测
======================================================================== */

#[derive(Debug, Clone)]
struct ParsedTestUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

fn parse_test_url(s: &str) -> Result<ParsedTestUrl, DelayError> {
    let (scheme, rest, port_default) = if let Some(r) = s.strip_prefix("https://") {
        (Scheme::Https, r, 443u16)
    } else if let Some(r) = s.strip_prefix("http://") {
        (Scheme::Http, r, 80u16)
    } else {
        return Err(DelayError::BadUrl(format!(
            "only http(s):// supported: {s}"
        )));
    };
    let (host_part, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
        (
            h.to_string(),
            p.parse()
                .map_err(|_| DelayError::BadUrl(format!("bad port in: {host_part}")))?,
        )
    } else {
        (host_part.to_string(), port_default)
    };
    Ok(ParsedTestUrl {
        scheme,
        host,
        port,
        path,
    })
}

async fn run_probe(
    stream: BoxedStream,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
) -> Result<u32, DelayError> {
    match url.scheme {
        Scheme::Http => probe_plain(stream, url, expected, unified_delay, started).await,
        Scheme::Https => probe_tls(stream, url, expected, unified_delay, started).await,
    }
}

async fn probe_plain<S>(
    mut s: S,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
) -> Result<u32, DelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    let _ = send_head_recv_status(&mut s, &url.host, &url.path, expected).await?;
    if unified_delay {
        let t2 = Instant::now();
        if let Ok(_) = send_head_recv_status(&mut s, &url.host, &url.path, expected).await {
            return Ok(t2.elapsed().as_millis().min(u32::MAX as u128) as u32);
        }
    }
    Ok(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

async fn probe_tls(
    inner: BoxedStream,
    url: &ParsedTestUrl,
    expected: &IntRanges,
    unified_delay: bool,
    started: Instant,
) -> Result<u32, DelayError> {
    let cfg = build_client_config();
    let connector = TlsConnector::from(cfg);
    let server_name = ServerName::try_from(url.host.clone())
        .map_err(|e| DelayError::Tls(format!("invalid SNI '{}': {e}", url.host)))?;
    let mut tls = connector
        .connect(server_name, inner)
        .await
        .map_err(|e| DelayError::Tls(e.to_string()))?;
    let _ = send_head_recv_status(&mut tls, &url.host, &url.path, expected).await?;
    if unified_delay {
        let t2 = Instant::now();
        if let Ok(_) = send_head_recv_status(&mut tls, &url.host, &url.path, expected).await {
            return Ok(t2.elapsed().as_millis().min(u32::MAX as u128) as u32);
        }
    }
    Ok(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// 发送 HEAD + 解析状态行；返回 status code。
async fn send_head_recv_status<S>(
    s: &mut S,
    host_header: &str,
    path: &str,
    expected: &IntRanges,
) -> Result<u16, DelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    // HEAD + keep-alive：unified_delay 复用同一连接做第二次。
    let req = format!(
        "HEAD {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: wuthercore-urltest/1.0\r\n\
         Connection: keep-alive\r\n\
         Accept: */*\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;
    s.flush()
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;

    // 读到 \r\n 即可拿状态行；HEAD 响应没有 body，且服务端发完 headers 后会
    // 等下一个请求（keep-alive）；为避免阻塞，先读到 256 字节就解析。
    let mut buf = [0u8; 256];
    let mut total = 0usize;
    loop {
        let n = s
            .read(&mut buf[total..])
            .await
            .map_err(|e| DelayError::Http(e.to_string()))?;
        if n == 0 {
            if total == 0 {
                return Err(DelayError::Closed);
            }
            break;
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") || total == buf.len() {
            break;
        }
    }
    let line = std::str::from_utf8(&buf[..total]).unwrap_or("");
    if !line.starts_with("HTTP/1.") {
        return Err(DelayError::Http(format!(
            "non-HTTP reply: {:?}",
            &line[..line.len().min(40)]
        )));
    }
    let code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            DelayError::Http(format!(
                "bad status line: {:?}",
                &line[..line.len().min(40)]
            ))
        })?;
    if !expected.check(code) {
        return Err(DelayError::StatusMismatch(code));
    }
    Ok(code)
}

/// 构建 TLS 客户端 cfg —— webpki-roots 内置 CA。
/// 显式指定 ring CryptoProvider，避免 rustls 0.23 多依赖时 builder() 全局歧义 panic。
fn build_client_config() -> Arc<ClientConfig> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("rustls ring default protocols")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url_default_port() {
        let p = parse_test_url("https://www.gstatic.com/generate_204").unwrap();
        assert_eq!(p.scheme, Scheme::Https);
        assert_eq!(p.host, "www.gstatic.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.path, "/generate_204");
    }

    #[test]
    fn parse_http_url_explicit_port_root_path() {
        let p = parse_test_url("http://10.0.0.1:8080").unwrap();
        assert_eq!(p.scheme, Scheme::Http);
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(parse_test_url("ws://x").is_err());
    }

    #[test]
    fn temp_dead_expires() {
        let stats = NodeUrlStats::default();
        assert!(stats.is_alive());
        stats.mark_temp_dead(Duration::from_millis(1));
        assert!(!stats.is_alive());
        std::thread::sleep(Duration::from_millis(5));
        assert!(stats.is_alive(), "temp dead must expire");
    }

    #[test]
    fn fast_pick_tolerance_keeps_current() {
        // 构造一个独立 UrlTester（不需要 Runtime）做 pick 测试。
        let t = UrlTester::new(UrlTestConfig::default());
        // 手工种 stats：a=200ms (alive), b=190ms (alive)
        let url = "https://t.example/";
        t.ensure_stats("a", url).record(200, true);
        t.ensure_stats("b", url).record(190, true);
        // 第一次：选最小 b
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "b");
        // 把 a 降到 175 —— tolerance=50，现 fast=b(190) vs new=a(175)，差 15 < 50，应保持 b。
        t.ensure_stats("a", url).record(175, true);
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "b");
        // 显式 invalidate 后才会换。
        t.invalidate_fast_pick("g");
        let pick = t
            .pick_fast("g", &["a".into(), "b".into()], url, 50)
            .unwrap();
        assert_eq!(pick, "a");
    }

    #[test]
    fn fast_pick_skips_dead_nodes() {
        let t = UrlTester::new(UrlTestConfig::default());
        let url = "https://t/";
        t.ensure_stats("dead", url).record(0, false);
        t.ensure_stats("ok", url).record(300, true);
        let pick = t
            .pick_fast("g", &["dead".into(), "ok".into()], url, 0)
            .unwrap();
        assert_eq!(pick, "ok");
    }

    #[test]
    fn last_delay_for_url_returns_dead_when_marked_dead() {
        let t = UrlTester::new(UrlTestConfig::default());
        t.ensure_stats("n", "u").record(0, false);
        assert_eq!(t.last_delay_for_url("n", "u"), DEAD_DELAY);
        t.ensure_stats("n", "u").record(123, true);
        assert_eq!(t.last_delay_for_url("n", "u"), 123);
    }

    #[test]
    fn singledo_window_returns_same_pick() {
        let t = UrlTester::new(UrlTestConfig::default());
        let url = "https://t/";
        t.ensure_stats("a", url).record(100, true);
        t.ensure_stats("b", url).record(200, true);
        let p1 = t.pick_fast("g", &["a".into(), "b".into()], url, 0).unwrap();
        // 即便此时 b 变得更快，10s 内仍返回 a（singledo TTL）。
        t.ensure_stats("b", url).record(50, true);
        let p2 = t.pick_fast("g", &["a".into(), "b".into()], url, 0).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p2, "a");
    }
}
