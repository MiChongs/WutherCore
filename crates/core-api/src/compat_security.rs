//! Clash 兼容层的安全中间件 —— 把"对外裸露的 dashboard API"变成生产可用。
//!
//! ## 提供的能力
//!
//! 1. **CORS allowlist** ([`build_cors`])：默认仅放行本机 origin（http(s)://
//!    localhost / 127.0.0.1 / `[::1]`）；用户可在 `ui.cors` 配置允许的来源；
//!    显式 `["*"]` 才用 `Any`（与旧行为兼容）。
//!
//! 2. **Body 大小限制** ([`body_limit_layer`])：默认 1 MiB。Clash 配置类
//!    PUT/POST 体积都很小；这里挡掉"几十 MB JSON 灌入耗光内存"的攻击面。
//!
//! 3. **请求超时** ([`request_timeout`])：30 s 上限；WS / SSE / 流式端点
//!    自动豁免。挡掉慢客户端攻击 (Slowloris-like)。
//!
//! 4. **安全 HTTP 头** ([`security_headers`])：
//!    `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
//!    `Referrer-Policy: no-referrer`。挡掉 XSS / clickjacking / referer 泄漏。
//!
//! 5. **常量时间凭证比对** ([`constant_time_eq`])：`secret == provided`
//!    用 byte-wise XOR 累加，避免 std `==` 短路对比的 timing 侧信道。
//!
//! 6. **WS 连接上限** ([`WsConnectionLimiter`])：全局原子计数器；
//!    超过上限直接拒 503，避免一次性几千 WS 把 fd 表打满。
//!
//! 7. **Per-IP 令牌桶** ([`IpRateLimiter`])：lock-free DashMap + 短锁的 token
//!    bucket；HTTP 请求过快时返回 429。WS / SSE 升级豁免（避免一次升级被
//!    挡住）。
//!
//! 8. **`?token=` 限定**（在 server.rs 调用处实现）：除 WS upgrade 请求外，
//!    `?token=` 不再被接受（防止凭证写入 access log / Referer）。

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde_json::json;
use tower_http::cors::{AllowOrigin, CorsLayer};

/* ====================== 1. CORS allowlist ====================== */

/// 根据用户配置生成 [`CorsLayer`]。
///
/// * `allow_list` 为空：放行 `http(s)://localhost`、`http(s)://127.0.0.1`、
///   `http(s)://[::1]`（任意端口）。这是 dashboard 跑在浏览器本地时的最小需求。
/// * `allow_list == ["*"]`：等价旧行为 `Any`（生产环境**不推荐**；保留用于
///   公网 dashboard 场景，但应配合 `secret` 鉴权）。
/// * 其它：精确 origin 匹配（包括 scheme + host + port）。
pub fn build_cors(allow_list: &[String]) -> CorsLayer {
    let methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::HEAD,
    ];
    let headers = [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        HeaderName::from_static("x-api-secret"),
        HeaderName::from_static("x-requested-with"),
    ];

    let base = CorsLayer::new()
        .allow_methods(methods)
        .allow_headers(headers)
        .expose_headers([header::CONTENT_TYPE, header::CONTENT_LENGTH])
        .allow_credentials(false)
        .max_age(Duration::from_secs(300));

    if allow_list.iter().any(|o| o.trim() == "*") {
        return base.allow_origin(tower_http::cors::Any);
    }
    if allow_list.is_empty() {
        // 默认安全集：仅本机。
        return base.allow_origin(AllowOrigin::predicate(|origin, _| {
            is_localhost_origin(origin.as_bytes())
        }));
    }
    let allow: Vec<HeaderValue> = allow_list
        .iter()
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    base.allow_origin(allow)
}

fn is_localhost_origin(o: &[u8]) -> bool {
    // 不引 url crate；逐 prefix 比较。schema://host[:port]
    let candidates: &[&[u8]] = &[
        b"http://localhost",
        b"https://localhost",
        b"http://127.0.0.1",
        b"https://127.0.0.1",
        b"http://[::1]",
        b"https://[::1]",
    ];
    for c in candidates {
        if o.starts_with(c) {
            // 余下部分必须为空或 ":<port>"
            let tail = &o[c.len()..];
            if tail.is_empty() || tail.starts_with(b":") {
                return true;
            }
        }
    }
    false
}

/* ====================== 2. Body 大小限制 ====================== */

/// axum 的 body 大小限制层 —— 默认 1 MiB；超出 → 413。
pub fn body_limit_layer() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(1 * 1024 * 1024)
}

/* ====================== 3. 请求超时 ====================== */

const STREAMING_PATHS: &[&str] = &["/logs", "/traffic", "/memory", "/connections"];

/// 30 s 请求级超时。WS / SSE / 流式端点豁免。
pub async fn request_timeout(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path();
    let is_streaming = req
        .headers()
        .get(header::UPGRADE)
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false)
        || req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("text/event-stream"))
            .unwrap_or(false)
        || STREAMING_PATHS.iter().any(|p| path == *p);
    if is_streaming {
        return next.run(req).await;
    }
    match tokio::time::timeout(Duration::from_secs(30), next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({"message": "request timeout"})),
        )
            .into_response(),
    }
}

/* ====================== 4. 安全 HTTP 头 ====================== */

pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if !h.contains_key("x-content-type-options") {
        h.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
    }
    if !h.contains_key("x-frame-options") {
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    }
    if !h.contains_key("referrer-policy") {
        h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    }
    resp
}

/* ====================== 5. 常量时间比较 ====================== */

/// byte-wise 累加 XOR；时间复杂度恒定 = max(len(a), len(b))。
/// 长度不同直接返回 false（信息泄漏量上限是"是否长度相同"，可接受）。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/* ====================== 6. WS 连接上限 ====================== */

pub struct WsConnectionLimiter {
    max: usize,
    current: AtomicUsize,
    label: &'static str,
}

impl WsConnectionLimiter {
    pub fn new(label: &'static str, max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            current: AtomicUsize::new(0),
            label,
        })
    }

    /// 尝试占用一个槽位；满则返回 None。
    pub fn try_acquire(self: &Arc<Self>) -> Option<WsPermit> {
        // fetch_add 然后回退的模式 —— 避免 CAS loop。短时超额 ≤ 并发线程数。
        let prev = self.current.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max {
            self.current.fetch_sub(1, Ordering::AcqRel);
            tracing::warn!(
                target: "api::ws_limit",
                label = self.label,
                max = self.max,
                "ws connection rejected — limit reached",
            );
            None
        } else {
            Some(WsPermit {
                limiter: self.clone(),
            })
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::Acquire)
    }
    pub fn max(&self) -> usize {
        self.max
    }
}

pub struct WsPermit {
    limiter: Arc<WsConnectionLimiter>,
}

impl Drop for WsPermit {
    fn drop(&mut self) {
        self.limiter.current.fetch_sub(1, Ordering::AcqRel);
    }
}

/* ====================== 7. Per-IP 令牌桶 ====================== */

/// 每个 IP 一只 token bucket。`tokens` f64 让 sub-1 速率配置生效；
/// `last_refill` 单调时钟（Instant）防止 NTP 跳变干扰。
///
/// `Arc<Mutex<TokenBucket>>`：把 mutex 包进 Arc 是为了能"先 clone Arc，再释放
/// dashmap entry"，规避 [`Self::allow`] 注释里讲的 entry × len 同 shard 死锁。
pub struct IpRateLimiter {
    buckets: DashMap<IpAddr, Arc<Mutex<TokenBucket>>>,
    rate_per_sec: f64,
    burst: f64,
    /// 估算的内存开销控制：bucket 数超过 max_entries 时跑一次 GC。
    max_entries: usize,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl IpRateLimiter {
    /// `rate_per_sec` = 稳态请求速率；`burst` = 短时突发上限。
    pub fn new(rate_per_sec: f64, burst: f64) -> Arc<Self> {
        Arc::new(Self {
            buckets: DashMap::new(),
            rate_per_sec,
            burst,
            max_entries: 4096,
        })
    }

    /// 返回 true 表示允许这次请求；false 表示触发限流。
    ///
    /// **重要 / DEADLOCK 教训**：
    /// `dashmap::DashMap::entry()` 返回的 `RefMut` 在作用域结束前持有所在 shard 的
    /// **write lock**。同 shard 上若再调用任何 `len()` / `iter()` / `retain()` 等
    /// 走 read lock 的方法 → 同线程递归 read-on-write，parking_lot 不可重入直接
    /// 死锁；表现为生产环境"API 一段时间后卡死，log bus 也死，但进程仍在"。
    ///
    /// 修复：把 entry 拿值（拷出 `Arc<Mutex<...>>`）之后立即释放 entry，再做任何
    /// 后续 `len` / `gc` 操作。
    pub fn allow(&self, ip: IpAddr) -> bool {
        // 第一步：拿到（或新建）这个 IP 对应的 bucket Arc，**短锁内必须只持
        // entry，不调任何 self.buckets.* 方法**。
        let bucket = {
            let entry = self.buckets.entry(ip).or_insert_with(|| {
                Arc::new(Mutex::new(TokenBucket {
                    tokens: self.burst,
                    last_refill: Instant::now(),
                }))
            });
            Arc::clone(entry.value())
            // entry 在这里 drop —— shard write lock 释放
        };

        // 第二步：在 entry 释放之后再 lock 内层 token bucket，无嵌套锁风险。
        let now = Instant::now();
        let allow = {
            let mut b = bucket.lock();
            let elapsed = now.duration_since(b.last_refill).as_secs_f64();
            b.tokens = (b.tokens + elapsed * self.rate_per_sec).min(self.burst);
            b.last_refill = now;
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                true
            } else {
                false
            }
        };

        // 第三步：偶发 LRU 清理 —— 现在 entry 已无 hold，调 len() / retain() 安全。
        if self.buckets.len() > self.max_entries {
            self.gc(now);
        }
        allow
    }

    /// 清理 30 秒未活跃的 bucket。
    fn gc(&self, now: Instant) {
        let cutoff = Duration::from_secs(30);
        self.buckets.retain(|_ip, m| {
            let b = m.lock();
            now.duration_since(b.last_refill) < cutoff
        });
    }

    /// 监控：当前桶数量。
    pub fn entries(&self) -> usize {
        self.buckets.len()
    }
}

/* ====================== 8. WS-only token gate ====================== */

/// 判断一个请求是否为 WebSocket Upgrade。仅 WS 请求才允许 `?token=` query
/// 参数携带 secret（浏览器 WS 不能带自定义头）；其它请求只接受
/// `Authorization: Bearer ...` 或 `x-api-secret` 头。
pub fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false)
}

/// 判断是否 SSE（Accept: text/event-stream）。SSE 也常被浏览器用，没有自定义
/// header 能力，行为同 WS。
pub fn is_sse_request(req: &Request<Body>) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_time_eq_basic() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "hellO"));
        assert!(!constant_time_eq("hello", "helloo"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn localhost_origin_matches_known_forms() {
        assert!(is_localhost_origin(b"http://localhost"));
        assert!(is_localhost_origin(b"http://localhost:9090"));
        assert!(is_localhost_origin(b"https://127.0.0.1:8080"));
        assert!(is_localhost_origin(b"https://[::1]"));
        assert!(!is_localhost_origin(b"http://example.com"));
        assert!(!is_localhost_origin(b"http://localhostfoo"));
    }

    #[test]
    fn ws_limiter_permits_then_blocks() {
        let l = WsConnectionLimiter::new("test", 2);
        let _a = l.try_acquire().expect("first");
        let _b = l.try_acquire().expect("second");
        assert!(l.try_acquire().is_none(), "third should be rejected");
        assert_eq!(l.current(), 2);
    }

    #[test]
    fn ws_limiter_releases_on_drop() {
        let l = WsConnectionLimiter::new("test", 1);
        {
            let _a = l.try_acquire().expect("first");
            assert!(l.try_acquire().is_none());
        }
        // After drop slot is free again.
        assert!(l.try_acquire().is_some());
    }

    #[test]
    fn rate_limiter_token_bucket_basic() {
        // 10 req/s, burst 5.
        let l = IpRateLimiter::new(10.0, 5.0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            assert!(l.allow(ip));
        }
        // 6th immediately should fail (no refill yet).
        assert!(!l.allow(ip));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let l = IpRateLimiter::new(100.0, 1.0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(l.allow(ip));
        assert!(!l.allow(ip));
        std::thread::sleep(Duration::from_millis(20));
        assert!(l.allow(ip), "refill should grant new token");
    }

    #[test]
    fn rate_limiter_isolates_ips() {
        let l = IpRateLimiter::new(0.0, 1.0); // No refill; burst 1.
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(l.allow(a));
        assert!(!l.allow(a));
        assert!(l.allow(b), "different IP must have its own bucket");
    }
}
