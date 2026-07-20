//! API server —— 与 mihomo `hub/route/server.go` 行为对齐，并加固安全 / 性能层：
//!
//! * **CORS allowlist**：默认仅本机 origin；用户配置覆盖；`["*"]` 显式开启
//!   公网。挡掉旧实现 `Any` 的 CSRF 风险。
//! * **Body limit**：1 MiB；防止"大 JSON 灌入耗光内存"。
//! * **Request timeout**：30 s；流式（WS / SSE）豁免；防 Slowloris。
//! * **安全头**：`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
//!   `Referrer-Policy: no-referrer`。
//! * **常量时间凭证比对**：`subtle`-style 等价实现，挡掉 timing 侧信道。
//! * **WS-only token gate**：`?token=` 仅 WebSocket Upgrade 请求接受；普通
//!   GET/POST 必须用 `Authorization: Bearer ...` 或 `x-api-secret` 头。
//! * **Per-IP 令牌桶**：默认 50 req/s + burst 100；WS / SSE 升级豁免。
//! * **响应缓存**：高频读端点（/proxies、/configs、/rules、…）用 250-1000 ms
//!   TTL + singleflight 重建，N 个并发请求共享 1 次 JSON 序列化。
//! * **WS 广播 hub**：traffic / memory / connections 各一个全局 producer，
//!   多 dashboard 共享，避免 N×snapshot/sec。
//!
//! ### 历史细节（必须保留）
//!
//! * **CORS 必须最外层**：浏览器 dashboard 从 `https://yacd.haishan.me` fetch
//!   到本地 API 时先 OPTIONS 预检；预检需要 200 + 全套 CORS 头才会发真请求。
//! * **PNA**：Chrome 110+ 要求 https→私有网段必须显式
//!   `Access-Control-Allow-Private-Network: true`。
//! * **GET `/` hello**：mihomo 兼容性探测端点，必须 200。
//! * **WebSocket 用 `?token=`**：浏览器 WS 不能带自定义 Authorization 头。
//! * **OPTIONS 永不要 secret**：否则浏览器吃 401，到不了 CORS 层。

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, Request},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use core_runtime::{Runtime, UrlTester};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use crate::{
    compat,
    compat_security::{
        IpRateLimiter, body_limit_layer, build_cors, constant_time_eq, is_sse_request,
        is_websocket_upgrade, request_timeout, security_headers,
    },
    compat_ws::WsHubs,
    native::NativeState,
};

pub struct ApiServer {
    pub addr: SocketAddr,
    pub runtime: Arc<Runtime>,
    pub secret: Option<String>,
    pub clash_compat: bool,
    pub urltest: Arc<UrlTester>,
    pub capture: Option<Arc<core_capture::CaptureSupervisor>>,
    /// 统一组网监督器；提供只读运行状态，不暴露认证材料。
    pub mesh: Option<Arc<core_mesh::MeshSupervisor>>,
    pub feeds: Option<Arc<core_feeds::FeedManager>>,
    /// CORS 允许 origin 列表。空 = 仅本机；`["*"]` = Any。
    /// 来自 `ui.cors` 配置。
    pub cors_origins: Vec<String>,
}

impl ApiServer {
    pub async fn run(self) -> anyhow::Result<()> {
        // ---------- 缓存 + WS hub 一次性构造 ----------
        let caches = crate::compat_cache::Caches::new();
        // /connections WS 默认 1Hz；可后续从配置读出来。
        let ws_hubs: Arc<WsHubs> = WsHubs::new(self.runtime.clone(), 1000);

        let state = NativeState {
            runtime: self.runtime.clone(),
            started_at: std::time::Instant::now(),
            secret: self.secret.clone(),
            urltest: self.urltest.clone(),
            capture: self.capture.clone(),
            mesh: self.mesh.clone(),
            feeds: self.feeds.clone(),
            caches: caches.clone(),
            ws_hubs: ws_hubs.clone(),
        };

        // ---------- 路由 ----------
        let mut app = Router::new()
            .route("/", get(hello))
            .route("/healthz", get(hello));
        app = app.nest("/v1", crate::native::router(state.clone()));
        if self.clash_compat {
            app = app.merge(compat::router(state.clone()));
        }

        // ---------- 中间件栈（注意顺序：layer 顺序与执行顺序相反）----------
        //
        // 实际请求流向（最外 → 最内）：
        //   1. PNA header injector
        //   2. CORS layer
        //   3. Per-IP rate limit
        //   4. Body size limit (DefaultBodyLimit, axum extractor 层)
        //   5. Request timeout
        //   6. Security headers
        //   7. Auth check
        //   8. 业务 handler
        //
        // tower-http 的 ServiceBuilder 风格 layer 是栈式的：先 layer 的最后执行。

        let listener_secret = self.secret.clone();
        let app = app
            .layer(middleware::from_fn(move |req, next| {
                let secret = listener_secret.clone();
                async move { check_secret(secret, req, next).await }
            }))
            .layer(middleware::from_fn(security_headers))
            .layer(middleware::from_fn(request_timeout))
            .layer(body_limit_layer());

        // Per-IP 限流：50 req/s 稳态、100 burst；WS / SSE 升级豁免。
        let rate_limiter = IpRateLimiter::new(50.0, 100.0);
        let app = app.layer(middleware::from_fn(move |req, next| {
            let limiter = rate_limiter.clone();
            async move { rate_limit_middleware(limiter, req, next).await }
        }));

        // CORS —— 用户配置生成 allowlist。
        let cors = build_cors(&self.cors_origins);
        // PNA header injector —— 必须在最外层（响应阶段最先执行）。
        let app = app
            .layer(cors)
            .layer(middleware::from_fn(add_private_network_header));

        // ---------- 启动监听 ----------
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        info!(
            addr = %self.addr,
            cors_origins = ?self.cors_origins,
            "api listening (Clash/mihomo compatible; CORS+PNA+rate-limit+body-limit enabled)",
        );
        // 用 ConnectInfo 暴露 SocketAddr，让 rate_limit_middleware 能取到 IP。
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

/* ====================== `GET /` hello ====================== */

async fn hello() -> impl IntoResponse {
    Json(json!({
        "hello": "clash.meta",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/* ====================== Auth middleware ====================== */

#[derive(Deserialize)]
struct TokenQ {
    #[serde(default)]
    token: Option<String>,
}

async fn check_secret(
    secret: Option<String>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // 1. OPTIONS 预检永不要求 secret —— 否则浏览器先拿到 401，根本到不了 CORS。
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let path = req.uri().path();
    // 2. 静态 / 根路径 / hello / dashboard UI 不要求 secret。
    if path == "/" || path == "/healthz" || path.starts_with("/ui") {
        return next.run(req).await;
    }

    // 3. 没设 secret = 不鉴权（仅本地监听场景）
    let Some(expect) = secret.filter(|s| !s.is_empty()) else {
        return next.run(req).await;
    };

    // 4. 头部 Authorization: Bearer / x-api-secret
    let header_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get("x-api-secret")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });

    // 5. WebSocket / SSE 用 `?token=` query —— 浏览器 fetch 这两类协议时
    // 不能带自定义 header；其它请求（普通 GET/POST）拒绝从 query 读 token，
    // 防止凭证写入 access log / Referer。
    let allow_query_token = is_websocket_upgrade(&req) || is_sse_request(&req);
    let query_token = if header_token.is_none() && allow_query_token {
        let q = req.uri().query().unwrap_or("");
        Query::<TokenQ>::try_from_uri(req.uri())
            .ok()
            .and_then(|q| q.0.token)
            .or_else(|| {
                // 兼容 Razord 旧版本用 `&secret=` 的写法
                for kv in q.split('&') {
                    if let Some(v) = kv.strip_prefix("secret=") {
                        return Some(v.to_string());
                    }
                }
                None
            })
    } else {
        None
    };

    let provided = header_token.as_deref().or(query_token.as_deref());
    let ok = provided
        .map(|p| constant_time_eq(p, expect.as_str()))
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        // 不区分"无 token"与"错 token"，统一 401，避免暴露详细原因。
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Unauthorized"})),
        )
            .into_response()
    }
}

/* ====================== Per-IP rate limit ====================== */

async fn rate_limit_middleware(
    limiter: Arc<IpRateLimiter>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // OPTIONS 不限流 —— 预检风暴一般无害且必要。
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    // WS / SSE 升级路径不限流 —— 一次握手等价数百轮询。
    if is_websocket_upgrade(&req) || is_sse_request(&req) {
        return next.run(req).await;
    }
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if let Some(ip) = ip {
        if !limiter.allow(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                Json(json!({"message": "rate limit exceeded"})),
            )
                .into_response();
        }
    }
    // 没拿到 ConnectInfo（如 unix socket）→ 跳过限流。
    next.run(req).await
}

/* ====================== PNA header injector ====================== */

/// Chrome PNA：`Access-Control-Allow-Private-Network: true`。
/// 仅在 OPTIONS 预检上需要；其它响应也加上无害。
async fn add_private_network_header(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HeaderName::from_static("access-control-allow-private-network"),
        HeaderValue::from_static("true"),
    );
    resp
}
