//! API server —— 与 mihomo `hub/route/server.go` 行为对齐：
//!
//! * **CORS 必须在最外层**：浏览器 dashboard（Yacd / metacubexd / Razord-meta /
//!   clash-dashboard）从 `https://yacd.haishan.me` 这种 https 源 fetch 到
//!   `http://127.0.0.1:9090` 时，必须先 `OPTIONS` 预检；预检答 200 + 全套
//!   `Access-Control-Allow-*` 头才会发真请求。
//! * **Private Network Access**：Chrome 110+ 的 PNA 安全规则要求"https → 私有
//!   网段（含 127.0.0.1 / *.local）"必须显式 `Access-Control-Allow-Private-Network:
//!   true`；缺这个头浏览器直接 *block*，表现就是"failed to fetch"。
//! * **GET `/` 必须存在**：mihomo `hello` 路由 —— `{"hello":"clash.meta"}`。
//!   绝大多数 dashboard "Add backend" 时第一步打这个端点确认连通性，404 = 失败。
//! * **WebSocket 用 `?token=` 鉴权**：浏览器 WS 不支持自定义 Authorization 头，
//!   只能通过 query string 传 secret。`/logs?token=...` / `/traffic?token=...` 等。
//! * **OPTIONS 预检 必须放行**：auth middleware 必须在 OPTIONS 上 200 直返，
//!   否则 401 让浏览器吃闭门羹。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::Query,
    http::{header, HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use core_runtime::Runtime;
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::{compat, native::NativeState};
use core_runtime::UrlTester;

pub struct ApiServer {
    pub addr: SocketAddr,
    pub runtime: Arc<Runtime>,
    pub secret: Option<String>,
    pub clash_compat: bool,
    pub urltest: Arc<UrlTester>,
    pub capture: Option<Arc<core_capture::CaptureSupervisor>>,
    pub feeds: Option<Arc<core_feeds::FeedManager>>,
}

impl ApiServer {
    pub async fn run(self) -> anyhow::Result<()> {
        let state = NativeState {
            runtime: self.runtime.clone(),
            started_at: std::time::Instant::now(),
            secret: self.secret.clone(),
            urltest: self.urltest.clone(),
            capture: self.capture.clone(),
            feeds: self.feeds.clone(),
        };

        // 1. 路由
        let mut app = Router::new()
            .route("/", get(hello))           // mihomo `hello` —— dashboard 连通性探测
            .route("/healthz", get(hello));    // 友好别名

        app = app.nest("/v1", crate::native::router(state.clone()));
        if self.clash_compat {
            app = app.merge(compat::router(state.clone()));
        }

        // 2. 认证中间件（在 CORS 之前 layer，运行顺序则相反 —— CORS 先于 auth）
        let listener_secret = self.secret.clone();
        let app = app.layer(middleware::from_fn(move |req, next| {
            let secret = listener_secret.clone();
            async move { check_secret(secret, req, next).await }
        }));

        // 3. CORS layer —— 必须最外层，预检在 auth 之前直接被 tower_http 处理
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
                Method::HEAD,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                HeaderName::from_static("x-api-secret"),
                HeaderName::from_static("x-requested-with"),
            ])
            .expose_headers([header::CONTENT_TYPE, header::CONTENT_LENGTH])
            .max_age(Duration::from_secs(300));

        // 4. PNA 头注入 —— Chrome 110+ 必需。tower_http CorsLayer 不直接支持，
        //    用一个 from_fn layer 在响应里追加。
        let app = app
            .layer(cors)
            .layer(middleware::from_fn(add_private_network_header));

        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        info!(addr = %self.addr, "api listening (Clash/mihomo compatible, CORS+PNA enabled)");
        axum::serve(listener, app).await?;
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

    // 5. WebSocket / 浏览器 fetch 用 `?token=` query —— mihomo authentication() 同语义。
    let query_token = if header_token.is_none() {
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
    if provided == Some(expect.as_str()) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "Unauthorized"})),
        )
            .into_response()
    }
}

/* ====================== PNA header injector ====================== */

/// Chrome PNA：`Access-Control-Allow-Private-Network: true`。
/// 仅在 OPTIONS 预检上需要；其它响应也加上无害。
async fn add_private_network_header(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HeaderName::from_static("access-control-allow-private-network"),
        HeaderValue::from_static("true"),
    );
    resp
}
