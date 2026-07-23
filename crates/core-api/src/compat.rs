//! Clash / mihomo Dashboard 全量兼容层。
//!
//! 端点契约对齐 sing-box `experimental/clashapi`（Yacd / metacubexd /
//! clash-dashboard / razord 等仪表盘的实际调用面）：
//!
//! ```text
//!   GET    /version                         内核版本 + premium / meta 标识
//!   GET    /traffic            [WS]         实时 up/down 字节速率
//!   GET    /memory             [WS]         进程 RSS / oslimit
//!   GET    /logs               [WS] [SSE]   日志流 (level + payload)
//!   GET    /connections        [WS]         连接列表 / 实时
//!   DEL    /connections                     关闭全部
//!   DEL    /connections/:id                 关闭单条 (uuid 或 numeric)
//!   DEL    /connections/smart/:id           关闭并把上游 smart-node 加入冷却
//!   GET    /proxies                         全量 proxy + group
//!   GET    /proxies/:name                   单个 proxy / group
//!   PUT    /proxies/:name                   选择 group 当前节点 ({name: "Tokyo-1"})
//!   PATCH  /proxies/:name                   PUT 别名（zashboard 等）
//!   DELETE /proxies/:name                   清除 group 固定 (mihomo "取消固定")
//!   GET    /proxies/:name/delay             单节点延迟测速（多采样取中位数）
//!   GET    /group                           列出所有 group
//!   GET    /group/:name                     单个 group 详情
//!   GET    /group/:name/delay               组内节点并发测速
//!   GET    /providers/proxies               proxy provider 列表
//!   GET    /providers/proxies/:name         单个 proxy provider
//!   PUT    /providers/proxies/:name         触发刷新
//!   GET    /providers/proxies/:name/healthcheck   立即测速
//!   GET    /providers/rules                 rule provider 列表
//!   GET    /providers/rules/:name           单个 rule provider
//!   PUT    /providers/rules/:name           触发 rule provider 刷新
//!   GET    /rules                           所有路由规则的 mihomo 序列化形式
//!   GET    /configs                         当前 mode / log-level / port 等
//!   PUT    /configs                         热改 mode / log-level / allow-lan / ipv6
//!   PATCH  /configs                         与 PUT 同义（兼容旧 dashboard）
//!   POST   /configs/geo                     触发 GeoIP/GeoSite 更新
//!   GET    /dns/query?name=&type=           DoH 风格上游解析
//!   POST   /cache/fakeip/flush              清空 fake-ip 池
//!   POST   /cache/dns/flush                 清空 DNS 缓存
//!   POST   /restart                         优雅重启（占位返回 503）
//!   POST   /upgrade                         内核升级占位
//!   POST   /upgrade/ui                      Dashboard 升级占位
//! ```

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::{delete, get, post},
};
use bytes::Bytes;
use core_runtime::Runtime;
use futures::Stream;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{compat_security::WsConnectionLimiter, native::NativeState};

/// 单 dashboard 实例同时打开的 WS 数量上限 —— 5 个端点（traffic / memory /
/// logs / connections / +1 留用）× 50 个 dashboard = 250。再保守 ×2 = 500。
const WS_CONNECTION_CAP: usize = 512;

/// JSON content-type，避免每次 IntoResponse 时重复构造 HeaderValue。
const JSON_CT: &str = "application/json";

fn json_bytes(bytes: Bytes) -> axum::response::Response {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(JSON_CT),
    );
    (StatusCode::OK, h, bytes).into_response()
}

pub fn router(state: NativeState) -> Router {
    Router::new()
        .route("/version", get(version))
        // ---------- traffic / memory / logs ----------
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(logs))
        // ---------- connections ----------
        .route("/connections", get(connections).delete(connections_close_all))
        .route("/connections/:id", delete(connections_close_one))
        .route("/connections/smart/:id", delete(connections_smart_block))
        // ---------- proxies ----------
        .route("/proxies", get(proxies))
        .route(
            "/proxies/:name",
            get(proxy_one)
                .put(proxy_put)
                .patch(proxy_put)
                .delete(proxy_clear),
        )
        .route("/proxies/:name/delay", get(proxy_delay))
        // ---------- group (mihomo meta API) ----------
        .route("/group", get(groups_list))
        .route("/group/:name", get(group_one))
        .route("/group/:name/delay", get(group_delay))
        // ---------- providers ----------
        .route("/providers/proxies", get(providers_proxies))
        .route(
            "/providers/proxies/:name",
            get(provider_proxy_one).put(provider_proxy_refresh),
        )
        .route(
            "/providers/proxies/:name/healthcheck",
            get(provider_proxy_healthcheck),
        )
        .route("/providers/rules", get(providers_rules))
        .route(
            "/providers/rules/:name",
            get(provider_rule_one).put(provider_rule_refresh),
        )
        // ---------- rules ----------
        .route("/rules", get(rules))
        // ---------- configs ----------
        .route("/configs", get(configs).put(configs_put).patch(configs_put))
        .route("/configs/geo", post(configs_geo))
        // ---------- DNS / cache ----------
        .route("/dns/query", get(dns_query))
        .route("/cache/fakeip/flush", post(cache_fakeip_flush))
        .route("/cache/dns/flush", post(cache_dns_flush))
        // ---------- misc ----------
        .route("/restart", post(restart))
        .route("/upgrade", post(upgrade_kernel))
        .route("/upgrade/ui", post(upgrade_ui))
        .with_state(state)
}

/* ====================== version ====================== */

async fn version() -> Json<Value> {
    Json(json!({
        "version": format!("wuthercore {}", env!("CARGO_PKG_VERSION")),
        "premium": true,
        "meta": true,
    }))
}

/* ====================== traffic / memory / logs ====================== */

async fn traffic(
    State(s): State<NativeState>,
    ws: Option<WebSocketUpgrade>,
) -> axum::response::Response {
    if let Some(ws) = ws {
        // 取 hub receiver；连接上限保护避免 fd 耗尽。
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        let rx = s.ws_hubs.traffic.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    // 非 WS：build_now 同步出一份最新（这会同时 push 到 hub watch，让 WS
    // subscriber 能立刻拿到）。
    let payload = s.ws_hubs.traffic.build_now();
    json_text(payload).into_response()
}

async fn memory(
    State(s): State<NativeState>,
    ws: Option<WebSocketUpgrade>,
) -> axum::response::Response {
    if let Some(ws) = ws {
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        let rx = s.ws_hubs.memory.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    let payload = s.ws_hubs.memory.build_now();
    json_text(payload).into_response()
}

/// 把 watch::Receiver<String> 桥接到一条 WebSocket。
/// 共享 hub 减少 N×snapshot/sec 重复成本；`permit` 持续到连接关闭。
async fn watch_to_ws(
    mut sock: WebSocket,
    mut rx: tokio::sync::watch::Receiver<String>,
    _permit: crate::compat_security::WsPermit,
) {
    // 立刻送当前值（如果非空）。
    let initial = rx.borrow_and_update().clone();
    if !initial.is_empty() {
        if sock.send(Message::Text(initial)).await.is_err() {
            return;
        }
    }
    // 之后监听变更；watch 永远只保留最新，慢消费者自动跳过中间帧。
    while rx.changed().await.is_ok() {
        let payload = rx.borrow_and_update().clone();
        if sock.send(Message::Text(payload)).await.is_err() {
            break;
        }
    }
}

/// 用 String 直接 build text/json 响应，避免再走一次 serde。
fn json_text(s: String) -> axum::response::Response {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(JSON_CT),
    );
    (StatusCode::OK, h, s).into_response()
}

/// 进程级 WS 连接上限 —— 避免 dashboard 滥连耗尽 fd 表。
fn ws_limiter() -> &'static Arc<WsConnectionLimiter> {
    use std::sync::OnceLock;
    static LIMITER: OnceLock<Arc<WsConnectionLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| WsConnectionLimiter::new("clash_ws", WS_CONNECTION_CAP))
}

#[derive(Deserialize)]
struct LogQ {
    #[serde(default)]
    level: Option<String>,
}

async fn logs(
    State(s): State<NativeState>,
    Query(q): Query<LogQ>,
    ws: Option<WebSocketUpgrade>,
) -> axum::response::Response {
    let level_filter = q.level.unwrap_or_else(|| "info".into());
    if let Some(ws) = ws {
        return ws.on_upgrade(move |sock| logs_ws(sock, s, level_filter));
    }
    // 没升级 WS 时返回 SSE，razord/yacd 历史版本会用。
    let stream = log_event_stream(s, level_filter);
    Sse::new(stream).into_response()
}

async fn logs_ws(mut sock: WebSocket, s: NativeState, level_filter: String) {
    // 原子拿历史 + 订阅，避免 push 在两步之间发生导致同事件被双投递。
    let (history, mut rx) = s.runtime.logs.subscribe_with_history();
    for ev in history {
        if !level_pass(&level_filter, &ev.level) {
            continue;
        }
        let payload = serde_json::to_string(&ev).unwrap_or_default();
        if sock.send(Message::Text(payload)).await.is_err() {
            return;
        }
    }
    while let Ok(ev) = rx.recv().await {
        if !level_pass(&level_filter, &ev.level) {
            continue;
        }
        let payload = serde_json::to_string(&ev).unwrap_or_default();
        if sock.send(Message::Text(payload)).await.is_err() {
            break;
        }
    }
}

fn log_event_stream(
    s: NativeState,
    level_filter: String,
) -> impl Stream<Item = Result<Event, Infallible>> {
    use tokio_stream::{StreamExt, wrappers::BroadcastStream};

    // 与 WS 路径同因——保持 snapshot/subscribe 原子化避免事件双发。
    let (snapshot, rx) = s.runtime.logs.subscribe_with_history();
    let history_filter = level_filter.clone();
    let history =
        tokio_stream::iter(snapshot).filter_map(move |ev| log_event_sse(&history_filter, ev));
    let live = BroadcastStream::new(rx).filter_map(move |r| match r {
        Ok(ev) => log_event_sse(&level_filter, ev),
        _ => None,
    });
    history.chain(live)
}

fn log_event_sse(filter: &str, ev: core_observe::LogEvent) -> Option<Result<Event, Infallible>> {
    if !level_pass(filter, &ev.level) {
        return None;
    }
    let body = serde_json::to_string(&ev).unwrap_or_default();
    Some(Ok(Event::default().data(body)))
}

fn level_pass(filter: &str, msg: &str) -> bool {
    let order = |s: &str| match s {
        "debug" => 0,
        "info" => 1,
        "warning" | "warn" => 2,
        "error" => 3,
        "silent" => 99,
        _ => 1,
    };
    order(msg) >= order(filter)
}

/* ====================== connections ====================== */

#[derive(Deserialize)]
struct ConnQ {
    #[serde(default)]
    interval: Option<u64>,
}

async fn connections(
    State(s): State<NativeState>,
    Query(q): Query<ConnQ>,
    ws: Option<WebSocketUpgrade>,
) -> axum::response::Response {
    if let Some(ws) = ws {
        // 注意：interval 参数只在历史代码里影响 per-client tick；现在 hub 全局
        // 用 connections_interval（在 server.rs 启动时配置）。query 参数仍接受
        // 为了向后兼容，但忽略。
        let _ = q.interval;
        let Some(permit) = ws_limiter().try_acquire() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ws connection limit reached",
            )
                .into_response();
        };
        let rx = s.ws_hubs.connections.subscribe();
        return ws.on_upgrade(move |sock| watch_to_ws(sock, rx, permit));
    }
    // 非 WS：fetch 缓存（200ms TTL）。多 dashboard 同时打 GET → 一次 build。
    let runtime = s.runtime.clone();
    let bytes = s
        .caches
        .connections
        .fetch_bytes(move || build_connections_value(&runtime));
    json_bytes(bytes)
}

fn build_connections_value(runtime: &Arc<Runtime>) -> Value {
    let manager = runtime.connections.manager_snapshot();
    let download_total = manager.download_total;
    let upload_total = manager.upload_total;
    let memory = manager.memory;
    let conns: Vec<Value> = manager
        .connections
        .into_iter()
        .map(|conn| {
            json!({
                "id": conn.id,
                "metadata": conn.metadata,
                "upload": conn.upload,
                "download": conn.download,
                "start": iso8601(conn.start),
                "chains": conn.chains,
                "providerChains": conn.provider_chains,
                "rule": conn.rule,
                "rulePayload": conn.rule_payload,
                "maxUploadRate": conn.max_upload_rate,
                "maxDownloadRate": conn.max_download_rate,
            })
        })
        .collect();
    json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": conns,
        "memory": memory,
    })
}

async fn connections_close_all(State(s): State<NativeState>) -> impl IntoResponse {
    let n = s.runtime.connections.close_all();
    s.caches.invalidate_connection_state();
    // mihomo 在 200 OK 下返回空 body；这里返回 {closed} 兼容已有脚本。
    Json(json!({"closed": n}))
}

async fn connections_close_one(
    State(s): State<NativeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 同时兼容 numeric id 与 uuid 字符串（mihomo dashboard 传 uuid）。
    if s.runtime.connections.close_by_uuid_or_numeric(&id) {
        s.caches.invalidate_connection_state();
        return (StatusCode::NO_CONTENT, Json(json!({}))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"message": "no such connection"})),
    )
        .into_response()
}

async fn connections_smart_block(
    State(s): State<NativeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _ = s.runtime.connections.set_smart_block_and_close(&id);
    StatusCode::NO_CONTENT
}

/* ====================== proxies ====================== */

async fn proxies(State(s): State<NativeState>) -> axum::response::Response {
    let bytes = proxy_map_bytes(&s);
    json_bytes(bytes)
}

async fn proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    // 使用缓存的 Arc<Value> —— 避免每次单条 lookup 重新解析整张 map。
    let value = proxy_map_value(&s);
    if let Some(p) = value
        .get("proxies")
        .and_then(|m| m.as_object())
        .and_then(|m| m.get(&name))
    {
        Json(p.clone()).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "proxy not found"})),
        )
            .into_response()
    }
}

fn proxy_map_bytes(s: &NativeState) -> Bytes {
    // 闭包必须捕获 s by clone (NativeState: Clone 中只持 Arc 字段)，
    // FnOnce 调用所有权 OK。
    let s_for_build = s.clone();
    s.caches
        .proxy_map
        .fetch_bytes(move || json!({"proxies": collect_proxy_map(&s_for_build)}))
}

fn proxy_map_value(s: &NativeState) -> Arc<Value> {
    let s_for_build = s.clone();
    s.caches
        .proxy_map
        .fetch_value(move || json!({"proxies": collect_proxy_map(&s_for_build)}))
}

#[derive(Deserialize)]
struct ProxyPutBody {
    #[serde(default)]
    name: String,
}

async fn proxy_put(
    State(s): State<NativeState>,
    Path(group): Path<String>,
    Json(body): Json<ProxyPutBody>,
) -> impl IntoResponse {
    // Empty name 与 mihomo / sing-box `URLTest.SelectOutbound("")` 等价 ——
    // 清空当前固定选择。
    if body.name.is_empty() {
        let r = clear_pin_inner(&s, &group);
        s.caches.invalidate_proxy_state();
        return r;
    }
    let groups = s.runtime.groups.read();
    let Some(g) = groups.get(&group) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "group not found"})),
        )
            .into_response();
    };
    if !g.members().iter().any(|m| m == &body.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "node not in group"})),
        )
            .into_response();
    }
    drop(groups);
    s.runtime.set_group_manual(&group, &body.name);
    s.caches.invalidate_proxy_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

/// `DELETE /proxies/:name` —— mihomo 的"取消固定"语义。等价于
/// `PUT /proxies/:name {"name": ""}`。
async fn proxy_clear(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let r = clear_pin_inner(&s, &name);
    s.caches.invalidate_proxy_state();
    r
}

fn clear_pin_inner(s: &NativeState, group: &str) -> axum::response::Response {
    let groups = s.runtime.groups.read();
    let Some(g) = groups.get(group) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "group not found"})),
        )
            .into_response();
    };
    let previous = g.current_manual().unwrap_or_default();
    let now = g
        .last_pick()
        .or_else(|| g.members().first().cloned())
        .unwrap_or_default();
    drop(groups);
    s.runtime.set_group_manual(group, "");
    Json(json!({
        "group": group,
        "previous_pin": previous,
        "now": now,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DelayQ {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
}

async fn proxy_delay(
    State(s): State<NativeState>,
    Path(name): Path<String>,
    Query(q): Query<DelayQ>,
) -> axum::response::Response {
    let to = q.timeout.map(Duration::from_millis);
    // Mihomo `proxy.URLTest()` 对 group 名递归到当前选中成员；WutherCore 的
    // `test_node` 只查 outbounds 注册表（不含 group），group 名直接 UnknownNode，
    // dashboard 看到全是 timeout。这里仿照 mihomo：name 是 group → 转测它的
    // `now` 成员；group 没选过 → 用 members.first() 兜底；name 不是 group →
    // 走原 test_node 路径。
    let target = match s.runtime.groups.read().get(&name) {
        Some(g) => g
            .to_clash_json()
            .get("now")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .or_else(|| g.members().first().cloned())
            .unwrap_or_else(|| name.clone()),
        None => name.clone(),
    };

    // sing-box `getProxyDelay`: 多采样取中位数稳定结果。第一次 < 50ms 直接采用。
    const MAX_SAMPLES: usize = 3;
    let mut samples: Vec<u32> = Vec::with_capacity(MAX_SAMPLES);
    let mut last_err: Option<String> = None;
    for i in 0..MAX_SAMPLES {
        match s
            .urltest
            .test_node(&s.runtime, &target, q.url.as_deref(), to)
            .await
        {
            Ok(ms) => {
                samples.push(ms);
                if i == 0 && ms < 50 {
                    break;
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    if samples.is_empty() {
        return (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({
                "message": last_err.unwrap_or_else(|| "An error occurred in the delay test".into())
            })),
        )
            .into_response();
    }

    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    Json(json!({"delay": median, "meanDelay": median})).into_response()
}

/* ====================== group (mihomo meta API) ====================== */

async fn groups_list(State(s): State<NativeState>) -> Json<Value> {
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    let groups: Vec<Value> = s
        .runtime
        .groups
        .read()
        .iter()
        .map(|(_, g)| group_json(g, urltest, &default_url, &s.runtime))
        .collect();
    Json(json!({"proxies": groups}))
}

async fn group_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    if let Some(g) = s.runtime.groups.read().get(&name) {
        return Json(group_json(g, urltest, &default_url, &s.runtime)).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"message": "group not found"})),
    )
        .into_response()
}

async fn group_delay(
    State(s): State<NativeState>,
    Path(name): Path<String>,
    Query(q): Query<DelayQ>,
) -> axum::response::Response {
    let members = match s.runtime.groups.read().get(&name) {
        Some(g) => g.members().to_vec(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"message": "group not found"})),
            )
                .into_response();
        }
    };
    let to = q.timeout.map(Duration::from_millis);
    // sing-box GroupBase.URLTest: 并发上限 4，避免 1000 节点同时拨号互相
    // 抢带宽导致测速值被网络拥塞放大。
    let body = group_delay_bounded(&s, &members, q.url, to, 4).await;
    Json(Value::Object(body)).into_response()
}

/// `test_many` + concurrency cap。对齐 sing-box `batch.WithConcurrencyNum(4)`。
async fn group_delay_bounded(
    s: &NativeState,
    members: &[String],
    url: Option<String>,
    timeout: Option<Duration>,
    max_in_flight: usize,
) -> Map<String, Value> {
    use tokio::sync::Semaphore;

    if members.is_empty() {
        return Map::new();
    }
    let sem = Arc::new(Semaphore::new(max_in_flight.max(1)));
    let mut handles = Vec::with_capacity(members.len());
    for name in members {
        // acquire 在 spawn 前完成；保证全局并发 ≤ max_in_flight。
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed (program shutting down)
        };
        let urltest = s.urltest.clone();
        let runtime = s.runtime.clone();
        let url_for = url.clone();
        let n = name.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit; // hold until task ends
            let r = urltest
                .test_node(&runtime, &n, url_for.as_deref(), timeout)
                .await;
            (n, r)
        }));
    }
    let mut out = Map::new();
    for h in handles {
        if let Ok((name, Ok(ms))) = h.await {
            out.insert(name, Value::from(ms));
        }
    }
    out
}

/* ====================== proxy map ====================== */

fn collect_proxy_map(s: &NativeState) -> Map<String, Value> {
    let runtime: &Arc<Runtime> = &s.runtime;
    let mut proxies = Map::new();

    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;

    let history_for = |node: &str| -> Value {
        // 1) URLTester per-(node, default_url) 历史 —— mihomo 主显示来源
        let mut entries: Vec<core_runtime::HistoryEntry> = urltest.history(node, &default_url);
        if entries.is_empty() {
            // 2) 退回 SmartSelector 历史（含其它 URL 的成功/失败）
            let stats = runtime.smart.ensure_node(node);
            entries = stats
                .history()
                .into_iter()
                .map(|e| core_runtime::HistoryEntry {
                    time_ms: e.time_ms,
                    delay_ms: e.delay_ms as u32,
                })
                .collect();
        }
        let h: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect();
        Value::Array(h)
    };

    // 把 URLTester 已知的 *所有* (node, url) per-URL 历史汇总 —— mihomo
    // `Proxy.extra` 等价；dashboard 显示"对各测速 URL 的延迟"时用。
    fn extra_for(urltest: &Arc<core_runtime::UrlTester>, node: &str) -> Value {
        // UrlTester 没有公开"拿某 node 全部 url 历史"的 API；这里只暴露 default_url
        // 一项作为最小可用集合（足够 dashboard 显示当前测速 URL）。
        let url = urltest.current_config().default_url;
        let entries = urltest.history(node, &url);
        if entries.is_empty() {
            return json!({});
        }
        let alive = urltest.alive_for_url(node, &url);
        let h: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect();
        json!({
            url: {
                "alive": alive,
                "history": h,
            }
        })
    }

    for (name, g) in runtime.groups.read().iter() {
        proxies.insert(name.clone(), group_json(g, urltest, &default_url, runtime));
        let _ = (name, g); // silence unused if future refactor
    }
    for n in &runtime.plan.nodes {
        let history = history_for(&n.name);
        let delay = delay_from_history(&history);
        let alive = urltest.alive_for_url(&n.name, &default_url);
        proxies.insert(
            n.name.clone(),
            json!({
                "type": map_proto(n.protocol.as_str()),
                "name": n.name,
                "history": history,
                "extra": extra_for(urltest, &n.name),
                "alive": alive,
                "delay": delay,
                "udp": true,
                "xudp": false,
                "tfo": false,
                "mptcp": false,
                "smux": false,
                "interface": "",
                "routing-mark": 0,
                "provider-name": provider_for_node(&n.name),
                "dialer-proxy": "",
            }),
        );
    }
    proxies.insert(
        "DIRECT".into(),
        json!({
            "type": "Direct", "name": "DIRECT",
            "history": [], "extra": {},
            "udp": true, "xudp": false, "tfo": false, "mptcp": false, "smux": false,
            "alive": true, "delay": 0,
        }),
    );
    proxies.insert(
        "REJECT".into(),
        json!({
            "type": "Reject", "name": "REJECT",
            "history": [], "extra": {},
            "udp": true, "xudp": false, "tfo": false, "mptcp": false, "smux": false,
            "alive": true, "delay": 0,
        }),
    );
    let global_now = runtime.plan.route.r#final.clone();
    let global_history = history_for(&global_now);
    let global_delay = delay_from_history(&global_history);
    let global_alive = if global_now.is_empty() || global_now == "DIRECT" || global_now == "REJECT"
    {
        true
    } else {
        urltest.alive_for_url(&global_now, &default_url)
    };
    proxies.insert(
        "GLOBAL".into(),
        json!({
            "type": "Selector",
            "name": "GLOBAL",
            "now": global_now,
            "all": runtime.group_names(),
            "history": global_history,
            "extra": {},
            "alive": global_alive,
            "delay": global_delay,
            "udp": true,
            "xudp": false,
            "tfo": false,
            "mptcp": false,
            "smux": false,
            "hidden": false,
            "icon": "",
            "fixed": "",
            "expectedStatus": "",
            "testUrl": default_url,
        }),
    );
    proxies
}

/// Group → mihomo 兼容 JSON。在 `to_clash_json` 基础上补全：
/// * 顶层 `delay` 数值（dashboard 主要展示用）
/// * `history` / `alive` / `extra` 取自当前 `now` 成员的 urltest 状态
/// * 与 sing-box `proxyInfo` 对齐
fn group_json(
    g: &core_runtime::GroupSelector,
    urltest: &Arc<core_runtime::UrlTester>,
    default_url: &str,
    runtime: &Arc<Runtime>,
) -> Value {
    let mut json = g.to_clash_json();
    let now = json
        .get("now")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty());

    if let Some(obj) = json.as_object_mut() {
        // 默认填空 history / alive / delay，避免 dashboard 取不到字段
        // 时把 group 渲染为"超时"。
        if !obj.contains_key("history") {
            obj.insert("history".into(), Value::Array(vec![]));
        }
        if !obj.contains_key("delay") {
            obj.insert("delay".into(), Value::from(0u64));
        }
        if let Some(now_node) = now.as_deref() {
            let history = node_history(urltest, runtime, now_node, default_url);
            let alive = urltest.alive_for_url(now_node, default_url);
            let delay = delay_from_history(&history);
            obj.insert("history".into(), history.clone());
            obj.insert("alive".into(), Value::Bool(alive));
            obj.insert("delay".into(), Value::from(delay));
            obj.insert(
                "extra".into(),
                node_extra(urltest, now_node, default_url, &history),
            );
        }
    }
    json
}

/// 按 (node, url) 拉历史；URLTester 空时退回 SmartSelector。
fn node_history(
    urltest: &Arc<core_runtime::UrlTester>,
    runtime: &Arc<Runtime>,
    node: &str,
    url: &str,
) -> Value {
    let mut entries: Vec<core_runtime::HistoryEntry> = urltest.history(node, url);
    if entries.is_empty() {
        let stats = runtime.smart.ensure_node(node);
        entries = stats
            .history()
            .into_iter()
            .map(|e| core_runtime::HistoryEntry {
                time_ms: e.time_ms,
                delay_ms: e.delay_ms as u32,
            })
            .collect();
    }
    Value::Array(
        entries
            .into_iter()
            .map(|e| {
                json!({
                    "time": iso8601(e.time_ms / 1000),
                    "delay": e.delay_ms,
                })
            })
            .collect(),
    )
}

fn node_extra(
    urltest: &Arc<core_runtime::UrlTester>,
    node: &str,
    url: &str,
    history: &Value,
) -> Value {
    if history.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        return json!({});
    }
    json!({
        url: {
            "alive": urltest.alive_for_url(node, url),
            "history": history.clone(),
        }
    })
}

/// 取 history 数组里最后一条的 `delay` 字段；空数组返回 0。
fn delay_from_history(history: &Value) -> u64 {
    history
        .as_array()
        .and_then(|arr| arr.last())
        .and_then(|entry| entry.get("delay"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// 节点名 → 所属 provider（feed）名。FeedManager 给节点加的命名约定为
/// `feedname/nodename` 或 `nodename[feedname]`。命中其一即视为该 feed。
fn provider_for_node(name: &str) -> String {
    if let Some(idx) = name.find('/') {
        return name[..idx].to_string();
    }
    if let (Some(start), Some(end)) = (name.rfind('['), name.rfind(']')) {
        if start < end {
            return name[start + 1..end].to_string();
        }
    }
    String::new()
}

fn map_proto(p: &str) -> &'static str {
    match p {
        "ss" => "Shadowsocks",
        "ssr" => "ShadowsocksR",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "hysteria" => "Hysteria",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "wireguard" => "WireGuard",
        "ssh" => "Ssh",
        "http" => "Http",
        "socks5" => "Socks5",
        "anytls" => "AnyTLS",
        "snell" => "Snell",
        "mieru" => "Mieru",
        _ => "Unknown",
    }
}

/* ====================== providers ====================== */

async fn providers_proxies(State(s): State<NativeState>) -> axum::response::Response {
    let s_for_build = s.clone();
    let bytes = s.caches.providers_proxies.fetch_bytes(move || {
        let mut providers = Map::new();
        for (name, _f) in &s_for_build.runtime.plan.feeds {
            providers.insert(name.clone(), provider_json(&s_for_build, name));
        }
        json!({"providers": providers})
    });
    json_bytes(bytes)
}

async fn provider_proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if !s.runtime.plan.feeds.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "provider not found"})),
        )
            .into_response();
    }
    Json(provider_json(&s, &name)).into_response()
}

async fn provider_proxy_refresh(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let exists = s.runtime.plan.feeds.contains_key(&name);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "provider not found"})),
        )
            .into_response();
    }
    // 触发后台 FeedManager 立即刷新该 feed。
    if let Some(mgr) = s.feeds.as_ref() {
        mgr.refresh_now(&name);
    }
    s.caches.invalidate_proxy_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

async fn provider_proxy_healthcheck(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let nodes: Vec<String> = nodes_in_provider(&s, &name);
    let res = s.urltest.test_many(&s.runtime, &nodes, None, None).await;
    let body: Map<String, Value> = res
        .into_iter()
        .map(|(n, r)| (n, r.map(Value::from).unwrap_or(Value::from(0))))
        .collect();
    Json(Value::Object(body)).into_response()
}

fn nodes_in_provider(s: &NativeState, name: &str) -> Vec<String> {
    if let Some(mgr) = s.feeds.as_ref() {
        if let Some(snap) = mgr.snapshot(name) {
            return snap.into_iter().map(|n| n.name).collect();
        }
    }
    s.runtime
        .plan
        .nodes
        .iter()
        .filter(|n| {
            n.name.starts_with(&format!("{}/", name)) || n.name.contains(&format!("[{}]", name))
        })
        .map(|n| n.name.clone())
        .collect()
}

fn provider_json(s: &NativeState, name: &str) -> Value {
    // 优先用 FeedManager.snapshot —— 可能比 plan.nodes 更新（订阅刷新过）。
    let urltest = &s.urltest;
    let default_url = urltest.current_config().default_url;
    let mut nodes: Vec<Value> = Vec::new();
    if let Some(mgr) = s.feeds.as_ref() {
        if let Some(snap) = mgr.snapshot(name) {
            nodes = snap
                .iter()
                .map(|n| {
                    let history = Value::Array(
                        urltest
                            .history(&n.name, &default_url)
                            .into_iter()
                            .map(|e| {
                                json!({
                                    "time": iso8601(e.time_ms / 1000),
                                    "delay": e.delay_ms,
                                })
                            })
                            .collect(),
                    );
                    let delay = delay_from_history(&history);
                    json!({
                        "type": map_proto(n.protocol.as_str()),
                        "name": n.name,
                        "history": history,
                        "alive": urltest.alive_for_url(&n.name, &default_url),
                        "delay": delay,
                        "udp": true,
                    })
                })
                .collect();
        }
    }
    if nodes.is_empty() {
        nodes = s
            .runtime
            .plan
            .nodes
            .iter()
            .filter(|n| {
                n.name.starts_with(&format!("{}/", name)) || n.name.contains(&format!("[{}]", name))
            })
            .map(|n| {
                let history = Value::Array(
                    urltest
                        .history(&n.name, &default_url)
                        .into_iter()
                        .map(|e| {
                            json!({
                                "time": iso8601(e.time_ms / 1000),
                                "delay": e.delay_ms,
                            })
                        })
                        .collect(),
                );
                let delay = delay_from_history(&history);
                json!({
                    "type": map_proto(n.protocol.as_str()),
                    "name": n.name,
                    "history": history,
                    "alive": urltest.alive_for_url(&n.name, &default_url),
                    "delay": delay,
                    "udp": true,
                })
            })
            .collect();
    }
    let status = s.feeds.as_ref().and_then(|m| m.status(name));
    let (last_ms, next_ms, raw_bytes, from_cache, every_secs, url, userinfo) = status
        .as_ref()
        .map(|st| {
            (
                st.last_refreshed_ms,
                st.next_due_ms,
                st.last_raw_bytes,
                st.last_from_cache,
                st.every_secs,
                st.url.clone(),
                st.userinfo,
            )
        })
        .unwrap_or((0, 0, 0, false, 0, String::new(), None));
    let vehicle_type = if url.is_empty() { "File" } else { "HTTP" };
    let userinfo_json = userinfo
        .map(|ui| {
            json!({
                "Upload":   ui.upload,
                "Download": ui.download,
                "Total":    ui.total,
                "Expire":   ui.expire,
            })
        })
        .unwrap_or_else(|| {
            json!({
                "Upload":   0,
                "Download": 0,
                "Total":    0,
                "Expire":   0,
            })
        });
    json!({
        "name": name,
        "type": "Proxy",
        "vehicleType": vehicle_type,
        "proxies": nodes,
        "updatedAt": iso8601(last_ms / 1000),
        "expectedStatus": "*",
        // 订阅用量四元组 —— 解析自 HTTP 响应的 Subscription-Userinfo
        // 或同义头。机场没回该头时四字段全 0，dashboard 视为"无配额信息"。
        "subscriptionInfo": userinfo_json,
        "healthCheck": {
            "enable":   true,
            "url":      default_url,
            "interval": every_secs,
            "lazy":     false,
        },
        // 私有扩展字段（dashboard 有就显示，没有就忽略）
        "nextDueAt": iso8601(next_ms / 1000),
        "rawBytes": raw_bytes,
        "fromCache": from_cache,
    })
}

async fn providers_rules(State(s): State<NativeState>) -> axum::response::Response {
    let runtime = s.runtime.clone();
    let bytes = s.caches.providers_rules.fetch_bytes(move || {
        let mut providers = Map::new();
        for (name, set) in &runtime.plan.route.sets {
            providers.insert(name.clone(), rule_provider_json(name, set));
        }
        json!({"providers": providers})
    });
    json_bytes(bytes)
}

async fn provider_rule_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if let Some(set) = s.runtime.plan.route.sets.get(&name) {
        Json(rule_provider_json(&name, set)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "ruleset not found"})),
        )
            .into_response()
    }
}

async fn provider_rule_refresh(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !s.runtime.plan.route.sets.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "ruleset not found"})),
        )
            .into_response();
    }
    // RulesetManager 的强制刷新 API 暂未公开（后台 ticker 自动周期刷）；
    // 这里 ack 让 dashboard 不报错。
    s.caches.invalidate_rule_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

fn rule_provider_json(name: &str, set: &core_config::model::RuleSetSpec) -> Value {
    // mihomo 字段：vehicleType ∈ {HTTP, FILE, INLINE} 全大写；behavior ∈
    // {DOMAIN, IPCIDR, CLASSICAL} 全大写。
    let vehicle_type = if set.url.is_some() {
        "HTTP"
    } else if set.path.is_some() {
        "FILE"
    } else {
        "INLINE"
    };
    let lowered = set.r#type.to_lowercase();
    let behavior = match lowered.as_str() {
        "domain" => "Domain".to_string(),
        "ipcidr" | "ip-cidr" | "ip_cidr" => "IPCIDR".to_string(),
        "classical" => "Classical".to_string(),
        _ => lowered.clone(),
    };
    json!({
        "name": name,
        "type": "Rule",
        "vehicleType": vehicle_type,
        "behavior": behavior,
        "format": set.format.clone().unwrap_or_else(|| "yaml".into()),
        "ruleCount": set.payload.len(),
        "updatedAt": iso8601_now(),
    })
}

/* ====================== rules ====================== */

async fn rules(State(s): State<NativeState>) -> axum::response::Response {
    let runtime = s.runtime.clone();
    let bytes = s
        .caches
        .rules
        .fetch_bytes(move || build_rules_value(&runtime));
    json_bytes(bytes)
}

fn build_rules_value(runtime: &Arc<Runtime>) -> Value {
    use core_config::runtime_plan::{RouteAction, RouteMatcher};
    let mut out = Vec::new();
    for st in &runtime.plan.route.steps {
        let (rtype, payload) = match &st.matcher {
            RouteMatcher::Any => ("MATCH", String::new()),
            RouteMatcher::Home => ("DOMAIN-SUFFIX", "lan,local,arpa".into()),
            RouteMatcher::Cn => ("GEOIP", "CN".into()),
            RouteMatcher::Ads => ("RULE-SET", "ads".into()),
            RouteMatcher::Service(svc) => ("RULE-SET", svc.clone()),
            RouteMatcher::Domain(d) => ("DOMAIN", d.clone()),
            RouteMatcher::Suffix(d) => ("DOMAIN-SUFFIX", d.clone()),
            RouteMatcher::Keyword(k) => ("DOMAIN-KEYWORD", k.clone()),
            RouteMatcher::Cidr(c) => ("IP-CIDR", c.clone()),
            RouteMatcher::Port(p) => ("DST-PORT", p.to_string()),
            RouteMatcher::PortRange(lo, hi) => ("DST-PORT", format!("{lo}-{hi}")),
            RouteMatcher::Network(n) => ("NETWORK", n.clone()),
            RouteMatcher::Process(p) => ("PROCESS-NAME", p.clone()),
            RouteMatcher::Set(s) => ("RULE-SET", s.clone()),
            RouteMatcher::Proto(p) => ("PROCESS-PATH", p.clone()),
            // mihomo 标准里没有 AND/OR 组合规则；为面板可读，输出占位类型。
            RouteMatcher::And(parts) => ("AND", format!("{} clauses", parts.len())),
            RouteMatcher::Or(parts) => ("OR", format!("{} clauses", parts.len())),
        };
        let proxy = match &st.action {
            RouteAction::Direct => "DIRECT".to_string(),
            RouteAction::Block => "REJECT".to_string(),
            RouteAction::Group(g) => g.clone(),
        };
        out.push(json!({
            "type": rtype,
            "payload": payload,
            "proxy": proxy,
        }));
    }
    json!({"rules": out})
}

/* ====================== configs ====================== */

async fn configs(State(s): State<NativeState>) -> axum::response::Response {
    let s_for_build = s.clone();
    let bytes = s
        .caches
        .configs
        .fetch_bytes(move || build_configs_value(&s_for_build));
    json_bytes(bytes)
}

fn build_configs_value(s: &NativeState) -> Value {
    let port = s
        .runtime
        .plan
        .listen
        .mixed
        .as_ref()
        .map(|m| m.port)
        .unwrap_or(0);
    let mc = s.runtime.mutable.read().clone();
    let find_process_mode = match s.runtime.plan.find_process_mode {
        core_config::model::FindProcessMode::Off => "off",
        core_config::model::FindProcessMode::Strict => "strict",
        core_config::model::FindProcessMode::Always => "always",
    };
    // 只回用户名，永不回明文密码。空数组表示未启用入站认证。
    let authentication: Vec<String> = s
        .runtime
        .plan
        .listen
        .auth
        .iter()
        .map(|up| up.user.clone())
        .collect();
    json!({
        "port": port,
        "socks-port": port,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": port,
        "authentication": authentication,
        "allow-lan": mc.allow_lan,
        "bind-address": "*",
        "mode": mc.mode,
        // sing-box 与 mihomo 的 dashboard 都看 mode-list；rule/global/direct 三态
        // 是 mihomo 内核的标准三档；dashboard 用它生成下拉选项。
        "mode-list": ["rule", "global", "direct"],
        "modes": ["rule", "global", "direct"],
        "log-level": mc.log_level,
        "ipv6": mc.ipv6,
        "tun": {
            "enable": mc.tun_enable,
            "stack": format!("{:?}", s.runtime.plan.capture.stack).to_lowercase(),
            "device": s.runtime.plan.capture.tun.interface_name.clone().unwrap_or_default(),
        },
        "find-process-mode": find_process_mode,
        // mihomo 配置项；WutherCore 没有暴露开关时按 sing-box 默认行为返回。
        "unified-delay": false,
        "tcp-concurrent": true,
        "geo-update-interval": 24,
        "interface-name": "",
        "global-client-fingerprint": "",
        // dashboard 通常会读这俩；空串表示走默认路由。
        "geox-url": {},
        "global-ua": "",
    })
}

#[derive(Deserialize, Default)]
struct ConfigsPut {
    #[serde(default)]
    mode: Option<String>,
    #[serde(rename = "log-level", default)]
    log_level: Option<String>,
    #[serde(rename = "allow-lan", default)]
    allow_lan: Option<bool>,
    #[serde(default)]
    ipv6: Option<bool>,
    #[serde(default)]
    tun: Option<TunPut>,
}

#[derive(Deserialize, Default)]
struct TunPut {
    #[serde(default)]
    enable: Option<bool>,
}

async fn configs_put(
    State(s): State<NativeState>,
    Json(body): Json<ConfigsPut>,
) -> impl IntoResponse {
    // mode 已接入选路；其余字段仍只更新 MutableConfig 视图。
    // allow-lan / tun_enable / ipv6 / log-level 的真实副作用尚未热切换绑定/capture，
    // 但至少 mode 不再是“写成功假象”。
    let mut mc = s.runtime.mutable.write();
    if let Some(v) = body.mode {
        let normalized = v.to_lowercase();
        match normalized.as_str() {
            "rule" | "global" | "direct" => mc.mode = normalized,
            other => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "message": format!(
                            "unsupported mode \"{other}\"; expected rule|global|direct"
                        )
                    })),
                )
                    .into_response();
            }
        }
    }
    if let Some(v) = body.log_level {
        mc.log_level = v.to_lowercase();
    }
    if let Some(v) = body.allow_lan {
        // 入站 bind 在启动时由 listen.share / host 决定，运行时无法安全热切换。
        // 拒绝静默写入，避免 dashboard 显示 allow-lan=false 但端口仍对外监听。
        let current = mc.allow_lan;
        if v != current {
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(json!({
                    "message": format!(
                        "allow-lan cannot be changed at runtime (current={current}, requested={v}); \
                         restart with listen.share false|home|all"
                    )
                })),
            )
                .into_response();
        }
    }
    if let Some(v) = body.ipv6 {
        mc.ipv6 = v;
    }
    if let Some(t) = body.tun {
        if let Some(e) = t.enable {
            let current = mc.tun_enable;
            if e != current {
                return (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "message": format!(
                            "tun.enable cannot be changed at runtime (current={current}, requested={e}); \
                             restart with capture.on"
                        )
                    })),
                )
                    .into_response();
            }
        }
    }
    drop(mc);
    s.caches.invalidate_config_state();
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

async fn configs_geo(State(_s): State<NativeState>) -> impl IntoResponse {
    // 触发 ruleset_index 全量刷新由 FeedManager 异步完成；这里仅 ack。
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

/* ====================== DNS / cache ====================== */

#[derive(Deserialize)]
struct DnsQ {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    qtype: Option<String>,
}

async fn dns_query(
    State(s): State<NativeState>,
    Query(q): Query<DnsQ>,
) -> axum::response::Response {
    let Some(name) = q.name else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "name required"})),
        )
            .into_response();
    };
    let qtype_label = q.qtype.as_deref().unwrap_or("A").to_uppercase();
    let qtype_num: u16 = match qtype_label.as_str() {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "TXT" => 16,
        "MX" => 15,
        "NS" => 2,
        "PTR" => 12,
        "SRV" => 33,
        "HTTPS" => 65,
        "SVCB" => 64,
        _ => 1,
    };
    let answers = s
        .runtime
        .resolver
        .resolve_compat(&name, qtype_label.as_str())
        .await;
    // sing-box `dnsRouter`: 用 mihomo `Question` 字段大写形式（Name/Qtype/Qclass）。
    Json(json!({
        "Status": 0,
        "TC": false,
        "RD": true,
        "RA": true,
        "AD": false,
        "CD": false,
        "Question": [{
            "Name": format!("{}.", name.trim_end_matches('.')),
            "Qtype": qtype_num,
            "Qclass": 1,
        }],
        "Answer": answers,
        "Server": "internal",
    }))
    .into_response()
}

async fn cache_fakeip_flush(State(s): State<NativeState>) -> impl IntoResponse {
    let n = s.runtime.resolver.flush_fakeip();
    (StatusCode::OK, Json(json!({"flushed": n}))).into_response()
}

/// `POST /cache/dns/flush` —— 与 sing-box 的 `flushDNS` 等价，清掉 DNS 解析
/// 缓存。这里同时清 fake-ip 池和 DNS cache（mihomo 的 `dnsRouter.ClearCache`）。
async fn cache_dns_flush(State(s): State<NativeState>) -> impl IntoResponse {
    s.runtime.resolver.cache().clear();
    let fakeip = s.runtime.resolver.flush_fakeip();
    (
        StatusCode::OK,
        Json(json!({"flushed": true, "fakeip_flushed": fakeip})),
    )
        .into_response()
}

/* ====================== misc ====================== */

async fn restart() -> impl IntoResponse {
    // 优雅重启需要外部 supervisor 协助；本进程内仅返回 503 让 dashboard 提示。
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"message": "in-process restart not supported; use systemd/runit"})),
    )
}

async fn upgrade_kernel() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"message": "kernel upgrade is out-of-band"})),
    )
}

async fn upgrade_ui() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"message": "ui upgrade is out-of-band"})),
    )
}

/* ====================== utils ====================== */

/// 把 Unix 秒时间戳格式化为 RFC3339 / ISO 8601（UTC zulu 风格），
/// 与 mihomo `time.Time.MarshalJSON` 输出兼容，让 yacd / metacubexd /
/// Razord-meta 等 dashboard 能正确 `new Date(...)` 解析展示。
///
/// 例：1714512345 → "2024-04-30T22:45:45Z"
///
/// 不引入 chrono：用 civil_from_days 算法把秒拆成 (y,m,d,h,m,s)。
fn iso8601(ts_secs: u64) -> String {
    let days = (ts_secs / 86_400) as i64;
    let secs_of_day = (ts_secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

/// Howard Hinnant 公元日历算法：从 1970-01-01 起的天数 → (year, month, day)。
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

fn iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601(secs)
}

#[cfg(test)]
mod time_tests {
    use super::*;
    #[test]
    fn rfc3339_known_dates() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        // 2024-04-30 22:45:45 UTC
        assert_eq!(iso8601(1_714_517_145), "2024-04-30T22:45:45Z");
        // 2025-01-01 00:00:00 UTC
        assert_eq!(iso8601(1_735_689_600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn delay_from_history_takes_last() {
        let h = json!([
            {"time": "2024-04-30T22:45:45Z", "delay": 80},
            {"time": "2024-04-30T22:46:45Z", "delay": 123},
        ]);
        assert_eq!(super::delay_from_history(&h), 123);
    }

    #[test]
    fn delay_from_empty_history_is_zero() {
        let h = json!([]);
        assert_eq!(super::delay_from_history(&h), 0);
    }

    #[test]
    fn provider_for_node_handles_slash_and_brackets() {
        assert_eq!(super::provider_for_node("primary/HK-01"), "primary");
        assert_eq!(super::provider_for_node("HK-01[primary]"), "primary");
        assert_eq!(super::provider_for_node("HK-01"), "");
    }
}
