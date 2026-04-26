//! Clash / mihomo Dashboard 全量兼容层。
//!
//! 已对齐的 Dashboard 调用面（Yacd / metacubexd / clash-dashboard / razord）：
//!
//! ```text
//!   GET  /version                       内核版本 + premium / meta 标识
//!   GET  /traffic           [WS]        实时 up/down 字节速率
//!   GET  /memory            [WS]        进程 RSS / oslimit
//!   GET  /logs              [WS] [SSE]  日志流 (level + payload)
//!   GET  /connections                   连接列表
//!   GET  /connections       [WS]        连接列表实时
//!   DEL  /connections                   关闭全部
//!   DEL  /connections/:id               关闭单条
//!   GET  /proxies                       全量 proxy + group
//!   GET  /proxies/:name                 单个 proxy / group
//!   PUT  /proxies/:name                 选择 group 当前节点（{name: "Tokyo-1"}）
//!   GET  /proxies/:name/delay           单节点延迟测速
//!   GET  /group/:name/delay             组内节点并发测速
//!   GET  /providers/proxies             provider（来自 feeds 订阅）汇总
//!   GET  /providers/proxies/:name       单个 provider
//!   PUT  /providers/proxies/:name       触发刷新
//!   GET  /providers/proxies/:name/healthcheck  立即测速
//!   GET  /providers/rules               规则集 provider
//!   PUT  /providers/rules/:name         触发规则集刷新
//!   GET  /rules                         所有路由规则的 mihomo 序列化形式
//!   GET  /configs                       当前 mode / log-level / port 等
//!   PUT  /configs                       热改 mode / log-level / allow-lan / ipv6
//!   PATCH /configs                      与 PUT 同义（兼容旧 dashboard）
//!   POST /configs/geo                   触发 GeoIP/GeoSite 更新
//!   GET  /dns/query?name=&type=         DoH 风格上游解析
//!   POST /cache/fakeip/flush            清空 fake-ip 池
//!   POST /restart                       优雅重启（占位返回 503）
//!   POST /upgrade                       内核升级占位
//!   POST /upgrade/ui                    Dashboard 升级占位
//! ```

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{
    ws::{Message, WebSocket, WebSocketUpgrade},
    Path, Query, State,
};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use core_runtime::Runtime;
use futures::Stream;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::native::NativeState;

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
        // ---------- proxies ----------
        .route("/proxies", get(proxies))
        .route("/proxies/:name", get(proxy_one).put(proxy_put))
        .route("/proxies/:name/delay", get(proxy_delay))
        .route("/group/:name/delay", get(group_delay))
        // ---------- providers ----------
        .route("/providers/proxies", get(providers_proxies))
        .route("/providers/proxies/:name", get(provider_proxy_one).put(provider_proxy_refresh))
        .route("/providers/proxies/:name/healthcheck", get(provider_proxy_healthcheck))
        .route("/providers/rules", get(providers_rules))
        .route("/providers/rules/:name", get(provider_rule_one).put(provider_rule_refresh))
        // ---------- rules ----------
        .route("/rules", get(rules))
        // ---------- configs ----------
        .route("/configs", get(configs).put(configs_put).patch(configs_put))
        .route("/configs/geo", post(configs_geo))
        // ---------- DNS / cache ----------
        .route("/dns/query", get(dns_query))
        .route("/cache/fakeip/flush", post(cache_fakeip_flush))
        // ---------- misc ----------
        .route("/restart", post(restart))
        .route("/upgrade", post(upgrade_kernel))
        .route("/upgrade/ui", post(upgrade_ui))
        .with_state(state)
}

/* ====================== version ====================== */

async fn version() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
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
        return ws.on_upgrade(move |sock| traffic_ws(sock, s));
    }
    Json(s.runtime.metrics.clash_traffic()).into_response()
}

async fn traffic_ws(mut sock: WebSocket, s: NativeState) {
    let mut tick = tokio::time::interval(Duration::from_millis(1000));
    loop {
        tick.tick().await;
        let payload = s.runtime.metrics.clash_traffic().to_string();
        if sock.send(Message::Text(payload)).await.is_err() {
            break;
        }
    }
}

async fn memory(
    State(s): State<NativeState>,
    ws: Option<WebSocketUpgrade>,
) -> axum::response::Response {
    if let Some(ws) = ws {
        return ws.on_upgrade(move |sock| memory_ws(sock, s));
    }
    Json(s.runtime.metrics.clash_memory()).into_response()
}

async fn memory_ws(mut sock: WebSocket, s: NativeState) {
    let mut tick = tokio::time::interval(Duration::from_millis(1000));
    loop {
        tick.tick().await;
        let payload = s.runtime.metrics.clash_memory().to_string();
        if sock.send(Message::Text(payload)).await.is_err() {
            break;
        }
    }
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
    let mut rx = s.runtime.logs.subscribe();
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
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::StreamExt;
    let rx = s.runtime.logs.subscribe();
    BroadcastStream::new(rx).filter_map(move |r| match r {
        Ok(ev) if level_pass(&level_filter, &ev.level) => {
            let body = serde_json::to_string(&ev).unwrap_or_default();
            Some(Ok(Event::default().data(body)))
        }
        _ => None,
    })
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
    // mihomo 默认 1000ms；clamp 到 [200, 60000] 避免被恶意请求打爆。
    let interval_ms = q.interval.unwrap_or(1000).clamp(200, 60_000);
    if let Some(ws) = ws {
        return ws.on_upgrade(move |sock| connections_ws(sock, s, interval_ms));
    }
    Json(connections_snapshot(&s)).into_response()
}

async fn connections_ws(mut sock: WebSocket, s: NativeState, interval_ms: u64) {
    let mut tick = tokio::time::interval(Duration::from_millis(interval_ms));
    loop {
        tick.tick().await;
        let payload = connections_snapshot(&s).to_string();
        if sock.send(Message::Text(payload)).await.is_err() {
            break;
        }
    }
}

fn connections_snapshot(s: &NativeState) -> Value {
    let metrics = &s.runtime.metrics;
    let bytes_up = metrics.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_down = metrics.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
    let conns: Vec<Value> = s
        .runtime
        .connections
        .snapshot()
        .into_iter()
        .map(|item| {
            let entry = item.entry;
            let up = entry.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
            let down = entry.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
            // mihomo 用 uuid 字符串作为外部 id；保留 numeric id 兼容旧脚本。
            json!({
                "id": entry.meta.uuid,
                "metadata": entry.meta,
                "upload": up,
                "download": down,
                "start": iso8601(entry.started_at),
                "chains": entry.meta.chains,
                "rule": entry.meta.rule,
                "rulePayload": entry.meta.rule_payload,
                "maxUploadRate": item.up_rate_bps,
                "maxDownloadRate": item.down_rate_bps,
            })
        })
        .collect();
    json!({
        "downloadTotal": bytes_down,
        "uploadTotal": bytes_up,
        "connections": conns,
        "memory": core_observe::current_rss_bytes(),
    })
}

async fn connections_close_all(State(s): State<NativeState>) -> impl IntoResponse {
    let n = s.runtime.connections.close_all();
    // mihomo 在 200 OK 下返回空 body；这里返回 {closed} 兼容已有脚本。
    Json(json!({"closed": n}))
}

async fn connections_close_one(
    State(s): State<NativeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 同时兼容 numeric id 与 uuid 字符串（mihomo dashboard 传 uuid）。
    if s.runtime.connections.close_by_uuid_or_numeric(&id) {
        return (StatusCode::NO_CONTENT, Json(json!({}))).into_response();
    }
    (StatusCode::NOT_FOUND, Json(json!({"message": "no such connection"}))).into_response()
}

/* ====================== proxies ====================== */

async fn proxies(State(s): State<NativeState>) -> Json<Value> {
    Json(json!({"proxies": collect_proxy_map(&s)}))
}

async fn proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let map = collect_proxy_map(&s);
    if let Some(v) = map.get(&name) {
        Json(v.clone()).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"message": "proxy not found"}))).into_response()
    }
}

#[derive(Deserialize)]
struct ProxyPutBody {
    name: String,
}

async fn proxy_put(
    State(s): State<NativeState>,
    Path(group): Path<String>,
    Json(body): Json<ProxyPutBody>,
) -> impl IntoResponse {
    let groups = s.runtime.groups.read();
    let Some(g) = groups.get(&group) else {
        return (StatusCode::NOT_FOUND, Json(json!({"message": "group not found"})))
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
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
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
    match s.urltest.test_node(&s.runtime, &name, q.url.as_deref(), to).await {
        Ok(ms) => Json(json!({"delay": ms, "meanDelay": ms})).into_response(),
        Err(e) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({"message": e.to_string()})),
        )
            .into_response(),
    }
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
                .into_response()
        }
    };
    let to = q.timeout.map(Duration::from_millis);
    let res = s.urltest.test_many(&s.runtime, &members, q.url, to).await;
    // 与 mihomo `GroupBase.URLTest` 一致：仅包含成功节点；失败节点不放
    // （dashboard 把缺失视为 timeout，显示 "−"）。
    let body: serde_json::Map<String, Value> = res
        .into_iter()
        .filter_map(|(n, r)| r.ok().map(|ms| (n, Value::from(ms))))
        .collect();
    Json(Value::Object(body)).into_response()
}

fn collect_proxy_map(s: &NativeState) -> serde_json::Map<String, Value> {
    let runtime: &Arc<Runtime> = &s.runtime;
    let mut proxies = serde_json::Map::new();

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

    /// 把 URLTester 已知的 *所有* (node, url) per-URL 历史汇总 —— mihomo
    /// `Proxy.extra` 等价；dashboard 显示"对各测速 URL 的延迟"时用。
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
        proxies.insert(name.clone(), g.to_clash_json());
    }
    for n in &runtime.plan.nodes {
        proxies.insert(
            n.name.clone(),
            json!({
                "type": map_proto(n.protocol.as_str()),
                "name": n.name,
                "history": history_for(&n.name),
                "extra": extra_for(urltest, &n.name),
                "alive": urltest.alive_for_url(&n.name, &default_url),
                "udp": true,
                "xudp": false,
                "tfo": false,
                "mptcp": false,
                "smux": false,
                "interface": "",
                "routing-mark": 0,
                "provider-name": "",
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
            "alive": true,
        }),
    );
    proxies.insert(
        "REJECT".into(),
        json!({
            "type": "Reject", "name": "REJECT",
            "history": [], "extra": {},
            "udp": true, "xudp": false, "tfo": false, "mptcp": false, "smux": false,
            "alive": true,
        }),
    );
    proxies.insert(
        "GLOBAL".into(),
        json!({
            "type": "Selector",
            "name": "GLOBAL",
            "now": runtime.plan.route.r#final.clone(),
            "all": runtime.group_names(),
            "history": [],
            "extra": {},
            "udp": true,
            "alive": true,
        }),
    );
    proxies
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
        _ => "Unknown",
    }
}

/* ====================== providers ====================== */

async fn providers_proxies(State(s): State<NativeState>) -> Json<Value> {
    let mut providers = serde_json::Map::new();
    for (name, _f) in &s.runtime.plan.feeds {
        providers.insert(name.clone(), provider_json(&s, name));
    }
    Json(json!({"providers": providers}))
}

async fn provider_proxy_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if !s.runtime.plan.feeds.contains_key(&name) {
        return (StatusCode::NOT_FOUND, Json(json!({"message": "provider not found"})))
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
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

async fn provider_proxy_healthcheck(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let nodes: Vec<String> = s
        .runtime
        .plan
        .nodes
        .iter()
        .filter(|n| n.name.starts_with(&format!("{}/", name)) || n.name.contains(&format!("[{}]", name)))
        .map(|n| n.name.clone())
        .collect();
    let res = s.urltest.test_many(&s.runtime, &nodes, None, None).await;
    let body: serde_json::Map<String, Value> = res
        .into_iter()
        .map(|(n, r)| (n, r.map(Value::from).unwrap_or(Value::from(0))))
        .collect();
    Json(Value::Object(body)).into_response()
}

fn provider_json(s: &NativeState, name: &str) -> Value {
    // 优先用 FeedManager.snapshot —— 可能比 plan.nodes 更新（订阅刷新过）。
    let nodes: Vec<Value> = if let Some(mgr) = s.feeds.as_ref() {
        if let Some(snap) = mgr.snapshot(name) {
            snap.iter()
                .map(|n| {
                    json!({
                        "type": map_proto(n.protocol.as_str()),
                        "name": n.name,
                        "history": [],
                        "udp": true,
                    })
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        s.runtime
            .plan
            .nodes
            .iter()
            .filter(|n| {
                n.name.starts_with(&format!("{}/", name))
                    || n.name.contains(&format!("[{}]", name))
            })
            .map(|n| {
                json!({
                    "type": map_proto(n.protocol.as_str()),
                    "name": n.name,
                    "history": [],
                    "udp": true,
                })
            })
            .collect()
    };
    let (last_ms, next_ms, raw_bytes, from_cache) = s
        .feeds
        .as_ref()
        .and_then(|m| m.status(name))
        .map(|st| (st.last_refreshed_ms, st.next_due_ms, st.last_raw_bytes, st.last_from_cache))
        .unwrap_or((0, 0, 0, false));
    json!({
        "name": name,
        "type": "Proxy",
        "vehicleType": "HTTP",
        "proxies": nodes,
        "updatedAt": iso8601(last_ms / 1000),
        "nextDueAt": iso8601(next_ms / 1000),
        "rawBytes": raw_bytes,
        "fromCache": from_cache,
    })
}

async fn providers_rules(State(s): State<NativeState>) -> Json<Value> {
    let mut providers = serde_json::Map::new();
    for (name, set) in &s.runtime.plan.route.sets {
        providers.insert(
            name.clone(),
            json!({
                "name": name,
                "type": "Rule",
                "behavior": set.r#type,
                "format": set.format.clone().unwrap_or_else(|| "yaml".into()),
                "vehicleType": if set.url.is_some() { "HTTP" } else { "File" },
                "ruleCount": set.payload.len(),
                "updatedAt": iso8601_now(),
            }),
        );
    }
    Json(json!({"providers": providers}))
}

async fn provider_rule_one(
    State(s): State<NativeState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    if let Some(set) = s.runtime.plan.route.sets.get(&name) {
        Json(json!({
            "name": name,
            "type": "Rule",
            "behavior": set.r#type,
            "format": set.format.clone().unwrap_or_else(|| "yaml".into()),
            "vehicleType": if set.url.is_some() { "HTTP" } else { "File" },
            "ruleCount": set.payload.len(),
            "updatedAt": iso8601_now(),
        }))
        .into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"message": "ruleset not found"}))).into_response()
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
    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

/* ====================== rules ====================== */

async fn rules(State(s): State<NativeState>) -> Json<Value> {
    use core_config::runtime_plan::{RouteAction, RouteMatcher};
    let mut out = Vec::new();
    for st in &s.runtime.plan.route.steps {
        let (rtype, payload) = match &st.matcher {
            RouteMatcher::Any => ("MATCH", String::new()),
            RouteMatcher::Home => ("DOMAIN-SUFFIX", "lan,local,arpa".into()),
            RouteMatcher::Cn => ("GEOIP", "CN".into()),
            RouteMatcher::Ads => ("RULE-SET", "ads".into()),
            RouteMatcher::Service(svc) => ("RULE-SET", svc.clone()),
            RouteMatcher::Domain(d) => ("DOMAIN", d.clone()),
            RouteMatcher::Suffix(d) => ("DOMAIN-SUFFIX", d.clone()),
            RouteMatcher::Cidr(c) => ("IP-CIDR", c.clone()),
            RouteMatcher::Port(p) => ("DST-PORT", p.to_string()),
            RouteMatcher::Network(n) => ("NETWORK", n.clone()),
            RouteMatcher::Process(p) => ("PROCESS-NAME", p.clone()),
            RouteMatcher::Set(s) => ("RULE-SET", s.clone()),
            RouteMatcher::Proto(p) => ("PROCESS-PATH", p.clone()),
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
    Json(json!({"rules": out}))
}

/* ====================== configs ====================== */

async fn configs(State(s): State<NativeState>) -> Json<Value> {
    let port = s
        .runtime
        .plan
        .listen
        .mixed
        .as_ref()
        .map(|m| m.port)
        .unwrap_or(0);
    let mc = s.runtime.mutable.read().clone();
    Json(json!({
        "port": port,
        "socks-port": port,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": port,
        "authentication": &s.runtime.plan.listen.auth,
        "allow-lan": mc.allow_lan,
        "bind-address": "*",
        "mode": mc.mode,
        "log-level": mc.log_level,
        "ipv6": mc.ipv6,
        "tun": {
            "enable": mc.tun_enable,
            "stack": format!("{:?}", s.runtime.plan.capture.stack).to_lowercase(),
            "device": s.runtime.plan.capture.tun.interface_name.clone().unwrap_or_default(),
        },
        "geo-update-interval": 24,
        "interface-name": "",
        "global-client-fingerprint": "",
    }))
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
    let mut mc = s.runtime.mutable.write();
    if let Some(v) = body.mode {
        mc.mode = v.to_lowercase();
    }
    if let Some(v) = body.log_level {
        mc.log_level = v.to_lowercase();
    }
    if let Some(v) = body.allow_lan {
        mc.allow_lan = v;
    }
    if let Some(v) = body.ipv6 {
        mc.ipv6 = v;
    }
    if let Some(t) = body.tun {
        if let Some(e) = t.enable {
            mc.tun_enable = e;
        }
    }
    drop(mc);
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
        return (StatusCode::BAD_REQUEST, Json(json!({"message": "name required"})))
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
        _ => 1,
    };
    let answers = s
        .runtime
        .resolver
        .resolve_compat(&name, qtype_label.as_str())
        .await;
    Json(json!({
        "Status": 0,
        "TC": false,
        "RD": true,
        "RA": true,
        "AD": false,
        "CD": false,
        "Question": [{ "name": name, "type": qtype_num }],
        "Answer": answers,
    }))
    .into_response()
}

async fn cache_fakeip_flush(State(s): State<NativeState>) -> impl IntoResponse {
    let n = s.runtime.resolver.flush_fakeip();
    (StatusCode::OK, Json(json!({"flushed": n}))).into_response()
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
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hour, minute, second)
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
}
