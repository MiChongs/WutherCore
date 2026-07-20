use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use core_route::{FlowContext, NetworkKind};
use core_runtime::{Runtime, UrlTester};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone)]
pub struct NativeState {
    pub runtime: Arc<Runtime>,
    pub started_at: std::time::Instant,
    pub secret: Option<String>,
    pub urltest: Arc<UrlTester>,
    /// 由 main.rs 在 capture 启动后注入；为空时 /v1/capture/state 仅回静态配置。
    pub capture: Option<Arc<core_capture::CaptureSupervisor>>,
    /// 订阅管理器（始终注入，可能 idle）—— `/providers/proxies` 端点使用。
    pub feeds: Option<Arc<core_feeds::FeedManager>>,
    /// 端点级响应缓存（singleflight + TTL）。
    /// 见 [`crate::compat_cache`]。
    pub caches: Arc<crate::compat_cache::Caches>,
    /// WS 广播 hub。所有 WS 客户端共享 producer，避免 N×snapshot/sec。
    /// 见 [`crate::compat_ws`]。
    pub ws_hubs: Arc<crate::compat_ws::WsHubs>,
}

impl NativeState {
    /// 测试用便利构造器：自动 build caches + ws_hubs。production 路径请用
    /// [`crate::server::ApiServer::run`]，它会传入 connections_interval 配置。
    pub fn for_tests(
        runtime: Arc<Runtime>,
        urltest: Arc<UrlTester>,
        feeds: Option<Arc<core_feeds::FeedManager>>,
    ) -> Self {
        let ws_hubs = crate::compat_ws::WsHubs::new(runtime.clone(), 1000);
        Self {
            runtime,
            started_at: std::time::Instant::now(),
            secret: None,
            urltest,
            capture: None,
            feeds,
            caches: crate::compat_cache::Caches::new(),
            ws_hubs,
        }
    }
}

pub fn router(state: NativeState) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/traffic", get(traffic))
        .route("/nodes", get(nodes))
        .route("/groups", get(groups))
        .route("/groups/:name", patch(patch_group))
        .route("/connections", get(list_conns))
        .route("/connections/:id", delete(close_conn))
        .route("/resolver/query", get(resolver_query))
        .route("/route/check", get(route_check))
        .route("/capture/state", get(capture_state))
        .route("/smart/why", get(smart_why))
        .route("/smart/pin", post(smart_pin))
        .route("/smart/avoid", post(smart_avoid))
        .route("/smart/reset", post(smart_reset))
        .route("/smart/cache", get(smart_cache))
        .route("/smart/nodes/:group", get(smart_nodes))
        .with_state(state)
}

async fn status(State(s): State<NativeState>) -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": s.started_at.elapsed().as_secs(),
        "profile": format!("{:?}", s.runtime.plan.profile).to_lowercase(),
        "platform": std::env::consts::OS,
        "groups": s.runtime.group_names(),
        "outbounds": s.runtime.outbound_names(),
    }))
}

async fn traffic(State(s): State<NativeState>) -> impl IntoResponse {
    Json(s.runtime.metrics.snapshot())
}

async fn nodes(State(s): State<NativeState>) -> impl IntoResponse {
    let nodes: Vec<_> = s
        .runtime
        .plan
        .nodes
        .iter()
        .map(|n| {
            json!({
                "name": n.name,
                "protocol": n.protocol.as_str(),
                "host": n.host,
                "port": n.port,
                "tls": n.tls,
                "transport": n.transport,
            })
        })
        .collect();
    Json(json!({ "nodes": nodes }))
}

async fn groups(State(s): State<NativeState>) -> impl IntoResponse {
    let groups: Vec<_> = s
        .runtime
        .groups
        .read()
        .iter()
        .map(|(_, g)| {
            json!({
                "name": g.name(),
                "members": g.members(),
                "manual": g.current_manual(),
            })
        })
        .collect();
    Json(json!({ "groups": groups }))
}

#[derive(Deserialize)]
struct GroupPatch {
    pick: String,
}

async fn patch_group(
    State(s): State<NativeState>,
    Path(name): Path<String>,
    Json(body): Json<GroupPatch>,
) -> impl IntoResponse {
    let exists = s.runtime.groups.read().contains_key(&name);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown group"})),
        )
            .into_response();
    }
    s.runtime.set_group_manual(&name, &body.pick);
    (
        StatusCode::OK,
        Json(json!({"ok": true, "group": name, "pick": body.pick})),
    )
        .into_response()
}

async fn list_conns(State(s): State<NativeState>) -> impl IntoResponse {
    // 复用 mihomo 兼容 snapshot：统一字段名（uuid / metadata / upload / download / chains / start ...）
    let conns: Vec<_> = s
        .runtime
        .connections
        .manager_snapshot()
        .connections
        .into_iter()
        .map(|conn| {
            json!({
                "id": conn.id,
                "metadata": conn.metadata,
                "upload": conn.upload,
                "download": conn.download,
                "start_at": conn.start,
                "chains": conn.chains,
                "providerChains": conn.provider_chains,
                "rule": conn.rule,
                "rulePayload": conn.rule_payload,
                "maxUploadRate": conn.max_upload_rate,
                "maxDownloadRate": conn.max_download_rate,
            })
        })
        .collect();
    Json(json!({ "connections": conns }))
}

async fn close_conn(State(s): State<NativeState>, Path(id): Path<String>) -> impl IntoResponse {
    if s.runtime.connections.close_by_uuid_or_numeric(&id) {
        return (StatusCode::NO_CONTENT, Json(json!({}))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "no such connection"})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ResolverQuery {
    host: String,
}

async fn resolver_query(
    State(s): State<NativeState>,
    Query(q): Query<ResolverQuery>,
) -> impl IntoResponse {
    match s.runtime.resolver.resolve(&q.host).await {
        Ok(ips) => Json(json!({"host": q.host, "ips": ips})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RouteCheck {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    network: Option<String>,
}

async fn route_check(
    State(s): State<NativeState>,
    Query(q): Query<RouteCheck>,
) -> impl IntoResponse {
    let port = q.port.unwrap_or(443);
    let network = match q.network.as_deref() {
        Some("udp") => NetworkKind::Udp,
        _ => NetworkKind::Tcp,
    };
    let ip = q.host.parse().ok();
    let ctx = FlowContext {
        host: q.host.clone(),
        ip,
        port,
        network,
        process: None,
        ruleset: Default::default(),
        protocol: None,
    };
    let (decision, kind, src) = s.runtime.route.decide(&ctx);
    Json(json!({
        "host": q.host,
        "port": port,
        "network": network.as_str(),
        "decision": format!("{:?}", decision).to_lowercase(),
        "matcher": kind,
        "rule": src,
    }))
}

async fn capture_state(State(s): State<NativeState>) -> impl IntoResponse {
    let c = &s.runtime.plan.capture;
    let mut body = json!({
        "on": c.on,
        "method": format!("{:?}", c.method).to_lowercase(),
        "traffic": format!("{:?}", c.traffic).to_lowercase(),
        "stack": format!("{:?}", c.stack).to_lowercase(),
        "platform": std::env::consts::OS,
        "tun": {
            "interface_name": c.tun.interface_name.clone(),
            "address": c.tun.address.clone(),
            "auto_route": c.tun.auto_route,
            "auto_redirect": c.tun.auto_redirect,
            "strict_route": c.tun.strict_route,
            "endpoint_independent_nat": c.tun.endpoint_independent_nat,
            "udp_timeout_secs": c.tun.udp_timeout.as_secs(),
            "exclude_mptcp": c.tun.exclude_mptcp,
            "iproute2_table_index": c.tun.iproute2_table_index,
            "iproute2_rule_index": c.tun.iproute2_rule_index,
            "route_address": c.tun.route_address.clone(),
            "route_exclude_address": c.tun.route_exclude_address.clone(),
            "route_address_set": c.tun.route_address_set.clone(),
            "route_exclude_address_set": c.tun.route_exclude_address_set.clone(),
            "loopback_address": c.tun.loopback_address.clone(),
        }
    });
    if let Some(sup) = &s.capture {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("runtime".into(), sup.report());
        }
    }
    Json(body)
}

#[derive(Deserialize)]
struct SmartWhyParams {
    host: String,
    #[serde(default = "default_group")]
    group: String,
}

fn default_group() -> String {
    "main".into()
}

async fn smart_why(
    State(s): State<NativeState>,
    Query(q): Query<SmartWhyParams>,
) -> impl IntoResponse {
    let groups = s.runtime.groups.read();
    let g = match groups.get(&q.group) {
        Some(g) => g,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown group"})),
            )
                .into_response();
        }
    };
    let ctx = core_smart::SmartContext {
        group: q.group.clone(),
        host: q.host.clone(),
        prefer: vec![],
        avoid: vec![],
    };
    let choice = s.runtime.smart.choose(&ctx, g.members());
    Json(serde_json::to_value(&choice.explain).unwrap_or_default()).into_response()
}

#[derive(Deserialize)]
struct PinBody {
    host: String,
    group: String,
    node: String,
}

async fn smart_pin(State(s): State<NativeState>, Json(b): Json<PinBody>) -> impl IntoResponse {
    s.runtime.smart.pin(&b.host, &b.group, &b.node);
    Json(json!({"ok": true}))
}

#[derive(Deserialize, Serialize)]
struct AvoidBody {
    node: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn smart_avoid(State(s): State<NativeState>, Json(b): Json<AvoidBody>) -> impl IntoResponse {
    s.runtime.smart.record_failure(
        &b.node,
        b.reason.clone().unwrap_or_else(|| "manual avoid".into()),
    );
    Json(json!({"ok": true}))
}

async fn smart_reset(State(s): State<NativeState>) -> impl IntoResponse {
    if let Some(store) = &s.runtime.store {
        match store.reset() {
            Ok(()) => Json(json!({"ok": true, "reset": "store cleared"})).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    } else {
        Json(json!({"ok": true, "note": "no store configured; nothing persisted"})).into_response()
    }
}

async fn smart_cache(State(s): State<NativeState>) -> impl IntoResponse {
    Json(json!({ "recent_explains": s.runtime.smart.recent_explains() }))
}

async fn smart_nodes(State(s): State<NativeState>, Path(group): Path<String>) -> impl IntoResponse {
    let groups = s.runtime.groups.read();
    if let Some(g) = groups.get(&group) {
        Json(json!({"group": g.name(), "members": g.members()})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown group"})),
        )
            .into_response()
    }
}
