//! Clash 兼容层关键端点的 smoke 测试 —— 直接打 axum router 验证响应形状。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use core_api::native::NativeState;
use core_config::loader::load_from_str;
use core_runtime::{Runtime, UrlTester};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const CFG: &str = r#"
version: 1
profile: desktop
listen:
  local: 7890
  panel: 9090
groups:
  main:
    choose: manual
nodes: []
"#;

fn build_state() -> NativeState {
    let plan = load_from_str(CFG).expect("plan");
    let runtime = Arc::new(Runtime::build(plan));
    NativeState {
        runtime,
        started_at: std::time::Instant::now(),
        secret: None,
        urltest: UrlTester::new(Default::default()),
        capture: None,
        feeds: None,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn version_advertises_meta() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(Request::builder().uri("/version").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["meta"], Value::Bool(true));
    assert_eq!(v["premium"], Value::Bool(true));
}

#[tokio::test]
async fn proxies_includes_global_and_direct() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(Request::builder().uri("/proxies").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v = body_json(resp).await;
    let proxies = &v["proxies"];
    assert!(proxies.get("DIRECT").is_some());
    assert!(proxies.get("REJECT").is_some());
    assert!(proxies.get("GLOBAL").is_some());
    assert!(proxies.get("main").is_some());
    // group main: choose=manual → Selector
    assert_eq!(proxies["main"]["type"], "Selector");
}

#[tokio::test]
async fn configs_get_and_put_round_trip() {
    let app = core_api::compat::router(build_state());
    // GET 默认值
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/configs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["mode"], "rule");
    assert_eq!(v["log-level"], "info");
    // PUT 修改 mode + log-level
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mode":"global","log-level":"debug","allow-lan":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // 再 GET
    let resp = app
        .oneshot(Request::builder().uri("/configs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["mode"], "global");
    assert_eq!(v["log-level"], "debug");
    assert_eq!(v["allow-lan"], true);
}

#[tokio::test]
async fn rules_serialize_steps() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(Request::builder().uri("/rules").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v = body_json(resp).await;
    let rules = v["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "rules should not be empty (preset cn_smart)");
    // 至少有一条 MATCH/兜底
    assert!(rules.iter().any(|r| r["type"] == "MATCH" || r["type"] == "GEOIP"));
}

#[tokio::test]
async fn connections_close_all_returns_count() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/connections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["closed"], 0);
}

#[tokio::test]
async fn proxies_put_changes_group_pick() {
    let cfg = r#"
version: 1
profile: desktop
listen:
  local: 7890
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#NodeA"
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@5.6.7.8:8388#NodeB"
groups:
  picker:
    choose: manual
    use: [nodes]
route:
  final: picker
"#;
    let plan = load_from_str(cfg).unwrap();
    let runtime = Arc::new(Runtime::build(plan));
    let state = NativeState {
        runtime: runtime.clone(),
        started_at: std::time::Instant::now(),
        secret: None,
        urltest: UrlTester::new(Default::default()),
        capture: None,
        feeds: None,
    };
    let app = core_api::compat::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/picker")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"NodeB"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let g = runtime.groups.read().get("picker").cloned().unwrap();
    assert_eq!(g.current_manual().as_deref(), Some("NodeB"));
}
