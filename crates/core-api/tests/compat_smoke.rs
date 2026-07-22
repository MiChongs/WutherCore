//! Clash 兼容层关键端点的 smoke 测试 —— 直接打 axum router 验证响应形状。

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use core_api::native::NativeState;
use core_config::loader::load_from_str;
use core_observe::ConnectionMeta;
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
    NativeState::for_tests(runtime, UrlTester::new(Default::default()), None)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

struct AdversarialMeshBackend {
    descriptor: core_mesh::BackendDescriptor,
    calls: Arc<AtomicUsize>,
}

impl AdversarialMeshBackend {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            descriptor: core_mesh::BackendDescriptor::new(
                core_mesh::BackendId::new("malicious-backend").unwrap(),
                core_mesh::BackendKind::Other("vendor\ncontrolled".to_owned()),
                core_mesh::BackendOwnership::AttachExternal,
            ),
            calls,
        }
    }

    fn status_value(&self) -> core_mesh::BackendStatus {
        let mut status = core_mesh::BackendStatus::new(
            self.descriptor.id().clone(),
            self.descriptor.kind().clone(),
            self.descriptor.ownership(),
        );
        status.phase = core_mesh::BackendPhase::Ready;
        status.version = Some(format!("v1\r\n{}", "版".repeat(100)));
        status.attachments = vec![
            core_mesh::Attachment::Endpoint(core_mesh::EndpointAttachment {
                purpose: core_mesh::EndpointPurpose::Health,
                address: core_mesh::EndpointAddress::Url(
                    "https://example.com:8443/health/check".to_owned(),
                ),
            }),
            core_mesh::Attachment::Endpoint(core_mesh::EndpointAttachment {
                purpose: core_mesh::EndpointPurpose::Control,
                address: core_mesh::EndpointAddress::Url(
                    "https://alice:password-secret@example.com:9443/private/path\
                     ?token=query-secret#fragment-secret"
                        .replace(' ', ""),
                ),
            }),
            core_mesh::Attachment::Endpoint(core_mesh::EndpointAttachment {
                purpose: core_mesh::EndpointPurpose::Other("invalid\nurl".to_owned()),
                address: core_mesh::EndpointAddress::Url("not a url invalid-url-secret".to_owned()),
            }),
            core_mesh::Attachment::Endpoint(core_mesh::EndpointAttachment {
                purpose: core_mesh::EndpointPurpose::Management,
                address: core_mesh::EndpointAddress::Opaque("opaque-secret".to_owned()),
            }),
        ];
        status.resource_claims.push(
            core_mesh::ResourceClaim::coordinated(
                core_mesh::SystemResource::Interface {
                    name: "mesh\ninterface".to_owned(),
                },
                "coordination-secret",
            )
            .unwrap(),
        );
        status.diagnostics.push(core_mesh::Diagnostic::new(
            core_mesh::DiagnosticLevel::Error,
            "unsafe\ncode",
            "diagnostic-secret",
        ));
        status
    }

    fn record_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl core_mesh::NetworkBackend for AdversarialMeshBackend {
    fn descriptor(&self) -> core_mesh::BackendDescriptor {
        self.descriptor.clone()
    }

    async fn probe(&self) -> core_mesh::BackendResult<core_mesh::BackendObservation> {
        self.record_call();
        Ok(self.status_value())
    }

    async fn reconcile(
        &self,
        _observation: &core_mesh::BackendObservation,
    ) -> core_mesh::BackendResult<core_mesh::BackendStatus> {
        self.record_call();
        Ok(self.status_value())
    }

    async fn status(&self) -> core_mesh::BackendResult<core_mesh::BackendStatus> {
        self.record_call();
        Ok(self.status_value())
    }
}

#[async_trait]
impl core_mesh::ExternalNetworkBackend for AdversarialMeshBackend {
    async fn detach(&self) -> core_mesh::BackendResult<()> {
        self.record_call();
        Ok(())
    }
}

#[tokio::test]
async fn version_advertises_meta() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["meta"], Value::Bool(true));
    assert_eq!(v["premium"], Value::Bool(true));
}

#[tokio::test]
async fn mesh_status_is_explicit_when_supervisor_is_not_injected() {
    let app = core_api::native::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/mesh/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = body_json(resp).await;
    assert_eq!(value["code"], "mesh_supervisor_unavailable");
}

#[tokio::test]
async fn mesh_status_returns_a_redacted_snapshot_without_backend_calls() {
    let mut state = build_state();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = core_mesh::BackendRegistry::new();
    registry
        .register_external(Arc::new(AdversarialMeshBackend::new(calls.clone())))
        .expect("backend registration");
    let mesh = Arc::new(core_mesh::MeshSupervisor::with_options(
        registry,
        Vec::new(),
        core_mesh::SupervisorOptions {
            monitor_interval: Duration::ZERO,
            ..core_mesh::SupervisorOptions::default()
        },
    ));
    mesh.start().await.expect("supervisor starts");
    let calls_after_start = calls.load(Ordering::SeqCst);
    assert_eq!(calls_after_start, 2, "start must probe and reconcile once");
    state.mesh = Some(mesh.clone());

    let app = core_api::native::router(state);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mesh/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_json(resp).await;
    assert_eq!(value["running"], true);
    assert_eq!(value["supervisor_phase"], "running");
    let generation = value["generation"].clone();
    let status = &value["statuses"]["malicious-backend"];
    assert_eq!(status["kind"]["other"], "vendor controlled");
    let version = status["version"].as_str().expect("public version");
    assert!(version.len() <= 128);
    assert!(!version.chars().any(char::is_control));

    let attachments = status["attachments"].as_array().expect("attachments");
    assert_eq!(
        attachments[0]["details"]["address"]["value"],
        "https://example.com:8443/"
    );
    assert_eq!(
        attachments[1]["details"]["address"]["value"],
        "https://example.com:9443/"
    );
    for hidden in [&attachments[2], &attachments[3]] {
        assert_eq!(hidden["details"]["address"]["type"], "hidden");
        assert!(hidden["details"]["address"].get("value").is_none());
    }
    assert_eq!(status["diagnostics"][0]["code"], "mesh.backend_diagnostic");
    assert_eq!(
        status["diagnostics"][0]["message"],
        "diagnostic details are available in local process logs"
    );

    let serialized = serde_json::to_string(&value).unwrap();
    for secret in [
        "alice",
        "password-secret",
        "query-secret",
        "fragment-secret",
        "health/check",
        "private/path",
        "invalid-url-secret",
        "opaque-secret",
        "coordination-secret",
        "coordination_key",
        "diagnostic-secret",
    ] {
        assert!(
            !serialized.contains(secret),
            "mesh API leaked {secret}: {serialized}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_after_start,
        "GET must not invoke a backend"
    );

    let second = app
        .oneshot(
            Request::builder()
                .uri("/mesh/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        body_json(second).await["generation"],
        generation,
        "read-only status requests must not publish a new generation"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_after_start,
        "repeated GET must remain snapshot-only"
    );
    mesh.stop().await.expect("supervisor stops");
}

#[tokio::test]
async fn proxies_includes_global_and_direct() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/proxies")
                .body(Body::empty())
                .unwrap(),
        )
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
        .oneshot(
            Request::builder()
                .uri("/configs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["mode"], "rule");
    assert_eq!(v["log-level"], "info");
    // authentication 必须是用户名列表，不能回传 password 字段对象。
    assert!(v["authentication"].is_array());
    // PUT 修改 mode + log-level（allow-lan 热切换已禁用，见下测）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mode":"global","log-level":"debug"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // 再 GET
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/configs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["mode"], "global");
    assert_eq!(v["log-level"], "debug");
}

#[tokio::test]
async fn configs_put_rejects_allow_lan_hot_toggle() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"allow-lan":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let v = body_json(resp).await;
    assert!(
        v["message"]
            .as_str()
            .unwrap_or("")
            .contains("allow-lan cannot be changed"),
        "unexpected body: {v}"
    );
}

#[tokio::test]
async fn configs_authentication_never_returns_passwords() {
    let yaml = r#"
version: 1
profile: desktop
listen:
  local: 7890
  panel: 9090
  auth:
    - "alice:super-secret-password"
groups:
  main:
    choose: manual
nodes: []
"#;
    let plan = load_from_str(yaml).expect("plan");
    let runtime = Arc::new(Runtime::build(plan));
    let state = NativeState::for_tests(runtime, UrlTester::new(Default::default()), None);
    let app = core_api::compat::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/configs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    let auth = v["authentication"]
        .as_array()
        .expect("authentication array");
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0], "alice");
    let body = serde_json::to_string(&v).unwrap();
    assert!(
        !body.contains("super-secret-password"),
        "password must not appear in /configs body: {body}"
    );
}

#[tokio::test]
async fn rules_serialize_steps() {
    let app = core_api::compat::router(build_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/rules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    let rules = v["rules"].as_array().unwrap();
    assert!(
        !rules.is_empty(),
        "rules should not be empty (preset cn_smart)"
    );
    // 至少有一条 MATCH/兜底
    assert!(
        rules
            .iter()
            .any(|r| r["type"] == "MATCH" || r["type"] == "GEOIP")
    );
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
async fn connections_snapshot_uses_connection_manager() {
    let state = build_state();
    let runtime = state.runtime.clone();
    let guard = runtime.connections.open(ConnectionMeta {
        network: "tcp".into(),
        kind: "HTTP".into(),
        host: "example.com".into(),
        destination_ip_asn: "AS15169".into(),
        smart_target: "example.com".into(),
        chains: core_observe::string_list_from(["main", "NodeA"]),
        rule: "MATCH".into(),
        rule_payload: "main".into(),
        ..ConnectionMeta::default()
    });
    guard.record_upload(7);
    guard.record_download(11);

    let app = core_api::compat::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/connections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["uploadTotal"], 7);
    assert_eq!(v["downloadTotal"], 11);
    assert_eq!(v["connections"].as_array().unwrap().len(), 1);
    let conn = &v["connections"][0];
    assert_eq!(conn["upload"], 7);
    assert_eq!(conn["download"], 11);
    assert_eq!(conn["metadata"]["id"], conn["id"]);
    assert_eq!(conn["metadata"]["smartTarget"], "example.com");
    assert_eq!(conn["metadata"]["destinationIPASN"], "AS15169");
    assert!(conn.get("providerChains").is_some());
    assert!(conn["maxUploadRate"].as_u64().unwrap() >= 7);
    assert!(conn["maxDownloadRate"].as_u64().unwrap() >= 11);

    drop(guard);
}

#[tokio::test]
async fn logs_sse_replays_recent_history() {
    let state = build_state();
    state.runtime.logs.push("info", "boot marker");

    let app = core_api::compat::router(state);
    let resp = app
        .oneshot(Request::builder().uri("/logs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let frame = tokio::time::timeout(Duration::from_secs(1), resp.into_body().frame())
        .await
        .expect("logs SSE should yield history")
        .expect("logs SSE frame")
        .expect("logs SSE frame ok");
    let bytes = frame.into_data().expect("data frame");
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("boot marker"), "{text}");
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
    let state = NativeState::for_tests(runtime.clone(), UrlTester::new(Default::default()), None);
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

#[tokio::test]
async fn group_history_inherits_from_selected_member() {
    // Mihomo: group 的 `history` / `alive` / `extra` 应取自当前 `now` 成员的
    // urltest 状态。WutherCore 之前 `to_clash_json` 永远输出 history=[]，
    // dashboard 把空 history 当超时；这里固化"API 边界回填"的契约。
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
    let urltest = UrlTester::new(Default::default());
    let url = urltest.current_config().default_url;
    urltest.ensure_stats("NodeB", &url).record(123, true);
    let state = NativeState::for_tests(runtime.clone(), urltest.clone(), None);
    let app = core_api::compat::router(state);
    let _ = app
        .clone()
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
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/proxies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    let picker = &v["proxies"]["picker"];
    assert_eq!(picker["now"], "NodeB");
    let history = picker["history"]
        .as_array()
        .expect("group history must be an array");
    assert!(
        !history.is_empty(),
        "group history must inherit from current member NodeB; got {picker}",
    );
    assert_eq!(history[0]["delay"], 123);
    assert_eq!(picker["alive"], true);
    let extra = picker["extra"]
        .as_object()
        .expect("extra must be an object");
    assert!(
        extra.contains_key(&url),
        "extra should expose default_url entry; got keys: {:?}",
        extra.keys().collect::<Vec<_>>()
    );
}
