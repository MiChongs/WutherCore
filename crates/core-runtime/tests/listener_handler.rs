use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use core_route::RouteDecision;
use core_runtime::{InboundMetadata, ListenerHandler, Runtime};

fn load_plan(yaml: &str) -> core_config::runtime_plan::RuntimePlan {
    core_config::loader::load_from_str(yaml).unwrap()
}

#[test]
fn inbound_metadata_keeps_fake_destination_out_of_route_context() {
    let source: SocketAddr = "10.0.0.2:50000".parse().unwrap();
    let inbound: SocketAddr = "127.0.0.1:7890".parse().unwrap();
    let fake_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 8));
    let metadata = InboundMetadata::tcp("tun", "Tun", source, inbound, "api.openai.com", 443)
        .with_destination_ip(Some(fake_ip))
        .with_route_ip(None)
        .with_dns_mode("fake-ip");

    let ctx = metadata.flow_context();

    assert_eq!(ctx.host, "api.openai.com");
    assert_eq!(ctx.ip, None);
    assert_eq!(metadata.destination_ip, Some(fake_ip));
    assert_eq!(metadata.dns_mode, "fake-ip");
}

#[test]
fn listener_handler_routes_ruleset_metadata_before_preset_fallback() {
    let idx = core_ruleset::RulesetIndex::new();
    idx.insert(Arc::new(core_ruleset::RulesetMatcher::compile_domains(
        "openai",
        vec!["+.openai.com".to_string()],
    )));
    let plan = load_plan(
        r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#node-a"
groups:
  main:
    choose: manual
    use: [nodes]
  ai:
    choose: manual
    use: [nodes]
route:
  preset: cn_smart
  final: main
  steps:
    - "set:openai -> ai"
"#,
    );
    let runtime = Arc::new(Runtime::build_with(plan, None, Some(idx)));
    let handler = ListenerHandler::new(runtime);
    let metadata = InboundMetadata::tcp(
        "mixed",
        "Socks5",
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        "127.0.0.1:7890".parse::<SocketAddr>().unwrap(),
        "api.openai.com",
        443,
    );

    let pick = handler.route(&metadata);

    assert!(matches!(pick.decision, RouteDecision::Group(ref group) if group == "ai"));
    assert_eq!(pick.rule, "RULE-SET");
    assert_eq!(pick.rule_payload, "set:openai -> ai");
}

#[tokio::test]
async fn listener_handler_rejects_tracked_tcp_loopback_before_dial() {
    let plan = load_plan(
        r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:9#node-a"
groups:
  main:
    choose: manual
    use: [nodes]
route:
  final: main
"#,
    );
    let runtime = Arc::new(Runtime::build(plan));
    let handler = ListenerHandler::new(runtime);
    let source: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let _guard = core_outbound::register_tcp(source);
    let metadata = InboundMetadata::tcp(
        "tun",
        "Tun",
        source,
        "127.0.0.1:7890".parse().unwrap(),
        "example.com",
        443,
    );

    let err = match handler.prepare_tcp(metadata).await {
        Ok(_) => panic!("tracked tcp loopback source was accepted"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("loopback self-capture"));
}

#[tokio::test]
async fn listener_handler_rejects_tracked_udp_loopback_before_dial() {
    let plan = load_plan(
        r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:9#node-a"
groups:
  main:
    choose: manual
    use: [nodes]
route:
  final: main
"#,
    );
    let runtime = Arc::new(Runtime::build(plan));
    let handler = ListenerHandler::new(runtime);
    let _guard = core_outbound::register_udp("0.0.0.0:42001".parse().unwrap());
    let metadata = InboundMetadata::udp(
        "tun",
        "Tun",
        "127.0.0.1:42001".parse().unwrap(),
        None,
        "example.com",
        443,
    );

    let err = match handler.prepare_udp(metadata).await {
        Ok(_) => panic!("tracked udp loopback source was accepted"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(err.to_string().contains("loopback self-capture"));
}

#[tokio::test]
async fn inner_connection_bypasses_loopback_check() {
    let plan = load_plan(
        r#"
version: 1
profile: desktop
listen:
  panel: false
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:9#node-a"
groups:
  main:
    choose: manual
    use: [nodes]
route:
  final: main
"#,
    );
    let runtime = Arc::new(Runtime::build(plan));
    let handler = ListenerHandler::new(runtime);
    let source: SocketAddr = "127.0.0.1:41002".parse().unwrap();
    let _guard = core_outbound::register_tcp(source);

    // 没有 is_inner → 应被拒绝
    let metadata_normal = InboundMetadata::tcp(
        "tun",
        "Tun",
        source,
        "127.0.0.1:7890".parse().unwrap(),
        "example.com",
        443,
    );
    assert!(handler.prepare_tcp(metadata_normal).await.is_err());

    // 标记 is_inner → 跳过 loopback（dial 可能因无真实出站而失败但不是 loopback 错误）
    let metadata_inner = InboundMetadata::tcp(
        "tun",
        "Tun",
        source,
        "127.0.0.1:7890".parse().unwrap(),
        "example.com",
        443,
    )
    .with_inner();
    match handler.prepare_tcp(metadata_inner).await {
        Err(e) => {
            assert!(
                !e.to_string().contains("loopback self-capture"),
                "inner connection should bypass loopback check: {e}"
            );
        }
        Ok(_) => {}
    }
}
