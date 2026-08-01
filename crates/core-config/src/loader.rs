//! 加载 + 校验 + 默认值合并 + 编译为 [`RuntimePlan`]。

use std::path::Path;

use crate::{
    error::{ConfigError, ConfigErrorKind, ConfigResult},
    model::*,
    profile::apply_defaults,
    runtime_plan::RuntimePlan,
};

/// 从字符串加载并完整编译。
pub fn load_from_str(text: &str) -> ConfigResult<RuntimePlan> {
    let mut cfg: UserConfig = serde_yaml::from_str(text)?;
    if cfg.version != 1 {
        return Err(
            ConfigError::new(ConfigErrorKind::UnsupportedVersion(cfg.version))
                .hint("当前版本为 1；请保持 version: 1"),
        );
    }
    apply_defaults(&mut cfg);
    crate::runtime_plan::compile(cfg)
}

/// 读取文件后转交 [`load_from_str`]。
pub fn load_from_path<P: AsRef<Path>>(path: P) -> ConfigResult<RuntimePlan> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::new(ConfigErrorKind::Io(e))
            .at(path.display().to_string())
            .hint("请确认文件存在且具有读取权限")
    })?;
    let mut plan = load_from_str(&text)?;
    if plan.database.enabled && plan.database.path.is_relative() {
        let base = match plan.database.relative_to {
            DatabasePathBase::Config => {
                let config_path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map_err(|error| {
                            ConfigError::new(ConfigErrorKind::Io(error))
                                .at(path.display().to_string())
                                .hint("无法读取当前工作目录")
                        })?
                        .join(path)
                };
                config_path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
            }
            DatabasePathBase::Cwd => std::env::current_dir().map_err(|error| {
                ConfigError::new(ConfigErrorKind::Io(error))
                    .at("database.relative-to")
                    .hint("无法读取当前工作目录")
            })?,
        };
        plan.database.path = base.join(&plan.database.path);
    }
    if plan.database.enabled && plan.database.path.is_dir() {
        return Err(ConfigError::invalid(format!(
            "database.path 必须是文件，当前指向目录: {}",
            plan.database.path.display()
        ))
        .at("database.path")
        .hint("请在路径末尾填写数据库文件名"));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::{ChooseStrategy, LogFormat, LogLevel};

    #[test]
    fn minimal_yaml_loads() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/sub"
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK-01"
  - "trojan://pwd@example.com:443?sni=example.com#US-01"
"#;
        let plan = load_from_str(yaml).unwrap();
        assert!(plan.groups.contains_key("main"));
        assert_eq!(plan.nodes.len(), 2);
        assert_eq!(plan.route.preset, "cn_smart");
    }

    #[test]
    fn feed_accepts_anytls_client_id_override() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  airport:
    url: "https://example.com/sub"
    override:
      clientId: "sing-anytls/0.0.11"
"#;
        let plan = load_from_str(yaml).unwrap();
        assert_eq!(
            plan.feeds["airport"].overrides.client_id.as_deref(),
            Some("sing-anytls/0.0.11")
        );

        let mut nodes = vec![
            crate::node_uri::ParsedNode::new(
                "AnyTLS",
                crate::node_uri::NodeProtocol::AnyTls,
                "proxy.example.com",
                443,
            ),
            crate::node_uri::ParsedNode::new(
                "Trojan",
                crate::node_uri::NodeProtocol::Trojan,
                "proxy.example.com",
                443,
            ),
        ];
        nodes[0]
            .params
            .insert("clientId".into(), "upstream-client/1.0".into());
        plan.feeds["airport"].apply_overrides(&mut nodes);
        assert_eq!(
            nodes[0].params.get("clientId").map(String::as_str),
            Some("sing-anytls/0.0.11")
        );
        assert!(!nodes[1].params.contains_key("clientId"));
    }

    #[test]
    fn feed_rejects_invalid_anytls_client_id_override() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  airport:
    url: "https://example.com/sub"
    override:
      clientId: ""
"#;
        let error = load_from_str(yaml).unwrap_err().to_string();
        assert!(error.contains("feeds.airport.override.clientId"), "{error}");
        assert!(error.contains("不能为空"), "{error}");
    }

    #[test]
    fn feed_accepts_native_inline_nodes_alias() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  local:
    nodes:
      - {name: DIRECT, type: direct}
      - {name: BLOCK, type: reject}
"#;
        let plan = load_from_str(yaml).unwrap();
        assert_eq!(plan.feeds["local"].payload.len(), 2);
        assert!(plan.feeds["local"].url.is_empty());
    }

    #[test]
    fn structured_node_accepts_type_as_protocol_alias() {
        let yaml = r#"
version: 1
profile: desktop
nodes:
  - name: local
    type: socks5
    address: 127.0.0.1:1080
"#;
        let plan = load_from_str(yaml).unwrap();
        assert_eq!(plan.nodes.len(), 1);
        assert_eq!(
            plan.nodes[0].protocol,
            crate::node_uri::NodeProtocol::Socks5
        );
    }

    #[test]
    fn unknown_group_use_yields_friendly_error() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/sub"
groups:
  main:
    choose: smart
    use: ["airport2"]
"#;
        let err = load_from_str(yaml).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("引用未定义"));
        assert!(s.contains("airport2"));
    }

    #[test]
    fn resolver_rules_and_default_servers_are_preserved() {
        let yaml = r#"
version: 1
profile: desktop
resolver:
  mode: smart
  rules:
    - "suffix:cn -> direct"
    - { match: "any", proxy: default, ttl: 60 }
"#;
        let plan = load_from_str(yaml).unwrap();

        assert!(plan.resolver.servers.contains_key("ali"));
        assert!(plan.resolver.servers.contains_key("cloudflare"));
        assert_eq!(plan.resolver.nameserver, vec!["ali"]);
        assert_eq!(plan.resolver.fallback, vec!["cloudflare"]);
        assert_eq!(plan.resolver.rules.len(), 2);
    }

    #[test]
    fn resolver_mihomo_dns_fields_are_preserved() {
        let yaml = r#"
version: 1
profile: desktop
resolver:
  mode: smart
  nameserver: [ali]
  fallback: [cloudflare]
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr: ["240.0.0.0/4"]
    domain: ["+.google.com"]
    geosite: [gfw]
  default-nameserver: ["223.5.5.5"]
  proxy-server-nameserver: [cloudflare]
  proxy-server-nameserver-policy:
    "+.node.example": [cloudflare]
  nameserver-policy:
    "+.baidu.com": [ali]
"#;
        let plan = load_from_str(yaml).unwrap();

        assert_eq!(plan.resolver.nameserver, vec!["ali"]);
        assert_eq!(plan.resolver.fallback, vec!["cloudflare"]);
        assert_eq!(plan.resolver.fallback_filter.geoip_code, "CN");
        assert_eq!(plan.resolver.fallback_filter.ipcidr, vec!["240.0.0.0/4"]);
        assert_eq!(plan.resolver.default_nameserver, vec!["223.5.5.5"]);
        assert_eq!(plan.resolver.proxy_server_nameserver, vec!["cloudflare"]);
        assert_eq!(plan.resolver.nameserver_policy.len(), 1);
        assert_eq!(plan.resolver.proxy_server_nameserver_policy.len(), 1);
    }

    #[test]
    fn resolver_friendly_and_advanced_dns_groups_are_preserved() {
        let yaml = r#"
version: 1
profile: desktop
resolver:
  fake: off
  servers:
    local: "udp://223.5.5.5"
    cloudflare:
      endpoint: "https://1.1.1.1/dns-query"
      exits: [node-a, node-b]
      strategy: adaptive
      timeout: 3s
      max-parallel: 1
  groups:
    cn: [local]
    public:
      members: [cloudflare, cn]
      strategy: parallel
      timeout: 4s
      max-parallel: 2
  nameserver: [public]
  fallback: []
  rules:
    - { suffix: example.com, route: public, strategy: round-robin }
"#;
        let plan = load_from_str(yaml).unwrap();

        assert_eq!(plan.resolver.groups.len(), 2);
        assert_eq!(
            plan.resolver.servers["cloudflare"].endpoint(),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            plan.resolver.servers["cloudflare"].exits(),
            ["node-a", "node-b"]
        );
        assert_eq!(
            plan.resolver.servers["cloudflare"].strategy(),
            ResolverStrategy::Adaptive
        );
        assert_eq!(
            plan.resolver.groups["public"].strategy(),
            ResolverStrategy::Parallel
        );
        assert_eq!(plan.resolver.groups["public"].max_parallel(), 2);
    }

    #[test]
    fn resolver_rejects_multiple_endpoints_in_one_server() {
        let yaml = r#"
version: 1
resolver:
  servers:
    cloudflare:
      endpoints: [https://1.1.1.1/dns-query, tls://1.1.1.1]
"#;
        let error = load_from_str(yaml).unwrap_err().to_string();
        assert!(error.contains("endpoints"), "{error}");
    }

    #[test]
    fn resolver_rejects_removed_mainland_overseas_fields() {
        let yaml = r#"
version: 1
profile: desktop
resolver:
  mainland: ali
  overseas: cloudflare
"#;
        let err = load_from_str(yaml).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("mainland") || s.contains("overseas"), "{s}");
    }

    #[test]
    fn log_config_is_preserved_in_runtime_plan() {
        let yaml = r#"
version: 1
profile: desktop
log:
  on: true
  level: debug
  filter: "info,capture::traffic=debug"
  stdout: false
  format: json
  file:
    on: true
    path: "data/logs/wuthercore-test.log"
"#;
        let plan = load_from_str(yaml).unwrap();
        let log = plan.log.expect("explicit log config must be preserved");

        assert!(log.on);
        assert_eq!(log.level, LogLevel::Debug);
        assert_eq!(log.filter.as_deref(), Some("info,capture::traffic=debug"));
        assert!(!log.stdout);
        assert_eq!(log.format, LogFormat::Json);
        assert!(log.file.on);
        assert_eq!(log.file.path, "data/logs/wuthercore-test.log");
    }

    #[test]
    fn missing_log_config_keeps_observe_defaults() {
        let yaml = r#"
version: 1
profile: desktop
"#;
        let plan = load_from_str(yaml).unwrap();

        assert!(plan.log.is_none());
    }

    #[test]
    fn singbox_rule_set_variants_normalize_into_route_sets() {
        let yaml = r#"
version: 1
profile: desktop
route:
  rule_set:
    - type: inline
      tag: inline-sites
      rules:
        - domain_suffix: example.com
        - type: logical
          mode: and
          rules:
            - domain: secure.example
            - port: 443
    - type: local
      tag: [local-a, local-b]
      format: source
      path: "./rules/{tag}.json"
    - type: remote
      tag: remote-binary
      format: binary
      url: "https://rules.example/remote.srs"
      update_interval: 6h
      http_client:
        detour: direct
"#;
        let plan = load_from_str(yaml).unwrap();
        assert_eq!(plan.route.sets.len(), 4);

        let inline = &plan.route.sets["inline-sites"];
        assert_eq!(inline.r#type, "mixed");
        assert_eq!(inline.format.as_deref(), Some("json"));
        assert_eq!(inline.payload.len(), 1);
        let inline_doc: serde_json::Value =
            serde_json::from_str(&inline.payload[0]).expect("normalized inline JSON");
        assert_eq!(inline_doc["version"], 5);
        assert_eq!(inline_doc["rules"].as_array().unwrap().len(), 2);

        assert_eq!(
            plan.route.sets["local-a"].path.as_deref(),
            Some("./rules/local-a.json")
        );
        assert_eq!(plan.route.sets["local-b"].format.as_deref(), Some("json"));
        let remote = &plan.route.sets["remote-binary"];
        assert_eq!(remote.format.as_deref(), Some("srs"));
        assert_eq!(remote.every, Duration::from_secs(6 * 3600));
        assert_eq!(remote.via, "direct");
    }

    #[test]
    fn mihomo_rule_providers_normalize_all_source_types() {
        let yaml = r#"
version: 1
profile: desktop
rule-providers:
  remote-domain:
    type: http
    behavior: domain
    format: mrs
    url: "https://rules.example/domain.mrs"
    path: "./cache/domain.mrs"
    interval: 600
    proxy: DIRECT
  local-ip:
    type: file
    behavior: ipcidr
    format: text
    path: "./rules/ip.list"
    interval: 2h
  inline-classical:
    type: inline
    behavior: classical
    format: yaml
    payload:
      - "DOMAIN-SUFFIX,example.org"
"#;
        let plan = load_from_str(yaml).unwrap();
        let remote = &plan.route.sets["remote-domain"];
        assert_eq!(
            remote.url.as_deref(),
            Some("https://rules.example/domain.mrs")
        );
        assert_eq!(remote.path.as_deref(), Some("./cache/domain.mrs"));
        assert_eq!(remote.r#type, "domain");
        assert_eq!(remote.format.as_deref(), Some("mrs"));
        assert_eq!(remote.every, Duration::from_secs(600));

        let local = &plan.route.sets["local-ip"];
        assert_eq!(local.url, None);
        assert_eq!(local.path.as_deref(), Some("./rules/ip.list"));
        assert_eq!(local.r#type, "ipcidr");
        assert_eq!(local.every, Duration::from_secs(2 * 3600));

        let inline = &plan.route.sets["inline-classical"];
        assert_eq!(inline.payload, vec!["DOMAIN-SUFFIX,example.org"]);
        assert_eq!(inline.r#type, "classical");
        assert_eq!(inline.format.as_deref(), Some("yaml"));
    }

    #[test]
    fn native_route_sets_remain_compatible_and_are_canonicalized() {
        let yaml = r#"
version: 1
profile: desktop
route:
  sets:
    legacy:
      type: IP
      format: yml
      url: "https://rules.example/ip.yaml"
      path: "./cache/ip.yaml"
      every: 1h
      via: legacy-group
"#;
        let plan = load_from_str(yaml).unwrap();
        let spec = &plan.route.sets["legacy"];
        assert_eq!(spec.r#type, "ipcidr");
        assert_eq!(spec.format.as_deref(), Some("yaml"));
        assert_eq!(spec.url.as_deref(), Some("https://rules.example/ip.yaml"));
        assert_eq!(spec.path.as_deref(), Some("./cache/ip.yaml"));
        assert_eq!(spec.every, Duration::from_secs(3600));
        assert_eq!(spec.via, "legacy-group");
    }

    #[test]
    fn mrs_rejects_classical_behavior_during_config_compile() {
        let yaml = r#"
version: 1
rule-providers:
  invalid:
    type: http
    behavior: classical
    format: mrs
    url: "https://rules.example/classical.mrs"
"#;
        let error = load_from_str(yaml).unwrap_err().to_string();
        assert!(error.contains("MRS"), "{error}");
        assert!(error.contains("classical"), "{error}");
        assert!(error.contains("rule-providers.invalid"), "{error}");
    }

    #[test]
    fn unsupported_provider_download_outbound_is_not_silently_ignored() {
        let mihomo = r#"
version: 1
rule-providers:
  proxied:
    type: http
    behavior: domain
    url: "https://rules.example/domain.yaml"
    proxy: select
"#;
        let error = load_from_str(mihomo).unwrap_err().to_string();
        assert!(error.contains("core-fetch"), "{error}");
        assert!(error.contains("proxy"), "{error}");

        let singbox = r#"
version: 1
route:
  rule_set:
    - type: remote
      tag: proxied
      format: source
      url: "https://rules.example/domain.json"
      download_detour: select
"#;
        let error = load_from_str(singbox).unwrap_err().to_string();
        assert!(error.contains("core-fetch"), "{error}");
        assert!(error.contains("download_detour"), "{error}");
    }

    #[test]
    fn unsupported_provider_fields_and_invalid_combinations_are_errors() {
        let unsupported_field = r#"
version: 1
rule-providers:
  custom-header:
    type: http
    behavior: domain
    url: "https://rules.example/domain.yaml"
    header:
      User-Agent: [mihomo]
"#;
        let error = load_from_str(unsupported_field).unwrap_err().to_string();
        assert!(error.contains("header"), "{error}");

        let invalid_http_client = r#"
version: 1
route:
  rule_set:
    - type: remote
      tag: custom-client
      format: source
      url: "https://rules.example/domain.json"
      http_client:
        headers:
          User-Agent: sing-box
"#;
        let error = load_from_str(invalid_http_client).unwrap_err().to_string();
        assert!(error.contains("http_client.headers"), "{error}");

        let named_http_client = r#"
version: 1
route:
  rule_set:
    - type: remote
      tag: named-client
      format: source
      url: "https://rules.example/domain.json"
      http_client: direct
"#;
        let error = load_from_str(named_http_client).unwrap_err().to_string();
        assert!(error.contains("共享 HTTP client"), "{error}");
        assert!(error.contains("http_clients registry"), "{error}");

        let nonstandard_nested_detour = r#"
version: 1
route:
  rule_set:
    - type: remote
      tag: invalid-nested-client
      format: source
      url: "https://rules.example/domain.json"
      http_client:
        download_detour: direct
"#;
        let error = load_from_str(nonstandard_nested_detour)
            .unwrap_err()
            .to_string();
        assert!(error.contains("http_client.download_detour"), "{error}");

        let invalid_local = r#"
version: 1
route:
  rule_set:
    - type: local
      tag: invalid-local
      format: source
      path: "./rules/local.json"
      update_interval: 1h
"#;
        let error = load_from_str(invalid_local).unwrap_err().to_string();
        assert!(error.contains("update_interval"), "{error}");
    }

    #[test]
    fn provider_names_cannot_overwrite_native_or_compatible_sets() {
        let yaml = r#"
version: 1
rule-providers:
  duplicate:
    type: inline
    behavior: domain
    payload: [example.org]
route:
  sets:
    duplicate:
      type: domain
      payload: [example.com]
"#;
        let error = load_from_str(yaml).unwrap_err().to_string();
        assert!(error.contains("duplicate"), "{error}");
        assert!(error.contains("重复"), "{error}");
    }

    #[test]
    fn advanced_dns_example_loads() {
        load_from_str(include_str!("../../../examples/dns-advanced.yaml")).unwrap();
    }

    #[test]
    fn android_root_examples_deserialize_with_explicit_data_planes() {
        let cases = [
            (
                include_str!("../../../examples/advanced/android-root-tun.yaml"),
                CaptureMethod::VirtualNic,
            ),
            (
                include_str!("../../../examples/advanced/android-root-tproxy.yaml"),
                CaptureMethod::Tproxy,
            ),
            (
                include_str!("../../../examples/advanced/android-root-redirect.yaml"),
                CaptureMethod::Redirect,
            ),
        ];

        for (yaml, expected_method) in cases {
            let config: UserConfig = serde_yaml::from_str(yaml).unwrap();
            let capture = config
                .capture
                .expect("Android root example enables capture");
            assert!(capture.on);
            assert_eq!(capture.method, expected_method);
            assert!(!capture.tun.auto_redirect);
        }
    }

    #[test]
    fn official_multi_platform_example_compiles_as_a_complete_runtime_plan() {
        let plan = load_from_str(include_str!(
            "../../../examples/official/multi-platform.yaml"
        ))
        .unwrap();

        assert_eq!(plan.name, "official-multi-platform");
        assert_eq!(plan.feeds.len(), 1);
        assert_eq!(plan.groups.len(), 23);
        assert_eq!(plan.route.sets.len(), 24);
        assert!(plan.capture.on);
        assert_eq!(plan.capture.method, CaptureMethod::VirtualNic);
        assert_eq!(plan.capture.tag, "系统接管");
        assert_eq!(
            plan.listen.mixed.as_ref().map(|mixed| mixed.tag.as_str()),
            Some("本地代理")
        );
        assert_eq!(plan.inbounds.len(), 2);
        assert!(!plan.capture.tun.auto_redirect);
        assert!(plan.groups.contains_key("智能节点"));
        assert!(plan.groups.contains_key("负载均衡节点"));
        assert!(plan.groups.contains_key("香港节点"));
        assert!(plan.groups.contains_key("美国节点"));
        assert!(plan.groups.contains_key("澳大利亚节点"));
        assert!(plan.groups.values().all(|group| {
            group
                .icon
                .starts_with("https://raw.githubusercontent.com/luestr/IconResource/")
        }));
        assert!(
            plan.groups["人工智能"]
                .icon
                .ends_with("/App_icon/120px/ChatGPT.png")
        );
        assert_eq!(plan.groups["节点选择"].choose, ChooseStrategy::Manual);
        assert!(
            plan.groups["节点选择"]
                .members
                .iter()
                .all(|member| plan.groups.contains_key(member))
        );
        assert!(
            plan.groups["人工智能"]
                .members
                .iter()
                .all(|member| plan.groups.contains_key(member))
        );
        assert!(
            plan.groups["香港节点"]
                .members
                .contains(&"feed:primary".to_string())
        );
        assert_eq!(plan.groups["香港节点"].empty_fallback, "DIRECT-FALLBACK");
        assert!(plan.route.sets.contains_key("ads"));
        assert!(plan.route.sets.contains_key("geoip-cn"));
        assert!(plan.route.sets.contains_key("global"));
    }

    #[test]
    fn database_options_are_compiled() {
        let plan = load_from_str(
            r#"
version: 1
database:
  enabled: true
  path: state/custom.sqlite
  relative-to: cwd
  busy-timeout: 9s
  max-write-attempts: 24
  multiprocess-wal: off
  experimental-vacuum: false
"#,
        )
        .unwrap();

        assert_eq!(
            plan.database.path,
            std::path::PathBuf::from("state/custom.sqlite")
        );
        assert_eq!(plan.database.relative_to, DatabasePathBase::Cwd);
        assert_eq!(plan.database.busy_timeout, Duration::from_secs(9));
        assert_eq!(plan.database.max_write_attempts, 24);
        assert_eq!(plan.database.multiprocess_wal, MultiprocessWalMode::Off);
        assert!(!plan.database.experimental_vacuum);
    }

    #[test]
    fn database_path_can_be_relative_to_config_file() {
        let root =
            std::env::temp_dir().join(format!("wuther-config-database-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let config_path = root.join("config.yaml");
        std::fs::write(
            &config_path,
            "version: 1\ndatabase:\n  path: state/custom.db\n  relative-to: config\n",
        )
        .unwrap();

        let plan = load_from_path(&config_path).unwrap();
        assert_eq!(plan.database.path, root.join("state/custom.db"));

        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn enabled_database_rejects_unsafe_empty_limits() {
        for yaml in [
            "version: 1\ndatabase:\n  path: ''\n",
            "version: 1\ndatabase:\n  busy-timeout: 0s\n",
            "version: 1\ndatabase:\n  max-write-attempts: 0\n",
        ] {
            let error = load_from_str(yaml).unwrap_err().to_string();
            assert!(error.contains("database."), "{error}");
        }
    }

    #[test]
    fn canonical_inbounds_compile_mixed_and_flat_tun_options() {
        let plan = load_from_str(
            r#"
version: 1
inbounds:
  - type: mixed
    tag: local-proxy
    listen: 127.0.0.1
    listen_port: 7890
    users:
      username: alice
      password: secret
  - type: tun
    tag: system-tun
    interface_name: rpktun0
    address: 198.18.0.1/15
    stack: mixed
    mtu: 1500
    dns_mode: hijack
    auto_route: true
    strict_route: true
    route_exclude_address: 192.168.0.0/16
"#,
        )
        .unwrap();

        assert_eq!(plan.inbounds.len(), 2);
        let mixed = plan.listen.mixed.expect("mixed inbound is compiled");
        assert_eq!(mixed.tag, "local-proxy");
        assert_eq!(mixed.socket_addr().unwrap().to_string(), "127.0.0.1:7890");
        assert_eq!(plan.listen.auth.len(), 1);
        assert_eq!(plan.listen.auth[0].user, "alice");
        assert_eq!(plan.listen.auth[0].pass, "secret");
        assert!(plan.capture.on);
        assert_eq!(plan.capture.tag, "system-tun");
        assert_eq!(plan.capture.method, CaptureMethod::VirtualNic);
        assert_eq!(plan.capture.tun.interface_name.as_deref(), Some("rpktun0"));
        assert_eq!(plan.capture.tun.address, ["198.18.0.1/15"]);
        assert_eq!(plan.capture.tun.route_exclude_address, ["192.168.0.0/16"]);
    }

    #[test]
    fn canonical_inbounds_reject_duplicate_tags_and_legacy_conflicts() {
        let duplicate = load_from_str(
            r#"
version: 1
inbounds:
  - type: mixed
    tag: duplicate
    listen_port: 7890
  - type: tun
    tag: duplicate
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("tag `duplicate` 重复"), "{duplicate}");

        let legacy = load_from_str(
            r#"
version: 1
listen:
  local: 7890
inbounds:
  - type: mixed
    tag: local-proxy
    listen_port: 7891
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(legacy.contains("listen.local"), "{legacy}");
    }

    #[test]
    fn canonical_inbounds_reject_multiple_transparent_data_planes() {
        let error = load_from_str(
            r#"
version: 1
inbounds:
  - type: tun
    tag: tun-in
  - type: tproxy
    tag: tproxy-in
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("只能启用一个 tun、tproxy、redirect 或 ebpf inbound"),
            "{error}"
        );
    }

    #[test]
    fn canonical_inbounds_serialize_list_options_as_arrays() {
        let config: UserConfig = serde_yaml::from_str(
            r#"
version: 1
inbounds:
  - type: tun
    tag: tun-in
    address: 198.18.0.1/15
    route_address:
      - 0.0.0.0/1
      - 128.0.0.0/1
"#,
        )
        .unwrap();
        let serialized = serde_yaml::to_string(&config).unwrap();
        let reparsed: UserConfig = serde_yaml::from_str(&serialized).unwrap();

        let Inbound::Tun(options) = &reparsed.inbounds[0] else {
            panic!("expected tun inbound");
        };
        assert_eq!(options.tun.address, ["198.18.0.1/15"]);
        assert_eq!(options.tun.route_address, ["0.0.0.0/1", "128.0.0.0/1"]);
        let value: serde_yaml::Value = serde_yaml::from_str(&serialized).unwrap();
        assert!(
            value["inbounds"][0]["address"]
                .as_sequence()
                .is_some_and(|items| items.len() == 1)
        );
    }
}
