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
    let text = std::fs::read_to_string(&path).map_err(|e| {
        ConfigError::new(ConfigErrorKind::Io(e))
            .at(path.as_ref().display().to_string())
            .hint("请确认文件存在且具有读取权限")
    })?;
    load_from_str(&text)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::{LogFormat, LogLevel};

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
}
