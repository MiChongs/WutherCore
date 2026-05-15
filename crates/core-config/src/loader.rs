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
}
