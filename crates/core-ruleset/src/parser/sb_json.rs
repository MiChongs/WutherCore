//! sing-box source rule-set JSON → 语义保持的共享 IR。
//!
//! 官方 default rule 的匹配语义不是把所有字段铺平为 OR，而是：
//! * destination domain/IP 字段组内 OR；
//! * destination port / source port 各自组内 OR；
//! * 各字段组之间 AND；
//! * logical rule 保留嵌套 AND / OR 与 invert。

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::RegexSet;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    ir::{PortRange, RulesetExpr, RulesetPredicate, RulesetProgram},
    parser::ParseError,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    version: Option<u64>,
    rules: Option<Vec<RawRule>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Many(items) if items.is_empty())
    }

    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(item) => vec![item],
            Self::Many(items) => items,
        }
    }
}

/// 同时声明当前官方 headless-rule 字段与本提交可求值字段。
///
/// `deny_unknown_fields` 负责拒绝真正未知的拼写；已知但当前上下文无法求值的字段
/// 保留为 `Value`，随后返回明确的 `UnsupportedField`。
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawRule {
    #[serde(rename = "type")]
    r#type: Option<String>,
    mode: Option<String>,
    rules: Option<Vec<RawRule>>,
    invert: bool,

    domain: OneOrMany<String>,
    domain_suffix: OneOrMany<String>,
    domain_keyword: OneOrMany<String>,
    domain_regex: OneOrMany<String>,
    ip_cidr: OneOrMany<String>,
    source_ip_cidr: OneOrMany<String>,
    port: OneOrMany<u16>,
    port_range: OneOrMany<String>,
    source_port: OneOrMany<u16>,
    source_port_range: OneOrMany<String>,
    process_name: OneOrMany<String>,
    network: OneOrMany<String>,

    query_type: Option<Value>,
    process_path: Option<Value>,
    process_path_regex: Option<Value>,
    package_name: Option<Value>,
    package_name_regex: Option<Value>,
    network_type: Option<Value>,
    network_is_expensive: Option<Value>,
    network_is_constrained: Option<Value>,
    network_interface_address: Option<Value>,
    default_interface_address: Option<Value>,
    wifi_ssid: Option<Value>,
    wifi_bssid: Option<Value>,
    adguard_domain: Option<Value>,
}

impl RawRule {
    fn unsupported_field(&self) -> Option<&'static str> {
        [
            ("query_type", self.query_type.is_some()),
            ("process_path", self.process_path.is_some()),
            ("process_path_regex", self.process_path_regex.is_some()),
            ("package_name", self.package_name.is_some()),
            ("package_name_regex", self.package_name_regex.is_some()),
            ("network_type", self.network_type.is_some()),
            ("network_is_expensive", self.network_is_expensive.is_some()),
            (
                "network_is_constrained",
                self.network_is_constrained.is_some(),
            ),
            (
                "network_interface_address",
                self.network_interface_address.is_some(),
            ),
            (
                "default_interface_address",
                self.default_interface_address.is_some(),
            ),
            ("wifi_ssid", self.wifi_ssid.is_some()),
            ("wifi_bssid", self.wifi_bssid.is_some()),
            ("adguard_domain", self.adguard_domain.is_some()),
        ]
        .into_iter()
        .find_map(|(field, present)| present.then_some(field))
    }

    fn has_default_fields(&self) -> bool {
        !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.ip_cidr.is_empty()
            || !self.source_ip_cidr.is_empty()
            || !self.port.is_empty()
            || !self.port_range.is_empty()
            || !self.source_port.is_empty()
            || !self.source_port_range.is_empty()
            || !self.process_name.is_empty()
            || !self.network.is_empty()
    }
}

pub fn parse(body: &[u8]) -> Result<RulesetProgram, ParseError> {
    let doc: Doc = serde_json::from_slice(body).map_err(|e| ParseError::Json(e.to_string()))?;
    let version = doc.version.ok_or(ParseError::MissingVersion)?;
    if !(1..=5).contains(&version) {
        return Err(ParseError::UnsupportedVersion(version));
    }
    let rules = doc
        .rules
        .ok_or_else(|| ParseError::InvalidRule("顶层缺少必填 rules".into()))?;
    let rule_count = rules.len();
    let root = RulesetExpr::Any(
        rules
            .into_iter()
            .map(compile_rule)
            .collect::<Result<Vec<_>, _>>()?,
    );
    Ok(RulesetProgram::new(version as u8, rule_count, root))
}

fn compile_rule(rule: RawRule) -> Result<RulesetExpr, ParseError> {
    if let Some(field) = rule.unsupported_field() {
        return Err(ParseError::UnsupportedField(field));
    }
    match rule.r#type.as_deref() {
        Some("logical") => compile_logical(rule),
        None | Some("") | Some("default") => compile_default(rule),
        Some(other) => Err(ParseError::InvalidRule(format!(
            "未知 type `{other}`；仅允许省略/空字符串/default 或 logical"
        ))),
    }
}

fn compile_logical(rule: RawRule) -> Result<RulesetExpr, ParseError> {
    if rule.has_default_fields() {
        return Err(ParseError::InvalidRule(
            "logical rule 不能同时包含 default predicate 字段".into(),
        ));
    }
    let mode = rule
        .mode
        .as_deref()
        .ok_or_else(|| ParseError::InvalidRule("logical rule 缺少必填 mode".into()))?;
    let rules = rule
        .rules
        .ok_or_else(|| ParseError::InvalidRule("logical rule 缺少必填 rules".into()))?;
    if rules.is_empty() {
        return Err(ParseError::InvalidRule(
            "logical rule 的 rules 不能为空".into(),
        ));
    }
    let children = rules
        .into_iter()
        .map(compile_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let expression = match mode {
        "and" => RulesetExpr::All(children),
        "or" => RulesetExpr::Any(children),
        other => {
            return Err(ParseError::InvalidRule(format!(
                "logical mode `{other}` 非法；仅允许 and/or"
            )));
        }
    };
    Ok(apply_invert(expression, rule.invert))
}

fn compile_default(rule: RawRule) -> Result<RulesetExpr, ParseError> {
    if rule.mode.is_some() || rule.rules.is_some() {
        return Err(ParseError::InvalidRule(
            "default rule 不能包含 logical 专用的 mode/rules".into(),
        ));
    }

    let mut groups = Vec::new();
    let mut destination_group = Vec::new();

    push_string_predicate(
        &mut destination_group,
        rule.domain.into_vec(),
        "domain",
        RulesetPredicate::Domain,
        normalize_exact_domain,
    )?;
    push_string_predicate(
        &mut destination_group,
        rule.domain_suffix.into_vec(),
        "domain_suffix",
        RulesetPredicate::DomainSuffix,
        normalize_domain_suffix,
    )?;
    push_string_predicate(
        &mut destination_group,
        rule.domain_keyword.into_vec(),
        "domain_keyword",
        RulesetPredicate::DomainKeyword,
        normalize_lower_nonempty,
    )?;

    let regex_patterns = rule.domain_regex.into_vec();
    if !regex_patterns.is_empty() {
        let regex = RegexSet::new(&regex_patterns)
            .map_err(|error| ParseError::InvalidRule(format!("domain_regex 编译失败: {error}")))?;
        destination_group.push(RulesetExpr::Predicate(RulesetPredicate::DomainRegex(regex)));
    }

    let destination_cidrs = parse_ip_nets("ip_cidr", rule.ip_cidr.into_vec())?;
    if !destination_cidrs.is_empty() {
        destination_group.push(RulesetExpr::Predicate(RulesetPredicate::DstIpCidr(
            destination_cidrs,
        )));
    }
    if !destination_group.is_empty() {
        groups.push(RulesetExpr::Any(destination_group));
    }

    let source_cidrs = parse_ip_nets("source_ip_cidr", rule.source_ip_cidr.into_vec())?;
    if !source_cidrs.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::SrcIpCidr(
            source_cidrs,
        )));
    }

    let destination_ports = parse_ports("port", rule.port.into_vec(), rule.port_range.into_vec())?;
    if !destination_ports.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::DstPort(
            destination_ports,
        )));
    }

    let source_ports = parse_ports(
        "source_port",
        rule.source_port.into_vec(),
        rule.source_port_range.into_vec(),
    )?;
    if !source_ports.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::SrcPort(
            source_ports,
        )));
    }

    let process_names = normalize_strings(
        "process_name",
        rule.process_name.into_vec(),
        normalize_trim_nonempty,
    )?;
    if !process_names.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::ProcessName(
            process_names,
        )));
    }

    let networks = normalize_networks(rule.network.into_vec())?;
    if !networks.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::Network(networks)));
    }

    if groups.is_empty() {
        return Err(ParseError::InvalidRule(
            "default rule 至少需要一个可求值 predicate".into(),
        ));
    }
    Ok(apply_invert(RulesetExpr::All(groups), rule.invert))
}

fn apply_invert(expression: RulesetExpr, invert: bool) -> RulesetExpr {
    if invert {
        RulesetExpr::Not(Box::new(expression))
    } else {
        expression
    }
}

fn push_string_predicate(
    target: &mut Vec<RulesetExpr>,
    values: Vec<String>,
    field: &'static str,
    constructor: fn(Vec<String>) -> RulesetPredicate,
    normalize: fn(&str) -> Option<String>,
) -> Result<(), ParseError> {
    let values = normalize_strings(field, values, normalize)?;
    if !values.is_empty() {
        target.push(RulesetExpr::Predicate(constructor(values)));
    }
    Ok(())
}

fn normalize_strings(
    field: &'static str,
    values: Vec<String>,
    normalize: fn(&str) -> Option<String>,
) -> Result<Vec<String>, ParseError> {
    values
        .into_iter()
        .map(|value| {
            normalize(&value)
                .ok_or_else(|| ParseError::InvalidRule(format!("{field} 含空值或非法值 `{value}`")))
        })
        .collect()
}

fn normalize_exact_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

fn normalize_domain_suffix(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    (!value.is_empty() && !value.starts_with("..")).then_some(value)
}

fn normalize_lower_nonempty(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

fn normalize_trim_nonempty(value: &str) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn normalize_networks(values: Vec<String>) -> Result<Vec<String>, ParseError> {
    values
        .into_iter()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "tcp" | "udp" | "icmp" => Ok(normalized),
                _ => Err(ParseError::InvalidRule(format!(
                    "network `{value}` 非法；仅允许 tcp/udp/icmp"
                ))),
            }
        })
        .collect()
}

fn parse_ip_nets(field: &'static str, values: Vec<String>) -> Result<Vec<IpNet>, ParseError> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .or_else(|_| {
                    value.parse::<IpAddr>().map(|ip| match ip {
                        IpAddr::V4(ip) => IpNet::V4(Ipv4Net::new(ip, 32).expect("/32 is valid")),
                        IpAddr::V6(ip) => IpNet::V6(Ipv6Net::new(ip, 128).expect("/128 is valid")),
                    })
                })
                .map_err(|_| ParseError::InvalidRule(format!("{field} 含非法 CIDR `{value}`")))
        })
        .collect()
}

fn parse_ports(
    field: &'static str,
    ports: Vec<u16>,
    ranges: Vec<String>,
) -> Result<Vec<PortRange>, ParseError> {
    let mut output = ports
        .into_iter()
        .map(|port| PortRange::new(port, port).expect("single port range is valid"))
        .collect::<Vec<_>>();
    for value in ranges {
        output.push(parse_port_range(field, &value)?);
    }
    Ok(output)
}

fn parse_port_range(field: &'static str, value: &str) -> Result<PortRange, ParseError> {
    let value = value.trim();
    let (start, end) = value.split_once(':').ok_or_else(|| {
        ParseError::InvalidRule(format!("{field}_range `{value}` 非法；应为 start:end"))
    })?;
    let start = if start.trim().is_empty() {
        0
    } else {
        start.trim().parse::<u16>().map_err(|_| {
            ParseError::InvalidRule(format!("{field}_range 起始端口非法: `{value}`"))
        })?
    };
    let end = if end.trim().is_empty() {
        u16::MAX
    } else {
        end.trim().parse::<u16>().map_err(|_| {
            ParseError::InvalidRule(format!("{field}_range 结束端口非法: `{value}`"))
        })?
    };
    PortRange::new(start, end).ok_or_else(|| {
        ParseError::InvalidRule(format!("{field}_range 起始端口大于结束端口: `{value}`"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RulesetMatchContext, RulesetMatcher, parser::RulesetCompiled};

    fn matcher(json: &[u8]) -> RulesetMatcher {
        let program = parse(json).unwrap();
        RulesetMatcher::compile_any("test", RulesetCompiled::Semantic(program))
    }

    fn context<'a>(
        host: &'a str,
        dst_port: Option<u16>,
        network: Option<&'a str>,
    ) -> RulesetMatchContext<'a> {
        RulesetMatchContext {
            dst_host: host,
            dst_port,
            network,
            ..Default::default()
        }
    }

    #[test]
    fn default_rule_requires_domain_and_port_groups() {
        let matcher = matcher(br#"{"version":1,"rules":[{"domain":"example.com","port":443}]}"#);
        assert!(matcher.matches_context(&context("example.com", Some(443), Some("tcp"))));
        assert!(!matcher.matches_context(&context("example.com", Some(80), Some("tcp"))));
        assert!(!matcher.matches_context(&context("other.com", Some(443), Some("tcp"))));
    }

    #[test]
    fn top_level_rules_are_or() {
        let matcher =
            matcher(br#"{"version":2,"rules":[{"domain":"a.example"},{"domain":"b.example"}]}"#);
        assert!(matcher.matches_context(&context("a.example", None, None)));
        assert!(matcher.matches_context(&context("b.example", None, None)));
        assert!(!matcher.matches_context(&context("c.example", None, None)));
    }

    #[test]
    fn empty_type_is_treated_as_default() {
        let matcher = matcher(br#"{"version":1,"rules":[{"type":"","domain":"example.com"}]}"#);
        assert!(matcher.matches_context(&context("example.com", None, None)));
    }

    #[test]
    fn domain_suffix_without_leading_dot_matches_root_and_subdomains() {
        let matcher = matcher(br#"{"version":2,"rules":[{"domain_suffix":"example.com"}]}"#);
        assert!(matcher.matches_context(&context("example.com", None, None)));
        assert!(matcher.matches_context(&context("www.example.com", None, None)));
        assert!(matcher.matches_context(&context("a.b.example.com", None, None)));
        assert!(!matcher.matches_context(&context("notexample.com", None, None)));
    }

    #[test]
    fn domain_suffix_with_leading_dot_matches_only_subdomains() {
        let matcher = matcher(br#"{"version":2,"rules":[{"domain_suffix":".example.com"}]}"#);
        assert!(!matcher.matches_context(&context("example.com", None, None)));
        assert!(matcher.matches_context(&context("www.example.com", None, None)));
        assert!(matcher.matches_context(&context("a.b.example.com", None, None)));
        assert!(!matcher.matches_context(&context("notexample.com", None, None)));
    }

    #[test]
    fn nested_logical_and_or_preserve_structure() {
        let matcher = matcher(
            br#"{
                "version":3,
                "rules":[{
                    "type":"logical",
                    "mode":"and",
                    "rules":[
                        {"type":"logical","mode":"or","rules":[
                            {"domain":"a.example"},
                            {"domain":"b.example"}
                        ]},
                        {"network":"udp"}
                    ]
                }]
            }"#,
        );
        assert!(matcher.matches_context(&context("a.example", None, Some("udp"))));
        assert!(matcher.matches_context(&context("b.example", None, Some("udp"))));
        assert!(!matcher.matches_context(&context("a.example", None, Some("tcp"))));
        assert!(!matcher.matches_context(&context("c.example", None, Some("udp"))));
    }

    #[test]
    fn invert_applies_to_whole_rule() {
        let matcher =
            matcher(br#"{"version":4,"rules":[{"domain":"blocked.example","invert":true}]}"#);
        assert!(!matcher.matches_context(&context("blocked.example", None, None)));
        assert!(matcher.matches_context(&context("allowed.example", None, None)));
    }

    #[test]
    fn logical_invert_applies_after_mode_evaluation() {
        let matcher = matcher(
            br#"{"version":4,"rules":[{
                "type":"logical",
                "mode":"and",
                "rules":[{"domain":"match.example"},{"network":"udp"}],
                "invert":true
            }]}"#,
        );
        assert!(!matcher.matches_context(&context("match.example", None, Some("udp"))));
        assert!(matcher.matches_context(&context("match.example", None, Some("tcp"))));
        assert!(matcher.matches_context(&context("other.example", None, Some("udp"))));
    }

    #[test]
    fn source_and_destination_are_isolated() {
        let source = matcher(
            br#"{"version":5,"rules":[{
                "source_ip_cidr":"10.0.0.0/8",
                "source_port_range":"1000:2000"
            }]}"#,
        );
        let destination_only = RulesetMatchContext {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            dst_port: Some(1500),
            ..Default::default()
        };
        assert!(!source.matches_context(&destination_only));

        let matching_source = RulesetMatchContext {
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: Some(443),
            src_ip: Some("10.9.8.7".parse().unwrap()),
            src_port: Some(1500),
            ..Default::default()
        };
        assert!(source.matches_context(&matching_source));

        let destination =
            matcher(br#"{"version":1,"rules":[{"ip_cidr":"10.0.0.0/8","port":443}]}"#);
        let source_only = RulesetMatchContext {
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: Some(443),
            src_ip: Some("10.9.8.7".parse().unwrap()),
            ..Default::default()
        };
        assert!(!destination.matches_context(&source_only));
    }

    #[test]
    fn supported_predicates_evaluate_together() {
        let matcher = matcher(
            br#"{"version":5,"rules":[{
                "domain_suffix":[".example.com"],
                "domain_keyword":["fallback"],
                "domain_regex":["^api\\."],
                "ip_cidr":["192.0.2.1"],
                "source_ip_cidr":["10.0.0.0/8"],
                "port_range":[":443"],
                "source_port":[12345],
                "process_name":["Curl"],
                "network":["tcp"]
            }]}"#,
        );
        let ctx = RulesetMatchContext {
            dst_host: "api.example.com",
            dst_ip: Some("203.0.113.1".parse().unwrap()),
            dst_port: Some(443),
            src_ip: Some("10.1.2.3".parse().unwrap()),
            src_port: Some(12345),
            network: Some("TCP"),
            process_name: Some("Curl"),
            ..Default::default()
        };
        assert!(matcher.matches_context(&ctx));
        let wrong_process_case = RulesetMatchContext {
            process_name: Some("curl"),
            ..ctx
        };
        assert!(!matcher.matches_context(&wrong_process_case));
    }

    #[test]
    fn versions_one_through_five_are_accepted_and_others_rejected() {
        for version in 1..=5 {
            let body = format!(r#"{{"version":{version},"rules":[]}}"#);
            let program = parse(body.as_bytes()).unwrap();
            assert_eq!(program.version(), version);
            assert!(!program.matches(&RulesetMatchContext::default()));
        }
        assert!(matches!(
            parse(br#"{"version":0,"rules":[]}"#),
            Err(ParseError::UnsupportedVersion(0))
        ));
        assert!(matches!(
            parse(br#"{"version":6,"rules":[]}"#),
            Err(ParseError::UnsupportedVersion(6))
        ));
        assert!(matches!(
            parse(br#"{"rules":[]}"#),
            Err(ParseError::MissingVersion)
        ));
    }

    #[test]
    fn known_unsupported_and_unknown_fields_are_errors() {
        assert!(matches!(
            parse(br#"{"version":5,"rules":[{"query_type":[]}]}"#),
            Err(ParseError::UnsupportedField("query_type"))
        ));
        assert!(matches!(
            parse(br#"{"version":5,"rules":[{"adguard_domain":["||example.org^"]}]}"#),
            Err(ParseError::UnsupportedField("adguard_domain"))
        ));
        let error = parse(br#"{"version":5,"rules":[{"totally_unknown":[]}]}"#).unwrap_err();
        assert!(matches!(error, ParseError::Json(_)));
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn empty_default_and_logical_rules_are_rejected() {
        assert!(matches!(
            parse(br#"{"version":1,"rules":[{}]}"#),
            Err(ParseError::InvalidRule(_))
        ));
        assert!(matches!(
            parse(br#"{"version":1,"rules":[{"type":"logical","mode":"and","rules":[]}]}"#),
            Err(ParseError::InvalidRule(_))
        ));
        assert!(matches!(
            parse(br#"{"version":1,"rules":[{"type":"logical","mode":"or","rules":[]}]}"#),
            Err(ParseError::InvalidRule(_))
        ));
    }

    #[test]
    fn port_range_requires_official_colon_syntax() {
        assert!(matches!(
            parse(br#"{"version":1,"rules":[{"port_range":"1000-2000"}]}"#),
            Err(ParseError::InvalidRule(_))
        ));
        assert!(parse(br#"{"version":1,"rules":[{"port_range":"1000:2000"}]}"#).is_ok());
    }

    #[test]
    fn network_icmp_is_accepted_and_matches() {
        let matcher = matcher(br#"{"version":1,"rules":[{"network":"icmp"}]}"#);
        assert!(matcher.matches_context(&context("", None, Some("icmp"))));
        assert!(matcher.matches_context(&context("", None, Some("ICMP"))));
        assert!(!matcher.matches_context(&context("", None, Some("udp"))));
    }
}
