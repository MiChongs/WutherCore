//! Mihomo TXT / LIST + 统一短写法解析。
//!
//! 每行支持：
//! * `KIND,VALUE[,policy]` —— mihomo classical 标准
//! * `+.example.com`        —— DOMAIN-SUFFIX 简写
//! * `.example.com`         —— DOMAIN-SUFFIX 简写
//! * `exact.host`           —— DOMAIN 简写
//! * `10.0.0.0/8`           —— IP-CIDR 简写
//! * `# comment`            —— 注释
//!
//! 与 mihomo / Clash / Quantumult 等绝大多数文本规则集互通。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use regex::{Regex, RegexSet};

use crate::{
    matcher::{ClassicalEntry, ClassicalKind},
    parser::ParseError,
    spec::RulesetType,
};

pub fn parse(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let text = std::str::from_utf8(body).unwrap_or("");
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(e) = parse_line(line) {
            out.push(e);
        }
    }
    Ok(out)
}

/// 严格解析 Mihomo provider 文本，并按 behavior/type 解释每一行。
///
/// 与兼容旧 API [`parse`] 不同，本入口绝不静默丢弃非空行。manager 使用本入口，
/// 以免未知规则被当成“成功加载”后产生不完整 matcher。
pub fn parse_for_type(
    body: &[u8],
    ruleset_type: RulesetType,
) -> Result<Vec<ClassicalEntry>, ParseError> {
    let text = std::str::from_utf8(body).map_err(|error| ParseError::Utf8(error.to_string()))?;
    parse_lines_for_type(text.lines(), ruleset_type)
}

pub(crate) fn parse_lines_for_type<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    ruleset_type: RulesetType,
) -> Result<Vec<ClassicalEntry>, ParseError> {
    let mut entries = Vec::new();
    for (index, line) in lines.into_iter().enumerate() {
        let trimmed = line.trim();
        if is_ignorable(trimmed) {
            continue;
        }
        let parsed = match ruleset_type {
            RulesetType::Domain => parse_domain_pattern(trimmed),
            RulesetType::Ipcidr => parse_ipcidr_value(trimmed),
            RulesetType::Classical => parse_classical_line_strict(trimmed),
            // WutherCore's native `mixed` keeps its documented shorthand syntax while
            // remaining strict: every line must be unambiguously classical, IP/CIDR,
            // or a valid Clash domain pattern.
            RulesetType::Mixed => parse_mixed_line_strict(trimmed),
        }
        .map_err(|reason| strict_line_error(index + 1, trimmed, reason))?;
        entries.push(parsed);
    }

    // RulesetMatcher::compile uses RegexSet for all classical/domain wildcard regexes.
    // Validate the exact batch here so a size/syntax error cannot make the matcher silently
    // omit every regex.
    let regexes: Vec<&str> = entries
        .iter()
        .filter_map(|entry| {
            (entry.kind == ClassicalKind::DomainRegex).then_some(entry.value.as_str())
        })
        .collect();
    if !regexes.is_empty() {
        RegexSet::new(regexes).map_err(|error| {
            ParseError::BadLine(format!("domain regex set cannot be compiled: {error}"))
        })?;
    }

    Ok(entries)
}

pub fn parse_line(line: &str) -> Option<ClassicalEntry> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') || s.starts_with("//") || s.starts_with(';') {
        return None;
    }

    // 短写法
    if let Some(rest) = s.strip_prefix("+.") {
        return Some(ClassicalEntry {
            kind: ClassicalKind::DomainSuffix,
            value: rest.into(),
            policy: None,
        });
    }
    if s.starts_with('.') && !s.contains(',') {
        return Some(ClassicalEntry {
            kind: ClassicalKind::DomainSuffix,
            value: s.trim_start_matches('.').into(),
            policy: None,
        });
    }

    // mihomo 标准 `KIND,VALUE[,policy[,no-resolve]]`
    if let Some((kind, rest)) = s.split_once(',') {
        if let Some(k) = ClassicalKind::parse(kind.trim()) {
            let mut parts = rest.split(',');
            let value = parts.next().unwrap_or("").trim().to_string();
            let policy = parts
                .next()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("no-resolve"));
            return Some(ClassicalEntry {
                kind: k,
                value,
                policy,
            });
        }
        // 不识别的 kind：丢
        return None;
    }

    // 没逗号：尝试自动判型
    if s.parse::<ipnet::IpNet>().is_ok() {
        return Some(ClassicalEntry {
            kind: ClassicalKind::IpCidr,
            value: s.into(),
            policy: None,
        });
    }
    if looks_like_domain(s) {
        return Some(ClassicalEntry {
            kind: ClassicalKind::Domain,
            value: s.into(),
            policy: None,
        });
    }
    None
}

fn parse_domain_pattern(value: &str) -> Result<ClassicalEntry, String> {
    if value.contains(',') {
        return Err("domain behavior does not accept classical `KIND,VALUE` rules".into());
    }
    if value.parse::<IpAddr>().is_ok() || value.parse::<IpNet>().is_ok() {
        return Err("domain behavior does not accept IP addresses or CIDR prefixes".into());
    }

    let value = value.trim_end_matches('.');
    if value.is_empty() {
        return Err("domain pattern is empty".into());
    }
    let normalized = value.to_ascii_lowercase();

    // `+.` includes the suffix root itself and all descendant levels.
    if let Some(suffix) = normalized.strip_prefix("+.") {
        validate_literal_domain(suffix)?;
        return Ok(ClassicalEntry {
            kind: ClassicalKind::DomainSuffix,
            value: suffix.into(),
            policy: None,
        });
    }

    // A leading `.` requires at least one label before the suffix, unlike `+.`.
    if let Some(suffix) = normalized.strip_prefix('.') {
        validate_literal_domain(suffix)?;
        return Ok(ClassicalEntry {
            kind: ClassicalKind::DomainRegex,
            value: format!(r"^(?:[^.]+\.)+{}$", regex::escape(suffix)),
            policy: None,
        });
    }

    if normalized.contains('+') {
        return Err("`+` wildcard is only valid as the leading `+.` prefix".into());
    }

    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.iter().any(|label| label.contains('*')) {
        let mut regex_labels = Vec::with_capacity(labels.len());
        for label in labels {
            if label == "*" {
                regex_labels.push("[^.]+".to_string());
            } else {
                if label.contains('*') {
                    return Err("`*` wildcard must occupy a complete domain label".into());
                }
                validate_literal_label(label)?;
                regex_labels.push(regex::escape(label));
            }
        }
        return Ok(ClassicalEntry {
            kind: ClassicalKind::DomainRegex,
            value: format!("^{}$", regex_labels.join(r"\.")),
            policy: None,
        });
    }

    validate_literal_domain(&normalized)?;
    Ok(ClassicalEntry {
        kind: ClassicalKind::Domain,
        value: normalized,
        policy: None,
    })
}

fn parse_ipcidr_value(value: &str) -> Result<ClassicalEntry, String> {
    if value.contains(',') {
        return Err("ipcidr behavior does not accept classical `KIND,VALUE` rules".into());
    }
    let normalized = normalize_ip_or_cidr(value)?;
    Ok(ClassicalEntry {
        kind: ClassicalKind::IpCidr,
        value: normalized,
        policy: None,
    })
}

fn parse_mixed_line_strict(value: &str) -> Result<ClassicalEntry, String> {
    if value.contains(',') {
        return parse_classical_line_strict(value);
    }
    if value.parse::<IpAddr>().is_ok() || value.parse::<IpNet>().is_ok() {
        return parse_ipcidr_value(value);
    }
    parse_domain_pattern(value)
}

fn parse_classical_line_strict(value: &str) -> Result<ClassicalEntry, String> {
    let mut fields = value.split(',').map(str::trim);
    let kind_name = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or_else(|| "classical rule is missing its kind".to_string())?;
    let raw_value = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or_else(|| "classical rule is missing its value".to_string())?;
    let kind = ClassicalKind::parse(kind_name)
        .ok_or_else(|| format!("unsupported classical rule kind `{kind_name}`"))?;

    let mut source_modifier = false;
    let mut no_resolve_modifier = false;
    for option in fields {
        if option.is_empty() {
            return Err("classical rule contains an empty trailing field".into());
        }
        if option.eq_ignore_ascii_case("no-resolve") {
            if kind != ClassicalKind::IpCidr {
                return Err(format!("`no-resolve` is not valid for `{kind_name}`"));
            }
            if no_resolve_modifier {
                return Err("classical rule contains duplicate `no-resolve` options".into());
            }
            no_resolve_modifier = true;
            continue;
        }
        if option.eq_ignore_ascii_case("src") {
            if kind != ClassicalKind::IpCidr {
                return Err(format!("`src` is not valid for `{kind_name}`"));
            }
            if source_modifier {
                return Err("classical rule contains duplicate `src` options".into());
            }
            source_modifier = true;
            continue;
        }
        return Err(format!(
            "classical provider action/policy field `{option}` is unsupported"
        ));
    }

    let normalized_value = match kind {
        ClassicalKind::Domain => {
            validate_literal_domain(raw_value)?;
            raw_value.trim_end_matches('.').to_ascii_lowercase()
        }
        ClassicalKind::DomainSuffix => {
            validate_literal_domain(raw_value)?;
            raw_value.trim_matches('.').to_ascii_lowercase()
        }
        ClassicalKind::DomainKeyword => {
            if raw_value.is_empty() {
                return Err("DOMAIN-KEYWORD value cannot be empty".into());
            }
            raw_value.to_ascii_lowercase()
        }
        ClassicalKind::DomainRegex => {
            Regex::new(raw_value).map_err(|error| format!("invalid DOMAIN-REGEX: {error}"))?;
            raw_value.into()
        }
        ClassicalKind::IpCidr | ClassicalKind::SrcIpCidr => {
            // Mihomo treats IP-CIDR6 as an alias of IP-CIDR; both accept either family.
            normalize_ip_or_cidr(raw_value)?
        }
        ClassicalKind::DstPort | ClassicalKind::SrcPort => {
            validate_port_range(raw_value)?;
            raw_value.into()
        }
        ClassicalKind::ProcessName => raw_value.into(),
    };
    let normalized_kind = if kind == ClassicalKind::IpCidr && source_modifier {
        ClassicalKind::SrcIpCidr
    } else {
        kind
    };

    Ok(ClassicalEntry {
        kind: normalized_kind,
        value: normalized_value,
        policy: None,
    })
}

fn normalize_ip_or_cidr(value: &str) -> Result<String, String> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net.to_string());
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Ok(host_prefix_v4(address)),
        Ok(IpAddr::V6(address)) => Ok(host_prefix_v6(address)),
        Err(_) => Err(format!(
            "`{value}` is not a valid IP address or CIDR prefix"
        )),
    }
}

fn host_prefix_v4(address: Ipv4Addr) -> String {
    format!("{address}/32")
}

fn host_prefix_v6(address: Ipv6Addr) -> String {
    format!("{address}/128")
}

fn validate_port_range(value: &str) -> Result<(), String> {
    let (start, end) = if let Some((start, end)) = value.split_once('-') {
        if end.contains('-') {
            return Err(format!("invalid port range `{value}`"));
        }
        let start = start
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{start}`"))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{end}`"))?;
        (start, end)
    } else {
        let port = value
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{value}`"))?;
        (port, port)
    };
    if start > end {
        return Err(format!("port range start exceeds end in `{value}`"));
    }
    Ok(())
}

fn validate_literal_domain(value: &str) -> Result<(), String> {
    let value = value.trim_end_matches('.');
    if value.is_empty() {
        return Err("domain is empty".into());
    }
    for label in value.split('.') {
        validate_literal_label(label)?;
    }
    Ok(())
}

fn validate_literal_label(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("domain contains an empty label".into());
    }
    if !label
        .chars()
        .all(|character| character.is_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(format!(
            "domain label `{label}` contains unsupported characters"
        ));
    }
    Ok(())
}

fn is_ignorable(value: &str) -> bool {
    value.is_empty() || value.starts_with('#') || value.starts_with("//") || value.starts_with(';')
}

fn strict_line_error(index: usize, line: &str, reason: String) -> ParseError {
    ParseError::BadLine(format!("line {index} `{line}`: {reason}"))
}

fn looks_like_domain(s: &str) -> bool {
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::RulesetMatcher;

    #[test]
    fn classical_lines() {
        let body = b"DOMAIN-SUFFIX,example.com\nIP-CIDR,1.2.3.0/24\nDOMAIN-KEYWORD,google\n# comment\n+.qq.com\n";
        let v = parse(body).unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].kind, ClassicalKind::DomainSuffix);
        assert_eq!(v[0].value, "example.com");
        assert_eq!(v[1].kind, ClassicalKind::IpCidr);
        assert_eq!(v[2].kind, ClassicalKind::DomainKeyword);
        assert_eq!(v[3].kind, ClassicalKind::DomainSuffix);
        assert_eq!(v[3].value, "qq.com");
    }

    #[test]
    fn ignore_comments_and_empty() {
        let body = b"\n# only comment\n   \n";
        assert!(parse(body).unwrap().is_empty());
    }

    #[test]
    fn auto_detect_short() {
        let body = b"10.0.0.0/8\nexact.host\n";
        let v = parse(body).unwrap();
        assert_eq!(v[0].kind, ClassicalKind::IpCidr);
        assert_eq!(v[1].kind, ClassicalKind::Domain);
    }

    #[test]
    fn preserves_policy() {
        let e = parse_line("DOMAIN,example.com,DIRECT").unwrap();
        assert_eq!(e.policy.as_deref(), Some("DIRECT"));
        let e2 = parse_line("IP-CIDR,1.0.0.0/8,DIRECT,no-resolve").unwrap();
        assert_eq!(e2.policy.as_deref(), Some("DIRECT"));
    }

    #[test]
    fn domain_behavior_implements_official_clash_wildcards() {
        let entries = parse_for_type(
            b".blogger.com\n*.*.microsoft.com\nbooks.itunes.apple.com\n+.xboxlive.com\n*\n",
            RulesetType::Domain,
        )
        .unwrap();
        let matcher = RulesetMatcher::compile("domain", entries);

        // Leading dot: descendants only, never the suffix root.
        assert!(matcher.matches("www.blogger.com", None, None, None));
        assert!(matcher.matches("a.b.blogger.com", None, None, None));
        assert!(!matcher.matches("blogger.com", None, None, None));

        // Each `*` consumes exactly one complete label.
        assert!(matcher.matches("a.b.microsoft.com", None, None, None));
        assert!(!matcher.matches("b.microsoft.com", None, None, None));
        assert!(!matcher.matches("a.b.c.microsoft.com", None, None, None));

        // Exact and `+.` (root plus arbitrarily deep descendants).
        assert!(matcher.matches("books.itunes.apple.com", None, None, None));
        assert!(!matcher.matches("other.itunes.apple.com", None, None, None));
        assert!(matcher.matches("xboxlive.com", None, None, None));
        assert!(matcher.matches("a.b.xboxlive.com", None, None, None));

        // A lone `*` only matches a single-label hostname.
        assert!(matcher.matches("localhost", None, None, None));
        assert!(!matcher.matches("www.localhost", None, None, None));
    }

    #[test]
    fn domain_behavior_rejects_ip_classical_and_invalid_wildcards() {
        for invalid in [
            "10.0.0.0/8",
            "192.0.2.1",
            "DOMAIN,example.com",
            "foo*bar.example",
            "example.+.com",
        ] {
            let error = parse_for_type(invalid.as_bytes(), RulesetType::Domain).unwrap_err();
            assert!(error.to_string().contains(invalid), "{error}");
        }
    }

    #[test]
    fn ipcidr_behavior_accepts_only_valid_ip_or_prefix() {
        let entries = parse_for_type(
            b"192.0.2.1\n10.0.0.0/8\n2001:db8::1\n2001:db8::/32\n",
            RulesetType::Ipcidr,
        )
        .unwrap();
        assert_eq!(entries[0].value, "192.0.2.1/32");
        assert_eq!(entries[2].value, "2001:db8::1/128");
        let matcher = RulesetMatcher::compile("ip", entries);
        assert!(matcher.matches("", Some("192.0.2.1".parse().unwrap()), None, None));
        assert!(matcher.matches("", Some("10.2.3.4".parse().unwrap()), None, None));
        assert!(matcher.matches("", Some("2001:db8::1".parse().unwrap()), None, None));
        assert!(!matcher.matches("example.com", None, None, None));

        for invalid in ["example.com", "IP-CIDR,10.0.0.0/8", "10.0.0.0/99"] {
            let error = parse_for_type(invalid.as_bytes(), RulesetType::Ipcidr).unwrap_err();
            assert!(error.to_string().contains(invalid), "{error}");
        }
    }

    #[test]
    fn classical_behavior_accepts_supported_kinds_and_rejects_every_other_line() {
        let entries = parse_for_type(
            b"DOMAIN-SUFFIX,google.com\nDOMAIN-KEYWORD,google\nDOMAIN,ad.com\nSRC-IP-CIDR,192.168.1.201/32\nIP-CIDR,127.0.0.0/8,no-resolve\nIP-CIDR,198.51.100.0/24,src\nIP-CIDR,2001:db8::/32\nIP-CIDR6,192.0.2.0/24\nDST-PORT,80\nSRC-PORT,7777\nPROCESS-NAME,browser.exe\nDOMAIN-REGEX,^api[0-9]+\\.example\\.com$\n",
            RulesetType::Classical,
        )
        .unwrap();
        assert!(entries.iter().any(|entry| {
            entry.kind == ClassicalKind::SrcIpCidr && entry.value == "198.51.100.0/24"
        }));
        let matcher = RulesetMatcher::compile("classical", entries);
        assert!(matcher.matches("mail.google.com", None, None, None));
        assert!(matcher.matches("api42.example.com", None, None, None));
        assert!(matcher.matches("", Some("127.0.0.1".parse().unwrap()), None, None));
        assert!(matcher.matches("", Some("2001:db8::1".parse().unwrap()), None, None));
        assert!(matcher.matches("", Some("192.0.2.1".parse().unwrap()), None, None));

        for invalid in [
            "GEOIP,CN",
            "NOT-A-RULE",
            "IP-CIDR,10.0.0.0/99",
            "DST-PORT,9000-8000",
            "DOMAIN-REGEX,[",
            "DOMAIN,example.com,DIRECT",
            "DOMAIN,example.com,src",
            "IP-CIDR,10.0.0.0/8,src,src",
        ] {
            let error = parse_for_type(invalid.as_bytes(), RulesetType::Classical).unwrap_err();
            assert!(error.to_string().contains(invalid), "{error}");
        }
    }

    #[test]
    fn strict_text_rejects_invalid_utf8() {
        let error = parse_for_type(&[0xff, 0xfe], RulesetType::Domain).unwrap_err();
        assert!(matches!(error, ParseError::Utf8(_)));
    }
}
