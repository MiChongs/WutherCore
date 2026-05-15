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

use crate::{
    matcher::{ClassicalEntry, ClassicalKind},
    parser::ParseError,
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

fn looks_like_domain(s: &str) -> bool {
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
