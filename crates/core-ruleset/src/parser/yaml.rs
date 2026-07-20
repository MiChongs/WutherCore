//! Mihomo / Clash YAML payload 解析。
//!
//! 兼容两种写法：
//!
//! ```yaml
//! payload:
//!   - "DOMAIN-SUFFIX,example.com"
//!   - "IP-CIDR,1.2.3.0/24"
//!   - "+.qq.com"        # 简短：自动识别为 DOMAIN-SUFFIX
//!   - "exact.test"      # 简短：自动识别为 DOMAIN
//!   - "10.0.0.0/8"      # 简短：自动识别为 IP-CIDR
//! ```

use serde::Deserialize;

use crate::{
    matcher::ClassicalEntry,
    parser::{ParseError, txt::parse_line},
    spec::RulesetType,
};

#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
    payload: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDoc {
    payload: Vec<String>,
}

pub fn parse(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let doc: Doc = serde_yaml::from_slice(body).map_err(|e| ParseError::Yaml(e.to_string()))?;
    let mut out = Vec::with_capacity(doc.payload.len());
    for line in doc.payload {
        if let Some(e) = parse_line(&line) {
            out.push(e);
        }
    }
    Ok(out)
}

/// 严格解析 Mihomo YAML provider。
///
/// Provider 文件必须显式包含唯一的 `payload` 字段；缺失字段或下载端返回的
/// 其它 YAML/JSON 对象不能被误判为空规则集。
pub fn parse_for_type(
    body: &[u8],
    ruleset_type: RulesetType,
) -> Result<Vec<ClassicalEntry>, ParseError> {
    let doc: ProviderDoc =
        serde_yaml::from_slice(body).map_err(|error| ParseError::Yaml(error.to_string()))?;
    crate::parser::txt::parse_lines_for_type(doc.payload.iter().map(String::as_str), ruleset_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::RulesetMatcher;

    #[test]
    fn parses_full_kinds() {
        let yaml = r#"
payload:
  - "DOMAIN-SUFFIX,example.com"
  - "IP-CIDR,10.0.0.0/8"
  - "DOMAIN-KEYWORD,google"
  - "+.qq.com"
  - "exact.host"
  - "1.2.3.0/24"
"#;
        let v = parse(yaml.as_bytes()).unwrap();
        assert_eq!(v.len(), 6);
    }

    #[test]
    fn provider_yaml_uses_declared_domain_behavior() {
        let yaml = r#"
payload:
  - '.blogger.com'
  - '*.*.microsoft.com'
  - 'books.itunes.apple.com'
"#;
        let entries = parse_for_type(yaml.as_bytes(), RulesetType::Domain).unwrap();
        let matcher = RulesetMatcher::compile("domain-yaml", entries);
        assert!(matcher.matches("www.blogger.com", None, None, None));
        assert!(!matcher.matches("blogger.com", None, None, None));
        assert!(matcher.matches("a.b.microsoft.com", None, None, None));
        assert!(!matcher.matches("a.microsoft.com", None, None, None));
        assert!(matcher.matches("books.itunes.apple.com", None, None, None));
    }

    #[test]
    fn provider_yaml_requires_payload_and_rejects_unknown_documents() {
        for invalid in [
            "message: rate-limited\n",
            "payload: [example.com]\nextra: ignored-before\n",
            "payload:\n  - 'DOMAIN,example.com'\n",
        ] {
            let error = parse_for_type(invalid.as_bytes(), RulesetType::Domain).unwrap_err();
            assert!(
                matches!(error, ParseError::Yaml(_) | ParseError::BadLine(_)),
                "{error}"
            );
        }
    }
}
