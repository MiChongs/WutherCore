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
};

#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
