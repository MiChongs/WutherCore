//! sing-box rule-set JSON 解析。
//!
//! 顶层结构（[reference](https://sing-box.sagernet.org/configuration/rule-set/)）：
//! ```json
//! {
//!   "version": 1 | 2,
//!   "rules": [
//!     {
//!       "domain": ["example.com"],
//!       "domain_suffix": [".example.com"],
//!       "domain_keyword": ["google"],
//!       "domain_regex": ["^a\\.b$"],
//!       "ip_cidr": ["1.2.3.0/24"],
//!       "source_ip_cidr": ["..."],
//!       "port": [443],
//!       "port_range": ["1000:2000"],
//!       "process_name": ["Code"]
//!     },
//!     {"type":"logical","mode":"or","rules":[...]}
//!   ]
//! }
//! ```
//! 我们把所有 default rule 字段铺平为 [`ClassicalEntry`]；logical 规则按子规则递归。

use serde::Deserialize;

use crate::{
    matcher::{ClassicalEntry, ClassicalKind},
    parser::ParseError,
};

#[derive(Deserialize)]
struct Doc {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Rule {
    /// 必须先匹配 logical（要求存在 `type` + `rules`），否则 untagged 会
    /// 先把它当作 default rule（含同名 `domain`/`ip_cidr` 字段时也成立）。
    Logical(LogicalRule),
    Default(DefaultRule),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DefaultRule {
    #[serde(rename = "type")]
    rtype: Option<String>,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<String>,
    ip_cidr: Vec<String>,
    source_ip_cidr: Vec<String>,
    port: Vec<u16>,
    port_range: Vec<String>,
    source_port: Vec<u16>,
    source_port_range: Vec<String>,
    process_name: Vec<String>,
}

#[derive(Deserialize)]
struct LogicalRule {
    #[serde(rename = "type")]
    _rtype: String,
    #[serde(default)]
    rules: Vec<Rule>,
}

pub fn parse(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let doc: Doc = serde_json::from_slice(body).map_err(|e| ParseError::Json(e.to_string()))?;
    let mut out = Vec::new();
    for r in doc.rules {
        flatten(r, &mut out);
    }
    Ok(out)
}

fn flatten(r: Rule, out: &mut Vec<ClassicalEntry>) {
    match r {
        Rule::Default(d) => {
            for v in d.domain {
                out.push(ce(ClassicalKind::Domain, v));
            }
            for v in d.domain_suffix {
                out.push(ce(ClassicalKind::DomainSuffix, v));
            }
            for v in d.domain_keyword {
                out.push(ce(ClassicalKind::DomainKeyword, v));
            }
            for v in d.domain_regex {
                out.push(ce(ClassicalKind::DomainRegex, v));
            }
            for v in d.ip_cidr {
                out.push(ce(ClassicalKind::IpCidr, v));
            }
            for v in d.source_ip_cidr {
                out.push(ce(ClassicalKind::SrcIpCidr, v));
            }
            for v in d.port {
                out.push(ce(ClassicalKind::DstPort, v.to_string()));
            }
            for v in d.port_range {
                out.push(ce(ClassicalKind::DstPort, v.replace(':', "-")));
            }
            for v in d.source_port {
                out.push(ce(ClassicalKind::SrcPort, v.to_string()));
            }
            for v in d.source_port_range {
                out.push(ce(ClassicalKind::SrcPort, v.replace(':', "-")));
            }
            for v in d.process_name {
                out.push(ce(ClassicalKind::ProcessName, v));
            }
            let _ = d.rtype;
        }
        Rule::Logical(l) => {
            for sub in l.rules {
                flatten(sub, out);
            }
        }
    }
}

fn ce(k: ClassicalKind, v: String) -> ClassicalEntry {
    ClassicalEntry {
        kind: k,
        value: v,
        policy: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_singbox_v2() {
        let json = br#"{
            "version": 2,
            "rules": [
                {"domain":["a.com"], "domain_suffix":[".b.com"], "ip_cidr":["1.0.0.0/24"], "port":[80,443], "port_range":["1000:2000"]},
                {"type":"logical", "mode":"or", "rules":[
                    {"domain_keyword":["google"]},
                    {"domain_regex":["^x\\.y$"]}
                ]}
            ]
        }"#;
        let v = parse(json).unwrap();
        // 1+1+1+2+1+1+1 = 8
        assert_eq!(v.len(), 8);
        assert!(
            v.iter()
                .any(|e| e.kind == ClassicalKind::DomainKeyword && e.value == "google")
        );
        assert!(
            v.iter()
                .any(|e| e.kind == ClassicalKind::DstPort && e.value == "1000-2000")
        );
    }
}
