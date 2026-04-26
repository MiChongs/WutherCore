//! `IntRanges<u16>` —— 端口/状态码范围解析与检查，与 mihomo `common/utils/ranges.go`
//! 行为对齐。
//!
//! 解析格式（与 mihomo 完全相同）：
//! ```text
//!   "200"                            → [200..=200]
//!   "200/204"                        → [200, 204]
//!   "200,204"                        → 同上（逗号 = 斜杠）
//!   "200-299"                        → [200..=299]
//!   "200/204/401-429/501-503"        → [200, 204, 401..=429, 501..=503]
//!   ""  / "*"                        → 空集，[`Self::check`] 返回 true
//! ```
//!
//! `check(status)`：空集任意通过；否则 status 必须落在某条 range。

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntRanges {
    parts: Vec<Range>,
}

impl IntRanges {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() || s == "*" {
            return Ok(Self::empty());
        }
        // 逗号 / 斜杠 二选一
        let normalized = s.replace(',', "/");
        let chunks: Vec<&str> = normalized.split('/').filter(|x| !x.is_empty()).collect();
        if chunks.len() > 28 {
            return Err(format!("too many ranges (max 28): {}", chunks.len()));
        }
        let mut parts = Vec::with_capacity(chunks.len());
        for c in chunks {
            parts.push(parse_one(c)?);
        }
        Ok(Self { parts })
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    pub fn check(&self, status: u16) -> bool {
        if self.parts.is_empty() {
            return true;
        }
        self.parts.iter().any(|r| status >= r.start && status <= r.end)
    }

    pub fn parts(&self) -> &[Range] {
        &self.parts
    }
}

fn parse_one(c: &str) -> Result<Range, String> {
    if let Some((a, b)) = c.split_once('-') {
        let start: u16 = a.trim().parse().map_err(|e| format!("bad range '{c}': {e}"))?;
        let end: u16 = b.trim().parse().map_err(|e| format!("bad range '{c}': {e}"))?;
        if end < start {
            return Err(format!("bad range '{c}': end < start"));
        }
        Ok(Range { start, end })
    } else {
        let v: u16 = c.trim().parse().map_err(|e| format!("bad value '{c}': {e}"))?;
        Ok(Range { start: v, end: v })
    }
}

impl fmt::Display for IntRanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.parts.is_empty() {
            return write!(f, "*");
        }
        let mut first = true;
        for r in &self.parts {
            if !first {
                write!(f, "/")?;
            }
            first = false;
            if r.start == r.end {
                write!(f, "{}", r.start)?;
            } else {
                write!(f, "{}-{}", r.start, r.end)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_star_passes_anything() {
        let r = IntRanges::parse("").unwrap();
        assert!(r.check(0));
        assert!(r.check(999));
        let r = IntRanges::parse("*").unwrap();
        assert!(r.check(200));
    }

    #[test]
    fn single_value() {
        let r = IntRanges::parse("204").unwrap();
        assert!(r.check(204));
        assert!(!r.check(203));
    }

    #[test]
    fn slash_and_comma() {
        let r = IntRanges::parse("200/204").unwrap();
        assert!(r.check(200) && r.check(204) && !r.check(201));
        let r = IntRanges::parse("200,204").unwrap();
        assert!(r.check(200) && r.check(204));
    }

    #[test]
    fn ranges_compound() {
        let r = IntRanges::parse("200/204/401-429/501-503").unwrap();
        assert!(r.check(200));
        assert!(r.check(204));
        assert!(r.check(401));
        assert!(r.check(415));
        assert!(r.check(429));
        assert!(!r.check(430));
        assert!(r.check(502));
        assert!(!r.check(504));
    }

    #[test]
    fn rejects_more_than_28_chunks() {
        let s: Vec<String> = (0..29).map(|i| format!("{i}")).collect();
        let res = IntRanges::parse(&s.join("/"));
        assert!(res.is_err());
    }

    #[test]
    fn display_roundtrip() {
        let r = IntRanges::parse("200/204/401-429").unwrap();
        assert_eq!(format!("{r}"), "200/204/401-429");
        let r = IntRanges::parse("").unwrap();
        assert_eq!(format!("{r}"), "*");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(IntRanges::parse("abc").is_err());
        assert!(IntRanges::parse("300-200").is_err());
    }
}
