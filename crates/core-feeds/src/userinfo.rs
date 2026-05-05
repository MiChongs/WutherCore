//! 订阅用量头解析 —— 把机场返回的 `Subscription-Userinfo` 等头解析出
//! upload / download / total / expire 四元组。
//!
//! ## 头格式
//!
//! ```text
//! Subscription-Userinfo: upload=12345; download=67890; total=99999999; expire=1738742400
//! ```
//!
//! 业内常见三种头名（按出现频率排序，全部 ASCII 大小写不敏感）：
//!
//! 1. `Subscription-Userinfo`
//! 2. `Ssr-Subscribe-Userinfo`（部分老牌机场）
//! 3. `Ssr-Subscription-Userinfo`（极少数）
//!
//! 字段都是十进制 u64：
//!
//! * `upload` / `download`：累计字节
//! * `total`：套餐总额（字节）；0 = 无限制
//! * `expire`：套餐过期 Unix 秒；0 = 无过期
//!
//! ## 设计要点（性能 / 内存）
//!
//! * 全程 `&str` 切片，零分配 —— 不拆 String，不构造中间集合。
//! * ASCII case-insensitive 比较手写，不调 `to_ascii_lowercase()`（避免
//!   构造临时 String）。
//! * 单次 O(N) 扫描；headers 列表 O(M) 命中第一个匹配项即可返回。
//! * 容错：值字段 trim 空白；非数字 / 缺等号 / 多余分号统统忽略，不让单条
//!   坏数据让整次解析失败。

use serde::Serialize;

/// 单个订阅的用量信息。所有字段单位与原始头一致。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubscriptionUserinfo {
    /// 已用上行字节数
    pub upload: u64,
    /// 已用下行字节数
    pub download: u64,
    /// 套餐总流量字节数；0 = 无限制
    pub total: u64,
    /// 套餐过期 Unix 秒；0 = 无过期
    pub expire: u64,
}

impl SubscriptionUserinfo {
    /// 解析单个头值。返回 None 表示一个已知字段都没解析到（坏数据 /
    /// 不是用量头）；返回 Some 时未提供的字段保持 0。
    pub fn parse(value: &str) -> Option<Self> {
        let mut info = Self::default();
        let mut found = false;
        // 用 split(';') 而非按字节扫描 —— 测过 100 字节级别 header，差异在
        // 噪声内；split 的可读性收益更大。
        for token in value.split(';') {
            let Some((key, val)) = token.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let val = val.trim();
            if key.is_empty() || val.is_empty() {
                continue;
            }
            // 单条坏数据不让整次失败 —— 配合 `found`，只要至少有一个有效字段
            // 就返回 Some。
            let parsed: u64 = match val.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if eq_ascii_ci(key, "upload") {
                info.upload = parsed;
                found = true;
            } else if eq_ascii_ci(key, "download") {
                info.download = parsed;
                found = true;
            } else if eq_ascii_ci(key, "total") {
                info.total = parsed;
                found = true;
            } else if eq_ascii_ci(key, "expire") {
                info.expire = parsed;
                found = true;
            }
            // 其它未知 key（如 reset_day、plan_id 等机场扩展）静默忽略。
        }
        if found {
            Some(info)
        } else {
            None
        }
    }

    /// 从一组 (name, value) 头里寻找已知用量头并解析。任何匹配项命中即返回。
    /// 头名匹配 ASCII case-insensitive。
    pub fn from_headers<'a, I>(headers: I) -> Option<Self>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        for (name, value) in headers {
            if is_userinfo_header_name(name) {
                if let Some(info) = Self::parse(value) {
                    return Some(info);
                }
            }
        }
        None
    }

    /// 是否为"无套餐限制"状态 —— total = 0 视为无限制。
    pub fn is_unlimited(&self) -> bool {
        self.total == 0
    }

    /// 套餐已用字节（upload + download）。
    pub fn used(&self) -> u64 {
        self.upload.saturating_add(self.download)
    }

    /// 套餐剩余字节；total = 0 时返回 [`u64::MAX`] 表示无限。
    pub fn remaining(&self) -> u64 {
        if self.is_unlimited() {
            u64::MAX
        } else {
            self.total.saturating_sub(self.used())
        }
    }
}

/// 已知的订阅用量头名。匹配 ASCII case-insensitive。
fn is_userinfo_header_name(name: &str) -> bool {
    eq_ascii_ci(name, "subscription-userinfo")
        || eq_ascii_ci(name, "ssr-subscribe-userinfo")
        || eq_ascii_ci(name, "ssr-subscription-userinfo")
}

/// 等长 ASCII 大小写不敏感比较；不分配。
fn eq_ascii_ci(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_header() {
        let h = "upload=455727930049; download=2056703039619; total=805306368000; expire=1738742400";
        let info = SubscriptionUserinfo::parse(h).expect("parse should succeed");
        assert_eq!(info.upload, 455_727_930_049);
        assert_eq!(info.download, 2_056_703_039_619);
        assert_eq!(info.total, 805_306_368_000);
        assert_eq!(info.expire, 1_738_742_400);
        assert!(!info.is_unlimited());
        assert_eq!(info.used(), 455_727_930_049 + 2_056_703_039_619);
    }

    #[test]
    fn parse_partial_header() {
        let h = "upload=100; download=200";
        let info = SubscriptionUserinfo::parse(h).expect("partial should still parse");
        assert_eq!(info.upload, 100);
        assert_eq!(info.download, 200);
        assert_eq!(info.total, 0);
        assert!(info.is_unlimited());
        assert_eq!(info.remaining(), u64::MAX);
    }

    #[test]
    fn parse_handles_extra_whitespace_and_unknown_fields() {
        let h = "  upload = 1 ; junk ; download=2 ;reset_day=15 ;total=10";
        let info = SubscriptionUserinfo::parse(h).expect("should parse with weird spacing");
        assert_eq!(info.upload, 1);
        assert_eq!(info.download, 2);
        assert_eq!(info.total, 10);
        assert_eq!(info.expire, 0);
    }

    #[test]
    fn parse_case_insensitive_keys() {
        let h = "UPLOAD=10; Download=20; Total=100; EXPIRE=999";
        let info = SubscriptionUserinfo::parse(h).expect("case-insensitive keys");
        assert_eq!(info.upload, 10);
        assert_eq!(info.download, 20);
        assert_eq!(info.total, 100);
        assert_eq!(info.expire, 999);
    }

    #[test]
    fn parse_returns_none_when_no_known_field() {
        assert!(SubscriptionUserinfo::parse("foo=1; bar=2").is_none());
        assert!(SubscriptionUserinfo::parse("").is_none());
        assert!(SubscriptionUserinfo::parse("garbage").is_none());
    }

    #[test]
    fn parse_skips_invalid_numbers() {
        let h = "upload=abc; download=200";
        let info = SubscriptionUserinfo::parse(h).expect("download should still parse");
        assert_eq!(info.upload, 0);
        assert_eq!(info.download, 200);
    }

    #[test]
    fn from_headers_picks_first_match() {
        let headers = vec![
            ("Content-Type", "text/plain"),
            ("Subscription-Userinfo", "upload=1; download=2; total=10"),
            ("X-Other", "noise"),
        ];
        let info = SubscriptionUserinfo::from_headers(headers.into_iter())
            .expect("should find subscription header");
        assert_eq!(info.upload, 1);
        assert_eq!(info.total, 10);
    }

    #[test]
    fn from_headers_recognizes_alternate_names() {
        let headers = vec![("Ssr-Subscribe-Userinfo", "upload=5; download=7")];
        let info = SubscriptionUserinfo::from_headers(headers.into_iter()).unwrap();
        assert_eq!(info.upload, 5);
        assert_eq!(info.download, 7);
    }

    #[test]
    fn used_and_remaining_saturating_arithmetic() {
        // used overflow protection
        let info = SubscriptionUserinfo {
            upload: u64::MAX,
            download: 1,
            total: 0,
            expire: 0,
        };
        assert_eq!(info.used(), u64::MAX);

        // remaining when used > total
        let info = SubscriptionUserinfo {
            upload: 100,
            download: 100,
            total: 50,
            expire: 0,
        };
        assert_eq!(info.remaining(), 0);
    }

    #[test]
    fn empty_value_pairs_are_skipped() {
        let h = "upload=; download=10; =5";
        let info = SubscriptionUserinfo::parse(h).expect("download should parse");
        assert_eq!(info.upload, 0);
        assert_eq!(info.download, 10);
    }

    #[test]
    fn json_serialization_uses_pascal_case() {
        // dashboard 期待的字段名是 PascalCase（Upload / Download / Total / Expire）
        // —— 与广泛使用的客户端响应保持一致。
        let info = SubscriptionUserinfo {
            upload: 1,
            download: 2,
            total: 3,
            expire: 4,
        };
        let s = serde_json::to_string(&info).unwrap();
        assert!(s.contains("\"Upload\":1"), "got {s}");
        assert!(s.contains("\"Download\":2"), "got {s}");
        assert!(s.contains("\"Total\":3"), "got {s}");
        assert!(s.contains("\"Expire\":4"), "got {s}");
    }
}
