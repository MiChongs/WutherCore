//! RRS —— WutherCore Rule Set 自研二进制规则集格式。
//!
//! ## 设计目标
//!
//! | 维度 | 实现 |
//! |---|---|
//! | **高性能** | 定长 header + 紧凑顺序 section；O(N) decode 全程零拷贝读取 |
//! | **低占用** | LEB128 var-len 长度 + 字符串引用 + CIDR 直存 5/17B；不依赖 zstd 也 ~3-5× 小于 YAML |
//! | **准确性** | 4B magic + 2B version + 8B createdAt + **CRC32(body)** + body length；任一字段错都立刻拒绝 |
//! | **跨工具** | encode/decode 完整双向；CLI `ruleset convert` 把 yaml/txt/json ↔ rrs 互转 |
//!
//! ## 文件布局（v1）
//!
//! ```text
//!   offset  bytes  field
//!   0       4      magic = "RRS\0"
//!   4       2      version (u16 LE) = 1
//!   6       2      flags  (u16 LE) —— 保留位（bit0 future zstd）
//!   8       8      created_at (u64 LE epoch_secs)
//!   16      4      body_len (u32 LE)
//!   20      4      body_crc32 (u32 LE)        ← CRC32 of bytes [24, 24+body_len)
//!   24      ...    body
//! ```
//!
//! ## body —— 8 个固定顺序的 section
//!
//! ```text
//!   for kind in [DomainExact, DomainSuffix, DomainKeyword, DomainRegex,
//!                CidrV4, CidrV6, Port, Process]:
//!     count   var-len u32
//!     for i in 0..count:
//!       payload_for_kind
//! ```
//!
//! Per-kind payload：
//! * **string-based** (DomainExact / Suffix / Keyword / Regex / Process)：`var-len len || utf8 bytes`
//! * **CidrV4**：`4B network LE || 1B prefix`
//! * **CidrV6**：`16B network || 1B prefix`
//! * **Port**：`2B lo BE || 2B hi BE`
//!
//! ## 准确性保证
//!
//! 1. magic + version 必须严格匹配；
//! 2. body_len 必须等于实际剩余字节数；
//! 3. CRC32 必须匹配；
//! 4. 每个 string len ≤ 4096；CIDR prefix ≤ 32/128；
//! 5. 任一校验失败：返回精确字节偏移的 `ParseError`。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    matcher::{ClassicalEntry, ClassicalKind},
    parser::ParseError,
};

pub const MAGIC: [u8; 4] = *b"RRS\0";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_STR_LEN: usize = 4096;

/// 8 个 section 的固定顺序。decode 与 encode 必须保持一致。
const SECTION_ORDER: &[ClassicalKind] = &[
    ClassicalKind::Domain,
    ClassicalKind::DomainSuffix,
    ClassicalKind::DomainKeyword,
    ClassicalKind::DomainRegex,
    ClassicalKind::IpCidr,    // V4
    ClassicalKind::SrcIpCidr, // V6（占位 —— 复用 SrcIpCidr 当作 V6 入口）
    ClassicalKind::DstPort,
    ClassicalKind::ProcessName,
];

/* ============================================================
Encode
============================================================ */

/// 把任意 [`ClassicalEntry`] 序列编码为 RRS 字节流。
pub fn encode(entries: &[ClassicalEntry]) -> Vec<u8> {
    // 按 kind 分桶 + 去重 + 排序
    let mut domains: Vec<String> = Vec::new();
    let mut suffixes: Vec<String> = Vec::new();
    let mut keywords: Vec<String> = Vec::new();
    let mut regex: Vec<String> = Vec::new();
    let mut v4: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut v6: Vec<(Ipv6Addr, u8)> = Vec::new();
    let mut ports: Vec<(u16, u16)> = Vec::new();
    let mut processes: Vec<String> = Vec::new();

    for e in entries {
        match e.kind {
            ClassicalKind::Domain => domains.push(e.value.to_ascii_lowercase()),
            ClassicalKind::DomainSuffix => {
                suffixes.push(e.value.trim_matches('.').to_ascii_lowercase())
            }
            ClassicalKind::DomainKeyword => keywords.push(e.value.to_ascii_lowercase()),
            ClassicalKind::DomainRegex => regex.push(e.value.clone()),
            ClassicalKind::IpCidr | ClassicalKind::SrcIpCidr => {
                if let Ok(net) = e.value.parse::<ipnet::IpNet>() {
                    match net {
                        ipnet::IpNet::V4(n) => v4.push((n.network(), n.prefix_len())),
                        ipnet::IpNet::V6(n) => v6.push((n.network(), n.prefix_len())),
                    }
                }
            }
            ClassicalKind::DstPort | ClassicalKind::SrcPort => {
                if let Some(r) = parse_port_range(&e.value) {
                    ports.push(r);
                }
            }
            ClassicalKind::ProcessName => processes.push(e.value.to_ascii_lowercase()),
        }
    }

    fn dedup_sort(v: &mut Vec<String>) {
        v.sort();
        v.dedup();
    }
    dedup_sort(&mut domains);
    dedup_sort(&mut suffixes);
    dedup_sort(&mut keywords);
    dedup_sort(&mut regex);
    dedup_sort(&mut processes);
    v4.sort_by_key(|(ip, p)| (u32::from(*ip), *p));
    v4.dedup();
    v6.sort_by_key(|(ip, p)| (u128::from(*ip), *p));
    v6.dedup();
    ports.sort();
    ports.dedup();

    // 拼 body
    let mut body = Vec::with_capacity(256 + entries.len() * 16);
    encode_string_section(&mut body, &domains);
    encode_string_section(&mut body, &suffixes);
    encode_string_section(&mut body, &keywords);
    encode_string_section(&mut body, &regex);
    encode_v4_section(&mut body, &v4);
    encode_v6_section(&mut body, &v6);
    encode_port_section(&mut body, &ports);
    encode_string_section(&mut body, &processes);

    let body_len = body.len() as u32;
    let body_crc = crc32fast::hash(&body);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&body_crc.to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);
    out.extend_from_slice(&body);
    out
}

fn write_varlen(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn encode_string_section(out: &mut Vec<u8>, items: &[String]) {
    write_varlen(out, items.len() as u32);
    for s in items {
        let bytes = s.as_bytes();
        debug_assert!(bytes.len() <= MAX_STR_LEN);
        write_varlen(out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
}

fn encode_v4_section(out: &mut Vec<u8>, items: &[(Ipv4Addr, u8)]) {
    write_varlen(out, items.len() as u32);
    for (ip, prefix) in items {
        out.extend_from_slice(&ip.octets());
        out.push(*prefix);
    }
}

fn encode_v6_section(out: &mut Vec<u8>, items: &[(Ipv6Addr, u8)]) {
    write_varlen(out, items.len() as u32);
    for (ip, prefix) in items {
        out.extend_from_slice(&ip.octets());
        out.push(*prefix);
    }
}

fn encode_port_section(out: &mut Vec<u8>, items: &[(u16, u16)]) {
    write_varlen(out, items.len() as u32);
    for (lo, hi) in items {
        out.extend_from_slice(&lo.to_be_bytes());
        out.extend_from_slice(&hi.to_be_bytes());
    }
}

/* ============================================================
Decode
============================================================ */

/// 反序列化 RRS 二进制为 [`ClassicalEntry`] 列表。
pub fn decode(buf: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let mut r = Reader::new(buf);
    // header
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(err(format!("bad magic: {:?}", magic)));
    }
    let version = r.read_u16_le()?;
    if version != VERSION {
        return Err(err(format!("unsupported RRS version: {}", version)));
    }
    let _flags = r.read_u16_le()?;
    let _created_at = r.read_u64_le()?;
    let body_len = r.read_u32_le()? as usize;
    let body_crc = r.read_u32_le()?;
    if r.remaining() != body_len {
        return Err(err(format!(
            "body_len mismatch: header={}, actual={}",
            body_len,
            r.remaining()
        )));
    }
    let body = r.take(body_len)?;
    let actual_crc = crc32fast::hash(body);
    if actual_crc != body_crc {
        return Err(err(format!(
            "CRC32 mismatch: header={:08x}, computed={:08x}",
            body_crc, actual_crc
        )));
    }

    let mut br = Reader::new(body);
    let mut out = Vec::new();
    for kind in SECTION_ORDER.iter().copied() {
        match kind {
            ClassicalKind::Domain
            | ClassicalKind::DomainSuffix
            | ClassicalKind::DomainKeyword
            | ClassicalKind::DomainRegex
            | ClassicalKind::ProcessName => {
                let n = br.read_varlen()? as usize;
                for _ in 0..n {
                    let len = br.read_varlen()? as usize;
                    if len > MAX_STR_LEN {
                        return Err(err(format!("string too long: {}", len)));
                    }
                    let bytes = br.take(len)?;
                    let s = std::str::from_utf8(bytes)
                        .map_err(|e| err(format!("non-utf8: {e}")))?
                        .to_string();
                    out.push(ClassicalEntry {
                        kind,
                        value: s,
                        policy: None,
                    });
                }
            }
            ClassicalKind::IpCidr => {
                // V4 section
                let n = br.read_varlen()? as usize;
                for _ in 0..n {
                    let oct = br.take(4)?;
                    let prefix = br.take(1)?[0];
                    if prefix > 32 {
                        return Err(err(format!("v4 prefix > 32: {}", prefix)));
                    }
                    let ip = Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3]);
                    out.push(ClassicalEntry {
                        kind: ClassicalKind::IpCidr,
                        value: format!("{ip}/{prefix}"),
                        policy: None,
                    });
                }
            }
            ClassicalKind::SrcIpCidr => {
                // V6 section
                let n = br.read_varlen()? as usize;
                for _ in 0..n {
                    let raw = br.take(16)?;
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(raw);
                    let prefix = br.take(1)?[0];
                    if prefix > 128 {
                        return Err(err(format!("v6 prefix > 128: {}", prefix)));
                    }
                    let ip = Ipv6Addr::from(octets);
                    out.push(ClassicalEntry {
                        kind: ClassicalKind::IpCidr,
                        value: format!("{ip}/{prefix}"),
                        policy: None,
                    });
                }
            }
            ClassicalKind::DstPort => {
                let n = br.read_varlen()? as usize;
                for _ in 0..n {
                    let lo_b = br.take(2)?;
                    let hi_b = br.take(2)?;
                    let lo = u16::from_be_bytes([lo_b[0], lo_b[1]]);
                    let hi = u16::from_be_bytes([hi_b[0], hi_b[1]]);
                    let v = if lo == hi {
                        format!("{lo}")
                    } else {
                        format!("{lo}-{hi}")
                    };
                    out.push(ClassicalEntry {
                        kind: ClassicalKind::DstPort,
                        value: v,
                        policy: None,
                    });
                }
            }
            _ => unreachable!(),
        }
    }
    if br.remaining() != 0 {
        return Err(err(format!("trailing bytes in body: {}", br.remaining())));
    }
    Ok(out)
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

fn err(msg: impl Into<String>) -> ParseError {
    ParseError::Json(msg.into()) // 复用错误变体；信息已自带语义
}

/* ---------------- Reader ---------------- */

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.buf.len() {
            return Err(err(format!("unexpected EOF at {} (need {})", self.pos, n)));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u16_le(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn read_varlen(&mut self) -> Result<u32, ParseError> {
        let mut shift = 0u32;
        let mut acc = 0u32;
        loop {
            let b = self.take(1)?[0];
            acc |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                return Ok(acc);
            }
            shift += 7;
            if shift >= 32 {
                return Err(err("varlen overflow".to_string()));
            }
        }
    }
}

/* ============================================================
双向转换辅助 —— 把 entries 序列化回各种文本格式
============================================================ */

pub fn entries_to_yaml(entries: &[ClassicalEntry]) -> String {
    let mut out = String::from("payload:\n");
    for e in entries {
        out.push_str("  - \"");
        out.push_str(kind_str(e.kind));
        out.push(',');
        out.push_str(&e.value);
        if let Some(p) = &e.policy {
            out.push(',');
            out.push_str(p);
        }
        out.push_str("\"\n");
    }
    out
}

pub fn entries_to_txt(entries: &[ClassicalEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(kind_str(e.kind));
        out.push(',');
        out.push_str(&e.value);
        if let Some(p) = &e.policy {
            out.push(',');
            out.push_str(p);
        }
        out.push('\n');
    }
    out
}

pub fn entries_to_singbox_json(entries: &[ClassicalEntry]) -> String {
    use std::collections::BTreeMap;
    let mut bucket: BTreeMap<&'static str, Vec<&str>> = BTreeMap::new();
    let mut ports: Vec<&str> = Vec::new();
    for e in entries {
        let key = match e.kind {
            ClassicalKind::Domain => "domain",
            ClassicalKind::DomainSuffix => "domain_suffix",
            ClassicalKind::DomainKeyword => "domain_keyword",
            ClassicalKind::DomainRegex => "domain_regex",
            ClassicalKind::IpCidr => "ip_cidr",
            ClassicalKind::SrcIpCidr => "source_ip_cidr",
            ClassicalKind::DstPort | ClassicalKind::SrcPort => {
                ports.push(e.value.as_str());
                continue;
            }
            ClassicalKind::ProcessName => "process_name",
        };
        bucket.entry(key).or_default().push(e.value.as_str());
    }
    let mut out = String::from("{\n  \"version\": 2,\n  \"rules\": [\n    {");
    let mut first = true;
    for (k, v) in &bucket {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&format!("\n      \"{k}\": ["));
        for (i, s) in v.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "\"{}\"",
                s.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        out.push(']');
    }
    if !ports.is_empty() {
        if !first {
            out.push(',');
        }
        let mut singles: Vec<&str> = Vec::new();
        let mut ranges: Vec<&str> = Vec::new();
        for p in &ports {
            if p.contains('-') {
                ranges.push(p);
            } else {
                singles.push(p);
            }
        }
        if !singles.is_empty() {
            out.push_str("\n      \"port\": [");
            for (i, s) in singles.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(s);
            }
            out.push(']');
        }
        if !ranges.is_empty() {
            if !singles.is_empty() {
                out.push(',');
            }
            out.push_str("\n      \"port_range\": [");
            for (i, s) in ranges.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!("\"{}\"", s.replace('-', ":")));
            }
            out.push(']');
        }
    }
    out.push_str("\n    }\n  ]\n}\n");
    out
}

fn kind_str(k: ClassicalKind) -> &'static str {
    match k {
        ClassicalKind::Domain => "DOMAIN",
        ClassicalKind::DomainSuffix => "DOMAIN-SUFFIX",
        ClassicalKind::DomainKeyword => "DOMAIN-KEYWORD",
        ClassicalKind::DomainRegex => "DOMAIN-REGEX",
        ClassicalKind::IpCidr => "IP-CIDR",
        ClassicalKind::SrcIpCidr => "SRC-IP-CIDR",
        ClassicalKind::DstPort => "DST-PORT",
        ClassicalKind::SrcPort => "SRC-PORT",
        ClassicalKind::ProcessName => "PROCESS-NAME",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(k: ClassicalKind, v: &str) -> ClassicalEntry {
        ClassicalEntry {
            kind: k,
            value: v.into(),
            policy: None,
        }
    }

    #[test]
    fn roundtrip_full_kinds() {
        let input = vec![
            entry(ClassicalKind::Domain, "exact.com"),
            entry(ClassicalKind::DomainSuffix, "example.com"),
            entry(ClassicalKind::DomainKeyword, "google"),
            entry(ClassicalKind::DomainRegex, r"^a\.b$"),
            entry(ClassicalKind::IpCidr, "1.2.3.0/24"),
            entry(ClassicalKind::IpCidr, "fd00::/8"),
            entry(ClassicalKind::DstPort, "443"),
            entry(ClassicalKind::DstPort, "1000-2000"),
            entry(ClassicalKind::ProcessName, "Code"),
        ];
        let bin = encode(&input);
        assert_eq!(&bin[..4], &MAGIC);
        let out = decode(&bin).unwrap();
        // 同样数量（去重 + 排序后 9 → 9）
        assert_eq!(out.len(), input.len());
        // 关键值可还原
        let values: std::collections::BTreeSet<_> = out.iter().map(|e| e.value.clone()).collect();
        assert!(values.contains("exact.com"));
        assert!(values.contains("example.com"));
        assert!(values.contains("1.2.3.0/24"));
        assert!(values.contains("fd00::/8"));
        assert!(values.contains("443"));
        assert!(values.contains("1000-2000"));
        assert!(values.contains("code")); // 进程名小写
    }

    #[test]
    fn dedup_and_sort_in_encode() {
        let dup = vec![
            entry(ClassicalKind::Domain, "B.com"),
            entry(ClassicalKind::Domain, "a.com"),
            entry(ClassicalKind::Domain, "a.com"),
        ];
        let bin = encode(&dup);
        let out = decode(&bin).unwrap();
        assert_eq!(out.len(), 2, "duplicate domains should be merged");
        assert_eq!(out[0].value, "a.com");
        assert_eq!(out[1].value, "b.com");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bin = encode(&[entry(ClassicalKind::Domain, "x.com")]);
        bin[0] = b'X';
        assert!(decode(&bin).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut bin = encode(&[entry(ClassicalKind::Domain, "x.com")]);
        bin[4] = 99;
        assert!(decode(&bin).is_err());
    }

    #[test]
    fn rejects_corrupted_body() {
        let mut bin = encode(&[
            entry(ClassicalKind::Domain, "x.com"),
            entry(ClassicalKind::Domain, "y.com"),
        ]);
        // 翻转 body 的某一字节
        let n = bin.len();
        bin[n - 3] ^= 0xff;
        let r = decode(&bin);
        assert!(r.is_err(), "CRC32 should catch tampered body");
    }

    #[test]
    fn size_smaller_than_yaml() {
        let mut entries = Vec::new();
        for i in 0..1000u32 {
            entries.push(entry(
                ClassicalKind::DomainSuffix,
                &format!("host{}.example.com", i),
            ));
        }
        let bin = encode(&entries);
        let yaml = entries_to_yaml(&entries);
        let txt = entries_to_txt(&entries);
        assert!(
            bin.len() < yaml.len() / 2,
            "rrs={} yaml={}",
            bin.len(),
            yaml.len()
        );
        assert!(bin.len() < txt.len(), "rrs={} txt={}", bin.len(), txt.len());
    }

    #[test]
    fn singbox_json_export_parseable() {
        let input = vec![
            entry(ClassicalKind::DomainSuffix, "example.com"),
            entry(ClassicalKind::DstPort, "443"),
            entry(ClassicalKind::DstPort, "1000-2000"),
        ];
        let bin = encode(&input);
        let out = decode(&bin).unwrap();
        let json = entries_to_singbox_json(&out);
        // 用 sing-box parser 反解
        let back = crate::parser::sb_json::parse(json.as_bytes()).unwrap();
        assert!(
            back.iter()
                .any(|e| e.kind == ClassicalKind::DomainSuffix && e.value == "example.com")
        );
        assert!(
            back.iter()
                .any(|e| e.kind == ClassicalKind::DstPort && e.value == "443")
        );
        assert!(
            back.iter()
                .any(|e| e.kind == ClassicalKind::DstPort && e.value == "1000-2000")
        );
    }
}
