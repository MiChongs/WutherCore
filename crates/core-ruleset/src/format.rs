//! 规则集格式枚举 + 自动嗅探。

use std::{
    io::{Cursor, Read},
    path::Path,
};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MRS_MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];
const MAX_MRS_SNIFF_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetFormat {
    /// mihomo / Clash payload yaml
    Yaml,
    /// 每行一条规则的 txt / list
    Text,
    /// sing-box ruleset JSON `{"version":N,"rules":[...]}`
    SingboxJson,
    /// mihomo binary（MRS）—— 嗅探后回退错误
    Mrs,
    /// sing-box binary（SRS）—— 嗅探后回退错误
    Srs,
    /// **WutherCore 自研二进制**：magic "RRS\0" + CRC32
    Rrs,
    Unknown,
}

/// 综合：1) 用户显式指定 → 2) 文件扩展名 → 3) 内容魔数。
pub fn detect_format(hint: Option<&str>, path: Option<&str>, body: &[u8]) -> RulesetFormat {
    if let Some(h) = hint {
        // An explicit but misspelled format must not silently fall through to a
        // different parser.
        return parse_hint(h).unwrap_or(RulesetFormat::Unknown);
    }
    if let Some(p) = path {
        if let Some(f) = from_extension(p) {
            return f;
        }
    }
    sniff(body)
}

fn parse_hint(s: &str) -> Option<RulesetFormat> {
    Some(match s.to_ascii_lowercase().as_str() {
        "yaml" | "yml" => RulesetFormat::Yaml,
        "txt" | "list" | "text" => RulesetFormat::Text,
        "json" | "singbox" | "sing-box" => RulesetFormat::SingboxJson,
        "mrs" | "mihomo-binary" => RulesetFormat::Mrs,
        "srs" | "singbox-binary" => RulesetFormat::Srs,
        "rrs" | "wuthercore" | "wuthercore-binary" => RulesetFormat::Rrs,
        _ => return None,
    })
}

fn from_extension(path: &str) -> Option<RulesetFormat> {
    // URLs commonly carry cache-busting query strings or fragments. They are
    // not part of the filename extension.
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "yaml" | "yml" => RulesetFormat::Yaml,
        "txt" | "list" => RulesetFormat::Text,
        "json" => RulesetFormat::SingboxJson,
        "mrs" => RulesetFormat::Mrs,
        "srs" => RulesetFormat::Srs,
        "rrs" => RulesetFormat::Rrs,
        _ => return None,
    })
}

fn sniff(body: &[u8]) -> RulesetFormat {
    if body.is_empty() {
        return RulesetFormat::Unknown;
    }
    // WutherCore RRS：magic = "RRS\0"
    if body.starts_with(&crate::rrs::MAGIC) {
        return RulesetFormat::Rrs;
    }
    // MRS wraps its complete payload, including `MRS\x01`, in zstd. Decode only
    // the four-byte prefix so extensionless/CDN URLs are still detectable
    // without inflating an attacker-controlled body.
    if sniff_compressed_mrs(body) {
        return RulesetFormat::Mrs;
    }
    // sing-box SRS：magic = "SRS\0" 0x53 0x52 0x53
    if body.starts_with(b"SRS") || body.starts_with(b"\x53\x52\x53") {
        return RulesetFormat::Srs;
    }
    // 文本：从前 256 字节判断
    let head = &body[..body.len().min(2048)];
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        if trimmed.contains("\"rules\"") {
            return RulesetFormat::SingboxJson;
        }
    }
    if trimmed.starts_with("payload:") || trimmed.contains("\npayload:") {
        return RulesetFormat::Yaml;
    }
    // 含 "DOMAIN," 或 "IP-CIDR," 关键字 → 文本
    if trimmed.contains("DOMAIN") || trimmed.contains("IP-CIDR") || trimmed.contains("PROCESS-NAME")
    {
        return RulesetFormat::Text;
    }
    // 默认按 text 试一次
    RulesetFormat::Text
}

fn sniff_compressed_mrs(body: &[u8]) -> bool {
    if body.len() > MAX_MRS_SNIFF_BYTES || !body.starts_with(&ZSTD_MAGIC) {
        return false;
    }
    let Ok(mut decoder) = ruzstd::decoding::StreamingDecoder::new(Cursor::new(body)) else {
        return false;
    };
    let mut magic = [0u8; MRS_MAGIC.len()];
    decoder.read_exact(&mut magic).is_ok() && magic == MRS_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    #[test]
    fn detects_compressed_mrs_without_filename_extension() {
        let body = compress_to_vec(
            &b"MRS\x01\x00\x00\x00\x00\x00\x00\x00\x00"[..],
            CompressionLevel::Fastest,
        );
        assert_eq!(
            detect_format(None, Some("https://cdn.example/download"), &body),
            RulesetFormat::Mrs
        );
    }

    #[test]
    fn strips_url_query_and_fragment_before_extension_detection() {
        assert_eq!(
            detect_format(
                None,
                Some("https://cdn.example/geosite.mrs?token=abc#download"),
                b""
            ),
            RulesetFormat::Mrs
        );
        assert_eq!(
            detect_format(None, Some("https://cdn.example/geosite.srs?v=5"), b""),
            RulesetFormat::Srs
        );
    }

    #[test]
    fn rejects_unknown_explicit_hint_instead_of_guessing() {
        assert_eq!(
            detect_format(Some("mrss"), Some("geosite.mrs"), b"MRS"),
            RulesetFormat::Unknown
        );
    }

    #[test]
    fn does_not_misclassify_other_zstd_payloads_as_mrs() {
        let body = compress_to_vec(&b"not an MRS payload"[..], CompressionLevel::Fastest);
        assert_ne!(detect_format(None, None, &body), RulesetFormat::Mrs);
    }
}
