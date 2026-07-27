//! XHTTP X-Padding —— 与 mihomo `transport/xhttp/xpadding.go` 等价。
//!
//! ## 两种 padding 方法
//!
//! * **repeat-x**：长度 N 的 'X' 字符（HPACK Huffman 编码 'X' 是 8 bit，与原始一致）
//! * **tokenish**：随机 base62 字符串，调整长度使 HPACK Huffman 编码后接近 target
//!
//! ## 放置位置
//!
//! padding 可放在：header / queryInHeader / cookie / query

use rand::RngCore;

/// 长度调整迭代上限
const MAX_ADJUST_ITER: usize = 150;
/// 校验容差（Huffman 长度）
pub const VALIDATION_TOLERANCE: i32 = 2;

/// HPACK base62 字符集 Huffman 平均比例（实测约 0.8 字节/字符）
const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;

const CHARSET_BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMethod {
    RepeatX,
    Tokenish,
}

impl PaddingMethod {
    pub fn parse(s: &str) -> Self {
        match s {
            "tokenish" => Self::Tokenish,
            "repeat-x" | _ => Self::RepeatX,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct XPaddingPlacement {
    pub placement: String,
    pub key: String,
    pub header: String,
    pub raw_url: String,
}

#[derive(Debug, Clone, Default)]
pub struct XPaddingConfig {
    pub length: usize,
    pub placement: XPaddingPlacement,
    pub method: PaddingMethod,
}

impl Default for PaddingMethod {
    fn default() -> Self {
        Self::RepeatX
    }
}

/// 生成 padding 字符串
pub fn generate_padding(method: PaddingMethod, length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    match method {
        PaddingMethod::RepeatX => "X".repeat(length),
        PaddingMethod::Tokenish => {
            let s = generate_tokenish_padding_base62(length as i32);
            if s.is_empty() { "X".repeat(length) } else { s }
        }
    }
}

/// Validate an incoming padding value against the configured on-wire range.
///
/// `repeat-x` is measured as raw bytes because the value is deliberately made
/// of the HPACK/QPACK eight-bit `X` code. `tokenish` is measured after the
/// RFC 7541 Huffman transform, matching Xray's server-side validation.
pub fn is_padding_valid(method: PaddingMethod, value: &str, min: usize, max: usize) -> bool {
    if value.is_empty() || min > max {
        return false;
    }

    match method {
        // Xray validates the encoded length here, not the alphabet.  The
        // client generator still emits only `X`, but accepting any value of
        // the configured length is required for wire compatibility with
        // alternate clients and with Xray's own server.
        PaddingMethod::RepeatX => (min..=max).contains(&value.len()),
        PaddingMethod::Tokenish => {
            let encoded = huffman_encode_length(value);
            let min = min.saturating_sub(VALIDATION_TOLERANCE as usize);
            let max = max.saturating_add(VALIDATION_TOLERANCE as usize);
            (min..=max).contains(&encoded)
        }
    }
}

pub fn generate_tokenish_padding_base62(target_huffman_bytes: i32) -> String {
    if target_huffman_bytes <= 0 {
        return String::new();
    }
    let mut n = (target_huffman_bytes as f64 / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).ceil() as usize;
    if n < 1 {
        n = 1;
    }
    let mut s = match rand_string_from_charset(n, CHARSET_BASE62) {
        Some(v) => v,
        None => return String::new(),
    };

    let mut adjust_char = b'X';
    for _ in 0..MAX_ADJUST_ITER {
        let cur = huffman_encode_length(&s) as i32;
        let diff = cur - target_huffman_bytes;
        if diff.abs() <= VALIDATION_TOLERANCE {
            return s;
        }
        if diff < 0 {
            s.push(adjust_char as char);
            adjust_char = if adjust_char == b'X' { b'Z' } else { b'X' };
        } else {
            if s.len() <= 1 {
                return s;
            }
            s.pop();
        }
    }
    s
}

fn rand_string_from_charset(n: usize, charset: &[u8]) -> Option<String> {
    if n == 0 || charset.is_empty() {
        return None;
    }
    let m = charset.len();
    let limit = 256 - (256 % m);
    let mut result = Vec::with_capacity(n);
    let mut buf = [0u8; 256];
    while result.len() < n {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        for &rb in buf.iter() {
            if (rb as usize) >= limit {
                continue;
            }
            result.push(charset[(rb as usize) % m]);
            if result.len() == n {
                break;
            }
        }
    }
    String::from_utf8(result).ok()
}

/// HPACK 静态 Huffman 编码长度（RFC 7541 Appendix B）。
/// 我们仅实现 ASCII 子集（base62 + 常见标点），用于估算 padding 大小。
pub fn huffman_encode_length(s: &str) -> usize {
    let mut total_bits = 0u64;
    for &b in s.as_bytes() {
        total_bits += HPACK_HUFFMAN_LEN_TABLE[b as usize] as u64;
    }
    ((total_bits + 7) / 8) as usize
}

/// HPACK 静态 Huffman 表的位长度（RFC 7541 Appendix B 完整表）
const HPACK_HUFFMAN_LEN_TABLE: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 0..15
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 16..31
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 32..47 (' '..'/')
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 48..63 ('0'..'?')
    13, 6, 7, 7, 7, 7, 7, 8, 8, 7, 8, 8, 8, 7, 7, 7, // 64..79 ('@'..'O')
    8, 7, 7, 7, 7, 8, 7, 8, 8, 8, 7, 13, 19, 13, 14, 6, // 80..95 ('P'..'_')
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, // 96..111 ('`'..'o')
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, // 112..127 ('p'..127)
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, // 128..143
    24, 24, 22, 23, 24, 23, 23, 24, 23, 23, 23, 23, 24, 23, 24, 23, // 144..159
    21, 22, 23, 22, 23, 23, 24, 24, 23, 22, 23, 24, 23, 23, 24, 24, // 160..175
    23, 23, 23, 23, 23, 24, 23, 24, 23, 24, 23, 23, 24, 25, 25, 24, // 176..191
    25, 26, 25, 27, 26, 26, 26, 27, 27, 26, 27, 27, 27, 27, 26, 27, // 192..207
    25, 27, 27, 27, 27, 27, 27, 27, 24, 26, 26, 26, 26, 27, 27, 27, // 208..223
    27, 27, 27, 27, 27, 27, 27, 26, 27, 26, 27, 27, 27, 27, 27, 27, // 224..239
    27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 27, 30, 30, 30, 30, // 240..255
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_x_length() {
        let s = generate_padding(PaddingMethod::RepeatX, 100);
        assert_eq!(s.len(), 100);
        assert!(s.chars().all(|c| c == 'X'));
    }

    #[test]
    fn empty_length() {
        assert_eq!(generate_padding(PaddingMethod::RepeatX, 0), "");
        assert_eq!(generate_padding(PaddingMethod::Tokenish, 0), "");
    }

    #[test]
    fn tokenish_close_to_target() {
        let target = 200;
        let s = generate_padding(PaddingMethod::Tokenish, target);
        let actual = huffman_encode_length(&s) as i32;
        assert!(
            (actual - target as i32).abs() <= VALIDATION_TOLERANCE + 5,
            "tokenish length deviation too large: {} vs {}",
            actual,
            target
        );
    }

    #[test]
    fn huffman_basic_chars_known_lengths() {
        // RFC 7541 Appendix B 已知值
        // ' ' (32) = 6 bits
        assert_eq!(HPACK_HUFFMAN_LEN_TABLE[b' ' as usize], 6);
        // 'a' (97) = 5 bits
        assert_eq!(HPACK_HUFFMAN_LEN_TABLE[b'a' as usize], 5);
        // 'e' (101) = 5 bits
        assert_eq!(HPACK_HUFFMAN_LEN_TABLE[b'e' as usize], 5);
    }

    #[test]
    fn huffman_repeat_x_returns_byte_count() {
        // N 个 X 的 Huffman 长度 ≈ N 字节（因为 'X' 是 7-8 位）
        for n in 1..50 {
            let s = "X".repeat(n);
            let len = huffman_encode_length(&s);
            // 容差：N*7/8 .. N*8/8 + 1
            let lower = (n * 7 + 7) / 8;
            let upper = (n * 8 + 7) / 8;
            assert!(
                len >= lower && len <= upper,
                "n={n}, expected [{lower},{upper}], got {len}"
            );
        }
    }

    #[test]
    fn rand_string_charset() {
        let s = rand_string_from_charset(20, CHARSET_BASE62).unwrap();
        assert_eq!(s.len(), 20);
        for c in s.chars() {
            assert!(c.is_ascii_alphanumeric());
        }
    }

    #[test]
    fn padding_method_parse() {
        assert_eq!(PaddingMethod::parse("tokenish"), PaddingMethod::Tokenish);
        assert_eq!(PaddingMethod::parse("repeat-x"), PaddingMethod::RepeatX);
        assert_eq!(PaddingMethod::parse(""), PaddingMethod::RepeatX);
    }

    #[test]
    fn repeat_x_validation_matches_xray_length_only_semantics() {
        assert!(is_padding_valid(PaddingMethod::RepeatX, "XXXXX", 5, 5));
        assert!(is_padding_valid(PaddingMethod::RepeatX, "XXYXX", 5, 5));
        assert!(!is_padding_valid(PaddingMethod::RepeatX, "XXXX", 5, 5));
    }

    #[test]
    fn tokenish_validation_uses_huffman_length_without_alphabet_restriction() {
        let value = generate_padding(PaddingMethod::Tokenish, 128);
        assert!(is_padding_valid(PaddingMethod::Tokenish, &value, 128, 128));
        let punctuation = "!@#$%^&*()";
        let encoded = huffman_encode_length(punctuation);
        assert!(is_padding_valid(
            PaddingMethod::Tokenish,
            punctuation,
            encoded,
            encoded,
        ));
    }
}
