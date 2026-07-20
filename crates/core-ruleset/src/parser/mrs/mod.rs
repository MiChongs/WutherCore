//! mihomo MRS v1 二进制规则集解析器（只读）。
//!
//! 完整流程兼容 MetaCubeX/mihomo `rules/provider/mrs_reader.go::rulesMrsParse`
//!（`Alpha` / `Meta` 内核分支）：
//! ```text
//!  原始 .mrs 字节流
//!         │
//!         ▼ ruzstd 解压（流式）
//!  +------+----+   +----------+   +---------------+   +------------+
//!  | magic 4B  |→  | behavior |→  | count i64BE   |→  | extra_len  |
//!  | "MRS\x01" |   | 1B (0/1) |   | （仅日志统计） |   | i64BE + 跳过|
//!  +-----------+   +----------+   +---------------+   +------------+
//!         │                               │
//!         ▼                               ▼
//!   behavior=0: domain_set::read     behavior=1: ipcidr_set::read
//!         │                               │
//!         ▼                               ▼
//!  MrsPayload::Domain(set)         MrsPayload::IpCidr(set)
//! ```
//!
//! ## 公开类型
//! * [`MrsPayload`] —— 解析结果，被 [`crate::parser::RulesetCompiled`] 包装。
//! * [`parse`] —— 入口函数，对应 `binary.rs::parse_mrs` 的真实实现。
//!
//! ## 公开子模块
//! * [`domain_set`] —— Domain Behavior 反序列化与查询。
//! * [`ipcidr_set`] —— IPCIDR Behavior 反序列化与查询。
//! * [`bitmap`] —— Succinct rank/select 位运算（被 domain_set 使用）。

use std::{
    io::{Cursor, Read},
    sync::Arc,
};

use crate::parser::ParseError;

pub mod bitmap;
pub mod domain_set;
pub mod ipcidr_set;

pub use domain_set::MrsDomainSet;
pub use ipcidr_set::MrsIpCidrSet;

const MRS_MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];

const BEHAVIOR_DOMAIN: u8 = 0;
const BEHAVIOR_IPCIDR: u8 = 1;
const BEHAVIOR_CLASSICAL: u8 = 2;

const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;
const MAX_DECLARED_ITEMS: usize = 16 * 1024 * 1024;
const MAX_EXTRA_BYTES: usize = 4 * 1024 * 1024;

/// 解析后的 MRS 内存结构。
#[derive(Debug)]
pub enum MrsPayload {
    Domain {
        set: Arc<MrsDomainSet>,
        /// header.count —— 仅用于日志/状态展示。
        count: usize,
    },
    IpCidr {
        set: Arc<MrsIpCidrSet>,
        count: usize,
    },
}

impl MrsPayload {
    /// 估算内存占用（字节），用于 manager / API 状态展示。
    pub fn approx_bytes(&self) -> usize {
        match self {
            Self::Domain { set, .. } => set.approx_bytes(),
            Self::IpCidr { set, .. } => set.approx_bytes(),
        }
    }
    pub fn count(&self) -> usize {
        match self {
            Self::Domain { count, .. } => *count,
            Self::IpCidr { count, .. } => *count,
        }
    }
    pub fn behavior_label(&self) -> &'static str {
        match self {
            Self::Domain { .. } => "domain",
            Self::IpCidr { .. } => "ipcidr",
        }
    }
}

/// 解析整个 .mrs body。
pub fn parse(body: &[u8]) -> Result<MrsPayload, ParseError> {
    if body.len() > MAX_COMPRESSED_BYTES {
        return Err(mrs_error(format!(
            "compressed body {} bytes exceeds limit {MAX_COMPRESSED_BYTES}",
            body.len()
        )));
    }
    let decoded = decompress_zstd_bounded(body, MAX_DECOMPRESSED_BYTES)?;
    parse_decompressed(&decoded)
}

fn decompress_zstd_bounded(body: &[u8], maximum: usize) -> Result<Vec<u8>, ParseError> {
    let cursor = Cursor::new(body);
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(cursor)
        .map_err(|e| ParseError::Other(format!("MRS zstd init failed: {e}")))?;
    let declared_size = decoder.decoder.content_size();
    if declared_size != 0 && declared_size > maximum as u64 {
        return Err(mrs_error(format!(
            "zstd declared output {declared_size} bytes exceeds limit {maximum}"
        )));
    }

    let mut output = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let produced = decoder
            .read(&mut buffer)
            .map_err(|error| mrs_error(format!("zstd decode failed: {error}")))?;
        if produced == 0 {
            break;
        }
        let new_length = output
            .len()
            .checked_add(produced)
            .ok_or_else(|| mrs_error("zstd output length overflow"))?;
        if new_length > maximum {
            return Err(mrs_error(format!(
                "zstd output exceeds limit {maximum} bytes"
            )));
        }
        output
            .try_reserve(produced)
            .map_err(|_| mrs_error("zstd output allocation failed"))?;
        output.extend_from_slice(&buffer[..produced]);
    }

    let source = decoder.into_inner();
    if source.position() != body.len() as u64 {
        return Err(mrs_error(format!(
            "compressed stream has {} trailing bytes",
            body.len().saturating_sub(source.position() as usize)
        )));
    }
    Ok(output)
}

fn parse_decompressed(decoded: &[u8]) -> Result<MrsPayload, ParseError> {
    let mut reader = Cursor::new(decoded);
    // 1) magic 4B
    let mut magic = [0u8; 4];
    read_full(&mut reader, &mut magic)?;
    if magic != MRS_MAGIC {
        return Err(ParseError::UnsupportedBinary(
            "MRS magic 不匹配（不是 mihomo MRSv1 文件）",
        ));
    }
    // 2) behavior 1B
    let mut bb = [0u8; 1];
    read_full(&mut reader, &mut bb)?;
    let behavior = bb[0];
    // 3) count i64BE
    // Mihomo's converter never emits a zero count, but its reader accepts it and
    // treats the field as metadata rather than the serialized set's cardinality.
    let count = read_bounded_len(&mut reader, "header count", MAX_DECLARED_ITEMS, true)?;
    // 4) extra_len i64BE + 跳过
    let extra_len = read_bounded_len(&mut reader, "extra_len", MAX_EXTRA_BYTES, true)?;
    discard_exact(&mut reader, extra_len)?;

    // 5) 按 behavior 分发
    let payload = match behavior {
        BEHAVIOR_DOMAIN => {
            let set = MrsDomainSet::read(&mut reader)?;
            MrsPayload::Domain {
                set: Arc::new(set),
                count,
            }
        }
        BEHAVIOR_IPCIDR => {
            let set = MrsIpCidrSet::read(&mut reader)?;
            MrsPayload::IpCidr {
                set: Arc::new(set),
                count,
            }
        }
        BEHAVIOR_CLASSICAL => {
            return Err(ParseError::UnsupportedBinary(
                "mihomo MRS classical behavior 尚未实现（mihomo 主分支也未提供 mrs converter classical 路径）",
            ));
        }
        _ => return Err(ParseError::UnsupportedBinary("MRS behavior 未知（>2）")),
    };
    if reader.position() != decoded.len() as u64 {
        return Err(mrs_error(format!(
            "decompressed payload has {} trailing bytes",
            decoded.len().saturating_sub(reader.position() as usize)
        )));
    }
    Ok(payload)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), ParseError> {
    r.read_exact(buf)
        .map_err(|e| ParseError::Other(format!("MRS read_exact failed ({} bytes): {e}", buf.len())))
}

fn read_i64_be<R: Read>(r: &mut R) -> Result<i64, ParseError> {
    let mut buf = [0u8; 8];
    read_full(r, &mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

fn read_bounded_len<R: Read>(
    reader: &mut R,
    field: &'static str,
    maximum: usize,
    allow_zero: bool,
) -> Result<usize, ParseError> {
    let raw = read_i64_be(reader)?;
    if raw < 0 {
        return Err(mrs_error(format!("{field} is negative")));
    }
    let value = usize::try_from(raw).map_err(|_| mrs_error(format!("{field} exceeds usize")))?;
    if (!allow_zero && value == 0) || value > maximum {
        return Err(mrs_error(format!(
            "{field} {value} is outside allowed range {}..={maximum}",
            usize::from(!allow_zero)
        )));
    }
    Ok(value)
}

fn discard_exact<R: Read>(reader: &mut R, mut length: usize) -> Result<(), ParseError> {
    let mut buffer = [0u8; 16 * 1024];
    while length != 0 {
        let chunk = length.min(buffer.len());
        read_full(reader, &mut buffer[..chunk])?;
        length -= chunk;
    }
    Ok(())
}

fn mrs_error(message: impl Into<String>) -> ParseError {
    ParseError::Other(format!("MRS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    fn push_i64(bytes: &mut Vec<u8>, value: i64) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn minimal_domain_payload(count: i64, extra: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MRS_MAGIC);
        bytes.push(BEHAVIOR_DOMAIN);
        push_i64(&mut bytes, count);
        push_i64(&mut bytes, extra.len() as i64);
        bytes.extend_from_slice(extra);
        bytes.push(1); // domain-set version
        push_i64(&mut bytes, 1);
        bytes.extend_from_slice(&0b10u64.to_be_bytes()); // child node is terminal
        push_i64(&mut bytes, 1);
        bytes.extend_from_slice(&0b110u64.to_be_bytes()); // root edge + two delimiters
        push_i64(&mut bytes, 1);
        bytes.push(b'a');
        bytes
    }

    fn compress(bytes: &[u8]) -> Vec<u8> {
        compress_to_vec(bytes, CompressionLevel::Fastest)
    }

    #[test]
    fn rejects_garbage() {
        let body = b"not zstd at all";
        let err = parse(body).unwrap_err();
        // 任何错误都接受 —— 主要确保不 panic
        let _ = format!("{err}");
    }

    #[test]
    fn rejects_empty() {
        let body = b"";
        assert!(parse(body).is_err());
    }

    #[test]
    fn parses_valid_bounded_frame_and_extra_header() {
        let body = compress(&minimal_domain_payload(1, b"future-header"));
        let payload = parse(&body).unwrap();
        match payload {
            MrsPayload::Domain { set, count } => {
                assert_eq!(count, 1);
                assert!(set.has("a"));
            }
            MrsPayload::IpCidr { .. } => panic!("unexpected behavior"),
        }
    }

    #[test]
    fn rejects_zstd_output_over_limit() {
        let body = compress(&vec![0u8; 4096]);
        assert!(decompress_zstd_bounded(&body, 128).is_err());
    }

    #[test]
    fn rejects_compressed_and_decompressed_trailing_bytes() {
        let raw = minimal_domain_payload(1, &[]);

        let mut compressed_trailing = compress(&raw);
        compressed_trailing.push(0xa5);
        assert!(parse(&compressed_trailing).is_err());

        let mut decoded_trailing = raw;
        decoded_trailing.push(0xa5);
        assert!(parse(&compress(&decoded_trailing)).is_err());
    }

    #[test]
    fn accepts_zero_header_count_for_reader_compatibility() {
        let payload = parse(&compress(&minimal_domain_payload(0, &[]))).unwrap();
        match payload {
            MrsPayload::Domain { set, count } => {
                assert_eq!(count, 0);
                assert!(set.has("a"));
            }
            MrsPayload::IpCidr { .. } => panic!("unexpected behavior"),
        }
    }

    #[test]
    fn rejects_header_count_and_extra_length_outside_bounds() {
        let negative_count = compress(&minimal_domain_payload(-1, &[]));
        assert!(parse(&negative_count).is_err());

        let oversized_count = compress(&minimal_domain_payload(
            (MAX_DECLARED_ITEMS as i64) + 1,
            &[],
        ));
        assert!(parse(&oversized_count).is_err());

        let mut oversized_extra = Vec::new();
        oversized_extra.extend_from_slice(&MRS_MAGIC);
        oversized_extra.push(BEHAVIOR_DOMAIN);
        push_i64(&mut oversized_extra, 1);
        push_i64(&mut oversized_extra, (MAX_EXTRA_BYTES as i64) + 1);
        assert!(parse(&compress(&oversized_extra)).is_err());
    }

    #[test]
    fn rejects_truncated_extra_header() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&MRS_MAGIC);
        raw.push(BEHAVIOR_DOMAIN);
        push_i64(&mut raw, 1);
        push_i64(&mut raw, 4);
        raw.extend_from_slice(&[1, 2]);
        assert!(parse(&compress(&raw)).is_err());
    }
}
