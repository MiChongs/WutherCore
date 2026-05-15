//! mihomo MRS v1 二进制规则集解析器（只读）。
//!
//! 完整流程（与 `mihomo-smart/rules/provider/mrs_reader.go::rulesMrsParse` 一致）：
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

use std::{io::Read, sync::Arc};

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
    // ruzstd::StreamingDecoder 需要 BufRead；用 std::io::Cursor 即可。
    let cursor = std::io::Cursor::new(body);
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(cursor)
        .map_err(|e| ParseError::Other(format!("MRS zstd init failed: {e}")))?;

    // 1) magic 4B
    let mut magic = [0u8; 4];
    read_full(&mut decoder, &mut magic)?;
    if magic != MRS_MAGIC {
        return Err(ParseError::UnsupportedBinary(
            "MRS magic 不匹配（不是 mihomo MRSv1 文件）",
        ));
    }
    // 2) behavior 1B
    let mut bb = [0u8; 1];
    read_full(&mut decoder, &mut bb)?;
    let behavior = bb[0];
    // 3) count i64BE
    let count = read_i64_be(&mut decoder)? as i64;
    if count < 0 {
        return Err(ParseError::UnsupportedBinary("MRS count 非法（< 0）"));
    }
    // 4) extra_len i64BE + 跳过
    let extra_len = read_i64_be(&mut decoder)?;
    if extra_len < 0 {
        return Err(ParseError::UnsupportedBinary("MRS extra_len 非法（< 0）"));
    }
    if extra_len > 0 {
        let mut extra = vec![0u8; extra_len as usize];
        read_full(&mut decoder, &mut extra)?;
    }
    // 5) 按 behavior 分发
    match behavior {
        BEHAVIOR_DOMAIN => {
            let set = MrsDomainSet::read(&mut decoder)?;
            Ok(MrsPayload::Domain {
                set: Arc::new(set),
                count: count as usize,
            })
        }
        BEHAVIOR_IPCIDR => {
            let set = MrsIpCidrSet::read(&mut decoder)?;
            Ok(MrsPayload::IpCidr {
                set: Arc::new(set),
                count: count as usize,
            })
        }
        BEHAVIOR_CLASSICAL => Err(ParseError::UnsupportedBinary(
            "mihomo MRS classical behavior 尚未实现（mihomo 主分支也未提供 mrs converter classical 路径）",
        )),
        _ => Err(ParseError::UnsupportedBinary("MRS behavior 未知（>2）")),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let _ = parse(body).err();
    }
}
