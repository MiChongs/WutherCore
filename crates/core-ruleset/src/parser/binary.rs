//! 二进制规则集 —— mihomo MRS / sing-box SRS 入口适配。
//!
//! **MRS**：完整支持（domain succinct trie + ipcidr range list + zstd 解压）。
//! 真正的解析在 [`crate::parser::mrs`] 子模块；本文件只是把 MRS 的预编译产物
//! 强制塞回老 API（`Vec<ClassicalEntry>`）—— 因为信息损失，**老 API 不能复
//! 现 trie wildcard 语义**。生产路径请改走 [`crate::parser::parse_ruleset_compiled`]，
//! 它会保留 `RulesetCompiled::Mrs` 以零拷贝挂到 matcher。
//!
//! **SRS**：sing-box 二进制规则集，结构与 MRS 完全不同（gob-like + 自定义版本协议），
//! 暂未实现。等上游 spec 稳定再补。

use crate::{
    matcher::ClassicalEntry,
    parser::{ParseError, mrs},
};

/// 老 API：把 MRS 解析成 `Vec<ClassicalEntry>`。
///
/// **注意**：MRS 的 domain succinct trie 不能无损展开成 ClassicalEntry —— 70k
/// 域名展开会爆内存且丢失 wildcard 语义。本函数仅对 ipcidr behavior 做"尽力
/// 转换"（每个 IpRange 拆成若干 CIDR）；domain behavior 直接报错引导用户走
/// `parse_ruleset_compiled` 新 API。
pub fn parse_mrs(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let payload = mrs::parse(body)?;
    match payload {
        mrs::MrsPayload::Domain { count, .. } => Err(ParseError::UnsupportedBinary(Box::leak(
            format!(
                "MRS domain set 含 {count} 条域名，无法无损展开成 ClassicalEntry；\
                     请通过 manager 的 `parse_ruleset_compiled` 路径加载（自动走 succinct trie）。"
            )
            .into_boxed_str(),
        ))),
        mrs::MrsPayload::IpCidr { set, .. } => {
            // 把 IpRange 转成 CIDR 列表 —— 仅在罕见的"老 API 直接读 mrs"路径用到，
            // 性能不是关键。
            let mut entries = Vec::new();
            for (from, to) in &set.v4_ranges {
                for net in v4_range_to_cidrs(*from, *to) {
                    entries.push(ClassicalEntry {
                        kind: crate::matcher::ClassicalKind::IpCidr,
                        value: net.to_string(),
                        policy: None,
                    });
                }
            }
            for (from, to) in &set.v6_ranges {
                for net in v6_range_to_cidrs(*from, *to) {
                    entries.push(ClassicalEntry {
                        kind: crate::matcher::ClassicalKind::IpCidr,
                        value: net.to_string(),
                        policy: None,
                    });
                }
            }
            Ok(entries)
        }
    }
}

pub fn parse_srs(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let _ = body;
    Err(ParseError::UnsupportedBinary(
        "sing-box SRS 二进制规则集尚未完整解码。请用 \
         `sing-box rule-set decompile xxx.srs` 转换为 json，或在配置中改 format: json 指向源 JSON。",
    ))
}

/// 把闭区间 [from, to]（u32）展开成最少的 IPv4 CIDR 列表。
fn v4_range_to_cidrs(mut from: u32, to: u32) -> Vec<ipnet::Ipv4Net> {
    let mut out = Vec::new();
    while from <= to {
        // 当前 from 能对齐的最大块 = 2^trailing_zeros(from)；同时不能越过 to。
        let max_size = if from == 0 {
            32
        } else {
            from.trailing_zeros().min(32)
        };
        // 简化版：取 max_size，再循环把 prefix 抬到不溢出 to 为止
        let mut prefix = 32 - max_size;
        // 校正：保证当前 CIDR 末尾 <= to
        loop {
            let block_size: u64 = 1u64 << (32 - prefix);
            let end = (from as u64) + block_size - 1;
            if end <= to as u64 {
                break;
            }
            prefix += 1;
            if prefix > 32 {
                break;
            }
        }
        if prefix > 32 {
            break;
        }
        let net = ipnet::Ipv4Net::new(std::net::Ipv4Addr::from(from), prefix as u8)
            .expect("valid prefix");
        out.push(net);
        let block_size: u64 = 1u64 << (32 - prefix);
        let next = from as u64 + block_size;
        if next > u32::MAX as u64 {
            break;
        }
        from = next as u32;
        if from == 0 {
            break; // 溢出
        }
    }
    out
}

/// 同 v4，但 128 位。生产路径基本不会用到（mihomo IPv6 ruleset 极少），保留对齐性。
fn v6_range_to_cidrs(mut from: u128, to: u128) -> Vec<ipnet::Ipv6Net> {
    let mut out = Vec::new();
    while from <= to {
        let max_size = if from == 0 {
            128
        } else {
            from.trailing_zeros().min(128)
        };
        let mut prefix: u32 = 128 - max_size;
        loop {
            let block: u128 = if 128 - prefix >= 128 {
                u128::MAX
            } else {
                1u128 << (128 - prefix)
            };
            let end = from.saturating_add(block.saturating_sub(1));
            if end <= to {
                break;
            }
            prefix += 1;
            if prefix > 128 {
                break;
            }
        }
        if prefix > 128 {
            break;
        }
        let net = ipnet::Ipv6Net::new(std::net::Ipv6Addr::from(from), prefix as u8)
            .expect("valid prefix");
        out.push(net);
        let block: u128 = if 128 - prefix >= 128 {
            u128::MAX
        } else {
            1u128 << (128 - prefix)
        };
        let next = from.saturating_add(block);
        if next == 0 || next > to {
            // 已覆盖到 to 或溢出
            if next > to {
                break;
            }
        }
        from = next;
        if from == 0 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_range_single_cidr_aligned() {
        // 10.0.0.0 - 10.255.255.255 == 10.0.0.0/8
        let from = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0));
        let to = u32::from(std::net::Ipv4Addr::new(10, 255, 255, 255));
        let nets = v4_range_to_cidrs(from, to);
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn v4_range_unaligned_splits() {
        // 192.168.1.10 - 192.168.1.20
        let from = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 10));
        let to = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 20));
        let nets = v4_range_to_cidrs(from, to);
        // 应覆盖整个范围
        let covered: u64 = nets.iter().map(|n| 1u64 << (32 - n.prefix_len())).sum();
        assert_eq!(covered, (to - from + 1) as u64);
    }
}
