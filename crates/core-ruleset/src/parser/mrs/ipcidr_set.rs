//! mihomo MRS IPCIDR Behavior —— IpRange 列表反序列化 + 二分包含查询。
//!
//! 1:1 移植自 `mihomo-smart/component/cidr/ipcidr_set_bin.go`。
//!
//! ## 二进制布局（位于 zstd 解压流的尾部）
//! ```text
//! version       : u8 (=1)
//! range_count   : i64BE
//! [range_count] × {
//!     from : [u8; 16]   // IPv6 大端表示；IPv4 走 4-in-6 mapping
//!     to   : [u8; 16]
//! }
//! ```
//!
//! ## 查询
//! mihomo 用 `go4.org/netipx.IPSet`（内部就是排好序的 IpRange 列表，二分查找）。
//! 我们直接照搬：把 v4 / v6 拆两个 Vec<(start,end)>，按 start 排序后二分。

use std::cmp::Ordering;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::parser::ParseError;

#[derive(Debug, Default)]
pub struct MrsIpCidrSet {
    /// (start, end) 闭区间，已按 start 升序排列。
    pub v4_ranges: Vec<(u32, u32)>,
    pub v6_ranges: Vec<(u128, u128)>,
}

impl MrsIpCidrSet {
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ParseError> {
        let mut byte = [0u8; 1];
        read_full(r, &mut byte)?;
        if byte[0] != 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS ipcidr_set version != 1（不兼容的 mihomo MRS 版本）",
            ));
        }
        let count = read_i64_be(r)?;
        if count < 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS ipcidr_set range_count 非法",
            ));
        }
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        let mut buf = [0u8; 16];
        for _ in 0..count {
            read_full(r, &mut buf)?;
            let from = unmap(&buf);
            read_full(r, &mut buf)?;
            let to = unmap(&buf);
            match (from, to) {
                (IpAddr::V4(a), IpAddr::V4(b)) => v4.push((u32::from(a), u32::from(b))),
                (IpAddr::V6(a), IpAddr::V6(b)) => v6.push((u128::from(a), u128::from(b))),
                _ => {
                    // mihomo 不会混发，但若遇到则视为损坏。跳过单条更友好。
                    continue;
                }
            }
        }
        v4.sort_unstable_by_key(|p| p.0);
        v6.sort_unstable_by_key(|p| p.0);
        Ok(Self { v4_ranges: v4, v6_ranges: v6 })
    }

    /// 包含查询：根据 IP 类型走对应 Vec 的二分。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains_range(&self.v4_ranges, u32::from(v4)),
            IpAddr::V6(v6) => contains_range(&self.v6_ranges, u128::from(v6)),
        }
    }

    pub fn approx_bytes(&self) -> usize {
        self.v4_ranges.len() * std::mem::size_of::<(u32, u32)>()
            + self.v6_ranges.len() * std::mem::size_of::<(u128, u128)>()
    }

    pub fn count(&self) -> usize {
        self.v4_ranges.len() + self.v6_ranges.len()
    }
}

#[inline]
fn unmap(b: &[u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(*b);
    // ::ffff:a.b.c.d → IPv4
    if let Some(v4) = v6.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else if v6.octets()[..12] == [0u8; 12] {
        // mihomo 使用 As16()，对 IPv4 会走 ::ffff:; 但有些上游可能写成纯 ::a.b.c.d。
        let oct = v6.octets();
        IpAddr::V4(Ipv4Addr::new(oct[12], oct[13], oct[14], oct[15]))
    } else {
        IpAddr::V6(v6)
    }
}

fn contains_range<T: Copy + Ord>(ranges: &[(T, T)], ip: T) -> bool {
    ranges
        .binary_search_by(|(from, to)| {
            if ip < *from {
                Ordering::Greater
            } else if ip > *to {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), ParseError> {
    r.read_exact(buf).map_err(|e| {
        ParseError::Other(format!("MRS read_exact failed ({} bytes): {e}", buf.len()))
    })
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
    fn binary_search_v4_hit_and_miss() {
        let r: Vec<(u32, u32)> = vec![
            (u32::from(Ipv4Addr::new(10, 0, 0, 0)), u32::from(Ipv4Addr::new(10, 255, 255, 255))),
            (u32::from(Ipv4Addr::new(192, 168, 0, 0)), u32::from(Ipv4Addr::new(192, 168, 255, 255))),
        ];
        assert!(contains_range(&r, u32::from(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(contains_range(&r, u32::from(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!contains_range(&r, u32::from(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn unmap_handles_v4_mapped_v6() {
        let mut buf = [0u8; 16];
        buf[10] = 0xff;
        buf[11] = 0xff;
        buf[12] = 1;
        buf[13] = 2;
        buf[14] = 3;
        buf[15] = 4;
        let ip = unmap(&buf);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }
}
