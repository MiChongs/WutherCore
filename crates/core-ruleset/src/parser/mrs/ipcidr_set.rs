//! mihomo MRS IPCIDR Behavior —— IpRange 列表反序列化 + 二分包含查询。
//!
//! 兼容 mihomo `component/cidr/ipcidr_set_bin.go`。
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
//! mihomo 用 `go4.org/netipx.IPSet`（内部就是排好序、互不重叠的 IpRange 列表）。
//! 我们在读取时验证同样的不变量，再把 v4 / v6 拆成两个 Vec<(start,end)> 二分查询。

use std::{
    cmp::Ordering,
    io::Read,
    net::{IpAddr, Ipv6Addr},
};

use crate::parser::ParseError;

const MAX_IP_RANGES: usize = 1024 * 1024;

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
        let count = read_bounded_count(r)?;
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        let mut previous_v4_end = None;
        let mut previous_v6_end = None;
        let mut seen_v6 = false;
        let mut buf = [0u8; 16];
        for _ in 0..count {
            read_full(r, &mut buf)?;
            let from = unmap(&buf);
            read_full(r, &mut buf)?;
            let to = unmap(&buf);
            match (from, to) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    if seen_v6 {
                        return Err(mrs_error("IPv4 range appears after an IPv6 range"));
                    }
                    let from = u32::from(a);
                    let to = u32::from(b);
                    validate_range(from, to, previous_v4_end, "IPv4")?;
                    v4.try_reserve(1)
                        .map_err(|_| mrs_error("IPv4 range allocation failed"))?;
                    v4.push((from, to));
                    previous_v4_end = Some(to);
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    seen_v6 = true;
                    let from = u128::from(a);
                    let to = u128::from(b);
                    validate_range(from, to, previous_v6_end, "IPv6")?;
                    v6.try_reserve(1)
                        .map_err(|_| mrs_error("IPv6 range allocation failed"))?;
                    v6.push((from, to));
                    previous_v6_end = Some(to);
                }
                _ => {
                    return Err(mrs_error("range endpoints use different address families"));
                }
            }
        }
        Ok(Self {
            v4_ranges: v4,
            v6_ranges: v6,
        })
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
    if let Some(v4) = v6.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(v6)
    }
}

fn validate_range<T: Copy + Ord + Into<u128>>(
    from: T,
    to: T,
    previous_end: Option<T>,
    family: &'static str,
) -> Result<(), ParseError> {
    if from > to {
        return Err(mrs_error(format!("{family} range start is after its end")));
    }
    if let Some(end) = previous_end {
        if from <= end
            || end
                .into()
                .checked_add(1)
                .is_some_and(|next| from.into() == next)
        {
            return Err(mrs_error(format!(
                "{family} ranges are unordered, overlapping, or contiguous"
            )));
        }
    }
    Ok(())
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
    r.read_exact(buf)
        .map_err(|e| ParseError::Other(format!("MRS read_exact failed ({} bytes): {e}", buf.len())))
}

fn read_i64_be<R: Read>(r: &mut R) -> Result<i64, ParseError> {
    let mut buf = [0u8; 8];
    read_full(r, &mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

fn read_bounded_count<R: Read>(reader: &mut R) -> Result<usize, ParseError> {
    let raw = read_i64_be(reader)?;
    if raw <= 0 {
        return Err(mrs_error("range_count must be positive"));
    }
    let count =
        usize::try_from(raw).map_err(|_| mrs_error("range_count exceeds usize capacity"))?;
    if count > MAX_IP_RANGES {
        return Err(mrs_error(format!(
            "range_count {count} exceeds limit {MAX_IP_RANGES}"
        )));
    }
    Ok(count)
}

fn mrs_error(message: impl Into<String>) -> ParseError {
    ParseError::Other(format!("MRS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, net::Ipv4Addr};

    fn mapped_v4(value: Ipv4Addr) -> [u8; 16] {
        value.to_ipv6_mapped().octets()
    }

    fn encoded_ranges(ranges: &[([u8; 16], [u8; 16])]) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(ranges.len() as i64).to_be_bytes());
        for (from, to) in ranges {
            bytes.extend_from_slice(from);
            bytes.extend_from_slice(to);
        }
        bytes
    }

    #[test]
    fn binary_search_v4_hit_and_miss() {
        let r: Vec<(u32, u32)> = vec![
            (
                u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                u32::from(Ipv4Addr::new(10, 255, 255, 255)),
            ),
            (
                u32::from(Ipv4Addr::new(192, 168, 0, 0)),
                u32::from(Ipv4Addr::new(192, 168, 255, 255)),
            ),
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

    #[test]
    fn pure_ipv4_compatible_ipv6_is_not_unmapped() {
        let buf = Ipv6Addr::LOCALHOST.octets();
        assert_eq!(unmap(&buf), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn read_accepts_official_ordered_family_layout() {
        let bytes = encoded_ranges(&[
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 0)),
                mapped_v4(Ipv4Addr::new(10, 255, 255, 255)),
            ),
            (Ipv6Addr::LOCALHOST.octets(), Ipv6Addr::LOCALHOST.octets()),
        ]);
        let set = MrsIpCidrSet::read(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(set.count(), 2);
        assert!(set.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(set.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn read_rejects_mixed_endpoint_families() {
        let bytes = encoded_ranges(&[(
            mapped_v4(Ipv4Addr::new(10, 0, 0, 0)),
            Ipv6Addr::LOCALHOST.octets(),
        )]);
        assert!(MrsIpCidrSet::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn read_rejects_reverse_overlap_and_family_reordering() {
        let reverse = encoded_ranges(&[(
            mapped_v4(Ipv4Addr::new(10, 0, 0, 2)),
            mapped_v4(Ipv4Addr::new(10, 0, 0, 1)),
        )]);
        assert!(MrsIpCidrSet::read(&mut Cursor::new(reverse)).is_err());

        let overlap = encoded_ranges(&[
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 0)),
                mapped_v4(Ipv4Addr::new(10, 0, 0, 10)),
            ),
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 10)),
                mapped_v4(Ipv4Addr::new(10, 0, 0, 20)),
            ),
        ]);
        assert!(MrsIpCidrSet::read(&mut Cursor::new(overlap)).is_err());

        let adjacent = encoded_ranges(&[
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 0)),
                mapped_v4(Ipv4Addr::new(10, 0, 0, 10)),
            ),
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 11)),
                mapped_v4(Ipv4Addr::new(10, 0, 0, 20)),
            ),
        ]);
        assert!(MrsIpCidrSet::read(&mut Cursor::new(adjacent)).is_err());

        let reordered = encoded_ranges(&[
            (Ipv6Addr::LOCALHOST.octets(), Ipv6Addr::LOCALHOST.octets()),
            (
                mapped_v4(Ipv4Addr::new(10, 0, 0, 0)),
                mapped_v4(Ipv4Addr::new(10, 0, 0, 1)),
            ),
        ]);
        assert!(MrsIpCidrSet::read(&mut Cursor::new(reordered)).is_err());
    }

    #[test]
    fn read_rejects_oversized_count_before_allocation() {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((MAX_IP_RANGES as i64) + 1).to_be_bytes());
        assert!(MrsIpCidrSet::read(&mut Cursor::new(bytes)).is_err());
    }
}
