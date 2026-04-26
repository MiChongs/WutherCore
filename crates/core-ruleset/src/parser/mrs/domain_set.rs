//! mihomo MRS Domain Behavior —— succinct trie 反序列化 + Has(key) 查询。
//!
//! 1:1 移植自：
//! * `mihomo-smart/component/trie/domain_set_bin.go`（线上格式）
//! * `mihomo-smart/component/trie/domain_set.go`（构造 + 查询算法）
//!
//! ## 二进制布局（位于 MRS zstd 解压流的尾部）
//! ```text
//! version       : u8 (=1)
//! leaves_len    : i64BE
//! leaves        : [u64BE; leaves_len]
//! labelmap_len  : i64BE
//! labelmap      : [u64BE; labelmap_len]
//! labels_len    : i64BE
//! labels        : [u8; labels_len]
//! ```
//!
//! ## 查询算法
//! 域名在编码时被反转（`example.com` → `moc.elpmaxe`），按字典序排好，
//! 经"前缀压缩 + bitmap 标记 child 边界"得到 succinct 表示。Has 时把查询
//! key 同样反转 + 转小写，沿位图走深度优先搜索，处理两种通配符：
//! * `+` —— complex wildcard：直接命中（mihomo `+.example.com` 语义）。
//! * `*` —— single-segment wildcard：把当前位置 push 进栈，DFS 失败时回退。

use std::io::Read;

use super::bitmap::{
    get_bit, index_select32_r64, rank64, select32_r64,
};
use crate::parser::ParseError;

const COMPLEX_WILDCARD: u8 = b'+';
const SINGLE_WILDCARD: u8 = b'*';
const DOMAIN_STEP: u8 = b'.';

/// MRS 域名 succinct trie。Arc 友好（数据结构创建后不变）。
#[derive(Debug)]
pub struct MrsDomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

impl MrsDomainSet {
    /// 从 zstd 已解压、跳过 header 之后的 reader 读出 trie。
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ParseError> {
        let mut byte = [0u8; 1];
        read_full(r, &mut byte)?;
        if byte[0] != 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS domain_set version != 1（不兼容的 mihomo MRS 版本）",
            ));
        }
        let leaves_len = read_i64_be(r)?;
        if leaves_len < 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS domain_set leaves_len 非法",
            ));
        }
        let leaves = read_u64_vec_be(r, leaves_len as usize)?;
        let labelmap_len = read_i64_be(r)?;
        if labelmap_len < 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS domain_set labelmap_len 非法",
            ));
        }
        let label_bitmap = read_u64_vec_be(r, labelmap_len as usize)?;
        let labels_len = read_i64_be(r)?;
        if labels_len < 1 {
            return Err(ParseError::UnsupportedBinary(
                "MRS domain_set labels_len 非法",
            ));
        }
        let mut labels = vec![0u8; labels_len as usize];
        read_full(r, &mut labels)?;

        let (selects, ranks) = index_select32_r64(&label_bitmap);
        Ok(Self { leaves, label_bitmap, labels, ranks, selects })
    }

    /// 查询某个域名是否被规则集命中。等价于 mihomo `domain_set.go::Has`（L74）。
    pub fn has(&self, key: &str) -> bool {
        // ToLower + reverse（按字节，与 mihomo 的 utils.Reverse 一致 —— mihomo
        // 在域名上下文也只处理 ASCII，IDN 域名外侧应已 punycode 转 ASCII）。
        let key: Vec<u8> = key.bytes().rev().map(ascii_to_lower).collect();
        if key.is_empty() {
            return false;
        }

        // 一个等价 Go labels 的别名：`labels[bm_idx - node_id]`
        // succinct 的"边"按出现顺序连续放在 labels；node_id 等于已遇到的 "1"
        // 数量，bm_idx 是当前位图位置。
        let mut node_id: i32 = 0;
        let mut bm_idx: i32 = 0;
        // wildcard 回退栈：当后续 DFS 失败时，回到这里继续走非 '*' 子节点。
        let mut stack: Vec<WildcardCursor> = Vec::new();

        let mut i: usize = 0;
        'outer: loop {
            // RESTART 标签的等价物：每轮重新读 c
            if i >= key.len() {
                break;
            }
            let c = key[i];
            loop {
                if get_bit(&self.label_bitmap, bm_idx as usize) != 0 {
                    // 此位为 1 —— node 边界结束，没找到与 c 匹配的子节点。
                    if let Some(cursor) = stack.pop() {
                        // 回退到 wildcard 锚点：跳到下一个 node 后，找含 '.' 的边
                        let next_node_id = count_zeros(&self.label_bitmap, &self.ranks, cursor.bm_idx + 1);
                        let mut next_bm_idx = select_ith_one(
                            &self.label_bitmap,
                            &self.ranks,
                            &self.selects,
                            next_node_id - 1,
                        ) + 1;
                        // 在 key 中跳到下一个 '.' 之前
                        let mut j = cursor.index;
                        while j < key.len() && key[j] != DOMAIN_STEP {
                            j += 1;
                        }
                        if j == key.len() {
                            if get_bit(&self.leaves, next_node_id as usize) != 0 {
                                return true;
                            } else {
                                continue 'outer;
                            }
                        }
                        // 在 next_node 的边集中找一条 label='.' 的边继续
                        loop {
                            let local = (next_bm_idx - next_node_id) as usize;
                            if local >= self.labels.len() {
                                continue 'outer;
                            }
                            if self.labels[local] == DOMAIN_STEP {
                                bm_idx = next_bm_idx;
                                node_id = next_node_id;
                                i = j;
                                continue 'outer;
                            }
                            next_bm_idx += 1;
                        }
                    }
                    return false;
                }
                let local = (bm_idx - node_id) as usize;
                if local >= self.labels.len() {
                    return false;
                }
                let lab = self.labels[local];
                if lab == COMPLEX_WILDCARD {
                    // mihomo `+` 直接 return true
                    return true;
                } else if lab == SINGLE_WILDCARD {
                    stack.push(WildcardCursor { bm_idx, index: i });
                } else if lab == c {
                    break;
                }
                bm_idx += 1;
            }
            // 跳到子节点
            node_id = count_zeros(&self.label_bitmap, &self.ranks, bm_idx + 1);
            bm_idx = select_ith_one(&self.label_bitmap, &self.ranks, &self.selects, node_id - 1) + 1;
            i += 1;
        }
        get_bit(&self.leaves, node_id as usize) != 0
    }

    /// 估算占用字节数，用于日志。
    pub fn approx_bytes(&self) -> usize {
        self.leaves.len() * 8
            + self.label_bitmap.len() * 8
            + self.labels.len()
            + self.ranks.len() * 4
            + self.selects.len() * 4
    }
}

#[derive(Clone, Copy)]
struct WildcardCursor {
    bm_idx: i32,
    index: usize,
}

#[inline]
fn ascii_to_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    }
}

#[inline]
fn count_zeros(bm: &[u64], ranks: &[i32], i: i32) -> i32 {
    let ones = rank64(bm, ranks, i);
    i - ones
}

#[inline]
fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: i32) -> i32 {
    select32_r64(bm, selects, ranks, i)
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

fn read_u64_vec_be<R: Read>(r: &mut R, n: usize) -> Result<Vec<u64>, ParseError> {
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 8];
    for _ in 0..n {
        read_full(r, &mut buf)?;
        out.push(u64::from_be_bytes(buf));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造极小 trie：人工填充 leaves/labelmap/labels，验证 has 的基础语义。
    /// 真实 mihomo 数据的端到端覆盖放在 tests/mrs_geoip_cn.rs。
    #[test]
    fn empty_set_returns_false() {
        let s = MrsDomainSet {
            leaves: vec![0],
            label_bitmap: vec![1u64], // 第 0 位 1 表示 root 无子节点
            labels: vec![],
            ranks: vec![0, 1],
            selects: vec![0],
        };
        assert!(!s.has("anything.com"));
    }

    #[test]
    fn ascii_lower_helper_works() {
        assert_eq!(ascii_to_lower(b'A'), b'a');
        assert_eq!(ascii_to_lower(b'Z'), b'z');
        assert_eq!(ascii_to_lower(b'a'), b'a');
        assert_eq!(ascii_to_lower(b'.'), b'.');
    }
}
