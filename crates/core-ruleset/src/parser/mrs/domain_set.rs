//! mihomo MRS Domain Behavior —— succinct trie 反序列化 + Has(key) 查询。
//!
//! 兼容 MetaCubeX/mihomo `component/trie/domain_set_bin.go` 与
//! `component/trie/domain_set.go`（`Alpha` / `Meta` 内核分支）。
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
//! 域名在编码时按 Unicode scalar 反转（`example.com` → `moc.elpmaxe`），按字典序排好，
//! 经"前缀压缩 + bitmap 标记 child 边界"得到 succinct 表示。Has 时把查询
//! key 同样反转 + 转小写，沿位图走深度优先搜索，处理两种通配符：
//! * `+` —— complex wildcard：直接命中（mihomo `+.example.com` 语义）。
//! * `*` —— single-segment wildcard：把当前位置 push 进栈，DFS 失败时回退。

use std::io::Read;

use super::bitmap::{get_bit, index_select32_r64, rank64, select32_r64};
use crate::parser::ParseError;

const COMPLEX_WILDCARD: u8 = b'+';
const SINGLE_WILDCARD: u8 = b'*';
const DOMAIN_STEP: u8 = b'.';

const MAX_DOMAIN_NODES: usize = 8 * 1024 * 1024;
const MAX_DOMAIN_DEPTH: usize = 1_024;
const MAX_DOMAIN_LEAF_WORDS: usize = MAX_DOMAIN_NODES.div_ceil(64);
const MAX_DOMAIN_BITMAP_WORDS: usize = (2 * MAX_DOMAIN_NODES - 1).div_ceil(64);

/// MRS 域名 succinct trie。Arc 友好（数据结构创建后不变）。
#[derive(Debug)]
pub struct MrsDomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
    node_count: usize,
    effective_bitmap_bits: usize,
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
        let leaves_len = read_bounded_len(r, "domain leaves_len", MAX_DOMAIN_LEAF_WORDS, false)?;
        let leaves = read_u64_vec_be(r, leaves_len, "domain leaves")?;
        let labelmap_len =
            read_bounded_len(r, "domain labelmap_len", MAX_DOMAIN_BITMAP_WORDS, false)?;
        let label_bitmap = read_u64_vec_be(r, labelmap_len, "domain label bitmap")?;
        let labels_len = read_bounded_len(r, "domain labels_len", MAX_DOMAIN_NODES - 1, false)?;
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(labels_len)
            .map_err(|_| mrs_error("domain labels allocation failed"))?;
        labels.resize(labels_len, 0);
        read_full(r, &mut labels)?;

        let (node_count, effective_bitmap_bits) =
            validate_succinct_set(&leaves, &label_bitmap, &labels)?;
        let (selects, ranks) = index_select32_r64(&label_bitmap)
            .map_err(|message| mrs_error(format!("domain bitmap index failed: {message}")))?;
        Ok(Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
            node_count,
            effective_bitmap_bits,
        })
    }

    /// 查询某个域名是否被规则集命中。等价于 mihomo `domain_set.go::Has`（L74）。
    pub fn has(&self, key: &str) -> bool {
        // Mihomo 的 utils.Reverse 基于 []rune；strings.ToLower 使用 Unicode simple mapping。
        let key: Vec<u8> = key
            .chars()
            .rev()
            .map(unicode_simple_lower)
            .collect::<String>()
            .into_bytes();
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
                if bm_idx < 0 || bm_idx as usize >= self.effective_bitmap_bits {
                    return false;
                }
                if get_bit(&self.label_bitmap, bm_idx as usize) != 0 {
                    // 此位为 1 —— node 边界结束，没找到与 c 匹配的子节点。
                    if let Some(cursor) = stack.pop() {
                        // 回退到 wildcard 锚点：跳到下一个 node 后，找含 '.' 的边
                        let Some(after_cursor) = cursor.bm_idx.checked_add(1) else {
                            return false;
                        };
                        let next_node_id =
                            count_zeros(&self.label_bitmap, &self.ranks, after_cursor);
                        if next_node_id <= 0 || next_node_id as usize >= self.node_count {
                            return false;
                        }
                        let mut next_bm_idx = select_ith_one(
                            &self.label_bitmap,
                            &self.ranks,
                            &self.selects,
                            next_node_id - 1,
                        );
                        let Some(next_index) = next_bm_idx.checked_add(1) else {
                            return false;
                        };
                        next_bm_idx = next_index;
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
                            if next_bm_idx < 0
                                || next_bm_idx as usize >= self.effective_bitmap_bits
                                || get_bit(&self.label_bitmap, next_bm_idx as usize) != 0
                            {
                                continue 'outer;
                            }
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
                let Some(local) = bm_idx
                    .checked_sub(node_id)
                    .and_then(|value| usize::try_from(value).ok())
                else {
                    return false;
                };
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
            let Some(after_edge) = bm_idx.checked_add(1) else {
                return false;
            };
            node_id = count_zeros(&self.label_bitmap, &self.ranks, after_edge);
            if node_id <= 0 || node_id as usize >= self.node_count {
                return false;
            }
            let delimiter =
                select_ith_one(&self.label_bitmap, &self.ranks, &self.selects, node_id - 1);
            let Some(next_bitmap_index) = delimiter.checked_add(1) else {
                return false;
            };
            bm_idx = next_bitmap_index;
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
            + std::mem::size_of::<usize>() * 2
    }
}

#[derive(Clone, Copy)]
struct WildcardCursor {
    bm_idx: i32,
    index: usize,
}

#[inline]
fn unicode_simple_lower(value: char) -> char {
    // The dependency is pinned to the same Unicode version as Mihomo's current
    // Go runtime. Its first scalar is the simple lowercase mapping Go applies to
    // each rune; zero means that the rune maps to itself.
    let first = unicode_case_mapping::to_lowercase(value)[0];
    if first == 0 {
        value
    } else {
        char::from_u32(first).unwrap_or(value)
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

fn read_u64_vec_be<R: Read>(
    r: &mut R,
    n: usize,
    field: &'static str,
) -> Result<Vec<u64>, ParseError> {
    let mut out = Vec::new();
    out.try_reserve_exact(n)
        .map_err(|_| mrs_error(format!("{field} allocation failed")))?;
    let mut buf = [0u8; 8];
    for _ in 0..n {
        read_full(r, &mut buf)?;
        out.push(u64::from_be_bytes(buf));
    }
    Ok(out)
}

fn validate_succinct_set(
    leaves: &[u64],
    label_bitmap: &[u64],
    labels: &[u8],
) -> Result<(usize, usize), ParseError> {
    let node_count = labels
        .len()
        .checked_add(1)
        .ok_or_else(|| mrs_error("domain node count overflow"))?;
    let effective_bits = node_count
        .checked_mul(2)
        .and_then(|bits| bits.checked_sub(1))
        .ok_or_else(|| mrs_error("domain bitmap bit count overflow"))?;
    let expected_bitmap_words = effective_bits.div_ceil(64);
    if label_bitmap.len() != expected_bitmap_words {
        return Err(mrs_error(format!(
            "domain label bitmap word count {}, expected {expected_bitmap_words}",
            label_bitmap.len()
        )));
    }
    if !effective_bits.is_multiple_of(64) {
        let used_mask = (1u64 << (effective_bits % 64)) - 1;
        if label_bitmap.last().copied().unwrap_or(0) & !used_mask != 0 {
            return Err(mrs_error("domain label bitmap padding is non-zero"));
        }
    }

    let allowed_leaf_words = node_count.div_ceil(64);
    if leaves.len() != allowed_leaf_words {
        return Err(mrs_error(format!(
            "domain leaves word count {}, expected {allowed_leaf_words}",
            leaves.len()
        )));
    }
    if !node_count.is_multiple_of(64) {
        let used_mask = (1u64 << (node_count % 64)) - 1;
        if leaves.last().copied().unwrap_or(0) & !used_mask != 0 {
            return Err(mrs_error("domain leaves reference non-existent nodes"));
        }
    }
    if get_bit(leaves, 0) != 0 {
        return Err(mrs_error("domain root cannot be terminal"));
    }
    if get_bit(leaves, node_count - 1) == 0 {
        return Err(mrs_error("domain final node must be terminal"));
    }

    let mut depths = Vec::new();
    depths
        .try_reserve_exact(node_count)
        .map_err(|_| mrs_error("domain depth index allocation failed"))?;
    depths.push(0u16);
    let mut bit_index = 0usize;
    let mut edge_index = 0usize;
    for node_index in 0..node_count {
        let parent_depth = depths
            .get(node_index)
            .copied()
            .ok_or_else(|| mrs_error("domain label bitmap references an unreachable node"))?;
        let mut child_count = 0usize;
        let mut previous_label = None;
        loop {
            if bit_index >= effective_bits {
                return Err(mrs_error("domain label bitmap ended before node delimiter"));
            }
            let bit = get_bit(label_bitmap, bit_index);
            bit_index += 1;
            if bit != 0 {
                break;
            }
            if edge_index >= labels.len() {
                return Err(mrs_error("domain label bitmap has more edges than labels"));
            }
            let label = labels[edge_index];
            if previous_label.is_some_and(|previous| label <= previous) {
                return Err(mrs_error(
                    "domain sibling labels are not strictly increasing",
                ));
            }
            previous_label = Some(label);
            let depth = usize::from(parent_depth) + 1;
            if depth > MAX_DOMAIN_DEPTH {
                return Err(mrs_error(format!(
                    "domain trie depth exceeds {MAX_DOMAIN_DEPTH}"
                )));
            }
            depths.push(depth as u16);
            edge_index += 1;
            child_count += 1;
        }
        if child_count == 0 && get_bit(leaves, node_index) == 0 {
            return Err(mrs_error("domain childless node is not terminal"));
        }
    }
    if bit_index != effective_bits || edge_index != labels.len() || depths.len() != node_count {
        return Err(mrs_error(
            "domain succinct set has unreferenced labels or bitmap bits",
        ));
    }
    Ok((node_count, effective_bits))
}

fn mrs_error(message: impl Into<String>) -> ParseError {
    ParseError::Other(format!("MRS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encoded_set(leaves: &[u64], label_bitmap: &[u64], labels: &[u8]) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(leaves.len() as i64).to_be_bytes());
        for word in leaves {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&(label_bitmap.len() as i64).to_be_bytes());
        for word in label_bitmap {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&(labels.len() as i64).to_be_bytes());
        bytes.extend_from_slice(labels);
        bytes
    }

    fn read_set(
        leaves: &[u64],
        label_bitmap: &[u64],
        labels: &[u8],
    ) -> Result<MrsDomainSet, ParseError> {
        MrsDomainSet::read(&mut Cursor::new(encoded_set(leaves, label_bitmap, labels)))
    }

    #[test]
    fn reads_minimal_valid_succinct_trie() {
        // root --'a'--> terminal child: LOUDS bits 0,1,1.
        let set = read_set(&[0b10], &[0b110], b"a").unwrap();
        assert!(set.has("a"));
        assert!(set.has("A"));
        assert!(!set.has("b"));
    }

    #[test]
    fn matches_unicode_by_rune_reverse_and_unicode_lowercase() {
        // "ä" is one rune but two UTF-8 trie edges (c3,a4).
        let set = read_set(&[0b100], &[0b1_1_01_0], &[0xc3, 0xa4]).unwrap();
        assert!(set.has("ä"));
        assert!(set.has("Ä"));
    }

    #[test]
    fn rejects_bitmap_padding_and_leaf_outside_nodes() {
        assert!(read_set(&[0b10], &[0b110 | (1u64 << 63)], b"a").is_err());
        assert!(read_set(&[0b100], &[0b110], b"a").is_err());
    }

    #[test]
    fn rejects_unreachable_nodes_and_edge_count_mismatch() {
        // For two nodes, 1,0,1 gives the root no children and leaves node 1 unreachable.
        assert!(read_set(&[0b10], &[0b101], b"a").is_err());
        // For two nodes, 0,1,0 omits the child delimiter and advertises an extra edge.
        assert!(read_set(&[0b10], &[0b010], b"a").is_err());
    }

    #[test]
    fn rejects_wrong_leaf_word_count_and_empty_terminal_set() {
        assert!(read_set(&[0b10, 0], &[0b110], b"a").is_err());
        assert!(read_set(&[0], &[0b110], b"a").is_err());
    }

    #[test]
    fn rejects_root_leaf_non_terminal_childless_node_and_unsorted_siblings() {
        assert!(read_set(&[0b11], &[0b110], b"a").is_err());

        // root has children a,b; both child nodes must be terminal.
        let bitmap = 0b1_1_1_00;
        assert!(read_set(&[0b010], &[bitmap], b"ab").is_err());
        assert!(read_set(&[0b110], &[bitmap], b"ba").is_err());
    }

    #[test]
    fn rejects_oversized_lengths_before_allocation() {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&((MAX_DOMAIN_LEAF_WORDS as i64) + 1).to_be_bytes());
        assert!(MrsDomainSet::read(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_excessive_trie_depth() {
        let label_count = MAX_DOMAIN_DEPTH + 1;
        let node_count = label_count + 1;
        let effective_bits = node_count * 2 - 1;
        let mut bitmap = vec![0u64; effective_bits.div_ceil(64)];
        for node in 0..label_count {
            super::super::bitmap::set_bit(&mut bitmap, node * 2 + 1, 1);
        }
        super::super::bitmap::set_bit(&mut bitmap, effective_bits - 1, 1);
        let mut leaves = vec![0u64; node_count.div_ceil(64)];
        super::super::bitmap::set_bit(&mut leaves, node_count - 1, 1);
        assert!(read_set(&leaves, &bitmap, &vec![b'a'; label_count]).is_err());
    }

    #[test]
    fn unicode_lower_helper_uses_simple_mapping() {
        assert_eq!(unicode_case_mapping::UNICODE_VERSION, (15, 0, 0));
        assert_eq!(unicode_simple_lower('A'), 'a');
        assert_eq!(unicode_simple_lower('Ä'), 'ä');
        assert_eq!(unicode_simple_lower('例'), '例');
        assert_eq!(unicode_simple_lower('İ'), 'i');
        // U+1C89 gained a lowercase mapping only after Unicode 15.0. Mihomo's
        // Go tables therefore preserve it even when Rust's newer tables do not.
        assert_eq!(unicode_simple_lower('\u{1c89}'), '\u{1c89}');
        assert_eq!(
            "Ä例.COM"
                .chars()
                .rev()
                .map(unicode_simple_lower)
                .collect::<String>(),
            "moc.例ä"
        );
    }
}
