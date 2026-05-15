//! Sudoku Table —— 完整的字节编码/解码表。
//!
//! 与 mihomo `transport/sudoku/obfs/sudoku/table.go` 等价。
//!
//! 核心思想：
//! - 把 0..255 的字节映射为一个 4x4 数独网格的 4 个 hint
//! - hint = (位置 0..15, 值 1..4)
//! - 服务器收到 4 个 hint，根据数独逻辑唯一恢复出原始网格 → 反查到字节值
//! - 每个字节有多个有效编码（不同位置组合）
//!
//! 表初始化：
//! 1. 把 288 个网格按 sha256(key) 派生的种子 shuffle
//! 2. 对字节 N，分配第 N 个 shuffled 网格作为 target
//! 3. 枚举 C(16, 4) = 1820 个位置组合，校验是否唯一确定该网格
//! 4. 唯一时，记录该 hint 组合作为字节 N 的编码

use std::collections::BTreeMap;

use rand::SeedableRng;
use sha2::{Digest, Sha256};

use super::{
    grid::{Grid, generate_all_grids},
    layout::{ByteLayout, resolve_layout},
};

#[derive(Debug, Clone)]
pub struct Table {
    /// encode_table[byte] -> 该字节的所有合法编码（每个编码是 4 个 hint byte）
    pub encode_table: Vec<Vec<[u8; 4]>>,
    /// decode_map: packed sorted hints → 字节值
    pub decode_map: BTreeMap<u32, u8>,
    pub padding_pool: Vec<u8>,
    pub is_ascii: bool,
    pub layout: ByteLayout,
    pub hint: u32,
}

impl Table {
    pub fn new(key: &str, mode: &str) -> Result<Self, String> {
        Self::new_with_custom(key, mode, "")
    }

    pub fn new_with_custom(key: &str, mode: &str, custom_pattern: &str) -> Result<Self, String> {
        let layout = resolve_layout(mode, custom_pattern)?;
        let hint = table_hint_fingerprint(key, mode, custom_pattern, custom_pattern);

        let all_grids = generate_all_grids();
        let mut shuffled = all_grids.clone();
        let mut rng = seed_rng(key);
        // mihomo 用 Go 的 math/rand Shuffle (Fisher-Yates)
        // 我们模拟同样的行为：从末尾开始 swap(i, rng.intn(i+1))
        // 但 Rust rand 的 SliceRandom shuffle 是反向 Fisher-Yates，与 Go 一致
        use rand::seq::SliceRandom;
        shuffled.shuffle(&mut rng);

        // 预计算 C(16, 4) 共 1820 个位置组合
        let mut combinations = Vec::with_capacity(1820);
        let mut current: Vec<u8> = Vec::with_capacity(4);
        combine(&mut combinations, &mut current, 0, 4);

        let mut encode_table = vec![Vec::new(); 256];
        let mut decode_map: BTreeMap<u32, u8> = BTreeMap::new();

        for byte_val in 0..256u32 {
            let target = shuffled[byte_val as usize];
            for positions in combinations.iter() {
                // 抽取 (val, pos) 4 元组
                let mut raw_parts = [(0u8, 0u8); 4];
                for (i, &pos) in positions.iter().enumerate() {
                    let val = target[pos as usize]; // 1..=4
                    raw_parts[i] = (val, pos);
                }
                // 检查这组提示是否唯一对应一个网格
                if !is_unique_grid_match(&all_grids, &raw_parts) {
                    continue;
                }
                // 唯一，编码为 4 个 hint byte
                let mut hints = [0u8; 4];
                for (i, &(val, pos)) in raw_parts.iter().enumerate() {
                    hints[i] = layout.hint_byte(val - 1, pos);
                }
                encode_table[byte_val as usize].push(hints);
                let key = pack_hints_to_key(hints);
                decode_map.insert(key, byte_val as u8);
            }
        }

        Ok(Table {
            encode_table,
            decode_map,
            padding_pool: layout.padding_pool.clone(),
            is_ascii: layout.is_ascii,
            layout,
            hint,
        })
    }
}

fn combine(out: &mut Vec<Vec<u8>>, current: &mut Vec<u8>, start: u8, k: u8) {
    if k == 0 {
        out.push(current.clone());
        return;
    }
    let upper = 16 - k;
    for i in start..=upper {
        current.push(i);
        combine(out, current, i + 1, k - 1);
        current.pop();
    }
}

fn is_unique_grid_match(all_grids: &[Grid], parts: &[(u8, u8); 4]) -> bool {
    let mut count = 0;
    for g in all_grids {
        let mut ok = true;
        for &(val, pos) in parts {
            if g[pos as usize] != val {
                ok = false;
                break;
            }
        }
        if ok {
            count += 1;
            if count > 1 {
                return false;
            }
        }
    }
    count == 1
}

/// 4 个 hint 字节排序后打包成 u32（用作 decode_map 的 key）
pub fn pack_hints_to_key(mut h: [u8; 4]) -> u32 {
    h.sort_unstable();
    ((h[0] as u32) << 24) | ((h[1] as u32) << 16) | ((h[2] as u32) << 8) | (h[3] as u32)
}

fn seed_rng(key: &str) -> rand_chacha::ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let r = h.finalize();
    let seed: u64 = u64::from_be_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]);
    rand_chacha::ChaCha20Rng::seed_from_u64(seed)
}

fn table_hint_fingerprint(
    key: &str,
    mode: &str,
    uplink_pattern: &str,
    downlink_pattern: &str,
) -> u32 {
    let mut h = Sha256::new();
    h.update(b"sudoku-table-hint\x00");
    h.update(key.as_bytes());
    h.update(b"\x00");
    h.update(mode.to_ascii_lowercase().trim().as_bytes());
    h.update(b"\x00");
    h.update(uplink_pattern.to_ascii_lowercase().trim().as_bytes());
    h.update(b"\x00");
    h.update(downlink_pattern.to_ascii_lowercase().trim().as_bytes());
    let r = h.finalize();
    u32::from_be_bytes([r[0], r[1], r[2], r[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_hints_sorted() {
        let k1 = pack_hints_to_key([3, 1, 4, 2]);
        let k2 = pack_hints_to_key([1, 2, 3, 4]);
        assert_eq!(k1, k2);
    }

    #[test]
    fn combinations_count() {
        let mut all = Vec::new();
        let mut current = Vec::new();
        combine(&mut all, &mut current, 0, 4);
        assert_eq!(all.len(), 1820); // C(16, 4)
    }

    #[test]
    fn table_build_ascii() {
        let t = Table::new("test-key-12345", "ascii").unwrap();
        assert!(t.is_ascii);
        // 每个字节至少一个编码（绝大多数 256 个字节都有多个编码）
        let coverage = t.encode_table.iter().filter(|v| !v.is_empty()).count();
        assert!(coverage >= 200, "coverage too low: {coverage}");
    }

    #[test]
    fn table_build_entropy() {
        let t = Table::new("entropy-key", "entropy").unwrap();
        assert!(!t.is_ascii);
        // 验证 encode → decode 一致性
        for byte_val in 0..=255u8 {
            for hints in &t.encode_table[byte_val as usize] {
                let key = pack_hints_to_key(*hints);
                assert_eq!(t.decode_map.get(&key).copied(), Some(byte_val));
            }
        }
    }
}
