//! Succinct bit-vector 操作 —— rank / select 的 O(1) 索引版本。
//!
//! 移植自 mihomo 使用的 `openacid/low/bitmap` 库，是 succinct domain trie
//! （`mihomo-smart/component/trie/domain_set.go`）的查询基础。
//!
//! ## 数据模型
//! * **bitmap**：`&[u64]`，bit-i 存放在 `bm[i>>6] & (1 << (i&63))`。
//! * **ranks**：每 64 bit 一个 i32 累计前缀 popcount。`ranks[k] = ∑ popcount(bm[0..k])`。
//!   长度 = `bm.len() + 1`，方便端点查询。
//! * **selects**：每 64 个 "1" 一个 i32 索引位置（即第 (i*64) 个 1 出现在 bm 的哪个 bit）。
//!
//! 以上三者构造耗时 O(N)，查询 O(1)（按 64-bit 分块二进制搜索 + popcount intrinsics）。

/// 在 `(*bm)[i>>6]` 的 i&63 位上写 v（0 或 1）；自动扩 bm 容量。
pub fn set_bit(bm: &mut Vec<u64>, i: usize, v: u64) {
    while (i >> 6) >= bm.len() {
        bm.push(0);
    }
    bm[i >> 6] |= (v & 1) << (i & 63);
}

/// 读 bit-i；越界视作 0（与 Go 版语义略不同：Go 直接 panic，但越界在我们这里
/// 只会出现在严重损坏的输入下，调用方应自行守护）。
#[inline]
pub fn get_bit(bm: &[u64], i: usize) -> u64 {
    let word = i >> 6;
    if word >= bm.len() {
        return 0;
    }
    (bm[word] >> (i & 63)) & 1
}

/// 构造 ranks 与 selects 索引。返回顺序与 Go 版 `bitmap.IndexSelect32R64` 一致：
/// `(selects, ranks)`。
///
/// * `ranks[k]` = bm[0..k] 中 "1" 的总数（k 取 0..=bm.len()）。
/// * `selects[i]` = 第 (i*64) 个 "1" 在 bm 中的全局 bit 索引。
pub fn index_select32_r64(bm: &[u64]) -> (Vec<i32>, Vec<i32>) {
    // ranks
    let mut ranks = Vec::with_capacity(bm.len() + 1);
    ranks.push(0i32);
    let mut acc: i32 = 0;
    for &w in bm {
        acc = acc.wrapping_add(w.count_ones() as i32);
        ranks.push(acc);
    }
    // selects：每 64 个 "1" 取 1 个采样
    let mut selects: Vec<i32> = Vec::new();
    let mut next_target: i64 = 0; // 下一个要采样的 "1" 的累计序号
    let mut count: i64 = 0;
    for (wi, &w) in bm.iter().enumerate() {
        let pop = w.count_ones() as i64;
        // 该 word 内是否存在采样目标
        while count + pop > next_target {
            // 找出 word 内第 (next_target - count) 个 "1" 的位偏移
            let need = (next_target - count) as u32;
            let bit = select_within_word(w, need);
            selects.push(((wi as i64) * 64 + bit as i64) as i32);
            next_target += 64;
        }
        count += pop;
    }
    (selects, ranks)
}

/// 在单个 u64 内找第 `idx`（0-based）个 "1" 的 bit 位置。
fn select_within_word(mut w: u64, mut idx: u32) -> u32 {
    let mut pos = 0u32;
    while idx > 0 {
        // 清掉最低的 "1"
        w &= w - 1;
        idx -= 1;
    }
    if w == 0 {
        // idx 越界 —— 对调用者来说是损坏输入；返回 0 让上层 has() 走 false 分支。
        return 0;
    }
    pos += w.trailing_zeros();
    pos
}

/// 返回 bm[0..i] 中 "1" 的个数（i 不含），等价 Go `bitmap.Rank64(bm, ranks, i)` 的第一个返回值。
#[inline]
pub fn rank64(bm: &[u64], ranks: &[i32], i: i32) -> i32 {
    if i <= 0 {
        return 0;
    }
    let i = i as usize;
    let word = i >> 6;
    let bit = i & 63;
    let base = if word < ranks.len() { ranks[word] } else { *ranks.last().unwrap_or(&0) };
    if bit == 0 || word >= bm.len() {
        base
    } else {
        let mask = (1u64 << bit) - 1;
        base + (bm[word] & mask).count_ones() as i32
    }
}

/// 返回 bm 中第 `i`（0-based）个 "1" 的全局 bit 索引；等价 Go
/// `bitmap.Select32R64(bm, selects, ranks, i)` 的第一个返回值。
#[inline]
pub fn select32_r64(bm: &[u64], selects: &[i32], ranks: &[i32], i: i32) -> i32 {
    if i < 0 || selects.is_empty() {
        return 0;
    }
    let bucket = (i / 64) as usize;
    let _inside = (i % 64) as u32; // 暂未使用：select_within_word 在 word 内重新定位
    // 起点：第 bucket 个 64-step 采样位置
    let start_bit = if bucket < selects.len() {
        selects[bucket] as usize
    } else {
        // 回落到从头扫描；正常输入不会走这里
        return scan_select(bm, i as i64);
    };
    let start_word = start_bit >> 6;
    // 该 word 内已经消耗掉的 "1" 数量（采样位置之前的，不含采样位置自身）
    let pre = if start_word < ranks.len() {
        let mask = (1u64 << (start_bit & 63)) - 1;
        let in_word = (bm[start_word] & mask).count_ones() as i32;
        ranks[start_word] + in_word
    } else {
        return scan_select(bm, i as i64);
    };
    // 我们要找的是全局第 i 个 "1"，已知 ranks[..start_word] + pre = bucket*64 个 "1" 以下。
    // 在 [start_word, ..) 内继续找 (i - bucket*64 - …) 个 "1"。
    let mut remaining = i - pre;
    if remaining < 0 {
        // 采样位置之前已经超过 i —— 重新从头扫（罕见，且只在异常构造时发生）
        return scan_select(bm, i as i64);
    }
    let mut wi = start_word;
    while wi < bm.len() {
        let pop = bm[wi].count_ones() as i32;
        if pop > remaining {
            let bit = select_within_word(bm[wi], remaining as u32);
            return ((wi as i64) * 64 + bit as i64) as i32;
        }
        remaining -= pop;
        wi += 1;
    }
    // 越界：返回 bm 末位 + 1（与 Go 版越界行为接近：调用方 has() 会 false）。
    (bm.len() as i32) * 64
}

fn scan_select(bm: &[u64], i: i64) -> i32 {
    let mut left = i;
    for (wi, &w) in bm.iter().enumerate() {
        let pop = w.count_ones() as i64;
        if pop > left {
            return ((wi as i64) * 64 + select_within_word(w, left as u32) as i64) as i32;
        }
        left -= pop;
    }
    (bm.len() as i32) * 64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_rank(bm: &[u64], i: usize) -> i32 {
        let mut s = 0u32;
        for k in 0..i {
            s += (get_bit(bm, k) as u32) & 1;
        }
        s as i32
    }
    fn naive_select(bm: &[u64], i: usize) -> i32 {
        let mut left = i as i32;
        for k in 0..(bm.len() * 64) {
            if get_bit(bm, k) == 1 {
                if left == 0 {
                    return k as i32;
                }
                left -= 1;
            }
        }
        (bm.len() * 64) as i32
    }

    #[test]
    fn rank_select_round_trip() {
        // 构造一段已知模式：交替 1010..., 然后随机一段
        let mut bm = vec![0u64; 16];
        for i in 0..1024 {
            if i % 3 == 0 {
                set_bit(&mut bm, i, 1);
            }
        }
        let (selects, ranks) = index_select32_r64(&bm);
        // rank 与朴素一致
        for i in [0, 1, 63, 64, 100, 200, 511, 512, 1023, 1024] {
            assert_eq!(rank64(&bm, &ranks, i as i32), naive_rank(&bm, i), "rank({i})");
        }
        // select：先用朴素跑一遍看有多少 "1"
        let total: usize = bm.iter().map(|w| w.count_ones() as usize).sum();
        for i in 0..total {
            assert_eq!(
                select32_r64(&bm, &selects, &ranks, i as i32),
                naive_select(&bm, i),
                "select({i})"
            );
        }
    }

    #[test]
    fn empty_bitmap_is_safe() {
        let bm: Vec<u64> = vec![];
        let (s, r) = index_select32_r64(&bm);
        assert_eq!(rank64(&bm, &r, 100), 0);
        assert_eq!(select32_r64(&bm, &s, &r, 0), 0);
    }

    #[test]
    fn all_ones_bitmap() {
        let bm = vec![u64::MAX; 4]; // 256 个 "1"
        let (s, r) = index_select32_r64(&bm);
        for i in 0..256 {
            assert_eq!(select32_r64(&bm, &s, &r, i), i, "select_all_ones({i})");
        }
    }
}
