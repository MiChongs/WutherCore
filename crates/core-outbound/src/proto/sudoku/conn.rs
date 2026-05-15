//! Sudoku obfs Conn —— 字节表混淆双向流。
//!
//! 与 mihomo `transport/sudoku/obfs/sudoku/conn.go` + `encode.go` + `padding_prob.go` 等价。
//!
//! ## 编码（write 方向）
//! 对每个明文字节 b，从 `table.encode_table[b]` 中随机选一个 hint 组合（[u8;4]），
//! 然后随机选一个 24 个 perm4 排列之一，按该顺序写出 4 个 hint 字节。
//! 在 hint 字节之间随机插入 padding pool 中的字节。
//!
//! ## 解码（read 方向）
//! 跳过非 hint 字节（视为 padding）。每收到 4 个 hint 字节，排序后查 `decode_map`
//! 得到原始字节。

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use parking_lot::Mutex as PlMutex;
use pin_project_lite::pin_project;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::table::{Table, pack_hints_to_key};
use crate::adapter::BoxedStream;

const PROB_ONE: u64 = 1u64 << 32;

const PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

pub fn pick_padding_threshold(p_min: i32, p_max: i32) -> u64 {
    let mut p_min = p_min.max(0);
    let mut p_max = p_max.max(p_min);
    if p_max > 100 {
        p_max = 100;
    }
    if p_min > 100 {
        p_min = 100;
    }
    let min = (p_min as u64) * PROB_ONE / 100;
    let max = (p_max as u64) * PROB_ONE / 100;
    if max <= min {
        return min;
    }
    let u = rand::random::<u32>() as u64;
    min + ((u * (max - min)) >> 32)
}

pub fn should_pad(threshold: u64) -> bool {
    if threshold == 0 {
        return false;
    }
    if threshold >= PROB_ONE {
        return true;
    }
    (rand::random::<u32>() as u64) < threshold
}

/// 编码一段明文为 sudoku-混淆 wire bytes
pub fn encode_payload(table: &Table, payload: &[u8], padding_threshold: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() * 6 + 1);
    let pads = &table.padding_pool;
    let pad_len = pads.len();
    let mut rng = rand::rngs::OsRng;

    for &b in payload {
        if should_pad(padding_threshold) && pad_len > 0 {
            out.push(pads[rng.gen_range(0..pad_len)]);
        }
        let puzzles = &table.encode_table[b as usize];
        if puzzles.is_empty() {
            // 该字节没有合法编码（极小概率）：跳过 padding，直接 fallback group_byte
            out.push(table.layout.group_byte(b));
            continue;
        }
        let puzzle = &puzzles[rng.gen_range(0..puzzles.len())];
        let perm = &PERM4[rng.gen_range(0..PERM4.len())];
        for &idx in perm {
            if should_pad(padding_threshold) && pad_len > 0 {
                out.push(pads[rng.gen_range(0..pad_len)]);
            }
            out.push(puzzle[idx as usize]);
        }
    }

    if should_pad(padding_threshold) && pad_len > 0 {
        out.push(pads[rng.gen_range(0..pad_len)]);
    }
    out
}

/* ---------------- AsyncRead/Write 包装 ---------------- */

struct WriteState {
    padding_threshold: u64,
}

struct ReadState {
    /// 已积累但尚未凑齐 4 个的 hint
    hint_buf: [u8; 4],
    hint_count: usize,
    /// 已解码但未交付给上层的明文
    plain_buf: BytesMut,
    /// 来自网络的原始密文 buffer
    cipher_buf: BytesMut,
}

pin_project! {
    pub struct ObfsStream {
        #[pin]
        inner: BoxedStream,
        table: Arc<Table>,
        write_state: PlMutex<WriteState>,
        read_state: PlMutex<ReadState>,
    }
}

impl ObfsStream {
    pub fn new(inner: BoxedStream, table: Arc<Table>, p_min: i32, p_max: i32) -> Self {
        Self {
            inner,
            table,
            write_state: PlMutex::new(WriteState {
                padding_threshold: pick_padding_threshold(p_min, p_max),
            }),
            read_state: PlMutex::new(ReadState {
                hint_buf: [0u8; 4],
                hint_count: 0,
                plain_buf: BytesMut::with_capacity(8 * 1024),
                cipher_buf: BytesMut::with_capacity(32 * 1024),
            }),
        }
    }
}

impl AsyncRead for ObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            // 优先交付已解码明文
            {
                let mut rs = this.read_state.lock();
                if !rs.plain_buf.is_empty() {
                    let n = std::cmp::min(buf.remaining(), rs.plain_buf.len());
                    buf.put_slice(&rs.plain_buf[..n]);
                    rs.plain_buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
            }
            // 尝试从 cipher_buf 解码
            let progressed = {
                let mut rs = this.read_state.lock();
                let layout = &this.table.layout;
                let mut chunk = Vec::with_capacity(rs.cipher_buf.len());
                std::mem::swap(&mut chunk, &mut rs.cipher_buf.to_vec());
                rs.cipher_buf.clear();
                let mut any = false;
                for b in chunk {
                    if !layout.is_hint(b) {
                        continue;
                    }
                    let cnt = rs.hint_count;
                    rs.hint_buf[cnt] = b;
                    rs.hint_count += 1;
                    if rs.hint_count == 4 {
                        let key = pack_hints_to_key(rs.hint_buf);
                        match this.table.decode_map.get(&key) {
                            Some(v) => {
                                rs.plain_buf.extend_from_slice(&[*v]);
                                rs.hint_count = 0;
                                any = true;
                            }
                            None => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "INVALID_SUDOKU_MAP_MISS",
                                )));
                            }
                        }
                    }
                }
                any
            };
            if progressed {
                continue;
            }
            // 读更多
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match this.inner.as_mut().poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let mut rs = this.read_state.lock();
                    rs.cipher_buf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl AsyncWrite for ObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        let threshold = this.write_state.lock().padding_threshold;
        let encoded = encode_payload(this.table, data, threshold);
        let mut written = 0;
        while written < encoded.len() {
            match this.inner.as_mut().poll_write(cx, &encoded[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_threshold_min_only() {
        let t = pick_padding_threshold(0, 0);
        assert_eq!(t, 0);
        assert!(!should_pad(t));
    }

    #[test]
    fn padding_threshold_full() {
        // 100% 应该总是 pad
        let t = (100u64) * PROB_ONE / 100;
        assert!(should_pad(t));
    }

    #[test]
    fn perm4_count() {
        assert_eq!(PERM4.len(), 24);
        // 每个元素应当是 [0,1,2,3] 的排列
        for p in &PERM4 {
            let mut sorted = *p;
            sorted.sort();
            assert_eq!(sorted, [0, 1, 2, 3]);
        }
    }

    #[test]
    fn encode_then_inplace_decode() {
        // 端到端编码 → 解码（直接调用底层逻辑）
        let table = Table::new("test-key", "ascii").unwrap();
        let payload = b"Hello, Sudoku Obfs!";
        let encoded = encode_payload(&table, payload, 0); // 无 padding
        // 直接走解码逻辑
        let mut hint_buf = [0u8; 4];
        let mut count = 0usize;
        let mut decoded = Vec::new();
        for b in encoded {
            if !table.layout.is_hint(b) {
                continue;
            }
            hint_buf[count] = b;
            count += 1;
            if count == 4 {
                let key = pack_hints_to_key(hint_buf);
                let v = table.decode_map.get(&key).copied().unwrap();
                decoded.push(v);
                count = 0;
            }
        }
        assert_eq!(&decoded, payload);
    }
}
