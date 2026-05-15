//! XHTTP UploadQueue —— 与 mihomo `transport/xhttp/upload_queue.go` 等价。
//!
//! 服务器端用 (packet-up 模式下) 把多个乱序 POST 请求按 seq 重排为单一字节流。
//! 客户端不直接使用该结构（客户端是 PacketUpWriter 串行 POST），但接口保留以
//! 便完整对齐。
//!
//! ## 行为
//!
//! * `push(packet)` 把 (seq, payload) 入队；若队列已满则阻塞
//! * `read(buf)` 按 seq 顺序输出字节
//! * 若队列超过 `max_packets` 视为重组缓冲过大，断开

use std::{collections::BTreeMap, io, sync::Arc};

use parking_lot::{Condvar, Mutex};

#[derive(Debug)]
pub struct Packet {
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct Inner {
    packets: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    buf: Vec<u8>,
    closed: bool,
}

#[derive(Debug)]
pub struct UploadQueue {
    inner: Mutex<Inner>,
    cv_pushed: Condvar,
    cv_popped: Condvar,
    max_packets: usize,
}

impl UploadQueue {
    pub fn new(max_packets: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                packets: BTreeMap::new(),
                next_seq: 0,
                buf: Vec::new(),
                closed: false,
            }),
            cv_pushed: Condvar::new(),
            cv_popped: Condvar::new(),
            max_packets,
        })
    }

    pub fn push(&self, p: Packet) -> io::Result<()> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "queue closed"));
        }
        while inner.packets.len() > self.max_packets {
            self.cv_popped.wait(&mut inner);
            if inner.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "queue closed"));
            }
        }
        inner.packets.insert(p.seq, p.payload);
        self.cv_pushed.notify_all();
        Ok(())
    }

    pub fn read(&self, dst: &mut [u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock();
        loop {
            if !inner.buf.is_empty() {
                let n = dst.len().min(inner.buf.len());
                dst[..n].copy_from_slice(&inner.buf[..n]);
                inner.buf.drain(..n);
                return Ok(n);
            }
            let next = inner.next_seq;
            if let Some(payload) = inner.packets.remove(&next) {
                inner.next_seq += 1;
                inner.buf = payload;
                self.cv_popped.notify_all();
                continue;
            }
            if inner.closed {
                return Ok(0); // EOF
            }
            if inner.packets.len() > self.max_packets {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "packet queue too large",
                ));
            }
            self.cv_pushed.wait(&mut inner);
        }
    }

    pub fn close(&self) {
        let mut inner = self.inner.lock();
        inner.closed = true;
        self.cv_pushed.notify_all();
        self.cv_popped.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn push_pop_in_order() {
        let q = UploadQueue::new(16);
        q.push(Packet {
            seq: 0,
            payload: b"hello ".to_vec(),
        })
        .unwrap();
        q.push(Packet {
            seq: 1,
            payload: b"world".to_vec(),
        })
        .unwrap();
        let mut out = vec![0u8; 16];
        let n = q.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"hello ");
        let n = q.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"world");
    }

    #[test]
    fn out_of_order_reassembly() {
        let q = UploadQueue::new(16);
        q.push(Packet {
            seq: 2,
            payload: b"!".to_vec(),
        })
        .unwrap();
        q.push(Packet {
            seq: 0,
            payload: b"hi".to_vec(),
        })
        .unwrap();
        q.push(Packet {
            seq: 1,
            payload: b" there".to_vec(),
        })
        .unwrap();
        let mut combined = Vec::new();
        let mut out = vec![0u8; 16];
        for _ in 0..3 {
            let n = q.read(&mut out).unwrap();
            combined.extend_from_slice(&out[..n]);
        }
        assert_eq!(&combined, b"hi there!");
    }

    #[test]
    fn close_signals_eof() {
        let q = UploadQueue::new(16);
        let q2 = q.clone();
        thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            q2.close();
        });
        let mut out = vec![0u8; 16];
        let n = q.read(&mut out).unwrap();
        assert_eq!(n, 0); // EOF
    }
}
