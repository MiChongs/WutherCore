use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use core_config::{FragmentMaskConfig, I32Range};
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};

use crate::adapter::BoxedStream;

struct Piece {
    bytes: Vec<u8>,
    written: usize,
    delay_after: Duration,
}

struct PendingWrite {
    original_len: usize,
    pieces: Vec<Piece>,
    current: usize,
    sleep: Option<Pin<Box<Sleep>>>,
}

pub(super) struct FragmentStream {
    inner: BoxedStream,
    config: FragmentMaskConfig,
    writes: u64,
    pending: Option<PendingWrite>,
}

impl FragmentStream {
    pub(super) fn wrap(inner: BoxedStream, config: FragmentMaskConfig) -> BoxedStream {
        Box::pin(Self {
            inner,
            config,
            writes: 0,
            pending: None,
        })
    }

    fn make_pending(&mut self, input: &[u8]) -> PendingWrite {
        self.writes += 1;
        let pieces = if self.is_tls_hello_write(input) {
            self.split_tls_hello(input)
        } else if self.should_fragment_write() {
            self.split_plain(input)
        } else {
            vec![Piece {
                bytes: input.to_vec(),
                written: 0,
                delay_after: Duration::ZERO,
            }]
        };
        PendingWrite {
            original_len: input.len(),
            pieces,
            current: 0,
            sleep: None,
        }
    }

    fn should_fragment_write(&self) -> bool {
        if self.config.packets.eq_ignore_ascii_case("tlshello") {
            return false;
        }
        let packets = self.config.packets.trim();
        if packets.is_empty() {
            return true;
        }
        let Some((from, to)) = parse_packet_range(packets) else {
            return false;
        };
        let count = self.writes as i64;
        count >= from && count <= to
    }

    fn is_tls_hello_write(&self, input: &[u8]) -> bool {
        if !self.config.packets.eq_ignore_ascii_case("tlshello")
            || self.writes != 1
            || input.len() <= 5
            || input[0] != 22
        {
            return false;
        }
        let record_len = 5 + usize::from(u16::from_be_bytes([input[3], input[4]]));
        input.len() >= record_len
    }

    fn lengths(&self) -> &[I32Range] {
        if self.config.lengths.is_empty() {
            std::slice::from_ref(&self.config.length)
        } else {
            &self.config.lengths
        }
    }

    fn delays(&self) -> &[I32Range] {
        if self.config.delays.is_empty() {
            std::slice::from_ref(&self.config.delay)
        } else {
            &self.config.delays
        }
    }

    fn split_plain(&self, input: &[u8]) -> Vec<Piece> {
        self.split_payload(input, false)
    }

    fn split_tls_hello(&self, input: &[u8]) -> Vec<Piece> {
        let record_len = 5 + usize::from(u16::from_be_bytes([input[3], input[4]]));
        let payload = &input[5..record_len];
        let merge = self.delays().len() == 1 && self.delays()[0].to == 0;
        let mut fragments = self.split_payload(payload, true);
        for fragment in &mut fragments {
            fragment.bytes[..3].copy_from_slice(&input[..3]);
        }
        let mut pieces = if merge {
            vec![Piece {
                bytes: fragments
                    .into_iter()
                    .flat_map(|piece| piece.bytes)
                    .collect(),
                written: 0,
                delay_after: Duration::ZERO,
            }]
        } else {
            fragments
        };
        if input.len() > record_len {
            pieces.push(Piece {
                bytes: input[record_len..].to_vec(),
                written: 0,
                delay_after: Duration::ZERO,
            });
        }
        pieces
    }

    fn split_payload(&self, input: &[u8], tls_records: bool) -> Vec<Piece> {
        if input.is_empty() {
            return vec![Piece {
                bytes: Vec::new(),
                written: 0,
                delay_after: Duration::ZERO,
            }];
        }
        let lengths = self.lengths();
        let delays = self.delays();
        let max_split = random_between(self.config.max_split).max(0) as usize;
        let mut pieces = Vec::new();
        let mut offset = 0;
        let mut index = 0;
        while offset < input.len() {
            let range = lengths[index.min(lengths.len() - 1)];
            let requested = random_between(range).max(0) as usize;
            let mut end = offset.saturating_add(requested).min(input.len());
            if max_split > 0 && index + 1 >= max_split {
                end = input.len();
            }
            // Earlier ranges may legally contain zero. Once the last range is
            // reached validation guarantees progress; this guard also avoids
            // a malformed runtime object spinning forever.
            if end == offset && index >= lengths.len() - 1 {
                end = input.len();
            }
            let delay = delays[index.min(delays.len() - 1)];
            let delay_ms = random_between(delay).max(0) as u64;
            let bytes = if tls_records {
                let payload = &input[offset..end];
                let mut record = Vec::with_capacity(5 + payload.len());
                record.extend_from_slice(&[22, 3, 0]);
                record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                record.extend_from_slice(payload);
                record
            } else {
                input[offset..end].to_vec()
            };
            pieces.push(Piece {
                bytes,
                written: 0,
                delay_after: Duration::from_millis(delay_ms),
            });
            offset = end;
            index += 1;
        }
        pieces
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let pending = self.pending.as_mut().expect("pending write");
        loop {
            if let Some(sleep) = pending.sleep.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                pending.sleep = None;
            }
            if pending.current >= pending.pieces.len() {
                let len = pending.original_len;
                self.pending = None;
                return Poll::Ready(Ok(len));
            }
            let piece = &mut pending.pieces[pending.current];
            if piece.written < piece.bytes.len() {
                match self
                    .inner
                    .as_mut()
                    .poll_write(cx, &piece.bytes[piece.written..])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "fragment carrier returned write zero",
                        )));
                    }
                    Poll::Ready(Ok(written)) => piece.written += written,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            let delay = piece.delay_after;
            pending.current += 1;
            if !delay.is_zero() {
                pending.sleep = Some(Box::pin(tokio::time::sleep(delay)));
            }
        }
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending.is_none() {
            self.pending = Some(self.make_pending(buf));
        }
        self.poll_pending(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending.is_some() {
            match self.poll_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending.is_some() {
            match self.poll_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.inner.as_mut().poll_shutdown(cx)
    }
}

fn random_between(range: I32Range) -> i32 {
    if range.from == range.to {
        range.from
    } else {
        rand::thread_rng().gen_range(range.from..range.to)
    }
}

fn parse_packet_range(value: &str) -> Option<(i64, i64)> {
    if let Ok(single) = value.parse::<i64>() {
        return Some((single, single));
    }
    let (from, to) = value.split_once('-')?;
    let from = from.trim().parse::<i64>().ok()?;
    let to = to.trim().parse::<i64>().ok()?;
    Some((from.min(to), from.max(to)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tlshello_golden_rewrites_each_record_length_and_preserves_tail() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut peer) = tokio::io::duplex(256);
        let config = FragmentMaskConfig {
            packets: "tlshello".into(),
            length: I32Range::fixed(2),
            delay: I32Range::fixed(0),
            max_split: I32Range::fixed(0),
            ..Default::default()
        };
        let mut stream = FragmentStream::wrap(Box::pin(client), config);
        let input = [22, 3, 3, 0, 5, 1, 2, 3, 4, 5, 99];
        stream.write_all(&input).await.unwrap();
        stream.flush().await.unwrap();
        let mut got = vec![0; 21];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got,
            vec![
                22, 3, 3, 0, 2, 1, 2, 22, 3, 3, 0, 2, 3, 4, 22, 3, 3, 0, 1, 5, 99
            ]
        );
    }
}
