use std::io::{self, BufRead, Read};

pub(crate) struct SliceReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> SliceReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    pub(crate) fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.read_slice(1)?[0])
    }

    pub(crate) fn read_u16_be(&mut self) -> io::Result<u16> {
        let b = self.read_slice(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn read_u24_be(&mut self) -> io::Result<usize> {
        let b = self.read_slice(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }

    pub(crate) fn read_slice(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;
        if end > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated input",
            ));
        }
        let out = &self.data[self.position..end];
        self.position = end;
        Ok(out)
    }

    pub(crate) fn skip(&mut self, len: usize) -> io::Result<()> {
        self.read_slice(len).map(|_| ())
    }
}

pub(crate) struct SlideBuffer {
    data: Vec<u8>,
    start: usize,
    capacity_limit: usize,
}

impl SlideBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            start: 0,
            capacity_limit: capacity,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len() - self.start
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(crate) fn remaining_capacity(&self) -> usize {
        self.capacity_limit.saturating_sub(self.len())
    }
    pub(crate) fn compact(&mut self) {
        if self.start > 0 {
            self.data.drain(..self.start);
            self.start = 0;
        }
    }
    pub(crate) fn maybe_compact(&mut self, threshold: usize) {
        if self.start > threshold {
            self.compact();
        }
    }
    pub(crate) fn extend_from_slice(&mut self, data: &[u8]) {
        self.compact();
        self.data.extend_from_slice(data);
    }
    pub(crate) fn consume(&mut self, amount: usize) {
        self.start = (self.start + amount).min(self.data.len());
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }
    pub(crate) fn get_u16_be(&self, offset: usize) -> Option<u16> {
        let bytes = self.as_slice().get(offset..offset.checked_add(2)?)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    pub(crate) fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        let start = self.start + range.start;
        let end = self.start + range.end;
        &mut self.data[start..end]
    }
}

impl Read for SlideBuffer {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.len());
        out[..n].copy_from_slice(&self.as_slice()[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for SlideBuffer {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(self.as_slice())
    }
    fn consume(&mut self, amt: usize) {
        SlideBuffer::consume(self, amt);
    }
}

impl std::ops::Index<usize> for SlideBuffer {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for SlideBuffer {
    type Output = [u8];
    fn index(&self, index: std::ops::Range<usize>) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl std::ops::Index<std::ops::RangeFrom<usize>> for SlideBuffer {
    type Output = [u8];
    fn index(&self, index: std::ops::RangeFrom<usize>) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for SlideBuffer {
    type Output = [u8];
    fn index(&self, index: std::ops::RangeTo<usize>) -> &Self::Output {
        &self.as_slice()[index]
    }
}
