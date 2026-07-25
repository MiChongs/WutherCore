use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock},
};

use core_config::SudokuMaskConfig;
use ggstd::math::rand::{Rand as GoRand, new_source};
use parking_lot::Mutex;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::BoxedStream;

const PERM4: [[usize; 4]; 24] = [
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

#[derive(Clone)]
enum LayoutKind {
    Ascii,
    Entropy,
    Custom {
        x_bits: [u8; 2],
        p_bits: [u8; 2],
        v_bits: [u8; 4],
        x_mask: u8,
    },
}

#[derive(Clone)]
struct Layout {
    hint_mask: u8,
    hint_value: u8,
    pad_marker: u8,
    padding_pool: Vec<u8>,
    kind: LayoutKind,
}

impl Layout {
    fn is_hint(&self, byte: u8) -> bool {
        (byte & self.hint_mask) == self.hint_value
            || (matches!(self.kind, LayoutKind::Ascii) && byte == b'\n')
    }

    fn encode_group(&self, group: u8) -> u8 {
        match &self.kind {
            LayoutKind::Ascii => {
                let byte = 0x40 | (group & 0x3f);
                if byte == 0x7f { b'\n' } else { byte }
            }
            LayoutKind::Entropy => {
                let value = group & 0x3f;
                ((value & 0x30) << 1) | (value & 0x0f)
            }
            LayoutKind::Custom {
                x_bits,
                p_bits,
                v_bits,
                x_mask,
            } => encode_custom_group(group, *x_bits, *p_bits, *v_bits, *x_mask, None),
        }
    }

    fn decode_group(&self, byte: u8) -> Option<u8> {
        match &self.kind {
            LayoutKind::Ascii => {
                if byte == b'\n' {
                    Some(0x3f)
                } else if byte & 0x40 != 0 {
                    Some(byte & 0x3f)
                } else {
                    None
                }
            }
            LayoutKind::Entropy => {
                (byte & 0x90 == 0).then_some(((byte >> 1) & 0x30) | (byte & 0x0f))
            }
            LayoutKind::Custom {
                p_bits,
                v_bits,
                x_mask,
                ..
            } => {
                if byte & x_mask != *x_mask {
                    return None;
                }
                let mut value = 0;
                let mut position = 0;
                if byte & (1 << p_bits[0]) != 0 {
                    value |= 2;
                }
                if byte & (1 << p_bits[1]) != 0 {
                    value |= 1;
                }
                for (index, bit) in v_bits.iter().copied().enumerate() {
                    if byte & (1 << bit) != 0 {
                        position |= 1 << (3 - index);
                    }
                }
                Some((value << 4) | position)
            }
        }
    }
}

struct Table {
    encode: Vec<Vec<[u8; 4]>>,
    decode: HashMap<u32, u8>,
    layout: Arc<Layout>,
}

type Grid = [u8; 16];
type BasePatterns = Vec<Vec<[u8; 4]>>;

static BASE_PATTERNS: LazyLock<Result<BasePatterns, String>> = LazyLock::new(build_base_patterns);
static TABLE_CACHE: LazyLock<Mutex<HashMap<String, Arc<Vec<Arc<Table>>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn wrap(inner: BoxedStream, config: &SudokuMaskConfig) -> std::io::Result<BoxedStream> {
    let tables = get_tables(config)?;
    let padding_min = effective_padding_min(config).min(100);
    let padding_max = effective_padding_max(config).max(padding_min).min(100);
    let (client, worker) = tokio::io::duplex(64 * 1024);
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let (mut raw_read, mut raw_write) = tokio::io::split(inner);
    let encode_tables = tables.clone();
    tokio::spawn(async move {
        let mut codec = Encoder::new(encode_tables, padding_min, padding_max);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = app_read.read(&mut buffer).await?;
                if count == 0 {
                    raw_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let encoded = codec.encode(&buffer[..count])?;
                raw_write.write_all(&encoded).await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku encoder stopped");
        }
    });
    tokio::spawn(async move {
        // Xray 26.7.11 is directional: clients write classic four-hint
        // Sudoku and read the packed 6-bit downlink representation.
        let mut decoder = PackedDecoder::new(tables);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = raw_read.read(&mut buffer).await?;
                if count == 0 {
                    app_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let decoded = decoder.decode(&buffer[..count])?;
                if !decoded.is_empty() {
                    app_write.write_all(&decoded).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku decoder stopped");
        }
    });
    Ok(Box::pin(client))
}

/// Server direction is intentionally asymmetric in Xray 26.7.11: the server
/// reads classic four-hint Sudoku and writes the packed six-bit form.
pub(super) fn wrap_server(
    inner: BoxedStream,
    config: &SudokuMaskConfig,
) -> std::io::Result<BoxedStream> {
    let tables = get_tables(config)?;
    let padding_min = effective_padding_min(config).min(100);
    let padding_max = effective_padding_max(config).max(padding_min).min(100);
    let (client, worker) = tokio::io::duplex(64 * 1024);
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let (mut raw_read, mut raw_write) = tokio::io::split(inner);
    let encode_tables = tables.clone();
    tokio::spawn(async move {
        let mut codec = PackedEncoder::new(encode_tables, padding_min, padding_max);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = app_read.read(&mut buffer).await?;
                if count == 0 {
                    raw_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                raw_write
                    .write_all(&codec.encode(&buffer[..count])?)
                    .await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku packed encoder stopped");
        }
    });
    tokio::spawn(async move {
        let mut decoder = HintDecoder::new(tables);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = raw_read.read(&mut buffer).await?;
                if count == 0 {
                    app_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let decoded = decoder.decode(&buffer[..count])?;
                if !decoded.is_empty() {
                    app_write.write_all(&decoded).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku hint decoder stopped");
        }
    });
    Ok(Box::pin(client))
}

pub(super) struct UdpCodec {
    tables: Arc<Vec<Arc<Table>>>,
    padding_min: u32,
    padding_max: u32,
}

impl UdpCodec {
    pub(super) fn new(config: &SudokuMaskConfig) -> std::io::Result<Self> {
        let tables = get_tables(config)?;
        let padding_min = effective_padding_min(config).min(100);
        let padding_max = effective_padding_max(config).max(padding_min).min(100);
        Ok(Self {
            tables,
            padding_min,
            padding_max,
        })
    }

    /// UDP resets table index and padding choice for every datagram upstream.
    pub(super) fn encode(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        Encoder::new(self.tables.clone(), self.padding_min, self.padding_max).encode(payload)
    }

    pub(super) fn decode(&self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut decoder = HintDecoder::new(self.tables.clone());
        let output = decoder.decode(packet)?;
        if !decoder.hints.is_empty() {
            return Err(invalid(
                "UDP Sudoku datagram ends with an incomplete hint tuple",
            ));
        }
        Ok(output)
    }
}

struct Encoder {
    tables: Arc<Vec<Arc<Table>>>,
    table_index: usize,
    padding_chance: u32,
}

impl Encoder {
    fn new(tables: Arc<Vec<Arc<Table>>>, min: u32, max: u32) -> Self {
        let padding_chance = if min == max {
            min
        } else {
            rand::thread_rng().gen_range(min..=max)
        };
        Self {
            tables,
            table_index: 0,
            padding_chance,
        }
    }

    fn should_pad(&self, rng: &mut impl Rng) -> bool {
        self.padding_chance >= 100
            || (self.padding_chance > 0 && rng.gen_range(0..100) < self.padding_chance)
    }

    fn encode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let mut output = Vec::with_capacity(input.len() * 6 + 8);
        for &byte in input {
            let table = &self.tables[self.table_index % self.tables.len()];
            if self.should_pad(&mut rng) {
                output.push(
                    table.layout.padding_pool[rng.gen_range(0..table.layout.padding_pool.len())],
                );
            }
            let candidates = &table.encode[byte as usize];
            let hints = candidates
                .get(rng.gen_range(0..candidates.len()))
                .ok_or_else(|| invalid("sudoku encode table is empty"))?;
            let permutation = PERM4[rng.gen_range(0..PERM4.len())];
            for index in permutation {
                if self.should_pad(&mut rng) {
                    output.push(
                        table.layout.padding_pool
                            [rng.gen_range(0..table.layout.padding_pool.len())],
                    );
                }
                output.push(hints[index]);
            }
            self.table_index += 1;
        }
        if self.should_pad(&mut rng) {
            let table = &self.tables[self.table_index % self.tables.len()];
            output
                .push(table.layout.padding_pool[rng.gen_range(0..table.layout.padding_pool.len())]);
        }
        Ok(output)
    }
}

struct PackedDecoder {
    tables: Arc<Vec<Arc<Table>>>,
    group_index: usize,
    bit_buffer: u64,
    bit_count: usize,
}

struct HintDecoder {
    tables: Arc<Vec<Arc<Table>>>,
    table_index: usize,
    hints: Vec<u8>,
}

impl HintDecoder {
    fn new(tables: Arc<Vec<Arc<Table>>>) -> Self {
        Self {
            tables,
            table_index: 0,
            hints: Vec::with_capacity(4),
        }
    }

    fn decode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() / 4 + 1);
        for &byte in input {
            let table = &self.tables[self.table_index % self.tables.len()];
            if !table.layout.is_hint(byte) {
                continue;
            }
            self.hints.push(byte);
            if self.hints.len() != 4 {
                continue;
            }
            let mut hints: [u8; 4] = self.hints[..].try_into().expect("four hints");
            hints.sort_unstable();
            let decoded = table
                .decode
                .get(&pack_key(hints))
                .copied()
                .ok_or_else(|| invalid("invalid sudoku hint tuple"))?;
            output.push(decoded);
            self.hints.clear();
            self.table_index += 1;
        }
        Ok(output)
    }
}

struct PackedEncoder {
    tables: Arc<Vec<Arc<Table>>>,
    group_index: usize,
    padding_chance: u32,
}

impl PackedEncoder {
    fn new(tables: Arc<Vec<Arc<Table>>>, min: u32, max: u32) -> Self {
        let padding_chance = if min == max {
            min
        } else {
            rand::thread_rng().gen_range(min..=max)
        };
        Self {
            tables,
            group_index: 0,
            padding_chance,
        }
    }

    fn should_pad(&self, rng: &mut impl Rng) -> bool {
        self.padding_chance >= 100
            || (self.padding_chance > 0 && rng.gen_range(0..100) < self.padding_chance)
    }

    fn maybe_pad(&self, output: &mut Vec<u8>, layout: &Layout, rng: &mut impl Rng) {
        if !self.should_pad(rng) {
            return;
        }
        loop {
            let byte = layout.padding_pool[rng.gen_range(0..layout.padding_pool.len())];
            if byte != layout.pad_marker {
                output.push(byte);
                return;
            }
        }
    }

    fn encode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() * 2 + 8);
        let mut bit_buffer = 0u64;
        let mut bit_count = 0usize;
        let mut rng = rand::thread_rng();
        for &byte in input {
            bit_buffer = (bit_buffer << 8) | u64::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                let layout = &self.tables[self.group_index % self.tables.len()].layout;
                let group = (bit_buffer >> bit_count) as u8 & 0x3f;
                self.maybe_pad(&mut output, layout, &mut rng);
                output.push(layout.encode_group(group));
                self.group_index += 1;
                if bit_count == 0 {
                    bit_buffer = 0;
                } else {
                    bit_buffer &= (1u64 << bit_count) - 1;
                }
            }
        }
        if bit_count > 0 {
            let layout = &self.tables[self.group_index % self.tables.len()].layout;
            let group = (bit_buffer << (6 - bit_count)) as u8 & 0x3f;
            self.maybe_pad(&mut output, layout, &mut rng);
            output.push(layout.encode_group(group));
            self.group_index += 1;
            output.push(
                self.tables[self.group_index % self.tables.len()]
                    .layout
                    .pad_marker,
            );
        }
        let layout = &self.tables[self.group_index % self.tables.len()].layout;
        self.maybe_pad(&mut output, layout, &mut rng);
        Ok(output)
    }
}

impl PackedDecoder {
    fn new(tables: Arc<Vec<Arc<Table>>>) -> Self {
        Self {
            tables,
            group_index: 0,
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn decode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        for &byte in input {
            let table = &self.tables[self.group_index % self.tables.len()];
            if !table.layout.is_hint(byte) {
                // Packed encoders terminate a padded partial 6-bit group with
                // the next layout's marker. Discarding the residual bits is
                // what keeps independently written chunks byte-aligned.
                if byte == table.layout.pad_marker {
                    self.bit_buffer = 0;
                    self.bit_count = 0;
                }
                continue;
            }
            let group = table
                .layout
                .decode_group(byte)
                .ok_or_else(|| invalid("invalid packed sudoku byte"))?;
            self.group_index += 1;
            self.bit_buffer = (self.bit_buffer << 6) | u64::from(group);
            self.bit_count += 6;
            while self.bit_count >= 8 {
                self.bit_count -= 8;
                output.push((self.bit_buffer >> self.bit_count) as u8);
                if self.bit_count == 0 {
                    self.bit_buffer = 0;
                } else {
                    self.bit_buffer &= (1u64 << self.bit_count) - 1;
                }
            }
        }
        Ok(output)
    }
}

fn get_tables(config: &SudokuMaskConfig) -> std::io::Result<Arc<Vec<Arc<Table>>>> {
    let key = serde_json::to_string(config).map_err(invalid)?;
    if let Some(cached) = TABLE_CACHE.lock().get(&key).cloned() {
        return Ok(cached);
    }
    let mode = normalize_ascii(&config.ascii)?;
    let patterns = normalized_patterns(config, mode)?;
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let layout = match mode {
            "prefer_ascii" => ascii_layout(),
            _ if !pattern.is_empty() => custom_layout(&pattern)?,
            _ => entropy_layout(),
        };
        tables.push(Arc::new(build_table(&config.password, Arc::new(layout))?));
    }
    let tables = Arc::new(tables);
    TABLE_CACHE.lock().insert(key, tables.clone());
    Ok(tables)
}

fn normalize_ascii(value: &str) -> std::io::Result<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Ok("prefer_entropy"),
        "ascii" | "prefer_ascii" => Ok("prefer_ascii"),
        _ => Err(invalid(format!("invalid sudoku ascii mode `{value}`"))),
    }
}

fn normalized_patterns(config: &SudokuMaskConfig, mode: &str) -> std::io::Result<Vec<String>> {
    if mode == "prefer_ascii" {
        return Ok(vec![String::new()]);
    }
    let custom_table = if config.custom_table.is_empty() {
        &config.legacy_custom_table
    } else {
        &config.custom_table
    };
    let source = if !config.custom_tables.is_empty() {
        config.custom_tables.clone()
    } else if !config.legacy_custom_sets.is_empty() {
        config.legacy_custom_sets.clone()
    } else {
        vec![custom_table.clone()]
    };
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for pattern in source {
        let pattern = if pattern.trim().is_empty() {
            String::new()
        } else {
            normalize_custom_table(&pattern)?
        };
        if seen.insert(pattern.clone()) {
            output.push(pattern);
        }
    }
    if output.is_empty() {
        output.push(String::new());
    }
    Ok(output)
}

fn effective_padding_min(config: &SudokuMaskConfig) -> u32 {
    if config.padding_min == 0 {
        config.legacy_padding_min
    } else {
        config.padding_min
    }
}

fn effective_padding_max(config: &SudokuMaskConfig) -> u32 {
    if config.padding_max == 0 {
        config.legacy_padding_max
    } else {
        config.padding_max
    }
}

fn ascii_layout() -> Layout {
    Layout {
        hint_mask: 0x40,
        hint_value: 0x40,
        pad_marker: 0x3f,
        padding_pool: (0x20..0x40).collect(),
        kind: LayoutKind::Ascii,
    }
}

fn entropy_layout() -> Layout {
    let mut padding_pool = Vec::with_capacity(16);
    for index in 0..8 {
        padding_pool.extend_from_slice(&[0x80 + index, 0x10 + index]);
    }
    Layout {
        hint_mask: 0x90,
        hint_value: 0,
        pad_marker: 0x80,
        padding_pool,
        kind: LayoutKind::Entropy,
    }
}

fn normalize_custom_table(pattern: &str) -> std::io::Result<String> {
    let pattern = pattern.trim().to_ascii_lowercase().replace(' ', "");
    if pattern.len() != 8
        || pattern.bytes().filter(|&byte| byte == b'x').count() != 2
        || pattern.bytes().filter(|&byte| byte == b'p').count() != 2
        || pattern.bytes().filter(|&byte| byte == b'v').count() != 4
        || pattern
            .bytes()
            .any(|byte| !matches!(byte, b'x' | b'p' | b'v'))
    {
        return Err(invalid("customTable must contain exactly 2 x, 2 p and 4 v"));
    }
    Ok(pattern)
}

fn custom_layout(pattern: &str) -> std::io::Result<Layout> {
    let pattern = normalize_custom_table(pattern)?;
    let mut x = Vec::new();
    let mut p = Vec::new();
    let mut v = Vec::new();
    for (index, byte) in pattern.bytes().enumerate() {
        let bit = 7 - index as u8;
        match byte {
            b'x' => x.push(bit),
            b'p' => p.push(bit),
            b'v' => v.push(bit),
            _ => unreachable!(),
        }
    }
    let x_bits = [x[0], x[1]];
    let p_bits = [p[0], p[1]];
    let v_bits = [v[0], v[1], v[2], v[3]];
    let x_mask = (1 << x_bits[0]) | (1 << x_bits[1]);
    let mut padding = HashSet::new();
    for drop in 0..2 {
        for value in 0..4 {
            for position in 0..16 {
                let group = (value << 4) | position;
                let byte = encode_custom_group(group, x_bits, p_bits, v_bits, x_mask, Some(drop));
                if byte.count_ones() >= 5 {
                    padding.insert(byte);
                }
            }
        }
    }
    let mut padding_pool = padding.into_iter().collect::<Vec<_>>();
    padding_pool.sort_unstable();
    if padding_pool.is_empty() {
        return Err(invalid("customTable produced empty padding pool"));
    }
    let pad_marker = padding_pool[0];
    Ok(Layout {
        hint_mask: x_mask,
        hint_value: x_mask,
        pad_marker,
        padding_pool,
        kind: LayoutKind::Custom {
            x_bits,
            p_bits,
            v_bits,
            x_mask,
        },
    })
}

fn encode_custom_group(
    group: u8,
    x_bits: [u8; 2],
    p_bits: [u8; 2],
    v_bits: [u8; 4],
    x_mask: u8,
    drop_x: Option<usize>,
) -> u8 {
    let mut output = x_mask;
    if let Some(drop) = drop_x {
        output &= !(1 << x_bits[drop]);
    }
    let value = (group >> 4) & 3;
    let position = group & 15;
    if value & 2 != 0 {
        output |= 1 << p_bits[0];
    }
    if value & 1 != 0 {
        output |= 1 << p_bits[1];
    }
    for (index, bit) in v_bits.into_iter().enumerate() {
        if (position >> (3 - index)) & 1 != 0 {
            output |= 1 << bit;
        }
    }
    output
}

fn build_table(password: &str, layout: Arc<Layout>) -> std::io::Result<Table> {
    let patterns = BASE_PATTERNS.as_ref().map_err(|error| invalid(error))?;
    if patterns.len() < 256 {
        return Err(invalid("not enough sudoku grids"));
    }
    let mut order = (0..patterns.len()).collect::<Vec<_>>();
    let hash = Sha256::digest(password.as_bytes());
    let seed = i64::from_be_bytes(hash[..8].try_into().expect("sha prefix"));
    let mut go_rng = GoRand::new(new_source(seed));
    for index in (1..order.len()).rev() {
        // Go's Shuffle uses its private Lemire `int31n`, deliberately not the
        // public compatibility-preserving `Int31n`. Copy that reduction over
        // the exact Go Source stream exposed by `ggstd`.
        let n = (index + 1) as u32;
        let mut value = go_rng.uint32();
        let mut product = u64::from(value) * u64::from(n);
        let mut low = product as u32;
        if low < n {
            let threshold = n.wrapping_neg() % n;
            while low < threshold {
                value = go_rng.uint32();
                product = u64::from(value) * u64::from(n);
                low = product as u32;
            }
        }
        order.swap(index, (product >> 32) as usize);
    }
    let mut encode = vec![Vec::new(); 256];
    let mut decode = HashMap::with_capacity(1 << 16);
    for byte in 0..256 {
        for groups in &patterns[order[byte]] {
            let mut hints = groups.map(|group| layout.encode_group(group));
            hints.sort_unstable();
            let key = pack_key(hints);
            if let Some(previous) = decode.insert(key, byte as u8)
                && previous != byte as u8
            {
                return Err(invalid("sudoku decode key collision"));
            }
            encode[byte].push(groups.map(|group| layout.encode_group(group)));
        }
    }
    Ok(Table {
        encode,
        decode,
        layout,
    })
}

fn build_base_patterns() -> Result<BasePatterns, String> {
    let grids = generate_all_grids();
    let positions = hint_positions();
    let mut patterns = vec![Vec::new(); grids.len()];
    for positions in positions {
        let mut counts = HashMap::<u32, u16>::with_capacity(grids.len());
        let mut keys = Vec::with_capacity(grids.len());
        let mut groups_by_grid = Vec::with_capacity(grids.len());
        for grid in &grids {
            let mut groups = positions.map(|position| clue_group(grid, position));
            groups.sort_unstable();
            let key = pack_key(groups);
            *counts.entry(key).or_default() += 1;
            keys.push(key);
            groups_by_grid.push(groups);
        }
        for index in 0..grids.len() {
            if counts[&keys[index]] == 1 {
                patterns[index].push(groups_by_grid[index]);
            }
        }
    }
    if patterns.iter().any(Vec::is_empty) {
        return Err("a sudoku grid has no uniquely decodable clue set".into());
    }
    Ok(patterns)
}

fn generate_all_grids() -> Vec<Grid> {
    fn dfs(index: usize, grid: &mut Grid, output: &mut Vec<Grid>) {
        if index == 16 {
            output.push(*grid);
            return;
        }
        let row = index / 4;
        let column = index % 4;
        let box_row = (row / 2) * 2;
        let box_column = (column / 2) * 2;
        for number in 1..=4 {
            if (0..4).any(|i| grid[row * 4 + i] == number || grid[i * 4 + column] == number) {
                continue;
            }
            if (0..2).any(|r| (0..2).any(|c| grid[(box_row + r) * 4 + box_column + c] == number)) {
                continue;
            }
            grid[index] = number;
            dfs(index + 1, grid, output);
            grid[index] = 0;
        }
    }
    let mut output = Vec::with_capacity(288);
    dfs(0, &mut [0; 16], &mut output);
    output
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut output = Vec::with_capacity(1820);
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    output.push([a, b, c, d]);
                }
            }
        }
    }
    output
}

fn clue_group(grid: &Grid, position: u8) -> u8 {
    ((grid[position as usize] - 1) << 4) | (position & 15)
}

fn pack_key(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_roundtrip_and_go_shuffle_are_stable() {
        let config = SudokuMaskConfig {
            password: "sudoku-golden".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let tables = get_tables(&config).unwrap();
        let table = &tables[0];
        // This table is derived using Go math/rand via `ggstd`, not Rust's
        // ChaCha RNG. Every official hint tuple must decode to its byte.
        for byte in [0u8, 1, 42, 127, 255] {
            let mut hints = table.encode[byte as usize][0];
            hints.sort_unstable();
            assert_eq!(table.decode.get(&pack_key(hints)), Some(&byte));
        }

        // Generated by the pinned Xray 26.7.11 `buildTable` implementation
        // (commit 6e3322d) over every candidate tuple, including list order.
        let mut digest = Sha256::new();
        for candidates in &table.encode {
            digest.update((candidates.len() as u32).to_be_bytes());
            for tuple in candidates {
                digest.update(tuple);
            }
        }
        assert_eq!(
            hex::encode(digest.finalize()),
            "8b1bf1fdb13064b003cda40f0d40a0bf7b3af2100e49c21db12e324e7271c564"
        );
        assert_eq!(table.encode[0][0], *b"KX`q");
        assert_eq!(table.encode[1][0], *b"JPis");
        assert_eq!(table.encode[42][0], *b"BD`{");
        assert_eq!(table.encode[127][0], *b"NTbp");
        assert_eq!(table.encode[255][0], *b"DPjr");
    }

    #[test]
    fn packed_client_downlink_matches_xray_ascii_golden_across_chunks() {
        let table = Arc::new(build_table("packed-golden", Arc::new(ascii_layout())).unwrap());
        let mut decoder = PackedDecoder::new(Arc::new(vec![table]));

        // Xray's packed encoder maps [0x48, 0x69, 0xff] to the four 6-bit
        // groups `R`, `F`, `g`, `\n`. A one-byte write [0xab] becomes `j`,
        // `p`, followed by ASCII's 0x3f pad marker to discard the padded tail.
        assert_eq!(decoder.decode(b"RF").unwrap(), [0x48]);
        assert_eq!(decoder.decode(b"g\n").unwrap(), [0x69, 0xff]);
        assert_eq!(decoder.decode(&[b'j', b'p', 0x3f]).unwrap(), [0xab]);
    }

    #[test]
    fn packed_group_codec_roundtrips_every_official_layout() {
        let layouts = [
            ascii_layout(),
            entropy_layout(),
            custom_layout("xxppvvvv").unwrap(),
        ];
        for layout in layouts {
            assert!(!layout.is_hint(layout.pad_marker));
            for group in 0..64 {
                let encoded = layout.encode_group(group);
                assert!(layout.is_hint(encoded));
                assert_eq!(layout.decode_group(encoded), Some(group));
            }
        }
    }

    #[test]
    fn udp_codec_restarts_at_table_zero_for_every_datagram() {
        let config = SudokuMaskConfig {
            password: "udp-golden".into(),
            custom_tables: vec!["xxppvvvv".into(), "vvxxppvv".into()],
            ..Default::default()
        };
        let codec = UdpCodec::new(&config).unwrap();
        for payload in [b"one".as_slice(), b"second datagram".as_slice()] {
            let encoded = codec.encode(payload).unwrap();
            assert_eq!(codec.decode(&encoded).unwrap(), payload);
        }
    }

    #[test]
    fn udp_codec_rejects_truncated_hint_tuple() {
        let config = SudokuMaskConfig {
            password: "udp-negative".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let codec = UdpCodec::new(&config).unwrap();
        assert!(codec.decode(b"ABC").is_err());
    }

    #[tokio::test]
    async fn client_and_server_stream_directions_roundtrip() {
        let config = SudokuMaskConfig {
            password: "stream-bidirectional".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let (left, right) = tokio::io::duplex(64 * 1024);
        let mut client = wrap(Box::pin(left), &config).unwrap();
        let mut server = wrap_server(Box::pin(right), &config).unwrap();
        client.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }
}
