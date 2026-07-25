use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::{Duration, Instant},
};

use base64::Engine;
use core_config::{
    CustomTransform, CustomTransformArg, HeaderCustomTcpConfig, HeaderCustomTcpItem,
    HeaderCustomUdpConfig, HeaderCustomUdpItem, I32Range,
};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::BoxedStream;

#[derive(Clone)]
enum EvalValue {
    Bytes(Vec<u8>),
    U64(u64),
}

#[derive(Default)]
struct EvalContext {
    vars: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, EvalValue>,
}

struct StateEntry {
    vars: HashMap<String, Vec<u8>>,
    expires_at: Instant,
}

static STATE: LazyLock<Mutex<HashMap<String, StateEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static VARIABLE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("static regex"));

pub(super) async fn wrap_client(
    mut stream: BoxedStream,
    config: &HeaderCustomTcpConfig,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    remote_host: &str,
    remote_port: u16,
) -> std::io::Result<BoxedStream> {
    validate_config(config)?;
    let mut context = EvalContext::default();
    if let Some(local) = local {
        load_metadata(&mut context.metadata, "local", local.ip(), local.port());
    }
    if let Some(remote) = remote {
        load_metadata(&mut context.metadata, "remote", remote.ip(), remote.port());
    } else if let Ok(ip) = remote_host.parse::<IpAddr>() {
        load_metadata(&mut context.metadata, "remote", ip, remote_port);
    } else {
        let port = u64::from(remote_port);
        context
            .metadata
            .insert("remote_port".into(), EvalValue::U64(port));
        context
            .metadata
            .insert("src_port_u16".into(), EvalValue::U64(port));
    }

    let state_key = state_key(config, local, remote, remote_host, remote_port)?;
    if let Some(vars) = get_state(&state_key) {
        context.vars = vars;
    }

    let mut server_index = 0;
    for client in &config.clients {
        write_sequence(&mut stream, client, &mut context).await?;
        if let Some(server) = config.servers.get(server_index) {
            read_sequence(&mut stream, server, &mut context).await?;
            server_index += 1;
        }
    }
    while let Some(server) = config.servers.get(server_index) {
        read_sequence(&mut stream, server, &mut context).await?;
        server_index += 1;
    }
    set_state(state_key, context.vars);
    Ok(stream)
}

pub(super) async fn wrap_server(
    mut stream: BoxedStream,
    config: &HeaderCustomTcpConfig,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> std::io::Result<BoxedStream> {
    validate_config(config)?;
    let mut context = EvalContext::default();
    if let Some(local) = local {
        load_metadata(&mut context.metadata, "local", local.ip(), local.port());
    }
    if let Some(remote) = remote {
        load_metadata(&mut context.metadata, "remote", remote.ip(), remote.port());
    }
    let state_key = state_key(
        config,
        local,
        remote,
        "",
        remote.map_or(0, |addr| addr.port()),
    )?;
    if let Some(vars) = get_state(&state_key) {
        context.vars = vars;
    }

    let mut server_index = 0;
    for (client_index, client) in config.clients.iter().enumerate() {
        if let Err(error) = read_sequence(&mut stream, client, &mut context).await {
            if let Some(sequence) = config.errors.get(client_index) {
                let _ = write_sequence(&mut stream, sequence, &mut context).await;
            }
            return Err(error);
        }
        if let Some(server) = config.servers.get(server_index) {
            write_sequence(&mut stream, server, &mut context).await?;
            server_index += 1;
        }
    }
    while let Some(server) = config.servers.get(server_index) {
        write_sequence(&mut stream, server, &mut context).await?;
        server_index += 1;
    }
    set_state(state_key, context.vars);
    Ok(stream)
}

fn state_key(
    config: &HeaderCustomTcpConfig,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    remote_host: &str,
    remote_port: u16,
) -> std::io::Result<String> {
    let encoded = serde_json::to_vec(config).map_err(invalid)?;
    let digest = blake3::hash(&encoded);
    Ok(format!(
        "{}|{}|{}",
        digest.to_hex(),
        local.map(|addr| addr.to_string()).unwrap_or_default(),
        remote
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| format!("{remote_host}:{remote_port}"))
    ))
}

fn get_state(key: &str) -> Option<HashMap<String, Vec<u8>>> {
    let mut state = STATE.lock();
    let now = Instant::now();
    state.retain(|_, entry| entry.expires_at > now);
    state.get(key).map(|entry| entry.vars.clone())
}

fn set_state(key: String, vars: HashMap<String, Vec<u8>>) {
    STATE.lock().insert(
        key,
        StateEntry {
            vars,
            expires_at: Instant::now() + Duration::from_secs(5),
        },
    );
}

fn load_metadata(metadata: &mut HashMap<String, EvalValue>, prefix: &str, ip: IpAddr, port: u16) {
    let port = u64::from(port);
    metadata.insert(format!("{prefix}_port"), EvalValue::U64(port));
    if prefix == "remote" {
        metadata.insert("src_port_u16".into(), EvalValue::U64(port));
    } else {
        metadata.insert("dst_port_u16".into(), EvalValue::U64(port));
    }
    if let IpAddr::V4(ip) = ip {
        let ip = u64::from(u32::from_be_bytes(ip.octets()));
        metadata.insert(format!("{prefix}_ip4_u32"), EvalValue::U64(ip));
        if prefix == "remote" {
            metadata.insert("src_ip4_u32".into(), EvalValue::U64(ip));
        } else {
            metadata.insert("dst_ip4_u32".into(), EvalValue::U64(ip));
        }
    }
}

fn validate_config(config: &HeaderCustomTcpConfig) -> std::io::Result<()> {
    for item in config
        .clients
        .iter()
        .chain(&config.servers)
        .chain(&config.errors)
        .flatten()
    {
        validate_name(&item.capture)?;
        validate_name(&item.reuse)?;
        let kinds = usize::from(item.packet.is_some())
            + usize::from(item.rand > 0)
            + usize::from(!item.reuse.is_empty())
            + usize::from(item.transform.is_some());
        if kinds > 1 || (kinds == 0 && !item.capture.is_empty()) {
            return Err(invalid("header-custom item must set exactly one kind"));
        }
        if let Some(range) = item.rand_range
            && (range.from < 0 || range.to > 255)
        {
            return Err(invalid("header-custom randRange must be within 0..=255"));
        }
        if let Some(transform) = &item.transform {
            validate_transform(transform)?;
        }
        if item.packet.is_some() {
            let _ = packet_bytes(item.packet.as_ref(), &item.packet_type)?;
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> std::io::Result<()> {
    if !name.is_empty() && !VARIABLE_NAME.is_match(name) {
        return Err(invalid(format!(
            "invalid header-custom variable name `{name}`"
        )));
    }
    Ok(())
}

fn validate_transform(transform: &CustomTransform) -> std::io::Result<()> {
    if transform.op.is_empty() || transform.args.is_empty() {
        return Err(invalid("header-custom transform requires op and args"));
    }
    for arg in &transform.args {
        let kinds = usize::from(arg.bytes.is_some())
            + usize::from(arg.u64.is_some())
            + usize::from(!arg.reuse.is_empty())
            + usize::from(!arg.metadata.is_empty())
            + usize::from(arg.transform.is_some());
        if kinds != 1 {
            return Err(invalid(
                "header-custom transform arg must set exactly one value",
            ));
        }
        validate_name(&arg.reuse)?;
        if let Some(nested) = &arg.transform {
            validate_transform(nested)?;
        }
        if arg.bytes.is_some() {
            let _ = packet_bytes(arg.bytes.as_ref(), &arg.bytes_type)?;
        }
    }
    Ok(())
}

async fn write_sequence(
    stream: &mut BoxedStream,
    sequence: &[HeaderCustomTcpItem],
    context: &mut EvalContext,
) -> std::io::Result<()> {
    let mut merged = Vec::new();
    for item in sequence {
        if item.delay.to > 0 {
            if !merged.is_empty() {
                stream.write_all(&merged).await?;
                merged.clear();
            }
            tokio::time::sleep(Duration::from_millis(
                random_between(item.delay).max(0) as u64
            ))
            .await;
        }
        merged.extend_from_slice(&evaluate_item(item, context)?);
    }
    if !merged.is_empty() {
        stream.write_all(&merged).await?;
    }
    Ok(())
}

async fn read_sequence(
    stream: &mut BoxedStream,
    sequence: &[HeaderCustomTcpItem],
    context: &mut EvalContext,
) -> std::io::Result<()> {
    for item in sequence {
        let length = measure_item(item, &context.vars)?;
        let mut received = vec![0; length];
        stream.read_exact(&mut received).await?;
        let expected = match item_kind(item)? {
            ItemKind::Random(_) | ItemKind::Empty => None,
            ItemKind::Packet(bytes) => Some(bytes),
            ItemKind::Reuse(name) => Some(
                context
                    .vars
                    .get(name)
                    .cloned()
                    .ok_or_else(|| invalid(format!("unknown variable `{name}`")))?,
            ),
            ItemKind::Transform(transform) => {
                Some(as_bytes(evaluate_transform(transform, context)?)?)
            }
        };
        if expected
            .as_ref()
            .is_some_and(|expected| expected != &received)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "header-custom server sequence mismatch",
            ));
        }
        if !item.capture.is_empty() {
            context.vars.insert(item.capture.clone(), received);
        }
    }
    Ok(())
}

enum ItemKind<'a> {
    Random(usize),
    Packet(Vec<u8>),
    Reuse(&'a str),
    Transform(&'a CustomTransform),
    Empty,
}

fn item_kind(item: &HeaderCustomTcpItem) -> std::io::Result<ItemKind<'_>> {
    if item.rand > 0 {
        Ok(ItemKind::Random(item.rand as usize))
    } else if item.packet.is_some() {
        Ok(ItemKind::Packet(packet_bytes(
            item.packet.as_ref(),
            &item.packet_type,
        )?))
    } else if !item.reuse.is_empty() {
        Ok(ItemKind::Reuse(&item.reuse))
    } else if let Some(transform) = &item.transform {
        Ok(ItemKind::Transform(transform))
    } else {
        Ok(ItemKind::Empty)
    }
}

fn evaluate_item(
    item: &HeaderCustomTcpItem,
    context: &mut EvalContext,
) -> std::io::Result<Vec<u8>> {
    let value = match item_kind(item)? {
        ItemKind::Random(length) => {
            let range = item.rand_range.unwrap_or_else(|| I32Range::new(0, 255));
            let mut value = vec![0; length];
            if range.from == 0 && range.to == 255 {
                rand::thread_rng().fill_bytes(&mut value);
            } else {
                let mut rng = rand::thread_rng();
                for byte in &mut value {
                    *byte = rng.gen_range(range.from..=range.to) as u8;
                }
            }
            value
        }
        ItemKind::Packet(value) => value,
        ItemKind::Reuse(name) => context
            .vars
            .get(name)
            .cloned()
            .ok_or_else(|| invalid(format!("unknown variable `{name}`")))?,
        ItemKind::Transform(transform) => as_bytes(evaluate_transform(transform, context)?)?,
        ItemKind::Empty => Vec::new(),
    };
    if !item.capture.is_empty() {
        context.vars.insert(item.capture.clone(), value.clone());
    }
    Ok(value)
}

fn measure_item(
    item: &HeaderCustomTcpItem,
    vars: &HashMap<String, Vec<u8>>,
) -> std::io::Result<usize> {
    match item_kind(item)? {
        ItemKind::Random(length) => Ok(length),
        ItemKind::Packet(value) => Ok(value.len()),
        ItemKind::Reuse(name) => vars
            .get(name)
            .map(Vec::len)
            .ok_or_else(|| invalid(format!("unknown variable `{name}`"))),
        ItemKind::Transform(transform) => measure_transform(transform, vars),
        ItemKind::Empty => Ok(0),
    }
}

fn measure_transform(
    transform: &CustomTransform,
    vars: &HashMap<String, Vec<u8>>,
) -> std::io::Result<usize> {
    match transform.op.as_str() {
        "concat" => transform
            .args
            .iter()
            .try_fold(0usize, |total, arg| Ok(total + measure_arg(arg, vars)?)),
        "slice" if transform.args.len() == 3 => literal_u64(&transform.args[2]).map(|v| v as usize),
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        "pad" if transform.args.len() == 3 => literal_u64(&transform.args[1]).map(|v| v as usize),
        "truncate" if transform.args.len() == 2 => {
            literal_u64(&transform.args[1]).map(|v| v as usize)
        }
        op => Err(invalid(format!("expr size is not bytes for op `{op}`"))),
    }
}

fn measure_arg(
    arg: &CustomTransformArg,
    vars: &HashMap<String, Vec<u8>>,
) -> std::io::Result<usize> {
    if arg.bytes.is_some() {
        packet_bytes(arg.bytes.as_ref(), &arg.bytes_type).map(|value| value.len())
    } else if !arg.reuse.is_empty() {
        vars.get(&arg.reuse)
            .map(Vec::len)
            .ok_or_else(|| invalid(format!("unknown variable `{}`", arg.reuse)))
    } else if let Some(transform) = &arg.transform {
        measure_transform(transform, vars)
    } else {
        Err(invalid("u64/metadata arg has no byte width"))
    }
}

fn evaluate_transform(
    transform: &CustomTransform,
    context: &EvalContext,
) -> std::io::Result<EvalValue> {
    let args = &transform.args;
    match transform.op.as_str() {
        "concat" => {
            let mut output = Vec::new();
            for arg in args {
                output.extend_from_slice(&as_bytes(evaluate_arg(arg, context)?)?);
            }
            Ok(EvalValue::Bytes(output))
        }
        "slice" => {
            expect_args(args, 3, "slice")?;
            let source = as_bytes(evaluate_arg(&args[0], context)?)?;
            let offset = as_u64(evaluate_arg(&args[1], context)?)? as usize;
            let length = as_u64(evaluate_arg(&args[2], context)?)? as usize;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("slice overflow"))?;
            Ok(EvalValue::Bytes(
                source
                    .get(offset..end)
                    .ok_or_else(|| invalid("slice out of bounds"))?
                    .to_vec(),
            ))
        }
        "xor16" => evaluate_xor(args, context, u16::MAX as u64, "xor16"),
        "xor32" => evaluate_xor(args, context, u32::MAX as u64, "xor32"),
        "be16" => pack(args, context, 2, true, "be16"),
        "be32" => pack(args, context, 4, true, "be32"),
        "le16" => pack(args, context, 2, false, "le16"),
        "le32" => pack(args, context, 4, false, "le32"),
        "le64" => pack(args, context, 8, false, "le64"),
        "pad" => {
            expect_args(args, 3, "pad")?;
            let mut source = as_bytes(evaluate_arg(&args[0], context)?)?;
            let target = as_u64(evaluate_arg(&args[1], context)?)? as usize;
            let fill = as_bytes(evaluate_arg(&args[2], context)?)?;
            if fill.is_empty() || target < source.len() {
                return Err(invalid("pad fill must be non-empty and target >= source"));
            }
            while source.len() < target {
                let count = (target - source.len()).min(fill.len());
                source.extend_from_slice(&fill[..count]);
            }
            Ok(EvalValue::Bytes(source))
        }
        "truncate" => {
            expect_args(args, 2, "truncate")?;
            let source = as_bytes(evaluate_arg(&args[0], context)?)?;
            let length = as_u64(evaluate_arg(&args[1], context)?)? as usize;
            Ok(EvalValue::Bytes(
                source
                    .get(..length)
                    .ok_or_else(|| invalid("truncate out of bounds"))?
                    .to_vec(),
            ))
        }
        "add" => binary_u64(args, context, "add", u64::checked_add),
        "sub" => binary_u64(args, context, "sub", u64::checked_sub),
        "and" => binary_u64(args, context, "and", |a, b| Some(a & b)),
        "or" => binary_u64(args, context, "or", |a, b| Some(a | b)),
        "shl" => shift(args, context, true),
        "shr" => shift(args, context, false),
        op => Err(invalid(format!("unsupported expr op `{op}`"))),
    }
}

fn evaluate_arg(arg: &CustomTransformArg, context: &EvalContext) -> std::io::Result<EvalValue> {
    if arg.bytes.is_some() {
        Ok(EvalValue::Bytes(packet_bytes(
            arg.bytes.as_ref(),
            &arg.bytes_type,
        )?))
    } else if let Some(value) = arg.u64 {
        Ok(EvalValue::U64(value))
    } else if !arg.reuse.is_empty() {
        context
            .vars
            .get(&arg.reuse)
            .cloned()
            .map(EvalValue::Bytes)
            .ok_or_else(|| invalid(format!("unknown variable `{}`", arg.reuse)))
    } else if !arg.metadata.is_empty() {
        context
            .metadata
            .get(&arg.metadata)
            .cloned()
            .ok_or_else(|| invalid(format!("unknown metadata `{}`", arg.metadata)))
    } else if let Some(transform) = &arg.transform {
        evaluate_transform(transform, context)
    } else {
        Err(invalid("empty transform arg"))
    }
}

fn evaluate_xor(
    args: &[CustomTransformArg],
    context: &EvalContext,
    mask: u64,
    name: &str,
) -> std::io::Result<EvalValue> {
    expect_args(args, 2, name)?;
    let left = as_u64(evaluate_arg(&args[0], context)?)?;
    let right = as_u64(evaluate_arg(&args[1], context)?)?;
    if left > mask || right > mask {
        return Err(invalid(format!("{name} overflow")));
    }
    Ok(EvalValue::U64((left ^ right) & mask))
}

fn pack(
    args: &[CustomTransformArg],
    context: &EvalContext,
    width: usize,
    big_endian: bool,
    name: &str,
) -> std::io::Result<EvalValue> {
    expect_args(args, 1, name)?;
    let value = as_u64(evaluate_arg(&args[0], context)?)?;
    if width < 8 && value >= (1u64 << (width * 8)) {
        return Err(invalid(format!("{name} overflow")));
    }
    let bytes = if big_endian {
        value.to_be_bytes()[8 - width..].to_vec()
    } else {
        value.to_le_bytes()[..width].to_vec()
    };
    Ok(EvalValue::Bytes(bytes))
}

fn binary_u64(
    args: &[CustomTransformArg],
    context: &EvalContext,
    name: &str,
    op: fn(u64, u64) -> Option<u64>,
) -> std::io::Result<EvalValue> {
    expect_args(args, 2, name)?;
    let left = as_u64(evaluate_arg(&args[0], context)?)?;
    let right = as_u64(evaluate_arg(&args[1], context)?)?;
    op(left, right)
        .map(EvalValue::U64)
        .ok_or_else(|| invalid(format!("{name} overflow/underflow")))
}

fn shift(
    args: &[CustomTransformArg],
    context: &EvalContext,
    left: bool,
) -> std::io::Result<EvalValue> {
    let name = if left { "shl" } else { "shr" };
    expect_args(args, 2, name)?;
    let value = as_u64(evaluate_arg(&args[0], context)?)?;
    let shift = as_u64(evaluate_arg(&args[1], context)?)?;
    if shift >= 64 {
        return Err(invalid("shift out of range"));
    }
    let result = if left {
        value.checked_shl(shift as u32)
    } else {
        value.checked_shr(shift as u32)
    }
    .ok_or_else(|| invalid(format!("{name} overflow")))?;
    if left && (result >> shift) != value {
        return Err(invalid("shl overflow"));
    }
    Ok(EvalValue::U64(result))
}

fn expect_args(args: &[CustomTransformArg], count: usize, name: &str) -> std::io::Result<()> {
    if args.len() == count {
        Ok(())
    } else {
        Err(invalid(format!("{name} expects {count} args")))
    }
}

fn literal_u64(arg: &CustomTransformArg) -> std::io::Result<u64> {
    arg.u64
        .ok_or_else(|| invalid("expression size requires a literal u64"))
}

fn as_bytes(value: EvalValue) -> std::io::Result<Vec<u8>> {
    match value {
        EvalValue::Bytes(value) => Ok(value),
        EvalValue::U64(_) => Err(invalid("expr value is not bytes")),
    }
}

fn as_u64(value: EvalValue) -> std::io::Result<u64> {
    match value {
        EvalValue::U64(value) => Ok(value),
        EvalValue::Bytes(_) => Err(invalid("expr value is not u64")),
    }
}

fn packet_bytes(value: Option<&serde_json::Value>, kind: &str) -> std::io::Result<Vec<u8>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match kind.to_ascii_lowercase().as_str() {
        "" | "array" => serde_json::from_value::<Vec<u8>>(value.clone()).map_err(invalid),
        "str" => value
            .as_str()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| invalid("header-custom str bytes must be a JSON string")),
        "hex" => value
            .as_str()
            .ok_or_else(|| invalid("header-custom hex bytes must be a JSON string"))
            .and_then(|value| hex::decode(value).map_err(invalid)),
        "base64" => value
            .as_str()
            .ok_or_else(|| invalid("header-custom base64 bytes must be a JSON string"))
            .and_then(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(invalid)
            }),
        kind => Err(invalid(format!("unknown header-custom byte type `{kind}`"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpRole {
    Client,
    Server,
}

pub(super) enum StandaloneServerAction {
    Reply(Vec<u8>),
    Payload(Vec<u8>),
    Drop,
}

/// Per-association UDP evaluator. Xray keys its state by peer address; a
/// `UdpSocketLike` already represents one association, so one instance is the
/// exact equivalent without an unbounded global peer map.
pub(super) struct UdpCustomCodec {
    config: HeaderCustomUdpConfig,
    role: UdpRole,
    context: EvalContext,
    expires_at: Option<Instant>,
}

impl UdpCustomCodec {
    pub(super) fn new(
        config: &HeaderCustomUdpConfig,
        role: UdpRole,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        validate_udp_config(config)?;
        let mut context = EvalContext::default();
        if let Some(local) = local {
            load_metadata(&mut context.metadata, "local", local.ip(), local.port());
        }
        if let Some(remote) = remote {
            load_metadata(&mut context.metadata, "remote", remote.ip(), remote.port());
        }
        Ok(Self {
            config: config.clone(),
            role,
            context,
            expires_at: None,
        })
    }

    pub(super) fn is_standalone(&self) -> bool {
        self.config.mode.eq_ignore_ascii_case("standalone")
    }

    pub(super) fn established(&mut self) -> bool {
        self.expire_state();
        self.expires_at.is_some()
    }

    pub(super) fn encode_prefix(&mut self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        if self.is_standalone() {
            return Ok(payload.to_vec());
        }
        self.expire_state();
        let items = match self.role {
            UdpRole::Client => &self.config.client,
            UdpRole::Server => &self.config.server,
        };
        let header = evaluate_udp_items(items, &mut self.context)?;
        self.touch();
        let mut packet = Vec::with_capacity(header.len() + payload.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(payload);
        Ok(packet)
    }

    pub(super) fn decode_prefix(&mut self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        if self.is_standalone() {
            return Ok(packet.to_vec());
        }
        self.expire_state();
        let items = match self.role {
            UdpRole::Client => &self.config.server,
            UdpRole::Server => &self.config.client,
        };
        let consumed = match_udp_items(items, packet, &mut self.context)?;
        self.touch();
        Ok(packet[consumed..].to_vec())
    }

    pub(super) fn standalone_request(&mut self) -> std::io::Result<Vec<u8>> {
        if !self.is_standalone() || self.role != UdpRole::Client {
            return Err(invalid(
                "header-custom standalone request used in the wrong role",
            ));
        }
        self.expire_state();
        evaluate_udp_items(&self.config.client, &mut self.context)
    }

    pub(super) fn accept_standalone_response(&mut self, packet: &[u8]) -> std::io::Result<bool> {
        if !self.is_standalone() || self.role != UdpRole::Client {
            return Err(invalid(
                "header-custom standalone response used in the wrong role",
            ));
        }
        let expected = measure_udp_items(&self.config.server, &self.context.vars)?;
        if packet.len() != expected {
            return Ok(false);
        }
        match match_udp_items(&self.config.server, packet, &mut self.context) {
            Ok(consumed) if consumed == packet.len() => {
                self.touch();
                Ok(true)
            }
            Ok(_) | Err(_) => Ok(false),
        }
    }

    pub(super) fn handle_standalone_server_packet(
        &mut self,
        packet: &[u8],
    ) -> std::io::Result<StandaloneServerAction> {
        if !self.is_standalone() || self.role != UdpRole::Server {
            return Err(invalid(
                "header-custom standalone server used in the wrong role",
            ));
        }
        self.expire_state();
        let expected = match measure_udp_items(&self.config.client, &self.context.vars) {
            Ok(expected) => expected,
            Err(_) => return Ok(StandaloneServerAction::Drop),
        };
        if packet.len() != expected {
            return Ok(StandaloneServerAction::Payload(packet.to_vec()));
        }
        if match_udp_items(&self.config.client, packet, &mut self.context).is_err() {
            return Ok(StandaloneServerAction::Payload(packet.to_vec()));
        }
        let reply = evaluate_udp_items(&self.config.server, &mut self.context)?;
        self.touch();
        Ok(StandaloneServerAction::Reply(reply))
    }

    fn touch(&mut self) {
        self.expires_at = Some(Instant::now() + Duration::from_secs(5));
    }

    fn expire_state(&mut self) {
        if self
            .expires_at
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            self.context.vars.clear();
            self.expires_at = None;
        }
    }
}

fn validate_udp_config(config: &HeaderCustomUdpConfig) -> std::io::Result<()> {
    if !matches!(
        config.mode.to_ascii_lowercase().as_str(),
        "" | "prefix" | "standalone"
    ) {
        return Err(invalid(format!(
            "unknown header-custom UDP mode `{}`",
            config.mode
        )));
    }
    for item in config.client.iter().chain(&config.server) {
        validate_name(&item.capture)?;
        validate_name(&item.reuse)?;
        let kinds = usize::from(item.packet.is_some())
            + usize::from(item.rand > 0)
            + usize::from(!item.reuse.is_empty())
            + usize::from(item.transform.is_some());
        if kinds > 1 || (kinds == 0 && !item.capture.is_empty()) {
            return Err(invalid("header-custom UDP item must set exactly one kind"));
        }
        if let Some(range) = item.rand_range
            && (range.from < 0 || range.to > 255)
        {
            return Err(invalid(
                "header-custom UDP randRange must be within 0..=255",
            ));
        }
        if let Some(transform) = &item.transform {
            validate_transform(transform)?;
        }
        if item.packet.is_some() {
            let _ = packet_bytes(item.packet.as_ref(), &item.packet_type)?;
        }
    }
    Ok(())
}

fn evaluate_udp_items(
    items: &[HeaderCustomUdpItem],
    context: &mut EvalContext,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for item in items {
        let value = evaluate_udp_item(item, context)?;
        output.extend_from_slice(&value);
    }
    Ok(output)
}

fn evaluate_udp_item(
    item: &HeaderCustomUdpItem,
    context: &mut EvalContext,
) -> std::io::Result<Vec<u8>> {
    let value = if item.rand > 0 {
        let length = usize::try_from(item.rand).map_err(invalid)?;
        let range = item.rand_range.unwrap_or_else(|| I32Range::new(0, 255));
        let mut output = vec![0; length];
        if range.from == 0 && range.to == 255 {
            rand::thread_rng().fill_bytes(&mut output);
        } else {
            let mut rng = rand::thread_rng();
            for byte in &mut output {
                *byte = rng.gen_range(range.from..=range.to) as u8;
            }
        }
        output
    } else if item.packet.is_some() {
        packet_bytes(item.packet.as_ref(), &item.packet_type)?
    } else if !item.reuse.is_empty() {
        context
            .vars
            .get(&item.reuse)
            .cloned()
            .ok_or_else(|| invalid(format!("unknown variable `{}`", item.reuse)))?
    } else if let Some(transform) = &item.transform {
        as_bytes(evaluate_transform(transform, context)?)?
    } else {
        Vec::new()
    };
    if !item.capture.is_empty() {
        context.vars.insert(item.capture.clone(), value.clone());
    }
    Ok(value)
}

fn measure_udp_items(
    items: &[HeaderCustomUdpItem],
    vars: &HashMap<String, Vec<u8>>,
) -> std::io::Result<usize> {
    items.iter().try_fold(0usize, |total, item| {
        total
            .checked_add(measure_udp_item(item, vars)?)
            .ok_or_else(|| invalid("header-custom UDP header size overflow"))
    })
}

fn measure_udp_item(
    item: &HeaderCustomUdpItem,
    vars: &HashMap<String, Vec<u8>>,
) -> std::io::Result<usize> {
    if item.rand > 0 {
        usize::try_from(item.rand).map_err(invalid)
    } else if item.packet.is_some() {
        packet_bytes(item.packet.as_ref(), &item.packet_type).map(|value| value.len())
    } else if !item.reuse.is_empty() {
        vars.get(&item.reuse)
            .map(Vec::len)
            .ok_or_else(|| invalid(format!("unknown variable `{}`", item.reuse)))
    } else if let Some(transform) = &item.transform {
        measure_transform(transform, vars)
    } else {
        Ok(0)
    }
}

fn match_udp_items(
    items: &[HeaderCustomUdpItem],
    packet: &[u8],
    context: &mut EvalContext,
) -> std::io::Result<usize> {
    let mut offset = 0usize;
    for item in items {
        let length = measure_udp_item(item, &context.vars)?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("header-custom UDP header size overflow"))?;
        let segment = packet
            .get(offset..end)
            .ok_or_else(|| invalid("header-custom UDP packet is truncated"))?;
        let expected = if item.rand > 0 {
            None
        } else if item.packet.is_some() {
            Some(packet_bytes(item.packet.as_ref(), &item.packet_type)?)
        } else if !item.reuse.is_empty() {
            Some(
                context
                    .vars
                    .get(&item.reuse)
                    .cloned()
                    .ok_or_else(|| invalid(format!("unknown variable `{}`", item.reuse)))?,
            )
        } else if let Some(transform) = &item.transform {
            Some(as_bytes(evaluate_transform(transform, context)?)?)
        } else {
            None
        };
        if expected
            .as_deref()
            .is_some_and(|expected| expected != segment)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "header-custom UDP header mismatch",
            ));
        }
        if !item.capture.is_empty() {
            context.vars.insert(item.capture.clone(), segment.to_vec());
        }
        offset = end;
    }
    Ok(offset)
}

fn random_between(range: I32Range) -> i32 {
    if range.from == range.to {
        range.from
    } else {
        rand::thread_rng().gen_range(range.from..range.to)
    }
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_golden_uses_metadata_capture_and_endianness() {
        let mut context = EvalContext::default();
        load_metadata(
            &mut context.metadata,
            "remote",
            "192.0.2.1".parse().unwrap(),
            443,
        );
        let expression = CustomTransform {
            op: "concat".into(),
            args: vec![
                CustomTransformArg {
                    metadata: "src_ip4_u32".into(),
                    transform: None,
                    ..Default::default()
                },
                CustomTransformArg {
                    transform: Some(Box::new(CustomTransform {
                        op: "be16".into(),
                        args: vec![CustomTransformArg {
                            metadata: "src_port_u16".into(),
                            ..Default::default()
                        }],
                    })),
                    ..Default::default()
                },
            ],
        };
        // Raw u64 metadata cannot be concatenated without packing.
        assert!(evaluate_transform(&expression, &context).is_err());
        let packed_ip = CustomTransform {
            op: "be32".into(),
            args: vec![expression.args[0].clone()],
        };
        assert_eq!(
            as_bytes(evaluate_transform(&packed_ip, &context).unwrap()).unwrap(),
            [192, 0, 2, 1]
        );
    }

    #[test]
    fn udp_prefix_captures_and_reuses_across_directions() {
        let config = HeaderCustomUdpConfig {
            mode: "prefix".into(),
            client: vec![HeaderCustomUdpItem {
                rand: 4,
                capture: "token".into(),
                ..Default::default()
            }],
            server: vec![HeaderCustomUdpItem {
                reuse: "token".into(),
                ..Default::default()
            }],
        };
        let remote = Some("192.0.2.1:443".parse().unwrap());
        let mut client = UdpCustomCodec::new(&config, UdpRole::Client, None, remote).unwrap();
        let mut server = UdpCustomCodec::new(&config, UdpRole::Server, None, remote).unwrap();
        let request = client.encode_prefix(b"hello").unwrap();
        assert_eq!(server.decode_prefix(&request).unwrap(), b"hello");
        let response = server.encode_prefix(b"world").unwrap();
        assert_eq!(client.decode_prefix(&response).unwrap(), b"world");
    }

    #[test]
    fn udp_prefix_rejects_mismatch_and_truncation() {
        let config = HeaderCustomUdpConfig {
            mode: "prefix".into(),
            client: vec![HeaderCustomUdpItem {
                packet_type: "hex".into(),
                packet: Some(serde_json::Value::String("aabb".into())),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut server = UdpCustomCodec::new(&config, UdpRole::Server, None, None).unwrap();
        assert!(server.decode_prefix(&[0xaa]).is_err());
        assert!(server.decode_prefix(&[0xaa, 0xbc, 1]).is_err());
    }

    #[test]
    fn udp_standalone_handshake_is_consumed_before_payload() {
        let config = HeaderCustomUdpConfig {
            mode: "standalone".into(),
            client: vec![HeaderCustomUdpItem {
                rand: 2,
                capture: "seed".into(),
                ..Default::default()
            }],
            server: vec![HeaderCustomUdpItem {
                reuse: "seed".into(),
                ..Default::default()
            }],
        };
        let mut client = UdpCustomCodec::new(&config, UdpRole::Client, None, None).unwrap();
        let mut server = UdpCustomCodec::new(&config, UdpRole::Server, None, None).unwrap();
        let request = client.standalone_request().unwrap();
        let StandaloneServerAction::Reply(response) =
            server.handle_standalone_server_packet(&request).unwrap()
        else {
            panic!("standalone request was not recognized")
        };
        assert!(client.accept_standalone_response(&response).unwrap());
        assert!(client.established());
        assert!(matches!(
            server.handle_standalone_server_packet(b"payload").unwrap(),
            StandaloneServerAction::Payload(payload) if payload == b"payload"
        ));
    }

    #[tokio::test]
    async fn tcp_client_and_server_handshake_roundtrip() {
        let config = HeaderCustomTcpConfig {
            clients: vec![vec![HeaderCustomTcpItem {
                packet_type: "str".into(),
                packet: Some(serde_json::Value::String("client".into())),
                ..Default::default()
            }]],
            servers: vec![vec![HeaderCustomTcpItem {
                packet_type: "str".into(),
                packet: Some(serde_json::Value::String("server".into())),
                ..Default::default()
            }]],
            errors: Vec::new(),
        };
        let (left, right) = tokio::io::duplex(4096);
        let client = wrap_client(Box::pin(left), &config, None, None, "test", 1);
        let server = wrap_server(Box::pin(right), &config, None, None);
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        client.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
    }
}
