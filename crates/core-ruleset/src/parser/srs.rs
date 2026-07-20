//! sing-box SRS binary v1–v5 → 语义保持的共享 IR。
//!
//! 格式以 sing-box `common/srs/binary.go`、`common/srs/ip_set.go` 和
//! sing `common/domain` 为准。解析器不信任长度字段：压缩/解压体、规则树、
//! 普通列表、字符串、compact-domain 节点和 IP range 都有独立上限。

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use flate2::{Decompress, FlushDecompress, Status};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::RegexSet;

use crate::{
    ir::{CompactDomainSet, PortRange, RulesetExpr, RulesetPredicate, RulesetProgram},
    parser::ParseError,
};

const MAGIC: &[u8; 3] = b"SRS";
const MIN_VERSION: u8 = 1;
const MAX_VERSION: u8 = 5;

const MAX_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;
const MAX_RULES_PER_LIST: usize = 262_144;
const MAX_TOTAL_RULE_NODES: usize = 524_288;
const MAX_LOGICAL_DEPTH: usize = 64;
const MAX_LIST_ITEMS: usize = 1_048_576;
const MAX_TOTAL_LIST_ITEMS: usize = 2_097_152;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_STRING_BYTES: usize = 64 * 1024 * 1024;
const MAX_REGEX_PATTERNS: usize = 65_536;
const MAX_REGEX_PATTERN_BYTES: usize = 64 * 1024;
const MAX_TOTAL_REGEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_SEMANTIC_ITEMS: usize = 2_097_152;
const MAX_IP_RANGES: usize = 1_048_576;
const MAX_DOMAIN_NODES: usize = 8 * 1024 * 1024;
const MAX_DOMAIN_DEPTH: usize = 1_024;
const MAX_DOMAIN_BITMAP_WORDS: usize = (2 * MAX_DOMAIN_NODES - 1).div_ceil(64);

const RULE_ITEM_QUERY_TYPE: u8 = 0;
const RULE_ITEM_NETWORK: u8 = 1;
const RULE_ITEM_DOMAIN: u8 = 2;
const RULE_ITEM_DOMAIN_KEYWORD: u8 = 3;
const RULE_ITEM_DOMAIN_REGEX: u8 = 4;
const RULE_ITEM_SOURCE_IP_CIDR: u8 = 5;
const RULE_ITEM_IP_CIDR: u8 = 6;
const RULE_ITEM_SOURCE_PORT: u8 = 7;
const RULE_ITEM_SOURCE_PORT_RANGE: u8 = 8;
const RULE_ITEM_PORT: u8 = 9;
const RULE_ITEM_PORT_RANGE: u8 = 10;
const RULE_ITEM_PROCESS_NAME: u8 = 11;
const RULE_ITEM_PROCESS_PATH: u8 = 12;
const RULE_ITEM_PACKAGE_NAME: u8 = 13;
const RULE_ITEM_WIFI_SSID: u8 = 14;
const RULE_ITEM_WIFI_BSSID: u8 = 15;
const RULE_ITEM_ADGUARD_DOMAIN: u8 = 16;
const RULE_ITEM_PROCESS_PATH_REGEX: u8 = 17;
const RULE_ITEM_NETWORK_TYPE: u8 = 18;
const RULE_ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const RULE_ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const RULE_ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const RULE_ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const RULE_ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const RULE_ITEM_FINAL: u8 = 0xff;

/// 严格解析一份完整 SRS 文件。
pub fn parse(body: &[u8]) -> Result<RulesetProgram, ParseError> {
    if body.len() < 4 {
        return Err(binary_error("文件头被截断"));
    }
    if &body[..3] != MAGIC {
        return Err(binary_error("magic 非 `SRS`"));
    }
    let version = body[3];
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
        return Err(ParseError::UnsupportedVersion(version as u64));
    }

    let compressed = &body[4..];
    if compressed.is_empty() {
        return Err(binary_error("缺少 zlib 压缩体"));
    }
    if compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(binary_error(format!(
            "压缩体超过上限 {MAX_COMPRESSED_BYTES} bytes"
        )));
    }
    let decoded = decompress_zlib_bounded(compressed, MAX_DECOMPRESSED_BYTES)?;
    let mut reader = Reader::new(&decoded);
    let mut state = DecodeState::new(version);
    let rule_count = reader.read_len("顶层 rule count", MAX_RULES_PER_LIST)?;
    state.add_list_items(rule_count, "顶层 rules")?;

    let mut rules = Vec::with_capacity(rule_count);
    for index in 0..rule_count {
        let rule = read_rule(&mut reader, &mut state, 1)
            .map_err(|error| add_context(error, format!("rule[{index}]")))?;
        rules.push(rule);
    }
    if !reader.is_eof() {
        return Err(binary_error(format!(
            "解压数据含 {} bytes 尾随内容",
            reader.remaining()
        )));
    }
    Ok(RulesetProgram::new(
        version,
        rule_count,
        RulesetExpr::Any(rules),
    ))
}

fn read_rule(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    depth: usize,
) -> Result<RulesetExpr, ParseError> {
    state.add_rule(depth)?;
    match reader.read_u8("rule type")? {
        0 => read_default_rule(reader, state),
        1 => read_logical_rule(reader, state, depth),
        other => Err(binary_error(format!("未知 rule type {other}"))),
    }
}

fn read_logical_rule(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    depth: usize,
) -> Result<RulesetExpr, ParseError> {
    let mode = reader.read_u8("logical mode")?;
    if mode > 1 {
        return Err(binary_error(format!("未知 logical mode {mode}")));
    }
    let length = reader.read_len("logical rule count", MAX_RULES_PER_LIST)?;
    if length == 0 {
        return Err(ParseError::InvalidRule(
            "SRS logical rule 的 rules 不能为空".into(),
        ));
    }
    state.add_list_items(length, "logical rules")?;
    let mut children = Vec::with_capacity(length);
    for index in 0..length {
        children.push(
            read_rule(reader, state, depth + 1)
                .map_err(|error| add_context(error, format!("logical rule[{index}]")))?,
        );
    }
    let invert = reader.read_bool("logical invert")?;
    let expression = if mode == 0 {
        RulesetExpr::All(children)
    } else {
        RulesetExpr::Any(children)
    };
    Ok(apply_invert(expression, invert))
}

#[derive(Default)]
struct DefaultRule {
    query_types: Vec<u16>,
    domain_matcher: Option<CompactDomainSet>,
    adguard_domain_matcher: Option<CompactDomainSet>,
    domain_keywords: Vec<String>,
    domain_regexes: Vec<String>,
    source_ip_cidrs: Vec<IpNet>,
    ip_cidrs: Vec<IpNet>,
    source_ports: Vec<PortRange>,
    ports: Vec<PortRange>,
    process_names: Vec<String>,
    process_paths: Vec<String>,
    process_path_regexes: Vec<String>,
    package_names: Vec<String>,
    package_name_regexes: Vec<String>,
    networks: Vec<String>,
    wifi_ssids: Vec<String>,
    wifi_bssids: Vec<String>,
    network_types: Vec<u8>,
    network_is_expensive: bool,
    network_is_constrained: bool,
    network_interface_addresses: Vec<(u8, Vec<IpNet>)>,
    default_interface_addresses: Vec<IpNet>,
}

fn read_default_rule(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
) -> Result<RulesetExpr, ParseError> {
    let mut rule = DefaultRule::default();
    let mut seen = 0u32;
    let invert;

    loop {
        let item_type = reader.read_u8("rule item type")?;
        if item_type == RULE_ITEM_FINAL {
            invert = reader.read_bool("default invert")?;
            break;
        }
        if item_type > RULE_ITEM_PACKAGE_NAME_REGEX {
            return Err(binary_error(format!("未知 rule item type {item_type}")));
        }
        check_item_version(state.version, item_type)?;
        let bit = 1u32 << item_type;
        if seen & bit != 0 {
            return Err(binary_error(format!("rule item type {item_type} 重复")));
        }
        seen |= bit;

        match item_type {
            RULE_ITEM_QUERY_TYPE => {
                rule.query_types = read_u16_list(reader, state, "query_type")?;
            }
            RULE_ITEM_NETWORK => {
                rule.networks =
                    read_string_list(reader, state, "network", MAX_LIST_ITEMS, MAX_STRING_BYTES)?;
                state.add_semantic_items(rule.networks.len(), "network")?;
            }
            RULE_ITEM_DOMAIN => {
                rule.domain_matcher = Some(read_compact_domain_set(reader, state, "domain")?);
            }
            RULE_ITEM_DOMAIN_KEYWORD => {
                rule.domain_keywords = read_string_list(
                    reader,
                    state,
                    "domain_keyword",
                    MAX_LIST_ITEMS,
                    MAX_STRING_BYTES,
                )?;
                state.add_semantic_items(rule.domain_keywords.len(), "domain_keyword")?;
            }
            RULE_ITEM_DOMAIN_REGEX => {
                rule.domain_regexes = read_string_list(
                    reader,
                    state,
                    "domain_regex",
                    MAX_REGEX_PATTERNS,
                    MAX_REGEX_PATTERN_BYTES,
                )?;
                check_regex_limits(state, &rule.domain_regexes, "domain_regex")?;
                state.add_semantic_items(rule.domain_regexes.len(), "domain_regex")?;
            }
            RULE_ITEM_SOURCE_IP_CIDR => {
                rule.source_ip_cidrs = read_ip_set(reader, state, "source_ip_cidr")?;
            }
            RULE_ITEM_IP_CIDR => {
                rule.ip_cidrs = read_ip_set(reader, state, "ip_cidr")?;
            }
            RULE_ITEM_SOURCE_PORT => {
                rule.source_ports
                    .extend(read_port_list(reader, state, "source_port")?);
            }
            RULE_ITEM_SOURCE_PORT_RANGE => {
                rule.source_ports
                    .extend(read_port_range_list(reader, state, "source_port")?);
            }
            RULE_ITEM_PORT => {
                rule.ports.extend(read_port_list(reader, state, "port")?);
            }
            RULE_ITEM_PORT_RANGE => {
                rule.ports
                    .extend(read_port_range_list(reader, state, "port")?);
            }
            RULE_ITEM_PROCESS_NAME => {
                rule.process_names = read_string_list(
                    reader,
                    state,
                    "process_name",
                    MAX_LIST_ITEMS,
                    MAX_STRING_BYTES,
                )?;
                state.add_semantic_items(rule.process_names.len(), "process_name")?;
            }
            RULE_ITEM_PROCESS_PATH => {
                rule.process_paths = read_string_list(
                    reader,
                    state,
                    "process_path",
                    MAX_LIST_ITEMS,
                    MAX_STRING_BYTES,
                )?;
                state.add_semantic_items(rule.process_paths.len(), "process_path")?;
            }
            RULE_ITEM_PACKAGE_NAME => {
                rule.package_names = read_string_list(
                    reader,
                    state,
                    "package_name",
                    MAX_LIST_ITEMS,
                    MAX_STRING_BYTES,
                )?;
                state.add_semantic_items(rule.package_names.len(), "package_name")?;
            }
            RULE_ITEM_WIFI_SSID => {
                rule.wifi_ssids =
                    read_string_list(reader, state, "wifi_ssid", MAX_LIST_ITEMS, MAX_STRING_BYTES)?;
                state.add_semantic_items(rule.wifi_ssids.len(), "wifi_ssid")?;
            }
            RULE_ITEM_WIFI_BSSID => {
                rule.wifi_bssids = read_string_list(
                    reader,
                    state,
                    "wifi_bssid",
                    MAX_LIST_ITEMS,
                    MAX_STRING_BYTES,
                )?
                .into_iter()
                .map(|value| normalize_wifi_bssid(&value))
                .collect();
                state.add_semantic_items(rule.wifi_bssids.len(), "wifi_bssid")?;
            }
            RULE_ITEM_ADGUARD_DOMAIN => {
                rule.adguard_domain_matcher =
                    Some(read_compact_domain_set(reader, state, "adguard_domain")?);
            }
            RULE_ITEM_PROCESS_PATH_REGEX => {
                rule.process_path_regexes = read_string_list(
                    reader,
                    state,
                    "process_path_regex",
                    MAX_REGEX_PATTERNS,
                    MAX_REGEX_PATTERN_BYTES,
                )?;
                check_regex_limits(state, &rule.process_path_regexes, "process_path_regex")?;
                state.add_semantic_items(rule.process_path_regexes.len(), "process_path_regex")?;
            }
            RULE_ITEM_NETWORK_TYPE => {
                rule.network_types = read_u8_list(reader, state, "network_type")?;
            }
            RULE_ITEM_NETWORK_IS_EXPENSIVE => {
                rule.network_is_expensive = true;
            }
            RULE_ITEM_NETWORK_IS_CONSTRAINED => {
                rule.network_is_constrained = true;
            }
            RULE_ITEM_NETWORK_INTERFACE_ADDRESS => {
                rule.network_interface_addresses = read_network_interface_addresses(reader, state)?;
            }
            RULE_ITEM_DEFAULT_INTERFACE_ADDRESS => {
                rule.default_interface_addresses =
                    read_prefix_list(reader, state, "default_interface_address")?;
            }
            RULE_ITEM_PACKAGE_NAME_REGEX => {
                rule.package_name_regexes = read_string_list(
                    reader,
                    state,
                    "package_name_regex",
                    MAX_REGEX_PATTERNS,
                    MAX_REGEX_PATTERN_BYTES,
                )?;
                check_regex_limits(state, &rule.package_name_regexes, "package_name_regex")?;
                state.add_semantic_items(rule.package_name_regexes.len(), "package_name_regex")?;
            }
            _ => unreachable!("item type was range checked"),
        }
    }

    compile_default_rule(rule, invert)
}

fn compile_default_rule(rule: DefaultRule, invert: bool) -> Result<RulesetExpr, ParseError> {
    let mut groups = Vec::new();
    let mut destination = Vec::new();

    if let Some(matcher) = rule.domain_matcher {
        destination.push(RulesetExpr::Predicate(
            RulesetPredicate::SingboxDomainMatcher(matcher),
        ));
    }
    if !rule.domain_keywords.is_empty() {
        destination.push(RulesetExpr::Predicate(
            RulesetPredicate::SingboxDomainKeyword(rule.domain_keywords),
        ));
    }
    if !rule.domain_regexes.is_empty() {
        let regex = RegexSet::new(&rule.domain_regexes).map_err(|error| {
            ParseError::InvalidRule(format!("SRS domain_regex 编译失败: {error}"))
        })?;
        destination.push(RulesetExpr::Predicate(
            RulesetPredicate::SingboxDomainRegex(regex),
        ));
    }
    if let Some(matcher) = rule.adguard_domain_matcher {
        destination.push(RulesetExpr::Predicate(
            RulesetPredicate::AdGuardDomainMatcher(matcher),
        ));
    }
    if !rule.ip_cidrs.is_empty() {
        destination.push(RulesetExpr::Predicate(RulesetPredicate::DstIpCidr(
            rule.ip_cidrs,
        )));
    }
    if !destination.is_empty() {
        groups.push(RulesetExpr::Any(destination));
    }
    if !rule.source_ip_cidrs.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::SrcIpCidr(
            rule.source_ip_cidrs,
        )));
    }
    if !rule.ports.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::DstPort(
            rule.ports,
        )));
    }
    if !rule.source_ports.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::SrcPort(
            rule.source_ports,
        )));
    }
    if !rule.process_names.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::ProcessName(
            rule.process_names,
        )));
    }
    if !rule.query_types.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::QueryType(
            rule.query_types,
        )));
    }
    if !rule.process_paths.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::ProcessPath(
            rule.process_paths,
        )));
    }
    if !rule.process_path_regexes.is_empty() {
        let regex = RegexSet::new(&rule.process_path_regexes).map_err(|error| {
            ParseError::InvalidRule(format!("SRS process_path_regex 编译失败: {error}"))
        })?;
        groups.push(RulesetExpr::Predicate(RulesetPredicate::ProcessPathRegex(
            regex,
        )));
    }
    if !rule.package_names.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::PackageName(
            rule.package_names,
        )));
    }
    if !rule.package_name_regexes.is_empty() {
        let regex = RegexSet::new(&rule.package_name_regexes).map_err(|error| {
            ParseError::InvalidRule(format!("SRS package_name_regex 编译失败: {error}"))
        })?;
        groups.push(RulesetExpr::Predicate(RulesetPredicate::PackageNameRegex(
            regex,
        )));
    }
    if !rule.networks.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::SingboxNetwork(
            rule.networks,
        )));
    }
    if !rule.wifi_ssids.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::WifiSsid(
            rule.wifi_ssids,
        )));
    }
    if !rule.wifi_bssids.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::WifiBssid(
            rule.wifi_bssids,
        )));
    }
    if !rule.network_types.is_empty() {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::NetworkType(
            rule.network_types,
        )));
    }
    if rule.network_is_expensive {
        groups.push(RulesetExpr::Predicate(RulesetPredicate::NetworkIsExpensive));
    }
    if rule.network_is_constrained {
        groups.push(RulesetExpr::Predicate(
            RulesetPredicate::NetworkIsConstrained,
        ));
    }
    if !rule.network_interface_addresses.is_empty() {
        groups.push(RulesetExpr::Predicate(
            RulesetPredicate::NetworkInterfaceAddress(rule.network_interface_addresses),
        ));
    }
    if !rule.default_interface_addresses.is_empty() {
        groups.push(RulesetExpr::Predicate(
            RulesetPredicate::DefaultInterfaceAddress(rule.default_interface_addresses),
        ));
    }
    if groups.is_empty() {
        return Err(ParseError::InvalidRule(
            "SRS default rule 至少需要一个可求值 predicate".into(),
        ));
    }
    Ok(apply_invert(RulesetExpr::All(groups), invert))
}

fn check_item_version(version: u8, item_type: u8) -> Result<(), ParseError> {
    let minimum = match item_type {
        RULE_ITEM_ADGUARD_DOMAIN => 2,
        RULE_ITEM_NETWORK_TYPE
        | RULE_ITEM_NETWORK_IS_EXPENSIVE
        | RULE_ITEM_NETWORK_IS_CONSTRAINED => 3,
        RULE_ITEM_NETWORK_INTERFACE_ADDRESS | RULE_ITEM_DEFAULT_INTERFACE_ADDRESS => 4,
        RULE_ITEM_PACKAGE_NAME_REGEX => 5,
        _ => 1,
    };
    if version < minimum {
        return Err(binary_error(format!(
            "rule item type {item_type} 至少需要 SRS v{minimum}，文件声明为 v{version}"
        )));
    }
    Ok(())
}

fn read_string_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
    maximum_items: usize,
    maximum_string_bytes: usize,
) -> Result<Vec<String>, ParseError> {
    let count = reader.read_len(field, maximum_items)?;
    state.add_list_items(count, field)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let length = reader.read_len("string length", maximum_string_bytes)?;
        state.add_string_bytes(length, field)?;
        let bytes = reader.take(length, field)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| binary_error(format!("{field}[{index}] 不是合法 UTF-8")))?;
        values.push(value.to_owned());
    }
    Ok(values)
}

fn check_regex_limits(
    state: &mut DecodeState,
    patterns: &[String],
    field: &'static str,
) -> Result<(), ParseError> {
    let bytes = patterns.iter().try_fold(0usize, |total, pattern| {
        total
            .checked_add(pattern.len())
            .ok_or_else(|| binary_error(format!("{field} regex 总长度溢出")))
    })?;
    state.add_regex_bytes(bytes, field)
}

fn read_u16_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<u16>, ParseError> {
    let count = reader.read_len(field, MAX_LIST_ITEMS)?;
    state.add_list_items(count, field)?;
    state.add_semantic_items(count, field)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| binary_error(format!("{field} 内存分配失败")))?;
    for _ in 0..count {
        values.push(reader.read_u16_be(field)?);
    }
    Ok(values)
}

fn read_u8_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let count = reader.read_len(field, MAX_LIST_ITEMS)?;
    state.add_list_items(count, field)?;
    state.add_semantic_items(count, field)?;
    let bytes = reader.take(count, field)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| binary_error(format!("{field} 内存分配失败")))?;
    values.extend_from_slice(bytes);
    Ok(values)
}

fn read_prefix_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<IpNet>, ParseError> {
    let count = reader.read_len(field, MAX_LIST_ITEMS)?;
    state.add_list_items(count, field)?;
    state.add_semantic_items(count, field)?;
    let mut prefixes = Vec::new();
    prefixes
        .try_reserve_exact(count)
        .map_err(|_| binary_error(format!("{field} 内存分配失败")))?;
    for index in 0..count {
        prefixes.push(
            read_prefix(reader, field)
                .map_err(|error| add_context(error, format!("{field}[{index}]")))?,
        );
    }
    Ok(prefixes)
}

fn read_prefix(reader: &mut Reader<'_>, field: &'static str) -> Result<IpNet, ParseError> {
    let address_length = reader.read_len("prefix address length", 16)?;
    let address = reader.take(address_length, "prefix address")?;
    let prefix_bits = reader.read_u8("prefix bits")?;
    match address {
        [a, b, c, d] if prefix_bits <= 32 => {
            let address = Ipv4Addr::new(*a, *b, *c, *d);
            Ipv4Net::new(address, prefix_bits)
                .map(IpNet::V4)
                .map_err(|error| binary_error(format!("{field} IPv4 prefix 非法: {error}")))
        }
        bytes if bytes.len() == 16 && prefix_bits <= 128 => {
            let octets: [u8; 16] = bytes.try_into().expect("length checked");
            Ipv6Net::new(Ipv6Addr::from(octets), prefix_bits)
                .map(IpNet::V6)
                .map_err(|error| binary_error(format!("{field} IPv6 prefix 非法: {error}")))
        }
        [_, _, _, _] => Err(binary_error(format!(
            "{field} IPv4 prefix bits {prefix_bits} 超过 32"
        ))),
        bytes if bytes.len() == 16 => Err(binary_error(format!(
            "{field} IPv6 prefix bits {prefix_bits} 超过 128"
        ))),
        _ => Err(binary_error(format!(
            "{field} prefix address 长度 {address_length} 非法；仅允许 4/16"
        ))),
    }
}

fn read_network_interface_addresses(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
) -> Result<Vec<(u8, Vec<IpNet>)>, ParseError> {
    let count = reader.read_len("network_interface_address map", 256)?;
    state.add_list_items(count, "network_interface_address map")?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| binary_error("network_interface_address map 内存分配失败"))?;
    for index in 0..count {
        let interface_type = reader.read_u8("network interface type")?;
        if !seen.insert(interface_type) {
            return Err(binary_error(format!(
                "network_interface_address interface type {interface_type} 重复"
            )));
        }
        let prefixes = read_prefix_list(reader, state, "network_interface_address")
            .map_err(|error| add_context(error, format!("map[{index}]")))?;
        if prefixes.is_empty() {
            return Err(ParseError::InvalidRule(format!(
                "network_interface_address type {interface_type} 的 prefix 列表为空"
            )));
        }
        entries.push((interface_type, prefixes));
    }
    Ok(entries)
}

fn normalize_wifi_bssid(value: &str) -> String {
    let trimmed = value.trim();
    let compact = trimmed
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | '.'))
        .collect::<String>();
    if compact.len() == 12 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return compact
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| std::str::from_utf8(chunk).expect("ASCII hex"))
            .collect::<Vec<_>>()
            .join(":")
            .to_ascii_lowercase();
    }
    trimmed.to_owned()
}

fn read_port_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<PortRange>, ParseError> {
    let count = reader.read_len(field, MAX_LIST_ITEMS)?;
    state.add_list_items(count, field)?;
    state.add_semantic_items(count, field)?;
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let port = reader.read_u16_be(field)?;
        ports.push(PortRange::new(port, port).expect("single port is valid"));
    }
    Ok(ports)
}

fn read_port_range_list(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<PortRange>, ParseError> {
    let values = read_string_list(reader, state, field, MAX_LIST_ITEMS, MAX_STRING_BYTES)?;
    state.add_semantic_items(values.len(), field)?;
    values
        .into_iter()
        .map(|value| parse_port_range(field, &value))
        .collect()
}

fn parse_port_range(field: &'static str, value: &str) -> Result<PortRange, ParseError> {
    let (start, end) = value.split_once(':').ok_or_else(|| {
        ParseError::InvalidRule(format!("SRS {field}_range `{value}` 非法；应为 start:end"))
    })?;
    let start = if start.is_empty() {
        0
    } else {
        start.parse::<u16>().map_err(|_| {
            ParseError::InvalidRule(format!("SRS {field}_range 起始端口非法: `{value}`"))
        })?
    };
    let end = if end.is_empty() {
        u16::MAX
    } else {
        end.parse::<u16>().map_err(|_| {
            ParseError::InvalidRule(format!("SRS {field}_range 结束端口非法: `{value}`"))
        })?
    };
    // 上游使用 `range.Parse` 保留反向区间；这种区间不会命中，但不是格式错误。
    Ok(PortRange { start, end })
}

fn read_compact_domain_set(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<CompactDomainSet, ParseError> {
    let set_version = reader.read_u8("compact domain matcher version")?;
    if set_version != 0 {
        return Err(binary_error(format!(
            "不支持的 compact domain matcher version {set_version}"
        )));
    }
    let leaves = read_u64_slice(reader, "compact domain leaves", MAX_DOMAIN_BITMAP_WORDS)?;
    let label_bitmap = read_u64_slice(
        reader,
        "compact domain label bitmap",
        MAX_DOMAIN_BITMAP_WORDS,
    )?;
    let labels_length = reader.read_len("compact domain labels length", MAX_DOMAIN_NODES - 1)?;
    state.add_string_bytes(labels_length, field)?;
    let label_bytes = reader.take(labels_length, "compact domain labels")?;
    let node_count = labels_length
        .checked_add(1)
        .ok_or_else(|| binary_error("compact domain 节点数溢出"))?;
    let effective_bits = node_count
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| binary_error("compact domain bitmap 位数溢出"))?;
    let expected_bitmap_words = effective_bits.div_ceil(64);
    if label_bitmap.len() != expected_bitmap_words {
        return Err(binary_error(format!(
            "compact domain label bitmap word 数应为 {expected_bitmap_words}，实际为 {}",
            label_bitmap.len()
        )));
    }

    if !effective_bits.is_multiple_of(64) {
        let used_mask = (1u64 << (effective_bits % 64)) - 1;
        if label_bitmap.last().copied().unwrap_or(0) & !used_mask != 0 {
            return Err(binary_error("compact domain label bitmap padding 非零"));
        }
    }

    let allowed_leaf_words = node_count.div_ceil(64);
    if leaves.len() > allowed_leaf_words {
        return Err(binary_error("compact domain leaves 超过节点范围"));
    }
    if leaves.last().is_some_and(|word| *word == 0) {
        return Err(binary_error("compact domain leaves 含多余零 word"));
    }
    if !leaves.is_empty() && !node_count.is_multiple_of(64) && leaves.len() == allowed_leaf_words {
        let used_mask = (1u64 << (node_count % 64)) - 1;
        if leaves.last().copied().unwrap_or(0) & !used_mask != 0 {
            return Err(binary_error("compact domain leaves 指向不存在节点"));
        }
    }

    let mut child_offsets = Vec::new();
    child_offsets
        .try_reserve_exact(node_count + 1)
        .map_err(|_| binary_error("compact domain child offsets 内存分配失败"))?;
    let mut depths = Vec::new();
    depths
        .try_reserve_exact(node_count)
        .map_err(|_| binary_error("compact domain depth 索引内存分配失败"))?;
    depths.push(0u16);

    let mut label_index = 0usize;
    let mut bit_index = 0usize;
    for node_index in 0..node_count {
        child_offsets.push(
            u32::try_from(label_index)
                .map_err(|_| binary_error("compact domain child offset 超出 u32"))?,
        );
        loop {
            if bit_index >= effective_bits {
                return Err(binary_error("compact domain bitmap 在节点结束前 EOF"));
            }
            let bit = bitmap_bit(&label_bitmap, bit_index);
            bit_index += 1;
            if bit {
                break;
            }
            if label_index >= labels_length {
                return Err(binary_error("compact domain bitmap 的 child 数超过 labels"));
            }
            let depth = usize::from(depths[node_index]) + 1;
            if depth > MAX_DOMAIN_DEPTH {
                return Err(binary_error(format!(
                    "compact domain 深度超过上限 {MAX_DOMAIN_DEPTH}"
                )));
            }
            depths.push(depth as u16);
            label_index += 1;
        }
    }
    child_offsets.push(
        u32::try_from(label_index)
            .map_err(|_| binary_error("compact domain child offset 超出 u32"))?,
    );
    if bit_index != effective_bits || label_index != labels_length {
        return Err(binary_error("compact domain 含未引用 label"));
    }
    let terminal_count = leaves
        .iter()
        .map(|word| word.count_ones() as usize)
        .sum::<usize>();
    if terminal_count == 0 {
        return Err(ParseError::InvalidRule(
            "SRS compact domain matcher 为空".into(),
        ));
    }
    state.add_semantic_items(terminal_count, field)?;

    let mut labels = Vec::new();
    labels
        .try_reserve_exact(labels_length)
        .map_err(|_| binary_error("compact domain labels 内存分配失败"))?;
    labels.extend_from_slice(label_bytes);
    Ok(CompactDomainSet::new(
        leaves,
        child_offsets,
        labels,
        terminal_count,
    ))
}

fn read_u64_slice(
    reader: &mut Reader<'_>,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<u64>, ParseError> {
    let count = reader.read_len(field, maximum)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| binary_error(format!("{field} 内存分配失败")))?;
    for _ in 0..count {
        values.push(reader.read_u64_be(field)?);
    }
    Ok(values)
}

fn bitmap_bit(bitmap: &[u64], index: usize) -> bool {
    bitmap
        .get(index / 64)
        .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
}

fn read_ip_set(
    reader: &mut Reader<'_>,
    state: &mut DecodeState,
    field: &'static str,
) -> Result<Vec<IpNet>, ParseError> {
    let set_version = reader.read_u8("IP set version")?;
    if set_version != 1 {
        return Err(binary_error(format!(
            "不支持的 IP set version {set_version}"
        )));
    }
    let range_count_u64 = reader.read_u64_be("IP range count")?;
    let range_count =
        usize::try_from(range_count_u64).map_err(|_| binary_error("IP range count 超出 usize"))?;
    if range_count > MAX_IP_RANGES {
        return Err(binary_error(format!(
            "IP range count {range_count} 超过上限 {MAX_IP_RANGES}"
        )));
    }
    state.add_list_items(range_count, field)?;

    let mut output = Vec::new();
    let mut previous: Option<(IpAddr, IpAddr)> = None;
    for index in 0..range_count {
        let from = read_ip_addr(reader, "IP range from")?;
        let to = read_ip_addr(reader, "IP range to")?;
        if std::mem::discriminant(&from) != std::mem::discriminant(&to) {
            return Err(binary_error(format!("{field} range[{index}] 地址族不一致")));
        }
        if ip_value(from) > ip_value(to) {
            return Err(binary_error(format!("{field} range[{index}] from 大于 to")));
        }
        if let Some((previous_from, previous_to)) = previous {
            let ordered = match (previous_from, previous_to, from) {
                (IpAddr::V4(_), IpAddr::V4(previous_to), IpAddr::V4(from)) => {
                    u32::from(from) > u32::from(previous_to)
                }
                (IpAddr::V6(_), IpAddr::V6(previous_to), IpAddr::V6(from)) => {
                    u128::from(from) > u128::from(previous_to)
                }
                (IpAddr::V4(_), IpAddr::V4(_), IpAddr::V6(_)) => true,
                _ => false,
            };
            if !ordered {
                return Err(binary_error(format!(
                    "{field} range[{index}] 未严格递增或发生重叠"
                )));
            }
        }
        let networks = ip_range_to_networks(from, to)?;
        state.add_semantic_items(networks.len(), field)?;
        output.extend(networks);
        previous = Some((from, to));
    }
    Ok(output)
}

fn read_ip_addr(reader: &mut Reader<'_>, field: &'static str) -> Result<IpAddr, ParseError> {
    let length = reader.read_len(field, 16)?;
    let bytes = reader.take(length, field)?;
    match bytes {
        [a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().expect("length checked");
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(binary_error(format!(
            "{field} 长度 {length} 非法；仅允许 4/16"
        ))),
    }
}

fn ip_value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u32::from(address) as u128,
        IpAddr::V6(address) => u128::from(address),
    }
}

fn ip_range_to_networks(from: IpAddr, to: IpAddr) -> Result<Vec<IpNet>, ParseError> {
    match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            Ok(ipv4_range_to_networks(u32::from(from), u32::from(to)))
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            Ok(ipv6_range_to_networks(u128::from(from), u128::from(to)))
        }
        _ => Err(binary_error("IP range 地址族不一致")),
    }
}

fn ipv4_range_to_networks(mut from: u32, to: u32) -> Vec<IpNet> {
    let mut output = Vec::new();
    loop {
        let aligned_bits = from.trailing_zeros();
        let remaining = to as u64 - from as u64 + 1;
        let range_bits = 63 - remaining.leading_zeros();
        let block_bits = aligned_bits.min(range_bits);
        let prefix = (32 - block_bits) as u8;
        output.push(IpNet::V4(
            Ipv4Net::new(Ipv4Addr::from(from), prefix).expect("aligned IPv4 range"),
        ));
        let next = from as u64 + (1u64 << block_bits);
        if next > to as u64 {
            break;
        }
        from = next as u32;
    }
    output
}

fn ipv6_range_to_networks(mut from: u128, to: u128) -> Vec<IpNet> {
    let mut output = Vec::new();
    loop {
        let aligned_bits = from.trailing_zeros();
        let range_bits = if from == 0 && to == u128::MAX {
            128
        } else {
            let remaining = to - from + 1;
            127 - remaining.leading_zeros()
        };
        let block_bits = aligned_bits.min(range_bits);
        let prefix = (128 - block_bits) as u8;
        output.push(IpNet::V6(
            Ipv6Net::new(Ipv6Addr::from(from), prefix).expect("aligned IPv6 range"),
        ));
        if block_bits == 128 {
            break;
        }
        let Some(next) = from.checked_add(1u128 << block_bits) else {
            break;
        };
        if next > to {
            break;
        }
        from = next;
    }
    output
}

fn apply_invert(expression: RulesetExpr, invert: bool) -> RulesetExpr {
    if invert {
        RulesetExpr::Not(Box::new(expression))
    } else {
        expression
    }
}

fn decompress_zlib_bounded(input: &[u8], maximum: usize) -> Result<Vec<u8>, ParseError> {
    let mut decompressor = Decompress::new(true);
    let mut remaining = input;
    let mut output = Vec::new();
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(remaining, &mut buffer, FlushDecompress::Finish)
            .map_err(|error| binary_error(format!("zlib 解压失败: {error}")))?;
        let consumed = usize::try_from(decompressor.total_in() - before_in)
            .map_err(|_| binary_error("zlib consumed 长度溢出"))?;
        let produced = usize::try_from(decompressor.total_out() - before_out)
            .map_err(|_| binary_error("zlib produced 长度溢出"))?;
        if output.len().saturating_add(produced) > maximum {
            return Err(binary_error(format!("zlib 解压体超过上限 {maximum} bytes")));
        }
        output.extend_from_slice(&buffer[..produced]);
        remaining = remaining
            .get(consumed..)
            .ok_or_else(|| binary_error("zlib consumed 超出输入"))?;

        match status {
            Status::StreamEnd => {
                if !remaining.is_empty() {
                    return Err(binary_error(format!(
                        "zlib stream 后含 {} bytes 尾随数据",
                        remaining.len()
                    )));
                }
                return Ok(output);
            }
            Status::Ok | Status::BufError if consumed != 0 || produced != 0 => {}
            Status::Ok | Status::BufError => {
                return Err(binary_error("zlib stream 被截断或无法继续"));
            }
        }
    }
}

struct DecodeState {
    version: u8,
    total_rule_nodes: usize,
    total_list_items: usize,
    total_string_bytes: usize,
    total_regex_bytes: usize,
    total_semantic_items: usize,
}

impl DecodeState {
    fn new(version: u8) -> Self {
        Self {
            version,
            total_rule_nodes: 0,
            total_list_items: 0,
            total_string_bytes: 0,
            total_regex_bytes: 0,
            total_semantic_items: 0,
        }
    }

    fn add_rule(&mut self, depth: usize) -> Result<(), ParseError> {
        if depth > MAX_LOGICAL_DEPTH {
            return Err(binary_error(format!(
                "logical 递归深度超过上限 {MAX_LOGICAL_DEPTH}"
            )));
        }
        self.total_rule_nodes = self.total_rule_nodes.saturating_add(1);
        if self.total_rule_nodes > MAX_TOTAL_RULE_NODES {
            return Err(binary_error(format!(
                "规则总节点数超过上限 {MAX_TOTAL_RULE_NODES}"
            )));
        }
        Ok(())
    }

    fn add_list_items(&mut self, count: usize, field: &'static str) -> Result<(), ParseError> {
        self.total_list_items = self.total_list_items.saturating_add(count);
        if self.total_list_items > MAX_TOTAL_LIST_ITEMS {
            return Err(binary_error(format!(
                "{field} 使列表元素总数超过上限 {MAX_TOTAL_LIST_ITEMS}"
            )));
        }
        Ok(())
    }

    fn add_string_bytes(&mut self, count: usize, field: &'static str) -> Result<(), ParseError> {
        self.total_string_bytes = self.total_string_bytes.saturating_add(count);
        if self.total_string_bytes > MAX_TOTAL_STRING_BYTES {
            return Err(binary_error(format!(
                "{field} 使字符串总长度超过上限 {MAX_TOTAL_STRING_BYTES}"
            )));
        }
        Ok(())
    }

    fn add_regex_bytes(&mut self, count: usize, field: &'static str) -> Result<(), ParseError> {
        self.total_regex_bytes = self.total_regex_bytes.saturating_add(count);
        if self.total_regex_bytes > MAX_TOTAL_REGEX_BYTES {
            return Err(binary_error(format!(
                "{field} 使 regex 总长度超过上限 {MAX_TOTAL_REGEX_BYTES}"
            )));
        }
        Ok(())
    }

    fn add_semantic_items(&mut self, count: usize, field: &'static str) -> Result<(), ParseError> {
        self.total_semantic_items = self.total_semantic_items.saturating_add(count);
        if self.total_semantic_items > MAX_SEMANTIC_ITEMS {
            return Err(binary_error(format!(
                "{field} 使语义条目总数超过上限 {MAX_SEMANTIC_ITEMS}"
            )));
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_eof(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], ParseError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| binary_error(format!("{field} 长度溢出")))?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            binary_error(format!(
                "{field} 在 offset {} 处 EOF（需要 {length} bytes，仅余 {}）",
                self.position,
                self.remaining()
            ))
        })?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, ParseError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_bool(&mut self, field: &'static str) -> Result<bool, ParseError> {
        match self.read_u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(binary_error(format!("{field} bool 编码 {value} 非法"))),
        }
    }

    fn read_u16_be(&mut self, field: &'static str) -> Result<u16, ParseError> {
        let bytes: [u8; 2] = self.take(2, field)?.try_into().expect("length checked");
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u64_be(&mut self, field: &'static str) -> Result<u64, ParseError> {
        let bytes: [u8; 8] = self.take(8, field)?.try_into().expect("length checked");
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_uvarint(&mut self, field: &'static str) -> Result<u64, ParseError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.read_u8(field)?;
            if index == 9 && byte > 1 {
                return Err(binary_error(format!("{field} uvarint 溢出")));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let encoded_length = if value == 0 {
                    1
                } else {
                    ((64 - value.leading_zeros()) as usize).div_ceil(7)
                };
                if encoded_length != index + 1 {
                    return Err(binary_error(format!("{field} 使用非规范 uvarint 编码")));
                }
                return Ok(value);
            }
        }
        Err(binary_error(format!("{field} uvarint 溢出")))
    }

    fn read_len(&mut self, field: &'static str, maximum: usize) -> Result<usize, ParseError> {
        let value = self.read_uvarint(field)?;
        let value =
            usize::try_from(value).map_err(|_| binary_error(format!("{field} 超出 usize")))?;
        if value > maximum {
            return Err(binary_error(format!("{field} {value} 超过上限 {maximum}")));
        }
        Ok(value)
    }
}

fn add_context(error: ParseError, context: String) -> ParseError {
    match error {
        ParseError::UnsupportedField(_) | ParseError::UnsupportedVersion(_) => error,
        other => ParseError::Other(format!("SRS {context}: {other}")),
    }
}

fn binary_error(message: impl Into<String>) -> ParseError {
    ParseError::Other(format!("SRS: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;

    fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push((value as u8) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    fn wrap(version: u8, payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut output = b"SRS".to_vec();
        output.push(version);
        output.extend_from_slice(&compressed);
        output
    }

    fn network_rule_payload() -> Vec<u8> {
        let mut payload = vec![1, 0, RULE_ITEM_NETWORK];
        write_uvarint(1, &mut payload);
        write_uvarint(3, &mut payload);
        payload.extend_from_slice(b"tcp");
        payload.extend_from_slice(&[RULE_ITEM_FINAL, 0]);
        payload
    }

    #[test]
    fn minimal_network_rule_decodes() {
        let program = parse(&wrap(1, &network_rule_payload())).unwrap();
        assert_eq!(program.version(), 1);
        assert_eq!(program.rule_count(), 1);
        assert!(program.matches(&crate::RulesetMatchContext {
            network: Some("tcp"),
            ..Default::default()
        }));
        assert!(!program.matches(&crate::RulesetMatchContext {
            network: Some("TCP"),
            ..Default::default()
        }));
        assert!(!program.matches(&crate::RulesetMatchContext {
            network: Some("udp"),
            ..Default::default()
        }));
    }

    #[test]
    fn port_and_range_items_are_order_independent() {
        let mut payload = vec![1, 0, RULE_ITEM_PORT_RANGE];
        write_uvarint(1, &mut payload);
        write_uvarint(7, &mut payload);
        payload.extend_from_slice(b"100:200");
        payload.push(RULE_ITEM_PORT);
        write_uvarint(1, &mut payload);
        payload.extend_from_slice(&443u16.to_be_bytes());
        payload.extend_from_slice(&[RULE_ITEM_FINAL, 0]);

        let program = parse(&wrap(1, &payload)).unwrap();
        for port in [150, 443] {
            assert!(program.matches(&crate::RulesetMatchContext {
                dst_port: Some(port),
                ..Default::default()
            }));
        }
        assert!(!program.matches(&crate::RulesetMatchContext {
            dst_port: Some(80),
            ..Default::default()
        }));
    }

    #[test]
    fn port_ranges_preserve_upstream_raw_parsing() {
        let mut reversed = vec![1, 0, RULE_ITEM_PORT_RANGE];
        write_uvarint(1, &mut reversed);
        write_uvarint(7, &mut reversed);
        reversed.extend_from_slice(b"200:100");
        reversed.extend_from_slice(&[RULE_ITEM_FINAL, 0]);
        let program = parse(&wrap(1, &reversed)).unwrap();
        for port in [99, 100, 150, 200, 201] {
            assert!(!program.matches(&crate::RulesetMatchContext {
                dst_port: Some(port),
                ..Default::default()
            }));
        }

        let mut whitespace = vec![1, 0, RULE_ITEM_PORT_RANGE];
        write_uvarint(1, &mut whitespace);
        write_uvarint(9, &mut whitespace);
        whitespace.extend_from_slice(b" 100:200");
        whitespace.extend_from_slice(&[RULE_ITEM_FINAL, 0]);
        assert!(parse(&wrap(1, &whitespace)).is_err());
    }

    #[test]
    fn rejects_magic_versions_and_truncated_streams() {
        assert!(parse(b"").is_err());
        assert!(parse(b"BAD\x01").is_err());
        assert!(matches!(
            parse(b"SRS\x00garbage"),
            Err(ParseError::UnsupportedVersion(0))
        ));
        assert!(matches!(
            parse(b"SRS\x06garbage"),
            Err(ParseError::UnsupportedVersion(6))
        ));
        assert!(parse(b"SRS\x01").is_err());

        let mut truncated = wrap(1, &network_rule_payload());
        truncated.pop();
        assert!(parse(&truncated).is_err());
    }

    #[test]
    fn rejects_noncanonical_overflowing_and_eof_varints() {
        assert!(parse(&wrap(1, &[0x80, 0x00])).is_err());
        assert!(parse(&wrap(1, &[0x80])).is_err());
        assert!(
            parse(&wrap(
                1,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_compressed_and_decompressed_trailing_data() {
        let mut compressed_trailing = wrap(1, &network_rule_payload());
        compressed_trailing.push(0);
        assert!(parse(&compressed_trailing).is_err());

        let mut payload = network_rule_payload();
        payload.push(0);
        assert!(parse(&wrap(1, &payload)).is_err());
    }

    #[test]
    fn bounded_decompress_rejects_zip_bomb() {
        let zeros = vec![0u8; 4096];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&zeros).unwrap();
        let compressed = encoder.finish().unwrap();
        let error = decompress_zlib_bounded(&compressed, 128).unwrap_err();
        assert!(error.to_string().contains("超过上限"));
    }

    #[test]
    fn rejects_oversized_rule_list_and_strings() {
        let mut count = Vec::new();
        write_uvarint((MAX_RULES_PER_LIST + 1) as u64, &mut count);
        assert!(parse(&wrap(1, &count)).is_err());

        let mut list = vec![1, 0, RULE_ITEM_NETWORK];
        write_uvarint((MAX_LIST_ITEMS + 1) as u64, &mut list);
        assert!(parse(&wrap(1, &list)).is_err());

        let mut string = vec![1, 0, RULE_ITEM_NETWORK];
        write_uvarint(1, &mut string);
        write_uvarint((MAX_STRING_BYTES + 1) as u64, &mut string);
        assert!(parse(&wrap(1, &string)).is_err());
    }

    #[test]
    fn rejects_excessive_logical_depth_and_total_nodes() {
        let mut payload = vec![1];
        for _ in 0..MAX_LOGICAL_DEPTH {
            payload.extend_from_slice(&[1, 0, 1]);
        }
        payload.extend_from_slice(&network_rule_payload()[1..]);
        payload.extend(std::iter::repeat_n(0, MAX_LOGICAL_DEPTH));
        let error = parse(&wrap(1, &payload)).unwrap_err();
        assert!(error.to_string().contains("递归深度"));

        let mut state = DecodeState::new(1);
        state.total_rule_nodes = MAX_TOTAL_RULE_NODES;
        assert!(state.add_rule(1).is_err());
    }

    #[test]
    fn enforces_item_version_gates_before_reading_payloads() {
        let v1_adguard = wrap(1, &[1, 0, RULE_ITEM_ADGUARD_DOMAIN]);
        let error = parse(&v1_adguard).unwrap_err();
        assert!(error.to_string().contains("至少需要 SRS v2"));

        let v2_network_type = wrap(2, &[1, 0, RULE_ITEM_NETWORK_TYPE]);
        assert!(
            parse(&v2_network_type)
                .unwrap_err()
                .to_string()
                .contains("至少需要 SRS v3")
        );

        let v3_interface = wrap(3, &[1, 0, RULE_ITEM_DEFAULT_INTERFACE_ADDRESS]);
        assert!(
            parse(&v3_interface)
                .unwrap_err()
                .to_string()
                .contains("至少需要 SRS v4")
        );

        let v4_package_regex = wrap(4, &[1, 0, RULE_ITEM_PACKAGE_NAME_REGEX]);
        assert!(
            parse(&v4_package_regex)
                .unwrap_err()
                .to_string()
                .contains("至少需要 SRS v5")
        );
    }

    #[test]
    fn rejects_duplicate_items_invalid_bool_and_unknown_tag() {
        let duplicate = wrap(
            1,
            &[
                1,
                0,
                RULE_ITEM_NETWORK,
                0,
                RULE_ITEM_NETWORK,
                0,
                RULE_ITEM_FINAL,
                0,
            ],
        );
        assert!(parse(&duplicate).is_err());

        let invalid_bool = wrap(1, &[1, 0, RULE_ITEM_NETWORK, 0, RULE_ITEM_FINAL, 2]);
        assert!(parse(&invalid_bool).is_err());

        let unknown = wrap(5, &[1, 0, 24]);
        assert!(parse(&unknown).is_err());
    }

    #[test]
    fn rejects_corrupt_compact_domain_and_ip_sets() {
        let invalid_domain_version = wrap(1, &[1, 0, RULE_ITEM_DOMAIN, 1]);
        assert!(parse(&invalid_domain_version).is_err());

        let mut oversized_bitmap = vec![1, 0, RULE_ITEM_DOMAIN, 0, 0];
        write_uvarint(
            u64::try_from(MAX_DOMAIN_BITMAP_WORDS + 1).unwrap(),
            &mut oversized_bitmap,
        );
        assert!(parse(&wrap(1, &oversized_bitmap)).is_err());

        let mut invalid_domain_bitmap = vec![1, 0, RULE_ITEM_DOMAIN, 0, 0, 1];
        invalid_domain_bitmap.extend_from_slice(&0u64.to_be_bytes());
        invalid_domain_bitmap.push(0);
        assert!(parse(&wrap(1, &invalid_domain_bitmap)).is_err());

        let mut extra_bitmap_word = vec![1, 0, RULE_ITEM_DOMAIN, 0, 0, 2];
        extra_bitmap_word.extend_from_slice(&1u64.to_be_bytes());
        extra_bitmap_word.extend_from_slice(&0u64.to_be_bytes());
        extra_bitmap_word.push(0);
        assert!(parse(&wrap(1, &extra_bitmap_word)).is_err());

        let mut nonzero_bitmap_padding = vec![1, 0, RULE_ITEM_DOMAIN, 0, 1];
        nonzero_bitmap_padding.extend_from_slice(&1u64.to_be_bytes());
        nonzero_bitmap_padding.push(1);
        nonzero_bitmap_padding.extend_from_slice(&3u64.to_be_bytes());
        nonzero_bitmap_padding.push(0);
        assert!(parse(&wrap(1, &nonzero_bitmap_padding)).is_err());

        let mut leaf_outside_nodes = vec![1, 0, RULE_ITEM_DOMAIN, 0, 1];
        leaf_outside_nodes.extend_from_slice(&2u64.to_be_bytes());
        leaf_outside_nodes.push(1);
        leaf_outside_nodes.extend_from_slice(&1u64.to_be_bytes());
        leaf_outside_nodes.push(0);
        assert!(parse(&wrap(1, &leaf_outside_nodes)).is_err());

        let mut oversized_labels = vec![1, 0, RULE_ITEM_DOMAIN, 0, 0, 0];
        write_uvarint(MAX_DOMAIN_NODES as u64, &mut oversized_labels);
        assert!(parse(&wrap(1, &oversized_labels)).is_err());

        let invalid_ip_version = wrap(1, &[1, 0, RULE_ITEM_IP_CIDR, 0]);
        assert!(parse(&invalid_ip_version).is_err());

        let mut truncated_ip_range = vec![1, 0, RULE_ITEM_IP_CIDR, 1];
        truncated_ip_range.extend_from_slice(&1u64.to_be_bytes());
        truncated_ip_range.extend_from_slice(&[4, 192, 0]);
        assert!(parse(&wrap(1, &truncated_ip_range)).is_err());

        let mut mismatched_ip_families = vec![1, 0, RULE_ITEM_IP_CIDR, 1];
        mismatched_ip_families.extend_from_slice(&1u64.to_be_bytes());
        mismatched_ip_families.extend_from_slice(&[4, 192, 0, 2, 1, 16]);
        mismatched_ip_families.extend_from_slice(&[0u8; 16]);
        assert!(parse(&wrap(1, &mismatched_ip_families)).is_err());

        let mut reversed_ip_range = vec![1, 0, RULE_ITEM_IP_CIDR, 1];
        reversed_ip_range.extend_from_slice(&1u64.to_be_bytes());
        reversed_ip_range.extend_from_slice(&[4, 192, 0, 2, 2, 4, 192, 0, 2, 1]);
        assert!(parse(&wrap(1, &reversed_ip_range)).is_err());

        let mut overlapping_ip_ranges = vec![1, 0, RULE_ITEM_IP_CIDR, 1];
        overlapping_ip_ranges.extend_from_slice(&2u64.to_be_bytes());
        overlapping_ip_ranges.extend_from_slice(&[4, 192, 0, 2, 0, 4, 192, 0, 2, 10]);
        overlapping_ip_ranges.extend_from_slice(&[4, 192, 0, 2, 10, 4, 192, 0, 2, 20]);
        assert!(parse(&wrap(1, &overlapping_ip_ranges)).is_err());

        let mut too_many_ip_ranges = vec![1, 0, RULE_ITEM_IP_CIDR, 1];
        too_many_ip_ranges.extend_from_slice(&((MAX_IP_RANGES as u64) + 1).to_be_bytes());
        assert!(parse(&wrap(1, &too_many_ip_ranges)).is_err());
    }

    #[test]
    fn rejects_malformed_v4_prefixes_and_duplicate_interface_keys() {
        let mut invalid_v4_bits = vec![1, 0, RULE_ITEM_DEFAULT_INTERFACE_ADDRESS, 1, 4];
        invalid_v4_bits.extend_from_slice(&[192, 0, 2, 0, 33]);
        assert!(parse(&wrap(4, &invalid_v4_bits)).is_err());

        let mut invalid_v6_bits = vec![1, 0, RULE_ITEM_DEFAULT_INTERFACE_ADDRESS, 1, 16];
        invalid_v6_bits.extend_from_slice(&[0u8; 16]);
        invalid_v6_bits.push(129);
        assert!(parse(&wrap(4, &invalid_v6_bits)).is_err());

        let mut invalid_address_length = vec![1, 0, RULE_ITEM_DEFAULT_INTERFACE_ADDRESS, 1, 5];
        invalid_address_length.extend_from_slice(&[192, 0, 2, 0, 0, 24]);
        assert!(parse(&wrap(4, &invalid_address_length)).is_err());

        let mut duplicate_keys = vec![1, 0, RULE_ITEM_NETWORK_INTERFACE_ADDRESS, 2];
        duplicate_keys.extend_from_slice(&[0, 1, 4, 192, 168, 1, 0, 24, 0]);
        assert!(
            parse(&wrap(4, &duplicate_keys))
                .unwrap_err()
                .to_string()
                .contains("重复")
        );
    }

    #[test]
    fn ip_range_conversion_covers_full_families() {
        let ipv4 = ipv4_range_to_networks(0, u32::MAX);
        assert_eq!(ipv4, vec!["0.0.0.0/0".parse::<IpNet>().unwrap()]);

        let ipv6 = ipv6_range_to_networks(0, u128::MAX);
        assert_eq!(ipv6, vec!["::/0".parse::<IpNet>().unwrap()]);

        let split = ipv4_range_to_networks(
            u32::from(Ipv4Addr::new(192, 0, 2, 1)),
            u32::from(Ipv4Addr::new(192, 0, 2, 6)),
        );
        assert_eq!(
            split,
            vec![
                "192.0.2.1/32".parse::<IpNet>().unwrap(),
                "192.0.2.2/31".parse::<IpNet>().unwrap(),
                "192.0.2.4/31".parse::<IpNet>().unwrap(),
                "192.0.2.6/32".parse::<IpNet>().unwrap(),
            ]
        );
    }
}
