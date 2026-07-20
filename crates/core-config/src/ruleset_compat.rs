//! sing-box / Mihomo 规则集 provider 配置兼容与统一归一化。
//!
//! 运行时只消费 [`RuleSetSpec`]。本模块把两套上游配置严格迁移到该结构，
//! 并在配置期拒绝互斥字段、未知枚举和当前下载器无法兑现的 detour/proxy。

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use crate::{
    error::{ConfigError, ConfigResult},
    model::{
        CompatDuration, MihomoRuleProviderSpec, RuleSetSpec, SingboxRuleSetSpec, SingboxRuleSetTags,
    },
};

const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// 校验 WutherCore 原生 `route.sets`，再合并 sing-box 与 Mihomo 兼容入口。
pub(crate) fn merge_compatible_rule_sets(
    sets: &mut BTreeMap<String, RuleSetSpec>,
    singbox: Vec<SingboxRuleSetSpec>,
    mihomo: BTreeMap<String, MihomoRuleProviderSpec>,
) -> ConfigResult<()> {
    for (name, spec) in sets.iter_mut() {
        if name.trim().is_empty() {
            return Err(rule_error(
                "route.sets",
                "规则集名称不能为空",
                "为每个 route.sets 条目设置非空名称",
            ));
        }
        normalize_canonical_spec(spec, &format!("route.sets.{name}"))?;
    }

    for (name, spec) in normalize_singbox_rule_sets(singbox)? {
        insert_unique(sets, name, spec, "route.rule_set")?;
    }
    for (name, spec) in normalize_mihomo_rule_providers(mihomo)? {
        insert_unique(sets, name, spec, "rule-providers")?;
    }
    Ok(())
}

/// 把 Mihomo providers 迁移成原生 `route.sets`。CLI migrate 与 loader 共用，
/// 保证两条入口的字段语义和错误完全一致。
pub(crate) fn normalize_mihomo_rule_providers(
    providers: BTreeMap<String, MihomoRuleProviderSpec>,
) -> ConfigResult<BTreeMap<String, RuleSetSpec>> {
    let mut result = BTreeMap::new();
    let mut paths = BTreeMap::<String, String>::new();

    for (name, provider) in providers {
        let location = format!("rule-providers.{name}");
        if name.trim().is_empty() {
            return Err(rule_error(
                "rule-providers",
                "provider 名称不能为空",
                "为每个 rule-providers 条目设置非空名称",
            ));
        }
        if let Some(path) = provider.path.as_deref() {
            require_nonempty(path, &location, "path")?;
            if let Some(previous) = paths.insert(path.to_string(), name.clone()) {
                return Err(rule_error(
                    &location,
                    format!("path `{path}` 已被 provider `{previous}` 使用"),
                    "Mihomo provider 的 path 必须唯一；为其中一个 provider 更换缓存/文件路径",
                ));
            }
        }

        let behavior = normalize_mihomo_behavior(&provider.behavior, &location)?;
        let format = normalize_mihomo_format(provider.format.as_deref(), &location)?;
        validate_mrs_behavior(&format, &behavior, &location)?;
        let kind = provider.kind.trim().to_ascii_lowercase();

        let mut spec = match kind.as_str() {
            "http" => {
                let url =
                    required_string(provider.url, &location, "url", "type: http 必须提供 url")?;
                validate_http_url(&url, &location)?;
                if provider.payload.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: http 不能包含 payload",
                        "删除 payload，或把 type 改为 inline",
                    ));
                }
                validate_direct_download(provider.proxy.as_deref(), &location, "proxy")?;
                RuleSetSpec {
                    url: Some(url),
                    // Mihomo HTTP provider 的 path 是下载缓存位置，不是另一个源。
                    path: provider.path,
                    payload: vec![],
                    r#type: behavior,
                    format: Some(format),
                    every: compat_interval(provider.interval.as_ref(), &location)?,
                    via: "direct".into(),
                }
            }
            "file" => {
                let path =
                    required_string(provider.path, &location, "path", "type: file 必须提供 path")?;
                if provider.url.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: file 不能包含 url",
                        "删除 url，或把 type 改为 http",
                    ));
                }
                if provider.payload.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: file 不能包含 payload",
                        "删除 payload，或把 type 改为 inline",
                    ));
                }
                if provider.proxy.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: file 的 proxy 不会参与本地文件读取",
                        "删除 proxy；本地 provider 不需要下载出站",
                    ));
                }
                RuleSetSpec {
                    url: None,
                    path: Some(path),
                    payload: vec![],
                    r#type: behavior,
                    format: Some(format),
                    every: compat_interval(provider.interval.as_ref(), &location)?,
                    via: "direct".into(),
                }
            }
            "inline" => {
                if provider.url.is_some() || provider.path.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: inline 不能包含 url/path",
                        "删除 url/path，内联 provider 只使用 payload",
                    ));
                }
                if provider.interval.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: inline 的 interval 无法生效",
                        "删除 interval；内联规则不会刷新",
                    ));
                }
                if provider.proxy.is_some() {
                    return Err(rule_error(
                        &location,
                        "type: inline 的 proxy 无法生效",
                        "删除 proxy；内联规则不需要下载",
                    ));
                }
                if format == "mrs" {
                    return Err(rule_error(
                        &location,
                        "MRS 是二进制格式，不能放进 inline payload",
                        "把 type 改为 http/file，或把 format 改为 yaml/text",
                    ));
                }
                let payload = provider.payload.ok_or_else(|| {
                    rule_error(&location, "type: inline 缺少 payload", "添加 payload 列表")
                })?;
                if payload.is_empty() {
                    return Err(rule_error(
                        &location,
                        "type: inline 的 payload 不能为空",
                        "至少添加一条规则",
                    ));
                }
                RuleSetSpec {
                    url: None,
                    path: None,
                    payload,
                    r#type: behavior,
                    format: Some(format),
                    every: DEFAULT_UPDATE_INTERVAL,
                    via: "direct".into(),
                }
            }
            other => {
                return Err(rule_error(
                    &location,
                    format!("未知 Mihomo provider type `{other}`"),
                    "type 仅允许 http / file / inline",
                ));
            }
        };
        normalize_canonical_spec(&mut spec, &location)?;
        result.insert(name, spec);
    }

    Ok(result)
}

fn normalize_singbox_rule_sets(
    specs: Vec<SingboxRuleSetSpec>,
) -> ConfigResult<BTreeMap<String, RuleSetSpec>> {
    let mut result = BTreeMap::new();
    for (index, raw) in specs.into_iter().enumerate() {
        let base_location = format!("route.rule_set[{index}]");
        let tags = normalize_tags(raw.tag, &base_location)?;
        let kind = raw
            .kind
            .as_deref()
            .unwrap_or("inline")
            .trim()
            .to_ascii_lowercase();

        match kind.as_str() {
            "inline" => {
                if tags.len() != 1 {
                    return Err(rule_error(
                        &base_location,
                        "sing-box inline rule-set 不允许 tag 列表",
                        "每个 inline rule-set 只保留一个 tag",
                    ));
                }
                reject_present(
                    raw.format.as_ref(),
                    &base_location,
                    "format",
                    "inline rule-set 的规则直接来自 rules",
                )?;
                reject_present(
                    raw.path.as_ref(),
                    &base_location,
                    "path",
                    "inline rule-set 不读取文件",
                )?;
                reject_present(
                    raw.url.as_ref(),
                    &base_location,
                    "url",
                    "inline rule-set 不下载文件",
                )?;
                reject_present(
                    raw.update_interval.as_ref(),
                    &base_location,
                    "update_interval",
                    "inline rule-set 不会刷新",
                )?;
                reject_present(
                    raw.download_detour.as_ref(),
                    &base_location,
                    "download_detour",
                    "inline rule-set 不会下载",
                )?;
                reject_present(
                    raw.http_client.as_ref(),
                    &base_location,
                    "http_client",
                    "inline rule-set 不会下载",
                )?;
                let rules = raw.rules.ok_or_else(|| {
                    rule_error(
                        &base_location,
                        "sing-box inline rule-set 缺少 rules",
                        "添加 headless rules 列表",
                    )
                })?;
                let json_rules = rules
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        rule_error(
                            &base_location,
                            format!("inline rules 不能转换为 sing-box source JSON: {error}"),
                            "确保 headless rule 的 key 都是字符串且值为 JSON 兼容类型",
                        )
                    })?;
                let body = serde_json::to_string(&serde_json::json!({
                    "version": 5,
                    "rules": json_rules,
                }))
                .map_err(|error| {
                    rule_error(
                        &base_location,
                        format!("inline rules JSON 编码失败: {error}"),
                        "检查 rules 中的值",
                    )
                })?;
                let name = tags.into_iter().next().expect("one tag was validated");
                result.insert(
                    name,
                    RuleSetSpec {
                        url: None,
                        path: None,
                        payload: vec![body],
                        r#type: "mixed".into(),
                        format: Some("json".into()),
                        every: DEFAULT_UPDATE_INTERVAL,
                        via: "direct".into(),
                    },
                );
            }
            "local" => {
                reject_present(
                    raw.url.as_ref(),
                    &base_location,
                    "url",
                    "local rule-set 只使用 path",
                )?;
                reject_present(
                    raw.rules.as_ref(),
                    &base_location,
                    "rules",
                    "local rule-set 的内容来自 path",
                )?;
                reject_present(
                    raw.update_interval.as_ref(),
                    &base_location,
                    "update_interval",
                    "sing-box 只允许 remote rule-set 设置 update_interval",
                )?;
                reject_present(
                    raw.download_detour.as_ref(),
                    &base_location,
                    "download_detour",
                    "local rule-set 不会下载",
                )?;
                reject_present(
                    raw.http_client.as_ref(),
                    &base_location,
                    "http_client",
                    "local rule-set 不会下载",
                )?;
                let path = required_string(
                    raw.path,
                    &base_location,
                    "path",
                    "type: local 必须提供 path",
                )?;
                let format =
                    normalize_singbox_file_format(raw.format.as_deref(), &path, &base_location)?;
                expand_singbox_sources(
                    &mut result,
                    tags,
                    path,
                    false,
                    format,
                    DEFAULT_UPDATE_INTERVAL,
                    &base_location,
                )?;
            }
            "remote" => {
                reject_present(
                    raw.path.as_ref(),
                    &base_location,
                    "path",
                    "remote rule-set 只使用 url；缓存由 manager 管理",
                )?;
                reject_present(
                    raw.rules.as_ref(),
                    &base_location,
                    "rules",
                    "remote rule-set 的内容来自 url",
                )?;
                let url =
                    required_string(raw.url, &base_location, "url", "type: remote 必须提供 url")?;
                validate_http_url(&url, &base_location)?;
                let format =
                    normalize_singbox_file_format(raw.format.as_deref(), &url, &base_location)?;
                let via = normalize_singbox_http_client(
                    raw.download_detour.as_deref(),
                    raw.http_client.as_ref(),
                    &base_location,
                )?;
                let every = compat_interval(raw.update_interval.as_ref(), &base_location)?;
                expand_singbox_sources_with_via(
                    &mut result,
                    tags,
                    url,
                    true,
                    format,
                    every,
                    via,
                    &base_location,
                )?;
            }
            other => {
                return Err(rule_error(
                    &base_location,
                    format!("未知 sing-box rule-set type `{other}`"),
                    "type 仅允许 inline / local / remote",
                ));
            }
        }
    }
    Ok(result)
}

fn expand_singbox_sources(
    result: &mut BTreeMap<String, RuleSetSpec>,
    tags: Vec<String>,
    source: String,
    remote: bool,
    format: String,
    every: Duration,
    location: &str,
) -> ConfigResult<()> {
    expand_singbox_sources_with_via(
        result,
        tags,
        source,
        remote,
        format,
        every,
        "direct".into(),
        location,
    )
}

#[allow(clippy::too_many_arguments)]
fn expand_singbox_sources_with_via(
    result: &mut BTreeMap<String, RuleSetSpec>,
    tags: Vec<String>,
    source: String,
    remote: bool,
    format: String,
    every: Duration,
    via: String,
    location: &str,
) -> ConfigResult<()> {
    if tags.len() > 1 && !source.contains("{tag}") {
        return Err(rule_error(
            location,
            "多个 tag 共用的 path/url 缺少 `{tag}` 占位符",
            "在 path/url 中加入 `{tag}`，或拆成多个 rule-set 条目",
        ));
    }
    for tag in tags {
        let expanded = source.replace("{tag}", &tag);
        let mut spec = RuleSetSpec {
            url: remote.then_some(expanded.clone()),
            path: (!remote).then_some(expanded),
            payload: vec![],
            r#type: "mixed".into(),
            format: Some(format.clone()),
            every,
            via: via.clone(),
        };
        normalize_canonical_spec(&mut spec, location)?;
        if result.insert(tag.clone(), spec).is_some() {
            return Err(rule_error(
                location,
                format!("重复的 sing-box rule-set tag `{tag}`"),
                "每个 tag 只能定义一次",
            ));
        }
    }
    Ok(())
}

fn normalize_tags(tags: SingboxRuleSetTags, location: &str) -> ConfigResult<Vec<String>> {
    let tags = match tags {
        SingboxRuleSetTags::One(tag) => vec![tag],
        SingboxRuleSetTags::Many(tags) => tags,
    };
    if tags.is_empty() {
        return Err(rule_error(
            location,
            "sing-box rule-set tag 列表不能为空",
            "至少添加一个 tag",
        ));
    }
    let mut seen = BTreeSet::new();
    for tag in &tags {
        if tag.trim().is_empty() {
            return Err(rule_error(
                location,
                "sing-box rule-set tag 不能为空",
                "填写非空 tag",
            ));
        }
        if !seen.insert(tag.clone()) {
            return Err(rule_error(
                location,
                format!("tag `{tag}` 在同一条配置中重复"),
                "删除重复 tag",
            ));
        }
    }
    Ok(tags)
}

fn normalize_singbox_file_format(
    format: Option<&str>,
    source: &str,
    location: &str,
) -> ConfigResult<String> {
    let normalized = match format.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) if value.eq_ignore_ascii_case("source") => "json",
        Some(value) if value.eq_ignore_ascii_case("binary") => "srs",
        Some(other) => {
            return Err(rule_error(
                location,
                format!("未知 sing-box rule-set format `{other}`"),
                "format 仅允许 source / binary",
            ));
        }
        None => match extension(source).as_deref() {
            Some("json") => "json",
            Some("srs") => "srs",
            _ => {
                return Err(rule_error(
                    location,
                    "format 省略时 path/url 必须以 .json 或 .srs 结尾",
                    "显式设置 format: source 或 format: binary",
                ));
            }
        },
    };
    Ok(normalized.into())
}

fn normalize_singbox_http_client(
    download_detour: Option<&str>,
    http_client: Option<&serde_yaml::Value>,
    location: &str,
) -> ConfigResult<String> {
    let mut nested_detour: Option<String> = None;
    if let Some(value) = http_client {
        match value {
            serde_yaml::Value::Null => {}
            serde_yaml::Value::String(client) => {
                return Err(rule_error(
                    location,
                    format!(
                        "http_client: `{client}` 是共享 HTTP client tag，但 WutherCore 尚无 top-level http_clients registry"
                    ),
                    "删除字符串 http_client；若只需直连，使用 http_client.detour: direct",
                ));
            }
            serde_yaml::Value::Mapping(mapping) => {
                for (key, value) in mapping {
                    let Some(key) = key.as_str() else {
                        return Err(rule_error(
                            location,
                            "http_client object 的 key 必须是字符串",
                            "仅使用 http_client.detour: direct",
                        ));
                    };
                    if key != "detour" {
                        return Err(rule_error(
                            location,
                            format!("当前不支持 http_client.{key}"),
                            "当前仅支持官方 Dial Field http_client.detour: direct；其它 HTTP client 字段尚未接入 core-fetch",
                        ));
                    }
                    let detour = value.as_str().ok_or_else(|| {
                        rule_error(
                            location,
                            format!("http_client.{key} 必须是字符串"),
                            "填写出站 tag；当前只支持 direct",
                        )
                    })?;
                    nested_detour = Some(detour.to_string());
                }
            }
            _ => {
                return Err(rule_error(
                    location,
                    "http_client 必须是字符串或 object",
                    "使用 http_client.detour: direct",
                ));
            }
        }
    }

    match (download_detour, nested_detour.as_deref()) {
        (Some(top), Some(nested)) if !top.eq_ignore_ascii_case(nested) => {
            return Err(rule_error(
                location,
                "download_detour 与 http_client.detour 冲突",
                "只保留一个下载出站字段，或让两者取值一致",
            ));
        }
        _ => {}
    }
    let detour = download_detour.or(nested_detour.as_deref());
    let detour_field = if download_detour.is_some() {
        "download_detour"
    } else {
        "http_client.detour"
    };
    validate_direct_download(detour, location, detour_field)?;
    Ok("direct".into())
}

fn normalize_canonical_spec(spec: &mut RuleSetSpec, location: &str) -> ConfigResult<()> {
    spec.r#type = normalize_wuthercore_type(&spec.r#type, location)?;
    spec.format = spec
        .format
        .as_deref()
        .map(|format| normalize_wuthercore_format(format, location))
        .transpose()?;

    if let Some(url) = spec.url.as_deref() {
        require_nonempty(url, location, "url")?;
    }
    if let Some(path) = spec.path.as_deref() {
        require_nonempty(path, location, "path")?;
    }
    let has_payload = !spec.payload.is_empty();
    let has_external_source = spec.url.is_some() || spec.path.is_some();
    if has_payload && has_external_source {
        return Err(rule_error(
            location,
            "payload 不能与 url/path 同时使用",
            "内联规则只保留 payload；远程/本地规则只保留 url/path",
        ));
    }
    if !has_payload && !has_external_source {
        return Err(rule_error(
            location,
            "规则集缺少来源",
            "配置 payload，或配置 url/path",
        ));
    }
    if has_payload && matches!(spec.format.as_deref(), Some("mrs" | "srs" | "rrs")) {
        return Err(rule_error(
            location,
            format!(
                "{} 是二进制格式，不能放进 YAML payload",
                spec.format.as_deref().unwrap_or("binary")
            ),
            "改用 url/path，或把 format 改为 yaml/text/json",
        ));
    }
    if spec.format.as_deref() == Some("mrs") {
        validate_mrs_behavior("mrs", &spec.r#type, location)?;
    }
    if spec.via.trim().is_empty() || spec.via.trim().eq_ignore_ascii_case("direct") {
        spec.via = "direct".into();
    }
    // 原生 route.sets.via 是既有字段，保留任意旧值以维持反序列化/plan
    // 向后兼容；manager 在真正远程拉取前会明确返回“不支持非 direct”错误。
    // 外来格式的 proxy/download_detour 则在各自归一化入口直接拒绝。
    Ok(())
}

fn normalize_wuthercore_type(value: &str, location: &str) -> ConfigResult<String> {
    let normalized = match value.trim().to_ascii_lowercase().as_str() {
        "domain" => "domain",
        "ip" | "ipcidr" => "ipcidr",
        "classical" => "classical",
        "mixed" => "mixed",
        other => {
            return Err(rule_error(
                location,
                format!("未知规则集 type `{other}`"),
                "type 仅允许 domain / ipcidr / classical / mixed",
            ));
        }
    };
    Ok(normalized.into())
}

fn normalize_wuthercore_format(value: &str, location: &str) -> ConfigResult<String> {
    let normalized = match value.trim().to_ascii_lowercase().as_str() {
        "yaml" | "yml" => "yaml",
        "txt" | "list" | "text" => "text",
        "json" | "singbox" | "sing-box" => "json",
        "mrs" | "mihomo-binary" => "mrs",
        "srs" | "singbox-binary" => "srs",
        "rrs" | "wuthercore" | "wuthercore-binary" => "rrs",
        other => {
            return Err(rule_error(
                location,
                format!("未知规则集 format `{other}`"),
                "format 仅允许 yaml / text / json / mrs / srs / rrs",
            ));
        }
    };
    Ok(normalized.into())
}

fn normalize_mihomo_behavior(value: &str, location: &str) -> ConfigResult<String> {
    let normalized = match value.trim().to_ascii_lowercase().as_str() {
        "domain" => "domain",
        "ipcidr" => "ipcidr",
        "classical" => "classical",
        other => {
            return Err(rule_error(
                location,
                format!("未知 Mihomo behavior `{other}`"),
                "behavior 仅允许 domain / ipcidr / classical",
            ));
        }
    };
    Ok(normalized.into())
}

fn normalize_mihomo_format(value: Option<&str>, location: &str) -> ConfigResult<String> {
    let normalized = match value.unwrap_or("yaml").trim().to_ascii_lowercase().as_str() {
        "yaml" | "yml" => "yaml",
        "text" | "txt" => "text",
        "mrs" => "mrs",
        other => {
            return Err(rule_error(
                location,
                format!("未知 Mihomo format `{other}`"),
                "format 仅允许 yaml / text / mrs",
            ));
        }
    };
    Ok(normalized.into())
}

fn validate_mrs_behavior(format: &str, behavior: &str, location: &str) -> ConfigResult<()> {
    if format == "mrs" && !matches!(behavior, "domain" | "ipcidr") {
        return Err(rule_error(
            location,
            format!("MRS 不支持 behavior/type `{behavior}`"),
            "MRS 仅允许 domain 或 ipcidr，且必须与文件内 behavior 一致",
        ));
    }
    Ok(())
}

fn compat_interval(interval: Option<&CompatDuration>, location: &str) -> ConfigResult<Duration> {
    let duration = interval
        .map(CompatDuration::duration)
        .unwrap_or(DEFAULT_UPDATE_INTERVAL);
    if duration.is_zero() {
        return Err(rule_error(
            location,
            "刷新周期不能为 0",
            "设置正数秒或 duration（例如 86400 / 24h）",
        ));
    }
    Ok(duration)
}

fn validate_direct_download(value: Option<&str>, location: &str, field: &str) -> ConfigResult<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !value.eq_ignore_ascii_case("direct") {
        return Err(rule_error(
            location,
            format!("{field}: `{value}` 当前无法兑现：core-fetch 尚未接入按出站下载"),
            "改为 direct；待下载器接入 outbound dialer 后才能使用其它 proxy/detour",
        ));
    }
    Ok(())
}

fn validate_http_url(value: &str, location: &str) -> ConfigResult<()> {
    let parsed = url::Url::parse(value).map_err(|error| {
        rule_error(
            location,
            format!("url 非法: {error}"),
            "填写完整的 http:// 或 https:// URL",
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(rule_error(
            location,
            format!("url scheme `{}` 不支持", parsed.scheme()),
            "远程 provider 仅支持 http:// 或 https://",
        ));
    }
    Ok(())
}

fn required_string(
    value: Option<String>,
    location: &str,
    field: &str,
    missing_message: &str,
) -> ConfigResult<String> {
    let value =
        value.ok_or_else(|| rule_error(location, missing_message, format!("添加非空 {field}")))?;
    require_nonempty(&value, location, field)?;
    Ok(value)
}

fn require_nonempty(value: &str, location: &str, field: &str) -> ConfigResult<()> {
    if value.trim().is_empty() {
        return Err(rule_error(
            location,
            format!("{field} 不能为空"),
            format!("填写非空 {field}"),
        ));
    }
    Ok(())
}

fn reject_present<T>(
    value: Option<&T>,
    location: &str,
    field: &str,
    reason: &str,
) -> ConfigResult<()> {
    if value.is_some() {
        return Err(rule_error(
            location,
            format!("字段 `{field}` 在当前 type 下无效：{reason}"),
            format!("删除 {field}"),
        ));
    }
    Ok(())
}

fn extension(source: &str) -> Option<String> {
    let source = source.split(['?', '#']).next().unwrap_or(source);
    Path::new(source)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn insert_unique(
    sets: &mut BTreeMap<String, RuleSetSpec>,
    name: String,
    spec: RuleSetSpec,
    source: &str,
) -> ConfigResult<()> {
    if sets.contains_key(&name) {
        return Err(rule_error(
            source,
            format!("规则集名称/tag `{name}` 重复"),
            "route.sets、route.rule_set tag 与 rule-providers 名称必须全局唯一",
        ));
    }
    sets.insert(name, spec);
    Ok(())
}

fn rule_error(
    location: impl Into<String>,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> ConfigError {
    ConfigError::bad_route(message).at(location).hint(hint)
}
