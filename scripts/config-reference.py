"""Generate and verify the exhaustive WutherCore configuration field reference.

The user-facing configuration contract lives in ``core-config``.  This script
extracts public Serde fields and enum spellings from the Rust sources without
third-party Python dependencies, then writes stable Markdown reference pages.

It intentionally complements, rather than replaces, the hand-written manual:
the generated pages are the exhaustive contract/index; the authored pages
explain behavior, interactions, platform limits, and operational guidance.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ROOT / "crates/core-config/src/model.rs",
    ROOT / "crates/core-config/src/stream_settings.rs",
)
OUTPUT_DIR = ROOT / "docs/manual/generated"

STRUCT_RE = re.compile(r"^pub struct ([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]+>)?\s*\{")
ENUM_RE = re.compile(r"^pub enum ([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]+>)?\s*\{")
FIELD_RE = re.compile(
    r"^\s*pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+),\s*$",
    re.DOTALL,
)
VARIANT_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)(\s*(?:\([^;]*\)|\{.*\}))?\s*,?\s*$",
    re.DOTALL,
)
RENAME_RE = re.compile(r'\brename\s*=\s*"([^"]+)"')
RENAME_ALL_RE = re.compile(r'\brename_all\s*=\s*"([^"]+)"')
ALIAS_RE = re.compile(r'\balias\s*=\s*"([^"]+)"')
DEFAULT_FN_RE = re.compile(r'\bdefault\s*=\s*"([^"]+)"')
DEFAULT_IMPL_RE = re.compile(r"impl\s+Default\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
DEFAULT_FUNCTION_RE = re.compile(
    r"^fn\s+(default_[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*->[^{]+\{"
)


@dataclasses.dataclass(frozen=True)
class Field:
    owner: str
    rust_name: str
    yaml_name: str
    rust_type: str
    aliases: tuple[str, ...]
    serde: str
    docs: str
    source: Path
    line: int
    owner_default: bool


@dataclasses.dataclass(frozen=True)
class Struct:
    name: str
    docs: str
    serde: str
    source: Path
    line: int
    fields: tuple[Field, ...]


@dataclasses.dataclass(frozen=True)
class Variant:
    rust_name: str
    yaml_name: str
    payload: str
    aliases: tuple[str, ...]
    docs: str
    is_default: bool


@dataclasses.dataclass(frozen=True)
class Enum:
    name: str
    docs: str
    serde: str
    source: Path
    line: int
    variants: tuple[Variant, ...]


CATEGORIES: dict[str, tuple[str, str]] = {
    "core": (
        "配置根、Profile 与日志",
        "顶层配置、Profile、进程识别和日志输出的完整字段合同。",
    ),
    "inbounds": (
        "统一入口与服务端入站",
        "Mixed、TUN、TPROXY、REDIRECT、Panel、Shadowsocks、WireGuard、Young、gRPC、REALITY 和 XHTTP 入站。",
    ),
    "feeds-nodes": (
        "订阅、节点与出站",
        "订阅源、手动节点、协议参数、认证、传输入口和节点网络策略。",
    ),
    "xhttp": (
        "XHTTP / SplitHTTP 高级字段",
        "XHTTP、下载通道、REALITY、TLS、XMUX、FinalMask 和包变换的完整长尾字段。",
    ),
    "routing-dns": (
        "策略组、路由、规则集与 DNS",
        "选择策略、逐步路由、兼容规则集、DNS 服务和 Fake IP。",
    ),
    "capture-runtime": (
        "系统接管、Smart、UI 与 Mesh",
        "透明接管/TUN、平台过滤、智能选择、管理面板和 Tailscale 协同。",
    ),
    "stream": (
        "StreamSettings 与 socket 策略",
        "Xray 兼容 streamSettings、sockopt、Happy Eyeballs 与 FinalMask 配置。",
    ),
    "other": (
        "其他配置结构",
        "未归入主要领域但仍属于用户配置合同的公开字段。",
    ),
}

# These types implement a flat, type-discriminated Serde contract manually.
# Rendering their Rust storage fields would incorrectly document the internal
# `tun` member as a nested YAML object.
MANUAL_SERDE_TYPES = {"Inbound", "TransparentInboundOptions"}


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def visible_text(value: str) -> str:
    """Normalize reader-facing prose to the project's plain punctuation style."""
    value = re.sub(r"\s*——\s*", "：", value)
    return value.replace("—", "-").replace("–", "-").replace("·", "/")


def strip_docs(lines: list[str]) -> str:
    parts: list[str] = []
    for raw in lines:
        text = raw.strip()
        if text.startswith("///"):
            text = text[3:].strip()
        elif text.startswith("//!"):
            text = text[3:].strip()
        if text:
            parts.append(text)
    return visible_text(compact(" ".join(parts)))


def attr_text(lines: list[str]) -> str:
    return compact(" ".join(line.strip() for line in lines))


def rename(name: str, policy: str | None) -> str:
    if not policy:
        return name
    words = name.split("_")
    if policy == "camelCase":
        return words[0] + "".join(word[:1].upper() + word[1:] for word in words[1:])
    if policy == "PascalCase":
        return "".join(word[:1].upper() + word[1:] for word in words)
    if policy == "kebab-case":
        return "-".join(words).lower()
    if policy == "snake_case":
        return "_".join(words).lower()
    if policy == "SCREAMING_SNAKE_CASE":
        return "_".join(words).upper()
    if policy == "lowercase":
        return "".join(words).lower()
    if policy == "UPPERCASE":
        return "".join(words).upper()
    return name


def rustdoc_link(source: Path, line: int) -> str:
    relative = source.relative_to(ROOT).as_posix()
    return (
        "https://github.com/MiChongs/WutherCore/blob/main/"
        f"{relative}#L{line}"
    )


def collect_attribute(lines: list[str], start: int) -> tuple[str, int]:
    parts = [lines[start].strip()]
    balance = lines[start].count("[") - lines[start].count("]")
    index = start
    while balance > 0 and index + 1 < len(lines):
        index += 1
        parts.append(lines[index].strip())
        balance += lines[index].count("[") - lines[index].count("]")
    return compact(" ".join(parts)), index


def item_body_end(lines: list[str], start: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start, len(lines)):
        line = lines[index]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth == 0:
            return index
    raise ValueError(f"unclosed Rust item at line {start + 1}")


def parse_struct(
    lines: list[str],
    start: int,
    source: Path,
    docs: list[str],
    attrs: list[str],
) -> tuple[Struct, int]:
    match = STRUCT_RE.match(lines[start])
    assert match
    name = match.group(1)
    end = item_body_end(lines, start)
    serde = attr_text(attrs)
    rename_all_match = RENAME_ALL_RE.search(serde)
    rename_all = rename_all_match.group(1) if rename_all_match else None
    owner_default = bool(re.search(r"#\[serde\([^]]*\bdefault\b", serde))

    fields: list[Field] = []
    pending_docs: list[str] = []
    pending_attrs: list[str] = []
    index = start + 1
    while index < end:
        stripped = lines[index].strip()
        if stripped.startswith("///"):
            pending_docs.append(stripped)
            index += 1
            continue
        if stripped.startswith("#["):
            attribute, index = collect_attribute(lines, index)
            pending_attrs.append(attribute)
            index += 1
            continue
        if stripped.startswith("pub "):
            declaration = stripped
            declaration_line = index + 1
            while not declaration.rstrip().endswith(",") and index + 1 < end:
                index += 1
                declaration += " " + lines[index].strip()
            field_match = FIELD_RE.match(declaration)
            if field_match:
                rust_name = field_match.group(1)
                rust_type = compact(field_match.group(2))
                field_serde = attr_text(pending_attrs)
                explicit = RENAME_RE.search(field_serde)
                yaml_name = explicit.group(1) if explicit else rename(rust_name, rename_all)
                aliases = tuple(dict.fromkeys(ALIAS_RE.findall(field_serde)))
                serde_directives = re.sub(r'"[^"]*"', "", field_serde)
                if not re.search(
                    r"\bskip(?:_deserializing)?\b", serde_directives
                ):
                    fields.append(
                        Field(
                            owner=name,
                            rust_name=rust_name,
                            yaml_name=yaml_name,
                            rust_type=rust_type,
                            aliases=aliases,
                            serde=field_serde,
                            docs=strip_docs(pending_docs),
                            source=source,
                            line=declaration_line,
                            owner_default=owner_default,
                        )
                    )
            pending_docs = []
            pending_attrs = []
            index += 1
            continue
        if stripped and not stripped.startswith("//"):
            pending_docs = []
            pending_attrs = []
        index += 1

    return (
        Struct(
            name=name,
            docs=strip_docs(docs),
            serde=serde,
            source=source,
            line=start + 1,
            fields=tuple(fields),
        ),
        end,
    )


def parse_enum(
    lines: list[str],
    start: int,
    source: Path,
    docs: list[str],
    attrs: list[str],
) -> tuple[Enum, int]:
    match = ENUM_RE.match(lines[start])
    assert match
    name = match.group(1)
    end = item_body_end(lines, start)
    serde = attr_text(attrs)
    rename_all_match = RENAME_ALL_RE.search(serde)
    rename_all = rename_all_match.group(1) if rename_all_match else None

    variants: list[Variant] = []
    pending_docs: list[str] = []
    pending_attrs: list[str] = []
    index = start + 1
    while index < end:
        stripped = lines[index].strip()
        if stripped.startswith("///"):
            pending_docs.append(stripped)
            index += 1
            continue
        if stripped.startswith("#["):
            attribute, index = collect_attribute(lines, index)
            pending_attrs.append(attribute)
            index += 1
            continue
        if stripped and not stripped.startswith("//"):
            declaration = stripped
            while (
                declaration.count("(") > declaration.count(")")
                or declaration.count("{") > declaration.count("}")
            ) and index + 1 < end:
                index += 1
                declaration += " " + lines[index].strip()
            variant_match = VARIANT_RE.match(declaration.rstrip(","))
            if variant_match:
                rust_name = variant_match.group(1)
                payload = compact(variant_match.group(2) or "")
                variant_attrs = attr_text(pending_attrs)
                explicit = RENAME_RE.search(variant_attrs)
                yaml_name = explicit.group(1) if explicit else rename(rust_name, rename_all)
                variants.append(
                    Variant(
                        rust_name=rust_name,
                        yaml_name=yaml_name,
                        payload=payload,
                        aliases=tuple(dict.fromkeys(ALIAS_RE.findall(variant_attrs))),
                        docs=strip_docs(pending_docs),
                        is_default="#[default]" in variant_attrs,
                    )
                )
            pending_docs = []
            pending_attrs = []
        index += 1

    return (
        Enum(
            name=name,
            docs=strip_docs(docs),
            serde=serde,
            source=source,
            line=start + 1,
            variants=tuple(variants),
        ),
        end,
    )


def parse_source(source: Path) -> tuple[list[Struct], list[Enum], str]:
    text = source.read_text(encoding="utf-8")
    lines = text.splitlines()
    structs: list[Struct] = []
    enums: list[Enum] = []
    pending_docs: list[str] = []
    pending_attrs: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if lines[index].startswith("///"):
            pending_docs.append(lines[index])
            index += 1
            continue
        if lines[index].startswith("#["):
            attribute, index = collect_attribute(lines, index)
            pending_attrs.append(attribute)
            index += 1
            continue
        if STRUCT_RE.match(lines[index]):
            item, index = parse_struct(
                lines, index, source, pending_docs, pending_attrs
            )
            structs.append(item)
            pending_docs = []
            pending_attrs = []
            index += 1
            continue
        if ENUM_RE.match(lines[index]):
            item, index = parse_enum(lines, index, source, pending_docs, pending_attrs)
            enums.append(item)
            pending_docs = []
            pending_attrs = []
            index += 1
            continue
        if (
            lines[index]
            and not lines[index].startswith("//")
            and not lines[index].startswith("use ")
        ):
            pending_docs = []
            pending_attrs = []
        index += 1
    return structs, enums, text


def parse_default_variants(text: str) -> dict[str, str]:
    defaults: dict[str, str] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = DEFAULT_IMPL_RE.search(line)
        if not match:
            continue
        owner = match.group(1)
        end = item_body_end(lines, index)
        body = "\n".join(lines[index : end + 1])
        variant_match = re.search(
            rf"(?:Self|{re.escape(owner)})::([A-Za-z_][A-Za-z0-9_]*)", body
        )
        if variant_match:
            defaults[owner] = variant_match.group(1)
    return defaults


def parse_default_functions(text: str) -> dict[str, str]:
    """Return the source expression used by each simple default helper."""
    defaults: dict[str, str] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = DEFAULT_FUNCTION_RE.match(line)
        if not match:
            continue
        end = item_body_end(lines, index)
        body = lines[index + 1 : end]
        expression_lines = [
            value.strip()
            for value in body
            if value.strip() and not value.strip().startswith("//")
        ]
        if expression_lines:
            defaults[match.group(1)] = compact(" ".join(expression_lines))
    return defaults


def parse_struct_default_fields(text: str) -> dict[tuple[str, str], str]:
    """Extract direct ``field: expression`` entries from ``impl Default``."""
    defaults: dict[tuple[str, str], str] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = DEFAULT_IMPL_RE.search(line)
        if not match:
            continue
        owner = match.group(1)
        end = item_body_end(lines, index)
        in_self = False
        self_depth = 0
        for body_line in lines[index + 1 : end]:
            if not in_self and re.match(r"^\s*Self\s*\{", body_line):
                in_self = True
                self_depth = body_line.count("{") - body_line.count("}")
                continue
            if not in_self:
                continue
            if self_depth == 1:
                field_match = re.match(
                    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+),\s*$",
                    body_line,
                )
                if field_match:
                    defaults[(owner, field_match.group(1))] = compact(
                        field_match.group(2)
                    )
            self_depth += body_line.count("{") - body_line.count("}")
            if self_depth <= 0:
                break
    return defaults


def category_for(name: str, source: Path) -> str:
    if source.name == "stream_settings.rs":
        return "stream"
    if name in {
        "UserConfig",
        "Profile",
        "FindProcessMode",
        "Log",
        "LogFile",
        "LogLevel",
        "LogFormat",
        "DatabaseConfig",
        "DatabasePathBase",
        "MultiprocessWalMode",
    }:
        return "core"
    if name.startswith("Xhttp"):
        return "xhttp"
    if name.startswith(("Feed", "Node", "RealityClient", "GrpcTransport")):
        return "feeds-nodes"
    if name in {
        "Inbound",
        "InboundUser",
        "MixedInboundOptions",
        "EbpfInboundOptions",
        "EbpfCapabilityOptions",
        "EbpfSharedNetworkOptions",
        "TransparentInboundOptions",
        "Listen",
        "PanelBind",
        "Share",
        "ShareValue",
        "ListenLocal",
    } or name.startswith(
        (
            "ListenLocal",
            "Shadowsocks",
            "WireGuardListen",
            "YoungListen",
            "GrpcListen",
            "Reality",
        )
    ):
        return "inbounds"
    if name.startswith(
        (
            "Group",
            "Choose",
            "Route",
            "Matcher",
            "RuleSet",
            "SingboxRule",
            "MihomoRule",
            "CompatDuration",
            "Resolver",
            "Fake",
        )
    ):
        return "routing-dns"
    if name.startswith(
        (
            "Capture",
            "Tun",
            "Smart",
            "Ui",
            "Mesh",
            "Tailscale",
        )
    ):
        return "capture-runtime"
    return "other"


def friendly_type(rust_type: str) -> str:
    value = rust_type
    replacements = (
        (r"Option<(.+)>", r"\1（可选）"),
        (r"Vec<(.+)>", r"\1 列表"),
        (r"BTreeMap<String,\s*(.+)>", r"名称 → \1 映射"),
        (r"HashMap<String,\s*(.+)>", r"名称 → \1 映射"),
        (r"Box<(.+)>", r"\1"),
        (r"String", "字符串"),
        (r"bool", "布尔值"),
        (r"u8", "0-255 整数"),
        (r"u16", "0-65535 整数"),
        (r"u32", "非负整数"),
        (r"u64", "非负整数"),
        (r"usize", "非负整数"),
        (r"i32", "整数"),
        (r"i64", "整数"),
        (r"Duration", "时长"),
    )
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    return compact(value)


def format_duration(seconds: int) -> str:
    units = ((86_400, "d"), (3_600, "h"), (60, "m"))
    for divisor, suffix in units:
        if seconds >= divisor and seconds % divisor == 0:
            return f"{seconds // divisor}{suffix}"
    return f"{seconds}s"


def safe_integer_expression(expression: str) -> int | None:
    value = expression.replace("_", "").strip()
    if not re.fullmatch(r"[0-9+*()/\s-]+", value):
        return None
    try:
        result = eval(value, {"__builtins__": {}}, {})
    except (SyntaxError, TypeError, ValueError, ZeroDivisionError):
        return None
    return result if isinstance(result, int) and result >= 0 else None


def format_default_expression(
    expression: str,
    default_functions: dict[str, str],
    depth: int = 0,
) -> str:
    value = expression.strip().rstrip(",")
    if depth < 3 and re.fullmatch(r"default_[A-Za-z_][A-Za-z0-9_]*\(\)", value):
        function_name = value[:-2]
        resolved = default_functions.get(function_name)
        if resolved:
            return format_default_expression(resolved, default_functions, depth + 1)
    string_match = re.fullmatch(r'"(.*)"\.(?:into|to_string)\(\)', value)
    if string_match:
        return f"`{string_match.group(1)}`"
    if value in {"true", "false"}:
        return f"`{value}`"
    if value == "None":
        return "不设置"
    if value in {"Vec::new()", "vec![]", "BTreeMap::new()", "HashMap::new()"}:
        return "空"
    duration_match = re.fullmatch(r"Duration::from_secs\((.+)\)", value)
    if duration_match:
        seconds = safe_integer_expression(duration_match.group(1))
        return f"`{format_duration(seconds)}`" if seconds is not None else f"`{value}`"
    millis_match = re.fullmatch(r"Duration::from_millis\((.+)\)", value)
    if millis_match:
        millis = safe_integer_expression(millis_match.group(1))
        return f"`{millis}ms`" if millis is not None else f"`{value}`"
    enum_match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*::([A-Za-z_][A-Za-z0-9_]*)", value)
    if enum_match:
        variant = enum_match.group(1)
        spelling = re.sub(r"(?<!^)(?=[A-Z])", "_", variant).lower()
        return f"`{spelling}`"
    integer = safe_integer_expression(value)
    if integer is not None:
        return f"`{integer}`"
    return f"`{visible_text(value)}`"


def default_text(
    field: Field,
    enum_defaults: dict[str, str],
    default_functions: dict[str, str],
    struct_defaults: dict[tuple[str, str], str],
) -> str:
    explicit = DEFAULT_FN_RE.search(field.serde)
    has_default = bool(re.search(r"\bdefault\b", field.serde)) or field.owner_default
    if explicit:
        expression = default_functions.get(explicit.group(1))
        if expression:
            return "可选；默认 " + format_default_expression(
                expression, default_functions
            )
        return f"可选；由 `{explicit.group(1)}()` 决定"
    if not has_default:
        return "必填"
    owner_expression = struct_defaults.get((field.owner, field.rust_name))
    if owner_expression:
        return "可选；默认 " + format_default_expression(
            owner_expression, default_functions
        )
    rust_type = field.rust_type
    bare_type = re.sub(r"^(?:Option|Box)<(.+)>$", r"\1", rust_type)
    if rust_type.startswith("Option<"):
        return "可选；默认不设置"
    if rust_type.startswith(("Vec<", "BTreeMap<", "HashMap<")):
        return "可选；默认空"
    if rust_type == "bool":
        return "可选；默认 `false`"
    if rust_type == "String":
        return "可选；默认空字符串"
    if rust_type in {"u8", "u16", "u32", "u64", "usize", "i32", "i64"}:
        return "可选；默认 `0`"
    if bare_type in enum_defaults:
        return f"可选；默认 `{enum_defaults[bare_type]}`"
    return "可选；使用类型默认值"


def fallback_description(field: Field) -> str:
    name = field.rust_name
    if name in {"on", "enabled"}:
        return "控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。"
    if name in {"name", "tag"}:
        return "用于显示、日志和其它配置项引用的稳定名称。"
    if name in {"host", "address", "server"}:
        return "监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。"
    if name == "port" or name.endswith("_port"):
        return "监听或连接使用的端口；`0` 是否允许由所在配置块校验。"
    if "timeout" in name:
        return "超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。"
    if name.startswith("max_"):
        return "对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。"
    if name.startswith("min_"):
        return "对应范围或资源量的下限。"
    if name.endswith(("_interval", "_every")) or name == "every":
        return "周期性任务的执行间隔；时长字段接受 humantime 写法。"
    if any(token in name for token in ("password", "secret", "private_key", "token")):
        return "敏感认证材料；不要写入公开仓库、日志或截图。"
    if name.endswith(("_path", "_file")) or name == "path":
        return "文件或 URL 路径；相对路径按运行进程的工作目录解析。"
    if name.startswith(("include_", "exclude_")):
        return "包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。"
    return (
        f"`{field.owner}` 的 `{field.yaml_name}` 参数。解析类型为 "
        f"`{friendly_type(field.rust_type)}`；组合约束由 `wuther-core check` 校验。"
    )


def enum_values(
    field: Field,
    enums: dict[str, Enum],
    enum_defaults: dict[str, str],
) -> str:
    candidates = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", field.rust_type)
    target = next((enums[name] for name in candidates if name in enums), None)
    if not target:
        return "无"
    values: list[str] = []
    default_variant = enum_defaults.get(target.name)
    for variant in target.variants:
        value = variant.yaml_name
        suffix = variant.payload
        if suffix:
            value += suffix
        if variant.is_default or variant.rust_name == default_variant:
            value += "（默认）"
        values.append(f"`{value}`")
    return "<br>".join(values) if values else "无"


def markdown_escape(value: str) -> str:
    return visible_text(value).replace("|", r"\|").replace("\n", " ")


def render_category(
    category: str,
    structs: list[Struct],
    enums: list[Enum],
    enum_defaults: dict[str, str],
    default_functions: dict[str, str],
    struct_defaults: dict[tuple[str, str], str],
    total_fields: int,
    total_enums: int,
) -> str:
    title, description = CATEGORIES[category]
    enum_map = {item.name: item for item in enums}
    lines = [
        "---",
        f"title: {title} 完整字段索引",
        "hide:",
        "  - feedback",
        "---",
        "",
        f"# {title} 完整字段索引",
        "",
        "!!! info \"由配置源码生成\"",
        "",
        "    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde",
        "    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和",
        "    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。",
        "",
        description,
        "",
        f"全手册当前覆盖 **{total_fields} 个字段**、**{total_enums} 个枚举类型**。",
        "行为说明和跨字段约束请同时阅读同分类下的人工手册页面。",
        "",
    ]

    if category == "inbounds":
        lines.extend(
            [
                "## `Inbound`",
                "",
                "`inbounds` 使用 `type` 判别入口，透明入口字段与 TUN 字段位于同一层。",
                "",
                "| `type` | 专用字段 | 公共透明字段 |",
                "| --- | --- | --- |",
                "| `mixed` | `listen`、`listen_port`、`udp`、`users`、`streamSettings` | `tag`、`enabled` |",
                "| `tun` | [TUN 全部字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`mtu`、`offload`、`exclude` |",
                "| `tproxy` | [透明入口共用字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`offload`、`exclude` |",
                "| `redirect` | [透明入口共用字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`offload`、`exclude` |",
                "| `ebpf` | [Aya eBPF 字段](#ebpfinboundoptions) | `tag`、`enabled`、`redirect_address`、`bypass_rule_set`、UID 过滤、`dns_mode`、策略路由与 map 容量 |",
                "",
                "每个 tag 必须唯一。当前运行时最多启用一个 Mixed，并且 tun、tproxy、redirect、ebpf 中最多启用一个宿主流量入口。",
                "",
            ]
        )

    for struct in structs:
        source_link = rustdoc_link(struct.source, struct.line)
        lines.extend(
            [
                f"## `{struct.name}`",
                "",
                struct.docs or f"`{struct.name}` 配置对象。",
                "",
                f"[查看权威源码]({source_link})",
                "",
                "| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for field in struct.fields:
            aliases = (
                "<br>".join(f"`{alias}`" for alias in field.aliases)
                if field.aliases
                else "无"
            )
            description_text = field.docs or fallback_description(field)
            description_text += (
                f" [源码]({rustdoc_link(field.source, field.line)})"
            )
            yaml_name = field.yaml_name
            if "flatten" in field.serde:
                yaml_name += "（展开）"
            lines.append(
                "| "
                + " | ".join(
                    markdown_escape(value)
                    for value in (
                        f"`{yaml_name}`",
                        f"`{friendly_type(field.rust_type)}`",
                        default_text(
                            field,
                            enum_defaults,
                            default_functions,
                            struct_defaults,
                        ),
                        aliases,
                        enum_values(field, enum_map, enum_defaults),
                        description_text,
                    )
                )
                + " |"
            )
        if not struct.fields:
            lines.append("| 无 | 无 | 无 | 无 | 无 | 此结构没有可反序列化公开字段。 |")
        lines.append("")

    if enums:
        lines.extend(["## 本分类枚举", ""])
        for enum in enums:
            source_link = rustdoc_link(enum.source, enum.line)
            lines.extend(
                [
                    f"### `{enum.name}`",
                    "",
                    (enum.docs or f"`{enum.name}` 的可接受配置形态。")
                    + f" [源码]({source_link})",
                    "",
                    "| 写法 | 兼容别名 | 含义 |",
                    "| --- | --- | --- |",
                ]
            )
            default_variant = enum_defaults.get(enum.name)
            for variant in enum.variants:
                spelling = variant.yaml_name + variant.payload
                if variant.is_default or variant.rust_name == default_variant:
                    spelling += "（默认）"
                aliases = (
                    "<br>".join(f"`{alias}`" for alias in variant.aliases)
                    if variant.aliases
                    else "无"
                )
                lines.append(
                    "| "
                    + " | ".join(
                        markdown_escape(value)
                        for value in (
                            f"`{spelling}`",
                            aliases,
                            variant.docs
                            or f"映射到 Rust 变体 `{enum.name}::{variant.rust_name}`。",
                        )
                    )
                    + " |"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_outputs() -> tuple[dict[Path, str], int, int]:
    all_structs: list[Struct] = []
    all_enums: list[Enum] = []
    enum_defaults: dict[str, str] = {}
    default_functions: dict[str, str] = {}
    struct_defaults: dict[tuple[str, str], str] = {}
    for source in SOURCES:
        structs, enums, text = parse_source(source)
        all_structs.extend(structs)
        all_enums.extend(enums)
        enum_defaults.update(parse_default_variants(text))
        default_functions.update(parse_default_functions(text))
        struct_defaults.update(parse_struct_default_fields(text))

    for enum in all_enums:
        explicit_default = next(
            (variant.rust_name for variant in enum.variants if variant.is_default),
            None,
        )
        if explicit_default:
            enum_defaults[enum.name] = explicit_default

    structs_by_category: dict[str, list[Struct]] = defaultdict(list)
    enums_by_category: dict[str, list[Enum]] = defaultdict(list)
    visible_structs = [item for item in all_structs if item.name not in MANUAL_SERDE_TYPES]
    visible_enums = [item for item in all_enums if item.name not in MANUAL_SERDE_TYPES]

    for item in visible_structs:
        structs_by_category[category_for(item.name, item.source)].append(item)
    for item in visible_enums:
        enums_by_category[category_for(item.name, item.source)].append(item)

    total_fields = sum(len(item.fields) for item in visible_structs)
    total_enums = len(visible_enums)
    outputs: dict[Path, str] = {}
    for category in CATEGORIES:
        if not structs_by_category[category] and not enums_by_category[category]:
            continue
        outputs[OUTPUT_DIR / f"{category}.md"] = render_category(
            category,
            structs_by_category[category],
            enums_by_category[category],
            enum_defaults,
            default_functions,
            struct_defaults,
            total_fields,
            total_enums,
        )
    return outputs, total_fields, total_enums


def write_outputs(outputs: dict[Path, str]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    expected = set(outputs)
    for stale in OUTPUT_DIR.glob("*.md"):
        if stale not in expected:
            stale.unlink()
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8", newline="\n")


def check_outputs(outputs: dict[Path, str]) -> list[str]:
    errors: list[str] = []
    expected = set(outputs)
    existing = set(OUTPUT_DIR.glob("*.md")) if OUTPUT_DIR.exists() else set()
    for missing in sorted(expected - existing):
        errors.append(f"missing generated page: {missing.relative_to(ROOT)}")
    for stale in sorted(existing - expected):
        errors.append(f"stale generated page: {stale.relative_to(ROOT)}")
    for path, expected_content in outputs.items():
        if path.exists() and path.read_text(encoding="utf-8") != expected_content:
            errors.append(
                f"outdated generated page: {path.relative_to(ROOT)} "
                "(run `python scripts/config-reference.py --write`)"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write generated pages")
    mode.add_argument("--check", action="store_true", help="verify committed pages")
    args = parser.parse_args()

    outputs, total_fields, total_enums = build_outputs()
    if args.write:
        write_outputs(outputs)
        print(
            f"Generated {len(outputs)} pages covering "
            f"{total_fields} fields and {total_enums} enums"
        )
        return 0

    errors = check_outputs(outputs)
    if errors:
        print("Configuration reference is not synchronized:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        f"Configuration reference is current: {total_fields} fields, "
        f"{total_enums} enums, {len(outputs)} pages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
