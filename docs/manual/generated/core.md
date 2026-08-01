---
title: 配置根、Profile 与日志 完整字段索引
hide:
  - feedback
---

# 配置根、Profile 与日志 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

顶层配置、Profile、进程识别和日志输出的完整字段合同。

全手册当前覆盖 **828 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `UserConfig`

顶层配置：用户实际写的 YAML。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L15)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `version` | `非负整数` | 必填 | 无 | 无 | 必填，目前固定为 `1`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L17) |
| `profile` | `Profile` | 可选；默认 `Desktop` | 无 | `desktop（默认）`<br>`router`<br>`server`<br>`mobile` | `UserConfig` 的 `profile` 参数。解析类型为 `Profile`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L19) |
| `name` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L21) |
| `log` | `Log（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `log` 参数。解析类型为 `Log（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L23) |
| `database` | `DatabaseConfig` | 可选；使用类型默认值 | `storage`<br>`store` | 无 | `UserConfig` 的 `database` 参数。解析类型为 `DatabaseConfig`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L25) |
| `inbounds` | `Inbound 列表` | 可选；默认空 | 无 | 无 | Canonical inbound configuration. Every entry uses a sing-box-style `type` discriminator and a stable route-visible `tag`. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L29) |
| `listen` | `Listen（可选）` | 可选；默认不设置 | 无 | 无 | Legacy listener configuration. New data-plane listeners belong in [`UserConfig::inbounds`]; control-plane fields remain supported here during the migration. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L34) |
| `feeds` | `名称 → FeedSpec 映射` | 可选；默认空 | 无 | 无 | `UserConfig` 的 `feeds` 参数。解析类型为 `名称 → FeedSpec 映射`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L36) |
| `nodes` | `NodeSpec 列表` | 可选；默认空 | 无 | 无 | `UserConfig` 的 `nodes` 参数。解析类型为 `NodeSpec 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L38) |
| `groups` | `名称 → GroupSpec 映射` | 可选；默认空 | 无 | 无 | `UserConfig` 的 `groups` 参数。解析类型为 `名称 → GroupSpec 映射`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L40) |
| `rule-providers` | `名称 → MihomoRuleProviderSpec 映射` | 可选；默认空 | `rule_providers` | 无 | Mihomo 顶层 `rule-providers` 兼容入口。编译阶段会归一化进 `route.sets`，不会原样进入 [`crate::runtime_plan::RuntimePlan`]。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L49) |
| `route` | `Route（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `route` 参数。解析类型为 `Route（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L51) |
| `resolver` | `Resolver（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `resolver` 参数。解析类型为 `Resolver（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L53) |
| `capture` | `Capture（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `capture` 参数。解析类型为 `Capture（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L55) |
| `smart` | `Smart（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `smart` 参数。解析类型为 `Smart（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L57) |
| `ui` | `Ui（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `ui` 参数。解析类型为 `Ui（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L59) |
| `mesh` | `Mesh（可选）` | 可选；默认不设置 | 无 | 无 | `UserConfig` 的 `mesh` 参数。解析类型为 `Mesh（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L61) |
| `find-process-mode` | `FindProcessMode` | 可选；默认 `Strict` | `find_process_mode` | `off`<br>`strict（默认）`<br>`always` | 反查发起进程名 / 路径：与 mihomo `find-process-mode` 1:1。 `off` 跳过反查；`strict`（默认）仅当路由规则用到 process 字段时反查； `always` 每条连接都反查。Off 时 dashboard `process` 列永远空。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L66) |

## `DatabaseConfig`

`DatabaseConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L130)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `true` | `on` | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L132) |
| `path` | `PathBuf` | 可选；默认 `PathBuf::from("data/state/wuthercore.db")` | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L134) |
| `relative-to` | `DatabasePathBase` | 可选；默认 `cwd` | `relative_to`<br>`path-base`<br>`path_base` | `config`<br>`cwd（默认）` | `DatabaseConfig` 的 `relative-to` 参数。解析类型为 `DatabasePathBase`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L142) |
| `busy-timeout` | `时长` | 可选；默认 `5s` | `busy_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L149) |
| `max-write-attempts` | `非负整数` | 可选；默认 `12` | `max_write_attempts` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L155) |
| `multiprocess-wal` | `MultiprocessWalMode` | 可选；默认 `auto` | `multiprocess_wal` | `auto（默认）`<br>`on`<br>`off` | `DatabaseConfig` 的 `multiprocess-wal` 参数。解析类型为 `MultiprocessWalMode`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L157) |
| `experimental-vacuum` | `布尔值` | 可选；默认 `true` | `experimental_vacuum`<br>`vacuum` | 无 | `DatabaseConfig` 的 `experimental-vacuum` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L164) |

## `LogFile`

`LogFile` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L243)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `on` | `布尔值` | 可选；默认 `false` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L245) |
| `path` | `字符串` | 可选；默认 `data/logs/wuthercore.log` | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L247) |

## `Log`

`Log` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L261)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `on` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L263) |
| `level` | `LogLevel` | 可选；默认 `info` | 无 | `off`<br>`error`<br>`warn`<br>`info（默认）`<br>`debug`<br>`trace` | `Log` 的 `level` 参数。解析类型为 `LogLevel`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L265) |
| `filter` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | `Log` 的 `filter` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L267) |
| `stdout` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Log` 的 `stdout` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L269) |
| `file` | `LogFile` | 可选；默认 `LogFile::default()` | 无 | 无 | `Log` 的 `file` 参数。解析类型为 `LogFile`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L271) |
| `format` | `LogFormat` | 可选；默认 `text` | 无 | `text（默认）`<br>`json` | `Log` 的 `format` 参数。解析类型为 `LogFormat`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L273) |
| `connection-summary-interval` | `时长` | 可选；默认 `z_e_r_o` | `connection_summary_interval` | 无 | 周期性打印连接表聚合摘要的间隔。`0s` = 关（默认）。 推荐值 30s ~ 5m；< 1s 视为关，避免日志洪水。 输出 target=`conntable`，level=info：总数 / top-N 目的地 / top-N 进程 / by-rule / by-outbound / 长连接清单。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L284) |

## 本分类枚举

### `FindProcessMode`

`find-process-mode` 三态：与 mihomo `C.FindProcessMode` 一致。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L72)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | 无 | 永不反查。 |
| `strict（默认）` | 无 | 仅当 `route.steps` 用到 `process` 匹配时反查。 |
| `always` | 无 | 每条 TCP/UDP 连接都反查。 |

### `DatabasePathBase`

`DatabasePathBase` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L97)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `config` | `config-directory`<br>`config_directory` | 映射到 Rust 变体 `DatabasePathBase::Config`。 |
| `cwd（默认）` | `working-directory`<br>`working_directory`<br>`workdir` | 映射到 Rust 变体 `DatabasePathBase::Cwd`。 |

### `MultiprocessWalMode`

`MultiprocessWalMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L116)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `auto（默认）` | 无 | 映射到 Rust 变体 `MultiprocessWalMode::Auto`。 |
| `on` | 无 | 映射到 Rust 变体 `MultiprocessWalMode::On`。 |
| `off` | 无 | 映射到 Rust 变体 `MultiprocessWalMode::Off`。 |

### `Profile`

`Profile` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L183)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `desktop（默认）` | 无 | 映射到 Rust 变体 `Profile::Desktop`。 |
| `router` | 无 | 映射到 Rust 变体 `Profile::Router`。 |
| `server` | 无 | 映射到 Rust 变体 `Profile::Server`。 |
| `mobile` | 无 | 映射到 Rust 变体 `Profile::Mobile`。 |

### `LogLevel`

`LogLevel` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L200)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | 无 | 映射到 Rust 变体 `LogLevel::Off`。 |
| `error` | 无 | 映射到 Rust 变体 `LogLevel::Error`。 |
| `warn` | 无 | 映射到 Rust 变体 `LogLevel::Warn`。 |
| `info（默认）` | 无 | 映射到 Rust 变体 `LogLevel::Info`。 |
| `debug` | 无 | 映射到 Rust 变体 `LogLevel::Debug`。 |
| `trace` | 无 | 映射到 Rust 变体 `LogLevel::Trace`。 |

### `LogFormat`

`LogFormat` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L230)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `text（默认）` | 无 | 映射到 Rust 变体 `LogFormat::Text`。 |
| `json` | 无 | 映射到 Rust 变体 `LogFormat::Json`。 |
