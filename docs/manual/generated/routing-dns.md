---
title: 策略组、路由、规则集与 DNS 完整字段索引
hide:
  - feedback
---

# 策略组、路由、规则集与 DNS 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

选择策略、逐步路由、兼容规则集、DNS 服务和 Fake IP。

全手册当前覆盖 **828 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `GroupSpec`

`GroupSpec` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4248)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `choose` | `ChooseStrategy` | 可选；默认 `smart` | 无 | `manual`<br>`smart`<br>`fast`<br>`stable`<br>`spread`<br>`random`<br>`weighted`<br>`chain` | `GroupSpec` 的 `choose` 参数。解析类型为 `ChooseStrategy`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4250) |
| `proxies` | `字符串 列表` | 可选；默认 空 | `members` | 无 | 明确列出的节点或下级策略组。与 Mihomo `proxies` 同语义。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4253) |
| `include-all` | `布尔值` | 可选；默认 `false` | `include_all`<br>`includeAll` | 无 | 同时纳入全部静态节点和全部 provider。等价于同时启用 `include-all-proxies` 与 `include-all-providers`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4265) |
| `include-all-proxies` | `布尔值` | 可选；默认 `false` | `include_all_proxies`<br>`includeAllProxies` | 无 | 自动纳入所有静态节点。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4273) |
| `include-all-providers` | `布尔值` | 可选；默认 `false` | `include_all_providers`<br>`includeAllProviders` | 无 | 自动纳入所有 provider，运行时随订阅刷新展开。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4281) |
| `include-groups` | `字符串 列表` | 可选；默认 空 | `include_groups`<br>`includeGroups` | 无 | 按 glob 批量引用其它策略组。仅 manual 分流策略组可用。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4289) |
| `exclude-groups` | `字符串 列表` | 可选；默认 空 | `exclude_groups`<br>`excludeGroups` | 无 | 从显式和批量组引用中按 glob 排除策略组。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4297) |
| `include-nodes` | `字符串 列表` | 可选；默认 空 | `include_nodes`<br>`includeNodes` | 无 | 按 glob 纳入静态节点。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4305) |
| `exclude-nodes` | `字符串 列表` | 可选；默认 空 | `exclude_nodes`<br>`excludeNodes` | 无 | 按 glob 排除静态节点。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4313) |
| `include-providers` | `字符串 列表` | 可选；默认 空 | `include_providers`<br>`includeProviders` | 无 | 按 glob 纳入 provider。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4321) |
| `exclude-providers` | `字符串 列表` | 可选；默认 空 | `exclude_providers`<br>`excludeProviders` | 无 | 按 glob 排除 provider。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4329) |
| `min-members` | `非负整数` | 可选；默认 `0` | `min_members`<br>`minMembers` | 无 | 组至少需要的可用候选数。provider 未加载或过滤后不足时使用 `empty-fallback`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4338) |
| `max-members` | `非负整数` | 可选；默认 `0` | `max_members`<br>`maxMembers` | 无 | 过滤后最多保留的候选数。0 表示不限制。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4346) |
| `default-selected` | `字符串` | 可选；默认 `String::new()` | `default_selected`<br>`defaultSelected` | 无 | 未指定 API pin 时的默认成员。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4354) |
| `empty-fallback` | `字符串` | 可选；默认 `BLOCK` | `empty_fallback`<br>`emptyFallback` | 无 | 组没有足够候选时使用的具体 outbound。可写 DIRECT、BLOCK 或静态节点，不允许引用另一个组。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4363) |
| `lazy` | `布尔值` | 可选；默认 `true` | 无 | 无 | 闲置时停止健康检查。false 表示持续保持组探活计划。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4366) |
| `weights` | `名称 → 非负整数 映射` | 可选；默认 空 | 无 | 无 | weighted 策略的 glob 权重表。未匹配成员权重为 1。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4369) |
| `prefer` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 节点名称软偏好。Fast 在 tolerance 内优先，Stable 提升检查层级， Smart 加入评分。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4373) |
| `avoid` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 自动策略的降级候选；正常候选全部不可用时才兜底。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4376) |
| `check` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | 组级 HTTP/HTTPS 健康检查 URL。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4379) |
| `expected-status` | `字符串` | 可选；默认 `String::new()` | `expected_status`<br>`expectedStatus` | 无 | 健康检查期望状态码，兼容 Mihomo 的 `expected-status` 表达式。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4387) |
| `interval` | `时长` | 可选；默认 `1m` | 无 | 无 | 自动探活间隔。组在 `idle-timeout` 内没有被使用时会自动停表。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4390) |
| `idle-timeout` | `时长` | 可选；默认 `10m` | `idle_timeout` | 无 | 未被选路使用多久后停止周期探活。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4398) |
| `tolerance` | `非负整数` | 可选；默认 `50` | 无 | 无 | Fast/Smart 切换迟滞，单位毫秒。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4401) |
| `unified-delay` | `布尔值（可选）` | 可选；默认 不设置 | `unified_delay`<br>`unifiedDelay` | 无 | 是否使用去除连接建立噪声的统一延迟。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4409) |
| `strategy` | `字符串` | 可选；默认 `consistent-hashing` | 无 | 无 | Spread 的分配算法：consistent-hashing / round-robin / sticky-sessions。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4412) |
| `filter` | `字符串` | 可选；默认 `String::new()` | 无 | 无 | 组内节点名包含过滤，多条表达式用反引号分隔。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4415) |
| `exclude-filter` | `字符串` | 可选；默认 `String::new()` | `exclude_filter`<br>`excludeFilter` | 无 | 组内节点名排除过滤。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4423) |
| `exclude-type` | `字符串` | 可选；默认 `String::new()` | `exclude_type`<br>`excludeType` | 无 | 组内协议类型排除过滤，使用 `\|` 分隔。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4431) |
| `max-failed-times` | `非负整数` | 可选；默认 `5` | `max_failed_times`<br>`maxFailedTimes` | 无 | 连续拨号失败后触发一次按需健康检查的阈值。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4439) |
| `test-timeout` | `时长` | 可选；默认 `5s` | `test_timeout`<br>`testTimeout` | 无 | 连续拨号失败统计窗口。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4448) |
| `disable-udp` | `布尔值` | 可选；默认 `false` | `disable_udp`<br>`disableUdp` | 无 | `GroupSpec` 的 `disable-udp` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4455) |
| `sticky` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | Smart 粘性作用域覆盖：off、site 或 session；省略时继承全局配置。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4458) |
| `path` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 预留的 chain 多跳节点顺序。当前 `choose: chain` 在编译期拒绝， 不会把该列表误当成文件路径或静默执行第一跳。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4462) |
| `hidden` | `布尔值` | 可选；默认 `false` | 无 | 无 | 是否在支持该字段的 Clash dashboard 中隐藏策略组。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4465) |
| `icon` | `字符串` | 可选；默认 `String::new()` | 无 | 无 | 图标 URL、路径、data:image Base64 URI、`base64:<payload>` 或原始 Base64 图像。Base64 写法在编译阶段统一为 data URI。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4469) |

## `Route`

`Route` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4533)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `preset` | `字符串` | 可选；默认 `cn_smart` | 无 | 无 | `Route` 的 `preset` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4535) |
| `steps` | `RouteStepEntry 列表` | 可选；默认空 | 无 | `Line(String)`<br>`Object(RouteStepObject)` | `Route` 的 `steps` 参数。解析类型为 `RouteStepEntry 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4539) |
| `sub-rules` | `名称 → RouteStepEntry 映射 列表` | 可选；默认空 | `sub_rules` | `Line(String)`<br>`Object(RouteStepObject)` | Mihomo `sub-rules` compatible named rule branches. A top-level `SUB-RULE,(<condition>),<name>` jumps into one of these ordered lists. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4548) |
| `sets` | `名称 → RuleSetSpec 映射` | 可选；默认空 | 无 | 无 | 外部规则集：mihomo / sing-box / 自定义 payload。 在 `steps` 中通过 `set:<name> -> <action>` 引用。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4552) |
| `rule_set` | `SingboxRuleSetSpec 列表` | 可选；默认空 | `rule-set` | 无 | sing-box `route.rule_set` 兼容入口。编译阶段按 `tag` 展开并合并进 [`Self::sets`]；运行时只保留统一后的 `sets`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4561) |

## `RouteStepObject`

路由规则对象。所有匹配字段均可选；至少需要一项匹配源（`match` 或具名字段）， `outbound` 必填。多个匹配源同时存在时按 AND 组合（核心引擎以 `RouteMatcher::And` 表示，可短路求值）。具名字段值若为列表，按 OR 组合（`RouteMatcher::Or`）。 `deny_unknown_fields` 故意启用：拼写错误（如 `port-num:`）会立刻报错而非被 当成"无匹配源"静默通过；命中即配置错误。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4595)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `domain` | `MatcherValue（可选）` | 可选；默认不设置 | 无 | `Single(String)`<br>`List(Vec<String>)` | 严格相等的域名。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4602) |
| `suffix` | `MatcherValue（可选）` | 可选；默认不设置 | `domain-suffix`<br>`domain_suffix` | `Single(String)`<br>`List(Vec<String>)` | 域名后缀。canonical: `suffix`；mihomo 友好别名 `domain-suffix` / `domain_suffix`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4605) |
| `keyword` | `MatcherValue（可选）` | 可选；默认不设置 | `domain-keyword`<br>`domain_keyword` | `Single(String)`<br>`List(Vec<String>)` | 子串关键字。canonical: `keyword`；mihomo 友好别名 `domain-keyword`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4608) |
| `regex` | `MatcherValue（可选）` | 可选；默认不设置 | `domain-regex`<br>`domain_regex` | `Single(String)`<br>`List(Vec<String>)` | Mihomo `DOMAIN-REGEX`，大小写不敏感并支持 look-around / backreference。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4611) |
| `ip` | `MatcherValue（可选）` | 可选；默认不设置 | `cidr`<br>`ip-cidr`<br>`ip_cidr` | `Single(String)`<br>`List(Vec<String>)` | IP CIDR。canonical: `ip`；别名 `cidr` / `ip-cidr`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4614) |
| `source-ip` | `MatcherValue（可选）` | 可选；默认不设置 | `source_ip`<br>`src-ip`<br>`src_ip`<br>`src-ip-cidr`<br>`src_ip_cidr` | `Single(String)`<br>`List(Vec<String>)` | 源 IP CIDR。canonical: `source-ip`；兼容 Mihomo `src-ip-cidr`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4625) |
| `port` | `MatcherValue（可选）` | 可选；默认不设置 | `dst-port`<br>`dst_port` | `Single(String)`<br>`List(Vec<String>)` | 目的端口（单个 `53` 或区间 `1000-2000`）。canonical: `port`；别名 `dst-port`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4628) |
| `source-port` | `MatcherValue（可选）` | 可选；默认不设置 | `source_port`<br>`src-port`<br>`src_port` | `Single(String)`<br>`List(Vec<String>)` | 源端口（单个或闭区间）。canonical: `source-port`；兼容 Mihomo `src-port`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4637) |
| `process` | `MatcherValue（可选）` | 可选；默认不设置 | `process-name`<br>`process_name` | `Single(String)`<br>`List(Vec<String>)` | 进程名。canonical: `process`；别名 `process-name`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4640) |
| `process-path` | `MatcherValue（可选）` | 可选；默认不设置 | `process_path` | `Single(String)`<br>`List(Vec<String>)` | 完整进程路径，大小写不敏感精确匹配。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4643) |
| `set` | `MatcherValue（可选）` | 可选；默认不设置 | `rule-set`<br>`rule_set` | `Single(String)`<br>`List(Vec<String>)` | 外部规则集名（`route.sets.<name>`）。canonical: `set`；别名 `rule-set`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4646) |
| `network` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 网络协议（`tcp` / `udp`）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4649) |
| `proto` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | L7 协议指纹（`tls` / `quic` / `stun` / `http` / `webrtc`...）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4652) |
| `no-resolve` | `布尔值` | 可选；默认 `false` | `no_resolve` | 无 | Do not resolve a domain solely to evaluate IP-based matchers. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4656) |
| `no-log` | `布尔值` | 可选；默认 `false` | `no_log` | 无 | Suppress the routine rule-hit log. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4659) |
| `no-track` | `布尔值` | 可选；默认 `false` | `no_track` | 无 | Keep matching flows out of the active connection table. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4662) |
| `outbound` | `字符串` | 必填 | `proxy`<br>`target`<br>`action` | 无 | 出站 / 分组名 / `direct` / `block`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4666) |

## `RuleSetSpec`

`route.sets.<name>` 配置：与 `core_ruleset::RulesetSpec` 一一对应， 这里只做 YAML 反序列化所需的最小字段；运行时由 core-ruleset 编译。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4764)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `url` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 远程来源；与 `path` 同时出现时，`path` 是该远程规则集的显式缓存。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4767) |
| `path` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `url` 为空时是本地来源；`url` 存在时是远程缓存位置。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4770) |
| `payload` | `字符串 列表` | 可选；默认空 | 无 | 无 | `RuleSetSpec` 的 `payload` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4772) |
| `format` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `RuleSetSpec` 的 `format` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4776) |
| `every` | `时长` | 可选；默认 `1d` | 无 | 无 | 周期性任务的执行间隔；时长字段接受 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4778) |
| `via` | `字符串` | 可选；默认 `direct` | 无 | 无 | `RuleSetSpec` 的 `via` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4780) |

## `SingboxRuleSetSpec`

sing-box `route.rule_set[]` 原始配置。 这里保留上游字段名与互斥关系；`runtime_plan` 编译阶段会严格校验后转换成 [`RuleSetSpec`]。因此 sing-box 的 source-kind `type` 不会与 WutherCore 表示 behavior 的 `RuleSetSpec::type` 混淆。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4790)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `type` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `inline` / `local` / `remote`；inline 可省略。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4793) |
| `tag` | `SingboxRuleSetTags` | 必填 | 无 | `One(String)`<br>`Many(Vec<String>)` | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4794) |
| `format` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `SingboxRuleSetSpec` 的 `format` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4796) |
| `path` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4798) |
| `url` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `SingboxRuleSetSpec` 的 `url` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4800) |
| `rules` | `serde_yaml::Value 列表（可选）` | 可选；默认不设置 | 无 | 无 | `SingboxRuleSetSpec` 的 `rules` 参数。解析类型为 `serde_yaml::Value 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4802) |
| `update_interval` | `Compat时长（可选）` | 可选；默认不设置 | 无 | `Seconds(u64)`<br>`Human(#[serde(with = "humantime_serde")] Duration)` | 周期性任务的执行间隔；时长字段接受 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4804) |
| `download_detour` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `SingboxRuleSetSpec` 的 `download_detour` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4806) |
| `http_client` | `serde_yaml::Value（可选）` | 可选；默认不设置 | 无 | 无 | 兼容任务所需的 `http_client.download_detour`。使用 `Value` 是为了让 归一化层能对 string/object 与不支持的嵌套字段给出精确错误。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4810) |

## `MihomoRuleProviderSpec`

Mihomo 顶层 `rule-providers.<name>` 原始配置。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4824)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `type` | `字符串` | 必填 | 无 | 无 | `http` / `file` / `inline`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4827) |
| `url` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `MihomoRuleProviderSpec` 的 `url` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4829) |
| `path` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4831) |
| `payload` | `字符串 列表（可选）` | 可选；默认不设置 | 无 | 无 | `MihomoRuleProviderSpec` 的 `payload` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4833) |
| `behavior` | `字符串` | 必填 | 无 | 无 | `MihomoRuleProviderSpec` 的 `behavior` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4834) |
| `format` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `MihomoRuleProviderSpec` 的 `format` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4836) |
| `interval` | `Compat时长（可选）` | 可选；默认不设置 | 无 | `Seconds(u64)`<br>`Human(#[serde(with = "humantime_serde")] Duration)` | `MihomoRuleProviderSpec` 的 `interval` 参数。解析类型为 `Compat时长（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4838) |
| `proxy` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `MihomoRuleProviderSpec` 的 `proxy` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4840) |

## `Resolver`

`Resolver` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4871)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `mode` | `ResolverMode` | 可选；默认 `normal` | 无 | `system`<br>`normal`<br>`fake` | `Resolver` 的 `mode` 参数。解析类型为 `ResolverMode`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4873) |
| `fake` | `FakeMode` | 可选；默认 `auto` | 无 | `off`<br>`auto`<br>`force` | `Resolver` 的 `fake` 参数。解析类型为 `FakeMode`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4875) |
| `cache` | `时长` | 可选；默认 `1d` | 无 | 无 | `Resolver` 的 `cache` 参数。解析类型为 `时长`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4877) |
| `ipv6` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Resolver` 的 `ipv6` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4879) |
| `ipv6-timeout` | `时长` | 可选；默认 `100ms` | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4885) |
| `use-hosts` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Resolver` 的 `use-hosts` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4887) |
| `use-system-hosts` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Resolver` 的 `use-system-hosts` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4889) |
| `hosts` | `serde_yaml::Mapping` | 可选；默认 `serde_yaml::Mapping::new()` | 无 | 无 | `Resolver` 的 `hosts` 参数。解析类型为 `serde_yaml::Mapping`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4891) |
| `fake-ip-filter` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `Resolver` 的 `fake-ip-filter` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4893) |
| `fake-ip-filter-mode` | `FakeIpFilterMode` | 可选；默认 `FakeIpFilterMode::default()` | 无 | `blacklist（默认）`<br>`whitelist` | `Resolver` 的 `fake-ip-filter-mode` 参数。解析类型为 `FakeIpFilterMode`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4895) |
| `prefer-h3` | `布尔值` | 可选；默认 `false` | 无 | 无 | `Resolver` 的 `prefer-h3` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4897) |
| `nameserver` | `字符串 列表` | 可选；默认 `vec!["ali".into()]` | 无 | 无 | `Resolver` 的 `nameserver` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4899) |
| `fallback` | `字符串 列表` | 可选；默认 `vec!["cloudflare".into()]` | 无 | 无 | `Resolver` 的 `fallback` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4901) |
| `fallback-filter` | `ResolverFallbackFilter` | 可选；默认 `ResolverFallbackFilter::default()` | 无 | 无 | `Resolver` 的 `fallback-filter` 参数。解析类型为 `ResolverFallbackFilter`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4903) |
| `default-nameserver` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `Resolver` 的 `default-nameserver` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4905) |
| `nameserver-policy` | `serde_yaml::Mapping` | 可选；默认 `serde_yaml::Mapping::new()` | 无 | 无 | `Resolver` 的 `nameserver-policy` 参数。解析类型为 `serde_yaml::Mapping`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4907) |
| `proxy-server-nameserver` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `Resolver` 的 `proxy-server-nameserver` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4909) |
| `proxy-server-nameserver-policy` | `serde_yaml::Mapping` | 可选；默认 `serde_yaml::Mapping::new()` | 无 | 无 | `Resolver` 的 `proxy-server-nameserver-policy` 参数。解析类型为 `serde_yaml::Mapping`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4911) |
| `direct-nameserver` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `Resolver` 的 `direct-nameserver` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4913) |
| `direct-nameserver-follow-policy` | `布尔值` | 可选；默认 `false` | 无 | 无 | `Resolver` 的 `direct-nameserver-follow-policy` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4915) |
| `servers` | `名称 → ResolverServer 映射` | 可选；默认 `BTreeMap::from([ ( "ali".into(), ResolverServer::from("https://223.5.5.5/dns-query"), ), ( "cloudflare".into(), ResolverServer::from("https://1.1.1.1/dns-query"), ), ])` | 无 | `Simple(String)`<br>`Advanced(ResolverServerAdvanced)` | 命名 DNS server。字符串是兼容/简洁写法；对象写法可让同一个 endpoint 通过多个代理出口查询。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4919) |
| `groups` | `名称 → ResolverGroup 映射` | 可选；默认 空 | 无 | `Simple(Vec<String>)`<br>`Advanced(ResolverGroupAdvanced)` | 可嵌套 DNS group。列表是简洁写法；对象写法可覆盖策略、超时和并发上限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4922) |
| `rules` | `serde_yaml::Value 列表` | 可选；默认 空 | 无 | 无 | `Resolver` 的 `rules` 参数。解析类型为 `serde_yaml::Value 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4924) |
| `listen` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | 标准 DNS 监听地址，对标 mihomo `dns.listen`。 例：`0.0.0.0:1053`、`127.0.0.1:53`、`[::]:5353`。 空 / None / 空串 = 不启动独立 DNS server。 同地址同时承载 UDP 和 TCP（与 mihomo 一致）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4930) |

## `ResolverServerAdvanced`

`ResolverServerAdvanced` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5069)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `endpoint` | `字符串` | 必填 | `address`<br>`upstream` | 无 | 唯一 DNS 服务 endpoint。服务级冗余应由 `resolver.groups` 表达。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5072) |
| `exits` | `字符串 列表` | 可选；默认空 | `outbound`<br>`outbounds`<br>`nodes` | 无 | 访问该 endpoint 的代理节点数组；空数组表示沿用默认直连 DNS socket。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5081) |
| `strategy` | `ResolverStrategy` | 可选；默认 `Adaptive` | 无 | `roundrobin`<br>`random`<br>`parallel`<br>`adaptive（默认）`<br>`sequential`<br>`all` | `ResolverServerAdvanced` 的 `strategy` 参数。解析类型为 `ResolverStrategy`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5083) |
| `timeout` | `时长` | 可选；默认 `5s` | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5085) |
| `max-parallel` | `非负整数` | 可选；默认 `2` | `max_parallel` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5091) |

## `ResolverGroupAdvanced`

`ResolverGroupAdvanced` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5134)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `members` | `字符串 列表` | 可选；默认空 | `member`<br>`servers`<br>`upstreams` | 无 | 成员可以引用命名 server、其它 group，或直接写 endpoint。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5143) |
| `strategy` | `ResolverStrategy` | 可选；默认 `Adaptive` | 无 | `roundrobin`<br>`random`<br>`parallel`<br>`adaptive（默认）`<br>`sequential`<br>`all` | `ResolverGroupAdvanced` 的 `strategy` 参数。解析类型为 `ResolverStrategy`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5145) |
| `timeout` | `时长` | 可选；默认 `5s` | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5147) |
| `max-parallel` | `非负整数` | 可选；默认 `2` | `max_parallel` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5153) |

## `ResolverFallbackFilter`

`ResolverFallbackFilter` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5175)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `geoip` | `布尔值` | 可选；默认 `true` | 无 | 无 | `ResolverFallbackFilter` 的 `geoip` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5177) |
| `geoip-code` | `字符串` | 可选；默认 `CN` | 无 | 无 | `ResolverFallbackFilter` 的 `geoip-code` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5179) |
| `ipcidr` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `ResolverFallbackFilter` 的 `ipcidr` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5181) |
| `domain` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `ResolverFallbackFilter` 的 `domain` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5183) |
| `geosite` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `ResolverFallbackFilter` 的 `geosite` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5185) |

## 本分类枚举

### `ChooseStrategy`

`ChooseStrategy` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4518)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `manual` | 无 | 映射到 Rust 变体 `ChooseStrategy::Manual`。 |
| `smart` | 无 | 映射到 Rust 变体 `ChooseStrategy::Smart`。 |
| `fast` | 无 | 映射到 Rust 变体 `ChooseStrategy::Fast`。 |
| `stable` | 无 | 映射到 Rust 变体 `ChooseStrategy::Stable`。 |
| `spread` | 无 | 映射到 Rust 变体 `ChooseStrategy::Spread`。 |
| `random` | 无 | 映射到 Rust 变体 `ChooseStrategy::Random`。 |
| `weighted` | 无 | 映射到 Rust 变体 `ChooseStrategy::Weighted`。 |
| `chain` | 无 | 映射到 Rust 变体 `ChooseStrategy::Chain`。 |

### `RouteStepEntry`

单条路由规则条目：接受四种写法（混用合法）： 1. **WutherCore DSL 字符串**：`"port:53 -> direct"`、`"set:openai -> ai"`。 2. **mihomo classical 字符串**：`"DST-PORT,53,DNS_Hijack"`（policy 内嵌）。 3. **mihomo classical mapping**：`{match: "DST-PORT,53", outbound: DNS_Hijack}`。 4. **typed-key mapping**（推荐写法）： ```yaml - {port: 53, outbound: DNS_Hijack} # 单值 - {port: [53, 5353], outbound: DNS_Hijack} # OR within field - {suffix: example.com, port: 443, outbound: direct} # AND across fields - {match: "DST-PORT,53", network: udp, outbound: hijack} # match + typed AND ``` 具名字段同时设置时按 AND 组合；列表值在单字段内按 OR 组合。 四种形式都在 `compile_route` 阶段编译为 `RouteStep`；object 形式不会经过 DSL 字符串再解析，省掉一次 round-trip。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4582)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Line(String)` | 无 | 映射到 Rust 变体 `RouteStepEntry::Line`。 |
| `Object(RouteStepObject)` | 无 | 映射到 Rust 变体 `RouteStepEntry::Object`。 |

### `MatcherValue`

单个或多个值的统一表示：让 `port: 53`、`port: "53"`、`port: [53, "5353"]` 都能解析。列表值在编译阶段会被包裹成 `RouteMatcher::Or`，匹配时短路求值。 自实现 `Deserialize` 而非 `derive(untagged)`，是为了把整型 / 布尔自动转成字符串：YAML 写 `port: 53` 时值是 i64，不会自动落到 `Single(String)` 上， 用户体验上为难。统一收敛成字符串，编译期再把 port 解析回 u16。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4677)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Single(String)` | 无 | 映射到 Rust 变体 `MatcherValue::Single`。 |
| `List(Vec<String>)` | 无 | 映射到 Rust 变体 `MatcherValue::List`。 |

### `SingboxRuleSetTags`

sing-box 1.14+ 允许一个 local/remote 配置用 tag 列表批量定义规则集。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4816)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(String)` | 无 | 映射到 Rust 变体 `SingboxRuleSetTags::One`。 |
| `Many(Vec<String>)` | 无 | 映射到 Rust 变体 `SingboxRuleSetTags::Many`。 |

### `CompatDuration`

上游刷新周期兼容表示：Mihomo 使用整数秒，sing-box 使用 duration 字符串。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4846)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Seconds(u64)` | 无 | 映射到 Rust 变体 `CompatDuration::Seconds`。 |
| `Human(#[serde(with = "humantime_serde")] Duration)` | 无 | 映射到 Rust 变体 `CompatDuration::Human`。 |

### `ResolverStrategy`

DNS 成员选择策略。 `random` 是均匀随机；`adaptive` 使用查询过程中学习到的平均 RTT 做加权随机， 与 AdGuard dnsproxy 的 load-balance 算法一致：平均 RTT 越小，权重越大。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4970)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `roundrobin` | 无 | 映射到 Rust 变体 `ResolverStrategy::RoundRobin`。 |
| `random` | 无 | 映射到 Rust 变体 `ResolverStrategy::Random`。 |
| `parallel` | 无 | 映射到 Rust 变体 `ResolverStrategy::Parallel`。 |
| `adaptive（默认）` | 无 | 映射到 Rust 变体 `ResolverStrategy::Adaptive`。 |
| `sequential` | `fallback` | 兼容旧的顺序故障转移语义。 |
| `all` | 无 | 并发收集所有成功答案。 |

### `ResolverServer`

命名 server 的兼容字符串写法或高级多出口写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4993)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Simple(String)` | 无 | 映射到 Rust 变体 `ResolverServer::Simple`。 |
| `Advanced(ResolverServerAdvanced)` | 无 | 映射到 Rust 变体 `ResolverServer::Advanced`。 |

### `ResolverGroup`

DNS group 的简洁列表写法或高级对象写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5097)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Simple(Vec<String>)` | 无 | 映射到 Rust 变体 `ResolverGroup::Simple`。 |
| `Advanced(ResolverGroupAdvanced)` | 无 | 映射到 Rust 变体 `ResolverGroup::Advanced`。 |

### `ResolverMode`

`ResolverMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5206)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `system` | 无 | 映射到 Rust 变体 `ResolverMode::System`。 |
| `normal` | `secure`<br>`smart` | 映射到 Rust 变体 `ResolverMode::Normal`。 |
| `fake` | 无 | 映射到 Rust 变体 `ResolverMode::Fake`。 |

### `FakeMode`

`FakeMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5216)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | 无 | 映射到 Rust 变体 `FakeMode::Off`。 |
| `auto` | 无 | 映射到 Rust 变体 `FakeMode::Auto`。 |
| `force` | 无 | 映射到 Rust 变体 `FakeMode::Force`。 |

### `FakeIpFilterMode`

`FakeIpFilterMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5224)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `blacklist（默认）` | 无 | 映射到 Rust 变体 `FakeIpFilterMode::Blacklist`。 |
| `whitelist` | 无 | 映射到 Rust 变体 `FakeIpFilterMode::Whitelist`。 |
