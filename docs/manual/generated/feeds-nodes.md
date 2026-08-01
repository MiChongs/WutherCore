---
title: 订阅、节点与出站 完整字段索引
hide:
  - feedback
---

# 订阅、节点与出站 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

订阅源、手动节点、协议参数、认证、传输入口和节点网络策略。

全手册当前覆盖 **828 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `FeedDetail`

`FeedDetail` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1328)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `url` | `字符串` | 可选；默认空字符串 | 无 | 无 | `FeedDetail` 的 `url` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1330) |
| `payload` | `serde_yaml::Value 列表` | 可选；默认空 | `nodes`<br>`outbounds` | 无 | Inline native nodes. Mihomo's `payload` spelling remains accepted; `nodes` and `outbounds` make the field independent of provider syntax. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1339) |
| `every` | `时长` | 可选；默认 `12h` | 无 | 无 | 周期性任务的执行间隔；时长字段接受 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1341) |
| `via` | `字符串` | 可选；默认 `direct` | 无 | 无 | `FeedDetail` 的 `via` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1343) |
| `keep` | `FeedFilter` | 可选；使用类型默认值 | 无 | 无 | `FeedDetail` 的 `keep` 参数。解析类型为 `FeedFilter`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1345) |
| `drop` | `FeedFilter` | 可选；使用类型默认值 | 无 | 无 | `FeedDetail` 的 `drop` 参数。解析类型为 `FeedFilter`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1347) |
| `rename` | `FeedRename` | 可选；使用类型默认值 | 无 | 无 | `FeedDetail` 的 `rename` 参数。解析类型为 `FeedRename`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1349) |
| `age-secret-key` | `字符串（可选）` | 可选；默认不设置 | `age_secret_key` | 无 | Mihomo provider `age-secret-key`. The fetched body is decrypted only when it is an ASCII-armored age document; plaintext remains accepted. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1358) |
| `size-limit` | `非负整数（可选）` | 可选；默认不设置 | `size_limit` | 无 | Provider response size ceiling in bytes. `0` follows Mihomo and means no provider-specific ceiling (the global fetch safety limit still applies). [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1368) |
| `header` | `名称 → FeedHeaderValue 映射` | 可选；默认空 | `headers` | `One(String)`<br>`Many(Vec<String>)` | Extra request headers. A single string and Mihomo's string-list form are both accepted. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1372) |
| `filter` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | Mihomo-compatible provider name/type filters. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1375) |
| `exclude-filter` | `字符串（可选）` | 可选；默认不设置 | `exclude_filter` | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1382) |
| `exclude-type` | `字符串（可选）` | 可选；默认不设置 | `exclude_type` | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1389) |
| `override` | `FeedOverride` | 可选；使用类型默认值 | `overrides` | 无 | Provider 级节点覆写。用于订阅源无法提供客户端所需字段，或机场按 AnyTLS `cmdSettings.client` 识别客户端实现的场景。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1393) |

## `FeedOverride`

`FeedOverride` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1414)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `clientId` | `字符串（可选）` | 可选；默认不设置 | `client-id`<br>`client_id`<br>`anytls-client-id`<br>`anytls_client_id` | 无 | 覆写该 provider 内全部 AnyTLS 节点上报的 `cmdSettings.client`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1424) |
| `tfo` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `FeedOverride` 的 `tfo` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1426) |
| `mptcp` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `FeedOverride` 的 `mptcp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1428) |
| `udp` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `FeedOverride` 的 `udp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1430) |
| `udp-over-tcp` | `布尔值（可选）` | 可选；默认不设置 | `udp_over_tcp` | 无 | `FeedOverride` 的 `udp-over-tcp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1432) |
| `up` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `FeedOverride` 的 `up` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1434) |
| `down` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `FeedOverride` 的 `down` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1436) |
| `dialer-proxy` | `字符串（可选）` | 可选；默认不设置 | `dialer_proxy` | 无 | `FeedOverride` 的 `dialer-proxy` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1438) |
| `skip-cert-verify` | `布尔值（可选）` | 可选；默认不设置 | `skip_cert_verify` | 无 | `FeedOverride` 的 `skip-cert-verify` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1440) |
| `name-cert-verify` | `字符串（可选）` | 可选；默认不设置 | `name_cert_verify` | 无 | `FeedOverride` 的 `name-cert-verify` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1442) |
| `interface-name` | `字符串（可选）` | 可选；默认不设置 | `interface_name` | 无 | `FeedOverride` 的 `interface-name` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1444) |
| `routing-mark` | `整数（可选）` | 可选；默认不设置 | `routing_mark` | 无 | `FeedOverride` 的 `routing-mark` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1446) |
| `ip-version` | `字符串（可选）` | 可选；默认不设置 | `ip_version` | 无 | `FeedOverride` 的 `ip-version` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1448) |
| `additional-prefix` | `字符串（可选）` | 可选；默认不设置 | `additional_prefix` | 无 | `FeedOverride` 的 `additional-prefix` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1450) |
| `additional-suffix` | `字符串（可选）` | 可选；默认不设置 | `additional_suffix` | 无 | `FeedOverride` 的 `additional-suffix` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1452) |
| `proxy-name` | `FeedProxyNameOverride 列表` | 可选；默认空 | `proxy_name` | 无 | `FeedOverride` 的 `proxy-name` 参数。解析类型为 `FeedProxyNameOverride 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1454) |

## `FeedProxyNameOverride`

`FeedProxyNameOverride` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1459)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `pattern` | `字符串` | 必填 | 无 | 无 | `FeedProxyNameOverride` 的 `pattern` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1460) |
| `target` | `字符串` | 可选；默认空字符串 | 无 | 无 | `FeedProxyNameOverride` 的 `target` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1462) |

## `FeedFilter`

`FeedFilter` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1523)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `name_has` | `字符串 列表` | 可选；默认空 | 无 | 无 | `FeedFilter` 的 `name_has` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1525) |

## `FeedRename`

`FeedRename` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1530)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `add_prefix` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `FeedRename` 的 `add_prefix` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1532) |
| `remove` | `字符串 列表` | 可选；默认空 | 无 | 无 | `FeedRename` 的 `remove` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1534) |

## `NodeDetail`

`NodeDetail` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1549)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `name` | `字符串` | 必填 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1550) |
| `link` | `字符串（可选）` | 可选；默认不设置 | `uri`<br>`url` | 无 | `NodeDetail` 的 `link` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1552) |
| `protocol` | `字符串（可选）` | 可选；默认不设置 | `type`<br>`kind` | 无 | Native subscriptions may use the concise `type` spelling while local configuration keeps the more descriptive `protocol` spelling. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1556) |
| `address` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1558) |
| `login` | `NodeLogin（可选）` | 可选；默认不设置 | 无 | 无 | `NodeDetail` 的 `login` 参数。解析类型为 `NodeLogin（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1560) |
| `secure` | `NodeSecure（可选）` | 可选；默认不设置 | 无 | 无 | `NodeDetail` 的 `secure` 参数。解析类型为 `NodeSecure（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1562) |
| `transport` | `NodeTransport（可选）` | 可选；默认不设置 | 无 | 无 | `NodeDetail` 的 `transport` 参数。解析类型为 `NodeTransport（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1564) |
| `network` | `NodeNetwork（可选）` | 可选；默认不设置 | 无 | 无 | `NodeDetail` 的 `network` 参数。解析类型为 `NodeNetwork（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1566) |
| `params` | `名称 → serde_json::Value 映射` | 可选；默认空 | `protocol-options`<br>`protocol_options` | 无 | 协议专属字段。标量保持文本语义，数组/对象会被编译为 JSON 后交给 对应协议注册器做严格校验；用于 WireGuard peers/allowed-ips 等结构。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1570) |
| `streamSettings` | `crate::stream_settings::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | `NodeDetail` 的 `streamSettings` 参数。解析类型为 `crate::stream_settings::NodeStreamSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1572) |

## `NodeLogin`

`NodeLogin` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1577)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `user` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeLogin` 的 `user` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1579) |
| `password` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1581) |
| `uuid` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeLogin` 的 `uuid` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1583) |
| `private_key` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1585) |

## `NodeSecure`

`NodeSecure` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1590)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tls` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `tls` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1592) |
| `sni` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `sni` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1594) |
| `fingerprint` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `fingerprint` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1596) |
| `utls` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `utls` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1598) |
| `reality` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `reality` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1600) |
| `realitySettings` | `RealityClientSettings（可选）` | 可选；默认不设置 | `reality_settings`<br>`reality-settings` | 无 | `NodeSecure` 的 `realitySettings` 参数。解析类型为 `RealityClientSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1607) |
| `ech` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeSecure` 的 `ech` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1609) |
| `tls-settings` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | `tls_settings`<br>`tlsSettings` | 无 | Xray-compatible TLS client settings. The legacy flat `sni`, `fingerprint`, and `utls` fields above remain accepted and are merged into this strongly typed object during runtime-plan compilation. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1620) |

## `RealityClientSettings`

Xray REALITY 客户端字段。`password` 是 Xray 新名称，`publicKey` 为兼容旧名称； 编译阶段会做冲突检测与统一解码。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1627)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `fingerprint` | `字符串` | 可选；默认 `chrome` | `fp` | 无 | `RealityClientSettings` 的 `fingerprint` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1629) |
| `serverName` | `字符串` | 可选；默认 `String::new()` | `server_name`<br>`server-name`<br>`sni` | 无 | `RealityClientSettings` 的 `serverName` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1637) |
| `password` | `字符串（可选）` | 可选；默认 不设置 | `pbk` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1639) |
| `publicKey` | `字符串（可选）` | 可选；默认 不设置 | `public_key`<br>`public-key` | 无 | `RealityClientSettings` 的 `publicKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1646) |
| `shortId` | `字符串` | 可选；默认 `String::new()` | `short_id`<br>`short-id`<br>`sid` | 无 | `RealityClientSettings` 的 `shortId` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1654) |
| `mldsa65Verify` | `字符串（可选）` | 可选；默认 不设置 | `mldsa65_verify`<br>`mldsa65-verify`<br>`pqv` | 无 | `RealityClientSettings` 的 `mldsa65Verify` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1662) |
| `spiderX` | `字符串` | 可选；默认 `/` | `spider_x`<br>`spider-x`<br>`spx` | 无 | `RealityClientSettings` 的 `spiderX` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1670) |
| `show` | `布尔值` | 可选；默认 `false` | 无 | 无 | `RealityClientSettings` 的 `show` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1672) |
| `masterKeyLog` | `字符串（可选）` | 可选；默认 不设置 | `master_key_log`<br>`master-key-log` | 无 | `RealityClientSettings` 的 `masterKeyLog` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1679) |

## `NodeTransport`

`NodeTransport` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1723)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `kind` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeTransport` 的 `kind` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1725) |
| `host` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1727) |
| `path` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1729) |
| `service` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeTransport` 的 `service` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1731) |
| `xhttp` | `XhttpConfig（可选）` | 可选；默认不设置 | `xhttpSettings`<br>`xhttp-settings`<br>`splithttpSettings`<br>`splithttp-settings` | 无 | XHTTP/SplitHTTP 的一等强类型配置。`xhttpSettings` 与 `splithttpSettings` 用于直接接收 Xray 风格配置。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1742) |
| `grpcSettings` | `GrpcTransportSettings（可选）` | 可选；默认不设置 | `grpc`<br>`grpc_settings`<br>`grpc-settings` | 无 | Xray-compatible gRPC transport settings. Keeping these settings typed prevents misspelled fields from being silently discarded before the runtime plan is built. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1753) |

## `GrpcTransportSettings`

Complete Xray gRPC (`gun`) stream settings plus bounded local resources.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1759)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `authority` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `GrpcTransportSettings` 的 `authority` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1761) |
| `serviceName` | `字符串（可选）` | 可选；默认不设置 | `service_name`<br>`service-name` | 无 | `GrpcTransportSettings` 的 `serviceName` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1768) |
| `multiMode` | `布尔值（可选）` | 可选；默认不设置 | `multi_mode`<br>`multi-mode` | 无 | `GrpcTransportSettings` 的 `multiMode` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1775) |
| `idle_timeout` | `Compat时长（可选）` | 可选；默认不设置 | `idleTimeout`<br>`idle-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1782) |
| `health_check_timeout` | `Compat时长（可选）` | 可选；默认不设置 | `healthCheckTimeout`<br>`health-check-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1789) |
| `permit_without_stream` | `布尔值（可选）` | 可选；默认不设置 | `permitWithoutStream`<br>`permit-without-stream` | 无 | `GrpcTransportSettings` 的 `permit_without_stream` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1796) |
| `initial_windows_size` | `非负整数（可选）` | 可选；默认不设置 | `initialWindowSize`<br>`initial_window_size`<br>`initial-window-size`<br>`initial-windows-size` | 无 | `GrpcTransportSettings` 的 `initial_windows_size` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1805) |
| `user_agent` | `字符串（可选）` | 可选；默认不设置 | `userAgent`<br>`user-agent` | 无 | `GrpcTransportSettings` 的 `user_agent` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1812) |
| `max_message_size` | `非负整数（可选）` | 可选；默认不设置 | `maxMessageSize`<br>`max-message-size` | 无 | Local defensive limit for the encoded protobuf message; Xray/grpc-go defaults to four MiB. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1821) |
| `queue_capacity` | `非负整数（可选）` | 可选；默认不设置 | `queueCapacity`<br>`queue-capacity` | 无 | Number of protobuf messages allowed to wait for transport backpressure. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1829) |

## `NodeNetwork`

`NodeNetwork` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4231)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `udp` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeNetwork` 的 `udp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4233) |
| `tfo` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeNetwork` 的 `tfo` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4235) |
| `mptcp` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `NodeNetwork` 的 `mptcp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4237) |
| `mark` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `NodeNetwork` 的 `mark` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4239) |
| `ip_family` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `NodeNetwork` 的 `ip_family` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L4241) |

## 本分类枚举

### `FeedSpec`

`FeedSpec` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1321)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Url(String)` | 无 | 映射到 Rust 变体 `FeedSpec::Url`。 |
| `Detail(FeedDetail)` | 无 | 映射到 Rust 变体 `FeedSpec::Detail`。 |

### `FeedHeaderValue`

`FeedHeaderValue` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1398)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(String)` | 无 | 映射到 Rust 变体 `FeedHeaderValue::One`。 |
| `Many(Vec<String>)` | 无 | 映射到 Rust 变体 `FeedHeaderValue::Many`。 |

### `NodeSpec`

手动节点；支持纯 URI 字符串或结构化对象。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1542)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Uri(String)` | 无 | 映射到 Rust 变体 `NodeSpec::Uri`。 |
| `Detail(NodeDetail)` | 无 | 映射到 Rust 变体 `NodeSpec::Detail`。 |
