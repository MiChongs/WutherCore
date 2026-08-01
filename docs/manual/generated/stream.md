---
title: StreamSettings 与 socket 策略 完整字段索引
hide:
  - feedback
---

# StreamSettings 与 socket 策略 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

Xray 兼容 streamSettings、sockopt、Happy Eyeballs 与 FinalMask 配置。

全手册当前覆盖 **828 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `NodeStreamSettings`

`streamSettings` on an outbound node.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L17)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `network` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | Xray names raw TCP `tcp`; `raw` is accepted by the higher-level model. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L19) |
| `sockopt` | `OutboundSocketConfig（可选）` | 可选；默认不设置 | 无 | 无 | `NodeStreamSettings` 的 `sockopt` 参数。解析类型为 `OutboundSocketConfig（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L20) |
| `finalmask` | `FinalMaskConfig（可选）` | 可选；默认不设置 | 无 | 无 | `NodeStreamSettings` 的 `finalmask` 参数。解析类型为 `FinalMaskConfig（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L21) |

## `OutboundSocketConfig`

`OutboundSocketConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L26)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `mark` | `整数` | 可选；默认 `0` | 无 | 无 | `OutboundSocketConfig` 的 `mark` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L27) |
| `tcpFastOpen` | `BoolOrI32（可选）` | 可选；默认不设置 | 无 | `Bool(bool)`<br>`Int(i32)` | `OutboundSocketConfig` 的 `tcpFastOpen` 参数。解析类型为 `BoolOrI32（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L28) |
| `tproxy` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | Inbound-only in Xray. Registered so an imported Xray object is not rejected; it is deliberately ignored for outbound sockets. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L31) |
| `acceptProxyProtocol` | `布尔值` | 可选；默认 `false` | 无 | 无 | Inbound-only in Xray. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L33) |
| `domainStrategy` | `DomainStrategy` | 可选；默认 `AsIs` | 无 | `AsIs（默认）`<br>`UseIP`<br>`UseIPv4`<br>`UseIPv6`<br>`UseIPv4v6`<br>`UseIPv6v4`<br>`ForceIP`<br>`ForceIPv4`<br>`ForceIPv6`<br>`ForceIPv4v6`<br>`ForceIPv6v4` | `OutboundSocketConfig` 的 `domainStrategy` 参数。解析类型为 `DomainStrategy`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L34) |
| `dialerProxy` | `字符串` | 可选；默认空字符串 | 无 | 无 | `OutboundSocketConfig` 的 `dialerProxy` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L35) |
| `tcpKeepAliveInterval` | `整数` | 可选；默认 `0` | 无 | 无 | 周期性任务的执行间隔；时长字段接受 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L36) |
| `tcpKeepAliveIdle` | `整数` | 可选；默认 `0` | 无 | 无 | `OutboundSocketConfig` 的 `tcpKeepAliveIdle` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L37) |
| `tcpCongestion` | `字符串` | 可选；默认空字符串 | 无 | 无 | `OutboundSocketConfig` 的 `tcpCongestion` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L38) |
| `interface` | `字符串` | 可选；默认空字符串 | 无 | 无 | `OutboundSocketConfig` 的 `interface` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L39) |
| `v6only` | `布尔值` | 可选；默认 `false` | 无 | 无 | Inbound listener-only in Xray. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L41) |
| `tcpWindowClamp` | `整数` | 可选；默认 `0` | 无 | 无 | `OutboundSocketConfig` 的 `tcpWindowClamp` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L42) |
| `tcpUserTimeout` | `整数` | 可选；默认 `0` | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L43) |
| `tcpMaxSeg` | `整数` | 可选；默认 `0` | 无 | 无 | `OutboundSocketConfig` 的 `tcpMaxSeg` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L44) |
| `penetrate` | `布尔值` | 可选；默认 `false` | 无 | 无 | Freedom/inbound metadata option, not a socket dial option. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L46) |
| `tcpMptcp` | `布尔值` | 可选；默认 `false` | 无 | 无 | `OutboundSocketConfig` 的 `tcpMptcp` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L47) |
| `customSockopt` | `CustomSockoptConfig 列表` | 可选；默认空 | 无 | 无 | `OutboundSocketConfig` 的 `customSockopt` 参数。解析类型为 `CustomSockoptConfig 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L49) |
| `addressPortStrategy` | `AddressPortStrategy` | 可选；默认 `None` | 无 | `none（默认）`<br>`srvPortOnly`<br>`srvAddressOnly`<br>`srvPortAndAddress`<br>`txtPortOnly`<br>`txtAddressOnly`<br>`txtPortAndAddress` | `OutboundSocketConfig` 的 `addressPortStrategy` 参数。解析类型为 `AddressPortStrategy`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L50) |
| `happyEyeballs` | `HappyEyeballsConfig` | 可选；使用类型默认值 | 无 | 无 | `OutboundSocketConfig` 的 `happyEyeballs` 参数。解析类型为 `HappyEyeballsConfig`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L51) |
| `trustedXForwardedFor` | `字符串 列表` | 可选；默认空 | 无 | 无 | HTTP/gRPC inbound-only in Xray. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L53) |

## `CustomSockoptConfig`

`CustomSockoptConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L82)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `system` | `字符串` | 可选；默认空字符串 | 无 | 无 | Xray 26.7.11 accidentally spells this field `Syetem` internally but the JSON spelling remains `system`. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L85) |
| `network` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomSockoptConfig` 的 `network` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L86) |
| `level` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomSockoptConfig` 的 `level` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L87) |
| `opt` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomSockoptConfig` 的 `opt` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L88) |
| `value` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomSockoptConfig` 的 `value` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L89) |
| `type` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomSockoptConfig` 的 `type` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L91) |

## `HappyEyeballsConfig`

`HappyEyeballsConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L236)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `prioritizeIPv6` | `布尔值` | 可选；默认 `false` | 无 | 无 | `HappyEyeballsConfig` 的 `prioritizeIPv6` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L238) |
| `interleave` | `非负整数` | 可选；默认 `1` | 无 | 无 | `HappyEyeballsConfig` 的 `interleave` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L239) |
| `tryDelayMs` | `非负整数` | 可选；默认 `0` | 无 | 无 | `HappyEyeballsConfig` 的 `tryDelayMs` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L240) |
| `maxConcurrentTry` | `非负整数` | 可选；默认 `4` | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L241) |

## `FinalMaskConfig`

`FinalMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L257)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tcp` | `TcpMaskConfig 列表` | 可选；默认空 | 无 | `header-custom(HeaderCustomTcpConfig)`<br>`fragment(FragmentMaskConfig)`<br>`sudoku(SudokuMaskConfig)`<br>`xmc(XmcMaskConfig)` | `FinalMaskConfig` 的 `tcp` 参数。解析类型为 `TcpMaskConfig 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L258) |
| `udp` | `UdpMaskConfig 列表` | 可选；默认空 | 无 | `header-custom(HeaderCustomUdpConfig)`<br>`mkcp-legacy(MkcpLegacyMaskConfig)`<br>`noise(NoiseMaskConfig)`<br>`salamander(SalamanderMaskConfig)`<br>`sudoku(SudokuMaskConfig)`<br>`xdns(XdnsMaskConfig)`<br>`xicmp(XicmpMaskConfig)`<br>`realm(RealmMaskConfig)` | `FinalMaskConfig` 的 `udp` 参数。解析类型为 `UdpMaskConfig 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L259) |
| `quicParams` | `QuicParamsConfig（可选）` | 可选；默认不设置 | 无 | 无 | `FinalMaskConfig` 的 `quicParams` 参数。解析类型为 `QuicParamsConfig（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L260) |

## `I32Range`

Xray integer range: either `7` or a string such as `"3-9"`.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L362)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `left` | `整数` | 必填 | 无 | 无 | `I32Range` 的 `left` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L363) |
| `right` | `整数` | 必填 | 无 | 无 | `I32Range` 的 `right` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L364) |
| `from` | `整数` | 必填 | 无 | 无 | `I32Range` 的 `from` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L365) |
| `to` | `整数` | 必填 | 无 | 无 | `I32Range` 的 `to` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L366) |

## `FragmentMaskConfig`

`FragmentMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L464)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `packets` | `字符串` | 可选；默认空字符串 | 无 | 无 | `FragmentMaskConfig` 的 `packets` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L465) |
| `length` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `FragmentMaskConfig` 的 `length` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L466) |
| `delay` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `FragmentMaskConfig` 的 `delay` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L467) |
| `lengths` | `I32Range 列表` | 可选；默认空 | 无 | 无 | `FragmentMaskConfig` 的 `lengths` 参数。解析类型为 `I32Range 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L468) |
| `delays` | `I32Range 列表` | 可选；默认空 | 无 | 无 | `FragmentMaskConfig` 的 `delays` 参数。解析类型为 `I32Range 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L469) |
| `maxSplit` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L470) |

## `HeaderCustomTcpConfig`

`HeaderCustomTcpConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L475)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `clients` | `Vec<HeaderCustomTcpItem> 列表` | 可选；默认空 | 无 | 无 | `HeaderCustomTcpConfig` 的 `clients` 参数。解析类型为 `Vec<HeaderCustomTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L476) |
| `servers` | `Vec<HeaderCustomTcpItem> 列表` | 可选；默认空 | 无 | 无 | `HeaderCustomTcpConfig` 的 `servers` 参数。解析类型为 `Vec<HeaderCustomTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L477) |
| `errors` | `Vec<HeaderCustomTcpItem> 列表` | 可选；默认空 | 无 | 无 | `HeaderCustomTcpConfig` 的 `errors` 参数。解析类型为 `Vec<HeaderCustomTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L478) |

## `HeaderCustomTcpItem`

`HeaderCustomTcpItem` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L483)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `delay` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `HeaderCustomTcpItem` 的 `delay` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L484) |
| `rand` | `整数` | 可选；默认 `0` | 无 | 无 | `HeaderCustomTcpItem` 的 `rand` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L485) |
| `randRange` | `I32Range（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomTcpItem` 的 `randRange` 参数。解析类型为 `I32Range（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L486) |
| `capture` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomTcpItem` 的 `capture` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L487) |
| `type` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomTcpItem` 的 `type` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L489) |
| `reuse` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomTcpItem` 的 `reuse` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L490) |
| `transform` | `CustomTransform（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomTcpItem` 的 `transform` 参数。解析类型为 `CustomTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L491) |
| `packet` | `serde_json::Value（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomTcpItem` 的 `packet` 参数。解析类型为 `serde_json::Value（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L492) |

## `HeaderCustomUdpConfig`

`HeaderCustomUdpConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L497)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `mode` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomUdpConfig` 的 `mode` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L498) |
| `client` | `HeaderCustomUdpItem 列表` | 可选；默认空 | 无 | 无 | `HeaderCustomUdpConfig` 的 `client` 参数。解析类型为 `HeaderCustomUdpItem 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L499) |
| `server` | `HeaderCustomUdpItem 列表` | 可选；默认空 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L500) |

## `HeaderCustomUdpItem`

`HeaderCustomUdpItem` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L505)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `rand` | `整数` | 可选；默认 `0` | 无 | 无 | `HeaderCustomUdpItem` 的 `rand` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L506) |
| `randRange` | `I32Range（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomUdpItem` 的 `randRange` 参数。解析类型为 `I32Range（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L507) |
| `capture` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomUdpItem` 的 `capture` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L508) |
| `type` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomUdpItem` 的 `type` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L510) |
| `reuse` | `字符串` | 可选；默认空字符串 | 无 | 无 | `HeaderCustomUdpItem` 的 `reuse` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L511) |
| `transform` | `CustomTransform（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomUdpItem` 的 `transform` 参数。解析类型为 `CustomTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L512) |
| `packet` | `serde_json::Value（可选）` | 可选；默认不设置 | 无 | 无 | `HeaderCustomUdpItem` 的 `packet` 参数。解析类型为 `serde_json::Value（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L513) |

## `CustomTransform`

`CustomTransform` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L518)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `op` | `字符串` | 必填 | 无 | 无 | `CustomTransform` 的 `op` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L519) |
| `args` | `CustomTransformArg 列表` | 必填 | 无 | 无 | `CustomTransform` 的 `args` 参数。解析类型为 `CustomTransformArg 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L520) |

## `CustomTransformArg`

`CustomTransformArg` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L525)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `type` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomTransformArg` 的 `type` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L527) |
| `bytes` | `serde_json::Value（可选）` | 可选；默认不设置 | 无 | 无 | `CustomTransformArg` 的 `bytes` 参数。解析类型为 `serde_json::Value（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L528) |
| `u64` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `CustomTransformArg` 的 `u64` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L529) |
| `reuse` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomTransformArg` 的 `reuse` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L530) |
| `metadata` | `字符串` | 可选；默认空字符串 | 无 | 无 | `CustomTransformArg` 的 `metadata` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L531) |
| `transform` | `CustomTransform（可选）` | 可选；默认不设置 | 无 | 无 | `CustomTransformArg` 的 `transform` 参数。解析类型为 `CustomTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L532) |

## `SudokuMaskConfig`

`SudokuMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L537)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `password` | `字符串` | 可选；默认空字符串 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L538) |
| `ascii` | `字符串` | 可选；默认空字符串 | 无 | 无 | `SudokuMaskConfig` 的 `ascii` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L539) |
| `customTable` | `字符串` | 可选；默认空字符串 | 无 | 无 | `SudokuMaskConfig` 的 `customTable` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L540) |
| `custom_table` | `字符串` | 可选；默认空字符串 | 无 | 无 | `SudokuMaskConfig` 的 `custom_table` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L542) |
| `customTables` | `字符串 列表` | 可选；默认空 | 无 | 无 | `SudokuMaskConfig` 的 `customTables` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L543) |
| `custom_tables` | `字符串 列表` | 可选；默认空 | 无 | 无 | `SudokuMaskConfig` 的 `custom_tables` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L545) |
| `paddingMin` | `非负整数` | 可选；默认 `0` | 无 | 无 | `SudokuMaskConfig` 的 `paddingMin` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L546) |
| `padding_min` | `非负整数` | 可选；默认 `0` | 无 | 无 | `SudokuMaskConfig` 的 `padding_min` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L548) |
| `paddingMax` | `非负整数` | 可选；默认 `0` | 无 | 无 | `SudokuMaskConfig` 的 `paddingMax` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L549) |
| `padding_max` | `非负整数` | 可选；默认 `0` | 无 | 无 | `SudokuMaskConfig` 的 `padding_max` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L551) |

## `XmcMaskConfig`

`XmcMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L556)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `hostname` | `字符串` | 可选；默认空字符串 | 无 | 无 | `XmcMaskConfig` 的 `hostname` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L557) |
| `usernames` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XmcMaskConfig` 的 `usernames` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L558) |
| `password` | `字符串` | 可选；默认空字符串 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L559) |

## `NoiseMaskConfig`

`NoiseMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L564)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `reset` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `NoiseMaskConfig` 的 `reset` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L565) |
| `noise` | `NoiseItemConfig 列表` | 可选；默认空 | 无 | 无 | `NoiseMaskConfig` 的 `noise` 参数。解析类型为 `NoiseItemConfig 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L566) |

## `NoiseItemConfig`

`NoiseItemConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L571)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `rand` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `NoiseItemConfig` 的 `rand` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L572) |
| `randRange` | `I32Range（可选）` | 可选；默认不设置 | 无 | 无 | `NoiseItemConfig` 的 `randRange` 参数。解析类型为 `I32Range（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L573) |
| `type` | `字符串` | 可选；默认空字符串 | 无 | 无 | `NoiseItemConfig` 的 `type` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L575) |
| `packet` | `serde_json::Value（可选）` | 可选；默认不设置 | 无 | 无 | `NoiseItemConfig` 的 `packet` 参数。解析类型为 `serde_json::Value（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L576) |
| `delay` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `NoiseItemConfig` 的 `delay` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L577) |

## `MkcpLegacyMaskConfig`

`MkcpLegacyMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L582)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `header` | `字符串` | 可选；默认空字符串 | 无 | 无 | `MkcpLegacyMaskConfig` 的 `header` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L583) |
| `value` | `字符串` | 可选；默认空字符串 | 无 | 无 | `MkcpLegacyMaskConfig` 的 `value` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L584) |

## `SalamanderMaskConfig`

`SalamanderMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L589)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `password` | `字符串` | 可选；默认空字符串 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L590) |
| `packetSize` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `SalamanderMaskConfig` 的 `packetSize` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L591) |

## `XdnsMaskConfig`

`XdnsMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L596)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `domain` | `serde_json::Value（可选）` | 可选；默认不设置 | 无 | 无 | Removed by Xray 26.7.11. Kept only so validation can emit the precise migration error instead of treating it as an unknown field. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L599) |
| `domains` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XdnsMaskConfig` 的 `domains` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L600) |
| `resolvers` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XdnsMaskConfig` 的 `resolvers` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L601) |

## `XicmpMaskConfig`

`XicmpMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L606)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `dgram` | `布尔值` | 可选；默认 `false` | 无 | 无 | `XicmpMaskConfig` 的 `dgram` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L608) |
| `ips` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XicmpMaskConfig` 的 `ips` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L609) |

## `RealmMaskConfig`

`RealmMaskConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L614)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `url` | `字符串` | 可选；默认空字符串 | 无 | 无 | `RealmMaskConfig` 的 `url` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L615) |
| `stunServers` | `字符串 列表` | 可选；默认空 | 无 | 无 | `RealmMaskConfig` 的 `stunServers` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L616) |
| `tlsConfig` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | 无 | 无 | Complete Xray TLS object shared with XHTTP/downloadSettings. Realm uses the same validated executor, so advanced fields (certificates, pins, versions, curves, uTLS fingerprints and ECH) cannot diverge or be lost. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L620) |

## `QuicParamsConfig`

`QuicParamsConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L625)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `congestion` | `字符串` | 可选；默认空字符串 | 无 | 无 | `QuicParamsConfig` 的 `congestion` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L626) |
| `debug` | `布尔值` | 可选；默认 `false` | 无 | 无 | `QuicParamsConfig` 的 `debug` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L627) |
| `bbrProfile` | `字符串` | 可选；默认空字符串 | 无 | 无 | `QuicParamsConfig` 的 `bbrProfile` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L628) |
| `brutalUp` | `BandwidthValue` | 可选；默认 `Empty` | 无 | `Empty（默认）`<br>`Number(u64)`<br>`Text(String)` | `QuicParamsConfig` 的 `brutalUp` 参数。解析类型为 `BandwidthValue`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L629) |
| `brutalDown` | `BandwidthValue` | 可选；默认 `Empty` | 无 | `Empty（默认）`<br>`Number(u64)`<br>`Text(String)` | `QuicParamsConfig` 的 `brutalDown` 参数。解析类型为 `BandwidthValue`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L630) |
| `brutalDisableLossCompensation` | `布尔值` | 可选；默认 `false` | 无 | 无 | Hysteria 2 `bandwidth.disableLossCompensation`. This is local to the sender and therefore belongs beside the executable Brutal parameters, not in the HTTP authentication frame. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L634) |
| `udpHop` | `UdpHopConfig` | 可选；使用类型默认值 | 无 | 无 | `QuicParamsConfig` 的 `udpHop` 参数。解析类型为 `UdpHopConfig`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L635) |
| `initStreamReceiveWindow` | `非负整数` | 可选；默认 `0` | 无 | 无 | `QuicParamsConfig` 的 `initStreamReceiveWindow` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L636) |
| `maxStreamReceiveWindow` | `非负整数` | 可选；默认 `0` | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L637) |
| `initConnectionReceiveWindow` | `非负整数` | 可选；默认 `0` | 无 | 无 | `QuicParamsConfig` 的 `initConnectionReceiveWindow` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L638) |
| `maxConnectionReceiveWindow` | `非负整数` | 可选；默认 `0` | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L639) |
| `maxIdleTimeout` | `整数` | 可选；默认 `0` | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L640) |
| `keepAlivePeriod` | `整数` | 可选；默认 `0` | 无 | 无 | `QuicParamsConfig` 的 `keepAlivePeriod` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L641) |
| `disablePathMTUDiscovery` | `布尔值` | 可选；默认 `false` | 无 | 无 | `QuicParamsConfig` 的 `disablePathMTUDiscovery` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L643) |
| `maxIncomingStreams` | `整数` | 可选；默认 `0` | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L644) |

## `UdpHopConfig`

`UdpHopConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L649)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `ports` | `PortListValue` | 可选；默认 `Empty` | 无 | `Empty（默认）`<br>`Number(u32)`<br>`Text(String)` | `UdpHopConfig` 的 `ports` 参数。解析类型为 `PortListValue`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L650) |
| `interval` | `I32Range` | 可选；使用类型默认值 | 无 | 无 | `UdpHopConfig` 的 `interval` 参数。解析类型为 `I32Range`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L651) |

## 本分类枚举

### `BoolOrI32`

`BoolOrI32` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L75)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Bool(bool)` | 无 | 映射到 Rust 变体 `BoolOrI32::Bool`。 |
| `Int(i32)` | 无 | 映射到 Rust 变体 `BoolOrI32::Int`。 |

### `DomainStrategy`

`DomainStrategy` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L95)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `AsIs（默认）` | `asis` | 映射到 Rust 变体 `DomainStrategy::AsIs`。 |
| `UseIP` | `useip` | 映射到 Rust 变体 `DomainStrategy::UseIp`。 |
| `UseIPv4` | `useipv4` | 映射到 Rust 变体 `DomainStrategy::UseIpv4`。 |
| `UseIPv6` | `useipv6` | 映射到 Rust 变体 `DomainStrategy::UseIpv6`。 |
| `UseIPv4v6` | `useipv4v6` | 映射到 Rust 变体 `DomainStrategy::UseIpv4v6`。 |
| `UseIPv6v4` | `useipv6v4` | 映射到 Rust 变体 `DomainStrategy::UseIpv6v4`。 |
| `ForceIP` | `forceip` | 映射到 Rust 变体 `DomainStrategy::ForceIp`。 |
| `ForceIPv4` | `forceipv4` | 映射到 Rust 变体 `DomainStrategy::ForceIpv4`。 |
| `ForceIPv6` | `forceipv6` | 映射到 Rust 变体 `DomainStrategy::ForceIpv6`。 |
| `ForceIPv4v6` | `forceipv4v6` | 映射到 Rust 变体 `DomainStrategy::ForceIpv4v6`。 |
| `ForceIPv6v4` | `forceipv6v4` | 映射到 Rust 变体 `DomainStrategy::ForceIpv6v4`。 |

### `AddressPortStrategy`

`AddressPortStrategy` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L179)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `none（默认）` | `None` | 映射到 Rust 变体 `AddressPortStrategy::None`。 |
| `srvPortOnly` | `SrvPortOnly`<br>`srvportonly` | 映射到 Rust 变体 `AddressPortStrategy::SrvPortOnly`。 |
| `srvAddressOnly` | `SrvAddressOnly`<br>`srvaddressonly` | 映射到 Rust 变体 `AddressPortStrategy::SrvAddressOnly`。 |
| `srvPortAndAddress` | `SrvPortAndAddress`<br>`srvportandaddress` | 映射到 Rust 变体 `AddressPortStrategy::SrvPortAndAddress`。 |
| `txtPortOnly` | `TxtPortOnly`<br>`txtportonly` | 映射到 Rust 变体 `AddressPortStrategy::TxtPortOnly`。 |
| `txtAddressOnly` | `TxtAddressOnly`<br>`txtaddressonly` | 映射到 Rust 变体 `AddressPortStrategy::TxtAddressOnly`。 |
| `txtPortAndAddress` | `TxtPortAndAddress`<br>`txtportandaddress` | 映射到 Rust 变体 `AddressPortStrategy::TxtPortAndAddress`。 |

### `TcpMaskConfig`

`TcpMaskConfig` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L265)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `header-custom(HeaderCustomTcpConfig)` | 无 | 映射到 Rust 变体 `TcpMaskConfig::HeaderCustom`。 |
| `fragment(FragmentMaskConfig)` | 无 | 映射到 Rust 变体 `TcpMaskConfig::Fragment`。 |
| `sudoku(SudokuMaskConfig)` | 无 | 映射到 Rust 变体 `TcpMaskConfig::Sudoku`。 |
| `xmc(XmcMaskConfig)` | 无 | 映射到 Rust 变体 `TcpMaskConfig::Xmc`。 |

### `UdpMaskConfig`

`UdpMaskConfig` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L297)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `header-custom(HeaderCustomUdpConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::HeaderCustom`。 |
| `mkcp-legacy(MkcpLegacyMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::MkcpLegacy`。 |
| `noise(NoiseMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Noise`。 |
| `salamander(SalamanderMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Salamander`。 |
| `sudoku(SudokuMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Sudoku`。 |
| `xdns(XdnsMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Xdns`。 |
| `xicmp(XicmpMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Xicmp`。 |
| `realm(RealmMaskConfig)` | 无 | 映射到 Rust 变体 `UdpMaskConfig::Realm`。 |

### `PortListValue`

`PortListValue` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L656)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Empty（默认）` | 无 | 映射到 Rust 变体 `PortListValue::Empty`。 |
| `Number(u32)` | 无 | 映射到 Rust 变体 `PortListValue::Number`。 |
| `Text(String)` | 无 | 映射到 Rust 变体 `PortListValue::Text`。 |

### `BandwidthValue`

`BandwidthValue` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/stream_settings.rs#L665)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Empty（默认）` | 无 | 映射到 Rust 变体 `BandwidthValue::Empty`。 |
| `Number(u64)` | 无 | 映射到 Rust 变体 `BandwidthValue::Number`。 |
| `Text(String)` | 无 | 映射到 Rust 变体 `BandwidthValue::Text`。 |
