---
title: 统一入口与服务端入站 完整字段索引
hide:
  - feedback
---

# 统一入口与服务端入站 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

Mixed、TUN、TPROXY、REDIRECT、Panel、Shadowsocks、WireGuard、Young、gRPC、REALITY 和 XHTTP 入站。

全手册当前覆盖 **828 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `Inbound`

`inbounds` 使用 `type` 判别入口，透明入口字段与 TUN 字段位于同一层。

| `type` | 专用字段 | 公共透明字段 |
| --- | --- | --- |
| `mixed` | `listen`、`listen_port`、`udp`、`users`、`streamSettings` | `tag`、`enabled` |
| `tun` | [TUN 全部字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`mtu`、`offload`、`exclude` |
| `tproxy` | [透明入口共用字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`offload`、`exclude` |
| `redirect` | [透明入口共用字段](capture-runtime.md#tuninboundoptions) | `tag`、`enabled`、`traffic`、`dns_mode`、`stack`、`offload`、`exclude` |
| `ebpf` | [Aya eBPF 字段](#ebpfinboundoptions) | `tag`、`enabled`、`redirect_address`、`bypass_rule_set`、UID 过滤、`dns_mode`、策略路由与 map 容量 |

每个 tag 必须唯一。当前运行时最多启用一个 Mixed，并且 tun、tproxy、redirect、ebpf 中最多启用一个宿主流量入口。

## `Listen`

`Listen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L305)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `local` | `ListenLocal（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Detail(ListenLocalDetail)` | `Listen` 的 `local` 参数。解析类型为 `ListenLocal（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L307) |
| `panel` | `PanelBind（可选）` | 可选；默认不设置 | 无 | `Off(bool)`<br>`Port(u16)`<br>`Address(String)` | `Listen` 的 `panel` 参数。解析类型为 `PanelBind（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L309) |
| `xhttp` | `XhttpListenSet（可选）` | 可选；默认不设置 | `split-http`<br>`split_http`<br>`splithttp` | 无 | XHTTP/SplitHTTP 服务端监听。既接受单个对象，也接受对象数组。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L317) |
| `shadowsocks` | `ShadowsocksListenSet（可选）` | 可选；默认不设置 | `ss` | `One(ShadowsocksListen)`<br>`Many(Vec<ShadowsocksListen>)` | Shadowsocks SIP003/SIP004/SIP022 服务端监听。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L320) |
| `share` | `Share（可选）` | 可选；默认不设置 | 无 | `false`<br>`home`<br>`all` | `Listen` 的 `share` 参数。解析类型为 `Share（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L322) |
| `auth` | `字符串 列表` | 可选；默认空 | 无 | 无 | `Listen` 的 `auth` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L324) |
| `reality` | `RealityListen 列表` | 可选；默认空 | `reality-inbounds`<br>`reality_inbounds` | 无 | REALITY 是一层入站流安全协议；每个条目独立监听并在认证后交给 `protocol` 指定的内层代理协议。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L328) |
| `wireguard` | `WireGuardListen 列表` | 可选；默认空 | `wireguard-inbounds`<br>`wireguard_inbounds` | 无 | WireGuard 服务端入站。每个条目绑定一个 UDP 端口，并把已认证对端的 IPv4/IPv6 包交给 WutherCore 的 TCP/UDP 路由运行时。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L332) |
| `young` | `YoungListen 列表` | 可选；默认空 | `young-inbounds`<br>`young_inbounds` | 无 | Young 原生入站。传输层是 Firefox 使用的 Mozilla Neqo HTTP/3/WebTransport。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L335) |
| `grpc` | `GrpcListen 列表` | 可选；默认空 | `grpc-inbounds`<br>`grpc_inbounds` | 无 | Xray gRPC (`gun`) 入站。每个条目独立监听，并把 Tun/TunMulti 双向流交给 `protocol` 指定的内层代理协议。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L339) |

## `ShadowsocksListen`

`ShadowsocksListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L360)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L362) |
| `address` | `字符串` | 可选；默认 `0.0.0.0` | `host` | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L364) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L365) |
| `method` | `字符串` | 必填 | 无 | 无 | `ShadowsocksListen` 的 `method` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L366) |
| `password` | `字符串` | 必填 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L367) |
| `mode` | `字符串` | 可选；默认 `tcp_and_udp` | 无 | 无 | `ShadowsocksListen` 的 `mode` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L369) |
| `plugin` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | SIP003 服务端插件可执行文件。插件监听公开地址，Shadowsocks 服务端本身只监听插件分配的回环地址。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L373) |
| `plugin-opts` | `字符串（可选）` | 可选；默认不设置 | `plugin_opts` | 无 | `ShadowsocksListen` 的 `plugin-opts` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L375) |
| `plugin-args` | `字符串 列表` | 可选；默认空 | `plugin_args` | 无 | `ShadowsocksListen` 的 `plugin-args` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L377) |
| `plugin-mode` | `字符串（可选）` | 可选；默认不设置 | `plugin_mode` | 无 | `ShadowsocksListen` 的 `plugin-mode` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L379) |
| `plugin-startup-timeout` | `时长` | 可选；默认 `10s` | `plugin_startup_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L386) |
| `users` | `ShadowsocksUser 列表` | 可选；默认空 | 无 | 无 | `ShadowsocksListen` 的 `users` 参数。解析类型为 `ShadowsocksUser 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L388) |
| `handshake-timeout` | `时长` | 可选；默认 `10s` | `handshake_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L395) |
| `udp-timeout` | `时长` | 可选；默认 `5m` | `udp_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L402) |
| `max-connections` | `非负整数` | 可选；默认 `1024` | `max_connections` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L408) |
| `max-udp-associations` | `非负整数` | 可选；默认 `4096` | `max_udp_associations` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L414) |
| `tag` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L416) |

## `ShadowsocksUser`

`ShadowsocksUser` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L421)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `name` | `字符串` | 必填 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L422) |
| `key` | `字符串` | 必填 | 无 | 无 | `ShadowsocksUser` 的 `key` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L423) |

## `WireGuardListen`

`WireGuardListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L469)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L471) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L472) |
| `privateKey` | `字符串` | 必填 | `private_key`<br>`private-key` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L474) |
| `peers` | `WireGuardListenPeer 列表` | 必填 | 无 | 无 | `WireGuardListen` 的 `peers` 参数。解析类型为 `WireGuardListenPeer 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L475) |
| `mtu` | `非负整数` | 可选；默认 `1420` | 无 | 无 | `WireGuardListen` 的 `mtu` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L477) |
| `packetQueue` | `非负整数` | 可选；默认 `1024` | `packet_queue`<br>`packet-queue` | 无 | `WireGuardListen` 的 `packetQueue` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L484) |
| `handshakeRateLimit` | `非负整数` | 可选；默认 `100` | `handshake_rate_limit`<br>`handshake-rate-limit` | 无 | `WireGuardListen` 的 `handshakeRateLimit` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L491) |

## `WireGuardListenPeer`

`WireGuardListenPeer` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L511)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `publicKey` | `字符串` | 必填 | `public_key`<br>`public-key` | 无 | `WireGuardListenPeer` 的 `publicKey` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L513) |
| `presharedKey` | `字符串（可选）` | 可选；默认不设置 | `preshared_key`<br>`preshared-key` | 无 | `WireGuardListenPeer` 的 `presharedKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L520) |
| `allowedIPs` | `字符串 列表` | 必填 | `allowed_ips`<br>`allowed-ips` | 无 | `WireGuardListenPeer` 的 `allowedIPs` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L522) |
| `reserved` | `0-255 整数 列表` | 可选；默认空 | 无 | 无 | `WireGuardListenPeer` 的 `reserved` 参数。解析类型为 `0-255 整数 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L524) |
| `persistentKeepalive` | `0-65535 整数（可选）` | 可选；默认不设置 | `persistent_keepalive`<br>`persistent-keepalive` | 无 | `WireGuardListenPeer` 的 `persistentKeepalive` 参数。解析类型为 `0-65535 整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L531) |

## `YoungListen`

`YoungListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L552)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L554) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L555) |
| `nssDatabase` | `字符串` | 必填 | `nss_database`<br>`nss-database`<br>`nss-db` | 无 | `YoungListen` 的 `nssDatabase` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L562) |
| `certificateNickname` | `字符串` | 必填 | `certificate_nickname`<br>`certificate-nickname`<br>`certificate` | 无 | `YoungListen` 的 `certificateNickname` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L569) |
| `authority` | `字符串` | 必填 | 无 | 无 | `YoungListen` 的 `authority` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L570) |
| `path` | `字符串` | 可选；默认 `/assets` | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L572) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `YoungListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L574) |
| `clockSkew` | `时长` | 可选；默认 `2m` | `clock_skew`<br>`clock-skew` | 无 | `YoungListen` 的 `clockSkew` 参数。解析类型为 `时长`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L582) |
| `idleTimeout` | `时长` | 可选；默认 `5m` | `idle_timeout`<br>`idle-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L590) |
| `maxStreams` | `非负整数` | 可选；默认 `1024` | `max_streams`<br>`max-streams` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L597) |
| `maxSessions` | `非负整数` | 可选；默认 `4096` | `max_sessions`<br>`max-sessions` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L604) |
| `maxFlowsPerSession` | `非负整数` | 可选；默认 `1024` | `max_flows_per_session`<br>`max-flows-per-session` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L611) |
| `paddingMin` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__m_i_n` | `padding_min`<br>`padding-min` | 无 | `YoungListen` 的 `paddingMin` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L618) |
| `paddingMax` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__m_a_x` | `padding_max`<br>`padding-max` | 无 | `YoungListen` 的 `paddingMax` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L625) |
| `paddingSchemeLength` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__s_c_h_e_m_e__l_e_n_g_t_h` | `padding_scheme_length`<br>`padding-scheme-length` | 无 | `YoungListen` 的 `paddingSchemeLength` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L632) |
| `decoyStatus` | `0-65535 整数` | 可选；默认 `404` | `decoy_status`<br>`decoy-status` | 无 | `YoungListen` 的 `decoyStatus` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L639) |
| `decoyBody` | `字符串` | 可选；默认 `<!doctype html><html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>` | `decoy_body`<br>`decoy-body` | 无 | `YoungListen` 的 `decoyBody` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L646) |

## `GrpcListen`

`GrpcListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L676)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L678) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L679) |
| `protocol` | `字符串` | 可选；默认 `vless` | 无 | 无 | `GrpcListen` 的 `protocol` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L681) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `GrpcListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L683) |
| `grpcSettings` | `GrpcTransportSettings` | 可选；使用类型默认值 | `grpc`<br>`grpc_settings`<br>`grpc-settings` | 无 | `GrpcListen` 的 `grpcSettings` 参数。解析类型为 `GrpcTransportSettings`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L691) |
| `security` | `GrpcListenSecurity` | 可选；默认 `None` | 无 | `none（默认）`<br>`tls`<br>`reality` | 底层安全载波。省略时是明文 h2c；TLS 与 REALITY 必须显式选择， 防止密钥配置存在但因拼写或遗漏而静默降级。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L695) |
| `tlsSettings` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | `tls_settings`<br>`tls-settings` | 无 | 与 Xray `tlsSettings` 同构的完整 TLS 对象。gRPC 会强制协商 h2， 其余证书、ECH、mTLS、版本、密码套件与曲线字段不做裁剪。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L704) |
| `requireClientCertificate` | `布尔值` | 可选；默认 `false` | `require_client_certificate`<br>`require-client-certificate` | 无 | `GrpcListen` 的 `requireClientCertificate` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L711) |
| `realitySettings` | `RealityListen（可选）` | 可选；默认不设置 | `reality_settings`<br>`reality-settings` | 无 | REALITY 服务端设置复用完整的监听模型。嵌套对象的 host、port、 protocol 与 users 由外层 gRPC 监听统一覆盖，避免重复配置冲突。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L720) |
| `handshakeTimeout` | `时长` | 可选；默认 `10s` | `handshake_timeout`<br>`handshake-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L728) |
| `maxMuxSessions` | `非负整数` | 可选；默认 `1024` | `max_mux_sessions`<br>`max-mux-sessions` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L735) |
| `maxConnections` | `非负整数` | 可选；默认 `4096` | `max_connections`<br>`max-connections` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L742) |
| `maxConcurrentStreams` | `非负整数` | 可选；默认 `1024` | `max_concurrent_streams`<br>`max-concurrent-streams` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L749) |
| `maxHeaderListSize` | `非负整数` | 可选；默认 `65536` | `max_header_list_size`<br>`max-header-list-size` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L756) |
| `trustedXForwardedFor` | `字符串 列表` | 可选；默认空 | `trusted_x_forwarded_for`<br>`trusted-x-forwarded-for` | 无 | 与 Xray 一致：这里存放“信任标记请求头”的名称；仅当请求中至少 存在一个标记头时，才采用 X-Forwarded-For 的第一个地址。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L765) |

## `RealityListen`

Xray REALITY 服务端监听配置。 字段名同时接受 Xray 的 camelCase 与本项目常用的 snake/kebab 写法； 未知字段一律拒绝，避免把密钥或限速字段拼错后静默降级。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L800)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L802) |
| `port` | `0-65535 整数` | 可选；默认 `0` | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L804) |
| `protocol` | `字符串` | 可选；默认 `vless` | 无 | 无 | `RealityListen` 的 `protocol` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L806) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `RealityListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L808) |
| `target` | `RealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `RealityListen` 的 `target` 参数。解析类型为 `RealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L810) |
| `dest` | `RealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `RealityListen` 的 `dest` 参数。解析类型为 `RealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L812) |
| `type` | `字符串（可选）` | 可选；默认不设置 | `target_type`<br>`target-type` | 无 | `RealityListen` 的 `type` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L814) |
| `show` | `布尔值` | 可选；默认 `false` | 无 | 无 | `RealityListen` 的 `show` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L816) |
| `masterKeyLog` | `字符串（可选）` | 可选；默认不设置 | `master_key_log`<br>`master-key-log` | 无 | `RealityListen` 的 `masterKeyLog` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L823) |
| `xver` | `0-255 整数` | 可选；默认 `0` | 无 | 无 | `RealityListen` 的 `xver` 参数。解析类型为 `0-255 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L825) |
| `serverNames` | `字符串 列表` | 可选；默认空 | `server_names`<br>`server-names` | 无 | `RealityListen` 的 `serverNames` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L832) |
| `privateKey` | `字符串` | 可选；默认空字符串 | `private_key`<br>`private-key` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L839) |
| `minClientVer` | `字符串（可选）` | 可选；默认不设置 | `min_client_ver`<br>`min-client-ver` | 无 | 对应范围或资源量的下限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L846) |
| `maxClientVer` | `字符串（可选）` | 可选；默认不设置 | `max_client_ver`<br>`max-client-ver` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L853) |
| `maxTimeDiff` | `非负整数` | 可选；默认 `0` | `max_time_diff`<br>`max-time-diff` | 无 | 与 Xray 一致，单位为毫秒；0 表示不限制时钟差。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L861) |
| `shortIds` | `字符串 列表` | 可选；默认空 | `short_ids`<br>`short-ids` | 无 | `RealityListen` 的 `shortIds` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L863) |
| `mldsa65Seed` | `字符串（可选）` | 可选；默认不设置 | `mldsa65_seed`<br>`mldsa65-seed` | 无 | `RealityListen` 的 `mldsa65Seed` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L870) |
| `limitFallbackUpload` | `RealityFallbackLimit` | 可选；使用类型默认值 | `limit_fallback_upload`<br>`limit-fallback-upload` | 无 | `RealityListen` 的 `limitFallbackUpload` 参数。解析类型为 `RealityFallbackLimit`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L877) |
| `limitFallbackDownload` | `RealityFallbackLimit` | 可选；使用类型默认值 | `limit_fallback_download`<br>`limit-fallback-download` | 无 | `RealityListen` 的 `limitFallbackDownload` 参数。解析类型为 `RealityFallbackLimit`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L884) |
| `limits` | `RealityResourceLimits` | 可选；使用类型默认值 | 无 | 无 | `RealityListen` 的 `limits` 参数。解析类型为 `RealityResourceLimits`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L886) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | Socket policy and TCP FinalMask applied before the REALITY ClientHello. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L889) |

## `RealityFallbackLimit`

`RealityFallbackLimit` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L942)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `afterBytes` | `非负整数` | 可选；默认 `0` | `after_bytes`<br>`after-bytes` | 无 | `RealityFallbackLimit` 的 `afterBytes` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L949) |
| `bytesPerSec` | `非负整数` | 可选；默认 `0` | `bytes_per_sec`<br>`bytes-per-sec` | 无 | `RealityFallbackLimit` 的 `bytesPerSec` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L956) |
| `burstBytesPerSec` | `非负整数` | 可选；默认 `0` | `burst_bytes_per_sec`<br>`burst-bytes-per-sec` | 无 | `RealityFallbackLimit` 的 `burstBytesPerSec` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L963) |

## `RealityResourceLimits`

`RealityResourceLimits` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L968)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `handshake_timeout` | `时长` | 可选；默认 `10s` | `handshake-timeout`<br>`handshakeTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L975) |
| `target_handshake_timeout` | `时长` | 可选；默认 `5s` | `target-handshake-timeout`<br>`targetHandshakeTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L982) |
| `idle_timeout` | `时长` | 可选；默认 `5m` | `idle-timeout`<br>`idleTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L989) |
| `max_client_hello_records` | `非负整数` | 可选；默认 `16` | `max-client-hello-records`<br>`maxClientHelloRecords` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L995) |
| `max_client_hello_record_payload` | `非负整数` | 可选；默认 `16640` | `max-client-hello-record-payload`<br>`maxClientHelloRecordPayload` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1001) |
| `max_client_hello_bytes` | `非负整数` | 可选；默认 `u16::MAX as usize` | `max-client-hello-bytes`<br>`maxClientHelloBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1007) |
| `max_client_hello_wire_bytes` | `非负整数` | 可选；默认 `98304` | `max-client-hello-wire-bytes`<br>`maxClientHelloWireBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1013) |
| `max_target_records` | `非负整数` | 可选；默认 `12` | `max-target-records`<br>`maxTargetRecords` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1019) |
| `max_target_handshake_bytes` | `非负整数` | 可选；默认 `98304` | `max-target-handshake-bytes`<br>`maxTargetHandshakeBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1025) |
| `application_buffer_bytes` | `非负整数` | 可选；默认 `262144` | `application-buffer-bytes`<br>`applicationBufferBytes` | 无 | `RealityResourceLimits` 的 `application_buffer_bytes` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1031) |
| `max_concurrent_handshakes` | `非负整数` | 可选；默认 `1024` | `max-concurrent-handshakes`<br>`maxConcurrentHandshakes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1037) |

## `ListenLocalDetail`

`ListenLocalDetail` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1068)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tag` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1070) |
| `host` | `字符串` | 可选；默认 `127.0.0.1` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1072) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1073) |
| `auth` | `字符串 列表` | 可选；默认空 | 无 | 无 | `ListenLocalDetail` 的 `auth` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1075) |
| `udp` | `布尔值` | 可选；默认 `true` | 无 | 无 | `ListenLocalDetail` 的 `udp` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1077) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | Xray-compatible listener socket policy and server-side final masks. Both spellings are accepted so native YAML and imported Xray objects share one typed configuration path. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1082) |

## `MixedInboundOptions`

`MixedInboundOptions` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5418)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tag` | `字符串` | 可选；由 `default_mixed_inbound_tag()` 决定 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5420) |
| `enabled` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5422) |
| `listen` | `字符串` | 可选；默认 `127.0.0.1` | `host`<br>`bind` | 无 | `MixedInboundOptions` 的 `listen` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5424) |
| `listen_port` | `0-65535 整数` | 必填 | `listen-port`<br>`port` | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5426) |
| `udp` | `布尔值` | 可选；默认 `true` | 无 | 无 | `MixedInboundOptions` 的 `udp` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5428) |
| `users` | `InboundUser 列表` | 可选；默认空 | 无 | 无 | `MixedInboundOptions` 的 `users` 参数。解析类型为 `InboundUser 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5431) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | `MixedInboundOptions` 的 `streamSettings` 参数。解析类型为 `crate::NodeStreamSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5433) |

## `InboundUser`

`InboundUser` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5442)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `username` | `字符串` | 必填 | `user` | 无 | `InboundUser` 的 `username` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5444) |
| `password` | `字符串` | 必填 | `pass` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5446) |

## `EbpfInboundOptions`

Aya eBPF inbound. The cgroup programs select local TCP and UDP sockets by UID and destination, TC ingress selects hotspot and forwarded-device traffic. Socket assignment prefers `sk_lookup` and automatically falls back to loopback TC ingress on Android kernels that reject netns BPF links. Neither path requires iptables, nftables, TPROXY, or destination NAT.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5472)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tag` | `字符串` | 可选；默认 `ebpf-in` | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5474) |
| `enabled` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5476) |
| `redirect_address` | `字符串 列表` | 可选；默认 `vec!["127.128.0.0/9".into(), "2001:db8:2030::/64".into()]` | 无 | 无 | `EbpfInboundOptions` 的 `redirect_address` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5479) |
| `bypass_rule_set` | `字符串 列表` | 可选；默认空 | 无 | 无 | `EbpfInboundOptions` 的 `bypass_rule_set` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5482) |
| `include_uid` | `非负整数 列表` | 可选；默认空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5485) |
| `include_uid_range` | `字符串 列表` | 可选；默认空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5488) |
| `exclude_uid` | `非负整数 列表` | 可选；默认空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5491) |
| `exclude_uid_range` | `字符串 列表` | 可选；默认空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5494) |
| `cgroup_path` | `PathBuf` | 可选；默认 `PathBuf::from("/sys/fs/cgroup")` | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5496) |
| `route_table` | `非负整数` | 可选；由 `default_ebpf_route_table()` 决定 | 无 | 无 | `EbpfInboundOptions` 的 `route_table` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5498) |
| `rule_priority` | `非负整数` | 可选；由 `default_ebpf_rule_priority()` 决定 | 无 | 无 | `EbpfInboundOptions` 的 `rule_priority` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5500) |
| `mark` | `非负整数` | 可选；由 `default_ebpf_mark()` 决定 | 无 | 无 | `EbpfInboundOptions` 的 `mark` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5502) |
| `map_capacity` | `非负整数` | 可选；由 `default_ebpf_map_capacity()` 决定 | 无 | 无 | `EbpfInboundOptions` 的 `map_capacity` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5504) |
| `capabilities` | `EbpfCapabilityOptions` | 可选；使用类型默认值 | 无 | 无 | Linux capability handling for the eBPF data plane. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5507) |
| `shared_network` | `EbpfSharedNetworkOptions` | 可选；使用类型默认值 | `shared-network`<br>`hotspot`<br>`tethering` | 无 | Optional hotspot, tethering, bridge, and router-forwarding data path. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5516) |
| `dns_mode` | `CaptureResolver` | 可选；默认 `hijack` | `dns-mode` | 无 | `EbpfInboundOptions` 的 `dns_mode` 参数。解析类型为 `CaptureResolver`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5522) |

## `EbpfCapabilityOptions`

Capability policy used while loading and maintaining the eBPF inbound. Linux capabilities are thread-local. The runtime therefore checks every privileged attach/reconcile path instead of assuming that uid 0 implies a complete capability set.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5532)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `auto_raise` | `布尔值` | 可选；默认 `true` | `auto-raise` | 无 | Promote a required capability from the permitted set into the effective set on the current worker thread before a privileged operation. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5536) |
| `allow_sys_admin_fallback` | `布尔值` | 可选；默认 `true` | `allow-sys-admin-fallback` | 无 | Accept CAP_SYS_ADMIN as the kernel-compatible BPF authority when CAP_BPF is unavailable. Required by kernels predating CAP_BPF and some Android vendor backports. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5545) |

## `EbpfSharedNetworkOptions`

Forwarded-device capture for Linux routers and Android hotspot/tethering. The TC ingress program is attached only to interfaces matched by `include_interface` and not matched by `exclude_interface`. Source filters are evaluated before a packet receives the eBPF inbound mark.

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5565)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `false` | 无 | 无 | Enable TC ingress capture for forwarded devices. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5568) |
| `include_interface` | `字符串 列表` | 可选；默认 `[ "ap*", "swlan*", "wlan*", "rndis*", "usb*", "bt-pan*", "bnep*", "br*", "eth*", "en*", ] .into_iter() .map(str::to_owned) .collect()` | 无 | 无 | Interface-name glob patterns eligible for dynamic TC attachment. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5572) |
| `exclude_interface` | `字符串 列表` | 可选；默认 `[ "lo", "tun*", "tap*", "wg*", "rpktun*", "docker*", "veth*", "rmnet*", "ccmni*", "wwan*", ] .into_iter() .map(str::to_owned) .collect()` | 无 | 无 | Interface-name glob patterns removed from the eligible set. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5576) |
| `include_source_address` | `字符串 列表` | 可选；默认 `vec!["0.0.0.0/0".into(), "::/0".into()]` | 无 | 无 | Source CIDRs accepted from selected downstream interfaces. An empty list accepts every source address. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5582) |
| `exclude_source_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | Source CIDRs bypassed before the include set is evaluated. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5586) |
| `interface_refresh_interval` | `时长` | 可选；由 `default_ebpf_interface_refresh_interval()` 决定 | 无 | 无 | Polling interval used to attach newly created hotspot interfaces and detach interfaces removed by Android or Linux network management. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5593) |
| `packet_stats` | `布尔值` | 可选；默认 `false` | 无 | 无 | Collect per-packet TC diagnostics for shared-network traffic. Disabled by default because updating a BPF counter for every forwarded packet adds measurable CPU cost on mobile hotspots. Flow-level lookup and local socket counters remain available when this is disabled. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5600) |
| `tc_priority` | `0-65535 整数` | 可选；由 `default_ebpf_tc_priority()` 决定 | 无 | 无 | Legacy clsact filter priority. Lower values run before tethering offload. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5603) |

## 本分类枚举

### `ShadowsocksListenSet`

`ShadowsocksListenSet` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L344)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(ShadowsocksListen)` | 无 | 映射到 Rust 变体 `ShadowsocksListenSet::One`。 |
| `Many(Vec<ShadowsocksListen>)` | 无 | 映射到 Rust 变体 `ShadowsocksListenSet::Many`。 |

### `GrpcListenSecurity`

完整的 Xray gRPC 服务端监听配置。 `grpcSettings` 沿用 Xray 字段名；本地资源上限单独注册，所有未知字段 均拒绝，避免拼写错误导致无界队列或静默使用默认值。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L460)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `none（默认）` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::None`。 |
| `tls` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::Tls`。 |
| `reality` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::Reality`。 |

### `RealityTarget`

`RealityTarget` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L926)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Port(u16)` | 无 | 映射到 Rust 变体 `RealityTarget::Port`。 |
| `Address(String)` | 无 | 映射到 Rust 变体 `RealityTarget::Address`。 |

### `ListenLocal`

listen.local 支持端口写法 / 完整对象。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1061)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Port(u16)` | 无 | 映射到 Rust 变体 `ListenLocal::Port`。 |
| `Detail(ListenLocalDetail)` | 无 | 映射到 Rust 变体 `ListenLocal::Detail`。 |

### `PanelBind`

`PanelBind` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1296)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Off(bool)` | 无 | 映射到 Rust 变体 `PanelBind::Off`。 |
| `Port(u16)` | 无 | 映射到 Rust 变体 `PanelBind::Port`。 |
| `Address(String)` | 无 | 映射到 Rust 变体 `PanelBind::Address`。 |

### `Share`

`Share` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1304)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `false` | 无 | 映射到 Rust 变体 `Share::False`。 |
| `home` | 无 | 映射到 Rust 变体 `Share::Home`。 |
| `all` | 无 | 映射到 Rust 变体 `Share::All`。 |

### `ShareValue`

`ShareValue` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1312)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Bool(bool)` | 无 | 映射到 Rust 变体 `ShareValue::Bool`。 |
| `Tag(Share)` | 无 | 映射到 Rust 变体 `ShareValue::Tag`。 |
