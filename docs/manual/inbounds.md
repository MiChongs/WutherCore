---
title: 监听与入站
description: Mixed、Panel 和所有服务端协议入站的配置语义
---

# 监听与入站

`inbounds` 是本地流量入口的统一配置。每个条目使用 `type` 选择数据面，使用
`tag` 提供稳定身份。路由规则、连接表、日志和 Clash API 都使用这个 tag。

当前统一入口支持 `mixed`、`tun`、`tproxy`、`redirect` 和 `ebpf`。管理面板及现有服务端
协议仍放在 `listen` 中。旧的 `listen.local` 和 `capture` 可以继续加载，但不能与
等价的 `inbounds` 条目同时声明。

完整字段、别名和枚举见[监听与入站字段索引](generated/inbounds.md)。

## 统一入口

```yaml
inbounds:
  - type: mixed
    tag: 本地代理
    listen: 127.0.0.1
    listen_port: 7890
    udp: true
    users:
      - username: alice
        password: replace-me

  - type: tun
    tag: 系统接管
    interface_name: rpktun0
    address:
      - 198.18.0.1/15
      - fdfe:dcba:9876::1/126
    stack: mixed
    dns_mode: hijack
    mtu: 1500
    auto_route: true
    strict_route: false
```

每个 tag 必须非空、唯一且不超过 128 字节。当前运行时最多启用一个 Mixed 入口，
并且 `tun`、`tproxy`、`redirect`、`ebpf` 四种宿主流量数据面合计只能启用一个。这样可以避免
多个入口同时争用系统路由、防火墙、TUN 设备和 DNS 劫持资源。

列表字段接受单值和数组两种写法。`address: 198.18.0.1/15` 与只包含一个元素的
数组等价，`explain` 会统一输出数组。

## `listen` 保留字段

| 字段 | 形态 | 用途 |
| --- | --- | --- |
| `panel` | 端口或地址 | 原生 API 与 Clash 兼容 API 的监听地址 |
| `xhttp` | 对象或对象列表 | XHTTP 和 SplitHTTP 服务端入站 |
| `shadowsocks` | 对象或对象列表 | Shadowsocks SIP003、SIP004 和 SIP022 服务端 |
| `share` | 布尔值、`home` 或 `all` | 控制 Profile 生成的本地监听是否对外共享 |
| `auth` | 字符串列表 | `user:password` 形式的全局 Mixed 认证 |
| `reality` | 对象列表 | REALITY 安全层和内层协议 |
| `wireguard` | 对象列表 | WireGuard UDP 服务端 |
| `young` | 对象列表 | Young Neqo HTTP/3 和 WebTransport 服务端 |
| `grpc` | 对象列表 | Xray gRPC 服务端 |

## Mixed 本地入口

```yaml
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890
    udp: true
    users:
      username: alice
      password: replace-me
```

`listen` 默认 `127.0.0.1`，`udp` 默认开启。`users` 可以写一个对象或对象数组。
用户名必须非空、唯一且不能包含冒号，密码不能为空。

如果绑定非回环地址，应同时设置认证、防火墙和明确的共享范围。不要把开放代理端口
直接暴露到互联网。

`streamSettings` 可为监听 socket 设置 Xray 兼容策略。字段见
[StreamSettings 字段索引](generated/stream.md)。

## 透明入口

`tun`、`tproxy` 和 `redirect` 使用同一套扁平字段，不再把参数拆到
`capture.tun`。三种类型分别映射虚拟网卡、Linux 或 Android root TPROXY、
Linux 或 Android root TCP REDIRECT。

完整的地址、路由、应用过滤、平台能力和迁移示例见[系统接管](capture.md)。

## Aya eBPF 入口

`ebpf` 是 `core-inbound` 自带的 Linux 和 Android root 入站，不经过旧的
capture supervisor，也不安装 iptables、nftables、TPROXY 或 REDIRECT 规则。
它使用 cgroup socket address 程序选择本机进程流量，使用策略路由把选中的
socket 送回本机协议栈，再由 `sk_lookup` 分配给核心持有的 TCP 和 UDP socket。
Android 内核拒绝 netns BPF link 时会自动切换到 loopback TC ingress 的
`bpf_sk_assign`，无需修改配置。
启用 `shared_network` 时，它还会把 TC ingress 挂到热点和共享网络的下游接口，
接管转发设备的 TCP、UDP、DNS 与 QUIC 流量。

```yaml
inbounds:
  - type: ebpf
    tag: ebpf-in
    redirect_address:
      - 127.128.0.0/9
      - 2001:db8:2030::/64
    bypass_rule_set: [geoip-cn]
    include_uid: []
    include_uid_range: []
    exclude_uid: []
    exclude_uid_range: []
    cgroup_path: /sys/fs/cgroup
    route_table: 721
    rule_priority: 8999
    mark: 721
    map_capacity: 65536
    capabilities:
      auto_raise: true
      allow_sys_admin_fallback: true
    shared_network:
      enabled: true
      include_interface: [ap*, wlan*, rndis*, usb*, bt-pan*, br*, eth*, en*]
      exclude_interface: [lo, tun*, wg*, rpktun*, docker*, veth*, rmnet*, ccmni*]
      include_source_address: [0.0.0.0/0, "::/0"]
      exclude_source_address: []
      interface_refresh_interval: 3s
      packet_stats: false
      tc_priority: 1
    dns_mode: hijack
```

排除 UID 的优先级高于包含 UID。包含列表和包含区间都为空时接管所有 UID。
`bypass_rule_set` 必须引用已经加载并能提取目标 IP 前缀的规则集。规则集刷新
先写入备用 LPM map，全部成功后再切换活动 map，因此运行流量不会看到半份规则。
`dns_mode: hijack` 同时接管 UDP 和 TCP 53，并交给核心 DNS 服务处理。
共享接口按 glob 动态发现，Android 开关热点或 USB 共享后无需重启核心。
默认的全地址源规则使用内核快速路径，不执行源地址 LPM 查询。逐包 TC 诊断统计
默认关闭，避免热点大流量时为每个包写统计 Map；需要排障时可设置
`packet_stats: true`。

该入口要求 `with_ebpf` 组件, effective `CAP_NET_ADMIN` 加 `CAP_BPF`, 或使用
`CAP_SYS_ADMIN` 的旧内核兼容路径, 同时要求 cgroup v2,
以及 cgroup sock_addr。socket 分配可以使用 sk_lookup，也可以使用 TC ingress
兼容路径。完整部署, 字段语义和诊断方法见[Aya eBPF 入站](ebpf-inbound.md)。

## 管理面板监听

```yaml
listen:
  panel: 127.0.0.1:9090

ui:
  on: true
  secret: "replace-with-random-token"
```

`panel` 接受：

- 整数端口，主机地址由分享策略和 Profile 决定。
- `host:port` 字符串。

当面板可被非本机访问时，`ui.secret` 是硬性要求。API 功能还要求编译组件
`with_api`。

## 共享策略

| 值 | 行为 |
| --- | --- |
| `false` | 仅本机使用 |
| `true` | 兼容布尔短写，按允许共享处理 |
| `home` | 面向家庭或局域网地址 |
| `all` | 允许绑定所有接口 |

共享策略影响自动选择的监听地址，不替代认证和防火墙。`router` Profile 默认
`home`，因此必须显式配置 `ui.secret`。

## Shadowsocks 入站

要求组件 `with_shadowsocks`。

```yaml
listen:
  shadowsocks:
    address: 0.0.0.0
    port: 8388
    method: aes-256-gcm
    password: "replace-me"
    mode: tcp_and_udp
    handshake-timeout: 10s
    udp-timeout: 5m
    max-connections: 4096
    max-udp-associations: 4096
```

关键规则：

- `port`、`method` 和 `password` 必须提供。
- `users` 用于多用户配置，每项包含 `name` 和 `key`。
- `plugin` 启用 SIP003 服务端插件。插件负责公开监听，内核改为监听插件分配的
  回环地址。
- `plugin-opts` 是插件协议选项，`plugin-args` 是额外进程参数，
  `plugin-startup-timeout` 限制启动等待时间。
- `mode` 决定 TCP、UDP 或两者。资源上限分别限制连接和 UDP association。

密码、用户密钥和插件命令行都可能进入进程环境或诊断输出，部署时按敏感信息处理。

## WireGuard 入站

要求组件 `with_wireguard`。

```yaml
listen:
  wireguard:
    - host: 0.0.0.0
      port: 51820
      privateKey: "server-private-key"
      mtu: 1420
      packetQueue: 1024
      handshakeRateLimit: 1000
      peers:
        - publicKey: "peer-public-key"
          allowedIPs: ["10.20.0.2/32"]
          persistentKeepalive: 25
```

关键规则：

- 服务端 `privateKey` 和每个 Peer 的 `publicKey` 必填。
- `allowedIPs` 同时参与 Peer 识别和包路由，Peer 之间不能产生不明确的归属。
- `presharedKey` 可选，必须与对端一致。
- `reserved` 是三个字节的兼容字段。
- `persistentKeepalive` 单位为秒，适合 NAT 后的 Peer。
- `packetQueue` 限制已认证明文包的排队量。
- `handshakeRateLimit` 在昂贵的密码学处理前限制握手洪泛。

出站字段和协议约束见[WireGuard 指南](../WIREGUARD.md)。

## Young 入站

要求组件 `with_young`。Young 使用 Mozilla Neqo 和 NSS 证书数据库。

```yaml
listen:
  young:
    - host: 0.0.0.0
      port: 443
      nssDatabase: sql:data/nss
      certificateNickname: wuthercore
      authority: example.com
      path: /young
      users: ["replace-me"]
```

`nssDatabase`、`certificateNickname`、`authority` 和 `port` 必填。`path` 是
WebTransport 路径。`clockSkew` 控制认证时间容差。`idleTimeout`、`maxStreams`、
`maxSessions` 和 `maxFlowsPerSession` 限制连接资源。padding 字段必须满足最小值
不大于最大值，Scheme 长度和 decoy 响应由协议实现校验。

协议和证书准备见[Young 指南](../YOUNG_PROTOCOL.md)。

## gRPC 入站

要求组件 `with_grpc`。

```yaml
listen:
  grpc:
    - host: 0.0.0.0
      port: 8443
      protocol: vless
      users: ["00000000-0000-0000-0000-000000000001"]
      security: tls
      grpcSettings:
        serviceName: TunService
        multiMode: false
      tlsSettings:
        certificates:
          - certificateFile: data/tls/fullchain.pem
            keyFile: data/tls/private.key
```

| 字段组 | 说明 |
| --- | --- |
| `protocol`、`users` | 认证后交给内层协议处理 |
| `grpcSettings` | Service name、Tun/TunMulti 模式和 gRPC 元数据 |
| `security` | `none`、`tls` 或 `reality`，必须显式选择安全载波 |
| `tlsSettings` | 完整 TLS、证书、ECH、mTLS、版本和密码套件配置 |
| `realitySettings` | 复用 REALITY 服务端模型，外层覆盖 host、port、protocol、users |
| 资源上限 | 限制连接、Mux session、并发 stream 和 Header List 大小 |
| `trustedXForwardedFor` | 配置信任标记请求头，满足标记后才采用首个 X-Forwarded-For |

存在 TLS 或 REALITY 密钥但 `security` 未选择对应模式时不会静默启用，配置应通过
`check` 明确确认。

## REALITY 入站

要求组件 `with_reality`。

```yaml
listen:
  reality:
    - host: 0.0.0.0
      port: 443
      protocol: vless
      users: ["00000000-0000-0000-0000-000000000001"]
      target: example.com:443
      serverNames: [example.com]
      privateKey: "replace-me"
      shortIds: ["0123456789abcdef"]
      maxTimeDiff: 60000
```

字段分为六组：

1. `host`、`port` 决定监听。
2. `protocol`、`users` 决定认证后的内层协议。
3. `target`、`dest`、`type` 决定伪装目标和兼容目标类型。
4. `serverNames`、`privateKey`、`shortIds` 和 `mldsa65Seed` 决定认证。
5. `minClientVer`、`maxClientVer`、`maxTimeDiff` 决定客户端版本和时间限制。
6. fallback 限速、资源上限和 `streamSettings` 控制抗滥用与底层 socket。

未知字段会被拒绝，避免密钥或限制字段拼错后降级。`maxTimeDiff` 单位为毫秒，
`0` 表示不限制时钟差。私钥和主密钥日志路径属于敏感配置。

## XHTTP 入站

要求组件 `with_xhttp`。`listen.xhttp` 接受单对象或对象列表。监听层包含
`enabled`、host、port、users、TLS、REALITY、CORS、资源限制和完整
`XhttpConfig`。

XHTTP 的字段数量较多，单独阅读：

- [XHTTP 与 StreamSettings](xhttp-stream.md)
- [XHTTP 字段索引](generated/xhttp.md)
- [XHTTP 协议指南](../XHTTP.md)

## 端口和资源冲突

`check` 会在运行计划阶段验证已知的重复监听和不合法端口。启动时仍可能遇到：

- 端口已被其它进程占用。
- 当前用户没有低端口绑定权限。
- IPv4 和 IPv6 dual-stack 行为造成地址冲突。
- 插件先占用或释放端口失败。
- TLS、NSS 或私钥文件无法读取。

生产部署应在目标系统上执行一次前台启动和停止，确认监听创建与资源回收都成功。
