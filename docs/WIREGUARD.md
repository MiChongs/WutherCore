# WireGuard 配置

WutherCore 的 WireGuard 出站运行在用户态，不会创建系统网卡。它使用标准 NoiseIK 握手和 WireGuard 数据报，在隧道内提供真实 TCP、UDP、IPv4 与 IPv6 协议栈；同时公开可嵌入的服务端数据面 API。实现支持多 Peer 最长前缀路由、预共享密钥、持久保活、保留字节、远端 DNS、MTU 分片与重组、端点漫游、计数器重放防护和有界资源限制。

## 完整多 Peer 示例

密钥为 32 字节 WireGuard 原始密钥的标准或 URL-safe Base64，可带或不带填充。示例中的密钥仅用于展示结构，不能直接用于生产环境。

```yaml
version: 1
profile: desktop

nodes:
  - name: wg-full
    protocol: wireguard
    login:
      private_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
    params:
      local-address:
        - 10.20.0.2/32
        - fd20::2/128
      mtu: 1280
      network: tcp,udp
      remote-dns-resolve: true
      dns:
        - 10.20.0.53
        - fd20::53
      tcp-buffer-size: 262144
      udp-buffer-size: 262144
      max-tcp-sessions: 4096
      max-udp-sessions: 4096
      packet-queue: 1024
      workers: 4
      connect-timeout: 15s
      udp-timeout: 5m
      peers:
        - server: wg-a.example.com
          port: 51820
          public-key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
          pre-shared-key: AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
          allowed-ips:
            - 10.20.0.0/16
            - fd20::/48
          persistent-keepalive: 25
          reserved: [0, 0, 0]
        - server: 192.0.2.20
          port: 51820
          public-key: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
          allowed-ips:
            - 0.0.0.0/0
            - ::/0
          persistent-keepalive: 25
```

`peers` 模式下顶层不需要 `address`。单 Peer 兼容模式可以把端点写为节点的 `address: host:port`，并在 `params` 中使用 `public-key`、`pre-shared-key`、`allowed-ips`、`persistent-keepalive` 和 `reserved`；两种 Peer 表达不能混用。

## 字段与约束

| 字段 | 默认值 | 约束或语义 |
| --- | --- | --- |
| `login.private_key` / `params.private-key` | 必填 | 32 字节 Base64 私钥，禁止全零；两个位置同时出现且值不同会拒绝配置 |
| `local-address` / `address` | 必填 | 1–8 个 CIDR；IPv4、IPv6 均支持，必须为单播地址 |
| `peers` | 必填或使用单 Peer 字段 | 1–4096 个；公钥必须唯一且不能等于本机公钥 |
| `mtu` | `1420` | 576–65475；启用 IPv6 时至少 1280 |
| `network` | `tcp,udp` | `tcp`、`udp`、`tcp,udp`、`udp,tcp` 或 `both` |
| `dns` | 空 | 隧道内 DNS 服务器 IP，必须被某个 `allowed-ips` 覆盖 |
| `remote-dns-resolve` | `false` | 开启后域名目标通过隧道内 DNS 查询 A/AAAA；UDP 截断响应自动改用 TCP |
| `tcp-buffer-size` / `udp-buffer-size` | `262144` | 4096–16777216 字节 |
| `max-tcp-sessions` / `max-udp-sessions` | `4096` | 1–65535；超过上限时拒绝新会话 |
| `packet-queue` | `1024` | 16–65536；限制收发队列与重组资源，达到上限时施加背压或明确丢包 |
| `workers` | 可用 CPU 数（最多 64） | `0` 或未填写时自动选择，显式值为 1–64；按 Peer 固定分片，保持同一 Peer 的密码学状态顺序 |
| `connect-timeout` | `15s` | 大于 0 且不超过 300 秒 |
| `udp-timeout` | `5m` | UDP 会话空闲回收时间，5 秒–24 小时 |

每个 Peer 支持下列字段：

| 字段 | 默认值 | 约束或语义 |
| --- | --- | --- |
| `server` / `address` | 必填 | UDP 端点主机或 IP |
| `port` / `server-port` | 必填 | 1–65535 |
| `public-key` | 必填 | 32 字节 Base64 公钥 |
| `pre-shared-key` | 无 | 可选 32 字节 Base64 PSK |
| `allowed-ips` | 必填 | CIDR 列表；用于出站最长前缀选路和入站源地址校验，精确重复路由会被拒绝 |
| `persistent-keepalive` | `0`（禁用） | 秒数，`0` 表示禁用，最大 65535 |
| `reserved` | `[0,0,0]` | 三个 0–255 字节，按兼容实现的 UDP bind 层语义收发；多 Peer 模式可用顶层值作为未单独配置 Peer 的默认值 |

字段同时接受连字符和下划线别名。列表可由结构化 YAML 数组提供；订阅解析也会保留 Clash/Mihomo WireGuard 的 `allowed-ips`、`dns`、`reserved` 与 `peers` 结构。

## 运行语义

- 多 Peer 出站使用 `allowed-ips` 最长前缀匹配。同一精确网段不能分配给两个 Peer，避免依赖配置顺序产生歧义。
- 对端发来的解密数据还会校验源 IP 是否属于该 Peer 的 `allowed-ips`，错误来源会被丢弃。
- 客户端 IPv4 支持任意合法 MTU 下的分片与重组；IPv6 使用 RFC 8200 Fragment Header，并有有界、超时、拒绝重叠片段的重组器。服务端数据面按 MTU 分片出站包，入站则向调用者交付对端产生的原始 IP 包或分片。
- TCP 流支持读写、刷新和半关闭；UDP 关联保留目标语义并按空闲时间自动回收。
- 所有内部队列、会话数、缓存和 IPv6 重组项都有上限；关闭或对象析构会触发取消并释放后台任务。
- 远端 DNS 缓存遵循响应 TTL（限制为 1 秒至 1 小时），最多保存 1024 条记录。

## 服务端 API

`core-outbound` 导出 `WireGuardServer`、`WireGuardServerConfig`、`WireGuardServerPeerConfig`、`WireGuardReceivedPacket` 和客户端/服务端 Peer 统计类型。服务端绑定真实 UDP 套接字，使用公钥识别握手 Peer，按接收索引处理后续数据，接受认证后的端点漫游，并对入站源地址和出站目的地址执行 `allowed-ips` 路由校验。调用 `recv_packet` 取得解密 IP 数据包，调用 `send_packet` 按目的地址加密并发送；`close` 用于显式取消，析构也会释放任务。

`listen.wireguard` 会把这个服务端数据面注册成正式入站。认证后的裸 IP 包进入独立的用户态 netstack，再交给与 TUN 入站相同的 Runtime 路由，因此隧道内 TCP、UDP、IPv4 和 IPv6 都会执行节点选择、规则、DNS 和连接跟踪。每个监听器使用独立的 NAT、会话和取消域；启动过程中任意监听器绑定失败时，已启动的 WireGuard、capture、mesh、feed 和 runtime 都会显式回滚。

```yaml
listen:
  wireguard:
    - host: 0.0.0.0
      port: 51820
      private-key: BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=
      mtu: 1420
      packet-queue: 1024
      handshake-rate-limit: 1000
      peers:
        - public-key: BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=
          pre-shared-key: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
          allowed-ips:
            - 10.30.0.2/32
            - fd30::2/128
          persistent-keepalive: 25
          reserved: [0, 0, 0]
```

服务端监听字段：

| 字段 | 默认值 | 约束或语义 |
| --- | --- | --- |
| `host` | `0.0.0.0` | 必须是数值 IPv4 或 IPv6 地址 |
| `port` | 必填 | 1–65535；同一配置内不能重复绑定 |
| `private-key` | 必填 | 32 字节 Base64 私钥，禁止全零 |
| `peers` | 必填 | 1–256 个，公钥必须唯一 |
| `mtu` | `1420` | 576–65475；存在 IPv6 AllowedIPs 时至少 1280 |
| `packet-queue` | `1024` | 16–65536；限制认证明文包队列 |
| `handshake-rate-limit` | `1000` | 1–1000000 次/秒；在密码学处理前限制握手洪泛 |

服务端 Peer 的 `public-key`、`pre-shared-key`、`allowed-ips`、`persistent-keepalive` 和 `reserved` 与客户端 Peer 语义一致。`allowed-ips` 既用于接收源地址授权，也用于服务端回包的最长前缀选路；精确重复网段会在 `check` 阶段拒绝。字段同时接受连字符、下划线和文档中列出的 camelCase 别名，未知字段会直接报错。

本实现覆盖标准 WireGuard v1 用户态协议。`system-interface`（系统网卡模式）、`dialer-proxy`（通过另一代理拨 WireGuard 端点）和 `amnezia-wg-option`（AmneziaWG 扩展协议）不属于这一数据面，配置注册器会明确拒绝这些字段，不会静默忽略或降级。

## 互操作验证

仓库包含固定官方模块版本的 `wireguard-go` 互操作测试：Rust 服务端与官方 Go Peer 通过真实 UDP 完成握手、加密数据传输和明文 IP 往返。该测试需要 Go 工具链和首次下载依赖，因此默认标记为 ignored，可按下列方式显式执行：

```powershell
cargo test -p core-outbound --test wireguard_go_interop -- --ignored --nocapture
```
