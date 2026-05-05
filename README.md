# WutherCore

一个用 Rust 写的、独立运行的代理内核。读 YAML 配置，拉订阅，连出站节点，按规则分流；可以用 HTTP / SOCKS5 监听端口，也可以接管整机流量做透明代理；跑起来之后通过 HTTP API 控制和观测。

它替换的是"代理客户端 + 自选节点逻辑 + 路由规则"这一整层 —— 路由器、桌面、安卓 root/VpnService 都跑得动。无 GUI，单二进制，无云控、无登录、无遥测。控制面板（如 yacd / metacubexd）通过兼容 API 接入，可选。

[![rust](https://img.shields.io/badge/rust-1.85%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![edition](https://img.shields.io/badge/edition-2024-000000)](https://doc.rust-lang.org/edition-guide/)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blueviolet)](LICENSE)

代码仓库：<https://github.com/MiChongs/WutherCore>

---

## 目录

- [它做什么 / 不做什么](#它做什么--不做什么)
- [快速开始](#快速开始)
- [CLI](#cli)
- [配置文件](#配置文件)
- [出站协议](#出站协议)
- [传输层](#传输层)
- [路由（route）](#路由route)
- [DNS（resolver）](#dnsresolver)
- [节点分组（groups）](#节点分组groups)
- [Smart 学习](#smart-学习)
- [透明代理（capture）](#透明代理capture)
- [入站与控制面](#入站与控制面)
- [持久化与可观测性](#持久化与可观测性)
- [状态与平台支持](#状态与平台支持)
- [工作空间](#工作空间)
- [构建](#构建)
- [HTTP API](#http-api)
- [测试](#测试)
- [许可证](#许可证)

---

## 它做什么 / 不做什么

**做**

- 接住入站流量：本机 HTTP / SOCKS5 同端口（含 SOCKS5 UDP ASSOCIATE）；TUN 设备（Windows wintun、macOS utun、Linux tun、Android VpnService fd）；Linux TPROXY / REDIRECT 链路
- 拨出出站连接：22 种代理协议（Shadowsocks 系、V 系、QUIC 系、SSH、WireGuard、AnyTLS、Mieru、Sudoku、Trusttunnel 等），7 种传输层（TCP/TLS/WS/HTTP/H2/gRPC/XHTTP）
- 选节点：订阅自动拉取 + 本地节点合并；EWMA 评分 + URLTest 周期测速；按域名记录"最近最优"，失败节点指数退避冷却
- 走规则：L4（IP / 端口 / 网络）+ L7（域名 / 进程名 / STUN-DTLS-QUIC-SNI-HTTP 嗅探）+ 5 种内置 preset + 外部规则集（YAML / 文本 / JSON / 自研 RRS 二进制）
- 接管 DNS：多上游分组并发、bootstrap 三层独立、乐观缓存、Fake-IP、ECS 三层 fallback、主流 DNS 规则动作（route/evaluate/respond/reject/predefined）
- 观察与控制：HTTP API（原生 `/v1` + 兼容路径）、redb 持久化（节点学习、手动选择、URLTest 历史跨重启保留）、watchdog 线程外捕栈、连接表周期摘要日志

**不做**

- 不是 GUI 客户端：没有桌面/移动 GUI；安卓宿主 App 由用户自行实现（仓库只到 native 与 JNI 桥）
- 不是云控代理：没有"远程下发配置"概念；订阅是本地拉取、配置是本地 YAML、控制面是本机 API
- 不是规则集编辑器：能做 yaml/txt/json/rrs 互转，但规则语义合并、去重、排序由用户自己决定
- 不主动收集任何使用数据：没有遥测、不上报任何统计

---

## 快速开始

最小可运行配置：

```yaml
version: 1
profile: desktop
listen:
  local: "127.0.0.1:7890"     # Mixed: HTTP + SOCKS5 同端口
feeds:
  airport: "https://example.com/your-subscription"
route:
  preset: cn_smart            # 国内直连 + 国外走代理的开箱即用规则
```

跑起来：

```bash
cargo build --release -p proxy-core
./target/release/proxy-core run -c config.yaml
```

`profile` 决定一组默认值：

| profile | 默认 listen | 默认 capture | 默认 resolver | 用途 |
|---|---|---|---|---|
| `desktop` | 127.0.0.1:7890 | 关闭 | 系统 + 优化覆盖 | 桌面挂代理 |
| `router` | 0.0.0.0:7890 | 自动（virtual_nic / tproxy） | 强制接管 | 旁路由 / 主路由 |
| `mobile` | 127.0.0.1:7890 | virtual_nic + VpnService | 强制接管 + Fake-IP | Android |

profile 是兜底层；显式写在 YAML 里的字段始终优先。

---

## CLI

```text
proxy-core run        -c <yaml>             启动内核（前台）
proxy-core check         <yaml>             仅校验配置，不启动
proxy-core explain       <yaml>             输出展开后的 RuntimePlan（JSON，便于排错）
proxy-core migrate clash  <old.yaml> -o <out.yaml>   旧 Clash 风格配置迁移到 Friendly YAML
proxy-core feeds   list / refresh           订阅源管理
proxy-core ruleset list / refresh / convert 规则集管理与格式互转
proxy-core store   info / reset             redb 持久化数据查看与清空
```

`ruleset convert` 做 yaml ↔ txt ↔ json ↔ rrs 互转，输入/输出格式按扩展名自动识别，可被 `--input-format` / `--output-format` 覆盖。

`migrate` 子命令读旧风格 YAML 输出 Friendly YAML，方便从已有客户端的配置迁移。

---

## 配置文件

顶层结构：

```yaml
version: 1                  # 必填，当前固定 1
profile: desktop            # 必填，决定默认值
listen:    { ... }          # 入站监听
feeds:     { ... }          # 远程/本地订阅源
nodes:     [ ... ]          # 手动节点（URI 或对象）
groups:    { ... }          # 节点分组定义
route:     { ... }          # 路由规则
resolver:  { ... }          # DNS 解析器
capture:   { ... }          # 透明代理
smart:     { ... }          # 自动选节点参数
ui:        { ... }          # 控制面板与 API
mesh:      { ... }          # Tailscale 协同
log:       { ... }          # 日志输出
```

除 `version` / `profile` 之外的所有顶层字段都可以省略 —— profile 会给出可用默认值。

### 示例配置

仓库 `examples/` 目录有 6 份完整模板：

| 文件 | 场景 |
|---|---|
| [examples/desktop.yaml](examples/desktop.yaml) | 桌面最简：订阅 + cn_smart 路由 |
| [examples/router.yaml](examples/router.yaml) | 路由器：virtual_nic + cn_smart + Tailscale 排除 |
| [examples/with_feed.yaml](examples/with_feed.yaml) | 订阅 + 节点 keep / drop / rename 过滤 |
| [examples/daily.yaml](examples/daily.yaml) | 自定义 route.steps 全量演示 |
| [examples/manual_only.yaml](examples/manual_only.yaml) | 仅手动节点，不拉订阅 |
| [examples/android.yaml](examples/android.yaml) | Android VpnService 完整模板 |

---

## 出站协议

22 种实现，含完整握手、加密、协议状态机，与主流客户端互通。按家族分组：

### 基础 4 种

| 协议 | 说明 |
|---|---|
| `direct` | TCP / UDP 直连，可绑定出站接口 / fwmark |
| `block` | 立即拒绝；可选 close 或 reset |
| `http` | HTTP CONNECT + Basic 鉴权 |
| `socks5` | TCP / UDP，含 username/password 鉴权 |

### Shadowsocks 系

| 协议 | 关键算法 / 扩展 |
|---|---|
| Shadowsocks AEAD | aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305；EVP_BytesToKey + HKDF-SHA1 |
| Shadowsocks 2022 | `2022-blake3-{aes-128-gcm, aes-256-gcm, chacha20-poly1305}`；EIH 多用户、UDP、timestamp 防重放、variable-header padding |
| ShadowsocksR | aes-128/256-cfb / aes-128/256-ctr / chacha20-ietf / rc4-md5；plain / http_simple / tls1.2_ticket_auth obfs；origin / auth_aes128_md5 / auth_aes128_sha1 / auth_chain_a / auth_chain_b protocol |
| Snell v3 | aes-128-gcm / chacha20-poly1305；CONNECT / PING / PONG / UDP_FORWARD / UDP_STREAM；HTTP / TLS obfs |

### V 系 + AnyTLS

| 协议 | 关键算法 / 扩展 |
|---|---|
| Trojan | TLS 隧道，56 字节 SHA-224(password) hex 鉴权，载荷为 SOCKS5 命令 |
| VLESS | UUID + addons + cmd；可叠加 7 种传输 |
| VMess AEAD | aes-128-gcm / chacha20-poly1305 / none；CHUNK_MASKING（SHAKE128）+ GLOBAL_PADDING + AUTH_LEN；UDP cmd；嵌套 HMAC-SHA256 KDF |
| VMess Legacy | HMAC-MD5 AuthInfo + AES-128-CFB header（兼容 alterId>0 老服务端） |
| AnyTLS | mux 多路复用（SYN/PSH/FIN/ALERT/SETTINGS）+ padding scheme 协商 |

### QUIC 系

| 协议 | 关键算法 / 扩展 |
|---|---|
| Hysteria v1 | QUIC + msgpack ClientHello/ServerHello + 上下行 Mbps 协商 |
| Hysteria2 | QUIC + HTTP/3 鉴权（POST /auth）+ TCP frame 0x401 + Salamander obfs（自定义 `AsyncUdpSocket` + BLAKE2 keystream） |
| TUIC v5 | QUIC + UUID + token 鉴权；Authenticate / Connect / Packet / Heartbeat / Dissociate；UDP relay 同时支持 datagram 与 stream 模式 |

### 其它

| 协议 | 关键算法 / 扩展 |
|---|---|
| WireGuard | 手写 Noise IK 完整握手（X25519 + HMAC-BLAKE2s + HKDF + ChaCha20-Poly1305）+ transport encryption；smoltcp 用户态网络栈 |
| SSH | 基于 russh：密码 / 私钥（路径或内容）/ passphrase 鉴权；session 复用；known_hosts 校验；direct-tcpip 通道 |
| Mieru | PBKDF2-SHA256（4096 iter）+ AES-256-GCM / ChaCha20-Poly1305 + 用户名 + timestamp 防重放 |
| Sudoku | 4×4 数独网格混淆（288 个网格 / ASCII / Entropy / Custom 三种 byte layout）+ AEAD RecordConn（epoch + seq + 自动密钥更新）+ KIP 握手（X25519 + HKDF）+ HTTP mask legacy |
| Trusttunnel | HTTP/2 CONNECT + Basic 鉴权；魔法地址 `_udp2` / `_icmp` / `_check`；连接池 max_connections / min_streams / max_streams |

---

## 传输层

VLESS / VMess 通过节点配置里的 `network` 字段（兼容别名 `net` / `type`）选传输层。下列任意一种都可叠加 TLS：

| 传输 | 用途 | 关键实现 |
|---|---|---|
| `tcp` | 裸 TCP | tokio TcpStream |
| `tls` | TLS 1.2/1.3 | rustls + ring + webpki-roots；ALPN；可关闭证书校验 |
| `ws` | WebSocket | tokio-tungstenite；可叠加 TLS |
| `http` | HTTP/1.1 伪装 | TLS + 写出伪装请求头后裸字节通信 |
| `h2` | HTTP/2 双向流 | hyper http2；自定义 Host / Path / Method（默认 PUT） |
| `grpc` | gRPC 隧道（gun） | hyper http2 + `/<service>/Tun` + frame `flag(1) ‖ length(4) ‖ protobuf-wrap(data)` |
| `xhttp` | xhttp 三模式 | stream-one / stream-up / packet-up；session/seq/uplink-data/x-padding 完整 placement |

### XHTTP 详细参数

| 参数 | 含义 |
|---|---|
| `mode` | `auto` / `stream-one` / `stream-up` / `packet-up` |
| `path` | 请求路径（自动补 `/`） |
| `host` | `:authority` |
| `session-placement` / `seq-placement` | `path` / `query` / `header` / `cookie` |
| `uplink-data-placement` | `body` / `header` / `cookie` / `auto` |
| `sc-max-each-post-bytes` | packet-up 单 POST 最大字节（默认 1000000） |
| `sc-min-posts-interval-ms` | packet-up POST 最小间隔（默认 30 ms） |
| `x-padding-bytes` | padding 长度区间（默认 100–1000） |
| `x-padding-method` | `repeat-x` / `tokenish` |
| `x-padding-obfs-mode` | 启用自定义 placement / 否则放 Referer 查询 |
| `no-grpc-header` | 不发 `Content-Type: application/grpc` |

详见 [proto/xhttp/config.rs](crates/core-outbound/src/proto/xhttp/config.rs)。

---

## 路由（route）

```yaml
route:
  preset: custom            # cn_smart | global | direct | privacy | custom
  final: proxy              # preset=custom 时必填，未命中所有 step 时使用
  steps:
    - "..."                 # 字符串行（兼容 Clash 简写）
    - { ... }               # 对象行（强类型 key）
  sets:                     # 外部规则集
    geoip-cn:
      type: ipcidr
      url:  "https://example.com/geoip-cn.mrs"
      every: 24h
```

匹配从上到下，第一条命中即终止。`set: name` 引用 `route.sets` 中预拉取的规则集；规则集自带的多条 domain/cidr/keyword/process 在内部按各自最优数据结构索引（见下文）。

### preset

| preset | 行为 |
|---|---|
| `cn_smart` | 中国大陆域名 + 内网 → direct；其余 → final（默认 proxy） |
| `global` | 全部 → final（默认 proxy）；保留本地直连 |
| `direct` | 全部 → direct（实质禁用代理） |
| `privacy` | 广告 / 追踪 → block；DNS 强制走加密上游；其余 → final |
| `custom` | 完全由 `route.final` + `route.steps` 决定 |

`preset != custom` 时也可以填 `steps` —— 自定义 step 优先匹配，未命中再走 preset 兜底。

### 字符串行（Clash 兼容简写）

```yaml
steps:
  - "*.cn          -> direct"            # 后缀（前导 *.）
  - "geosite:cn    -> direct"            # 内置 / 外部规则集
  - "geoip:cn      -> direct"
  - "process:dnf   -> direct"            # 进程名匹配
  - "192.168.0.0/16 -> direct"           # CIDR
  - "443           -> proxy"             # 端口
  - "tcp           -> proxy"             # 网络类型
  - "stun          -> proxy"             # L7 嗅探协议
  - "any           -> proxy"             # 通配
```

### 对象行（强类型）

每个对象有恰好一个 matcher 字段 + 一个 outbound 字段：

```yaml
steps:
  - { domain:  "youtube.com",   outbound: streaming }
  - { suffix:  ".cn",           outbound: direct    }
  - { keyword: "ad",            outbound: block     }
  - { ip:      "8.8.8.8",       outbound: proxy     }
  - { ip:      "10.0.0.0/8",    outbound: direct    }
  - { port:    "443",           outbound: proxy     }
  - { port:    "1024-65535",    outbound: proxy     }
  - { process: "discord.exe",   outbound: proxy     }
  - { set:     "geoip-cn",      outbound: direct    }
  - { network: "udp",           outbound: proxy     }
  - { proto:   "quic",          outbound: proxy     }
```

### 全部 matcher 类型

| matcher | 含义 | 示例 |
|---|---|---|
| `domain` | 精确域名 | `youtube.com` |
| `suffix` | 后缀（含点） | `.cn`、`.googleapis.com` |
| `keyword` | 子串 | `cdn`、`ad` |
| `ip` | 单 IP 或 CIDR | `8.8.8.8`、`10.0.0.0/8`、`fe80::/10` |
| `port` | 端口或区间 | `443`、`1024-65535` |
| `process` | 进程名（需启用 `find-process-mode`） | `chrome.exe` |
| `set` | 引用 `route.sets` 中的规则集 | `geoip-cn`、`category-ads` |
| `network` | `tcp` / `udp` | `udp` |
| `proto` | L7 嗅探协议 | `quic`、`stun`、`sni`、`dtls`、`http` |
| `home` / `cn` / `ads` | 内置语义类别 | 等价 `set: home` 等 |

### And / Or 复合

```yaml
- and:
    - suffix: .cn
    - port: 443
  outbound: direct

- or:
    - keyword: ad
    - keyword: tracker
  outbound: block

- and:
    - suffix: .corp.example.com
    - or:
        - ip: 10.0.0.0/8
        - ip: 172.16.0.0/12
  outbound: home_lan
```

### 外部规则集（route.sets）

```yaml
sets:
  geoip-cn:                 # 远程拉取（按周期刷新）
    type: ipcidr
    url:  "https://example.com/geoip-cn.mrs"
    every: 24h
  ads:
    type: domain
    url:  "https://example.com/ads.txt"
    every: 12h
  home_lan:                 # 本地内联 payload
    type: ipcidr
    payload:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - fc00::/7
```

`type`：`domain` / `ipcidr` / `classical` / `mixed`。`format` 自动嗅探，可显式指定：

| 格式 | 来源 |
|---|---|
| `yaml` | 主流 YAML payload（domain / ipcidr / classical） |
| `txt` / `list` | 纯文本（含 `+.suffix`、`.suffix`、CIDR、policy 短写法） |
| `json` | 主流 JSON rule-set（v1 / v2 + logical 嵌套） |
| `mrs` / `srs` | 主流二进制规则集；本内核仅嗅探识别，提示用 `ruleset convert` 转文本 |
| `rrs` | 自研二进制（CRC32 校验，体积约为 YAML 的 45%） |

#### RRS 格式

```
24 字节 header
  magic       "RRS\0"
  version     2 字节
  flags       2 字节
  created_at  8 字节
  body_len    4 字节
  body_crc32  4 字节

body 8 段紧凑编码：
  DomainExact  var-len string
  Suffix       var-len string
  Keyword      var-len string
  Regex        var-len string
  V4 CIDR      5  字节 (4B addr  + 1B prefix)
  V6 CIDR      17 字节 (16B addr + 1B prefix)
  Port         2  字节
  Process      var-len string
```

转换：

```bash
proxy-core ruleset convert in.yaml  out.rrs
proxy-core ruleset convert in.json  out.rrs
proxy-core ruleset convert in.rrs   out.yaml
proxy-core ruleset convert in.txt   out.rrs --output-format rrs
```

实测 1000 条规则：YAML 27075 字节 → RRS 12044 字节，且 RRS → JSON → RRS 字节级一致。

#### 索引

后缀 trie + AHashSet 精确 + Vec 关键字 + RegexSet + 按掩码长度倒序的 CIDR + 端口区间 + 进程名集合。10 万条规则量级下命中约 100 µs。

---

## DNS（resolver）

```yaml
resolver:
  enable: true
  ipv6: true                          # 全局 AAAA 开关
  ipv6-timeout: 100ms                 # AAAA 超时不阻塞 A
  enhanced-mode: fake-ip              # off | redir-host | fake-ip
  fake-ip-range: "198.18.0.0/16"
  fake-ip-filter:
    - "+.lan"
    - "+.local"
    - "stun.*.*"
  use-hosts: true
  use-system-hosts: true
  hosts:
    "router.local": "192.168.1.1"
    "ad-server":    "0.0.0.0"
  default-nameserver:                 # bootstrap：必须直连 IP，无递归
    - 223.5.5.5
    - 119.29.29.29
  nameserver:                         # 主上游
    - "https://dns.google/dns-query"
    - "tls://1.1.1.1"
    - "udp://223.5.5.5:53"
  fallback:                           # 备用上游：被 fallback-filter 触发时启用
    - "https://1.1.1.1/dns-query"
    - "tls://8.8.8.8"
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite: [gfw]
    ipcidr:  [240.0.0.0/4]
    domain:  ["+.google.com"]
  nameserver-policy:                  # 域名 / 规则集 → 自定义上游
    "+.cn":                  ["udp://223.5.5.5:53"]
    "geosite:category-ads":  ["rcode://refused"]
  proxy-server-nameserver:            # 解析代理节点本身域名所用 DNS
    - "https://1.1.1.1/dns-query"
  listen: "0.0.0.0:5353"              # 独立 DNS 服务器（可选）
  prefer-h3: false
```

### 字段总览

| 字段 | 默认 | 说明 |
|---|---|---|
| `enable` | `true` | 关闭后内核走系统解析器 |
| `ipv6` | `true` | 全局 AAAA 开关；关闭后 TUN 也丢弃 IPv6 包 |
| `ipv6-timeout` | `100ms` | A+AAAA 并发时 AAAA 超时不阻塞返回 |
| `enhanced-mode` | `off` | `off` / `redir-host` / `fake-ip` |
| `fake-ip-range` | `198.18.0.0/16` | Fake-IP 池；不能与真实路由冲突 |
| `fake-ip-filter` | `[]` | 跳过 Fake-IP 分配的域名（支持 `+.lan` 等） |
| `use-hosts` | `true` | 是否使用 `hosts:` 字段 |
| `use-system-hosts` | `true` | 是否使用系统 hosts 文件 |
| `hosts` | `{}` | 用户自定义域名 → IP 直接映射 |
| `nameserver` | profile 决定 | 主上游列表 |
| `fallback` | `[]` | 备用上游 |
| `fallback-filter` | —— | 触发 fallback 的条件（geoip / geosite / ipcidr / domain） |
| `nameserver-policy` | `{}` | 域名 / 规则集 → 自定义上游覆盖 |
| `proxy-server-nameserver` | profile 决定 | 解析代理节点域名专用（独立第三层） |
| `default-nameserver` | profile 决定 | bootstrap 阶段用，必须是直连 IP 的纯文本 DNS |
| `listen` | `null` | 独立 DNS 服务器（同时绑 UDP+TCP） |
| `prefer-h3` | `false` | DoH 优先尝试 HTTP/3 |

### 三层 bootstrap 互不串扰

```
1. main          resolver.nameserver / nameserver-policy 命中的上游
2. proxy-server  resolver.proxy-server-nameserver（解析代理节点域名专用）
3. direct        resolver.default-nameserver（bootstrap，必须是 IP 纯文本）
```

直连上游不会回落到代理路径，否则解析代理节点本身的域名会触发死循环。

### Friendly DSL

`nameserver-policy` 的 value 可以是上游列表，也可以借助 DSL 映射到常见动作：

```yaml
nameserver-policy:
  # 字符串简写
  "ads.com":              "drop"            # 直接拒答
  "tracker.example.com":  "refuse"          # 返回 REFUSED
  "*.cn":                 "direct:mainland" # group=mainland 解析
  "=foo.local":           "hosts:127.0.0.1" # 等价 hosts 注入
  "geosite:cn":           "direct:mainland"

  # 对象
  "+.ads.example":        { drop: true }
  "stale.example":        { suffix: stale.example, hosts: ["127.0.0.1", "::1"] }
  "+.cn":                 { set: cn, direct: mainland, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }
  "any":                  { match: any, evaluate: overseas, no_cache: true }
  "rev":                  { match_response: 1.1.1.0/24, respond: true }
  "nx.local":             { suffix: nx.local, nxdomain: true }
```

### Fake-IP

启用 `enhanced-mode: fake-ip` 后：

- A / AAAA 查询返回 `fake-ip-range` 池里的虚拟地址
- TUN 抓到该虚拟 IP 的连接，反查为真实域名再做路由决策
- `fake-ip-filter` 命中的域名跳过分配（继续走真实解析）
- IP ↔ Host 反向映射 LRU 持久化在 redb，重启不丢

### IPv6 全局开关

`ipv6: false` 同时影响三层：DNS 不发 AAAA、TUN 丢弃 IPv6 包、出站 socket 不绑 IPv6。三处同步避免"DNS 没解析却被 TUN 抓到 IPv6 流量然后超时"这种割裂。

---

## 节点分组（groups）

```yaml
groups:
  proxy:
    choose: smart                 # manual | smart | fast | stable | spread | chain
    use:    [airport]             # 节点来源：feed 名 / 节点名
    prefer: ["{country}=hk"]      # 偏好（可选）
    avoid:  ["{name}~=test"]      # 避免（可选）
    check:
      url: "https://www.gstatic.com/generate_204"
      every: 60s
      tolerance: 50ms             # URLTest 抖动容忍
    sticky:
      domain: 5m                  # 同 host 在 N 秒内复用上次最优
      negative: 30s               # 失败节点冷却

  streaming:
    choose: fast
    use: [airport]
    prefer: ["{country}=us", "{country}=jp"]
    check:
      url: "https://www.netflix.com/title/70143836"
      every: 5m
```

### choose 策略

| 策略 | 行为 |
|---|---|
| `manual` | 用户经面板手动选择；持久化到 redb，重启保留 |
| `smart` | EWMA 评分 + domain_best + cooldown，连接时即时决策（见下节） |
| `fast` | 取 URLTest 当前最低延迟节点 |
| `stable` | 取抖动最小节点（连续 N 次 URLTest 方差最低） |
| `spread` | 每次连接轮转，分担负载 |
| `chain` | 按 `use` 顺序串联，构成 multi-hop 链 |

### prefer / avoid 表达式

`{country}=hk` 国家 ISO；`{name}~=keyword` 名称包含；`{port}=443`；可叠加。

---

## Smart 学习

`choose: smart` 不是简单的 URLTest，而是按"域名 → 最近最优节点"的滑动窗口。

```yaml
smart:
  goal: balanced               # balanced | speed | stability | low_cost | privacy
  ewma-alpha: 0.3              # 评分衰减因子
  domain-best-ttl: 5m
  negative-base: 30s
  negative-max: 30m
  url-test:
    url: "https://www.gstatic.com/generate_204"
    every: 60s
    concurrency: 8
  sticky:
    enabled: true
    domain: 5m
```

| 维度 | 实现 |
|---|---|
| 评分 | EWMA 成功率衰减 |
| 最近最优 | `domain_best` 域名级缓存 |
| 失败冷却 | `negative` 表，连续失败的节点冷却时间指数退避 |
| 主动测速 | URLTest 周期任务，目标 URL 与并发度可配置 |
| 持久化 | redb 落盘，跨重启保留评分、域名最优、冷却、URLTest 历史 |
| 控制面 | `/v1/smart/why?host=&group=`、`/v1/smart/{pin,avoid,reset}` |

### goal 解释

| goal | 评分权重 |
|---|---|
| `balanced`（默认） | 成功率 / 延迟 / 抖动 各占 1/3 |
| `speed` | 偏向带宽与延迟（URLTest 权重↑） |
| `stability` | 偏向抖动小、失败少 |
| `low_cost` | 偏向廉价或免费节点（按 feed metadata 标签） |
| `privacy` | 偏向加密强度高、不允许日志的节点 |

`/v1/smart/why?host=&group=` 返回该域名当前选择的节点 + 各维度评分，便于排查"为什么走了这个节点"。

---

## 透明代理（capture）

```yaml
capture:
  on: true
  method: auto                  # auto | virtual_nic | tproxy | redirect
  stack:  system                # system | mixed | native | smoltcp | gvisor
  mtu:    1500
  exclude:
    addresses: [10.0.0.0/8, 172.16.0.0/12, fe80::/10]
    processes: ["docker.exe", "tailscaled"]
    interfaces: ["tailscale0"]
  fwmark:
    auto-redirect-input: 0x2023
    output:              0x2024
    reset:               0x2025
    nfqueue:             100
```

### method × stack

| method | 用法 |
|---|---|
| `auto` | 探测系统能力，按 NftablesFull → IptablesV4V6Tproxy → IptablesV4V6Redirect → IptablesV4Only → VirtualNic 顺序降级 |
| `virtual_nic` | TUN 设备（Windows wintun / macOS utun / Linux tun / Android VpnService fd） |
| `tproxy` | Linux TPROXY，不修改包头，零拷贝转发 |
| `redirect` | Linux NAT REDIRECT；UDP 受限 |

| stack | 用途 |
|---|---|
| `system` | 内核协议栈（TPROXY / REDIRECT 路径默认） |
| `mixed` | TCP 走系统、UDP 走用户态（兼顾性能与可控性） |
| `native` | 用户态 TCP + native UDP（默认 TUN 路径） |
| `smoltcp` | 纯 smoltcp 用户态栈（无 IP 转发权限时备选） |
| `gvisor` | gvisor netstack（实验，仅 Linux） |

### Linux TProxy / Redirect 路径

`fwmark` 三个 mark 各有分工：

| mark | 用途 |
|---|---|
| `auto-redirect-input` (`0x2023`) | TUN 反向回注流量识别 |
| `output` (`0x2024`) | 出站 socket 标记，绕过自身 TPROXY 链 |
| `reset` (`0x2025`) | block 路径上发 RST 时使用 |
| `nfqueue` (`100`) | nftables / iptables NFQUEUE 编号 |

`route.sets` 的 `ipcidr` 集合可注入到 capture supervisor，作为 `route_address_set: [geoip-cn]` 形式的快速白 / 黑名单。

### Android VpnService

未 root 时由宿主 App 持有 VpnService.Builder，把内核解析后的字段（地址、路由、DNS、应用白/黑名单）写入 Builder：

```kotlin
val cfg = VpnBridge.vpnServiceConfigJson(configPath)
// 把 cfg 的 addresses / routes / dns / bypass-applications 逐项写入 builder
val fd = builder.establish()!!.detachFd()
VpnBridge.setVpnService(this)
VpnBridge.setVpnFd(fd)
```

Root 路径按可用能力 4 层降级：

| 层级 | 名称 | 条件 |
|---|---|---|
| 1 | NftablesFull | nft + ip6 nat + IPv4/v6 TPROXY |
| 2 | IptablesV4V6Tproxy | iptables + ip6tables + 双栈 TPROXY |
| 3 | IptablesV4V6Redirect | iptables + ip6tables NAT REDIRECT；UDP 受限 |
| 4 | IptablesV4Only | 仅 iptables v4 NAT REDIRECT |

`AndroidCapability::detect_capability()` 通过 `su -c` 探测 11 项能力（has_root、has_ip6tables、has_nftables、kernel_ipv6_nat、kernel_tproxy_v6、uid_owner_match 等），自动选最高可用层。

---

## 入站与控制面

```yaml
listen:
  local: "127.0.0.1:7890"        # Mixed 入站（HTTP + SOCKS5 同端口自动嗅探）
  panel: "127.0.0.1:9090"        # 控制面板 / API
  share: false                   # 是否允许 0.0.0.0 监听
  auth:
    - { username: "u", password: "p" }

ui:
  on: true
  secret: "your-api-secret"      # /v1 与兼容 API 共用
  cors:
    - "https://yacd.example.com"
  api:
    clash-compat: true           # 同时暴露 /proxies / /connections 等兼容路径
```

`local` 端口同时支持 HTTP CONNECT、HTTP 代理、SOCKS5（含 UDP ASSOCIATE），按首字节嗅探分发。`auth` 留空表示无鉴权；填了用户名密码即两种协议都强制鉴权。

启动钩子检测特权失败时自动降级（绑高端口 / 跳过 capture 改 socks 模式），不会因为没 root / 没 admin 直接退出。

---

## 持久化与可观测性

### redb 持久化

默认路径 `data/state/wuthercore.redb`。下列状态全部跨重启保留：

- Smart 节点评分、domain_best、negative cooldown、URLTest 历史
- 用户 pin / avoid 选择
- Group `manual` 模式的当前节点
- Feed 元数据（last-modified / etag）
- Fake-IP 反向映射

`proxy-core store info` 查看大小与各表行数；`proxy-core store reset` 清空学习数据（保留 schema 版本）。

### 日志与连接表

```yaml
log:
  on: true
  level: info                    # off / error / warn / info / debug / trace
  filter: "info,capture::traffic=trace"
  stdout: true
  file:
    on: true
    path: "data/logs/wuthercore.log"
  format: text                   # text | json
  connection-summary-interval: 0s   # >0 启用周期连接表摘要
```

`connection-summary-interval > 0s` 时，每 N 秒输出一次 by-process / by-dst / by-rule 的聚合 + 长连接清单 —— 用来回答"连接表为什么这么大"。

### Watchdog

`proxy-core run` 启动时安装独立 std::thread + 同步文件 IO 的 watchdog，与 tokio 运行时完全解耦。即便整个 tokio 卡死（典型成因：DashMap entry × len 同 shard 递归 RwLock；Arc 循环让 producer 永不退出），独立线程仍会在 `data/logs/watchdog.log` 写出 STUCK / DEADLOCK 报告 + 全线程栈，不必再面对"进程在跑但啥都不响应"的黑盒。

---

## 状态与平台支持

| 模块 | 状态 |
|---|---|
| Mixed 入站 + Mixed 鉴权 | 稳定 |
| 22 种出站协议 + 7 种传输 | 稳定 |
| 路由（preset + steps + sets） | 稳定 |
| DNS（多上游、Fake-IP、ECS、所有动作） | 稳定 |
| Smart 学习 + URLTest | 稳定 |
| redb 持久化 + watchdog | 稳定 |
| HTTP API（`/v1` + 兼容路径） | 稳定 |
| 规则集互转（yaml/txt/json/rrs） | 稳定 |
| Linux TPROXY / REDIRECT | 稳定 |
| TUN：Windows wintun / macOS utun / Linux tun | 稳定 |
| Android：root 4 层降级 + VpnService fd | 稳定 |
| Tailscale 协同（Tailnet 自动排除） | 部分；userspace_proxy 接入待 |
| iOS NEPacketTunnelProvider 桥 | 实验；fd 注入路径未在生产验证 |
| capture stack: gvisor | 实验，仅 Linux |

| 平台 | 透明代理路径 | 说明 |
|---|---|---|
| Windows 10 / 11 | wintun TUN | Mixed 入站无需特权；TUN 需要管理员 |
| macOS | utun TUN | TUN 需要 root |
| Linux x86_64 / aarch64 | TPROXY / REDIRECT / TUN | TPROXY 推荐，最高性能；root 必需 |
| Android（root） | iptables / nftables 4 层降级 | `su -c` 自动探测 |
| Android（无 root） | VpnService fd 注入 | 宿主 App 持有 Builder |
| iOS | NEPacketTunnelProvider | 实验，仅留接口 |

---

## 工作空间

17 个生产 crate + 1 个 e2e 测试 crate：

```
crates/
  core-config        YAML / 节点 URI 解析 / profile 默认值 / 迁移
  core-runtime       Runtime + GroupSelector + URLTest 周期测速
  core-fetch         HTTP / HTTPS 抓取（feeds 与 ruleset 共用，含 gzip / brotli 解压）
  core-inbound       Mixed (HTTP+SOCKS5) + 权限检测 + 端口降级
  core-outbound      22 种代理协议 + 7 种传输层
  core-route         规则引擎 + 内置 preset + L7 嗅探（STUN/DTLS/QUIC/SNI/HTTP）
  core-resolver      DNS：多 group / 乐观缓存 / 完整动作集 / ECS 三层 / Fake-IP
  core-ruleset       YAML / TXT / LIST / JSON / 自研 RRS 二进制 + 互转
  core-feeds         订阅拉取 + 缓存 + 周期刷新
  core-smart         EWMA 评分 + domain_best + cooldown
  core-store         redb 嵌入式 KV + AsyncWriter
  core-capture       TUN / TPROXY / REDIRECT + Android 4 层降级
  core-process       4 平台进程查找（Windows / Linux / macOS / Android），LRU 缓存
  core-mesh          Tailscale 协同
  core-observe       tracing / metrics / connections + watchdog
  core-api           /v1 原生 API + 兼容路径 + URLTest delay
  proxy-core         CLI 入口

tests-e2e/           端到端测试（跨 crate 集成）
examples/            6 份示例配置
docs/                构建性能优化等文档
scripts/             多平台一键构建脚本
```

---

## 构建

最小：

```bash
cargo build --release -p proxy-core
cargo test  --workspace
```

要求 Rust 1.85+ / edition 2024。

### 多平台一键构建（Windows 主机）

```cmd
build.cmd                  默认矩阵
build.cmd windows
build.cmd linux            x86_64-unknown-linux-musl，cargo-zigbuild 后端
build.cmd android          aarch64-linux-android，cargo-ndk 后端
```

强制指定后端：

```powershell
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
```

### 编译目标矩阵

| 目标 | 后端 | Windows 主机可用 |
|---|---|---|
| x86_64-pc-windows-msvc | cargo | 是 |
| aarch64-pc-windows-msvc | cargo | 是 |
| x86_64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-linux-android | cargo-ndk + 自动从 `%LOCALAPPDATA%\Android\Sdk\ndk` 发现 NDK | 是 |
| x86_64 / aarch64-apple-darwin | 仅 macOS 主机 | 否 |

### 编译性能（仓库内置）

| 优化 | 位置 | 效果 |
|---|---|---|
| `incremental` + `codegen-units=256`（dev） | [Cargo.toml](Cargo.toml) | 单 crate 内并行 |
| `[profile.dev.package."*"] opt-level=1` | 同上 | 依赖也快 |
| `debug="line-tables-only"` + `split-debuginfo` | 同上 | debuginfo 减少约 80% |
| `lto="thin"` + `codegen-units=16`（release） | 同上 | 性能差约 1%，构建时间减少约 60% |
| `release-fast` profile | 同上 | CI 冒烟用，比 release 快约 4× |
| `rust-lld`（Windows MSVC） | [.cargo/config.toml](.cargo/config.toml) | 链接时间减少 50%–70% |
| `mold`（Linux x64） | 同上 | 链接时间减少约 80% |

实测增量构建：改一行 `main.rs` 全量从 22 秒降到 2 秒。详见 [docs/BUILD-PERF.md](docs/BUILD-PERF.md)。

---

## HTTP API

### 原生 `/v1`

```
GET    /v1/status                              版本 / 运行时间 / profile / 平台
GET    /v1/traffic                             实时流量
GET    /v1/nodes                               节点列表
GET    /v1/groups                              分组列表
PATCH  /v1/groups/:name                        手动切节点（持久化到 redb）
GET    /v1/connections                         连接列表
DELETE /v1/connections/:id                     关闭指定连接
GET    /v1/route/check?host=&port=&network=    路由命中调试
GET    /v1/proxies/:name/delay                 URLTest 单节点延迟
POST   /v1/groups/:name/healthcheck            整组测速
POST   /v1/healthcheck                         全局测速
GET    /v1/smart/why?host=&group=              解释 Smart 选择
POST   /v1/smart/pin                           固定节点
POST   /v1/smart/avoid                         避开节点
POST   /v1/smart/reset                         重置 Smart 学习数据
GET    /v1/logs                                WebSocket 日志流
GET    /v1/providers/proxies                   订阅 provider 列表
GET    /v1/providers/rules                     规则集 provider 列表
```

### 兼容路径

`/proxies` · `/proxies/:name` · `/proxies/:name/delay` · `/group/:name/delay` · `/connections` · `/configs` · `/version` · `/traffic` · `/logs`

控制面板（如 yacd / metacubexd）直接连入 `panel` 监听端口即可使用。

---

## 测试

```bash
cargo test --workspace
```

主要 crate 关注点：

| crate | 关注 |
|---|---|
| core-config | YAML 加载、profile 兜底、节点 URI 解析、迁移 |
| core-route | matcher 优先级、preset、ruleset 集成、L7 嗅探 |
| core-resolver | 完整动作集、ECS 三层、fallback-filter、Fake-IP |
| core-outbound | 22 种协议握手、7 种传输层、TLS 包装、UDP 隧道 |
| core-ruleset | yaml/txt/json/rrs 互转的字节级一致性 |
| core-capture | 4 种 method × 5 种 stack 的诊断与降级 |
| core-smart | EWMA / domain_best / cooldown / sticky |
| core-api | /v1 与兼容路径的契约 |
| tests-e2e | 跨 crate 集成 |

---

## 许可证

[MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE)，二选一。

---

## 设计文档

完整设计参见 [RP内核设计文档.md](RP内核设计文档.md) 与各 crate 顶部 doc 注释。
