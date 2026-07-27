# Young v1 协议规范与部署指南

Young 是 WutherCore 自主实现的新代理协议。它不是 VLESS、REALITY、Hysteria
或其他现有协议的改名，也不复用这些协议的握手。Young v1 的网络栈为：

```text
UDP
└── Mozilla Neqo QUIC v1 + NSS/TLS 1.3
    └── HTTP/3（ALPN: h3）
        └── WebTransport
            ├── 双向流：Young TCP
            └── Datagram：Young UDP
```

客户端与服务端都直接调用 Mozilla 的 Rust Neqo API。当前依赖固定到 Neqo
`main` 的提交 `76673b127251c90ad6250de7a0a7400ddd4661f1`，确保可复现构建。
Neqo 的 TLS 实现通过 `nss-rs` 使用 Mozilla NSS；WutherCore 不包含手写 FFI，
但运行和构建仍需要 NSS 原生库。`nss-rs` 同样固定到
`b7cfa30c8a526167cf6bd653b4a6d4f8549280eb`。

## 1. 设计目标

- 外层是可互操作的 HTTP/3 + WebTransport，不伪造“类似 QUIC”的私有报文。
- 一个已认证的 QUIC 连接承载多个并发 TCP、UDP 流。
- 预共享密钥不直接作为流量密钥；会话密钥同时绑定 TLS exporter 和随机 nonce。
- 抵抗无凭据主动探测、认证重放、路径枚举和内层报文篡改。
- 未认证请求表现为普通 HTTP/3 响应，不暴露 Young 错误、版本或认证状态。
- TCP 支持双向传输和半关闭；UDP 支持最大 65507 字节报文、分片和乱序重组。
- 配置限制会话数、每会话流数、QUIC 流数、重放缓存和重组缓存。

## 2. 密钥和证书

### 2.1 Young 用户密钥

每个用户密钥必须是 32 个 CSPRNG 随机字节，以无填充 base64url 表示：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
```

`key_id = SHA-256(key)[0..8]`，只用于服务端从 key ring 选择密钥。日志和
`Debug` 输出只显示 key id，不显示密钥。服务端 `users` 可以同时保留新旧密钥，
用于无中断轮换。

### 2.2 TLS 证书固定

Young 客户端必须提供服务端叶证书 DER 的 SHA-256 摘要，支持 64 位十六进制或
无填充 base64url。客户端严格校验该摘要，不提供跳过校验的开关。

```bash
openssl x509 -in cert.pem -outform DER |
  openssl dgst -sha256
```

证书固定值变化时，必须先更新客户端，再替换服务端证书。

## 3. WebTransport 会话认证

客户端向每日轮换的路径发送标准 WebTransport CONNECT。客户端使用 Firefox
User-Agent，并携带以下 HTTP/3 请求信息；这些头部位于 QUIC 加密层内：

```text
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = <configured authority>
:path = <base path>/<daily token>
authorization = Bearer <Young authorization>
```

每日路径为：

```text
day = floor(unix_seconds / 86400)
daily_token = base64url(HMAC-SHA256(key, "young/path/v1" || day)[0..9])
path = trim_end_slash(base_path) || "/" || daily_token
```

服务端接受当前日期及前后各一天的轮换路径，以容忍日期边界。

Authorization 解码后的固定布局如下，所有整数使用网络字节序：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Version | 1 | `0x01` |
| Key ID | 8 | `SHA-256(key)[0..8]` |
| Timestamp | 8 | UNIX 秒 |
| Client nonce | 16 | CSPRNG 随机数 |
| Capabilities | 4 | 客户端能力位 |
| Tag | 32 | HMAC-SHA-256 |

Tag 覆盖：

```text
"young/session/v1" || authority || path || fields_before_tag
```

服务端按固定时间窗校验时间戳，并把 `(key_id, nonce)` 原子写入有界重放缓存。
同一个认证值只能成功一次。认证成功后服务端在
`sec-young-accept` 响应头中返回：

```text
base64url(HMAC-SHA256(key, "young/server-accept/v1" || client_nonce))
```

客户端必须验证服务端证明。随后双方从 WebTransport 会话导出的 TLS exporter
生成内层会话密钥：

```text
session_key = HMAC-SHA256(
  key,
  "young/exporter/v1" || tls_exporter || client_nonce
)
```

因此，截获的 Young Authorization 不能脱离原 TLS 会话复用为内层流量密钥。

## 4. TCP 流

每个 TCP 代理流使用一条 WebTransport 双向流。第一个帧为 FlowOpen：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YF` |
| Version | 1 | `0x01` |
| Kind | 1 | `1=TCP`，`2=UDP association` |
| Flow ID | 8 | 随机会话内标识 |
| Target | 可变 | IPv4、IPv6 或域名及端口 |
| Padding length | 2 | `0..=4096` |
| Random padding | 可变 | CSPRNG 字节 |
| Tag | 16 | 截断 HMAC-SHA-256 |

Tag 覆盖：

```text
"young/flow-open/v1" || all_fields_before_tag
```

服务端响应固定长度 FlowResponse：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YR` |
| Version | 1 | `0x01` |
| Status | 1 | 状态码 |
| Flow ID | 8 | 对应请求 |
| Tag | 16 | 截断 HMAC-SHA-256 |

状态码为 `0=成功`、`1=请求错误`、`2=未授权`、`3=连接失败`、
`4=不支持`、`5=资源上限`。成功响应后是目标 TCP 字节流。WebTransport
两个发送方向分别映射 TCP 两个发送方向，FIN 独立传播，支持“发送完成后继续接收”
的半关闭语义。

## 5. UDP association

UDP association 先用双向流执行与 TCP 相同的 FlowOpen/FlowResponse，随后每个
UDP 报文通过 WebTransport Datagram 传输。报文长度范围为 `1..=65507`。

当一份 UDP 报文超过当前 QUIC datagram 上限时，编码为多个 Young 分片：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YD` |
| Version | 1 | `0x01` |
| Flags | 1 | v1 必须为 0 |
| Association ID | 8 | 对应 UDP association |
| Packet ID | 4 | 每份原始 UDP 报文递增 |
| Fragment index | 2 | 从 0 开始 |
| Fragment count | 2 | 总分片数 |
| Total length | 2 | 原始 UDP 报文长度 |
| Payload | 可变 | 当前分片 |
| Tag | 16 | 截断 HMAC-SHA-256 |

Tag 覆盖：

```text
"young/udp-fragment/v1" || all_fields_before_tag
```

接收端先验证 Tag，再进行有界、带超时的乱序重组。Association ID、Packet ID、
分片数量、总长度或 Tag 不一致时丢弃整份报文，避免把不同 UDP 报文拼接在一起。
每份原始报文最多 256 个分片，未知 association 不进入重组缓存。

## 6. 主动探测和封锁对抗

Young v1 实现以下防护：

- 使用真实 Neqo QUIC、HTTP/3 和 WebTransport 状态机，不发送自制伪 QUIC 握手。
- Young 认证头、轮换路径、目标地址和内层帧均位于 QUIC 加密层内。
- 每日路径、随机 nonce、时间窗和有界重放缓存消除可长期重放的固定入口。
- 双向认证：证书 SHA-256 固定与 `sec-young-accept` 同时验证服务端。
- 内层 FlowOpen、FlowResponse 和每个 UDP 分片都用 TLS-exporter 派生密钥认证。
- 无效认证、错误路径和普通 HTTP/3 请求返回可配置的普通网页，不返回 Young
  专用错误；并在验证认证前不连接任意目标。
- 随机 FlowOpen padding 降低固定长度特征；一个连接复用多个流，减少逐流握手。
- 会话、流、缓存和报文尺寸均有限制；每流待发送队列上限为 1 MiB，流结束或
  重置时会取消对应 relay task，降低慢连接和探测造成的资源消耗。
- 已认证会话中的非法流帧只重置该流，非法 UDP 分片只丢弃该报文，不会终止
  整个 Neqo server worker。

这里的“抗封锁”不是“不可封锁”。能够整体阻断 UDP、QUIC 或目标 IP 的网络仍可
中断 Young；流量分析者也可能基于长期统计特征分类 HTTP/3。Young v1 不宣称具备
尚未实现的 ECH、域前置或 TCP fallback。需要运营侧配合轮换 IP、证书、密钥和
伪装内容，并监控 QUIC 可达性。

## 7. 服务端配置

NSS 数据库中必须存在可用于 `authority` 的证书及私钥。一个进程只能初始化一份
NSS 数据库，因此同一配置中的所有 Young listener 必须使用相同的
`nssDatabase`。

```bash
mkdir -p data/nss
certutil -N -d sql:data/nss
pk12util -i server.p12 -d sql:data/nss
certutil -L -d sql:data/nss
```

```yaml
version: 1
profile: server

listen:
  young:
    - host: 0.0.0.0
      port: 443
      nssDatabase: data/nss
      certificateNickname: young.example.com
      authority: young.example.com
      path: /assets
      users:
        - REPLACE_WITH_32_BYTE_BASE64URL_KEY
      clockSkew: 2m
      idleTimeout: 5m
      maxStreams: 1024
      maxSessions: 4096
      maxFlowsPerSession: 256
      decoyStatus: 404
      decoyBody: "<!doctype html><title>Not Found</title>"

route:
  preset: direct
```

`wuther-core check` 会验证端口冲突、密钥长度和 key id 重复、NSS 数据库一致性、
路径、状态码及所有资源上限。`run` 会先启动 Young UDP listener，再启动本地
Mixed listener；出站客户端延迟初始化，从而避免 NSS 全局初始化顺序冲突。

## 8. 客户端 URI

```text
young://<base64url-key>@<server-ip-or-host>:443\
?security=tls\
&sni=young.example.com\
&authority=young.example.com\
&path=%2Fassets\
&pin-sha256=<leaf-certificate-sha256-hex>\
&padding-min=64\
&padding-max=512\
&idle-secs=300\
&max-streams=1024\
#Young
```

必填项是 32 字节 base64url key、服务器地址、端口、`security=tls`、SNI 和
`pin-sha256`。`authority` 默认等于 SNI，`path` 默认 `/assets`。

## 9. 构建依赖

Linux（Debian/Ubuntu）：

```bash
# Debian/Ubuntu 稳定版的 NSS 若低于 3.121，不要安装 libnss3-dev：
# nss-rs 会拉取并构建满足版本要求的 NSS/NSPR。
sudo apt-get install clang gyp mercurial ninja-build pkg-config
cargo build --release -p wuther-core
```

若 `pkg-config --modversion nss` 已报告 `3.121` 或更高版本，可改用发行版提供的
`libnss3-dev` 与 `libnspr4-dev`，避免源码构建。

Windows 需要可供 `nss-rs` 使用的 NSS/NSPR、Clang/libclang 和相应构建环境；
MozillaBuild 是推荐的准备方式。若依赖不在默认搜索路径，需要配置
`NSS_DIR`、`NSPR_DIR` 和 `LIBCLANG_PATH`。纯协议编解码测试可以关闭 Neqo：

```bash
cargo test -p core-young --no-default-features --lib
```

真实网络互操作测试需要 NSS：

```bash
cargo test -p core-young --features firefox-stack --test neqo_roundtrip
```

该测试覆盖错误用户密钥拒绝后服务端继续可用、真实 WebTransport 会话、TCP
半关闭后回包，以及 5000 字节 UDP 报文的分片和乱序安全重组路径。

## 10. 实现状态与上游边界

Young v1 已接入配置解析、运行计划、内核 listener、出站注册、TCP、UDP、
半关闭、证书固定、重放防护、伪装响应和真实 Neqo 互操作测试。Mozilla 当前仍将
Neqo 服务端能力标记为实验性；部署前应进行容量、升级和异常网络回归，不应把
上游实验性服务端当作无风险的长期兼容承诺。

参考：

- [Mozilla Neqo](https://github.com/mozilla/neqo)
- [Firefox HTTP/3 文档](https://firefox-source-docs.mozilla.org/networking/http/http3.html)
- [Firefox Networking / Necko 术语](https://firefox-source-docs.mozilla.org/networking/necko_lingo.html)
