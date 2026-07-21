# XHTTP / SplitHTTP 配置

WutherCore 的 XHTTP 实现以 Xray 26.7.11 的线协议和配置语义为兼容基准，提供客户端与服务端、HTTP/1.1、HTTP/2、HTTP/3，以及 `stream-one`、`stream-up`、`packet-up` 三种模式。`splithttp` 作为 `xhttp` 的兼容别名。

## 客户端

XHTTP 是 VLESS、VMess、Trojan 等代理协议的传输层。节点使用结构化 `transport.xhttp`，不要把完整配置压缩成未校验的字符串参数：

```yaml
nodes:
  - name: edge
    protocol: vless
    address: edge.example.com:443
    login:
      uuid: 00000000-0000-0000-0000-000000000000
    secure:
      tls: true
      tls-settings:
        serverName: edge.example.com
        alpn: [h2]
        fingerprint: chrome
        pinnedPeerCertSha256: "64 位十六进制 SHA-256"
    transport:
      kind: xhttp
      xhttp:
        host: edge.example.com
        path: /api
        mode: packet-up
        xPaddingBytes: 100-1000
        xmux:
          maxConcurrency: 8-16
```

HTTP 版本由 TLS/REALITY 和 ALPN 决定：

- `http/1.1`：H1；
- `h2`：H2；
- `h3`：H3，必须启用 TLS；
- REALITY 使用其允许的 H2 路径。

`downloadSettings` 可以为 `stream-up` 或 `packet-up` 指定独立下载地址、TLS/REALITY 及独立 XHTTP 配置。`stream-one` 不允许独立下载端点。

## 服务端

`listen.xhttp` 可为单个对象或数组。服务端既支持 TLS TCP 上的 H1/H2，也支持 TLS QUIC 上的 H3：

```yaml
listen:
  xhttp:
    address: 0.0.0.0
    port: 443
    alpn: [h2, http/1.1, h3]
    tls:
      certificates:
        - certificateFile: /etc/wuther/fullchain.pem
          keyFile: /etc/wuther/private.key
          usage: encipherment
          ocspStapling: 3600
      minVersion: "1.2"
      maxVersion: "1.3"
      rejectUnknownSni: true
    target:
      host: 127.0.0.1
      port: 10000
    max-active-connections: 4096
    max-concurrent-streams: 128
    max-active-http-streams: 4096
    http-idle-timeout: 90s
    settings:
      path: /api
      mode: auto
```

没有 `target` 时，服务端只允许显式启用的本机安全用法；非回环裸转发必须明确设置 `allow-unauthenticated-non-loopback`。生产环境应配置 TLS、目标端认证协议及连接/流并发限制。

## XHTTP 字段

线协议字段均使用 Xray 的 camelCase 名称；WutherCore 同时接受相应的 kebab-case 与 snake_case 别名：

- 基础：`host`、`path`、`mode`、`headers`、`extra`；
- 填充：`xPaddingBytes`、`xPaddingObfsMode`、`xPaddingKey`、`xPaddingHeader`、`xPaddingPlacement`、`xPaddingMethod`；
- 上行：`uplinkHTTPMethod`、`uplinkDataPlacement`、`uplinkDataKey`、`uplinkChunkSize`；
- 会话：`sessionIDPlacement`、`sessionIDKey`、`sessionIDTable`、`sessionIDLength`、`seqPlacement`、`seqKey`；
- 响应：`noGRPCHeader`、`noSSEHeader`；
- 流控：`scMaxEachPostBytes`、`scMinPostsIntervalMs`、`scMaxBufferedPosts`、`scStreamUpServerSecs`、`serverMaxHeaderBytes`；
- 连接复用：`xmux.maxConcurrency`、`maxConnections`、`cMaxReuseTimes`、`hMaxRequestTimes`、`hMaxReusableSecs`、`hKeepAlivePeriod`；
- 独立下载：`downloadSettings`，含地址、端口、网络、安全、TLS、REALITY、套接字和嵌套 XHTTP 设置。

未知字段会被拒绝。互斥字段、非法范围、冲突的通用/嵌套地址，以及无法在所选模式执行的字段也会在启动前失败。

## TLS 与 ECH

TLS 配置完整注册：

- `certificates`：`certificateFile`/`certificate`、`keyFile`/`key`、`usage`、`ocspStapling`、`oneTimeLoading`、`buildChain`；
- `serverName`、`alpn`、`enableSessionResumption`、`disableSystemRoot`；
- `minVersion`、`maxVersion`、`cipherSuites`、`curvePreferences`；
- `fingerprint`、`rejectUnknownSni`、`masterKeyLog`；
- `pinnedPeerCertSha256`、`verifyPeerCertByName`；
- `echServerKeys`、`echConfigList`、`echSockopt`。

服务端支持静态证书、文件热更新、OCSP Stapling、`usage=verify` 的客户端证书校验、`usage=issue` 的按 SNI 动态签发，以及 ECH 服务端密钥。需要 TLS 1.0/1.1、ECH 服务端或仅 BoringSSL 支持的密码/曲线时会自动选择兼容后端；普通 TLS 1.2/1.3 使用 rustls。

客户端支持系统根、附加验证 CA、证书/CA SHA-256 固定、按名称验证、会话恢复、uTLS ClientHello 指纹、直接 ECHConfigList 或通过 DNS HTTPS/H2C/UDP 获取 ECH 配置。H3 的 QUIC TLS 不伪装成 TCP uTLS ClientHello。

Xray 26.7.11 已移除 `allowInsecure=true`；WutherCore 同样拒绝该值。需要私有 CA 时使用 `certificates[].usage=verify`，需要固定证书时使用 `pinnedPeerCertSha256`。

## 验证范围

互操作测试使用官方 Xray 26.7.11，覆盖：

- H1/H2/H3 双向连接；
- `stream-one`、`stream-up`、`packet-up`；
- 独立下载端点和流式关闭；
- TLS 默认 ALPN、ECH ClientHello、证书固定失败；
- Trojan 叠加 XHTTP 的 H1/H2/H3 全模式。
