# Snell 配置

WutherCore 实现 Snell v1–v5 的客户端与服务端。记录层与 Mihomo
`transport/snell` 对齐：v1 使用 ChaCha20-Poly1305，v2/v3 使用
AES-128-GCM，v4/v5 使用带自适应首帧填充的 v4 记录格式；各方向均以
16 字节随机盐和 Argon2id 派生独立密钥。

## 出站节点

Mihomo/Clash YAML 中支持以下字段：

```yaml
nodes:
  - name: snell-v5
    type: snell
    server: proxy.example.com
    port: 443
    psk: replace-with-a-strong-secret
    version: 5
    udp: true
    reuse: true
    obfs-opts:
      mode: tls
      host: cdn.example.com
```

| 字段 | 必填 | 说明 |
| --- | :---: | --- |
| `server`、`port` | 是 | Snell 服务端地址 |
| `psk` | 是 | 预共享密钥，不允许为空 |
| `version` | 否 | `1`–`5`，默认 `1` |
| `udp` | 否 | v3–v5 可用；v1/v2 配置为 `true` 会被拒绝 |
| `reuse` | 否 | v4/v5 显式开启；v2 按协议要求自动复用 |
| `obfs-opts.mode` | 否 | `http` 或 `tls` |
| `obfs-opts.host` | 否 | simple-obfs 伪装主机；省略时使用 `server` |

旧配置中的 `cipher` 仅作为一致性校验：v1 必须是
`chacha20-poly1305`，v2–v5 必须是 `aes-128-gcm`。算法由协议版本固定，
不能用该字段替换。

## 服务端监听

`listen.snell` 可写单个对象或数组。监听在主进程报告启动成功前完成
配置校验和 TCP 预绑定；任一监听失败时，同批已启动监听会被关闭。

```yaml
profile: server

listen:
  panel: false
  snell:
    - enabled: true
      address: 0.0.0.0
      port: 443
      psk: replace-with-a-strong-secret
      version: 5
      udp: true
      obfs-opts:
        mode: tls
        host: cdn.example.com
      handshake-timeout: 10s
      max-connections: 4096
      tag: public-snell
```

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 是否启动此监听 |
| `address` | `127.0.0.1` | TCP 绑定地址；也接受别名 `host` |
| `port` | 无 | 必须为 `1`–`65535` |
| `psk` | 无 | 必填预共享密钥 |
| `version` | `4` | `1`–`5` |
| `udp` | `false` | 启用 TCP 承载的 Snell UDP；仅 v3–v5 |
| `obfs-opts` | 无 | 与客户端相同的 HTTP/TLS simple-obfs |
| `handshake-timeout` | `10s` | 首个认证命令的读取期限，必须大于零 |
| `max-connections` | `4096` | 并发底层 TCP 连接上限，范围 `1`–`65535` |
| `tag` | `snell-N` | 入站名称；同一配置内必须唯一 |

UDP 关联支持同一 Snell 连接内最多 64 个目标，每个目标建立独立的运行时
路由、出站关联和连接计费。协议帧最大载荷为 `0x3fff` 字节，超过上限的
数据报会被拒绝，不会截断。

## 版本行为

| 版本 | 加密记录 | TCP | UDP | 顺序连接复用 |
| --- | --- | :---: | :---: | :---: |
| v1 | ChaCha20-Poly1305 | 是 | 否 | 否 |
| v2 | AES-128-GCM | 是 | 否 | 自动 |
| v3 | AES-128-GCM | 是 | 是 | 否 |
| v4 | AES-128-GCM + 填充 | 是 | 是 | `reuse: true` |
| v5 | v4 兼容记录 | 是 | 是 | `reuse: true` |

服务端的 TCP 与 UDP 都进入统一 `ListenerHandler`，因此会应用正常的域名
解析、路由规则、代理链、连接表与上下行计费。暴露到公网时请使用强随机
PSK，并配合系统防火墙限制来源。
