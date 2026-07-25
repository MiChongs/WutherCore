# Shadowsocks 完整协议支持

WutherCore 的 Shadowsocks 客户端与服务端统一使用 `shadowsocks-rust 1.24.0`。TCP、UDP、经典流加密、AEAD、扩展 AEAD、Shadowsocks 2022（SIP022）以及 EIH 多用户验证共享同一套上游协议实现和重放保护。

## 客户端

节点可以来自 `ss://` SIP002 URI、订阅或手工节点。URI 查询参数支持 SIP003：

```text
ss://BASE64(method:password)@server.example:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example&plugin-mode=tcp_only#example
```

- `plugin`：插件可执行文件；分号后的内容作为插件选项。
- `plugin-opts` / `plugin_opts`：独立插件选项，优先于内联选项。
- `plugin-args` / `plugin_args`：JSON 字符串数组（或单个参数），作为独立命令行参数传给插件。
- `plugin-mode` / `plugin_mode`：`tcp_only`、`udp_only` 或 `tcp_and_udp`。

插件按 SIP003 环境变量规范作为受管子进程启动，首次连接会等待插件就绪。插件模式未覆盖请求的 TCP/UDP 载体时会明确报错，不会绕过插件直连。

启用的加密族包括经典 AES/Camellia/RC4/ChaCha20 流加密，AES-GCM 与 ChaCha20-IETF-Poly1305，AES-CCM、AES-GCM-SIV、XChaCha20、SM4 扩展 AEAD，以及全部 BLAKE3 Shadowsocks 2022 方法。具体名称以 `shadowsocks-rust 1.24.0` 接受的标准名称为准。2022 密码必须是长度匹配的 Base64；EIH 客户端身份链使用 SIP022 的冒号分隔格式。

## 服务端

`listen.shadowsocks` 接受单个对象或数组：

```yaml
version: 1
profile: server

listen:
  panel: false
  shadowsocks:
    - tag: ss-classic
      address: 0.0.0.0
      port: 8388
      method: aes-256-gcm
      password: replace-with-a-strong-password
      mode: tcp_and_udp
      handshake-timeout: 10s
      udp-timeout: 5m
      max-connections: 4096
      max-udp-associations: 4096

    - tag: ss-sip003
      address: 0.0.0.0
      port: 8443
      method: aes-256-gcm
      password: replace-with-a-strong-password
      mode: tcp_only
      plugin: v2ray-plugin
      plugin-opts: server;tls;host=cdn.example
      plugin-args: [--loglevel, warning]
      plugin-mode: tcp_only
      plugin-startup-timeout: 10s

    - tag: ss-2022-eih
      address: 0.0.0.0
      port: 8390
      method: 2022-blake3-aes-128-gcm
      password: MDEyMzQ1Njc4OWFiY2RlZg==
      mode: tcp_and_udp
      users:
        - name: alice
          key: YWJjZGVmZ2hpamtsbW5vcA==
```

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `true` | 是否启动 |
| `address` / `host` | `127.0.0.1` | 监听 IP |
| `port` | 必填 | TCP/UDP 端口，不能为 0 |
| `method` | 必填 | 标准 Shadowsocks 方法名 |
| `password` | 必填 | 密码或 2022 Base64 PSK/EIH 密钥链 |
| `mode` | `tcp_and_udp` | `tcp_only`、`udp_only` 或 `tcp_and_udp` |
| `plugin` | 未启用 | SIP003 服务端插件可执行文件 |
| `plugin-opts` / `plugin_opts` | 未设置 | 传入 `SS_PLUGIN_OPTIONS` 的插件选项 |
| `plugin-args` / `plugin_args` | `[]` | 直接传给插件进程的独立命令行参数 |
| `plugin-mode` / `plugin_mode` | 继承 `mode` | 插件载体模式；必须与监听模式一致 |
| `plugin-startup-timeout` / `plugin_startup_timeout` | `10s` | 受管插件和内部回环监听的启动上限 |
| `users` | `[]` | 仅 SIP022 EIH 使用的用户名称与 Base64 密钥 |
| `handshake-timeout` | `10s` | TCP 认证及目标头读取上限 |
| `udp-timeout` | `5m` | UDP 关联空闲回收时间 |
| `max-connections` | `4096` | 单监听 TCP 并发上限 |
| `max-udp-associations` | `4096` | 单监听 UDP 关联上限 |
| `tag` | 自动生成 | 路由与观测标签，必须唯一 |

未知字段会被拒绝。启动前会验证方法、密码/PSK、EIH 用户 Base64 与精确密钥长度、空或重复用户名、模式、插件字段依赖关系、插件/监听载体一致性、标签及按传输层区分的端口冲突。启用 SIP003 时，插件按服务端模式监听公开地址，Shadowsocks 解密服务只绑定插件分配的回环地址；插件进程由监听句柄托管并随关闭一并终止。`tcp_and_udp` 会先完成两个内部 socket 的预绑定再启动任务，任一绑定失败都会整体回滚。

## 运行与安全语义

- TCP 在解密并认证目标头后才进入统一入站路由。
- UDP 按客户端地址、SIP022 会话 ID 和目标地址隔离关联，并保留真实响应源地址。
- 监听级共享上下文让重放检测跨 TCP 连接和 UDP 数据包生效。
- 无效密文、错误密码、未知 EIH 用户及重放包会在进入路由前拒绝。
- TCP 连接、UDP 关联、单关联队列和空闲时间都有界；关闭会取消全部子任务。
- 客户端 UDP 复用运行时已施加 VPN protect、接口/mark 绑定和回环登记的原始 socket；独立密文缓冲保证较小的调用方明文缓冲不会被加密开销挤爆。
- mesh 预检会按模式分别声明 TCP/UDP 独占监听资源。

## Rust 版本

`shadowsocks-rust 1.24.0` 的 MSRV 为 Rust 1.88，本项目工作区的 `rust-version` 因此同步提升为 1.88；CI 与发布流程使用满足该下限的 stable 工具链。
