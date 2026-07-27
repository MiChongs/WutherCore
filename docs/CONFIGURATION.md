# 配置指南

WutherCore 使用 `version: 1` YAML。配置先经过反序列化和 Profile 默认值，再编译为运行时计划；启动前可以用 `check` 与 `explain` 观察结果。

## 建议流程

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core run -c config.yaml
```

- `check`：检查字段、引用关系和运行计划是否可构建。
- `explain`：输出补全默认值后的 `RuntimePlan`。
- `run`：启动内核、入站、API 和可选流量接管。

配置错误时先修复 `check` 的第一条根因，不要直接用管理员权限反复启动。

## 顶层结构

| 字段 | 用途 |
| --- | --- |
| `version` | 配置格式版本，当前为 `1` |
| `profile` | `desktop`、`router`、`server` 或 `mobile` 默认值 |
| `name` | 配置显示名称 |
| `log` | 日志级别、过滤器和文件输出 |
| `listen` | Mixed 入站、管理面板、共享和认证 |
| `feeds` | 订阅源 |
| `nodes` | 手动节点 |
| `groups` | 节点选择策略 |
| `route` | 路由步骤、Preset、最终动作和规则集 |
| `resolver` | DNS、Fake IP、Hosts 与上游策略 |
| `capture` | TUN、TPROXY、REDIRECT 和排除项 |
| `smart` | 学习目标、周期、粘性和选择解释 |
| `ui` | 管理 API、密钥、Dashboard 与 CORS |
| `mesh` | Mesh 相关配置 |
| `find-process-mode` | `off`、`strict` 或 `always` 进程识别策略 |

## 选择 Profile

| Profile | 适合场景 |
| --- | --- |
| `desktop` | 本机 HTTP/SOCKS5，按需开启 TUN |
| `router` | 网关、透明代理和局域网流量 |
| `server` | 无桌面交互的服务进程 |
| `mobile` | Android 宿主或移动网络环境 |

Profile 只提供默认值；配置文件中显式填写的字段优先。升级版本后用 `explain` 比较最终计划，可以发现默认值变化。

## 节点来源与分组

```yaml
feeds:
  airport: "https://example.com/subscription"

nodes:
  - name: local-socks
    type: socks5
    server: 127.0.0.1
    port: 1080

groups:
  main:
    choose: smart
    use: [airport]
    prefer: ["HK", "SG"]
    avoid: ["expired"]
```

订阅地址和节点凭据属于敏感信息。不要提交真实配置、订阅缓存或完整节点 URI。

策略组可以从订阅和其他路径聚合节点，并通过 `prefer`、`avoid`、健康检查和粘性配置影响选择。修改后用 API 的 Smart 解释端点确认实际决策。

## 路由

```yaml
route:
  preset: cn_smart
  final: main
  steps:
    - domain-suffix: example.org
      action: direct
    - dst-port: 22
      action: main
```

路由可以匹配域名、IP、端口、进程和外部规则集。多个字段组合的语义应通过 `check`、`explain` 和 `/v1/route/check` 验证，不要只根据配置外观推测。

规则集可在 `route.sets` 中声明，并通过 `set:<name>` 引用。转换工具：

```bash
wuther-core ruleset convert input.yaml output.rrs
wuther-core ruleset convert input.json output.txt
```

## DNS

```yaml
resolver:
  mode: smart
  ipv6: true
  nameserver:
    - https://1.1.1.1/dns-query
  fallback:
    - tls://8.8.8.8
  listen: 127.0.0.1:1053
```

`resolver.listen` 会在同一地址启动 UDP 和 TCP DNS。启用 Fake IP 时，需要确保捕获路径能够把 Fake IP 反查回域名；排错时可先关闭 Fake IP，区分解析问题与路由问题。

## 流量接管

```yaml
capture:
  on: true
  method: tun
  stack: system
  mtu: 1500
```

建议顺序：

1. `capture.on: false` 验证 HTTP/SOCKS5。
2. 确认 DNS 和路由选择正确。
3. 使用管理员/root 权限启用 Capture。
4. 检查默认路由、排除网段和回环保护。
5. 停止进程，确认系统路由已经恢复。

Linux 的 TPROXY/REDIRECT、Android root 和网关模式还需要系统防火墙与转发能力。参考 [排错手册](TROUBLESHOOTING.md)。

## 管理 API

```yaml
listen:
  panel: 127.0.0.1:9090

ui:
  on: true
  secret: "replace-with-a-long-random-secret"
  api:
    native: true
    clash-compat: true
  cors:
    - "http://127.0.0.1:3000"
```

面板暴露到局域网前：

- 配置 `ui.secret`（**硬门禁**：`listen.share: home|all` 或非 loopback `listen.panel` 且 `ui.secret` 为空时，`check`/`run` 直接失败）；
- `profile: router` 默认 `share: home`，因此也必须显式填写 `ui.secret`；
- 将 `ui.cors` 限制为实际 Dashboard 来源；
- 不要在 URL、日志或截图中公开密钥；
- 用防火墙限制管理端口。

策略组 `choose: chain`（多跳 relay）尚未实现，配置编译期会拒绝，不会静默退化为单跳。

端点和鉴权方式见 [管理 API](API.md)。

## 迁移与升级

```bash
wuther-core migrate mihomo old.yaml -o config.yaml
wuther-core check config.yaml
wuther-core explain config.yaml
```

迁移输出是起点，不保证每个第三方扩展字段都能一一转换。重点检查：

- 节点协议和传输参数；
- 策略组引用；
- 规则顺序与最终动作；
- DNS/Fake IP 行为；
- TUN、路由表和排除项；
- Dashboard 密钥与监听地址。

