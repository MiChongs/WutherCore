# 管理 API

管理服务默认包含健康检查、原生 `/v1` API，以及可选的 Clash/Mihomo 兼容接口。实际监听地址来自 `listen.panel`，接口开关和密钥来自 `ui`。

## 启用

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

没有配置 `ui.secret` 时，API 不鉴权，**仅允许本机 loopback 监听**。  
`listen.share: home|all`、`0.0.0.0`/`::` 或其它非本机 `listen.panel` 且 `ui.secret` 为空时，配置编译会失败（`check`/`run` 拒绝启动）。暴露到局域网或容器网络时还必须配置 CORS allowlist。

## 鉴权

普通 API 请求支持：

```http
Authorization: Bearer <secret>
```

或：

```http
x-api-secret: <secret>
```

WebSocket/SSE 因浏览器协议限制，可使用 `?token=<secret>`。普通 GET/POST 不接受 query token，避免凭据进入访问日志和 Referer。

Clash 兼容 `GET /configs` 的 `authentication` 字段只返回用户名列表，不回传 Mixed 入站密码。  
`PUT /configs` 的 `mode`（`rule` / `global` / `direct`）会真正改变选路；`log-level` 更新运行时视图。  
`allow-lan` / `tun.enable` 不能热切换：值与启动配置不同时返回 `501`，避免 dashboard 假安全控制。

以下路径不要求密钥：

- `GET /`
- `GET /healthz`
- `/ui...` 静态 Dashboard 路径
- CORS `OPTIONS` 预检

认证失败统一返回 `401`：

```json
{"message":"Unauthorized"}
```

## 原生 `/v1` 端点

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/v1/status` | 运行状态与启动时间 |
| `GET` | `/v1/traffic` | 流量统计 |
| `GET` | `/v1/nodes` | 节点列表与状态 |
| `GET` | `/v1/groups` | 策略组列表 |
| `PATCH` | `/v1/groups/:name` | 修改策略组选择 |
| `GET` | `/v1/connections` | 当前连接 |
| `DELETE` | `/v1/connections/:id` | 关闭指定连接 |
| `GET` | `/v1/resolver/query` | 调试 DNS 查询 |
| `GET` | `/v1/route/check` | 调试路由结果 |
| `GET` | `/v1/capture/state` | 流量接管状态 |
| `GET` | `/v1/mesh/status` | 组网监督器、后端、动态附件、资源声明与冲突快照 |
| `GET` | `/v1/smart/why` | 查看 Smart 选择理由 |
| `POST` | `/v1/smart/pin` | 固定节点 |
| `POST` | `/v1/smart/avoid` | 临时回避节点 |
| `POST` | `/v1/smart/reset` | 重置 Smart 状态 |
| `GET` | `/v1/smart/cache` | 查看 Smart 缓存 |
| `GET` | `/v1/smart/nodes/:group` | 查看组内 Smart 节点 |

请求参数和响应结构在 1.0 前仍可能变化。集成时应保留未知字段，并对非 2xx 响应记录状态码和脱敏后的消息。

`/v1/mesh/status` 只返回监督器当前内存快照的安全公开投影：handler 调用 `MeshSupervisor::snapshot().public_view()`，不会执行 `probe`、`status` 或 `refresh`，不会访问外部 daemon、触发后端启停/隔离，也不会推进快照 generation。启动、停止和默认 5 秒一次的后台监控负责发布新的内部快照。

公开投影会解析 URL endpoint，只保留 scheme、host 和 port，删除 userinfo、path、query、fragment；非法 URL、Unix socket、named pipe 与 `Opaque` endpoint 只返回无 value 的 `hidden`。version 和所有自定义字符串有长度上限并清理控制字符；diagnostic 只公开 level、安全 code 和固定 message；资源声明与冲突均不公开 `coordination_key`。响应模型也没有命令环境或秘密文件字段。

主程序未注入组网监督器时，该端点明确返回 `503 mesh_supervisor_unavailable`，不会把“未初始化”误报成“所有后端正常”。当前基础设施阶段没有注册具体产品后端，因此 `statuses` 可以为空；capture 以及 DNS/Mixed/API 固定监听的 reservations 仍会正常出现在快照中。

## 示例

```bash
curl http://127.0.0.1:9090/healthz
```

```bash
curl \
  -H "Authorization: Bearer $WUTHERCORE_SECRET" \
  http://127.0.0.1:9090/v1/status
```

```bash
curl \
  -H "x-api-secret: $WUTHERCORE_SECRET" \
  "http://127.0.0.1:9090/v1/route/check?host=example.org&port=443"
```

不要把密钥直接写进 Shell 历史；上例建议通过环境变量提供。

## 兼容 API

`ui.api.clash-compat: true` 时，服务会合并 Clash/Mihomo 兼容路由，供现有 Dashboard 查询版本、配置、代理、规则、连接、日志与流量，并执行部分控制操作。

兼容目标是常见 Dashboard 工作流，不承诺实现上游项目的每个私有或实验接口。集成前应针对实际 Dashboard 版本执行冒烟测试。

## 服务端保护

API 层包含：

- CORS allowlist 与 Private Network Access 响应头；
- 按来源 IP 的请求限流；
- 请求体大小限制；
- 请求超时；
- 安全响应头；
- 常量时间密钥比较；
- WebSocket/SSE 的单独处理。

这些保护不代替反向代理、防火墙或网络隔离。

