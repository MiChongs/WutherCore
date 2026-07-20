# 排错手册

先缩小问题范围，再修改系统网络。推荐从普通 HTTP/SOCKS5 开始，确认节点、DNS 与路由后再启用透明代理。

## 基线检查

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
```

开发版本再运行：

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

提交日志或配置前，删除订阅 URL、节点 URI、密码、UUID、PSK、私钥、访问密钥、个人域名/IP 和本地用户名路径。

## 内核无法启动

1. 用 `check` 确认配置引用和字段。
2. 检查 Mixed 端口、Panel 端口和 DNS 监听是否被占用。
3. 暂时关闭 `capture`，排除权限与系统路由问题。
4. 检查 Store 路径是否可写。
5. 查看第一条错误及其 cause chain，不要只看最后一行。

## HTTP/SOCKS5 可用，但 TUN 不通

- 确认以管理员/root 权限运行。
- 检查虚拟网卡是否成功创建。
- 检查默认路由、策略路由和排除网段。
- 暂停其他 VPN、加速器或会修改路由的安全软件。
- 关闭 Fake IP，判断是否是 Fake IP 回查链路。
- 停止 WutherCore 后确认路由和防火墙规则已经恢复。

Windows 重点检查 Wintun、接口索引和系统路由；Linux 重点检查 `ip rule`、路由表、iptables/nftables 与转发；Android 重点检查 VpnService FD 生命周期或 root 能力。

## 出现流量回环

典型表现是 CPU/流量快速上升、订阅拉取失败或连接不断建立。

- 确认出站 socket 绑定或保护逻辑生效。
- 将代理服务器 IP、管理端口、订阅和 DNS 上游加入必要的排除路径。
- 检查 TUN 接口是否被误识别为默认出口。
- 在 Android VpnService 中确认宿主对出站 socket 执行保护。

## DNS 失败

1. 直接测试上游 DNS 是否可达。
2. 检查 `resolver.ipv6`、Fallback 与 Policy。
3. 关闭 Fake IP 再测试。
4. 检查 `resolver.listen` 端口是否冲突。
5. 用 `/v1/resolver/query` 查看解析结果。
6. 对代理节点域名确认使用了合适的 bootstrap/direct nameserver。

只有部分域名失败时，优先检查规则顺序、Fallback Filter、Hosts 和 Fake IP Filter。

## 订阅或规则集刷新失败

```bash
wuther-core feeds refresh config.yaml
wuther-core ruleset refresh config.yaml
```

- 确认 URL、TLS 时间和系统证书。
- 检查订阅流量是否被自己的 TUN 再次捕获。
- 检查缓存目录权限。
- 对规则集使用 `ruleset convert` 验证输入能否单独解析。
- 不要把完整响应或订阅内容上传到公开 Issue。

## 节点能连接但没有数据

- 确认服务端协议版本、加密方式、SNI、ALPN 和传输参数。
- 区分 TCP 与 UDP；某些节点只实现或只启用了其中一种。
- 关闭复用、特殊传输或不安全兼容项，回到最小配置。
- 使用 IP 与域名分别测试，区分协议和 DNS 问题。
- 检查系统时间，TLS/QUIC/UUID 协议通常依赖正确时间。

## 路由结果不符合预期

- 用 `explain` 检查规则展开顺序。
- 用 `/v1/route/check` 输入同样的域名、IP、端口和进程信息。
- 确认 `find-process-mode` 已允许进程识别。
- 检查外部规则集是否刷新成功。
- 确认最终动作对应的策略组存在且含有可用节点。

## API 返回 401 或浏览器跨域失败

- 普通请求使用 `Authorization: Bearer` 或 `x-api-secret`。
- Query token 只用于 WebSocket/SSE。
- 将 Dashboard 的精确 Origin 加入 `ui.cors`。
- 检查 Panel 是否监听在预期地址。
- 反向代理后保留 Authorization 和 WebSocket Upgrade 头。

## 仍无法定位

提交 [Bug Report](https://github.com/MiChongs/WutherCore/issues/new?template=bug_report.yml)，包含：

- WutherCore 版本或 commit；
- 操作系统、架构、权限和接管方式；
- 已脱敏的最小配置；
- 可重复步骤和预期行为；
- 错误前后的脱敏日志；
- 已尝试的排查步骤。

安全漏洞请按照 [SECURITY.md](../SECURITY.md) 私下报告。

