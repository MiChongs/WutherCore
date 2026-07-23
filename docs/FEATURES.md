# 功能矩阵

本页描述当前代码边界。WutherCore 仍在 1.0 之前；“已实现”表示存在对应代码路径，不等同于对所有服务端版本、传输组合和网络环境作出兼容承诺。

## 核心能力

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| Friendly YAML | 已实现 | Profile 默认值、显式覆盖、`check` 与 `explain` |
| Mixed 入站 | 已实现 | 一个监听端口同时接受 HTTP 和 SOCKS5 |
| 订阅管理 | 已实现 | 拉取、缓存、解析、过滤、重命名与去重 |
| 外部规则集 | 已实现 | Mihomo YAML/文本/MRS v1、sing-box JSON/SRS v1–v5、内联 Payload、RRS |
| 路由匹配 | 已实现 | 域名、IP、端口、进程、规则集与嗅探信息 |
| 策略组 | 已实现 | Manual、Load Balance、URLTest、Smart |
| DNS | 已实现 | 多上游、缓存、Hosts、Fallback、Fake IP、IPv6 策略 |
| 独立 DNS 服务 | 已实现 | 同一地址提供 UDP 与 TCP DNS |
| 透明代理 | 平台相关 | TUN、TPROXY、REDIRECT 与 Android VpnService |
| API | 已实现 | 原生 `/v1` 与 Clash/Mihomo 兼容接口 |
| 可观测性 | 已实现 | 日志、流量、连接、策略组和节点状态 |
| 持久化 | 已实现 | Smart 学习、手动选择、Pin 和节点历史 |
| 配置迁移 | 已实现 | Mihomo 配置迁移到 WutherCore YAML |

## 平台能力

| 平台 | HTTP / SOCKS5 | TUN | TPROXY | REDIRECT | 特殊接入 |
| --- | :---: | :---: | :---: | :---: | --- |
| Windows | 是 | 是 | — | — | Wintun 与系统路由 |
| Linux | 是 | 是 | 是 | 是 | 策略路由、iptables/nftables 环境 |
| macOS | 是 | 是 | — | — | 系统 TUN 与路由 |
| Android | 宿主决定 | 是 | root | root | VpnService 文件描述符 |

符号“—”表示该平台没有对应实现路径。透明代理通常需要管理员或 root 权限，并可能受防火墙、虚拟网卡和其他 VPN 软件影响。

## 出站实现

| 类别 | 协议或动作 | 说明 |
| --- | --- | --- |
| 内置动作 | Direct、Block、DNS Hijack | 直连、拒绝和 DNS 劫持 |
| 通用代理 | HTTP、SOCKS5 | 支持认证；UDP 能力由具体实现决定 |
| Shadowsocks | Shadowsocks、Shadowsocks 2022、SSR | 包含多种 AEAD/流加密与 SSR 组件 |
| 经典 TLS | Trojan、VLESS、VMess | 支持对应 TLS、UUID 与安全参数 |
| 现代隧道 | AnyTLS、Hysteria、Hysteria 2、TUIC | 包含 TLS/QUIC 路径与协议参数 |
| 专用协议 | Snell、Mieru、Sudoku、TrustTunnel | 按各自握手、加密和复用模型实现 |
| 系统隧道 | WireGuard、SSH | 密钥或主机校验需要单独配置 |

## 传输与解析

代码中包含 TCP、TLS、WebSocket、HTTP、HTTP/2、gRPC 与 XHTTP 等传输配置路径。可用组合由具体协议、节点字段和服务端实现共同决定；不要假设任意协议都能与任意传输组合。

节点来源支持：

- 配置文件中的手动节点；
- 订阅中的 URI；
- Mihomo/Clash 风格节点；
- 配置迁移生成的节点；
- 运行时订阅更新。

规则集运行时支持 Mihomo YAML/文本/MRS v1、sing-box JSON/SRS v1–v5 和 WutherCore RRS。二进制输入会先经过有界解压与结构校验，再编译为与文本规则共用的 matcher。

规则集索引还提供版本化的 destination-IP 前缀快照与 `watch` 更新通知：

- 一次读取多个规则集时共享同一 revision，重复名称按首次出现去重；
- 首次加载中的集合、首次加载失败、未知名称和合法的非 IP 集合具有不同状态；
- MRS 闭区间无损转换为最小 IPv4/IPv6 CIDR，转换有总量和分配保护；
- `Exact` 表示前缀与完整规则语义等价；`Extracted` 明确表示采用 sing-box `RuleSet.ExtractIPSet` 兼容投影，安全敏感的绕过/排除消费者可以拒绝；
- 内容相同的前缀替换不会产生伪 revision，慢消费者可以直接收敛到最新完整快照。

这是一项跨平台 provider 能力；把快照原子安装进 Linux nftables、策略路由或其他平台数据面仍由各 capture 后端分别完成。

## 已知边界

- 项目不包含桌面、Web 或移动端 GUI。
- 第三方协议可能随服务端演进；需要在实际服务端环境中验证。
- 透明代理依赖系统权限和外部网络状态，无法只靠单元测试覆盖。
- 当前配置与 API 尚未承诺 1.0 级别的长期稳定性。
- Android VpnService 需要宿主应用负责生命周期、权限申请和文件描述符传递。
- CodeQL 初始告警正在 [Issue #9](https://github.com/MiChongs/WutherCore/issues/9) 中逐条分类。

## 判断是否适合使用

如果只需要一个可直接点击使用的 GUI 客户端，这个仓库不是成品应用。如果需要嵌入式代理内核、透明代理网关、可编排的 Rust 网络组件，或希望研究协议与路由实现，WutherCore 提供了相应基础。

