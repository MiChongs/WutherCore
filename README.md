# WutherCore

WutherCore 是一个用 Rust 编写的代理内核。它读取 YAML 配置，负责订阅更新、节点选择、规则分流、DNS 解析和流量接管，并通过 HTTP API 暴露运行状态。

这个仓库只提供内核和命令行工具，不包含桌面或移动端 GUI。如果你想自己搭一套代理客户端、路由器网关，或者研究透明代理的实现，可以从这里开始。

[![Rust 1.85+](https://img.shields.io/badge/Rust-1.85%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Required CI](https://github.com/MiChongs/WutherCore/actions/workflows/ci.yml/badge.svg)](https://github.com/MiChongs/WutherCore/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> WutherCore 仍在开发中。现阶段更适合愿意阅读日志、自己维护配置的用户；稳定版之前，配置结构和 API 都可能调整。

[快速开始](#快速开始) · [配置示例](#配置) · [参与贡献](CONTRIBUTING.md) · [问题反馈](https://github.com/MiChongs/WutherCore/issues/new/choose) · [交流讨论](https://github.com/MiChongs/WutherCore/discussions)

## 能做什么

- 在同一个端口提供 HTTP 和 SOCKS5 代理。
- 从订阅或本地配置加载节点，并按名称、地区等条件过滤。
- 使用手动选择、负载均衡、URLTest 或 Smart 策略选取节点。
- 按域名、IP、端口、进程和外部规则集分流。
- 提供多上游 DNS、缓存、Fake IP 和 DNS 规则。
- 通过 TUN、TPROXY 或 REDIRECT 接管流量；具体方式取决于平台和权限。
- 保存节点评分、手动选择等运行状态，并通过 HTTP API 查看流量、连接和分组。

出站实现覆盖直连、HTTP、SOCKS5、Shadowsocks、Shadowsocks 2022、SSR、Snell、Trojan、VLESS、VMess、AnyTLS、Hysteria、Hysteria 2、TUIC、SSH、WireGuard、Mieru、Sudoku 和 TrustTunnel 等协议。不同协议的功能完整度并不完全一致，使用前建议先在自己的服务端环境中验证。

## 快速开始

需要 Rust 1.85 或更高版本。仓库中的 `rust-toolchain.toml` 默认使用 stable 工具链。

```bash
git clone https://github.com/MiChongs/WutherCore.git
cd WutherCore
cargo build --release -p wuther-core
```

先复制一份示例配置，并把其中的订阅地址或节点信息换成自己的：

```bash
cp examples/desktop.yaml config.yaml
```

检查配置：

```bash
./target/release/wuther-core check config.yaml
```

启动内核：

```bash
./target/release/wuther-core run -c config.yaml
```

Windows 下的可执行文件是 `target\release\wuther-core.exe`。

也可以跳过单独构建，直接通过 Cargo 运行：

```bash
cargo run --release -p wuther-core -- check config.yaml
cargo run --release -p wuther-core -- run -c config.yaml
```

## 配置

下面是一份桌面端配置的基本轮廓：

```yaml
version: 1
profile: desktop
name: my-profile

listen:
  local: 7890
  panel: 9090
  share: false

feeds:
  airport: "https://example.com/your-subscription"

groups:
  main:
    choose: smart
    use: [airport]

route:
  preset: cn_smart
  final: main

resolver:
  mode: smart
```

`profile` 用来提供一组场景默认值，目前有 `desktop`、`router` 和 `mobile`。配置文件中显式填写的字段会覆盖 profile 默认值。

仓库提供了几份可以直接修改的模板：

| 文件 | 用途 |
| --- | --- |
| [`examples/desktop.yaml`](examples/desktop.yaml) | 桌面端最小配置 |
| [`examples/router.yaml`](examples/router.yaml) | 路由器与透明代理 |
| [`examples/android.yaml`](examples/android.yaml) | Android VpnService |
| [`examples/with_feed.yaml`](examples/with_feed.yaml) | 订阅过滤和重命名 |
| [`examples/manual_only.yaml`](examples/manual_only.yaml) | 只使用手动节点 |
| [`examples/daily.yaml`](examples/daily.yaml) | 自定义分组和路由 |

配置项较多时，推荐用 `explain` 查看默认值补全后的运行计划：

```bash
wuther-core explain config.yaml
```

## 命令行

```text
wuther-core run -c <file>                         启动内核
wuther-core check <file>                          校验配置
wuther-core explain <file>                        输出编译后的 RuntimePlan
wuther-core migrate mihomo <input> -o <output>   迁移 Mihomo 配置
wuther-core feeds list <file>                     列出订阅
wuther-core feeds refresh <file>                  立即刷新订阅
wuther-core ruleset list <file>                   列出外部规则集
wuther-core ruleset refresh <file>                立即刷新外部规则集
wuther-core ruleset convert <input> <output>      转换规则集格式
wuther-core store info                            查看持久化存储
wuther-core store reset                           清空学习数据
```

每个子命令都可以通过 `--help` 查看完整参数。例如：

```bash
wuther-core ruleset convert --help
```

规则集转换支持 YAML、文本、sing-box JSON 和 WutherCore RRS 格式；输入格式通常可以自动识别，输出格式默认取决于文件扩展名。

## 入站、流量接管与 API

普通桌面使用只需要 `listen.local`，这个端口同时接受 HTTP 和 SOCKS5 请求。透明代理则通过 `capture` 配置启用：

- Windows：TUN
- Linux：TUN、TPROXY 或 REDIRECT
- macOS：TUN
- Android：root 模式或由宿主应用传入 VpnService 文件描述符

TUN 和系统路由修改通常需要管理员或 root 权限。建议先关闭 `capture`，确认普通代理和规则工作正常后，再配置透明代理。

启用 `ui` 后，`listen.panel` 会提供原生 `/v1` API，以及一组兼容 Clash 控制面板的接口。可以查询状态、流量、节点、分组和连接，也可以触发测速或修改分组选择。面板暴露到局域网前，请务必配置访问密钥并限制监听地址。

## 项目结构

WutherCore 使用 Cargo workspace 拆分各个模块：

| 目录 | 职责 |
| --- | --- |
| `crates/wuther-core` | 命令行入口和启动流程 |
| `crates/core-config` | YAML 加载、默认值和配置迁移 |
| `crates/core-inbound` | HTTP / SOCKS5 入站 |
| `crates/core-outbound` | 节点协议和传输层 |
| `crates/core-route` | 路由匹配与流量嗅探 |
| `crates/core-resolver` | DNS 解析、缓存和 Fake IP |
| `crates/core-capture` | TUN、TPROXY、REDIRECT 和平台适配 |
| `crates/core-feeds` / `core-ruleset` | 订阅与外部规则集 |
| `crates/core-runtime` / `core-smart` | 运行时编排和节点选择 |
| `crates/core-api` / `core-observe` | 管理 API、日志和连接观测 |
| `crates/core-store` | redb 持久化 |

更完整的实现说明见 [`RP内核设计文档.md`](RP内核设计文档.md)。

## 开发

常用命令：

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace
cargo build --release -p wuther-core
```

端到端测试位于 `tests-e2e`。构建脚本和交叉编译说明位于 [`scripts/README.md`](scripts/README.md)，编译配置说明见 [`docs/BUILD-PERF.md`](docs/BUILD-PERF.md)。

准备提交代码前，请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。其中说明了开发环境、测试范围、提交方式和 Pull Request 要求。

使用中遇到问题时，请根据类型选择 [Bug 报告或功能建议](https://github.com/MiChongs/WutherCore/issues/new/choose)；配置讨论和一般问题更适合放在 [Discussions](https://github.com/MiChongs/WutherCore/discussions)。安全问题不要公开提交 Issue，请按照 [`SECURITY.md`](SECURITY.md) 私下报告。

项目的维护方式、合并规则和紧急合并流程见 [`GOVERNANCE.md`](GOVERNANCE.md)。

## License

WutherCore 使用 [MIT License](LICENSE) 开源。
