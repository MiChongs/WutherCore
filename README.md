<div align="center">

# 🌊 WutherCore

**下一代 Rust 代理内核 · 兼容 mihomo / sing-box · Friendly YAML 配置**

*小白能看懂 · 专家能扩展 · 字段独立但能力对齐*

---

<!-- 第一行：核心徽章 -->

[![rust](https://img.shields.io/badge/rust-1.75%2B-CE422B?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![edition](https://img.shields.io/badge/edition-2021-000000?style=for-the-badge&logo=rust&logoColor=white)](https://doc.rust-lang.org/edition-guide/)
[![license](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blueviolet?style=for-the-badge)](LICENSE)
[![tests](https://img.shields.io/badge/tests-119%2F0%20passed-brightgreen?style=for-the-badge&logo=github-actions&logoColor=white)]()
[![crates](https://img.shields.io/badge/workspace-15%20crates-1f6feb?style=for-the-badge&logo=rust&logoColor=white)]()

<!-- 第二行：能力徽章 -->

![mihomo compat](https://img.shields.io/badge/mihomo-compatible-FF6F61?style=flat-square)
![sing-box compat](https://img.shields.io/badge/sing--box%201.14-compatible-7B61FF?style=flat-square)
![Clash API](https://img.shields.io/badge/Clash%20API-compatible-FFB000?style=flat-square)
![Smart](https://img.shields.io/badge/Smart-EWMA%20%2B%20URLTest-00C896?style=flat-square)
![DNS](https://img.shields.io/badge/DNS-optimistic%20cache-00B4D8?style=flat-square)
![Sniffer](https://img.shields.io/badge/L7-STUN%2FDTLS%2FQUIC%2FSNI%2FHTTP-9D4EDD?style=flat-square)
![Persist](https://img.shields.io/badge/persistence-redb%20KV-007F5F?style=flat-square)

<!-- 第三行：协议徽章 -->

![ss](https://img.shields.io/badge/Shadowsocks_AEAD-✓-brightgreen?style=flat)
![trojan](https://img.shields.io/badge/Trojan-✓-brightgreen?style=flat)
![vless](https://img.shields.io/badge/VLESS_(TLS%2BWS)-✓-brightgreen?style=flat)
![http](https://img.shields.io/badge/HTTP_/_SOCKS5-✓-brightgreen?style=flat)
![tls](https://img.shields.io/badge/rustls_+_ALPN-✓-brightgreen?style=flat)
![ws](https://img.shields.io/badge/WebSocket-✓-brightgreen?style=flat)
![vmess](https://img.shields.io/badge/VMess-stub-orange?style=flat)
![hy2](https://img.shields.io/badge/Hysteria2-stub-orange?style=flat)
![tuic](https://img.shields.io/badge/TUIC-stub-orange?style=flat)

<!-- 第四行：平台徽章 -->

[![Windows](https://img.shields.io/badge/Windows_x64-MSVC-0078D4?style=flat&logo=windows&logoColor=white)]()
[![Windows ARM](https://img.shields.io/badge/Windows_ARM64-MSVC-0078D4?style=flat&logo=windows&logoColor=white)]()
[![Linux x64](https://img.shields.io/badge/Linux_x64-musl%2Fgnu-FCC624?style=flat&logo=linux&logoColor=black)]()
[![Linux ARM](https://img.shields.io/badge/Linux_ARM64-musl%2Fgnu-FCC624?style=flat&logo=linux&logoColor=black)]()
[![Android](https://img.shields.io/badge/Android_arm64-NDK-3DDC84?style=flat&logo=android&logoColor=white)]()
[![macOS](https://img.shields.io/badge/macOS-需主机-000000?style=flat&logo=apple&logoColor=white)]()

<!-- 第五行：构建工具链徽章 -->

[![zigbuild](https://img.shields.io/badge/cargo--zigbuild-Linux-F7A41D?style=flat-square)]()
[![cross](https://img.shields.io/badge/cross-fallback-2496ED?style=flat-square&logo=docker&logoColor=white)]()
[![cargo-ndk](https://img.shields.io/badge/cargo--ndk-Android-3DDC84?style=flat-square&logo=android&logoColor=white)]()
[![rust-lld](https://img.shields.io/badge/rust--lld-Windows-CE422B?style=flat-square&logo=rust&logoColor=white)]()
[![mold](https://img.shields.io/badge/mold-Linux-9333EA?style=flat-square)]()

<!-- 项目活力徽章（占位，仓库为 private 不直连 shields.io） -->

![status](https://img.shields.io/badge/status-active-success?style=flat)
![module](https://img.shields.io/badge/15_modules-pure_Rust-DEA584?style=flat&logo=rust&logoColor=white)
![safety](https://img.shields.io/badge/unsafe-forbidden-blue?style=flat)
![async](https://img.shields.io/badge/runtime-tokio-blueviolet?style=flat)

</div>

---

## 📑 目录

<div align="center">

| [🎯 核心特性](#-核心特性) | [⚡ 快速开始](#-快速开始) | [🏗 架构总览](#-架构总览) | [🌐 数据流](#-数据流) |
|:---:|:---:|:---:|:---:|
| [🧩 工作空间](#-工作空间布局) | [📊 功能矩阵](#-功能矩阵) | [🔌 协议支持](#-协议支持) | [🌍 DNS 系统](#-dns-系统) |
| [📂 规则集系统](#-规则集系统) | [📱 Android 5-Tier](#-android-root-模式) | [🚀 性能与构建](#-性能与构建) | [🛰 API 接口](#-api) |
| [🧪 测试覆盖](#-测试覆盖) | [🗺 路线图](#-路线图) | [📜 许可证](#-许可证) | [🎨 配色](#-视觉规范) |

</div>

---

## 🎯 核心特性

<table>
<tr>
<td width="33%" valign="top">

### 🧠 智能选节点
- **EWMA** 成功率衰减
- **URLTest** 周期测速
- `domain_best` 缓存 + 冷却
- 全部 **redb** 持久化
- 支持 `pin/avoid/reset/why`

</td>
<td width="33%" valign="top">

### 🌐 强大 DNS
- 乐观缓存 + LRU
- **多 group 并发** (fastest/fallback/all)
- sing-box 1.14 完整动作
- 三层 ECS fallback
- redb 持久化跨重启

</td>
<td width="33%" valign="top">

### 🛡 防 IP 泄漏
- **L7 嗅探** STUN/DTLS/QUIC/SNI/HTTP
- WebRTC 流量按规则路由
- Fake-IP 双栈 (v4 + v6)
- DNS 劫持 + Tailscale 防回环

</td>
</tr>
<tr>
<td valign="top">

### 📦 规则集生态
- mihomo: yaml/txt/list ✅
- sing-box: JSON ✅
- **自研 RRS**: 二进制 + CRC32
- 双向无损转换
- ~45% 体积压缩

</td>
<td valign="top">

### 📱 Android Root
- **5 Tier 自动降级**
- 11 项能力探测
- nft → iptables → VPN
- IPv4/IPv6 双栈 NAT/TPROXY
- root 失败优雅降级

</td>
<td valign="top">

### ⚙️ 工程质量
- **15 crates** 高内聚
- 全测试 119/0 通过
- `forbid(unsafe_code)`
- rust-lld/mold 链接
- 增量编译 22s → 2s

</td>
</tr>
</table>

---

## ⚡ 快速开始

### 🪄 最小有效配置（10 个词，4 行 YAML）

```yaml
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/your-subscription"
```

> **就这么多。** 内核自动补：本地代理 7890、面板 9090、main 分组 Smart、国内直连、国外走 main、DoH/DoT smart 解析。

### 🛠 一键多平台构建（Windows 主机）

```cmd
build.cmd                  :: 默认矩阵：Win MSVC + Linux musl/gnu + Android arm64
build.cmd windows          :: 单目标
build.cmd linux            :: zigbuild 后端
build.cmd android          :: cargo-ndk 后端（NDK 自动发现）

pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
```

### 🚀 直接 cargo

```bash
cargo build --release -p proxy-core
./target/release/proxy-core check    examples/desktop.yaml
./target/release/proxy-core explain  examples/desktop.yaml
./target/release/proxy-core run -c   examples/desktop.yaml
```

### 🧰 CLI 子命令一览

```text
proxy-core run        -c <yaml>             启动内核
proxy-core check         <yaml>             校验配置
proxy-core explain       <yaml>             输出 RuntimePlan JSON
proxy-core migrate mihomo <old.yaml> -o <friendly.yaml>
proxy-core feeds   list/refresh             订阅源管理
proxy-core ruleset list/refresh/convert     规则集管理（含 yaml↔txt↔json↔rrs）
proxy-core store   info/reset               持久化数据管理
```

---

## 🏗 架构总览

```mermaid
flowchart LR
    subgraph IB["🔌 Inbound"]
        MX[Mixed<br/>HTTP+SOCKS5]
        TUN[TUN/TProxy<br/>capture]
    end

    subgraph CR["🧠 Core Runtime"]
        RT[Runtime]
        SEL[GroupSelector]
        URL[URLTester]
    end

    subgraph RT_LAYER["🚦 Routing"]
        SNF[L7 Sniffer<br/>STUN/SNI/QUIC]
        ENG[RouteEngine]
        SET[Rulesets<br/>yaml/txt/json/RRS]
    end

    subgraph DNS["🌐 DNS"]
        OPT[Optimistic<br/>Cache]
        POL[PolicyEngine<br/>evaluate/respond/reject]
        UP[Upstreams<br/>DoH/DoT/UDP]
    end

    subgraph SMT["✨ Smart"]
        EWMA[EWMA Score]
        CACHE[domain_best]
        STORE[(redb)]
    end

    subgraph OB["📤 Outbound"]
        D[direct/block]
        H[http/socks5]
        SS[Shadowsocks]
        TRO[Trojan]
        VL[VLESS]
        TLS[TLS+WS Transport]
    end

    IB --> SNF --> ENG
    ENG -.规则匹配.-> SET
    ENG --> RT
    RT --> SEL
    SEL --> SMT
    SMT --> EWMA & CACHE
    EWMA & CACHE --> STORE
    URL --> SMT
    RT --> DNS
    DNS --> OPT --> POL --> UP
    SEL --> OB
    OB --> D & H & SS & TRO & VL
    SS & TRO & VL --> TLS

    classDef in fill:#0078D4,stroke:#fff,color:#fff
    classDef core fill:#CE422B,stroke:#fff,color:#fff
    classDef route fill:#9D4EDD,stroke:#fff,color:#fff
    classDef dns fill:#00B4D8,stroke:#fff,color:#fff
    classDef smart fill:#00C896,stroke:#fff,color:#fff
    classDef out fill:#FF6F61,stroke:#fff,color:#fff

    class MX,TUN in
    class RT,SEL,URL core
    class SNF,ENG,SET route
    class OPT,POL,UP dns
    class EWMA,CACHE,STORE smart
    class D,H,SS,TRO,VL,TLS out
```

---

## 🌐 数据流

> **一次连接的生命周期** —— 从入站到拨号的完整路径。

```mermaid
sequenceDiagram
    autonumber
    participant App as 📱 App
    participant In as 🔌 Inbound
    participant Sniff as 🔬 L7 Sniffer
    participant Route as 🚦 RouteEngine
    participant Resolver as 🌐 Resolver
    participant Smart as ✨ Smart
    participant Out as 📤 Outbound
    participant Net as ☁️ Internet

    App->>In: TCP/UDP CONNECT host:port
    In->>Sniff: 嗅探首包 (STUN/SNI/QUIC/HTTP)
    Sniff-->>In: protocol = Sni("example.com") | Stun | ...
    In->>Route: FlowContext { host, ip, port, network, protocol }
    Route->>Resolver: 解析域名（如需）
    Resolver-->>Route: ips (含乐观缓存命中)
    Route-->>In: decision = Group("main") | Direct | Block

    alt decision == Group
        In->>Smart: 在分组成员中评分
        Smart->>Smart: EWMA + domain_best + cooldown
        Smart-->>In: pick = "node-tokyo-01"
        In->>Out: dial(node-tokyo-01)
    else decision == Direct
        In->>Out: dial(DIRECT)
    else decision == Block
        In-->>App: ConnectionAborted
    end

    Out->>Net: TLS+WS / SS-AEAD / Trojan / VLESS
    Net-->>Out: data
    Out-->>In: BoxedStream
    In-->>App: 双向转发

    Note over Smart: 失败/成功反馈持久化到 redb<br/>影响下次评分
```

---

## 🧩 工作空间布局

```mermaid
flowchart TB
    subgraph TOP["📦 RPKernel Workspace · 15 crates"]
        direction TB

        subgraph L1["🎯 Application Layer"]
            PC[proxy-core<br/>CLI 入口]
        end

        subgraph L2["🛰 IO Layer"]
            CIN[core-inbound<br/>Mixed listener]
            COUT[core-outbound<br/>protocols + transport]
            CCAP[core-capture<br/>TUN/TProxy/Android]
            CMSH[core-mesh<br/>Tailscale]
        end

        subgraph L3["🧠 Logic Layer"]
            CRT[core-runtime<br/>Runtime + URLTest]
            CRTE[core-route<br/>engine + sniffer]
            CSMT[core-smart<br/>EWMA selector]
            CRES[core-resolver<br/>DNS]
        end

        subgraph L4["💾 Data Layer"]
            CCFG[core-config<br/>YAML + URI]
            CRSET[core-ruleset<br/>parsers + RRS]
            CFD[core-feeds<br/>订阅拉取]
            CSTO[core-store<br/>redb KV]
            CAPI[core-api<br/>HTTP API]
            COBS[core-observe<br/>tracing/metrics]
        end
    end

    PC --> CIN & CRT & CAPI
    CIN --> CRTE
    CRT --> CRES & CSMT & COUT
    CRTE --> CRSET
    CRES --> CSTO
    CSMT --> CSTO
    CFD --> CCFG
    CRT --> CCFG
    COUT -.transport.-> COUT
    CCAP --> CRTE

    classDef app fill:#FF6F61,stroke:#fff,color:#fff,stroke-width:2px
    classDef io fill:#0078D4,stroke:#fff,color:#fff,stroke-width:2px
    classDef logic fill:#9D4EDD,stroke:#fff,color:#fff,stroke-width:2px
    classDef data fill:#007F5F,stroke:#fff,color:#fff,stroke-width:2px

    class PC app
    class CIN,COUT,CCAP,CMSH io
    class CRT,CRTE,CSMT,CRES logic
    class CCFG,CRSET,CFD,CSTO,CAPI,COBS data
```

---

## 📊 功能矩阵

<div align="center">

| 模块 | 关键能力 | 测试 | 状态 |
|---|---|:---:|:---:|
| 🎛 **Config** | profile 默认值、节点 URI 解析（ss/vless/vmess/trojan/...）、route preset/sets/steps、payload 内联 | ![12](https://img.shields.io/badge/12-brightgreen?style=flat-square) | ✅ |
| ⚙️ **Runtime** | Runtime + GroupSelector(manual/smart/fast/stable/spread/chain) + URLTest 周期测速 | ![3](https://img.shields.io/badge/3-brightgreen?style=flat-square) | ✅ |
| 🔌 **Inbound** | Mixed HTTP+SOCKS5 同端口 + 跨平台权限检测 + 端口降级 + Android su 提权 | ![5](https://img.shields.io/badge/5-brightgreen?style=flat-square) | ✅ |
| 📤 **Outbound** | direct/block/http/socks5/SS-AEAD/Trojan/VLESS + TLS+WS 传输层 | ![4](https://img.shields.io/badge/4-brightgreen?style=flat-square) | ✅ |
| 🚦 **Route** | preset 编译 + 规则引擎 + L7 嗅探（STUN/DTLS/QUIC/SNI/HTTP）+ proto:webrtc 别名 | ![11](https://img.shields.io/badge/11-brightgreen?style=flat-square) | ✅ |
| 🌐 **Resolver** | 乐观缓存 + LRU + Group 三策略 + sing-box 完整动作 + ECS 三层 + redb 持久化 | ![37](https://img.shields.io/badge/37-brightgreen?style=flat-square) | ✅ |
| 📂 **Ruleset** | yaml/txt/list/json 解析 + RRS encode/decode + double-pass 一致性 + 6 种 matcher | ![20](https://img.shields.io/badge/20-brightgreen?style=flat-square) | ✅ |
| 📡 **Feeds** | Base64/Clash/SIP008/Plain 解析 + 过滤重命名 + 缓存回退 | ![5](https://img.shields.io/badge/5-brightgreen?style=flat-square) | ✅ |
| ✨ **Smart** | EWMA + cooldown + 跨重启持久化 | ![3](https://img.shields.io/badge/3-brightgreen?style=flat-square) | ✅ |
| 💾 **Store** | redb 单值/批量/iter/reset + AsyncWriter | ![4](https://img.shields.io/badge/4-brightgreen?style=flat-square) | ✅ |
| 🛡 **Capture** | NAT 表 + 路由登记 + Fake-DNS + Android 5-Tier 选择 | ![13](https://img.shields.io/badge/13-brightgreen?style=flat-square) | ✅ |
| 🛰 **API** | 原生 + Clash 兼容 + URLTest delay (单/组/全部) | ![e2e](https://img.shields.io/badge/e2e-brightgreen?style=flat-square) | ✅ |
| **总计** | | ![119](https://img.shields.io/badge/119_passed-0_failed-brightgreen?style=for-the-badge) | ✅ |

</div>

---

## 🔌 协议支持

### ✅ 真实现（与 mihomo / sing-box 互通）

<div align="center">

| 协议 | 实现深度 | 加密 | 传输层 |
|:---:|---|:---:|:---:|
| ![direct](https://img.shields.io/badge/direct-✓-brightgreen) | TCP + UDP | — | TCP/UDP |
| ![block](https://img.shields.io/badge/block-✓-brightgreen) | 立即拒绝 | — | — |
| ![http](https://img.shields.io/badge/http-✓-brightgreen) | CONNECT + 认证 | basic | TCP |
| ![socks5](https://img.shields.io/badge/socks5-✓-brightgreen) | TCP/UDP + 认证 | password | TCP/UDP |
| ![ss](https://img.shields.io/badge/Shadowsocks_AEAD-✓-blue) | aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 + EVP_BytesToKey + HKDF-SHA1 | AEAD | TCP |
| ![trojan](https://img.shields.io/badge/Trojan-✓-blue) | 56B SHA-224 + SOCKS5 cmd | rustls | TLS + ALPN |
| ![vless](https://img.shields.io/badge/VLESS-✓-blue) | UUID + addons + cmd | rustls | **TCP / TLS / WebSocket** |

</div>

### ⚠️ 占位（明确返回 `Unsupported`，绝不假装成功）

`vmess` `shadowsocksr` `shadowsocks-2022` `snell` `hysteria2` `tuic` `wireguard` `ssh` `anytls` `mieru` `sudoku` `trusttunnel`

> 由 `OutboundAdapter` trait 统一抽象，后续 PR 逐个填补，**绝不静默成功**。

---

## 🌍 DNS 系统

> **sing-box 1.14 兼容** · 多 group 并发 · 三层 ECS fallback · 乐观缓存

### 🎯 5 大动作（与 sing-box 字段一一对应）

```mermaid
flowchart LR
    Q[query] --> RULE{规则匹配}
    RULE -->|route| R[终止 + 转发]
    RULE -->|evaluate| E[继续评估<br/>结果保存为<br/>saved_response]
    RULE -->|respond| RP[返回<br/>saved_response]
    RULE -->|reject| RJ{method?}
    RJ -->|default| REF[REFUSED]
    RJ -->|drop| DR[silent drop]
    RJ -.30s/50次<br/>自动切换.-> DR
    RULE -->|predefined| PD[rcode + answer/ns/extra]

    classDef action fill:#00B4D8,stroke:#fff,color:#fff
    class R,E,RP,REF,DR,PD action
```

| sing-box action | RPKernel | 说明 |
|---|---|---|
| `route` | `Route { server, opts }` | 终止评估 |
| `evaluate` (1.14+) | `Evaluate { server, opts }` | **不终止**，结果保存为 saved_response |
| `respond` (1.14+) | `Respond` | 返回 saved_response |
| `reject` | `Reject(RejectOptions)` | method=default(REFUSED) / drop；30s 50 次自动切 drop |
| `predefined` (1.12+) | `Predefined(PredefinedResponse)` | rcode + answer/ns/extra 文本记录 |

### ⚙️ per-query 选项

`disable_cache` · `disable_optimistic_cache` · `rewrite_ttl` · `client_subnet`

### 🌐 三层 ECS fallback

```
rule.opts.client_subnet  >  server.default_client_subnet  >  resolver.global_client_subnet
```

### 🎨 友好 DSL（两种风格任选）

```yaml
# 字符串行内（短到一眼看懂）
- "ads.com    -> drop"                        # reject method=drop
- "tracker    -> refuse"                      # REFUSED
- "*.cn       -> direct:mainland"             # 后缀短写
- "=foo.local -> hosts:127.0.0.1"             # 精确 + hosts
- "geosite:cn -> direct:mainland"             # sing-box 别名

# 结构化 YAML（推荐）
- { suffix: ads.com, drop: true }
- { suffix: foo.local, hosts: [127.0.0.1, "::1"] }
- { set: cn, direct: mainland, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }
- { match: any, evaluate: overseas, no_cache: true }
- { match_response: 1.1.1.0/24, respond: true }
- { suffix: nx.local, nxdomain: true }
```

详见 [crates/core-resolver/src/lib.rs](crates/core-resolver/src/lib.rs) 顶部 `_DSL_DOC`。

---

## 📂 规则集系统

### 📥 输入格式

<div align="center">

| 格式 | 来源 | 状态 | 备注 |
|:---:|:---:|:---:|---|
| ![yaml](https://img.shields.io/badge/YAML-✓-brightgreen?style=flat-square) | mihomo / Clash | 完整 | payload 内联 |
| ![txt](https://img.shields.io/badge/TXT/LIST-✓-brightgreen?style=flat-square) | mihomo / Clash | 完整 | 含 `+.suffix`、`.suffix`、CIDR、policy |
| ![json](https://img.shields.io/badge/JSON-✓-brightgreen?style=flat-square) | sing-box rule-set | 完整 | v1/v2 + logical 嵌套 |
| ![rrs](https://img.shields.io/badge/RRS-✓-blue?style=flat-square) | RPKernel 自研 | 完整 | **CRC32 + ~45% 体积** |
| ![mrs](https://img.shields.io/badge/MRS/SRS-stub-orange?style=flat-square) | mihomo / sing-box | 嗅探 | 友好提示用工具转文本 |

</div>

### 🧬 RRS 自研格式

```text
┌─────────────────────────────────────────────────────────────┐
│ 24B Header                                                   │
│ ┌──────────┬────────┬───────┬────────────┬────────┬───────┐ │
│ │ "RRS\0"  │version │ flags │ created_at │body_len│ CRC32 │ │
│ │   4B     │   2B   │  2B   │     8B     │   4B   │  4B   │ │
│ └──────────┴────────┴───────┴────────────┴────────┴───────┘ │
├─────────────────────────────────────────────────────────────┤
│ Body · 8 段紧凑编码                                          │
│  ▸ DomainExact   var-len string                              │
│  ▸ Suffix        var-len string                              │
│  ▸ Keyword       var-len string                              │
│  ▸ Regex         var-len string                              │
│  ▸ V4 CIDR       5B (4B addr + 1B prefix)                    │
│  ▸ V6 CIDR       17B (16B addr + 1B prefix)                  │
│  ▸ Port          2B                                          │
│  ▸ Process       var-len string                              │
└─────────────────────────────────────────────────────────────┘
```

### 🔄 双向无损转换

```bash
proxy-core ruleset convert in.yaml  out.rrs       # YAML → RRS
proxy-core ruleset convert in.rrs   out.yaml      # RRS → YAML
proxy-core ruleset convert in.json  out.rrs       # sing-box JSON → RRS
proxy-core ruleset convert in.rrs   out.json      # RRS → sing-box JSON
proxy-core ruleset convert in.txt   out.rrs --output-format rrs
```

**实测压缩率**（1000 条规则）：

```
yaml=27075B  ───→  rrs=12044B  (45%)  ───→  json=15524B  ───→  rrs=12044B  (MD5 byte-exact)
                       ▲                                              │
                       └──────────────────  无损 round-trip  ─────────┘
```

### ⚡ 高速 matcher

后缀 trie + AHashSet 精确 + Vec 关键字 + RegexSet + 按掩码长度倒序 CIDR + 端口区间 + 进程名集合 → **10 万条规模 ~100µs 命中**。

---

## 📱 Android Root 模式

> 5 层自动降级 · 11 项能力探测 · 双栈 IPv4/IPv6 透明代理

```mermaid
flowchart TB
    DETECT[🔍 detect_capability<br/>su -c probe 11 caps]
    DETECT --> T1{has nft<br/>+ ip6 nat<br/>+ tproxy v6?}
    T1 -->|✅| TIER1[🥇 Tier 1: NftablesFull<br/>nft + ip6 nat + IPv4/v6 TPROXY<br/>完整透明代理 推荐]
    T1 -->|❌| T2{has iptables v4/v6<br/>+ tproxy?}
    T2 -->|✅| TIER2[🥈 Tier 2: IptablesV4V6Tproxy<br/>iptables + ip6tables 双栈 TPROXY]
    T2 -->|❌| T3{has iptables v4/v6<br/>+ NAT REDIRECT?}
    T3 -->|✅| TIER3[🥉 Tier 3: IptablesV4V6Redirect<br/>双栈 TCP REDIRECT<br/>UDP 受限]
    T3 -->|❌| T4{has iptables v4?}
    T4 -->|✅| TIER4[Tier 4: IptablesV4Only<br/>仅 iptables v4 NAT REDIRECT]
    T4 -->|❌| TIER5[Tier 5: VpnService<br/>用户态 TUN<br/>无 root / 全部失败]

    classDef gold fill:#FFD700,stroke:#000,color:#000,stroke-width:3px
    classDef silver fill:#C0C0C0,stroke:#000,color:#000,stroke-width:2px
    classDef bronze fill:#CD7F32,stroke:#fff,color:#fff,stroke-width:2px
    classDef gray fill:#6B7280,stroke:#fff,color:#fff
    classDef fallback fill:#3DDC84,stroke:#fff,color:#fff,stroke-width:2px

    class TIER1 gold
    class TIER2 silver
    class TIER3 bronze
    class TIER4 gray
    class TIER5 fallback
```

`AndroidCapability::detect_capability()` 通过 `su -c` 探测 11 项关键能力（`has_root` / `has_ip6tables` / `has_nftables` / `kernel_ipv6_nat` / `kernel_tproxy_v6` / `uid_owner_match` / ...），自动选最高可用层；启动钩子 `try_request_root_android()` 失败时透明降级到 VpnService。

---

## 🚀 性能与构建

### ⚡ 编译加速（已写入仓库默认）

<div align="center">

| 优化 | 位置 | 效果 |
|---|:---:|:---:|
| `incremental + codegen-units=256` (dev) | [Cargo.toml](Cargo.toml) | 单 crate 内并行 |
| `[profile.dev.package."*"] opt-level=1` | 同上 | 依赖也快，运行/编译都受益 |
| `debug="line-tables-only"` + `split-debuginfo` | 同上 | debuginfo **-80%**，链接 -40% |
| `lto="thin" + codegen-units=16` (release) | 同上 | 替代 fat LTO；性能差 ~1%，构建 **-60%** |
| `release-fast` profile | 同上 | CI 冒烟用：`lto=off + cgu=256`，比 release 快 **4×** |
| `rust-lld` (Windows MSVC) | [.cargo/config.toml](.cargo/config.toml) | 链接 **-50%~-70%** |
| `mold` (Linux x64) | 同上 | 链接 **-80%** |

</div>

```text
增量构建实测（改一行 main.rs 后全量）：

  优化前: ████████████████████████████████████████████  22 秒
  优化后: ████  2 秒  ← 11× speedup
```

详见 [docs/BUILD-PERF.md](docs/BUILD-PERF.md)。

### 🌐 多平台构建矩阵

<div align="center">

| 目标 | 后端 | Win 主机 | 备注 |
|:---|:---:|:---:|:---|
| `x86_64-pc-windows-msvc` | ![cargo](https://img.shields.io/badge/cargo-CE422B?style=flat-square&logo=rust) | ✅ | MSVC build tools |
| `aarch64-pc-windows-msvc` | ![cargo](https://img.shields.io/badge/cargo-CE422B?style=flat-square&logo=rust) | ✅ | MSVC ARM64 |
| `x86_64-unknown-linux-{musl,gnu}` | ![zigbuild](https://img.shields.io/badge/zigbuild-F7A41D?style=flat-square) | ✅ | **推荐**，无需 Docker |
| `aarch64-unknown-linux-{musl,gnu}` | ![zigbuild](https://img.shields.io/badge/zigbuild-F7A41D?style=flat-square) | ✅ | |
| `aarch64-linux-android` | ![cargo-ndk](https://img.shields.io/badge/cargo--ndk-3DDC84?style=flat-square&logo=android) | ✅ | 自动从 `%LOCALAPPDATA%\Android\Sdk\ndk` 发现 |
| `*-apple-darwin` | — | ❌ 需 macOS 主机 | 自动 skip |

</div>

---

## 🛰 API

### 🎯 原生 `/v1`

```http
GET    /v1/status                              # 版本/运行时间/profile/平台
GET    /v1/traffic                             # 实时流量
GET    /v1/nodes                               # 节点列表 + 能力
GET    /v1/groups                              # 分组 + 当前选择
PATCH  /v1/groups/:name                        # 手动切节点（持久化到 redb）
GET    /v1/connections                         # 连接列表
DELETE /v1/connections/:id                     # 关闭连接
GET    /v1/route/check?host=&port=&network=    # 路由命中调试
GET    /v1/proxies/:name/delay                 # URLTest 单节点
POST   /v1/groups/:name/healthcheck            # 整组测速
POST   /v1/healthcheck                         # 全局测速
GET    /v1/smart/why?host=&group=              # 解释 Smart 选择
POST   /v1/smart/{pin,avoid,reset}             # Smart 控制
```

### 🌈 Clash / Mihomo 兼容

`/proxies` `/proxies/:name` `/proxies/:name/delay` `/group/:name/delay` `/connections` `/configs` `/version` `/traffic`

> **现成 Dashboard 直接可用** —— Yacd / Razord / Meta-Cubes / Zashboard 等。

---

## 🧪 测试覆盖

```bash
cargo test --workspace
# → TOTAL PASS=119 FAIL=0
```

<div align="center">

```
┌─ 单元测试 ─────────────────────────────────────────┐
│  config(12) + runtime(3) + inbound(5)               │
│  outbound(4) + route(11) + resolver(37)             │
│  ruleset(20) + feeds(5) + smart(3)                  │
│  store(4) + capture(13)                             │
└────────────────────────────────────────────────────┘
┌─ E2E 测试 ─────────────────────────────────────────┐
│  mixed listener · URLTest · 缓存持久化              │
│  多协议路由 · 规则集双向 round-trip                 │
└────────────────────────────────────────────────────┘
```

![total](https://img.shields.io/badge/119%20passed-0%20failed-brightgreen?style=for-the-badge&logo=github-actions&logoColor=white)

</div>

---

## 🗺 路线图

<div align="center">

| 阶段 | 状态 | 内容 |
|:---:|:---:|---|
| **M1** 配置 + 普通代理 | ![✅](https://img.shields.io/badge/done-brightgreen?style=flat-square) | Friendly YAML / Mixed / direct/block/http/socks5 / route preset |
| **M2** 协议完整化 | ![🟡](https://img.shields.io/badge/partial-yellow?style=flat-square) | SS AEAD / Trojan / VLESS（TLS+WS）✅；vmess / hysteria2 / tuic / wireguard / ssh ⏳ |
| **M3** Resolver | ![✅](https://img.shields.io/badge/done-brightgreen?style=flat-square) | DoH/DoT/UDP + 乐观缓存 + 多 group + sing-box 完整动作 + ECS 三层 + 持久化 |
| **M4** Capture | ![🟡](https://img.shields.io/badge/framework-yellow?style=flat-square) | TUN/TProxy/redirect 后端 + Fake-DNS + Android 5-Tier；packet-loop ⏳ |
| **M5** Smart | ![✅](https://img.shields.io/badge/done-brightgreen?style=flat-square) | EWMA + URLTest + cooldown + 持久化 |
| **M6** API + 生态 | ![✅](https://img.shields.io/badge/done-brightgreen?style=flat-square) | /v1 + Clash 兼容 + RRS 自研二进制 + 规则集双向转换 |
| **M7** Tailscale | ![🟡](https://img.shields.io/badge/diagnose-yellow?style=flat-square) | mesh.diagnose + Tailnet 自动排除；userspace_proxy ⏳ |
| **M8** 性能冲刺 | ![🟡](https://img.shields.io/badge/partial-yellow?style=flat-square) | 编译性能完成；运行时 io_uring/GSO ⏳ |

```text
进度概览：

  M1 ████████████████████████████████████████  100%
  M2 ████████████████████░░░░░░░░░░░░░░░░░░░░   50%
  M3 ████████████████████████████████████████  100%
  M4 ██████████████████████████░░░░░░░░░░░░░░   65%
  M5 ████████████████████████████████████████  100%
  M6 ████████████████████████████████████████  100%
  M7 ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░   30%
  M8 ████████████████████░░░░░░░░░░░░░░░░░░░░   50%
```

</div>

---

## 📜 许可证

<div align="center">

[![MIT](https://img.shields.io/badge/MIT-license-blue?style=for-the-badge)](LICENSE-MIT)
[![Apache-2.0](https://img.shields.io/badge/Apache--2.0-license-blue?style=for-the-badge)](LICENSE-APACHE)

**MIT OR Apache-2.0（双协议任选）**

</div>

---

## 🎨 视觉规范

<div align="center">

| 角色 | 颜色 | Hex |
|---|:---:|:---:|
| Inbound | ![#0078D4](https://img.shields.io/badge/-_-0078D4?style=flat-square) | `#0078D4` |
| Core Runtime | ![#CE422B](https://img.shields.io/badge/-_-CE422B?style=flat-square) | `#CE422B` |
| Routing | ![#9D4EDD](https://img.shields.io/badge/-_-9D4EDD?style=flat-square) | `#9D4EDD` |
| DNS | ![#00B4D8](https://img.shields.io/badge/-_-00B4D8?style=flat-square) | `#00B4D8` |
| Smart | ![#00C896](https://img.shields.io/badge/-_-00C896?style=flat-square) | `#00C896` |
| Outbound | ![#FF6F61](https://img.shields.io/badge/-_-FF6F61?style=flat-square) | `#FF6F61` |
| Persistence | ![#007F5F](https://img.shields.io/badge/-_-007F5F?style=flat-square) | `#007F5F` |

</div>

---

## 📖 设计文档

完整设计参见 [RP内核设计文档.md](RP内核设计文档.md) 与各 crate 顶部 doc 注释。

<div align="center">

---

**Made with ❤️ in Rust** · **WutherCore** · 2026

[⬆ 回到顶部](#-wuthercore)

</div>
