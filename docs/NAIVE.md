# Naive 出站

WutherCore 的 Naive 出站基于 `cronet` 0.2.0 和 SagerNet/Naive Cronet 原生库。实现与 sing-box 当前 Naive 出站字段对齐，支持：

- HTTP/2 CONNECT 与 HTTP/3 CONNECT；
- Basic 认证、自定义请求头与 H2 非安全并发连接池；
- Naive 前 8 个数据块填充；
- UDP over TCP v2；
- QUIC 拥塞控制与接收窗口；
- SNI、自定义根证书、ECH Config List 和 ECH DNS 查询；
- 内核的 socket protect、出站 mark、bind-interface 与 DNS 钩子。

## 构建

Naive 是显式启用的 Cargo feature：

```bash
cargo build --release -p wuther-core --features naive
```

该 feature 需要 Rust 1.88 或更高版本，以及与 `cronet` crate ABI 匹配的 SagerNet/Naive Cronet 动态库。可使用 `cronet-rs` v0.2.0 中带校验和验证的下载脚本。

Windows PowerShell：

```powershell
git clone --branch v0.2.0 --depth 1 https://github.com/MiChongs/cronet-rs.git
Set-Location cronet-rs
.\scripts\fetch-native.ps1
$env:CRONET_LIB_DIR = "$PWD\target\cronet-sdk\lib"
$env:CRONET_LIB_NAME = "cronet"
$env:PATH = "$PWD\target\cronet-sdk\bin;$env:PATH"
Set-Location ..\WutherCore
cargo build --release -p wuther-core --features naive
```

Linux：

```bash
git clone --branch v0.2.0 --depth 1 https://github.com/MiChongs/cronet-rs.git
cd cronet-rs
./scripts/fetch-native.sh
export CRONET_LIB_DIR="$PWD/target/cronet-sdk/lib"
export CRONET_LIB_NAME=cronet
export LD_LIBRARY_PATH="$CRONET_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd ../WutherCore
cargo build --release -p wuther-core --features naive
```

运行时也必须让系统能够找到 `cronet.dll`、`libcronet.so` 或对应平台的兼容动态库。Windows 可将 DLL 放在 `wuther-core.exe` 同目录；Linux 可安装到系统库目录或保留 `LD_LIBRARY_PATH`。

## 配置

手动节点示例：

```yaml
nodes:
  - name: naive-h2
    type: naive
    server: proxy.example.com
    port: 443
    username: alice
    password: replace-me
    udp: true
    sni: front.example.com
    udp-over-tcp: true
    insecure-concurrency: 2
    extra-headers:
      X-Client: WutherCore

  - name: naive-h3
    type: naive
    server: proxy.example.com
    port: 443
    username: alice
    password: replace-me
    udp: true
    quic: true
    udp-over-tcp: true
    quic-congestion-control: bbr
```

也支持 URI：

```text
naive://alice:password@proxy.example.com:443?udp-over-tcp=true#naive-h2
naive+quic://alice:password@proxy.example.com:443?udp-over-tcp=true#naive-h3
```

主要扩展字段：

| 字段 | 说明 |
| --- | --- |
| `insecure-concurrency` | H2 连接池并发数；QUIC 模式只能为 1 |
| `extra-headers` | Mihomo 风格头部映射；URI 可使用 `extra-header.<名称>` |
| `udp-over-tcp` | 使用 sing-box UoT v2 封装 UDP |
| `quic` | 启用 H3；`naive+quic://` 会自动启用 |
| `quic-congestion-control` | `bbr`、`bbr2`、`cubic` 或 `reno` |
| `stream-receive-window` | QUIC 单流接收窗口 |
| `quic-session-receive-window` | QUIC 会话接收窗口 |
| `certificate-path` | PEM 根证书文件 |
| `certificate` | 内联 PEM 根证书 |
| `ech` | 启用 ECH |
| `ech-config` | Base64 或十六进制 ECH Config List |
| `ech-query-server-name` | 用于获取 ECH HTTPS 记录的名称 |

`insecure`、`skip-cert-verify` 等跳过验证选项会被拒绝。Cronet 不提供可靠的“忽略证书错误”能力；私有 CA 应通过 `certificate-path` 或 `certificate` 配置。

UoT v2 是定目标 packet socket：同一 UDP socket 只能收发创建时的目标地址。长度超过调用方缓冲区的数据报会被完整丢弃并返回错误，避免破坏后续帧边界。

## 许可与发布

WutherCore 默认构建仍为 MIT，且不包含 Naive feature。`cronet` crate 与 SagerNet/Naive Cronet 原生组件使用 GPL-3.0-or-later；启用、链接或分发 Naive 构建时，发布者必须按 GPL-3.0-or-later 履行相应义务。官方默认 Release 产物不会自动携带该动态库。
