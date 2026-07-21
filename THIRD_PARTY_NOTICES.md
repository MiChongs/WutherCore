# 第三方组件声明

## shaped-rustls

- 上游：`https://github.com/aimalygin/shaped-rustls`
- 固定提交：`94f088e210fd2a56e413cce1c6d79c10852d500a`
- 基线版本：rustls `0.23.40`
- 用途：提供可选的 ClientHello shaping 原语；未安装 customizer 时保持上游 rustls 行为。
- 本地形式：源码固定 vendored 于 `third_party/shaped-rustls-94f088e`。仅有的
  行为补丁允许 TLS 1.2 extension plan 省略可选的 `supported_versions`；TLS 1.3
  仍强制该扩展。上游来源及精确补丁范围分别见该目录的 `UPSTREAM.md` 与
  `PATCHES.md`。
- 许可证：Apache-2.0、MIT 或 ISC（三选一）。仓库在固定提交中同时包含
  `LICENSE-APACHE`、`LICENSE-MIT` 与 `LICENSE-ISC`，本项目按 MIT 条款使用。

## rustls-native-certs

- 上游：`https://github.com/rustls/rustls-native-certs`
- 版本：`0.8.4`
- 用途：从操作系统证书库加载 TLS 根证书。
- 许可证：Apache-2.0、ISC 或 MIT。

## rcgen

- 上游：`https://github.com/rustls/rcgen`
- 固定版本：`0.13.2`
- 用途：实现 Xray `certificates[].usage=issue` 的按 SNI 动态叶证书签发；
  签发密钥、SAN、CA 签名与可选 `buildChain` 均在本地完成。
- 许可证：MIT 或 Apache-2.0。

## ocsp-stapler

- 上游：`https://github.com/blind-oracle/ocsp-stapler`
- 固定版本：`0.4.9`
- 用途：为文件型服务端证书按 Xray `ocspStapling` 周期查询、解析并校验
  OCSP 响应，再分别装订到 rustls 与 BoringSSL 握手；查询失败保持证书可用并
  记录告警，与 Xray 的软失败语义一致。
- 许可证：MPL-2.0。

## OCSP 响应验证依赖

- `rasn`、`rasn-ocsp`、`rasn-pkix 0.28.13`：严格解码并重新编码 OCSP/X.509
  ASN.1 结构，用于验证响应类型、CertID、响应者身份和签名数据；许可证 MIT 或
  Apache-2.0。
- `x509-parser 0.18.1`：解析叶证书、签发证书和委托 OCSP 响应证书，并通过
  AWS-LC 验证证书链及 OCSP 签名；许可证 MIT 或 Apache-2.0。
- `sha1 0.10`：按照 RFC 6960 计算 CertID 和 ResponderID 中规定的 SHA-1
  标识哈希（不用于签名安全性）；许可证 MIT 或 Apache-2.0。
- `chrono 0.4`：验证 OCSP `thisUpdate`/`nextUpdate` 时间窗口；许可证 MIT 或
  Apache-2.0。

## 协议与解析辅助依赖

- `rsteria2 0.1.1`：提供 Hysteria2 的 HTTP/3 认证、TCP/UDP 中继、Brutal
  拥塞控制、Salamander 混淆与端口跳跃客户端实现；许可证 MIT。
- `hickory-proto 0.24.4`：为 DNS 解析器及 ECH 配置发现提供 DNS wire
  message 编解码；许可证 MIT 或 Apache-2.0。
- `data-encoding 2.11.0`：为依赖树中的 SSH 密钥、WebSocket 与 X.509
  解析器提供文本编码；许可证 MIT。
- `percent-encoding 2.3.2`：解码节点 URI 配置，并支持 XHTTP URL 与查询
  参数的百分号编码；许可证 MIT 或 Apache-2.0。

## boring / tokio-boring / BoringSSL

- Rust 绑定上游：`https://github.com/cloudflare/boring`
- 固定版本：`boring 4.19.0`、`tokio-boring 4.19.0`（对应的
  `boring-sys 4.19.0` 由同一版本依赖固定）。
- BoringSSL 上游：`https://boringssl.googlesource.com/boringssl`
- 用途：为普通（`fingerprint=unsafe`）TLS 提供可执行的 TLS 1.0/1.1
  兼容后端，并承载 rustls 服务端尚不支持的 ECH server keys。
- 许可证：Rust 绑定为 Apache-2.0；BoringSSL 为 ISC 风格许可证。构建时
  `boring-sys` 从其固定源码包编译，不从网络下载浮动代码。

## refraction-networking/utls

- 上游：`https://github.com/refraction-networking/utls`
- Xray 固定版本：`v1.8.3-0.20260301010127-aa6edf4b11af`
- 用途：`utls_profiles.rs` 内的指纹形状数据由该固定版本实际生成的
  ClientHello 经协议解析、去除随机字节后生成；没有嵌入其 Go 源码。
- 许可证：BSD-3-Clause。

## Xray-core 兼容基线

- 上游：`https://github.com/XTLS/Xray-core`
- 固定提交：`6e3322d219140a025285ded1114fe17a5edb74d8`
- 用途：确认指纹名称、别名、默认值和随机化策略的兼容基线。项目不嵌入
  Xray-core 源码；Xray-core 使用 MPL-2.0 许可证。

## Go 标准库 legacy math/rand

- 上游：`https://go.googlesource.com/go`
- 用途：`proto/xhttp/browser_headers.rs` 与 `transport/browser_identity.rs` 为复现
  Xray 浏览器头部及进程级浏览器版本身份选择，移植了 Go legacy `math/rand`
  的反馈寄存器步骤及其 607 项 `rngCooked` 表中的 40 个实际使用常量。该兼容
  例程只用于得到与 Go 相同的确定性序列。
- 许可证：BSD-3-Clause。

## Xray browser-headers 测试 oracle

- 文件：`tests-e2e/oracles/xray_browser_headers.go`
- 固定来源：Xray-core 提交
  `6e3322d219140a025285ded1114fe17a5edb74d8` 中的浏览器头部公式。
- 用途：只在测试中生成对照结果，不进入运行时。
- 许可证：MPL-2.0。

## hyperium/h3

- 上游：`https://github.com/hyperium/h3`
- 固定提交：`c38a1af632afbbbc8f6716c196ad67f40bc122e3`
- 本地形式：vendored 于 `third_party/h3-c38a1af`；包含一个最小通用补丁，令
  request stream 跳过合法的零长度 DATA frame，而不把它误判为消息 EOF。
  完整来源、补丁范围和回归命令见该目录 `UPSTREAM.md`。
- 许可证：MIT。
