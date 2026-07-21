# 本地补丁

## TLS 1.2 可省略 `supported_versions`

动机：固定的 Go uTLS/Xray legacy ClientHello（例如 360Browser 7.5）按 TLS 1.2
传统格式协商，不发送 RFC 8446 的 `supported_versions`（扩展 `0x002b`）。上游
shaped-rustls 将该扩展对所有协议版本都视为不可禁用，因而无法复现 oracle 的
精确扩展集合与顺序。

补丁范围仅为 `rustls/src/client/hs.rs::apply_extension_plan`：

- TLS 1.3 仍严格禁止禁用 `supported_versions`；
- 仅当配置不启用 TLS 1.3 时，允许 extension plan 将
  `ClientExtensions::supported_versions` 置空；
- 没有修改协议版本选择、ServerHello 处理、密码套件或证书验证。

另外，vendor 根 `Cargo.toml` 只把 workspace member/default-member 缩减为
`rustls`，以排除未复制且与生产构建无关的上游测试/示例 crates；依赖版本表保持
固定提交原样。

该通用行为由 RPKernel 的全部静态 Xray/uTLS profile wire golden 测试覆盖，
不会针对单个 fingerprint 写特判。
