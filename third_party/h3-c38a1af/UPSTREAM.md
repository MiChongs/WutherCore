# Vendored h3 source

- 上游仓库：https://github.com/hyperium/h3
- 固定提交：`c38a1af632afbbbc8f6716c196ad67f40bc122e3`
- 上游许可：MIT，完整文本见同目录 `LICENSE`

此目录保留上游 `h3` 源码，并额外保留同一固定提交中的
`h3-quinn/src/lib.rs` 与 `h3-quinn/src/datagram.rs`，仅用于满足上游
`h3` 私有测试模块的相对路径布局。生产依赖中的 `h3-quinn` 仍直接固定到
上述 Git 提交；Cargo 只用这里的 `h3` 覆盖同源包，随附的 `h3-quinn`
源码不参与生产构建。

相对固定提交仅有两类运行/打包差异：

1. `h3::connection::RequestStream::poll_recv_data` 跳过合法零长度 DATA
   帧，而不把它误报成 HTTP 消息结束；同文件加入
   `zero_length_data_frame_is_not_message_eof` 回归测试。仓库内的真实
   H3 生命周期测试还会验证该帧不产生代理字节，且能观察对端
   STOP_SENDING。
2. `h3/Cargo.toml` 移除只供上游测试使用的 `h3-datagram` dev-dependency，
   避免为生产构建额外 vendoring 无关 crate；其余 package metadata 与
   运行时依赖保持上游原样。

随附的两个 `h3-quinn` 测试支持文件均逐字复制自固定提交，没有本地修改。

可从仓库根目录独立验证回归：

```text
cargo test --manifest-path third_party/h3-c38a1af/h3/Cargo.toml --features i-implement-a-third-party-backend-and-opt-into-breaking-changes zero_length_data_frame_is_not_message_eof
```
