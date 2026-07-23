# 本地补丁

WutherCore 需要完整对齐 Xray REALITY 的 invalid-certificate `spiderX` 行为：
TLS 握手成功但证书不带 REALITY 绑定时，必须在**同一条 TLS 连接**上执行 HTTP/2
伪装抓取，不能丢弃连接后重新拨号。

相对上游 `bb3e00da1abfc5fff70487b0dd2ba16054797584` 的最小修改：

1. `src/reality_connector.rs`：增加 `RealityTlsSessionOutcome`，让会话完成结果区分
   `Verified` 与 `NotReality`，两种结果都携带已握手流。
2. `src/reality_rustls.rs`：证书校验器以共享状态记录 REALITY 绑定结果；
   `NotReality` 不再中断 TLS 握手，而是返回带原连接的 outcome。证书解析错误、
   TLS 签名错误仍然失败关闭。
3. `src/lib.rs`：增加明确的 `RealityNotVerified` 错误类别。
4. `RealityTlsSession::complete` 的默认实现保持原通用运行时的 fail-closed 行为；
   `src/reality_runtime.rs` 无需改动。只有显式调用 `complete_with_outcome` 的
   WutherCore REALITY 客户端会把原连接交给 spiderX。

补丁不改变 ClientHello、X25519/X25519MLKEM768、ML-DSA-65、密钥派生或直通流语义。
