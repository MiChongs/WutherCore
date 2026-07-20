# 参与贡献

感谢你愿意改进 WutherCore。这个项目涉及网络协议、系统路由和多平台差异；一个容易复现、边界清楚的改动，通常比一次覆盖很多模块的提交更容易审查和维护。

## 开始之前

- Bug、回归和明确的小改动可以直接提交 Pull Request。
- 新协议、大范围配置变更或架构调整，请先开 Discussion 或 Feature Request 对齐方案。
- 安全漏洞不要提交公开 Issue，按照 [SECURITY.md](SECURITY.md) 私下报告。
- 参与项目即表示同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

## 开发环境

仓库使用 `rust-toolchain.toml` 中的 stable 工具链，并需要 Rust 1.85 或更高版本。

```bash
git clone https://github.com/MiChongs/WutherCore.git
cd WutherCore
cargo check --workspace --all-targets
```

建议从最新 `main` 创建短生命周期分支。分支名使用简短的用途说明，例如 `fix/tun-route-rollback` 或 `feat/dns-policy`。

## 修改原则

- 保持改动聚焦；不要在功能修复中混入无关格式化或重构。
- 新增配置项时，同时覆盖反序列化、默认值和 `RuntimePlan`。
- 修改协议实现时，关注握手、异常输入、超时、连接关闭和敏感信息日志。
- 修改 TUN、TPROXY、REDIRECT 或系统路由时，写清平台、权限、恢复路径和失败回滚。
- 修改公开 API 或配置结构时，在 Pull Request 中说明兼容性和迁移方式。
- 可以使用自动化工具辅助开发，但提交者必须理解、验证并负责最终改动。

## 提交前检查

至少运行与改动相关的检查。通用基线为：

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace
```

平台专属代码无法在本机执行时，请在 Pull Request 中明确说明已验证和未验证的部分。不要用跳过测试来隐藏失败。

## Commit 与 Pull Request

Commit 标题使用简短的祈使句，并尽量带上范围：

```text
fix(capture): restore routes after partial failure
feat(resolver): add per-group DNS policy
docs: clarify Android capture setup
```

Pull Request 应包含：

- 问题或目标；
- 采用的方案以及没有采用其他方案的原因；
- 用户可见影响和兼容性；
- 实际运行过的检查；
- 涉及网络、权限或持久化时的回滚方式。

`main` 默认要求 `Required CI` 通过、至少一名 Reviewer 批准，并解决所有 Review 对话。新提交会使旧批准失效。

## Review

Review 重点关注正确性、安全边界、平台差异和长期维护成本。作者应直接回应问题；如果意见涉及不同取舍，可以在对应线程说明理由，不必为了关闭评论而机械修改。

合并通常使用 squash 或 rebase，以保持历史可读。维护者可能要求拆分过大的 Pull Request。
