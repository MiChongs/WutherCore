# Changelog

本文件记录用户可见的重要变化。正式版本的发布说明由 GitHub Release 根据 `.github/release.yml` 分类生成，并补充兼容性、已知限制和升级方式。

## [Unreleased]

### Security

- Clash 兼容 `GET /configs` 的 `authentication` 只返回用户名，不再回传明文密码。

### Fixed

- Clash `PUT /configs` 的 `mode`（rule/global/direct）接入真实选路；
- `allow-lan` / `tun.enable` 热切换改为 `501`，不再写成功假象。
- 非本机管理面板（`listen.share: home|all` 或非 loopback `listen.panel`）在 `ui.secret` 为空时拒绝编译/启动。
- `groups.*.choose: chain` 在配置编译期拒绝，避免静默退化为单跳第一节点。
- `auto_route` / TPROXY / REDIRECT 下 capture 启动失败改为 fail-closed。

### Added

- 组网后端能力/附件模型、冻结 descriptor、强类型宿主资源声明与语义化系统资源冲突预检；
- 带阶段超时、调用方取消安全、逆序回滚、后台状态监控和 fail-closed 隔离的事务监督器；
- 基于 Unix process group/Windows Job 的托管 daemon、显式 readiness、后台退出监控、有界自动重启、脱敏日志与显式 `close` 契约；
- Linux、Android、Windows、macOS capture 与 DNS/Mixed/API 固定监听的实际资源声明，以及纯快照读取、URL/诊断/共享密钥安全投影的 `/v1/mesh/status`；
- 本阶段只交付通用组网基础设施，不包含 Tailscale、Cloudflare 等具体产品适配器，也不修改代理协议；
- 仓库文档中心、功能矩阵、架构、配置、API、排错和路线图；
- 结构化 Issue 表单、Pull Request 模板和 CODEOWNERS；
- Dependabot、依赖变更审查、CodeQL 与私密漏洞报告；
- 项目治理、紧急合并、安全、支持和行为准则；
- README 与 GitHub Social Preview 共用的品牌横幅。

### Changed

- README 改为按使用、集成和贡献场景组织；
- 合并门禁使用 `Required CI`，发布构建不作为 PR 必需检查；
- GitHub About、Topics、合并策略、标签和社区功能完成配置。

### Security

- 高危依赖变更会阻止 Pull Request 合并；
- CodeQL 初次扫描告警由 [Issue #9](https://github.com/MiChongs/WutherCore/issues/9) 跟踪，未批量忽略。

[Unreleased]: https://github.com/MiChongs/WutherCore/compare/main...HEAD
