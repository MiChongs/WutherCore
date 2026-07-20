## 目标

<!-- 这个 PR 解决什么问题？请关联 Issue 或 Discussion。 -->

## 改动

<!-- 列出关键改动，以及为什么选择这个方案。 -->

## 影响与风险

<!-- 说明用户可见影响、兼容性、平台差异、安全边界和回滚方式。 -->

## 验证

<!-- 删除未运行的项目，并补充实际命令或环境。 -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo check --workspace --all-targets`
- [ ] `cargo test --workspace`
- [ ] `cargo doc --workspace --no-deps`
- [ ] `python scripts/check-repository.py`
- [ ] 已完成与改动相关的平台或手动验证

## 提交前确认

- [ ] 改动范围聚焦，没有混入无关重构
- [ ] 新行为、配置或兼容性变化已经更新文档
- [ ] 日志、配置和测试数据不包含凭据或隐私信息
- [ ] 我已说明无法在本地验证的部分
- [ ] 我同意遵守项目的行为准则
