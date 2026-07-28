# 发版指南

WutherCore 使用 Git 标签驱动 GitHub Actions 发版。工作流只接受已经推送到仓库的标签，不会代替维护者创建或移动标签。

## 版本通道

| 通道 | 标签与 workspace 版本 | GitHub Release 行为 |
| --- | --- | --- |
| Pre-release | `vX.Y.Z-alpha.N`、`vX.Y.Z-beta.N`、`vX.Y.Z-rc.N` | 标记为 Pre-release，不会成为 Latest |
| Release | `vX.Y.Z` | 发布为正式版本，并标记为 Latest |

标签去掉前导 `v` 后，必须与 `Cargo.toml` 的 `[workspace.package].version` 完全一致。比如 `v0.4.0-rc.1` 对应 `version = "0.4.0-rc.1"`，不能只写 `0.4.0`。

正式版本的标签提交还必须已经进入 `main`。预发布可以来自候选分支。两种通道都要求标签提交已经通过 `Required CI`，Release 工作流直接复用该结果，不重复编译和检查。

## 发版前准备

1. 更新 `Cargo.toml` 中的 workspace 版本，并同步 `Cargo.lock`。
2. 把用户可见变化从 `CHANGELOG.md` 的 `Unreleased` 整理到对应版本。
3. 运行本地基线：

   ```bash
   cargo fmt --all --check
   cargo check --workspace --all-targets --locked
   cargo test --workspace --locked
   cargo doc --workspace --no-deps
   python scripts/check-repository.py
   ```

4. 通过 Pull Request 合入版本准备提交。正式版必须从 `main` 上的该提交打标签。

## 创建预发布

```bash
git switch main
git pull --ff-only
git tag -a v0.4.0-rc.1 -m "WutherCore 0.4.0-rc.1"
git push origin v0.4.0-rc.1
```

`alpha`、`beta` 和 `rc` 后必须带非负序号。工作流会从标签后缀自动判断这是 Pre-release。

## 创建正式发布

```bash
git switch main
git pull --ff-only
git tag -a v0.4.0 -m "WutherCore 0.4.0"
git push origin v0.4.0
```

正式标签没有预发布后缀。工作流会将其设为 Latest Release。

## 工作流保证

发布前会依次执行：

1. 校验标签格式、版本通道与 workspace 版本；
2. 确认正式版提交属于 `main`，并确认标签提交已有成功的 `Required CI`；
3. 调用统一的 Build Matrix，并行构建全部 9 个目标；Windows 和 macOS
   产物会在对应架构的原生 runner 上执行冒烟验证；
4. 将每个平台 ZIP 作为非嵌套 artifact 上传，并只保留 1 天；
5. 发布 job 按 `wuther-core-$VERSION-*` 前缀下载一次全部 9 个产物，校验数量，用
   `scripts/verify-release-components.py` 逐个读取归档内的 `BUILD-COMPONENTS.txt`，
   核对每个平台应有的组件（例如 Windows AMD64 的 `with_young`）确实编译进去，
   再生成 `SHA256SUMS`；
6. 生成 GitHub Artifact Attestation；
7. 使用 `.github/release.yml` 自动分类 Release Notes；
8. 直接上传文件到 GitHub Release，并按照标签设置 Pre-release 或 Latest。

Release 不会再次调用完整 CI，也不会创建汇总 artifact 后重复上传和下载。正式版的质量门禁由标签提交已经通过的 `Required CI` 保证。

正式发布不会覆盖已经发布的同名 Release。若首次发布在上传阶段中断，重新运行可以续传仍处于 Draft 状态的 Release；已发布的资产保持不可变。

## 发布产物

| 系统 | 架构 / ABI |
| --- | --- |
| Linux GNU | AMD64、ARM64 |
| Linux musl | AMD64、ARM64 |
| Android | ARM64、ARMv7 |
| Windows MSVC | AMD64、ARM64 |
| macOS | Apple Silicon |

每个 ZIP 包含：

- `wuther-core` 或 `wuther-core.exe`；
- `README.md` 与 MIT `LICENSE`；
- `examples/` 示例配置；
- `BUILD-COMPONENTS.txt` 版本、Rust target 与实际组件预设；
- `licenses/xray-transport-MPL-2.0.txt` 第三方许可证。

各目标的默认组件预设：

| 目标 | 预设 | Young |
| --- | --- | --- |
| Linux GNU AMD64 / ARM64 | `standard` | ✅ |
| macOS Apple Silicon | `standard` | ✅ |
| Linux musl AMD64 / ARM64 | `portable,with_young` | ✅ |
| Windows MSVC AMD64 | `portable,with_young` | ✅ |
| Android ARM64 / ARMv7 | `portable,with_young` | ✅ |
| Windows MSVC ARM64 | `portable` | ❌ |

`portable` 避开上游尚未覆盖这些目标的 BoringSSL 构建链；可用目标仍能显式选择
`portable_boringssl` 或具体的 `with_grpc`、`with_utls`、`with_xhttp`。

除 Windows ARM64 外的全部目标都编入 `with_young`。Linux GNU 与 macOS 沿用动态
NSS 并在归档内携带运行库；musl、Windows AMD64 与 Android 静态链接 NSS，归档仍是
单文件二进制。Windows ARM64 的 runner 镜像没有 MSYS2，NSS 也没有原生 ARM64
Windows 构建链，对它显式请求 `with_young`（含 `standard`、`all_components`）会让
构建直接失败，不会静默降级成不含该组件的归档。各目标的 NSS 来源与本地等价命令见
[组件化构建](BUILDING.md)。

预设都会在 `BUILD-COMPONENTS.txt` 中明确记录，显式传入 `tags` 时则完全采用请求的组件集。

## 校验下载

Linux 或 macOS：

```bash
sha256sum -c SHA256SUMS
gh attestation verify wuther-core-0.4.0-linux-amd64.zip --repo MiChongs/WutherCore
```

PowerShell：

```powershell
Get-FileHash .\wuther-core-0.4.0-windows-amd64-msvc.zip -Algorithm SHA256
gh attestation verify .\wuther-core-0.4.0-windows-amd64-msvc.zip --repo MiChongs/WutherCore
```

## 手动重跑

在 GitHub Actions 的 `Release` 工作流中选择 `Run workflow`，填写一个已经存在的标签。通常保持 `channel = auto`；显式选择 `prerelease` 或 `release` 时，选择必须与标签格式一致，否则工作流会拒绝执行。

手动运行用于恢复失败的 Draft Release，不用于绕过版本、标签或已有的 `Required CI` 校验。

需要验证裁剪构建时，在 `CI` 或 `Build Matrix` 工作流中选择 `Run workflow`，
并在 `tags` 中填写逗号分隔的组件标签，例如
`with_quic,with_vless,with_grpc,with_utls`。留空执行各目标支持的默认组件集。标签含义、
本地等价命令和许可边界见[组件化构建](BUILDING.md)。
Build Matrix 的 `platforms` 可只重跑一个平台组；`macos` 使用 Apple Silicon
原生 runner。
