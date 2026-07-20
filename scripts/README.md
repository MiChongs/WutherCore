# WutherCore 多平台构建

## 一键构建（Windows 主机）

```cmd
:: 默认矩阵：Windows MSVC x64/ARM64 + Linux gnu/musl x64/ARM64
build.cmd

:: 仅构建 Windows
build.cmd windows

:: 仅构建 Linux x64 静态
build.cmd linux

:: 多目标 + 先清理
build.cmd --clean windows linux

:: 强制使用某个后端
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
pwsh -File scripts/build-all.ps1 -Backend cross    -Targets "aarch64-linux-android"
```

## 短别名

`build.cmd` 接受这些口语化别名（不区分大小写）：

| 别名 | 实际三元组 |
|---|---|
| `windows`, `win` | `x86_64-pc-windows-msvc` |
| `win-arm64` | `aarch64-pc-windows-msvc` |
| `linux` | `x86_64-unknown-linux-musl` |
| `linux-gnu` | `x86_64-unknown-linux-gnu` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` |
| `android` | `aarch64-linux-android` |
| `macos` | `x86_64-apple-darwin` |
| `macos-arm64` | `aarch64-apple-darwin` |

## 交叉编译后端

脚本默认 **auto** 后端选择，按以下顺序：

| 目标类别 | 首选后端 | 兜底 | 备注 |
|---|---|---|---|
| `*-pc-windows-msvc` | cargo（本机） | — | 直接 cargo build |
| `*-unknown-linux-*` | **cargo-zigbuild + zig** | cross 0.2.5 + Docker | zigbuild 无需 Docker，体积更小 |
| `*-linux-android*` | **cargo-ndk + Android NDK** | cross 0.2.5 | cross 0.2.5 的 android 镜像缺 `libunwind`；强烈建议用 cargo-ndk |
| `*-unknown-freebsd*` | cross + Docker | — | |
| `*-apple-*` | — | — | 必须 macOS 主机 |

脚本启动时会自动安装：

- `pip install ziglang` 或直接下载 zig 0.13.0 二进制（Linux 目标）
- `cargo install cargo-zigbuild --locked`
- `cargo install cargo-ndk --locked`（Android 目标）
- `cargo install cross --version 0.2.5 --locked`（兜底）
- 探测 `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` / `NDK_HOME` / `ANDROID_HOME/ndk/<latest>`

强制指定后端：

```powershell
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
pwsh -File scripts/build-all.ps1 -Backend cross    -Targets "x86_64-unknown-linux-gnu"
```

> Android 不接受 `-Backend zigbuild/cross` 强制；总是按“NDK 优先 → cross 兜底”自动选择，
> 因为 cross 0.2.5 + android 镜像缺 libunwind 是已知问题。

## 输出

构建产物落在 `dist/`：

```
dist/
  wuther-core-0.3.0-x86_64-pc-windows-msvc.zip
  wuther-core-0.3.0-x86_64-pc-windows-msvc.zip.sha256
  wuther-core-0.3.0-x86_64-unknown-linux-musl.tar.gz
  wuther-core-0.3.0-x86_64-unknown-linux-musl.tar.gz.sha256
  ...
```

每个归档包含：
- `wuther-core[.exe]` —— 内核可执行文件
- `README.md`、`RP内核设计文档.md`
- `examples/` —— 桌面、路由器、Android、订阅和手动节点模板

## 平台支持矩阵

| 目标三元组 | Windows 主机 | 推荐后端 | 备注 |
|---|---|---|---|
| `x86_64-pc-windows-msvc` | ✅ 本机 | cargo | MSVC build tools |
| `aarch64-pc-windows-msvc` | ✅ 本机 | cargo | MSVC ARM64 toolchain |
| `x86_64-unknown-linux-gnu` | ✅ | zigbuild | 推荐：无需 Docker |
| `aarch64-unknown-linux-gnu` | ✅ | zigbuild | 推荐 |
| `x86_64-unknown-linux-musl` | ✅ | zigbuild | 静态二进制 |
| `aarch64-unknown-linux-musl` | ✅ | zigbuild | 静态二进制 |
| `armv7-unknown-linux-gnueabihf` | ✅ | zigbuild | |
| `aarch64-linux-android` | ✅ | **cargo-ndk** | 需要 ANDROID_NDK_HOME（推荐 NDK r26+） |
| `armv7-linux-androideabi` | ✅ | cargo-ndk | 同上 |
| `x86_64-linux-android` | ✅ | cargo-ndk | 同上 |
| `x86_64-apple-darwin` | ❌ 跳过 | — | 需 macOS 主机或 zigbuild + Apple SDK |
| `aarch64-apple-darwin` | ❌ 跳过 | — | 同上 |
| `aarch64-apple-ios` | ❌ 跳过 | — | 需 macOS + Xcode |

## 校验

```cmd
:: 验证
certutil -hashfile dist\wuther-core-0.3.0-x86_64-pc-windows-msvc.zip SHA256
type    dist\wuther-core-0.3.0-x86_64-pc-windows-msvc.zip.sha256
```

## 常见问题

- **`error: toolchain 'stable-x86_64-unknown-linux-gnu' may not be able to run on this system`**
  这是 cross 0.2.5+ 的已知 bug；本脚本默认改用 zigbuild，
  并在选择 cross 时 pin 到 0.2.5 来规避。如果你已自行升级 cross，
  请运行 `cargo install cross --version 0.2.5 --locked --force` 降级。
- **`zig: command not found`**
  脚本会自动 `pip install ziglang`；若失败请从 https://ziglang.org/download/
  下载 `zig.exe` 并加入 PATH。
- **`cross` Docker pull 慢**：配置 Docker 镜像加速；或预先
  `docker pull ghcr.io/cross-rs/aarch64-linux-android:main`。
- **`ld: cannot find -lunwind` (android)**：cross 0.2.5 的 android 镜像 bug。
  本脚本默认改用 cargo-ndk，请安装 Android NDK r26+ 并设置 `ANDROID_NDK_HOME`。
- **`Android NDK 未检测到`**：从 https://developer.android.com/ndk/downloads 下载 r26+，
  解压后 `setx ANDROID_NDK_HOME C:\path\to\android-ndk-r26d`，重开终端。
- **`Compress-Archive` 限制 2GB**：debug 构建产物可能过大，请使用 release profile（默认）。
- **macOS 构建**：在 macOS 主机直接 `cargo build --release --target aarch64-apple-darwin`，
  或在 GitHub Actions `macos-latest` runner 跑。
