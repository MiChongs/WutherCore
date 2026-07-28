# WutherCore 多平台构建

仓库的 GitHub Release 使用 [Release 工作流](https://github.com/MiChongs/WutherCore/blob/main/.github/workflows/release.yml) 自动构建并发布；本页脚本用于本地构建、调试工具链或复现单个平台问题。正式版与预发布的标签规则见 [发版指南](https://michongs.github.io/WutherCore/RELEASING/)。

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

:: 精确组件构建（指定 --tags 后不会隐式加入 standard）
build.cmd --tags "with_quic,with_vless,with_grpc,with_utls" windows

:: 强制使用某个后端
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
pwsh -File scripts/build-all.ps1 -Backend cross    -Targets "aarch64-linux-android"
```

## 按组件标签编译

WutherCore 使用 Cargo features 提供与 Go `-tags` 等价的编译期组件裁剪。未指定
`--tags` 时，本机脚本使用 `standard`，行为与引入组件标签前一致（除需单独许可
的 Naive 外全部启用）。`portable` 不包含
上游无法覆盖全部 musl/交叉架构的 BoringSSL 传输；支持 BoringSSL 的目标可选择
`portable_boringssl`，或显式加入对应标签。一旦指定 `--tags`，
脚本和 CI 都会自动添加 `--no-default-features`，只有列出的标签及其依赖会进入构建。

CI 每个目标的默认预设见下表。留空 `tags` 时按此选择，显式传入则所有目标一律
采用请求的组件集：

| 目标 | 默认预设 | Young | NSS 链接方式 |
|---|---|---|---|
| Linux GNU AMD64 / ARM64 | `standard` | ✅ | 动态，归档携带 `.so` |
| macOS Apple Silicon | `standard` | ✅ | 动态，归档携带 `.dylib` |
| Linux musl AMD64 / ARM64 | `portable,with_young` | ✅ | 静态 |
| Windows MSVC AMD64 | `portable,with_young` | ✅ | 静态 |
| Android ARM64 / ARMv7 | `portable,with_young` | ✅ | 静态 |
| Windows MSVC ARM64 | `portable` | ❌ | 不适用 |

`with_young` 通过 `nss-rs` 内嵌 Mozilla NSS，各目标的 NSS 来源不同：

- **Linux GNU / macOS**：`nss-rs` 自行拉取并构建 NSS，`setup-neqo` 只补齐 runner
  缺的 gyp / ninja / mercurial / clang；
- **Windows AMD64**：`mozilla/actions/nss`（neqo CI 同款）提供 NSS 与 MSVC 环境。
  `nss-rs` 在 Windows 走静态链接，归档不额外携带 NSS 运行库；
- **Android**：`setup-nss-android` 调用 `mozilla/application-services` 的
  `build-nss-android.sh`（Firefox for Android 同款）交叉编译静态 NSS。NSS 与 Rust
  用同一个 NDK 和同一个 API level（见 `build.yml` 的 `ANDROID_API_LEVEL`）；
- **musl**：`setup-nss-musl` 在同架构 Alpine 容器里从源码编译静态 NSS，归档保持
  单文件全静态二进制；
- **Windows ARM64**：runner 镜像没有 MSYS2，NSS 也没有原生 ARM64 Windows 构建链，
  因此不提供 Young。

上游 `nss-rs` 只在 `PROFILE=debug`、Windows 或 fuzzing 时静态链接 NSS，这会让
Android 与 musl 的 release 构建去找根本不生成的 `libnss3` 等共享库。仓库因此在
`third_party/nss-rs-b7cfa30` 保留一份按 target 而非 profile 判定的副本，见根
`Cargo.toml` 的 `[patch."https://github.com/mozilla/nss-rs"]`。

在不支持的目标上显式请求 `with_young`（含 `standard`、`all_components`）会直接失败，
不会静默降级。发布流程还会用 `scripts/verify-release-components.py` 读取每个归档里的
`BUILD-COMPONENTS.txt`，核对该平台应有的组件确实编译进去了。

```cmd
:: VLESS + gRPC + uTLS，只构建 Windows x64
build.cmd --tags "with_vless,with_grpc,with_utls" windows

:: Hysteria 2 会自动带上 with_quic
build.cmd --tags "with_hysteria2" linux

:: 完整标准集
build.cmd --tags "standard" windows

:: 标准集再加 GPL/Cronet Naive
build.cmd --tags "all_components" windows
```

也可以直接使用 Cargo：

```bash
cargo build --release -p wuther-core \
  --no-default-features \
  --features "with_quic,with_vless,with_grpc,with_utls"

# 检查一个二进制实际包含哪些组件
wuther-core components
wuther-core components --json
```

### 可用标签

| 类别 | 标签 | 能力 |
|---|---|---|
| 预设 | `portable` | 所有发布架构通用，不含 BoringSSL/Young/Naive |
| 预设 | `portable_boringssl` | `portable` 加 gRPC、uTLS 与 XHTTP |
| 预设 | `standard` | 默认标准组件集，不含 Naive/Cronet |
| 预设 | `all_components` | `standard` 加 `with_naive` |
| 运行组件 | `with_api` | 管理 API 与面板服务 |
| 运行组件 | `with_tun` | TUN/TProxy/Redirect capture |
| 传输 | `with_quic` | QUIC/H3 基础能力 |
| 传输 | `with_grpc` | Xray gRPC 入站与出站传输 |
| 传输 | `with_reality` | REALITY |
| 传输 | `with_utls` | uTLS ClientHello 指纹 |
| 传输 | `with_ws` | WebSocket 传输 |
| 传输 | `with_http_transport` | HTTP/2 transport |
| 传输 | `with_xhttp` | XHTTP/SplitHTTP（自动启用 `with_quic`） |
| 协议 | `with_http`, `with_socks` | HTTP 与 SOCKS5 出站 |
| 协议 | `with_shadowsocks`, `with_shadowsocksr` | Shadowsocks/2022 与 SSR |
| 协议 | `with_vmess`, `with_vless`, `with_trojan` | VMess、VLESS、Trojan |
| 协议 | `with_hysteria`, `with_hysteria2`, `with_tuic` | QUIC 协议（自动启用 `with_quic`） |
| 协议 | `with_wireguard` | WireGuard 客户端与服务端 |
| 协议 | `with_anytls`, `with_snell`, `with_ssh` | AnyTLS、Snell、SSH |
| 协议 | `with_mieru`, `with_sudoku`, `with_trusttunnel` | Mieru、Sudoku、TrustTunnel |
| 协议 | `with_young` | Young + Mozilla Neqo/NSS |
| 协议 | `with_naive` | Naive + Cronet；需单独满足 GPL 与原生库要求 |

`DIRECT`、`BLOCK` 与 DNS hijack 是路由运行时的基础能力，所有构建始终保留。
若配置引用了未编译组件，`check` 和 `run` 会直接给出缺少的 `with_*` 标签，不会
静默注册占位实现。每个本地和 CI 归档都包含 `BUILD-COMPONENTS.txt`。

GitHub Actions 的 **Build Matrix** 和 **CI** 手动运行入口也提供 `tags` 输入，
显式填写时语义与本地 `--tags` 完全相同。Build Matrix 留空时会按目标选择上述
`standard` 或 `portable` 平台预设，并把最终选择写进归档。它还可用 `platforms`
只运行 `linux`、`android`、`windows` 或 `macos` 子矩阵；`all` 会并行构建
9 个目标。官方 macOS 自动构建只使用 Apple Silicon runner，产出
`aarch64-apple-darwin`，不依赖不完整的 Darwin 交叉编译环境。

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
| `*-pc-windows-msvc` | cargo（本机） | 无 | 直接 cargo build |
| `*-unknown-linux-*` | **cargo-zigbuild + zig** | cross 0.2.5 + Docker | zigbuild 无需 Docker，体积更小 |
| `*-linux-android*` | **cargo-ndk + Android NDK** | cross 0.2.5 | cross 0.2.5 的 android 镜像缺 `libunwind`；强烈建议用 cargo-ndk |
| `*-unknown-freebsd*` | cross + Docker | 无 | |
| `*-apple-*` | 无 | 无 | 必须 macOS 主机 |

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
  wuther-core-0.3.1-x86_64-pc-windows-msvc.zip
  wuther-core-0.3.1-x86_64-pc-windows-msvc.zip.sha256
  wuther-core-0.3.1-x86_64-unknown-linux-musl.zip
  wuther-core-0.3.1-x86_64-unknown-linux-musl.zip.sha256
  ...
```

每个归档包含：
- `wuther-core[.exe]`：内核可执行文件
- `README.md`、`LICENSE` 与 `BUILD-COMPONENTS.txt`
- `examples/`：桌面、路由器、Android、订阅和手动节点模板

GitHub Release 还会统一生成 `SHA256SUMS`，并为所有归档写入 GitHub Artifact Attestation。

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
| `x86_64-apple-darwin` | ❌ 跳过 | 无 | 需 macOS 主机或 zigbuild + Apple SDK |
| `aarch64-apple-darwin` | ❌ 跳过 | 无 | 同上 |
| `aarch64-apple-ios` | ❌ 跳过 | 无 | 需 macOS + Xcode |

## 校验

```cmd
:: 验证
certutil -hashfile dist\wuther-core-0.3.1-x86_64-pc-windows-msvc.zip SHA256
type    dist\wuther-core-0.3.1-x86_64-pc-windows-msvc.zip.sha256
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
- **macOS 构建**：在对应架构的 macOS 主机直接运行
  `cargo build --release --target aarch64-apple-darwin` 或
  `cargo build --release --target x86_64-apple-darwin`。官方 CI 仅使用
  `macos-15` Apple Silicon runner 构建并冒烟测试。
