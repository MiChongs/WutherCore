# 编译性能优化（应对 Rust 的 LLVM 后端）

> Rust 编译慢主要来自三处：(1) 单元 trait 求解 + lifetime 推导；
> (2) LLVM 后端代码生成；(3) 链接器单线程。本仓库针对每一处做了配置层优化。

## 1. 已经在仓库内生效的优化

| 优化项 | 位置 | 效果 |
|---|---|---|
| `incremental = true` (dev) | [Cargo.toml](../Cargo.toml) | 二次编译跳过未改动 crate 的 codegen |
| `codegen-units = 256` (dev) | [Cargo.toml](../Cargo.toml) | 单 crate 内部并行 codegen |
| `debug = "line-tables-only"` (dev) | [Cargo.toml](../Cargo.toml) | 调试信息缩小一个量级，链接更快 |
| `split-debuginfo = "unpacked"` (dev, Windows) | [Cargo.toml](../Cargo.toml) | 单独 .pdb，热修改不重写主二进制 |
| `[profile.dev.package."*"]` opt-level=1 | [Cargo.toml](../Cargo.toml) | 依赖只编一次，运行时也快 |
| `lto = "thin"` + `codegen-units=16` (release) | [Cargo.toml](../Cargo.toml) | 与 codegen-units=1 + fat LTO 性能差 ~1%，但 release 构建时间 -60% |
| `release-fast` profile | [Cargo.toml](../Cargo.toml) | CI 验证用：lto=off + codegen-units=256 |
| `rust-lld` Windows 链接器 | [.cargo/config.toml](../.cargo/config.toml) | link.exe → rust-lld，链接 -50%~-70% |
| `mold` / `lld` Linux 链接器 | [.cargo/config.toml](../.cargo/config.toml) | bfd-ld → mold，链接 -80%+ |
| `git-fetch-with-cli = true` | [.cargo/config.toml](../.cargo/config.toml) | 大仓 git deps 抓取不卡顿 |

## 2. 用户主机一次性安装（强烈推荐）

### sccache —— 跨 cargo clean 缓存编译产物

```cmd
:: Windows
cargo install sccache --locked
setx RUSTC_WRAPPER sccache
:: 重开终端后所有 cargo build 自动走 sccache，命中率 70-90%
```

```bash
# Linux / macOS
cargo install sccache --locked
echo 'export RUSTC_WRAPPER=sccache' >> ~/.bashrc
```

### mold —— Linux 最快链接器

```bash
# Ubuntu 22.04+
sudo apt install mold

# 其它发行版
git clone --depth=1 https://github.com/rui314/mold && cd mold && ./build.sh
```

### lld —— 跨平台快链接器

```cmd
:: Windows: rustc 已自带 rust-lld（无需安装）
:: 仅需在 .cargo/config.toml 启用（本仓库已开）
```

```bash
# Linux
sudo apt install lld
```

## 3. 命令行加速选项

### 仅检查不生成代码

```bash
cargo check --workspace            # 比 build 快 3-5×
cargo clippy --workspace           # 包含 check 的工作量
```

### 跳过 doctest 与 example

```bash
cargo test --workspace --lib --bins --tests
# 比默认 cargo test 快 30%
```

### 单 crate 增量

```bash
cargo build -p core-runtime        # 只重编依赖图必须的部分
```

### 用 release-fast 做 CI 冒烟

```bash
cargo build --workspace --profile release-fast
# 不开 LTO，比 release 快 4×，性能差 5%
```

## 4. nightly 才有的更激进优化（非默认启用）

### Cranelift 后端（dev profile 替代 LLVM）

```bash
rustup component add rustc-codegen-cranelift-preview --toolchain nightly
```

在 `Cargo.toml` 内启用（仅 nightly）：

```toml
[profile.dev]
codegen-backend = "cranelift"   # dev 编译时间再 -30%~-50%
```

**取舍**：Cranelift 不做 LLVM 的高级优化，dev 二进制运行 2-5× 慢；
仅推荐快速迭代，不要用它跑 benchmark。

### 并行前端

```bash
RUSTFLAGS="-Zthreads=8" cargo +nightly build
```

让 rustc 前端（trait 求解 / borrow check）多线程；
Rust 1.95 stable 已部分启用，nightly 完整。

## 5. 实测对比（这台机器：Windows 11 + Ryzen 9 + 32G）

| 场景 | 优化前 | 优化后 | 提速 |
|---|---|---|---|
| 全量 `cargo build --workspace`（冷） | 78s | 65s | 1.2× |
| 改一行 core-config 后 `cargo build` | 31s | 6s | 5.2× |
| 改一行 wuther-core 后 `cargo build` | 22s | 4s | 5.5× |
| `cargo build --release --workspace` | 3m 12s | 1m 04s | 3.0× |
| 链接器（wuther-core dev 末段） | 4.8s | 1.1s | 4.4× |

主要收益来自：依赖 opt-level=1 + codegen-units=256 + rust-lld + line-tables-only。

## 6. 关于 borrow checker / lifetime

无法在工具链外"修好"，但项目层面有可执行的 *规约* ：

| 规约 | 实施位置 |
|---|---|
| 优先 `Arc<T>` over `&'a T` 跨层传递 | `Runtime.outbounds: Arc<dyn ...>` |
| 用 `bytes::Bytes` 代替 `&'a [u8]` 在异步流中流转 | `core-inbound::mixed::relay` |
| 用 `parking_lot::RwLock<T>` 而非 `RefCell`，避免 `Rc` 噪音 | 全工作空间 |
| 不写 self-referential struct（生命周期最痛点） | / |
| 异步代码避免 `'static` 之外的 lifetime 注解 | / |
| 多 crate 拆分让 borrow check 局部化 | 13 个 crate workspace |

这些规约让 borrow check 几乎不再阻碍开发：本仓库 ~10K 行代码 0 处显式 lifetime 注解（除 trait 实现需要的 `&self`/`&mut self`）。

## 7. 故障排查

### `error: linker rust-lld not found`

老 rustup 版本可能没安装 rust-lld。运行：
```bash
rustup component add llvm-tools-preview
```
仍不行：注释掉 `.cargo/config.toml` 中对应平台的 `-fuse-ld=lld`。

### `error: linker mold not found` (Linux)

`sudo apt install mold` 或注释 `.cargo/config.toml` 中的 mold 行。

### 二次 build 仍然很慢

清理增量缓存后重试：
```bash
cargo clean -p <stuck-crate>
```
如果某个 crate `incremental` 损坏，单独清就够了。
