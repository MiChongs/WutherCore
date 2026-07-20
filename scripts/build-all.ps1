<#
.SYNOPSIS
  WutherCore 一键多平台构建脚本（Windows 主机）。

.DESCRIPTION
  在 Windows 11 上完成以下工作：
    1. 检测/安装 rustup、Rust target、cargo-zigbuild（首选）或 cross（兜底）。
    2. 按 -Targets 参数为多个三元组构建 release 二进制。
    3. 把每个目标产物连同 README/LICENSE/examples 打包为 zip / tar.gz。
    4. 输出 SHA256 校验文件。

  非 Windows 目标的交叉编译策略（默认 zigbuild → cross 兜底）：
    * cargo-zigbuild —— 纯 Rust + Zig 链接器，无需 Docker；
    * cross 0.2.5    —— pin 在 0.2.5 以避开新版 rustup 检查 bug；
                       需要 Docker Desktop。

.PARAMETER Targets
  覆盖默认目标列表，用逗号分隔。例：-Targets "x86_64-pc-windows-msvc,x86_64-unknown-linux-musl"

.PARAMETER Profile
  cargo profile，默认 release。

.PARAMETER NoArchive
  跳过打包步骤，仅产出二进制。

.PARAMETER SkipChecks
  跳过环境检查（假定 toolchain 已就绪）。

.PARAMETER Clean
  构建前 cargo clean。

.PARAMETER Backend
  强制指定交叉编译后端：zigbuild / cross / auto（默认 auto）。

.EXAMPLE
  pwsh -File scripts/build-all.ps1
  pwsh -File scripts/build-all.ps1 -Targets "x86_64-pc-windows-msvc"
  pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
#>
[CmdletBinding()]
param(
    [string]$Targets = "",
    [string]$Profile = "release",
    [switch]$NoArchive,
    [switch]$SkipChecks,
    [switch]$Clean,
    [ValidateSet("auto","zigbuild","cross")]
    [string]$Backend = "auto"
)

$ErrorActionPreference = "Stop"
$env:CROSS_NO_WARNINGS = "1"

# ---------- 路径 / 元数据 ----------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Resolve-Path (Join-Path $ScriptDir "..")
$DistDir     = Join-Path $RepoRoot "dist"
$BinaryName  = "wuther-core"
$Version     = (Select-String -Path (Join-Path $RepoRoot "Cargo.toml") `
                              -Pattern '^version\s*=\s*"(.+)"' `
                              -List).Matches[0].Groups[1].Value
if (-not $Version) { $Version = "0.3.0" }

# ---------- 颜色辅助 ----------
function Write-Step ($msg) { Write-Host "[$(Get-Date -Format HH:mm:ss)] >>> $msg" -ForegroundColor Cyan }
function Write-Ok   ($msg) { Write-Host "[$(Get-Date -Format HH:mm:ss)]  OK $msg"  -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "[$(Get-Date -Format HH:mm:ss)] !!! $msg" -ForegroundColor Yellow }
function Write-Err  ($msg) { Write-Host "[$(Get-Date -Format HH:mm:ss)] ERR $msg" -ForegroundColor Red }

# ---------- 默认目标 ----------
$DefaultTargets = @(
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin"
)

if ($Targets -ne "") {
    $TargetList = $Targets.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
} else {
    $TargetList = $DefaultTargets
}

# ---------- 工具检测 ----------
function Test-Tool($name) { return ($null -ne (Get-Command $name -ErrorAction SilentlyContinue)) }

$HasZig          = Test-Tool "zig"
$HasZigbuild     = Test-Tool "cargo-zigbuild"
$HasDocker       = Test-Tool "docker"
$HasCross        = Test-Tool "cross"
$HasCargoNdk     = Test-Tool "cargo-ndk"
$NdkRoot         = $null

function Ensure-Rustup {
    if (-not (Test-Tool "rustup")) {
        Write-Err "未检测到 rustup。请先安装：https://rustup.rs/"
        throw "missing rustup"
    }
    Write-Ok ("rustup: " + (rustup --version 2>$null))
    Write-Ok ("rustc:  " + (rustc  --version))
    Write-Ok ("cargo:  " + (cargo  --version))
}

function Ensure-Zig {
    if ($script:HasZig) { return $true }

    # 1) pip install ziglang
    foreach ($pyExe in @("python", "python3", "py")) {
        if (Test-Tool $pyExe) {
            Write-Step "尝试通过 $pyExe -m pip 安装 ziglang ..."
            & $pyExe -m pip install --user --upgrade ziglang 2>&1 | Out-Host
            if ($LASTEXITCODE -eq 0) {
                $py = & $pyExe -c "import ziglang, os; print(os.path.dirname(ziglang.__file__))" 2>$null
                if ($py -and (Test-Path (Join-Path $py "zig.exe"))) {
                    $env:PATH = "$py;$env:PATH"
                    $script:HasZig = $true
                    Write-Ok "zig 已就绪 ($py)"
                    return $true
                }
            }
        }
    }

    # 2) 直接下载 zig 二进制到 scripts/.cache/zig/
    $cacheDir = Join-Path $ScriptDir ".cache/zig"
    if (-not (Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir | Out-Null
    }
    $existing = Get-ChildItem -Path $cacheDir -Filter "zig.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        $env:PATH = "$($existing.DirectoryName);$env:PATH"
        $script:HasZig = $true
        Write-Ok "zig 已就绪（缓存）：$($existing.FullName)"
        return $true
    }

    $zigVersion = "0.13.0"
    $zigArch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
    $zipName = "zig-windows-$zigArch-$zigVersion.zip"
    $url = "https://ziglang.org/download/$zigVersion/$zipName"
    $zipPath = Join-Path $cacheDir $zipName
    Write-Step "下载 zig $zigVersion ($url) ..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Warn2 "下载 zig 失败：$_"
        return $false
    }
    Expand-Archive -Path $zipPath -DestinationPath $cacheDir -Force
    Remove-Item $zipPath -Force
    $found = Get-ChildItem -Path $cacheDir -Filter "zig.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) {
        $env:PATH = "$($found.DirectoryName);$env:PATH"
        $script:HasZig = $true
        Write-Ok "zig 已就绪（已下载）：$($found.FullName)"
        return $true
    }
    Write-Warn2 "未能自动安装 zig。请从 https://ziglang.org/download/ 下载 zig.exe 并加入 PATH。"
    return $false
}

function Ensure-Zigbuild {
    if ($script:HasZigbuild) { return $true }
    Write-Step "安装 cargo-zigbuild ..."
    cargo install cargo-zigbuild --locked 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        $script:HasZigbuild = $true
        return $true
    }
    Write-Warn2 "cargo-zigbuild 安装失败"
    return $false
}

function Ensure-Cross-Pinned {
    # 安装 cross 0.2.5（更新版本在 Windows 主机有 'toolchain may not be able to run' 的 bug）。
    Write-Step "安装/锁定 cross 0.2.5（Windows 兼容） ..."
    cargo install cross --version 0.2.5 --locked 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        $script:HasCross = $true
        return $true
    }
    return $false
}

function Need-Cross($target) {
    return ($target -like "*-unknown-freebsd*")
}

function Need-Ndk($target) {
    return ($target -like "*-linux-android*")
}

function Find-Ndk {
    if ($script:NdkRoot) { return $script:NdkRoot }

    # ---------- (1) 显式 NDK 环境变量 ----------
    foreach ($v in @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME", "ANDROID_NDK")) {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val -and (Test-Path (Join-Path $val "source.properties"))) {
            $script:NdkRoot = $val
            return $val
        }
    }

    # 选取候选 ndk 父目录里 *cargo-ndk 4.x 兼容* 且版本号最大的一个 NDK。
    # cargo-ndk 4.1.2 在 NDK r28+ 上 panic（toolchain 目录布局变化），
    # 因此只接受 r17..r27 之间的版本；都没有则降级取任意可用版本。
    function _NdkMajor([string]$dirName) {
        $m = [regex]::Match($dirName, '^(\d+)')
        if ($m.Success) { return [int]$m.Value }
        return 0
    }
    function _PickLatestNdk([string]$ndkParent) {
        if (-not (Test-Path $ndkParent)) { return $null }
        $candidates = Get-ChildItem -Directory -Path $ndkParent -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "source.properties") }
        if (-not $candidates) { return $null }
        $sorter = {
            $name = $_.Name
            $parts = $name -split '\.'
            $major = _NdkMajor $name
            $minor = if ($parts.Count -ge 2) { [int]([regex]::Match($parts[1], '\d+').Value -as [int]) } else { 0 }
            $patch = if ($parts.Count -ge 3) { [int]([regex]::Match($parts[2], '\d+').Value -as [int]) } else { 0 }
            $major * 1000000 + $minor * 1000 + $patch
        }
        $compatible = $candidates | Where-Object { $maj = _NdkMajor $_.Name ; $maj -ge 17 -and $maj -le 27 }
        if ($compatible) {
            $best = $compatible | Sort-Object @{ Expression = $sorter } -Descending | Select-Object -First 1
            return $best.FullName
        }
        $best = $candidates | Sort-Object @{ Expression = $sorter } -Descending | Select-Object -First 1
        return $best.FullName
    }

    # ---------- (2) ANDROID_HOME / ANDROID_SDK_ROOT/ndk ----------
    foreach ($v in @("ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK_HOME")) {
        $val = [Environment]::GetEnvironmentVariable($v)
        if (-not $val) { continue }
        foreach ($sub in @("ndk", "ndk-bundle")) {
            $cand = Join-Path $val $sub
            if (Test-Path (Join-Path $cand "source.properties")) {
                $script:NdkRoot = $cand
                return $cand
            }
            $latest = _PickLatestNdk $cand
            if ($latest) { $script:NdkRoot = $latest; return $latest }
        }
    }

    # ---------- (3) 默认用户目录候选 ----------
    $userProfile = $env:USERPROFILE
    if (-not $userProfile) { $userProfile = [Environment]::GetFolderPath("UserProfile") }
    $localApp    = $env:LOCALAPPDATA
    if (-not $localApp) { $localApp = Join-Path $userProfile "AppData\Local" }
    $progFiles   = $env:ProgramFiles
    $progFilesX  = ${env:ProgramFiles(x86)}
    $progData    = $env:ProgramData
    if (-not $progData) { $progData = "C:\ProgramData" }

    # Android Studio 默认安装位置 + JetBrains Toolbox + 各种历史路径。
    $candidates = @()
    foreach ($base in @(
        (Join-Path $localApp  "Android\Sdk"),
        (Join-Path $localApp  "Android\sdk"),
        (Join-Path $userProfile "Android\Sdk"),
        (Join-Path $userProfile "AppData\Roaming\Android\Sdk"),
        (Join-Path $userProfile ".android\sdk"),
        (Join-Path $progData  "Android\sdk"),
        "C:\Android\Sdk",
        "C:\Android\sdk",
        "C:\android-sdk",
        "D:\Android\Sdk",
        "D:\android-sdk"
    )) {
        if ($base -and (Test-Path $base)) {
            $candidates += (Join-Path $base "ndk")
            $candidates += (Join-Path $base "ndk-bundle")
        }
    }

    # 直接放在用户目录下的独立 NDK
    foreach ($base in @(
        (Join-Path $userProfile "AndroidNDK"),
        (Join-Path $userProfile "android-ndk"),
        (Join-Path $userProfile "ndk"),
        (Join-Path $localApp  "Android\NDK"),
        (Join-Path $progFiles "Android\android-ndk"),
        (Join-Path $progFilesX "Android\android-ndk"),
        "C:\android-ndk",
        "D:\android-ndk"
    )) {
        if ($base -and (Test-Path $base)) {
            if (Test-Path (Join-Path $base "source.properties")) {
                $script:NdkRoot = $base
                return $base
            }
            # 父目录下展开的 android-ndk-rXX
            $sub = Get-ChildItem -Directory -Path $base -ErrorAction SilentlyContinue |
                   Where-Object { Test-Path (Join-Path $_.FullName "source.properties") } |
                   Sort-Object Name -Descending | Select-Object -First 1
            if ($sub) { $script:NdkRoot = $sub.FullName; return $sub.FullName }
        }
    }

    foreach ($cand in $candidates) {
        if (Test-Path (Join-Path $cand "source.properties")) {
            $script:NdkRoot = $cand
            return $cand
        }
        $latest = _PickLatestNdk $cand
        if ($latest) { $script:NdkRoot = $latest; return $latest }
    }

    # ---------- (4) 注册表（Android Studio SDK Path） ----------
    try {
        foreach ($key in @(
            "HKCU:\SOFTWARE\Android Studio",
            "HKLM:\SOFTWARE\Android Studio",
            "HKCU:\SOFTWARE\Google\AndroidStudio"
        )) {
            if (Test-Path $key) {
                $sdk = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).SdkPath
                if ($sdk) {
                    $cand = Join-Path $sdk "ndk"
                    $latest = _PickLatestNdk $cand
                    if ($latest) { $script:NdkRoot = $latest; return $latest }
                }
            }
        }
    } catch {}

    return $null
}

function Ensure-Ndk {
    $found = Find-Ndk
    if ($found) {
        $env:ANDROID_NDK_HOME = $found
        Write-Ok "Android NDK: $found"
        return $true
    }
    Write-Warn2 @"
未检测到 Android NDK。已搜索：
  - 环境变量 ANDROID_NDK_HOME / ANDROID_NDK_ROOT / NDK_HOME / ANDROID_NDK
  - ANDROID_HOME / ANDROID_SDK_ROOT / ANDROID_SDK_HOME 下的 ndk / ndk-bundle
  - %LOCALAPPDATA%\Android\Sdk\ndk\* （Android Studio 默认）
  - %USERPROFILE%\AndroidNDK / android-ndk / ndk
  - C:\Android\Sdk\ndk\* / C:\android-ndk / D:\Android\Sdk\ndk\* / D:\android-ndk
  - HKCU/HKLM\SOFTWARE\Android Studio (SdkPath)\ndk

请二选一安装：
  (a) Android Studio → SDK Manager → SDK Tools → NDK (Side by side)
  (b) https://developer.android.com/ndk/downloads 下载 r26+ 解压

然后设置：
  setx ANDROID_NDK_HOME C:\path\to\android-ndk-r26d
（重开终端后生效）
"@
    return $false
}

function Ensure-CargoNdk {
    if ($script:HasCargoNdk) { return $true }
    Write-Step "安装 cargo-ndk ..."
    cargo install cargo-ndk --locked 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        $script:HasCargoNdk = $true
        return $true
    }
    Write-Warn2 "cargo-ndk 安装失败"
    return $false
}

function Android-Abi($target) {
    switch ($target) {
        "aarch64-linux-android"   { return "arm64-v8a" }
        "armv7-linux-androideabi" { return "armeabi-v7a" }
        "x86_64-linux-android"    { return "x86_64" }
        "i686-linux-android"      { return "x86" }
        default { return $null }
    }
}

# cross 内部会调用 `rustup toolchain add stable-<HOST_FOR_TARGET>`，
# rustup 1.28+ 在 Windows 主机会拒绝安装 Linux toolchain。
# 预先用 --force-non-host 添加好，cross 就会发现已存在直接跳过。
function Ensure-CrossHostToolchain($target) {
    $hostTriple = switch -Wildcard ($target) {
        "*android*"        { "x86_64-unknown-linux-gnu" }
        "*-unknown-linux*" { "x86_64-unknown-linux-gnu" }
        "*-unknown-freebsd*"{ "x86_64-unknown-linux-gnu" }
        default            { return }
    }
    $toolchain = "stable-$hostTriple"
    Write-Step "预装 cross 需要的 toolchain $toolchain (--force-non-host)"
    rustup toolchain install $toolchain --profile minimal --force-non-host 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "预装 toolchain $toolchain 失败 —— cross 后续可能出错"
    }
}

function Need-Crosscompile($target) {
    if ($target -like "*pc-windows-msvc") { return $false }
    return $true
}

function Skip-OnWindows($target) {
    return ($target -like "*-apple-*") # macOS 目标无法在 Windows 主机交叉编译。
}

# ---------- 环境检查 ----------
if (-not $SkipChecks) {
    Write-Step "环境检查"
    Ensure-Rustup

    # Android：优先准备 cargo-ndk。
    $needNdk = $TargetList | Where-Object { Need-Ndk $_ }
    if ($needNdk) {
        if (Ensure-Ndk) { [void](Ensure-CargoNdk) }
    }

    $needCross = $TargetList | Where-Object { Need-Crosscompile $_ -and -not (Skip-OnWindows $_) -and -not (Need-Ndk $_) }
    if ($needCross) {
        if ($Backend -eq "cross") {
            if (-not $HasDocker) {
                Write-Warn2 "Backend=cross 但未检测到 docker；非 Windows 目标可能失败。"
            } elseif (-not $HasCross) {
                [void](Ensure-Cross-Pinned)
            }
        } elseif ($Backend -eq "zigbuild") {
            if (-not (Ensure-Zig))      { Write-Warn2 "zig 不可用 —— zigbuild 后端不可用" }
            if (-not (Ensure-Zigbuild)) { Write-Warn2 "cargo-zigbuild 不可用" }
        } else {
            # auto：优先 zigbuild；其次 cross
            $z = $false
            if (Ensure-Zig) { if (Ensure-Zigbuild) { $z = $true } }
            if (-not $z) {
                if ($HasDocker) {
                    [void](Ensure-Cross-Pinned)
                } else {
                    Write-Warn2 "zigbuild 与 cross 均不可用 —— 非 Windows 目标将被跳过"
                }
            }
        }
    }
}

# ---------- 后端选择 ----------
function Pick-Backend($target) {
    if (-not (Need-Crosscompile $target)) { return "cargo" }
    if (Need-Ndk $target) {
        # Android：优先 cargo-ndk。cross 0.2.5 的 android 镜像缺 libunwind，
        # 默认不回落到 cross；用户必须显式 -Backend cross 才会走那条路径
        # （脚本会写入 Cross.toml 的 unwind 修复）。
        if ($script:HasCargoNdk -and $script:NdkRoot) { return "ndk" }
        if ($Backend -eq "cross" -and $script:HasCross) { return "cross" }
        Write-Warn2 "android 目标需要 ANDROID_NDK_HOME（推荐 NDK r26+）。如果一定要用 cross，请加 -Backend cross。"
        return "skip"
    }
    if (Need-Cross $target) {
        if ($script:HasCross) { return "cross" }
        return "skip"
    }
    if ($Backend -eq "cross") {
        if ($script:HasCross) { return "cross" } else { return "skip" }
    }
    if ($Backend -eq "zigbuild") {
        if ($script:HasZig -and $script:HasZigbuild) { return "zigbuild" } else { return "skip" }
    }
    # auto
    if ($script:HasZig -and $script:HasZigbuild) { return "zigbuild" }
    if ($script:HasCross) { return "cross" }
    return "skip"
}

# ---------- 清理 ----------
if ($Clean) {
    Write-Step "cargo clean"
    Push-Location $RepoRoot
    cargo clean
    Pop-Location
}

# ---------- 准备 dist ----------
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
}

$Summary = @()
$Failed  = @()

foreach ($target in $TargetList) {
    Write-Step "构建目标: $target"

    if (Skip-OnWindows $target) {
        Write-Warn2 "跳过 $target （macOS/iOS 目标需要 macOS 主机）"
        $Failed += [pscustomobject]@{ Target=$target; Reason="skip:host=windows" }
        continue
    }

    $useBackend = Pick-Backend $target
    if ($useBackend -eq "skip") {
        Write-Warn2 "跳过 $target （无可用交叉编译后端）"
        $Failed += [pscustomobject]@{ Target=$target; Reason="skip:no-backend" }
        continue
    }

    # 总是预 add target，避免 cross/zigbuild 内部触发 toolchain 安装。
    Write-Step "rustup target add $target"
    rustup target add $target 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "rustup target add $target 失败"
        $Failed += [pscustomobject]@{ Target=$target; Reason="rustup-add failed" }
        continue
    }

    # 如果会走 cross 后端，预装 cross 需要的"非宿主"toolchain。
    if ($useBackend -eq "cross") {
        Ensure-CrossHostToolchain $target
    }

    Push-Location $RepoRoot
    try {
        $args = @()
        switch ($useBackend) {
            "cargo" {
                $cmd  = "cargo"
                $args = @("build", "--$Profile", "-p", $BinaryName, "--target", $target, "--locked")
            }
            "zigbuild" {
                $cmd  = "cargo"
                $args = @("zigbuild", "--$Profile", "-p", $BinaryName, "--target", $target, "--locked")
            }
            "cross" {
                $cmd  = "cross"
                $args = @("build", "--$Profile", "-p", $BinaryName, "--target", $target, "--locked")
            }
            "ndk" {
                $abi = Android-Abi $target
                if (-not $abi) { throw "无法识别 android 三元组: $target" }
                $cmd  = "cargo"
                # cargo-ndk 4.x: --platform 指定 API 级别（旧版 -p 33 已被 cargo --package 占用）。
                $args = @("ndk", "--target", $abi, "--platform", "33", "build", "--$Profile", "-p", $BinaryName, "--target", $target, "--locked")
            }
        }
        Write-Step "$cmd $($args -join ' ')"
        & $cmd @args
        if ($LASTEXITCODE -ne 0) { throw "$cmd build failed (exit $LASTEXITCODE)" }

        $exeSuffix = if ($target -like "*windows*") { ".exe" } else { "" }
        $built = Join-Path $RepoRoot ("target/$target/$Profile/" + $BinaryName + $exeSuffix)
        if (-not (Test-Path $built)) { throw "build artifact not found: $built" }
        $size = (Get-Item $built).Length
        Write-Ok ("产物: {0}  ({1:N1} MB) [{2}]" -f $built, ($size / 1MB), $useBackend)

        $stageDir = Join-Path $DistDir ("$BinaryName-$Version-$target")
        if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
        New-Item -ItemType Directory -Path $stageDir | Out-Null
        Copy-Item $built (Join-Path $stageDir ($BinaryName + $exeSuffix))
        Copy-Item (Join-Path $RepoRoot "README.md") $stageDir
        Copy-Item (Join-Path $RepoRoot "RP内核设计文档.md") $stageDir -ErrorAction SilentlyContinue
        Copy-Item (Join-Path $RepoRoot "examples") (Join-Path $stageDir "examples") -Recurse

        if (-not $NoArchive) {
            $archiveBase = "$BinaryName-$Version-$target"
            if ($target -like "*windows*") {
                $archive = Join-Path $DistDir ($archiveBase + ".zip")
                if (Test-Path $archive) { Remove-Item $archive -Force }
                Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $archive -Force
            } else {
                $archiveName = $archiveBase + ".tar.gz"
                $archive = Join-Path $DistDir $archiveName
                if (Test-Path $archive) { Remove-Item $archive -Force }
                Push-Location $DistDir
                try {
                    # Windows 上 tar.exe 不接受带盘符的绝对路径作为 -f 参数；
                    # 在 $DistDir 内用相对路径，归档落在当前目录。
                    & tar -czf $archiveName $archiveBase
                    if ($LASTEXITCODE -ne 0) { throw "tar failed (exit $LASTEXITCODE)" }
                } finally {
                    Pop-Location
                }
            }
            $sha = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
            Set-Content -Path ($archive + ".sha256") -Value "$sha  $(Split-Path $archive -Leaf)" -Encoding ASCII
            Write-Ok "归档: $archive"
            $Summary += [pscustomobject]@{
                Target  = $target
                Backend = $useBackend
                Path    = $archive
                SizeMB  = [math]::Round((Get-Item $archive).Length / 1MB, 2)
                SHA256  = $sha
            }
        } else {
            $Summary += [pscustomobject]@{
                Target  = $target
                Backend = $useBackend
                Path    = $stageDir
                SizeMB  = [math]::Round($size / 1MB, 2)
                SHA256  = ""
            }
        }
    } catch {
        Write-Err "目标 $target 失败：$_"
        if (Need-Ndk $target -and $useBackend -eq "cross") {
            Write-Warn2 @"
Android 推荐改用 cargo-ndk：
  1. 安装 Android NDK r26+ (https://developer.android.com/ndk/downloads)
  2. setx ANDROID_NDK_HOME C:\path\to\android-ndk-r26d
  3. 重开终端后重跑 build.cmd android
"@
        }
        $Failed += [pscustomobject]@{ Target=$target; Reason=$_.Exception.Message }
    } finally {
        Pop-Location
    }
}

# ---------- 总结 ----------
Write-Host ""
Write-Step "构建完成总结"
if ($Summary.Count -gt 0) {
    $Summary | Format-Table Target, Backend, Path, SizeMB, SHA256 -AutoSize
} else {
    Write-Warn2 "没有成功构建的目标。"
}
if ($Failed.Count -gt 0) {
    Write-Host ""
    Write-Warn2 "以下目标被跳过或失败："
    $Failed | Format-Table -AutoSize
    if ($Summary.Count -eq 0) { exit 1 }
}
exit 0
