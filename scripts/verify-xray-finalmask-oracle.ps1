[CmdletBinding()]
param(
    [string]$XrayCore,
    [switch]$SkipRust
)

$ErrorActionPreference = 'Stop'
$PinnedCommit = '50231eaff98ccc31b5cbd247a721c16e97fe5ec1'
$Repository = 'https://github.com/XTLS/Xray-core.git'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Assert-LastExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation 失败，退出码 $LASTEXITCODE"
    }
}

if ([string]::IsNullOrWhiteSpace($XrayCore)) {
    if (-not [string]::IsNullOrWhiteSpace($env:XRAY_CORE_ORACLE_DIR)) {
        $XrayCore = $env:XRAY_CORE_ORACLE_DIR
    } else {
        $XrayCore = Join-Path ([System.IO.Path]::GetTempPath()) "rpkernel-xray-$PinnedCommit"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $XrayCore '.git'))) {
    New-Item -ItemType Directory -Force -Path $XrayCore | Out-Null
    git -C $XrayCore init
    Assert-LastExitCode '初始化 Xray oracle 仓库'
    git -C $XrayCore remote add origin $Repository
    Assert-LastExitCode '配置 Xray oracle 远端'
    git -C $XrayCore fetch --depth 1 origin $PinnedCommit
    Assert-LastExitCode '获取固定 Xray 提交'
    git -C $XrayCore checkout --detach FETCH_HEAD
    Assert-LastExitCode '检出固定 Xray 提交'
}

$ActualCommit = (git -C $XrayCore rev-parse HEAD).Trim()
Assert-LastExitCode '读取 Xray oracle 提交'
if ($ActualCommit -ne $PinnedCommit) {
    throw "Xray oracle 提交不匹配：期望 $PinnedCommit，实际 $ActualCommit"
}

$Dirty = git -C $XrayCore status --porcelain --untracked-files=no
Assert-LastExitCode '检查 Xray oracle 工作区'
if ($Dirty) {
    throw 'Xray oracle 已有受跟踪文件改动；拒绝在非固定源码上验证'
}

Write-Host "[oracle] Xray-core $PinnedCommit"
Push-Location $XrayCore
try {
    go test -count=1 ./transport/internet/finalmask/...
    Assert-LastExitCode '运行 Xray FinalMask 官方测试'
} finally {
    Pop-Location
}

if (-not $SkipRust) {
    Push-Location $ProjectRoot
    try {
        cargo test -p core-config stream_settings::tests --lib
        Assert-LastExitCode '运行 Rust FinalMask 配置测试'
        cargo test -p core-outbound transport::finalmask --lib
        Assert-LastExitCode '运行 Rust FinalMask 实现测试'
        cargo test -p core-inbound --lib proxy_protocol_v
        Assert-LastExitCode '运行 Rust 入站 PROXY Protocol 测试'
    } finally {
        Pop-Location
    }
}

Write-Host '[oracle] Xray 固定基线与 Rust FinalMask 测试全部通过'
