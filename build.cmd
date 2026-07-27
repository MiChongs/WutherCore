@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM WutherCore one-shot multi-platform build entry (Windows).
REM Usage:
REM   build.cmd                              default target matrix
REM   build.cmd x86_64-pc-windows-msvc       single target
REM   build.cmd --clean                      cargo clean before build
REM   build.cmd android                      shorthand for aarch64-linux-android
REM   build.cmd --tags "with_quic,with_vless" windows
REM Other args are forwarded to scripts\build-all.ps1.

set "SCRIPT_DIR=%~dp0"

where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PS=pwsh"
) else (
    set "PS=powershell"
)

set "EXTRA_ARGS="
set "TARGETS="

:parse
if "%~1"=="" goto run

if /I "%~1"=="--clean" (
    set "EXTRA_ARGS=!EXTRA_ARGS! -Clean"
    shift
    goto parse
)
if /I "%~1"=="--no-archive" (
    set "EXTRA_ARGS=!EXTRA_ARGS! -NoArchive"
    shift
    goto parse
)
if /I "%~1"=="--skip-checks" (
    set "EXTRA_ARGS=!EXTRA_ARGS! -SkipChecks"
    shift
    goto parse
)
if /I "%~1"=="--profile" (
    if "%~2"=="" (
        echo ERROR: --profile requires a value.
        exit /b 2
    )
    set "EXTRA_ARGS=!EXTRA_ARGS! -Profile %~2"
    shift
    shift
    goto parse
)
if /I "%~1"=="--tags" (
    if "%~2"=="" (
        echo ERROR: --tags requires a comma-separated value.
        exit /b 2
    )
    set "EXTRA_ARGS=!EXTRA_ARGS! -Tags ""%~2"""
    shift
    shift
    goto parse
)

REM short aliases
set "ALIAS=%~1"
if /I "!ALIAS!"=="windows"     set "ALIAS=x86_64-pc-windows-msvc"
if /I "!ALIAS!"=="win"         set "ALIAS=x86_64-pc-windows-msvc"
if /I "!ALIAS!"=="win-arm64"   set "ALIAS=aarch64-pc-windows-msvc"
if /I "!ALIAS!"=="linux"       set "ALIAS=x86_64-unknown-linux-musl"
if /I "!ALIAS!"=="linux-gnu"   set "ALIAS=x86_64-unknown-linux-gnu"
if /I "!ALIAS!"=="linux-arm64" set "ALIAS=aarch64-unknown-linux-gnu"
if /I "!ALIAS!"=="android"     set "ALIAS=aarch64-linux-android"
if /I "!ALIAS!"=="macos"       set "ALIAS=x86_64-apple-darwin"
if /I "!ALIAS!"=="macos-arm64" set "ALIAS=aarch64-apple-darwin"

if "!TARGETS!"=="" (
    set "TARGETS=!ALIAS!"
) else (
    set "TARGETS=!TARGETS!,!ALIAS!"
)
shift
goto parse

:run
if not "!TARGETS!"=="" (
    set "EXTRA_ARGS=!EXTRA_ARGS! -Targets ""!TARGETS!"""
)

%PS% -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\build-all.ps1"!EXTRA_ARGS!
exit /b %ERRORLEVEL%
