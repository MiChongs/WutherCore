# FinalMask 固定 Xray Oracle

FinalMask 的上游行为固定到 Xray-core `26.7.11` 对应提交
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1`。验证脚本会拒绝其他提交或带有受跟踪改动的
Xray 工作区，先运行该提交下的全部官方 FinalMask Go 测试，再运行本项目的配置、实现与入站
PROXY Protocol 测试。

```powershell
pwsh -File scripts/verify-xray-finalmask-oracle.ps1
```

如已有固定提交的 Xray 工作区，可避免重复下载：

```powershell
$env:XRAY_CORE_ORACLE_DIR = 'D:\src\Xray-core'
pwsh -File scripts/verify-xray-finalmask-oracle.ps1
```

仅核验上游 Oracle 时使用 `-SkipRust`。脚本不会修改传入的 Xray 工作区。
