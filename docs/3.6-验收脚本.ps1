# 3.6 自动验收（VM）
#
# 用法（管理员 PowerShell）：
#   powershell -ExecutionPolicy Bypass -File .\3.6-验收脚本.ps1
#   powershell -ExecutionPolicy Bypass -File .\3.6-验收脚本.ps1 -SkipServiceRestart
#
# 顺序：版本 → 重启服务 → 离线流量页 → 独立 ETW → 3.5 回归
#       → 临时锁网 → 清空流量（最后）→ ETW 会话 → 服务日志。
# 只应在验收用的 VM 上跑；会重启服务、短暂断网并清空流量计数。

param(
    [switch]$SkipServiceRestart
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$selfCheck = Join-Path $scriptDir 'WinAppGuard.SelfCheck.exe'
$installDir = Join-Path $env:ProgramFiles 'WinAppGuard'
$serviceExe = Join-Path $installDir 'WinAppGuardSvc.exe'
$uiExe = Join-Path $installDir 'WinAppGuard.exe'
$serviceName = 'WinAppGuardSvc'

$script:failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([string]$Title, [bool]$Condition, [string]$Detail = '')

    if ($Condition) {
        Write-Host "  [通过] $Title" -ForegroundColor Green
    }
    else {
        $text = if ($Detail) { "$Title（$Detail）" } else { $Title }
        Write-Host "  [失败] $text" -ForegroundColor Red
        $script:failures.Add($text)
    }
}

function Get-ProductVersion {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return $null
    }

    return (Get-Item $Path).VersionInfo.ProductVersion
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    throw '请用管理员 PowerShell 运行本脚本。'
}

Write-Host '===== 1. 安装与版本 =====' -ForegroundColor Cyan

$uiVersion = Get-ProductVersion $uiExe
$svcVersion = Get-ProductVersion $serviceExe
$distUiVersion = Get-ProductVersion (Join-Path $scriptDir 'WinAppGuard.exe')
$distSvcVersion = Get-ProductVersion (Join-Path $scriptDir 'WinAppGuardSvc.exe')

Write-Host "  界面：$uiVersion"
Write-Host "  服务：$svcVersion"
Write-Host "  验收包界面：$distUiVersion"
Write-Host "  验收包服务：$distSvcVersion"

Assert-True '界面版本是 3.6' ($uiVersion -like '3.6*') "$uiVersion"
Assert-True '服务版本是 3.6' ($svcVersion -like '3.6*') "$svcVersion"
Assert-True '已安装的界面与验收包一致' ($uiVersion -eq $distUiVersion) "安装=$uiVersion 包=$distUiVersion"
Assert-True '已安装的服务与验收包一致' ($svcVersion -eq $distSvcVersion) "安装=$svcVersion 包=$distSvcVersion"
Assert-True '自检工具存在' (Test-Path $selfCheck) $selfCheck
Assert-True '服务已安装' ($null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue))

Write-Host ''
Write-Host '===== 2. 重启服务 =====' -ForegroundColor Cyan

if (-not $SkipServiceRestart) {
    Restart-Service $serviceName -Force
    Start-Sleep -Seconds 3
}

$service = Get-Service $serviceName -ErrorAction SilentlyContinue
Assert-True '服务已运行' ($null -ne $service -and $service.Status -eq 'Running')

Write-Host ''
Write-Host '===== 3. 流量页离线检查 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --traffic-records-test --no-pause
    $recordsExit = $LASTEXITCODE
    Assert-True '--traffic-records-test 全部通过' ($recordsExit -eq 0) "退出码 $recordsExit"
}

Write-Host ''
Write-Host '===== 4. ETW Network 独立实测 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --etw-network-test --no-pause
    $etwExit = $LASTEXITCODE
    Assert-True '--etw-network-test 全部通过' ($etwExit -eq 0) "退出码 $etwExit"
}

Write-Host ''
Write-Host '===== 5. 3.5 流量 + DNS 回归 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-35-test --no-pause
    $trafficExit = $LASTEXITCODE
    Assert-True '--service-35-test 全部通过' ($trafficExit -eq 0) "退出码 $trafficExit"
}

Write-Host ''
Write-Host '===== 6. 临时锁网实测（会短暂断网） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-lockdown-test --no-pause
    $lockdownExit = $LASTEXITCODE
    Assert-True '--service-lockdown-test 全部通过' ($lockdownExit -eq 0) "退出码 $lockdownExit"
}

Write-Host ''
Write-Host '===== 7. 清空流量统计（会清零，放在最后） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-traffic-clear-test --no-pause
    $clearExit = $LASTEXITCODE
    Assert-True '--service-traffic-clear-test 全部通过' ($clearExit -eq 0) "退出码 $clearExit"
}

Write-Host ''
Write-Host '===== 8. ETW 会话 =====' -ForegroundColor Cyan

$logman = & logman query -ets 2>&1 | Out-String
Assert-True 'DNS ETW 会话存在（WinAppGuard-Dns）' ([bool]($logman -match 'WinAppGuard-Dns\s'))
Assert-True '流量 ETW 会话存在（WinAppGuard-Net）' ([bool]($logman -match 'WinAppGuard-Net\s'))

Write-Host ''
Write-Host '===== 9. 服务日志 =====' -ForegroundColor Cyan

$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$logFile = Get-ChildItem $logDir -Filter 'winappguard-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $logFile) {
    Assert-True '找到服务日志' $false $logDir
}
else {
    Write-Host "  日志：$($logFile.FullName)"
    $recent = Get-Content $logFile.FullName -Tail 400

    Assert-True '日志里有流量采集启动记录（WAG-TRAFFIC-001）' ([bool]($recent -match 'WAG-TRAFFIC-001'))
    Assert-True '日志里有 DNS 采集启动记录（WAG-DNS-002）'     ([bool]($recent -match 'WAG-DNS-002'))
    Assert-True '日志里有清空流量记录（WAG-TRAFFIC-007）'     ([bool]($recent -match 'WAG-TRAFFIC-007'))
    Assert-True '日志里没有持续的采样失败（WAG-TRAFFIC-003 少于 3 条）' (($recent | Select-String 'WAG-TRAFFIC-003').Count -lt 3)
}

Write-Host ''
Write-Host '===== 10. 需要人工确认的界面项 =====' -ForegroundColor Cyan
Write-Host '  1) 「流量」页：两个程序同时下载，确认各一行、合计正确；'
Write-Host '     点表头按总计/上传/下载/最后活动/程序名排序，箭头与顺序一致。'
Write-Host '  2) 搜索程序名 / 路径；关闭其中一个程序后记录仍在。'
Write-Host '  3) 「清空…」应弹 UAC，清空后归零、统计起点更新、托盘提示。'
Write-Host '  4) 重启服务后流量页从 0 开始、统计起点更新。'
Write-Host '  5) 英文界面页签/列头/统计行/按钮无中文；100%/150% DPI 不截断。'
Write-Host '  6) 回归：连接页流量列、DNS 页、30 分钟锁网、3.4 双账户 DACL。'

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
