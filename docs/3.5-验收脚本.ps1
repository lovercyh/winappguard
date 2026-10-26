# 3.5 自动验收（VM）
#
# 用法（管理员 PowerShell）：
#   powershell -ExecutionPolicy Bypass -File .\3.5-验收脚本.ps1
#   powershell -ExecutionPolicy Bypass -File .\3.5-验收脚本.ps1 -SkipServiceRestart
#
# 它会：
#   1. 检查安装版本 / 服务状态；
#   2. 重启服务，确认流量采集与 DNS ETW 会话启动；
#   3. 跑 --service-35-test（回环下载 + DNS 探针，输出实测数字）；
#   4. 跑 --service-lockdown-test（会短暂建立严格模式会话，立刻关闭）；
#   5. 检查 ETW 会话与服务日志。
#
# 只应在验收用的 VM 上跑；会重启服务、短暂改变断网状态。

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

Write-Host "  界面：$uiVersion"
Write-Host "  服务：$svcVersion"

Assert-True '界面版本是 3.5' ($uiVersion -like '3.5*') "$uiVersion"
Assert-True '服务版本是 3.5' ($svcVersion -like '3.5*') "$svcVersion"
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
Write-Host '===== 3. ETW Network 独立实测 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --etw-network-test --no-pause
    $etwExit = $LASTEXITCODE
    Assert-True '--etw-network-test 全部通过' ($etwExit -eq 0) "退出码 $etwExit"
}

Write-Host ''
Write-Host '===== 4. 流量 + DNS 端到端实测 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-35-test --no-pause
    $trafficExit = $LASTEXITCODE
    Assert-True '--service-35-test 全部通过' ($trafficExit -eq 0) "退出码 $trafficExit"
}

Write-Host ''
Write-Host '===== 5. 临时锁网实测（会短暂断网） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-lockdown-test --no-pause
    $lockdownExit = $LASTEXITCODE
    Assert-True '--service-lockdown-test 全部通过' ($lockdownExit -eq 0) "退出码 $lockdownExit"
}

Write-Host ''
Write-Host '===== 6. ETW 会话 =====' -ForegroundColor Cyan

$logman = & logman query -ets 2>&1 | Out-String
Assert-True 'DNS ETW 会话存在（WinAppGuard-Dns）' ([bool]($logman -match 'WinAppGuard-Dns'))
Assert-True '流量 ETW 会话存在（WinAppGuard-Net）' ([bool]($logman -match 'WinAppGuard-Net'))

Write-Host ''
Write-Host '===== 7. 服务日志 =====' -ForegroundColor Cyan

$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$logFile = Get-ChildItem $logDir -Filter 'winappguard-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $logFile) {
    Assert-True '找到服务日志' $false $logDir
}
else {
    Write-Host "  日志：$($logFile.FullName)"
    $recent = Get-Content $logFile.FullName -Tail 300

    Assert-True '日志里有流量采集启动记录（WAG-TRAFFIC-001）' ([bool]($recent -match 'WAG-TRAFFIC-001'))
    Assert-True '日志里有 DNS 采集启动记录（WAG-DNS-002）'     ([bool]($recent -match 'WAG-DNS-002'))
    Assert-True '日志里没有持续的采样失败（WAG-TRAFFIC-003 少于 3 条）' (($recent | Select-String 'WAG-TRAFFIC-003').Count -lt 3)
}

Write-Host ''
Write-Host '===== 8. 需要人工确认的界面项 =====' -ForegroundColor Cyan
Write-Host '  1) 「联网连接」页：边下载边看「上传 / 下载 / 总计」三列是否增长；'
Write-Host '     与任务管理器「性能 → 以太网」的量级对比（允许误差，界面注明仅 TCP）。'
Write-Host '  2) 用一个提权程序联网（例如管理员 PowerShell 里 Invoke-WebRequest），'
Write-Host '     确认它的路径由服务补全，不再显示「（无法获取）」。'
Write-Host '  3) 「DNS」页：打开几个网站，确认域名/PID/程序出现；'
Write-Host '     再用 DoH 浏览器访问一个站点，确认界面没有假装记录（可以看不到）。'
Write-Host '  4) 设置页 →「临时锁网 30 分钟」：'
Write-Host '     - 未加白名单的程序断网；状态栏显示倒计时；'
Write-Host '     - 点「关闭严格模式」能提前恢复；'
Write-Host '     - 再开一次后强杀服务（Stop-Service -Force），确认网络恢复且托盘提示。'
Write-Host '  5) 回归：跑一遍 3.4-验收脚本.ps1（双账户 DACL 部分按原说明执行）。'

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
