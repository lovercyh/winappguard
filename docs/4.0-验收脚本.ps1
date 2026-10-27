# 4.0 自动验收（VM）
#
# 用法（管理员 PowerShell）：
#   cd <项目>\dist-tools
#   & .\4.0-验收脚本.ps1
#   & .\4.0-验收脚本.ps1 -SkipServiceRestart
#   & .\4.0-验收脚本.ps1 -LogPath "$env:USERPROFILE\Desktop\wag-4.0-验收.txt"
#
# 必须和 WinAppGuard.SelfCheck.exe 放在同一目录（dist-tools）；放错目录会直接报错退出，
# 不会静默跳过 3–11 步。
#
# 只应在验收用的 VM 上跑；会重启服务、短暂断网，并清空反扫描事件 / 临时封禁 / 流量计数。
# 不会修改规则、白名单或 Windows 防火墙设置。

param(
    [switch]$SkipServiceRestart,
    [string]$LogPath = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:transcriptStarted = $false

if ($LogPath) {
    try {
        Start-Transcript -Path $LogPath -Force | Out-Null
        $script:transcriptStarted = $true
    }
    catch {
        Write-Host "  [警告] 无法写入日志文件：$LogPath（$($_.Exception.Message)）" -ForegroundColor Yellow
    }
}

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

# 自检工具必须和脚本在同一目录。放错目录（例如 docs）时直接失败，
# 否则 3–11 步会被静默跳过，最后还会误报“只剩 3 项失败”。
if (-not (Test-Path $selfCheck)) {
    $candidates = @(
        (Join-Path $scriptDir '..\dist-tools'),
        (Join-Path $scriptDir '..\dist')
    ) | ForEach-Object { [IO.Path]::GetFullPath($_) }

    $found = $candidates | Where-Object { Test-Path (Join-Path $_ 'WinAppGuard.SelfCheck.exe') } |
        Select-Object -First 1

    if ($found) {
        $selfCheck = Join-Path $found 'WinAppGuard.SelfCheck.exe'
        $scriptDir = $found
        Write-Host "  [提示] 脚本不在 dist-tools，已自动改用：$scriptDir" -ForegroundColor Yellow
    }
    else {
        Write-Host '  [失败] 找不到 WinAppGuard.SelfCheck.exe，验收无法继续。' -ForegroundColor Red
        Write-Host '         请先 cd 到 dist-tools，再运行本脚本，例如：' -ForegroundColor Yellow
        Write-Host '           cd <项目>\dist-tools' -ForegroundColor Yellow
        Write-Host '           & .\4.0-验收脚本.ps1 -LogPath "$env:USERPROFILE\Desktop\wag-4.0-验收.txt"' -ForegroundColor Yellow

        if ($script:transcriptStarted) { Stop-Transcript | Out-Null }
        exit 2
    }
}

Write-Host '===== 1. 安装、版本与 Npcap =====' -ForegroundColor Cyan

$uiVersion = Get-ProductVersion $uiExe
$svcVersion = Get-ProductVersion $serviceExe
$distUiVersion = Get-ProductVersion (Join-Path $scriptDir 'WinAppGuard.exe')
$distSvcVersion = Get-ProductVersion (Join-Path $scriptDir 'WinAppGuardSvc.exe')
$wpcap = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'

$npcapVersion = $null
foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst')) {
    if (Test-Path $key) {
        $npcapVersion = (Get-ItemProperty $key).DisplayVersion
        break
    }
}

if (-not $npcapVersion -and (Test-Path $wpcap)) {
    $npcapVersion = (Get-Item $wpcap).VersionInfo.FileVersion
}

Write-Host "  界面：$uiVersion"
Write-Host "  服务：$svcVersion"
Write-Host "  验收包界面：$distUiVersion"
Write-Host "  验收包服务：$distSvcVersion"
Write-Host "  Npcap：$(if (Test-Path $wpcap) { "$npcapVersion（$wpcap）" } else { '未安装' })"
Write-Host "  脚本目录：$scriptDir"

Assert-True '界面版本是 4.0' ($uiVersion -like '4.0*') "$uiVersion"
Assert-True '服务版本是 4.0' ($svcVersion -like '4.0*') "$svcVersion"
Assert-True '已安装的界面与验收包一致' ($uiVersion -eq $distUiVersion) "安装=$uiVersion 包=$distUiVersion"
Assert-True '已安装的服务与验收包一致' ($svcVersion -eq $distSvcVersion) "安装=$svcVersion 包=$distSvcVersion"
Assert-True 'Npcap 已安装（反扫描需要）' (Test-Path $wpcap) $wpcap
Assert-True '服务已安装' ($null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue))

Write-Host ''
Write-Host '===== 2. 重启服务 =====' -ForegroundColor Cyan

if (-not $SkipServiceRestart) {
    Restart-Service $serviceName -Force
    Start-Sleep -Seconds 5
}

$service = Get-Service $serviceName -ErrorAction SilentlyContinue
Assert-True '服务已运行' ($null -ne $service -and $service.Status -eq 'Running')

Write-Host ''
Write-Host '===== 3. 反扫描离线规则 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --antiscan-test --no-pause
    $antiExit = $LASTEXITCODE
    Assert-True '--antiscan-test 全部通过' ($antiExit -eq 0) "退出码 $antiExit"
}

Write-Host ''
Write-Host '===== 4. WFP 入站临时封禁（真实过滤器） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --wfp-inbound-test --no-pause
    $wfpExit = $LASTEXITCODE
    Assert-True '--wfp-inbound-test 全部通过' ($wfpExit -eq 0) "退出码 $wfpExit"
}

Write-Host ''
Write-Host '===== 5. 3.7 IDS 与 3.6 流量页回归 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --ids-test --no-pause
    $idsExit = $LASTEXITCODE
    Assert-True '--ids-test 全部通过' ($idsExit -eq 0) "退出码 $idsExit"

    & $selfCheck --traffic-records-test --no-pause
    $recordsExit = $LASTEXITCODE
    Assert-True '--traffic-records-test 全部通过' ($recordsExit -eq 0) "退出码 $recordsExit"
}

Write-Host ''
Write-Host '===== 6. ETW Network 独立实测 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --etw-network-test --no-pause
    $etwExit = $LASTEXITCODE
    Assert-True '--etw-network-test 全部通过' ($etwExit -eq 0) "退出码 $etwExit"
}

Write-Host ''
Write-Host '===== 7. 3.5 流量 + DNS 回归 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-35-test --no-pause
    $trafficExit = $LASTEXITCODE
    Assert-True '--service-35-test 全部通过' ($trafficExit -eq 0) "退出码 $trafficExit"
}

Write-Host ''
Write-Host '===== 8. 反扫描服务端（Npcap / 设置 / 解除 / 清空） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-antiscan-test --no-pause
    $antiServiceExit = $LASTEXITCODE
    Assert-True '--service-antiscan-test 全部通过' ($antiServiceExit -eq 0) "退出码 $antiServiceExit"
}

Write-Host ''
Write-Host '===== 9. 3.7 IDS 服务端回归 =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-ids-test --no-pause
    $idsServiceExit = $LASTEXITCODE
    Assert-True '--service-ids-test 全部通过' ($idsServiceExit -eq 0) "退出码 $idsServiceExit"
}

Write-Host ''
Write-Host '===== 10. 临时锁网（会短暂断网） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-lockdown-test --no-pause
    $lockdownExit = $LASTEXITCODE
    Assert-True '--service-lockdown-test 全部通过' ($lockdownExit -eq 0) "退出码 $lockdownExit"
}

Write-Host ''
Write-Host '===== 11. 清空流量统计（会清零，放在最后） =====' -ForegroundColor Cyan

if (Test-Path $selfCheck) {
    & $selfCheck --service-traffic-clear-test --no-pause
    $clearExit = $LASTEXITCODE
    Assert-True '--service-traffic-clear-test 全部通过' ($clearExit -eq 0) "退出码 $clearExit"
}

Write-Host ''
Write-Host '===== 12. ETW 会话 =====' -ForegroundColor Cyan

$logman = & logman query -ets 2>&1 | Out-String
Assert-True 'DNS ETW 会话存在（WinAppGuard-Dns）' ([bool]($logman -match 'WinAppGuard-Dns\s'))
Assert-True '流量 ETW 会话存在（WinAppGuard-Net）' ([bool]($logman -match 'WinAppGuard-Net\s'))

Write-Host ''
Write-Host '===== 13. 服务日志 =====' -ForegroundColor Cyan

$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$logFile = Get-ChildItem $logDir -Filter 'winappguard-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $logFile) {
    Assert-True '找到服务日志' $false $logDir
}
else {
    Write-Host "  日志：$($logFile.FullName)"
    $recent = Get-Content $logFile.FullName -Tail 800

    Assert-True '日志里有反扫描启动记录（WAG-ANTISCAN-004）' ([bool]($recent -match 'WAG-ANTISCAN-004'))
    Assert-True '日志里有 IDS 启动记录（WAG-IDS-001）' ([bool]($recent -match 'WAG-IDS-001'))
    Assert-True '日志里有流量采集启动记录（WAG-TRAFFIC-001）' ([bool]($recent -match 'WAG-TRAFFIC-001'))
    Assert-True '日志里有 DNS 采集启动记录（WAG-DNS-002）' ([bool]($recent -match 'WAG-DNS-002'))
    Assert-True '没有持续的 Npcap 启动失败（WAG-ANTISCAN-013 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-013').Count -lt 3)
    Assert-True '没有持续的反扫描封禁失败（WAG-ANTISCAN-014 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-014').Count -lt 3)
    Assert-True '没有持续的 IDS 告警写盘失败（WAG-IDS-003 少于 3 条）' (
        ($recent | Select-String 'WAG-IDS-003').Count -lt 3)
    Assert-True '没有持续的采样失败（WAG-TRAFFIC-003 少于 3 条）' (
        ($recent | Select-String 'WAG-TRAFFIC-003').Count -lt 3)
}

Write-Host ''
Write-Host '===== 14. 需要人工确认的界面项 =====' -ForegroundColor Cyan
Write-Host '  1) 安装包：干净 VM 双击 Setup，选择安装 Npcap，确认弹出的官方 GUI 选项：'
Write-Host '     WinPcap 兼容模式 / loopback / 802.11 不勾；Restrict to Administrators 勾选。'
Write-Host '     用户取消 Npcap 时，防火墙主功能仍可用，防护页明确显示 Npcap 未安装。'
Write-Host '  2) 「防护」页：Npcap 版本、采集中、事件 / 临时封禁数量正确；'
Write-Host '     来源 IP 可搜索；中英文、100%/150% DPI 不截断。'
Write-Host '  3) 在第二台 VM 用 nmap 对本机做连接扫描（-sT）；IDS/防护页出现入站扫描事件。'
Write-Host '  4) 设置里开启「自动临时封禁」，高危扫描后来源 IP 出现在临时封禁列表；'
Write-Host '     「解除选中 / 解除全部」后来源可以重新连接；到期后自动消失。'
Write-Host '  5) 关闭反扫描后不再产生新事件，已有临时封禁解除；服务停止后不会留下孤儿封禁。'
Write-Host '  6) 回归：连接页流量列、DNS 页、流量页、IDS 页、30 分钟锁网、3.4 双账户 DACL。'
Write-Host '  7) 24 小时 soak：CPU / 内存 / 反扫描事件数 / 临时封禁数 / 丢弃计数。'

Write-Host ''
if ($script:transcriptStarted) { Stop-Transcript | Out-Null }

if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
