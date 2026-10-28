# 4.1 自动验收（VM）
#
# 用法（管理员 PowerShell）：
#   cd <项目>\dist-tools
#   & .\4.1-验收脚本.ps1
#   & .\4.1-验收脚本.ps1 -SkipServiceRestart
#   & .\4.1-验收脚本.ps1 -LogPath "$env:USERPROFILE\Desktop\wag-4.1-验收.txt"
#
# 必须和 WinAppGuard.SelfCheck.exe 放在同一目录（dist-tools）；放错目录会直接报错退出。
#
# 只应在验收用的 VM 上跑：会重启服务、短暂断网、暂停/恢复流量采集，并清空流量计数。
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

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '  [失败] 请用管理员 PowerShell 运行本脚本。' -ForegroundColor Red
    if ($script:transcriptStarted) { Stop-Transcript | Out-Null }
    exit 2
}

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
        Write-Host '         请先 cd 到 dist-tools，再运行本脚本。' -ForegroundColor Yellow
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
$bundledNpcap = Join-Path $installDir 'npcap-1.90.exe'
$license = Join-Path $installDir 'Npcap-LICENSE.txt'

$npcapVersion = $null
foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst')) {
    if (Test-Path $key) {
        $npcapVersion = (Get-ItemProperty $key).DisplayVersion
        break
    }
}

Write-Host "  界面：$uiVersion"
Write-Host "  服务：$svcVersion"
Write-Host "  验收包界面：$distUiVersion"
Write-Host "  验收包服务：$distSvcVersion"
Write-Host "  Npcap：$(if (Test-Path $wpcap) { "$npcapVersion（$wpcap）" } else { '未安装' })"
Write-Host "  脚本目录：$scriptDir"

Assert-True '界面版本是 4.1' ($uiVersion -like '4.1*') "$uiVersion"
Assert-True '服务版本是 4.1' ($svcVersion -like '4.1*') "$svcVersion"
Assert-True '已安装的界面与验收包一致' ($uiVersion -eq $distUiVersion) "安装=$uiVersion 包=$distUiVersion"
Assert-True '已安装的服务与验收包一致' ($svcVersion -eq $distSvcVersion) "安装=$svcVersion 包=$distSvcVersion"
Assert-True 'Npcap 已安装（4.1 起为必需组件）' (Test-Path $wpcap) $wpcap
Assert-True '安装目录带随包 Npcap 安装程序（状态栏补装用）' (Test-Path $bundledNpcap) $bundledNpcap
Assert-True '安装目录带 Npcap 许可证' (Test-Path $license) $license
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
Write-Host '===== 3. 离线：精确流量聚合 =====' -ForegroundColor Cyan

& $selfCheck --traffic-capture-test --no-pause
$captureExit = $LASTEXITCODE
Assert-True '--traffic-capture-test 全部通过' ($captureExit -eq 0) "退出码 $captureExit"

Write-Host ''
Write-Host '===== 3.1 真实抓包冒烟（Npcap 打开 / 解析 / 归属） =====' -ForegroundColor Cyan

& $selfCheck --traffic-live-test --no-pause
$liveExit = $LASTEXITCODE
Assert-True '--traffic-live-test 全部通过' ($liveExit -eq 0) "退出码 $liveExit"

Write-Host ''
Write-Host '===== 4. 离线：反扫描规则 =====' -ForegroundColor Cyan

& $selfCheck --antiscan-test --no-pause
$antiExit = $LASTEXITCODE
Assert-True '--antiscan-test 全部通过' ($antiExit -eq 0) "退出码 $antiExit"

Write-Host ''
Write-Host '===== 5. WFP 入站临时封禁（真实过滤器） =====' -ForegroundColor Cyan

& $selfCheck --wfp-inbound-test --no-pause
$wfpExit = $LASTEXITCODE
Assert-True '--wfp-inbound-test 全部通过' ($wfpExit -eq 0) "退出码 $wfpExit"

Write-Host ''
Write-Host '===== 6. 界面回归（列宽 / 语言 / DPI） =====' -ForegroundColor Cyan

& $selfCheck --traffic-records-test --no-pause
$recordsExit = $LASTEXITCODE
Assert-True '--traffic-records-test 全部通过' ($recordsExit -eq 0) "退出码 $recordsExit"

& $selfCheck --ui-language-test --no-pause
$langExit = $LASTEXITCODE
Assert-True '--ui-language-test 全部通过' ($langExit -eq 0) "退出码 $langExit"

& $selfCheck --ui-dpi-test --no-pause
$dpiExit = $LASTEXITCODE
Assert-True '--ui-dpi-test 全部通过' ($dpiExit -eq 0) "退出码 $dpiExit"

Write-Host ''
Write-Host '===== 7. 服务端：精确流量（Npcap / 暂停 / 曲线 / 清空） =====' -ForegroundColor Cyan

& $selfCheck --service-traffic-precise-test --no-pause
$preciseExit = $LASTEXITCODE
Assert-True '--service-traffic-precise-test 全部通过' ($preciseExit -eq 0) "退出码 $preciseExit"

Write-Host ''
Write-Host '===== 8. 服务端：反扫描（Npcap / 设置 / 解除 / 清空） =====' -ForegroundColor Cyan

& $selfCheck --service-antiscan-test --no-pause
$antiServiceExit = $LASTEXITCODE
Assert-True '--service-antiscan-test 全部通过' ($antiServiceExit -eq 0) "退出码 $antiServiceExit"

Write-Host ''
Write-Host '===== 9. 服务端：DNS 与回环排除（3.5 回归） =====' -ForegroundColor Cyan

& $selfCheck --service-35-test --no-pause
$trafficExit = $LASTEXITCODE
Assert-True '--service-35-test 全部通过' ($trafficExit -eq 0) "退出码 $trafficExit"

Write-Host ''
Write-Host '===== 10. 服务端：IDS 回归 =====' -ForegroundColor Cyan

& $selfCheck --service-ids-test --no-pause
$idsServiceExit = $LASTEXITCODE
Assert-True '--service-ids-test 全部通过' ($idsServiceExit -eq 0) "退出码 $idsServiceExit"

Write-Host ''
Write-Host '===== 11. 临时锁网（会短暂断网） =====' -ForegroundColor Cyan

& $selfCheck --service-lockdown-test --no-pause
$lockdownExit = $LASTEXITCODE
Assert-True '--service-lockdown-test 全部通过' ($lockdownExit -eq 0) "退出码 $lockdownExit"

Write-Host ''
Write-Host '===== 12. 清空流量统计（会清零，放在最后） =====' -ForegroundColor Cyan

& $selfCheck --service-traffic-clear-test --no-pause
$clearExit = $LASTEXITCODE
Assert-True '--service-traffic-clear-test 全部通过' ($clearExit -eq 0) "退出码 $clearExit"

Write-Host ''
Write-Host '===== 13. ETW 会话与日志 =====' -ForegroundColor Cyan

$logman = & logman query -ets 2>&1 | Out-String
Assert-True 'DNS ETW 会话存在（WinAppGuard-Dns）' ([bool]($logman -match 'WinAppGuard-Dns\s'))
Assert-True '流量 ETW 会话存在（WinAppGuard-Net，仅供 IDS）' ([bool]($logman -match 'WinAppGuard-Net\s'))

$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$logFile = Get-ChildItem $logDir -Filter 'winappguard-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $logFile) {
    Assert-True '找到服务日志' $false $logDir
}
else {
    Write-Host "  日志：$($logFile.FullName)"
    $recent = Get-Content $logFile.FullName -Tail 1200

    Assert-True '日志里有精确流量启动记录（WAG-TRAFFIC-010）' ([bool]($recent -match 'WAG-TRAFFIC-010'))
    Assert-True '日志里有反扫描启动记录（WAG-ANTISCAN-004）' ([bool]($recent -match 'WAG-ANTISCAN-004'))
    Assert-True '日志里有 IDS 启动记录（WAG-IDS-001）' ([bool]($recent -match 'WAG-IDS-001'))
    Assert-True '日志里有 ETW 网络会话启动记录（WAG-TRAFFIC-001）' ([bool]($recent -match 'WAG-TRAFFIC-001'))
    Assert-True '日志里有 DNS 采集启动记录（WAG-DNS-002）' ([bool]($recent -match 'WAG-DNS-002'))
    Assert-True '没有持续的 Npcap 启动失败（WAG-ANTISCAN-013 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-013').Count -lt 3)
    Assert-True '没有持续的精确流量启动失败（WAG-TRAFFIC-018 少于 3 条）' (
        ($recent | Select-String 'WAG-TRAFFIC-018').Count -lt 3)
    Assert-True '没有反扫描封禁失败（WAG-ANTISCAN-014 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-014').Count -lt 3)
    Assert-True '没有持续采样失败（WAG-TRAFFIC-003 少于 3 条）' (
        ($recent | Select-String 'WAG-TRAFFIC-003').Count -lt 3)
}

Write-Host ''
Write-Host '===== 14. 需要人工确认的项 =====' -ForegroundColor Cyan
Write-Host '  A) 安装器（干净快照，且未装 Npcap）：'
Write-Host '     - 拒绝 Npcap：退出码 8；服务/文件/快捷方式/注册表项都没有创建。'
Write-Host '     - 官方 GUI 里取消：退出码 8，同样零残留。'
Write-Host '     - 让安装器失败（例如断网/占位）：退出码 9，WAG 未安装。'
Write-Host '     - 正常安装：Npcap GUI 选项为「不勾 WinPcap 兼容 / loopback / 802.11，勾选仅管理员」；'
Write-Host '       装完 %ProgramFiles%\WinAppGuard 下应有 npcap-1.90.exe 与 Npcap-LICENSE.txt。'
Write-Host '  B) 流量页：'
Write-Host '     - 曲线 5 分钟、每秒一个点；入站/出站两条线颜色可区分。'
Write-Host '     - iperf3 100 MB TCP 上下行误差 ≤1%；UDP 100 MB 误差 ≤2%。'
Write-Host '     - 1000 次 1 KB 短连接全部计入；3000 次 DNS 查询计入 UDP。'
Write-Host '     - 回环流量（127.0.0.1）不计；分片非首片归「未归属」。'
Write-Host '     - 正常使用时「丢包」为 0；>0 时页面必须标注“数据可能不完整”。'
Write-Host '     - 「暂停统计」后曲线停止，按钮变「继续统计」；继续后恢复。'
Write-Host '     - 清空后程序列表与曲线同时归零。'
Write-Host '  C) Npcap 状态项：'
Write-Host '     - 正常：`Npcap：已连接（1.90）`；停服务：`未连接（服务离线）`。'
Write-Host '     - 卸掉 Npcap → 重启服务 → `未连接（点击安装）`，点击应弹 UAC + 官方 GUI。'
Write-Host '  D) 环境与回归：'
Write-Host '     - Hyper-V / VPN / 双网卡下不重复计数；IPv6 流量能统计。'
Write-Host '     - 24h soak：无崩溃、无持续丢包、内存无持续增长。'
Write-Host '     - 3.4–4.0 回归：规则、白名单、IDS、锁网、记录页、DNS 页、防护页。'

Write-Host ''
if ($script:transcriptStarted) { Stop-Transcript | Out-Null }

if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
