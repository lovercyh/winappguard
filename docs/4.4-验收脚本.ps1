# 4.4 自动验收（VM，IPv6 邻接安全）
#
# 用法（管理员 PowerShell）：
#   cd <项目>\dist-tools
#   & .\4.4-验收脚本.ps1
#   & .\4.4-验收脚本.ps1 -SkipServiceRestart
#   & .\4.4-验收脚本.ps1 -SkipDisruptive
#   & .\4.4-验收脚本.ps1 -LogPath "$env:USERPROFILE\Desktop\wag-4.4-验收.txt"
#
# 必须和 WinAppGuard.SelfCheck.exe 放在同一目录（dist-tools）。
#
# 只应在验收 VM 上跑：会重启服务、清空 IPv6/DNS 事件，可选短暂断网。
# 不会修改规则、白名单或 Windows 防火墙设置；不会修改 IPv4/局域网基线。

param(
    [switch]$SkipServiceRestart,
    [switch]$SkipDisruptive,
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

Write-Host "  界面：$uiVersion"
Write-Host "  服务：$svcVersion"
Write-Host "  验收包界面：$distUiVersion"
Write-Host "  验收包服务：$distSvcVersion"
Write-Host "  脚本目录：$scriptDir"

Assert-True '界面版本是 4.4' ($uiVersion -like '4.4*') "$uiVersion"
Assert-True '服务版本是 4.4' ($svcVersion -like '4.4*') "$svcVersion"
Assert-True '已安装的界面与验收包一致' ($uiVersion -eq $distUiVersion) "安装=$uiVersion 包=$distUiVersion"
Assert-True '已安装的服务与验收包一致' ($svcVersion -eq $distSvcVersion) "安装=$svcVersion 包=$distSvcVersion"
Assert-True 'Npcap 已安装' (Test-Path $wpcap) $wpcap
Assert-True '安装目录带随包 Npcap 安装程序' (Test-Path $bundledNpcap) $bundledNpcap
Assert-True '安装目录带 Npcap 许可证' (Test-Path $license) $license
Assert-True '服务已安装' ($null -ne (Get-Service $serviceName -ErrorAction SilentlyContinue))

# IPv6 实验网提示（当前生产网没有 IPv6 时只提示，不判失败）。
$ipv6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike 'fe80::*' -and $_.IPAddress -ne '::1' })

if ($ipv6.Count -gt 0) {
    $ipv6 | ForEach-Object { Write-Host "  IPv6：$($_.InterfaceAlias) -> $($_.IPAddress)/$($_.PrefixLength)" }
}
else {
    Write-Host '  [提示] 没有全局 IPv6 地址；检测规则需要 IPv6 实验网（radvd）。' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '===== 2. 重启服务 =====' -ForegroundColor Cyan

if (-not $SkipServiceRestart) {
    try {
        Restart-Service $serviceName -Force -ErrorAction Stop
        Start-Sleep -Seconds 5
    }
    catch {
        Write-Host "  [警告] 重启服务失败：$($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$service = Get-Service $serviceName -ErrorAction SilentlyContinue
Assert-True '服务已运行' ($null -ne $service -and $service.Status -eq 'Running')

Write-Host ''
Write-Host '===== 3. 离线：IPv6 邻接安全（新增） =====' -ForegroundColor Cyan

& $selfCheck --ipv6-security-test --no-pause
$ipv6Exit = $LASTEXITCODE
Assert-True '--ipv6-security-test 全部通过' ($ipv6Exit -eq 0) "退出码 $ipv6Exit"

Write-Host ''
Write-Host '===== 4. 离线回归：DNS / 局域网 / 反扫描 / 流量 =====' -ForegroundColor Cyan

& $selfCheck --dns-security-test --no-pause
$dnsExit = $LASTEXITCODE
Assert-True '--dns-security-test 全部通过' ($dnsExit -eq 0) "退出码 $dnsExit"

& $selfCheck --lan-test --no-pause
$lanExit = $LASTEXITCODE
Assert-True '--lan-test 全部通过' ($lanExit -eq 0) "退出码 $lanExit"

& $selfCheck --antiscan-test --no-pause
$antiExit = $LASTEXITCODE
Assert-True '--antiscan-test 全部通过' ($antiExit -eq 0) "退出码 $antiExit"

& $selfCheck --traffic-capture-test --no-pause
$captureExit = $LASTEXITCODE
Assert-True '--traffic-capture-test 全部通过' ($captureExit -eq 0) "退出码 $captureExit"

Write-Host ''
Write-Host '===== 5. 界面回归（局域网 IPv4/IPv6 / DNS / 语言 / DPI） =====' -ForegroundColor Cyan

& $selfCheck --traffic-records-test --no-pause
$recordsExit = $LASTEXITCODE
Assert-True '--traffic-records-test 全部通过（含 IPv6 页布局与深链）' ($recordsExit -eq 0) "退出码 $recordsExit"

& $selfCheck --ui-language-test --no-pause
$langExit = $LASTEXITCODE
Assert-True '--ui-language-test 全部通过（含 IPv6 页英文）' ($langExit -eq 0) "退出码 $langExit"

& $selfCheck --ui-dpi-test --no-pause
$dpiExit = $LASTEXITCODE
Assert-True '--ui-dpi-test 全部通过' ($dpiExit -eq 0) "退出码 $dpiExit"

& $selfCheck --ui-check --no-pause
$uiExit = $LASTEXITCODE
Assert-True '--ui-check 全部通过' ($uiExit -eq 0) "退出码 $uiExit"

Write-Host ''
Write-Host '===== 6. 服务端：IPv6 邻接安全（状态 / 信任 / 清空 / 基线） =====' -ForegroundColor Cyan

& $selfCheck --service-ipv6-security-test --no-pause
$ipv6ServiceExit = $LASTEXITCODE
Assert-True '--service-ipv6-security-test 全部通过' ($ipv6ServiceExit -eq 0) "退出码 $ipv6ServiceExit"

Write-Host ''
Write-Host '===== 7. 服务端回归：DNS / 局域网 / IDS / 反扫描 =====' -ForegroundColor Cyan

& $selfCheck --service-dns-security-test --no-pause
$dnsServiceExit = $LASTEXITCODE
Assert-True '--service-dns-security-test 全部通过' ($dnsServiceExit -eq 0) "退出码 $dnsServiceExit"

& $selfCheck --service-lan-test --no-pause
$lanServiceExit = $LASTEXITCODE
Assert-True '--service-lan-test 全部通过' ($lanServiceExit -eq 0) "退出码 $lanServiceExit"

& $selfCheck --service-35-test --no-pause
$trafficExit = $LASTEXITCODE
Assert-True '--service-35-test 全部通过' ($trafficExit -eq 0) "退出码 $trafficExit"

& $selfCheck --service-ids-test --no-pause
$idsServiceExit = $LASTEXITCODE
Assert-True '--service-ids-test 全部通过' ($idsServiceExit -eq 0) "退出码 $idsServiceExit"

& $selfCheck --service-antiscan-test --no-pause
$antiServiceExit = $LASTEXITCODE
Assert-True '--service-antiscan-test 全部通过' ($antiServiceExit -eq 0) "退出码 $antiServiceExit"

if (-not $SkipDisruptive) {
    Write-Host ''
    Write-Host '===== 8. 临时锁网 / 清空流量（会短暂断网，可 -SkipDisruptive 跳过） =====' -ForegroundColor Cyan

    & $selfCheck --service-lockdown-test --no-pause
    $lockdownExit = $LASTEXITCODE
    Assert-True '--service-lockdown-test 全部通过' ($lockdownExit -eq 0) "退出码 $lockdownExit"

    & $selfCheck --service-traffic-clear-test --no-pause
    $clearTrafficExit = $LASTEXITCODE
    Assert-True '--service-traffic-clear-test 全部通过' ($clearTrafficExit -eq 0) "退出码 $clearTrafficExit"
}

Write-Host ''
Write-Host '===== 9. 日志与事件文件 =====' -ForegroundColor Cyan

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

    Assert-True '日志里有 IPv6 清空记录（WAG-LAN-023）' ([bool]($recent -match 'WAG-LAN-023'))
    Assert-True '日志里有 IPv6 信任记录（WAG-LAN-024）' ([bool]($recent -match 'WAG-LAN-024'))
    Assert-True '日志里有 IPv6 基线重置记录（WAG-LAN-025）' ([bool]($recent -match 'WAG-LAN-025'))
    Assert-True '没有持续的 Npcap 启动失败（WAG-ANTISCAN-013 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-013').Count -lt 3)
    Assert-True '没有持续的局域网启动失败（WAG-LAN-019 少于 3 条）' (
        ($recent | Select-String 'WAG-LAN-019').Count -lt 3)
}

$lanDir = Join-Path $env:ProgramData 'WinAppGuard\lan'
$ipv6Dir = Join-Path $env:ProgramData 'WinAppGuard\ipv6'
Assert-True '局域网事件目录存在' (Test-Path $lanDir) $lanDir
Assert-True 'IPv6 事件目录存在' (Test-Path $ipv6Dir) $ipv6Dir
Assert-True 'IPv6 状态文件存在' (Test-Path (Join-Path $ipv6Dir 'state.json')) $ipv6Dir

Write-Host ''
Write-Host '===== 10. 4.4 IPv6 邻接安全手工项 =====' -ForegroundColor Cyan
Write-Host '  当前生产网没有 IPv6 时，必须搭实验网：路由器 VM + radvd / Kali + thc-ipv6。'
Write-Host '  安全提示：RA 投毒可能改掉 Windows 的 IPv6 默认路由，只在隔离网络/快照里做。'
Write-Host ''
Write-Host '  A) 路由器 VM（radvd）播 fd00:4:4::/64；Windows 应拿到 fd00:4:4:: 地址和默认路由。'
Write-Host '  B) Rogue RA：sudo fake_router6 eth0 fd00:6:6::/64'
Write-Host '     → ipv6_ra_unexpected_router（高）；多路由器 / 前缀 / 生命周期 / 洪水分别验证。'
Write-Host '  C) Rogue DHCPv6：dnsmasq（不同 Server ID / DNS / 30 秒租期）'
Write-Host '     → ipv6_dhcpv6_unexpected_server（高）/ multiple / option_mismatch / short_lease。'
Write-Host '  D) NDP：fake_advertise6 / parasite6 / redir6，或 Scapy 构造 NA/NS/Redirect'
Write-Host '     → 路由器 NA MAC 变化（高）、邻居缓存不一致、MAC 多地址、NA 突发、SLLA/TLLA、Redirect、DAD。'
Write-Host '  E) 信任路由器 / DHCPv6 后不再重复；取消信任后恢复。'
Write-Host '  F) IPv6 页「清空」只删 ipv6_*；IPv4/DNS 事件不受影响；重启后基线/信任仍在。'
Write-Host '  G) 24h：合法 IPv6 网络正常使用，高危/中危应为 0；低危严格冷却。'
Write-Host '  H) WFP 阻断 POC：RA（ICMPv6 type 134）和 DHCPv6（UDP 547->546）分别试；'
Write-Host '     通过才提供“临时阻断”，NDP 永不阻断。'
Write-Host '  I) 3.4–4.3 回归：IPv4 局域网、DNS 安全、IDS、反扫描、记录、流量。'

Write-Host ''
if ($script:transcriptStarted) { Stop-Transcript | Out-Null }

if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
