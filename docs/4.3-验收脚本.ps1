# 4.3 自动验收（VM）
#
# 用法（管理员 PowerShell）：
#   cd <项目>\dist-tools
#   & .\4.3-验收脚本.ps1
#   & .\4.3-验收脚本.ps1 -SkipServiceRestart
#   & .\4.3-验收脚本.ps1 -LogPath "$env:USERPROFILE\Desktop\wag-4.3-验收.txt"
#
# 必须和 WinAppGuard.SelfCheck.exe 放在同一目录（dist-tools）；放错目录会直接报错退出。
#
# 只应在验收用的 VM 上跑：会重启服务、短暂断网，并清空流量统计与 DNS 安全事件。
# 不会修改规则、白名单或 Windows 防火墙设置；也不会修改局域网基线。

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

Assert-True '界面版本是 4.3' ($uiVersion -like '4.3*') "$uiVersion"
Assert-True '服务版本是 4.3' ($svcVersion -like '4.3*') "$svcVersion"
Assert-True '已安装的界面与验收包一致' ($uiVersion -eq $distUiVersion) "安装=$uiVersion 包=$distUiVersion"
Assert-True '已安装的服务与验收包一致' ($svcVersion -eq $distSvcVersion) "安装=$svcVersion 包=$distSvcVersion"
Assert-True 'Npcap 已安装（4.1 起为必需组件）' (Test-Path $wpcap) $wpcap
Assert-True '安装目录带随包 Npcap 安装程序' (Test-Path $bundledNpcap) $bundledNpcap
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
Write-Host '===== 3. 离线：DNS 安全规则（新增） =====' -ForegroundColor Cyan

& $selfCheck --dns-security-test --no-pause
$dnsExit = $LASTEXITCODE
Assert-True '--dns-security-test 全部通过' ($dnsExit -eq 0) "退出码 $dnsExit"

Write-Host ''
Write-Host '===== 4. 离线回归：局域网 / 反扫描 / 流量 =====' -ForegroundColor Cyan

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
Write-Host '===== 5. 界面回归（四子标签 / 列宽 / 语言 / DPI） =====' -ForegroundColor Cyan

& $selfCheck --traffic-records-test --no-pause
$recordsExit = $LASTEXITCODE
Assert-True '--traffic-records-test 全部通过（含 DNS 安全页布局与深链）' ($recordsExit -eq 0) "退出码 $recordsExit"

& $selfCheck --ui-language-test --no-pause
$langExit = $LASTEXITCODE
Assert-True '--ui-language-test 全部通过（含四子标签英文）' ($langExit -eq 0) "退出码 $langExit"

& $selfCheck --ui-dpi-test --no-pause
$dpiExit = $LASTEXITCODE
Assert-True '--ui-dpi-test 全部通过' ($dpiExit -eq 0) "退出码 $dpiExit"

Write-Host ''
Write-Host '===== 6. 服务端：DNS 安全（状态 / 服务器 / 信任 / 清空） =====' -ForegroundColor Cyan

& $selfCheck --service-dns-security-test --no-pause
$dnsServiceExit = $LASTEXITCODE
Assert-True '--service-dns-security-test 全部通过' ($dnsServiceExit -eq 0) "退出码 $dnsServiceExit"

Write-Host ''
Write-Host '===== 7. 服务端回归：局域网 / DNS / IDS / 反扫描 =====' -ForegroundColor Cyan

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

Write-Host ''
Write-Host '===== 8. 日志与事件文件 =====' -ForegroundColor Cyan

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

    Assert-True '日志里有局域网/DNS 事件记录（WAG-LAN-017）' ([bool]($recent -match 'WAG-LAN-017'))
    Assert-True '日志里有 DNS 清空记录（WAG-LAN-021）' ([bool]($recent -match 'WAG-LAN-021'))
    Assert-True '日志里有 DNS 信任记录（WAG-LAN-022）' ([bool]($recent -match 'WAG-LAN-022'))
    Assert-True '没有持续的 Npcap 启动失败（WAG-ANTISCAN-013 少于 3 条）' (
        ($recent | Select-String 'WAG-ANTISCAN-013').Count -lt 3)
    Assert-True '没有持续的局域网启动失败（WAG-LAN-019 少于 3 条）' (
        ($recent | Select-String 'WAG-LAN-019').Count -lt 3)
}

$lanDir = Join-Path $env:ProgramData 'WinAppGuard\lan'
Assert-True '事件目录存在' (Test-Path $lanDir) $lanDir
Assert-True '状态文件存在（含 DNS 信任）' (Test-Path (Join-Path $lanDir 'state.json')) $lanDir

Write-Host ''
Write-Host '===== 9. 4.3 DNS 安全手工项 =====' -ForegroundColor Cyan
Write-Host '  A) DNS 投毒（Kali dnsspoof）：'
Write-Host '     sudo dnsspoof -i eth0 -f hosts.txt'
Write-Host '     - 5 秒内「防护 → DNS 安全」出现“应答来源异常 / 事务 ID 不匹配 / 应答域名不符”高危；'
Write-Host '       详情能指出“请求发往配置服务器，应答却来自攻击者”。'
Write-Host '     - 同时在「局域网」页可看到先发生的网关 MAC 变化，两条时间线对得上。'
Write-Host '  B) DNS 投毒（ettercap）：'
Write-Host '     sudo ettercap -T -q -i eth0 -M arp:remote /<网关>// /<验收机>//，启用 dns_spoof 插件。'
Write-Host '     - 命中规则与 A 相同；「信任此 DNS 服务器」后不再重复。'
Write-Host '  C) 明文 DNS 绕过（第二台 VM 起 dnsmasq）：'
Write-Host '     - 把验收机 DNS 手动改成 rogue DNS（非系统配置）后解析任意域名；'
Write-Host '       出现“明文 DNS 绕过”中危，目标为 rogue IP。'
Write-Host '     - 点“信任此 DNS 服务器”后不再报；取消信任后恢复。'
Write-Host '  D) 正常 24h：'
Write-Host '     - 浏览、视频、游戏、系统更新 24 小时，DNS 安全告警应为 0（TTL 低危除外需人工判断）。'
Write-Host '     - DoH/DoT 不告警（看不到内容），文档已写明边界。'
Write-Host '  E) 落盘 / 清空：'
Write-Host '     - 重启服务后 DNS 事件仍在；保留期跟随 4.2 设置（7/15/30 天）。'
Write-Host '     - DNS 安全页「清空」只删 dns_* 事件，ARP/DHCP 事件仍在；局域网页「清空」不影响 DNS 事件。'
Write-Host '  F) 界面：'
Write-Host '     - 防护页四个子标签（端口扫描 / 局域网 / DNS 安全 / IDS）可切换；'
Write-Host '       托盘高危 DNS 气泡点击定位到 DNS 安全子标签。'
Write-Host '     - 中英文、100%/150% DPI 不截断；「每 3 秒自动刷新」默认开，取消后表格不再变化。'
Write-Host '  G) 3.4–4.2 回归：规则、白名单、IDS、锁网、记录页、DNS 页、局域网页。'

Write-Host ''
if ($script:transcriptStarted) { Stop-Transcript | Out-Null }

if ($script:failures.Count -eq 0) {
    Write-Host '===== 自动检查全部通过 =====' -ForegroundColor Green
    exit 0
}

Write-Host "===== 自动检查失败 $($script:failures.Count) 项 =====" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Red }
exit 1
