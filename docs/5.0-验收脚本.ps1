# WinAppGuard 5.0 网络被动检测验收脚本
#
# 用法（管理员 PowerShell）：
#   powershell -ExecutionPolicy Bypass -File .\5.0-验收脚本.ps1
#
# 只检查已安装环境和基础状态，不生成恶意流量。

$ErrorActionPreference = 'Stop'
$install = Join-Path $env:ProgramFiles 'WinAppGuard'
$data = Join-Path $env:ProgramData 'WinAppGuard\network-detection'
$suricataDir = Join-Path $data 'suricata'
$rulesDir = Join-Path $suricataDir 'rules'
$fails = 0

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) {
        Write-Host "[通过] $name $detail" -ForegroundColor Green
    } else {
        Write-Host "[失败] $name $detail" -ForegroundColor Red
        $script:fails++
    }
}

Write-Host '== WinAppGuard 5.0 网络被动检测 =='

Check '安装目录存在' (Test-Path $install) $install
Check 'GPL-2.0 许可证' (Test-Path (Join-Path $install 'GPL-2.0.txt'))
Check '第三方 notices' (Test-Path (Join-Path $install 'THIRD-PARTY-NOTICES.md'))
Check 'Suricata 源码说明' (Test-Path (Join-Path $install 'SURICATA-SOURCE-OFFER.txt'))

$suricata = @(
    (Join-Path $install 'suricata\suricata.exe'),
    (Join-Path $env:ProgramFiles 'Suricata\suricata.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1

Check 'Suricata 已安装' ($null -ne $suricata) ($(if ($null -eq $suricata) { '' } else { $suricata }))

$standard = Join-Path $rulesDir 'standard.rules'
$all = Join-Path $rulesDir 'all.rules'
Check '标准规则存在' (Test-Path $standard)
Check '全量规则存在' (Test-Path $all)

if (Test-Path $standard) {
    $count = (Get-Content $standard | Where-Object { $_ -match '^(alert|drop|pass|reject)\s' }).Count
    Check '标准规则数量约 12,528' ($count -gt 12000) "$count"
}

$eve = Join-Path $suricataDir 'eve.json'
Check 'eve.json 已生成' (Test-Path $eve) $eve

$svc = Get-Service -Name 'WinAppGuardSvc' -ErrorAction SilentlyContinue
Check 'WinAppGuardSvc 已安装' ($null -ne $svc)
Check 'WinAppGuardSvc 正在运行' ($svc -and $svc.Status -eq 'Running') ($svc.Status)

$ui = Join-Path $install 'WinAppGuard.exe'
Check '界面程序存在' (Test-Path $ui)

Write-Host ''
if ($fails -eq 0) {
    Write-Host '基础检查全部通过。' -ForegroundColor Green
    Write-Host '请再手工验证：网络检测页能显示告警；点击拦截后活动拦截列表出现；到期后自动消失。'
    exit 0
}

Write-Host "失败 $fails 项。" -ForegroundColor Red
exit 1

