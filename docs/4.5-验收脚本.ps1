# 4.5 自动验收（VM）：UDP/ICMP 扫描 · 名称解析投毒 · 本机配置完整性
#
# 用法（管理员 PowerShell，项目根目录）：
#   powershell -ExecutionPolicy Bypass -File .\docs\4.5-验收脚本.ps1
#
# 只读/自动化部分：跑自检与服务端测试；不会修改系统设置。
# 手工攻击用例在最后打印，需要 Kali / Responder / nmap 配合。

param(
    [string]$SelfCheck = (Join-Path $PSScriptRoot '..\dist-tools\WinAppGuard.SelfCheck.exe')
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:failures = @()

function Assert-True {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) {
        Write-Host "  [通过] $Name" -ForegroundColor Green
    }
    else {
        Write-Host "  [失败] $Name $Detail" -ForegroundColor Red
        $script:failures += $Name
    }
}

function Invoke-SelfCheck {
    param([string]$Mode)
    & $SelfCheck $Mode --no-pause | Out-Host
    return $LASTEXITCODE
}

if (-not (Test-Path $SelfCheck)) {
    throw "找不到自检程序：$SelfCheck"
}

Write-Host ''
Write-Host '===== 1. 离线自检 =====' -ForegroundColor Cyan

Assert-True 'UDP/ICMP 阈值（--antiscan-proto-test）' ((Invoke-SelfCheck '--antiscan-proto-test') -eq 0)
Assert-True '名称解析解析/规则（--name-resolution-test）' ((Invoke-SelfCheck '--name-resolution-test') -eq 0)
Assert-True '本机配置差异/基线（--config-integrity-test）' ((Invoke-SelfCheck '--config-integrity-test') -eq 0)

Write-Host ''
Write-Host '===== 2. 界面 / 语言 / 审计 =====' -ForegroundColor Cyan

Assert-True '界面检查（--ui-check）' ((Invoke-SelfCheck '--ui-check') -eq 0)
Assert-True '中英文（--ui-language-test）' ((Invoke-SelfCheck '--ui-language-test') -eq 0)
Assert-True '依赖审计（--audit）' ((Invoke-SelfCheck '--audit') -eq 0)

Write-Host ''
Write-Host '===== 3. 回归（4.0–4.4） =====' -ForegroundColor Cyan

Assert-True '4.0 反扫描（--antiscan-test）' ((Invoke-SelfCheck '--antiscan-test') -eq 0)
Assert-True '4.4 IPv6 邻接（--ipv6-security-test）' ((Invoke-SelfCheck '--ipv6-security-test') -eq 0)
Assert-True '流量/记录（--traffic-records-test）' ((Invoke-SelfCheck '--traffic-records-test') -eq 0)

Write-Host ''
Write-Host '===== 4. 服务端实测（需要已安装 4.5 服务） =====' -ForegroundColor Cyan

$svc = Get-Service -Name WinAppGuardSvc -ErrorAction SilentlyContinue
$serviceUp = ($null -ne $svc) -and ($svc.Status -eq 'Running')

if (-not $serviceUp) {
    Write-Host '  [跳过] 服务不可用；先安装 dist\WinAppGuardSetup.exe --install' -ForegroundColor Yellow
}
else {
    Assert-True '反扫描设置/阻断（--service-antiscan-test）' ((Invoke-SelfCheck '--service-antiscan-test') -eq 0)
    Assert-True '名称解析窄阻断（--service-name-resolution-test）' ((Invoke-SelfCheck '--service-name-resolution-test') -eq 0)
    Assert-True '配置快照/基线（--service-config-integrity-test）' ((Invoke-SelfCheck '--service-config-integrity-test') -eq 0)
    Assert-True '4.4 IPv6 阻断回归（--service-ipv6-security-test）' ((Invoke-SelfCheck '--service-ipv6-security-test') -eq 0)
}

Write-Host ''
Write-Host '===== 5. 数据目录 =====' -ForegroundColor Cyan

$configDir = Join-Path $env:ProgramData 'WinAppGuard\config'
$lanDir = Join-Path $env:ProgramData 'WinAppGuard\lan'
Assert-True '本机配置目录存在' (Test-Path $configDir) $configDir
Assert-True '本机配置状态文件存在' (Test-Path (Join-Path $configDir 'state.json')) $configDir
Assert-True '局域网事件目录存在（名称解析事件写这里）' (Test-Path $lanDir) $lanDir

Write-Host ''
Write-Host '===== 6. 手工攻击用例（Kali + Windows 同一二层） =====' -ForegroundColor Cyan
Write-Host '  A) UDP 扫描：Kali 执行  sudo nmap -sU -p 1-200 <Windows-IP>'
Write-Host '     → 端口扫描页出现 protocol=udp 事件；自动封禁关闭时只告警。'
Write-Host '  B) ICMP 扫描：sudo nmap -sn <同网段>'
Write-Host '     → 出现 protocol=icmp 事件。'
Write-Host '  C) LLMNR/NBNS 投毒：sudo responder -I eth0 -wrv'
Write-Host '     在 Windows 上查询不存在的主机名（如 ping nosuchhost）→'
Write-Host '     局域网 → 名称解析出现“冲突 / 一来源多名称”；'
Write-Host '     选中来源 →「临时阻断此来源（10 分钟）」→ Responder 不再收到应答。'
Write-Host '  D) WPAD：dnsmasq 加 --dhcp-option=252,"http://<Kali>/wpad.dat"'
Write-Host '     → 出现“DHCP 下发 WPAD”；LLMNR 应答 wpad 时出现“WPAD 劫持”。'
Write-Host '  E) hosts 篡改：在 C:\Windows\System32\drivers\etc\hosts 加一行'
Write-Host '     10.0.0.66 update.example.com → 本机配置页出现 hosts 变化（高危）。'
Write-Host '  F) 代理篡改：设置 → 网络 → 代理，填一个测试代理 → WinINET 代理变化事件。'
Write-Host '  G) 24h：正常使用，UDP/名称解析/配置均不应产生高危误报；UDP 丢包高时状态行会提示暂停。'

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host '结果：自动验收全部通过。' -ForegroundColor Green
    exit 0
}

Write-Host "结果：$($script:failures.Count) 项失败：" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
