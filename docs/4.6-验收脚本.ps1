# 4.6 自动验收：数字签名检查（离线不再整批卡住）
#
# 用法（管理员 PowerShell，项目根目录）：
#   powershell -ExecutionPolicy Bypass -File .\docs\4.6-验收脚本.ps1
#
# 重点验证：
#   - 单个文件检查失败/超时只影响自己；
#   - 未完成的行显示“检查中…”；
#   - 取消“检查证书吊销状态”后签名立刻出现，未签名行标黄。

param(
    [string]$SelfCheck = (Join-Path $PSScriptRoot '..\dist-tools\WinAppGuard.SelfCheck.exe')
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$script:failures = @()

function Assert-True {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host "  [通过] $Name" -ForegroundColor Green }
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
Write-Host '===== 1. 数字签名离线用例 =====' -ForegroundColor Cyan
Assert-True '签名缓存/文件变化（--signature-test）' ((Invoke-SelfCheck '--signature-test') -eq 0)

Write-Host ''
Write-Host '===== 2. 回归（4.5 / 4.4） =====' -ForegroundColor Cyan
Assert-True 'UDP/ICMP（--antiscan-proto-test）' ((Invoke-SelfCheck '--antiscan-proto-test') -eq 0)
Assert-True '名称解析（--name-resolution-test）' ((Invoke-SelfCheck '--name-resolution-test') -eq 0)
Assert-True '本机配置（--config-integrity-test）' ((Invoke-SelfCheck '--config-integrity-test') -eq 0)
Assert-True 'IPv6 邻接（--ipv6-security-test）' ((Invoke-SelfCheck '--ipv6-security-test') -eq 0)

Write-Host ''
Write-Host '===== 3. 界面 / 语言 / 审计 =====' -ForegroundColor Cyan
Assert-True '界面检查（--ui-check）' ((Invoke-SelfCheck '--ui-check') -eq 0)
Assert-True '中英文（--ui-language-test）' ((Invoke-SelfCheck '--ui-language-test') -eq 0)
Assert-True '依赖审计（--audit）' ((Invoke-SelfCheck '--audit') -eq 0)

Write-Host ''
Write-Host '===== 4. 手工验证（联网连接页） =====' -ForegroundColor Cyan
Write-Host '  A) 保持「设置 → 数据与隐私 → 检查证书吊销状态」勾选，断开外网：'
Write-Host '     刷新后行内先显示「检查中…」；5 秒内出结果或「检查失败」，'
Write-Host '     且其它行不会被一起拖住（不再整列空白）。'
Write-Host '  B) 取消勾选后刷新：'
Write-Host '     已签名程序立即显示签名者（如 Microsoft / VMware）；'
Write-Host '     未签名程序显示「未签名」并整行标浅黄。'
Write-Host '  C) 随便找一个无签名 exe（自编译的即可）加入连接：'
Write-Host '     应显示「未签名」+ 浅黄；签名被改过的显示「签名无效」+ 粉红。'

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host '结果：自动验收全部通过。' -ForegroundColor Green
    exit 0
}

Write-Host "结果：$($script:failures.Count) 项失败：" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
