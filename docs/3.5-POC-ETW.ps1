# 3.5 POC：ETW 事件量 / CPU 测量
#
# 用法（管理员 PowerShell）：
#   .\3.5-POC-ETW.ps1 -Provider Microsoft-Windows-Kernel-Network -Seconds 30
#   .\3.5-POC-ETW.ps1 -Provider Microsoft-Windows-DNS-Client -Seconds 60
#
# 它只做测量，不修改系统设置；ETL/CSV 都放在临时目录，结束后删除。

param(
    [string]$Provider = 'Microsoft-Windows-Kernel-Network',
    [int]$Seconds = 30
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    throw '请用管理员 PowerShell 运行（ETW 会话需要管理员）。'
}

$guidMap = @{
    'Microsoft-Windows-Kernel-Network' = '{7DD42A49-5329-4832-8DFD-43D979153A88}'
    'Microsoft-Windows-DNS-Client'     = '{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}'
    'Microsoft-Windows-TCPIP'          = '{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}'
}

$providerArg = $Provider
if ($guidMap.ContainsKey($Provider)) {
    $providerArg = $guidMap[$Provider]
}

$session = 'WagPoc' + (Get-Random)
$temp = Join-Path $env:TEMP $session
$etl = "$temp.etl"
$csv = "$temp.csv"
$started = $false

Write-Host "Provider = $Provider ($providerArg)"
Write-Host "时长     = $Seconds 秒"

try {
    & logman start $session -p $providerArg -o $etl -ets | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "logman start 失败（退出码 $LASTEXITCODE），provider 可能不可用。"
    }

    $started = $true

    # 采集期间顺便量整机 CPU（用 CIM，避免中文系统计数器路径本地化问题）
    $cpuSamples = New-Object System.Collections.Generic.List[double]

    for ($i = 0; $i -lt $Seconds; $i++) {
        $total = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor |
            Where-Object { $_.Name -eq '_Total' } |
            Select-Object -First 1

        if ($null -ne $total) {
            [void]$cpuSamples.Add([double]$total.PercentProcessorTime)
        }

        Start-Sleep -Seconds 1
    }

    $avgCpu = if ($cpuSamples.Count -gt 0) {
        ($cpuSamples | Measure-Object -Average).Average
    } else {
        0
    }

    & logman stop $session -ets | Out-Null
    $started = $false

    if (-not (Test-Path $etl)) {
        throw '没有生成 ETL。'
    }

    & tracerpt $etl -of CSV -o $csv -y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "tracerpt 失败（退出码 $LASTEXITCODE）。"
    }

    $etlMB = [math]::Round((Get-Item $etl).Length / 1MB, 2)
    $csvLines = (Get-Content $csv | Measure-Object -Line).Lines
    $csvMB = [math]::Round((Get-Item $csv).Length / 1MB, 2)

    Write-Host ''
    Write-Host '===== 结果 =====' -ForegroundColor Cyan
    Write-Host "ETL 大小      = $etlMB MB"
    Write-Host "CSV 大小      = $csvMB MB"
    Write-Host "CSV 行数      = $csvLines（含表头）"
    Write-Host "平均 CPU      = $([math]::Round($avgCpu, 2)) %"
    Write-Host ''
    Write-Host '前 5 行预览：'
    Get-Content $csv -TotalCount 5 | ForEach-Object { Write-Host "  $_" }
}
finally {
    if ($started) {
        & logman stop $session -ets 2>$null | Out-Null
    }

    Remove-Item $etl -Force -ErrorAction SilentlyContinue
    Remove-Item $csv -Force -ErrorAction SilentlyContinue
}
