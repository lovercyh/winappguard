# 3.5 POC：ETW 事件量 / CPU 测量
#
# 用法（管理员 PowerShell）：
#   .\3.5-POC-ETW.ps1 -Provider Microsoft-Windows-Kernel-Network -Seconds 30
#   .\3.5-POC-ETW.ps1 -Provider Microsoft-Windows-DNS-Client -Seconds 60
#
# 只做测量，不修改系统设置；ETL/XML 都放在临时目录，结束后删除。
# 输出是“按事件类型统计 + 前 5 条样本字段”，不再打印 CSV 原始行。

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
$xml = "$temp.xml"
$started = $false

Write-Host "Provider = $Provider ($providerArg)"
Write-Host "时长     = $Seconds 秒"
Write-Host ''
Write-Host '请现在开始一个下载 / 视频播放 / 打开网站；3 秒后开始采集…' -ForegroundColor Yellow
Start-Sleep -Seconds 3

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

    & tracerpt $etl -of XML -o $xml -y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "tracerpt 失败（退出码 $LASTEXITCODE）。"
    }

    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($xml)

    $events = $doc.SelectNodes("//*[local-name()='Event']")
    $etlMB = [math]::Round((Get-Item $etl).Length / 1MB, 2)
    $xmlMB = [math]::Round((Get-Item $xml).Length / 1MB, 2)

    Write-Host ''
    Write-Host '===== 结果 =====' -ForegroundColor Cyan
    Write-Host "ETL 大小      = $etlMB MB"
    Write-Host "XML 大小      = $xmlMB MB"
    Write-Host "事件总数      = $($events.Count)"
    Write-Host "平均 CPU      = $([math]::Round($avgCpu, 2)) %"

    Write-Host ''
    Write-Host '按事件类型统计（前 10）：'

    $events | ForEach-Object {
        $providerName = $_.SelectSingleNode(".//*[local-name()='Provider']").GetAttribute('Name')
        $eventId = $_.SelectSingleNode(".//*[local-name()='EventID']").InnerText
        $task = $_.SelectSingleNode(".//*[local-name()='Task']")
        $taskName = if ($null -ne $task) { $task.InnerText } else { '' }

        [pscustomobject]@{
            Provider = $providerName
            EventId  = $eventId
            Task     = $taskName
        }
    } |
        Group-Object Provider, EventId, Task |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object { Write-Host ("  {0,6}x  {1}" -f $_.Count, $_.Name) }

    Write-Host ''
    Write-Host '前 5 条事件样本：'

    $events | Select-Object -First 5 | ForEach-Object {
        $providerName = $_.SelectSingleNode(".//*[local-name()='Provider']").GetAttribute('Name')
        $eventId = $_.SelectSingleNode(".//*[local-name()='EventID']").InnerText
        $execution = $_.SelectSingleNode(".//*[local-name()='Execution']")
        $pidText = if ($null -ne $execution) { $execution.GetAttribute('ProcessID') } else { '?' }
        $dataNode = $_.SelectSingleNode(".//*[local-name()='EventData']")

        $pairs = @()
        if ($null -ne $dataNode) {
            $pairs = $dataNode.ChildNodes | ForEach-Object {
                "$($_.GetAttribute('Name'))=$($_.InnerText)"
            }
        }

        Write-Host ("  {0} / ID {1} / PID {2}" -f $providerName, $eventId, $pidText)
        if ($pairs.Count -gt 0) {
            Write-Host ("    " + ($pairs -join '  '))
        }
    }

    if ($events.Count -lt 20) {
        Write-Host ''
        Write-Host '事件很少：确认采集期间确实有下载/视频/网页访问。' -ForegroundColor Yellow
    }
}
finally {
    if ($started) {
        & logman stop $session -ets 2>$null | Out-Null
    }

    Remove-Item $etl -Force -ErrorAction SilentlyContinue
    Remove-Item $xml -Force -ErrorAction SilentlyContinue
}
