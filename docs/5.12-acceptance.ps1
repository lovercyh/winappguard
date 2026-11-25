#requires -Version 5.1
<#
    WinAppGuard 5.12 acceptance script (read-only)

    Applies to: a VM with 5.12.0 already installed.
    It does NOT change rules, install/uninstall the service, or stop the service.

    Usage (administrator PowerShell is better; S8/Npcap checks need admin):
        powershell -ExecutionPolicy Bypass -File .\5.12-acceptance.ps1

    If WinAppGuard.SelfCheck.exe is not next to this script:
        powershell -ExecutionPolicy Bypass -File .\5.12-acceptance.ps1 `
            -SelfCheckPath "C:\path\to\WinAppGuard.SelfCheck.exe"

    Optional:
        -SkipPerf        skip the perf/concurrency scenarios
        -PerfIterations  status/rules/traffic/ids iterations (default 200)
        -PerfThreads     concurrent threads (default 10)
        -PerfRequests    requests per thread (default 100)
#>
[CmdletBinding()]
param(
    [string]$SelfCheckPath = '',
    [int]$PerfIterations = 200,
    [int]$PerfThreads = 10,
    [int]$PerfRequests = 100,
    [switch]$SkipPerf
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$script:pass = 0
$script:fail = 0
$script:warn = 0
$script:skip = 0

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP')][string]$Status,
        [string]$Detail = ''
    )

    switch ($Status) {
        'PASS' { $script:pass++ }
        'FAIL' { $script:fail++ }
        'WARN' { $script:warn++ }
        'SKIP' { $script:skip++ }
    }

    $color = 'Gray'
    if ($Status -eq 'PASS') { $color = 'Green' }
    elseif ($Status -eq 'FAIL') { $color = 'Red' }
    elseif ($Status -eq 'WARN') { $color = 'Yellow' }

    Write-Host ("[{0}] {1,-30} {2}" -f $Status, $Name, $Detail) -ForegroundColor $color
}

function Get-ProductVersion {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $version = (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($version)) { return $null }
        return ($version -split '\+')[0]
    }
    catch {
        return $null
    }
}

Write-Host ''
Write-Host '===== WinAppGuard 5.12 acceptance =====' -ForegroundColor Cyan
Write-Host ''

# ----------------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Add-Result 'administrator' 'PASS' 'elevated'
}
else {
    Add-Result 'administrator' 'WARN' 'not elevated; S8/npcap-open may be skipped'
}

# ----------------------------------------------------------------
$service = Get-CimInstance Win32_Service -Filter "Name='WinAppGuardSvc'" -ErrorAction SilentlyContinue

if ($null -eq $service) {
    Add-Result 'service-installed' 'FAIL' 'WinAppGuardSvc is not installed'
    Write-Host ''
    Write-Host ("PASS={0} FAIL={1} WARN={2} SKIP={3}" -f $script:pass, $script:fail, $script:warn, $script:skip)
    exit 1
}

$svcPath = $service.PathName
if ($svcPath -match '^\s*"([^"]+)"') {
    $svcPath = $Matches[1]
}
else {
    $svcPath = ($svcPath -split '\s+')[0]
}

$installDir = Split-Path -Parent $svcPath
$uiPath = Join-Path $installDir 'WinAppGuard.exe'

if (Test-Path -LiteralPath $svcPath) {
    Add-Result 'service-installed' 'PASS' $svcPath
}
else {
    Add-Result 'service-installed' 'FAIL' "missing: $svcPath"
}

# ----------------------------------------------------------------
$expectedVersion = '5.12.0'
$uiVersion = Get-ProductVersion $uiPath
$svcVersion = Get-ProductVersion $svcPath

if ($uiVersion -eq $expectedVersion -and $svcVersion -eq $expectedVersion) {
    Add-Result 'version-5.12.0' 'PASS' "UI=$uiVersion service=$svcVersion"
}
else {
    Add-Result 'version-5.12.0' 'FAIL' "UI=$uiVersion service=$svcVersion expected=$expectedVersion"
}

if ($null -ne $uiVersion -and $uiVersion -eq $svcVersion) {
    Add-Result 'ui-service-match' 'PASS' "$uiVersion = $svcVersion"
}
else {
    Add-Result 'ui-service-match' 'FAIL' "UI=$uiVersion service=$svcVersion"
}

# ----------------------------------------------------------------
$svc = Get-Service -Name 'WinAppGuardSvc' -ErrorAction SilentlyContinue

if ($null -ne $svc -and $svc.Status -eq 'Running') {
    Add-Result 'service-running' 'PASS' $svc.Status
}
else {
    Add-Result 'service-running' 'FAIL' "status=$($svc.Status)"
}

if ($null -ne $svc -and $svc.StartType -eq 'Automatic') {
    Add-Result 'service-autostart' 'PASS' $svc.StartType
}
else {
    Add-Result 'service-autostart' 'WARN' "startType=$($svc.StartType)"
}

# ----------------------------------------------------------------
$pipes = @()
try {
    $pipes = @(Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop |
        Where-Object { $_.Name -like 'WinAppGuard*' } |
        ForEach-Object { $_.Name })
}
catch {
    Add-Result 'control-pipe-enum' 'WARN' $_.Exception.Message
}

$hasV4 = $pipes -contains 'WinAppGuard.Control.v4'
$hasV3 = $pipes -contains 'WinAppGuard.Control.v3'
$pipeText = ($pipes -join ', ')

if ($hasV4) {
    Add-Result 'control-pipe-v4' 'PASS' $pipeText
}
else {
    Add-Result 'control-pipe-v4' 'FAIL' "no v4 pipe; found: $pipeText"
}

if ($hasV3) {
    Add-Result 'no-legacy-v3' 'FAIL' "legacy v3 pipe still exists: $pipeText"
}
else {
    Add-Result 'no-legacy-v3' 'PASS' $pipeText
}

# ----------------------------------------------------------------
$doctorOutput = ''
$doctorExit = 1

try {
    $doctorOutput = & $svcPath --cli --doctor 2>&1 | Out-String
    $doctorExit = $LASTEXITCODE
}
catch {
    $doctorOutput = $_.Exception.Message
}

Write-Host ''
Write-Host '----- doctor -----' -ForegroundColor Cyan
Write-Host $doctorOutput.Trim()
Write-Host '------------------' -ForegroundColor Cyan
Write-Host ''

$doctorFailLines = @($doctorOutput -split "`r?`n" | Where-Object { $_ -match '^\[FAIL\]' })

if ($doctorFailLines.Count -eq 0 -and $doctorExit -eq 0) {
    Add-Result 'doctor' 'PASS' "exit=$doctorExit"
}
else {
    Add-Result 'doctor' 'FAIL' ("exit=$doctorExit; " + ($doctorFailLines -join ' | '))
}

$requiredDoctorChecks = @(
    'service',
    'protocol',
    'payload-contract',
    'control-pipe',
    'installed-versions'
)

foreach ($name in $requiredDoctorChecks) {
    $pattern = '(?m)^\[OK\]\s+' + [regex]::Escape($name) + '\b'
    if ($doctorOutput -match $pattern) {
        Add-Result ("doctor-" + $name) 'PASS' ''
    }
    else {
        Add-Result ("doctor-" + $name) 'FAIL' 'not OK in doctor output'
    }
}

# ----------------------------------------------------------------
function Invoke-CliCheck {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [string]$FailureStatus = 'FAIL'
    )

    try {
        $output = & $svcPath --cli @Arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    }
    catch {
        $output = $_.Exception.Message
        $code = 1
    }

    if ($code -eq 0) {
        Add-Result $Name 'PASS' ''
    }
    else {
        $short = $output.Trim()
        if ($short.Length -gt 180) { $short = $short.Substring(0, 180) + '...' }
        Add-Result $Name $FailureStatus ("exit=$code " + $short)
    }
}

Invoke-CliCheck 'cli-status' @('--status')
Invoke-CliCheck 'cli-list-rules' @('--list-rules')
Invoke-CliCheck 'cli-network-status' @('--network-status') 'WARN'

# ----------------------------------------------------------------
$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$setupLog = $null

if (Test-Path -LiteralPath $logDir) {
    $setupLog = Get-ChildItem -LiteralPath $logDir -Filter 'setup-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^setup-\d{8}\.log$' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

if ($null -eq $setupLog) {
    Add-Result 'setup-log' 'SKIP' "no setup log under $logDir"
}
else {
    $setupText = Get-Content -LiteralPath $setupLog.FullName -Raw -ErrorAction SilentlyContinue
    $hasCheck = $setupText -match 'Version check:'
    $hasVerified = $setupText -match 'Installed versions verified\.'
    $has512 = $setupText -match '5\.12\.0'

    if ($hasCheck -and $hasVerified -and $has512) {
        Add-Result 'setup-log' 'PASS' $setupLog.Name
    }
    else {
        Add-Result 'setup-log' 'WARN' "found $($setupLog.Name), but version-verification lines are missing"
    }
}

# ----------------------------------------------------------------
$svcLog = $null

if (Test-Path -LiteralPath $logDir) {
    $svcLog = Get-ChildItem -LiteralPath $logDir -Filter 'winappguard-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

if ($null -eq $svcLog) {
    Add-Result 'service-log-v4' 'WARN' "no service log under $logDir"
}
else {
    $svcText = Get-Content -LiteralPath $svcLog.FullName -Raw -ErrorAction SilentlyContinue

    if ($svcText -match 'IPC started: .*v4 signed session') {
        Add-Result 'service-log-v4' 'PASS' $svcLog.Name
    }
    else {
        Add-Result 'service-log-v4' 'WARN' "no 'v4 signed session' line in $($svcLog.Name)"
    }

    $perfLines = @($svcText -split "`r?`n" | Where-Object { $_ -match 'WAG-PERF-|WAG-RULE-031' })

    if ($perfLines.Count -gt 0) {
        $lastPerf = $perfLines[$perfLines.Count - 1].Trim()
        if ($lastPerf.Length -gt 180) { $lastPerf = $lastPerf.Substring(0, 180) + '...' }
        Add-Result 'perf-log' 'PASS' $lastPerf
    }
    else {
        Add-Result 'perf-log' 'SKIP' 'no slow/import perf log yet (normal on an idle machine)'
    }
}

# ----------------------------------------------------------------
if ($SkipPerf) {
    Add-Result 'perf' 'SKIP' 'by -SkipPerf'
}
else {
    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($SelfCheckPath)) {
        $candidates.Add($SelfCheckPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $candidates.Add((Join-Path $PSScriptRoot 'WinAppGuard.SelfCheck.exe'))
        $candidates.Add((Join-Path $PSScriptRoot 'dist-tools\WinAppGuard.SelfCheck.exe'))
    }

    $candidates.Add((Join-Path $installDir 'WinAppGuard.SelfCheck.exe'))
    $candidates.Add((Join-Path ([Environment]::GetFolderPath('Desktop')) 'WinAppGuard.SelfCheck.exe'))
    $candidates.Add((Join-Path ([Environment]::GetFolderPath('Desktop')) 'dist-tools\WinAppGuard.SelfCheck.exe'))
    $candidates.Add((Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WinAppGuard.SelfCheck.exe'))

    $selfCheck = $candidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } |
        Select-Object -First 1

    if ($null -eq $selfCheck) {
        Add-Result 'perf' 'SKIP' 'WinAppGuard.SelfCheck.exe not found; pass -SelfCheckPath or copy dist-tools next to this script'
    }
    else {
        $selfCheckVersion = Get-ProductVersion $selfCheck

        if ($selfCheckVersion -ne $expectedVersion) {
            Add-Result 'perf' 'SKIP' "SelfCheck version is $selfCheckVersion; need $expectedVersion"
        }
        else {
        $perfOut = Join-Path $env:TEMP 'wag-perf-acceptance.json'
        $perfOutput = ''
        $perfExit = 1

        try {
            $perfOutput = & $selfCheck --perf --no-pause `
                --perf-iterations $PerfIterations `
                --perf-threads $PerfThreads `
                --perf-requests $PerfRequests `
                --perf-idle-seconds 0 `
                --perf-out $perfOut 2>&1 | Out-String
            $perfExit = $LASTEXITCODE
        }
        catch {
            $perfOutput = $_.Exception.Message
        }

        Write-Host ''
        Write-Host '----- perf -----' -ForegroundColor Cyan
        Write-Host $perfOutput.Trim()
        Write-Host '----------------' -ForegroundColor Cyan
        Write-Host ''

        $errorMatches = [regex]::Matches($perfOutput, 'errors=(\d+)')
        $errorTotal = 0

        foreach ($match in $errorMatches) {
            $errorTotal += [int]$match.Groups[1].Value
        }

        if ($perfExit -eq 0 -and $errorTotal -eq 0) {
            Add-Result 'perf' 'PASS' "errors=0; result=$perfOut"
        }
        else {
            Add-Result 'perf' 'FAIL' "exit=$perfExit errors=$errorTotal"
        }
        }
    }
}

# ----------------------------------------------------------------
Write-Host ''
Write-Host '===== acceptance summary =====' -ForegroundColor Cyan
Write-Host ("PASS={0}  FAIL={1}  WARN={2}  SKIP={3}" -f $script:pass, $script:fail, $script:warn, $script:skip)

if ($script:fail -gt 0) {
    Write-Host 'Result: FAILED.' -ForegroundColor Red
    exit 1
}

Write-Host 'Result: PASSED.' -ForegroundColor Green
exit 0
