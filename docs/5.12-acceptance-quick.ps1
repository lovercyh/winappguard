#requires -Version 5.1
# WinAppGuard 5.12 quick acceptance (read-only, paste-safe: no top-level if/else)

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0
$script:warn = 0
$script:skip = 0

function Check {
    param($Name, $Ok, $Detail = '')
    if ($Ok) {
        $script:pass++
        Write-Host "[PASS] $Name $Detail" -ForegroundColor Green
    }
    else {
        $script:fail++
        Write-Host "[FAIL] $Name $Detail" -ForegroundColor Red
    }
}

function Warn {
    param($Name, $Detail = '')
    $script:warn++
    Write-Host "[WARN] $Name $Detail" -ForegroundColor Yellow
}

function Skip {
    param($Name, $Detail = '')
    $script:skip++
    Write-Host "[SKIP] $Name $Detail" -ForegroundColor Gray
}

function Pause-IfNeeded {
    if (-not $env:WAG_NO_PAUSE) {
        [void](Read-Host 'Press Enter to exit')
    }
}

function Get-Ver {
    param($Path)
    if (Test-Path -LiteralPath $Path) {
        $v = (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
        if ($v) { return ($v -split '\+')[0] }
    }
    return $null
}

function Get-SvcPath {
    param($Raw)
    if ($Raw -match '^\s*"([^"]+)"') { return $Matches[1] }
    return ($Raw -split '\s+')[0]
}

$expected = '5.12.0'
$scriptBase = $PSScriptRoot
if (-not $scriptBase) { $scriptBase = (Get-Location).Path }
$svcInfo = Get-CimInstance Win32_Service -Filter "Name='WinAppGuardSvc'" -ErrorAction SilentlyContinue
Check 'service-installed' ($null -ne $svcInfo) ''

if ($null -eq $svcInfo) {
    Write-Host ("PASS={0} FAIL={1} WARN={2} SKIP={3}" -f $script:pass, $script:fail, $script:warn, $script:skip)
    Pause-IfNeeded
    exit 1
}

$svcPath = Get-SvcPath $svcInfo.PathName
$uiPath = Join-Path (Split-Path -Parent $svcPath) 'WinAppGuard.exe'
$uiVer = Get-Ver $uiPath
$svcVer = Get-Ver $svcPath

Check 'version-5.12.0' ($uiVer -eq $expected -and $svcVer -eq $expected) "UI=$uiVer service=$svcVer"
Check 'ui-service-match' ($null -ne $uiVer -and $uiVer -eq $svcVer) "UI=$uiVer service=$svcVer"

$svc = Get-Service -Name 'WinAppGuardSvc' -ErrorAction SilentlyContinue
Check 'service-running' ($null -ne $svc -and $svc.Status -eq 'Running') "status=$($svc.Status)"
Check 'service-autostart' ($null -ne $svc -and $svc.StartType -eq 'Automatic') "startType=$($svc.StartType)"

$pipes = @()
try {
    $pipes = @(Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop |
        Where-Object { $_.Name -like 'WinAppGuard*' } |
        ForEach-Object { $_.Name })
}
catch {
    Warn 'control-pipe-enum' $_.Exception.Message
}

$hasV4 = $pipes -contains 'WinAppGuard.Control.v4'
$hasV3 = $pipes -contains 'WinAppGuard.Control.v3'
$pipeText = ($pipes -join ', ')
Check 'control-pipe-v4' $hasV4 $pipeText
Check 'no-legacy-v3' (-not $hasV3) $pipeText

$doctor = ''
$doctorExit = 1
try {
    $doctor = & $svcPath --cli --doctor 2>&1 | Out-String
    $doctorExit = $LASTEXITCODE
}
catch {
    $doctor = $_.Exception.Message
}

Write-Host ''
Write-Host '----- doctor -----' -ForegroundColor Cyan
Write-Host $doctor.Trim()
Write-Host '------------------' -ForegroundColor Cyan
Write-Host ''

Check 'doctor' ($doctorExit -eq 0 -and $doctor -notmatch '(?m)^\[FAIL\]') "exit=$doctorExit"

foreach ($name in @('service', 'protocol', 'payload-contract', 'control-pipe', 'installed-versions')) {
    $pattern = '(?m)^\[OK\]\s+' + [regex]::Escape($name) + '\b'
    Check ("doctor-" + $name) ($doctor -match $pattern) ''
}

& $svcPath --cli --status *> $null
Check 'cli-status' ($LASTEXITCODE -eq 0) ''
& $svcPath --cli --list-rules *> $null
Check 'cli-list-rules' ($LASTEXITCODE -eq 0) ''

$logDir = Join-Path $env:ProgramData 'WinAppGuard\logs'
$setupLogs = @()
if (Test-Path -LiteralPath $logDir) {
    $setupLogs = @(Get-ChildItem -LiteralPath $logDir -Filter 'setup-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^setup-\d{8}\.log$' })
}

$setupOk = $false
$setupName = ''
foreach ($log in $setupLogs) {
    $setupText = Get-Content -LiteralPath $log.FullName -Raw -ErrorAction SilentlyContinue
    if ($setupText -match 'Version check:' -and $setupText -match 'Installed versions verified\.' -and $setupText -match '5\.12\.0') {
        $setupOk = $true
        $setupName = $log.Name
        break
    }
}

if ($setupOk) {
    Check 'setup-log' $true $setupName
}

if (-not $setupOk -and $setupLogs.Count -gt 0) {
    Warn 'setup-log' "setup logs exist, but no 5.12 verification line (supplementary check; not a failure)"
}

if ($setupLogs.Count -eq 0) {
    Skip 'setup-log' 'no setup-YYYYMMDD.log'
}

$selfCheck = $null
$candidates = @(
    (Join-Path $scriptBase 'WinAppGuard.SelfCheck.exe'),
    (Join-Path $scriptBase 'dist-tools\WinAppGuard.SelfCheck.exe'),
    (Join-Path (Split-Path -Parent $svcPath) 'WinAppGuard.SelfCheck.exe'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'WinAppGuard.SelfCheck.exe'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'dist-tools\WinAppGuard.SelfCheck.exe')
)

foreach ($candidate in $candidates) {
    if (-not $selfCheck -and $candidate -and (Test-Path -LiteralPath $candidate)) {
        $selfCheck = $candidate
    }
}

if ($selfCheck) {
    $selfCheckVer = Get-Ver $selfCheck
    if ($selfCheckVer -eq $expected) {
        $perf = & $selfCheck --perf --no-pause --perf-iterations 100 --perf-threads 10 --perf-requests 50 --perf-idle-seconds 0 2>&1 | Out-String
        Write-Host ''
        Write-Host '----- perf -----' -ForegroundColor Cyan
        Write-Host $perf.Trim()
        Write-Host '----------------' -ForegroundColor Cyan
        Write-Host ''
        $sum = 0
        foreach ($m in [regex]::Matches($perf, 'errors=(\d+)')) { $sum += [int]$m.Groups[1].Value }
        Check 'perf' ($LASTEXITCODE -eq 0 -and $sum -eq 0) "errors=$sum"
    }
    else {
        Skip 'perf' "SelfCheck=$selfCheckVer (need $expected)"
    }
}

if (-not $selfCheck) {
    Skip 'perf' 'WinAppGuard.SelfCheck.exe not found'
}

Write-Host ''
Write-Host ("PASS={0} FAIL={1} WARN={2} SKIP={3}" -f $script:pass, $script:fail, $script:warn, $script:skip)

if ($script:fail -gt 0) {
    Write-Host 'Result: FAILED.' -ForegroundColor Red
    Pause-IfNeeded
    exit 1
}

Write-Host 'Result: PASSED.' -ForegroundColor Green
Pause-IfNeeded
exit 0
