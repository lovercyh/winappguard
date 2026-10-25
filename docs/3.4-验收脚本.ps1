# WinAppGuard 3.4 一键验收脚本
#
# 用法（管理员 PowerShell）：
#   .\3.4-验收脚本.ps1 -Phase Owner     # 账户 A：安装时的所有者
#   .\3.4-验收脚本.ps1 -Phase NonOwner  # 账户 B：另一个管理员（非所有者）
#   .\3.4-验收脚本.ps1 -Phase Cleanup   # 回到账户 A，最后卸载
#
# 说明：
#   - 三个阶段必须用对应账户分别运行，脚本无法替你切换 Windows 账户；
#   - 默认目录是 VM 的 dist-tools，如果不对，改下面的 $Dist；
#   - 只做验收，不会上传任何数据。

param(
    [ValidateSet('Owner', 'NonOwner', 'Cleanup')]
    [string]$Phase = 'Owner'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Dist = 'C:\Users\VM\Downloads\默认项目\dist-tools'
if (-not (Test-Path (Join-Path $Dist 'WinAppGuardSetup.exe'))) {
    $Dist = (Get-Location).Path
}

$setup = Join-Path $Dist 'WinAppGuardSetup.exe'
$svc   = Join-Path $Dist 'WinAppGuardSvc.exe'
$check = Join-Path $Dist 'WinAppGuard.SelfCheck.exe'
$data  = Join-Path $env:ProgramData 'WinAppGuard'
$logs  = Join-Path $data 'logs'
$marker = Join-Path $data 'wfp-dacl-owner-only'

$script:fail = 0

function Write-Step([string]$name) {
    Write-Host ""
    Write-Host "=== $name ===" -ForegroundColor Cyan
}

function Assert($name, $ok, $detail = '') {
    if ([bool]$ok) {
        Write-Host "[通过] $name $detail" -ForegroundColor Green
    }
    else {
        Write-Host "[失败] $name $detail" -ForegroundColor Red
        $script:fail++
    }
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RuleCount {
    $output = & $svc --cli --list-blocked --lang zh 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "读取规则失败：$LASTEXITCODE`n$output"
    }
    return @($output | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' }).Count
}

function Get-LatestLog {
    return Get-ChildItem $logs -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Count-Marker([string]$pattern) {
    $count = 0
    Get-ChildItem $logs -Filter '*.log' -ErrorAction SilentlyContinue | ForEach-Object {
        $text = Get-Content $_.FullName -Raw -Encoding UTF8
        $count += ([regex]::Matches($text, [regex]::Escape($pattern))).Count
    }
    return $count
}

function Get-OwnerSid {
    $configPath = Join-Path $data 'protected-mode\config.json'
    if (-not (Test-Path $configPath)) {
        return $null
    }
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    if ($config.OwnerSid) { return $config.OwnerSid }
    return $config.ownerSid
}

# ======================================================================
# 阶段 1：所有者
# ======================================================================
function Invoke-OwnerPhase {
    Write-Step '0. 环境检查'
    Assert '管理员权限' (Test-Admin)
    if (-not (Test-Admin)) { throw '请用管理员 PowerShell 运行' }

    Assert '存在 WinAppGuardSetup.exe' (Test-Path $setup) $setup
    Assert '存在 WinAppGuardSvc.exe' (Test-Path $svc) $svc
    Assert '存在 WinAppGuard.SelfCheck.exe' (Test-Path $check) $check
    if (-not (Test-Path $check)) {
        throw '请把 WinAppGuard.SelfCheck.exe 一起复制到 dist-tools'
    }

    $version = (Get-Item $setup).VersionInfo.ProductVersion
    $svcVersion = (Get-Item $svc).VersionInfo.ProductVersion
    Assert 'Setup 版本是 3.4+' ($version -like '3.4+*') $version
    Assert '服务版本是 3.4+' ($svcVersion -like '3.4+*') $svcVersion

    if ($version -notlike '3.4+*' -or $svcVersion -notlike '3.4+*') {
        Write-Host 'dist-tools 里还是旧版本。请先覆盖 Setup / Uninstall / WinAppGuard.exe / WinAppGuardSvc.exe。' -ForegroundColor Red
        return
    }

    $probe = & $check --wfp-dacl-sddl-test --no-pause 2>&1
    $probeText = $probe -join "`n"
    Assert 'SelfCheck 是 3.4 版' ($probeText -match 'WFP DACL（离线）')
    Assert '--wfp-dacl-sddl-test' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

    if ($probeText -notmatch 'WFP DACL（离线）') {
        Write-Host 'WinAppGuard.SelfCheck.exe 还是旧版，请重新发布并覆盖。' -ForegroundColor Red
        return
    }

    Write-Step '1. 记录升级前规则'
    $beforeCount = Get-RuleCount
    Write-Host "升级前规则数：$beforeCount"

    Write-Step '2. 覆盖安装（--repair）'
    & $setup --repair
    Assert 'Setup --repair' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

    Start-Sleep -Seconds 3
    $service = Get-Service -Name WinAppGuardSvc -ErrorAction SilentlyContinue
    Assert '服务正在运行' ($null -ne $service -and $service.Status -eq 'Running')

    Write-Step '3. 迁移标记'
    Assert '迁移标记存在' (Test-Path $marker) $marker
    $ownerSid = Get-OwnerSid
    Assert '能读到所有者 SID' (-not [string]::IsNullOrWhiteSpace($ownerSid)) $ownerSid
    if (Test-Path $marker) {
        $saved = (Get-Content $marker -Raw).Trim()
        Assert '标记内容 = 所有者 SID' ($saved -eq $ownerSid) $saved
    }

    Write-Step '4. 服务日志'
    $log = Get-LatestLog
    Assert '存在服务日志' ($null -ne $log)
    if ($null -ne $log) {
        $tail = Get-Content $log.FullName -Raw -Encoding UTF8
        Assert '日志出现 WAG-WFP-011（迁移成功）' ($tail -match 'WAG-WFP-011')
    }

    Write-Step '5. 真实 DACL'
    & $check --wfp-dacl-test --no-pause
    Assert '--wfp-dacl-test' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

    # --wfp-dacl-sddl-test 已在第 0 步跑过

    Write-Step '6. 规则没有丢'
    $afterCount = Get-RuleCount
    Assert '升级后规则数不少于升级前' ($afterCount -ge $beforeCount) "before=$beforeCount after=$afterCount"

    Write-Step '7. 迁移重试（删除标记 → 重启服务）'
    $markerBefore = Count-Marker 'WAG-WFP-011'
    Remove-Item $marker -Force
    Restart-Service WinAppGuardSvc
    Start-Sleep -Seconds 5

    $markerAfter = Count-Marker 'WAG-WFP-011'
    Assert '再次出现 WAG-WFP-011' ($markerAfter -gt $markerBefore) "before=$markerBefore after=$markerAfter"
    Assert '迁移标记重新写入' (Test-Path $marker)

    $retryCount = Get-RuleCount
    Assert '重试后规则数不变' ($retryCount -eq $afterCount) "expected=$afterCount actual=$retryCount"

    Write-Step '8. 回归自检'
    $modes = @(
        '--audit',
        '--ui-check',
        '--ui-language-test',
        '--cli-test',
        '--log-format-test',
        '--service-auth-test',
        '--service-acl-test',
        '--protected-mode-ui-test'
    )

    foreach ($mode in $modes) {
        & $check $mode --no-pause
        Assert $mode ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
    }

    Write-Step '结果'
    if ($script:fail -eq 0) {
        Write-Host '阶段 A（所有者）全部通过。' -ForegroundColor Green
        Write-Host '请切换到非所有者管理员账户，运行：' -ForegroundColor Yellow
        Write-Host '  .\3.4-验收脚本.ps1 -Phase NonOwner' -ForegroundColor Yellow
    }
    else {
        Write-Host "阶段 A 有 $script:fail 项失败。" -ForegroundColor Red
    }
}

# ======================================================================
# 阶段 2：非所有者管理员
# ======================================================================
function Invoke-NonOwnerPhase {
    Write-Step '0. 环境检查'
    Assert '管理员权限' (Test-Admin)
    if (-not (Test-Admin)) { throw '请用管理员 PowerShell 运行' }

    $version = (Get-Item $setup).VersionInfo.ProductVersion
    $svcVersion = (Get-Item $svc).VersionInfo.ProductVersion
    Assert 'Setup 版本是 3.4+' ($version -like '3.4+*') $version
    Assert '服务版本是 3.4+' ($svcVersion -like '3.4+*') $svcVersion
    if ($version -notlike '3.4+*' -or $svcVersion -notlike '3.4+*') { return }

    $service = Get-Service -Name WinAppGuardSvc -ErrorAction SilentlyContinue
    Assert '服务仍在运行' ($null -ne $service -and $service.Status -eq 'Running')

    Write-Step '1. --recover 必须被拒绝'
    & $svc --cli --recover --lang zh
    Assert '--recover 退出码 = 2' ($LASTEXITCODE -eq 2) "exit=$LASTEXITCODE"

    Write-Step '2. 卸载必须被拒绝'
    & $setup --uninstall
    Assert '卸载退出码 = 7' ($LASTEXITCODE -eq 7) "exit=$LASTEXITCODE"

    Write-Step '3. 没有被半卸载'
    $service = Get-Service -Name WinAppGuardSvc -ErrorAction SilentlyContinue
    Assert '服务仍然存在且运行' ($null -ne $service -and $service.Status -eq 'Running')

    Assert '安装目录仍在' (Test-Path (Join-Path $env:ProgramFiles 'WinAppGuard\WinAppGuard.exe'))
    Assert '规则快照仍在' (Test-Path (Join-Path $data 'rules.json'))
    Assert '迁移标记仍在' (Test-Path $marker)

    Write-Step '结果'
    if ($script:fail -eq 0) {
        Write-Host '阶段 B（非所有者）全部通过。' -ForegroundColor Green
        Write-Host '请切换回所有者账户，做最后清理：' -ForegroundColor Yellow
        Write-Host '  .\3.4-验收脚本.ps1 -Phase Cleanup' -ForegroundColor Yellow
    }
    else {
        Write-Host "阶段 B 有 $script:fail 项失败。" -ForegroundColor Red
    }
}

# ======================================================================
# 阶段 3：所有者卸载
# ======================================================================
function Invoke-CleanupPhase {
    Write-Step '0. 环境检查'
    Assert '管理员权限' (Test-Admin)
    if (-not (Test-Admin)) { throw '请用管理员 PowerShell 运行' }

    $version = (Get-Item $setup).VersionInfo.ProductVersion
    Assert 'Setup 版本是 3.4+' ($version -like '3.4+*') $version
    if ($version -notlike '3.4+*') { return }

    $ownerSid = Get-OwnerSid
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert '当前账户是所有者' ($ownerSid -eq $currentSid) "owner=$ownerSid current=$currentSid"

    Write-Step '1. 完整卸载'
    & $setup --uninstall
    Assert '卸载退出码 = 0' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"

    Start-Sleep -Seconds 2
    $service = Get-Service -Name WinAppGuardSvc -ErrorAction SilentlyContinue
    Assert '服务已删除' ($null -eq $service)
    Assert '数据目录已删除' (-not (Test-Path $data))
    Assert '安装目录已删除' (-not (Test-Path (Join-Path $env:ProgramFiles 'WinAppGuard')))

    Write-Step '结果'
    if ($script:fail -eq 0) {
        Write-Host '阶段 C（卸载）全部通过。' -ForegroundColor Green
    }
    else {
        Write-Host "阶段 C 有 $script:fail 项失败。" -ForegroundColor Red
    }
}

switch ($Phase) {
    'Owner'    { Invoke-OwnerPhase }
    'NonOwner' { Invoke-NonOwnerPhase }
    'Cleanup'  { Invoke-CleanupPhase }
}

if ($script:fail -gt 0) {
    Write-Host ''
    Write-Host "共 $script:fail 项失败，请把上面的红色输出贴回来。" -ForegroundColor Red
}
