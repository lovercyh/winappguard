<#
    5.12 覆盖安装矩阵（只在 VM 里跑，会安装/卸载服务并修改 WFP 规则）

    用法（管理员 PowerShell）：
        powershell -ExecutionPolicy Bypass -File .\build\upgrade-matrix.ps1 `
            -OldSetup "A:\backup\5.10.1\WinAppGuardSetup.exe" `
            -NewSetup ".\dist\WinAppGuardSetup.exe"

    验证：
        1. 安装旧版；
        2. 只运行一次新版 --install；
        3. 界面/服务版本必须一致，且控制管道是 v4；
        4. doctor 必须通过；
        5. 默认最后卸载，保持 VM 干净。
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)] [string] $OldSetup,
    [Parameter(Mandatory = $true)] [string] $NewSetup,
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'WinAppGuard'),
    [switch] $KeepInstalled
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Get-ProductVersion([string] $Path) {
    if (-not (Test-Path $Path)) { return $null }
    $version = (Get-Item $Path).VersionInfo.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { return $null }
    return ($version -split '\+')[0]
}

function Invoke-Installer([string] $Setup, [string] $Arguments) {
    Write-Host "==> $Setup $Arguments"
    $process = Start-Process -FilePath $Setup -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "安装器退出码 $($process.ExitCode)：$Setup $Arguments"
    }
}

function Assert-ServiceVersion([string] $Expected, [string] $Label) {
    $service = Join-Path $InstallDir 'WinAppGuardSvc.exe'
    $ui = Join-Path $InstallDir 'WinAppGuard.exe'
    $serviceVersion = Get-ProductVersion $service
    $uiVersion = Get-ProductVersion $ui

    Write-Host "    $Label：界面=$uiVersion 服务=$serviceVersion"

    if ($serviceVersion -ne $Expected) {
        throw "$Label 服务版本不是 $Expected，而是 $serviceVersion"
    }

    if ($uiVersion -ne $Expected) {
        throw "$Label 界面版本不是 $Expected，而是 $uiVersion"
    }
}

function Assert-Pipe([string] $Expected, [string] $Label) {
    $pipes = @(Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -like 'WinAppGuard*' })
    $names = ($pipes | ForEach-Object { $_.Name }) -join ', '
    Write-Host "    $Label 管道：$names"

    if ($names -notmatch [regex]::Escape($Expected)) {
        throw "没有找到 $Expected 管道"
    }
}

$oldVersion = Get-ProductVersion (Join-Path (Split-Path $OldSetup) 'WinAppGuardSvc.exe')
$newVersion = Get-ProductVersion (Join-Path (Split-Path $NewSetup) 'WinAppGuardSvc.exe')

if (-not $oldVersion -or -not $newVersion) {
    throw '无法从安装器旁边的 WinAppGuardSvc.exe 读取版本；请使用完整 dist 目录。'
}

Write-Host "旧版=$oldVersion 新版=$newVersion"
Write-Host ''

try {
    if (Get-Service -Name 'WinAppGuardSvc' -ErrorAction SilentlyContinue) {
        Write-Host '==> 清理已有安装'
        Invoke-Installer $NewSetup '--uninstall'
    }

    Write-Host '==> 安装旧版'
    Invoke-Installer $OldSetup '--install'
    Assert-ServiceVersion $oldVersion '旧版安装后'
    Assert-Pipe 'WinAppGuard.Control.v3' '旧版'

    Write-Host '==> 只运行一次新版 --install（覆盖安装）'
    Invoke-Installer $NewSetup '--install'
    Assert-ServiceVersion $newVersion '覆盖安装后'
    Assert-Pipe 'WinAppGuard.Control.v4' '新版'

    Write-Host '==> doctor'
    $doctor = Join-Path $InstallDir 'WinAppGuardSvc.exe'
    & $doctor --cli --doctor
    if ($LASTEXITCODE -ne 0) {
        throw "doctor 退出码 $LASTEXITCODE"
    }

    Write-Host ''
    Write-Host '结果：覆盖安装矩阵通过。' -ForegroundColor Green
}
finally {
    if (-not $KeepInstalled) {
        Write-Host '==> 卸载，恢复 VM'
        Invoke-Installer $NewSetup '--uninstall'
    }
}
