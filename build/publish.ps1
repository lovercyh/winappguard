<#
    WinAppGuard 单文件发布脚本

    用法（在项目根目录执行）：
        powershell -ExecutionPolicy Bypass -File .\build\publish.ps1

    产出：
        dist\WinAppGuard.exe    —— win-x64 自包含单文件，双击即可运行
#>

$ErrorActionPreference = 'Stop'

# 让控制台按 UTF-8 输出中文，避免中文提示变成乱码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 项目根目录 = 本脚本所在目录的上一级
$root       = Split-Path -Parent $PSScriptRoot
$project    = Join-Path $root 'src\WinAppGuard\WinAppGuard.csproj'
$service    = Join-Path $root 'src\WinAppGuard.Svc\WinAppGuard.Svc.csproj'
$setup      = Join-Path $root 'src\WinAppGuard.Setup\WinAppGuard.Setup.csproj'
$distDir    = Join-Path $root 'dist'
$publishDir = Join-Path $root 'build\_publish'

Write-Host '==> 清理旧的输出目录'
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
if (Test-Path $distDir)    { Remove-Item $distDir    -Recurse -Force }
New-Item -ItemType Directory -Path $distDir | Out-Null

Write-Host '==> 发布（Release / win-x64 / self-contained / 单文件）'
dotnet publish $project -c Release -o $publishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败，退出码 $LASTEXITCODE" }

$exePath = Join-Path $publishDir 'WinAppGuard.exe'
if (-not (Test-Path $exePath)) { throw "发布失败：未找到 $exePath" }

# 校验单文件是否真的打成单文件：除了 exe 和调试符号 pdb，不应该再有别的文件
$extraFiles = Get-ChildItem $publishDir -File |
    Where-Object { $_.Name -ne 'WinAppGuard.exe' -and $_.Extension -ne '.pdb' }

if ($extraFiles) {
    Write-Warning '检测到单文件之外还存在以下文件，说明单文件打包未完全生效，请检查 csproj 配置：'
    $extraFiles | ForEach-Object { Write-Warning ("    " + $_.Name) }
}

Copy-Item $exePath $distDir -Force

# ---- 3.0：服务与安装器（同样是自包含单文件）----
Write-Host '==> 发布服务与安装器'
$serviceDir = Join-Path $root 'build\_publish_svc'
$setupDir   = Join-Path $root 'build\_publish_setup'

foreach ($dir in @($serviceDir, $setupDir)) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
}

dotnet publish $service -c Release -o $serviceDir
if ($LASTEXITCODE -ne 0) { throw "发布服务失败，退出码 $LASTEXITCODE" }

dotnet publish $setup -c Release -o $setupDir
if ($LASTEXITCODE -ne 0) { throw "发布安装器失败，退出码 $LASTEXITCODE" }

foreach ($pair in @(
    @{ Dir = $serviceDir; Name = 'WinAppGuardSvc.exe' },
    @{ Dir = $setupDir;   Name = 'WinAppGuardSetup.exe' }
)) {
    $path = Join-Path $pair.Dir $pair.Name
    if (-not (Test-Path $path)) { throw "发布失败：未找到 $path" }
    Copy-Item $path $distDir -Force
}

$sizeMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuard.exe')).Length / 1MB, 1)
$serviceMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuardSvc.exe')).Length / 1MB, 1)
$setupMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuardSetup.exe')).Length / 1MB, 1)
Write-Host ''
Write-Host "==> 完成：dist\WinAppGuard.exe  （$sizeMB MB）"
Write-Host "           dist\WinAppGuardSvc.exe  （$serviceMB MB）"
Write-Host "           dist\WinAppGuardSetup.exe  （$setupMB MB）"
Write-Host '    安装：管理员运行 dist\WinAppGuardSetup.exe --install'
Write-Host '    双击界面会先弹出 UAC 确认框，这是预期行为。'
