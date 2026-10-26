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
$selfCheck  = Join-Path $root 'tools\SelfCheck\SelfCheck.csproj'
$selfCheckOut = Join-Path $root 'build\_selfcheck'
$distTools  = Join-Path $root 'dist-tools'

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

# 卸载器：与安装器同一份二进制，文件名决定双击行为（完整卸载）
Copy-Item (Join-Path $distDir 'WinAppGuardSetup.exe') (Join-Path $distDir 'WinAppGuardUninstall.exe') -Force

# ---- 3.0 发布版：把界面 / 服务 / 卸载器追加进 Setup 的内部载荷 ----
# 用户从 Releases 只需要下载 Setup + Uninstall；单独下载界面或服务是没用的。
$payloadDir = Join-Path $root 'build\_payload'
$payloadZip = Join-Path $root 'build\_payload.zip'

if (Test-Path $payloadDir) { Remove-Item $payloadDir -Recurse -Force }
New-Item -ItemType Directory -Path $payloadDir | Out-Null
Copy-Item (Join-Path $distDir 'WinAppGuard.exe')     $payloadDir
Copy-Item (Join-Path $distDir 'WinAppGuardSvc.exe')  $payloadDir
# 安装器本体（未追加载荷的 base）：安装到 Program Files 后既能修复也能充当卸载器。
Copy-Item (Join-Path $distDir 'WinAppGuardSetup.exe') $payloadDir

if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $payloadDir, $payloadZip,
    [System.IO.Compression.CompressionLevel]::Optimal, $false)

$zipBytes    = [System.IO.File]::ReadAllBytes($payloadZip)
$magic       = [System.Text.Encoding]::ASCII.GetBytes('WAGPAY01')
$lengthBytes = [BitConverter]::GetBytes([int64]$zipBytes.Length)
$setupPath   = Join-Path $distDir 'WinAppGuardSetup.exe'

$stream = [System.IO.File]::Open($setupPath, 'Append', 'Write')
try {
    $stream.Write($zipBytes, 0, $zipBytes.Length)
    $stream.Write($magic, 0, $magic.Length)
    $stream.Write($lengthBytes, 0, $lengthBytes.Length)
} finally {
    $stream.Dispose()
}

Remove-Item $payloadDir -Recurse -Force
Remove-Item $payloadZip -Force
Write-Host "    内置载荷：$([math]::Round($zipBytes.Length / 1MB, 1)) MB（界面 + 服务 + 卸载器）"

$sizeMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuard.exe')).Length / 1MB, 1)
$serviceMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuardSvc.exe')).Length / 1MB, 1)
$setupMB = [math]::Round((Get-Item (Join-Path $distDir 'WinAppGuardSetup.exe')).Length / 1MB, 1)

# ---- 同步 dist-tools：VM 是整目录复制，必须让这个目录也保持最新 ----
# 以前只更新 dist，VM 复制过去的 dist-tools 仍是旧版本，验收会跑到旧包上。
Write-Host '==> 同步 dist-tools（VM 整目录复制用）'
New-Item -ItemType Directory -Path $distTools -Force | Out-Null

foreach ($name in @(
    'WinAppGuard.exe',
    'WinAppGuardSvc.exe',
    'WinAppGuardSetup.exe',
    'WinAppGuardUninstall.exe'
)) {
    Copy-Item (Join-Path $distDir $name) (Join-Path $distTools $name) -Force
}

if (Test-Path $selfCheckOut) { Remove-Item $selfCheckOut -Recurse -Force }
dotnet publish $selfCheck -c Release -o $selfCheckOut
if ($LASTEXITCODE -ne 0) { throw "发布自检工具失败，退出码 $LASTEXITCODE" }

Copy-Item (Join-Path $selfCheckOut 'WinAppGuard.SelfCheck.exe') $distTools -Force

foreach ($name in @('3.4-验收脚本.ps1', '3.5-验收脚本.ps1', '3.6-验收脚本.ps1', '3.7-验收脚本.ps1')) {
    $acceptanceScript = Join-Path $root "docs\$name"

    if (Test-Path $acceptanceScript) {
        Copy-Item $acceptanceScript $distTools -Force
    }
}

Write-Host ''
Write-Host "==> 完成：dist\WinAppGuard.exe  （$sizeMB MB）"
Write-Host "           dist\WinAppGuardSvc.exe  （$serviceMB MB）"
Write-Host "           dist\WinAppGuardSetup.exe  （$setupMB MB）"
Write-Host "           dist\WinAppGuardUninstall.exe  （卸载器，双击完整卸载）"
Write-Host "           dist-tools\  （已同步：4 个 exe + WinAppGuard.SelfCheck.exe + 验收脚本）"
Write-Host '    安装：管理员运行 dist\WinAppGuardSetup.exe --install'
Write-Host '    界面以普通权限运行；修改规则时才弹一次 UAC。'
