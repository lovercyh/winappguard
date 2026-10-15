<#
    WinAppGuard 防火墙验证工具 —— 单文件发布脚本

    用法（在项目根目录执行）：
        powershell -ExecutionPolicy Bypass -File .\tools\publish-check.ps1

    产出：
        dist-tools\WinAppGuard.FirewallCheck.exe

    这个 exe 是自包含单文件，可以直接拷到任何 Windows 10/11 x64 机器上运行，
    目标机器不需要安装 .NET。

    注意：这是**开发期验证工具**，不是产品的一部分。
#>

$ErrorActionPreference = 'Stop'

# 让控制台按 UTF-8 输出中文，避免中文提示变成乱码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root       = Split-Path -Parent $PSScriptRoot
$project    = Join-Path $root 'tools\SelfCheck\SelfCheck.csproj'
$distDir    = Join-Path $root 'dist-tools'
$publishDir = Join-Path $root 'tools\_publish'

Write-Host '==> 清理旧的输出目录'
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
if (Test-Path $distDir)    { Remove-Item $distDir    -Recurse -Force }
New-Item -ItemType Directory -Path $distDir | Out-Null

Write-Host '==> 发布自检工具（Release / win-x64 / self-contained / 单文件）'
# RID、自包含、单文件这些配置都写在 SelfCheck.csproj 的 Release 段里，命令行不用再重复一遍。
dotnet publish $project -c Release -o $publishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败，退出码 $LASTEXITCODE" }

$exeName = 'WinAppGuard.SelfCheck.exe'
$exePath = Join-Path $publishDir $exeName
if (-not (Test-Path $exePath)) { throw "发布失败：未找到 $exePath" }

# 被引用的 WinAppGuard 本身是个可执行工程，发布会顺带把它的 runtimeconfig.json 复制过来。
# 验证工具自己的运行配置已经内嵌在单文件 exe 里，这个文件完全没有用，直接删掉。
$strayRuntimeConfig = Join-Path $publishDir 'WinAppGuard.runtimeconfig.json'
if (Test-Path $strayRuntimeConfig) { Remove-Item $strayRuntimeConfig -Force }

$extraFiles = Get-ChildItem $publishDir -File |
    Where-Object { $_.Name -ne $exeName -and $_.Extension -ne '.pdb' }

if ($extraFiles) {
    Write-Warning '检测到单文件之外还存在以下文件，说明单文件打包未完全生效：'
    $extraFiles | ForEach-Object { Write-Warning ("    " + $_.Name) }
}

Copy-Item $exePath $distDir -Force

$sizeMB = [math]::Round((Get-Item (Join-Path $distDir $exeName)).Length / 1MB, 1)
Write-Host ''
Write-Host "==> 完成：dist-tools\$exeName  （$sizeMB MB）"
Write-Host ''
Write-Host '用法：'
Write-Host "    .\dist-tools\$exeName --status            防火墙：只读，只看不改"
Write-Host "    .\dist-tools\$exeName                     防火墙：完整自动化测试，结束后自动清理"
Write-Host "    .\dist-tools\$exeName --leave             防火墙：建一条演示规则并保留，供在 wf.msc 里核对"
Write-Host "    .\dist-tools\$exeName --cleanup           防火墙：删除全部 AppGuard 规则"
Write-Host "    .\dist-tools\$exeName --autostart-status  自启：只读，打印任务状态和原始 XML"
Write-Host "    .\dist-tools\$exeName --autostart-test    自启：完整测试（建 → 逐项核对 → 删）"
Write-Host "    .\dist-tools\$exeName --autostart-disable 自启：删除 WinAppGuard 自启任务"
