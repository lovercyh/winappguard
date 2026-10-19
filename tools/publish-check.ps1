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

# 3.0：把服务与安装器也放进 dist-tools，方便在虚拟机里跑 --service-install-test
$distRoot = Join-Path $root 'dist'
foreach ($name in @('WinAppGuardSvc.exe', 'WinAppGuardSetup.exe')) {
    $source = Join-Path $distRoot $name
    if (Test-Path $source) {
        Copy-Item $source $distDir -Force
    } else {
        Write-Warning "未找到 $source（先运行 build\publish.ps1 才会生成服务与安装器）"
    }
}

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
Write-Host "    .\dist-tools\$exeName --ownership-test    IP 归属：**会联网**（whois.cymru.com:43）"
Write-Host "    .\dist-tools\$exeName --ownership-core-test  IP 归属：离线，缓存 / 开关 / 设置持久化"
Write-Host "    .\dist-tools\$exeName --connection-filter-test  连接列表：离线，搜索过滤与排序规则"
Write-Host "    .\dist-tools\$exeName --temp-block-test   临时阻断：离线，到期信息的编码 / 解析 / 判定"
Write-Host "    .\dist-tools\$exeName --temp-block-status 临时阻断：只读，打印每条规则的到期解析结果"
Write-Host "    .\dist-tools\$exeName --ui-check          界面：离线，布局与各种接线（会短暂闪一下窗口）"
Write-Host "    .\dist-tools\$exeName --strict-mode-test  严格模式：**会短暂断开未放行程序的网络**（会话级，结束即恢复，需管理员）"
Write-Host "    .\dist-tools\$exeName --strict-mode-lifecycle-test  严格模式：同上，验证白名单变化后重建会话、且不写 1.x 标志"
Write-Host "    .\dist-tools\$exeName --render-docs [目录]  生成 README 用的界面截图（离线，不需要管理员）"
Write-Host "    .\dist-tools\$exeName --audit [dll]       出厂审计：读编译产物元数据"
Write-Host "    .\dist-tools\$exeName --ui-polish-test    界面打磨：搜索 / 空状态 / 快捷键 / ui-state（离线）"
Write-Host "    .\dist-tools\$exeName --ui-dpi-test       界面：150% 字体下的布局（离线）"
Write-Host "    .\dist-tools\$exeName --rules-io-test     规则：分组与导入导出（离线，不建规则）"
Write-Host "    .\dist-tools\$exeName --rule-scope-test   规则：协议 / 远端端口（离线，不建规则）"
Write-Host "    .\dist-tools\$exeName --ipc-codec-test    服务：IPC 编解码（离线）"
Write-Host "    .\dist-tools\$exeName --service-ui-test    服务：状态显示（离线）"
Write-Host "    .\dist-tools\$exeName --service-install-test 服务：安装/查询/卸载（需管理员；会删除全部规则）"
Write-Host "    .\dist-tools\$exeName --wfp-scope-test    规则：真实过滤器的端口条件（需管理员，只拦 43）"
Write-Host "    .\dist-tools\$exeName --wfp-status        WFP：只读，打印当前规则与子层状态"
Write-Host "    .\dist-tools\$exeName --wfp-test          WFP：地基（结构体 / 子层 / 过滤器 / 动态会话，需管理员）"
Write-Host "    .\dist-tools\$exeName --wfp-rule-test     WFP：规则模型（编码解析 / V4+V6 / 幂等，需管理员）"
Write-Host "    .\dist-tools\$exeName --wfp-migrate-test  WFP：1.x → 2.0 迁移（需管理员）"
Write-Host "    .\dist-tools\$exeName --wfp-recover-test  WFP：恢复（清自己的对象 + 不碰 Windows 防火墙，需管理员）"
Write-Host "    .\dist-tools\$exeName --wfp-strict-test   WFP：严格模式会话（会真的拦，退出即恢复，需管理员）"
Write-Host "    .\dist-tools\$exeName --wfp-ip-rule-test  封禁 IP：**会联网**（只封一个 IP，验证邻居不受影响，需管理员）"
Write-Host "    .\dist-tools\$exeName --audit-store-test  记录：落盘（往返 / 轮转 / 保留期 / 半行容错，离线）"
Write-Host "    .\dist-tools\$exeName --audit-dns-test    记录：读本机 DNS 缓存 + 域名索引（离线、不联网）"
Write-Host "    .\dist-tools\$exeName --audit-service-test 记录：完整服务跑 12 秒（写临时目录）"
Write-Host "    .\dist-tools\$exeName --audit-live-test   记录：实时采集（连接 + 拦截事件，需管理员）"
Write-Host "    .\dist-tools\$exeName --audit-ui-test     记录：页结构（工具条 / 表格 / 开关，离线）"
Write-Host ''
Write-Host "（也可以直接双击 dist-tools\运行自检.cmd —— 它会把 9 项离线检查依次跑一遍。）"
Write-Host "  两个 --strict-mode-* 刻意不在那个启动器里：它们需要管理员、而且会真的断开网络，只适合手动单独跑。"

# 生成一个双击即可运行的启动器，方便在虚拟机里验证。
#
# ⚠️ 内容必须是**纯 ASCII**：cmd.exe 用系统 ANSI 代码页解码批处理文件，
#    UTF-8 中文会被解成乱码，进而破坏命令解析（和 PowerShell 5.1 的 BOM 坑同一类）。
#    用 ASCIIEncoding 写，既无 BOM 也不会写入非 ASCII 字节。
$launcherName = '运行自检.cmd'
$launcherPath = Join-Path $distDir $launcherName
$launcher = @'
@echo off
REM Generated by tools\publish-check.ps1. Must stay pure ASCII (see that script).
chcp 65001 >nul
cd /d "%~dp0"

set "EXE=WinAppGuard.SelfCheck.exe"

if not exist "%EXE%" (
    echo [ERROR] not found: %EXE%
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   [1/9]  connection filter and sort  (offline, no UI)
echo          keyword matching / numeric port and IP sorting
echo ============================================================
echo.
"%EXE%" --connection-filter-test --no-pause

echo.
echo ============================================================
echo   [2/9]  temporary block expiry  (offline, no system changes)
echo          encode / parse / expire judgement, incl. truncation
echo ============================================================
echo.
"%EXE%" --temp-block-test --no-pause

echo.
echo ============================================================
echo   [3/9]  ownership core check  (offline, no network)
echo          cache / expiry / capacity / switch / settings
echo ============================================================
echo.
"%EXE%" --ownership-core-test --no-pause

echo.
echo ============================================================
echo   [4/9]  ownership online lookup check
echo          NOTE: uses the network, only whois.cymru.com:43
echo ============================================================
echo.
"%EXE%" --ownership-test --no-pause

echo.
echo ============================================================
echo   [5/9]  UI layout check
echo          NOTE: a window will flash briefly, then close
echo          offline / no admin needed
echo ============================================================
echo.
"%EXE%" --ui-check --no-pause

echo.
echo ============================================================
echo   [6/9]  UI polish wiring  (offline)
echo          rules search / empty states / shortcuts / ui-state
echo ============================================================
echo.
"%EXE%" --ui-polish-test --no-pause

echo.
echo ============================================================
echo   [7/9]  high-DPI layout at 150%%  (offline)
echo          banner fit / toolbar overlap / button text fit
echo ============================================================
echo.
"%EXE%" --ui-dpi-test --no-pause

echo.
echo ============================================================
echo   [8/9]  rule groups and import/export  (offline)
echo          group store round-trip / export-import / bad files
echo ============================================================
echo.
"%EXE%" --rules-io-test --no-pause

echo.
echo ============================================================
echo   [9/9]  rule scope: protocol / port / network profile  (offline)
echo          encode-parse round-trip / validation / rule naming
echo ============================================================
echo.
"%EXE%" --rule-scope-test --no-pause

echo.
echo ---- done. press any key to close ----
pause >nul
'@
[System.IO.File]::WriteAllText($launcherPath, $launcher, (New-Object System.Text.ASCIIEncoding))
Write-Host "==> 完成：dist-tools\$launcherName"
