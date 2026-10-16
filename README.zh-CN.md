# WinAppGuard

**看清谁在联网，两次点击把它拦掉。**

[English](README.md) · 简体中文

WinAppGuard 是一个 Windows 防火墙规则管理工具，但它和多数同类工具的入手方向相反：
它不让你去翻程序列表，而是直接展示**当前正在联网的 TCP 连接** ——
从「现在是哪个程序在联网」出发，到「已阻止」结束。

> WinAppGuard 本身不拦截任何流量。真正生效的是 **Windows 防火墙**。
> WinAppGuard 只负责按你的选择创建和清理这些规则。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-lightgrey.svg)](#环境要求)

![联网连接页](docs/screenshots/01-connections.png)

---

## 它做什么

- **列出正在联网的 TCP 连接**：程序名、完整路径、PID、本地端口、远程 IP、远程端口、状态、协议（IPv4/IPv6）、**以及该程序的数字签名**
- **阻止某个程序联网**：为该可执行文件写一条出站防火墙规则（TCP 和 UDP 一起管）
- **允许它重新联网**：删掉自己为它创建的规则
- **有一页专门管理自己建的规则**，所以程序就算已经不运行了，也随时能恢复
- **可选开机自启**，启动后直接进系统托盘
- **所有规则名都以 `AppGuard_` 开头**，你自己打开 `wf.msc` 也能一眼认出来

## 它**不**做什么

这一点必须说清楚，因为它需要管理员权限。

- ❌ **不**过滤、检查或转发任何流量 —— 那全是 Windows 防火墙在做
- ❌ **不**修改全局防火墙策略：从不禁用防火墙，从不改默认入站/出站动作
- ❌ **不**碰别人创建的防火墙规则 —— 删除被硬性限制在 `AppGuard_` 前缀之内
- ❌ **不**阻止系统关键进程（`lsass.exe`、`svchost.exe`、它自己……）
- ❌ **不**发送任何数据出去：没有遥测、没有更新检查、没有任何统计
- ⚠️ **但默认会联网查询证书吊销状态** —— 下方「关于不联网，说实话」一节有完整说明

### 关于「不联网」，说实话

本程序**自身不含任何网络代码**（这一点可以用 `--audit` 验证）。

但「数字签名」这一列默认会检查证书吊销状态，此时 **Windows 的证书服务（Crypt32）会代表本程序
去联系 CA 服务器**。在资源监视器里能看到 `WinAppGuard.exe` 有对外连接。

- **这是刻意的取舍**：查吊销才能知道一张证书是否已被吊销，结论更准。
- **可以关掉**：「设置 → 数据与隐私」里取消勾选「检查证书吊销状态」。
  关掉之后只读本地缓存，本程序**完全不留任何网络流量**。
- 发起请求的始终是 **Windows 的证书服务**，不是本程序的代码；
  过程中不会送出任何关于你或你机器的信息，就是一次标准的 CRL/OCSP 查询。
- ❌ **不**用注册表做持久化 —— 开机自启只用任务计划程序

## 界面

| 已阻止的程序 | 设置 |
|---|---|
| ![规则页](docs/screenshots/02-rules.png) | ![设置页](docs/screenshots/03-settings.png) |

![阻止确认框](docs/screenshots/04-confirm-block.png)

所有会改动系统状态的操作都要先过确认框。确认框里会写明：程序名、**完整路径**、
影响范围、**即将创建或删除的规则名**。

## 下载与使用

从 [最新 Release](https://github.com/lovercyh/winappguard/releases/latest) 下载 `WinAppGuard.exe`。

- 单文件自包含，约 49 MB，**目标机器不需要安装 .NET**
- 可用发布说明里的 SHA-256 校验下载是否被篡改：
  ```powershell
  Get-FileHash .\WinAppGuard.exe -Algorithm SHA256
  ```
- **exe 没有代码签名**，SmartScreen 会提示「未知发布者」，这属于预期情况，见下方常见问题

## 环境要求

- Windows 10 / 11 x64
- 管理员权限（它要改防火墙规则和任务计划程序）

## 工作原理

| 环节 | 实现 |
|---|---|
| 拦截 | 每个可执行文件路径一条出站防火墙规则，协议「任意」（TCP + UDP），所有网络配置文件 |
| 规则命名 | `AppGuard_Block_<程序名>_<路径哈希前 8 位>` —— 确定性命名，重复阻止是幂等的 |
| 访问防火墙 | Windows 防火墙 COM 接口（`HNetCfg.FwPolicy2`），无需任何第三方库 |
| 读取连接表 | `iphlpapi.dll` 的 `GetExtendedTcpTable` |
| 反查程序路径 | `QueryFullProcessImageNameW`（不创建 `Process` 对象，所以每 3 秒刷新也不会泄漏句柄） |
| 开机自启 | 一条名为 `WinAppGuard` 的计划任务，登录时触发，最高权限，**不限执行时长** |
| 单实例 | 命名互斥体 + 广播窗口消息，重复启动会把已有窗口叫到前台 |

## 可验证的信任

多数工具只能让你「相信它」。这个工具自带验证手段：

```powershell
WinAppGuard.SelfCheck.exe --audit
```

它**不是搜源码**，而是直接读**编译出来的程序集的元数据** —— 包括间接引用和框架自动带进来的东西：

```
引用的程序集          22 个，全部来自 .NET 框架     → 零第三方库
会发起网络行为的类型   0 个                          → 程序自身零网络代码
原生 API 调用（P/Invoke）  16 个
注册表访问             无
```

那 16 个原生调用就是程序能碰到的**全部**非托管函数：

```
iphlpapi.dll!GetExtendedTcpTable                    读 TCP 连接表
kernel32.dll!OpenProcess                            打开进程（查路径用）
kernel32.dll!QueryFullProcessImageNameW             查进程可执行文件路径
kernel32.dll!CloseHandle                            关句柄
user32.dll!RegisterWindowMessageW                   注册单实例用的自定义消息
user32.dll!PostMessageW                             广播单实例消息
wintrust.dll!WinVerifyTrust                         验证内嵌数字签名
wintrust.dll!CryptCATAdminAcquireContext2           打开目录签名上下文
wintrust.dll!CryptCATAdminCalcHashFromFileHandle2   算文件哈希
wintrust.dll!CryptCATAdminEnumCatalogFromHash       按哈希找所属目录
wintrust.dll!CryptCATCatalogInfoFromContext         取目录文件路径
wintrust.dll!CryptCATAdminReleaseCatalogContext     释放目录上下文
wintrust.dll!CryptCATAdminReleaseContext            释放目录管理上下文
wintrust.dll!WTHelperProvDataFromStateData          从验证状态取数据
wintrust.dll!WTHelperGetProvSignerFromChain         取签名者
wintrust.dll!WTHelperGetProvCertFromChain           取签名者证书
```

**16 个，除此之外它碰不到任何东西。**

## 安全护栏

这些检查做在**防火墙底层**，不在界面层 —— 界面逻辑写错也绕不过去。

| 护栏 | 位置 |
|---|---|
| 只允许删除 `AppGuard_` 开头的规则，其余直接抛异常拒绝 | `FirewallManager.DeleteRule` |
| 创建规则前拒绝系统关键进程 | `FirewallManager.ValidateProgramPath` |
| 拒绝不存在的文件、非 `.exe`、UNC 网络路径 | 同上 |
| 所有危险操作都要弹确认框，删除全部规则要**连续确认两次** | `Forms/ConfirmForm.cs` |

逐条的实现说明和**自查方法**见 [`docs/安全说明.md`](docs/安全说明.md)。

## 从源码构建

需要 [.NET SDK 10](https://dotnet.microsoft.com/download) 或更高。

```powershell
git clone https://github.com/lovercyh/winappguard.git
cd winappguard

dotnet build WinAppGuard.sln -c Debug

# 产出 dist\WinAppGuard.exe（win-x64、自包含、单文件）
powershell -ExecutionPolicy Bypass -File .\build\publish.ps1
```

构建必须 **0 警告 0 错误**。在这个项目里，警告当作缺陷处理，不当噪音。

## 常见问题

### 为什么杀毒软件会报毒？

因为它确实在做这些事：

- 创建 Windows 防火墙规则；
- 创建一条**登录时以最高权限运行**的计划任务 —— 这在技术上就是提权持久化；
- 读取 TCP 连接表并反查进程路径。

启发式引擎对这套组合很敏感。但它创建的东西全部可见、可删：任务名固定为 `WinAppGuard`
且**未勾选隐藏**，防火墙规则全部以 `AppGuard_` 开头。
想核实二进制文件的能力，跑上面那个 `--audit`。

### SmartScreen 提示「未知发布者」

exe 没有代码签名 —— 代码签名证书要花钱，而这是个免费工具。
点「更多信息」→「仍要运行」，或者先核对发布说明里的 SHA-256。

### 为什么必须管理员权限？

创建防火墙规则和注册计划任务都必须提权。程序在清单里声明了 `requireAdministrator`，
所以启动时会弹 UAC。

### 我点了关闭，但它还在运行

这是刻意设计的。关闭窗口只是收进托盘 —— 如果直接退出，防火墙规则还在生效，
而用户会以为工具已经关掉了，回头找不到恢复入口。
要真正退出，请右键托盘图标选「退出」。

### 退出程序等于放行吗？

**不等于。** 退出只结束界面进程，防火墙规则依然生效，被阻止的程序依然上不了网。
要放行必须用「允许选中程序联网」或「删除全部 AppGuard 规则」。退出时的确认框会明确写这一点。

### 怎么彻底清理干净？

```
1. 打开 WinAppGuard
2. 「已阻止的程序」页 → 删除全部 AppGuard 规则
3. 「设置」页 → 关闭开机自启
4. 托盘右键 → 退出
5. 删除 WinAppGuard.exe
6. （可选）删除 %LOCALAPPDATA%\WinAppGuard 目录
```

第 2、3 步不做就直接删 exe 的话，规则和计划任务会留在系统里继续生效。
真遇到这种情况：`wf.msc` 搜 `AppGuard` 删规则、`taskschd.msc` 删任务。

### 阻止是按路径生效的，不是按 PID

Windows 防火墙按可执行文件路径匹配，所以：

- 同一个路径的所有实例会被一起拦掉（不看命令行参数）；
- 同一个程序换到别的目录运行**不受影响**；
- 程序更新后如果安装路径变了，旧规则会失效，重新拦一次即可。

### 为什么被阻止的程序从连接列表里消失了？

因为它连不上网，自然就没有连接可列。请去「已阻止的程序」页管理它
—— 那一页是基于**你的规则**，不是基于实时流量。

### 日志在哪？

`%LOCALAPPDATA%\WinAppGuard\logs\`，按天分文件，保留最近 7 天。
**只写本机，不会发送到任何地方。** 「设置」页显示这个路径，并提供打开按钮。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/安全说明.md`](docs/安全说明.md) | 安全模型，九条约定逐条给出自查方法 |
| [`docs/验收清单.md`](docs/验收清单.md) | 全量验收清单（自动化结论 + 手动勾选项） |
| [`docs/测试用例.md`](docs/测试用例.md) | 各阶段测试用例与实测结论 |
| [`docs/发布手册.md`](docs/发布手册.md) | 从构建、验证到发布的操作流程 |

## 参与贡献

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。简短版：**代码注释和提交信息用中文**，
构建必须零警告，行为改动要配一条能抓住该 bug 的断言。

## 许可证

[MIT](LICENSE)。
