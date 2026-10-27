# WinAppGuard

**看清谁在联网，两次点击把它拦掉。**

**开源防火墙** · 基于 WFP 的程序联网控制 · **源码公开，可自行审计与构建**

简体中文 · [English](README.en.md)

> 源码与许可证：[github.com/lovercyh/winappguard](https://github.com/lovercyh/winappguard)（MIT）

WinAppGuard 是一个 Windows 程序联网控制工具，但它和多数同类工具的入手方向相反：
它不让你去翻程序列表，而是直接展示**当前正在联网的 TCP 连接** ——
从「现在是哪个程序在联网」出发，到「已阻止」结束。

> WinAppGuard 不转发、不修改任何流量。真正生效的是基于 WFP 的独立过滤引擎：
> WinAppGuard 只负责按你的选择创建和清理 WFP 过滤器，数据包匹配与拦截由 Windows 内核 WFP 执行。
> 4.0 的反扫描只读取入站 TCP 头做检测，不读载荷、不阻断数据包。
> 从 2.0 起它不再使用 Windows 防火墙，也不再修改 Windows 防火墙的任何设置。
>
> **3.0 起拆成「防护服务 + 界面」**：规则写入、严格模式会话、审计采集都由服务
> `WinAppGuardSvc` 持有；界面以普通权限运行，改规则时才弹一次 UAC。
>
> **3.1 起启用受保护模式**：安装时的账户成为**唯一所有者**。服务只接受所有者签名，
> 其他账户（包括其他管理员）不能通过界面或 IPC 修改规则。私钥用 DPAPI 用户级加密，
> 服务端只保存公钥。详见 [`docs/受保护模式设计.md`](docs/受保护模式设计.md)。
>
> **3.7 新增用户态 Flow IDS**：用连接元数据与 DNS 检测周期性外联、端口/主机扫描、
> 内网横向和 DNS 异常。**只检测、不阻断**，默认开启，告警本地保留 30 天。详见
> [`docs/3.7-用户态FlowIDS设计.md`](docs/3.7-用户态FlowIDS设计.md)。
>
> **4.0 新增反端口扫描**：通过可选的 Npcap 采集入站 TCP SYN，检测端口扫描，
> 并可临时封禁扫描来源 IP；**自动封禁默认关闭**，只封新连接。安装器可选安装
> 官方 Npcap，不会静默安装。详见
> [`docs/4.0-反端口扫描设计.md`](docs/4.0-反端口扫描设计.md)。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-lightgrey.svg)](#环境要求)
[![Release](https://img.shields.io/github/v/release/lovercyh/winappguard)](https://github.com/lovercyh/winappguard/releases/latest)

![联网连接页](docs/screenshots/01-connections.png)

---

## 它做什么

- **列出正在联网的 TCP 连接**：程序名、完整路径、PID、本地端口、远程 IP、远程端口、状态、协议（IPv4/IPv6）、**以及该程序的数字签名**
- **告诉你这个连接在跟谁通信**：鼠标停在远程 IP 上，就能看到它的国家/地区和运营商（自治系统）
- **搜索与排序**：按 进程名 / PID / 远程 IP / 远程端口 过滤；点表头排序（端口和 IP 按**数值**排，不是按字符串）
- **阻止某个程序联网**：为该可执行文件写一条出站过滤器（TCP、UDP、IPv4 与 IPv6 一起管），
  并且可以选择**阻止多久** —— 永久 / 30 分钟 / 2 小时 / 直到下次重启；
  限时阻断到期后会**自己解除**
- **允许它重新联网**：删掉自己为它创建的过滤器
- **严格模式（默认关闭，高级功能）**：**真白名单** —— 只有白名单里的程序能上网。
  它在**防护服务**里建立一个动态会话（白名单放行 + 阻止全部），**不改任何系统设置**；
  关掉界面保护仍在；服务停止、崩溃或被强杀，限制都会**自动消失**。
  为保证 DNS / 时间同步 / Windows 更新不被一起挡掉，内置放行一份系统必需程序清单
  （以 `svchost.exe` 为主）。
- **每程序流量**：「联网连接」页显示该程序本次服务运行以来的**上传 / 下载 / 总计**
  （ETW 按 TCP + UDP 统计，近似值；短连接可能漏计）。服务重启后从 0 开始。
- **「流量」页**：按程序汇总本次服务运行以来的上传/下载/总计，可按时间或流量排序、
  搜索、查看统计起点和合计，也可以一键清空（需要一次 UAC）。
- **DNS 查询记录**：新增「DNS」页，显示最近查询的**域名、PID、程序、结果**；
  只记录系统 DNS 客户端看到的域名，**不记录 URL、不记录响应内容**；DoH/DoT 可能看不到。
- **IDS（只检测、不阻断）**：「IDS」页默认开启，用连接元数据与 DNS 检测
  **周期性外联、端口/主机扫描、内网横向、DNS 异常**；告警本地保留 30 天，
  可确认 / 抑制 / 清空。不做 DPI / HTTPS 解密，不抓包，不自动阻断。
- **反端口扫描（4.0）**：「防护」页通过可选的 Npcap 检测入站 TCP SYN 端口扫描；
  可临时封禁扫描来源 IP（5 / 10 / 30 / 60 分钟），自动封禁**默认关闭**，
  只拦新连接、不切断已有连接。Npcap 未安装时反扫描不可用，不影响防火墙主功能。
- **临时锁网**：严格模式面板 / 托盘菜单提供 **30 分钟 / 2 小时**；
  到点自动恢复，服务停止或崩溃也会立即恢复，不残留断网状态。
- **提权/受保护进程路径**：界面读不到时由服务（SYSTEM）代查并补全，
  不会再只显示「（无法获取）」。
- **有一页专门管理自己建的规则**，所以程序就算已经不运行了，也随时能恢复
- **「记录」页**：过去一段时间**谁连了谁、有没有被拦** —— 类型（连接·拦截）、程序、远端、
  **域名（推测）**、**命中的是哪条规则**；支持搜索、只看拦截、一键清空。
  记录只写本机、默认开启，**保留期可在记录页选（1 / 3 / 7 / 30 天，默认 7 天）**。
- **封禁 IP**：在「记录」页选中一条连接直接「拦截此 IP」，或手动「添加 IP」。
  规则按**远端 IP** 生效（IPv4 / IPv6），不经过域名解析；同一 IP 上的其它服务会一起被拦。
- **「黑名单」与「严格模式下白名单」分开两页**：黑名单 = 谁不许上网（程序阻止 + 封禁 IP，
  带「类型」列区分）；白名单 = 严格模式下谁可以上网，页面上直接写明"现在生不生效"。
  两页各有搜索，也都可以按路径「添加程序…」（严格模式下没放行的程序不会出现在连接页）。
- **精细化规则**：可以只拦 / 只放行某个**协议**（TCP / UDP）和某个**远端端口**（单个或范围）；
  规则列表里有「范围」列。
- **规则分组**：黑名单 / 白名单都有「分组」列和分组筛选；
  分组只影响界面归类，不影响规则是否生效。
- **规则导出 / 导入**：黑名单和白名单各有「导出…」「导入…」，各自导出本页规则（含分组），
  换台机器再导入；导入只创建、不删除，坏文件整份拒绝，跨页导入会被拦住。
- **快捷键**：`F5` 刷新、`Ctrl+F` 搜索、`Esc` 清空、`Delete` 删除选中。
- **界面语言**：状态栏可切换「跟随系统 / 简体中文 / English」；非中文系统默认英文，切换后重启生效
- **安装器 / 卸载器固定中英双语**（不做语言开关）；**CLI 默认跟随界面已生效语言**，也可用 `--lang zh|en|auto` 只覆盖本次
- **服务日志固定英文 + 事件码**（如 `WAG-RULE-913`），不随界面语言变化，方便检索和远程排障
- **记住窗口大小与列宽**（只存尺寸，不存任何隐私数据），下次打开还是原样；
  记录页还能右键复制远端地址 / 程序路径 / 域名。
- **可选开机自启**，启动后直接进系统托盘
- **规则都落在自己专属的 WFP 子层里**，用界面上的两个清单页查看；
  `wf.msc` 里不会出现它们（那里本来就只显示 Windows 防火墙自己的规则）

## 它**不**做什么

这一点必须说清楚。

- ❌ **不**过滤、检查或转发任何流量 —— 那全是系统的 WFP 在做
- ❌ **不**修改 Windows 防火墙的任何设置 —— 也不禁用防火墙、不改默认入站/出站动作。
  **严格模式也不例外**：它只在进程内建立会话，退出即撤销
- ❌ **不**碰别人创建的过滤器或规则 —— 只看、只删自己子层 GUID 下的过滤器
- ❌ **不**抓包、不做 DPI / HTTPS 解密：流量只是 ETW 字节计数，DNS 只记域名，
  不保存任何载荷或 URL 路径
- ❌ 反扫描只检测**入站 TCP SYN**，不做 UDP 扫描、载荷检测或永久自动封禁；
  Npcap 未安装时反扫描不可用
- ❌ **不**阻止系统关键进程（`lsass.exe`、`svchost.exe`、它自己……）——
  这道护栏只管「阻止」，不管「允许」（放行永远不会把谁锁在外面）
- ⚠️ 它**默认会联网**，但只有三个明确用途（见下）。**没有遥测、没有统计、没有更新检查**

### 关于「不联网」，说实话

**WinAppGuard 不是零联网程序，文档也不再用含糊的说法掩盖这一点。**
1.1 及更早的版本确实做到了「自身不含任何网络代码」；1.2 加入 IP 归属查询之后，
这个说法**被正式作废**，而不是靠措辞继续维持。

会碰网络的只有**三处**，**都默认开启，也都能在界面上关掉**：

| | 联网由谁发起 | 发什么 | 发给谁 | 怎么关 |
|---|---|---|---|---|
| **IP 归属查询** | 本程序自己的代码 | 只发**远程 IP** | `whois.cymru.com:43` | 设置 → 数据与隐私 |
| **证书吊销检查** | Windows 的证书服务（Crypt32） | CRL / OCSP 查询 | 该证书的 CA | 设置 → 数据与隐私 |
| **域名推测** | 本程序自己的代码 | DNS 查询（**只查系统缓存里已有的名字**） | **本机配置的 DNS 服务器** | **记录** 页的开关 |

三处都关掉之后，本程序**不产生任何网络流量**。

> 关于「域名推测」：它读的是 Windows 的 DNS 缓存；缓存条目刚好过期时，
> Windows 可能向**本机 DNS 服务器**补发一次查询。关掉后程序**不发任何 DNS 查询**，
> 代价是「记录」页的域名覆盖率明显下降（实测 29% → 8%）。

**关于 IP 归属查询**（1.2 新增）：它把每条连接的远程 IP 解析成国家/地区和运营商（自治系统），
让连接列表能回答「我在跟谁通信」，而不只是「是哪个 IP」：

- 只发送**远程 IP** —— 不发进程名、程序路径、PID、端口，或任何其它本机信息；
- 局域网 / 回环 / 链路本地地址**在发送之前就被过滤掉**，根本不出本机；
- 按主机名连接意味着 .NET 运行时会先对 `whois.cymru.com` 做一次 DNS 解析。
  这不是 HTTP 请求，但确实是一次域名解析，所以我们写出来而不是藏着；
- 关掉是**持久生效**的（记在 `settings.json`），重启不会自己打开；
- **第一次运行**会弹一次说明，把上面这些讲清楚。

**关于证书吊销检查**：发起请求的始终是 **Windows 的证书服务**，不是本程序的代码；
过程中不会送出任何关于你或你机器的信息，就是一次标准的 CRL/OCSP 查询。
关掉之后只读本地缓存。

- ❌ **不**用注册表做持久化 —— 开机自启只用任务计划程序，设置只写 `%LOCALAPPDATA%` 下的文件
- ❌ IDS 告警**不上传**：只写本机 `%ProgramData%\WinAppGuard\ids\`，只含连接元数据和证据摘要，
  不含载荷、URL 或 HTTPS 内容；默认保留 30 天，可清空。

## 命令行模式

想脚本化 / 批量部署时可以直接用命令行（**需要管理员权限**，包括 `--help`）：

```powershell
WinAppGuard.exe --block "C:\Tools\a.exe"   # 阻止某个程序联网（可重复执行，幂等）
WinAppGuard.exe --list-blocked             # 列出所有「阻止」规则
WinAppGuard.exe --unblock-all              # 只预览要删什么，什么都不删
WinAppGuard.exe --unblock-all --yes        # 真的删掉
WinAppGuard.exe --help                     # 用法
WinAppGuard.exe --list-blocked --lang en   # 本次使用英文（默认跟随界面语言）
```

- **语言**：默认跟随界面已生效的语言；`--lang zh|en|auto` 只影响本次命令，不写任何设置。
- **退出码**：`0` 成功 / `1` 参数错误或未确认 / `2` 执行失败 / `3` 缺少管理员权限。
- `--list-blocked` **一行一条**、制表符分隔，`#` 开头的是说明行 —— 便于脚本解析。
- 这些命令**不弹确认框**（命令行参数本身就是明确指令）；**图形界面里的操作仍然每条都要确认**。
- 图形界面启动时会先出现约 0.5 秒的控制台窗口（控制台子系统换来的同步 CLI），随后自动收起。

## 界面

| IDS（只检测、不阻断） | 防护（反端口扫描） |
|---|---|
| ![IDS 页](docs/screenshots/06-ids.png) | ![防护页](docs/screenshots/09-protection.png) |
| **流量** | **DNS** |
| ![流量页](docs/screenshots/07-traffic.png) | ![DNS 页](docs/screenshots/08-dns.png) |
| **黑名单** | **严格模式下白名单** |
| ![黑名单页](docs/screenshots/02-rules.png) | ![严格模式下白名单](docs/screenshots/05-whitelist.png) |
| **设置** | |
| ![设置页](docs/screenshots/03-settings.png) | |

![阻止确认框](docs/screenshots/04-confirm-block.png)

所有会改动系统状态的操作都要先过确认框。确认框里会写明：程序名、**完整路径**、
影响范围、**即将创建或删除的规则名**。

> IDS 页只产生告警，不会自动阻断；确认 / 抑制 / 清空和改设置同样要过一次 UAC。

## 下载（Releases 只需要两个文件）

从 [Releases](https://github.com/lovercyh/winappguard/releases) 下载：

| 文件 | 用途 |
|---|---|
| **`WinAppGuardSetup.exe`** | 安装 / 修复（**界面与服务已经打包在里面**） |
| **`WinAppGuardUninstall.exe`** | 完整卸载 |

> ⚠️ **不要**单独下载或运行 `WinAppGuard.exe` / `WinAppGuardSvc.exe`。
> 它们不是独立可用的程序：前者只是界面、后者只是服务；
> 没有安装器就不会注册服务、不会创建快捷方式，**单独下载不起作用**。

安装器双击后会请求一次管理员权限，然后自动完成：
复制文件 → 创建服务（SYSTEM、自动启动）→ 创建桌面快捷方式。

- 目标机器**不需要安装 .NET**；安装器已内置界面、服务和卸载器。
- 安装器可选安装官方 Npcap（反端口扫描需要）；不勾选也能正常使用防火墙，反扫描不可用。
- Npcap 由官方 GUI 安装，不静默安装；安装目录会保留 `Npcap-LICENSE.txt`。
- 安装包和卸载器**没有代码签名**，SmartScreen 首次运行会提示「未知发布者」，这是预期情况。
- 下载后可用发布说明里的 SHA-256 校验文件是否被篡改。

## 安装 / 卸载

- **双击 `WinAppGuardSetup.exe`**：未安装则安装，已安装则修复；会自动创建桌面快捷方式。
- **双击 `WinAppGuardUninstall.exe`**：完整卸载（服务、规则、快捷方式、记录与设置、安装目录）。
- 命令行：`WinAppGuardSetup.exe --install|--repair|--start-service|--uninstall`。

## 环境要求

- Windows 10 / 11 x64
- 安装与 CLI 需要管理员权限；界面用普通权限运行，改规则时弹一次 UAC
- 运行发布包不需要 .NET；从源码构建需要 .NET SDK 10
- 反端口扫描需要 Npcap（安装器可选安装；不安装不影响其它功能）

## 工作原理

| 环节 | 实现 |
|---|---|
| 拦截 | 每个可执行文件路径写**两条**出站过滤器（IPv4 + IPv6），挂在 WFP 的 `ALE_AUTH_CONNECT` 层 |
| 规则命名 | `AppGuard_Block_<程序名>_<路径哈希前 8 位>` —— 确定性命名，重复阻止是幂等的 |
| 访问防火墙 | 直接调用 `fwpuclnt.dll`（WFP 用户态 API），12 个函数、零第三方库 |
| 只碰自己 | 所有枚举/删除都按**子层 GUID** 过滤，别的软件与系统对象一律不碰 |
| 读取连接表 | `iphlpapi.dll` 的 `GetExtendedTcpTable` |
| 反查程序路径 | `QueryFullProcessImageNameW`（不创建 `Process` 对象，所以每 3 秒刷新也不会泄漏句柄） |
| 开机自启 | 一条名为 `WinAppGuard` 的计划任务，登录时触发，最高权限，**不限执行时长** |
| 单实例 | 命名互斥体 + 广播窗口消息，重复启动会把已有窗口叫到前台 |
| IP 归属 | Team Cymru WHOIS，走普通 TCP 连 `whois.cymru.com:43` —— 本程序**主动连接外部主机**的唯一端点；批量查询 + 内存缓存；默认开启，可关闭 |
| 严格模式 | 进程内建立**动态 WFP 会话**：白名单放行（高权重）+ 阻止全部（低权重）。退出/崩溃即自动撤销，不改任何系统设置 |
| 限时阻断 | 到期时间存在**过滤器自己的说明字段**里（`AppGuard\|1\|Block\|路径\|自动解除=…`），重启也不会丢。后台 30 秒定时器负责清理到期规则并弹托盘提示 |
| 流量统计 | ETW `Microsoft-Windows-Kernel-Network` 的 TCP/UDP 收发事件，按 PID 累加；不抓包、不看载荷 |
| DNS 记录 | ETW `Microsoft-Windows-DNS-Client`，只取域名、PID 和结果码；内存保留最近 2000 条 |
| Flow IDS | 复用上面两个 ETW 会话，把连接五元组 / 次数 / 字节 / 域名交给内存规则引擎；只产生告警，不 inline 阻断 |
| 反端口扫描 | 可选 Npcap 在 NDIS 层只抓入站 TCP SYN（BPF 过滤），按来源 IP 统计端口 / 主机数；不读载荷 |
| 临时 IP 封禁 | 用户态 WFP `ALE_AUTH_RECV_ACCEPT_V4/V6` 过滤器，按远端 IP 拦新入站连接；到期或手动解除，不切断已有连接 |

## 可验证的信任

多数工具只能让你「相信它」。这个工具自带验证手段：

```powershell
WinAppGuard.SelfCheck.exe --audit
```

它**不是搜源码**，而是直接读**编译出来的程序集的元数据** —— 包括间接引用和框架自动带进来的东西：

```
引用的程序集            25 个，全部来自 .NET 框架    → 零第三方库
网络相关类型引用        2 个：TcpClient / NetworkStream
                        → 都在预期清单内，只属于 IP 归属查询
原生 API 调用（P/Invoke）  17 个
网络相关原生调用        无                          → 没有绕过托管检查直接用网络 API
注册表访问              无
```

关于这份输出，有两句话要说：

- 从 1.2 起，审计**不再要求「网络类型为零」**，而是要求所有网络类型**全部落在预期清单内**，
  并新增一项检查：不允许有人用 P/Invoke 直接调 `ws2_32` / `winhttp` / `wininet` 绕过去。
  **一份「绿的但藏着联网路径」的审计，比没有审计更糟。**
- `--audit` 不需要管理员权限，所以 CI 里也能跑。

那 17 个原生调用就是程序能碰到的**全部**非托管函数：

```
iphlpapi.dll!GetExtendedTcpTable                    读 TCP 连接表
kernel32.dll!OpenProcess                            打开进程（查路径用）
kernel32.dll!QueryFullProcessImageNameW             查进程可执行文件路径
kernel32.dll!CloseHandle                            关句柄
kernel32.dll!FreeConsole                            图形界面模式启动时收掉控制台窗口
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

**29 个（17 个 Win32 + 12 个 WFP），除此之外它碰不到任何东西。**

## 安全护栏

这些检查做在**规则写入的底层**，不在界面层 —— 界面逻辑写错也绕不过去。

| 护栏 | 位置 |
|---|---|
| 只删除自己子层 GUID 下的过滤器，其余一律看不见、也删不到 | `WfpRuleStore` / `WfpEngine` |
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

- 往 WFP 里写过滤器（这需要管理员权限，也需要直接调用系统 API）；
- 创建一条**登录时以最高权限运行**的计划任务 —— 这在技术上就是提权持久化；
- 读取 TCP 连接表并反查进程路径。

启发式引擎对这套组合很敏感。但它创建的东西全部可见、可删：任务名固定为 `WinAppGuard`
且**未勾选隐藏**，过滤器全部在固定 GUID 的专属子层里（一条命令就能清干净）。
想核实二进制文件的能力，跑上面那个 `--audit`。

### SmartScreen 提示「未知发布者」

exe 没有代码签名 —— 代码签名证书要花钱，而这是个免费工具。
点「更多信息」→「仍要运行」，或者先核对发布说明里的 SHA-256。

### 权限模型（3.1 起，3.4 起含 WFP 对象）

- **所有者**：运行安装器时的提权账户。只有所有者能使用界面/服务。
- **界面**：`asInvoker`，双击不弹 UAC；所有者查看连接、规则、记录不需要管理员。
- **修改规则 / 严格模式 / 记录设置**：弹一次 UAC，由提权助手
  （`WinAppGuardSvc.exe --elevated-ipc`）转发给服务；助手也使用所有者密钥签名。
- **服务** `WinAppGuardSvc`：以 SYSTEM 运行，是**唯一**写 WFP 的进程；
  只接受所有者 ECDSA 签名。
- **管道/服务 ACL**：管道只允许 `SYSTEM` + 所有者；服务 DACL 给
  `Administrators` 仅查询/启动，其他账户无权限。管理员仍可通过接管所有权绕过。
- **WFP 对象 ACL（3.4 起）**：子层与过滤器使用**受保护 DACL**（`SE_DACL_PROTECTED`），
  对象 Owner 设为创建者（服务 = SYSTEM），只允许 `SYSTEM` + 所有者删除/改 ACL；父容器的继承 ACE 被拒绝，`Administrators` 不再有写权限。拥有 `SeTakeOwnership` / `SeRestore` 的管理员仍可先夺取所有权，
  所以这是提高门槛，不是“管理员绝对删不掉”。
- **密钥**：`%ProgramData%\WinAppGuard\protected-mode\client-key.dpapi`
  （DPAPI 用户级）；`config.json` 只存公钥/entropy/指纹。卸载时始终删除。
- **开机自启**：计划任务以「最高权限」运行，登录时**不会弹 UAC**，并可静默拉起服务。
- **命令行模式**：`--block / --list-blocked / --unblock-all` 通过签名 IPC 执行；
  `--migrate / --recover` 是管理员恢复命令。CLI 仍要求管理员权限。

> 不是所有者 / 密钥不可用 / 未初始化时，界面会明确说明原因，规则页只读。
> 更换所有者请用所有者运行 `WinAppGuardSetup.exe --reset-owner`。

### 我点了关闭，但它还在运行

这是刻意设计的。关闭窗口只是收进托盘 —— 如果直接退出，防火墙规则还在生效，
而用户会以为工具已经关掉了，回头找不到恢复入口。
要真正退出，请右键托盘图标选「退出」。

### 退出程序等于放行吗？

**不等于。** 退出只结束界面进程，防火墙规则依然生效，被阻止的程序依然上不了网。
要放行必须用「解除阻止（允许联网）」或「删除全部 AppGuard 规则」。退出时的确认框会明确写这一点。

### 界面提示“当前账户不是所有者”/“密钥不可用”

3.1 起只有安装时的账户（所有者）能使用界面和服务。

- **不是所有者**：用安装时的账户登录；确需更换所有者，由管理员以新所有者身份运行
  `WinAppGuardSetup.exe --reset-owner`。
- **密钥不可用**：密钥文件缺失或 DPAPI 解不开。由所有者运行
  `WinAppGuardSetup.exe --rotate-key` 重建密钥。
- **未初始化**：3.0 升级后还没生成密钥，运行 `WinAppGuardSetup.exe --repair`。

其他管理员仍可以杀进程、替换二进制或直接操作 WFP；受保护模式提高门槛并留痕，
但不宣称防住铁了心的本机管理员。

### 怎么彻底清理干净？

```
1. 双击 WinAppGuardUninstall.exe（或 WinAppGuardSetup.exe --uninstall）
2. 确认卸载
```

卸载会删除服务、WFP 规则/子层、快捷方式、开机自启任务、记录、设置、
受保护模式密钥和安装目录。
想保留规则/记录（但**仍会删除密钥**）可以运行：

```powershell
WinAppGuardUninstall.exe --uninstall --keep-data
```

如果只是遇到异常、想清掉本工具在 WFP 里的对象，用管理员运行：

```powershell
WinAppGuard.exe --recover
```

### 阻止是按路径生效的，不是按 PID

规则按程序身份（可执行文件路径）匹配，所以：

- 同一个路径的所有实例会被一起拦掉（不看命令行参数）；
- 同一个程序换到别的目录运行**不受影响**；
- 程序更新后如果安装路径变了，旧规则会失效，重新拦一次即可。

### 为什么被阻止的程序从连接列表里消失了？

因为它连不上网，自然就没有连接可列。请去「规则」页管理它
—— 那一页是基于**你的规则**，不是基于实时流量。

### 日志在哪？

- 界面日志：`%LOCALAPPDATA%\WinAppGuard\logs\`，按天分文件，保留最近 7 天。
- 服务日志：`%ProgramData%\WinAppGuard\logs\`，**固定英文 + 事件码**（如 `[WAG-SVC-002] Service started.`），
  不随界面语言变化；异常只记录类型、HResult、Win32 错误码和堆栈，不写本地化的系统消息。

**只写本机，不会发送到任何地方。** 「设置」页显示界面日志路径，并提供打开按钮。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/安全说明.md`](docs/安全说明.md) | 安全模型，九条约定逐条给出自查方法 |
| [`docs/验收清单.md`](docs/验收清单.md) | 全量验收清单（自动化结论 + 手动勾选项） |
| [`docs/测试用例.md`](docs/测试用例.md) | 各阶段测试用例与实测结论 |
| [`docs/发布手册.md`](docs/发布手册.md) | 从构建、验证到发布的操作流程 |
| [`docs/服务化设计.md`](docs/服务化设计.md) | 3.0 防护服务 + 界面客户端设计（已实现） |
| [`docs/受保护模式设计.md`](docs/受保护模式设计.md) | 3.1 单所有者、ECDSA/DPAPI、协议 v2、ACL 与生命周期 |
| [`docs/3.6-流量记录设计.md`](docs/3.6-流量记录设计.md) | 3.6 流量页的聚合、排序与清空 |
| [`docs/3.7-用户态FlowIDS设计.md`](docs/3.7-用户态FlowIDS设计.md) | 3.7 用户态 Flow IDS：规则、阈值、存储与边界 |
| [`docs/3.7-VM验收.md`](docs/3.7-VM验收.md) | 3.7 自动验收与 VM 实测结果 |
| [`docs/4.0-反端口扫描设计.md`](docs/4.0-反端口扫描设计.md) | 4.0 Npcap 采集、扫描规则、WFP 入站封禁与边界 |
| [`docs/4.0-VM验收.md`](docs/4.0-VM验收.md) | 4.0 Npcap 安装、扫描测试与 soak 验收 |

## 参与贡献

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。简短版：**代码注释和提交信息用中文**，
构建必须零警告，行为改动要配一条能抓住该 bug 的断言。

## 许可证

[MIT](LICENSE)。
