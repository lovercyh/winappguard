# 贡献指南

感谢你愿意参与。这个项目有些自己的规矩，先说清楚，省得来回改。

---

## 一、最重要的一条：注释和文档用中文

**代码注释、提交信息、Issue、PR 描述、文档，全部使用中文。**

这不是排外，而是这个项目从一开始就是这么写的，21 个源文件、约 5300 行代码的注释都是中文。
混进英文注释会让整个文件读起来割裂。

对外介绍用的 `README.md` 是英文的，方便别人判断这个工具敢不敢用；
但 `README.zh-CN.md` 和 `docs/` 下的文档是中文。

**Pull request 用中文或英文写都可以**，我们看得懂。

---

## 二、代码风格

### 必须遵守

| 规矩 | 原因 |
|---|---|
| **构建必须 0 警告 0 错误** | 警告在这个项目里当缺陷处理。CI 会用 `-warnaserror` 卡住 |
| **不引入第三方库** | 这是项目的核心卖点之一。能用 BCL 解决就用 BCL |
| **注释解释「为什么」，不是「做什么」** | 代码本身说明做了什么；注释要留下判断依据和踩过的坑 |
| **界面布局用 Dock，不要用「AutoSize 控件 + 绝对坐标 + 固定高度容器」** | 这个组合在文字长度会变化的地方**必然**出问题，项目里因此真实出过 bug |

### 具体约定

- 一个类型一个文件；数据模型放 `Models/`，与系统交互的代码放 `Core/`，界面放 `Forms/`
- **所有 P/Invoke 只能写在 `Interop/NativeMethods.cs`**，这样安全审计只看一个文件
- 所有对防火墙的写入**只能**经过 `Core/FirewallManager.cs`
- 所有对计划任务的写入**只能**经过 `Core/AutoStartManager.cs`
- 所有会改动系统状态的操作**必须**走 `Forms/ConfirmForm.cs` 弹确认框
- 错误处理统一走 `ShowError`（一处写日志、一处弹框），不要各写各的

---

## 三、安全红线

以下几条属于**安全边界**，改动它们需要特别说明理由：

1. **只创建和删除 `AppGuard_` 前缀的规则** —— 删除前有硬性校验，不要把校验挪到界面层
2. **不修改全局防火墙策略 —— 唯一例外是严格模式**：`FirewallManager.SetOutboundDefaultAllowed`
   是**全项目唯一**会写全局策略的方法，只被 `Core/StrictModeManager.cs` 调用。
   如果你想动它，必须先保证：**先落盘意图再动系统**、**三条还原路径齐备**
   （正常退出 / 启动兜底 / `--cleanup` 与「删除全部规则」）、
   **原值不是「三套全允许」就拒绝开启**。
   `FirewallEnabled` 与 `DefaultInboundAction` **仍然只读**
3. **关键进程保护做在防火墙底层**，不能只做界面置灰。
   ⚠️ 它**只限制「阻止」，不限制「允许」**（`ValidateProgramPath` 的 `forBlocking` 参数）
4. **联网只能从 `Core/IpOwnershipLookup.cs` 一个出口走**，且只连
   `AppConstants.OwnershipLookupHost:OwnershipLookupPort` 这一个固定地址。
   私有 / 回环 / 链路本地地址必须在**发送前**过滤掉
5. **没有遥测、没有更新检查、没有统计**；唯一会发出去的是远程 IP（第 4 条，可关闭）
6. **不用注册表做持久化**（自启用计划任务，设置写 `%LOCALAPPDATA%` 下的 JSON）
7. **日志只写本机**，不上传任何内容；设置文件只存布尔值
8. **界面字符串里不要写 Markdown 强调符（`**`）**：WinForms 会原样显示给用户。
   自检会扫一遍整个控件树来守着这条

`tools/SelfCheck` 的 `--audit` 模式会检查第 4、5、6 条（含一项防 P/Invoke 绕过的检查），
CI 每次都会跑。

---

## 四、提交之前请自查

```powershell
# 1. 三个构建都要 0 警告 0 错误
dotnet build WinAppGuard.sln -c Debug
dotnet build WinAppGuard.sln -c Release
dotnet build .\tools\SelfCheck\SelfCheck.csproj -c Debug

# 2. 编译产物审计（不需要管理员权限）
.\dist-tools\WinAppGuard.SelfCheck.exe --audit
```

### 改动了界面？

界面在这个项目里没法「跑起来看一眼」就完事 —— 很多问题在特定状态下才出现。
请用**渲染 + 断言**的方式验证，至少要覆盖：

- 三种真实文字长度（短 / 中 / 最长）
- 标签页来回切换之后的状态
- 窗口缩放之后的状态

并且断言要写成可重复运行的，不要只靠人工看一次。项目里已有的几个断言可以直接照着改。

### 改动了行为？

请附一条**能抓住这个 bug 的断言**。这个项目的原则是：

> 修一个 bug 的时候，顺手写一条能复现它的断言。
> 否则下次改别的地方很容易把它改回来。

举个真实的例子：项目里有一条断言专门检查「分区宽度不超过可视宽度」，
因为 `AutoScroll` 和 `Anchor=Right` 同用会让控件越排越宽（实测从 1361 涨到 2532），
而这个现象第一眼看上去是正常的。

---

## 五、报告问题

- **安全漏洞**：不要开公开 issue，见 [`SECURITY.md`](SECURITY.md)
- **普通 bug**：用 Issue 模板，尽量带上
  - Windows 版本（`winver`）
  - WinAppGuard 版本
  - `%LOCALAPPDATA%\WinAppGuard\logs\` 里相关的日志行
  - 复现步骤

---

## 六、不要做的事

- 不要为了让某个测试通过而放宽安全校验
- 不要提交 `bin/`、`obj/`、`dist/`、`dist-tools/`（已在 `.gitignore` 里）
- 不要把含中文的 `.ps1` 存成**不带 BOM** 的 UTF-8
  —— PowerShell 5.1 会按 ANSI 解析，中文会变乱码导致脚本直接跑不起来
- 不要用 `Get-Content` / `Set-Content` 批量改含中文的 `.cs` 文件，同样会毁掉编码
