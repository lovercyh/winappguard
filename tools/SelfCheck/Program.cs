using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Principal;
using System.Text;
using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.SelfCheck;

/// <summary>
/// WinAppGuard 自检工具。
///
/// 这是一个**开发期工具**，不是产品的一部分，不会被发布到最终 exe 里。
/// 它的作用是让「程序对系统做了什么」可以被亲眼验证，而不是只能相信代码注释。
///
/// 覆盖两块：
///   防火墙  —— 规则的创建 / 查询 / 删除，以及 17 项安全护栏；
///   开机自启 —— 计划任务的创建 / 查询 / 删除，以及任务内容的逐项核对。
///
/// 用法：
///   WinAppGuard.SelfCheck.exe                    防火墙：完整自动化测试，结束后自动清理
///   WinAppGuard.SelfCheck.exe --leave            防火墙：建一条演示规则并**保留**，供你在 wf.msc 里核对
///   WinAppGuard.SelfCheck.exe --cleanup          防火墙：删除全部 AppGuard 规则
///   WinAppGuard.SelfCheck.exe --status           防火墙：只读，打印全局状态和现有 AppGuard 规则
///   WinAppGuard.SelfCheck.exe --autostart-status  自启：只读，打印任务状态和原始 XML
///   WinAppGuard.SelfCheck.exe --autostart-test    自启：完整测试（建 → 逐项核对 → 删）
///   WinAppGuard.SelfCheck.exe --autostart-disable 自启：删除 WinAppGuard 自启任务
///   WinAppGuard.SelfCheck.exe --audit [dll]      出厂审计：读编译产物元数据，证明零网络代码 / 零第三方库
///   任一模式加 --no-pause 可以不等待回车直接退出
///
/// 安全说明：
///   1. 防火墙部分只创建/删除以 AppGuard_ 开头的规则，从不修改全局防火墙策略；
///   2. 自启部分只创建/删除名为 WinAppGuard 的计划任务，绝不碰其他人的任务；
///   3. 两种完整测试模式无论中途是否出错，最后都会强制清理自己创建的东西；
///   4. 审计模式是纯只读的，只是读一个文件。
/// </summary>
internal static class Program
{
    private static readonly StringBuilder Report = new();

    /// <summary>失败项计数。用于让进程返回非零退出码 —— CI 需要靠它判断成败。</summary>
    private static int _failedCheckCount;

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        var noPause = args.Contains("--no-pause", StringComparer.OrdinalIgnoreCase);

        // 只有 --audit 是纯只读的（只读一个文件的元数据），不需要管理员权限。
        // 这样它在 CI（无法弹 UAC）里也能跑起来。
        var needsAdmin = !args.Contains("--audit", StringComparer.OrdinalIgnoreCase);

        if (needsAdmin && !AdminHelper.IsRunningAsAdmin())
        {
            // 自己提权，而不是靠清单强制提权 —— 清单强制的话，CI 里连 --audit 都起不来。
            Console.WriteLine("本模式需要管理员权限，正在请求提权…");

            if (AdminHelper.RestartAsAdmin(string.Join(' ', args)))
            {
                return 0;
            }

            Console.WriteLine("提权被拒绝或失败。请右键以管理员身份运行，或在管理员命令行里执行。");
            if (!noPause)
            {
                Pause();
            }

            return 2;
        }

        try
        {
            if (args.Contains("--status", StringComparer.OrdinalIgnoreCase))
            {
                RunStatus();
            }
            else if (args.Contains("--cleanup", StringComparer.OrdinalIgnoreCase))
            {
                RunCleanup();
            }
            else if (args.Contains("--leave", StringComparer.OrdinalIgnoreCase))
            {
                RunLeaveOneRule();
            }
            else if (args.Contains("--autostart-status", StringComparer.OrdinalIgnoreCase))
            {
                RunAutoStartStatus();
            }
            else if (args.Contains("--autostart-disable", StringComparer.OrdinalIgnoreCase))
            {
                RunAutoStartDisable();
            }
            else if (args.Contains("--autostart-test", StringComparer.OrdinalIgnoreCase))
            {
                RunAutoStartTest();
            }
            else if (args.Contains("--audit", StringComparer.OrdinalIgnoreCase))
            {
                RunAudit(args);
            }
            else
            {
                RunFullTest();
            }
        }
        catch (Exception ex)
        {
            // 连顶层都兜住：这是给人看的验证工具，宁可打印异常也不要静默退出。
            W();
            W("!!! 验证程序自身出错了 !!!");
            W(ex.ToString());
            SaveReport();
            if (!noPause) Pause();
            return 1;
        }

        SaveReport();
        if (!noPause) Pause();

        // 返回非零退出码，CI 才能判断成败。
        return _failedCheckCount > 0 ? 1 : 0;
    }

    // ==================================================================
    // 模式 1：完整自动化测试
    // ==================================================================

    private static void RunFullTest()
    {
        var isAdmin = IsAdmin();
        var candidates = FindTestTargets();

        if (candidates.Count < 2)
        {
            W("找不到足够的测试目标 exe，无法验证。");
            return;
        }

        var target1 = candidates[0];
        var target2 = candidates[1];

        // 记录本次创建过的规则名，放在 finally 里兜底清理。
        var created = new List<string>();

        var results = new List<(string Title, bool Passed)>();
        void Check(string title, bool passed) => results.Add((title, passed));

        try
        {
            W("################################################################");
            W("#   WinAppGuard 防火墙底层能力验证                              #");
            W("################################################################");

            // ---------------- 0. 环境 ----------------
            W();
            W("================= 0. 环境 =================");
            W($"管理员身份         = {isAdmin}{(isAdmin ? "" : "   <<< 没有管理员权限，后面的操作会失败")}");
            W($"测试目标 1         = {target1}");
            W($"测试目标 2         = {target2}");
            W($"防火墙 COM 组件    = 可访问（能走到这一步说明 HNetCfg.FwPolicy2 正常）");

            var stateBefore = FirewallManager.GetGlobalState();
            var totalBefore = FirewallManager.GetTotalRuleCount();
            var existingBefore = FirewallManager.GetAppGuardRules().Count;

            W($"防火墙启用         = {stateBefore.FirewallEnabled}");
            W($"默认入站动作       = {DescribeAction(stateBefore.DefaultInboundAction)}");
            W($"默认出站动作       = {DescribeAction(stateBefore.DefaultOutboundAction)}");
            W($"系统防火墙规则总数 = {totalBefore}");
            W($"现有 AppGuard 规则 = {existingBefore} 条{(existingBefore > 0 ? "   <<< 注意：本来就存在，测试结束会被删掉" : "")}");

            // ---------------- 1. 创建阻止规则 ----------------
            W();
            W("================= 1. 创建「阻止」规则 =================");
            var blockName = FirewallManager.CreateBlockRule(target1);
            created.Add(blockName);
            W($"返回的规则名       = {blockName}");
            Check("规则名以 AppGuard_ 开头", blockName.StartsWith(AppConstants.RulePrefix, StringComparison.Ordinal));

            var rulesAfterCreate = FirewallManager.GetAppGuardRules();
            W($"AppGuard 规则条数  = {rulesAfterCreate.Count}");
            Check("创建后能查到 1 条规则", rulesAfterCreate.Count == 1);

            foreach (var rule in rulesAfterCreate)
            {
                W($"  +-- 名称   = {rule.Name}");
                W($"  |   程序   = {rule.ApplicationPath}");
                W($"  |   动作   = {rule.ActionText}     方向 = {rule.DirectionText}     协议 = {rule.ProtocolText}");
                W($"  |   启用   = {rule.EnabledText}     分组 = {rule.Grouping}");
                W($"  \\-- 说明   = {rule.Description}");
            }

            if (rulesAfterCreate.Count == 1)
            {
                var r = rulesAfterCreate[0];
                Check("动作是「阻止」", r.Action == FirewallAction.Block);
                Check("方向是「出站」", r.Direction == FirewallDirection.Outbound);
                Check("协议是「任意」（TCP+UDP 一起管）", r.Protocol == 256);
                Check("规则已启用", r.Enabled);
                Check("程序路径正确", string.Equals(r.ApplicationPath, target1, StringComparison.OrdinalIgnoreCase));
                Check("分组名是 AppGuard", r.Grouping == AppConstants.RuleGroupingName);
            }

            // ---------------- 2. 幂等性 ----------------
            W();
            W("================= 2. 重复创建（幂等性）=================");
            var blockName2 = FirewallManager.CreateBlockRule(target1);
            W($"第二次返回的规则名  = {blockName2}");
            W($"AppGuard 规则条数   = {FirewallManager.GetAppGuardRules().Count}");
            Check("重复创建不会产生第二条规则", FirewallManager.GetAppGuardRules().Count == 1);
            Check("两次生成的规则名完全一致", blockName == blockName2);
            Check("IsProgramBlocked 返回 True", FirewallManager.IsProgramBlocked(target1));

            // ---------------- 3. 允许规则 ----------------
            W();
            W("================= 3. 创建「允许」规则 =================");
            var allowName = FirewallManager.CreateAllowRule(target1);
            created.Add(allowName);
            W($"返回的规则名        = {allowName}");
            W($"AppGuard 规则条数   = {FirewallManager.GetAppGuardRules().Count}");
            Check("允许规则名以 AppGuard_Allow_ 开头", allowName.StartsWith(AppConstants.RulePrefixAllow, StringComparison.Ordinal));
            Check("允许规则也能创建成功（共 2 条）", FirewallManager.GetAppGuardRules().Count == 2);

            // ---------------- 4. 按程序删除 ----------------
            W();
            W("================= 4. 删除某个程序的全部规则 =================");
            var deleted = FirewallManager.DeleteRulesForProgram(target1);
            W($"删除条数            = {deleted}");
            W($"AppGuard 规则条数   = {FirewallManager.GetAppGuardRules().Count}");
            W($"IsProgramBlocked    = {FirewallManager.IsProgramBlocked(target1)}");
            Check("按程序删除返回 2", deleted == 2);
            Check("删除后规则数归零", FirewallManager.GetAppGuardRules().Count == 0);
            Check("IsProgramBlocked 返回 False", !FirewallManager.IsProgramBlocked(target1));
            created.Clear();

            // ---------------- 5. 安全护栏 ----------------
            W();
            W("================= 5. 安全护栏（每一条都必须被拒绝）=================");

            var guardResults = new List<(string Title, bool Rejected)>();

            void ExpectReject(string title, Action action)
            {
                var rejected = false;
                string detail;
                try
                {
                    action();
                    detail = "没有抛出异常";
                }
                catch (Exception ex)
                {
                    rejected = true;
                    detail = $"{ex.GetType().Name}: {ex.Message}";
                }

                guardResults.Add((title, rejected));
                W($"  [{(rejected ? "拒绝" : "!!! 放行 !!!")}] {title}");
                W($"             {detail}");
            }

            ExpectReject("空路径", () => FirewallManager.CreateBlockRule(""));
            ExpectReject("全是空格的路径", () => FirewallManager.CreateBlockRule("   "));
            ExpectReject("不存在的文件", () => FirewallManager.CreateBlockRule(@"C:\这个文件不存在\fake.exe"));
            ExpectReject("非 exe 文件（hosts）", () => FirewallManager.CreateBlockRule(
                Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts")));
            ExpectReject("网络共享路径（UNC）", () => FirewallManager.CreateBlockRule(@"\\server\share\a.exe"));

            foreach (var sys in new[] { "lsass.exe", "svchost.exe", "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "dwm.exe" })
            {
                var path = Path.Combine(Environment.SystemDirectory, sys);
                ExpectReject($"系统关键进程 {sys}", () => FirewallManager.CreateBlockRule(path));
            }

            var selfPath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(selfPath))
            {
                ExpectReject($"自我保护（{Path.GetFileName(selfPath)}）", () => FirewallManager.CreateBlockRule(selfPath));
            }

            ExpectReject("删除非 AppGuard 前缀的规则", () => FirewallManager.DeleteRule("Core Networking - DNS (UDP-Out)"));
            ExpectReject("删除空规则名", () => FirewallManager.DeleteRule(""));

            // 名字合法但不存在，属于正常情况：应该安静返回 false，不该抛异常。
            var notExist = FirewallManager.DeleteRule("AppGuard_Block_不存在.exe_00000000");
            guardResults.Add(("删除不存在的 AppGuard 规则应返回 false", !notExist));
            W($"  [{(notExist ? "!!! 异常 !!!" : "正常")}] 删除不存在的 AppGuard 规则 -> 返回 {notExist}");

            // 把每一项护栏的结果计入总结
            foreach (var (title, rejected) in guardResults)
            {
                Check($"护栏：{title}", rejected);
            }

            // 预期要覆盖的护栏清单。
            //
            // 这里刻意写成「显式清单」而不是一个数字上限：
            //   - 写数字的话，数字本身算错会误报（本次就发生过：写成 19，实际只有 17）；
            //   - 写数字的话，将来漏掉一条护栏反而可能照样通过。
            // 清单比对能同时抓出「漏测」和「多测」两种情况。
            var expectedGuards = new List<string>
            {
                "空路径",
                "全是空格的路径",
                "不存在的文件",
                "非 exe 文件（hosts）",
                "网络共享路径（UNC）",
                "系统关键进程 lsass.exe",
                "系统关键进程 svchost.exe",
                "系统关键进程 csrss.exe",
                "系统关键进程 services.exe",
                "系统关键进程 smss.exe",
                "系统关键进程 winlogon.exe",
                "系统关键进程 wininit.exe",
                "系统关键进程 dwm.exe",
                $"自我保护（{Path.GetFileName(selfPath)}）",
                "删除非 AppGuard 前缀的规则",
                "删除空规则名",
                "删除不存在的 AppGuard 规则应返回 false",
            };

            var actualGuards = guardResults.Select(r => r.Title).ToList();
            var missingGuards = expectedGuards.Where(t => !actualGuards.Contains(t)).ToList();
            var unexpectedGuards = actualGuards.Where(t => !expectedGuards.Contains(t)).ToList();

            W();
            W($"护栏清单核对：预期 {expectedGuards.Count} 项，实际跑了 {actualGuards.Count} 项");
            if (missingGuards.Count > 0)
            {
                W($"  漏测：{string.Join(" / ", missingGuards)}");
            }

            if (unexpectedGuards.Count > 0)
            {
                W($"  多余：{string.Join(" / ", unexpectedGuards)}");
            }

            Check("护栏覆盖完整（无漏测、无多余）", missingGuards.Count == 0 && unexpectedGuards.Count == 0);

            // ---------------- 6. 批量删除 ----------------
            W();
            W("================= 6. 批量删除全部 AppGuard 规则 =================");
            var a = FirewallManager.CreateBlockRule(target1);
            var b = FirewallManager.CreateBlockRule(target2);
            created.Add(a);
            created.Add(b);
            W($"先创建 2 条         = {a}");
            W($"                      {b}");
            var countBeforeWipe = FirewallManager.GetAppGuardRules().Count;
            W($"创建后条数          = {countBeforeWipe}");
            var wiped = FirewallManager.DeleteAllAppGuardRules();
            W($"DeleteAll 返回      = {wiped}");
            W($"删除后条数          = {FirewallManager.GetAppGuardRules().Count}");
            Check("删除前确实是 2 条", countBeforeWipe == 2);
            Check("批量删除返回 2", wiped == 2);
            Check("批量删除后归零", FirewallManager.GetAppGuardRules().Count == 0);
            created.Clear();

            // ---------------- 7. 收尾对比 ----------------
            W();
            W("================= 7. 收尾对比（证明没动全局策略、没动别人的规则）=================");
            var stateAfter = FirewallManager.GetGlobalState();
            var totalAfter = FirewallManager.GetTotalRuleCount();

            W($"防火墙启用     = {stateBefore.FirewallEnabled} -> {stateAfter.FirewallEnabled}");
            W($"默认入站动作   = {DescribeAction(stateBefore.DefaultInboundAction)} -> {DescribeAction(stateAfter.DefaultInboundAction)}");
            W($"默认出站动作   = {DescribeAction(stateBefore.DefaultOutboundAction)} -> {DescribeAction(stateAfter.DefaultOutboundAction)}");
            W($"规则总数       = {totalBefore} -> {totalAfter}");
            W($"残留 AppGuard 规则 = {FirewallManager.GetAppGuardRules().Count}");

            Check("防火墙启用状态未被改动", stateBefore.FirewallEnabled == stateAfter.FirewallEnabled);
            Check("默认入站动作未被改动", stateBefore.DefaultInboundAction == stateAfter.DefaultInboundAction);
            Check("默认出站动作未被改动", stateBefore.DefaultOutboundAction == stateAfter.DefaultOutboundAction);
            Check("防火墙规则总数未被改动（没动别人的规则）", totalBefore == totalAfter);
            Check("没有残留 AppGuard 规则", FirewallManager.GetAppGuardRules().Count == 0);
        }
        finally
        {
            // 无论中途发生什么，都不留残留规则。
            foreach (var name in created)
            {
                try { FirewallManager.DeleteRule(name); } catch { /* 收尾清理，忽略 */ }
            }

            PrintSummary(results);
        }
    }

    // ==================================================================
    // 模式 2：保留一条演示规则，供人工在 wf.msc 里核对
    // ==================================================================

    private static void RunLeaveOneRule()
    {
        var targets = FindTestTargets();
        if (targets.Count == 0)
        {
            W("找不到可用的测试目标 exe。");
            return;
        }

        var target = targets[0];

        W("################################################################");
        W("#   创建一条演示规则并保留，供你人工核对                        #");
        W("################################################################");
        W();
        W($"目标程序 = {target}");
        W();

        var ruleName = FirewallManager.CreateBlockRule(target);

        W($"已创建规则名 = {ruleName}");
        W();
        W("现在请打开「高级安全 Windows 防火墙」核对：");
        W("  方式一：Win+R 输入  wf.msc  回车");
        W("  方式二：打开 出站规则，按「组」排序，找到分组为 AppGuard 的规则");
        W();
        W("你应该看到：");
        W("  - 名称以 AppGuard_Block_ 开头");
        W("  - 分组为 AppGuard");
        W("  - 操作为「阻止」，方向为「出站」");
        W("  - 协议为「任何」，配置文件为「所有」");
        W("  - 程序与路径列指向上面那个目标程序");
        W();
        W("核对完之后，运行下面这条命令把它删掉：");
        W("  WinAppGuard.FirewallCheck.exe --cleanup");
    }

    // ==================================================================
    // 模式 3：清理
    // ==================================================================

    private static void RunCleanup()
    {
        var before = FirewallManager.GetAppGuardRules();
        W("================= 清理全部 AppGuard 规则 =================");
        W($"清理前 = {before.Count} 条");
        foreach (var rule in before)
        {
            W($"  - {rule.Name}   ->   {rule.ApplicationPath}");
        }

        var deleted = FirewallManager.DeleteAllAppGuardRules();
        W($"已删除 = {deleted} 条");
        W($"清理后 = {FirewallManager.GetAppGuardRules().Count} 条");
        W();
        W($"系统防火墙规则总数 = {FirewallManager.GetTotalRuleCount()}（非 AppGuard 前缀的规则不受影响）");
    }

    // ==================================================================
    // 模式 4：只读状态
    // ==================================================================

    private static void RunStatus()
    {
        W("================= 只读状态（不修改任何东西）=================");
        W($"管理员身份         = {IsAdmin()}");

        var state = FirewallManager.GetGlobalState();
        W($"防火墙启用         = {state.FirewallEnabled}");
        W($"默认入站动作       = {DescribeAction(state.DefaultInboundAction)}");
        W($"默认出站动作       = {DescribeAction(state.DefaultOutboundAction)}");
        W($"系统防火墙规则总数 = {FirewallManager.GetTotalRuleCount()}");

        var rules = FirewallManager.GetAppGuardRules();
        W($"AppGuard 规则      = {rules.Count} 条");
        foreach (var rule in rules)
        {
            W($"  - {rule.Name}");
            W($"      程序 = {rule.ApplicationPath}");
            W($"      动作 = {rule.ActionText}   方向 = {rule.DirectionText}   协议 = {rule.ProtocolText}   启用 = {rule.EnabledText}");
        }
    }

    // ==================================================================
    // 开机自启（计划任务）
    // ==================================================================

    /// <summary>只读模式：打印自启任务的状态和原始定义。</summary>
    private static void RunAutoStartStatus()
    {
        W("================= 开机自启状态（只读，不修改任何东西）=================");
        W($"本工具自身路径 = {Environment.ProcessPath}");
        W($"任务名         = {AppConstants.ScheduledTaskName}");
        W($"期望的参数     = {AppConstants.AutostartArgument}");
        W();

        var status = AutoStartManager.GetStatus();
        W($"任务是否存在   = {status.Exists}");

        if (!status.Exists)
        {
            W("系统里没有这个任务。");
            return;
        }

        W($"执行的程序     = {status.ExecutablePath}");
        W($"参数           = {status.Arguments}");
        W($"运行级别       = {status.RunLevel}");
        W($"触发器         = {status.Trigger}");
        W($"任务状态       = {status.TaskState}");
        W();
        W("它指向的是不是本工具自己 = " +
          (string.Equals(status.ExecutablePath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)
              ? "是"
              : "否（正常现象：产品 WinAppGuard.exe 和本自检工具是两个不同的 exe）"));
        W();
        W("---- 任务的原始 XML 定义 ----");
        W(status.RawXml);
        W("---- XML 结束 ----");
    }

    /// <summary>删除自启任务。用于清理残留。</summary>
    private static void RunAutoStartDisable()
    {
        W("================= 删除开机自启任务 =================");

        var before = AutoStartManager.GetStatus();
        W($"删除前：任务存在 = {before.Exists}");
        if (before.Exists)
        {
            W($"        执行的程序 = {before.ExecutablePath}");
        }

        var deleted = AutoStartManager.Disable();
        W($"Disable 返回     = {deleted}");
        W($"删除后：任务存在 = {AutoStartManager.GetStatus().Exists}");

        if (!deleted)
        {
            W();
            W("（本来就不存在，所以什么都没做。）");
        }
    }

    /// <summary>
    /// 开机自启的完整测试：创建 → 逐项核对 → 幂等性 → 删除。
    ///
    /// 测试对象是**本工具自己**（自检工具也是 .exe），不是产品 WinAppGuard.exe。
    /// 这样测完就能干净删除，不会影响你自己的开机自启配置。
    /// </summary>
    private static void RunAutoStartTest()
    {
        var results = new List<(string Title, bool Passed)>();

        void Check(string title, bool passed)
        {
            results.Add((title, passed));
            W($"  [{(passed ? "通过" : "失败")}] {title}");
        }

        var exePath = Environment.ProcessPath!;

        W("################################################################");
        W("#   WinAppGuard 开机自启（计划任务）测试                        #");
        W("################################################################");
        W($"测试用的程序 = {exePath}");
        W($"当前用户     = {WindowsIdentity.GetCurrent().Name}");
        W();

        if (AutoStartManager.GetStatus().Exists)
        {
            // 不擅自删掉用户已有的配置 —— 那可能正是他想要的。
            W("!!! 测试开始前系统里就已经存在名为 WinAppGuard 的任务。");
            W("    为了不破坏你的配置，本次测试不会继续。");
            W("    请先运行 --autostart-status 看看它是什么，确认后运行 --autostart-disable 删掉。");
            return;
        }

        try
        {
            W("---- 1. 创建任务 ----");
            AutoStartManager.Enable(exePath);
            var after = AutoStartManager.GetStatus();

            Check("任务已创建", after.Exists);
            Check("任务里配置的程序 = 本工具路径",
                string.Equals(after.ExecutablePath, exePath, StringComparison.OrdinalIgnoreCase));
            Check($"任务里配置的参数 = {AppConstants.AutostartArgument}",
                string.Equals(after.Arguments.Trim(), AppConstants.AutostartArgument, StringComparison.OrdinalIgnoreCase));

            W();
            W("---- 2. 逐项核对任务内容 ----");
            var xml = after.RawXml;
            W("原始 XML：");
            foreach (var line in xml.Split('\n'))
            {
                W("    " + line.TrimEnd());
            }

            W();
            Check("运行级别 = HighestAvailable（开机启动不弹 UAC）",
                xml.Contains("<RunLevel>HighestAvailable</RunLevel>"));
            Check("触发器是「用户登录时」",
                xml.Contains("<LogonTrigger>"));
            Check("执行时长不限（PT0S）—— 否则常驻托盘的程序会在 72 小时后被计划程序杀掉",
                xml.Contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
            Check("多实例策略 = IgnoreNew（不会同时冒出两个托盘图标）",
                xml.Contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
            Check("任务描述里写明了是 WinAppGuard 创建的，用户一眼能看懂",
                xml.Contains("WinAppGuard"));
            Check("任务没有被隐藏（透明可见的要求）",
                !xml.Contains("<Hidden>true</Hidden>"));
            Check("运行身份是当前用户",
                xml.Contains(WindowsIdentity.GetCurrent().Name));
            Check("「切到电池就停止」已关闭，否则笔记本拔电源就会退出",
                xml.Contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));

            W();
            W("---- 3. 幂等性：重复创建不应产生第二条 ----");
            AutoStartManager.Enable(exePath);
            var count = CountTasksNamed(AppConstants.ScheduledTaskName);
            W($"  名叫 {AppConstants.ScheduledTaskName} 的任务条数 = {count}");
            Check("重复创建后仍然只有一条任务", count == 1);

            W();
            W("---- 4. 删除 ----");
            var deleted = AutoStartManager.Disable();
            Check("Disable 返回 true", deleted);
            Check("删除后任务确实消失了", !AutoStartManager.GetStatus().Exists);
        }
        finally
        {
            // 无论中途出什么事，都不把这个任务留在系统里。
            try
            {
                if (AutoStartManager.GetStatus().Exists)
                {
                    AutoStartManager.Disable();
                }
            }
            catch
            {
                // 收尾清理，忽略
            }

            W();
            W($"收尾：当前残留的 WinAppGuard 任务 = {AutoStartManager.GetStatus().Exists}（应为 False）");
            PrintSummary(results);
        }
    }

    /// <summary>
    /// 用一条独立于 AutoStartManager 的 COM 调用路径去数任务条数。
    /// 刻意不复用产品代码，这样它才能真的起到交叉验证的作用。
    /// </summary>
    private static int CountTasksNamed(string taskName)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service")
            ?? throw new PlatformNotSupportedException("系统没有 Schedule.Service 组件");

        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        dynamic folder = service.GetFolder("\\");

        var count = 0;
        foreach (var task in folder.GetTasks(0))
        {
            if (string.Equals(Convert.ToString(task.Name), taskName, StringComparison.OrdinalIgnoreCase))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// 出厂审计：直接读**编译出来的程序集**的元数据，而不是靠搜源码。
    ///
    /// 搜源码只能证明「我没写」，读元数据能证明「编出来的东西里确实没有」——
    /// 包括间接引用和框架自动带进来的东西。结论更硬。
    /// </summary>
    private static void RunAudit(string[] args)
    {
        W("################################################################");
        W("#   WinAppGuard 出厂审计                                        #");
        W("################################################################");
        W();

        var target = ResolveAuditTarget(args);
        if (target is null)
        {
            W("找不到要审计的程序集。");
            W("用法：--audit [WinAppGuard.dll 的路径]");
            W("（不传路径时会在几个常见位置自动找。）");
            W();
            W("提示：要审计的是编译出来的程序集 DLL，不是单文件 exe ——");
            W("      单文件 exe 是宿主程序，我们的代码被打包在里面，直接读它的元数据读不到。");
            return;
        }

        W($"审计对象 = {target}");
        W($"文件大小 = {new FileInfo(target).Length / 1024.0:F0} KB");
        W();

        var results = new List<(string Title, bool Passed)>();

        using var stream = File.OpenRead(target);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        AuditAssemblies(metadata, results);
        AuditNetworking(metadata, results);
        AuditNativeImports(metadata);
        AuditSensitiveApis(metadata);

        PrintSummary(results);

        W();
        W("说明：单文件发布出来的 WinAppGuard.exe 就是把上面这个程序集打包进去的，");
        W("      所以这里审计到的引用关系，和用户拿到手的 exe 是一致的。");
    }

    /// <summary>找要审计的程序集。优先用命令行给的路径，否则从当前目录往上找项目根目录。</summary>
    private static string? ResolveAuditTarget(string[] args)
    {
        // 1) 命令行里 --audit 后面跟的第一个不是 -- 开头的参数，当作路径
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--audit", StringComparison.OrdinalIgnoreCase)
                && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                return File.Exists(args[i + 1]) ? Path.GetFullPath(args[i + 1]) : null;
            }
        }

        // 2) 自动查找：从当前目录逐级往上，找到含 src\WinAppGuard\WinAppGuard.csproj 的那一级，
        //    就是项目根目录，再从它的 bin 里找编译产物。
        //
        //    为什么要这样绕：这个工具可能在两个位置运行 ——
        //    发布出来的 dist-tools\，或者开发时的 tools\SelfCheck\bin\<配置>\<框架>\。
        //    两者的相对层级不同，写死相对路径一定会有一边找不到。
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        for (var depth = 0; depth < 8 && directory is not null; depth++, directory = directory.Parent)
        {
            var projectFile = Path.Combine(directory.FullName, "src", "WinAppGuard", "WinAppGuard.csproj");
            if (!File.Exists(projectFile))
            {
                continue;
            }

            // Release 优先（发布用的就是它），然后 Debug。
            // 不写死目标框架名，用递归查找，将来升级 .NET 版本也不用改这里。
            foreach (var configuration in new[] { "Release", "Debug" })
            {
                var binPath = Path.Combine(directory.FullName, "src", "WinAppGuard", "bin", configuration);
                if (!Directory.Exists(binPath))
                {
                    continue;
                }

                var found = Directory
                    .EnumerateFiles(binPath, "WinAppGuard.dll", SearchOption.AllDirectories)
                    .OrderByDescending(File.GetLastWriteTime)
                    .FirstOrDefault();

                if (found is not null)
                {
                    return found;
                }
            }
        }

        return null;
    }

    /// <summary>引用了哪些程序集 —— 用来证明没有引入第三方库。</summary>
    private static void AuditAssemblies(MetadataReader metadata, List<(string, bool)> results)
    {
        W("===== 1. 引用的程序集（应当全部是 .NET 框架自带的）=====");

        var names = new List<string>();
        foreach (var handle in metadata.AssemblyReferences)
        {
            names.Add(metadata.GetString(metadata.GetAssemblyReference(handle).Name));
        }

        names.Sort(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names)
        {
            W($"    {name}");
        }

        var thirdParty = names
            .Where(n => !n.StartsWith("System", StringComparison.OrdinalIgnoreCase)
                        && !n.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)
                        && !n.StartsWith("mscorlib", StringComparison.OrdinalIgnoreCase)
                        && !n.StartsWith("netstandard", StringComparison.OrdinalIgnoreCase)
                        && !n.StartsWith("WindowsBase", StringComparison.OrdinalIgnoreCase))
            .ToList();

        W($"    共 {names.Count} 个");
        W();
        results.Add(("零第三方库：引用的程序集全部来自 .NET 框架", thirdParty.Count == 0));
        if (thirdParty.Count > 0)
        {
            W($"    发现第三方程序集：{string.Join(", ", thirdParty)}");
        }
    }

    /// <summary>
    /// 有没有引用「会发起网络行为」的类型 —— 用来证明程序运行期不联网。
    ///
    /// 注意区分：System.Net.IPAddress / IPEndPoint / AddressFamily 这类是**纯数据类型**，
    /// 只用来把连接表里的字节格式化成可读地址，本身不会发起任何连接。
    /// </summary>
    private static void AuditNetworking(MetadataReader metadata, List<(string, bool)> results)
    {
        W("===== 2. 网络相关类型引用（用来证明运行期不联网）=====");

        // 纯数据类型，允许出现
        var allowedTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Net.IPAddress",
            "System.Net.IPEndPoint",
            "System.Net.Sockets.AddressFamily",
            "System.Net.Sockets.SocketError",
            "System.Net.Sockets.SocketException",
        };

        // 只要出现就说明程序有能力联网
        var dangerousNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "HttpClient", "HttpMessageHandler", "HttpContent", "HttpRequestMessage", "HttpResponseMessage",
            "WebClient", "WebRequest", "HttpWebRequest", "HttpListener",
            "Socket", "TcpClient", "TcpListener", "UdpClient", "UdpAnySourceMulticastClient",
            "NetworkStream", "SslStream", "AuthenticatedStream",
            "SmtpClient", "Ping", "Dns", "WebSocket", "ClientWebSocket",
            "NamedPipeClientStream", "NamedPipeServerStream",
        };

        var hits = new List<string>();
        foreach (var handle in metadata.TypeReferences)
        {
            var typeRef = metadata.GetTypeReference(handle);
            var ns = metadata.GetString(typeRef.Namespace);
            var name = metadata.GetString(typeRef.Name);
            var full = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

            if (allowedTypes.Contains(full))
            {
                continue;
            }

            if (full.StartsWith("System.Net", StringComparison.Ordinal)
                || dangerousNames.Contains(name))
            {
                hits.Add(full);
            }
        }

        hits.Sort(StringComparer.OrdinalIgnoreCase);

        if (hits.Count == 0)
        {
            W("    没有引用任何会发起网络行为的类型。");
        }
        else
        {
            foreach (var hit in hits)
            {
                W($"    ！{hit}");
            }
        }

        W();
        W("    （已排除的纯数据类型：System.Net.IPAddress / IPEndPoint / AddressFamily ——");
        W("      它们只是把连接表里的字节转成可读地址，不会建立任何连接。）");
        W();

        results.Add(("零网络代码：没有引用任何会发起网络行为的类型", hits.Count == 0));
    }

    /// <summary>列出全部 P/Invoke —— 这是程序能碰到的原生 API 的完整清单，供人工审计。</summary>
    private static void AuditNativeImports(MetadataReader metadata)
    {
        W("===== 3. 全部原生 API 调用（P/Invoke 完整清单）=====");

        var imports = new List<string>();
        foreach (var handle in metadata.MethodDefinitions)
        {
            var method = metadata.GetMethodDefinition(handle);
            var import = method.GetImport();

            // MethodImport 是结构体不是句柄，没有 IsNil；用它的 Module 判断有没有 P/Invoke。
            if (import.Module.IsNil)
            {
                continue;
            }

            var dll = metadata.GetString(metadata.GetModuleReference(import.Module).Name);
            var entry = metadata.GetString(import.Name);
            imports.Add($"{dll}!{entry}");
        }

        imports.Sort(StringComparer.OrdinalIgnoreCase);
        foreach (var import in imports)
        {
            W($"    {import}");
        }

        W($"    共 {imports.Count} 个");
        W();
        W("    上面就是这个程序能调用的全部非托管函数。除这些以外它碰不到任何系统底层。");
        W();
    }

    /// <summary>列出值得注意的托管 API 引用，用于人工确认用途。</summary>
    private static void AuditSensitiveApis(MetadataReader metadata)
    {
        W("===== 4. 需要留意的托管 API（确认用途都在预期内）=====");

        var interesting = new (string Type, string Member, string Reason)[]
        {
            ("System.Diagnostics.Process", "Start", "启动外部进程：提权重启自身、打开日志目录"),
            ("System.IO.File", "AppendAllText", "写文件：只用于日志"),
            ("System.IO.File", "WriteAllText", "写文件：只用于日志"),
            ("System.IO.Directory", "CreateDirectory", "建目录：只用于日志目录"),
            ("Microsoft.Win32.Registry", "*", "读写注册表（预期：不应出现）"),
        };

        foreach (var (type, member, reason) in interesting)
        {
            var found = false;
            foreach (var handle in metadata.MemberReferences)
            {
                var memberRef = metadata.GetMemberReference(handle);
                if (memberRef.Parent.Kind != HandleKind.TypeReference)
                {
                    continue;
                }

                var typeRef = metadata.GetTypeReference((TypeReferenceHandle)memberRef.Parent);
                var ns = metadata.GetString(typeRef.Namespace);
                var typeName = metadata.GetString(typeRef.Name);
                var fullType = string.IsNullOrEmpty(ns) ? typeName : $"{ns}.{typeName}";
                var memberName = metadata.GetString(memberRef.Name);

                var typeMatches = type.EndsWith(".*", StringComparison.Ordinal)
                    ? fullType.StartsWith(type[..^2], StringComparison.Ordinal)
                    : fullType == type;

                if (typeMatches && (member == "*" || memberName == member))
                {
                    found = true;
                    break;
                }
            }

            W($"    [{(found ? "有" : "无")}] {type}.{member}");
            W($"          用途：{reason}");
        }

        W();
    }

    // ==================================================================
    // 公共工具
    // ==================================================================

    /// <summary>找一个确定存在的系统 exe 作为测试目标（它们都没有联网行为，即使规则残留也无影响）。</summary>
    private static List<string> FindTestTargets()
        => new[] { "notepad.exe", "cmd.exe", "where.exe", "timeout.exe", "find.exe" }
            .Select(name => Path.Combine(Environment.SystemDirectory, name))
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static bool IsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string DescribeAction(FirewallAction action)
        => $"{action}（{(action == FirewallAction.Block ? "阻止" : "允许")}）";

    /// <summary>打印总结，并明确列出所有失败的检查项。</summary>
    private static void PrintSummary(List<(string Title, bool Passed)> results)
    {
        W();
        W("################################################################");
        W("#   总结                                                        #");
        W("################################################################");

        var failed = results.Where(r => !r.Passed).ToList();
        _failedCheckCount += failed.Count;

        W($"检查项总数 = {results.Count}");
        W($"通过       = {results.Count - failed.Count}");
        W($"失败       = {failed.Count}");
        W();

        if (failed.Count == 0)
        {
            W("结果：全部通过。");
        }
        else
        {
            W("结果：以下检查项未通过 ——");
            foreach (var item in failed)
            {
                W($"  ! {item.Title}");
            }
        }

        W();
        W($"收尾后残留的 AppGuard 规则 = {FirewallManager.GetAppGuardRules().Count} 条（应为 0）");
    }

    /// <summary>同时输出到控制台和报告缓冲。</summary>
    private static void W(string line = "")
    {
        Console.WriteLine(line);
        Report.AppendLine(line);
    }

    /// <summary>把报告写到 exe 同目录下的文本文件，方便贴给别人看。</summary>
    private static void SaveReport()
    {
        try
        {
            var directory = AppContext.BaseDirectory;
            var path = Path.Combine(directory, "WinAppGuard-自检报告.txt");
            File.WriteAllText(path, Report.ToString(), Encoding.UTF8);
            Console.WriteLine();
            Console.WriteLine($"报告已保存到：{path}");
        }
        catch (Exception ex)
        {
            // 报告写不出来不影响验证结论，不要因此报错退出。
            Console.WriteLine($"（报告文件写入失败：{ex.Message}）");
        }
    }

    private static void Pause()
    {
        Console.WriteLine();
        Console.WriteLine("按回车键退出...");
        Console.ReadLine();
    }
}
